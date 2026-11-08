// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Request/response correlation for the Algorand topic-based RPC protocol.
//!
//! When a node sends a request, it:
//! 1. Appends a unique nonce topic (key `"nonce"`, uvarint-encoded value)
//! 2. Serializes the Topics to bytes
//! 3. Computes the SHA-512/256 hash of the serialized bytes
//! 4. Truncates the hash to a `u64` (first 8 bytes, little-endian)
//! 5. Stores a oneshot sender keyed by that `u64`
//!
//! When a response arrives, the `"RequestHash"` topic carries the `u64` hash
//! of the original request (as uvarint bytes), allowing the response to be
//! routed to the correct waiting receiver.
//!
//! Reference: go-algorand/network/topics.go (hashTopics, MakeNonceTopic)
//!            go-algorand/network/wsPeer.go  (Request, Respond, readLoop)
//!            go-algorand/crypto/util.go     (Hash = SHA-512/256, TrimUint64)

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use sha2::{Digest as _, Sha512_256};
use tokio::sync::{oneshot, Mutex};
use tracing::warn;

use crate::topics::{Topic, Topics, TopicsError};

// ---------------------------------------------------------------------------
// uvarint helpers (matching Go's binary.PutUvarint / binary.Uvarint)
// ---------------------------------------------------------------------------

/// Encode a `u64` as an unsigned variable-length integer (LEB128).
///
/// Public so transports outside this crate that need to build a
/// hand-rolled `TopicMsgResp` (mirroring [`crate::ws_peer`]'s own
/// `ForwardingPolicy::Respond` handling) can encode the `RequestHash`
/// topic value themselves — see `bin/algod-rust`'s P2P `/algorand-ws`
/// stream reply path (issue #591), which cannot depend on `ws_peer`'s
/// private read-loop internals.
pub fn encode_uvarint(mut value: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10);
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
    buf
}

/// Decode a `u64` from an unsigned variable-length integer (LEB128).
/// Returns `(value, bytes_consumed)` or `None` if malformed.
fn decode_uvarint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 63 && byte > 1 {
            return None;
        }
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Topic key for the nonce added to every request.
///
/// Go equivalent: `MakeNonceTopic` uses `"nonce"` as the key.
pub const REQUEST_NONCE_FIELD: &str = "nonce";

/// Topic key for the response hash that correlates a response to its request.
///
/// Go equivalent: `requestHashKey = "RequestHash"` in topics.go.
pub const RESPONSE_HASH_FIELD: &str = "RequestHash";

/// Default timeout for waiting on a request response (60 seconds).
///
/// Go equivalent: `httpServerWriteTimeout = 60 * time.Second` in wsNetwork.go.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// hash_topics — mirrors Go's hashTopics() in network/topics.go
// ---------------------------------------------------------------------------

/// Compute the SHA-512/256 hash of serialized topics, then truncate to a u64
/// by reading the first 8 bytes as little-endian.
///
/// This matches Go's `hashTopics()` which calls `crypto.Hash()` (SHA-512/256)
/// followed by `digest.TrimUint64()` (`binary.LittleEndian.Uint64(d[:8])`).
pub fn hash_topics(serialized: &[u8]) -> u64 {
    let digest: [u8; 32] = {
        let mut hasher = Sha512_256::new();
        hasher.update(serialized);
        hasher.finalize().into()
    };
    u64::from_le_bytes(digest[..8].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during request/response processing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestResponseError {
    /// Failed to deserialize response data as Topics.
    #[error("failed to deserialize response topics: {0}")]
    DeserializationFailed(TopicsError),

    /// The response Topics are missing the required `RESPONSE_HASH_FIELD`.
    #[error("response is missing the '{RESPONSE_HASH_FIELD}' hash field")]
    MissingHashField,

    /// The response hash field could not be decoded as a uvarint.
    #[error("response hash is not a valid uvarint")]
    InvalidHashEncoding,

    /// A `TopicMsgResp` arrived with no matching outstanding request: the
    /// per-peer outstanding-topic-request counter went negative.
    ///
    /// Mirrors go-algorand's `disconnectUnexpectedTopicResp` protocol
    /// violation (`network/wsPeer.go:547-556`) — a peer sending more
    /// `TS`/`TopicMsgResp` responses than we've ever sent it requests. The
    /// caller (the read loop) must disconnect the peer on this error, the
    /// same way go tears down the connection with
    /// `networkConnectionsDroppedTotal{reason="unrequestedTS"}`.
    #[error("peer sent a TopicMsgResp with no matching outstanding request")]
    UnrequestedResponse,
}

// ---------------------------------------------------------------------------
// RequestTracker
// ---------------------------------------------------------------------------

/// Tracks pending request/response correlations.
///
/// Each outgoing request is assigned a unique nonce and hashed; the truncated
/// u64 hash (first 8 bytes of SHA-512/256 as little-endian) is used to match
/// the eventual response back to the waiting receiver.
pub struct RequestTracker {
    /// Monotonically-increasing nonce counter.
    nonce: AtomicU64,

    /// Pending requests: truncated u64 hash → oneshot sender.
    pending: Mutex<HashMap<u64, oneshot::Sender<Topics>>>,

    /// Outstanding topic-request counter, mirroring go-algorand's
    /// `wsPeer.outstandingTopicRequests` (`network/wsPeer.go:175-177`): one
    /// per peer, incremented when a request is handed off to the send queue
    /// ([`mark_request_sent`](Self::mark_request_sent)) and decremented once
    /// per arriving `TopicMsgResp` response ([`handle_response`](Self::handle_response)),
    /// regardless of whether that particular response's hash is found.
    /// A negative value after decrementing is a protocol violation (the peer
    /// has sent more responses than we've ever requested) ONLY when no
    /// request is pending, as in go (`network/wsPeer.go:547`); while a
    /// request is pending the value may transiently be negative because the
    /// request is registered before it is counted.
    ///
    /// Unlike the `pending` map (whose entries are removed as soon as an
    /// individual `Request()` call's own wait ends, including on a
    /// client-side timeout), this counter is never decremented by a local
    /// timeout — only by an actual response arriving — so it also catches a
    /// *late* response (for a request whose local wait already gave up) that
    /// nonetheless corresponds to a real, previously-sent request.
    outstanding: AtomicI64,

    /// Test-only: invoked right before a response payload is parsed.
    #[cfg(test)]
    parse_hook: std::sync::Mutex<Option<std::sync::Arc<dyn Fn() + Send + Sync>>>,
}

impl RequestTracker {
    /// Create a new, empty `RequestTracker`.
    pub fn new() -> Self {
        Self {
            nonce: AtomicU64::new(0),
            pending: Mutex::new(HashMap::new()),
            outstanding: AtomicI64::new(0),
            #[cfg(test)]
            parse_hook: std::sync::Mutex::new(None),
        }
    }

    /// Record that a request was successfully handed off to the peer's send
    /// queue. Mirrors go's `wp.outstandingTopicRequests.Add(1)`
    /// (`network/wsPeer.go:1064`), called only once the request message has
    /// actually been enqueued for sending (not if enqueueing failed).
    pub fn mark_request_sent(&self) {
        self.outstanding.fetch_add(1, Ordering::SeqCst);
    }

    /// The current value of the outstanding-topic-request counter. Exposed
    /// for tests and diagnostics.
    pub fn outstanding_topic_requests(&self) -> i64 {
        self.outstanding.load(Ordering::SeqCst)
    }

    /// Prepare a request for sending.
    ///
    /// This method:
    /// 1. Generates a unique nonce and appends it as a uvarint-encoded topic
    /// 2. Serializes the augmented Topics
    /// 3. Computes the SHA-512/256 hash of the serialized bytes
    /// 4. Truncates to u64 (first 8 bytes, little-endian — `TrimUint64`)
    /// 5. Registers a oneshot channel for the response
    ///
    /// Returns `(serialized_bytes, request_hash_u64, response_receiver)`.
    ///
    /// The caller should send the serialized bytes over the wire and then
    /// await the receiver (with a timeout via `tokio::time::timeout`).
    pub async fn prepare_request(
        &self,
        mut topics: Topics,
    ) -> (Vec<u8>, u64, oneshot::Receiver<Topics>) {
        // 1. Generate nonce (atomic increment, starting from 1)
        let nonce_val = self.nonce.fetch_add(1, Ordering::Relaxed) + 1;
        let nonce_bytes = encode_uvarint(nonce_val);

        // 2. Append nonce topic
        topics.0.push(Topic::new(REQUEST_NONCE_FIELD, nonce_bytes));

        // 3. Serialize
        let serialized = topics.marshal();

        // 4. Compute SHA-512/256 hash, then TrimUint64 (first 8 bytes LE)
        let hash = hash_topics(&serialized);

        // 5. Create oneshot channel
        let (tx, rx) = oneshot::channel();

        // 6. Store in pending map
        {
            let mut pending = self.pending.lock().await;
            pending.insert(hash, tx);
        }

        (serialized, hash, rx)
    }

    /// Handle an incoming response message.
    ///
    /// Deserializes the data as Topics, extracts the `RESPONSE_HASH_FIELD`
    /// (a uvarint-encoded u64), and routes the response to the matching
    /// pending request.
    ///
    /// The outstanding-topic-request counter is decremented first. When NO
    /// request is pending (go: `lenResponseChannels() == 0`) the response is
    /// not parsed: it is an [`UnrequestedResponse`](RequestResponseError::UnrequestedResponse)
    /// violation if the counter went negative, otherwise a late reply that is
    /// silently discarded. With a request pending the counter is not judged;
    /// if the hash is not found (stale/late response) a warning is logged and
    /// `Ok(())` is returned, and a missing/undecodable hash field is an error.
    pub async fn handle_response(&self, data: &[u8]) -> Result<(), RequestResponseError> {
        // Judge the outstanding-topic-request counter exactly as go does
        // (`network/wsPeer.go:547-556`, `lenResponseChannels() == 0`): the
        // counter is decremented once for every arriving `TopicMsgResp`
        // (go: `:548`/`:644`), but a negative value is a protocol violation
        // (`disconnectUnexpectedTopicResp`) ONLY when no request is pending.
        //
        // With a request pending the decrement alone is no violation: a
        // request is registered before it is enqueued and counted after, so a
        // fast reply can arrive in between with the counter still at zero
        // (issue #2249: it disconnected the relay under load and stalled an
        // all-Rust cluster). With nothing pending, a reply that is not beyond
        // the requests ever counted is a late answer to a request whose wait
        // timed out and is discarded without being parsed.
        //
        // The `pending` lock is held only for the emptiness check next to the
        // decrement, never while the (untrusted, peer-supplied) payload is
        // parsed: a large or malformed reply must not block
        // `prepare_request` / `cancel_request` / `pending_count` or another
        // reply. The check is not atomic with the later lookup (a request can
        // be registered or cancelled in between, and `mark_request_sent` is
        // lock-free), which is harmless: go's `lenResponseChannels()` read
        // (`wsPeer.go:547`) is equally a point-in-time snapshot.
        {
            let pending = self.pending.lock().await;
            let remaining = self.outstanding.fetch_sub(1, Ordering::SeqCst) - 1;
            if pending.is_empty() {
                return if remaining < 0 {
                    Err(RequestResponseError::UnrequestedResponse)
                } else {
                    Ok(())
                };
            }
        }

        #[cfg(test)]
        {
            let hook = self.parse_hook.lock().unwrap().clone();
            if let Some(hook) = hook {
                hook();
            }
        }

        // Deserialize response Topics
        let topics =
            Topics::unmarshal(data).map_err(RequestResponseError::DeserializationFailed)?;

        // Extract the response hash field
        let hash_bytes = topics
            .get_value(RESPONSE_HASH_FIELD)
            .ok_or(RequestResponseError::MissingHashField)?;

        // Decode the hash as a uvarint (matching Go's binary.Uvarint)
        let (hash_key, _) =
            decode_uvarint(hash_bytes).ok_or(RequestResponseError::InvalidHashEncoding)?;

        // Look up and remove the pending request (lock re-taken only now).
        let sender = self.pending.lock().await.remove(&hash_key);

        match sender {
            Some(tx) => {
                // Send the response; if the receiver was dropped, that's fine
                let _ = tx.send(topics);
            }
            None => {
                warn!(
                    hash = hash_key,
                    "received response for unknown/stale request"
                );
            }
        }

        Ok(())
    }

    /// Cancel a pending request without sending a response.
    ///
    /// The corresponding receiver will get a `RecvError` indicating that
    /// the sender was dropped.
    pub async fn cancel_request(&self, hash: u64) {
        let mut pending = self.pending.lock().await;
        pending.remove(&hash);
        // Sender is dropped, receiver will get RecvError
    }

    /// Returns the number of currently pending (unresolved) requests.
    pub async fn pending_count(&self) -> usize {
        let pending = self.pending.lock().await;
        pending.len()
    }
}

impl Default for RequestTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a fake response Topics with the given hash as uvarint.
    fn make_response(hash: u64, extra_key: &str, extra_val: &[u8]) -> Vec<u8> {
        let hash_bytes = encode_uvarint(hash);
        let topics = Topics::from_vec(vec![
            Topic::new(RESPONSE_HASH_FIELD, hash_bytes),
            Topic::new(extra_key, extra_val.to_vec()),
        ]);
        topics.marshal()
    }

    #[tokio::test]
    async fn roundtrip_prepare_and_handle() {
        let tracker = RequestTracker::new();

        // Prepare a request
        let request_topics = Topics::from_vec(vec![Topic::new("key", b"value".to_vec())]);
        let (_serialized, hash, rx) = tracker.prepare_request(request_topics).await;
        // Simulate the request having actually been enqueued for sending
        // (mirrors ws_peer.rs's `request_with_timeout_via_tracker` calling
        // this only once `try_send` succeeds).
        tracker.mark_request_sent();

        assert_eq!(tracker.pending_count().await, 1);

        // Build a response containing the request hash
        let response_data = make_response(hash, "result", b"ok");

        // Handle the response
        tracker.handle_response(&response_data).await.unwrap();

        // Receiver should get the response
        let response_topics = rx.await.unwrap();
        assert!(response_topics.get_value(RESPONSE_HASH_FIELD).is_some());
        assert_eq!(response_topics.get_value("result"), Some(b"ok".as_slice()));

        assert_eq!(tracker.pending_count().await, 0);
    }

    #[tokio::test]
    async fn stale_response_does_not_error() {
        let tracker = RequestTracker::new();

        // A request was genuinely sent (and thus is counted as outstanding),
        // but the response we receive carries an unknown/mismatched hash —
        // e.g. a late reply for a request whose local wait already timed out
        // and removed its `pending` map entry, or a reply for some other
        // request race. Since the peer HAS been sent at least one real
        // request, this must not be treated as the "unrequested" protocol
        // violation — only a genuinely unmatched-and-uncounted-for response
        // (see `unrequested_response_is_detected` below) should disconnect.
        let request_topics = Topics::from_vec(vec![Topic::new("q", b"data".to_vec())]);
        let (_serialized, _hash, _rx) = tracker.prepare_request(request_topics).await;
        tracker.mark_request_sent();

        // Build a response with an unknown hash
        let response_data = make_response(0xDEAD_BEEF, "data", b"stale");

        // Should not return an error
        let result = tracker.handle_response(&response_data).await;
        assert!(result.is_ok());
    }

    /// Issue #2249: the request is registered (`prepare_request`) before it is
    /// handed to the send queue and only COUNTED (`mark_request_sent`) after
    /// it, so a fast peer's reply (a block service answering "not available"
    /// at once, a loaded one-CPU runner) can reach the read loop between the
    /// two. go's read loop only judges the counter when NO request is pending
    /// (`lenResponseChannels() == 0`), so this ordering is harmless there; it
    /// must not disconnect the peer here either. The reply is delivered and the
    /// counter is back to zero once the send path has counted its request.
    #[tokio::test]
    async fn a_response_that_beats_the_requests_own_count_is_not_a_violation() {
        let tracker = RequestTracker::new();
        let request_topics = Topics::from_vec(vec![Topic::new("key", b"value".to_vec())]);
        let (_serialized, hash, rx) = tracker.prepare_request(request_topics).await;

        // The reply arrives BEFORE `mark_request_sent` ran.
        let response_data = make_response(hash, "result", b"ok");
        tracker
            .handle_response(&response_data)
            .await
            .expect("a pending request makes an early reply legitimate");

        tracker.mark_request_sent();
        assert_eq!(tracker.outstanding_topic_requests(), 0);
        let response_topics = rx.await.expect("the reply is delivered");
        assert_eq!(response_topics.get_value("result"), Some(b"ok".as_slice()));
    }

    /// Issue #2251: two requests A and B are registered, a reply to A arrives
    /// before EITHER has been counted, then both are counted, then B's reply
    /// arrives. None of them is a violation and each receiver gets its own
    /// reply; the counter ends at zero.
    #[tokio::test]
    async fn two_concurrent_requests_with_an_early_reply_are_not_violations() {
        let tracker = RequestTracker::new();
        let (_sa, hash_a, rx_a) = tracker
            .prepare_request(Topics::from_vec(vec![Topic::new("q", b"a".to_vec())]))
            .await;
        let (_sb, hash_b, rx_b) = tracker
            .prepare_request(Topics::from_vec(vec![Topic::new("q", b"b".to_vec())]))
            .await;
        assert_eq!(tracker.pending_count().await, 2);

        // A's reply beats both counts.
        tracker
            .handle_response(&make_response(hash_a, "r", b"for-a"))
            .await
            .expect("an early reply with requests pending");
        tracker.mark_request_sent();
        tracker.mark_request_sent();
        assert_eq!(tracker.outstanding_topic_requests(), 1);

        tracker
            .handle_response(&make_response(hash_b, "r", b"for-b"))
            .await
            .expect("B's reply");
        assert_eq!(tracker.outstanding_topic_requests(), 0);
        assert_eq!(tracker.pending_count().await, 0);
        assert_eq!(
            rx_a.await.unwrap().get_value("r"),
            Some(b"for-a".as_slice())
        );
        assert_eq!(
            rx_b.await.unwrap().get_value("r"),
            Some(b"for-b".as_slice())
        );
    }

    /// Issue #2251: a request whose enqueue failed (`try_send` full) is
    /// cancelled and never counted (`request_with_timeout_via_tracker`). While
    /// another request is pending a stray reply is judged like any reply with a
    /// pending request (delivered or logged stale, no violation); once nothing
    /// is pending, a reply beyond the requests ever counted is the violation.
    #[tokio::test]
    async fn a_cancelled_uncounted_request_never_makes_a_reply_a_violation_while_another_is_pending(
    ) {
        let tracker = RequestTracker::new();
        // A: registered, enqueue failed, cancelled, never counted.
        let (_sa, hash_a, rx_a) = tracker
            .prepare_request(Topics::from_vec(vec![Topic::new("q", b"a".to_vec())]))
            .await;
        tracker.cancel_request(hash_a).await;
        assert!(
            rx_a.await.is_err(),
            "the cancelled request's receiver is closed"
        );
        assert_eq!(tracker.outstanding_topic_requests(), 0);

        // B: a real, counted request is pending.
        let (_sb, hash_b, rx_b) = tracker
            .prepare_request(Topics::from_vec(vec![Topic::new("q", b"b".to_vec())]))
            .await;
        tracker.mark_request_sent();

        assert_eq!(tracker.outstanding_topic_requests(), 1, "only B counted");

        // A reply carrying A's (cancelled) hash: stale, but B is pending, so
        // the decrement (1 -> 0) is no violation and the stray is discarded.
        tracker
            .handle_response(&make_response(hash_a, "r", b"stray"))
            .await
            .expect("a pending request makes a stray reply no violation");
        assert_eq!(tracker.outstanding_topic_requests(), 0);
        assert_eq!(tracker.pending_count().await, 1, "B is still pending");

        // B's own reply arrives with the counter at zero: it goes negative
        // (0 -> -1), which is still no violation because B is pending, and
        // B receives its answer.
        tracker
            .handle_response(&make_response(hash_b, "r", b"for-b"))
            .await
            .expect("B's reply");
        assert_eq!(tracker.outstanding_topic_requests(), -1);
        assert_eq!(
            rx_b.await.unwrap().get_value("r"),
            Some(b"for-b".as_slice())
        );

        // Nothing pending and the counter negative (-1 -> -2): the violation.
        assert!(matches!(
            tracker
                .handle_response(&make_response(hash_a, "r", b"x"))
                .await,
            Err(RequestResponseError::UnrequestedResponse)
        ));
        assert_eq!(tracker.outstanding_topic_requests(), -2);
    }

    /// Issue #2251 review: the `pending` lock must NOT be held while the
    /// peer-supplied payload is parsed. The parse hook parks `handle_response`
    /// at the parse point (deterministically, no sleeps); `prepare_request`,
    /// `cancel_request` and `pending_count` must still complete meanwhile.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_parsing_response_does_not_block_the_pending_map() {
        use std::sync::mpsc;
        use std::sync::Arc;
        use std::time::Duration;

        let tracker = Arc::new(RequestTracker::new());
        let (_s, hash, _rx) = tracker
            .prepare_request(Topics::from_vec(vec![Topic::new("q", b"a".to_vec())]))
            .await;
        tracker.mark_request_sent();

        let (in_parse_tx, in_parse_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = std::sync::Mutex::new(release_rx);
        *tracker.parse_hook.lock().unwrap() = Some(Arc::new(move || {
            in_parse_tx.send(()).unwrap();
            // Parked "mid-parse" until the test releases it.
            release_rx.lock().unwrap().recv().unwrap();
        }));

        let handler = {
            let tracker = Arc::clone(&tracker);
            let reply = make_response(hash, "r", b"v");
            tokio::spawn(async move { tracker.handle_response(&reply).await })
        };
        tokio::task::spawn_blocking(move || in_parse_rx.recv().unwrap())
            .await
            .unwrap();

        // handle_response is now inside the parse. The map must be usable.
        let blocked = tokio::time::timeout(Duration::from_secs(10), async {
            let (_s2, hash2, _rx2) = tracker
                .prepare_request(Topics::from_vec(vec![Topic::new("q", b"b".to_vec())]))
                .await;
            assert_eq!(tracker.pending_count().await, 2);
            tracker.cancel_request(hash2).await;
        })
        .await
        .is_err();
        // Release before asserting so a failure does not leave the thread parked.
        release_tx.send(()).unwrap();
        assert!(!blocked, "the pending lock was held while parsing");
        handler.await.unwrap().expect("the reply is delivered");
    }

    /// The other half of go's rule: with NO request pending, a late reply to a
    /// request whose wait already timed out (counter still above zero) is
    /// discarded, and one beyond the requests ever sent is a violation.
    #[tokio::test]
    async fn without_a_pending_request_only_an_uncounted_response_is_a_violation() {
        let tracker = RequestTracker::new();
        let request_topics = Topics::from_vec(vec![Topic::new("key", b"value".to_vec())]);
        let (_serialized, hash, _rx) = tracker.prepare_request(request_topics).await;
        tracker.mark_request_sent();
        // The local wait timed out: the pending entry is gone, the count stays.
        tracker.cancel_request(hash).await;

        let late = make_response(hash, "result", b"late");
        tracker
            .handle_response(&late)
            .await
            .expect("late reply is discarded");
        assert_eq!(tracker.outstanding_topic_requests(), 0);

        // One more than ever requested, nothing pending: the violation.
        assert!(matches!(
            tracker.handle_response(&late).await,
            Err(RequestResponseError::UnrequestedResponse)
        ));
    }

    /// Ports go-algorand's `TestDiscardUnrequestedBlockResponse`
    /// (`network/wsNetwork_test.go:4182`): a peer sending a `TopicMsgResp`
    /// with no matching outstanding request at all (the outstanding-topic-
    /// request counter is already at zero — we never sent this peer any
    /// request) is a protocol violation the caller must disconnect for,
    /// mirroring go's `disconnectUnexpectedTopicResp`
    /// (`network/wsPeer.go:547-556`,
    /// `networkConnectionsDroppedTotal{reason="unrequestedTS"}`).
    #[tokio::test]
    async fn unrequested_response_is_detected() {
        let tracker = RequestTracker::new();

        // No request was ever prepared/sent — the counter starts at zero.
        assert_eq!(tracker.outstanding_topic_requests(), 0);

        let response_data = make_response(0xDEAD_BEEF, "data", b"unrequested");
        let result = tracker.handle_response(&response_data).await;

        assert!(matches!(
            result,
            Err(RequestResponseError::UnrequestedResponse)
        ));
        assert_eq!(tracker.outstanding_topic_requests(), -1);
    }

    /// A second unrequested response after the first drives the counter
    /// further negative and is detected the same way — mirroring the
    /// unconditional per-arrival decrement in go's readLoop.
    #[tokio::test]
    async fn repeated_unrequested_responses_keep_being_detected() {
        let tracker = RequestTracker::new();

        for _ in 0..3 {
            let response_data = make_response(0xDEAD_BEEF, "data", b"unrequested");
            let result = tracker.handle_response(&response_data).await;
            assert!(matches!(
                result,
                Err(RequestResponseError::UnrequestedResponse)
            ));
        }
        assert_eq!(tracker.outstanding_topic_requests(), -3);
    }

    /// Sending exactly N requests and receiving N+1 responses is detected on
    /// the (N+1)th response, even though the first N all matched fine.
    #[tokio::test]
    async fn excess_response_beyond_sent_count_is_detected() {
        let tracker = RequestTracker::new();

        let t1 = Topics::from_vec(vec![Topic::new("req", b"1".to_vec())]);
        let (_s1, h1, _rx1) = tracker.prepare_request(t1).await;
        tracker.mark_request_sent();

        // First response: matches the one request we sent. Not unrequested.
        let resp1 = make_response(h1, "ans", b"one");
        assert!(tracker.handle_response(&resp1).await.is_ok());

        // Second response: no more outstanding requests at all now.
        let resp2 = make_response(0xBEEF, "ans", b"two");
        let result = tracker.handle_response(&resp2).await;
        assert!(matches!(
            result,
            Err(RequestResponseError::UnrequestedResponse)
        ));
    }

    #[tokio::test]
    async fn missing_hash_field_returns_error() {
        let tracker = RequestTracker::new();
        // A request is pending (as go's read loop requires before it looks
        // at a response's payload), so the payload validation being
        // exercised here is reached.
        let _pending = tracker
            .prepare_request(Topics::from_vec(vec![Topic::new("q", b"x".to_vec())]))
            .await;
        tracker.mark_request_sent();

        // Build a response without the RESPONSE_HASH_FIELD
        let topics = Topics::from_vec(vec![Topic::new("other", b"data".to_vec())]);
        let data = topics.marshal();

        let result = tracker.handle_response(&data).await;
        assert!(matches!(
            result,
            Err(RequestResponseError::MissingHashField)
        ));
    }

    #[tokio::test]
    async fn cancel_request_drops_sender() {
        let tracker = RequestTracker::new();

        let request_topics = Topics::from_vec(vec![Topic::new("q", b"data".to_vec())]);
        let (_serialized, hash, rx) = tracker.prepare_request(request_topics).await;

        assert_eq!(tracker.pending_count().await, 1);

        // Cancel the request
        tracker.cancel_request(hash).await;

        assert_eq!(tracker.pending_count().await, 0);

        // Receiver should get an error because the sender was dropped
        assert!(rx.await.is_err());
    }

    #[tokio::test]
    async fn multiple_concurrent_requests_out_of_order() {
        let tracker = RequestTracker::new();

        // Prepare three requests
        let t1 = Topics::from_vec(vec![Topic::new("req", b"1".to_vec())]);
        let t2 = Topics::from_vec(vec![Topic::new("req", b"2".to_vec())]);
        let t3 = Topics::from_vec(vec![Topic::new("req", b"3".to_vec())]);

        let (_s1, h1, rx1) = tracker.prepare_request(t1).await;
        let (_s2, h2, rx2) = tracker.prepare_request(t2).await;
        let (_s3, h3, rx3) = tracker.prepare_request(t3).await;
        tracker.mark_request_sent();
        tracker.mark_request_sent();
        tracker.mark_request_sent();

        assert_eq!(tracker.pending_count().await, 3);

        // Respond out of order: 3, 1, 2
        let resp3 = make_response(h3, "ans", b"three");
        tracker.handle_response(&resp3).await.unwrap();

        let resp1 = make_response(h1, "ans", b"one");
        tracker.handle_response(&resp1).await.unwrap();

        let resp2 = make_response(h2, "ans", b"two");
        tracker.handle_response(&resp2).await.unwrap();

        // Each receiver should get its correct response
        let r1 = rx1.await.unwrap();
        assert_eq!(r1.get_value("ans"), Some(b"one".as_slice()));

        let r2 = rx2.await.unwrap();
        assert_eq!(r2.get_value("ans"), Some(b"two".as_slice()));

        let r3 = rx3.await.unwrap();
        assert_eq!(r3.get_value("ans"), Some(b"three".as_slice()));

        assert_eq!(tracker.pending_count().await, 0);
    }

    #[tokio::test]
    async fn nonce_uniqueness() {
        let tracker = RequestTracker::new();

        let mut hashes = Vec::new();
        for i in 0..10 {
            let t = Topics::from_vec(vec![Topic::new("x", vec![i])]);
            let (_serialized, hash, _rx) = tracker.prepare_request(t).await;
            hashes.push(hash);
        }

        // All hashes must be unique (different nonces produce different serializations)
        let mut unique = hashes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            hashes.len(),
            "all request hashes should be unique"
        );
    }

    #[tokio::test]
    async fn nonce_values_are_sequential_uvarint() {
        let tracker = RequestTracker::new();

        // After two prepare_requests, the nonces should be 1 and 2
        let t1 = Topics::from_vec(vec![Topic::new("a", b"1".to_vec())]);
        let t2 = Topics::from_vec(vec![Topic::new("a", b"2".to_vec())]);

        let (s1, _, _rx1) = tracker.prepare_request(t1).await;
        let (s2, _, _rx2) = tracker.prepare_request(t2).await;

        // Deserialize and check nonce values (uvarint encoded)
        let decoded1 = Topics::unmarshal(&s1).unwrap();
        let nonce1_data = decoded1.get_value(REQUEST_NONCE_FIELD).unwrap();
        let (nonce1, _) = decode_uvarint(nonce1_data).unwrap();
        assert_eq!(nonce1, 1);

        let decoded2 = Topics::unmarshal(&s2).unwrap();
        let nonce2_data = decoded2.get_value(REQUEST_NONCE_FIELD).unwrap();
        let (nonce2, _) = decode_uvarint(nonce2_data).unwrap();
        assert_eq!(nonce2, 2);
    }

    #[tokio::test]
    async fn deserialization_failure_returns_error() {
        let tracker = RequestTracker::new();
        // A pending request, so the payload is looked at (see above).
        let _pending = tracker
            .prepare_request(Topics::from_vec(vec![Topic::new("q", b"x".to_vec())]))
            .await;
        tracker.mark_request_sent();

        // Pass garbage data that can't be deserialized as Topics
        let result = tracker.handle_response(&[]).await;
        assert!(matches!(
            result,
            Err(RequestResponseError::DeserializationFailed(_))
        ));
    }

    #[tokio::test]
    async fn prepare_request_includes_nonce_topic() {
        let tracker = RequestTracker::new();

        let original = Topics::from_vec(vec![Topic::new("foo", b"bar".to_vec())]);
        let (serialized, _hash, _rx) = tracker.prepare_request(original).await;

        // Deserialize and verify the nonce topic was added
        let decoded = Topics::unmarshal(&serialized).unwrap();
        assert_eq!(decoded.0.len(), 2); // original + nonce
        assert_eq!(decoded.0[0].key, "foo");
        assert_eq!(decoded.0[1].key, REQUEST_NONCE_FIELD);
    }

    #[tokio::test]
    async fn hash_is_sha512_256_trimmed_u64() {
        let tracker = RequestTracker::new();

        let topics = Topics::from_vec(vec![Topic::new("test", b"data".to_vec())]);
        let (serialized, hash, _rx) = tracker.prepare_request(topics).await;

        // Independently compute SHA-512/256 and TrimUint64
        let expected = hash_topics(&serialized);

        assert_eq!(hash, expected);
    }

    #[tokio::test]
    async fn default_timeout_is_60_seconds() {
        assert_eq!(DEFAULT_REQUEST_TIMEOUT, Duration::from_secs(60));
    }

    #[test]
    fn uvarint_round_trip() {
        for &val in &[0u64, 1, 127, 128, 255, 300, 65535, u64::MAX] {
            let encoded = encode_uvarint(val);
            let (decoded, len) = decode_uvarint(&encoded).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(len, encoded.len());
        }
    }

    #[test]
    fn hash_topics_produces_u64() {
        let topics = Topics::from_vec(vec![Topic::new("a", b"b".to_vec())]);
        let serialized = topics.marshal();
        let h = hash_topics(&serialized);
        // Just verify it's non-zero and deterministic
        assert_ne!(h, 0);
        assert_eq!(h, hash_topics(&serialized));
    }

    #[test]
    fn nonce_field_key_is_correct() {
        assert_eq!(REQUEST_NONCE_FIELD, "nonce");
    }

    #[test]
    fn response_hash_field_key_is_correct() {
        assert_eq!(RESPONSE_HASH_FIELD, "RequestHash");
    }
}
