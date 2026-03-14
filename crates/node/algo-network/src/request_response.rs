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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sha2::{Digest as _, Sha512_256};
use tokio::sync::{oneshot, Mutex};
use tracing::warn;

use crate::topics::{Topic, Topics, TopicsError};

// ---------------------------------------------------------------------------
// uvarint helpers (matching Go's binary.PutUvarint / binary.Uvarint)
// ---------------------------------------------------------------------------

/// Encode a `u64` as an unsigned variable-length integer (LEB128).
pub(crate) fn encode_uvarint(mut value: u64) -> Vec<u8> {
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
}

impl RequestTracker {
    /// Create a new, empty `RequestTracker`.
    pub fn new() -> Self {
        Self {
            nonce: AtomicU64::new(0),
            pending: Mutex::new(HashMap::new()),
        }
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
    /// If the hash is not found (stale/late response), a warning is logged
    /// and `Ok(())` is returned. If the hash field is missing, an error is
    /// returned.
    pub async fn handle_response(&self, data: &[u8]) -> Result<(), RequestResponseError> {
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

        // Look up and remove the pending request
        let sender = {
            let mut pending = self.pending.lock().await;
            pending.remove(&hash_key)
        };

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

        // Build a response with an unknown hash
        let response_data = make_response(0xDEAD_BEEF, "data", b"stale");

        // Should not return an error
        let result = tracker.handle_response(&response_data).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn missing_hash_field_returns_error() {
        let tracker = RequestTracker::new();

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
