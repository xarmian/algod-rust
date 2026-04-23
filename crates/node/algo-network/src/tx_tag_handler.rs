//! TX-tag message handler — inbound transaction ingestion.
//!
//! Registers on the gossip node's [`Multiplexer`] for [`Tag::Transaction`]
//! (tag `TX`) and routes decoded signed transactions into the
//! [`TransactionPool`]. This closes the inbound half of gap **G1** in
//! [`DOC-23`]; the outbound (local-broadcast) half lands in TASK-70.
//!
//! ## Wire format
//!
//! A single TX message payload is a **streaming msgpack concatenation**
//! of up to `MaxTxGroupSize` (= 16, per consensus v18+) `SignedTransaction`
//! values. Mirrors `go-algorand/data/txHandler.go::decodeMsg` at
//! v4.5.1-stable.
//!
//! ## Dedup
//!
//! Incoming txids are tested against the [`SeenTxCache`] shared with
//! [`TxSyncer`]. A cache hit means we've processed this txid recently
//! (either via another gossip message or via a sync response), so we
//! drop it without another round-trip to the pool. Cache misses are
//! inserted before the pool call.
//!
//! ## Pool call
//!
//! The whole decoded group is submitted as one unit via
//! [`TransactionPool::remember`]. Pool-side validation errors are
//! logged at `warn!` level and do **not** propagate up to the
//! dispatcher — matching Go's "drop-on-error" posture for unsolicited
//! inbound txns.
//!
//! ## Return value
//!
//! Always returns [`OutgoingMessage`] with [`ForwardingPolicy::Ignore`].
//! Relay-path rebroadcast (Go's `TxHandler.net.Relay`) is intentionally
//! out of scope for TASK-69 and tracked as a PLAN-33 follow-up. Local
//! (REST-origin) broadcast lives in TASK-70.
//!
//! [`Multiplexer`]: crate::handler::Multiplexer
//! [`TransactionPool`]: algo_pool::TransactionPool
//! [`DOC-23`]: #
//! [`TxSyncer`]: crate::tx_syncer::TxSyncer

use std::io::Cursor;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, warn};

use algo_codec::compute_txn_id;
use algo_pool::TransactionPool;
use algo_types::SignedTransaction;

use crate::forwarding_policy::ForwardingPolicy;
use crate::handler::MessageHandler;
use crate::message::{IncomingMessage, OutgoingMessage};
use crate::tag::Tag;
use crate::tx_syncer::SeenTxCache;

/// Maximum number of signed transactions in a single TX-tag message.
///
/// Matches `MaxTxGroupSize` in `config/consensus.go` for v18+ consensus
/// versions. Messages carrying more than this are truncated to this
/// many and the excess is reported as a decode error.
pub const MAX_TX_GROUP_SIZE: usize = 16;

/// Errors raised during TX-tag decoding or handling.
#[derive(Debug, thiserror::Error)]
pub enum TxTagError {
    /// Payload decoded to zero signed transactions.
    #[error("empty TX group (zero signed transactions)")]
    EmptyGroup,

    /// Payload contained more than [`MAX_TX_GROUP_SIZE`] signed
    /// transactions.
    #[error("TX group too large (> {MAX_TX_GROUP_SIZE})")]
    GroupTooLarge,

    /// Payload bytes remained after decoding the allowed maximum
    /// — the message is malformed.
    #[error("trailing bytes after TX group")]
    TrailingBytes,

    /// msgpack decode failed.
    #[error("msgpack decode failed at offset {offset}: {source}")]
    Decode {
        /// Byte offset within the payload where decoding failed.
        offset: u64,
        /// Underlying decoder error.
        #[source]
        source: rmp_serde::decode::Error,
    },
}

/// Decode a TX-tag payload as a streaming concatenation of
/// [`SignedTransaction`] values.
///
/// Mirrors `go-algorand/data/txHandler.go::decodeMsg` at v4.5.1-stable:
/// we read values back-to-back until either the buffer is exhausted
/// (Ok) or a decode error occurs. An empty group is rejected as Go
/// does.
pub fn decode_tx_message(data: &[u8]) -> Result<Vec<SignedTransaction>, TxTagError> {
    if data.is_empty() {
        return Err(TxTagError::EmptyGroup);
    }

    let mut cursor = Cursor::new(data);
    let mut group: Vec<SignedTransaction> = Vec::with_capacity(1);

    loop {
        // Cap the group at MAX_TX_GROUP_SIZE. If more values remain in
        // the buffer, that's an overflow — matches Go's `dec.Remaining()
        // > 0` check after MaxTxGroupSize.
        if group.len() == MAX_TX_GROUP_SIZE {
            if (cursor.position() as usize) < data.len() {
                return Err(TxTagError::TrailingBytes);
            }
            break;
        }

        let offset = cursor.position();
        match rmp_serde::from_read::<_, SignedTransaction>(&mut cursor) {
            Ok(tx) => group.push(tx),
            Err(e) => {
                // Clean end-of-stream means we *started* the read at
                // EOF — i.e. the previous decode exactly exhausted the
                // buffer. Checking where the cursor *landed* after an
                // `UnexpectedEof` is wrong: a truncated trailing
                // object (e.g. a valid txn followed by a partial
                // msgpack prefix that consumes the remaining bytes)
                // can also end with the cursor at `data.len()`, and
                // that case must be rejected as malformed — not
                // silently accepted with the partial tail dropped.
                if is_eof_like(&e) && (offset as usize) == data.len() {
                    break;
                }
                return Err(TxTagError::Decode { offset, source: e });
            }
        }
    }

    if group.is_empty() {
        return Err(TxTagError::EmptyGroup);
    }

    Ok(group)
}

fn is_eof_like(err: &rmp_serde::decode::Error) -> bool {
    use rmp_serde::decode::Error::*;
    matches!(err, InvalidMarkerRead(e) | InvalidDataRead(e) if e.kind() == std::io::ErrorKind::UnexpectedEof)
}

/// Multiplexer handler for the TX tag.
///
/// One instance per node. Cloneable via `Arc` — registration expects an
/// `Arc<dyn MessageHandler>`.
pub struct TxTagHandler {
    pool: Arc<TransactionPool>,
    seen: Arc<SeenTxCache>,
}

impl std::fmt::Debug for TxTagHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxTagHandler")
            .field("seen_cache", &*self.seen)
            .finish()
    }
}

impl TxTagHandler {
    /// Create a new handler.
    ///
    /// `seen` should be shared with the [`TxSyncer`] so outbound and
    /// inbound paths agree on "what we've already processed".
    ///
    /// [`TxSyncer`]: crate::tx_syncer::TxSyncer
    #[must_use]
    pub fn new(pool: Arc<TransactionPool>, seen: Arc<SeenTxCache>) -> Self {
        Self { pool, seen }
    }

    /// Returns a reference to the shared seen-tx cache.
    #[must_use]
    pub fn seen_cache(&self) -> Arc<SeenTxCache> {
        self.seen.clone()
    }
}

#[async_trait]
impl MessageHandler for TxTagHandler {
    async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
        // Decode the payload.
        let group = match decode_tx_message(&msg.data) {
            Ok(g) => g,
            Err(e) => {
                warn!(
                    sender = %msg.sender,
                    bytes = msg.data.len(),
                    error = %e,
                    "TxTagHandler: failed to decode TX message",
                );
                return OutgoingMessage {
                    action: ForwardingPolicy::Ignore,
                    tag: Tag::Transaction,
                    payload: Vec::new(),
                    topics: None,
                };
            }
        };

        // Compute txids once up front — `compute_txn_id` hashes the
        // Transaction body (not the signature), so we can dedup
        // consistently across different signed variants of the same
        // txn.
        let txids: Vec<algo_types::Digest> =
            group.iter().map(|tx| compute_txn_id(&tx.txn)).collect();

        // Dedup fast-path: if every txid in the group has already been
        // *successfully ingested* (see below — we only insert on
        // Ok(())), the pool would just return duplicates. Skip the
        // round-trip.
        let any_new = txids.iter().any(|id| !self.seen.contains(id));
        if !any_new {
            debug!(
                sender = %msg.sender,
                group_len = group.len(),
                "TxTagHandler: all txns in group already seen, dropping",
            );
            return OutgoingMessage {
                action: ForwardingPolicy::Ignore,
                tag: Tag::Transaction,
                payload: Vec::new(),
                topics: None,
            };
        }

        // Submit the whole group to the pool on the blocking executor.
        // `TransactionPool::remember` is a synchronous mutex/condvar
        // flow that can wait up to ~`timeout_on_new_block` (default
        // 1 s) when the evaluator lags, so running it inline on a
        // Tokio worker would stall peer dispatch under TX bursts. We
        // offload to `spawn_blocking` so the async receive task can
        // proceed to the next message immediately.
        //
        // On `Ok(())` we record the txids in the seen cache so
        // subsequent duplicates short-circuit. On failure, the txids
        // are NOT recorded — a bad-signed or otherwise rejected
        // variant must not suppress a valid retransmission of the
        // same Transaction body (txids are body-derived).
        //
        // Errors are logged and dropped; unsolicited inbound txns
        // must never panic or propagate back to the dispatcher.
        let pool = self.pool.clone();
        let result = tokio::task::spawn_blocking(move || pool.remember(group)).await;
        match result {
            Ok(Ok(())) => {
                for id in &txids {
                    self.seen.insert(*id);
                }
                debug!(
                    sender = %msg.sender,
                    ingested = txids.len(),
                    "TxTagHandler: group accepted",
                );
            }
            Ok(Err(e)) => {
                warn!(
                    sender = %msg.sender,
                    error = %e,
                    "TxTagHandler: pool rejected inbound TX group",
                );
            }
            Err(join_err) => {
                warn!(
                    sender = %msg.sender,
                    error = %join_err,
                    "TxTagHandler: pool ingest task join failed",
                );
            }
        }

        OutgoingMessage {
            action: ForwardingPolicy::Ignore,
            tag: Tag::Transaction,
            payload: Vec::new(),
            topics: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    /// Build a minimal valid-shape signed transaction for decode tests.
    ///
    /// These txns do not have real signatures or fees — they are used
    /// only to exercise the msgpack decoder path, not the pool. We
    /// start from [`Default`] and tweak just the `fee` field so the
    /// round-trip test can distinguish decoded txns.
    fn make_signed_txn(fee: u64) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.fee = fee;
        stx
    }

    fn encode_group(group: &[SignedTransaction]) -> Vec<u8> {
        let mut out = Vec::new();
        for tx in group {
            let bytes = rmp_serde::to_vec_named(tx).expect("encode stxn");
            out.extend_from_slice(&bytes);
        }
        out
    }

    #[test]
    fn decode_single_txn() {
        let tx = make_signed_txn(1000);
        let encoded = encode_group(std::slice::from_ref(&tx));
        let group = decode_tx_message(&encoded).expect("single-txn decode");
        assert_eq!(group.len(), 1);
        assert_eq!(group[0].txn.fee, 1000);
    }

    #[test]
    fn decode_group_of_three() {
        let group_in = vec![make_signed_txn(1), make_signed_txn(2), make_signed_txn(3)];
        let encoded = encode_group(&group_in);
        let group = decode_tx_message(&encoded).expect("group decode");
        assert_eq!(group.len(), 3);
        assert_eq!(group[0].txn.fee, 1);
        assert_eq!(group[1].txn.fee, 2);
        assert_eq!(group[2].txn.fee, 3);
    }

    #[test]
    fn decode_empty_payload_is_error() {
        let err = decode_tx_message(&[]).unwrap_err();
        assert!(matches!(err, TxTagError::EmptyGroup));
    }

    #[test]
    fn decode_oversized_group_is_error() {
        let big: Vec<SignedTransaction> = (0..MAX_TX_GROUP_SIZE + 2)
            .map(|i| make_signed_txn(i as u64 + 1))
            .collect();
        let encoded = encode_group(&big);
        let err = decode_tx_message(&encoded).unwrap_err();
        assert!(
            matches!(err, TxTagError::TrailingBytes),
            "expected TrailingBytes, got {err:?}",
        );
    }

    #[test]
    fn decode_malformed_msgpack_is_error() {
        // 0xC1 is "never used" in msgpack and decodes to an error.
        let err = decode_tx_message(&[0xC1, 0xC1, 0xC1]).unwrap_err();
        assert!(
            matches!(err, TxTagError::Decode { .. }),
            "expected Decode, got {err:?}",
        );
    }

    #[test]
    fn decode_truncated_tail_is_error() {
        // A valid txn followed by a truncated msgpack object must be
        // rejected, not silently accepted with the partial tail
        // dropped. Regression for a prior bug where the EOF-check
        // keyed off the cursor *after* an UnexpectedEof, which could
        // land at `data.len()` when the partial object consumed the
        // remaining bytes.
        let good = encode_group(&[make_signed_txn(42)]);
        let mut truncated = good.clone();
        // Append a msgpack "map of 3 entries" header (0x83) with no
        // entries — an unexpected-EOF candidate.
        truncated.push(0x83);

        let err = decode_tx_message(&truncated).unwrap_err();
        assert!(
            matches!(err, TxTagError::Decode { .. }),
            "expected Decode error for truncated tail, got {err:?}",
        );
    }

    #[test]
    fn decode_exactly_max_group_size() {
        let group_in: Vec<SignedTransaction> = (0..MAX_TX_GROUP_SIZE)
            .map(|i| make_signed_txn(i as u64 + 1))
            .collect();
        let encoded = encode_group(&group_in);
        let group = decode_tx_message(&encoded).expect("max-size group decode");
        assert_eq!(group.len(), MAX_TX_GROUP_SIZE);
    }
}
