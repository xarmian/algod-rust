//! Local transaction submission + broadcast — outbound half of gap G1.
//!
//! Mirrors `go-algorand/data/txHandler.go::TxHandler.LocalTransaction` at
//! v4.5.1-stable. The REST layer calls [`LocalTxBroadcaster::submit_group`]
//! to ingest a locally-originated transaction group into the pool and,
//! on success, broadcast it to peers via the gossip TX tag. Closes the
//! outbound half of gap **G1** in [`DOC-23`].
//!
//! ## Flow
//!
//! 1. Encode the group as a concatenated msgpack stream (matches the
//!    wire format parsed by [`decode_tx_message`]).
//! 2. Compute txids (body-derived via [`compute_txn_id`]).
//! 3. Submit the group to the pool via
//!    [`PoolIngest`]. On failure, return the error without broadcasting.
//! 4. Record each txid in the shared [`SeenTxCache`] **before**
//!    broadcasting — otherwise a peer relaying the message back to us
//!    could hit [`TxTagHandler`] before the seen entry exists, causing
//!    the pool to see the echo as a genuine inbound and reject it as a
//!    duplicate. Populating the cache first means the echo short-
//!    circuits cleanly in the inbound handler.
//! 5. Broadcast via [`GossipNode::broadcast`] with `except = None` — we
//!    originated this group, there's no sender to exclude.
//!
//! ## Relay path
//!
//! Transactions received via the inbound [`TxTagHandler`] (TASK-69) do
//! NOT go through this path, so they are NOT re-broadcast here. Go's
//! `TxHandler.processIncomingTxn` performs relay-path rebroadcast via
//! `net.Relay(...)`; porting that is deliberately deferred out of
//! PLAN-33's scope. See the TASK-69 / TASK-70 follow-up notes.
//!
//! [`decode_tx_message`]: crate::tx_tag_handler::decode_tx_message
//! [`TxTagHandler`]: crate::tx_tag_handler::TxTagHandler
//! [`DOC-23`]: #

use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, warn};

use algo_codec::compute_txn_id;
use algo_pool::TransactionPool;
use algo_types::{Digest, SignedTransaction};

use crate::gossip_node::GossipNode;
use crate::tag::Tag;
use crate::tx_syncer::SeenTxCache;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised during local-txn submission.
#[derive(Debug, thiserror::Error)]
pub enum LocalTxError {
    /// Input group was empty.
    #[error("empty transaction group")]
    Empty,

    /// The pool rejected the group (bad fee, bad sig, duplicate, etc.).
    #[error("pool rejected group: {0}")]
    Pool(String),

    /// msgpack encode of a txn in the group failed.
    #[error("encode failed: {0}")]
    Encode(String),

    /// Gossip broadcast failed.
    #[error("broadcast failed: {0}")]
    Broadcast(String),
}

// ---------------------------------------------------------------------------
// PoolIngest trait
// ---------------------------------------------------------------------------

/// Async wrapper over the pool's `remember` call.
///
/// Abstracting the pool behind a trait lets this module be unit-tested
/// without constructing a full [`TransactionPool`] (which requires a
/// real [`algo_pool::traits::PoolLedger`]). The production impl is
/// [`PoolIngestAdapter`]; tests supply a trivial fake.
#[async_trait]
pub trait PoolIngest: Send + Sync + 'static {
    /// Submit `group` to the pool and wait for completion.
    async fn ingest(&self, group: Vec<SignedTransaction>) -> Result<(), String>;
}

/// Production [`PoolIngest`] adapter over [`TransactionPool`].
///
/// Runs `pool.remember` on Tokio's blocking threadpool so the async
/// caller doesn't stall on the synchronous mutex/condvar flow in
/// `TransactionPool` (see TASK-69's rationale).
pub struct PoolIngestAdapter {
    pool: Arc<TransactionPool>,
}

impl PoolIngestAdapter {
    /// Wrap `pool` as a [`PoolIngest`] implementation.
    #[must_use]
    pub fn new(pool: Arc<TransactionPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PoolIngest for PoolIngestAdapter {
    async fn ingest(&self, group: Vec<SignedTransaction>) -> Result<(), String> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || pool.remember(group))
            .await
            .map_err(|e| format!("pool ingest task join failed: {e}"))?
            .map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Encode a transaction group as the TX-tag wire payload.
///
/// The wire format is a concatenation of `rmp_serde::to_vec_named`
/// outputs — same shape `decode_tx_message` expects.
pub fn encode_tx_group(group: &[SignedTransaction]) -> Result<Vec<u8>, LocalTxError> {
    let mut out = Vec::with_capacity(group.len().saturating_mul(256));
    for tx in group {
        let bytes = rmp_serde::to_vec_named(tx).map_err(|e| LocalTxError::Encode(e.to_string()))?;
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// LocalTxBroadcaster
// ---------------------------------------------------------------------------

/// Ingest + broadcast a locally-originated transaction group.
pub struct LocalTxBroadcaster {
    ingest: Arc<dyn PoolIngest>,
    gossip: Arc<dyn GossipNode>,
    seen: Arc<SeenTxCache>,
}

impl std::fmt::Debug for LocalTxBroadcaster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalTxBroadcaster")
            .field("seen_cache", &*self.seen)
            .finish()
    }
}

impl LocalTxBroadcaster {
    /// Build a new broadcaster.
    ///
    /// `seen` should be the same cache shared with the inbound
    /// [`TxTagHandler`] so that echoes from peers (relaying our
    /// broadcast back) are dedupedcleanly.
    ///
    /// [`TxTagHandler`]: crate::tx_tag_handler::TxTagHandler
    #[must_use]
    pub fn new(
        ingest: Arc<dyn PoolIngest>,
        gossip: Arc<dyn GossipNode>,
        seen: Arc<SeenTxCache>,
    ) -> Self {
        Self {
            ingest,
            gossip,
            seen,
        }
    }

    /// Submit a local transaction group.
    ///
    /// Returns the txid of the first transaction in the group on
    /// success — matching Go's `Node.BroadcastSignedTxGroup` return
    /// value and the API contract exposed by
    /// `POST /v2/transactions`.
    pub async fn submit_group(
        &self,
        group: Vec<SignedTransaction>,
    ) -> Result<Digest, LocalTxError> {
        if group.is_empty() {
            return Err(LocalTxError::Empty);
        }

        // 1. Pre-compute txids (body-derived).
        let txids: Vec<Digest> = group.iter().map(|tx| compute_txn_id(&tx.txn)).collect();
        let first_txid = txids[0];

        // 2. Encode the wire payload up-front so we can submit the
        //    group by value to `ingest` without needing a clone.
        let payload = encode_tx_group(&group)?;

        // 3. Submit to pool. On failure, do not broadcast and do not
        //    touch the seen cache — a rejected local txn might be
        //    resubmitted after the user fixes the issue, and we don't
        //    want the cache to suppress the retry.
        //
        // NOTE: `self.ingest` only rejects *pending*-pool duplicates (see
        // `algo_pool::Pool::check_duplicate`) -- it has no check against
        // already-*confirmed* transactions the way go's block evaluator
        // does (`ledgercore.TransactionInLedgerError`). `AlgodNodeInterface`'s
        // dev-mode broadcast path (`bin/algod-rust/src/node_interface_impl.rs`,
        // `txn_confirmed_in_ledger`) has this check because issue #449's live
        // harness exercises dev-mode specifically; this non-dev-mode path
        // (relay/participate) hasn't been live-verified and likely has the
        // same gap -- follow-up work, not fixed here.
        if let Err(e) = self.ingest.ingest(group).await {
            warn!(error = %e, "LocalTxBroadcaster: pool rejected local group");
            return Err(LocalTxError::Pool(e));
        }

        // 4. Record txids in the seen cache *before* broadcasting, so
        //    peer echoes are dropped by the inbound handler.
        for id in &txids {
            self.seen.insert(*id);
        }

        // 5. Broadcast to all peers. `except = None` — we're the origin,
        //    no sender to exclude. `wait = false` — matches Go's
        //    `LocalTransaction` which does not block on per-peer queues.
        if let Err(e) = self
            .gossip
            .broadcast(Tag::Transaction, payload, false, None)
            .await
        {
            warn!(error = %e, "LocalTxBroadcaster: gossip broadcast failed");
            return Err(LocalTxError::Broadcast(e.to_string()));
        }

        debug!(
            txid = %first_txid,
            group_len = txids.len(),
            "LocalTxBroadcaster: local group submitted and broadcast",
        );
        Ok(first_txid)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::gossip_node::{Peer, PeerOption, Router};
    use crate::handler::{TaggedMessageHandler, TaggedMessageValidatorHandler};

    // ── Mocks ───────────────────────────────────────────────────

    /// Records every `ingest` call for assertions.
    struct RecordingIngestor {
        calls: Mutex<Vec<Vec<SignedTransaction>>>,
        result: Result<(), String>,
    }

    impl RecordingIngestor {
        fn accepting() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                result: Ok(()),
            }
        }
        fn rejecting(err: &str) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                result: Err(err.to_string()),
            }
        }
        fn recorded(&self) -> Vec<Vec<SignedTransaction>> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl PoolIngest for RecordingIngestor {
        async fn ingest(&self, group: Vec<SignedTransaction>) -> Result<(), String> {
            self.calls.lock().unwrap().push(group);
            self.result.clone()
        }
    }

    struct RecordedBroadcast {
        tag: Tag,
        payload: Vec<u8>,
        wait: bool,
    }

    /// Captures every `broadcast` call. All other trait methods are
    /// stubbed as no-ops — the broadcaster under test only calls
    /// `broadcast`.
    struct MockGossipNode {
        broadcasts: Mutex<Vec<RecordedBroadcast>>,
    }

    impl MockGossipNode {
        fn new() -> Self {
            Self {
                broadcasts: Mutex::new(Vec::new()),
            }
        }
        fn recorded(&self) -> Vec<RecordedBroadcast> {
            self.broadcasts
                .lock()
                .unwrap()
                .iter()
                .map(|b| RecordedBroadcast {
                    tag: b.tag,
                    payload: b.payload.clone(),
                    wait: b.wait,
                })
                .collect()
        }
    }

    #[async_trait]
    impl GossipNode for MockGossipNode {
        fn address(&self) -> (String, bool) {
            (String::new(), false)
        }

        async fn broadcast(
            &self,
            tag: Tag,
            data: Vec<u8>,
            wait: bool,
            _except: Option<Arc<dyn Peer>>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.broadcasts.lock().unwrap().push(RecordedBroadcast {
                tag,
                payload: data,
                wait,
            });
            Ok(())
        }

        async fn relay(
            &self,
            _tag: Tag,
            _data: Vec<u8>,
            _wait: bool,
            _except: Option<Arc<dyn Peer>>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }

        fn disconnect(&self, _peer: Arc<dyn Peer>) {}
        fn disconnect_peers(&self) {}

        async fn request_connect_outgoing(&self, _replace: bool) {}

        fn get_peers(&self, _options: &[PeerOption]) -> Vec<Arc<dyn Peer>> {
            Vec::new()
        }

        async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn stop(&self) {}

        fn register_handlers(&self, _dispatch: Vec<TaggedMessageHandler>) {}
        fn clear_handlers(&self) {}
        fn register_validator_handlers(&self, _dispatch: Vec<TaggedMessageValidatorHandler>) {}
        fn clear_validator_handlers(&self) {}

        fn on_network_advance(&self) {}

        fn get_genesis_id(&self) -> &str {
            ""
        }

        fn register_http_handler(&self, _path: &str, _handler: Router) {}
    }

    /// Build a minimal-shape signed transaction with a distinct fee so
    /// we can eyeball round-trips in assertions.
    fn make_signed_txn(fee: u64) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.fee = fee;
        stx
    }

    // ── Tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn submit_group_ingests_then_broadcasts() {
        let ingestor = Arc::new(RecordingIngestor::accepting());
        let gossip = Arc::new(MockGossipNode::new());
        let seen = Arc::new(SeenTxCache::new(16));
        let bx = LocalTxBroadcaster::new(ingestor.clone(), gossip.clone(), seen.clone());

        let group = vec![make_signed_txn(11), make_signed_txn(22)];
        let expected_first_txid = compute_txn_id(&group[0].txn);

        let txid = bx
            .submit_group(group.clone())
            .await
            .expect("submit should succeed");
        assert_eq!(txid, expected_first_txid);

        // Ingest called exactly once with the whole group.
        let recorded = ingestor.recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].len(), 2);
        assert_eq!(recorded[0][0].txn.fee, 11);
        assert_eq!(recorded[0][1].txn.fee, 22);

        // Broadcast called exactly once with the TX tag.
        let bcasts = gossip.recorded();
        assert_eq!(bcasts.len(), 1);
        assert_eq!(bcasts[0].tag, Tag::Transaction);
        // Payload should round-trip via the same decoder TxTagHandler uses.
        let decoded = crate::tx_tag_handler::decode_tx_message(&bcasts[0].payload)
            .expect("payload must be decodable");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].txn.fee, 11);
        assert_eq!(decoded[1].txn.fee, 22);

        // Seen cache was populated — peer echoes will be dropped.
        for tx in &group {
            assert!(seen.contains(&compute_txn_id(&tx.txn)));
        }
    }

    #[tokio::test]
    async fn submit_group_skips_broadcast_when_pool_rejects() {
        let ingestor = Arc::new(RecordingIngestor::rejecting("bad fee"));
        let gossip = Arc::new(MockGossipNode::new());
        let seen = Arc::new(SeenTxCache::new(16));
        let bx = LocalTxBroadcaster::new(ingestor.clone(), gossip.clone(), seen.clone());

        let group = vec![make_signed_txn(7)];
        let err = bx.submit_group(group.clone()).await.unwrap_err();
        assert!(
            matches!(err, LocalTxError::Pool(_)),
            "expected Pool error, got {err:?}",
        );

        // Broadcast was NOT called.
        assert!(gossip.recorded().is_empty());
        // Seen cache was NOT updated — a retry after fix must not be
        // suppressed.
        assert!(!seen.contains(&compute_txn_id(&group[0].txn)));
        // Ingest was called exactly once.
        assert_eq!(ingestor.recorded().len(), 1);
    }

    #[tokio::test]
    async fn submit_empty_group_is_error() {
        let ingestor = Arc::new(RecordingIngestor::accepting());
        let gossip = Arc::new(MockGossipNode::new());
        let seen = Arc::new(SeenTxCache::new(16));
        let bx = LocalTxBroadcaster::new(ingestor.clone(), gossip.clone(), seen);

        let err = bx.submit_group(Vec::new()).await.unwrap_err();
        assert!(matches!(err, LocalTxError::Empty));
        assert!(ingestor.recorded().is_empty());
        assert!(gossip.recorded().is_empty());
    }

    #[tokio::test]
    async fn seen_cache_is_populated_before_broadcast() {
        // Regression guard: the order is (ingest → seen.insert →
        // broadcast). If seen.insert happened *after* broadcast, a
        // peer echo returning before the insert would hit the
        // TxTagHandler's seen check with a miss, potentially letting
        // the pool see a duplicate.
        //
        // We can't easily observe interleaving in a unit test, but we
        // CAN assert the post-submit state: at the moment broadcast
        // returns, the seen cache contains the txid.
        let ingestor = Arc::new(RecordingIngestor::accepting());
        let gossip = Arc::new(MockGossipNode::new());
        let seen = Arc::new(SeenTxCache::new(16));
        let bx = LocalTxBroadcaster::new(ingestor.clone(), gossip.clone(), seen.clone());

        let group = vec![make_signed_txn(42)];
        let txid = compute_txn_id(&group[0].txn);
        bx.submit_group(group).await.expect("submit");

        // Post-condition: seen is populated AND broadcast recorded —
        // both must be true at the caller's observation point.
        assert!(seen.contains(&txid));
        assert_eq!(gossip.recorded().len(), 1);
    }

    #[test]
    fn encode_roundtrips_through_decode() {
        let group = vec![make_signed_txn(1), make_signed_txn(2), make_signed_txn(3)];
        let payload = encode_tx_group(&group).expect("encode");
        let decoded = crate::tx_tag_handler::decode_tx_message(&payload).expect("decode");
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].txn.fee, 1);
        assert_eq!(decoded[1].txn.fee, 2);
        assert_eq!(decoded[2].txn.fee, 3);
    }

    #[test]
    fn encode_empty_produces_empty_payload() {
        let payload = encode_tx_group(&[]).expect("encode");
        assert!(payload.is_empty());
    }
}
