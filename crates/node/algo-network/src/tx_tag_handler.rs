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
//! v4.6.0-stable.
//!
//! ## Dedup
//!
//! Incoming txids are tested against the [`SeenTxCache`] shared with
//! [`TxSyncer`]. A cache hit means we've processed this txid recently
//! (either via another gossip message or via a sync response), so we
//! drop it without another round-trip to the pool. Cache misses are
//! inserted before the pool call.
//!
//! ## Signature verification (issue #1043)
//!
//! When [`TxTagHandler::with_batch_verifier`] has been used to attach a
//! shared [`BatchVerifier`], each decoded (and not-already-seen) group is
//! submitted to it *before* [`TransactionPool::remember`] is called,
//! mirroring go-algorand's `data/txHandler.go` routing every incoming
//! gossip group through its `StreamToBatch` async worker pool
//! (`data/transactions/verify/txnBatch.go`) rather than verifying
//! synchronously inline. A batch-verification failure is logged and the
//! group is dropped (`Ignore`) without ever reaching the pool — it is not
//! treated as a `remember`/eval-error for `appLimiter.penalizeEvalError`
//! purposes (see that section below), since a bad signature is a distinct
//! failure kind from a valid-signature group that the evaluator rejects.
//!
//! The `BatchVerifier` is constructed against the *same*
//! `algo_validate::VerifiedTransactionCache` instance the node's
//! `BlockEvaluator` consults (mirrors go's single node-wide
//! `VerifiedTransactionCache` shared between `node.go`'s tx handler and
//! block evaluator), so a group verified here is a cache hit — not
//! redundant work — when the pool's evaluator verifies it again inside
//! `remember()`.
//!
//! Without a verifier attached (the default from [`TxTagHandler::new`]),
//! behavior is unchanged from before issue #1043: no pre-admission
//! signature verification happens in this handler, and `remember()`'s own
//! (evaluator-internal) verification is the only gate, exactly as before.
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
//! ## Application-call excessive-rate-limiter (ARL) gate (issue #821)
//!
//! `TxTagHandler` is the correct, and — after re-tracing go-algorand's
//! actual pull-sync path — the *only* legitimate wiring point for
//! [`algo_pool::AppRateLimiter`] in algod-rust. This is a genuinely
//! unsolicited, peer-pushed transaction ingestion path (a peer relays a
//! `TX`-tagged gossip message without algod-rust having asked for it),
//! the exact architectural analogue of go-algorand's
//! `TxHandler.processIncomingTxn`/`validateIncomingTxMessage` — the only
//! two call sites in go-algorand @ v5.0.0-stable that invoke
//! `incomingTxGroupAppRateLimit`/`appLimiter.shouldDrop`. See
//! [`algo_pool::app_rate_limiter`]'s module doc for the full trace
//! establishing that go's own pull-sync mechanism
//! (`rpcs.TxSyncer`/`data.SolicitedTxHandler`, the analogue of
//! `crates/node/algo-network/src/tx_syncer.rs`) never applies this gate,
//! and why that rules out wiring it into `tx_syncer.rs` instead.
//!
//! When [`TxTagHandler::with_app_rate_limiter`] has been used to attach a
//! limiter:
//!
//! * **Admission gate**, mirroring `incomingTxGroupAppRateLimit`: once
//!   the pool's pending-transaction count exceeds
//!   `congestion_threshold` (the analogue of go's
//!   `len(handler.backlogQueue) > handler.appLimiterBacklogThreshold` —
//!   algod-rust has no separate backlog queue on this path, since a
//!   decoded group goes straight to `spawn_blocking(|| pool.remember(..))`,
//!   so *pool occupancy* is the natural congestion signal here instead of
//!   *unprocessed-message-queue depth*), a group containing an
//!   application call is checked against
//!   [`AppRateLimiter::should_drop`][algo_pool::AppRateLimiter::should_drop]
//!   keyed by the sending peer's address (IP only, port stripped — the
//!   `origin` analogue of go's `wsPeer.RoutingAddr()`) and dropped
//!   (`Ignore`, never reaching the pool) if the app is over its rate.
//! * **Eval-error penalty**, mirroring `postProcessCheckedTxn`'s
//!   `appLimiter.penalizeEvalError` call: when `pool.remember(group)`
//!   returns an error,
//!   [`AppRateLimiter::penalize_eval_error`][algo_pool::AppRateLimiter::penalize_eval_error]
//!   is called with the same group/origin so a misbehaving app is rate
//!   limited faster than its raw request volume alone would trigger. Go
//!   excludes two specific error kinds from this call
//!   (`bookkeeping.TxnDeadError` — the txn's `LastValid` has already
//!   passed, which can just mean this node fell behind, not the app's
//!   fault — and `ledgercore.ErrEvaluatorCorruptedState`, an internal
//!   fault); algod-rust's [`algo_pool::PoolError`] has no variants
//!   corresponding to either today, so this port penalizes on every
//!   `remember` failure. If/when those distinctions are added to
//!   `PoolError`, this call site should skip penalizing them too, to stay
//!   in parity.
//!
//! Without a limiter attached (the default from [`TxTagHandler::new`]),
//! behavior is unchanged from before issue #821: no per-app rate limiting
//! is applied.
//!
//! ## Canonical-form dedup / anti-censoring cache and cache rotation (issue #1084)
//!
//! go-algorand's `TxHandler.processIncomingTxn` runs every decoded group
//! through `incomingTxGroupCanonicalDedup` (`data/txHandler.go`), which
//! re-encodes the group deterministically (`SignedTxn.MarshalMsg`,
//! concatenated for a multi-txn group) and drops the message if that
//! canonical digest has already been seen — *before* the group ever
//! reaches rate limiting or verification. The function's own comment
//! (`dedupCanonical`) explains why: without this, an adversary could
//! resubmit a semantically-identical group under a different *raw* byte
//! encoding (non-canonical field ordering, or simply a different wire
//! framing) and force the node to redundantly re-verify/re-relay it —
//! `TestTxHandlerProcessIncomingCensoring` pins that a re-signed variant
//! (a genuinely different signed group) is admitted, while a
//! non-canonically-*re-encoded* copy of the exact same signed group is
//! not.
//!
//! [`TxTagHandler::with_canonical_cache`] attaches this behavior, keyed
//! on `SHA512/256` over the concatenated
//! [`canonical_encode_signed_transaction`] bytes of every txn in the
//! group (mirrors `MarshalMsg`'s deterministic struct-field encoding —
//! re-derived from the *decoded* values, so it is insensitive to
//! whatever raw wire encoding the sender actually used). This check runs
//! immediately after decoding, before the existing txid-based
//! [`SeenTxCache`] fast path, mirroring go's ordering
//! (`incomingTxGroupCanonicalDedup` before `incomingTxGroupAppRateLimit`).
//! Unlike the txid-based `SeenTxCache` (which only records a group once
//! [`TransactionPool::remember`] *succeeds*), the canonical cache records
//! eagerly at decode time — so it catches a second copy of the exact
//! same signed bytes arriving while the first copy's `remember` call is
//! still in flight (or has failed), which the existing seen-cache cannot.
//! A different signature over the same txn body — go's "forged
//! signature, ensure accepted" case — hashes to a different canonical
//! digest and is therefore never suppressed by this cache; it is still
//! free to be rejected later by signature verification, exactly as go's
//! test expects.
//!
//! The canonical cache reuses [`SeenTxCache`] itself (issue #1083's
//! `cur`/`prev` two-generation rotation with a `capacity`-triggered
//! rotate and an explicit manual [`SeenTxCache::rotate`]) rather than
//! introducing a second cache type — the eviction/rotation semantics
//! [`TestTxHandlerProcessIncomingCacheRotation`] pins (drop survives one
//! rotation via `prev`, is gone after two) are identical to what
//! `SeenTxCache` already implements and has dedicated tests for in
//! `tx_syncer.rs`. When a canonical cache is attached with the *same*
//! `Arc` a [`TxSyncer`] is also periodically rotating (via
//! `TxSyncerConfig::seen_cache_rotate_interval`), the canonical cache
//! gets the same scheduled-rotation behavior
//! (`TestTxHandlerProcessIncomingCacheRotation`'s "scheduled" case) for
//! free; [`SeenTxCache::rotate`] remains available for a manual/ad-hoc
//! rotation policy instead.
//!
//! Without a canonical cache attached (the default from
//! [`TxTagHandler::new`]), behavior is unchanged: no canonical-form dedup
//! runs, exactly as before issue #1084.
//!
//! ## Backlog admission queue and drop-on-full (issue #1096)
//!
//! go-algorand's `TxHandler.processIncomingTxn`/`validateIncomingTxMessage`
//! enqueue each decoded, cache-admitted group onto a bounded
//! `backlogQueue` channel via a non-blocking `select`/`default`. On a
//! full queue the message is dropped and
//! `transactionMessagesDroppedFromBacklog` is incremented, but critically
//! `deleteFromCaches` also rolls back the cache entries that group had
//! just been inserted under, so a legitimately-dropped message isn't
//! permanently poisoned as "seen" and can be resubmitted once there's
//! room. `TestTxHandlerProcessIncomingCacheBacklogDrop`
//! (`data/txHandler_test.go`) pins this.
//!
//! [`TxTagHandler::with_backlog_queue`] attaches this behavior: a bounded
//! `tokio::sync::mpsc` channel sits between "decoded, cache-admitted,
//! rate-limit/verification-gated" and "submitted to the pool", with a
//! background consumer task pulling from it and running the same
//! `pool.remember`/seen-cache-insert/`penalize_eval_error` sequence the
//! inline path below already runs when no queue is attached. A
//! non-blocking `try_send` mirrors go's `select`/`default`: on success
//! the group is now the consumer task's responsibility; on failure (the
//! queue is full) the group is dropped, [`Self::backlog_dropped_count`]
//! is incremented, and the canonical-cache entry this group was just
//! admitted under (if a [`Self::with_canonical_cache`] cache is attached)
//! is rolled back via [`SeenTxCache::remove`].
//!
//! Unlike go's `msgCache` (populated eagerly at raw-message-dedup time,
//! before the canonical check even runs), algod-rust's txid-based `seen`
//! cache (passed to [`Self::new`]) only records a group once
//! `pool.remember` actually *succeeds* — see the "Pool call" section
//! below — so it never holds an entry for a group that was dropped here
//! and has nothing to roll back at this point in the pipeline. Only the
//! canonical cache needs the rollback.
//!
//! Without a backlog queue attached (the default from [`TxTagHandler::new`]),
//! behavior is unchanged from before issue #1096: every admitted group is
//! submitted to the pool inline (via `spawn_blocking`, awaited) exactly
//! as before, with no bounded queue to overflow.
//!
//! [`Multiplexer`]: crate::handler::Multiplexer
//! [`TransactionPool`]: algo_pool::TransactionPool
//! [`DOC-23`]: #
//! [`TxSyncer`]: crate::tx_syncer::TxSyncer
//! [`canonical_encode_signed_transaction`]: algo_codec::canonical_encode_signed_transaction

use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest as Sha2DigestTrait, Sha512_256};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use algo_codec::{canonical_encode_signed_transaction, compute_txn_id};
use algo_pool::{AppRateLimiter, TransactionPool};
use algo_types::{Digest, SignedTransaction};
use algo_validate::{BatchVerifier, BatchVerifyRequest, SpecialAddresses, VerificationContext};

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
/// Mirrors `go-algorand/data/txHandler.go::decodeMsg` at v4.6.0-stable:
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
    app_limiter: Option<Arc<AppRateLimiter>>,
    app_limiter_congestion_threshold: usize,
    batch_verifier: Option<Arc<BatchVerifier>>,
    canonical_cache: Option<Arc<SeenTxCache>>,
    backlog_tx: Option<mpsc::Sender<BacklogItem>>,
    backlog_dropped: Arc<AtomicU64>,
}

impl std::fmt::Debug for TxTagHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxTagHandler")
            .field("seen_cache", &*self.seen)
            .field("app_limiter_enabled", &self.app_limiter.is_some())
            .field(
                "app_limiter_congestion_threshold",
                &self.app_limiter_congestion_threshold,
            )
            .field("batch_verifier_enabled", &self.batch_verifier.is_some())
            .field("canonical_cache_enabled", &self.canonical_cache.is_some())
            .field("backlog_queue_enabled", &self.backlog_tx.is_some())
            .field(
                "backlog_dropped",
                &self.backlog_dropped.load(Ordering::Relaxed),
            )
            .finish()
    }
}

/// A decoded, admission-gated group queued for pool submission by
/// [`TxTagHandler::with_backlog_queue`] (issue #1096).
struct BacklogItem {
    group: Vec<SignedTransaction>,
    txids: Vec<Digest>,
    sender: String,
}

impl TxTagHandler {
    /// Create a new handler.
    ///
    /// `seen` should be shared with the [`TxSyncer`] so outbound and
    /// inbound paths agree on "what we've already processed".
    ///
    /// No [`AppRateLimiter`] is attached by default — see
    /// [`Self::with_app_rate_limiter`] to enable the per-app rate-limiting
    /// gate (issue #821).
    ///
    /// [`TxSyncer`]: crate::tx_syncer::TxSyncer
    #[must_use]
    pub fn new(pool: Arc<TransactionPool>, seen: Arc<SeenTxCache>) -> Self {
        Self {
            pool,
            seen,
            app_limiter: None,
            app_limiter_congestion_threshold: 0,
            batch_verifier: None,
            canonical_cache: None,
            backlog_tx: None,
            backlog_dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Attach an [`AppRateLimiter`] (issue #821), mirroring go-algorand's
    /// `TxHandler.appLimiter`/`appLimiterBacklogThreshold`. `limiter`
    /// should typically be shared (same `Arc`) across every `TxTagHandler`
    /// instance registered on this node (e.g. one per active transport —
    /// WS-gossip and libp2p both route inbound `TX`-tagged messages
    /// through their own `TxTagHandler`), since go-algorand's `appLimiter`
    /// is a single node-wide limiter regardless of which peer/transport a
    /// message arrived on.
    ///
    /// `congestion_threshold` is compared against
    /// `TransactionPool::pending_count()`: the rate-limit check only runs
    /// once the pool holds more than this many pending transactions,
    /// mirroring go's `appLimiterBacklogThreshold = TxBacklogSize *
    /// TxBacklogAppRateLimitingCongestionPct / 100` (default 10%) applied
    /// to its backlog-queue depth. See the module doc for why algod-rust
    /// uses pool occupancy rather than a message-backlog-queue depth as
    /// the congestion signal.
    #[must_use]
    pub fn with_app_rate_limiter(
        mut self,
        limiter: Arc<AppRateLimiter>,
        congestion_threshold: usize,
    ) -> Self {
        self.app_limiter = Some(limiter);
        self.app_limiter_congestion_threshold = congestion_threshold;
        self
    }

    /// Attach a shared [`BatchVerifier`] (issue #1043), mirroring
    /// go-algorand's `TxHandler` routing every incoming gossip transaction
    /// group through its `StreamToBatch` async worker pool before it ever
    /// reaches the transaction pool. See the module doc's "Signature
    /// verification" section for the full behavioral contract.
    ///
    /// `verifier` should typically be shared (same `Arc`) across every
    /// `TxTagHandler` instance registered on this node (one per active
    /// transport, same as [`Self::with_app_rate_limiter`]'s `limiter`), and
    /// should be constructed against the same
    /// `algo_validate::VerifiedTransactionCache` the node's `BlockEvaluator`
    /// uses, so verification here and inside `remember()` share one cache
    /// rather than each verifying independently.
    #[must_use]
    pub fn with_batch_verifier(mut self, verifier: Arc<BatchVerifier>) -> Self {
        self.batch_verifier = Some(verifier);
        self
    }

    /// Attach a canonical-form dedup cache (issue #1084), mirroring
    /// go-algorand's `TxHandler.txCanonicalCache`. See the module doc's
    /// "Canonical-form dedup / anti-censoring cache" section for the full
    /// behavioral contract.
    ///
    /// `cache` reuses [`SeenTxCache`] itself — it is a *separate* instance
    /// from the txid-keyed `seen` cache passed to [`Self::new`] (the two
    /// serve different purposes and are keyed differently), but nothing
    /// stops sharing the same `Arc` with a [`TxSyncer`]'s own periodic
    /// rotation if a caller wants scheduled rotation for free; see the
    /// module doc.
    ///
    /// [`TxSyncer`]: crate::tx_syncer::TxSyncer
    #[must_use]
    pub fn with_canonical_cache(mut self, cache: Arc<SeenTxCache>) -> Self {
        self.canonical_cache = Some(cache);
        self
    }

    /// Attach a bounded backlog admission queue (issue #1096), mirroring
    /// go-algorand's `TxHandler.backlogQueue`/`backlogWorker`. See the
    /// module doc's "Backlog admission queue and drop-on-full" section
    /// for the full behavioral contract.
    ///
    /// Spawns a background consumer task (via [`tokio::spawn`]) that owns
    /// the receiving half of the channel for the lifetime of the
    /// returned handler, so this must be called from within a Tokio
    /// runtime. `capacity` is clamped to at least 1.
    #[must_use]
    pub fn with_backlog_queue(mut self, capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        tokio::spawn(backlog_worker(
            rx,
            self.pool.clone(),
            self.seen.clone(),
            self.app_limiter.clone(),
        ));
        self.backlog_tx = Some(tx);
        self
    }

    /// Returns a reference to the shared seen-tx cache.
    #[must_use]
    pub fn seen_cache(&self) -> Arc<SeenTxCache> {
        self.seen.clone()
    }

    /// Number of groups dropped for arriving while the backlog queue
    /// (see [`Self::with_backlog_queue`]) was full — the analogue of
    /// go's `transactionMessagesDroppedFromBacklog` metric. Always `0`
    /// when no backlog queue is attached.
    #[must_use]
    pub fn backlog_dropped_count(&self) -> u64 {
        self.backlog_dropped.load(Ordering::Relaxed)
    }
}

/// Compute the canonical-form dedup digest for a decoded TX group (issue
/// #1084), mirroring go-algorand's `dedupCanonical`: `SHA512/256` over the
/// concatenation of each txn's canonical (`MarshalMsg`-equivalent)
/// encoding, re-derived from the *decoded* values rather than the
/// original wire bytes. Two groups with byte-identical decoded values
/// (including signatures) always hash to the same digest, regardless of
/// what raw encoding either sender used.
fn canonical_group_digest(group: &[SignedTransaction]) -> Digest {
    let mut hasher = Sha512_256::new();
    for tx in group {
        hasher.update(canonical_encode_signed_transaction(tx));
    }
    Digest(hasher.finalize().into())
}

/// Build a [`BatchVerifyRequest`] for pre-admission signature verification
/// of an inbound gossip group, from the pool's current ledger tip (issue
/// #1043).
///
/// Returns `None` when the ledger has no committed tip yet (e.g. during
/// node startup, before `pool.on_new_block` has bootstrapped an
/// evaluator) -- in that case pre-admission verification is skipped and
/// `pool.remember()` itself surfaces the appropriate
/// `NoPendingBlockEvaluator`-style error, exactly as it did before a
/// `BatchVerifier` was attached.
fn build_verify_request(
    pool: &TransactionPool,
    group: &[SignedTransaction],
) -> Option<BatchVerifyRequest> {
    let ledger = pool.ledger();
    let round = ledger.latest();
    let hdr = ledger.block_hdr(round).ok()?;
    let params = ledger.consensus_params(round).ok()?;
    Some(BatchVerifyRequest {
        group: group.to_vec(),
        context: VerificationContext {
            spec_addrs: SpecialAddresses {
                fee_sink: hdr.fee_sink,
                rewards_pool: hdr.rewards_pool,
            },
            consensus_version: hdr.current_protocol,
        },
        params,
    })
}

/// Extract the `origin` byte string used to key [`AppRateLimiter`]
/// entries from a gossip message's sender address string (e.g.
/// `"1.2.3.4:4160"`). Strips the port, mirroring go-algorand's
/// `wsPeer.RoutingAddr()`/`gsPeer.RoutingAddr()` (both return the peer's
/// IP only, deliberately excluding the ephemeral port so that repeated
/// connections from the same origin address bucket together). Falls back
/// to the raw sender string's bytes when it doesn't parse as a
/// `host:port` socket address (e.g. a synthetic/test sender, or a P2P
/// peer id string) — still deterministic per distinct sender, just not
/// byte-identical to go's IP-octet encoding, which is immaterial since
/// these bytes are only ever hashed locally within this process.
fn origin_bytes(sender: &str) -> Vec<u8> {
    match sender.parse::<std::net::SocketAddr>() {
        Ok(addr) => match addr.ip() {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        },
        Err(_) => sender.as_bytes().to_vec(),
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

        // Canonical-form dedup / anti-censoring gate (issue #1084),
        // mirroring go's `incomingTxGroupCanonicalDedup` — runs
        // immediately after decoding, before the txid-based fast path
        // below, and keys on the full signed encoding (signature
        // included) so a re-signed variant of the same txn body is never
        // suppressed here. See the module doc for the full contract.
        // Recorded (only when a canonical cache is attached and this
        // group was actually admitted by it, i.e. not an early-return
        // dup above) so a later full-backlog-queue drop can roll this
        // entry back — see the backlog-submission block below.
        let mut canonical_digest: Option<Digest> = None;
        if let Some(cache) = &self.canonical_cache {
            let digest = canonical_group_digest(&group);
            if !cache.insert(digest) {
                debug!(
                    sender = %msg.sender,
                    group_len = group.len(),
                    "TxTagHandler: dropped by canonical-form dedup cache",
                );
                return OutgoingMessage {
                    action: ForwardingPolicy::Ignore,
                    tag: Tag::Transaction,
                    payload: Vec::new(),
                    topics: None,
                };
            }
            canonical_digest = Some(digest);
        }

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

        // Application-call excessive-rate-limiter (ARL) admission gate
        // (issue #821), mirroring go's
        // `TxHandler.incomingTxGroupAppRateLimit`: only engages once the
        // pool is congested, and only ever drops the *entire* group (a
        // single over-rate app in a group is enough to drop it all,
        // matching go's `shouldDrop` semantics — see
        // `algo_pool::app_rate_limiter`'s doc comment).
        if let Some(limiter) = &self.app_limiter {
            let congested = self.pool.pending_count() > self.app_limiter_congestion_threshold;
            if congested {
                let origin = origin_bytes(&msg.sender);
                if limiter.should_drop(&group, &origin) {
                    debug!(
                        sender = %msg.sender,
                        group_len = group.len(),
                        "TxTagHandler: dropped by application rate limiter",
                    );
                    return OutgoingMessage {
                        action: ForwardingPolicy::Ignore,
                        tag: Tag::Transaction,
                        payload: Vec::new(),
                        topics: None,
                    };
                }
            }
        }

        // Batch signature verification (issue #1043), mirroring go's
        // `TxHandler` routing every incoming gossip group through
        // `StreamToBatch` before it reaches the pool. Only engages when a
        // verifier has been attached (see module doc); a rejection here
        // drops the group without ever calling `pool.remember()` and
        // without penalizing the app rate limiter -- a bad signature is a
        // distinct failure kind from a `remember`/eval-error.
        if let Some(verifier) = &self.batch_verifier {
            if let Some(request) = build_verify_request(&self.pool, &group) {
                if let Err(e) = verifier.verify(request).await {
                    warn!(
                        sender = %msg.sender,
                        error = %e,
                        "TxTagHandler: batch signature verification rejected inbound TX group",
                    );
                    return OutgoingMessage {
                        action: ForwardingPolicy::Ignore,
                        tag: Tag::Transaction,
                        payload: Vec::new(),
                        topics: None,
                    };
                }
            }
            // `None` means the ledger has no committed tip yet -- fall
            // through to `pool.remember()` below, which surfaces the
            // correct error for that case itself.
        }

        // Hand the group off for pool submission -- either onto the
        // bounded backlog queue (issue #1096, if attached) or, as
        // before #1096, straight to `pool.remember()` inline.
        if let Some(backlog_tx) = &self.backlog_tx {
            let item = BacklogItem {
                group,
                txids,
                sender: msg.sender.clone(),
            };
            // Non-blocking `try_send` mirrors go's `select { case
            // backlogQueue <- wi: ... default: ... }`: a full queue
            // drops the message rather than blocking this handler (and
            // therefore this peer's whole dispatch loop).
            if backlog_tx.try_send(item).is_err() {
                self.backlog_dropped.fetch_add(1, Ordering::Relaxed);
                // Roll back the canonical-cache entry this group was
                // just admitted under so it isn't permanently poisoned
                // as "seen" -- mirrors go's `deleteFromCaches`. The
                // txid-based `seen` cache needs no rollback here: it
                // only records on a successful `remember()`, which
                // never happened for a group dropped before reaching
                // the pool. See the module doc for the full rationale.
                if let (Some(digest), Some(cache)) = (canonical_digest, &self.canonical_cache) {
                    cache.remove(&digest);
                }
                debug!(
                    sender = %msg.sender,
                    "TxTagHandler: dropped, backlog queue full",
                );
            }
        } else {
            ingest_group(
                &self.pool,
                &self.seen,
                &self.app_limiter,
                group,
                txids,
                msg.sender.clone(),
            )
            .await;
        }

        OutgoingMessage {
            action: ForwardingPolicy::Ignore,
            tag: Tag::Transaction,
            payload: Vec::new(),
            topics: None,
        }
    }
}

/// Submit `group` to `pool` on the blocking executor and apply the
/// success/failure post-processing every ingestion path shares: record
/// `txids` in `seen` on success, or penalize `app_limiter` (if attached)
/// on failure. Shared by [`TxTagHandler::handle`]'s inline (no backlog
/// queue) path and [`backlog_worker`]'s consumer loop.
///
/// `TransactionPool::remember` is a synchronous mutex/condvar flow that
/// can wait up to ~`timeout_on_new_block` (default 1 s) when the
/// evaluator lags, so running it inline on a Tokio worker would stall
/// progress -- we offload to `spawn_blocking` so the caller's async task
/// can proceed immediately once this completes.
///
/// On `Ok(())` the txids are recorded in the seen cache so subsequent
/// duplicates short-circuit. On failure, the txids are NOT recorded — a
/// bad-signed or otherwise rejected variant must not suppress a valid
/// retransmission of the same Transaction body (txids are body-derived).
/// Errors are logged and dropped; unsolicited inbound txns must never
/// panic or propagate back to the dispatcher.
async fn ingest_group(
    pool: &Arc<TransactionPool>,
    seen: &Arc<SeenTxCache>,
    app_limiter: &Option<Arc<AppRateLimiter>>,
    group: Vec<SignedTransaction>,
    txids: Vec<Digest>,
    sender: String,
) {
    // Cloned only when a limiter is attached: `penalize_eval_error` needs
    // the group's app ids after `remember` has moved `group` into the
    // blocking task. Mirrors go's `postProcessCheckedTxn` calling
    // `appLimiter.penalizeEvalError(wi.unverifiedTxGroup, ...)` on a
    // `Remember` failure.
    let group_for_penalty = app_limiter.is_some().then(|| group.clone());
    let pool_for_task = pool.clone();
    let result = tokio::task::spawn_blocking(move || pool_for_task.remember(group)).await;
    match result {
        Ok(Ok(())) => {
            for id in &txids {
                seen.insert(*id);
            }
            debug!(
                sender = %sender,
                ingested = txids.len(),
                "TxTagHandler: group accepted",
            );
        }
        Ok(Err(e)) => {
            warn!(
                sender = %sender,
                error = %e,
                "TxTagHandler: pool rejected inbound TX group",
            );
            if let (Some(limiter), Some(group)) = (app_limiter, group_for_penalty) {
                let origin = origin_bytes(&sender);
                limiter.penalize_eval_error(&group, &origin);
            }
        }
        Err(join_err) => {
            warn!(
                sender = %sender,
                error = %join_err,
                "TxTagHandler: pool ingest task join failed",
            );
        }
    }
}

/// Background consumer for [`TxTagHandler::with_backlog_queue`] (issue
/// #1096): pulls admitted groups off the bounded channel one at a time
/// and runs them through [`ingest_group`], exactly mirroring go's
/// `TxHandler.backlogWorker` draining `backlogQueue`.
async fn backlog_worker(
    mut rx: mpsc::Receiver<BacklogItem>,
    pool: Arc<TransactionPool>,
    seen: Arc<SeenTxCache>,
    app_limiter: Option<Arc<AppRateLimiter>>,
) {
    while let Some(item) = rx.recv().await {
        ingest_group(
            &pool,
            &seen,
            &app_limiter,
            item.group,
            item.txids,
            item.sender,
        )
        .await;
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

    // -----------------------------------------------------------------
    // origin_bytes (issue #821)
    // -----------------------------------------------------------------

    #[test]
    fn origin_bytes_strips_port_from_ipv4_socket_addr() {
        assert_eq!(origin_bytes("1.2.3.4:4160"), vec![1u8, 2, 3, 4]);
        // Same IP, different port -> same origin bytes (go's RoutingAddr
        // deliberately ignores the ephemeral port so reconnects bucket
        // together).
        assert_eq!(origin_bytes("1.2.3.4:9999"), vec![1u8, 2, 3, 4]);
    }

    #[test]
    fn origin_bytes_falls_back_to_raw_string_for_unparseable_sender() {
        // A P2P peer-id-shaped sender (not a `host:port` socket address)
        // still yields a deterministic, non-empty byte string.
        let a = origin_bytes("12D3KooWAbCdEf");
        let b = origin_bytes("12D3KooWAbCdEf");
        let c = origin_bytes("12D3KooWDifferent");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(!a.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Tests: application rate limiter wiring (issue #821)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod app_rate_limiter_wiring_tests {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use algo_error::AlgoError;
    use algo_pool::traits::{BlockEvaluator, PoolLedger};
    use algo_pool::{AppRateLimiter, PoolConfig, TransactionPool};
    use algo_types::{Address, Block, BlockHeader, ConsensusParams, Round, TxnType};

    use super::*;
    use crate::tx_syncer::SeenTxCache;

    /// Minimal stub ledger, replicated from the pattern already used by
    /// `tests/tx_propagation_inproc.rs` — see that file's doc comment.
    /// `fail` lets a test force `remember` to fail so the eval-error
    /// penalty path can be exercised deterministically.
    struct StubLedger {
        round: Round,
        fail: std::sync::Arc<AtomicBool>,
    }

    impl PoolLedger for StubLedger {
        fn latest(&self) -> Round {
            self.round
        }
        fn block_hdr(&self, _round: Round) -> Result<BlockHeader, AlgoError> {
            Ok(BlockHeader::default())
        }
        fn consensus_params(&self, _round: Round) -> Result<ConsensusParams, AlgoError> {
            Ok(ConsensusParams::default())
        }
        fn start_evaluator(
            &self,
            _hdr: BlockHeader,
            _payset_hint: usize,
            _max_txn_bytes_per_block: usize,
        ) -> Result<Box<dyn BlockEvaluator>, AlgoError> {
            Ok(Box::new(StubEvaluator {
                round: self.round.next(),
                fail: self.fail.clone(),
            }))
        }
    }

    struct StubEvaluator {
        round: Round,
        fail: std::sync::Arc<AtomicBool>,
    }

    impl BlockEvaluator for StubEvaluator {
        fn round(&self) -> Round {
            self.round
        }
        fn pay_set_size(&self) -> usize {
            0
        }
        fn test_transaction_group(&self, _txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
            Ok(())
        }
        fn transaction_group(&mut self, _txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
            if self.fail.load(Ordering::SeqCst) {
                Err(AlgoError::Validation {
                    message: "stub eval failure".to_string(),
                })
            } else {
                Ok(())
            }
        }
        fn generate_block(&mut self, _voting_accounts: &[Address]) -> Result<Block, AlgoError> {
            Ok(Block::default())
        }
        fn reset_txn_bytes(&mut self) {}
    }

    /// Build a pool with a stub evaluator wired via `on_new_block`, plus
    /// the shared `fail` flag that controls whether `remember` succeeds.
    fn make_pool() -> (Arc<TransactionPool>, std::sync::Arc<AtomicBool>) {
        let fail = std::sync::Arc::new(AtomicBool::new(false));
        let ledger: Arc<dyn PoolLedger> = Arc::new(StubLedger {
            round: Round(1),
            fail: fail.clone(),
        });
        let pool = Arc::new(TransactionPool::new(PoolConfig::default(), ledger));
        pool.on_new_block(&Block::default(), &HashSet::new());
        (pool, fail)
    }

    /// An application-call transaction touching `app_id`, otherwise
    /// well-formed enough to pass the pool's admission checks.
    fn make_app_call_txn(app_id: u64, note: u8) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = TxnType::Appl;
        stx.txn.sender = Address([1u8; 32]);
        stx.txn.fee = 1_000_000;
        stx.txn.first_valid = Round(1);
        stx.txn.last_valid = Round(1_000);
        stx.txn.application_id = app_id;
        stx.txn.note = serde_bytes::ByteBuf::from(vec![note]);
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

    fn incoming(group: &[SignedTransaction], sender: &str) -> IncomingMessage {
        let data = encode_group(group);
        IncomingMessage::new(Tag::Transaction, data, sender.to_string(), 0)
    }

    /// Below the congestion threshold, the limiter must never engage —
    /// mirrors go's `congestedARL := len(handler.backlogQueue) >
    /// handler.appLimiterBacklogThreshold` guard on
    /// `incomingTxGroupAppRateLimit`.
    #[tokio::test]
    async fn admits_when_pool_is_not_congested_even_if_limiter_would_drop() {
        let (pool, _fail) = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        // A limiter with rate 0/window: the very first attempt would be
        // dropped once congested. Congestion threshold is high (100), so
        // with an empty pool this must NOT engage.
        let limiter = Arc::new(AppRateLimiter::new(1024, 0, Duration::from_secs(10)));
        let handler = TxTagHandler::new(pool.clone(), seen).with_app_rate_limiter(limiter, 100);

        let tx = make_app_call_txn(7, 1);
        let msg = incoming(std::slice::from_ref(&tx), "1.2.3.4:4160");
        let out = handler.handle(msg).await;
        assert_eq!(out.action, ForwardingPolicy::Ignore);

        let txid = compute_txn_id(&tx.txn);
        assert!(
            pool.pending_tx_ids().contains(&txid),
            "group should be admitted to the pool while uncongested"
        );
    }

    /// Once the pool is congested (pending count > threshold), a *second*
    /// attempt from the same app/origin pair, over the configured rate,
    /// must be dropped before it ever reaches the pool — mirrors go's
    /// `incomingTxGroupAppRateLimit`/`shouldDrop`. (A brand-new
    /// `(app, origin)` pair is always admitted unconditionally on its
    /// first sighting — see `AppRateLimiter::should_drop_keys` — so the
    /// rate check only bites from the second attempt onward.)
    #[tokio::test]
    async fn drops_over_rate_app_group_once_congested() {
        let (pool, _fail) = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        // Rate 0/window, congestion threshold 0: any pending txn counts
        // as "congested", and any repeat attempt is instantly over rate.
        let limiter = Arc::new(AppRateLimiter::new(1024, 0, Duration::from_secs(10)));
        let handler = TxTagHandler::new(pool.clone(), seen).with_app_rate_limiter(limiter, 0);

        // Prime the pool with an unrelated pending txn so pending_count()
        // > congestion_threshold (0) for every subsequent group.
        let filler = {
            let mut stx = SignedTransaction::default();
            stx.txn.txn_type = TxnType::Pay;
            stx.txn.sender = Address([2u8; 32]);
            stx.txn.fee = 1_000_000;
            stx.txn.first_valid = Round(1);
            stx.txn.last_valid = Round(1_000);
            stx.txn.note = serde_bytes::ByteBuf::from(vec![0xAA]);
            stx
        };
        pool.remember(vec![filler]).expect("filler txn admitted");
        assert!(pool.pending_count() > 0);

        // First attempt for app 7 from this origin: a brand-new
        // (app, origin) pair is always admitted.
        let tx1 = make_app_call_txn(7, 1);
        let txid1 = compute_txn_id(&tx1.txn);
        let msg1 = incoming(&[tx1], "1.2.3.4:4160");
        let out1 = handler.handle(msg1).await;
        assert_eq!(out1.action, ForwardingPolicy::Ignore);
        assert!(
            pool.pending_tx_ids().contains(&txid1),
            "first attempt for a fresh (app, origin) pair must be admitted"
        );

        // Second attempt, same app + same origin: now over rate.
        let tx2 = make_app_call_txn(7, 2);
        let txid2 = compute_txn_id(&tx2.txn);
        let msg2 = incoming(&[tx2], "1.2.3.4:4160");
        let out2 = handler.handle(msg2).await;
        assert_eq!(out2.action, ForwardingPolicy::Ignore);
        assert!(
            !pool.pending_tx_ids().contains(&txid2),
            "over-rate app group must be dropped before reaching the pool"
        );
    }

    /// A `remember` failure must penalize the app so a *subsequent*
    /// attempt from the same app/origin gets rate limited faster than
    /// raw volume alone would trigger — mirrors go's
    /// `postProcessCheckedTxn`'s `appLimiter.penalizeEvalError` call.
    #[tokio::test]
    async fn penalizes_app_on_remember_failure() {
        let (pool, fail) = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        // Rate 0/window: the penalty (`max(1, service_rate_per_window /
        // 4)` = `max(1, 0)` = 1) plus the next attempt's own `+1` already
        // exceeds the window's admitted rate of 0, so a *second* attempt
        // for the same (app, origin) pair — this time via the success
        // path — must be dropped. Congestion threshold 0 so the gate
        // always runs once anything is pending.
        let limiter = Arc::new(AppRateLimiter::new(1024, 0, Duration::from_secs(10)));
        let handler = TxTagHandler::new(pool.clone(), seen).with_app_rate_limiter(limiter, 0);

        // First: force `remember` to fail and penalize app 9.
        fail.store(true, Ordering::SeqCst);
        let failing_tx = make_app_call_txn(9, 1);
        let msg = incoming(&[failing_tx], "5.6.7.8:4160");
        let out = handler.handle(msg).await;
        assert_eq!(out.action, ForwardingPolicy::Ignore);
        assert_eq!(pool.pending_count(), 0, "failed remember admits nothing");

        // Now let remember succeed again, and prime congestion with an
        // unrelated txn.
        fail.store(false, Ordering::SeqCst);
        let filler = {
            let mut stx = SignedTransaction::default();
            stx.txn.txn_type = TxnType::Pay;
            stx.txn.sender = Address([3u8; 32]);
            stx.txn.fee = 1_000_000;
            stx.txn.first_valid = Round(1);
            stx.txn.last_valid = Round(1_000);
            stx.txn.note = serde_bytes::ByteBuf::from(vec![0xBB]);
            stx
        };
        pool.remember(vec![filler]).expect("filler txn admitted");

        // Same app id + same origin: the penalty already recorded should
        // now cause this admission attempt to be dropped even though it's
        // the "first" successful attempt from this origin.
        let tx = make_app_call_txn(9, 2);
        let txid = compute_txn_id(&tx.txn);
        let msg = incoming(&[tx], "5.6.7.8:4160");
        let out = handler.handle(msg).await;
        assert_eq!(out.action, ForwardingPolicy::Ignore);
        assert!(
            !pool.pending_tx_ids().contains(&txid),
            "app penalized for the earlier eval error should be rate limited on retry"
        );
    }

    /// A non-application-call group must never be gated by the app rate
    /// limiter, congested or not — mirrors `txgroupToKeys` returning
    /// `None`/empty for a group with no `ApplicationCallTx`.
    #[tokio::test]
    async fn non_app_call_group_is_never_gated() {
        let (pool, _fail) = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        let limiter = Arc::new(AppRateLimiter::new(1024, 0, Duration::from_secs(10)));
        let handler = TxTagHandler::new(pool.clone(), seen).with_app_rate_limiter(limiter, 0);

        // Prime congestion so the gate actually runs (congestion
        // threshold is 0, so any pending txn is enough) — this test
        // must prove the app rate limiter itself never engages for a
        // non-application-call group, not merely that the congestion
        // pre-check was skipped.
        let congestion_filler = {
            let mut stx = SignedTransaction::default();
            stx.txn.txn_type = TxnType::Pay;
            stx.txn.sender = Address([5u8; 32]);
            stx.txn.fee = 1_000_000;
            stx.txn.first_valid = Round(1);
            stx.txn.last_valid = Round(1_000);
            stx.txn.note = serde_bytes::ByteBuf::from(vec![0xDD]);
            stx
        };
        pool.remember(vec![congestion_filler])
            .expect("congestion filler admitted");
        assert!(pool.pending_count() > 0);

        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = TxnType::Pay;
        stx.txn.sender = Address([4u8; 32]);
        stx.txn.fee = 1_000_000;
        stx.txn.first_valid = Round(1);
        stx.txn.last_valid = Round(1_000);
        stx.txn.note = serde_bytes::ByteBuf::from(vec![0xCC]);
        let txid = compute_txn_id(&stx.txn);

        let msg = incoming(&[stx], "9.9.9.9:4160");
        let out = handler.handle(msg).await;
        assert_eq!(out.action, ForwardingPolicy::Ignore);
        assert!(
            pool.pending_tx_ids().contains(&txid),
            "a plain payment group must never be gated by the app rate limiter"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests: BatchVerifier wiring into the live gossip tx-admission path
// (issue #1043)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod batch_verifier_wiring_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use algo_error::AlgoError;
    use algo_pool::traits::{BlockEvaluator, PoolLedger};
    use algo_pool::{PoolConfig, TransactionPool};
    use algo_types::{Address, Block, BlockHeader, ConsensusParams, Round, TxnType};
    use algo_validate::{
        BatchVerifier, BatchVerifierConfig, BatchVerifyRequest, VerifiedTransactionCache,
    };

    use super::*;
    use crate::tx_syncer::SeenTxCache;

    /// Test-only alias for a `BatchVerifier::spawn_with_verifier` closure
    /// (the real crate uses an equivalent private alias internally).
    type TestVerifyFn = dyn Fn(&BatchVerifyRequest, &VerifiedTransactionCache) -> Result<(), AlgoError>
        + Send
        + Sync;

    /// Minimal stub ledger/evaluator, replicated from
    /// `app_rate_limiter_wiring_tests::StubLedger` above -- `remember`
    /// always succeeds so these tests isolate the *verification* gate.
    struct StubLedger {
        round: Round,
    }

    impl PoolLedger for StubLedger {
        fn latest(&self) -> Round {
            self.round
        }
        fn block_hdr(&self, _round: Round) -> Result<BlockHeader, AlgoError> {
            Ok(BlockHeader::default())
        }
        fn consensus_params(&self, _round: Round) -> Result<ConsensusParams, AlgoError> {
            Ok(ConsensusParams::default())
        }
        fn start_evaluator(
            &self,
            _hdr: BlockHeader,
            _payset_hint: usize,
            _max_txn_bytes_per_block: usize,
        ) -> Result<Box<dyn BlockEvaluator>, AlgoError> {
            Ok(Box::new(StubEvaluator {
                round: self.round.next(),
            }))
        }
    }

    struct StubEvaluator {
        round: Round,
    }

    impl BlockEvaluator for StubEvaluator {
        fn round(&self) -> Round {
            self.round
        }
        fn pay_set_size(&self) -> usize {
            0
        }
        fn test_transaction_group(&self, _txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
            Ok(())
        }
        fn transaction_group(&mut self, _txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
            Ok(())
        }
        fn generate_block(&mut self, _voting_accounts: &[Address]) -> Result<Block, AlgoError> {
            Ok(Block::default())
        }
        fn reset_txn_bytes(&mut self) {}
    }

    fn make_pool() -> Arc<TransactionPool> {
        let ledger: Arc<dyn PoolLedger> = Arc::new(StubLedger { round: Round(1) });
        let pool = Arc::new(TransactionPool::new(PoolConfig::default(), ledger));
        pool.on_new_block(&Block::default(), &std::collections::HashSet::new());
        pool
    }

    fn make_payment_txn(sender_byte: u8, note: u8) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = TxnType::Pay;
        stx.txn.sender = Address([sender_byte; 32]);
        stx.txn.fee = 1_000_000;
        stx.txn.first_valid = Round(1);
        stx.txn.last_valid = Round(1_000);
        stx.txn.note = serde_bytes::ByteBuf::from(vec![note]);
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

    fn incoming(group: &[SignedTransaction], sender: &str) -> IncomingMessage {
        let data = encode_group(group);
        IncomingMessage::new(Tag::Transaction, data, sender.to_string(), 0)
    }

    /// A group that verifies successfully must be routed through the
    /// attached `BatchVerifier` (proven by the injected verify function
    /// being invoked) and then still reach the pool exactly as before.
    #[tokio::test]
    async fn successful_verification_routes_through_batch_verifier_then_admits_to_pool() {
        let pool = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_closure = calls.clone();
        let cache = Arc::new(VerifiedTransactionCache::new(100));
        let verify_fn: Arc<TestVerifyFn> = Arc::new(move |_request, _cache| {
            calls_for_closure.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let verifier = Arc::new(BatchVerifier::spawn_with_verifier(
            BatchVerifierConfig::default(),
            cache,
            verify_fn,
        ));
        let handler = TxTagHandler::new(pool.clone(), seen).with_batch_verifier(verifier.clone());

        let tx = make_payment_txn(1, 1);
        let txid = compute_txn_id(&tx.txn);
        let msg = incoming(std::slice::from_ref(&tx), "1.2.3.4:4160");
        let out = handler.handle(msg).await;

        assert_eq!(out.action, ForwardingPolicy::Ignore);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the injected BatchVerifier verify function must be invoked exactly once"
        );
        assert!(
            pool.pending_tx_ids().contains(&txid),
            "a group that verifies successfully must still reach the pool"
        );

        drop(handler);
        Arc::try_unwrap(verifier)
            .unwrap_or_else(|_| panic!("verifier still shared"))
            .shutdown()
            .await;
    }

    /// A group that fails batch verification must never reach the pool at
    /// all -- proving the verifier actually *gates* admission rather than
    /// being called and ignored.
    #[tokio::test]
    async fn failed_verification_never_reaches_the_pool() {
        let pool = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        let cache = Arc::new(VerifiedTransactionCache::new(100));
        let verify_fn: Arc<TestVerifyFn> = Arc::new(|_request, _cache| {
            Err(AlgoError::Validation {
                message: "injected verification failure".into(),
            })
        });
        let verifier = Arc::new(BatchVerifier::spawn_with_verifier(
            BatchVerifierConfig::default(),
            cache,
            verify_fn,
        ));
        let handler = TxTagHandler::new(pool.clone(), seen).with_batch_verifier(verifier.clone());

        let tx = make_payment_txn(2, 2);
        let txid = compute_txn_id(&tx.txn);
        let msg = incoming(std::slice::from_ref(&tx), "5.6.7.8:4160");
        let out = handler.handle(msg).await;

        assert_eq!(out.action, ForwardingPolicy::Ignore);
        assert_eq!(
            pool.pending_count(),
            0,
            "a failed-verification group must admit nothing"
        );
        assert!(
            !pool.pending_tx_ids().contains(&txid),
            "a failed-verification group must never reach the pool"
        );

        drop(handler);
        Arc::try_unwrap(verifier)
            .unwrap_or_else(|_| panic!("verifier still shared"))
            .shutdown()
            .await;
    }

    /// Concurrently-submitted gossip transaction groups must both be
    /// processed through the *same* shared `BatchVerifier` instance, not
    /// each bypass it independently -- the core architectural claim of
    /// issue #1043.
    #[tokio::test]
    async fn concurrent_submissions_share_one_batch_verifier() {
        let pool = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_closure = calls.clone();
        let cache = Arc::new(VerifiedTransactionCache::new(100));
        let verify_fn: Arc<TestVerifyFn> = Arc::new(move |_request, _cache| {
            calls_for_closure.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let verifier = Arc::new(BatchVerifier::spawn_with_verifier(
            BatchVerifierConfig {
                num_workers: 2,
                max_batch_size: 8,
                batch_linger: std::time::Duration::from_millis(20),
                ..Default::default()
            },
            cache,
            verify_fn,
        ));
        let handler =
            Arc::new(TxTagHandler::new(pool.clone(), seen).with_batch_verifier(verifier.clone()));

        let tx1 = make_payment_txn(3, 1);
        let tx2 = make_payment_txn(4, 2);
        let txid1 = compute_txn_id(&tx1.txn);
        let txid2 = compute_txn_id(&tx2.txn);
        let msg1 = incoming(std::slice::from_ref(&tx1), "9.9.9.1:4160");
        let msg2 = incoming(std::slice::from_ref(&tx2), "9.9.9.2:4160");

        let h1 = handler.clone();
        let h2 = handler.clone();
        let (out1, out2) = tokio::join!(h1.handle(msg1), h2.handle(msg2));

        assert_eq!(out1.action, ForwardingPolicy::Ignore);
        assert_eq!(out2.action, ForwardingPolicy::Ignore);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "both concurrently-submitted groups must be verified via the shared pool"
        );
        assert!(pool.pending_tx_ids().contains(&txid1));
        assert!(pool.pending_tx_ids().contains(&txid2));

        drop(h1);
        drop(h2);
        drop(handler);
        Arc::try_unwrap(verifier)
            .unwrap_or_else(|_| panic!("verifier still shared"))
            .shutdown()
            .await;
    }
}

// ---------------------------------------------------------------------------
// Tests: canonical-form dedup / anti-censoring cache and cache rotation
// (issue #1084)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod canonical_cache_wiring_tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use algo_error::AlgoError;
    use algo_pool::traits::{BlockEvaluator, PoolLedger};
    use algo_pool::{PoolConfig, TransactionPool};
    use algo_types::{Address, Block, BlockHeader, ConsensusParams, Round, TxnType};

    use super::*;
    use crate::tx_syncer::SeenTxCache;

    /// Stub ledger/evaluator, replicated from
    /// `app_rate_limiter_wiring_tests::StubLedger` — `fail` lets a test
    /// force `remember` to fail deterministically, `calls` counts every
    /// time the evaluator actually runs a group so tests can prove
    /// whether a resend reached it or was dropped upstream.
    struct StubLedger {
        round: Round,
        fail: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
    }

    impl PoolLedger for StubLedger {
        fn latest(&self) -> Round {
            self.round
        }
        fn block_hdr(&self, _round: Round) -> Result<BlockHeader, AlgoError> {
            Ok(BlockHeader::default())
        }
        fn consensus_params(&self, _round: Round) -> Result<ConsensusParams, AlgoError> {
            Ok(ConsensusParams::default())
        }
        fn start_evaluator(
            &self,
            _hdr: BlockHeader,
            _payset_hint: usize,
            _max_txn_bytes_per_block: usize,
        ) -> Result<Box<dyn BlockEvaluator>, AlgoError> {
            Ok(Box::new(StubEvaluator {
                round: self.round.next(),
                fail: self.fail.clone(),
                calls: self.calls.clone(),
            }))
        }
    }

    struct StubEvaluator {
        round: Round,
        fail: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
    }

    impl BlockEvaluator for StubEvaluator {
        fn round(&self) -> Round {
            self.round
        }
        fn pay_set_size(&self) -> usize {
            0
        }
        fn test_transaction_group(&self, _txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
            Ok(())
        }
        fn transaction_group(&mut self, _txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                Err(AlgoError::Validation {
                    message: "stub eval failure".to_string(),
                })
            } else {
                Ok(())
            }
        }
        fn generate_block(&mut self, _voting_accounts: &[Address]) -> Result<Block, AlgoError> {
            Ok(Block::default())
        }
        fn reset_txn_bytes(&mut self) {}
    }

    fn make_pool() -> (Arc<TransactionPool>, Arc<AtomicBool>, Arc<AtomicUsize>) {
        let fail = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let ledger: Arc<dyn PoolLedger> = Arc::new(StubLedger {
            round: Round(1),
            fail: fail.clone(),
            calls: calls.clone(),
        });
        let pool = Arc::new(TransactionPool::new(PoolConfig::default(), ledger));
        pool.on_new_block(&Block::default(), &std::collections::HashSet::new());
        (pool, fail, calls)
    }

    fn make_payment_txn(sender_byte: u8, note: u8, fee: u64) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = TxnType::Pay;
        stx.txn.sender = Address([sender_byte; 32]);
        stx.txn.fee = fee;
        stx.txn.first_valid = Round(1);
        stx.txn.last_valid = Round(1_000);
        stx.txn.note = serde_bytes::ByteBuf::from(vec![note]);
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

    fn incoming(group: &[SignedTransaction], sender: &str) -> IncomingMessage {
        let data = encode_group(group);
        IncomingMessage::new(Tag::Transaction, data, sender.to_string(), 0)
    }

    /// The canonical cache must drop an exact resend of the same signed
    /// bytes even when the first attempt's `remember` failed — proving
    /// this is a genuinely independent gate from the txid-based
    /// `SeenTxCache` (which only records a group once `remember`
    /// succeeds, so it alone would let this resend straight through).
    #[tokio::test]
    async fn drops_exact_resend_even_after_remember_failed() {
        let (pool, fail, calls) = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        let canonical = Arc::new(SeenTxCache::new(1024));
        let handler = TxTagHandler::new(pool.clone(), seen).with_canonical_cache(canonical);

        fail.store(true, Ordering::SeqCst);
        let tx = make_payment_txn(1, 1, 1_000_000);
        let msg1 = incoming(std::slice::from_ref(&tx), "1.2.3.4:4160");
        let out1 = handler.handle(msg1).await;
        assert_eq!(out1.action, ForwardingPolicy::Ignore);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "first attempt must reach the evaluator"
        );

        // Resend the exact same bytes — must be dropped by the canonical
        // cache before ever reaching the evaluator again.
        let msg2 = incoming(std::slice::from_ref(&tx), "1.2.3.4:4160");
        let out2 = handler.handle(msg2).await;
        assert_eq!(out2.action, ForwardingPolicy::Ignore);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "exact resend must be dropped by the canonical cache, not reach the evaluator again"
        );
    }

    /// A different signature over the *same* txn body must not be
    /// suppressed by the canonical cache — go's "forged signature, ensure
    /// accepted" case (`TestTxHandlerProcessIncomingCensoring`).
    #[tokio::test]
    async fn admits_forged_signature_variant_of_a_cached_group() {
        let (pool, fail, calls) = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        let canonical = Arc::new(SeenTxCache::new(1024));
        let handler = TxTagHandler::new(pool.clone(), seen).with_canonical_cache(canonical);

        fail.store(true, Ordering::SeqCst);
        let mut tx = make_payment_txn(2, 1, 1_000_000);
        let msg1 = incoming(std::slice::from_ref(&tx), "5.6.7.8:4160");
        let out1 = handler.handle(msg1).await;
        assert_eq!(out1.action, ForwardingPolicy::Ignore);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Same body, different signature bytes: different canonical
        // digest, must reach the evaluator again.
        tx.sig = [7u8; 64];
        let msg2 = incoming(std::slice::from_ref(&tx), "5.6.7.8:4160");
        let out2 = handler.handle(msg2).await;
        assert_eq!(out2.action, ForwardingPolicy::Ignore);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a re-signed variant of the same txn body must not be suppressed by the canonical cache"
        );
    }

    /// Two manual rotations forget a previously-cached group, letting an
    /// identical resend through again — mirrors
    /// `TestTxHandlerProcessIncomingCacheRotation`'s "manual" sub-test:
    /// one rotation is not enough (the entry survives via `prev`), a
    /// second one is.
    #[tokio::test]
    async fn two_rotations_let_an_exact_resend_through_again() {
        let (pool, fail, calls) = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        let canonical = Arc::new(SeenTxCache::new(1024));
        let handler = TxTagHandler::new(pool.clone(), seen).with_canonical_cache(canonical.clone());

        // `remember` must fail throughout, so the txid-based `seen` cache
        // (which only records on success) never itself starts
        // suppressing the resends — this test isolates the *canonical*
        // cache's rotation behavior specifically.
        fail.store(true, Ordering::SeqCst);
        let tx = make_payment_txn(3, 1, 1_000_000);

        let msg1 = incoming(std::slice::from_ref(&tx), "9.9.9.9:4160");
        let out1 = handler.handle(msg1).await;
        assert_eq!(out1.action, ForwardingPolicy::Ignore);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // One rotation: entry moved from `cur` into `prev`, still live.
        canonical.rotate();
        let msg2 = incoming(std::slice::from_ref(&tx), "9.9.9.9:4160");
        let out2 = handler.handle(msg2).await;
        assert_eq!(out2.action, ForwardingPolicy::Ignore);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "one rotation must not yet forget the entry (still visible via prev)"
        );

        // Second rotation: the old `prev` (holding the entry) is
        // discarded outright.
        canonical.rotate();
        let msg3 = incoming(std::slice::from_ref(&tx), "9.9.9.9:4160");
        let out3 = handler.handle(msg3).await;
        assert_eq!(out3.action, ForwardingPolicy::Ignore);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "two rotations must forget the entry, admitting an exact resend again"
        );
    }

    /// Without a canonical cache attached, behavior is unchanged: repeat
    /// resends of the same bytes still reach the evaluator every time
    /// (only the txid-based `SeenTxCache`, keyed on success, applies —
    /// and it never records a `remember` failure).
    #[tokio::test]
    async fn no_canonical_cache_attached_does_not_dedup_on_resend() {
        let (pool, fail, calls) = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        let handler = TxTagHandler::new(pool.clone(), seen);

        fail.store(true, Ordering::SeqCst);
        let tx = make_payment_txn(4, 1, 1_000_000);
        let msg1 = incoming(std::slice::from_ref(&tx), "1.1.1.1:4160");
        handler.handle(msg1).await;
        let msg2 = incoming(std::slice::from_ref(&tx), "1.1.1.1:4160");
        handler.handle(msg2).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "without a canonical cache attached, both resends must reach the evaluator"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests: backlog admission queue and drop-on-full (issue #1096)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod backlog_queue_tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use algo_error::AlgoError;
    use algo_pool::traits::{BlockEvaluator, PoolLedger};
    use algo_pool::{PoolConfig, TransactionPool};
    use algo_types::{Address, Block, BlockHeader, ConsensusParams, Round, TxnType};

    use super::*;
    use crate::tx_syncer::SeenTxCache;

    /// Stub ledger/evaluator, replicated from
    /// `canonical_cache_wiring_tests::StubLedger` -- `calls` counts every
    /// time the evaluator actually runs a group so tests can prove
    /// whether a group reached the pool or was dropped upstream.
    struct StubLedger {
        round: Round,
        fail: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
    }

    impl PoolLedger for StubLedger {
        fn latest(&self) -> Round {
            self.round
        }
        fn block_hdr(&self, _round: Round) -> Result<BlockHeader, AlgoError> {
            Ok(BlockHeader::default())
        }
        fn consensus_params(&self, _round: Round) -> Result<ConsensusParams, AlgoError> {
            Ok(ConsensusParams::default())
        }
        fn start_evaluator(
            &self,
            _hdr: BlockHeader,
            _payset_hint: usize,
            _max_txn_bytes_per_block: usize,
        ) -> Result<Box<dyn BlockEvaluator>, AlgoError> {
            Ok(Box::new(StubEvaluator {
                round: self.round.next(),
                fail: self.fail.clone(),
                calls: self.calls.clone(),
            }))
        }
    }

    struct StubEvaluator {
        round: Round,
        fail: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
    }

    impl BlockEvaluator for StubEvaluator {
        fn round(&self) -> Round {
            self.round
        }
        fn pay_set_size(&self) -> usize {
            0
        }
        fn test_transaction_group(&self, _txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
            Ok(())
        }
        fn transaction_group(&mut self, _txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                Err(AlgoError::Validation {
                    message: "stub eval failure".to_string(),
                })
            } else {
                Ok(())
            }
        }
        fn generate_block(&mut self, _voting_accounts: &[Address]) -> Result<Block, AlgoError> {
            Ok(Block::default())
        }
        fn reset_txn_bytes(&mut self) {}
    }

    fn make_pool() -> (Arc<TransactionPool>, Arc<AtomicUsize>) {
        let fail = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let ledger: Arc<dyn PoolLedger> = Arc::new(StubLedger {
            round: Round(1),
            fail,
            calls: calls.clone(),
        });
        let pool = Arc::new(TransactionPool::new(PoolConfig::default(), ledger));
        pool.on_new_block(&Block::default(), &std::collections::HashSet::new());
        (pool, calls)
    }

    fn make_payment_txn(sender_byte: u8, note: u8) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = TxnType::Pay;
        stx.txn.sender = Address([sender_byte; 32]);
        stx.txn.fee = 1_000_000;
        stx.txn.first_valid = Round(1);
        stx.txn.last_valid = Round(1_000);
        stx.txn.note = serde_bytes::ByteBuf::from(vec![note]);
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

    fn incoming(group: &[SignedTransaction], sender: &str) -> IncomingMessage {
        let data = encode_group(group);
        IncomingMessage::new(Tag::Transaction, data, sender.to_string(), 0)
    }

    /// Build a handler with a capacity-1 backlog queue whose receiver is
    /// held open but never drained -- mirrors go's
    /// `makeTestTxHandlerOrphanedWithContext` (backlog worker not
    /// started) so the queue genuinely fills instead of racing a live
    /// consumer task that would otherwise drain the first item before
    /// the second `handle()` call observes the queue as full.
    fn make_orphaned_handler(
        pool: Arc<TransactionPool>,
        canonical: Arc<SeenTxCache>,
    ) -> (TxTagHandler, mpsc::Receiver<BacklogItem>) {
        let seen = Arc::new(SeenTxCache::new(1024));
        let (tx, rx) = mpsc::channel(1);
        let mut handler = TxTagHandler::new(pool, seen).with_canonical_cache(canonical);
        handler.backlog_tx = Some(tx);
        (handler, rx)
    }

    /// TDD regression for issue #1096, pinning go's exact
    /// `TestTxHandlerProcessIncomingCacheBacklogDrop` semantics: with a
    /// full capacity-1 backlog queue and no consumer draining it, a
    /// second, distinct group is dropped, the drop counter increments by
    /// exactly 1, and the canonical cache still holds exactly 1 entry
    /// (the first group's) -- proving the dropped group's entry was
    /// rolled back, not left dangling.
    #[tokio::test]
    async fn drop_on_full_backlog_rolls_back_canonical_cache() {
        let (pool, _calls) = make_pool();
        let canonical = Arc::new(SeenTxCache::new(1024));
        let (handler, _rx) = make_orphaned_handler(pool, canonical.clone());

        let tx1 = make_payment_txn(1, 1);
        let out1 = handler
            .handle(incoming(std::slice::from_ref(&tx1), "1.2.3.4:4160"))
            .await;
        assert_eq!(out1.action, ForwardingPolicy::Ignore);
        assert_eq!(canonical.len(), 1);
        assert_eq!(handler.backlog_dropped_count(), 0);

        let tx2 = make_payment_txn(2, 2);
        let out2 = handler
            .handle(incoming(std::slice::from_ref(&tx2), "1.2.3.4:4160"))
            .await;
        assert_eq!(out2.action, ForwardingPolicy::Ignore);

        assert_eq!(
            canonical.len(),
            1,
            "the dropped group's canonical-cache entry must be rolled back"
        );
        assert_eq!(
            handler.backlog_dropped_count(),
            1,
            "drop counter must increment by exactly 1"
        );
    }

    /// Proves the rollback in the test above actually un-poisons the
    /// entry (rather than merely leaving the count unchanged by
    /// coincidence): after a group is dropped for a full backlog queue,
    /// resubmitting the *exact same bytes* once the queue has room again
    /// must reach the evaluator, not be suppressed as an already-seen
    /// canonical duplicate.
    #[tokio::test]
    async fn dropped_group_can_be_resubmitted_after_rollback() {
        let (pool, calls) = make_pool();
        let canonical = Arc::new(SeenTxCache::new(1024));
        let (handler, mut rx) = make_orphaned_handler(pool, canonical.clone());

        // Fill the capacity-1 queue with an unrelated filler group.
        let filler = make_payment_txn(9, 9);
        handler
            .handle(incoming(std::slice::from_ref(&filler), "9.9.9.9:4160"))
            .await;

        // This group is dropped -- the queue is full and nothing is
        // draining it yet.
        let dropped = make_payment_txn(5, 5);
        handler
            .handle(incoming(std::slice::from_ref(&dropped), "5.5.5.5:4160"))
            .await;
        assert_eq!(handler.backlog_dropped_count(), 1);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "nothing has been drained yet"
        );

        // Drain the filler out of the channel, freeing capacity.
        rx.recv().await.expect("filler item present");

        // Resubmit the exact same bytes that were dropped -- if the
        // rollback worked, the canonical cache holds no entry for it and
        // it is enqueued fresh (not suppressed as a dup).
        handler
            .handle(incoming(std::slice::from_ref(&dropped), "5.5.5.5:4160"))
            .await;
        assert_eq!(
            handler.backlog_dropped_count(),
            1,
            "the resubmission must be enqueued, not dropped again"
        );

        let requeued = rx.recv().await.expect("resubmitted item present");
        assert_eq!(requeued.sender, "5.5.5.5:4160");
    }

    /// Without a backlog queue attached, behavior is unchanged from
    /// before issue #1096: every admitted group reaches the pool inline,
    /// and the drop counter never moves.
    #[tokio::test]
    async fn no_backlog_queue_attached_admits_inline() {
        let (pool, calls) = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        let handler = TxTagHandler::new(pool.clone(), seen);

        let tx = make_payment_txn(1, 1);
        let txid = compute_txn_id(&tx.txn);
        let out = handler
            .handle(incoming(std::slice::from_ref(&tx), "1.2.3.4:4160"))
            .await;
        assert_eq!(out.action, ForwardingPolicy::Ignore);
        assert!(pool.pending_tx_ids().contains(&txid));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(handler.backlog_dropped_count(), 0);
    }

    /// A capacity that comfortably fits every concurrently-admitted group
    /// must let all of them reach the pool via the background consumer
    /// task -- proving `with_backlog_queue` is a real end-to-end path,
    /// not just an enqueue-and-drop stub.
    #[tokio::test]
    async fn backlog_queue_consumer_admits_to_pool() {
        let (pool, calls) = make_pool();
        let seen = Arc::new(SeenTxCache::new(1024));
        let handler = TxTagHandler::new(pool.clone(), seen).with_backlog_queue(8);

        let tx1 = make_payment_txn(1, 1);
        let tx2 = make_payment_txn(2, 2);
        let txid1 = compute_txn_id(&tx1.txn);
        let txid2 = compute_txn_id(&tx2.txn);

        let out1 = handler
            .handle(incoming(std::slice::from_ref(&tx1), "1.1.1.1:4160"))
            .await;
        let out2 = handler
            .handle(incoming(std::slice::from_ref(&tx2), "2.2.2.2:4160"))
            .await;
        assert_eq!(out1.action, ForwardingPolicy::Ignore);
        assert_eq!(out2.action, ForwardingPolicy::Ignore);

        // The consumer task runs concurrently -- poll briefly for it to
        // catch up rather than asserting immediately.
        for _ in 0..200 {
            if pool.pending_tx_ids().contains(&txid1) && pool.pending_tx_ids().contains(&txid2) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(pool.pending_tx_ids().contains(&txid1));
        assert!(pool.pending_tx_ids().contains(&txid2));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(handler.backlog_dropped_count(), 0);
    }
}
