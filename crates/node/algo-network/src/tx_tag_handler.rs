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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sha2::{Digest as Sha2DigestTrait, Sha512_256};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use algo_codec::{canonical_encode_signed_transaction, compute_txn_id};
use algo_pool::{
    classify_pool_error, AppRateLimiter, CapacityGuard, ElasticRateLimiter,
    ElasticRateLimiterError, PoolErrorTag, TransactionPool,
};
use algo_types::{Digest, SignedTransaction};
use algo_validate::{BatchVerifier, BatchVerifyRequest, SpecialAddresses, VerificationContext};

use crate::forwarding_policy::ForwardingPolicy;
use crate::gossip_node::{GossipNode, Peer};
use crate::handler::MessageHandler;
use crate::local_tx_broadcast::encode_tx_group;
use crate::message::{IncomingMessage, OutgoingMessage};
use crate::tag::Tag;
use crate::tx_syncer::SeenTxCache;

// ---------------------------------------------------------------------------
// TxPoolRememberCounter — per-tag inbound-gossip `pool.remember()` failure
// counter (issue #1134)
// ---------------------------------------------------------------------------

/// Per-[`PoolErrorTag`] counter for inbound gossip transaction groups that
/// [`TransactionPool::remember`] rejected, mirroring go-algorand's
/// `data/txHandler.go`:
/// `transactionMessageTxPoolRememberCounter = metrics.NewTagCounter(
/// "algod_transaction_messages_txpool_remember_err_{TAG}", "Number of
/// transaction messages not remembered by txpool b/c of {TAG}",
/// pools.TxPoolErrTags...)`, incremented in `TxHandler.postProcessCheckedTxn`
/// at `transactionMessageTxPoolRememberCounter.Add(pools.ClassifyTxPoolError(err), 1)`
/// — the exact go-side call site [`ingest_group`] below is the structural
/// analogue of (decoded gossip group -> `pool.Remember`/`pool.remember` ->
/// classify the failure).
///
/// Lock-free fixed-size array indexed by [`PoolErrorTag`], same pattern as
/// `algo_pool::TxPoolReevalCounter`.
#[derive(Debug, Default)]
pub struct TxPoolRememberCounter {
    counts: [AtomicU64; PoolErrorTag::ALL.len()],
}

impl TxPoolRememberCounter {
    /// A fresh, all-zero counter set.
    pub fn new() -> Self {
        Self::default()
    }

    fn index_of(tag: PoolErrorTag) -> usize {
        PoolErrorTag::ALL
            .iter()
            .position(|t| *t == tag)
            .expect("PoolErrorTag::ALL is exhaustive over PoolErrorTag")
    }

    /// Record one inbound gossip group rejected by `pool.remember()`,
    /// classified as `tag`. Go:
    /// `transactionMessageTxPoolRememberCounter.Add(ClassifyTxPoolError(err), 1)`.
    pub fn record(&self, tag: PoolErrorTag) {
        self.counts[Self::index_of(tag)].fetch_add(1, Ordering::Relaxed);
    }

    /// Current count for `tag`. Zero for a tag nothing has been recorded
    /// for yet.
    pub fn count(&self, tag: PoolErrorTag) -> u64 {
        self.counts[Self::index_of(tag)].load(Ordering::Relaxed)
    }

    /// Render as Prometheus text exposition format, substituting the
    /// literal tag into `algod_transaction_messages_txpool_remember_err_{TAG}`
    /// — not as a label — matching go's `metrics.TagCounter` naming
    /// convention.
    pub fn to_prometheus_text(&self) -> String {
        let mut out = String::with_capacity(96 * PoolErrorTag::ALL.len());
        for tag in PoolErrorTag::ALL {
            let name = format!(
                "algod_transaction_messages_txpool_remember_err_{}",
                tag.as_str()
            );
            out.push_str(&format!(
                "# HELP {name} Number of transaction messages not remembered by txpool b/c of {}.\n# TYPE {name} counter\n{name} {}\n",
                tag.as_str(),
                self.count(*tag)
            ));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// TxBacklogPeerLimiter — per-peer backlog-admission fairness gate
// (issue #1195)
// ---------------------------------------------------------------------------

/// Free-shared-capacity threshold (as a percentage of the limiter's
/// `max_capacity`) below which congestion control is enabled, and at/above
/// which it is disabled again. Mirrors go's `TxBacklogRateLimitingCongestionPct`
/// default (50%, `config/localTemplate.go:251`) — that field itself is not
/// config-plumbed here (see [`TxBacklogPeerLimiter`]'s doc comment), same
/// deliberate choice `crate::tx_sync_service::TxSyncPeerLimiter` already
/// made for its own (differently-scoped) `CONGESTION_THRESHOLD_PCT`.
const BACKLOG_CONGESTION_THRESHOLD_PCT: usize = 50;

/// Per-peer admission-fairness gate for [`TxTagHandler::with_backlog_queue`]
/// (issue #1195), the push-side analogue of
/// [`crate::tx_sync_service::TxSyncPeerLimiter`]'s pull-side gate. Both wrap
/// [`algo_pool::ElasticRateLimiter`] — see that module's doc comment for the
/// full algorithm — but this one guards admission onto `TxTagHandler`'s
/// *own* inbound gossip backlog queue, exactly mirroring go's real
/// `TxHandler.erl`/`incomingMsgErlCheck` (`data/txHandler.go:189-199,
/// 640-659`) rather than needing an architectural workaround: unlike
/// [`crate::tx_syncer::TxSyncer`]'s pull-based sync path (which has no
/// reachable "unsolicited incoming transaction" admission point, see
/// `algo_pool::elastic_rate_limiter`'s module doc), `TxTagHandler` genuinely
/// *is* algod-rust's push-based, peer-unsolicited transaction-relay
/// ingestion path — the direct structural analogue of go's
/// `TxHandler.processIncomingTxn`. So this is a real, direct port of go's
/// mechanism, not a redesigned mirror image of it.
///
/// ## Wiring (mirrors go's `processIncomingTxn`/`incomingMsgErlCheck`)
///
/// * Each distinct peer (keyed by [`backlog_peer_key`], go's
///   `erlClientMapper` IP-bucketing analogue) gets a small guaranteed
///   reservation (`capacity_per_peer`, go's `TxBacklogReservedCapacityPerPeer`)
///   out of a shared pool (`max_capacity`) — so one peer relaying many
///   groups back-to-back cannot exhaust capacity another, already-active
///   peer has reserved for itself (see this module's
///   `backlog_peer_limiter_protects_reserved_share_from_a_flooding_peer`
///   test).
/// * [`TxTagHandler::handle`] calls [`Self::admit`] *before* the group is
///   handed to the bounded `mpsc` channel [`TxTagHandler::with_backlog_queue`]
///   attaches: a rejected admission drops the group exactly like a full
///   `mpsc` channel would (same [`TxTagHandler::backlog_dropped_count`]
///   counter, mirroring go incrementing the same
///   `transactionMessagesDroppedFromBacklog` metric from both
///   `incomingMsgErlCheck`'s no-capacity path and the `mpsc`-queue-full
///   path).
/// * A consumed capacity unit is released back (via [`Self::release_unserved`])
///   immediately if the group never actually reaches the queue (the `mpsc`
///   channel was momentarily full despite ERL admitting it) — mirrors go's
///   `processIncomingTxn` `defer`: `if !accepted && capguard != nil {
///   capguard.Release() }`.
/// * Once a group *is* enqueued, its capacity unit stays held until
///   [`TxTagHandler`]'s background consumer dequeues it, at which point
///   [`Self::release_and_serve`] both returns the unit and records the
///   service-rate event — mirrors go's `backlogWorker` releasing
///   `wi.capguard` and calling `wi.capguard.Served()` immediately after
///   dequeuing (`data/txHandler.go:331-365`), *not* after the group finishes
///   pool processing. A capacity unit therefore measures "how long this
///   group sat in the queue before being picked up", the same signal go's
///   port measures.
/// * Congestion control toggles on falling free-shared-capacity, exactly
///   like [`crate::tx_sync_service::TxSyncPeerLimiter`] (see that struct's
///   doc comment for the shared rationale on using free-shared-capacity
///   rather than a raw queue-depth read as the congestion signal).
///
/// ## Deliberately deferred (see issue #1195's own acceptance criteria)
///
/// * **Exact `erlClientMapper` parity.** go's mapper bounds how many
///   distinct connection objects register under one IP
///   (`erlClientMapper.maxClients`, fed by `MaxConnectionsPerIP`) purely as
///   a map-capacity bookkeeping hint with no observable effect on
///   `ConsumeCapacity` itself — every connection from the same IP already
///   shares one `erlIPClient`, and therefore one reservation, regardless of
///   `maxClients`. [`backlog_peer_key`] achieves the same IP-level
///   reservation-sharing directly (by keying on IP alone) without porting
///   the connection-object bookkeeping around it, since that bookkeeping
///   has no effect on the fairness property this gate exists to guarantee.
/// * **`TxBacklogRateLimitingCongestionPct`/`TxBacklogAppRateLimitingCountERLDrops`**
///   remain out of `algo_config::Local` (see `algo_config`'s doc comment on
///   [`TX_BACKLOG_RESERVED_CAPACITY_PER_PEER`]-adjacent fields) — this gate
///   uses [`BACKLOG_CONGESTION_THRESHOLD_PCT`], a hardcoded default matching
///   go's own default value, the same judgment call
///   `crate::tx_sync_service::TxSyncPeerLimiter` already made.
///
/// [`TX_BACKLOG_RESERVED_CAPACITY_PER_PEER`]: algo_config
pub struct TxBacklogPeerLimiter {
    erl: Mutex<ElasticRateLimiter<String>>,
    max_capacity: usize,
}

impl TxBacklogPeerLimiter {
    /// Creates a peer-fairness limiter with `max_capacity` total
    /// concurrently-admittable backlog-queue slots, of which
    /// `capacity_per_peer` units are set aside as a guaranteed reservation
    /// for each distinct peer (by [`backlog_peer_key`]) the first time it
    /// is seen. `service_rate_window` sizes the sliding window
    /// [`algo_pool::RedCongestionManager`] uses to estimate arrival/service
    /// rates once congestion control is enabled. `max_capacity` should
    /// typically be [`TxTagHandler::with_backlog_queue`]'s own `capacity`
    /// argument, so admission into the ERL and admission into the `mpsc`
    /// channel it guards are sized consistently.
    #[must_use]
    pub fn new(
        max_capacity: usize,
        capacity_per_peer: usize,
        service_rate_window: Duration,
    ) -> Self {
        let max_capacity = max_capacity.max(1);
        Self {
            erl: Mutex::new(ElasticRateLimiter::new(
                max_capacity,
                capacity_per_peer,
                service_rate_window,
            )),
            max_capacity,
        }
    }

    /// Attempts to admit one backlog-queue slot for `peer_key`. Mirrors
    /// go's `incomingMsgErlCheck`'s congestion-control toggle (using
    /// free-shared-capacity rather than a raw queue-depth read as the
    /// signal — see this struct's doc comment).
    fn admit(&self, peer_key: &str) -> Result<CapacityGuard<String>, ElasticRateLimiterError> {
        let mut erl = self
            .erl
            .lock()
            .expect("TxBacklogPeerLimiter mutex poisoned");
        let was_congested =
            Self::shared_pool_congested(erl.shared_capacity_len(), self.max_capacity);
        let (is_cm_enabled, res) = erl.consume_capacity(&peer_key.to_string());
        if res.is_err() || (!is_cm_enabled && was_congested) {
            erl.enable_congestion_control();
        } else if !was_congested {
            erl.disable_congestion_control();
        }
        res
    }

    /// Returns `guard`'s capacity unit to its origin queue and records a
    /// service-rate event, mirroring go's `backlogWorker` calling
    /// `wi.capguard.Release()` then `wi.capguard.Served()` immediately
    /// after dequeuing a work item (*not* after it finishes pool
    /// processing).
    fn release_and_serve(&self, mut guard: CapacityGuard<String>) {
        let mut erl = self
            .erl
            .lock()
            .expect("TxBacklogPeerLimiter mutex poisoned");
        let _ = erl.release(&mut guard);
        erl.served(Instant::now());
    }

    /// Returns `guard`'s capacity unit to its origin queue without
    /// recording a service event — mirrors go's `processIncomingTxn`
    /// `defer`, releasing capacity for a group that was admitted by ERL but
    /// never actually reached the backlog queue (e.g. the `mpsc` channel
    /// was momentarily full).
    fn release_unserved(&self, mut guard: CapacityGuard<String>) {
        let mut erl = self
            .erl
            .lock()
            .expect("TxBacklogPeerLimiter mutex poisoned");
        let _ = erl.release(&mut guard);
    }

    fn shared_pool_congested(free: usize, max_capacity: usize) -> bool {
        free.saturating_mul(100) / max_capacity.max(1) < BACKLOG_CONGESTION_THRESHOLD_PCT
    }
}

impl std::fmt::Debug for TxBacklogPeerLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxBacklogPeerLimiter")
            .field("max_capacity", &self.max_capacity)
            .finish()
    }
}

/// Derives the client key [`TxBacklogPeerLimiter`] reserves capacity under
/// from a gossip message's sender address string. Strips the port exactly
/// like [`origin_bytes`] — mirroring go's `erlClientMapper` bucketing every
/// connection from the same source IP under one shared `erlIPClient` (and
/// therefore one reservation) for ERL purposes, regardless of how many
/// distinct logical connections that IP has open. Falls back to the raw
/// sender string when it doesn't parse as a `host:port` socket address
/// (e.g. a synthetic/test sender, or a P2P peer-id string) — still
/// deterministic per distinct sender, just not IP-bucketed in that case.
fn backlog_peer_key(sender: &str) -> String {
    match sender.parse::<std::net::SocketAddr>() {
        Ok(addr) => addr.ip().to_string(),
        Err(_) => sender.to_string(),
    }
}

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
    remember_counter: Arc<TxPoolRememberCounter>,
    backlog_peer_limiter: Option<Arc<TxBacklogPeerLimiter>>,
    net: Option<Arc<dyn GossipNode>>,
}

/// Minimal [`Peer`] wrapper carrying only an address string, used as the
/// `except` argument to [`GossipNode::relay`] — [`TxTagHandler`] only ever
/// needs to exclude the originating peer by address (mirroring go's
/// `wi.rawmsg.Sender`), never anything else `Peer` exposes.
struct AddrPeer(String);

impl Peer for AddrPeer {
    fn get_address(&self) -> &str {
        &self.0
    }

    fn get_connection_latency(&self) -> Duration {
        Duration::ZERO
    }

    fn routing_addr(&self) -> &[u8] {
        &[]
    }
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
            .field(
                "backlog_peer_limiter_enabled",
                &self.backlog_peer_limiter.is_some(),
            )
            .field("relay_enabled", &self.net.is_some())
            .finish()
    }
}

/// A decoded, admission-gated group queued for pool submission by
/// [`TxTagHandler::with_backlog_queue`] (issue #1096).
struct BacklogItem {
    group: Vec<SignedTransaction>,
    txids: Vec<Digest>,
    sender: String,
    /// Capacity unit held against a [`TxBacklogPeerLimiter`] (issue #1195),
    /// if one is attached. Released — and the service event recorded — when
    /// [`backlog_worker`] dequeues this item; released without a service
    /// event if this item is constructed but never successfully enqueued
    /// (see [`TxTagHandler::handle`]'s backlog-submission block).
    peer_guard: Option<CapacityGuard<String>>,
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
            remember_counter: Arc::new(TxPoolRememberCounter::new()),
            backlog_peer_limiter: None,
            net: None,
        }
    }

    /// Attach a [`GossipNode`] to relay successfully-admitted inbound
    /// groups to this node's other peers, mirroring go-algorand's
    /// `TxHandler.net.Relay(handler.ctx, protocol.TxnTag,
    /// reencode(verifiedTxGroup), false, wi.rawmsg.Sender)`
    /// (`data/txHandler.go`), called only after `pool.Remember` succeeds
    /// and the group is not being processed in synchronous (locally
    /// submitted) mode.
    ///
    /// Without this attached (the default from [`Self::new`]), an inbound
    /// group is ingested into the local pool but never re-propagated to
    /// other peers — a relay node's own peers other than the original
    /// sender would never learn about the transaction via gossip at all,
    /// unlike go. `net` should be the same [`GossipNode`] the transport
    /// this handler is registered on serves gossip over (e.g. the
    /// `WebsocketNetwork`/`Arc<dyn GossipNode>` passed to
    /// [`crate::local_tx_broadcast::LocalTxBroadcaster::new`] for the same
    /// node), so relay reaches this handler's actual peers.
    ///
    /// Must be called *before* [`Self::with_backlog_queue`] — like
    /// [`Self::with_remember_counter`]/[`Self::with_backlog_peer_limiter`],
    /// the spawned worker captures whichever `net` is attached at the
    /// moment `with_backlog_queue` runs.
    #[must_use]
    pub fn with_relay(mut self, net: Arc<dyn GossipNode>) -> Self {
        self.net = Some(net);
        self
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
    ///
    /// Call [`Self::with_remember_counter`]/[`Self::with_backlog_peer_limiter`]
    /// (if attaching either) *before* this method — the spawned worker
    /// captures whichever [`TxPoolRememberCounter`]/[`TxBacklogPeerLimiter`]
    /// is attached at the moment this is called.
    #[must_use]
    pub fn with_backlog_queue(mut self, capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        tokio::spawn(backlog_worker(
            rx,
            self.pool.clone(),
            self.seen.clone(),
            self.app_limiter.clone(),
            self.remember_counter.clone(),
            self.backlog_peer_limiter.clone(),
            self.net.clone(),
        ));
        self.backlog_tx = Some(tx);
        self
    }

    /// Attach a [`TxBacklogPeerLimiter`] (issue #1195), gating admission
    /// onto the bounded backlog queue [`Self::with_backlog_queue`] attaches
    /// so a single flooding peer cannot exhaust another peer's guaranteed
    /// reserved share of it. See [`TxBacklogPeerLimiter`]'s doc comment for
    /// the full behavioral contract, and `bin/algod-rust/src/commands/participate.rs`
    /// for how `config.json`'s `TxBacklogReservedCapacityPerPeer`/
    /// `TxBacklogServiceRateWindowSeconds`/`EnableTxBacklogRateLimiting` feed
    /// its construction.
    ///
    /// `limiter` should typically be shared (same `Arc`) across every
    /// `TxTagHandler` instance registered on this node (same sharing
    /// rationale as [`Self::with_app_rate_limiter`]'s `limiter`), so one
    /// node-wide reservation pool sees traffic from every transport — but
    /// unlike that limiter, each `TxTagHandler`'s *own* `mpsc` backlog
    /// channel is still transport-local (WS-gossip and P2P each get their
    /// own bounded queue via their own `with_backlog_queue` call), so
    /// `max_capacity` passed to [`TxBacklogPeerLimiter::new`] should match
    /// whichever single `capacity` value is passed to every transport's
    /// `with_backlog_queue` call in practice (algod-rust computes one
    /// shared `tx_backlog_queue_capacity` and reuses it verbatim for both).
    ///
    /// Must be called *before* [`Self::with_backlog_queue`] — see that
    /// method's doc comment. Without this attached, admission onto the
    /// backlog queue is unchanged from before issue #1195: first-come,
    /// first-served, drop-on-full with no per-peer notion.
    #[must_use]
    pub fn with_backlog_peer_limiter(mut self, limiter: Arc<TxBacklogPeerLimiter>) -> Self {
        self.backlog_peer_limiter = Some(limiter);
        self
    }

    /// Attach a shared [`TxPoolRememberCounter`] (issue #1134), so its
    /// counts are shared (and thus node-wide, matching go's single
    /// `TxHandler`) across multiple `TxTagHandler` instances registered on
    /// different transports (e.g. one per WS-gossip and one per P2P — see
    /// [`Self::with_app_rate_limiter`]'s doc comment for the same sharing
    /// rationale). Without this, [`Self::new`]'s fresh, unshared counter is
    /// used.
    #[must_use]
    pub fn with_remember_counter(mut self, counter: Arc<TxPoolRememberCounter>) -> Self {
        self.remember_counter = counter;
        self
    }

    /// The per-tag `pool.remember()` failure counters this handler updates.
    /// Exposed so `GET /metrics` can render them (issue #1134).
    #[must_use]
    pub fn remember_counter(&self) -> &Arc<TxPoolRememberCounter> {
        &self.remember_counter
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

        // `checkAlreadyCommitted`-equivalent pre-check (issue #1249),
        // mirroring go's `backlogWorker` calling `checkAlreadyCommitted(wi)`
        // -- which calls `txPool.Test(tx.unverifiedTxGroup)` -- immediately
        // after pulling an item off the backlog queue, *before* handing the
        // group to `streamVerifierChan` (`data/txHandler.go:341`, `:905`).
        // `TransactionPool::test()` runs the same well-formedness /
        // duplicate / eviction-fee checks `remember()`'s evaluator step
        // does, against the pool's live pending-block-evaluator state, but
        // without storing anything and without any cryptographic signature
        // verification. The `seen`/canonical-form dedup caches above only
        // catch a group this node has personally, successfully remembered
        // before via this exact gossip path -- they miss a group that's
        // already committed to the ledger, conflicts with a currently
        // pending group, or would be rejected on fee/eviction-priority
        // grounds under pool congestion. Without this check, such a group
        // falls through to full batch signature verification below only to
        // be rejected by `pool.remember()` afterward anyway -- exactly the
        // wasted crypto work `pool.Test()` exists to short-circuit.
        //
        // A rejection here mirrors go's `continue` right after
        // `checkAlreadyCommitted` returns `true`: the group never reaches
        // batch verification or `pool.remember()`, and the canonical-cache
        // entry it was tentatively admitted under above is rolled back
        // (mirroring the other early-drop paths in this handler) since the
        // group never earns a legitimate `seen`/canonical slot.
        if let Err(e) = self.pool.test(&group) {
            debug!(
                sender = %msg.sender,
                group_len = group.len(),
                error = %e,
                "TxTagHandler: dropped by pool pre-check (already committed/duplicate/rejected)",
            );
            if let (Some(digest), Some(cache)) = (canonical_digest, &self.canonical_cache) {
                cache.remove(&digest);
            }
            return OutgoingMessage {
                action: ForwardingPolicy::Ignore,
                tag: Tag::Transaction,
                payload: Vec::new(),
                topics: None,
            };
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
            // Per-peer admission-fairness gate (issue #1195), mirroring
            // go's `processIncomingTxn` calling `incomingMsgErlCheck`
            // *before* the group is handed to the backlog channel: a
            // rejected admission (the peer's reserved share -- and, once
            // exhausted, its fair share of the shared pool -- is used up)
            // drops the group exactly like a full `mpsc` channel would,
            // via the same drop-counter/cache-rollback path below.
            let mut peer_guard: Option<CapacityGuard<String>> = None;
            if let Some(limiter) = &self.backlog_peer_limiter {
                let peer_key = backlog_peer_key(&msg.sender);
                match limiter.admit(&peer_key) {
                    Ok(guard) => peer_guard = Some(guard),
                    Err(_) => {
                        self.backlog_dropped.fetch_add(1, Ordering::Relaxed);
                        if let (Some(digest), Some(cache)) =
                            (canonical_digest, &self.canonical_cache)
                        {
                            cache.remove(&digest);
                        }
                        debug!(
                            sender = %msg.sender,
                            "TxTagHandler: dropped by backlog peer-fairness limiter",
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

            let item = BacklogItem {
                group,
                txids,
                sender: msg.sender.clone(),
                peer_guard,
            };
            // Non-blocking `try_send` mirrors go's `select { case
            // backlogQueue <- wi: ... default: ... }`: a full queue
            // drops the message rather than blocking this handler (and
            // therefore this peer's whole dispatch loop).
            if let Err(err) = backlog_tx.try_send(item) {
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
                // This item was already admitted by the ERL gate above
                // (if attached) but never actually reached the queue --
                // release its capacity unit now rather than leaking it
                // until this peer's *next* message, mirroring go's
                // `processIncomingTxn` `defer`: `if !accepted &&
                // capguard != nil { capguard.Release() }`.
                if let (Some(limiter), Some(guard)) =
                    (&self.backlog_peer_limiter, err.into_inner().peer_guard)
                {
                    limiter.release_unserved(guard);
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
                &self.remember_counter,
                &self.net,
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
#[allow(clippy::too_many_arguments)]
async fn ingest_group(
    pool: &Arc<TransactionPool>,
    seen: &Arc<SeenTxCache>,
    app_limiter: &Option<Arc<AppRateLimiter>>,
    remember_counter: &Arc<TxPoolRememberCounter>,
    net: &Option<Arc<dyn GossipNode>>,
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
    // Cloned only when relay is attached: go re-encodes
    // (`reencode(verifiedTxGroup)`) and relays the group to other peers
    // only *after* `pool.Remember` succeeds — see the `Ok(Ok(()))` arm
    // below.
    let group_for_relay = net.is_some().then(|| group.clone());
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
            // Issue found during the Phase 17 second-pass network audit
            // (`docs/phase17/parity_network.md`'s `TestLineNetwork` row):
            // mirrors go's `TxHandler.postProcessCheckedTxn` calling
            // `handler.net.Relay(handler.ctx, protocol.TxnTag,
            // reencode(verifiedTxGroup), false, wi.rawmsg.Sender)`
            // immediately after a successful `Remember` — without this, a
            // relay node ingests an inbound gossip group into its own
            // pool but never re-propagates it to its *other* peers, so
            // multi-hop gossip propagation across a relay chain silently
            // never happens (a peer two hops from the originator never
            // learns about the transaction at all). `except` excludes the
            // sender by address only (an [`AddrPeer`]), matching go's
            // `wi.rawmsg.Sender` — a full `Peer` is not otherwise needed
            // here.
            if let (Some(net), Some(group)) = (net, group_for_relay) {
                match encode_tx_group(&group) {
                    Ok(payload) => {
                        let except: Arc<dyn Peer> = Arc::new(AddrPeer(sender.clone()));
                        if let Err(e) = net
                            .relay(Tag::Transaction, payload, false, Some(except))
                            .await
                        {
                            debug!(
                                sender = %sender,
                                error = %e,
                                "TxTagHandler: relay failed",
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            sender = %sender,
                            error = %e,
                            "TxTagHandler: failed to re-encode group for relay",
                        );
                    }
                }
            }
        }
        Ok(Err(e)) => {
            warn!(
                sender = %sender,
                error = %e,
                "TxTagHandler: pool rejected inbound TX group",
            );
            // Issue #1134: mirrors go's `postProcessCheckedTxn` calling
            // `transactionMessageTxPoolRememberCounter.Add(ClassifyTxPoolError(err), 1)`
            // on a `Remember` failure.
            remember_counter.record(classify_pool_error(&e));
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
///
/// If a [`TxBacklogPeerLimiter`] (issue #1195) is attached, each item's
/// capacity unit is released back — and its service event recorded — the
/// moment it is dequeued here, mirroring go's `backlogWorker` calling
/// `wi.capguard.Release()` then `wi.capguard.Served()` immediately after
/// pulling a work item off `backlogQueue`, *before* `checkAlreadyCommitted`
/// or any further processing (`data/txHandler.go:331-365`).
async fn backlog_worker(
    mut rx: mpsc::Receiver<BacklogItem>,
    pool: Arc<TransactionPool>,
    seen: Arc<SeenTxCache>,
    app_limiter: Option<Arc<AppRateLimiter>>,
    remember_counter: Arc<TxPoolRememberCounter>,
    peer_limiter: Option<Arc<TxBacklogPeerLimiter>>,
    net: Option<Arc<dyn GossipNode>>,
) {
    while let Some(item) = rx.recv().await {
        let BacklogItem {
            group,
            txids,
            sender,
            peer_guard,
        } = item;
        if let (Some(limiter), Some(guard)) = (&peer_limiter, peer_guard) {
            limiter.release_and_serve(guard);
        }
        ingest_group(
            &pool,
            &seen,
            &app_limiter,
            &remember_counter,
            &net,
            group,
            txids,
            sender,
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

    // -----------------------------------------------------------------
    // TxPoolRememberCounter (issue #1134)
    // -----------------------------------------------------------------

    #[test]
    fn remember_counter_starts_at_zero_for_every_tag() {
        let c = TxPoolRememberCounter::new();
        for tag in algo_pool::PoolErrorTag::ALL {
            assert_eq!(c.count(*tag), 0);
        }
    }

    #[test]
    fn remember_counter_record_increments_only_matching_tag() {
        let c = TxPoolRememberCounter::new();
        c.record(algo_pool::PoolErrorTag::Overspend);
        c.record(algo_pool::PoolErrorTag::Overspend);
        c.record(algo_pool::PoolErrorTag::Cap);

        assert_eq!(c.count(algo_pool::PoolErrorTag::Overspend), 2);
        assert_eq!(c.count(algo_pool::PoolErrorTag::Cap), 1);
        assert_eq!(c.count(algo_pool::PoolErrorTag::Fee), 0);
    }

    #[test]
    fn remember_counter_prometheus_text_uses_tag_in_series_name() {
        let c = TxPoolRememberCounter::new();
        c.record(algo_pool::PoolErrorTag::TealReject);
        let text = c.to_prometheus_text();

        assert!(text.contains("algod_transaction_messages_txpool_remember_err_teal_reject 1\n"));
        assert!(text
            .contains("# TYPE algod_transaction_messages_txpool_remember_err_teal_reject counter"));
        assert!(!text.contains("tag=\""));
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

        // Issue #1134: the failed `remember()` must also increment the
        // per-tag remember-error counter (go: `transactionMessageTxPoolRememberCounter`).
        // The stub evaluator's generic failure message matches no known
        // substring in `classify_pool_error`, so it falls into `EvalGeneric`.
        assert_eq!(
            handler
                .remember_counter()
                .count(algo_pool::PoolErrorTag::EvalGeneric),
            1,
            "remember counter should record one EvalGeneric rejection"
        );

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

    /// Ledger/evaluator whose `test_transaction_group` always rejects --
    /// used to prove the `pool.test()` pre-check (issue #1249) gates
    /// admission *before* batch signature verification, the way go's
    /// `checkAlreadyCommitted` gates admission before `streamVerifierChan`.
    struct RejectingTestLedger {
        round: Round,
    }

    impl PoolLedger for RejectingTestLedger {
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
            Ok(Box::new(RejectingTestEvaluator {
                round: self.round.next(),
            }))
        }
    }

    struct RejectingTestEvaluator {
        round: Round,
    }

    impl BlockEvaluator for RejectingTestEvaluator {
        fn round(&self) -> Round {
            self.round
        }
        fn pay_set_size(&self) -> usize {
            0
        }
        fn test_transaction_group(&self, _txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
            Err(AlgoError::Validation {
                message: "injected: already committed / duplicate / rejected".into(),
            })
        }
        fn transaction_group(&mut self, _txgroup: &[SignedTransaction]) -> Result<(), AlgoError> {
            // Would succeed if reached -- proves the pre-check, not
            // `remember()`'s own evaluator step, is what gates this group.
            Ok(())
        }
        fn generate_block(&mut self, _voting_accounts: &[Address]) -> Result<Block, AlgoError> {
            Ok(Block::default())
        }
        fn reset_txn_bytes(&mut self) {}
    }

    fn make_pool_rejecting_test() -> Arc<TransactionPool> {
        let ledger: Arc<dyn PoolLedger> = Arc::new(RejectingTestLedger { round: Round(1) });
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

    /// A group `TransactionPool::test()` rejects (already committed,
    /// conflicting with a pending group, or otherwise doomed under
    /// `remember()`) must be dropped *before* it ever reaches the attached
    /// `BatchVerifier` -- proving the `checkAlreadyCommitted`-equivalent
    /// pre-check (issue #1249) actually short-circuits batch signature
    /// verification rather than running it unconditionally. Mirrors go's
    /// `backlogWorker` calling `checkAlreadyCommitted(wi)` (which calls
    /// `txPool.Test(...)`) before handing the group to
    /// `streamVerifierChan` (`data/txHandler.go:341`).
    #[tokio::test]
    async fn pool_test_rejection_never_reaches_batch_verifier_or_pool() {
        let pool = make_pool_rejecting_test();
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

        let tx = make_payment_txn(3, 3);
        let txid = compute_txn_id(&tx.txn);
        let msg = incoming(std::slice::from_ref(&tx), "9.9.9.9:4160");
        let out = handler.handle(msg).await;

        assert_eq!(out.action, ForwardingPolicy::Ignore);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "the pool pre-check must reject the group before batch verification ever runs"
        );
        assert!(
            !pool.pending_tx_ids().contains(&txid),
            "a group rejected by the pool pre-check must never reach the pool"
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

    // ── TxBacklogPeerLimiter (issue #1195) ──────────────────────────────

    /// Builds a handler with a [`TxBacklogPeerLimiter`] attached and a
    /// generously-sized (never-fills) orphaned backlog queue, so every
    /// drop this test observes is attributable to the ERL admission gate
    /// itself rather than a full `mpsc` channel -- the equivalent
    /// isolation `make_orphaned_handler` gives the plain-queue tests
    /// above.
    fn make_peer_limited_handler(
        pool: Arc<TransactionPool>,
        limiter: Arc<TxBacklogPeerLimiter>,
    ) -> (TxTagHandler, mpsc::Receiver<BacklogItem>) {
        let seen = Arc::new(SeenTxCache::new(1024));
        let (tx, rx) = mpsc::channel(100);
        let mut handler = TxTagHandler::new(pool, seen).with_backlog_peer_limiter(limiter);
        handler.backlog_tx = Some(tx);
        (handler, rx)
    }

    /// TDD anchor for issue #1195: a flooding peer must not be able to
    /// exhaust another peer's guaranteed reserved share of the backlog
    /// queue.
    ///
    /// `max_capacity=4`, `capacity_per_peer=2`. The "quiet" peer opens its
    /// reservation and consumes its first of 2 reserved units. The "noisy"
    /// peer then floods: its own first two messages open and drain its own
    /// 2-unit reservation (drawing the last of the shared pool to do so),
    /// and every message after that is rejected once the shared pool is
    /// empty -- proving the flood is capped, not merely slowed. Crucially,
    /// the quiet peer's *second* message -- drawn from its own untouched
    /// reservation -- is still admitted afterward, even though the shared
    /// pool the noisy peer drained is completely empty. Nothing drains the
    /// queue in this test (orphaned, no consumer task), so this isolates
    /// the ERL gate's admission decisions from the `mpsc` channel and from
    /// any capacity the background worker's dequeue-time release would
    /// otherwise return.
    #[tokio::test]
    async fn backlog_peer_limiter_protects_reserved_share_from_a_flooding_peer() {
        let (pool, _calls) = make_pool();
        let limiter = Arc::new(TxBacklogPeerLimiter::new(
            4,
            2,
            std::time::Duration::from_secs(10),
        ));
        let (handler, mut rx) = make_peer_limited_handler(pool, limiter);

        // Quiet peer's first message: opens its reservation, consumes 1 of
        // its 2 reserved units.
        let quiet1 = make_payment_txn(1, 1);
        handler
            .handle(incoming(std::slice::from_ref(&quiet1), "1.1.1.1:4160"))
            .await;
        assert_eq!(
            handler.backlog_dropped_count(),
            0,
            "quiet peer's first message must be admitted"
        );

        // Noisy peer floods 4 messages. Its first 2 open and fully drain
        // its own reservation (2 units, drawn from what's left of the
        // shared pool: max_capacity(4) - quiet's reservation(2) = 2). The
        // remaining 2 fall through to the now-empty shared pool and are
        // dropped.
        for i in 0..4u8 {
            let noisy = make_payment_txn(100 + i, i);
            handler
                .handle(incoming(std::slice::from_ref(&noisy), "2.2.2.2:4160"))
                .await;
        }
        assert_eq!(
            handler.backlog_dropped_count(),
            2,
            "noisy peer's flood must be capped at its own reservation plus the drained shared pool"
        );

        // Quiet peer's second message draws from its own reservation's
        // last unit -- untouched by the noisy peer's flood -- and must
        // still be admitted despite the shared pool being fully drained.
        let quiet2 = make_payment_txn(2, 2);
        handler
            .handle(incoming(std::slice::from_ref(&quiet2), "1.1.1.1:4160"))
            .await;
        assert_eq!(
            handler.backlog_dropped_count(),
            2,
            "quiet peer's reserved second message must not be starved by the flood"
        );

        // Sanity: exactly 4 groups (quiet x2, noisy x2) actually reached
        // the backlog queue; the other 2 noisy groups never got that far.
        let mut senders = Vec::new();
        while let Ok(item) = rx.try_recv() {
            senders.push(item.sender);
        }
        assert_eq!(senders.len(), 4);
        assert_eq!(
            senders.iter().filter(|s| s.starts_with("1.1.1.1")).count(),
            2
        );
        assert_eq!(
            senders.iter().filter(|s| s.starts_with("2.2.2.2")).count(),
            2
        );
    }

    /// A capacity unit consumed by the ERL gate but never actually
    /// enqueued (the `mpsc` channel itself was full) must be released
    /// immediately rather than leaked -- otherwise a peer's *next*
    /// legitimate message would incorrectly find its reservation still
    /// exhausted. Mirrors go's `processIncomingTxn` `defer` releasing
    /// `capguard` when `!accepted`.
    #[tokio::test]
    async fn backlog_peer_limiter_releases_capacity_when_mpsc_queue_is_full() {
        let (pool, _calls) = make_pool();
        // capacity_per_peer=1 so a single peer's reservation is exactly 1
        // unit -- easy to prove it comes back after a full-queue drop.
        let limiter = Arc::new(TxBacklogPeerLimiter::new(
            4,
            1,
            std::time::Duration::from_secs(10),
        ));
        let seen = Arc::new(SeenTxCache::new(1024));
        // A capacity-1 `mpsc` channel, orphaned (nothing drains it), so
        // the *second* message from the same peer is ERL-admitted (it has
        // no reservation yet on the first call, so the first call opens
        // one and drains it into the channel) but then rejected by the
        // full `mpsc` channel.
        let (tx, mut rx) = mpsc::channel(1);
        let mut handler = TxTagHandler::new(pool, seen).with_backlog_peer_limiter(limiter.clone());
        handler.backlog_tx = Some(tx);

        let tx1 = make_payment_txn(1, 1);
        handler
            .handle(incoming(std::slice::from_ref(&tx1), "1.1.1.1:4160"))
            .await;
        assert_eq!(handler.backlog_dropped_count(), 0, "first message admitted");

        // Second message from the same peer: its 1-unit reservation is
        // already exhausted (msg1 consumed it), so ERL falls back to the
        // shared pool -- which has room and admits it -- but the `mpsc`
        // channel is still full since nothing has drained msg1 out of it
        // yet, so this message is dropped there instead.
        let tx2 = make_payment_txn(2, 2);
        handler
            .handle(incoming(std::slice::from_ref(&tx2), "1.1.1.1:4160"))
            .await;
        assert_eq!(
            handler.backlog_dropped_count(),
            1,
            "second message dropped by the full mpsc channel"
        );

        // Drain the one item that did make it onto the queue.
        let queued = rx.try_recv().expect("first message reached the queue");
        assert_eq!(queued.sender, "1.1.1.1:4160");

        // If the second message's capacity unit was correctly released
        // back on the full-queue drop (rather than leaked), a *third*
        // message from the same peer -- after freeing `mpsc` capacity by
        // draining the first item above -- must be admitted again rather
        // than immediately rejected by a starved reservation.
        let tx3 = make_payment_txn(3, 3);
        handler
            .handle(incoming(std::slice::from_ref(&tx3), "1.1.1.1:4160"))
            .await;
        assert_eq!(
            handler.backlog_dropped_count(),
            1,
            "third message must be admitted once mpsc capacity is free again"
        );
    }
}
