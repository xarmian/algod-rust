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

//! Application-call excessive-rate-limiter (ERL) algorithm.
//!
//! Ports the *algorithm* of go-algorand's `data/appRateLimiter.go`
//! (`appRateLimiter`, `makeAppRateLimiter`, `shouldDrop`/`shouldDropAt`,
//! `penalizeEvalError`, `txgroupToKeys`, `memhash64`) — a sliding-window
//! counter rate limiter keyed by `(app id, origin)` that admits or drops
//! application-call transaction groups, with an eval-error penalty that
//! lets misbehaving/buggy apps get rate limited faster than their raw
//! request volume would otherwise trigger.
//!
//! # Algorithm (mirrors go-algorand exactly)
//!
//! * The limiter is a sharded map of [`NUM_BUCKETS`] buckets. Each bucket
//!   is keyed by an 8-byte digest (`blake2b256(app_id_le || salt || origin)`
//!   truncated to 8 bytes) and holds up to `max_bucket_size` entries with
//!   LRU eviction (least-recently-*attempted* entry is evicted, "last use"
//!   is updated on every attempt, not just admission — see
//!   [`AppRateLimiter::should_drop_at`]).
//! * The bucket for a given app id is `memhash64(app_id, seed) % NUM_BUCKETS`
//!   (go's runtime `memhash64`, ported bit-for-bit including its multiplier
//!   constants) — hashing (rather than a plain modulo) avoids concentrating
//!   popular low-numbered app ids into a single bucket.
//! * Rate is tracked with a two-window (`prev`, `cur`) sliding counter per
//!   entry. `interval(now) = now_nanos / window_nanos` identifies the
//!   current fixed window; `fraction(now)` is how far into that window
//!   `now` is. The estimated current rate for an admission decision is
//!   `prev * (1 - fraction) + cur + 1` (linear decay of the previous
//!   window's count blended with the current window's count) — see
//!   [`AppRateLimiter::should_drop_keys`].
//! * `penalize_eval_error` — called when an application's approval/clear
//!   program evaluation errors — adds `max(1, service_rate_per_window / 4)`
//!   directly to `cur` for every app id touched by the group (the app
//!   itself, its foreign apps, and any apps named in its resource-access
//!   list), i.e. a flat 25%-of-window penalty per offending group,
//!   independent of how much of the group's own admission budget was
//!   already consumed.
//! * A **new** key (first time an app id + origin pair is seen in a
//!   bucket) is always admitted unconditionally — the rate check only
//!   applies to entries that already exist.
//!
//! # Deliberate deviations from go-algorand
//!
//! * **Locking granularity.** go-algorand's `appRateLimiterEntry` stores
//!   `prev`/`cur` as `atomic.Int64` specifically so that
//!   `shouldDropKeys`/`penalizeEvalError` can read/increment them *after*
//!   releasing the bucket mutex taken by `entry()`, to reduce lock
//!   contention on a live, concurrently-hammered gossip ingestion path.
//!   This port is not yet wired into any concurrent ingestion path (see
//!   "Wiring into algod-rust" below), so it holds the bucket's
//!   [`parking_lot::Mutex`] for the whole lookup-plus-decision critical
//!   section per key instead of splitting it. The admission algorithm,
//!   its constants, and its outputs for a given call sequence are
//!   unchanged; only the concurrency micro-optimization is dropped. A
//!   future wiring PR that puts this on a hot concurrent path should
//!   re-evaluate whether that optimization is worth reintroducing (it
//!   would require `Arc`-based entries so a caller can keep operating on
//!   an entry's counters after another thread evicts it from the bucket
//!   map).
//! * **Eviction bookkeeping.** go-algorand keeps `evictions`/`evictionTime`
//!   counters marked `// TODO: delete?`. This port keeps an `evictions`
//!   counter (useful for tests/metrics) but drops the eviction-duration
//!   timing, which go itself flags as dead weight.
//!
//! # Wiring into algod-rust (issue #821)
//!
//! This module is now wired into algod-rust's live transaction ingestion
//! path — [`crate::tx_tag_handler`] in `crates/node/algo-network`, via
//! [`TxTagHandler::with_app_rate_limiter`], attached in
//! `bin/algod-rust/src/commands/participate.rs`.
//!
//! ## Two prior investigation passes looked in the wrong place
//!
//! Two earlier passes on this issue (see the issue's own history)
//! considered only two candidate wiring points — algod-rust's REST
//! transaction-submission path, and its pull-based tx-syncer
//! (`crates/node/algo-network/src/tx_syncer.rs`) — and rejected both, the
//! second time concluding no legitimate wiring point existed at all.
//! Both candidates were the right *kind* of question (find go-algorand's
//! actual, current call sites for `incomingTxGroupAppRateLimit` and match
//! algod-rust's architecture to them) but missed a third candidate that
//! already existed in this repo: [`crate::tx_tag_handler::TxTagHandler`],
//! registered on `Tag::Transaction` for both the WS-gossip and libp2p P2P
//! transports (`bin/algod-rust/src/commands/participate.rs`). This is a
//! genuinely unsolicited, peer-pushed transaction ingestion path — a peer
//! relays a `TX`-tagged gossip message without algod-rust having asked
//! for it — the exact architectural analogue of go-algorand's
//! `TxHandler.processIncomingTxn`/`validateIncomingTxMessage`, the only
//! two call sites in go-algorand @ v5.0.0-stable (`data/txHandler.go`)
//! that invoke `incomingTxGroupAppRateLimit`/`appLimiter.shouldDrop`.
//!
//! ## Confirming go-algorand's own pull-sync path never calls this either
//!
//! Before wiring `TxTagHandler`, this third pass re-traced go-algorand's
//! actual pull-sync code (`data/txHandler.go`, `rpcs/txSyncer.go` @
//! v5.0.0-stable) to settle whether the prior conclusion — that
//! algod-rust's `tx_syncer.rs` (pull-based) has no legitimate wiring
//! point for this gate — still holds now that a genuine push-side
//! candidate exists:
//!
//! * go-algorand's own pull-based transaction sync — `rpcs.TxSyncer`,
//!   wired up in `node/node.go`'s `MakeTxSyncer(..., node.txHandler.SolicitedTxHandler(), ...)`
//!   — is precisely the go-algorand analogue of algod-rust's
//!   `tx_syncer.rs`: both poll peers on a timer and pull candidate
//!   transaction groups rather than being pushed them. `TxSyncer.sync`
//!   (`rpcs/txSyncer.go:166`) hands every pulled group to
//!   `data.SolicitedTxHandler.Handle`, whose sole implementation
//!   (`data/txHandler.go:978`, `solicitedTxHandler.Handle`) calls
//!   `handler.txHandler.processDecoded(txgroup)`.
//! * `processDecoded` (`data/txHandler.go:914-960`) runs
//!   `checkAlreadyCommitted` → `verify.PaysetGroups` →
//!   `handler.txPool.Remember` — the full admission sequence — and calls
//!   **neither** `incomingTxGroupAppRateLimit` **nor**
//!   `appLimiter.shouldDrop`/`penalizeEvalError` anywhere in that path.
//!   Compare this to the push path, `processIncomingTxn`
//!   (`data/txHandler.go:740-808`) and `validateIncomingTxMessage`
//!   (`data/txHandler.go:811-869`), both of which call
//!   `handler.incomingTxGroupAppRateLimit(unverifiedTxGroup, rawmsg.Sender)`
//!   before the group ever reaches the backlog queue, and
//!   `postProcessCheckedTxn` (`data/txHandler.go:407-464`), which calls
//!   `appLimiter.penalizeEvalError` on a `txPool.Remember` failure — but
//!   only `if handler.appLimiter != nil && !wi.rawmsg.Outgoing &&
//!   wi.rawmsg.Sender != nil`, i.e. only for messages that came in with a
//!   real gossip `Sender`. A pulled group handed to `processDecoded` never
//!   sets `rawmsg` at all (`solicitedTxHandler.Handle` calls
//!   `processDecoded(txgroup)` directly, not through a `txBacklogMsg` with
//!   a `rawmsg.Sender`), so it structurally cannot reach either check.
//! * `incomingTxGroupAppRateLimit` is additionally gated by
//!   `congestedARL := len(handler.backlogQueue) > handler.appLimiterBacklogThreshold`
//!   — a push-specific gossip-backlog-queue-depth signal with no
//!   analogue on a pull path at all.
//! * Confirmed empirically: every `TestTxHandlerAppRateLimiter*`/
//!   `TestAppRateLimiter_*` test in `data/txHandler_test.go` @
//!   v5.0.0-stable drives the limiter exclusively through
//!   `handler.processIncomingTxn(...)`; none exercise `processDecoded` or
//!   `SolicitedTxHandler`.
//!
//! So `tx_syncer.rs` correctly remains unwired — go-algorand's own close
//! structural analogue of a pull-sync mechanism (`TxSyncer` +
//! `SolicitedTxHandler`) deliberately never applies this gate either, in
//! the one version this project tracks (v5.0.0-stable). The earlier
//! passes' conclusion about the *pull* side was right; what they missed
//! was that algod-rust already has a genuine *push* side
//! (`TxTagHandler`) that go's gate does apply to.
//!
//! ## Wiring summary
//!
//! [`crate::tx_tag_handler`]'s module doc has the concrete design:
//! `TxTagHandler::with_app_rate_limiter` attaches a shared
//! [`AppRateLimiter`], the admission check runs once
//! `TransactionPool::pending_count()` exceeds a configured congestion
//! threshold (the analogue of go's backlog-queue-depth signal — see that
//! module for why pool occupancy is used instead), keyed by the sending
//! peer's IP (port stripped, the analogue of go's `RoutingAddr()`), and
//! `penalize_eval_error` is called on every `pool.remember` failure
//! (go additionally excludes `TxnDeadError`/`ErrEvaluatorCorruptedState`,
//! which algod-rust's `PoolError` has no equivalents for today — see that
//! module for the full deviation note). Config knobs
//! (`TxBacklogServiceRateWindowSeconds`, `TxBacklogAppTxRateLimiterMaxSize`,
//! `TxBacklogAppTxPerSecondRate`, `TxBacklogAppRateLimitingCongestionPct`,
//! `EnableTxBacklogAppRateLimiting`) are threaded through
//! `algo_config::Local` at their go-algorand v5.0.0-stable defaults.
//!
//! ## Investigated and rejected: wiring into the REST submission path
//!
//! A natural-looking candidate is algod-rust's REST transaction-submission
//! admission point (`bin/algod-rust/src/node_interface_impl.rs`'s
//! `AlgodNodeInterface::reserve_async_backlog_permit`, a flat
//! `tokio::sync::Semaphore` guarding
//! `NodeInterface::async_broadcast_signed_tx_group`) — unlike the tx-syncer,
//! it *is* a push-style entry point (an external caller hits `/v2/transactions`
//! unsolicited). It was investigated for this reason and rejected: it would
//! not be a faithful port, because go-algorand itself never applies
//! `appRateLimiter` (or the sibling `ElasticRateLimiter`/RED gate, see issue
//! #860) to REST-submitted transactions.
//!
//! Tracing go-algorand's own code confirms this:
//! * `daemon/algod/api/server/v2/handlers.go`'s `RawTransaction` (sync
//!   `POST /v2/transactions`) calls `node.BroadcastSignedTxGroup` →
//!   `node/node.go`'s `broadcastSignedTxGroup`, which calls
//!   `node.transactionPool.Remember` directly — it never touches
//!   `TxHandler` at all, so `appLimiter`/`erl` cannot apply.
//! * `RawTransactionAsync` (`POST /v2/transactions/async`) calls
//!   `node.AsyncBroadcastSignedTxGroup` → `data/txHandler.go`'s
//!   `TxHandler.LocalTransaction`, which pushes straight onto
//!   `handler.backlogQueue` with `rawmsg: &network.IncomingMessage{}`
//!   (`Sender == nil`) — bypassing `processIncomingTxn` entirely. Only
//!   `processIncomingTxn` calls `incomingTxGroupAppRateLimit`
//!   (`shouldDrop`) and the ERL capacity-guard check
//!   (`incomingMsgErlCheck`); `LocalTransaction`'s backlog item is
//!   processed straight to `postProcessCheckedTxn`, and even the
//!   eval-error *penalty* hook there is explicitly guarded by
//!   `wi.rawmsg.Sender != nil`, so a locally-submitted transaction can
//!   never penalize or be penalized by the app rate limiter.
//! * There is no rate-limiting middleware anywhere under
//!   `daemon/algod/api/` — a grep for `RateLimit`/`rateLimit` under
//!   `daemon/` in go-algorand @ v5.0.0-stable returns nothing.
//!
//! In other words, go-algorand treats a transaction submitted through its
//! own node's REST API as a **trusted local-client boundary**, categorically
//! different from an **untrusted peer-gossip boundary** — ARL/ERL exist
//! specifically to shed load and penalize misbehavior from the latter, and
//! go deliberately never subjects the former to either. Reusing
//! `AppRateLimiter::should_drop`/`penalize_eval_error` to gate
//! `reserve_async_backlog_permit` would therefore invent rate-limiting
//! behavior go-algorand does not have, not port behavior it does. The flat
//! `Semaphore` in `reserve_async_backlog_permit` remains the correct,
//! faithful analogue of go's un-gated `broadcastSignedTxGroup`/
//! `LocalTransaction` paths and is intentionally left unchanged.
//!
//! REST submission remains correctly ungated, matching go. `TxTagHandler`
//! — algod-rust's inbound gossip TX-tag handler for both the WS-gossip
//! and libp2p P2P transports — is the legitimate wiring point instead
//! (see "Wiring summary" above): it is a genuinely unsolicited,
//! peer-pushed ingestion path, the direct analogue of go's
//! `TxHandler.processIncomingTxn`/`validateIncomingTxMessage`, and is now
//! wired accordingly.
//!
//! # References
//!
//! * `data/appRateLimiter.go` (`makeAppRateLimiter`, `entry`, `interval`,
//!   `fraction`, `shouldDrop`/`shouldDropAt`/`shouldDropKeys`,
//!   `penalizeEvalError`, `txgroupToKeys`, `memhash64`, `rotl31`)
//! * `data/appRateLimiter_test.go` (`TestAppRateLimiter_*`) — the TDD
//!   oracle for [`tests`] below.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use parking_lot::Mutex;
use rand::RngCore;

use algo_types::{ResourceRef, SignedTransaction, TxnType};

/// Number of shards in the rate limiter's sharded map. Mirrors go's
/// `numBuckets = 128`.
pub const NUM_BUCKETS: usize = 128;

/// 8-byte digest key identifying an `(app id, origin)` pair within a
/// bucket. Mirrors go's `type keyType [8]byte`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AppKey([u8; 8]);

/// Per-`(app id, origin)` sliding-window counters plus LRU linkage.
/// Mirrors go's `appRateLimiterEntry`. `prev`/`cur` are plain `i64`
/// (not atomics) because, unlike go, this port always mutates them while
/// holding the owning bucket's mutex — see the module-level "Deliberate
/// deviations" note.
#[derive(Debug)]
struct Entry {
    /// Count accrued during the previous window.
    prev: i64,
    /// Count accrued during the current window.
    cur: i64,
    /// Numeric representation of the window this entry's `cur` belongs to.
    interval: i64,
    /// LRU linkage: neighbor closer to the tail (least recently used).
    lru_prev: Option<AppKey>,
    /// LRU linkage: neighbor closer to the head (most recently used).
    lru_next: Option<AppKey>,
}

impl Entry {
    fn new(interval: i64) -> Self {
        Entry {
            prev: 0,
            cur: 0,
            interval,
            lru_prev: None,
            lru_next: None,
        }
    }
}

/// One shard of the sharded rate-limiter map: an LRU-bounded
/// `HashMap<AppKey, Entry>` plus explicit doubly-linked LRU order (`head`
/// is most-recently-used, `tail` is least-recently-used / next to evict).
/// Mirrors go's `appRateLimiterBucket` (`entries` + `lru *util.List`).
#[derive(Debug, Default)]
struct Bucket {
    entries: HashMap<AppKey, Entry>,
    head: Option<AppKey>,
    tail: Option<AppKey>,
}

impl Bucket {
    /// Unlink `key` from the LRU list without removing it from `entries`.
    fn lru_unlink(&mut self, key: AppKey) {
        let (prev, next) = {
            let e = self.entries.get(&key).expect("key must be present");
            (e.lru_prev, e.lru_next)
        };
        match prev {
            Some(p) => self.entries.get_mut(&p).unwrap().lru_next = next,
            None => self.head = next,
        }
        match next {
            Some(n) => self.entries.get_mut(&n).unwrap().lru_prev = prev,
            None => self.tail = prev,
        }
    }

    /// Link `key` (already present in `entries`, with cleared LRU
    /// pointers) in as the new head (most recently used).
    fn lru_push_front(&mut self, key: AppKey) {
        let old_head = self.head;
        {
            let e = self.entries.get_mut(&key).unwrap();
            e.lru_prev = None;
            e.lru_next = old_head;
        }
        match old_head {
            Some(h) => self.entries.get_mut(&h).unwrap().lru_prev = Some(key),
            None => self.tail = Some(key),
        }
        self.head = Some(key);
    }

    /// Move an already-present entry to the front (most recently used).
    fn lru_move_to_front(&mut self, key: AppKey) {
        if self.head == Some(key) {
            return;
        }
        self.lru_unlink(key);
        self.lru_push_front(key);
    }

    /// Evict and remove the least-recently-used entry, if any. Returns the
    /// evicted key.
    fn evict_back(&mut self) -> Option<AppKey> {
        let tail = self.tail?;
        self.lru_unlink(tail);
        self.entries.remove(&tail);
        Some(tail)
    }
}

/// Sliding-window application-call rate limiter. Mirrors go's
/// `appRateLimiter`. See the module doc comment for the algorithm and its
/// deliberate deviations from go, and for the (unimplemented) wiring
/// sketch into algod-rust's pull-based tx-sync architecture.
pub struct AppRateLimiter {
    max_bucket_size: usize,
    service_rate_per_window: u64,
    service_rate_window: Duration,

    /// Seed for hashing an app id to a bucket index.
    seed: u64,
    /// Salt mixed into the per-`(app id, origin)` digest key.
    salt: [u8; 16],

    buckets: Vec<Mutex<Bucket>>,

    /// Number of LRU evictions performed since creation (informational;
    /// mirrors go's `evictions` counter — go itself flags this, and the
    /// eviction-duration counter it also keeps, as possibly dead weight).
    evictions: std::sync::atomic::AtomicU64,
}

impl AppRateLimiter {
    /// Create a new rate limiter.
    ///
    /// * `max_cache_size` — maximum total number of `(app id, origin)`
    ///   entries to keep across all buckets (memory bound). Mirrors go's
    ///   `maxCacheSize`.
    /// * `max_app_peer_rate` — maximum number of admitted requests per app
    ///   per origin per second. Mirrors go's `maxAppPeerRate`.
    /// * `service_rate_window` — the sliding window duration. Mirrors go's
    ///   `serviceRateWindow`.
    ///
    /// Mirrors go's `makeAppRateLimiter`.
    pub fn new(
        max_cache_size: usize,
        max_app_peer_rate: u64,
        service_rate_window: Duration,
    ) -> Self {
        // go computes `serviceRateWindow / time.Second` as an integer
        // division of durations (truncating toward zero), then multiplies
        // by `maxAppPeerRate`. Replicate that truncation exactly.
        let whole_seconds = service_rate_window.as_nanos() / Duration::from_secs(1).as_nanos();
        let service_rate_per_window = max_app_peer_rate * (whole_seconds as u64);

        let max_bucket_size = {
            let v = max_cache_size / NUM_BUCKETS;
            if v == 0 {
                2
            } else {
                v
            }
        };

        let mut rng = rand::thread_rng();
        let seed = rng.next_u64();
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);

        let buckets = (0..NUM_BUCKETS)
            .map(|_| Mutex::new(Bucket::default()))
            .collect();

        AppRateLimiter {
            max_bucket_size,
            service_rate_per_window,
            service_rate_window,
            seed,
            salt,
            buckets,
            evictions: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The interval (fixed-window number) containing `now_nanos`. Mirrors
    /// go's `interval`.
    fn interval(&self, now_nanos: i64) -> i64 {
        now_nanos / (self.service_rate_window.as_nanos() as i64)
    }

    /// Fraction (`[0, 1)`) of the current window elapsed at `now_nanos`.
    /// Mirrors go's `fraction`.
    fn fraction(&self, now_nanos: i64) -> f64 {
        let window_nanos = self.service_rate_window.as_nanos() as i64;
        (now_nanos.rem_euclid(window_nanos)) as f64 / window_nanos as f64
    }

    /// Get-or-create the entry for `key` in `bucket_idx`, applying LRU
    /// touch and interval-rollover bookkeeping. Mirrors go's `entry`.
    /// Returns `(prev, cur_before_this_call, existed)`; the caller is
    /// responsible for incrementing `cur` under the same lock (unlike go,
    /// which releases the lock between `entry()` and the counter
    /// increment — see the module-level deviation note).
    fn with_entry<R>(
        &self,
        bucket_idx: usize,
        key: AppKey,
        cur_interval: i64,
        f: impl FnOnce(&mut Entry, bool) -> R,
    ) -> R {
        let mut bucket = self.buckets[bucket_idx].lock();

        if bucket.entries.len() >= self.max_bucket_size && bucket.evict_back().is_some() {
            self.evictions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        let existed = bucket.entries.contains_key(&key);
        if existed {
            bucket.lru_move_to_front(key);

            let entry = bucket.entries.get_mut(&key).unwrap();
            match entry.interval {
                i if i == cur_interval => {
                    // same interval: leave prev/cur untouched
                }
                i if i == cur_interval - 1 => {
                    // contiguous interval: roll cur into prev
                    entry.prev = entry.cur;
                    entry.cur = 0;
                    entry.interval = cur_interval;
                }
                _ => {
                    // non-contiguous: reset entirely
                    entry.prev = 0;
                    entry.cur = 0;
                    entry.interval = cur_interval;
                }
            }
        } else {
            bucket.entries.insert(key, Entry::new(cur_interval));
            bucket.lru_push_front(key);
        }

        let entry = bucket.entries.get_mut(&key).unwrap();
        f(entry, existed)
    }

    /// Should the given transaction group be dropped, evaluated at the
    /// current wall-clock time? Mirrors go's `shouldDrop`.
    pub fn should_drop(&self, txgroup: &[SignedTransaction], origin: &[u8]) -> bool {
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        self.should_drop_at(txgroup, origin, now_nanos)
    }

    /// Same as [`Self::should_drop`] but takes the current time explicitly
    /// (for deterministic tests). Mirrors go's `shouldDropAt`.
    pub fn should_drop_at(
        &self,
        txgroup: &[SignedTransaction],
        origin: &[u8],
        now_nanos: i64,
    ) -> bool {
        let Some(keys) = txgroup_to_keys(txgroup, origin, self.seed, self.salt, NUM_BUCKETS) else {
            return false;
        };
        if keys.is_empty() {
            return false;
        }
        self.should_drop_keys(&keys, now_nanos)
    }

    fn should_drop_keys(&self, keys: &[(usize, AppKey)], now_nanos: i64) -> bool {
        let cur_interval = self.interval(now_nanos);
        let cur_fraction = self.fraction(now_nanos);

        for &(bucket_idx, key) in keys {
            let should_drop_this_key =
                self.with_entry(bucket_idx, key, cur_interval, |entry, existed| {
                    if !existed {
                        // new entry: always admit, do not rate-check.
                        entry.cur += 1;
                        return false;
                    }
                    let rate = (entry.prev as f64 * (1.0 - cur_fraction)) as i64 + entry.cur + 1;
                    if rate > self.service_rate_per_window as i64 {
                        return true;
                    }
                    entry.cur += 1;
                    false
                });
            if should_drop_this_key {
                return true;
            }
        }
        false
    }

    /// Penalize every app id touched by `txgroup` (the group's own app,
    /// its foreign apps, and any apps in its resource-access list) for an
    /// evaluation error, by adding `max(1, service_rate_per_window / 4)`
    /// to each app id's current-window counter. Mirrors go's
    /// `penalizeEvalError`.
    pub fn penalize_eval_error(&self, txgroup: &[SignedTransaction], origin: &[u8]) {
        let Some(keys) = txgroup_to_keys(txgroup, origin, self.seed, self.salt, NUM_BUCKETS) else {
            return;
        };
        if keys.is_empty() {
            return;
        }

        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        let cur_interval = self.interval(now_nanos);

        const PENALTY_FACTOR: i64 = 4;
        let penalty = (self.service_rate_per_window as i64 / PENALTY_FACTOR).max(1);

        for &(bucket_idx, key) in &keys {
            self.with_entry(bucket_idx, key, cur_interval, |entry, _existed| {
                entry.cur += penalty;
            });
        }
    }

    /// Total number of entries currently tracked across all buckets.
    /// Mirrors go's `len`.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.lock().entries.len()).sum()
    }

    /// Whether the limiter is tracking zero entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Convert a transaction group into `(bucket_index, key)` pairs, one per
/// distinct non-zero app id referenced by any application-call transaction
/// in the group (the transaction's own `application_id`, its
/// `foreign_apps`, and any app ids named in its resource-`access` list).
/// Returns `None` if the group contains no application-call transaction at
/// all (mirrors go's `nil` "hasApps == false" fast path). Mirrors go's
/// `txgroupToKeys`.
fn txgroup_to_keys(
    txgroup: &[SignedTransaction],
    origin: &[u8],
    seed: u64,
    salt: [u8; 16],
    num_buckets: usize,
) -> Option<Vec<(usize, AppKey)>> {
    let has_apps = txgroup
        .iter()
        .any(|stxn| stxn.txn.txn_type == TxnType::Appl);
    if !has_apps {
        return None;
    }

    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut out = Vec::new();

    let mut record = |app_id: u64| {
        if app_id != 0 && seen.insert(app_id) {
            let bucket = (memhash64(app_id, seed) % num_buckets as u64) as usize;
            let key = digest_key(app_id, salt, origin);
            out.push((bucket, key));
        }
    };

    for stxn in txgroup {
        if stxn.txn.txn_type != TxnType::Appl {
            continue;
        }
        record(stxn.txn.application_id);
        if let Some(foreign_apps) = &stxn.txn.foreign_apps {
            for &app_id in foreign_apps {
                record(app_id);
            }
        }
        if let Some(access) = &stxn.txn.access {
            for r in access {
                record_resource_app(r, &mut record);
            }
        }
    }

    Some(out)
}

/// Helper so the `record` closure (which borrows `seen`/`out` mutably) can
/// still be called from inside the `access` loop above.
fn record_resource_app(r: &ResourceRef, record: &mut impl FnMut(u64)) {
    if r.app != 0 {
        record(r.app);
    }
}

/// `blake2b256(app_id_le(8) || salt(16) || origin(<=16)) [:8]`. Mirrors
/// go's inline digest computation in `txgroupToKeys`.
fn digest_key(app_id: u64, salt: [u8; 16], origin: &[u8]) -> AppKey {
    let mut buf = [0u8; 8 + 16 + 16];
    buf[0..8].copy_from_slice(&app_id.to_le_bytes());
    buf[8..24].copy_from_slice(&salt);
    let copied = origin.len().min(16);
    buf[24..24 + copied].copy_from_slice(&origin[..copied]);
    let buf_len = 8 + 16 + copied;

    type Blake2b256 = Blake2b<U32>;
    let mut hasher = Blake2b256::new();
    hasher.update(&buf[..buf_len]);
    let hash = hasher.finalize();

    let mut key = [0u8; 8];
    key.copy_from_slice(&hash[..8]);
    AppKey(key)
}

// Multiplication constants for `memhash64`, ported bit-for-bit from go
// runtime's `src/runtime/hash64.go` (see
// https://go-review.googlesource.com/c/go/+/59352/4/src/runtime/hash64.go#96),
// as used by go-algorand's `data/appRateLimiter.go`.
const M1: u64 = 16877499708836156737;
const M2: u64 = 2820277070424839065;
const M3: u64 = 9497967016996688599;

/// go runtime's `memhash64`, ported bit-for-bit (wrapping arithmetic
/// throughout, matching Go's unsigned-overflow semantics).
fn memhash64(val: u64, seed: u64) -> u64 {
    let mut h = seed;
    h ^= val;
    h = rotl31(h.wrapping_mul(M1)).wrapping_mul(M2);
    h ^= h >> 29;
    h = h.wrapping_mul(M3);
    h ^= h >> 32;
    h
}

fn rotl31(x: u64) -> u64 {
    x.rotate_left(31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::Transaction;

    fn appl_txn(app_id: u64) -> SignedTransaction {
        let mut txn = Transaction {
            txn_type: TxnType::Appl,
            ..Default::default()
        };
        txn.application_id = app_id;
        SignedTransaction {
            txn,
            ..Default::default()
        }
    }

    fn appl_group(app_id: u64) -> Vec<SignedTransaction> {
        vec![appl_txn(app_id)]
    }

    #[test]
    fn make_initializes_buckets_and_bucket_size() {
        let rm = AppRateLimiter::new(10, 10, Duration::from_secs(1));
        assert_eq!(rm.max_bucket_size, 2);
        assert_ne!(
            rm.seed, 0,
            "seed should be randomized (astronomically unlikely to be 0)"
        );
        assert_ne!(rm.salt, [0u8; 16], "salt should be randomized");
        assert_eq!(rm.buckets.len(), NUM_BUCKETS);
    }

    #[test]
    fn no_apps_never_drops() {
        let rm = AppRateLimiter::new(10, 10, Duration::from_secs(1));
        let mut pay = Transaction {
            txn_type: TxnType::Pay,
            ..Default::default()
        };
        pay.txn_type = TxnType::Pay;
        let txns = vec![
            SignedTransaction {
                txn: Transaction {
                    txn_type: TxnType::Acfg,
                    ..Default::default()
                },
                ..Default::default()
            },
            SignedTransaction {
                txn: pay,
                ..Default::default()
            },
        ];
        assert!(!rm.should_drop(&txns, &[]));
    }

    /// Mirrors `TestAppRateLimiter_Basics`.
    #[test]
    fn basics() {
        let rate = 10u64;
        let window = Duration::from_secs(1);
        let rm = AppRateLimiter::new(512, rate, window);

        let txns = appl_group(1);
        let now = 0i64;
        assert!(!rm.should_drop_at(&txns, &[], now));

        for _ in 1..rate as i64 {
            assert!(!rm.should_drop_at(&txns, &[], now));
        }
        assert!(rm.should_drop_at(&txns, &[], now));
        assert_eq!(rm.len(), 1);

        // A single group with many refs to the SAME app cannot itself
        // exceed the rate (dedup within a group).
        let mut apptxn2 = Transaction {
            txn_type: TxnType::Appl,
            ..Default::default()
        };
        apptxn2.application_id = 2;
        let big_group: Vec<SignedTransaction> = (0..=rate)
            .map(|_| SignedTransaction {
                txn: apptxn2.clone(),
                ..Default::default()
            })
            .collect();
        assert!(!rm.should_drop_at(&big_group, &[], now));

        for _ in 0..rate - 1 {
            assert!(!rm.should_drop_at(&big_group, &[], now));
        }
        assert!(rm.should_drop_at(&big_group, &[], now));
        assert_eq!(rm.len(), 2);

        // Foreign apps referencing the SAME app id as the txn itself do
        // not multiply-count within one group either.
        let mut apptxn3 = Transaction {
            txn_type: TxnType::Appl,
            ..Default::default()
        };
        apptxn3.application_id = 3;
        apptxn3.foreign_apps = Some(vec![3; rate as usize]);
        let group3 = vec![SignedTransaction {
            txn: apptxn3,
            ..Default::default()
        }];
        assert!(!rm.should_drop_at(&group3, &[], now));
        for _ in 0..rate - 1 {
            assert!(!rm.should_drop_at(&group3, &[], now));
        }
        assert!(rm.should_drop_at(&group3, &[], now));
        assert_eq!(rm.len(), 3);
    }

    /// Mirrors `TestAppRateLimiter_Interval`: prev+cur decay approximation.
    #[test]
    fn interval_decay() {
        let rate = 10u64;
        let window = Duration::from_secs(10);
        let per_second_rate = window.as_secs() / rate;
        let rm = AppRateLimiter::new(512, per_second_rate, window);

        let txns = appl_group(1);
        // 11 seconds => 1 sec into a 10-sec interval (10% elapsed).
        let now = 11 * 1_000_000_000i64;

        for _ in 0..(0.8 * rate as f64) as i64 {
            assert!(!rm.should_drop_at(&txns, &[], now));
        }

        let next = now + window.as_nanos() as i64;
        for _ in 0..(0.3 * rate as f64) as i64 {
            assert!(!rm.should_drop_at(&txns, &[], next));
        }
        assert!(rm.should_drop_at(&txns, &[], next));
    }

    /// Mirrors `TestAppRateLimiter_IntervalAdmitted`: `cur` only accounts
    /// for admitted requests, never exceeds the rate even when hammered.
    #[test]
    fn interval_admitted_only() {
        let rate = 10u64;
        let window = Duration::from_secs(10);
        let per_second_rate = window.as_secs() / rate;
        let rm = AppRateLimiter::new(512, per_second_rate, window);

        let txns = appl_group(1);
        let now = 11 * 1_000_000_000i64;

        for _ in 0..rate {
            assert!(!rm.should_drop_at(&txns, &[], now));
        }
        assert!(rm.should_drop_at(&txns, &[], now));

        let keys = txgroup_to_keys(&txns, &[], rm.seed, rm.salt, NUM_BUCKETS).unwrap();
        assert_eq!(keys.len(), 1);
        let (b, k) = keys[0];
        let cur = rm.buckets[b].lock().entries.get(&k).unwrap().cur;
        assert_eq!(cur, rate as i64);
    }

    /// Mirrors `TestAppRateLimiter_IntervalSkip`: a fully-idle interval
    /// resets the budget.
    #[test]
    fn interval_skip_resets() {
        let rate = 10u64;
        let window = Duration::from_secs(10);
        let per_second_rate = window.as_secs() / rate;
        let rm = AppRateLimiter::new(512, per_second_rate, window);

        let txns = appl_group(1);
        let now = 11 * 1_000_000_000i64;

        for _ in 0..(0.8 * rate as f64) as i64 {
            assert!(!rm.should_drop_at(&txns, &[], now));
        }

        let next_next = now + 2 * window.as_nanos() as i64;
        for _ in 0..rate {
            assert!(!rm.should_drop_at(&txns, &[], next_next));
        }
        assert!(rm.should_drop_at(&txns, &[], next_next));
    }

    /// Mirrors `TestAppRateLimiter_PenalizeEvalError`.
    #[test]
    fn penalize_eval_error() {
        let window = Duration::from_secs(10);
        let per_window_rate = 200u64;
        let per_second_rate = per_window_rate / window.as_secs();
        let rm = AppRateLimiter::new(512, per_second_rate, window);

        let txns = appl_group(1);
        let keys = txgroup_to_keys(&txns, &[], rm.seed, rm.salt, NUM_BUCKETS).unwrap();
        assert_eq!(keys.len(), 1);
        let (b, k) = keys[0];

        let expected_penalty = (rm.service_rate_per_window / 4) as i64;

        rm.penalize_eval_error(&txns, &[]);
        assert_eq!(
            rm.buckets[b].lock().entries.get(&k).unwrap().cur,
            expected_penalty
        );

        rm.penalize_eval_error(&txns, &[]);
        assert_eq!(
            rm.buckets[b].lock().entries.get(&k).unwrap().cur,
            2 * expected_penalty
        );

        // Use real wall-clock time here so this falls in the same window
        // as the `penalize_eval_error` calls above (which use
        // `SystemTime::now()` internally) — mirrors go's test, which also
        // uses `time.Now().UnixNano()` for both.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap();
        let allowed = per_window_rate as i64 - 2 * expected_penalty;
        let mut executed = false;
        for _ in 0..allowed {
            assert!(!rm.should_drop_at(&txns, &[], now));
            executed = true;
        }
        assert!(executed);
        assert!(rm.should_drop_at(&txns, &[], now));

        // Multiple app ids in one group (own app + foreign apps) all get
        // penalized.
        let mut apptxn = Transaction {
            txn_type: TxnType::Appl,
            ..Default::default()
        };
        apptxn.application_id = 10;
        apptxn.foreign_apps = Some(vec![20, 30]);
        let group = vec![SignedTransaction {
            txn: apptxn,
            ..Default::default()
        }];

        let keys = txgroup_to_keys(&group, &[], rm.seed, rm.salt, NUM_BUCKETS).unwrap();
        assert_eq!(keys.len(), 3);

        rm.penalize_eval_error(&group, &[]);
        // 4 distinct apps total tracked now: 1, 10, 20, 30.
        assert_eq!(rm.len(), 4);

        for app_id in [10u64, 20, 30] {
            let keys =
                txgroup_to_keys(&appl_group(app_id), &[], rm.seed, rm.salt, NUM_BUCKETS).unwrap();
            let (b, k) = keys[0];
            assert_eq!(
                rm.buckets[b].lock().entries.get(&k).unwrap().cur,
                expected_penalty
            );
        }
    }

    /// Mirrors `TestAppRateLimiter_IPAddr`: different origins for the same
    /// app id are tracked independently.
    #[test]
    fn distinct_origins_tracked_independently() {
        let rate = 10u64;
        let window = Duration::from_secs(10);
        let per_second_rate = window.as_secs() / rate;
        let rm = AppRateLimiter::new(512, per_second_rate, window);

        let txns = appl_group(1);
        let now = 0i64;

        for _ in 0..rate {
            assert!(!rm.should_drop_at(&txns, &[1], now));
            assert!(!rm.should_drop_at(&txns, &[2], now));
        }
        assert!(rm.should_drop_at(&txns, &[1], now));
        assert!(rm.should_drop_at(&txns, &[2], now));
    }

    /// Mirrors `TestAppRateLimiter_MaxSize`: total entries stay capped.
    #[test]
    fn max_size_is_capped() {
        const BUCKET_SIZE: usize = 4;
        const SIZE: usize = BUCKET_SIZE * NUM_BUCKETS;
        let rm = AppRateLimiter::new(SIZE, 10, Duration::from_secs(10));

        for i in 1..=SIZE + 1 {
            assert!(!rm.should_drop(&appl_group(1), &[i as u8]));
        }
        let bucket = (memhash64(1, rm.seed) % NUM_BUCKETS as u64) as usize;
        assert_eq!(rm.buckets[bucket].lock().entries.len(), BUCKET_SIZE);

        let mut total = 0;
        for (i, b) in rm.buckets.iter().enumerate() {
            let n = b.lock().entries.len();
            total += n;
            if i != bucket {
                assert_eq!(n, 0);
            }
        }
        assert!(total <= SIZE);
    }

    /// Mirrors `TestAppRateLimiter_EvictOrder`: LRU order is respected.
    #[test]
    fn evict_order_is_lru() {
        const BUCKET_SIZE: usize = 4;
        const SIZE: usize = BUCKET_SIZE * NUM_BUCKETS;
        let rm = AppRateLimiter::new(SIZE, 10, Duration::from_secs(10));

        let bucket = (memhash64(1, rm.seed) % NUM_BUCKETS as u64) as usize;
        let mut keys = Vec::with_capacity(BUCKET_SIZE + 1);
        for i in 0..BUCKET_SIZE {
            let kb =
                txgroup_to_keys(&appl_group(1), &[i as u8], rm.seed, rm.salt, NUM_BUCKETS).unwrap();
            assert_eq!(kb.len(), 1);
            assert_eq!(kb[0].0, bucket);
            keys.push(kb[0].1);
            assert!(!rm.should_drop(&appl_group(1), &[i as u8]));
        }
        assert_eq!(rm.buckets[bucket].lock().entries.len(), BUCKET_SIZE);

        // One more distinct origin evicts the least-recently-used (keys[0]).
        assert!(!rm.should_drop(&appl_group(1), &[BUCKET_SIZE as u8]));

        let locked = rm.buckets[bucket].lock();
        assert_eq!(locked.entries.len(), BUCKET_SIZE);
        assert!(!locked.entries.contains_key(&keys[0]));
        for k in &keys[1..] {
            assert!(locked.entries.contains_key(k));
        }
        drop(locked);

        let mut total = 0;
        for (i, b) in rm.buckets.iter().enumerate() {
            let n = b.lock().entries.len();
            total += n;
            if i != bucket {
                assert_eq!(n, 0);
            }
        }
        assert!(total <= SIZE);
    }

    /// Mirrors `TestAppRateLimiter_TxgroupToKeys`.
    #[test]
    fn txgroup_to_keys_dedup_and_zero_handling() {
        let pay_group = vec![SignedTransaction {
            txn: Transaction {
                txn_type: TxnType::Pay,
                ..Default::default()
            },
            ..Default::default()
        }];
        assert!(txgroup_to_keys(&pay_group, &[], 123, [0u8; 16], 1).is_none());

        let mut apptxn = Transaction {
            txn_type: TxnType::Appl,
            ..Default::default()
        };
        apptxn.application_id = 0;
        apptxn.foreign_apps = Some(vec![0]);
        let mut group = vec![SignedTransaction {
            txn: apptxn.clone(),
            ..Default::default()
        }];
        let keys = txgroup_to_keys(&group, &[], 123, [0u8; 16], 1).unwrap();
        assert_eq!(keys.len(), 0);

        apptxn.application_id = 1;
        group[0].txn = apptxn.clone();
        let keys = txgroup_to_keys(&group, &[], 123, [0u8; 16], 1).unwrap();
        assert_eq!(keys.len(), 1);

        apptxn.foreign_apps = Some(vec![0, 1]);
        group[0].txn = apptxn.clone();
        let keys = txgroup_to_keys(&group, &[], 123, [0u8; 16], 1).unwrap();
        assert_eq!(
            keys.len(),
            1,
            "app id 1 already seen via ApplicationID, dedup'd"
        );

        apptxn.foreign_apps = Some(vec![0, 1, 2]);
        group[0].txn = apptxn.clone();
        let keys = txgroup_to_keys(&group, &[], 123, [0u8; 16], 1).unwrap();
        assert_eq!(keys.len(), 2);

        let mut apptxn2 = apptxn.clone();
        apptxn2.application_id = 2;
        group.push(SignedTransaction {
            txn: apptxn2.clone(),
            ..Default::default()
        });
        let keys = txgroup_to_keys(&group, &[], 123, [0u8; 16], 1).unwrap();
        assert_eq!(
            keys.len(),
            2,
            "app id 2 already seen via first txn's foreign_apps"
        );

        apptxn2.access = Some(vec![ResourceRef {
            app: 3,
            ..Default::default()
        }]);
        group.push(SignedTransaction {
            txn: apptxn2.clone(),
            ..Default::default()
        });
        let keys = txgroup_to_keys(&group, &[], 123, [0u8; 16], 1).unwrap();
        assert_eq!(keys.len(), 3, "new app id 3 from access list");

        apptxn2.access = Some(vec![
            ResourceRef {
                app: 3,
                ..Default::default()
            },
            ResourceRef {
                app: 2,
                ..Default::default()
            },
        ]);
        group.push(SignedTransaction {
            txn: apptxn2,
            ..Default::default()
        });
        let keys = txgroup_to_keys(&group, &[], 123, [0u8; 16], 1).unwrap();
        assert_eq!(
            keys.len(),
            3,
            "already-seen app id 2 in access list stays dedup'd"
        );
    }

    #[test]
    fn memhash64_matches_go_constants() {
        // Deterministic sanity check that memhash64 is a pure function of
        // (val, seed) and does not panic/overflow across the u64 range.
        let a = memhash64(1, 42);
        let b = memhash64(1, 42);
        let c = memhash64(2, 42);
        assert_eq!(a, b);
        assert_ne!(a, c);
        let _ = memhash64(u64::MAX, u64::MAX);
    }
}
