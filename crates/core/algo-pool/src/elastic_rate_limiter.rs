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

//! Elastic per-client capacity reservation plus RED (Random Early
//! Detection) congestion management.
//!
//! Ports the *algorithm* of go-algorand's `util/rateLimit.go`
//! (`ElasticRateLimiter`, `ErlClient`, `capacityQueue`, `CongestionManager`,
//! `redCongestionManager`, `NewElasticRateLimiter`, `NewREDCongestionManager`)
//! — a capacity pool that (a) hands out small, per-client reserved slices of
//! a shared capacity budget so one noisy/malicious client cannot starve
//! everyone else, and (b) probabilistically pre-empts hard cliff-style
//! rejection by dropping requests from over-quota clients *before* the
//! shared pool is fully exhausted, proportional to how far over their fair
//! share of the pool's service rate they are.
//!
//! # Algorithm (mirrors go-algorand)
//!
//! * [`ElasticRateLimiter`] owns one shared [`CapacityQueue`] sized
//!   `max_capacity`, plus a `client -> CapacityQueue` map of per-client
//!   reservations sized `capacity_per_reservation`.
//! * [`ElasticRateLimiter::consume_capacity`] mirrors go's `ConsumeCapacity`
//!   exactly:
//!   1. If the client has no reservation yet *and* `capacity_per_reservation`
//!      is nonzero, open one ([`ElasticRateLimiter::open_reservation`] —
//!      moves `capacity_per_reservation` units out of the shared queue into
//!      a new reservation, guarded by the same "would this overcommit
//!      `max_capacity`" bookkeeping check as go's `openReservation`), then
//!      draw the client's very first unit directly from that reservation.
//!   2. Otherwise, try to draw from the client's existing reservation first
//!      — reserved capacity is *never* subject to congestion-manager
//!      dropping, only the shared pool is.
//!   3. If the reservation is empty (or the client has none), consult the
//!      [`CongestionManager`] (when congestion control is enabled) —
//!      [`CongestionManager::should_drop`] may refuse the request before it
//!      ever touches the shared queue.
//!   4. Otherwise draw from the shared queue.
//! * [`RedCongestionManager`] mirrors go's `redCongestionManager`:
//!   [`RedCongestionManager::consumed`]/[`RedCongestionManager::served`]
//!   record timestamped events (per-client arrivals, and total completions);
//!   [`RedCongestionManager::should_drop`] recomputes, over a sliding
//!   `window`, the *target rate* (average per-client share of the overall
//!   service rate: `serves_in_window / window_seconds / distinct_clients`)
//!   and each client's own arrival rate, then drops with probability
//!   `(arrival_rate / target_rate) ^ exp` (`exp = 4`, matching go, to sharply
//!   punish clients that are well over their fair share while barely
//!   throttling clients that are only slightly over).
//!
//! # Deliberate deviations from go-algorand
//!
//! * **Concurrency model.** go-algorand's `ElasticRateLimiter` moves
//!   capacity between queues via buffered Go channels drained by background
//!   goroutines (`capacityQueue.blockingConsume`/`blockingRelease`), and its
//!   `redCongestionManager` runs its own event-loop goroutine reading from
//!   `consumed`/`served`/`shouldDropQueries` channels, refreshing the target
//!   rate periodically (`targetRateRefreshTicks`) rather than on every
//!   query. This port is not wired into any live concurrent ingestion path
//!   (see "Wiring into algod-rust" below), so both types are plain
//!   synchronous structs guarded by a single [`parking_lot::Mutex`]:
//!   `open_reservation`/`close_reservation` move capacity immediately and
//!   non-blockingly (taking only what is currently available rather than
//!   go's blocking wait for capacity that doesn't yet exist), and
//!   `should_drop` recomputes the target rate fresh on every call instead of
//!   periodically. For the single-threaded call sequences this module's
//!   tests replay (which is also how a future wiring point would call
//!   these, one call at a time under whatever lock the caller already
//!   holds) the observable results are identical — this drops only the
//!   channel/goroutine plumbing, not the algorithm or its arithmetic.
//! * **No blocking wait on reservation open/close.** Because there is no
//!   background goroutine to eventually satisfy a blocked transfer, this
//!   port's `open_reservation` fills a new reservation with
//!   `min(capacity_per_reservation, currently_available_in_shared)` units
//!   rather than blocking until the full amount is available, and
//!   `close_reservation` returns to the shared pool whatever the closed
//!   reservation currently holds rather than blocking until any
//!   already-consumed-and-not-yet-released units trickle back in. Go's
//!   `MaxCapacity`-vs-reservation-count bookkeeping check (guarding against
//!   overcommitting the pool) is preserved unchanged.
//! * **`ErlClient::OnClose`** (go's hook so a reservation is closed
//!   automatically when the owning connection closes) is not ported —
//!   nothing in algod-rust yet owns the connection lifecycle this would
//!   attach to. Callers call [`ElasticRateLimiter::close_reservation`]
//!   directly, exactly as go-algorand's own tests do (`erl.closeReservation`
//!   is unexported and only ever driven by tests plus the `OnClose` hook
//!   this port omits).
//!
//! # Wiring into algod-rust's pull-based architecture (issues #821, #860)
//!
//! go-algorand's `ElasticRateLimiter`/RED pair guards `data/txHandler.go`'s
//! incoming-transaction backlog queue, which is fed by its push-based
//! gossip layer (peers unsolicitedly relay transactions to this node, and
//! the RED manager decides whether to admit each one *before* it reaches
//! the shared backlog channel). algod-rust's actual peer-to-peer
//! transaction path (`crates/node/algo-network/src/tx_syncer.rs`) is
//! pull-based (this node polls each peer's synced-transaction set on a
//! timer via `TxSyncer`/`SolicitedTxHandler`, mirroring the architectural
//! note already recorded in `app_rate_limiter.rs` for issue #821) rather
//! than being pushed transactions unsolicited. A pull-based node decides
//! *when* and *from whom* to ask for transactions in the first place, so
//! there is no reachable point in the sync loop's own request-issuing side
//! that receives an unsolicited, not-yet-admitted transaction the way go's
//! RED gate does — the congestion this algorithm exists to shed (an inbound
//! flood this node did not ask for) cannot occur on that side by
//! construction.
//!
//! Two wiring points were evaluated:
//!
//! 1. **REST submission admission** (`AlgodNodeInterface::reserve_async_backlog_permit`).
//!    Investigated and **rejected**: tracing go-algorand's actual
//!    `RawTransaction`/`RawTransactionAsync` handlers
//!    (`daemon/algod/api/server/v2/handlers.go`) confirms neither ever
//!    reaches `TxHandler.processIncomingTxn` — REST submission is a trusted
//!    local-client boundary go never rate-limits with RED or any other
//!    mechanism, categorically different from the untrusted peer-gossip
//!    boundary RED exists to protect. Wiring RED here would invent
//!    behavior go-algorand doesn't have, not port it.
//! 2. **Fairness across which peer's pull request this node services
//!    first**, when this node's own servicing capacity (pool
//!    snapshot/encoding/response bandwidth) is under pressure — the mirror
//!    image of go's inbound-admission gate rather than a direct port of
//!    it. This *is* implemented: see `TxSyncPeerLimiter`
//!    in `crates/node/algo-network/src/tx_sync_service.rs`, wired into
//!    `TxSyncService`'s HTTP endpoint (the server side that answers a
//!    peer's `POST .../txsync` pull request). It applies this module's
//!    per-client capacity-reservation model, keyed by the requesting
//!    peer's source IP, to that servicing capacity — so one peer polling
//!    aggressively cannot starve another peer's already-reserved share of
//!    this node's own resources — and dynamically toggles
//!    [`RedCongestionManager`] the same way go's
//!    `TxHandler.incomingMsgErlCheck` does (on when free shared capacity
//!    drops below a threshold, off on recovery). See that module's doc
//!    comment for the full fairness-property mapping and honest
//!    limitations, and its test module for coverage (peer-reservation
//!    isolation under a flooding peer, congestion-control auto-toggle, and
//!    end-to-end HTTP wiring).
//!
//! # References
//!
//! * `util/rateLimit.go` (`ElasticRateLimiter`, `ErlClient`,
//!   `NewElasticRateLimiter`, `ConsumeCapacity`, `openReservation`,
//!   `closeReservation`, `CongestionManager`, `redCongestionManager`,
//!   `NewREDCongestionManager`, `shouldDrop`, `prune`) — go-algorand
//!   commit `50d5dfde5` ("txHandler: Random Early Detection for backlog
//!   queue (#4797)"), first released in `v3.14.1-beta`.
//! * `util/rateLimit_test.go` (`TestNewElasticRateLimiter`,
//!   `TestElasticRateLimiterCongestionControlled`, `TestReservations`,
//!   `TestZeroSizeReservations`, `TestConsumeReleaseCapacity`,
//!   `TestREDCongestionManagerShouldDrop`,
//!   `TestREDCongestionManagerShouldntDrop`,
//!   `TestREDCongestionManagerTargetRate`, `TestREDCongestionManagerPrune`,
//!   `TestREDCongestionManagerStopStart`) — the TDD oracle for [`tests`]
//!   below.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use rand::Rng;

/// Errors raised while consuming or managing capacity. Mirrors go's
/// sentinel errors (`errConManDropped`, `errFailedConsume`,
/// `errERLReservationExists`, `errCapacityReturn`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ElasticRateLimiterError {
    /// The [`CongestionManager`] recommended dropping this request. Mirrors
    /// go's `errConManDropped`.
    #[error("congestion manager prevented client from consuming capacity")]
    CongestionDropped,
    /// Neither the client's reservation nor the shared pool had capacity
    /// available. Mirrors go's `errFailedConsume`.
    #[error("could not consume capacity from capacity queue")]
    NoCapacity,
    /// [`ElasticRateLimiter::open_reservation`] was called for a client
    /// that already has one. Mirrors go's `errERLReservationExists`.
    #[error("client already has a reservation")]
    ReservationExists,
    /// The reservation could not be opened because doing so would
    /// overcommit `max_capacity`. Mirrors go's `openReservation`'s
    /// "not enough capacity to reserve for client" error.
    #[error(
        "not enough capacity to reserve for client: {remaining} remaining, {requested} requested"
    )]
    InsufficientCapacity {
        /// Capacity units left unreserved before this request.
        remaining: usize,
        /// Capacity units this reservation would need.
        requested: usize,
    },
}

/// A bounded, non-blocking capacity counter. Mirrors go's
/// `capacityQueue` (a buffered `chan capacity`), minus the channel/goroutine
/// plumbing — see the module-level "Deliberate deviations" note.
#[derive(Debug, Clone, Copy)]
struct CapacityQueue {
    available: usize,
    max: usize,
}

impl CapacityQueue {
    fn new(max: usize, available: usize) -> Self {
        debug_assert!(available <= max);
        CapacityQueue { available, max }
    }

    fn len(&self) -> usize {
        self.available
    }

    /// Non-blocking consume: takes one unit if available. Mirrors go's
    /// `capacityQueue.consume`'s non-blocking `select`/`default` behavior.
    fn try_consume(&mut self) -> bool {
        if self.available > 0 {
            self.available -= 1;
            true
        } else {
            false
        }
    }

    /// Non-blocking release: returns one unit if there's room. Mirrors go's
    /// `ErlCapacityGuard.Release`'s non-blocking `select`/`default`
    /// behavior (`errCapacityReturn` on a full queue).
    fn try_release(&mut self) -> bool {
        if self.available < self.max {
            self.available += 1;
            true
        } else {
            false
        }
    }
}

/// Which queue a [`CapacityGuard`] draws capacity from, so `Release` returns
/// it to the right place. A reservation guard also remembers *whose*
/// reservation it came from — go's guard closes over the client's specific
/// channel directly; this port instead looks the client's queue back up by
/// key in [`ElasticRateLimiter::release`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum QueueKind<C> {
    Shared,
    Reservation(C),
}

/// Token returned by [`ElasticRateLimiter::consume_capacity`]; the caller
/// releases capacity back to its origin queue by calling
/// [`ElasticRateLimiter::release`] (or by calling
/// [`ElasticRateLimiter::served`], mirroring go's `ErlCapacityGuard.Served`,
/// once its underlying request is fully served). Mirrors go's
/// `ErlCapacityGuard`.
#[derive(Debug)]
pub struct CapacityGuard<C> {
    origin: QueueKind<C>,
    released: bool,
}

impl<C> CapacityGuard<C> {
    fn new(origin: QueueKind<C>) -> Self {
        CapacityGuard {
            origin,
            released: false,
        }
    }
}

/// Elastic, per-client capacity pool with optional RED congestion
/// management. Mirrors go's `ElasticRateLimiter`.
///
/// `C` is the client-identity type (go's `ErlClient` interface, here just a
/// hashable/cloneable key — see the module-level "Deliberate deviations"
/// note on why `OnClose` is not ported).
pub struct ElasticRateLimiter<C: Eq + Hash + Clone + Send + 'static> {
    max_capacity: usize,
    capacity_per_reservation: usize,
    shared_capacity: CapacityQueue,
    capacity_by_client: HashMap<C, CapacityQueue>,
    cm: Option<Box<dyn CongestionManager<C> + Send>>,
    enable_cm: bool,
}

impl<C: Eq + Hash + Clone + Send + 'static> ElasticRateLimiter<C> {
    /// Creates an `ElasticRateLimiter` with a fresh [`RedCongestionManager`]
    /// (`window`-second sliding window). Mirrors go's
    /// `NewElasticRateLimiter`. Congestion control is *disabled* by default
    /// (matching go's `enableCM` zero value) — call
    /// [`Self::enable_congestion_control`] to turn it on.
    pub fn new(max_capacity: usize, capacity_per_reservation: usize, window: Duration) -> Self {
        ElasticRateLimiter {
            max_capacity,
            capacity_per_reservation,
            shared_capacity: CapacityQueue::new(max_capacity, max_capacity),
            capacity_by_client: HashMap::new(),
            cm: Some(Box::new(RedCongestionManager::new(window))),
            enable_cm: false,
        }
    }

    /// Number of capacity units currently free in the shared pool. Test/
    /// introspection helper mirroring go's tests reading `len(erl.sharedCapacity)`.
    pub fn shared_capacity_len(&self) -> usize {
        self.shared_capacity.len()
    }

    /// Number of clients currently holding an open reservation. Mirrors
    /// go's tests reading `len(erl.capacityByClient)`.
    pub fn reservation_count(&self) -> usize {
        self.capacity_by_client.len()
    }

    /// Number of capacity units currently free in `client`'s reservation
    /// (`0` if it has none). Mirrors go's tests reading
    /// `len(erl.capacityByClient[client])`.
    pub fn client_capacity_len(&self, client: &C) -> usize {
        self.capacity_by_client
            .get(client)
            .map(CapacityQueue::len)
            .unwrap_or(0)
    }

    /// Turns on congestion-manager gating of the shared pool. Mirrors go's
    /// `EnableCongestionControl`.
    pub fn enable_congestion_control(&mut self) {
        self.enable_cm = true;
    }

    /// Turns off congestion-manager gating of the shared pool. Mirrors go's
    /// `DisableCongestionControl`.
    pub fn disable_congestion_control(&mut self) {
        self.enable_cm = false;
    }

    /// Replaces the congestion manager (test hook — go's tests assign
    /// `erl.cm = mockCongestionControl{}` directly).
    pub fn set_congestion_manager(&mut self, cm: Option<Box<dyn CongestionManager<C> + Send>>) {
        self.cm = cm;
    }

    /// Dispenses one capacity unit to `client`, opening a reservation first
    /// if the client doesn't have one yet and `capacity_per_reservation >
    /// 0`. Mirrors go's `ConsumeCapacity` step-for-step (see the
    /// module-level algorithm summary). Returns the guard plus whether
    /// congestion control was enabled for this call (matching go's 3-tuple
    /// return), or an [`ElasticRateLimiterError`] if no capacity could be
    /// vended.
    pub fn consume_capacity(
        &mut self,
        client: &C,
    ) -> (bool, Result<CapacityGuard<C>, ElasticRateLimiterError>) {
        let is_cm_enabled = self.enable_cm;

        // Step 0: open a reservation if the client doesn't have one yet.
        if !self.capacity_by_client.contains_key(client) && self.capacity_per_reservation > 0 {
            return match self.open_reservation(client) {
                Ok(()) => {
                    // Take the reservation's very first unit directly.
                    let q = self
                        .capacity_by_client
                        .get_mut(client)
                        .expect("just opened");
                    q.try_consume();
                    (
                        is_cm_enabled,
                        Ok(CapacityGuard::new(QueueKind::Reservation(client.clone()))),
                    )
                }
                Err(e) => (is_cm_enabled, Err(e)),
            };
        }

        // Step 1: attempt consumption from the client's reservation.
        if let Some(q) = self.capacity_by_client.get_mut(client) {
            if q.try_consume() {
                if let Some(cm) = &mut self.cm {
                    cm.consumed(client.clone(), Instant::now());
                }
                return (
                    is_cm_enabled,
                    Ok(CapacityGuard::new(QueueKind::Reservation(client.clone()))),
                );
            }
        }

        // Step 2: congestion-manager gate on the shared pool.
        if is_cm_enabled {
            if let Some(cm) = &mut self.cm {
                if cm.should_drop(client) {
                    return (
                        is_cm_enabled,
                        Err(ElasticRateLimiterError::CongestionDropped),
                    );
                }
            }
        }

        // Step 3: attempt consumption from the shared pool.
        if self.shared_capacity.try_consume() {
            if let Some(cm) = &mut self.cm {
                cm.consumed(client.clone(), Instant::now());
            }
            (is_cm_enabled, Ok(CapacityGuard::new(QueueKind::Shared)))
        } else {
            (is_cm_enabled, Err(ElasticRateLimiterError::NoCapacity))
        }
    }

    /// Returns `guard`'s capacity unit to its origin queue. Mirrors go's
    /// `ErlCapacityGuard.Release`.
    pub fn release(&mut self, guard: &mut CapacityGuard<C>) -> Result<(), ElasticRateLimiterError> {
        if guard.released {
            return Ok(());
        }
        let q = match &guard.origin {
            QueueKind::Shared => &mut self.shared_capacity,
            QueueKind::Reservation(client) => match self.capacity_by_client.get_mut(client) {
                Some(q) => q,
                // The client has since closed its reservation — nowhere to
                // return to; treat as a no-op success like go's guard
                // holding a nil channel.
                None => {
                    guard.released = true;
                    return Ok(());
                }
            },
        };
        if q.try_release() {
            guard.released = true;
            Ok(())
        } else {
            Err(ElasticRateLimiterError::NoCapacity)
        }
    }

    /// Notifies the congestion manager that a served request completed,
    /// informing the service rate. Mirrors go's `ErlCapacityGuard.Served`.
    pub fn served(&mut self, now: Instant) {
        if let Some(cm) = &mut self.cm {
            cm.served(now);
        }
    }

    /// Opens a reservation for `client`, moving up to
    /// `capacity_per_reservation` units out of the shared pool. Mirrors
    /// go's `openReservation` (see the module-level "no blocking wait"
    /// deviation note for why this takes only currently-available units
    /// instead of blocking).
    fn open_reservation(&mut self, client: &C) -> Result<(), ElasticRateLimiterError> {
        if self.capacity_by_client.contains_key(client) {
            return Err(ElasticRateLimiterError::ReservationExists);
        }
        let remaining = self
            .max_capacity
            .saturating_sub(self.capacity_per_reservation * self.capacity_by_client.len());
        if self.capacity_per_reservation > remaining {
            return Err(ElasticRateLimiterError::InsufficientCapacity {
                remaining,
                requested: self.capacity_per_reservation,
            });
        }
        let mut q = CapacityQueue::new(self.capacity_per_reservation, 0);
        for _ in 0..self.capacity_per_reservation {
            if !self.shared_capacity.try_consume() {
                break;
            }
            q.try_release();
        }
        self.capacity_by_client.insert(client.clone(), q);
        Ok(())
    }

    /// Closes `client`'s reservation, returning whatever capacity it
    /// currently holds to the shared pool. Mirrors go's `closeReservation`
    /// (see the module-level "no blocking wait" deviation note).
    pub fn close_reservation(&mut self, client: &C) {
        let Some(q) = self.capacity_by_client.remove(client) else {
            return;
        };
        for _ in 0..q.len() {
            if !self.shared_capacity.try_release() {
                break;
            }
        }
    }
}

/// `Consumed`/`Served` event-recording plus RED drop decisions. Mirrors
/// go's `CongestionManager` interface + `redCongestionManager`.
pub trait CongestionManager<C> {
    /// Records that `client` consumed one unit of capacity at `t`.
    fn consumed(&mut self, client: C, t: Instant);
    /// Records that a request was fully served at `t`.
    fn served(&mut self, t: Instant);
    /// Returns whether `client`'s next request should be dropped.
    fn should_drop(&mut self, client: &C) -> bool;
}

/// "Random Early Detection" congestion manager: recommends dropping
/// requests from a client proportional to how far its own arrival rate
/// exceeds the pool's fair per-client target rate. Mirrors go's
/// `redCongestionManager` — see the module-level algorithm summary and
/// "Deliberate deviations" note (synchronous recompute-on-query instead of
/// a periodically-refreshing background goroutine).
pub struct RedCongestionManager<C> {
    window: Duration,
    /// Exponential contrast factor applied to the arrival/target ratio.
    /// `4`, matching go's `exp`.
    exp: f64,
    consumed_by_client: HashMap<C, Vec<Instant>>,
    serves: Vec<Instant>,
    target_rate: f64,
}

impl<C: Eq + Hash + Clone> RedCongestionManager<C> {
    /// Creates a `RedCongestionManager` with the given sliding `window`.
    /// Mirrors go's `NewREDCongestionManager` (the `bsize` parameter there
    /// only sizes internal channel buffers and the refresh-tick cadence,
    /// both dropped in this synchronous port, so it is not needed here).
    pub fn new(window: Duration) -> Self {
        RedCongestionManager {
            window,
            exp: 4.0,
            consumed_by_client: HashMap::new(),
            serves: Vec::new(),
            target_rate: 0.0,
        }
    }

    /// Clears all recorded state. Mirrors go's `Start()` implicitly
    /// resetting its event-loop's local accumulators on each new run —
    /// see the module-level "Deliberate deviations" note. A no-op
    /// synchronous port has no background loop to start, but tests
    /// (`TestREDCongestionManagerStopStart`) rely on `Start` resetting
    /// state after a prior `Stop`, so this port exposes that reset
    /// explicitly.
    pub fn start(&mut self) {
        self.consumed_by_client.clear();
        self.serves.clear();
        self.target_rate = 0.0;
    }

    /// No-op in this synchronous port (there is no background loop to
    /// join) — kept for API parity with go's `Stop`.
    pub fn stop(&mut self) {}

    /// Current target rate (average per-client share of the service rate,
    /// as of the last recompute). Exposed for tests mirroring go's
    /// `red.targetRate`.
    pub fn target_rate(&self) -> f64 {
        self.target_rate
    }

    /// Number of recorded arrivals still within the window for `client`.
    /// Exposed for tests mirroring go's `len(*red.consumedByClient[client])`.
    pub fn consumed_count(&self, client: &C) -> usize {
        self.consumed_by_client
            .get(client)
            .map(Vec::len)
            .unwrap_or(0)
    }

    /// Number of recorded serves still within the window. Exposed for
    /// tests mirroring go's `len(red.serves)`.
    pub fn serves_count(&self) -> usize {
        self.serves.len()
    }

    /// `client`'s arrival rate (events/second) over the window, pruning
    /// stale entries first. Mirrors go's `arrivalRateFor`.
    pub fn arrival_rate_for(&mut self, client: &C, now: Instant) -> f64 {
        self.prune(now);
        self.arrival_rate_for_unpruned(client)
    }

    fn arrival_rate_for_unpruned(&self, client: &C) -> f64 {
        match self.consumed_by_client.get(client) {
            Some(ts) if !ts.is_empty() => ts.len() as f64 / self.window.as_secs_f64(),
            _ => 0.0,
        }
    }

    fn prune(&mut self, now: Instant) {
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        self.serves.retain(|t| *t > cutoff);
        self.consumed_by_client.retain(|_, ts| {
            ts.retain(|t| *t > cutoff);
            !ts.is_empty()
        });
        self.recompute_target_rate();
    }

    fn recompute_target_rate(&mut self) {
        if self.consumed_by_client.is_empty() {
            self.target_rate = 0.0;
            return;
        }
        let service_rate = self.serves.len() as f64 / self.window.as_secs_f64();
        self.target_rate = service_rate / self.consumed_by_client.len() as f64;
    }
}

impl<C: Eq + Hash + Clone> CongestionManager<C> for RedCongestionManager<C> {
    fn consumed(&mut self, client: C, t: Instant) {
        self.consumed_by_client.entry(client).or_default().push(t);
    }

    fn served(&mut self, t: Instant) {
        self.serves.push(t);
    }

    /// Mirrors go's `shouldDrop`: prunes stale entries, recomputes the
    /// target rate, then drops with probability
    /// `(arrival_rate / target_rate) ^ exp` — never dropping a client with
    /// zero recorded arrivals ("never seen"), and never dropping while
    /// `target_rate` is `0` (insufficient data).
    fn should_drop(&mut self, client: &C) -> bool {
        self.prune(Instant::now());
        let arrival_rate = self.arrival_rate_for_unpruned(client);
        if arrival_rate == 0.0 || self.target_rate == 0.0 {
            return false;
        }
        let r: f64 = rand::thread_rng().gen();
        (arrival_rate / self.target_rate).powf(self.exp) > r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct MockClient(&'static str);

    /// Mirrors go's `mockCongestionControl`: `ShouldDrop` always `true`,
    /// everything else a no-op.
    struct MockCongestionControl;

    impl<C> CongestionManager<C> for MockCongestionControl {
        fn consumed(&mut self, _client: C, _t: Instant) {}
        fn served(&mut self, _t: Instant) {}
        fn should_drop(&mut self, _client: &C) -> bool {
            true
        }
    }

    // ---- ElasticRateLimiter -------------------------------------------

    /// Ports go's `TestNewElasticRateLimiter` (rateLimit_test.go:42).
    #[test]
    fn new_elastic_rate_limiter() {
        let erl: ElasticRateLimiter<MockClient> =
            ElasticRateLimiter::new(100, 10, Duration::from_secs(1));
        assert_eq!(erl.shared_capacity_len(), 100);
        assert_eq!(erl.reservation_count(), 0);
    }

    /// Ports go's `TestElasticRateLimiterCongestionControlled`
    /// (rateLimit_test.go:50). Uses a mock congestion manager
    /// (`ShouldDrop` always `true`) exactly like go's test, so the
    /// synchronous port's step-by-step results line up with go's
    /// (post-sleep) assertions without needing any sleeps.
    #[test]
    fn congestion_controlled() {
        let client = MockClient("client");
        let mut erl: ElasticRateLimiter<MockClient> =
            ElasticRateLimiter::new(3, 2, Duration::from_secs(1));
        // Swap in the mock congestion manager, exactly like go's test does
        // with `erl.cm = mockCongestionControl{}` (`ShouldDrop` always
        // `true`, everything else a no-op).
        erl.set_congestion_manager(Some(Box::new(MockCongestionControl)));

        let (_, res) = erl.consume_capacity(&client);
        res.expect("first consume opens a reservation");
        assert_eq!(erl.client_capacity_len(&client), 1);
        assert_eq!(erl.shared_capacity_len(), 1);

        erl.enable_congestion_control();
        // Reservation still has 1 unit — Step 1 succeeds before ever
        // consulting the congestion manager, matching go.
        let (_, res) = erl.consume_capacity(&client);
        res.expect("reservation still has capacity");
        assert_eq!(erl.client_capacity_len(&client), 0);
        assert_eq!(erl.shared_capacity_len(), 1);

        // Reservation now empty: falls through to the (always-drop) mock
        // congestion manager.
        let (_, res) = erl.consume_capacity(&client);
        assert!(matches!(
            res,
            Err(ElasticRateLimiterError::CongestionDropped)
        ));
        assert_eq!(erl.client_capacity_len(&client), 0);
        assert_eq!(erl.shared_capacity_len(), 1);

        erl.disable_congestion_control();
        let (_, res) = erl.consume_capacity(&client);
        res.expect("congestion control disabled, shared pool has capacity");
        assert_eq!(erl.client_capacity_len(&client), 0);
        assert_eq!(erl.shared_capacity_len(), 0);
    }

    /// Ports go's `TestReservations` (rateLimit_test.go:83).
    #[test]
    fn reservations() {
        let client1 = MockClient("client1");
        let client2 = MockClient("client2");
        let mut erl: ElasticRateLimiter<MockClient> =
            ElasticRateLimiter::new(4, 1, Duration::from_secs(1));

        let (_, res) = erl.consume_capacity(&client1);
        res.expect("client1 opens a reservation");
        assert_eq!(erl.reservation_count(), 1);

        let (_, res) = erl.consume_capacity(&client2);
        res.expect("client2 opens a reservation");
        assert_eq!(erl.reservation_count(), 2);

        erl.close_reservation(&client1);
        assert_eq!(erl.reservation_count(), 1);
        erl.close_reservation(&client2);
        assert_eq!(erl.reservation_count(), 0);
    }

    /// Ports go's `TestZeroSizeReservations` (rateLimit_test.go:111).
    #[test]
    fn zero_size_reservations() {
        let client1 = MockClient("client1");
        let client2 = MockClient("client2");
        let mut erl: ElasticRateLimiter<MockClient> =
            ElasticRateLimiter::new(4, 0, Duration::from_secs(1));

        let (_, res) = erl.consume_capacity(&client1);
        res.expect("draws straight from shared pool");
        assert_eq!(erl.reservation_count(), 0);

        let (_, res) = erl.consume_capacity(&client2);
        res.expect("draws straight from shared pool");
        assert_eq!(erl.reservation_count(), 0);

        erl.close_reservation(&client1);
        assert_eq!(erl.reservation_count(), 0);
        erl.close_reservation(&client2);
        assert_eq!(erl.reservation_count(), 0);
    }

    /// Ports go's `TestConsumeReleaseCapacity` (rateLimit_test.go:133).
    #[test]
    fn consume_release_capacity() {
        let client = MockClient("client");
        let mut erl: ElasticRateLimiter<MockClient> =
            ElasticRateLimiter::new(4, 3, Duration::from_secs(1));

        let (_, res1) = erl.consume_capacity(&client);
        let mut c1 = res1.expect("opens reservation, consumes first unit");
        assert_eq!(erl.client_capacity_len(&client), 2);
        assert_eq!(erl.shared_capacity_len(), 1);

        let (_, res) = erl.consume_capacity(&client);
        res.expect("reservation has capacity");
        assert_eq!(erl.client_capacity_len(&client), 1);
        assert_eq!(erl.shared_capacity_len(), 1);

        let (_, res) = erl.consume_capacity(&client);
        res.expect("reservation has capacity");
        assert_eq!(erl.client_capacity_len(&client), 0);
        assert_eq!(erl.shared_capacity_len(), 1);

        let (_, res4) = erl.consume_capacity(&client);
        let mut c4 = res4.expect("reservation empty, falls back to shared pool");
        assert_eq!(erl.client_capacity_len(&client), 0);
        assert_eq!(erl.shared_capacity_len(), 0);

        let (_, res) = erl.consume_capacity(&client);
        assert!(matches!(res, Err(ElasticRateLimiterError::NoCapacity)));
        assert_eq!(erl.client_capacity_len(&client), 0);
        assert_eq!(erl.shared_capacity_len(), 0);

        erl.release(&mut c1).expect("reservation has room");
        assert_eq!(erl.client_capacity_len(&client), 1);
        assert_eq!(erl.shared_capacity_len(), 0);

        erl.release(&mut c4).expect("shared pool has room");
        assert_eq!(erl.client_capacity_len(&client), 1);
        assert_eq!(erl.shared_capacity_len(), 1);
    }

    // ---- RedCongestionManager -------------------------------------------

    /// Ports go's `TestREDCongestionManagerShouldDrop`
    /// (rateLimit_test.go:181).
    #[test]
    fn red_should_drop() {
        let client = MockClient("client");
        let other = MockClient("other");
        let mut red: RedCongestionManager<MockClient> =
            RedCongestionManager::new(Duration::from_secs(10));
        let now = Instant::now();

        for _ in 0..10 {
            red.consumed(client, now);
        }
        for _ in 0..9 {
            red.served(now);
        }

        // Arrival rate for `client` is 10/10s = 1/s; service rate is
        // 9/10s = 0.9/s over 1 distinct client, so target rate is 0.9/s.
        // (1/0.9)^4 > any r in [0,1) — always drop.
        for _ in 0..100 {
            assert!(red.should_drop(&client));
        }
        // `other` has never consumed — never dropped.
        for _ in 0..10 {
            assert!(!red.should_drop(&other));
        }

        assert_eq!(red.consumed_count(&client), 10);
        assert_eq!(red.arrival_rate_for(&client, now), 1.0);
        assert_eq!(red.arrival_rate_for(&other, now), 0.0);
        assert_eq!(red.target_rate(), 0.9);
    }

    /// Ports go's `TestREDCongestionManagerShouldntDrop`
    /// (rateLimit_test.go:217).
    #[test]
    fn red_shouldnt_drop() {
        let client = MockClient("client");
        let mut red: RedCongestionManager<MockClient> =
            RedCongestionManager::new(Duration::from_secs(10));
        let now = Instant::now();

        red.consumed(client, now);
        for _ in 0..10_000 {
            red.served(now);
        }

        // Arrival rate 1/10 = 0.1/s; service rate 10000/10 = 1000/s over 1
        // client, so target rate 1000/s. (0.1/1000)^4 is astronomically
        // small — essentially never drops.
        for _ in 0..10 {
            assert!(!red.should_drop(&client));
        }

        assert_eq!(red.consumed_count(&client), 1);
        assert_eq!(red.serves_count(), 10_000);
        assert_eq!(red.arrival_rate_for(&client, now), 0.1);
        assert_eq!(red.target_rate(), 1000.0);
    }

    /// Ports go's `TestREDCongestionManagerTargetRate`
    /// (rateLimit_test.go:249).
    #[test]
    fn red_target_rate() {
        let client = MockClient("client");
        let mut red: RedCongestionManager<MockClient> =
            RedCongestionManager::new(Duration::from_secs(10));
        let now = Instant::now();

        red.consumed(client, now);
        red.consumed(client, now);
        red.consumed(client, now);
        red.served(now);
        red.served(now);
        red.served(now);

        assert_eq!(red.arrival_rate_for(&client, now), 0.3);
        assert_eq!(red.target_rate(), 0.3);
    }

    /// Ports go's `TestREDCongestionManagerPrune` (rateLimit_test.go:267).
    #[test]
    fn red_prune() {
        let client = MockClient("client");
        let mut red: RedCongestionManager<MockClient> =
            RedCongestionManager::new(Duration::from_secs(10));
        let now = Instant::now();
        let stale = now - Duration::from_secs(11);

        red.consumed(client, stale);
        red.consumed(client, stale);
        red.consumed(client, stale);
        red.consumed(client, now);
        red.served(stale);
        red.served(stale);
        red.served(stale);
        red.served(now);

        assert_eq!(red.arrival_rate_for(&client, now), 0.1);
        assert_eq!(red.target_rate(), 0.1);
    }

    /// Ports go's `TestREDCongestionManagerStopStart`
    /// (rateLimit_test.go:287).
    #[test]
    fn red_stop_start() {
        let client = MockClient("client");
        let mut red: RedCongestionManager<MockClient> =
            RedCongestionManager::new(Duration::from_secs(10));
        let now = Instant::now();

        red.consumed(client, now);
        red.consumed(client, now);
        red.consumed(client, now);
        red.served(now);
        red.served(now);
        red.served(now);
        assert_eq!(red.arrival_rate_for(&client, now), 0.3);
        assert_eq!(red.target_rate(), 0.3);
        red.stop();

        // Restart resets accumulated state, matching go's fresh event-loop
        // local variables on each Start().
        red.start();
        red.consumed(client, now);
        red.consumed(client, now);
        red.served(now);
        red.served(now);
        red.served(now);
        red.served(now);
        assert_eq!(red.arrival_rate_for(&client, now), 0.2);
        assert_eq!(red.target_rate(), 0.4);
        red.stop();
    }
}
