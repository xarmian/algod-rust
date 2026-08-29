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

// `MessageReorderingFilter` — buffers a small per-direction pool of
// in-flight messages and emits them out-of-insertion-order under a
// seeded RNG. Mirrors `agreement/fuzzer/messageReorderingFilter_test.go`.
//
// Behavior (per direction, configurable independently):
//   * `shuffle_size == 0` ⇒ no reordering; every message passes
//     through unchanged.
//   * `shuffle_size == N > 0` ⇒
//      1. Every observed message is appended to the pool, tagged
//         with the current scheduler tick.
//      2. While `pool.len() <= N`, the message is HELD (the filter
//         returns `Drop`); the harness gets nothing this call.
//      3. Once `pool.len() > N`, the filter picks a uniformly-random
//         index and emits THAT message in place of the current
//         arrival via `FilterDecision::Substitute { with: vec![picked] }`.
//
// Retention flush: every `tick(...)` call sweeps the pool and emits
// any message whose arrival tick is older than `max_retention_ticks`
// — mirrors Go's `MaxRetension` parameter at
// `messageReorderingFilter_test.go:32-34, 165-184`. Without this,
// the trailing `shuffle_size` messages would be permanently parked
// because the harness can't drive the chain to displace them via
// fresh arrivals after the test's send sequence ends.
//
// Determinism: each direction has its own `ChaCha8Rng`, seeded from
// the configured `u64`. We use `ChaCha8Rng` (not `StdRng`) because
// `StdRng`'s underlying algorithm is documented as subject to change
// across `rand` minor versions, while `ChaCha8Rng` is a named fixed
// algorithm — stable across `rand_chacha` versions, so a recorded
// fuzz seed replays identically after dependency upgrades.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::fuzzer::filter::{Filter, FilterDecision};
use crate::fuzzer::AlgoMessage;

/// Builder for [`MessageReorderingFilter`]. Independent shuffle sizes
/// and seeds per direction; a size of `0` disables reordering on
/// that direction.
#[derive(Clone, Debug, Default)]
pub struct MessageReorderingFilterBuilder {
    outgoing_shuffle_size: usize,
    incoming_shuffle_size: usize,
    outgoing_seed: u64,
    incoming_seed: u64,
    /// Maximum ticks a message may sit in the pool before being
    /// auto-flushed by `tick`. `0` disables retention flushing — the
    /// pool only releases via fresh-arrival displacement (used by
    /// the unit tests that want to assert the held-state directly).
    max_retention_ticks: u64,
}

impl MessageReorderingFilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the outgoing shuffle pool. `size = 0` disables
    /// reordering. The RNG is seeded with `seed`.
    pub fn outgoing(mut self, size: usize, seed: u64) -> Self {
        self.outgoing_shuffle_size = size;
        self.outgoing_seed = seed;
        self
    }

    /// Configure the incoming shuffle pool. Same caveats as
    /// [`Self::outgoing`].
    pub fn incoming(mut self, size: usize, seed: u64) -> Self {
        self.incoming_shuffle_size = size;
        self.incoming_seed = seed;
        self
    }

    /// Configure the maximum number of ticks a message may sit in
    /// the pool before being auto-flushed by [`MessageReorderingFilter::tick`].
    /// `0` (the default) disables retention flushing — useful for
    /// unit tests that assert the held-state directly. Mirrors Go's
    /// `MaxRetension` parameter at
    /// `messageReorderingFilter_test.go:32-34`.
    pub fn max_retention_ticks(mut self, ticks: u64) -> Self {
        self.max_retention_ticks = ticks;
        self
    }

    pub fn build(self) -> MessageReorderingFilter {
        MessageReorderingFilter {
            outgoing: ShufflePool::new(self.outgoing_shuffle_size, self.outgoing_seed),
            incoming: ShufflePool::new(self.incoming_shuffle_size, self.incoming_seed),
            max_retention_ticks: self.max_retention_ticks,
            current_tick: 0,
        }
    }
}

/// One in-pool entry — pairs the message with the tick at which the
/// filter first observed it (used for retention-based flush).
struct PendingMessage {
    arrival_tick: u64,
    message: AlgoMessage,
}

/// Per-direction shuffle pool — buffers up to `shuffle_size` messages
/// before emitting any; once full, every new arrival displaces a
/// random pool resident.
struct ShufflePool {
    shuffle_size: usize,
    rng: ChaCha8Rng,
    pool: Vec<PendingMessage>,
}

impl ShufflePool {
    fn new(shuffle_size: usize, seed: u64) -> Self {
        Self {
            shuffle_size,
            rng: ChaCha8Rng::seed_from_u64(seed),
            pool: Vec::new(),
        }
    }

    /// Process one message arrival and return the harness's decision.
    fn handle(&mut self, msg: &AlgoMessage, current_tick: u64) -> FilterDecision {
        if self.shuffle_size == 0 {
            return FilterDecision::Keep;
        }

        // Append the new arrival to the pool with its arrival tick.
        self.pool.push(PendingMessage {
            arrival_tick: current_tick,
            message: msg.clone(),
        });

        if self.pool.len() <= self.shuffle_size {
            return FilterDecision::Drop;
        }

        // Pool is over-full — pick a random resident to emit.
        let idx = self.rng.gen_range(0..self.pool.len());
        let displaced = self.pool.swap_remove(idx);
        FilterDecision::Substitute {
            with: vec![displaced.message],
        }
    }

    /// Sweep the pool for messages whose arrival_tick + max_retention_ticks
    /// is `< current_tick` (i.e. they have been pending for STRICTLY MORE
    /// than `max_retention_ticks` ticks) and return them.
    /// `max_retention_ticks == 0` disables retention entirely.
    ///
    /// Care: avoid `saturating_sub` for the cutoff. A naive
    /// `current_tick.saturating_sub(max_retention_ticks)` floors at
    /// zero when `current_tick < max_retention_ticks`, so a message
    /// with `arrival_tick == 0` would expire at `tick(1)` even with
    /// `max_retention_ticks == 4` — a 1-tick effective retention,
    /// not the configured 4. We instead bail early when the elapsed
    /// time can't possibly exceed the retention budget.
    fn flush_expired(&mut self, current_tick: u64, max_retention_ticks: u64) -> Vec<AlgoMessage> {
        if max_retention_ticks == 0 {
            return Vec::new();
        }
        // No message can have aged past `max_retention_ticks` if
        // we haven't reached at least `max_retention_ticks + 1`
        // ticks since clock zero — the earliest possible
        // `arrival_tick` is 0. Bail before computing the cutoff to
        // avoid `saturating_sub` clamping us into a premature flush.
        if current_tick <= max_retention_ticks {
            return Vec::new();
        }
        let cutoff = current_tick - max_retention_ticks; // > 0, no underflow.
        let mut out = Vec::new();
        // Walk from the back so swap_remove preserves earlier indices
        // for the not-yet-inspected entries.
        let mut i = self.pool.len();
        while i > 0 {
            i -= 1;
            if self.pool[i].arrival_tick < cutoff {
                let entry = self.pool.swap_remove(i);
                out.push(entry.message);
            }
        }
        out.reverse(); // restore arrival order for the emitted batch.
        out
    }

    /// Drain any messages still parked in the pool (used by the
    /// scaffold's escape hatch to assert no message is lost).
    fn drain(&mut self) -> Vec<AlgoMessage> {
        std::mem::take(&mut self.pool)
            .into_iter()
            .map(|p| p.message)
            .collect()
    }

    /// Snapshot the current pool size — exposed for white-box
    /// assertions in unit tests.
    fn pool_size(&self) -> usize {
        self.pool.len()
    }
}

/// Per-node reorder filter. See module doc for semantics.
pub struct MessageReorderingFilter {
    outgoing: ShufflePool,
    incoming: ShufflePool,
    max_retention_ticks: u64,
    current_tick: u64,
}

impl Filter for MessageReorderingFilter {
    fn name(&self) -> &str {
        "MessageReorderingFilter"
    }

    fn filter_outgoing(&mut self, msg: &AlgoMessage) -> FilterDecision {
        self.outgoing.handle(msg, self.current_tick)
    }

    fn filter_incoming(&mut self, msg: &AlgoMessage) -> FilterDecision {
        self.incoming.handle(msg, self.current_tick)
    }

    /// Advance the filter's clock and emit any messages whose arrival
    /// tick is now older than `max_retention_ticks`. Mirrors Go's
    /// `Tick` retention sweep at
    /// `messageReorderingFilter_test.go:159-214`.
    ///
    /// Both directions are flushed; emissions surface as outgoing
    /// (the `Filter::tick` return contract). The incoming side's
    /// flush therefore re-emits onto the wire — that's a known
    /// scope shortcut for the message-pump scaffold; the multi-
    /// Service follow-up will route incoming flushes into the local
    /// node's received log instead. The unit-test for retention only
    /// exercises the outgoing direction.
    fn tick(&mut self, new_clock_time: u64) -> Vec<AlgoMessage> {
        self.current_tick = new_clock_time;
        let mut out = self
            .outgoing
            .flush_expired(new_clock_time, self.max_retention_ticks);
        out.extend(
            self.incoming
                .flush_expired(new_clock_time, self.max_retention_ticks),
        );
        out
    }
}

impl MessageReorderingFilter {
    /// Drain everything still parked in either direction. Returns
    /// `(outgoing_pool_remainder, incoming_pool_remainder)`. Used at
    /// end-of-test by harness consumers that need to assert
    /// no-message-loss invariants when retention flushing is disabled.
    pub fn drain_pending(&mut self) -> (Vec<AlgoMessage>, Vec<AlgoMessage>) {
        (self.outgoing.drain(), self.incoming.drain())
    }

    /// Snapshot the current outgoing pool size — exposed for unit
    /// tests that want to assert the "messages 1..N stay buffered until
    /// N+1" invariant.
    pub fn outgoing_pool_size(&self) -> usize {
        self.outgoing.pool_size()
    }

    /// Snapshot the current incoming pool size.
    pub fn incoming_pool_size(&self) -> usize {
        self.incoming.pool_size()
    }
}
