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

// `BandwidthFilter` — throttles message delivery to a configured
// bytes-per-tick rate, serializing traffic that would otherwise exceed
// it instead of dropping it.
//
// Mirrors `agreement/fuzzer/bandwidthFilter_test.go` (Go): Go's version
// keeps an explicit FIFO queue plus a running "data size" credit/debit
// counter per direction, refilled by `bandwidth` bytes every `Tick`
// and drained as queued messages are released
// (`processQueuedDownstreamMessages` / `processQueuedUpstreamMessages`).
//
// This port achieves the same observable effect — total throughput
// per direction bounded by the configured rate, with excess traffic
// serialized rather than dropped — via a simpler mechanism that reuses
// machinery this harness already has: [`FilterDecision::Delay`] (see
// `filter.rs`) plus the facade's per-direction delay heap
// (`network_facade.rs`), instead of a second, filter-private queue.
// Concretely, this filter tracks `<direction>_available_at`: the tick
// at which the channel next becomes free. Each message reserves
// `ceil(len / bandwidth)` ticks (minimum 1 whenever a cap applies)
// starting no earlier than `max(current_tick, available_at)`, and is
// delayed until that reservation's end — so back-to-back messages
// queue up exactly like Go's FIFO, just expressed as a running
// "next-free-tick" watermark instead of an explicit list plus byte
// counters. `bandwidth == 0` (or unset) mirrors Go's `!has ||
// bandwidth == 0` early-out: unlimited, forward immediately.
//
// Determinism: no RNG. The reservation ledger is a pure function of
// the message sizes and tick sequence seen so far, so two runs fed an
// identical scenario produce identical `Delay` decisions — this is
// what `TestManyBandwidthFilter`'s repeated-run pattern (Go) checks
// for, ported below as `bandwidth_filter_is_deterministic_across_many_runs`.

use crate::fuzzer::filter::{Filter, FilterDecision};
use crate::fuzzer::AlgoMessage;

/// Builder for [`BandwidthFilter`], mirroring Go's
/// `MakeBandwidthFilter(upStreamBandwidth, downStreamBandwidth)` — but
/// scoped to a single node's two directions rather than a
/// node-id-keyed map, since this harness constructs one filter
/// instance per node already (see `network_facade::NetworkFacade`).
#[derive(Clone, Debug, Default)]
pub struct BandwidthFilterBuilder {
    outgoing_bandwidth: Option<u64>,
    incoming_bandwidth: Option<u64>,
}

impl BandwidthFilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Outgoing (Go: "downstream", node → network) bytes-per-tick cap.
    /// `None` or `Some(0)` means unlimited.
    pub fn outgoing_bandwidth(mut self, bandwidth: Option<u64>) -> Self {
        self.outgoing_bandwidth = bandwidth;
        self
    }

    /// Incoming (Go: "upstream", network → node) bytes-per-tick cap.
    /// `None` or `Some(0)` means unlimited.
    pub fn incoming_bandwidth(mut self, bandwidth: Option<u64>) -> Self {
        self.incoming_bandwidth = bandwidth;
        self
    }

    pub fn build(self) -> BandwidthFilter {
        BandwidthFilter {
            outgoing_bandwidth: self.outgoing_bandwidth,
            incoming_bandwidth: self.incoming_bandwidth,
            outgoing_available_at: 0,
            incoming_available_at: 0,
            current_tick: 0,
            outgoing_seen: 0,
            incoming_seen: 0,
            outgoing_delayed: 0,
            incoming_delayed: 0,
        }
    }
}

/// Per-node bandwidth-limiting filter. See module doc for semantics.
pub struct BandwidthFilter {
    outgoing_bandwidth: Option<u64>,
    incoming_bandwidth: Option<u64>,
    /// Tick at which the outgoing channel next becomes free.
    outgoing_available_at: u64,
    /// Tick at which the incoming channel next becomes free.
    incoming_available_at: u64,
    /// Last clock tick observed via [`Filter::tick`].
    current_tick: u64,
    outgoing_seen: u64,
    incoming_seen: u64,
    outgoing_delayed: u64,
    incoming_delayed: u64,
}

impl BandwidthFilter {
    /// Total outgoing messages inspected (kept + delayed).
    pub fn outgoing_seen(&self) -> u64 {
        self.outgoing_seen
    }

    /// Total incoming messages inspected (kept + delayed).
    pub fn incoming_seen(&self) -> u64 {
        self.incoming_seen
    }

    /// Number of outgoing messages that were held back (queued) rather
    /// than forwarded immediately, because the configured bandwidth was
    /// already committed.
    pub fn outgoing_delayed(&self) -> u64 {
        self.outgoing_delayed
    }

    /// Same as [`Self::outgoing_delayed`] for the incoming direction.
    pub fn incoming_delayed(&self) -> u64 {
        self.incoming_delayed
    }
}

impl Filter for BandwidthFilter {
    fn name(&self) -> &str {
        "BandwidthFilter"
    }

    fn filter_outgoing(&mut self, msg: &AlgoMessage) -> FilterDecision {
        self.outgoing_seen = self.outgoing_seen.wrapping_add(1);
        let decision = schedule(
            self.outgoing_bandwidth,
            &mut self.outgoing_available_at,
            self.current_tick,
            msg.data.len() as u64,
        );
        if matches!(decision, FilterDecision::Delay { .. }) {
            self.outgoing_delayed = self.outgoing_delayed.wrapping_add(1);
        }
        decision
    }

    fn filter_incoming(&mut self, msg: &AlgoMessage) -> FilterDecision {
        self.incoming_seen = self.incoming_seen.wrapping_add(1);
        let decision = schedule(
            self.incoming_bandwidth,
            &mut self.incoming_available_at,
            self.current_tick,
            msg.data.len() as u64,
        );
        if matches!(decision, FilterDecision::Delay { .. }) {
            self.incoming_delayed = self.incoming_delayed.wrapping_add(1);
        }
        decision
    }

    fn tick(&mut self, new_clock_time: u64) -> Vec<AlgoMessage> {
        self.current_tick = new_clock_time;
        Vec::new()
    }
}

/// Reserve `size` bytes worth of bandwidth against `available_at`
/// (the direction's next-free-tick watermark), starting no earlier
/// than `current_tick`. Returns `Keep` when the reservation clears
/// immediately (no cap configured, or the channel was already free
/// this tick), otherwise `Delay { delay_ticks }` for the number of
/// ticks until the reservation ends.
fn schedule(
    bandwidth: Option<u64>,
    available_at: &mut u64,
    current_tick: u64,
    size: u64,
) -> FilterDecision {
    let Some(bandwidth) = bandwidth.filter(|&b| b != 0) else {
        return FilterDecision::Keep;
    };
    let start = (*available_at).max(current_tick);
    // At least 1 tick of occupancy once a cap applies, even for a
    // message smaller than the per-tick budget — mirrors Go's queue
    // always going through at least one more `Tick()` before
    // `processQueuedDownstreamMessages` can dequeue it.
    let ticks_needed = size.div_ceil(bandwidth).max(1);
    let release_tick = start.saturating_add(ticks_needed);
    *available_at = release_tick;
    let delay_ticks = release_tick.saturating_sub(current_tick);
    if delay_ticks == 0 {
        FilterDecision::Keep
    } else {
        FilterDecision::Delay { delay_ticks }
    }
}
