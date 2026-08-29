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

// Per-node facade that owns the outgoing & incoming filter chains.
//
// Mirrors `agreement/fuzzer/networkFacade_test.go`. Each node owns one
// `NetworkFacade`; the `scheduler::Scheduler` calls into it for every
// outbound message the node produces and every inbound message the
// router has steered toward it.
//
// Filter chain semantics:
//   * Outgoing: head→tail. The first filter sees the original message;
//     each subsequent filter sees only what the previous one passed
//     through.
//   * Incoming: head→tail (same direction). Go's chain is wired so
//     receive flows in the *opposite* order to send, but our chain
//     applies in declared order in both directions — simpler to reason
//     about and adequate for the drop / duplicate filters this task
//     ships. If a future filter (e.g. reorder) needs reverse order
//     for receive, that's a follow-up refactor.
//
// `FilterDecision::Delay` enqueues the message in the per-direction
// `BinaryHeap<DelayedMessage>`. The scheduler calls `tick(...)` to
// advance the clock and pop everything whose `release_tick` has come
// due, re-feeding them to the *remaining* filters in the chain.

use std::collections::BinaryHeap;

use super::filter::{Filter, FilterDecision};
use super::{AlgoMessage, DelayedMessage};

/// Outcome of running a filter chain on one message — the messages
/// that escaped end-to-end (after every filter ran). `Drop` produces
/// `Vec::new()`; `Duplicate` accumulates one entry per copy that
/// survived the remaining filters; `Delay` adds nothing here (the
/// item lands in the per-direction `delay_heap` instead).
type ChainResult = Vec<AlgoMessage>;

/// One node's filter chains plus its delayed-message scheduling state.
pub struct NetworkFacade {
    pub node_id: usize,
    /// Outgoing chain — runs on every message the node sends.
    outgoing: Vec<Box<dyn Filter>>,
    /// Incoming chain — runs on every message the router delivers here.
    incoming: Vec<Box<dyn Filter>>,
    /// Messages the outgoing chain delayed (release at `tick >= release_tick`).
    delayed_outgoing: BinaryHeap<DelayedMessage>,
    /// Messages the incoming chain delayed (release at `tick >= release_tick`).
    delayed_incoming: BinaryHeap<DelayedMessage>,
    /// Monotonic counter for `DelayedMessage.sequence` tie-breaking so
    /// same-tick deliveries fire in insertion order.
    delay_seq: u64,
    /// Last clock tick observed via [`Self::tick`]; bumped on every
    /// call so re-firing works correctly even if the harness skips
    /// ticks.
    current_tick: u64,
}

impl NetworkFacade {
    /// Build a facade for `node_id` with the given outgoing and incoming
    /// filter chains. Filter ownership is transferred — the facade is
    /// the single mutable accessor for each filter for the lifetime of
    /// the simulation.
    pub fn new(
        node_id: usize,
        outgoing: Vec<Box<dyn Filter>>,
        incoming: Vec<Box<dyn Filter>>,
    ) -> Self {
        Self {
            node_id,
            outgoing,
            incoming,
            delayed_outgoing: BinaryHeap::new(),
            delayed_incoming: BinaryHeap::new(),
            delay_seq: 0,
            current_tick: 0,
        }
    }

    /// Run the OUTGOING chain on `msg` (a message produced by this
    /// node) and return the messages that survived end-to-end.
    /// Delayed messages are queued internally and will surface on a
    /// subsequent [`Self::tick`] whose tick number meets their release.
    pub fn process_outgoing(&mut self, msg: AlgoMessage) -> Vec<AlgoMessage> {
        run_chain(
            &mut self.outgoing,
            &mut self.delayed_outgoing,
            &mut self.delay_seq,
            self.current_tick,
            msg,
            Direction::Outgoing,
        )
    }

    /// Run the INCOMING chain on `msg` (a message the router delivered
    /// to this node) and return the messages that survived end-to-end.
    pub fn process_incoming(&mut self, msg: AlgoMessage) -> Vec<AlgoMessage> {
        run_chain(
            &mut self.incoming,
            &mut self.delayed_incoming,
            &mut self.delay_seq,
            self.current_tick,
            msg,
            Direction::Incoming,
        )
    }

    /// Advance this node's clock to `new_clock_time` and return any
    /// `(direction, message)` items that became deliverable as a result.
    ///
    /// `outgoing` items still need to be routed by the scheduler;
    /// `incoming` items are immediately observable by the test harness
    /// via [`Self::drain_delivered_incoming`] semantics — but we expose
    /// them in a single return for simplicity since the scheduler is
    /// the only caller.
    ///
    /// Also calls `tick()` on every filter (in chain order) so that
    /// filters with tick-driven emissions (regossip / reflection) can
    /// produce traffic; those emissions are funneled back into the
    /// outgoing chain *starting at the next filter* so a regossip
    /// filter doesn't observe its own re-emission.
    pub fn tick(&mut self, new_clock_time: u64) -> TickResult {
        self.current_tick = new_clock_time;
        let mut tick_result = TickResult::default();

        // Filter-driven spontaneous emissions go through the entire
        // outgoing chain BUT skipping the originating filter — that's
        // how Go's design avoids self-feeding regossip loops. The drop
        // / duplicate filters in TASK-84 never emit from `tick`, so the
        // simpler "feed through full chain" behavior would also work,
        // but the skip-self pattern is cheap to implement and matches
        // the documented intent.
        for i in 0..self.outgoing.len() {
            let emissions = self.outgoing[i].tick(new_clock_time);
            for m in emissions {
                let delivered = run_chain_from(
                    &mut self.outgoing,
                    &mut self.delayed_outgoing,
                    &mut self.delay_seq,
                    self.current_tick,
                    m,
                    i + 1,
                    Direction::Outgoing,
                );
                tick_result.outgoing.extend(delivered);
            }
        }
        for i in 0..self.incoming.len() {
            let emissions = self.incoming[i].tick(new_clock_time);
            for m in emissions {
                let delivered = run_chain_from(
                    &mut self.incoming,
                    &mut self.delayed_incoming,
                    &mut self.delay_seq,
                    self.current_tick,
                    m,
                    i + 1,
                    Direction::Incoming,
                );
                tick_result.incoming.extend(delivered);
            }
        }

        // Pop everything whose release_tick has come due. Outgoing
        // delayed messages re-enter the chain at filter 0 (the delay
        // was applied AT some filter k, so we re-feed from k+1; but
        // for simplicity we re-feed from the START — this is what Go's
        // priority-queue release pattern does too).
        while let Some(top) = self.delayed_outgoing.peek() {
            if top.release_tick > self.current_tick {
                break;
            }
            let item = self.delayed_outgoing.pop().expect("just peeked, must pop");
            // Released delayed messages bypass the chain — they were
            // already filtered when they got into the queue. This
            // mirrors Go's `processDownstreamBuffer` behavior of
            // calling `n.downstream.SendMessage(...)` directly, not
            // re-running the full chain.
            tick_result.outgoing.push(item.message);
        }
        while let Some(top) = self.delayed_incoming.peek() {
            if top.release_tick > self.current_tick {
                break;
            }
            let item = self.delayed_incoming.pop().expect("just peeked, must pop");
            tick_result.incoming.push(item.message);
        }

        tick_result
    }
}

/// What direction a chain is processing. Used only to format better
/// panic messages if a future filter misbehaves; carries no semantics.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Direction {
    Outgoing,
    Incoming,
}

/// Output of one [`NetworkFacade::tick`] call.
#[derive(Default, Debug)]
pub struct TickResult {
    /// Outgoing messages released this tick — the scheduler still has
    /// to route them.
    pub outgoing: Vec<AlgoMessage>,
    /// Incoming messages released this tick — already addressed to
    /// this node; the harness can observe them as "received".
    pub incoming: Vec<AlgoMessage>,
}

/// Run a single message through a filter chain starting at filter 0.
fn run_chain(
    chain: &mut [Box<dyn Filter>],
    delay_heap: &mut BinaryHeap<DelayedMessage>,
    delay_seq: &mut u64,
    current_tick: u64,
    msg: AlgoMessage,
    direction: Direction,
) -> ChainResult {
    run_chain_from(
        chain,
        delay_heap,
        delay_seq,
        current_tick,
        msg,
        0,
        direction,
    )
}

/// Run a single message through `chain[start_idx..]`, applying each
/// filter's `FilterDecision`. Returns the messages that exited the
/// final filter. `Duplicate` decisions cause every copy to be funneled
/// through the *remaining* filters too, so a chain of `[Drop(rate=2),
/// Duplicate(rate=3)]` applied to messages 1..N drops the even
/// originals first, then duplicates the odd survivors per the rate.
fn run_chain_from(
    chain: &mut [Box<dyn Filter>],
    delay_heap: &mut BinaryHeap<DelayedMessage>,
    delay_seq: &mut u64,
    current_tick: u64,
    msg: AlgoMessage,
    start_idx: usize,
    direction: Direction,
) -> ChainResult {
    if start_idx >= chain.len() {
        return vec![msg];
    }

    let decision = match direction {
        Direction::Outgoing => chain[start_idx].filter_outgoing(&msg),
        Direction::Incoming => chain[start_idx].filter_incoming(&msg),
    };

    match decision {
        FilterDecision::Keep => run_chain_from(
            chain,
            delay_heap,
            delay_seq,
            current_tick,
            msg,
            start_idx + 1,
            direction,
        ),
        FilterDecision::Drop => Vec::new(),
        FilterDecision::Duplicate { extra_copies } => {
            // Recurse for each copy. We emit `1 + extra_copies` total
            // messages — the original plus N duplicates. Each one
            // continues through the remaining filters.
            let total = 1u32.saturating_add(extra_copies);
            let mut all: ChainResult = Vec::new();
            for _ in 0..total {
                let copy = msg.clone();
                let sub = run_chain_from(
                    chain,
                    delay_heap,
                    delay_seq,
                    current_tick,
                    copy,
                    start_idx + 1,
                    direction,
                );
                all.extend(sub);
            }
            all
        }
        FilterDecision::Delay { delay_ticks } => {
            // Park the message in the delay heap; do NOT continue the
            // chain. When the heap releases it, it re-enters the
            // outgoing/incoming stream as a fully-filtered delivery
            // (matching Go's `processDownstreamBuffer` semantics).
            //
            // Panic on `current_tick + delay_ticks` overflow rather
            // than silently saturating: a fuzzer scaffold should fail
            // loudly on configuration that's outside the harness's
            // representable range — silent saturation could mask a
            // bug where a filter accidentally requested an enormous
            // delay (e.g. `u64::MAX` from an unchecked subtraction).
            // `delay_seq.wrapping_add` is fine because the sequence
            // is purely a tie-breaker — wrap is harmless.
            *delay_seq = delay_seq.wrapping_add(1);
            let release_tick = current_tick.checked_add(delay_ticks).unwrap_or_else(|| {
                panic!(
                    "Filter::Delay: current_tick {current_tick} + delay_ticks {delay_ticks} overflows u64",
                )
            });
            delay_heap.push(DelayedMessage {
                release_tick,
                sequence: *delay_seq,
                message: msg,
            });
            Vec::new()
        }
        FilterDecision::Substitute { with } => {
            // Drop the original; feed each replacement through the
            // *remaining* filters. Empty `with` collapses to `Drop`;
            // single-element `with` is a pure substitution; multi-
            // element fans out (each replacement flows independently).
            // Used by the reorder filter to emit a buffered displaced
            // message in place of the fresh arrival.
            let mut all: ChainResult = Vec::new();
            for replacement in with {
                let sub = run_chain_from(
                    chain,
                    delay_heap,
                    delay_seq,
                    current_tick,
                    replacement,
                    start_idx + 1,
                    direction,
                );
                all.extend(sub);
            }
            all
        }
    }
}
