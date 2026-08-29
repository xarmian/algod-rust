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

// Top-level tick-driven scheduler.
//
// Owns the per-node `NetworkFacade`s and the cluster `Router`, exposes
// the entry points the test harness uses (`enqueue_send`,
// `tick_until`, `drain_received`), and wires the
// outgoing-chain → router → incoming-chain pipeline together.
//
// Mirrors the message-pump shape of go-algorand's
// `agreement/fuzzer/fuzzer_test.go::Run`. We keep the Rust version
// simpler — no goroutines, no real Service per node — because the
// "live multi-node consensus" surface is a TASK-85 deliverable and
// belongs in its own PR (CONVE-14: keep task scope to one PR).
//
// Determinism: the scheduler iterates nodes in ascending node-ID order
// for every step (tick, send, receive). Per-tick deliveries are
// emitted in `(release_tick ascending, sequence ascending)` order via
// the facade's `BinaryHeap`. Combined with the counter-based filter
// designs, the entire harness is deterministic and replayable from a
// recorded send sequence alone.

use super::network_facade::NetworkFacade;
use super::router::Router;
use super::AlgoMessage;

/// Top-level fuzzer harness state. One scheduler == one cluster.
pub struct Scheduler {
    router: Router,
    facades: Vec<NetworkFacade>,
    /// Per-node received-message log. The harness drains this via
    /// [`Self::drain_received`] to assert delivery counts / contents.
    received: Vec<Vec<AlgoMessage>>,
    /// Current logical clock tick. Bumped by [`Self::tick_to`].
    current_tick: u64,
}

impl Scheduler {
    /// Construct a scheduler from a `Router` and the per-node facades.
    /// The two collections must agree on cluster size — panics otherwise
    /// because that's a harness construction bug, not a runtime input.
    pub fn new(router: Router, facades: Vec<NetworkFacade>) -> Self {
        assert_eq!(
            router.node_count(),
            facades.len(),
            "Scheduler: router node_count ({}) must match the number of facades ({})",
            router.node_count(),
            facades.len(),
        );
        let n = facades.len();
        Self {
            router,
            facades,
            received: vec![Vec::new(); n],
            current_tick: 0,
        }
    }

    /// Number of nodes in the cluster.
    pub fn node_count(&self) -> usize {
        self.facades.len()
    }

    /// Current logical clock tick.
    pub fn current_tick(&self) -> u64 {
        self.current_tick
    }

    /// Enqueue a message produced by `source_node`. Runs it through
    /// the source's outgoing chain, routes the survivors to their
    /// targets, and runs each through the target's incoming chain;
    /// the final per-target survivors land in the per-node received
    /// log. Messages held by `Delay` decisions stay in the relevant
    /// facade's heap and surface on subsequent [`Self::tick_to`] calls.
    ///
    /// Panics if `source_node` is out of range — that's a harness bug.
    pub fn enqueue_send(&mut self, msg: AlgoMessage) {
        assert!(
            msg.source_node < self.facades.len(),
            "Scheduler::enqueue_send: source node {} out of range (cluster size {})",
            msg.source_node,
            self.facades.len(),
        );
        let outgoing = self.facades[msg.source_node].process_outgoing(msg);
        for survivor in outgoing {
            self.route_and_deliver(survivor);
        }
    }

    /// Advance the cluster clock to `target_tick` (must be ≥ current).
    /// At each integer tick in `(current, target]`, every facade gets
    /// a `tick(t)` call; any messages those ticks release are routed /
    /// delivered immediately. After this returns, `current_tick ==
    /// target_tick`.
    pub fn tick_to(&mut self, target_tick: u64) {
        assert!(
            target_tick >= self.current_tick,
            "Scheduler::tick_to: target_tick {} must be >= current_tick {}",
            target_tick,
            self.current_tick,
        );
        while self.current_tick < target_tick {
            self.current_tick = self.current_tick.saturating_add(1);
            for node_id in 0..self.facades.len() {
                let result = self.facades[node_id].tick(self.current_tick);
                for outgoing in result.outgoing {
                    // The outgoing message already escaped the
                    // outgoing chain (it was delayed THERE), so we
                    // route it without re-running the chain. That
                    // matches `processDownstreamBuffer` in Go.
                    let routed = self.router.route(&outgoing);
                    for delivery in routed {
                        if let Some(target) = delivery.target_node {
                            let final_deliveries = self.facades[target].process_incoming(delivery);
                            self.received[target].extend(final_deliveries);
                        }
                    }
                }
                for incoming in result.incoming {
                    // Same reasoning: this already passed the incoming
                    // chain, so just deposit in the receive log.
                    if let Some(target) = incoming.target_node {
                        if target == node_id {
                            self.received[target].push(incoming);
                        }
                    }
                }
            }
        }
    }

    /// Drain and return everything node `target_node` has received so
    /// far; subsequent calls return only messages that arrived after
    /// the previous drain. Useful for per-tick assertions in tests.
    pub fn drain_received(&mut self, target_node: usize) -> Vec<AlgoMessage> {
        std::mem::take(&mut self.received[target_node])
    }

    /// Borrow the per-node received log without draining — useful for
    /// assertions when the harness wants to keep counting across calls.
    pub fn received(&self, target_node: usize) -> &[AlgoMessage] {
        &self.received[target_node]
    }

    fn route_and_deliver(&mut self, msg: AlgoMessage) {
        let routed = self.router.route(&msg);
        for delivery in routed {
            let Some(target) = delivery.target_node else {
                continue;
            };
            let final_deliveries = self.facades[target].process_incoming(delivery);
            self.received[target].extend(final_deliveries);
        }
    }
}
