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

// Quiescence detection for the multi-node service-level harness.
//
// Mirrors the *purpose* of go-algorand's `agreement/service_test.go::
// activityMonitor` — after firing a global timeout across every simulated
// node's clock, the test driver needs to know when the whole cluster (N
// independently-scheduled goroutines/threads, cascading network sends) has
// finished reacting before it asserts on state. Go's version does this
// precisely: every coroutine (network tokenizer, demux, clock, crypto
// verifier pool) increments/decrements a shared counter through
// `coserviceListener.inc/dec`, and `waitForQuiet` blocks on a channel fed by
// those transitions.
//
// algod-rust's `EventsProcessingMonitor` hook only reports two named queues
// (`demux`, `pseudonode` — see `src/demux.rs::EVENT_QUEUE_DEMUX` /
// `EVENT_QUEUE_PSEUDONODE`), not a full coservice-count equivalent for the
// network/clock/crypto-verifier layers. Rather than instrument production
// code to add matching counters, this port uses a *direct, exact* signal
// available without any extra plumbing: the real message-channel lengths
// (`TestingNetwork::pending_message_count`, and the crypto verifier's own
// `verified_votes()`/`verified(tag)` receiver lengths, which are already
// `crossbeam_channel::Receiver`s the harness can call `.len()` on). Waiting
// for every one of these counters to read zero *and stay at zero* for a
// short debounce window is a safe proxy for "nothing left to react to":
// unlike the demux/pseudonode-queue counters alone, it can't miss a message
// that already left the sender's hands but hasn't yet been picked up by the
// receiving thread (the exact race go's `n.monitors[peerid].inc(...)` call
// — synchronous with the channel send — exists to avoid).
//
// This is a deliberate simplification, not a claim of byte-for-byte
// fidelity with Go's coservice accounting; it is cross-checked against two
// scenarios (`fast_recovery_down_early`/`fast_recovery_down_miss`) whose
// final round/period/committed-block assertions are known independently
// from go's own `TestAgreementFastRecoveryDownEarly`/`...DownMiss` bodies.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use algo_agreement::demux::{EVENT_QUEUE_DEMUX, EVENT_QUEUE_PSEUDONODE};
use algo_agreement::types::TimeoutType;
use algo_agreement::EventsProcessingMonitor;

use super::testing_clock::TestingClock;
use super::testing_network::TestingNetwork;

/// How many consecutive all-zero polls are required before the cluster is
/// declared quiet. At `POLL_INTERVAL` this is the debounce window.
const STABLE_STREAK: u32 = 300;
const POLL_INTERVAL: Duration = Duration::from_millis(2);
/// Hard ceiling — mirrors go's `waitForQuiet`'s `time.After(10 * time.Second)`
/// dump-and-panic.
const QUIET_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-cluster quiescence tracker. One instance shared by every simulated
/// node's `Parameters::monitor` (via [`ActivityMonitor::listener`]).
pub struct ActivityMonitor {
    demux_q: Vec<AtomicUsize>,
    pseudo_q: Vec<AtomicUsize>,
}

impl ActivityMonitor {
    /// Build a monitor sized for `nodes` simulated services.
    pub fn new(nodes: usize) -> Arc<Self> {
        Arc::new(Self {
            demux_q: (0..nodes).map(|_| AtomicUsize::new(0)).collect(),
            pseudo_q: (0..nodes).map(|_| AtomicUsize::new(0)).collect(),
        })
    }

    /// Build the `EventsProcessingMonitor` this node's `Parameters::monitor`
    /// should hold.
    pub fn listener(self: &Arc<Self>, node_id: usize) -> ActivityListener {
        ActivityListener {
            monitor: Arc::clone(self),
            node_id,
        }
    }

    fn reported_pending(&self) -> usize {
        self.demux_q
            .iter()
            .map(|c| c.load(Ordering::SeqCst))
            .sum::<usize>()
            + self
                .pseudo_q
                .iter()
                .map(|c| c.load(Ordering::SeqCst))
                .sum::<usize>()
    }

    /// Block until the cluster has settled: every node's reported
    /// demux/pseudonode queue lengths are zero, every network channel is
    /// empty, every node's crypto-verifier result channels are drained, AND
    /// every node has reached an idle `Demux::next()` `Select` call (i.e.
    /// its `TestingClock` has both `Deadline` and `FastRecovery` currently
    /// registered — see `TestingClock::has_pending`'s doc comment for why
    /// this last check is required, not just the queue/channel counts) —
    /// stably, for `STABLE_STREAK` consecutive polls. Panics (with a
    /// diagnostic dump) if that doesn't happen within `QUIET_TIMEOUT`,
    /// mirroring go's `activityMonitor.waitForQuiet` timeout behavior.
    ///
    /// `extra_pending` lets the caller fold in any additional per-node
    /// "still working" signals it can observe directly (e.g. crypto
    /// verifier output-channel lengths) without this module needing to be
    /// generic over the crypto verifier's concrete type.
    pub fn wait_for_quiet(
        &self,
        network: &TestingNetwork,
        clocks: &[Arc<TestingClock>],
        extra_pending: impl Fn() -> usize,
    ) {
        let deadline = Instant::now() + QUIET_TIMEOUT;
        let mut streak = 0u32;
        loop {
            let pending =
                self.reported_pending() + network.pending_message_count() + extra_pending();
            let all_idle = clocks.iter().all(|c| {
                c.has_pending(TimeoutType::Deadline) && c.has_pending(TimeoutType::FastRecovery)
            });
            if pending == 0 && all_idle {
                streak += 1;
                if streak >= STABLE_STREAK {
                    return;
                }
            } else {
                streak = 0;
            }
            if Instant::now() >= deadline {
                panic!(
                    "ActivityMonitor::wait_for_quiet timed out after {:?}: \
                     reported_pending={} network_pending={} all_idle={}",
                    QUIET_TIMEOUT,
                    self.reported_pending(),
                    network.pending_message_count(),
                    all_idle,
                );
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

/// Per-node `EventsProcessingMonitor` handle, feeding [`ActivityMonitor`].
pub struct ActivityListener {
    monitor: Arc<ActivityMonitor>,
    node_id: usize,
}

impl EventsProcessingMonitor for ActivityListener {
    fn update_events_queue(&self, queue_name: &str, queue_length: usize) {
        let cell = match queue_name {
            EVENT_QUEUE_DEMUX => &self.monitor.demux_q[self.node_id],
            EVENT_QUEUE_PSEUDONODE => &self.monitor.pseudo_q[self.node_id],
            _ => return,
        };
        cell.store(queue_length, Ordering::SeqCst);
    }
}
