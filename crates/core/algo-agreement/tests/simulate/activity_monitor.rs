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
/// Stall watchdog — mirrors the *purpose* of go's `waitForQuiet`'s
/// `time.After(10 * time.Second)` dump-and-panic, but not its mechanics.
///
/// Root-cause note (issue #986): this used to be a flat wall-clock budget
/// for the *entire* `wait_for_quiet` call — measured from the call's start,
/// unconditionally. That's wrong for what this harness actually runs: every
/// node's demux/pseudonode processing and crypto verification
/// (`AsyncCryptoVerifier`, real Falcon/VRF work — see
/// `AgreementCluster::wait_for_quiet`'s doc comment) happens on real OS
/// threads with no simulated-time shortcut, so the *genuine* wall-clock cost
/// of a settle point scales with however much CPU those threads actually get
/// scheduled. On a machine running a full parallel `cargo test --workspace`
/// (or any other heavy concurrent load) those threads can be legitimately
/// slow without being stuck — a flat 10s-from-start budget then fires while
/// the cluster is still making real progress, which is exactly what issue
/// #986 reproduced (a single `large_periods_five_node` run takes ~226s
/// *even in full isolation*, driven by dozens of genuine settle points; the
/// same run under synthetic CPU contention took far longer without ever
/// actually deadlocking).
///
/// So this is now a *stall* timeout, not a *total-duration* timeout: it
/// resets every time the observed (pending, all_idle) signature changes —
/// i.e. every time there is any sign of life at all, whether that's new
/// work appearing or existing work draining. It only fires if that exact
/// signature is observed unchanged for the full `QUIET_TIMEOUT`, which is a
/// much stronger signal of a genuine hang/deadlock than "settling took a
/// while." `MAX_TOTAL_TIMEOUT` below remains as a hard backstop against a
/// pathological signature that oscillates forever without ever truly
/// settling.
const QUIET_TIMEOUT: Duration = Duration::from_secs(10);
/// Absolute backstop regardless of observed progress, so a wait_for_quiet
/// call cannot hang a test suite indefinitely even in a pathological case
/// (e.g. a signature that keeps oscillating without ever reaching true
/// quiescence). Generous enough to comfortably outlast one settle point
/// under heavy contention (see `QUIET_TIMEOUT`'s doc comment) while still
/// bounding worst-case test run time.
const MAX_TOTAL_TIMEOUT: Duration = Duration::from_secs(120);

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
    /// stably, for `STABLE_STREAK` consecutive polls.
    ///
    /// Panics (with a diagnostic dump) if the observed `(pending, all_idle)`
    /// signature stays unchanged for `QUIET_TIMEOUT` without ever reaching
    /// quiescence (a stall/deadlock watchdog — see `QUIET_TIMEOUT`'s doc
    /// comment for why this is progress-based rather than a flat
    /// from-the-start budget), or unconditionally after `MAX_TOTAL_TIMEOUT`
    /// regardless of progress, mirroring the intent of go's
    /// `activityMonitor.waitForQuiet` timeout behavior.
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
        self.wait_for_quiet_with_timeouts(
            network,
            clocks,
            extra_pending,
            QUIET_TIMEOUT,
            MAX_TOTAL_TIMEOUT,
        )
    }

    /// [`Self::wait_for_quiet`] with the stall/hard timeouts as explicit
    /// parameters, so unit tests can pin the stall-vs-progress behavior on a
    /// millisecond timescale instead of `QUIET_TIMEOUT`/`MAX_TOTAL_TIMEOUT`'s
    /// real (seconds-scale) values.
    fn wait_for_quiet_with_timeouts(
        &self,
        network: &TestingNetwork,
        clocks: &[Arc<TestingClock>],
        extra_pending: impl Fn() -> usize,
        quiet_timeout: Duration,
        max_total_timeout: Duration,
    ) {
        let hard_deadline = Instant::now() + max_total_timeout;
        let mut stall_deadline = Instant::now() + quiet_timeout;
        let mut last_signature: Option<(usize, bool)> = None;
        let mut streak = 0u32;
        loop {
            let pending =
                self.reported_pending() + network.pending_message_count() + extra_pending();
            let all_idle = clocks.iter().all(|c| {
                c.has_pending(TimeoutType::Deadline) && c.has_pending(TimeoutType::FastRecovery)
            });

            if pending == 0 && all_idle {
                // On the success path: an unchanged (0, true) signature here
                // isn't staleness, it's the debounce window
                // (STABLE_STREAK * POLL_INTERVAL) doing its job, so keep
                // pushing the watchdog out every poll rather than measuring
                // it against `last_signature`. Without this, a debounce
                // window longer than `quiet_timeout` (never true for the
                // real QUIET_TIMEOUT/STABLE_STREAK values, but easy to hit
                // with a short `quiet_timeout` in a test) would panic while
                // the cluster is already quiet and just finishing the
                // debounce count.
                stall_deadline = Instant::now() + quiet_timeout;
                streak += 1;
                if streak >= STABLE_STREAK {
                    return;
                }
            } else {
                streak = 0;
                let signature = (pending, all_idle);
                if last_signature != Some(signature) {
                    // Any change at all — new work, draining work, or a
                    // node finally reaching its idle `Select` — is a sign
                    // of life: push the stall watchdog back out rather
                    // than judging the whole call against a fixed
                    // from-the-start budget.
                    stall_deadline = Instant::now() + quiet_timeout;
                    last_signature = Some(signature);
                }
            }

            let now = Instant::now();
            if now >= stall_deadline || now >= hard_deadline {
                panic!(
                    "ActivityMonitor::wait_for_quiet timed out ({}) after stall_timeout={:?} \
                     max_total_timeout={:?}: reported_pending={} network_pending={} all_idle={}",
                    if now >= hard_deadline {
                        "MAX_TOTAL_TIMEOUT exceeded"
                    } else {
                        "no progress within QUIET_TIMEOUT"
                    },
                    quiet_timeout,
                    max_total_timeout,
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

#[cfg(test)]
mod tests {
    //! Pins issue #986's fix directly: `wait_for_quiet` must tolerate a
    //! settle point that takes far longer than `QUIET_TIMEOUT` as long as
    //! `extra_pending` keeps changing (genuine, if slow, progress), and must
    //! still fail fast when `extra_pending` is frozen at a nonzero value for
    //! that long (a genuine stall). Drives `extra_pending` directly rather
    //! than spinning up a real 5-node cluster, so this runs in well under a
    //! second instead of the minutes a live scenario needs.
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use algo_agreement::Clock;

    use super::*;

    /// Two idle clocks: both timeout types registered and never fired, so
    /// `all_idle` reads true throughout — isolates the test to the
    /// `extra_pending` signal alone.
    fn idle_clocks() -> Vec<Arc<TestingClock>> {
        (0..1)
            .map(|_| {
                let clock = TestingClock::new();
                let _ = clock.timeout_at(Duration::from_secs(1), TimeoutType::Deadline);
                let _ = clock.timeout_at(Duration::from_secs(1), TimeoutType::FastRecovery);
                clock
            })
            .collect()
    }

    #[test]
    fn wait_for_quiet_tolerates_slow_but_changing_progress() {
        // extra_pending counts down 50 -> 0, one tick every 30ms — several
        // times slower than the 100ms `quiet_timeout` used here, so a flat
        // from-the-start budget would panic partway through. Because each
        // tick is a *change*, the progress-based stall watchdog never fires.
        // This is the shape of a genuinely busy (not stuck) cluster under
        // heavy CPU contention: settling takes a while, but there's
        // continuous, if slow, forward motion (issue #986).
        let monitor = ActivityMonitor::new(1);
        let network = TestingNetwork::new(1, 8);
        let clocks = idle_clocks();

        let remaining = AtomicUsize::new(50);
        let started = Instant::now();
        let last_tick = std::sync::Mutex::new(Instant::now());

        monitor.wait_for_quiet_with_timeouts(
            &network,
            &clocks,
            || {
                // Advance the counter down at a slower-than-instant cadence
                // so successive polls really do observe distinct values.
                let mut last = last_tick.lock().unwrap();
                if last.elapsed() >= Duration::from_millis(30) {
                    let prev = remaining.load(Ordering::SeqCst);
                    if prev > 0 {
                        remaining.store(prev - 1, Ordering::SeqCst);
                    }
                    *last = Instant::now();
                }
                remaining.load(Ordering::SeqCst)
            },
            Duration::from_millis(100),
            Duration::from_secs(30),
        );

        // Must have actually taken a while (proving the debounce/decay ran
        // its course, well past what a flat 100ms budget would allow)
        // rather than returning immediately by accident.
        assert!(
            started.elapsed() >= Duration::from_millis(500),
            "expected the countdown to take a while, took {:?}",
            started.elapsed()
        );
        assert_eq!(remaining.load(Ordering::SeqCst), 0);
    }

    #[test]
    #[should_panic(expected = "no progress within QUIET_TIMEOUT")]
    fn wait_for_quiet_still_fails_fast_on_a_genuine_stall() {
        // extra_pending is frozen at a nonzero value forever: a real
        // deadlock. Must still panic, and via the stall path specifically
        // (not the max_total_timeout backstop, which is set far larger
        // here), well before a real cluster's QUIET_TIMEOUT would apply.
        let monitor = ActivityMonitor::new(1);
        let network = TestingNetwork::new(1, 8);
        let clocks = idle_clocks();

        monitor.wait_for_quiet_with_timeouts(
            &network,
            &clocks,
            || 1,
            Duration::from_millis(100),
            Duration::from_secs(30),
        );
    }

    #[test]
    #[should_panic(expected = "MAX_TOTAL_TIMEOUT exceeded")]
    fn wait_for_quiet_hard_backstop_fires_on_perpetual_oscillation() {
        // extra_pending toggles between two nonzero values every poll: the
        // signature keeps "changing" (so the stall watchdog alone would
        // never fire), but the cluster never actually reaches (0, true).
        // max_total_timeout is the backstop that still bounds this case.
        let monitor = ActivityMonitor::new(1);
        let network = TestingNetwork::new(1, 8);
        let clocks = idle_clocks();
        let toggle = AtomicUsize::new(0);

        monitor.wait_for_quiet_with_timeouts(
            &network,
            &clocks,
            || {
                let prev = toggle.fetch_xor(1, Ordering::SeqCst);
                (prev ^ 1) + 1 // alternates between 1 and 2, never 0
            },
            Duration::from_secs(30),
            Duration::from_millis(150),
        );
    }
}
