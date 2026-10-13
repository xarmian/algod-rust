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
// independently-scheduled threads, cascading network sends) has finished
// reacting before it asserts on state. Go does this with exact accounting:
// every coroutine increments/decrements a shared counter through
// `coserviceListener.inc/dec` and `waitForQuiet` blocks on those
// transitions.
//
// Issue #1695: this port used to approximate that with channel lengths plus
// a 600 ms "stay at zero" debounce, which is load-sensitive (a starved
// thread can sit between "dequeued" and "counted" for longer than any fixed
// window). It is now EXACT and timing-independent, built from four facts:
//
//   1. A node's demux thread is the only thread that turns inputs into
//      work (the main loop, action execution and pseudonode actions run in
//      lockstep with it). `DemuxActivity` reports when it is parked in its
//      blocking `Select` with every input empty (it try-selects first and
//      only then publishes "parked"), plus a wake counter bumped BEFORE the
//      woken thread pops anything.
//   2. Every request handed to a node's `AsyncCryptoVerifier` is counted
//      from before it is enqueued until its result is in an output channel
//      (`outstanding_verifications`), so no request is ever in neither the
//      count nor a channel.
//   3. A driver-fired timeout is visible immediately: `TestingClock::fire`
//      drops the entry's sender under the clock mutex, so `has_pending`
//      reads false from that instant until the woken demux re-registers it.
//      (Without this a fired-but-not-yet-woken node looks parked.)
//   4. Network delivery is a synchronous `try_send` into the receiver's
//      channel, so `TestingNetwork::pending_message_count` is exact.
//
// The cluster is quiet iff, across one double-collect (wake counters read,
// then parked flags / verifier counts / channel lengths, then wake counters
// read again) every node is parked, everything is empty and no wake counter
// moved. Parked nodes are inert, the driver thread is the caller, and the
// verifier workers are idle iff nothing is outstanding, so nothing can
// change the state during that window: the observation is atomic, with no
// debounce and no dependence on scheduling speed.
//
// The only timeouts left are the stall/hard watchdogs below, which turn a
// genuine hang into a diagnostic panic; they never decide "quiet".

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use algo_agreement::demux::{EVENT_QUEUE_DEMUX, EVENT_QUEUE_PSEUDONODE};
use algo_agreement::types::TimeoutType;
use algo_agreement::{DemuxActivity, EventsProcessingMonitor};

use super::testing_clock::TestingClock;
use super::testing_network::TestingNetwork;

/// Delay between failed quiescence attempts. Pure polling cadence; it has no
/// bearing on correctness (an attempt is exact whenever it succeeds).
const POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Stall watchdog — mirrors the *purpose* of go's `waitForQuiet`'s
/// `time.After(10 * time.Second)` dump-and-panic, but not its mechanics.
///
/// This is a *stall* timeout, not a *total-duration* timeout (issue #986):
/// it resets every time the observed progress signature changes (work
/// appearing, draining, a node waking or parking). The real OS-thread
/// demux/crypto work of a settle point scales with however much CPU those
/// threads get, so a flat budget fires while the cluster is still making
/// real progress. It only fires if the exact signature is observed
/// unchanged for the full `QUIET_TIMEOUT`, a much stronger hang signal.
const QUIET_TIMEOUT: Duration = Duration::from_secs(90);
/// Absolute backstop regardless of observed progress, so a `wait_for_quiet`
/// call cannot hang a test suite indefinitely even in a pathological case
/// (e.g. a signature that keeps oscillating without ever settling). Sized
/// to comfortably outlast one settle point under heavy contention
/// (issues #986, #1595).
const MAX_TOTAL_TIMEOUT: Duration = Duration::from_secs(300);

/// Progress signature `(pending, parked_nodes, total_wakes)` used only by
/// the stall watchdog.
type Signature = (usize, usize, u64);

/// Per-cluster quiescence tracker. One instance shared by every simulated
/// node's `Parameters::monitor` (via [`ActivityMonitor::listener`]).
pub struct ActivityMonitor {
    /// Last reported demux/pseudonode queue lengths (diagnostics only; the
    /// quiescence decision does not depend on them).
    demux_q: Vec<AtomicUsize>,
    pseudo_q: Vec<AtomicUsize>,
    /// Per-node exact demux idleness probes.
    activities: Vec<Arc<DemuxActivity>>,
}

impl ActivityMonitor {
    /// Build a monitor sized for `nodes` simulated services.
    pub fn new(nodes: usize) -> Arc<Self> {
        Arc::new(Self {
            demux_q: (0..nodes).map(|_| AtomicUsize::new(0)).collect(),
            pseudo_q: (0..nodes).map(|_| AtomicUsize::new(0)).collect(),
            activities: (0..nodes).map(|_| Arc::new(DemuxActivity::new())).collect(),
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

    /// Block until the cluster is EXACTLY quiet: every node's demux thread
    /// is parked in its blocking select with nothing ready, every network
    /// channel is empty, and `extra_pending` (the caller's verifier
    /// accounting) reads zero, all within one window during which no node
    /// woke. See the module comment for why this is atomic and needs no
    /// debounce.
    ///
    /// `extra_pending` must sum, per verifier, the outstanding-request
    /// count FIRST and then the output-channel lengths (a result is sent
    /// before the outstanding count drops, so this order cannot miss it).
    ///
    /// Panics (with a diagnostic dump) if the observed signature stays
    /// unchanged for `QUIET_TIMEOUT` (a stall/deadlock watchdog; see issue
    /// #986) or unconditionally after `MAX_TOTAL_TIMEOUT`, mirroring go's
    /// `activityMonitor.waitForQuiet` timeout.
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

    /// One exact quiescence attempt. `Ok(())` means the cluster was
    /// provably quiet; `Err(sig)` carries the watchdog's progress signature.
    fn try_quiet(
        &self,
        network: &TestingNetwork,
        clocks: &[Arc<TestingClock>],
        extra_pending: &impl Fn() -> usize,
    ) -> Result<(), Signature> {
        // Wake counters FIRST (before any parked flag or channel read).
        let wakes_before: Vec<u64> = self.activities.iter().map(|a| a.wake_count()).collect();
        let total_wakes: u64 = wakes_before.iter().sum();
        let parked = self.activities.iter().filter(|a| a.is_parked()).count();
        let pending = network.pending_message_count() + extra_pending();
        let clocks_armed = clocks.iter().all(|c| {
            c.has_pending(TimeoutType::Deadline) && c.has_pending(TimeoutType::FastRecovery)
        });
        if parked != self.activities.len() || pending != 0 || !clocks_armed {
            return Err((pending, parked, total_wakes));
        }
        // Double-collect: if any node woke since the first read, a node ran
        // during the window and the samples above are not mutually
        // consistent. Retry rather than trust them.
        let unchanged = self
            .activities
            .iter()
            .zip(&wakes_before)
            .all(|(a, w)| a.wake_count() == *w);
        if unchanged {
            Ok(())
        } else {
            Err((pending, parked, total_wakes.wrapping_add(1)))
        }
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
        let mut last_signature: Option<Signature> = None;
        loop {
            let signature = match self.try_quiet(network, clocks, &extra_pending) {
                Ok(()) => return,
                Err(sig) => sig,
            };
            if last_signature != Some(signature) {
                // Any change at all — new work, draining work, a node waking
                // or parking — is a sign of life: push the stall watchdog
                // back out rather than judging against a from-the-start
                // budget (issue #986).
                stall_deadline = Instant::now() + quiet_timeout;
                last_signature = Some(signature);
            }

            let now = Instant::now();
            if now >= stall_deadline || now >= hard_deadline {
                panic!(
                    "ActivityMonitor::wait_for_quiet timed out ({}) after stall_timeout={:?} \
                     max_total_timeout={:?}: reported_pending={} network_pending={} \
                     parked_nodes={}/{} total_wakes={} extra_pending={}",
                    if now >= hard_deadline {
                        "MAX_TOTAL_TIMEOUT exceeded"
                    } else {
                        "no progress within QUIET_TIMEOUT"
                    },
                    quiet_timeout,
                    max_total_timeout,
                    self.reported_pending(),
                    network.pending_message_count(),
                    signature.1,
                    self.activities.len(),
                    signature.2,
                    extra_pending(),
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
    fn demux_activity(&self) -> Option<Arc<DemuxActivity>> {
        Some(Arc::clone(&self.monitor.activities[self.node_id]))
    }

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
    //! Pins issue #986's stall-vs-progress behavior and issue #1695's exact
    //! parked/wake accounting directly, without spinning up a real cluster.
    //! `extra_pending` and the nodes' `DemuxActivity` probes are driven by
    //! hand, so these run in well under a second.
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use super::*;

    fn no_clocks() -> Vec<Arc<TestingClock>> {
        Vec::new()
    }

    /// A one-node monitor whose node is already parked.
    fn parked_monitor() -> Arc<ActivityMonitor> {
        let monitor = ActivityMonitor::new(1);
        monitor.activities[0].mark_parked();
        monitor
    }

    #[test]
    fn wait_for_quiet_tolerates_slow_but_changing_progress() {
        // extra_pending counts down 20 -> 0, one tick every 100ms; the whole
        // countdown (2s) is twice the 1s `quiet_timeout` used here, so a flat
        // from-the-start budget would panic partway through. Because each
        // tick is a *change*, the progress-based stall watchdog never fires.
        // The 10x margin between tick and stall timeout keeps the test from
        // flaking when the polling thread is descheduled under heavy CPU
        // contention (issue #1900: a 30ms tick vs 100ms timeout failed 1 in
        // 100 loaded runs).
        // This is the shape of a genuinely busy (not stuck) cluster under
        // heavy CPU contention: settling takes a while, but there's
        // continuous, if slow, forward motion (issue #986).
        let monitor = parked_monitor();
        let network = TestingNetwork::new(1, 8);

        let remaining = AtomicUsize::new(20);
        let started = Instant::now();
        let last_tick = std::sync::Mutex::new(Instant::now());

        monitor.wait_for_quiet_with_timeouts(
            &network,
            &no_clocks(),
            || {
                let mut last = last_tick.lock().unwrap();
                if last.elapsed() >= Duration::from_millis(100) {
                    let prev = remaining.load(Ordering::SeqCst);
                    if prev > 0 {
                        remaining.store(prev - 1, Ordering::SeqCst);
                    }
                    *last = Instant::now();
                }
                remaining.load(Ordering::SeqCst)
            },
            Duration::from_secs(1),
            Duration::from_secs(30),
        );

        assert!(
            started.elapsed() >= Duration::from_millis(1500),
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
        // (not the max_total_timeout backstop, which is set far larger).
        let monitor = parked_monitor();
        let network = TestingNetwork::new(1, 8);
        monitor.wait_for_quiet_with_timeouts(
            &network,
            &no_clocks(),
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
        // never fire), but the cluster never actually reaches quiet.
        let monitor = parked_monitor();
        let network = TestingNetwork::new(1, 8);
        let toggle = AtomicUsize::new(0);
        monitor.wait_for_quiet_with_timeouts(
            &network,
            &no_clocks(),
            || {
                let prev = toggle.fetch_xor(1, Ordering::SeqCst);
                (prev ^ 1) + 1 // alternates between 1 and 2, never 0
            },
            Duration::from_secs(30),
            Duration::from_millis(150),
        );
    }

    #[test]
    fn quiet_requires_every_node_parked() {
        // Two nodes, one never parked (still bootstrapping / mid-event):
        // everything else reads zero, but the cluster must NOT be quiet.
        let monitor = ActivityMonitor::new(2);
        let network = TestingNetwork::new(2, 8);
        monitor.activities[0].mark_parked();
        assert!(monitor.try_quiet(&network, &no_clocks(), &|| 0).is_err());
        monitor.activities[1].mark_parked();
        assert!(monitor.try_quiet(&network, &no_clocks(), &|| 0).is_ok());
    }

    #[test]
    fn quiet_rejects_a_sample_during_which_a_node_woke() {
        // Models the dequeue race the old debounce papered over: a node
        // wakes, pops a message (channel now empty) and re-parks while the
        // observer is mid-sample. Every individual reading looks quiet, but
        // the wake counter moved, so the sample must be rejected.
        let monitor = parked_monitor();
        let network = TestingNetwork::new(1, 8);
        let woke = std::cell::Cell::new(false);
        let result = monitor.try_quiet(&network, &no_clocks(), &|| {
            if !woke.replace(true) {
                monitor.activities[0].mark_woken();
                monitor.activities[0].mark_parked();
            }
            0
        });
        assert!(result.is_err(), "a wake inside the window must reject");
        // The very next attempt, with no interference, is exact.
        assert!(monitor.try_quiet(&network, &no_clocks(), &|| 0).is_ok());
    }

    #[test]
    fn quiet_rejects_a_fired_but_not_yet_woken_node() {
        // `fire` drops the sender before the (parked) demux thread wakes:
        // the node still reads parked with empty channels, but the clock
        // reports the fire, so the cluster must not be quiet.
        use algo_agreement::Clock;
        let monitor = parked_monitor();
        let network = TestingNetwork::new(1, 8);
        let clock = TestingClock::new();
        let _ = clock.timeout_at(Duration::from_secs(1), TimeoutType::Deadline);
        let _ = clock.timeout_at(Duration::from_secs(1), TimeoutType::FastRecovery);
        let clocks = vec![clock];
        assert!(monitor.try_quiet(&network, &clocks, &|| 0).is_ok());
        clocks[0].fire(TimeoutType::Deadline);
        assert!(monitor.try_quiet(&network, &clocks, &|| 0).is_err());
    }

    #[test]
    fn quiet_rejects_pending_work_even_when_parked() {
        let monitor = parked_monitor();
        let network = TestingNetwork::new(1, 8);
        assert!(monitor.try_quiet(&network, &no_clocks(), &|| 1).is_err());
    }
}
