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

// Explicitly-fireable mock clock for the multi-node service-level harness.
//
// Mirrors go-algorand's `agreement/service_test.go::testingClock`: a `Clock`
// whose `timeout_at` never fires on its own. The test driver calls
// `fire(timeout_type)` to release whichever receiver is currently pending for
// that type; `zero()` (called once per round-bootstrap / rezero) discards all
// pending entries the same way Go's `Zero()` replaces `c.TA` with a fresh map.
//
// Divergence from Go, and why it's safe: go-algorand's demux keys its
// `Clock.TimeoutAt` calls by `TimeoutFilter` (period-0 round-start / regular
// filter timeout) *and* `TimeoutDeadline` (soft/cert deadline) as two
// distinct map entries, and its `testingClock.fire` closure just closes the
// requested type's channel — `triggerGlobalTimeout`'s `d time.Duration`
// parameter is not read by `fire` (only used at call sites for readability).
// algod-rust's `Demux::next` (`src/demux.rs:395`) always requests the
// deadline receiver keyed as `TimeoutType::Deadline` regardless of whether
// the current `player.deadline` is semantically a period-0 filter timeout or
// a later real deadline timeout — the *duration* differs, the *clock key*
// does not. So this harness only ever needs two logical keys (`Deadline` and
// `FastRecovery`), and `fire(TimeoutType::Deadline)` is the port target for
// every one of Go's `triggerGlobalTimeout(_, TimeoutFilter, ...)` /
// `triggerGlobalTimeout(_, TimeoutDeadline, ...)` call sites.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, Receiver, Sender};

use algo_agreement::types::TimeoutType;
use algo_agreement::Clock;

/// One pending timeout registration: the duration it was requested with
/// (so a *different* delta creates a fresh entry, mirroring Go's
/// `if !ok || ta.delta != d`), plus the sender the harness drops to "fire"
/// it and the receiver handed out to callers (kept so repeat `timeout_at`
/// calls with the same delta return the exact same channel).
struct ClockEntry {
    delta: Duration,
    sender: Option<Sender<Instant>>,
    receiver: Receiver<Instant>,
}

struct ClockState {
    entries: HashMap<TimeoutType, ClockEntry>,
}

/// Multi-node testing clock. One instance per simulated node.
///
/// `Arc<TestingClock>` is handed to `Parameters::clock` (as `Arc<dyn
/// Clock>`) *and* kept by the test driver to call `fire`/`zero_count`/
/// `shutdown`.
pub struct TestingClock {
    state: Mutex<ClockState>,
    zeroes: AtomicU64,
    shutting_down: AtomicBool,
}

impl TestingClock {
    /// Construct a fresh, un-fired clock.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ClockState {
                entries: HashMap::new(),
            }),
            zeroes: AtomicU64::new(0),
            shutting_down: AtomicBool::new(false),
        })
    }

    /// Number of times `zero()` has been called — mirrors Go's
    /// `testingClock.zeroes`, read by `expectNewPeriod`/`expectNoNewPeriod`
    /// to assert whether a round/period transition happened.
    pub fn zeroes(&self) -> u64 {
        self.zeroes.load(Ordering::SeqCst)
    }

    /// Release the entry currently registered for `timeout_type`, letting
    /// any thread parked on the receiver `Demux::next` obtained from
    /// `timeout_at` observe it as ready (a dropped `Sender` disconnects the
    /// `Receiver`, which `crossbeam_channel::Select` treats as immediately
    /// selectable — the same "closed channel" idiom Go's `close(ch)` uses).
    ///
    /// Mirrors Go's `testingClock.fire`. Panics if nothing is registered for
    /// `timeout_type` yet, matching Go's `panic(fmt.Errorf("no timeout of
    /// type %v", timeoutType))` — a harness-usage bug, not a runtime input.
    pub fn fire(&self, timeout_type: TimeoutType) {
        let mut state = self.state.lock().expect("TestingClock state poisoned");
        let entry = state
            .entries
            .get_mut(&timeout_type)
            .unwrap_or_else(|| panic!("TestingClock::fire: no timeout of type {timeout_type:?}"));
        entry.sender = None;
    }

    /// Like [`Self::fire`], but a silent no-op instead of a panic when
    /// nothing is registered for `timeout_type` yet.
    ///
    /// For a driver that wants to repeatedly fire a timeout across an
    /// unknown number of round/period transitions without a settle
    /// (`wait_for_quiet`) between attempts (e.g.
    /// `arm_and_catch_next_proposal_broadcast`,
    /// `service_multi_node_test.rs`, issue #1035): a bare `fire()` loop
    /// races a node's `zero()` (called on every round rezero, which clears
    /// every entry) against the driver's own retry cadence, and can hit
    /// the exact window between a rezero and that node's demux thread
    /// reaching its next `Demux::next()` `Select` call (which re-registers
    /// `Deadline`) — an entirely expected timing gap under this harness's
    /// real threading, not a harness-usage bug the way calling `fire()`
    /// with NOTHING ever registered (a genuine test-setup mistake) is. Note
    /// this is deliberately not `has_pending`-then-`fire`: `has_pending`
    /// additionally requires the entry to be un-fired, which stays false
    /// forever once two consecutive registrations share the same delta
    /// (see `has_pending`'s own doc comment) — this method only checks that
    /// an entry exists at all, regardless of its fired state, since
    /// `fire()`'s own effect (`entry.sender = None`) is idempotent and safe
    /// to repeat.
    pub fn try_fire(&self, timeout_type: TimeoutType) {
        let mut state = self.state.lock().expect("TestingClock state poisoned");
        if let Some(entry) = state.entries.get_mut(&timeout_type) {
            entry.sender = None;
        }
    }

    /// True if `timeout_type` currently has an un-fired entry registered
    /// (i.e. some thread has called `timeout_at` for it since the last
    /// `zero()`/`fire()` and hasn't been released yet).
    ///
    /// Used by the harness's quiescence poll (`activity_monitor.rs`) as a
    /// "this node has reached its next `Demux::next()` `Select` call and is
    /// genuinely parked" signal — `Demux::next` unconditionally requests
    /// both `Deadline` and `FastRecovery` on every iteration
    /// (`src/demux.rs:395-398`), so a node that hasn't registered both yet
    /// is still mid-iteration (bootstrapping, or executing an action
    /// batch), not idle. Without this check, a freshly-started node that
    /// hasn't reached its first `Select` yet is indistinguishable from a
    /// genuinely quiet one purely by demux/pseudonode queue length +
    /// network channel emptiness, since those all read zero before the
    /// node has done anything at all — exactly the false-quiet race this
    /// method closes.
    pub fn has_pending(&self, timeout_type: TimeoutType) -> bool {
        let state = self.state.lock().expect("TestingClock state poisoned");
        state
            .entries
            .get(&timeout_type)
            .map(|e| e.sender.is_some())
            .unwrap_or(false)
    }

    /// Drop every currently-registered sender so any parked `Select` wakes
    /// up as disconnected, and make every subsequent `timeout_at` call
    /// return a pre-disconnected receiver. Called once by the driver before
    /// shutting down each node's `ServiceHandle`, mirroring
    /// `InstantClock::shutdown` (`tests/simulate/instant_clock.rs`) — without
    /// this, a node parked in `Demux::next`'s `Select` on a never-firing
    /// deadline/fast-recovery receiver would make `ServiceHandle::shutdown`
    /// hang forever waiting for the thread to join.
    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        self.state
            .lock()
            .expect("TestingClock state poisoned")
            .entries
            .clear();
    }
}

impl Clock for TestingClock {
    fn timeout_at(&self, delta: Duration, timeout_type: TimeoutType) -> Receiver<Instant> {
        if self.shutting_down.load(Ordering::SeqCst) {
            let (tx, rx) = bounded::<Instant>(0);
            drop(tx);
            return rx;
        }

        let mut state = self.state.lock().expect("TestingClock state poisoned");
        let need_new = !matches!(state.entries.get(&timeout_type), Some(e) if e.delta == delta);
        if need_new {
            let (tx, rx) = bounded::<Instant>(0);
            state.entries.insert(
                timeout_type,
                ClockEntry {
                    delta,
                    sender: Some(tx),
                    receiver: rx,
                },
            );
        }
        state
            .entries
            .get(&timeout_type)
            .expect("just inserted or already present")
            .receiver
            .clone()
    }

    fn since(&self) -> Duration {
        // Mirrors Go's `testingClock.Since()`, which always returns `1`
        // (nanosecond).
        Duration::from_nanos(1)
    }

    fn zero(&self) {
        self.zeroes.fetch_add(1, Ordering::SeqCst);
        self.state
            .lock()
            .expect("TestingClock state poisoned")
            .entries
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fire_releases_pending_receiver() {
        let clock = TestingClock::new();
        let rx = clock.timeout_at(Duration::from_secs(1), TimeoutType::Deadline);
        assert!(rx.try_recv().is_err());
        clock.fire(TimeoutType::Deadline);
        // Disconnected sender -> recv() returns Err(Disconnected) immediately.
        assert!(rx.recv().is_err());
    }

    #[test]
    fn timeout_at_same_delta_returns_same_receiver() {
        let clock = TestingClock::new();
        let rx1 = clock.timeout_at(Duration::from_secs(1), TimeoutType::Deadline);
        let rx2 = clock.timeout_at(Duration::from_secs(1), TimeoutType::Deadline);
        clock.fire(TimeoutType::Deadline);
        assert!(rx1.recv().is_err());
        assert!(rx2.recv().is_err());
    }

    #[test]
    fn timeout_at_different_delta_creates_new_entry() {
        let clock = TestingClock::new();
        let rx1 = clock.timeout_at(Duration::from_secs(1), TimeoutType::Deadline);
        let _rx2 = clock.timeout_at(Duration::from_secs(2), TimeoutType::Deadline);
        // Firing the (now current) entry must not affect the stale rx1.
        clock.fire(TimeoutType::Deadline);
        assert!(rx1.try_recv().is_err());
    }

    #[test]
    fn zero_increments_counter_and_clears_entries() {
        let clock = TestingClock::new();
        assert_eq!(clock.zeroes(), 0);
        clock.zero();
        assert_eq!(clock.zeroes(), 1);
        clock.zero();
        assert_eq!(clock.zeroes(), 2);
    }

    #[test]
    #[should_panic(expected = "no timeout of type")]
    fn fire_without_registration_panics() {
        let clock = TestingClock::new();
        clock.fire(TimeoutType::FastRecovery);
    }
}
