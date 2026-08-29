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

// Default production implementation of the `Clock` trait.
//
// Mirrors go-algorand/util/timers/monotonic.go — `Monotonic[TimeoutType]`.
//
// `SystemClock` wraps `std::time::Instant` and delegates timer firing to
// `crossbeam_channel::after`, which uses a shared background scheduler — no
// per-call OS thread spawn. This preserves the timing semantics the agreement
// service had before the `Clock` abstraction was introduced.
//
// Mutability: `zero()` resets the monotonic reference in place (interior
// mutability via a `Mutex`). Both `main_loop` (which handles `Action::Rezero`)
// and `demux_loop` (which calls `timeout_at`) share the same `Arc<dyn Clock>`,
// so a `zero()` from the main loop is immediately visible to the demux.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crossbeam_channel::{bounded, Receiver};

use crate::clock::Clock;
use crate::types::TimeoutType;

/// Mutable state behind a `Mutex`. Kept small so `zero()` is cheap.
struct State {
    /// Monotonic zero point. Timeouts fire at `zero + delta`.
    zero: Instant,
    /// Wall-clock stamp corresponding to `zero`. Useful for logging /
    /// future persistence.
    #[allow(dead_code)]
    zero_wall: SystemTime,
}

/// Default production clock — wraps `Instant::now()` with in-place `zero()`
/// support, matching go-algorand's `timers.Monotonic` for timing semantics.
pub struct SystemClock {
    state: Mutex<State>,
}

impl SystemClock {
    /// Create a new `SystemClock` zeroed at the current wall-clock instant,
    /// returning it as an `Arc<dyn Clock>` ready to hand to `Parameters`.
    ///
    /// Mirrors `timers.MakeMonotonicClock[TimeoutType](time.Now())` — the Go
    /// equivalent constructs and returns the concrete type; the Rust service
    /// threads clocks as trait objects so every call site wants the
    /// `Arc<dyn Clock>` shape.
    #[allow(clippy::new_ret_no_self)] // returns trait object by design — see doc.
    pub fn new() -> Arc<dyn Clock> {
        Arc::new(Self {
            state: Mutex::new(State {
                zero: Instant::now(),
                zero_wall: SystemTime::now(),
            }),
        })
    }
}

impl Clock for SystemClock {
    fn timeout_at(&self, delta: Duration, _timeout_type: TimeoutType) -> Receiver<Instant> {
        // Snapshot `zero` under the mutex, then drop the guard before touching
        // crossbeam's timer scheduler.
        let zero = {
            let state = self.state.lock().expect("SystemClock state mutex poisoned");
            state.zero
        };

        // `Instant::checked_add` guards against overflow for pathological
        // deltas (the bare `zero + delta` would panic); an overflowed target
        // is indistinguishable from "never fires" since no monotonic clock
        // reading could ever reach it, so return a never-channel — the demux
        // happily selects on it and simply never takes that branch.
        let target = match zero.checked_add(delta) {
            Some(t) => t,
            None => return crossbeam_channel::never(),
        };
        let left = target.saturating_duration_since(Instant::now());

        if left.is_zero() {
            // Already elapsed — return a pre-dropped channel so
            // `Select::recv(&rx)` surfaces it as ready immediately. Mirrors
            // Go's "closed channel always receives" idiom.
            let (tx, rx) = bounded::<Instant>(0);
            drop(tx);
            rx
        } else {
            // crossbeam's `after` uses a shared internal timer thread — it
            // does NOT spawn one OS thread per call, avoiding the thread-
            // accumulation risk that the first iteration of this refactor
            // had with `thread::sleep`.
            crossbeam_channel::after(left)
        }
    }

    fn since(&self) -> Duration {
        let state = self.state.lock().expect("SystemClock state mutex poisoned");
        Instant::now().saturating_duration_since(state.zero)
    }

    fn zero(&self) {
        let mut state = self.state.lock().expect("SystemClock state mutex poisoned");
        state.zero = Instant::now();
        state.zero_wall = SystemTime::now();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::select;
    use std::thread;

    #[test]
    fn since_is_small_at_construction() {
        let clock = SystemClock::new();
        let since = clock.since();
        // Allow a generous upper bound; we just want to assert it's not bogus.
        assert!(
            since < Duration::from_secs(1),
            "since() at construction was {:?}",
            since
        );
    }

    #[test]
    fn zero_resets_the_monotonic_reference() {
        let clock = SystemClock::new();
        thread::sleep(Duration::from_millis(20));
        let before = clock.since();
        clock.zero();
        let after = clock.since();
        // `after` should be much smaller than `before`.
        assert!(
            after < before,
            "zero() did not reset the monotonic reference (before={:?}, after={:?})",
            before,
            after
        );
        assert!(
            after < Duration::from_millis(10),
            "since() immediately after zero() was {:?}; expected <10ms",
            after
        );
    }

    #[test]
    fn timeout_at_elapsed_delta_fires_immediately() {
        let clock = SystemClock::new();
        // Sleep past the delta window.
        thread::sleep(Duration::from_millis(10));
        let rx = clock.timeout_at(Duration::from_millis(1), TimeoutType::Deadline);
        // With delta already elapsed, the receiver should be disconnected.
        assert!(
            rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "expected elapsed timeout_at to surface immediately"
        );
    }

    #[test]
    fn timeout_at_waits_before_firing() {
        let clock = SystemClock::new();
        let rx = clock.timeout_at(Duration::from_millis(50), TimeoutType::Deadline);
        // Before 50ms the receiver should not be ready.
        assert!(
            rx.recv_timeout(Duration::from_millis(10)).is_err(),
            "timeout_at fired before delta elapsed"
        );
        // After sufficient wait the timeout should fire.
        select! {
            recv(rx) -> _ => {
                // Either an Ok(Instant) from crossbeam::after or
                // Err(Disconnected) — both mean the timer fired / was ready.
            },
            default(Duration::from_millis(500)) => {
                panic!("timeout_at did not fire within 500ms");
            }
        }
    }

    #[test]
    fn timeout_at_after_zero_measures_from_new_zero() {
        let clock = SystemClock::new();
        // Sleep to accumulate monotonic time past any short delta.
        thread::sleep(Duration::from_millis(30));
        clock.zero();
        // A 50ms delta, measured from the new zero, should NOT fire immediately.
        let rx = clock.timeout_at(Duration::from_millis(50), TimeoutType::Deadline);
        assert!(
            rx.recv_timeout(Duration::from_millis(10)).is_err(),
            "timeout_at fired immediately after zero() — clock was not reset"
        );
    }

    #[test]
    fn timeout_at_pathological_delta_does_not_panic() {
        // Regression: an extreme delta must not panic via Instant overflow
        // inside `zero + delta`. The clock should gracefully surface a
        // never-firing receiver.
        let clock = SystemClock::new();
        let rx = clock.timeout_at(Duration::MAX, TimeoutType::Deadline);
        // Not ready under any reasonable wait.
        assert!(
            rx.recv_timeout(Duration::from_millis(20)).is_err(),
            "pathological timeout_at should surface a never-firing receiver"
        );
    }

    #[test]
    fn since_progresses_between_zero_calls() {
        let clock = SystemClock::new();
        thread::sleep(Duration::from_millis(15));
        let first_since = clock.since();
        clock.zero();
        thread::sleep(Duration::from_millis(15));
        let second_since = clock.since();
        // Both should be ~15ms; neither should be dramatically bigger than the other.
        assert!(
            first_since >= Duration::from_millis(10),
            "first_since was {:?}",
            first_since
        );
        assert!(
            second_since >= Duration::from_millis(10) && second_since < first_since * 2,
            "second_since={:?} didn't reset properly against first_since={:?}",
            second_since,
            first_since
        );
    }
}
