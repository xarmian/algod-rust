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

// A cluster-wide, driver-controlled pause point on top of
// `algo_agreement::service::ProposeBroadcastHook` (issue #1035).
//
// New design, no go-algorand equivalent: go's `agreement/service_test.go`
// harness drives a single goroutine, so it can arm a suspension
// (`validator.suspend()`) or payload interception (`pocketAllCompound`)
// synchronously, between one round/period transition committing and the
// next round's proposal broadcast, purely via program order. This port's
// multi-node harness (`crates/core/algo-agreement/tests/simulate/`) drives
// real, independently-scheduled `Service` threads, each of which
// auto-broadcasts its own proposal the instant it enters a round/period —
// there is no equivalent program-order guarantee. `ProposeBroadcastGate`
// closes that gap: installed as every node's `Service::with_propose_
// broadcast_hook`, it lets a test driver `arm()` the gate, block until at
// least one node's outbound proposal broadcast is actually paused right
// before hitting the network (`wait_for_pause`), do whatever setup needs to
// happen strictly before that broadcast is visible to the network (suspend
// a validator, arm payload pocketing), then `release()` it.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A single-use closable gate — mirrors
/// `super::suspendable_validator::SuspendableBlockValidator`'s internal
/// `Gate`: dropping every `Sender` clone (on `release()`, or on the next
/// `arm()` replacing it) makes every clone of the paired `Receiver` observe
/// `Disconnected` on `recv()`, releasing every blocked waiter at once.
struct Gate {
    _tx: Option<crossbeam_channel::Sender<()>>,
    rx: crossbeam_channel::Receiver<()>,
}

/// Shared pause point for outbound proposal-payload broadcasts across an
/// entire [`super::setup_agreement::AgreementCluster`]. See the module doc
/// comment for the full rationale.
pub struct ProposeBroadcastGate {
    armed: AtomicBool,
    paused_count: AtomicUsize,
    gate: Mutex<Gate>,
}

impl ProposeBroadcastGate {
    /// A gate that starts disarmed: [`Self::on_broadcast`] (what
    /// `Service::with_propose_broadcast_hook` actually installs) returns
    /// immediately until [`Self::arm`] is called.
    pub fn new() -> Arc<Self> {
        let (tx, rx) = crossbeam_channel::bounded::<()>(0);
        drop(tx); // already "open": a stray recv() would return Disconnected immediately.
        Arc::new(Self {
            armed: AtomicBool::new(false),
            paused_count: AtomicUsize::new(0),
            gate: Mutex::new(Gate { _tx: None, rx }),
        })
    }

    /// Arm a fresh pause: from now on, every node's next outbound
    /// proposal-payload broadcast blocks (inside the agreement service's own
    /// demux thread) until [`Self::release`] is called. Resets the paused
    /// count.
    pub fn arm(&self) {
        let (tx, rx) = crossbeam_channel::bounded::<()>(0);
        self.paused_count.store(0, Ordering::SeqCst);
        *self.gate.lock().unwrap() = Gate { _tx: Some(tx), rx };
        self.armed.store(true, Ordering::SeqCst);
    }

    /// The hook body installed on every node via
    /// `Service::with_propose_broadcast_hook`. A no-op while disarmed —
    /// production code and every non-test caller never sees this type at
    /// all, so ordinary broadcasts are completely unaffected.
    pub fn on_broadcast(&self) {
        if !self.armed.load(Ordering::SeqCst) {
            return;
        }
        self.paused_count.fetch_add(1, Ordering::SeqCst);
        // Clone the receiver out from under the mutex before blocking, so
        // `release()`/`arm()` remain callable concurrently from the driver
        // thread while one or more demux threads sit here.
        let rx = self.gate.lock().unwrap().rx.clone();
        let _ = rx.recv();
    }

    /// Number of proposal broadcasts currently paused (or that were paused
    /// and have since resumed) since the most recent [`Self::arm`].
    pub fn paused_count(&self) -> usize {
        self.paused_count.load(Ordering::SeqCst)
    }

    /// Block (bounded by `timeout`) until at least `min_count` broadcasts
    /// have reached the paused gate. Returns `false` on timeout rather than
    /// panicking, so callers can produce a precise diagnostic.
    pub fn wait_for_pause(&self, min_count: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while self.paused_count() < min_count {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        true
    }

    /// Release every broadcast currently blocked on the gate armed by the
    /// most recent [`Self::arm`] (and let future broadcasts pass straight
    /// through, until the next `arm()`).
    pub fn release(&self) {
        self.armed.store(false, Ordering::SeqCst);
        self.gate.lock().unwrap()._tx = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disarmed_gate_never_blocks() {
        let gate = ProposeBroadcastGate::new();
        gate.on_broadcast();
        gate.on_broadcast();
        assert_eq!(gate.paused_count(), 0);
    }

    #[test]
    fn armed_gate_blocks_until_released() {
        let gate = ProposeBroadcastGate::new();
        gate.arm();

        let gate2 = Arc::clone(&gate);
        let handle = std::thread::spawn(move || gate2.on_broadcast());

        assert!(
            gate.wait_for_pause(1, Duration::from_secs(2)),
            "on_broadcast must report itself paused while armed"
        );
        assert!(!handle.is_finished(), "on_broadcast must still be blocked");

        gate.release();
        handle.join().unwrap();
    }

    #[test]
    fn release_unblocks_multiple_waiters_at_once() {
        let gate = ProposeBroadcastGate::new();
        gate.arm();

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let g = Arc::clone(&gate);
                std::thread::spawn(move || g.on_broadcast())
            })
            .collect();

        assert!(gate.wait_for_pause(4, Duration::from_secs(2)));
        assert!(handles.iter().all(|h| !h.is_finished()));

        gate.release();
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn re_arming_resets_the_paused_count() {
        let gate = ProposeBroadcastGate::new();
        gate.arm();
        let gate2 = Arc::clone(&gate);
        let handle = std::thread::spawn(move || gate2.on_broadcast());
        assert!(gate.wait_for_pause(1, Duration::from_secs(2)));
        gate.release();
        handle.join().unwrap();

        gate.arm();
        assert_eq!(gate.paused_count(), 0, "arm() must reset the counter");
    }

    #[test]
    fn wait_for_pause_times_out_when_nothing_pauses() {
        let gate = ProposeBroadcastGate::new();
        gate.arm();
        assert!(!gate.wait_for_pause(1, Duration::from_millis(50)));
    }
}
