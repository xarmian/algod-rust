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

// Deterministic agreement simulation driver.
//
// Mirrors go-algorand/agreement/agreementtest/simulate.go — the synchronous
// driver used by go-algorand tests to step the agreement state machine
// through N rounds without real wall-clock timing or real network I/O.
//
// Public API:
//   * [`simulate`] — takes a preconstructed `Parameters` plus an
//     `Arc<InstantClock>` handle, starts the service, rendezvouses with
//     each of `n` rounds' `clock.zero()` via `clock.run_round(r)`, then
//     shuts down cleanly. Use this when the test only needs to exercise
//     the clock handshake (no commits expected — e.g.
//     `EmptyKeyManager` smokes).
//   * [`simulate_until_committed`] — the commit-driven variant that
//     mirrors Go's `for ledger.NextRound() < stopRound` loop
//     (`agreement/agreementtest/simulate.go:179-193`). Takes a
//     `next_round_fn` closure so the driver can poll a cloned handle
//     without re-borrowing the ledger that's been moved into
//     `Parameters`. Use this whenever the test asserts that N rounds
//     actually commit — TASK-90's `TestLedger` (clonable, with real
//     stake / sortition) is the canonical pairing.
//
// Composition: see the `instant_clock` and `blackhole_network` sibling
// modules. Callers construct an `InstantClock`, an `InstantMonitor` (via
// `clock.make_monitor()`), a `BlackholeNetwork`, a ledger, and
// participation key/factory/validator stubs — then hand them to
// `Parameters` and call the appropriate driver above.

pub mod activity_monitor;
pub mod blackhole_network;
pub mod instant_clock;
pub mod propose_broadcast_gate;
pub mod setup_agreement;
pub mod suspendable_validator;
pub mod test_account;
pub mod test_factory;
pub mod test_ledger;
pub mod testing_clock;
pub mod testing_network;

use std::sync::Arc;

use algo_agreement::{
    AgreementKeyManager, AgreementNetwork, BlockFactory, BlockValidator, CryptoVerifier,
    EventsProcessingMonitor, LedgerReader, LedgerWriter, Parameters, RandomSource, Service,
};
use algo_types::Round;

pub use blackhole_network::BlackholeNetwork;
pub use instant_clock::InstantClock;
#[allow(unused_imports)] // exposed for future permutation / fuzzer tests.
pub use instant_clock::InstantMonitor;

/// Run `n` rounds of agreement synchronously under the given `InstantClock`.
///
/// `parameters` must have been constructed with `clock` as its `Clock` field
/// (passed here via the separate `Arc<InstantClock>` handle so we can call
/// `run_round`/`shutdown` from the driver thread). The service is started,
/// stepped through `n` rounds, then shut down cleanly.
///
/// Mirrors Go's `agreementtest.Simulate` (simulate.go:143-196), minus the
/// ledger-deadline watchdog — see [`simulate_until_committed`] for the
/// commit-driven variant that mirrors Go's `for ledger.NextRound() <
/// stopRound` loop.
pub fn simulate<N, L, K, BF, BV, R, M, C>(
    parameters: Parameters<N, L, K, BF, BV, R, M, C>,
    clock: Arc<InstantClock>,
    n: Round,
) where
    N: AgreementNetwork + Send + Sync + 'static,
    L: LedgerReader + LedgerWriter + Send + Sync + 'static,
    K: AgreementKeyManager + Send + 'static,
    BF: BlockFactory + Send + 'static,
    BV: BlockValidator + Send + 'static,
    R: RandomSource + Send + 'static,
    M: EventsProcessingMonitor + Send + 'static,
    C: CryptoVerifier + Send + 'static,
{
    let service = Service::new(parameters);
    let handle = service.start();

    for i in 0..n.0 {
        // The mock clock's handshake alone is sufficient to drive the
        // service through the filter step of each round deterministically —
        // whether or not blocks actually commit depends on the ledger +
        // participation-key setup (see TASK-90 follow-up).
        clock.run_round(Round(i));
    }

    // `clock.shutdown()` drops active timeout senders and sets the
    // "shutting_down" flag; any in-flight or subsequent `timeout_at` call
    // surfaces as Disconnected, waking the demux's `Select`. Without this,
    // `handle.shutdown()` would hang because the demux has no way to
    // observe the `quit` atomic while parked on never-firing receivers.
    clock.shutdown();
    handle.shutdown();
}

/// Run agreement until the ledger has committed all rounds up to and
/// including `target`, then shut down cleanly.
///
/// Mirrors Go's `agreementtest.Simulate`'s commit-driven loop
/// (`agreement/agreementtest/simulate.go:179-193`):
///
/// ```text
/// for ledger.NextRound() < stopRound {
///     stopwatch.runRound(r)
///     <-ledger.Wait(r)
/// }
/// ```
///
/// The Rust version here uses the `next_round_fn` closure to read
/// `Ledger::next_round()` from outside `Parameters` (which has consumed
/// the ledger by value). Each `run_round` call drains one
/// `clock.zero()` → `clock.timeout_at()` → `Z0` handshake — the bootstrap
/// fires the first one; every subsequent committed round fires the next
/// from the player's `enter_round(R+1)` → `Action::Rezero(R+1)` path.
///
/// The loop stops as soon as `next_round_fn() > target`; at that point the
/// service may already be parked on the post-commit `Rezero` of `target+1`,
/// so `clock.shutdown()` drops active senders to wake the demux's
/// `Select` and let `handle.shutdown()` complete.
pub fn simulate_until_committed<N, L, K, BF, BV, R, M, C>(
    parameters: Parameters<N, L, K, BF, BV, R, M, C>,
    clock: Arc<InstantClock>,
    target: Round,
    next_round_fn: impl Fn() -> Round,
) where
    N: AgreementNetwork + Send + Sync + 'static,
    L: LedgerReader + LedgerWriter + Send + Sync + 'static,
    K: AgreementKeyManager + Send + 'static,
    BF: BlockFactory + Send + 'static,
    BV: BlockValidator + Send + 'static,
    R: RandomSource + Send + 'static,
    M: EventsProcessingMonitor + Send + 'static,
    C: CryptoVerifier + Send + 'static,
{
    let service = Service::new(parameters);
    let handle = service.start();

    let mut iteration: u64 = 0;
    while next_round_fn().0 <= target.0 {
        clock.run_round(Round(iteration));
        iteration = iteration.saturating_add(1);
    }

    clock.shutdown();
    handle.shutdown();
}
