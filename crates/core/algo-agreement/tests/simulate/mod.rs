// Deterministic agreement simulation driver.
//
// Mirrors go-algorand/agreement/agreementtest/simulate.go — the synchronous
// driver used by go-algorand tests to step the agreement state machine
// through N rounds without real wall-clock timing or real network I/O.
//
// Public API: [`simulate`] — takes a preconstructed `Parameters` plus an
// `Arc<InstantClock>` handle, starts the service, rendezvouses with each
// round's `clock.zero()` via `clock.run_round(r)`, then shuts down cleanly.
//
// Composition: see the `instant_clock` and `blackhole_network` sibling
// modules. Callers construct an `InstantClock`, an `InstantMonitor` (via
// `clock.make_monitor()`), a `BlackholeNetwork`, a ledger, and
// participation key/factory/validator stubs — then hand them to
// `Parameters` and call `simulate(parameters, clock, n)`.
//
// Deliberately omitted in this iteration:
//   - `round_deadline` / ledger-wait watchdog. Implementing this requires
//     a shared handle to the ledger that the driver can poll
//     `round_notify` on; `Parameters` takes the ledger by value today, so
//     the driver doesn't see it. Will land with the follow-up test
//     infrastructure (TASK-90) that introduces a cloneable test ledger
//     with stake/sortition support — at which point it becomes possible
//     to assert "N blocks committed within deadline".
//   - Multi-round driving. Without participation keys the service never
//     produces a block, so the ledger never advances and a second
//     `clock.zero()` never fires. The 1-round smoke here exercises the
//     entire clock handshake; multi-round is unblocked by TASK-90.

pub mod blackhole_network;
pub mod instant_clock;

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
/// ledger-deadline watchdog — see the module-level doc comment for the
/// rationale and the TASK-90 follow-up pointer.
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
