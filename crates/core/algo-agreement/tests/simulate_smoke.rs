// Integration smoke test for the deterministic agreement simulation driver
// (TASK-81).
//
// Verifies that `simulate::simulate(...)` can:
//   1. Construct an agreement `Service` with an injected `InstantClock`,
//      `BlackholeNetwork`, and stub implementations of every other role.
//   2. Rendezvous with the service's first `clock.zero()` via
//      `InstantClock::run_round` (the key piece the whole mock-clock story
//      depends on).
//   3. Shut down cleanly without deadlocking.
//
// Full end-to-end "3 blocks committed + 3 certificates" assertion requires
// participation-key / stake / sortition infrastructure that the existing
// stubs don't yet expose — that's tracked in its own follow-up task (see
// PR body). The pieces delivered here (the InstantClock + BlackholeNetwork
// + simulate fn) are the *driver* the follow-up will build on top of.

#![deny(unsafe_code)]

mod simulate;

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use algo_agreement::{
    stubs::{
        StubBlockFactory, StubBlockValidator, StubCryptoVerifier, StubLedger, StubRandomSource,
    },
    AgreementKeyManager, Parameters, ParticipationAction, ParticipationRecord,
};
use algo_types::{Address, ConsensusParams, Round};

use crate::simulate::{simulate, BlackholeNetwork, InstantClock};

fn v41_params() -> ConsensusParams {
    algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
        .expect("v41 params available")
}

/// Key manager with no participation keys — the simulate smoke test only
/// verifies the driver plumbing, not sortition. Matches the simpler
/// `EmptyKeyManager` used elsewhere in `service_test.rs`.
struct EmptyKeyManager;
impl AgreementKeyManager for EmptyKeyManager {
    fn voting_keys(&self, _voting_round: Round, _keys_round: Round) -> Vec<ParticipationRecord> {
        Vec::new()
    }
    fn record(&self, _account: &Address, _round: Round, _action: ParticipationAction) {}
}

#[test]
fn simulate_zero_rounds_returns_immediately() {
    // With n=0 the driver should never invoke `run_round` — it simply starts
    // and shuts down the service. This catches startup-path regressions in
    // the `Parameters` construction, the Clock wiring, and the BlackholeNetwork
    // message-channel registration.
    let clock = InstantClock::new();
    let monitor = clock.make_monitor();
    let params = Parameters {
        network: BlackholeNetwork::new(),
        ledger: StubLedger::new(v41_params(), Round(1)),
        key_manager: EmptyKeyManager,
        block_factory: StubBlockFactory::new(),
        block_validator: StubBlockValidator::accepting(),
        random_source: StubRandomSource::constant(0),
        monitor,
        crypto: StubCryptoVerifier::new(),
        clock: Arc::clone(&clock) as Arc<dyn algo_agreement::Clock>,
        crash_db: None,
    };

    simulate(params, clock, Round(0));
}

#[test]
fn simulate_one_round_completes_clock_handshake() {
    // n=1 exercises one full `run_round` ↔ `clock.zero()` rendezvous.
    // With `EmptyKeyManager` the service can't advance the ledger, but the
    // clock handshake still proceeds: the service's first Rezero action
    // triggers `clock.zero()`, which our driver's `run_round(0)` unblocks.
    //
    // We wrap the call in a spawned thread with a bounded join window so a
    // deadlocked driver fails the test instead of hanging CI indefinitely.
    let clock = InstantClock::new();
    let monitor = clock.make_monitor();
    let params = Parameters {
        network: BlackholeNetwork::new(),
        ledger: StubLedger::new(v41_params(), Round(1)),
        key_manager: EmptyKeyManager,
        block_factory: StubBlockFactory::new(),
        block_validator: StubBlockValidator::accepting(),
        random_source: StubRandomSource::constant(0),
        monitor,
        crypto: StubCryptoVerifier::new(),
        clock: Arc::clone(&clock) as Arc<dyn algo_agreement::Clock>,
        crash_db: None,
    };

    let handle = thread::Builder::new()
        .name("simulate-smoke-driver".into())
        .spawn(move || simulate(params, clock, Round(1)))
        .expect("spawn simulate thread");

    // 10s is plenty for a single-round rendezvous on any machine; a
    // deadlock would otherwise hang forever.
    match join_with_timeout(handle, Duration::from_secs(10)) {
        Ok(()) => {}
        Err(()) => {
            panic!("simulate did not complete within 10s — likely a clock handshake deadlock")
        }
    }
}

// NOTE: A multi-round simulate smoke (n=3+ with "3 blocks committed" /
// "3 certs produced" assertions) is deferred to a follow-up task. It
// requires participation-key + stake + sortition infrastructure beyond
// what the existing stubs provide — the service's ledger does not advance
// without a proposing participant, so subsequent `clock.zero()` calls are
// never issued. The driver delivered here (InstantClock + BlackholeNetwork
// + `simulate` fn) is the substrate the follow-up will build on.
//
// Follow-up will cover:
//   - Port of go-algorand's `generateNAccounts` (simulate_test.go:330) or
//     equivalent Rust-side helper that constructs real VRF + OTS keys.
//   - A test-ledger with stake/sortition support so `ensure_block` advances
//     the `next_round`.
//   - Assertions: 3 blocks committed, 3 certificates produced (matching
//     TASK-81's original acceptance criterion).

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Join a spawned test thread with a bounded wait. Returns `Err(())` on
/// timeout so the test can fail with a clear message instead of hanging.
fn join_with_timeout<T: Send + 'static>(
    handle: thread::JoinHandle<T>,
    budget: Duration,
) -> Result<T, ()> {
    let (tx, rx) = std::sync::mpsc::channel();
    let _reporter = thread::Builder::new()
        .name("simulate-smoke-joiner".into())
        .spawn(move || {
            let out = handle.join();
            let _ = tx.send(out);
        })
        .expect("spawn joiner thread");

    match rx.recv_timeout(budget) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => Err(()),
    }
}

// ---------------------------------------------------------------------------
// InstantClock trait-level tests (exercise the mock in isolation)
// ---------------------------------------------------------------------------

#[test]
fn instant_clock_since_is_zero() {
    let clock = InstantClock::new();
    assert_eq!(
        <InstantClock as algo_agreement::Clock>::since(&clock),
        Duration::ZERO,
        "InstantClock::since must always return Duration::ZERO (mirrors Go simulate.go:84)"
    );
}

#[test]
fn instant_clock_first_timeout_at_returns_never_channel() {
    use algo_agreement::{types::TimeoutType, Clock};
    let clock = InstantClock::new();
    let rx = clock.timeout_at(Duration::from_secs(60), TimeoutType::Deadline);
    // A "never" channel never delivers; a short poll should time out.
    assert!(
        rx.recv_timeout(Duration::from_millis(20)).is_err(),
        "first timeout_at must return a never-firing receiver"
    );
}

#[test]
fn instant_clock_deadline_timeout_never_fires_until_shutdown() {
    use algo_agreement::{types::TimeoutType, Clock};
    use crossbeam_channel::TryRecvError;
    let clock = InstantClock::new();
    // Consume the first-call side effect (drops the timeout_at_sender).
    let _first = clock.timeout_at(Duration::from_secs(60), TimeoutType::Deadline);
    // A subsequent Deadline timeout should be "open but empty" pre-shutdown
    // — the driver advances rounds via `run_round`, not by firing deadline
    // timers. `try_recv` distinguishes `Empty` (sender alive, no message)
    // from `Disconnected` — we want `Empty`, asserting the sender is still
    // held inside `active_senders`.
    let rx = clock.timeout_at(Duration::from_millis(1), TimeoutType::Deadline);
    assert_eq!(
        rx.try_recv().unwrap_err(),
        TryRecvError::Empty,
        "Deadline receiver should be Empty pre-shutdown (sender held in active_senders)"
    );
    // After shutdown, the sender held inside `active_senders` is dropped,
    // so `try_recv` on the receiver we captured above must surface
    // `Disconnected` — not `Empty`. This is exactly the wake-up the real
    // service's `Select::select` depends on.
    clock.shutdown();
    // Allow the sender drop to propagate; crossbeam guarantees eventual
    // visibility but the mutex release ordering can lag a hair.
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(
        rx.try_recv().unwrap_err(),
        TryRecvError::Disconnected,
        "shutdown() must disconnect live timeout receivers so the demux wakes"
    );
}

#[test]
fn instant_clock_timeout_after_shutdown_surfaces_immediately() {
    use algo_agreement::{types::TimeoutType, Clock};
    use crossbeam_channel::TryRecvError;
    // Regression: a `timeout_at` request that races `shutdown()` and lands
    // AFTER the flag flips must return a pre-disconnected receiver —
    // otherwise its sender would live outside `active_senders` and the
    // demux would park forever. Assert `Disconnected` specifically (not
    // merely `is_err`) so a future regression returning a never-channel
    // here would fail loudly.
    let clock = InstantClock::new();
    clock.shutdown();
    let rx = clock.timeout_at(Duration::from_secs(60), TimeoutType::Deadline);
    assert_eq!(
        rx.try_recv().unwrap_err(),
        TryRecvError::Disconnected,
        "post-shutdown timeout_at must return a Disconnected receiver, not a never-channel"
    );
}

#[test]
fn instant_clock_zero_rendezvous_with_run_round() {
    // Directly exercise the Z0/Z1/timeout_at rendezvous pattern from a pair
    // of threads (no Service involved) — verifies the handshake primitive
    // independent of any agreement plumbing.
    use algo_agreement::{types::TimeoutType, Clock};

    let clock = InstantClock::new();

    let driver_clock = Arc::clone(&clock);
    let driver = thread::spawn(move || {
        // Must be called AFTER Service-equivalent has reached the zero()
        // call site. For this direct test we can just call it immediately;
        // the main thread below will call zero() + timeout_at in short
        // order.
        driver_clock.run_round(Round(0));
    });

    // "Service" side — do the calls run_round expects.
    thread::sleep(Duration::from_millis(5)); // let driver park on z1_rx
    clock.zero(); // Z0 push + Z1 rendezvous (blocks until driver reads)
    let _rx = clock.timeout_at(Duration::from_secs(60), TimeoutType::Deadline);

    // If everything is wired correctly, run_round returns and the thread
    // joins cleanly. A deadlock here would hang the test.
    join_with_timeout(driver, Duration::from_secs(5))
        .expect("zero()/run_round rendezvous deadlocked");
}
