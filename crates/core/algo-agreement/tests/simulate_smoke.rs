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

// The shared simulate test-support module carries more machinery than this
// binary consumes on its own (e.g. the multi-node testing_clock/
// testing_network/setup_agreement pieces added for issue #825/#827) —
// silence the per-binary dead-code lint the unused parts would otherwise
// trip.
#[allow(dead_code, unused_imports)]
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

use crate::simulate::{simulate, simulate_until_committed, BlackholeNetwork, InstantClock};

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
        signing_keys: std::collections::HashMap::new(),
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
        signing_keys: std::collections::HashMap::new(),
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

// ---------------------------------------------------------------------------
// Multi-round simulate smoke (TASK-90)
// ---------------------------------------------------------------------------

/// Drives 3 rounds of agreement against a real pseudonode-signed test
/// ledger and asserts the acceptance criteria from TASK-90: ledger
/// advances past round 3, each round has a block + certificate, and at
/// least one round elects a Rust-generated proposer.
///
/// Verifies that the full pseudonode → bind → soft-vote → cert-vote →
/// `Action::Ensure` pipeline runs end-to-end against the deterministic
/// `TestLedger`. Three production fixes shipped under TASK-99 unblocked
/// this:
///
/// 1. **Bootstrap pseudonode dispatch.** The main loop now executes
///    `Action::Pseudonode` actions itself (since issue #482, right after
///    the demux thread acknowledges the rest of the same batch);
///    previously the bootstrap `Pseudonode(Assemble)` was sent straight
///    to the demux's no-op arm and dropped, so `make_proposals` never ran
///    and the player never saw a proposal.
/// 2. **Canonical `ProposalMachinePeriod` routing.** `RootRouter::dispatch`
///    now routes `ProposalMachinePeriod` queries (`ProposalFrozen`,
///    `ReadStaging`, `ReadLowestVote`) through `ProposalManager.stores[r]
///    .trackers[p]` — the same `ProposalTracker` that absorbed the
///    `VoteVerified` events. Previously they read from the legacy
///    `PeriodRouter.proposal_tracker` mirror, which is never written by
///    production dispatch, so `issue_soft_vote` saw `BOTTOM` and skipped.
/// 3. **Commit-driven simulate loop.** [`simulate_until_committed`]
///    polls the ledger and runs `clock.run_round` while
///    `ledger.next_round() <= target`, mirroring Go's
///    `for ledger.NextRound() < stopRound` shape; the previous
///    fixed-count loop shut down the service mid-round on the third
///    iteration.
#[test]
fn simulate_three_rounds_commits_three_blocks() {
    use crate::simulate::test_account::generate_n_accounts;
    use crate::simulate::test_factory::{
        signing_keys_from_accounts, AutoBlockFactory, TestKeyManager,
    };
    use crate::simulate::test_ledger::TestLedger;

    // Diagnostic tracing subscriber — read RUST_LOG to scope verbosity.
    // `try_init` so concurrent tests in the binary don't double-init.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    let params = v41_params();
    let key_dilution = params.default_key_dilution;
    let target_round = Round(3);

    // Four staked accounts — each holds 1/4 of total online stake. With
    // committee sizes of 2_990 (soft) and 1_500 (cert) under v41 and
    // each account's expected weight ≈ committee_size / 4, the sum of
    // selected weights reliably crosses quorum across 4 accounts.
    let accounts = generate_n_accounts(
        4,
        Round(0),
        Round(target_round.0 + 10),
        key_dilution,
        0xa9_3e,
    );

    let key_manager = TestKeyManager::new(&accounts);
    let log = key_manager.log();
    let ledger = TestLedger::new(
        &accounts,
        100_000,
        params.clone(),
        algo_types::CONSENSUS_V41.to_string(),
    );
    let ledger_handle = ledger.clone();

    // Move secrets into the signing-keys map; `accounts` is consumed.
    let (signing_keys, _addrs) = signing_keys_from_accounts(accounts);

    let clock = InstantClock::new();
    let monitor = clock.make_monitor();
    let agreement_params = Parameters {
        network: BlackholeNetwork::new(),
        ledger,
        key_manager,
        block_factory: AutoBlockFactory,
        block_validator: StubBlockValidator::accepting(),
        random_source: StubRandomSource::constant(0),
        monitor,
        crypto: StubCryptoVerifier::new(),
        clock: Arc::clone(&clock) as Arc<dyn algo_agreement::Clock>,
        crash_db: None,
        signing_keys,
    };

    // The driver reads `next_round` through this clone of the ledger
    // handle so it can poll commit progress without re-borrowing the
    // ledger that's already moved into `agreement_params`.
    let ledger_for_driver = ledger_handle.clone();
    let handle = thread::Builder::new()
        .name("simulate-three-rounds-driver".into())
        .spawn(move || {
            simulate_until_committed(agreement_params, clock, target_round, move || {
                ledger_for_driver.next_round()
            })
        })
        .expect("spawn simulate thread");

    // 30s budget — three rounds with a real pseudonode + sortition +
    // bundle generation should finish in a small fraction of that even
    // on a busy CI runner. A timeout indicates a deadlock.
    join_with_timeout(handle, Duration::from_secs(30))
        .expect("simulate did not complete within 30s — likely a consensus deadlock");

    // Acceptance #1: ledger advanced past round 3 → rounds 1..=3 committed.
    let next = ledger_handle.next_round();
    assert!(
        next.0 > target_round.0,
        "expected next_round > {} after committing 3 rounds, got {}",
        target_round.0,
        next.0,
    );

    // Acceptance #2: each of the 3 rounds has both a block AND a cert.
    for r in 1..=target_round.0 {
        let r = Round(r);
        assert!(
            ledger_handle.block(r).is_some(),
            "round {r} block not committed",
        );
        assert!(
            ledger_handle.cert(r).is_some(),
            "round {r} certificate not recorded",
        );
    }

    // Acceptance #3: at least one round elected a proposer from our
    // test accounts. The KeyManager records `Proposed` per successful
    // sortition; with 4 accounts holding all online stake, every round
    // is expected to elect at least one.
    let log = log.lock().unwrap();
    let any_round_proposed = (1..=target_round.0).map(Round).any(|r| log.proposed_in(r));
    assert!(
        any_round_proposed,
        "expected ≥1 round to elect a Rust-generated proposer; participation log: {:?}",
        log.entries,
    );
}

/// Regression test for issue #482: `Assemble` for round N must never run
/// before `Ensure` has committed block N-1.
///
/// Production block assembly (`TransactionPool::assemble_empty_block`) reads
/// round N-1's block header out of the ledger, so a proposal for round N can
/// only be built once round N-1 is committed. The agreement main loop used to
/// execute a batch's `Pseudonode(Assemble N)` action *before* sending the same
/// batch — which begins with `Ensure(block N-1)` — to the demux thread that
/// actually performs it. The result in a live mixed Go/Rust cluster: every
/// proposal attempt failed with
/// `TransactionPool.assembleEmptyBlock: cannot get prev header for N-1`, so
/// the Rust node voted normally but proposed 0 of 287 blocks.
///
/// [`PrevRoundGuardBlockFactory`] reproduces that ledger dependency
/// deterministically: it refuses to assemble round N unless the ledger's
/// `next_round()` has already reached N (i.e. N-1 is committed) and records
/// every refusal. With the ordering bug present, the very first round records
/// a failure and — because a blackhole network means the only proposals are
/// the ones this node assembles — no round ever commits, so the driver hits
/// its join deadline.
#[test]
fn assemble_never_runs_before_previous_round_is_committed() {
    use crate::simulate::test_account::generate_n_accounts;
    use crate::simulate::test_factory::{
        signing_keys_from_accounts, PrevRoundGuardBlockFactory, TestKeyManager,
    };
    use crate::simulate::test_ledger::TestLedger;

    let params = v41_params();
    let key_dilution = params.default_key_dilution;
    let target_round = Round(3);

    let accounts = generate_n_accounts(
        4,
        Round(0),
        Round(target_round.0 + 10),
        key_dilution,
        0xa9_3e,
    );

    let key_manager = TestKeyManager::new(&accounts);
    let ledger = TestLedger::new(
        &accounts,
        100_000,
        params.clone(),
        algo_types::CONSENSUS_V41.to_string(),
    );
    let ledger_handle = ledger.clone();

    let (signing_keys, _addrs) = signing_keys_from_accounts(accounts);

    // The factory reads committed progress through its own ledger handle,
    // exactly as the production pool reads the shared `SqliteLedger`.
    let ledger_for_factory = ledger_handle.clone();
    let block_factory = PrevRoundGuardBlockFactory::new(move || ledger_for_factory.next_round());
    let failures = block_factory.failures();

    let clock = InstantClock::new();
    let monitor = clock.make_monitor();
    let agreement_params = Parameters {
        network: BlackholeNetwork::new(),
        ledger,
        key_manager,
        block_factory,
        block_validator: StubBlockValidator::accepting(),
        random_source: StubRandomSource::constant(0),
        monitor,
        crypto: StubCryptoVerifier::new(),
        clock: Arc::clone(&clock) as Arc<dyn algo_agreement::Clock>,
        crash_db: None,
        signing_keys,
    };

    let ledger_for_driver = ledger_handle.clone();
    let handle = thread::Builder::new()
        .name("simulate-assemble-ordering-driver".into())
        .spawn(move || {
            simulate_until_committed(agreement_params, clock, target_round, move || {
                ledger_for_driver.next_round()
            })
        })
        .expect("spawn simulate thread");

    join_with_timeout(handle, Duration::from_secs(30)).expect(
        "simulate did not complete within 30s — with the assemble/ensure ordering \
         broken no proposal can be built, so no round ever commits",
    );

    let failures = failures.lock().unwrap();
    assert!(
        failures.is_empty(),
        "Assemble ran before the previous round was committed (issue #482); \
         (requested round, ledger next_round) pairs: {:?}",
        failures,
    );

    // Sanity: the rounds really did commit (so the assertion above is not
    // vacuously true because assembly was never attempted).
    for r in 1..=target_round.0 {
        assert!(
            ledger_handle.block(Round(r)).is_some(),
            "round {r} block not committed",
        );
    }
}

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
    use algo_agreement::{types::TimeoutType, Clock, EventsProcessingMonitor};
    use crossbeam_channel::TryRecvError;
    // Seed the pseudonode queue as having pending work so the
    // post-TASK-90 filter-timer gate keeps the receiver alive
    // (sender held in `active_senders`). With an empty pseudonode
    // queue the receiver would surface as `Disconnected` immediately
    // — that's the firing-path covered by the simulate harness; here
    // we want to assert the *never-firing* baseline.
    let clock = InstantClock::new();
    clock.make_monitor().update_events_queue("pseudonode", 1);
    let rx = clock.timeout_at(Duration::from_secs(60), TimeoutType::Deadline);
    // The receiver must be open-but-empty (sender alive in
    // `active_senders`) — distinguish from `Disconnected` which would
    // indicate the sender was already dropped (only happens after
    // `shutdown()` or via the empty-queue fast-fire path).
    assert_eq!(
        rx.try_recv().unwrap_err(),
        TryRecvError::Empty,
        "first timeout_at with pending pseudonode work must return a live, never-firing receiver",
    );
}

#[test]
fn instant_clock_deadline_timeout_never_fires_until_shutdown() {
    use algo_agreement::{types::TimeoutType, Clock, EventsProcessingMonitor};
    use crossbeam_channel::TryRecvError;
    let clock = InstantClock::new();
    // Mark the pseudonode queue as having pending work; otherwise the
    // post-TASK-90 InstantClock fires Deadline timeouts immediately
    // (mirroring Go's `instant.HasPending("pseudonode")` gate). This
    // test asserts the *non-firing* path.
    clock.make_monitor().update_events_queue("pseudonode", 1);
    // Consume the first-call side effect (drops the timeout_at_sender).
    let _first = clock.timeout_at(Duration::from_secs(60), TimeoutType::Deadline);
    // A subsequent Deadline timeout should be "open but empty" pre-shutdown
    // — with pending pseudonode work, the timer never fires; the driver
    // advances rounds via `run_round`, not by firing deadline timers.
    // `try_recv` distinguishes `Empty` (sender alive, no message) from
    // `Disconnected` — we want `Empty`, asserting the sender is still
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
