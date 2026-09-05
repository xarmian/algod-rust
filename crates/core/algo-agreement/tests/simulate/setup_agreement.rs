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

// Wires up a full N-node agreement cluster over `TestingNetwork` /
// `TestingClock`, each node running a REAL `Service` (real threads, real
// `AsyncCryptoVerifier`-backed vote/proposal/bundle verification, real
// VRF/OTS-signed sortition via `AsyncPseudonode`).
//
// Mirrors go-algorand's `agreement/service_test.go::setupAgreement` /
// `setupAgreementWithValidator` — one account per node (mirroring go's
// `keys := makeRecordingKeyManager(accounts[i:i+1])`), all accounts online
// in every node's ledger (mirroring go's `ledgers[i] = ledgerFactory(balances)`
// — go gives every node an *independently constructed* ledger over the same
// balances, not a shared one; this port does the same via `TestLedger::new`
// per node).
//
// Divergence from go, noted once here rather than at every call site:
// go's `setupAgreement` returns *unstarted* services (the test calls
// `services[i].Start()` itself); this port starts every node's `Service`
// before returning, since algod-rust's `Service::start()` both spawns the
// real threads and returns the `ServiceHandle` needed for shutdown in one
// step, and every scenario ported so far starts every node immediately
// anyway.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Arc;

use algo_agreement::stubs::StubBlockValidator;
use algo_agreement::{
    AccountSigningKeys, AsyncCryptoVerifier, Clock, CryptoVerifier, NoOpValidator, Parameters,
    ProposeBroadcastHook, RandomSource, Service, ServiceHandle, AGREEMENT_VOTE_TAG,
    PROPOSAL_PAYLOAD_TAG, VOTE_BUNDLE_TAG,
};
use algo_types::{ConsensusParams, Round};

use super::activity_monitor::ActivityMonitor;
use super::propose_broadcast_gate::ProposeBroadcastGate;
use super::suspendable_validator::SuspendableBlockValidator;
use super::test_account::{generate_n_accounts, TestAccount};
use super::test_factory::{AutoBlockFactory, TestKeyManager};
use super::test_ledger::TestLedger;
use super::testing_clock::TestingClock;
use super::testing_network::TestingNetwork;

/// Fixed-value `RandomSource`, mirroring go's `testingRand{}`: `Uint64()`
/// always returns `math.MaxUint64 / 2`.
struct FixedRandomSource;

impl RandomSource for FixedRandomSource {
    fn uint64(&self) -> u64 {
        u64::MAX / 2
    }
}

/// Everything a theme-3 service-level test needs: the shared network (for
/// `drop_all_*`/`repair_all`), the per-node `TestingClock` handles (for
/// `fire`), the per-node `TestLedger` handles (for post-run sanity checks),
/// the shared `ActivityMonitor`, and the running `ServiceHandle`s.
///
/// `shutdown()` must be called before the test returns (put it behind a
/// `defer`-equivalent — a local closure or just call it at the end of a
/// `#[test]` fn body) — mirrors go's `cleanupFn`.
pub struct AgreementCluster<
    BV: algo_agreement::BlockValidator + Send + Sync + 'static = NoOpValidator,
> {
    pub network: Arc<TestingNetwork>,
    pub start_round: Round,
    pub clocks: Vec<Arc<TestingClock>>,
    pub ledgers: Vec<TestLedger>,
    pub monitor: Arc<ActivityMonitor>,
    /// Per-node handle to the SAME `AsyncCryptoVerifier` instance each
    /// `Service` is actually running against (a second `Arc` clone of what
    /// was handed to `Parameters::crypto`, made possible by the
    /// `CryptoVerifier for Arc<C>` blanket impl added for this — see
    /// `wait_for_quiet`'s doc comment for why this is needed).
    verifiers: Vec<Arc<AsyncCryptoVerifier<TestLedger, BV>>>,
    handles: Cell<Vec<ServiceHandle>>,
}

impl<BV: algo_agreement::BlockValidator + Send + Sync + 'static> AgreementCluster<BV> {
    /// Sum, across every node, of proposal-verification requests currently
    /// blocked inside `BlockValidator::validate` — see
    /// `AsyncCryptoVerifier::pending_proposal_validations`'s doc comment.
    /// Used by scenarios driving a [`super::suspendable_validator::SuspendableBlockValidator`]
    /// (theme-3's `8ba23942` regression) to synchronize on a precise count
    /// of pending verifications rather than on quiescence (which, by
    /// design, never arrives while the validator stays suspended).
    pub fn pending_proposal_validations(&self) -> usize {
        self.verifiers
            .iter()
            .map(|v| v.pending_proposal_validations())
            .sum()
    }
    /// Block until every node's demux/pseudonode-reported queues, every
    /// network channel, AND every node's crypto-verifier output channels
    /// (votes/proposals/bundles verified but not yet drained by that node's
    /// demux thread) are empty and stay empty for the debounce window.
    ///
    /// Root-cause note (issue #920): this previously folded in a stubbed
    /// `|| 0` for the verifier-backlog term, even though
    /// `ActivityMonitor::wait_for_quiet`'s own doc comment claimed to check
    /// it. Under real-thread scheduling, a proposal payload can finish
    /// async verification (landing in `AsyncCryptoVerifier`'s output
    /// channel) in the same narrow window the poll sees every OTHER queue
    /// at zero, so `wait_for_quiet` returned before that node's demux
    /// thread actually drained and processed the result — i.e. before
    /// `staged_value` reflected it. `fast_recovery_late_five_node`/
    /// `fast_recovery_redo_five_node` (multi-fire fast-recovery scenarios
    /// spanning several settle points in quick succession) hit this gap
    /// often enough to be genuinely flaky; folding the verifiers' output
    /// channels into the quiescence check closes it.
    ///
    /// Also folds in `pending_proposal_validations()` (issue #825's
    /// coservice-count-equivalent primitive, added for the `8ba23942`
    /// investigation): a request that has been dequeued from
    /// `proposal_in_rx` but not yet resolved to `proposal_out_rx` (e.g.
    /// blocked inside a [`super::suspendable_validator::SuspendableBlockValidator`])
    /// is invisible to every OTHER term here (it has left the input
    /// channel but hasn't reached the output channel yet), so without this
    /// a driver that suspends validation mid-scenario would see a false
    /// "quiet" instead of the genuine stall. A caller that deliberately
    /// suspends a validator and wants to keep making progress elsewhere
    /// must poll `pending_proposal_validations()` directly instead of
    /// calling `wait_for_quiet()` during the suspended window — this method
    /// will now correctly refuse to report quiescence until resumed.
    pub fn wait_for_quiet(&self) {
        self.monitor
            .wait_for_quiet(&self.network, &self.clocks, || {
                self.verifiers
                    .iter()
                    .map(|v| {
                        v.verified_votes().len()
                            + v.verified(PROPOSAL_PAYLOAD_TAG).len()
                            + v.verified(VOTE_BUNDLE_TAG).len()
                            + v.pending_proposal_validations()
                            + (v.channel_full(AGREEMENT_VOTE_TAG)
                                || v.channel_full(PROPOSAL_PAYLOAD_TAG)
                                || v.channel_full(VOTE_BUNDLE_TAG))
                                as usize
                    })
                    .sum()
            });
    }

    /// Shut down every node: release each `TestingClock`'s pending
    /// receivers (so no thread stays parked in `Demux::next`'s `Select`
    /// forever — see `TestingClock::shutdown`'s doc comment) and then join
    /// every `ServiceHandle`. Mirrors go's `cleanupFn`.
    pub fn shutdown(&self) {
        for clock in &self.clocks {
            clock.shutdown();
        }
        for handle in self.handles.take() {
            handle.shutdown();
        }
    }
}

/// Build and start an `n`-node agreement cluster. Mirrors go's
/// `setupAgreement(t, numNodes, traceLevel, makeTestLedger)` — this port
/// always uses `TestLedger` (the sortition-aware, real-stake ledger from
/// the single-node full-consensus harness), which is go's `makeTestLedger`
/// equivalent.
pub fn setup_agreement(n: usize) -> AgreementCluster {
    setup_agreement_with_version_fn(n, None)
}

/// Like [`setup_agreement`], but installs `propose_gate` (issue #1035) as
/// every node's `Service::with_propose_broadcast_hook` — a single,
/// cluster-wide pause point on outbound proposal-payload broadcasts. Used by
/// scenarios (`SlowPayloadsPreDeadline`/`PostDeadline`) that need to arm
/// `pocket_all_compound` strictly BEFORE a specific round's proposal reaches
/// the network, without also needing a suspendable validator (unlike the
/// `8ba23942` regression — see [`setup_agreement_with_validator_and_propose_gate`]
/// for that combination).
pub fn setup_agreement_with_propose_gate(
    n: usize,
    propose_gate: Arc<ProposeBroadcastGate>,
) -> AgreementCluster {
    setup_agreement_inner(n, None, Some(propose_gate))
}

/// Like [`setup_agreement`], but installs `version_fn` (if given) on every
/// node's [`TestLedger`] via [`TestLedger::with_version_fn`] — mirrors go's
/// `setupAgreement(t, numNodes, traceLevel, ledgerFactory)` where
/// `ledgerFactory` is `makeTestLedgerWithConsensusVersion(data,
/// consensusVersion)` (used by `simulateAgreementWithConsensusVersion` /
/// `TestAgreementSynchronousFutureUpgrade`) instead of the fixed-version
/// `makeTestLedger`.
pub fn setup_agreement_with_version_fn(
    n: usize,
    version_fn: Option<Arc<dyn Fn(Round) -> String + Send + Sync>>,
) -> AgreementCluster {
    setup_agreement_inner(n, version_fn, None)
}

fn setup_agreement_inner(
    n: usize,
    version_fn: Option<Arc<dyn Fn(Round) -> String + Send + Sync>>,
    propose_gate: Option<Arc<ProposeBroadcastGate>>,
) -> AgreementCluster {
    let buf_capacity = 1000;
    let consensus_version = algo_types::CONSENSUS_V41;
    let params: ConsensusParams =
        algo_types::consensus::consensus_params_for_version(consensus_version)
            .expect("v41 consensus params available");

    let mut accounts: Vec<TestAccount> =
        generate_n_accounts(n, Round(0), Round(1000), 10_000, rand_salt());

    // Every node gets its OWN ledger instance seeded from the same account
    // balances (mirrors go's `ledgers[i] = ledgerFactory(balances)` — a
    // fresh ledger per node, not a shared one). They share ONE
    // `SharedCommits` registry so a node whose own vote tally never
    // reaches quorum locally (e.g. it missed the round's proposal payload
    // broadcast) can still catch up via `ensure_digest` — see
    // `test_ledger.rs`'s doc comment on `SharedCommits` for why this
    // matters: without it, that node stalls forever (issue #911).
    let shared_commits = super::test_ledger::SharedCommits::default();
    let mut ledgers = Vec::with_capacity(n);
    for _ in 0..n {
        let mut ledger = TestLedger::new(
            &accounts,
            1_000_000_000_000,
            params.clone(),
            consensus_version.to_string(),
        );
        ledger.share_commits(shared_commits.clone());
        if let Some(f) = version_fn.clone() {
            ledger = ledger.with_version_fn(move |r| f(r));
        }
        ledgers.push(ledger);
    }
    let start_round = ledgers[0].next_round();

    let network = TestingNetwork::new(n, buf_capacity);
    let monitor = ActivityMonitor::new(n);

    let mut clocks = Vec::with_capacity(n);
    let mut handles = Vec::with_capacity(n);
    let mut verifiers = Vec::with_capacity(n);

    for (i, account) in accounts.drain(..).enumerate() {
        // Node `i` only ever votes/proposes as its own account — mirrors
        // go's `makeRecordingKeyManager(accounts[i:i+1])`.
        let key_manager = TestKeyManager::new(std::slice::from_ref(&account));
        let TestAccount {
            address, vrf, ots, ..
        } = account;
        let mut signing_keys = HashMap::new();
        signing_keys.insert(address, AccountSigningKeys { vrf, ots });

        let clock = TestingClock::new();
        let ledger = ledgers[i].clone();
        // Wrapped in `Arc` (rather than handed to `Parameters::crypto` by
        // value) so the driver keeps a second handle to the SAME verifier
        // instance the `Service` runs against — needed by `wait_for_quiet`
        // to fold the verifier's output-channel backlog into its
        // quiescence check (issue #920). `Arc<AsyncCryptoVerifier<..>>`
        // satisfies `Parameters`'s `C: CryptoVerifier` bound via the
        // blanket `impl<C: CryptoVerifier> CryptoVerifier for Arc<C>`.
        let crypto = Arc::new(AsyncCryptoVerifier::new(Arc::new(ledger.clone())));
        verifiers.push(Arc::clone(&crypto));

        let this_params = Parameters {
            network: network.endpoint(i),
            ledger,
            key_manager,
            block_factory: AutoBlockFactory,
            block_validator: StubBlockValidator::accepting(),
            random_source: FixedRandomSource,
            monitor: monitor.listener(i),
            crypto,
            clock: Arc::clone(&clock) as Arc<dyn Clock>,
            crash_db: None,
            signing_keys,
        };

        let mut service = Service::new(this_params);
        if let Some(gate) = propose_gate.clone() {
            let hook: ProposeBroadcastHook = Arc::new(move || gate.on_broadcast());
            service = service.with_propose_broadcast_hook(hook);
        }
        let handle = service.start();
        clocks.push(clock);
        handles.push(handle);
    }

    AgreementCluster {
        network,
        start_round,
        clocks,
        ledgers,
        monitor,
        verifiers,
        handles: Cell::new(handles),
    }
}

/// Like [`setup_agreement`], but wires EVERY node's `AsyncCryptoVerifier` to
/// the SAME `validator` handle (clones of one `SuspendableBlockValidator`,
/// sharing its inner gate — see that type's doc comment) instead of the
/// fixed `NoOpValidator`. Mirrors go's `setupAgreementWithValidator`, whose
/// single `validator BlockValidator` argument is handed to every node's
/// `Parameters.BlockValidator` AND to the shared `testingNetwork` (which
/// wires it into every node's crypto verifier) — a genuinely global,
/// cluster-wide suspend switch, used by
/// `TestAgreementRegression_WrongPeriodPayloadVerificationCancellation_8ba23942`
/// to pin every node's stale-period proposal-payload verification in place
/// at once.
///
/// Note: this only swaps the crypto verifier's validator (the one actually
/// exercised by real proposal-payload verification). Each node's
/// `Parameters::block_validator` (the separate, ensure-path fallback used by
/// `do_ensure_action`/`set_prev_timestamp` — see `crypto_verifier.rs`'s and
/// `service.rs`'s independent `BV` type parameters) stays the ordinary
/// always-accepting `StubBlockValidator`, since a block already carrying a
/// crypto-verifier-attached `ValidatedBlock` never re-enters
/// `BlockValidator::validate` on the ensure path — go's version shares one
/// instance for both roles only because its ensure path also always takes
/// the already-validated fast path in these scenarios, so this is a
/// behavior-preserving simplification, not a divergence.
pub fn setup_agreement_with_validator(
    n: usize,
    validator: SuspendableBlockValidator,
) -> AgreementCluster<SuspendableBlockValidator> {
    build_cluster_with_validator(n, validator, None)
}

/// Like [`setup_agreement_with_validator`], but additionally installs
/// `propose_gate` as every node's `Service::with_propose_broadcast_hook`
/// (issue #1035) — a single, cluster-wide pause point on outbound
/// proposal-payload broadcasts. Used by scenarios (the `8ba23942`
/// regression) that need to arm a suspension/pocketing setup strictly
/// BEFORE a specific round/period transition's proposal reaches the
/// network, not just after the previous round's `wait_for_quiet` settles —
/// see `propose_broadcast_gate.rs`'s module doc comment for why
/// `wait_for_quiet` alone is provably too late for that.
pub fn setup_agreement_with_validator_and_propose_gate(
    n: usize,
    validator: SuspendableBlockValidator,
    propose_gate: Arc<ProposeBroadcastGate>,
) -> AgreementCluster<SuspendableBlockValidator> {
    build_cluster_with_validator(n, validator, Some(propose_gate))
}

fn build_cluster_with_validator(
    n: usize,
    validator: SuspendableBlockValidator,
    propose_gate: Option<Arc<ProposeBroadcastGate>>,
) -> AgreementCluster<SuspendableBlockValidator> {
    let buf_capacity = 1000;
    let consensus_version = algo_types::CONSENSUS_V41;
    let params: ConsensusParams =
        algo_types::consensus::consensus_params_for_version(consensus_version)
            .expect("v41 consensus params available");

    let mut accounts: Vec<TestAccount> =
        generate_n_accounts(n, Round(0), Round(1000), 10_000, rand_salt());

    let shared_commits = super::test_ledger::SharedCommits::default();
    let mut ledgers = Vec::with_capacity(n);
    for _ in 0..n {
        let mut ledger = TestLedger::new(
            &accounts,
            1_000_000_000_000,
            params.clone(),
            consensus_version.to_string(),
        );
        ledger.share_commits(shared_commits.clone());
        ledgers.push(ledger);
    }
    let start_round = ledgers[0].next_round();

    let network = TestingNetwork::new(n, buf_capacity);
    let monitor = ActivityMonitor::new(n);

    let mut clocks = Vec::with_capacity(n);
    let mut handles = Vec::with_capacity(n);
    let mut verifiers = Vec::with_capacity(n);

    for (i, account) in accounts.drain(..).enumerate() {
        let key_manager = TestKeyManager::new(std::slice::from_ref(&account));
        let TestAccount {
            address, vrf, ots, ..
        } = account;
        let mut signing_keys = HashMap::new();
        signing_keys.insert(address, AccountSigningKeys { vrf, ots });

        let clock = TestingClock::new();
        let ledger = ledgers[i].clone();
        let crypto = Arc::new(AsyncCryptoVerifier::new_with_validator(
            Arc::new(ledger.clone()),
            Arc::new(validator.clone()),
        ));
        verifiers.push(Arc::clone(&crypto));

        let this_params = Parameters {
            network: network.endpoint(i),
            ledger,
            key_manager,
            block_factory: AutoBlockFactory,
            block_validator: StubBlockValidator::accepting(),
            random_source: FixedRandomSource,
            monitor: monitor.listener(i),
            crypto,
            clock: Arc::clone(&clock) as Arc<dyn Clock>,
            crash_db: None,
            signing_keys,
        };

        let mut service = Service::new(this_params);
        if let Some(gate) = propose_gate.clone() {
            let hook: ProposeBroadcastHook = Arc::new(move || gate.on_broadcast());
            service = service.with_propose_broadcast_hook(hook);
        }
        let handle = service.start();
        clocks.push(clock);
        handles.push(handle);
    }

    AgreementCluster {
        network,
        start_round,
        clocks,
        ledgers,
        monitor,
        verifiers,
        handles: Cell::new(handles),
    }
}

/// Namespacing salt for `generate_n_accounts` so repeated calls across
/// tests in the same process don't collide on VRF-derived addresses. A
/// process-local atomic counter is enough — the accounts only need to be
/// distinct within one test's cluster, not globally stable.
fn rand_salt() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0xA6ED);
    COUNTER.fetch_add(1, Ordering::SeqCst)
}
