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

use algo_agreement::crypto_verifier::AsyncCryptoVerifier;
use algo_agreement::stubs::StubBlockValidator;
use algo_agreement::{AccountSigningKeys, Clock, Parameters, RandomSource, Service, ServiceHandle};
use algo_types::{ConsensusParams, Round};

use super::activity_monitor::ActivityMonitor;
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
pub struct AgreementCluster {
    pub network: Arc<TestingNetwork>,
    pub start_round: Round,
    pub clocks: Vec<Arc<TestingClock>>,
    pub ledgers: Vec<TestLedger>,
    pub monitor: Arc<ActivityMonitor>,
    handles: Cell<Vec<ServiceHandle>>,
}

impl AgreementCluster {
    /// Block until every node's demux/pseudonode-reported queues and every
    /// network channel are empty and stay empty for the debounce window.
    /// Thin wrapper over `ActivityMonitor::wait_for_quiet` so call sites
    /// don't need to know about the network-pending-count plumbing.
    pub fn wait_for_quiet(&self) {
        self.monitor
            .wait_for_quiet(&self.network, &self.clocks, || 0);
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
    let buf_capacity = 1000;
    let consensus_version = algo_types::CONSENSUS_V41;
    let params: ConsensusParams =
        algo_types::consensus::consensus_params_for_version(consensus_version)
            .expect("v41 consensus params available");

    let mut accounts: Vec<TestAccount> =
        generate_n_accounts(n, Round(0), Round(1000), 10_000, rand_salt());

    // Every node gets its OWN ledger instance seeded from the same account
    // balances (mirrors go's `ledgers[i] = ledgerFactory(balances)` — a
    // fresh ledger per node, not a shared one).
    let mut ledgers = Vec::with_capacity(n);
    for _ in 0..n {
        ledgers.push(TestLedger::new(
            &accounts,
            1_000_000_000_000,
            params.clone(),
            consensus_version.to_string(),
        ));
    }
    let start_round = ledgers[0].next_round();

    let network = TestingNetwork::new(n, buf_capacity);
    let monitor = ActivityMonitor::new(n);

    let mut clocks = Vec::with_capacity(n);
    let mut handles = Vec::with_capacity(n);

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
        let crypto = AsyncCryptoVerifier::new(Arc::new(ledger.clone()));

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

        let handle = Service::new(this_params).start();
        clocks.push(clock);
        handles.push(handle);
    }

    AgreementCluster {
        network,
        start_round,
        clocks,
        ledgers,
        monitor,
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
