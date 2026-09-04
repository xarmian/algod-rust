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

// In-memory ledger with stake / sortition / auto-advance support, used by
// the full-consensus simulate harness.
//
// Mirrors go-algorand `agreement/agreementtest/simulate_test.go::testLedger`
// at the level of behavior the agreement service relies on:
//
//   - `seed(round)` returns the per-round VRF seed used as input to
//     committee sortition.
//   - `lookup_agreement(round, addr)` returns the address's online stake +
//     voting keys (`vote_id`, `selection_id`).
//   - `circulation(rnd, vote_rnd)` returns the total online stake. The
//     committee module divides each vote's stake by this to derive the
//     sortition probability.
//   - `ensure_block(b, c)` records the certified block + certificate AND
//     advances `next_round`, firing pending `round_notify` waiters. This
//     is the piece the existing `StubLedger` punts on: tests today have
//     to call `advance_round(...)` explicitly. The simulate harness needs
//     auto-advance so the service can move past round N to round N+1
//     without driver-side glue.
//
// Implementation: an `Arc<Mutex<TestLedgerState>>` that the harness can
// clone freely. The wrapper struct `TestLedger` owns one `Arc` clone and
// implements both `LedgerReader` + `LedgerWriter`. Test code can keep a
// second clone via [`TestLedger::handle`] to read assertions out of the
// committed-blocks map after `simulate(...)` returns.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use algo_agreement::{
    Certificate, LedgerError, LedgerReader, LedgerWriter, OnlineAccountData, Seed, ValidatedBlock,
};
use algo_types::{Address, Block, ConsensusParams, Digest, Round};
use crossbeam_channel::Sender;

use super::test_account::TestAccount;

/// Cluster-wide registry of committed `(Block, Certificate)` pairs, keyed by
/// round, shared by every node's [`TestLedger`] in a multi-node cluster.
///
/// This is what makes [`TestLedger::ensure_digest`] a real (if simplified)
/// catch-up path instead of a no-op: when a node reaches vote quorum for a
/// round but hasn't itself received/staged that round's proposal payload
/// (a real possibility — proposal broadcasts can race a slower node's round
/// transition, or simply be dropped in flight, exactly as on a real
/// network), go-algorand's production code calls `EnsureDigest` to fetch the
/// block from a peer via the ledger's catchup service and commit it that
/// way instead of via its own vote tally. Single-`TestLedger` tests (that
/// don't go through this path) are unaffected: each `TestLedger::new` call
/// still gets its own private, empty registry unless explicitly shared via
/// [`TestLedger::share_commits`].
pub type SharedCommits = Arc<Mutex<HashMap<Round, (Block, Certificate)>>>;

/// Inner mutable state for the test ledger — guarded by a single mutex so
/// the read + write paths can race safely.
pub struct TestLedgerState {
    /// Committed blocks keyed by round.
    pub blocks: HashMap<Round, Block>,
    /// Certificates keyed by round.
    pub certs: HashMap<Round, Certificate>,
    /// Per-round seeds. Pre-populated for the first
    /// `seed_lookback` rounds; subsequent rounds inherit the previous
    /// seed (the test factory doesn't propagate VRF-derived seeds, so a
    /// stable seed is sufficient for sortition to elect proposers).
    pub seeds: HashMap<Round, Seed>,
    /// Per-round block digests. Round 0 is pre-populated with a
    /// synthetic genesis digest so `lookup_digest(0)` resolves for
    /// verifier paths that mix in the previous block's digest at round 1.
    /// `ensure_block` records the actual block's digest under its round.
    pub digests: HashMap<Round, Digest>,
    /// Per-address online account data. The test never changes account
    /// state, so a single map (addr → data) suffices regardless of the
    /// queried round.
    pub accounts: HashMap<Address, OnlineAccountData>,
    /// Total online circulation (= sum of `accounts[].micro_algos`).
    pub circulation: u64,
    /// Consensus params (same for every round), used when [`Self::version_fn`]
    /// is `None`.
    pub params: ConsensusParams,
    /// Consensus version string, used when [`Self::version_fn`] is `None`.
    pub version: String,
    /// When set, overrides `version`/`params` with a per-round consensus
    /// version — mirrors go's `makeTestLedgerWithConsensusVersion`
    /// (`agreement/agreementtest/simulate_test.go`), which lets a test
    /// select a different `protocol.ConsensusVersion` per round (e.g.
    /// `TestAgreementSynchronousFutureUpgrade`'s round >= 5 ->
    /// `ConsensusFuture` switch). `consensus_params(round)` resolves the
    /// selected version's params via
    /// `algo_types::consensus::consensus_params_for_version`.
    pub version_fn: Option<Arc<dyn Fn(Round) -> String + Send + Sync>>,
    /// Next round = highest committed round + 1.
    pub next_rnd: Round,
    /// Pending `round_notify` waiters: `(requested_round, sender)`.
    pub waiters: Vec<(Round, Sender<Round>)>,
}

/// Cloneable handle to the test ledger.
///
/// `Service` consumes the ledger by value via `Parameters`, so to read
/// post-run assertions out of the same state the harness must hold a
/// second handle. Cloning `TestLedger` clones the inner `Arc<Mutex<_>>`,
/// not the state.
#[derive(Clone)]
pub struct TestLedger {
    state: Arc<Mutex<TestLedgerState>>,
    /// Cluster-wide committed-block registry — see [`SharedCommits`]. Each
    /// `TestLedger::new` call gets its own private, empty registry by
    /// default; multi-node callers wire every node's ledger to the same
    /// one via [`TestLedger::share_commits`] so `ensure_digest` can
    /// actually catch a lagging node up.
    shared_commits: SharedCommits,
}

impl TestLedger {
    /// Construct a fresh ledger with `accounts` online. Each account
    /// holds `stake_per_account` microAlgos; total circulation is
    /// `n_accounts * stake_per_account`.
    ///
    /// Pre-populates a stable seed for round 0 so the `seed_round(R)`
    /// lookback (which lands on round 0 for small R under v41) resolves
    /// without panicking.
    pub fn new(
        accounts: &[TestAccount],
        stake_per_account: u64,
        params: ConsensusParams,
        version: String,
    ) -> Self {
        let mut acct_map = HashMap::with_capacity(accounts.len());
        for a in accounts {
            acct_map.insert(
                a.address,
                OnlineAccountData {
                    micro_algos: stake_per_account,
                    vote_id: a.vote_id,
                    selection_id: a.selection_id(),
                    vote_first_valid: a.vote_first_valid,
                    vote_last_valid: a.vote_last_valid,
                    vote_key_dilution: a.vote_key_dilution,
                    incentive_eligible: false,
                    last_proposed: Round(0),
                    last_heartbeat: Round(0),
                    state_proof_id: [0u8; 64],
                },
            );
        }
        let circulation = stake_per_account.saturating_mul(accounts.len() as u64);

        let mut seeds = HashMap::new();
        // Stable, non-zero seed for round 0 — feeds into VRF sortition
        // for the earliest rounds.
        seeds.insert(Round(0), Seed([0x42u8; 32]));

        // Pre-populate a synthetic genesis digest at round 0 so
        // `lookup_digest(0)` doesn't return `RoundNotAvailable` for
        // verifier paths that mix in the previous block's digest at
        // round 1. The actual bytes don't matter — the agreement
        // service hashes them in but never inspects the value.
        let mut digests = HashMap::new();
        digests.insert(Round(0), Digest([0u8; 32]));

        let state = TestLedgerState {
            blocks: HashMap::new(),
            digests,
            certs: HashMap::new(),
            seeds,
            accounts: acct_map,
            circulation,
            params,
            version,
            version_fn: None,
            // The ledger starts "at round 1" — i.e., round 0 is implicitly
            // "the genesis" and the agreement service drives round 1 next.
            next_rnd: Round(1),
            waiters: Vec::new(),
        };
        Self {
            state: Arc::new(Mutex::new(state)),
            shared_commits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Wire this ledger's committed-block registry to `shared` — call once
    /// per node right after construction, all with the SAME `shared`
    /// handle, so [`LedgerWriter::ensure_digest`] can serve a lagging
    /// node's catch-up fetch from whichever peer's ledger already committed
    /// that round. Mirrors go-algorand's real ledger catchup fetcher, at
    /// the granularity this in-memory harness needs (no wire encoding: the
    /// `Block`/`Certificate` values are shared directly rather than
    /// serialized and re-verified).
    pub fn share_commits(&mut self, shared: SharedCommits) {
        self.shared_commits = shared;
    }

    /// Install a per-round consensus-version selector — mirrors go's
    /// `makeTestLedgerWithConsensusVersion`. From now on,
    /// `consensus_version(round)`/`consensus_params(round)` resolve via `f`
    /// instead of the fixed `version`/`params` this ledger was constructed
    /// with.
    pub fn with_version_fn(self, f: impl Fn(Round) -> String + Send + Sync + 'static) -> Self {
        self.state.lock().unwrap().version_fn = Some(Arc::new(f));
        self
    }

    /// Snapshot the current `next_round` (advances on every `ensure_block`).
    pub fn next_round(&self) -> Round {
        self.state.lock().unwrap().next_rnd
    }

    /// Snapshot the certificate for `round`, if committed.
    pub fn cert(&self, round: Round) -> Option<Certificate> {
        self.state.lock().unwrap().certs.get(&round).cloned()
    }

    /// Snapshot the committed block for `round`, if committed.
    pub fn block(&self, round: Round) -> Option<Block> {
        self.state.lock().unwrap().blocks.get(&round).cloned()
    }

    /// Number of committed rounds.
    #[allow(dead_code)] // convenience accessor; current tests use block(r).is_some() loops.
    pub fn committed_count(&self) -> usize {
        self.state.lock().unwrap().blocks.len()
    }

    /// Helper that mirrors the StubLedger semantics: when a block is
    /// recorded, advance `next_rnd` and drain any waiters whose round is
    /// now satisfied.
    fn record_block_locked(state: &mut TestLedgerState, block: Block, cert: Certificate) {
        let r = block.round;
        // Record the block's digest from the certificate (== block_digest).
        // Mirrors what a real ledger does: `lookup_digest(r)` returns the
        // digest the consensus voted on at round r.
        state.digests.insert(r, cert.proposal.block_digest);
        // Record the block's seed so subsequent rounds' sortition reads
        // the committed seed (via `seed_round(R)` lookback) rather than
        // falling back to the genesis seed for every round. Mirrors
        // `LedgerWriter`'s contract that `Seed(r)` reflects written
        // blocks at round r.
        state.seeds.insert(r, Seed(block.seed));
        state.blocks.insert(r, block);
        state.certs.insert(r, cert);
        if state.next_rnd.0 < r.0 + 1 {
            state.next_rnd = Round(r.0 + 1);
        }
        // Drain waiters whose round is now available
        // (`requested_round < next_rnd`).
        state.waiters.retain(|(req, tx)| {
            if req.0 < state.next_rnd.0 {
                let _ = tx.send(*req);
                false
            } else {
                true
            }
        });
    }
}

impl LedgerReader for TestLedger {
    fn seed(&self, round: Round) -> Result<Seed, LedgerError> {
        let s = self.state.lock().unwrap();
        // Stable-seed policy: if no specific seed is recorded for `round`,
        // fall back to the genesis seed at round 0. The test factory
        // doesn't propagate per-round seeds, so this keeps sortition
        // input consistent across rounds.
        s.seeds
            .get(&round)
            .copied()
            .or_else(|| s.seeds.get(&Round(0)).copied())
            .ok_or(LedgerError::RoundNotAvailable(round))
    }

    fn lookup_agreement(
        &self,
        _round: Round,
        addr: &Address,
    ) -> Result<OnlineAccountData, LedgerError> {
        // Static accounts: stake / keys don't change across rounds in
        // this fixture, so the round arg is ignored.
        self.state
            .lock()
            .unwrap()
            .accounts
            .get(addr)
            .cloned()
            .ok_or_else(|| LedgerError::Other(format!("account {addr:?} not found")))
    }

    fn circulation(&self, _rnd: Round, _vote_rnd: Round) -> Result<u64, LedgerError> {
        Ok(self.state.lock().unwrap().circulation)
    }

    fn lookup_digest(&self, round: Round) -> Result<Digest, LedgerError> {
        let s = self.state.lock().unwrap();
        // Try the explicit digests map first (round 0 = synthetic
        // genesis, round N = recorded by `ensure_block`); fall back to
        // a zero placeholder if the round was committed but no digest
        // was recorded (defensive — `record_block_locked` always
        // populates digests).
        s.digests
            .get(&round)
            .copied()
            .ok_or(LedgerError::RoundNotAvailable(round))
    }

    fn consensus_params(&self, round: Round) -> Result<ConsensusParams, LedgerError> {
        let s = self.state.lock().unwrap();
        match &s.version_fn {
            Some(f) => {
                let version = f(round);
                algo_types::consensus::consensus_params_for_version(&version).ok_or_else(|| {
                    LedgerError::Other(format!("unknown consensus version {version:?}"))
                })
            }
            None => Ok(s.params.clone()),
        }
    }

    fn next_round(&self) -> Round {
        self.state.lock().unwrap().next_rnd
    }

    fn consensus_version(&self, round: Round) -> Result<String, LedgerError> {
        let s = self.state.lock().unwrap();
        match &s.version_fn {
            Some(f) => Ok(f(round)),
            None => Ok(s.version.clone()),
        }
    }

    fn wait_for_round(&self, round: Round) -> Result<(), LedgerError> {
        if round.0 < self.state.lock().unwrap().next_rnd.0 {
            Ok(())
        } else {
            Err(LedgerError::RoundNotAvailable(round))
        }
    }

    fn round_notify(&self, round: Round) -> crossbeam_channel::Receiver<Round> {
        let mut s = self.state.lock().unwrap();
        if round.0 < s.next_rnd.0 {
            // Already available — fire immediately.
            let (tx, rx) = crossbeam_channel::bounded(1);
            let _ = tx.send(round);
            return rx;
        }
        let (tx, rx) = crossbeam_channel::bounded(1);
        s.waiters.push((round, tx));
        rx
    }
}

impl LedgerWriter for TestLedger {
    fn ensure_block(&self, block: &Block, cert: &Certificate) {
        // Publish to `SharedCommits` BEFORE advancing `next_rnd`
        // (`record_block_locked`), not after — see this method's sibling
        // `ensure_validated_block`'s doc note and `SharedCommits`'s own
        // doc comment for why the ordering matters: another thread that
        // observes `next_round()` advance must never be able to run
        // `ensure_digest` and find `SharedCommits` still empty for that
        // round.
        self.publish_commit(block.clone(), cert.clone());
        let mut s = self.state.lock().unwrap();
        TestLedger::record_block_locked(&mut s, block.clone(), cert.clone());
    }

    fn ensure_validated_block(&self, vb: &dyn ValidatedBlock, cert: &Certificate) {
        // Same publish-before-advance ordering as `ensure_block` above —
        // found while investigating a real, harness-only flake in
        // `certificate_does_not_stall_single_relay_five_node`
        // (`service_multi_node_test.rs`): the OLD ordering (advance
        // `next_rnd` first, publish to `SharedCommits` after dropping the
        // state lock) left a genuine, if usually narrow, window in which
        // another node's `next_round()`-driven observation of "this round
        // committed" could win a race against this node's own
        // `publish_commit` — so a peer's `ensure_digest` catch-up fetch,
        // triggered right after seeing that, could poll `SharedCommits`
        // before the entry existed. `ensure_digest`'s own retry loop
        // (`Duration::from_secs(5)`) usually papers over a narrow window,
        // but under real thread contention (5 live `Service` instances
        // competing for CPU) the window was observed to occasionally
        // outlast it, permanently stalling the catching-up node for the
        // rest of that test run. Publishing first makes the race
        // impossible instead of just unlikely.
        self.publish_commit(vb.block().clone(), cert.clone());
        let mut s = self.state.lock().unwrap();
        TestLedger::record_block_locked(&mut s, vb.block().clone(), cert.clone());
    }

    /// Mirrors go-algorand's `EnsureDigest`: the player reached vote quorum
    /// for `cert.round` but doesn't have that round's proposal payload
    /// staged locally (see `player::handle_threshold_event`'s "we don't
    /// have the block" branch), so it hints the ledger to fetch the block
    /// out-of-band instead of via its own vote tally.
    ///
    /// A real ledger's catchup fetcher pulls the block from a peer over the
    /// network and authenticates it against `cert` (`verifier` is the hook
    /// for that authentication in production). This harness has no
    /// separate block-fetch network, so it serves the fetch directly from
    /// [`SharedCommits`] — whichever peer's `TestLedger` already committed
    /// this round (via `ensure_block`/`ensure_validated_block` above)
    /// published it there. Polls with a bounded retry/timeout (like a real
    /// async fetch that may need to wait for the block to actually arrive
    /// at a peer first) rather than a single lookup, since `ensure_digest`
    /// can legitimately fire before any peer has committed the round yet.
    fn ensure_digest(&self, cert: &Certificate, _verifier: &algo_agreement::AsyncVoteVerifier) {
        let round = cert.round;
        // Already have it (e.g. a race with our own vote-driven commit) —
        // nothing to fetch.
        if self.state.lock().unwrap().next_rnd.0 > round.0 {
            return;
        }
        let digest = cert.proposal.block_digest;
        let shared = self.shared_commits.clone();
        let state = self.state.clone();
        let cert = cert.clone();
        // Mirrors the real ledger's async catchup fetch: retry until the
        // block turns up (or we give up), off the demux thread that fired
        // this action, so it never blocks agreement's own event loop.
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some((block, source_cert)) = shared.lock().unwrap().get(&round).cloned() {
                    if source_cert.proposal.block_digest == digest {
                        let mut s = state.lock().unwrap();
                        if s.next_rnd.0 <= round.0 {
                            TestLedger::record_block_locked(&mut s, block, cert);
                        }
                        return;
                    }
                }
                if Instant::now() >= deadline {
                    return;
                }
                thread::sleep(Duration::from_millis(5));
            }
        });
    }
}

impl TestLedger {
    /// Publish a just-committed block into the cluster-wide registry so a
    /// lagging peer's `ensure_digest` catch-up fetch can find it. A no-op
    /// (writes to this ledger's own private, unshared registry) unless
    /// [`TestLedger::share_commits`] wired every node's ledger to the same
    /// `SharedCommits` handle.
    fn publish_commit(&self, block: Block, cert: Certificate) {
        self.shared_commits
            .lock()
            .unwrap()
            .insert(block.round, (block, cert));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simulate::test_account::generate_n_accounts;
    use algo_agreement::AsyncVoteVerifier;
    use algo_types::CONSENSUS_V41;

    fn new_ledger() -> TestLedger {
        let accounts = generate_n_accounts(1, Round(0), Round(1000), 10_000, 0xC0FFEE);
        let params = algo_types::consensus::consensus_params_for_version(CONSENSUS_V41)
            .expect("v41 consensus params available");
        TestLedger::new(&accounts, 1_000_000, params, CONSENSUS_V41.to_string())
    }

    /// Regression test for issue #911: before this fix, `ensure_digest` was
    /// a no-op, so a node that reached vote quorum for a round without
    /// having that round's proposal payload staged locally had NO way to
    /// ever commit it — it would call `ensure_digest` and simply never
    /// catch up, staying parked forever (this is exactly what the 5-node
    /// convergence stall investigated in #911 turned out to be: a harness
    /// gap, not a `Service`/`Player` liveness bug — see
    /// `service_multi_node_test.rs`'s `fast_recovery_down_early_five_node`
    /// doc comment).
    ///
    /// Deterministic, race-free reproduction of the fix: two ledgers share
    /// one `SharedCommits` registry (mirroring `setup_agreement`'s
    /// cluster wiring). Ledger A commits round 1 via `ensure_block` (as it
    /// would after winning its own local vote quorum with the payload in
    /// hand); ledger B never receives the payload directly, but calling
    /// `ensure_digest` with the SAME certificate must still bring ledger
    /// B's `next_round`/`block(1)` in line with ledger A's, by fetching the
    /// block A already published into the shared registry.
    #[test]
    fn ensure_digest_catches_up_from_shared_commits() {
        let shared = SharedCommits::default();

        let mut ledger_a = new_ledger();
        ledger_a.share_commits(shared.clone());
        let mut ledger_b = new_ledger();
        ledger_b.share_commits(shared);

        let block = Block {
            round: Round(1),
            ..Block::default()
        };
        let cert = Certificate {
            round: Round(1),
            proposal: algo_agreement::ProposalValue {
                block_digest: Digest([0x11u8; 32]),
                ..Default::default()
            },
            ..Certificate::default()
        };

        // Ledger A commits normally (it has the payload in hand).
        ledger_a.ensure_block(&block, &cert);
        assert_eq!(ledger_a.next_round(), Round(2));

        // Ledger B never got the payload, but reached the SAME cert's vote
        // quorum — mirrors `player::handle_threshold_event`'s
        // `Action::StageDigest` path calling `LedgerWriter::ensure_digest`.
        assert_eq!(ledger_b.next_round(), Round(1), "B hasn't caught up yet");
        let verifier = AsyncVoteVerifier::new();
        ledger_b.ensure_digest(&cert, &verifier);

        // The catch-up fetch runs on a background thread (mirrors a real
        // async block fetch); poll briefly for it to land rather than
        // asserting immediately.
        let deadline = Instant::now() + Duration::from_secs(2);
        while ledger_b.next_round().0 <= Round(1).0 {
            assert!(
                Instant::now() < deadline,
                "ensure_digest did not catch B up within 2s"
            );
            thread::sleep(Duration::from_millis(5));
        }

        assert_eq!(ledger_b.next_round(), Round(2));
        assert_eq!(
            ledger_b.block(Round(1)).map(|b| b.round),
            Some(Round(1)),
            "B must have actually recorded A's block, not just advanced next_round"
        );
        assert_eq!(
            ledger_b.cert(Round(1)).map(|c| c.proposal.block_digest),
            Some(cert.proposal.block_digest)
        );
    }

    /// Without ever sharing a `SharedCommits` registry (the single-ledger,
    /// pre-#911 default), `ensure_digest` has nothing to fetch from and
    /// must not silently advance the round — it should just give up after
    /// its bounded retry window, exactly as go-algorand's real fetcher
    /// would if the block genuinely never became available.
    #[test]
    fn ensure_digest_without_shared_commits_does_not_advance() {
        let ledger = new_ledger();
        let cert = Certificate {
            round: Round(1),
            proposal: algo_agreement::ProposalValue {
                block_digest: Digest([0x22u8; 32]),
                ..Default::default()
            },
            ..Certificate::default()
        };

        let verifier = AsyncVoteVerifier::new();
        ledger.ensure_digest(&cert, &verifier);

        // Give the (doomed) background fetch a moment to have committed
        // something, then confirm it didn't.
        thread::sleep(Duration::from_millis(100));
        assert_eq!(ledger.next_round(), Round(1));
    }
}
