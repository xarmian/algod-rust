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

use algo_agreement::{
    Certificate, LedgerError, LedgerReader, LedgerWriter, OnlineAccountData, Seed, ValidatedBlock,
};
use algo_types::{Address, Block, ConsensusParams, Digest, Round};
use crossbeam_channel::Sender;

use super::test_account::TestAccount;

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
    /// Consensus params (same for every round).
    pub params: ConsensusParams,
    /// Consensus version string.
    pub version: String,
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
            // The ledger starts "at round 1" — i.e., round 0 is implicitly
            // "the genesis" and the agreement service drives round 1 next.
            next_rnd: Round(1),
            waiters: Vec::new(),
        };
        Self {
            state: Arc::new(Mutex::new(state)),
        }
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

    fn consensus_params(&self, _round: Round) -> Result<ConsensusParams, LedgerError> {
        Ok(self.state.lock().unwrap().params.clone())
    }

    fn next_round(&self) -> Round {
        self.state.lock().unwrap().next_rnd
    }

    fn consensus_version(&self, _round: Round) -> Result<String, LedgerError> {
        Ok(self.state.lock().unwrap().version.clone())
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
        let mut s = self.state.lock().unwrap();
        TestLedger::record_block_locked(&mut s, block.clone(), cert.clone());
    }

    fn ensure_validated_block(&self, vb: &dyn ValidatedBlock, cert: &Certificate) {
        let mut s = self.state.lock().unwrap();
        TestLedger::record_block_locked(&mut s, vb.block().clone(), cert.clone());
    }

    fn ensure_digest(&self, _cert: &Certificate, _verifier: &algo_agreement::AsyncVoteVerifier) {
        // The simulate harness never goes through the EnsureDigest path
        // (no fork / catch-up scenarios), so this is a no-op. Mirroring
        // `StubLedger::ensure_digest` for completeness.
    }
}
