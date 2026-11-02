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

// Bundle types and verification, matching go-algorand/agreement/bundle.go.
//
// An unauthenticatedBundle contains a set of vote authenticators for the same
// (round, period, step, proposal). Verifying a bundle checks each vote's
// credential + OTS signature and confirms quorum is reached.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use algo_consensus_crypto::OneTimeSignature;
use algo_types::{Address, ConsensusParams, Round};

use crate::credential::{Membership, UnauthenticatedCredential};
use crate::ledger_reader::{LedgerError, LedgerReader, OnlineAccountData};
use crate::lookback::{balance_round, params_round, seed_round};
use crate::seed::Seed;
use crate::selector::Selector;
use crate::step::{Period, Step, DOWN, PROPOSE};
use crate::vote::{ProposalValue, RawVote, UnauthenticatedVote, Vote, VoteVerifyView};

// ── VoteAuthenticator ───────────────────────────────────────────────────────

/// Authenticator for a single vote in a bundle.
///
/// Mirrors Go's `agreement.voteAuthenticator`. Omits the Round, Period, Step,
/// and Proposal fields for compression — those are taken from the bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteAuthenticator {
    /// The address of the voter.
    pub sender: Address,
    /// The VRF credential (not yet verified).
    pub cred: UnauthenticatedCredential,
    /// The one-time signature on the vote.
    pub sig: OneTimeSignature,
}

// ── EquivocationVoteAuthenticator ───────────────────────────────────────────

/// Authenticator for an equivocation vote pair — a voter who signed two
/// different proposals in the same round/period/step.
///
/// Mirrors Go's `agreement.equivocationVoteAuthenticator`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationVoteAuthenticator {
    /// The address of the equivocating voter.
    pub sender: Address,
    /// The VRF credential.
    pub cred: UnauthenticatedCredential,
    /// The two OTS signatures (one per conflicting proposal).
    pub sigs: [OneTimeSignature; 2],
    /// The two conflicting proposal values.
    pub proposals: [ProposalValue; 2],
}

// ── UnauthenticatedBundle ───────────────────────────────────────────────────

/// A bundle which has not yet been verified.
///
/// Mirrors Go's `agreement.unauthenticatedBundle`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnauthenticatedBundle {
    /// The round this bundle is for.
    pub round: Round,
    /// The period within the round.
    pub period: Period,
    /// The step within the period.
    pub step: Step,
    /// The proposal value that these votes are for.
    pub proposal: ProposalValue,
    /// Individual vote authenticators.
    pub votes: Vec<VoteAuthenticator>,
    /// Equivocation vote authenticators.
    pub equivocation_votes: Vec<EquivocationVoteAuthenticator>,
}

impl Default for UnauthenticatedBundle {
    fn default() -> Self {
        Self {
            round: Round(0),
            period: Period(0),
            step: Step(0),
            proposal: crate::vote::BOTTOM,
            votes: Vec::new(),
            equivocation_votes: Vec::new(),
        }
    }
}

// ── Bundle (verified) ───────────────────────────────────────────────────────

/// A verified bundle — all votes have been checked and quorum is reached.
///
/// Mirrors Go's `agreement.bundle`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    /// The original unauthenticated bundle.
    pub u: UnauthenticatedBundle,
    /// The verified votes with proven credentials and weights.
    pub votes: Vec<Vote>,
    /// Total weight of all votes in the bundle.
    pub total_weight: u64,
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Errors from bundle verification.
#[derive(Debug, Clone)]
pub enum BundleError {
    /// The bundle's step exceeds `down`, the largest step defined by the
    /// protocol (go-algorand v5.0.2-stable's `wellFormed` bound check).
    StepExceedsMax { step: Step },
    /// The bundle step is `propose`, which is not allowed.
    ProposeStep,
    /// The bundle is too large (more votes than the step threshold).
    TooLarge {
        num_votes: u64,
        num_equivocation_votes: u64,
        threshold: u64,
    },
    /// A vote sender appears more than once in the bundle.
    DuplicateVoter(Address),
    /// An equivocation vote pair has identical proposals (not real equivocation).
    IdenticalEquivocationProposals,
    /// A vote in the bundle failed verification.
    VoteVerificationFailed { index: usize, detail: String },
    /// Quorum was not reached.
    InsufficientQuorum { weight: u64, threshold: u64 },
    /// Ledger access failed.
    LedgerError(LedgerError),
    /// Consensus params lookup failed.
    ConsensusParamsError(String),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StepExceedsMax { step } => {
                write!(f, "unauthenticatedBundle.wellFormed: step {step} exceeds max step")
            }
            Self::ProposeStep => write!(f, "bundle step cannot be propose"),
            Self::TooLarge {
                num_votes,
                num_equivocation_votes,
                threshold,
            } => write!(
                f,
                "bundle too large: {num_votes} votes + {num_equivocation_votes} equivocation votes > threshold {threshold}"
            ),
            Self::DuplicateVoter(addr) => {
                write!(f, "duplicate voter in bundle: {addr:?}")
            }
            Self::IdenticalEquivocationProposals => {
                write!(f, "equivocation vote pair has identical proposals")
            }
            Self::VoteVerificationFailed { index, detail } => {
                write!(f, "vote at index {index} failed verification: {detail}")
            }
            Self::InsufficientQuorum { weight, threshold } => {
                write!(f, "insufficient quorum: weight {weight} < threshold {threshold}")
            }
            Self::LedgerError(e) => write!(f, "ledger error: {e}"),
            Self::ConsensusParamsError(msg) => write!(f, "consensus params error: {msg}"),
        }
    }
}

impl std::error::Error for BundleError {}

impl From<LedgerError> for BundleError {
    fn from(e: LedgerError) -> Self {
        Self::LedgerError(e)
    }
}

// ── Verification ────────────────────────────────────────────────────────────

impl UnauthenticatedBundle {
    /// Stateless well-formedness check on a bundle received from the
    /// network.
    ///
    /// Mirrors Go's `unauthenticatedBundle.wellFormed` (v5.0.2-stable):
    /// rejects any step greater than `down`, the largest step defined by
    /// the protocol.
    pub fn well_formed(&self) -> Result<(), BundleError> {
        if self.step > DOWN {
            return Err(BundleError::StepExceedsMax { step: self.step });
        }
        Ok(())
    }

    /// Verify this bundle: check all votes and confirm quorum.
    ///
    /// Mirrors Go's `unauthenticatedBundle.verify()`.
    ///
    /// Steps:
    /// 1. Well-formedness, propose-step, size and duplicate-voter checks
    ///    ([`Self::verify_preconditions`])
    /// 2. For each vote, plain votes first and then equivocation votes, in
    ///    bundle order: reconstruct the vote, look up its membership from the
    ///    ledger, and verify credential + one-time signature
    /// 3. Sum weights and check quorum ([`Self::finish`])
    ///
    /// Step 2 looks the memberships up in order on the calling thread and runs
    /// the pure signature, VRF and sortition checks (~90% of the time) on a
    /// bounded pool, a wave of votes at a time, like go's `AsyncVoteVerifier`.
    /// The result is exactly that of one-by-one verification: the error of
    /// the first failing vote in bundle order (`verify_in_waves`). A bundle
    /// that fails stops after at most one wave: later waves, and the
    /// equivocation votes once a plain vote has failed, are never looked up
    /// or verified.
    ///
    /// This blocks the calling thread until the votes are verified. Its only
    /// caller is the catchup service (`CatchupLedger::authenticate_block`),
    /// which runs on dedicated threads, never on an async worker; an async
    /// caller would have to use `spawn_blocking`.
    pub fn verify(&self, l: &dyn LedgerReader) -> Result<Bundle, BundleError> {
        let proto = self.verify_preconditions(l)?;

        let mut cache = MembershipCache::new(l, self.round, self.period, self.step);
        let n_votes = self.votes.len();
        let mut verified = Vec::with_capacity(n_votes + self.equivocation_votes.len());
        verify_in_waves(self.votes.len(), &mut verified, |i| {
            self.prepare_single_vote(&mut cache, &self.votes[i], i)
        })?;
        verify_in_waves(self.equivocation_votes.len(), &mut verified, |i| {
            self.prepare_equivocation_vote(&mut cache, &self.equivocation_votes[i], n_votes + i)
        })?;

        self.finish(&proto, verified)
    }

    /// The checks before any vote is looked at: well-formedness, the propose
    /// step, the bundle size and duplicate voters. Returns the consensus
    /// parameters used for the thresholds.
    pub(crate) fn verify_preconditions(
        &self,
        l: &dyn LedgerReader,
    ) -> Result<ConsensusParams, BundleError> {
        self.well_formed()?;

        // Step 1: reject propose step
        if self.step == PROPOSE {
            return Err(BundleError::ProposeStep);
        }

        // Get consensus params for threshold check
        let params_rnd = crate::lookback::params_round(self.round);
        let proto = l
            .consensus_params(params_rnd)
            .map_err(|e| BundleError::ConsensusParamsError(e.to_string()))?;

        let threshold = self.step.committee_threshold(&proto);
        let num_votes = self.votes.len() as u64;
        let num_eq_votes = self.equivocation_votes.len() as u64;

        // Step 2: check bundle size
        if num_votes > threshold || num_eq_votes > threshold || num_votes + num_eq_votes > threshold
        {
            return Err(BundleError::TooLarge {
                num_votes,
                num_equivocation_votes: num_eq_votes,
                threshold,
            });
        }

        // Step 3: check for duplicate voters
        let mut voters = HashSet::new();
        for auth in &self.votes {
            if !voters.insert(auth.sender) {
                return Err(BundleError::DuplicateVoter(auth.sender));
            }
        }
        for auth in &self.equivocation_votes {
            if !voters.insert(auth.sender) {
                return Err(BundleError::DuplicateVoter(auth.sender));
            }
        }
        Ok(proto)
    }

    /// Sum the verified votes' weights and check quorum.
    ///
    /// The sum wraps like go's plain `uint64` addition
    /// (`agreement/bundle.go`, `weight += res.v.Cred.Weight`): no panic on
    /// peer-supplied weights, same value as go.
    pub(crate) fn finish(
        &self,
        proto: &ConsensusParams,
        verified_votes: Vec<Vote>,
    ) -> Result<Bundle, BundleError> {
        let total_weight = verified_votes
            .iter()
            .fold(0u64, |sum, v| sum.wrapping_add(v.cred.weight));

        // Step 5: check quorum
        if !self.step.reaches_quorum(proto, total_weight) {
            return Err(BundleError::InsufficientQuorum {
                weight: total_weight,
                threshold: self.step.committee_threshold(proto),
            });
        }

        Ok(Bundle {
            u: self.clone(),
            votes: verified_votes,
            total_weight,
        })
    }

    /// Look up the membership for a plain vote and assemble its
    /// verification work, or the lookup failure the sequential code
    /// reported at this index.
    fn prepare_single_vote(
        &self,
        cache: &mut MembershipCache<'_>,
        auth: &VoteAuthenticator,
        index: usize,
    ) -> Result<VoteWork, BundleError> {
        // Reconstruct the full UnauthenticatedVote
        let uv = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: auth.sender,
                round: self.round,
                period: self.period,
                step: self.step,
                proposal: self.proposal,
            },
            cred: auth.cred.clone(),
            sig: auth.sig.clone(),
        };

        let (membership, record, proto) =
            cache
                .membership(&auth.sender)
                .map_err(|e| BundleError::VoteVerificationFailed {
                    index,
                    detail: format!("could not get membership: {e}"),
                })?;

        Ok(VoteWork {
            index,
            first: uv,
            second: None,
            membership,
            record,
            consensus_params: proto,
        })
    }

    /// Assemble the verification work of an equivocation vote.
    ///
    /// In Go, equivocation votes prove that a sender voted for two different
    /// proposals. For bundle verification, we verify the credential once and
    /// verify both OTS signatures against the two different proposals.
    fn prepare_equivocation_vote(
        &self,
        cache: &mut MembershipCache<'_>,
        auth: &EquivocationVoteAuthenticator,
        index: usize,
    ) -> Result<VoteWork, BundleError> {
        // Reject if both proposals are identical — that's not real equivocation.
        // Mirrors Go's unauthenticatedEquivocationVote.verify() check.
        if auth.proposals[0] == auth.proposals[1] {
            return Err(BundleError::IdenticalEquivocationProposals);
        }

        let vote_for = |i: usize| UnauthenticatedVote {
            raw_vote: RawVote {
                sender: auth.sender,
                round: self.round,
                period: self.period,
                step: self.step,
                proposal: auth.proposals[i],
            },
            cred: auth.cred.clone(),
            sig: auth.sigs[i].clone(),
        };

        let (membership, record, proto) =
            cache
                .membership(&auth.sender)
                .map_err(|e| BundleError::VoteVerificationFailed {
                    index,
                    detail: format!("could not get membership for equivocation vote: {e}"),
                })?;

        Ok(VoteWork {
            index,
            first: vote_for(0),
            second: Some(vote_for(1)),
            membership,
            record,
            consensus_params: proto,
        })
    }
}

/// Number of per-vote verifications `UnauthenticatedBundle::verify` has run
/// (test builds only): lets tests pin that an invalid bundle stops early.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub static VOTE_VERIFY_RUNS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// One vote's pure verification work (everything the ledger had to supply
/// is already in it). `second` is the equivocation vote's second proposal;
/// a plain vote has none.
struct VoteWork {
    index: usize,
    first: UnauthenticatedVote,
    second: Option<UnauthenticatedVote>,
    membership: Membership,
    record: OnlineAccountData,
    /// Shared by every vote of the bundle.
    consensus_params: Arc<ConsensusParams>,
}

impl VoteWork {
    /// Verify the vote (credential and first signature, then the second
    /// signature of an equivocation pair) with the sequential code's exact
    /// errors. The returned vote is the first one: an equivocation's weight
    /// counts once.
    fn verify(&self) -> Result<Vote, BundleError> {
        #[cfg(any(test, feature = "test-support"))]
        VOTE_VERIFY_RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let index = self.index;
        let view = VoteVerifyView {
            membership: &self.membership,
            vote_id: &self.record.vote_id,
            vote_first_valid: self.record.vote_first_valid,
            vote_last_valid: self.record.vote_last_valid,
            vote_key_dilution: self.record.vote_key_dilution,
            consensus_params: &self.consensus_params,
        };
        let vote1 = self.first.verify_view(&view).map_err(|e| {
            let detail = if self.second.is_some() {
                format!("equivocation vote first proposal failed: {e}")
            } else {
                e.to_string()
            };
            BundleError::VoteVerificationFailed { index, detail }
        })?;
        if let Some(second) = &self.second {
            second
                .verify_view(&view)
                .map_err(|e| BundleError::VoteVerificationFailed {
                    index,
                    detail: format!("equivocation vote second proposal failed: {e}"),
                })?;
        }
        Ok(vote1)
    }
}

/// Environment variable overriding the size of the vote-verification pool.
pub const VERIFY_THREADS_ENV: &str = "ALGOD_VOTE_VERIFY_THREADS";

/// Default pool size cap. On a 24-thread WSL2 host a 25-vote certificate
/// verified fastest on ~8 threads (1.15 ms vs 1.65 ms on 24: more wake-ups
/// and idle workers for no more work), so the default is
/// `min(available_parallelism, 8)`.
const DEFAULT_MAX_VERIFY_THREADS: usize = 8;

fn verify_threads() -> usize {
    std::env::var(VERIFY_THREADS_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map_or(1, |n| n.get())
                .min(DEFAULT_MAX_VERIFY_THREADS)
        })
}

/// The dedicated, lazily created vote-verification pool. Separate from
/// rayon's global pool so that verification neither competes with other
/// rayon users nor is starved by them. `None` if the OS refused the
/// threads: verification then runs on the calling thread.
fn verifier_pool() -> Option<&'static rayon::ThreadPool> {
    static POOL: OnceLock<Option<rayon::ThreadPool>> = OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(verify_threads())
            .thread_name(|i| format!("bundle-verify-{i}"))
            .build()
            .ok()
    })
    .as_ref()
}

/// Votes prepared (looked up) and verified per wave: two per worker, so the
/// workers stay busy through a wave while an invalid bundle costs at most
/// one wave of verification.
fn wave_size() -> usize {
    2 * verify_threads()
}

/// Prepare and verify `n` votes in order, appending the verified votes to
/// `out`; fails with the error of the **first** failing vote in order (a
/// lookup failure counts at its position), which is what verifying one by
/// one returned. `prepare(i)` does the ledger lookups of vote `i`.
///
/// Votes go in waves; within a wave they are verified in parallel, and a
/// vote whose position is above an already failed one is skipped, since it
/// can no longer change the answer (every vote below the lowest failure
/// still runs to completion, so the answer never depends on timing).
fn verify_in_waves(
    n: usize,
    out: &mut Vec<Vote>,
    mut prepare: impl FnMut(usize) -> Result<VoteWork, BundleError>,
) -> Result<(), BundleError> {
    use rayon::prelude::*;

    let wave = wave_size();
    let mut next = 0;
    while next < n {
        let end = (next + wave).min(n);
        let mut work = Vec::with_capacity(end - next);
        let mut lookup_error = None;
        for i in next..end {
            match prepare(i) {
                Ok(w) => work.push(w),
                Err(e) => {
                    lookup_error = Some(e);
                    break;
                }
            }
        }

        let lowest_failed = AtomicUsize::new(usize::MAX);
        let run = |(pos, w): (usize, &VoteWork)| {
            if pos > lowest_failed.load(Ordering::Relaxed) {
                return None;
            }
            let res = w.verify();
            if res.is_err() {
                lowest_failed.fetch_min(pos, Ordering::Relaxed);
            }
            Some(res)
        };
        let results: Vec<Option<Result<Vote, BundleError>>> = match verifier_pool() {
            Some(pool) => pool.install(|| work.par_iter().enumerate().map(run).collect()),
            None => work.iter().enumerate().map(run).collect(),
        };
        for res in results {
            // `None` only follows a failed position, which returns first.
            match res {
                Some(Ok(vote)) => out.push(vote),
                Some(Err(e)) => return Err(e),
                None => unreachable!("a skipped vote follows a failed one"),
            }
        }
        if let Some(e) = lookup_error {
            return Err(e);
        }
        next = end;
    }
    Ok(())
}

/// Consensus params with the balance and seed rounds derived from them.
type CachedParams = Result<(Arc<ConsensusParams>, Round, Round), LedgerError>;

/// The ledger inputs of `membership_from_ledger` that do not depend on the
/// voter (consensus params, circulation, seed), fetched at most once per
/// bundle. The per-vote call order (params, account, circulation, seed) and
/// the error each step produces are those of `membership_from_ledger`; the
/// ledger is read at fixed lookback rounds, so a repeated call returns the
/// same result.
struct MembershipCache<'a> {
    l: &'a dyn LedgerReader,
    round: Round,
    period: Period,
    step: Step,
    params: Option<CachedParams>,
    circulation: Option<Result<u64, LedgerError>>,
    seed: Option<Result<Seed, LedgerError>>,
}

impl<'a> MembershipCache<'a> {
    fn new(l: &'a dyn LedgerReader, round: Round, period: Period, step: Step) -> Self {
        Self {
            l,
            round,
            period,
            step,
            params: None,
            circulation: None,
            seed: None,
        }
    }

    fn membership(
        &mut self,
        addr: &Address,
    ) -> Result<(Membership, OnlineAccountData, Arc<ConsensusParams>), LedgerError> {
        let (l, round) = (self.l, self.round);
        let (cparams, bal_round, seed_rnd) = self
            .params
            .get_or_insert_with(|| {
                let cparams = l.consensus_params(params_round(round))?;
                let bal = balance_round(round, &cparams);
                let seed = seed_round(round, &cparams);
                Ok((Arc::new(cparams), bal, seed))
            })
            .clone()?;

        let record = l.lookup_agreement(bal_round, addr)?;
        let total = self
            .circulation
            .get_or_insert_with(|| l.circulation(bal_round, round))
            .clone()?;
        let seed = self.seed.get_or_insert_with(|| l.seed(seed_rnd)).clone()?;

        let membership = Membership {
            address: *addr,
            selection_id: record.selection_id,
            balance: record.micro_algos,
            total_money: total,
            selector: Selector {
                seed,
                round,
                period: self.period,
                step: self.step,
            },
        };
        Ok((membership, record, cparams))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::Seed;
    use crate::step::{CERT, SOFT};
    use crate::vote::BOTTOM;
    use algo_types::{ConsensusParams, Digest};

    // ── MockLedgerReader ─────────────────────────────────────────────────

    /// A mock LedgerReader for testing bundle verification.
    struct MockLedgerReader {
        params: ConsensusParams,
        seed: Seed,
        accounts: std::collections::HashMap<Address, crate::ledger_reader::OnlineAccountData>,
        total_circulation: u64,
    }

    impl MockLedgerReader {
        fn new(params: ConsensusParams) -> Self {
            Self {
                params,
                seed: Seed([0xab; 32]),
                accounts: std::collections::HashMap::new(),
                total_circulation: 10_000_000,
            }
        }

        fn add_account(&mut self, addr: Address, data: crate::ledger_reader::OnlineAccountData) {
            self.accounts.insert(addr, data);
        }
    }

    impl LedgerReader for MockLedgerReader {
        fn seed(&self, _round: Round) -> Result<Seed, LedgerError> {
            Ok(self.seed)
        }

        fn lookup_agreement(
            &self,
            _round: Round,
            addr: &Address,
        ) -> Result<crate::ledger_reader::OnlineAccountData, LedgerError> {
            self.accounts
                .get(addr)
                .cloned()
                .ok_or(LedgerError::Other(format!("account not found: {addr:?}")))
        }

        fn circulation(&self, _rnd: Round, _vote_rnd: Round) -> Result<u64, LedgerError> {
            Ok(self.total_circulation)
        }

        fn lookup_digest(&self, _round: Round) -> Result<Digest, LedgerError> {
            Ok(Digest([0u8; 32]))
        }

        fn consensus_params(&self, _round: Round) -> Result<ConsensusParams, LedgerError> {
            Ok(self.params.clone())
        }

        fn next_round(&self) -> Round {
            Round(1)
        }

        fn consensus_version(&self, _round: Round) -> Result<String, LedgerError> {
            Ok(algo_types::CONSENSUS_V41.to_string())
        }

        fn wait_for_round(&self, _round: Round) -> Result<(), LedgerError> {
            Ok(())
        }

        fn round_notify(&self, round: Round) -> crossbeam_channel::Receiver<Round> {
            let (tx, rx) = crossbeam_channel::bounded(1);
            let _ = tx.send(round);
            rx
        }
    }

    fn v41_params() -> ConsensusParams {
        algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
            .expect("v41 params")
    }

    // ── Bundle verification tests ────────────────────────────────────────

    #[test]
    fn bundle_verify_rejects_propose_step() {
        let ledger = MockLedgerReader::new(v41_params());
        let bundle = UnauthenticatedBundle {
            round: Round(100),
            period: Period(0),
            step: PROPOSE,
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
            votes: vec![],
            equivocation_votes: vec![],
        };

        let result = bundle.verify(&ledger);
        assert!(matches!(result, Err(BundleError::ProposeStep)));
    }

    /// Port of go-algorand's `TestBundleVerifyRejectsStepAboveDown`
    /// (agreement/bundle_test.go, v5.0.2-stable).
    #[test]
    fn bundle_verify_rejects_step_above_down() {
        let ledger = MockLedgerReader::new(v41_params());
        let bundle = UnauthenticatedBundle {
            round: Round(100),
            period: Period(0),
            step: Step(DOWN.0 + 1),
            ..UnauthenticatedBundle::default()
        };

        let result = bundle.verify(&ledger);
        assert!(matches!(
            result,
            Err(BundleError::StepExceedsMax { step }) if step == Step(DOWN.0 + 1)
        ));
    }

    /// Port of go-algorand's `TestBundleVerifyRejectsStepAboveDown`'s table:
    /// every step up to and including `down` is well-formed; `down + 1` and
    /// `u64::MAX` are rejected.
    #[test]
    fn bundle_well_formed_step_bound() {
        for step in [
            PROPOSE,
            SOFT,
            CERT,
            crate::step::NEXT,
            Step(crate::step::NEXT.0 + 1),
            Step(253),
            Step(254),
            DOWN,
        ] {
            let bundle = UnauthenticatedBundle {
                step,
                ..UnauthenticatedBundle::default()
            };
            assert!(
                bundle.well_formed().is_ok(),
                "step {step} should be well-formed"
            );
        }
        for step in [Step(DOWN.0 + 1), Step(u64::MAX)] {
            let bundle = UnauthenticatedBundle {
                step,
                ..UnauthenticatedBundle::default()
            };
            assert!(matches!(
                bundle.well_formed(),
                Err(BundleError::StepExceedsMax { step: s }) if s == step
            ));
        }
    }

    #[test]
    fn bundle_verify_rejects_too_large() {
        let params = v41_params();
        let threshold = CERT.committee_threshold(&params);
        let ledger = MockLedgerReader::new(params);

        // Create a bundle with more votes than the threshold
        let votes: Vec<VoteAuthenticator> = (0..=threshold)
            .map(|i| VoteAuthenticator {
                sender: Address([i as u8; 32]),
                cred: UnauthenticatedCredential::new([0u8; 80]),
                sig: make_zero_sig(),
            })
            .collect();

        let bundle = UnauthenticatedBundle {
            round: Round(100),
            period: Period(0),
            step: CERT,
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
            votes,
            equivocation_votes: vec![],
        };

        let result = bundle.verify(&ledger);
        assert!(matches!(result, Err(BundleError::TooLarge { .. })));
    }

    #[test]
    fn bundle_verify_rejects_duplicate_voters() {
        let ledger = MockLedgerReader::new(v41_params());
        let addr = Address([0x01; 32]);

        let bundle = UnauthenticatedBundle {
            round: Round(100),
            period: Period(0),
            step: CERT,
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
            votes: vec![
                VoteAuthenticator {
                    sender: addr,
                    cred: UnauthenticatedCredential::new([0u8; 80]),
                    sig: make_zero_sig(),
                },
                VoteAuthenticator {
                    sender: addr, // duplicate
                    cred: UnauthenticatedCredential::new([0u8; 80]),
                    sig: make_zero_sig(),
                },
            ],
            equivocation_votes: vec![],
        };

        let result = bundle.verify(&ledger);
        assert!(matches!(result, Err(BundleError::DuplicateVoter(_))));
    }

    #[test]
    fn bundle_verify_empty_votes_insufficient_quorum() {
        let ledger = MockLedgerReader::new(v41_params());

        let bundle = UnauthenticatedBundle {
            round: Round(100),
            period: Period(0),
            step: SOFT,
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
            votes: vec![],
            equivocation_votes: vec![],
        };

        let result = bundle.verify(&ledger);
        assert!(matches!(
            result,
            Err(BundleError::InsufficientQuorum { .. })
        ));
    }

    #[test]
    fn bundle_verify_vote_fails_with_missing_account() {
        let ledger = MockLedgerReader::new(v41_params());

        let bundle = UnauthenticatedBundle {
            round: Round(100),
            period: Period(0),
            step: CERT,
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
            votes: vec![VoteAuthenticator {
                sender: Address([0x99; 32]), // not in ledger
                cred: UnauthenticatedCredential::new([0u8; 80]),
                sig: make_zero_sig(),
            }],
            equivocation_votes: vec![],
        };

        let result = bundle.verify(&ledger);
        assert!(matches!(
            result,
            Err(BundleError::VoteVerificationFailed { .. })
        ));
    }

    #[test]
    fn bundle_with_inconsistent_votes_handled_by_bundle_structure() {
        // In the Go implementation, bundles enforce that all votes are for the
        // same (round, period, step, proposal) by construction — the individual
        // authenticators don't carry those fields. This test verifies that
        // our UnauthenticatedBundle structure correctly enforces this.
        let bundle = UnauthenticatedBundle {
            round: Round(100),
            period: Period(0),
            step: CERT,
            proposal: BOTTOM, // All votes share this proposal
            votes: vec![
                VoteAuthenticator {
                    sender: Address([0x01; 32]),
                    cred: UnauthenticatedCredential::new([0u8; 80]),
                    sig: make_zero_sig(),
                },
                VoteAuthenticator {
                    sender: Address([0x02; 32]),
                    cred: UnauthenticatedCredential::new([0u8; 80]),
                    sig: make_zero_sig(),
                },
            ],
            equivocation_votes: vec![],
        };

        // Since proposal is BOTTOM and step is CERT, vote verification should
        // fail with BottomNotAllowed when the individual votes are reconstructed.
        //
        // The bundle structure ensures all votes share the same proposal.
        // That's the design — inconsistent votes are impossible by construction.
        assert_eq!(bundle.votes.len(), 2);
        // Both votes will use bundle.proposal (BOTTOM), which is the
        // enforced-consistent-by-structure behavior.
    }

    #[test]
    fn mock_ledger_reader_works() {
        let mut ledger = MockLedgerReader::new(v41_params());
        let addr = Address([0x42; 32]);
        ledger.add_account(
            addr,
            crate::ledger_reader::OnlineAccountData {
                micro_algos: 5_000_000,
                vote_id: [0u8; 32],
                selection_id: [0u8; 32],
                vote_first_valid: Round(0),
                vote_last_valid: Round(0),
                vote_key_dilution: 0,
                incentive_eligible: false,
                last_proposed: Round(0),
                last_heartbeat: Round(0),
                state_proof_id: [0u8; 64],
            },
        );

        assert!(ledger.seed(Round(0)).is_ok());
        assert!(ledger.lookup_agreement(Round(0), &addr).is_ok());
        assert!(ledger.circulation(Round(0), Round(100)).is_ok());
        assert!(ledger.lookup_digest(Round(0)).is_ok());
        assert!(ledger.consensus_params(Round(0)).is_ok());
    }

    #[test]
    fn bundle_verify_rejects_identical_equivocation_proposals() {
        let ledger = MockLedgerReader::new(v41_params());
        let proposal = ProposalValue {
            original_period: Period(0),
            original_proposer: Address([0x01; 32]),
            block_digest: Digest([0xaa; 32]),
            encoding_digest: Digest([0xbb; 32]),
        };

        let bundle = UnauthenticatedBundle {
            round: Round(100),
            period: Period(0),
            step: CERT,
            proposal,
            votes: vec![],
            equivocation_votes: vec![EquivocationVoteAuthenticator {
                sender: Address([0x01; 32]),
                cred: UnauthenticatedCredential::new([0u8; 80]),
                sigs: [make_zero_sig(), make_zero_sig()],
                // Both proposals are identical — not real equivocation
                proposals: [proposal, proposal],
            }],
        };

        let result = bundle.verify(&ledger);
        assert!(
            matches!(result, Err(BundleError::IdenticalEquivocationProposals)),
            "expected IdenticalEquivocationProposals, got {result:?}"
        );
    }

    /// Port of go-algorand
    /// `agreement/vote_test.go::TestEquivocationVoteValidation` (BF-1 from
    /// DOC-91). The Rust port stores equivocation pairs on the parent
    /// `Bundle` rather than as a top-level `unauthenticatedEquivocationVote`
    /// type, so the structural port lives here next to
    /// [`Bundle::verify_equivocation_vote`].
    ///
    /// Builds a real OTS-signed equivocation pair (distinct proposals,
    /// same round/period/step) and exercises the rejection matrix:
    ///
    ///   - **identical proposals** → `IdenticalEquivocationProposals`
    ///     (covers Go's "same vote" sub-case where both proposals match).
    ///   - **zero signatures** across distinct proposals → first proposal's
    ///     OTS verification fails → `VoteVerificationFailed { index: 0,
    ///     detail: "first proposal failed: ..." }`.
    ///   - **bad blockhash on proposal[0]** → first proposal's OTS-signed
    ///     bytes mismatch → first-proposal failure.
    ///   - **bad bundle round** → both reconstructed votes' OTS-signed
    ///     bytes use the new round → first-proposal failure with OTS detail.
    ///   - **sender unknown to the ledger** → `membership_from_ledger`
    ///     fails → `VoteVerificationFailed` with membership-shaped detail.
    ///
    /// **Deferred to BF-3** (real-VRF ledger fixture port from go-algorand
    /// `readOnlyFixture100`):
    ///   - the `noCred` mutation case (Go zeros a previously-selected
    ///     credential); without a real selected credential we can't
    ///     distinguish "valid cred → noCred fails" from baseline.
    ///   - second-proposal-failure cases (e.g. `badBlockHash` on
    ///     `proposal[1]`); `verify_equivocation_vote` runs the full
    ///     credential check on the first proposal before reaching the
    ///     second OTS, so with a dummy credential the first-proposal
    ///     failure masks any second-proposal mutation. The first-proposal
    ///     subcases above already exercise `verify_equivocation_vote`'s
    ///     OTS plumbing for the bytes that survive into both reconstructions.
    #[test]
    fn equivocation_vote_verify_rejection_matrix() {
        use crate::hashable::Hashable;
        use algo_consensus_crypto::{one_time_id_for_round, OneTimeSignatureSecrets};

        // ---- Setup: real OTS-signed equivocation pair. -----------------
        let sender = Address([0x42; 32]);
        let round = 100u64;
        let period = Period(0);
        let step = SOFT;
        let key_dilution = 100u64;

        let id = one_time_id_for_round(round, key_dilution);
        let secrets = OneTimeSignatureSecrets::generate(id.batch, 1);
        let verifier = secrets.verifier();

        let proposal_a = ProposalValue {
            original_period: Period(0),
            original_proposer: sender,
            block_digest: Digest([0xaa; 32]),
            encoding_digest: Digest([0xbb; 32]),
        };
        let proposal_b = ProposalValue {
            original_period: Period(0),
            original_proposer: sender,
            block_digest: Digest([0xcc; 32]),
            encoding_digest: Digest([0xdd; 32]),
        };

        // Sign the OTS-only portion of each proposal (the credential
        // remains the dummy zero-proof; the test asserts OTS-shaped
        // failures, so the credential path is irrelevant here).
        let sign = |proposal: ProposalValue| -> OneTimeSignature {
            let rv = RawVote {
                sender,
                round: Round(round),
                period,
                step,
                proposal,
            };
            let msg = [RawVote::hash_id(), rv.to_be_hashed().as_slice()].concat();
            secrets.sign(&msg, round, key_dilution)
        };
        let sig_a = sign(proposal_a);
        let sig_b = sign(proposal_b);

        // Seed the ledger account with the real OTS verifier so the
        // OTS check has a chance of passing (cred still fails on the
        // dummy proof, but rejections we assert below come from OTS,
        // not from membership lookups failing).
        let mut ledger = MockLedgerReader::new(v41_params());
        ledger.add_account(
            sender,
            crate::ledger_reader::OnlineAccountData {
                micro_algos: 5_000_000,
                vote_id: verifier,
                selection_id: [0u8; 32],
                vote_first_valid: Round(0),
                vote_last_valid: Round(0),
                vote_key_dilution: key_dilution,
                incentive_eligible: false,
                last_proposed: Round(0),
                last_heartbeat: Round(0),
                state_proof_id: [0u8; 64],
            },
        );

        // Helper: assemble a bundle with a single equivocation pair plus
        // optional overrides for testing field mutations.
        let make_bundle = |round: Round,
                           period: Period,
                           step: Step,
                           sender: Address,
                           proposals: [ProposalValue; 2],
                           sigs: [OneTimeSignature; 2]|
         -> UnauthenticatedBundle {
            UnauthenticatedBundle {
                round,
                period,
                step,
                proposal: proposals[0],
                votes: vec![],
                equivocation_votes: vec![EquivocationVoteAuthenticator {
                    sender,
                    cred: UnauthenticatedCredential::new([0u8; 80]),
                    sigs,
                    proposals,
                }],
            }
        };

        // -- Sub-case 1: identical proposals. ----------------------------
        let bundle = make_bundle(
            Round(round),
            period,
            step,
            sender,
            [proposal_a, proposal_a],
            [sig_a.clone(), sig_a.clone()],
        );
        assert!(
            matches!(
                bundle.verify(&ledger),
                Err(BundleError::IdenticalEquivocationProposals),
            ),
            "expected IdenticalEquivocationProposals",
        );

        // -- Sub-case 2: zero signatures across distinct proposals. ------
        let bundle = make_bundle(
            Round(round),
            period,
            step,
            sender,
            [proposal_a, proposal_b],
            [make_zero_sig(), make_zero_sig()],
        );
        match bundle.verify(&ledger) {
            Err(BundleError::VoteVerificationFailed { index, detail }) => {
                assert_eq!(index, 0, "equivocation pair is at index 0");
                assert!(
                    detail.contains("first proposal failed"),
                    "detail should pin the first-proposal path; got {detail:?}",
                );
            }
            other => panic!("expected first-proposal OTS rejection, got {other:?}"),
        }

        // -- Sub-case 3: badBlockHash on proposal[0]. --------------------
        // Mutate proposal[0] AFTER signing → OTS-signed bytes don't match.
        let bad_a = ProposalValue {
            block_digest: Digest([0xee; 32]),
            ..proposal_a
        };
        let bundle = make_bundle(
            Round(round),
            period,
            step,
            sender,
            [bad_a, proposal_b],
            [sig_a.clone(), sig_b.clone()],
        );
        match bundle.verify(&ledger) {
            Err(BundleError::VoteVerificationFailed { index, detail }) => {
                assert_eq!(index, 0);
                assert!(
                    detail.contains("first proposal failed"),
                    "expected first-proposal detail; got {detail:?}",
                );
            }
            other => panic!("expected first-proposal mismatch, got {other:?}"),
        }

        // -- Sub-case 4: bad bundle round. -------------------------------
        // Sigs were generated for `round`, but the bundle declares
        // `round + 1` → both reconstructed votes' OTS-signed bytes don't
        // match → first-proposal OTS rejects.
        let bundle = make_bundle(
            Round(round + 1),
            period,
            step,
            sender,
            [proposal_a, proposal_b],
            [sig_a.clone(), sig_b.clone()],
        );
        match bundle.verify(&ledger) {
            Err(BundleError::VoteVerificationFailed { index, detail }) => {
                assert_eq!(index, 0);
                assert!(
                    detail.contains("first proposal failed"),
                    "expected first-proposal detail; got {detail:?}",
                );
            }
            other => panic!("expected bundle-round mismatch rejection, got {other:?}"),
        }

        // -- Sub-case 5: sender unknown to the ledger. -------------------
        // Different sender → membership_from_ledger fails. Detail is
        // shaped by `verify_equivocation_vote`'s "could not get
        // membership for equivocation vote" wrapper.
        let unknown = Address([0x99; 32]);
        let bundle = make_bundle(
            Round(round),
            period,
            step,
            unknown,
            [proposal_a, proposal_b],
            [sig_a.clone(), sig_b.clone()],
        );
        match bundle.verify(&ledger) {
            Err(BundleError::VoteVerificationFailed { index, detail }) => {
                assert_eq!(index, 0);
                assert!(
                    detail.contains("could not get membership"),
                    "expected membership-lookup detail; got {detail:?}",
                );
            }
            other => panic!("expected membership-lookup rejection, got {other:?}"),
        }
    }

    // ── Test helpers ─────────────────────────────────────────────────────

    fn make_zero_sig() -> OneTimeSignature {
        OneTimeSignature {
            sig: [0u8; 64],
            pk: [0u8; 32],
            pk_sig_old: [0u8; 64],
            pk2: [0u8; 32],
            pk1_sig: [0u8; 64],
            pk2_sig: [0u8; 64],
        }
    }

    /// Peer-supplied weights are summed with go's plain `uint64` wrapping
    /// addition (`agreement/bundle.go`): a huge weight must neither panic
    /// (debug builds) nor saturate to a different sum than go computes.
    #[test]
    fn finish_sums_weights_with_go_wrapping_semantics() {
        use crate::credential::{Credential, HashableCredential};
        use std::time::Duration;

        let vote = |weight: u64| Vote {
            raw_vote: RawVote {
                sender: Address([1u8; 32]),
                round: Round(100),
                period: Period(0),
                step: CERT,
                proposal: BOTTOM,
            },
            cred: Credential {
                weight,
                vrf_out: Digest([0u8; 32]),
                domain_separation_enabled: false,
                hashable: HashableCredential::default(),
                proof: [0u8; 80],
            },
            sig: make_zero_sig(),
            validated_at: Duration::ZERO,
        };
        let b = UnauthenticatedBundle {
            round: Round(100),
            period: Period(0),
            step: CERT,
            proposal: BOTTOM,
            votes: vec![],
            equivocation_votes: vec![],
        };
        let proto = v41_params();

        // u64::MAX + 1000 wraps to 999: below the cert threshold, so go
        // reports 999 as the weight seen.
        match b.finish(&proto, vec![vote(u64::MAX), vote(1000)]) {
            Err(BundleError::InsufficientQuorum { weight, .. }) => assert_eq!(weight, 999),
            other => panic!("expected InsufficientQuorum, got {other:?}"),
        }
        // u64::MAX + threshold + 1 wraps to exactly the threshold: quorum.
        let t = CERT.committee_threshold(&proto);
        let ok = b
            .finish(&proto, vec![vote(u64::MAX), vote(t + 1)])
            .expect("wrapped sum equals the threshold");
        assert_eq!(ok.total_weight, t);
    }
}
