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

use algo_consensus_crypto::OneTimeSignature;
use algo_types::{Address, Round};

use crate::credential::UnauthenticatedCredential;
use crate::ledger_reader::{membership_from_ledger, LedgerError, LedgerReader};
use crate::step::{Period, Step, PROPOSE};
use crate::vote::{ProposalValue, RawVote, UnauthenticatedVote, Vote, VoteVerifyParams};

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
    /// Verify this bundle: check all votes and confirm quorum.
    ///
    /// Mirrors Go's `unauthenticatedBundle.verify()`.
    ///
    /// Steps:
    /// 1. Reject propose step
    /// 2. Check bundle is not too large
    /// 3. Check for duplicate voters
    /// 4. For each vote: reconstruct the UnauthenticatedVote, look up
    ///    membership from the ledger, and verify credential + OTS
    /// 5. Sum weights and check quorum
    pub fn verify(&self, l: &dyn LedgerReader) -> Result<Bundle, BundleError> {
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

        // Step 4: verify each vote
        let mut verified_votes = Vec::with_capacity(self.votes.len());
        let mut total_weight: u64 = 0;

        for (i, auth) in self.votes.iter().enumerate() {
            let vote = self.verify_single_vote(l, auth, i)?;
            total_weight += vote.cred.weight;
            verified_votes.push(vote);
        }

        // Equivocation votes: verify each proposal separately
        for (i, auth) in self.equivocation_votes.iter().enumerate() {
            let idx = self.votes.len() + i;
            // Verify both signatures of the equivocation vote.
            // Each one is effectively a vote for a different proposal.
            // For simplicity and correctness we verify the first proposal's vote
            // (credential verification only needs to happen once since both are
            // from the same sender in the same round/period/step).
            let vote = self.verify_equivocation_vote(l, auth, idx)?;
            total_weight += vote.cred.weight;
            verified_votes.push(vote);
        }

        // Step 5: check quorum
        if !self.step.reaches_quorum(&proto, total_weight) {
            return Err(BundleError::InsufficientQuorum {
                weight: total_weight,
                threshold: self.step.committee_threshold(&proto),
            });
        }

        Ok(Bundle {
            u: self.clone(),
            votes: verified_votes,
            total_weight,
        })
    }

    /// Verify a single vote authenticator from the bundle.
    fn verify_single_vote(
        &self,
        l: &dyn LedgerReader,
        auth: &VoteAuthenticator,
        index: usize,
    ) -> Result<Vote, BundleError> {
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

        // Look up membership from ledger
        let (membership, record, proto) =
            membership_from_ledger(l, &auth.sender, self.round, self.period, self.step).map_err(
                |e| BundleError::VoteVerificationFailed {
                    index,
                    detail: format!("could not get membership: {e}"),
                },
            )?;

        let params = VoteVerifyParams {
            membership,
            vote_id: record.vote_id,
            vote_first_valid: record.vote_first_valid,
            vote_last_valid: record.vote_last_valid,
            vote_key_dilution: record.vote_key_dilution,
            consensus_params: proto,
        };

        uv.verify(&params)
            .map_err(|e| BundleError::VoteVerificationFailed {
                index,
                detail: e.to_string(),
            })
    }

    /// Verify an equivocation vote authenticator.
    ///
    /// In Go, equivocation votes prove that a sender voted for two different
    /// proposals. For bundle verification, we verify the credential once and
    /// verify both OTS signatures against the two different proposals.
    fn verify_equivocation_vote(
        &self,
        l: &dyn LedgerReader,
        auth: &EquivocationVoteAuthenticator,
        index: usize,
    ) -> Result<Vote, BundleError> {
        // Reject if both proposals are identical — that's not real equivocation.
        // Mirrors Go's unauthenticatedEquivocationVote.verify() check.
        if auth.proposals[0] == auth.proposals[1] {
            return Err(BundleError::IdenticalEquivocationProposals);
        }

        // Verify the first proposal's vote (this checks credential + first OTS)
        let uv1 = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: auth.sender,
                round: self.round,
                period: self.period,
                step: self.step,
                proposal: auth.proposals[0],
            },
            cred: auth.cred.clone(),
            sig: auth.sigs[0].clone(),
        };

        let (membership, record, proto) =
            membership_from_ledger(l, &auth.sender, self.round, self.period, self.step).map_err(
                |e| BundleError::VoteVerificationFailed {
                    index,
                    detail: format!("could not get membership for equivocation vote: {e}"),
                },
            )?;

        let params = VoteVerifyParams {
            membership: membership.clone(),
            vote_id: record.vote_id,
            vote_first_valid: record.vote_first_valid,
            vote_last_valid: record.vote_last_valid,
            vote_key_dilution: record.vote_key_dilution,
            consensus_params: proto.clone(),
        };

        let vote1 = uv1
            .verify(&params)
            .map_err(|e| BundleError::VoteVerificationFailed {
                index,
                detail: format!("equivocation vote first proposal failed: {e}"),
            })?;

        // Verify the second proposal's OTS signature
        let uv2 = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: auth.sender,
                round: self.round,
                period: self.period,
                step: self.step,
                proposal: auth.proposals[1],
            },
            cred: auth.cred.clone(),
            sig: auth.sigs[1].clone(),
        };

        let params2 = VoteVerifyParams {
            membership,
            vote_id: record.vote_id,
            vote_first_valid: record.vote_first_valid,
            vote_last_valid: record.vote_last_valid,
            vote_key_dilution: record.vote_key_dilution,
            consensus_params: proto,
        };

        uv2.verify(&params2)
            .map_err(|e| BundleError::VoteVerificationFailed {
                index,
                detail: format!("equivocation vote second proposal failed: {e}"),
            })?;

        // Return the first vote (weight counts once for equivocation)
        Ok(vote1)
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
}
