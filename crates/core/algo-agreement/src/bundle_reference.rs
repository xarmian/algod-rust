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

//! Test-only reference copy of the original sequential
//! `UnauthenticatedBundle::verify` (issue #2145), used by the differential
//! tests that pin the parallel implementation to the old behaviour.

use std::collections::HashSet;

use crate::bundle::{
    Bundle, BundleError, EquivocationVoteAuthenticator, UnauthenticatedBundle, VoteAuthenticator,
};
use crate::ledger_reader::{membership_from_ledger, LedgerReader};
use crate::step::PROPOSE;
use crate::vote::{RawVote, UnauthenticatedVote, Vote, VoteVerifyParams};

impl UnauthenticatedBundle {
    /// Reference (pre-#2145) implementation of [`UnauthenticatedBundle::verify`]:
    /// strictly sequential, one membership lookup per vote. Kept verbatim
    /// so differential tests can pin that the parallel path accepts and
    /// rejects exactly the same bundles with the same error.
    ///
    /// Mirrors Go's `unauthenticatedBundle.verify()`.
    ///
    /// Steps:
    /// 1. Well-formedness (step bound check), as defense in depth
    /// 2. Reject propose step
    /// 3. Check bundle is not too large
    /// 4. Check for duplicate voters
    /// 5. For each vote: reconstruct the UnauthenticatedVote, look up
    ///    membership from the ledger, and verify credential + OTS
    /// 6. Sum weights and check quorum
    #[doc(hidden)]
    pub fn verify_reference_sequential(&self, l: &dyn LedgerReader) -> Result<Bundle, BundleError> {
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

        // Step 4: verify each vote
        let mut verified_votes = Vec::with_capacity(self.votes.len());
        let mut total_weight: u64 = 0;

        for (i, auth) in self.votes.iter().enumerate() {
            let vote = self.reference_verify_single_vote(l, auth, i)?;
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
            let vote = self.reference_verify_equivocation_vote(l, auth, idx)?;
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
    fn reference_verify_single_vote(
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
    fn reference_verify_equivocation_vote(
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
