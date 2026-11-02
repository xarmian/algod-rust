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

use crate::bundle::{
    Bundle, BundleError, EquivocationVoteAuthenticator, UnauthenticatedBundle, VoteAuthenticator,
};
use crate::ledger_reader::{membership_from_ledger, LedgerReader};
use crate::vote::{RawVote, UnauthenticatedVote, Vote, VoteVerifyParams};

impl UnauthenticatedBundle {
    /// Reference (pre-#2145) implementation of [`UnauthenticatedBundle::verify`]:
    /// strictly sequential, one membership lookup and one verification per
    /// vote, stopping at the first failure. The vote loop is the original
    /// code; the checks around it are shared with `verify`
    /// (`verify_preconditions`, `finish`). Differential tests pin that
    /// `verify` accepts and rejects exactly the same bundles with the same
    /// error.
    #[doc(hidden)]
    pub fn verify_reference_sequential(&self, l: &dyn LedgerReader) -> Result<Bundle, BundleError> {
        let proto = self.verify_preconditions(l)?;

        // The original loop: one lookup and one verification per vote, in
        // order, stopping at the first failure.
        let mut verified_votes = Vec::with_capacity(self.votes.len());
        for (i, auth) in self.votes.iter().enumerate() {
            verified_votes.push(self.reference_verify_single_vote(l, auth, i)?);
        }
        // Equivocation votes: verify each proposal separately
        for (i, auth) in self.equivocation_votes.iter().enumerate() {
            let idx = self.votes.len() + i;
            verified_votes.push(self.reference_verify_equivocation_vote(l, auth, idx)?);
        }

        self.finish(&proto, verified_votes)
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
