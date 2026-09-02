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

// `VoteMakerHelper` and friends — fabricators for `RawVote`, `Vote`, and
// `Bundle` values used by white-box state-machine tests.
//
// Mirrors go-algorand `agreement/common_test.go::voteMakerHelper` plus the
// `MakeRandomProposalPayload` and `randomBlockHash` helpers used by the
// permutation test. The fabricated values bypass real signature crypto:
// votes carry `Credential { weight: 1 }` so the threshold math (`s.threshold(params)`)
// produces sensible bundle sizes, but the OTS signature and VRF proof
// fields are zeroed. The agreement state machine never validates these in
// the white-box tests — verification happens elsewhere (the crypto verifier
// stub returns success).

use std::collections::HashMap;

use algo_types::{Address, Block, ConsensusParams, Digest, Round};

use crate::bundle::{Bundle, UnauthenticatedBundle, VoteAuthenticator};
use crate::credential::{Credential, HashableCredential, UnauthenticatedCredential};
use crate::events::Proposal;
use crate::proposal::UnauthenticatedProposal;
use crate::step::{Period, Step};
use crate::vote::{ProposalValue, RawVote, Vote};
use crate::VRF_PROOF_SIZE;

// ---------------------------------------------------------------------------
// Random-bytes helpers (deterministic per-test via thread-local counter)
// ---------------------------------------------------------------------------

/// Generate a fresh 32-byte digest. Used to fabricate distinct addresses
/// and block digests within a test.
///
/// Mirrors Go's `randomBlockHash()`. The Go version uses `crypto.RandBytes`;
/// here we use a simple deterministic counter so failure traces are
/// reproducible. The values are not cryptographically meaningful — they
/// just need to be distinct within a single test invocation.
pub fn random_block_hash() -> Digest {
    use std::cell::Cell;
    thread_local! {
        static COUNTER: Cell<u64> = const { Cell::new(0) };
    }
    let n = COUNTER.with(|c| {
        let v = c.get().wrapping_add(1);
        c.set(v);
        v
    });
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&n.to_le_bytes());
    // Salt with a constant so a fresh-counter `1` doesn't collide with any
    // other `[1, 0, 0, ...]` zero-padding the test machinery might fabricate.
    bytes[31] = 0xAB;
    Digest(bytes)
}

// ---------------------------------------------------------------------------
// Proposal payload fabrication
// ---------------------------------------------------------------------------

/// Fabricate a minimal `Proposal` for round `r`.
///
/// Mirrors Go's `makeRandomProposalPayload(r)` in
/// `agreement/player_permutation_test.go:34`. The Go version goes through
/// `testBlockFactory{Owner: 1}.AssembleBlock(r, nil).FinishBlock(...)`; we
/// shortcut directly to a `Block` whose only meaningful field is `round`,
/// which is sufficient for the permutation matrix's trace-level assertions
/// (no test inspects block contents).
///
/// The returned `Proposal` has its `unauthenticated_proposal.value()` digest
/// derived from the block + zero VRF proof, so callers can compute
/// `payload.unauthenticated_proposal.value()` to obtain a stable
/// `ProposalValue` for the same payload across the test run.
pub fn make_random_proposal_payload(r: Round) -> Proposal {
    let block = Block {
        round: r,
        ..Block::default()
    };
    let unauth = UnauthenticatedProposal {
        block,
        seed_proof: [0u8; VRF_PROOF_SIZE],
        original_period: Period(0),
        original_proposer: Address([0u8; 32]),
        ..UnauthenticatedProposal::default()
    };
    Proposal {
        unauthenticated_proposal: unauth,
        validated_at: std::time::Duration::ZERO,
        received_at: std::time::Duration::ZERO,
        validated_block: None,
    }
}

// ---------------------------------------------------------------------------
// VoteMakerHelper
// ---------------------------------------------------------------------------

/// Index-keyed fabricator for test votes and bundles.
///
/// Mirrors Go's `voteMakerHelper`. Each `index` argument maps to a stable
/// `Address` so multiple votes from the same caller appear to come from
/// the same sender (necessary for duplicate-detection tests). The first
/// `make_*` call for a given index lazily fabricates the address.
#[derive(Default)]
pub struct VoteMakerHelper {
    /// Stable proposal-value reused across vote fabrication when callers
    /// don't pass an explicit value. Set by [`Self::setup`].
    pub proposal: ProposalValue,
    /// Per-index address cache.
    pub addresses: HashMap<usize, Address>,
}

impl VoteMakerHelper {
    /// Fresh helper. Call [`Self::setup`] before use to populate the
    /// default proposal-value. (Go's helper does this implicitly via
    /// `Setup()`; we keep it explicit so the test reads top-down.)
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize `proposal` with a fresh random value (if unset) and clear
    /// the address cache.
    ///
    /// Mirrors Go's `voteMakerHelper.Setup()`. Safe to call repeatedly; it
    /// only initializes on first use.
    pub fn setup(&mut self) {
        if self.proposal == ProposalValue::default() {
            self.proposal = self.make_random_proposal_value();
            self.addresses = HashMap::new();
        }
    }

    /// Fresh random proposal-value with all-zero `original_*` fields and
    /// distinct digests. Mirrors Go's
    /// `voteMakerHelper.MakeRandomProposalValue()`.
    pub fn make_random_proposal_value(&self) -> ProposalValue {
        ProposalValue {
            original_period: Period(0),
            original_proposer: Address([0u8; 32]),
            block_digest: random_block_hash(),
            encoding_digest: random_block_hash(),
        }
    }

    /// Address for `index`, fabricating one on first call.
    fn address_for(&mut self, index: usize) -> Address {
        if let Some(a) = self.addresses.get(&index) {
            return *a;
        }
        let h = random_block_hash();
        let a = Address(h.0);
        self.addresses.insert(index, a);
        a
    }

    /// Build a `RawVote` for `(index, round, period, step, value)`.
    ///
    /// Mirrors Go's `voteMakerHelper.MakeRawVote`.
    pub fn make_raw_vote(
        &mut self,
        index: usize,
        round: Round,
        period: Period,
        step: Step,
        value: ProposalValue,
    ) -> RawVote {
        let sender = self.address_for(index);
        RawVote {
            sender,
            round,
            period,
            step,
            proposal: value,
        }
    }

    /// Build a verified `Vote` (with `Credential { weight: 1 }`).
    ///
    /// Mirrors Go's `voteMakerHelper.MakeVerifiedVote`.
    pub fn make_verified_vote(
        &mut self,
        index: usize,
        round: Round,
        period: Period,
        step: Step,
        value: ProposalValue,
    ) -> Vote {
        let raw = self.make_raw_vote(index, round, period, step, value);
        Vote {
            raw_vote: raw,
            cred: Credential {
                weight: 1,
                vrf_out: Digest([0u8; 32]),
                domain_separation_enabled: false,
                hashable: HashableCredential::default(),
                proof: [0u8; VRF_PROOF_SIZE],
            },
            sig: zero_one_time_signature(),
            // Mirrors Go's `MakeVerifiedVote`, which also leaves
            // `validatedAt` zero — timing is attached separately via
            // `MessageEvent::attach_validated_at` at the point a
            // `voteVerified` event is dispatched, mirroring demux's
            // real behavior.
            validated_at: std::time::Duration::ZERO,
        }
    }

    /// Build a verified `Bundle` for `(round, period, step, value)`. The
    /// bundle has `s.threshold(params)` votes — exactly the threshold size
    /// — using indices `0..N`. Mirrors Go's
    /// `voteMakerHelper.MakeVerifiedBundle`.
    pub fn make_verified_bundle(
        &mut self,
        round: Round,
        period: Period,
        step: Step,
        value: ProposalValue,
        params: &ConsensusParams,
    ) -> Bundle {
        let n = step.committee_threshold(params) as usize;
        let mut votes = Vec::with_capacity(n);
        for i in 0..n {
            votes.push(self.make_verified_vote(i, round, period, step, value));
        }
        let unauth = UnauthenticatedBundle {
            round,
            period,
            step,
            proposal: value,
            votes: votes
                .iter()
                .map(|v| VoteAuthenticator {
                    sender: v.raw_vote.sender,
                    cred: UnauthenticatedCredential::new(v.cred.proof),
                    sig: v.sig.clone(),
                })
                .collect(),
            equivocation_votes: Vec::new(),
        };
        let total_weight = votes.iter().map(|v| v.cred.weight).sum();
        Bundle {
            u: unauth,
            votes,
            total_weight,
        }
    }

    /// Plain unauthenticated-bundle (no votes), used in `bundlePresent`
    /// permutation arms where the player only sees the bundle envelope.
    /// The `s.threshold(params)` votes still get materialized so the
    /// round-trip `verify_bundle_action(...)` constructed in expected
    /// matches the bundle the player would receive.
    pub fn make_unauthenticated_bundle_with_votes(
        &mut self,
        round: Round,
        period: Period,
        step: Step,
        value: ProposalValue,
        params: &ConsensusParams,
    ) -> UnauthenticatedBundle {
        self.make_verified_bundle(round, period, step, value, params)
            .u
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// All-zero `OneTimeSignature`. The white-box tests don't validate
/// signatures (the verifier stub returns OK), so a zeroed sig is sufficient.
fn zero_one_time_signature() -> algo_consensus_crypto::OneTimeSignature {
    algo_consensus_crypto::OneTimeSignature {
        sig: [0u8; 64],
        pk: [0u8; 32],
        pk_sig_old: [0u8; 64],
        pk2: [0u8; 32],
        pk1_sig: [0u8; 64],
        pk2_sig: [0u8; 64],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::step::SOFT;

    #[test]
    fn random_block_hash_is_unique_within_thread() {
        let a = random_block_hash();
        let b = random_block_hash();
        assert_ne!(a.0, b.0);
        // Sanity: salt byte is set so zero-padding doesn't collide.
        assert_eq!(a.0[31], 0xAB);
    }

    #[test]
    fn vote_maker_index_addresses_are_stable() {
        let mut h = VoteMakerHelper::new();
        let v0a = h.make_verified_vote(0, Round(1), Period(0), SOFT, ProposalValue::default());
        let v0b = h.make_verified_vote(0, Round(2), Period(0), SOFT, ProposalValue::default());
        assert_eq!(v0a.raw_vote.sender, v0b.raw_vote.sender);
    }

    #[test]
    fn vote_maker_distinct_indices_have_distinct_addresses() {
        let mut h = VoteMakerHelper::new();
        let v0 = h.make_verified_vote(0, Round(1), Period(0), SOFT, ProposalValue::default());
        let v1 = h.make_verified_vote(1, Round(1), Period(0), SOFT, ProposalValue::default());
        assert_ne!(v0.raw_vote.sender, v1.raw_vote.sender);
    }

    #[test]
    fn make_random_proposal_payload_carries_round() {
        let p = make_random_proposal_payload(Round(42));
        assert_eq!(p.unauthenticated_proposal.round(), Round(42));
    }
}
