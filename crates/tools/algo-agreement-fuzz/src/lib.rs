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

//! Negative Layer-9 conformance: construct agreement messages carrying exactly
//! one injected fault (issue #472).
//!
//! # Why this exists
//!
//! The positive conformance suite (#470) proves a Go quorum *accepts* the Rust
//! node's valid agreement messages. It says nothing about whether Go's
//! acceptance path is accidentally permissive. This crate builds the converse
//! evidence: a message that is byte-identical to an honest one except for a
//! single, precisely-named fault, so that a Go rejection is attributable to
//! that fault and nothing else.
//!
//! # Full-parity discipline
//!
//! Everything here goes through the production encoders in
//! [`algo_agreement::codec`] and the production crypto in
//! `algo_consensus_crypto`. No msgpack is hand-rolled, and no corruption is
//! applied at the byte level: a fault is injected into the *typed* message
//! before encoding, so the encoding is always the one an honest node would
//! have produced for that (faulted) value.
//!
//! Every builder therefore has the shape:
//!
//! 1. build the honest baseline message from real keys and real ledger
//!    parameters,
//! 2. apply exactly one corruption,
//! 3. encode with the production encoder.
//!
//! [`baseline_and_faulted`] returns both halves so a caller (or a test) can
//! diff them and prove only the intended field moved.
//!
//! # The four required cases
//!
//! | Case | [`VoteFault`] / [`ProposalFault`] | Go rejection site |
//! |---|---|---|
//! | 1. bad VRF proof | [`VoteFault::BadVrfProof`] | `committee.UnauthenticatedCredential.Verify` → "could not verify VRF Proof" |
//! | 2. wrong committee weight | [`VoteFault::ZeroWeightCredential`] | `committee.UnauthenticatedCredential.Verify` → "credential has weight 0" |
//! | 3. wrong OTS domain | [`VoteFault::WrongOtsDomain`] | `agreement.unauthenticatedVote.verify` → "could not verify FS signature on vote" |
//! | 4. malformed proposal | [`ProposalFault`] | `agreement.proposal.validate` / `verifyProposer` / block validation |
//!
//! ## A note on case 2, and what is *not* representable on the wire
//!
//! The issue asks for "a credential/vote claiming a stake weight inconsistent
//! with the account's actual online balance". That claim **cannot be placed on
//! the wire at all**: go-algorand's wire type is
//! `committee.UnauthenticatedCredential`, whose only field is the 80-byte VRF
//! proof (`codec:"pf"`). `Weight` exists solely on the *verified*
//! `committee.Credential`, which is never transmitted — see
//! `data/committee/credential.go` and this repo's
//! [`algo_agreement::UnauthenticatedCredential`]. The verifier always recomputes
//! the weight itself from `sortition.Select(userMoney, totalMoney, …)`.
//!
//! That is itself a (positive) conformance finding: the protocol is not
//! *vulnerable* to a claimed-weight mismatch because there is no claimed weight.
//! The reachable weight-related rejection is therefore the one Go actually
//! implements — a credential whose recomputed sortition weight is zero, i.e. a
//! vote from an account that did **not** win a seat on that committee. That is
//! what [`VoteFault::ZeroWeightCredential`] produces, and
//! [`committee_weight`] / [`find_zero_weight_round`] let a caller pick a
//! `(round, period, step)` where that is true for the real online stake.

use algo_agreement::codec;
use algo_agreement::{hash_rep, Hashable};
use algo_agreement::{
    CompoundMessage, Membership, Period, ProposalValue, RawVote, Seed, Selector, Step,
    UnauthenticatedCredential, UnauthenticatedProposal, UnauthenticatedVote, VoteVerifyParams,
    BOTTOM, PROPOSE,
};
use algo_consensus_crypto::onetimesig::{one_time_id_for_round, OneTimeSignatureSecrets};
use algo_consensus_crypto::sortition;
use algo_consensus_crypto::vrf::VrfKeypair;
use algo_types::{Address, ConsensusParams, Round};

pub mod inject;
pub mod inject_p2p;

/// Go's `protocol.Vote` HashID — the correct domain-separation prefix for the
/// message an agreement vote signs.
pub const VOTE_DOMAIN: &[u8] = b"VO";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised while constructing a faulted message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzError {
    /// A fault's precondition does not hold for the supplied context, so the
    /// message would not exercise the intended rejection path.
    ///
    /// Refusing to build here is deliberate: a "negative" test that rejects for
    /// the wrong reason is worse than no test.
    PreconditionViolated(String),
}

impl std::fmt::Display for FuzzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PreconditionViolated(m) => write!(f, "fault precondition violated: {m}"),
        }
    }
}

impl std::error::Error for FuzzError {}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/// Everything an honest node would look up from its ledger in order to emit a
/// vote, gathered into one plain value so message construction is pure and
/// unit-testable without a ledger.
///
/// Mirrors the inputs to Go's `agreement.makeVote` plus the `committee.Membership`
/// its `membership()` helper derives.
#[derive(Debug, Clone)]
pub struct VoteContext {
    /// The voting account.
    pub sender: Address,
    /// Round being voted on (the *player's* round, not the last committed one).
    pub round: Round,
    /// Period within the round.
    pub period: Period,
    /// Agreement step.
    pub step: Step,
    /// The proposal value being endorsed (`BOTTOM` is only legal for steps
    /// above `cert`).
    pub proposal: ProposalValue,
    /// Committee seed, i.e. the seed of `seed_round(round)`.
    pub seed: Seed,
    /// The account's voting stake (microAlgos) at the balance-lookback round.
    pub balance: u64,
    /// Total online stake (microAlgos) at the balance-lookback round.
    pub total_money: u64,
    /// Effective key dilution for the account.
    pub key_dilution: u64,
    /// First round this participation key is valid for.
    pub vote_first_valid: Round,
    /// Last round this participation key is valid for (0 = unbounded).
    pub vote_last_valid: Round,
    /// Consensus params of `params_round(round)`.
    pub params: ConsensusParams,
}

impl VoteContext {
    /// The sortition selector for this `(seed, round, period, step)`.
    pub fn selector(&self) -> Selector {
        Selector {
            seed: self.seed,
            round: self.round,
            period: self.period,
            step: self.step,
        }
    }

    /// The `committee.Membership` a verifier reconstructs for this vote.
    pub fn membership(&self, selection_id: [u8; 32]) -> Membership {
        Membership {
            address: self.sender,
            selection_id,
            balance: self.balance,
            total_money: self.total_money,
            selector: self.selector(),
        }
    }

    /// The unsigned vote body an honest node would sign.
    pub fn raw_vote(&self) -> RawVote {
        RawVote {
            sender: self.sender,
            round: self.round,
            period: self.period,
            step: self.step,
            proposal: self.proposal,
        }
    }

    /// Verification parameters mirroring what a Go verifier would assemble,
    /// so a test can run the same checks Go runs.
    pub fn verify_params(&self, secrets: &ParticipationSecrets) -> VoteVerifyParams {
        VoteVerifyParams {
            membership: self.membership(*secrets.vrf.pk.as_bytes()),
            vote_id: secrets.ots.verifier(),
            vote_first_valid: self.vote_first_valid,
            vote_last_valid: self.vote_last_valid,
            vote_key_dilution: self.key_dilution,
            consensus_params: self.params.clone(),
        }
    }
}

/// The signing material for the injected identity: a real participation key.
pub struct ParticipationSecrets {
    /// VRF keypair used for sortition credentials.
    pub vrf: VrfKeypair,
    /// One-time signature secrets used to sign the vote body.
    pub ots: OneTimeSignatureSecrets,
}

// ---------------------------------------------------------------------------
// Faults
// ---------------------------------------------------------------------------

/// How to corrupt a VRF proof while keeping it structurally valid (80 bytes,
/// the shape `Gamma(32) || c(16) || s(32)`).
///
/// Go decodes the proof as a fixed-size array, so a *shape* error would be
/// rejected by msgpack before verification ever runs. Every variant here keeps
/// the shape intact so the rejection genuinely comes from
/// `crypto.VrfPubkey.Verify`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VrfCorruption {
    /// Flip the lowest bit of the `Gamma` point (proof byte 0).
    FlipGamma,
    /// Flip the lowest bit of the challenge scalar `c` (proof byte 32).
    FlipChallenge,
    /// Flip the lowest bit of the response scalar `s` (proof byte 48).
    FlipResponse,
    /// Replace the proof with a valid proof produced by a *different* VRF key
    /// over the same selector. Structurally perfect, verifies under the wrong
    /// public key — the closest analogue of a real forgery attempt.
    ForeignKey([u8; 32]),
}

impl VrfCorruption {
    fn apply(self, proof: [u8; 80], alpha: &[u8]) -> [u8; 80] {
        let mut p = proof;
        match self {
            Self::FlipGamma => p[0] ^= 0x01,
            Self::FlipChallenge => p[32] ^= 0x01,
            Self::FlipResponse => p[48] ^= 0x01,
            Self::ForeignKey(seed) => {
                let other = VrfKeypair::from_seed(seed);
                p = other.sk.prove(alpha).0 .0;
            }
        }
        p
    }
}

/// Which domain-separation prefix to sign the vote body under.
///
/// go-algorand signs `crypto.HashRep(rawVote)` = `"VO" || msgpack(rawVote)`
/// (`protocol.Vote`, `protocol/hash.go`). The one-time key tree itself is
/// separately domain-separated with `"OT1"`/`"OT2"`
/// (`crypto/onetimesig.go`). Each variant below signs the *same bytes* with the
/// *same key* under a different context, which is exactly the fault the issue
/// asks for: correct key, wrong domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtsDomain {
    /// The correct `protocol.Vote` domain (`"VO"`) — the honest baseline.
    Vote,
    /// No domain-separation prefix at all: sign the bare msgpack body.
    Absent,
    /// `protocol.Payload` (`"PL"`) — the proposal-payload domain.
    Payload,
    /// `protocol.AgreementSelector` (`"AS"`) — the sortition-selector domain.
    Selector,
    /// `protocol.Credential` (`"CR"`) — the credential domain.
    Credential,
    /// `protocol.OneTimeSigKey1` (`"OT1"`) — the OTS batch-subkey domain, i.e.
    /// re-using an internal key-tree context for the outer message.
    OneTimeSigKey1,
}

impl OtsDomain {
    /// The bytes prefixed to the msgpack body before signing.
    pub fn prefix(self) -> &'static [u8] {
        match self {
            Self::Vote => b"VO",
            Self::Absent => b"",
            Self::Payload => b"PL",
            Self::Selector => b"AS",
            Self::Credential => b"CR",
            Self::OneTimeSigKey1 => b"OT1",
        }
    }
}

/// A single injected fault for an agreement vote (`AV`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VoteFault {
    /// No fault: the honest baseline.
    #[default]
    None,
    /// **Case 1** — a valid-shaped VRF proof that does not verify against the
    /// account's registered selection key.
    BadVrfProof(VrfCorruption),
    /// **Case 2** — an entirely honest credential for a `(round, period, step)`
    /// at which the account's real online stake wins **zero** committee seats.
    ///
    /// This produces no wire-level mutation (see the module docs on why a
    /// claimed weight is not representable); the fault lives in the choice of
    /// selector. [`build_vote`] therefore *refuses* to build this variant
    /// unless [`committee_weight`] really is zero, so the test cannot silently
    /// degrade into "sent a perfectly valid vote".
    ZeroWeightCredential,
    /// **Case 3** — signed by the correct one-time key, over the correct body,
    /// under the wrong domain-separation context.
    WrongOtsDomain(OtsDomain),
}

impl VoteFault {
    /// The substring of go-algorand's error text this fault should provoke.
    ///
    /// Sourced from `agreement/vote.go` and `data/committee/credential.go` at
    /// v4.6.0-stable; used by the live harness to attribute a rejection.
    pub fn expected_go_error(self) -> &'static str {
        match self {
            Self::None => "",
            Self::BadVrfProof(_) => "could not verify VRF Proof",
            Self::ZeroWeightCredential => "credential has weight 0",
            Self::WrongOtsDomain(_) => "could not verify FS signature on vote",
        }
    }

    /// Short stable identifier used in CLI arguments and report JSON.
    pub fn case_name(self) -> &'static str {
        match self {
            Self::None => "baseline",
            Self::BadVrfProof(_) => "bad-vrf-proof",
            Self::ZeroWeightCredential => "wrong-committee-weight",
            Self::WrongOtsDomain(_) => "wrong-ots-domain",
        }
    }
}

// ---------------------------------------------------------------------------
// Vote construction
// ---------------------------------------------------------------------------

/// The sortition weight the account really has for `ctx`'s selector — exactly
/// the number Go recomputes in `UnauthenticatedCredential.Verify`.
pub fn committee_weight(ctx: &VoteContext, secrets: &ParticipationSecrets) -> u64 {
    let cred = honest_credential(ctx, secrets);
    match cred.verify(&ctx.params, &ctx.membership(*secrets.vrf.pk.as_bytes())) {
        Ok(c) => c.weight,
        // `ZeroWeight` is the only "failure" reachable with an honest proof.
        Err(_) => 0,
    }
}

/// Search forward from `ctx.round` for a round at which the account wins zero
/// seats on `ctx.step`'s committee, given a seed lookup for each round.
///
/// Returns the first `(round, seed)` that yields weight 0, or `None` if the
/// account is selected at every round in `rounds`.
///
/// Used by the live harness for case 2: the injected vote must stay inside the
/// verifier's freshness window, so the *round* (not the period) is the free
/// variable to search over.
pub fn find_zero_weight_round<F>(
    ctx: &VoteContext,
    secrets: &ParticipationSecrets,
    rounds: impl IntoIterator<Item = Round>,
    mut seed_for_round: F,
) -> Option<(Round, Seed)>
where
    F: FnMut(Round) -> Option<Seed>,
{
    for round in rounds {
        let seed = seed_for_round(round)?;
        let mut probe = ctx.clone();
        probe.round = round;
        probe.seed = seed;
        if committee_weight(&probe, secrets) == 0 {
            return Some((round, seed));
        }
    }
    None
}

/// The honest credential for `ctx`: a VRF proof over `HashRep(selector)`.
///
/// Matches Go's `committee.MakeCredential(&selection.SK, m.Selector)`.
fn honest_credential(
    ctx: &VoteContext,
    secrets: &ParticipationSecrets,
) -> UnauthenticatedCredential {
    let alpha = hash_rep(&ctx.selector());
    let (proof, _) = secrets.vrf.sk.prove(&alpha);
    UnauthenticatedCredential::new(proof.0)
}

/// Reject inputs where a *structural* rule would make Go bail out before it
/// reaches the check the fault is aimed at.
fn check_preconditions(
    ctx: &VoteContext,
    secrets: &ParticipationSecrets,
    fault: VoteFault,
) -> Result<(), FuzzError> {
    let rv = ctx.raw_vote();
    if ctx.step <= algo_agreement::CERT && rv.proposal.is_bottom() {
        return Err(FuzzError::PreconditionViolated(format!(
            "step {} cannot vote bottom; Go rejects before verifying the credential",
            ctx.step
        )));
    }
    if ctx.step == PROPOSE
        && rv.period == rv.proposal.original_period
        && rv.sender != rv.proposal.original_proposer
    {
        return Err(FuzzError::PreconditionViolated(
            "propose-step vote sender must equal the proposal's original proposer".into(),
        ));
    }
    if fault == VoteFault::ZeroWeightCredential {
        let weight = committee_weight(ctx, secrets);
        if weight != 0 {
            return Err(FuzzError::PreconditionViolated(format!(
                "account wins {weight} seat(s) at round {} period {} step {}; \
                 pick a selector where it wins none",
                ctx.round, ctx.period, ctx.step
            )));
        }
    }
    Ok(())
}

/// The honest vote for `ctx`: real credential, real signature, correct domain.
fn honest_vote(ctx: &VoteContext, secrets: &ParticipationSecrets) -> UnauthenticatedVote {
    let rv = ctx.raw_vote();
    let msg = [OtsDomain::Vote.prefix(), rv.to_be_hashed().as_slice()].concat();
    let sig = secrets.ots.sign(&msg, rv.round.0, ctx.key_dilution);
    UnauthenticatedVote {
        raw_vote: rv,
        cred: honest_credential(ctx, secrets),
        sig,
    }
}

/// Apply exactly one fault to an already-built honest vote.
fn apply_vote_fault(
    honest: &UnauthenticatedVote,
    ctx: &VoteContext,
    secrets: &ParticipationSecrets,
    fault: VoteFault,
) -> UnauthenticatedVote {
    let mut v = honest.clone();
    match fault {
        // No wire-level mutation: the fault is the selector's zero weight.
        VoteFault::None | VoteFault::ZeroWeightCredential => {}
        VoteFault::BadVrfProof(c) => {
            let alpha = hash_rep(&ctx.selector());
            v.cred = UnauthenticatedCredential::new(c.apply(honest.cred.proof, &alpha));
        }
        VoteFault::WrongOtsDomain(d) => {
            let msg = [d.prefix(), v.raw_vote.to_be_hashed().as_slice()].concat();
            v.sig = secrets.ots.sign(&msg, v.raw_vote.round.0, ctx.key_dilution);
        }
    }
    v
}

/// Build an agreement vote carrying exactly `fault` and nothing else.
///
/// With [`VoteFault::None`] this is the honest message an algod-rust pseudonode
/// would have produced for the same inputs; every other variant differs from it
/// in exactly one field.
pub fn build_vote(
    ctx: &VoteContext,
    secrets: &ParticipationSecrets,
    fault: VoteFault,
) -> Result<UnauthenticatedVote, FuzzError> {
    check_preconditions(ctx, secrets, fault)?;
    let honest = honest_vote(ctx, secrets);
    Ok(apply_vote_fault(&honest, ctx, secrets, fault))
}

/// Build the honest baseline **and** the faulted message from *one* honest
/// build, so the two really do differ in exactly one field.
///
/// Building them independently would not be enough: one-time signatures are
/// non-deterministic by protocol design — go-algorand's
/// `OneTimeSignatureSecrets.Sign` mints a fresh ephemeral offset subkey for
/// every signature (`crypto/onetimesig.go`), and this repo's port does the same
/// — so two honest signings of the same body differ in `pk`/`p1s`/`s`. Sharing
/// the single honest build keeps the diff attributable.
pub fn baseline_and_faulted(
    ctx: &VoteContext,
    secrets: &ParticipationSecrets,
    fault: VoteFault,
) -> Result<(UnauthenticatedVote, UnauthenticatedVote), FuzzError> {
    check_preconditions(ctx, secrets, fault)?;
    let baseline = honest_vote(ctx, secrets);
    let faulted = apply_vote_fault(&baseline, ctx, secrets, fault);
    Ok((baseline, faulted))
}

/// Encode a vote for the `AV` tag using the production encoder.
pub fn encode_vote(vote: &UnauthenticatedVote) -> Vec<u8> {
    codec::encode_vote(vote)
}

// ---------------------------------------------------------------------------
// Proposal construction (case 4)
// ---------------------------------------------------------------------------

/// A single injected fault for a proposal payload (`PP`).
///
/// Unlike votes, a proposal is rejected by the *block* validator rather than by
/// signature verification, so each variant names the go-algorand check it is
/// aimed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProposalFault {
    /// No fault: the payload exactly as received/assembled.
    #[default]
    None,
    /// Corrupt the payset commitment (`BlockHeader.TxnCommitments`, `"txn"`),
    /// so the block's transaction root does not match its payset.
    ///
    /// Rejected by `ledger/eval` block validation.
    BadPaysetCommitment,
    /// Corrupt the previous-block pointer (`BlockHeader.Branch`, `"prev"`), so
    /// the block does not extend the chain the verifier is on.
    BadPrevBlockHash,
    /// Corrupt the block's genesis hash (`"gh"`), a header field every node
    /// checks unconditionally.
    BadGenesisHash,
    /// Corrupt the VRF seed proof (`"sdpf"`), so `agreement.verifyProposer`'s
    /// seed check fails ("seed proof malformed" / seed mismatch).
    BadSeedProof,
    /// Make the header's `Proposer` disagree with `OriginalProposer`, which
    /// `agreement.verifyProposer` rejects with "wrong proposer".
    ProposerMismatch,
    /// Truncate the payset while leaving the commitment intact, so the
    /// commitment no longer covers the transactions present.
    DropTransaction,
}

impl ProposalFault {
    /// The substring of go-algorand's error text this fault should provoke.
    pub fn expected_go_error(self) -> &'static str {
        match self {
            Self::None => "",
            Self::BadPaysetCommitment | Self::DropTransaction => "transaction commitment",
            Self::BadPrevBlockHash => "block branch",
            Self::BadGenesisHash => "genesis hash",
            Self::BadSeedProof => "seed",
            Self::ProposerMismatch => "wrong proposer",
        }
    }

    /// Short stable identifier used in CLI arguments and report JSON.
    pub fn case_name(self) -> &'static str {
        match self {
            Self::None => "baseline",
            Self::BadPaysetCommitment => "bad-payset-commitment",
            Self::BadPrevBlockHash => "bad-prev-block-hash",
            Self::BadGenesisHash => "bad-genesis-hash",
            Self::BadSeedProof => "bad-seed-proof",
            Self::ProposerMismatch => "proposer-mismatch",
            Self::DropTransaction => "drop-transaction",
        }
    }
}

/// Apply exactly one structural fault to a proposal payload.
///
/// The input is expected to be a genuine payload (assembled locally or captured
/// off the wire); the output differs from it in exactly one field.
pub fn corrupt_proposal(
    proposal: &UnauthenticatedProposal,
    fault: ProposalFault,
) -> Result<UnauthenticatedProposal, FuzzError> {
    let mut p = proposal.clone();
    match fault {
        ProposalFault::None => {}
        ProposalFault::BadPaysetCommitment => p.block.txn_commitment[0] ^= 0x01,
        ProposalFault::BadPrevBlockHash => p.block.branch[0] ^= 0x01,
        ProposalFault::BadGenesisHash => p.block.genesis_hash[0] ^= 0x01,
        ProposalFault::BadSeedProof => p.seed_proof[0] ^= 0x01,
        ProposalFault::ProposerMismatch => {
            // Flip a byte of the header's Proposer so it disagrees with
            // OriginalProposer, which is what `verifyProposer` compares.
            let mut proposer = p.block.proposer;
            proposer.0[0] ^= 0x01;
            p.block.proposer = proposer;
        }
        ProposalFault::DropTransaction => {
            if p.block.payset.is_empty() {
                return Err(FuzzError::PreconditionViolated(
                    "cannot drop a transaction from an empty payset; \
                     inject traffic into the cluster first"
                        .into(),
                ));
            }
            p.block.payset.pop();
        }
    }
    Ok(p)
}

/// Wrap a proposal payload with the prior proposal-vote, forming Go's
/// `transmittedPayload` (the `PP` message body).
pub fn build_compound_message(
    proposal: UnauthenticatedProposal,
    prior_vote: UnauthenticatedVote,
) -> CompoundMessage {
    CompoundMessage {
        vote: prior_vote,
        proposal,
    }
}

/// Encode a proposal payload for the `PP` tag using the production encoder.
pub fn encode_compound_message(cm: &CompoundMessage) -> Vec<u8> {
    codec::encode_compound_message(cm)
}

// ---------------------------------------------------------------------------
// Small helpers shared with the binary
// ---------------------------------------------------------------------------

/// A non-bottom proposal value that no honest node will ever have voted for,
/// derived deterministically from `(sender, round, period)`.
///
/// Injected votes must not be *valid*, so this only matters as a placeholder;
/// deriving it deterministically keeps a test run reproducible.
pub fn synthetic_proposal_value(sender: Address, round: Round, period: Period) -> ProposalValue {
    use algo_types::Digest;
    let tag = |salt: u8| {
        let mut d = [0u8; 32];
        d[0] = salt;
        d[1..9].copy_from_slice(&round.0.to_be_bytes());
        d[9..17].copy_from_slice(&period.0.to_be_bytes());
        d[17..25].copy_from_slice(&sender.0[..8]);
        Digest(d)
    };
    ProposalValue {
        original_period: period,
        original_proposer: sender,
        block_digest: tag(0xd1),
        encoding_digest: tag(0xd2),
    }
}

/// `BOTTOM`, re-exported so callers building recovery-step votes do not need to
/// depend on `algo-agreement` directly.
pub fn bottom() -> ProposalValue {
    BOTTOM
}

/// The sortition weight `sortition.Select` yields for explicit inputs.
///
/// Exposed so a caller can reason about committee sizes without building a
/// whole vote.
pub fn select_weight(money: u64, total: u64, expected: f64, vrf_out: [u8; 32]) -> u64 {
    sortition::select(money, total, expected, vrf_out)
}

/// The one-time-signature batch/offset a vote for `round` uses.
pub fn ots_id(round: Round, key_dilution: u64) -> (u64, u64) {
    let id = one_time_id_for_round(round.0, key_dilution);
    (id.batch, id.offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_agreement::{CERT, DOWN, SOFT};
    use algo_consensus_crypto::onetimesig::OneTimeSignature;

    /// `UnauthenticatedVote` and `OneTimeSignature` mirror Go's structs, which
    /// have no equality operator either; compare through the wire encoding —
    /// which is what actually has to match — and field-wise for signatures.
    fn same_vote(a: &UnauthenticatedVote, b: &UnauthenticatedVote) -> bool {
        encode_vote(a) == encode_vote(b)
    }

    fn same_sig(a: &OneTimeSignature, b: &OneTimeSignature) -> bool {
        a.sig == b.sig
            && a.pk == b.pk
            && a.pk_sig_old == b.pk_sig_old
            && a.pk2 == b.pk2
            && a.pk1_sig == b.pk1_sig
            && a.pk2_sig == b.pk2_sig
    }
    use algo_types::consensus::consensus_params_for_version;
    use algo_types::{Block, Digest, CONSENSUS_V41};

    const KEY_DILUTION: u64 = 10_000;

    fn params() -> ConsensusParams {
        consensus_params_for_version(CONSENSUS_V41).expect("v41 params")
    }

    fn secrets(seed: u8) -> ParticipationSecrets {
        ParticipationSecrets {
            vrf: VrfKeypair::from_seed([seed; 32]),
            // A single batch starting at 0 covers rounds < KEY_DILUTION.
            ots: OneTimeSignatureSecrets::generate(0, 2),
        }
    }

    fn ctx(step: Step, proposal: ProposalValue) -> VoteContext {
        VoteContext {
            sender: Address([0x42; 32]),
            round: Round(100),
            period: Period(0),
            step,
            proposal,
            seed: Seed([0x11; 32]),
            balance: 10,
            total_money: 100,
            key_dilution: KEY_DILUTION,
            vote_first_valid: Round(0),
            vote_last_valid: Round(30_000),
            params: params(),
        }
    }

    fn value() -> ProposalValue {
        synthetic_proposal_value(Address([0x42; 32]), Round(100), Period(0))
    }

    // ── Baseline parity ────────────────────────────────────────────────

    /// The whole harness rests on this: with no fault injected, the message
    /// verifies under the very checks go-algorand runs. If this ever fails,
    /// every negative result below is unattributable.
    #[test]
    fn baseline_vote_verifies() {
        let s = secrets(1);
        let c = ctx(SOFT, value());
        let v = build_vote(&c, &s, VoteFault::None).unwrap();
        let verified = v
            .verify(&c.verify_params(&s))
            .expect("honest baseline must verify");
        assert!(verified.cred.weight > 0);
        assert_eq!(verified.raw_vote, c.raw_vote());
    }

    #[test]
    fn baseline_vote_signs_the_vote_domain() {
        let s = secrets(1);
        let c = ctx(SOFT, value());
        let v = build_vote(&c, &s, VoteFault::None).unwrap();

        let (batch, offset) = ots_id(c.round, c.key_dilution);
        let correct = [VOTE_DOMAIN, c.raw_vote().to_be_hashed().as_slice()].concat();
        assert!(
            algo_consensus_crypto::onetimesig::verify_one_time_signature(
                &v.sig,
                &s.ots.verifier(),
                batch,
                offset,
                &correct
            )
        );
        // ...and specifically *not* the undomained body.
        let undomained = c.raw_vote().to_be_hashed();
        assert!(
            !algo_consensus_crypto::onetimesig::verify_one_time_signature(
                &v.sig,
                &s.ots.verifier(),
                batch,
                offset,
                &undomained
            )
        );
    }

    #[test]
    fn baseline_credential_matches_go_make_credential() {
        // MakeCredential proves over HashRep(selector) — "AS" || msgpack(selector).
        let s = secrets(3);
        let c = ctx(SOFT, value());
        let v = build_vote(&c, &s, VoteFault::None).unwrap();
        let alpha = hash_rep(&c.selector());
        let expected = s.vrf.sk.prove(&alpha).0 .0;
        assert_eq!(v.cred.proof, expected);
        assert_eq!(&alpha[..2], b"AS");
    }

    #[test]
    fn baseline_encoding_is_the_production_encoding() {
        let s = secrets(1);
        let c = ctx(SOFT, value());
        let v = build_vote(&c, &s, VoteFault::None).unwrap();
        let bytes = encode_vote(&v);
        let round_tripped = codec::decode_vote(&bytes).expect("must decode");
        assert!(same_vote(&round_tripped, &v));
    }

    // ── Case 1: bad VRF proof ──────────────────────────────────────────

    #[test]
    fn case1_bad_vrf_proof_differs_only_in_the_credential() {
        for corruption in [
            VrfCorruption::FlipGamma,
            VrfCorruption::FlipChallenge,
            VrfCorruption::FlipResponse,
            VrfCorruption::ForeignKey([0x9e; 32]),
        ] {
            let s = secrets(1);
            let c = ctx(SOFT, value());
            let (good, bad) =
                baseline_and_faulted(&c, &s, VoteFault::BadVrfProof(corruption)).unwrap();

            assert_eq!(
                good.raw_vote, bad.raw_vote,
                "{corruption:?}: body must match"
            );
            assert!(
                same_sig(&good.sig, &bad.sig),
                "{corruption:?}: signature must match"
            );
            assert_ne!(
                good.cred, bad.cred,
                "{corruption:?}: credential must differ"
            );
            assert_eq!(
                bad.cred.proof.len(),
                80,
                "{corruption:?}: proof must stay 80 bytes so Go decodes it"
            );
        }
    }

    #[test]
    fn case1_bad_vrf_proof_is_rejected_by_credential_verification() {
        for corruption in [
            VrfCorruption::FlipGamma,
            VrfCorruption::FlipChallenge,
            VrfCorruption::FlipResponse,
            VrfCorruption::ForeignKey([0x9e; 32]),
        ] {
            let s = secrets(1);
            let c = ctx(SOFT, value());
            let bad = build_vote(&c, &s, VoteFault::BadVrfProof(corruption)).unwrap();
            let err = bad.verify(&c.verify_params(&s)).unwrap_err();
            let text = err.to_string();
            assert!(
                text.contains("credential"),
                "{corruption:?}: expected a credential failure, got {text}"
            );
        }
    }

    #[test]
    fn case1_foreign_key_proof_is_valid_under_its_own_key() {
        // Proves the ForeignKey variant really is a well-formed proof and only
        // fails because it is bound to the wrong public key.
        let s = secrets(1);
        let c = ctx(SOFT, value());
        let bad = build_vote(
            &c,
            &s,
            VoteFault::BadVrfProof(VrfCorruption::ForeignKey([0x9e; 32])),
        )
        .unwrap();

        let other = VrfKeypair::from_seed([0x9e; 32]);
        let alpha = hash_rep(&c.selector());
        assert!(
            other
                .pk
                .verify(
                    &algo_consensus_crypto::vrf::VrfProof(bad.cred.proof),
                    &alpha
                )
                .is_some(),
            "foreign proof must verify under the foreign key"
        );
        assert!(
            s.vrf
                .pk
                .verify(
                    &algo_consensus_crypto::vrf::VrfProof(bad.cred.proof),
                    &alpha
                )
                .is_none(),
            "foreign proof must NOT verify under the registered key"
        );
    }

    // ── Case 2: wrong committee weight ─────────────────────────────────

    #[test]
    fn case2_refuses_to_build_when_the_account_is_actually_selected() {
        let s = secrets(1);
        let c = ctx(SOFT, value());
        assert!(committee_weight(&c, &s) > 0, "soft committee is large");
        let err = build_vote(&c, &s, VoteFault::ZeroWeightCredential).unwrap_err();
        assert!(matches!(err, FuzzError::PreconditionViolated(_)));
    }

    #[test]
    fn case2_zero_weight_vote_is_rejected_for_weight_not_for_crypto() {
        // Zero stake ⇒ sortition weight 0 for any selector, which is the
        // reachable form of "committee weight inconsistent with real stake".
        let s = secrets(1);
        let mut c = ctx(SOFT, value());
        c.balance = 0;

        assert_eq!(committee_weight(&c, &s), 0);
        // The credential itself is honest: byte-identical to the no-fault build.
        let (honest, v) = baseline_and_faulted(&c, &s, VoteFault::ZeroWeightCredential).unwrap();
        assert!(
            same_vote(&v, &honest),
            "case 2 injects no wire-level mutation"
        );

        // The VRF proof verifies; only the weight is zero.
        let alpha = hash_rep(&c.selector());
        assert!(s
            .vrf
            .pk
            .verify(&algo_consensus_crypto::vrf::VrfProof(v.cred.proof), &alpha)
            .is_some());

        let err = v
            .cred
            .verify(&c.params, &c.membership(*s.vrf.pk.as_bytes()));
        assert_eq!(err, Err(algo_agreement::CredentialError::ZeroWeight));
    }

    #[test]
    fn case2_find_zero_weight_round_locates_an_unselected_round() {
        // The proposer committee is small (NumProposers), so an account with a
        // minority stake misses it regularly — search over rounds the way the
        // live harness does.
        let s = secrets(7);
        let sender = Address([0x42; 32]);
        let mut c = ctx(PROPOSE, ProposalValue::default());
        c.balance = 10;
        c.total_money = 100;

        let found = find_zero_weight_round(&c, &s, (100..400).map(Round), |r| {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&r.0.to_be_bytes());
            Some(Seed(seed))
        });
        let (round, seed) = found.expect("a minority stake must miss the proposer committee");

        let mut zero = c.clone();
        zero.round = round;
        zero.seed = seed;
        zero.proposal = synthetic_proposal_value(sender, round, Period(0));
        assert_eq!(committee_weight(&zero, &s), 0);
        // ...and the vote builds, because the precondition now holds.
        build_vote(&zero, &s, VoteFault::ZeroWeightCredential).unwrap();
    }

    #[test]
    fn case2_weight_matches_direct_sortition_select() {
        // Cross-check `committee_weight` against `sortition::Select` driven by
        // the same hashed credential, i.e. Go's formula.
        let s = secrets(5);
        let c = ctx(SOFT, value());
        let v = build_vote(&c, &s, VoteFault::None).unwrap();
        let cred = v
            .cred
            .verify(&c.params, &c.membership(*s.vrf.pk.as_bytes()))
            .unwrap();
        let expected = select_weight(
            c.balance,
            c.total_money,
            c.step.committee_size(&c.params) as f64,
            cred.vrf_out.0,
        );
        assert_eq!(cred.weight, expected);
        assert_eq!(committee_weight(&c, &s), expected);
    }

    // ── Case 3: wrong OTS domain separation ────────────────────────────

    #[test]
    fn case3_wrong_domain_differs_only_in_the_signature() {
        for domain in [
            OtsDomain::Absent,
            OtsDomain::Payload,
            OtsDomain::Selector,
            OtsDomain::Credential,
            OtsDomain::OneTimeSigKey1,
        ] {
            let s = secrets(1);
            let c = ctx(SOFT, value());
            let (good, bad) =
                baseline_and_faulted(&c, &s, VoteFault::WrongOtsDomain(domain)).unwrap();

            assert_eq!(good.raw_vote, bad.raw_vote, "{domain:?}: body must match");
            assert_eq!(good.cred, bad.cred, "{domain:?}: credential must match");
            assert!(
                !same_sig(&good.sig, &bad.sig),
                "{domain:?}: signature must differ"
            );

            // The key *tree* is untouched: the same master key authenticated
            // the same batch subkey. (`pk`/`p1s` necessarily differ — Go's
            // `OneTimeSignatureSecrets.Sign` mints a fresh ephemeral offset
            // subkey for every signature, so a re-signature is never
            // byte-identical even under the correct domain.)
            assert_eq!(good.sig.pk2, bad.sig.pk2, "{domain:?}: same batch subkey");
            assert_eq!(
                good.sig.pk2_sig, bad.sig.pk2_sig,
                "{domain:?}: same master authentication of that batch"
            );
        }
    }

    #[test]
    fn case3_wrong_domain_fails_signature_verification() {
        for domain in [
            OtsDomain::Absent,
            OtsDomain::Payload,
            OtsDomain::Selector,
            OtsDomain::Credential,
            OtsDomain::OneTimeSigKey1,
        ] {
            let s = secrets(1);
            let c = ctx(SOFT, value());
            let bad = build_vote(&c, &s, VoteFault::WrongOtsDomain(domain)).unwrap();
            let err = bad.verify(&c.verify_params(&s)).unwrap_err();
            assert_eq!(
                err,
                algo_agreement::VoteError::OtsVerificationFailed,
                "{domain:?}: expected an OTS failure"
            );
        }
    }

    #[test]
    fn case3_wrong_domain_signature_is_valid_under_the_wrong_domain() {
        // The signature is genuine — the *only* defect is the context. This is
        // what makes it a domain-separation test rather than a forgery test.
        for domain in [
            OtsDomain::Payload,
            OtsDomain::Selector,
            OtsDomain::Credential,
        ] {
            let s = secrets(1);
            let c = ctx(SOFT, value());
            let bad = build_vote(&c, &s, VoteFault::WrongOtsDomain(domain)).unwrap();
            let (batch, offset) = ots_id(c.round, c.key_dilution);
            let wrong_msg = [domain.prefix(), c.raw_vote().to_be_hashed().as_slice()].concat();
            assert!(
                algo_consensus_crypto::onetimesig::verify_one_time_signature(
                    &bad.sig,
                    &s.ots.verifier(),
                    batch,
                    offset,
                    &wrong_msg
                ),
                "{domain:?}: signature must be genuine under its own domain"
            );
        }
    }

    #[test]
    fn case3_vote_domain_is_a_no_op() {
        // Naming the *correct* domain must leave a message that still verifies
        // — this is the control that proves the other domains fail because of
        // the domain and not because re-signing is inherently broken.
        let s = secrets(1);
        let c = ctx(SOFT, value());
        let b = build_vote(&c, &s, VoteFault::WrongOtsDomain(OtsDomain::Vote)).unwrap();
        b.verify(&c.verify_params(&s))
            .expect("the Vote domain is the honest one");
        assert_eq!(OtsDomain::Vote.prefix(), VOTE_DOMAIN);
    }

    #[test]
    fn one_time_signatures_are_non_deterministic_by_design() {
        // Documents why `baseline_and_faulted` shares a single honest build:
        // Go mints a fresh ephemeral offset subkey per signature, so two honest
        // signings of the same body are never byte-identical. Both still
        // verify, so full parity is preserved where it matters.
        let s = secrets(1);
        let c = ctx(SOFT, value());
        let a = build_vote(&c, &s, VoteFault::None).unwrap();
        let b = build_vote(&c, &s, VoteFault::None).unwrap();
        assert_eq!(a.raw_vote, b.raw_vote);
        assert_eq!(a.cred, b.cred, "the VRF credential IS deterministic");
        assert!(
            !same_sig(&a.sig, &b.sig),
            "the OTS subkey is fresh each time"
        );
        assert_eq!(a.sig.pk2, b.sig.pk2, "but the batch subkey is stable");
        a.verify(&c.verify_params(&s)).unwrap();
        b.verify(&c.verify_params(&s)).unwrap();
    }

    // ── Structural preconditions ───────────────────────────────────────

    #[test]
    fn refuses_bottom_for_steps_up_to_cert() {
        let s = secrets(1);
        for step in [PROPOSE, SOFT, CERT] {
            let c = ctx(step, bottom());
            let err = build_vote(&c, &s, VoteFault::None).unwrap_err();
            assert!(
                matches!(err, FuzzError::PreconditionViolated(_)),
                "step {step} must refuse bottom"
            );
        }
    }

    #[test]
    fn allows_bottom_for_recovery_steps() {
        let s = secrets(1);
        let c = ctx(DOWN, bottom());
        let v = build_vote(&c, &s, VoteFault::None).unwrap();
        assert!(v.raw_vote.proposal.is_bottom());
        v.verify(&c.verify_params(&s))
            .expect("a down-step bottom vote is legal");
    }

    #[test]
    fn refuses_propose_vote_whose_sender_is_not_the_original_proposer() {
        let s = secrets(1);
        let mut c = ctx(PROPOSE, value());
        c.proposal.original_proposer = Address([0x77; 32]);
        let err = build_vote(&c, &s, VoteFault::None).unwrap_err();
        assert!(matches!(err, FuzzError::PreconditionViolated(_)));
    }

    #[test]
    fn expected_go_errors_are_distinct_per_case() {
        let all = [
            VoteFault::BadVrfProof(VrfCorruption::FlipGamma).expected_go_error(),
            VoteFault::ZeroWeightCredential.expected_go_error(),
            VoteFault::WrongOtsDomain(OtsDomain::Payload).expected_go_error(),
        ];
        for (i, a) in all.iter().enumerate() {
            assert!(!a.is_empty());
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b, "each case must be attributable by its own error text");
            }
        }
    }

    #[test]
    fn case_names_are_stable_and_distinct() {
        let names = [
            VoteFault::None.case_name(),
            VoteFault::BadVrfProof(VrfCorruption::FlipGamma).case_name(),
            VoteFault::ZeroWeightCredential.case_name(),
            VoteFault::WrongOtsDomain(OtsDomain::Payload).case_name(),
        ];
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
    }

    // ── Case 4: malformed proposal ─────────────────────────────────────

    fn sample_proposal() -> UnauthenticatedProposal {
        let mut block = Block {
            round: Round(101),
            branch: [0x21; 32],
            seed: [0x22; 32],
            txn_commitment: [0x23; 32],
            genesis_hash: [0x24; 32],
            proposer: Address([0x42; 32]),
            ..Default::default()
        };
        block.genesis_id = "phase6net-v1".into();
        block.current_protocol = CONSENSUS_V41.to_string();
        UnauthenticatedProposal {
            block,
            seed_proof: [0x55; 80],
            original_period: Period(0),
            original_proposer: Address([0x42; 32]),
        }
    }

    /// Asserts what stayed the same and what moved, given (honest, faulted).
    type FieldCheck = fn(&UnauthenticatedProposal, &UnauthenticatedProposal);

    /// Every corruption must move exactly one field and nothing else.
    #[test]
    fn case4_each_fault_moves_exactly_one_field() {
        let base = sample_proposal();

        let checks: Vec<(ProposalFault, FieldCheck)> = vec![
            (ProposalFault::BadPaysetCommitment, |a, b| {
                assert_ne!(a.block.txn_commitment, b.block.txn_commitment);
                assert_eq!(a.block.branch, b.block.branch);
                assert_eq!(a.block.genesis_hash, b.block.genesis_hash);
                assert_eq!(a.seed_proof, b.seed_proof);
                assert_eq!(a.block.proposer, b.block.proposer);
            }),
            (ProposalFault::BadPrevBlockHash, |a, b| {
                assert_ne!(a.block.branch, b.block.branch);
                assert_eq!(a.block.txn_commitment, b.block.txn_commitment);
                assert_eq!(a.seed_proof, b.seed_proof);
            }),
            (ProposalFault::BadGenesisHash, |a, b| {
                assert_ne!(a.block.genesis_hash, b.block.genesis_hash);
                assert_eq!(a.block.branch, b.block.branch);
            }),
            (ProposalFault::BadSeedProof, |a, b| {
                assert_ne!(a.seed_proof, b.seed_proof);
                assert_eq!(a.block.seed, b.block.seed);
                assert_eq!(a.block.branch, b.block.branch);
            }),
            (ProposalFault::ProposerMismatch, |a, b| {
                assert_ne!(a.block.proposer, b.block.proposer);
                assert_eq!(a.original_proposer, b.original_proposer);
                assert_ne!(
                    b.block.proposer, b.original_proposer,
                    "the point of the fault is that these now disagree"
                );
            }),
        ];

        for (fault, check) in checks {
            let bad = corrupt_proposal(&base, fault).unwrap();
            check(&base, &bad);
            assert_ne!(
                base.value().encoding_digest,
                bad.value().encoding_digest,
                "{fault:?}: the payload digest must change"
            );
            assert_eq!(base.round(), bad.round(), "{fault:?}: round is untouched");
        }
    }

    #[test]
    fn case4_none_is_the_identity() {
        let base = sample_proposal();
        let same = corrupt_proposal(&base, ProposalFault::None).unwrap();
        // Reuse one vote: signatures are non-deterministic (see
        // `one_time_signatures_are_non_deterministic_by_design`), so the
        // payload half is what this asserts.
        let vote = sample_vote();
        assert_eq!(
            encode_compound_message(&build_compound_message(base, vote.clone())),
            encode_compound_message(&build_compound_message(same, vote))
        );
    }

    fn sample_vote() -> UnauthenticatedVote {
        let s = secrets(1);
        let c = ctx(SOFT, value());
        build_vote(&c, &s, VoteFault::None).unwrap()
    }

    #[test]
    fn case4_block_digest_changes_for_header_faults_but_not_for_seed_proof() {
        let base = sample_proposal();

        // Header faults change the *block* digest too.
        for fault in [
            ProposalFault::BadPaysetCommitment,
            ProposalFault::BadPrevBlockHash,
            ProposalFault::BadGenesisHash,
            ProposalFault::ProposerMismatch,
        ] {
            let bad = corrupt_proposal(&base, fault).unwrap();
            assert_ne!(
                base.block_digest(),
                bad.block_digest(),
                "{fault:?}: must change the block digest"
            );
        }

        // The seed proof lives outside the block, so only the payload
        // encoding digest moves — which is precisely why it isolates
        // `verifyProposer`'s seed check from block validation.
        let bad = corrupt_proposal(&base, ProposalFault::BadSeedProof).unwrap();
        assert_eq!(base.block_digest(), bad.block_digest());
        assert_ne!(base.value().encoding_digest, bad.value().encoding_digest);
    }

    #[test]
    fn case4_drop_transaction_requires_a_non_empty_payset() {
        let base = sample_proposal();
        assert!(base.block.payset.is_empty());
        let err = corrupt_proposal(&base, ProposalFault::DropTransaction).unwrap_err();
        assert!(matches!(err, FuzzError::PreconditionViolated(_)));
    }

    #[test]
    fn case4_compound_message_round_trips_through_the_production_codec() {
        let base = sample_proposal();
        let bad = corrupt_proposal(&base, ProposalFault::BadPaysetCommitment).unwrap();
        let cm = build_compound_message(bad, sample_vote());
        let bytes = encode_compound_message(&cm);
        let decoded = codec::decode_compound_message(&bytes).expect("must decode");
        assert_eq!(
            decoded.proposal.block.txn_commitment,
            cm.proposal.block.txn_commitment
        );
        assert_eq!(decoded.vote.raw_vote, cm.vote.raw_vote);
    }

    #[test]
    fn case4_expected_go_errors_and_names_are_populated() {
        for fault in [
            ProposalFault::BadPaysetCommitment,
            ProposalFault::BadPrevBlockHash,
            ProposalFault::BadGenesisHash,
            ProposalFault::BadSeedProof,
            ProposalFault::ProposerMismatch,
            ProposalFault::DropTransaction,
        ] {
            assert!(!fault.expected_go_error().is_empty(), "{fault:?}");
            assert_ne!(fault.case_name(), "baseline", "{fault:?}");
        }
    }

    // ── Misc helpers ───────────────────────────────────────────────────

    #[test]
    fn synthetic_proposal_values_are_never_bottom_and_are_deterministic() {
        let a = synthetic_proposal_value(Address([1; 32]), Round(5), Period(0));
        let b = synthetic_proposal_value(Address([1; 32]), Round(5), Period(0));
        let c = synthetic_proposal_value(Address([1; 32]), Round(6), Period(0));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(!a.is_bottom());
    }

    #[test]
    fn ots_id_matches_round_division() {
        assert_eq!(ots_id(Round(10_005), 10_000), (1, 5));
        assert_eq!(ots_id(Round(0), 10_000), (0, 0));
    }

    #[test]
    fn digest_helper_is_used_by_synthetic_values() {
        let v = synthetic_proposal_value(Address([9; 32]), Round(1), Period(2));
        assert_ne!(v.block_digest, Digest([0; 32]));
        assert_ne!(v.encoding_digest, v.block_digest);
    }
}
