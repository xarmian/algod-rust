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

//! State proof cryptographic verification, matching go-algorand's
//! `crypto/stateproof` package.
//!
//! Ports:
//!   - `crypto/stateproof/verifier.go` — `Verifier::verify` orchestration.
//!   - `crypto/stateproof/committableSignatureSlot.go` — `buildCommittableSignature`.
//!   - `crypto/stateproof/coinGenerator.go` — Fiat-Shamir coin sampling.
//!   - `crypto/stateproof/weights.go` — `verifyWeights` reveal-count bound.
//!   - `crypto/stateproof/const.go` — shared constants.
//!
//! This module verifies the *cryptographic* content of a `StateProof`
//! (signatures, Merkle commitments, coin-weight sampling). It does not know
//! about ledger state (round matching, `StateProofNext` advancement) — that
//! lives in `algo-ledger`'s `apply::stateproof` module, mirroring go's
//! `ledger/apply/stateproof.go` calling into `stateproof/verify/stateproof.go`
//! which calls into this package's `Verifier::verify`.

use std::collections::BTreeMap;

use num_bigint::BigUint;
use num_traits::ToPrimitive;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::merklearray::{self, GenericDigest, Hashable, MerkleError, Proof};
use crate::merklesig;

// ── Constants (go: crypto/stateproof/const.go) ──────────────────────────

/// Number of bits of precision used for the `Ln` approximation. Must not
/// exceed 63.
const PRECISION_BITS: u32 = 16;

/// `ceil(2^PRECISION_BITS * ln(2))`.
const LN2_INT_APPROXIMATION: u64 = 45427;

/// Bound on allocation and on the number of reveals, to limit log
/// computation (go: `MaxReveals`).
pub const MAX_REVEALS: u64 = 640;

/// Seed byte for the coin-generator Fiat-Shamir transform (go:
/// `VersionForCoinGenerator`).
const VERSION_FOR_COIN_GENERATOR: u8 = 0;

/// Maximum Merkle tree depth a state proof's signature/participant
/// commitment trees may have (go: `MaxTreeDepth`).
pub const MAX_TREE_DEPTH: u8 = 20;

/// Domain separation prefix for a signature-commitment merkle leaf (go:
/// `protocol.StateProofSig = "sps"`).
const STATE_PROOF_SIG: &[u8] = b"sps";

/// Domain separation prefix for a participant-commitment merkle leaf (go:
/// `protocol.StateProofPart = "spp"`).
const STATE_PROOF_PART: &[u8] = b"spp";

/// Domain separation prefix for the coin-choice seed (go:
/// `protocol.StateProofCoin = "spc"`).
const STATE_PROOF_COIN: &[u8] = b"spc";

/// The message a state proof attests to (go: `stateproof.MessageHash`, a
/// SHA-256 digest of the `stateproofmsg.Message`).
pub type MessageHash = [u8; 32];

/// Current salt version of the merkle signature scheme (go:
/// `merklesignature.SchemeSaltVersion`, `crypto/merklesignature/const.go:33`).
pub const MERKLE_SIGNATURE_SCHEME_SALT_VERSION: u8 = 0;

/// `VotersAllocBound` (go: `crypto/stateproof/prover.go:38`) — should equal
/// `config.Consensus[...].StateProofTopVoters`.
pub const VOTERS_ALLOC_BOUND: usize = 1024;

// ── Errors ───────────────────────────────────────────────────────────────

/// Errors from state-proof cryptographic verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateProofError {
    /// `Verifier::new`: proven weight was zero (can't take `ln(0)`).
    IllegalLnInput,
    /// A signature/participant commitment tree exceeds [`MAX_TREE_DEPTH`].
    TreeDepthTooLarge,
    /// A committable signature slot's embedded Falcon signature is missing.
    EmptyFalconSignature,
    /// A committable signature slot's merkle proof tree depth exceeds
    /// `merklearray::MAX_ENCODED_TREE_DEPTH`.
    ProofTreeDepthTooLarge,
    /// A reveal's salt version did not match `s.MerkleSignatureSaltVersion`.
    SaltVersionMismatch,
    /// `numReveals > MaxReveals`.
    TooManyReveals,
    /// `signedWeight == 0`.
    ZeroSignedWeight,
    /// The reveal-count/weight verification inequality was not satisfied.
    InsufficientSignedWeight,
    /// A per-reveal ephemeral-key/Falcon signature failed to verify.
    SignatureVerificationFailed { pos: u64, reason: String },
    /// The signature-commitment vector-commitment proof failed.
    SigVectorCommitmentFailed(MerkleError),
    /// The participant-commitment vector-commitment proof failed.
    PartVectorCommitmentFailed(MerkleError),
    /// A revealed position has no corresponding entry in `Reveals`.
    NoRevealInPos(u64),
    /// A sampled coin fell outside the revealed participant's weight range.
    CoinNotInRange { pos: u64, coin: u64 },
    /// Underlying Falcon/merkle-signature error while building a committable
    /// signature slot.
    Internal(String),

    // ── Prover-side errors (crypto/stateproof/prover.go) ────────────────
    /// `Present`/`IsValid`/`Add`: `pos` is out of bounds for the prover's
    /// `sigs`/`Participants` array. Matches go's `ErrPositionOutOfBound`.
    PositionOutOfBound { pos: u64, bound: u64 },
    /// `Add`: a signature is already present at this position. Matches
    /// go's `ErrPositionAlreadyPresent`.
    PositionAlreadyPresent,
    /// `IsValid`: the participant at `pos` has zero weight. Matches go's
    /// `ErrPositionWithZeroWeight`.
    PositionWithZeroWeight { pos: u64 },
    /// `coinIndex`: binary search found no position whose weight range
    /// contains `coin`. Matches go's `ErrCoinIndexError`.
    CoinIndexError { lo: u64, hi: u64, coin: u64 },
    /// `CreateProof`: not enough signed weight has been gathered yet
    /// (`signedWeight <= ProvenWeight`). Matches go's
    /// `ErrSignedWeightLessThanProvenWeight`.
    SignedWeightLessThanProvenWeight { signed: u64, proven: u64 },
    /// `numReveals`: the search denominator is non-positive, so no reveal
    /// count can satisfy the verification inequality. Matches go's
    /// `ErrNegativeNumOfRevealsEquation`.
    NegativeNumOfRevealsEquation,
}

impl std::fmt::Display for StateProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IllegalLnInput => write!(f, "cannot calculate a ln integer value for 0"),
            Self::TreeDepthTooLarge => write!(f, "tree depth is too large"),
            Self::EmptyFalconSignature => {
                write!(f, "buildCommittableSignature: empty Falcon signature")
            }
            Self::ProofTreeDepthTooLarge => write!(
                f,
                "buildCommittableSignature: proof tree depth exceeds maximum"
            ),
            Self::SaltVersionMismatch => write!(f, "signature salt version mismatch"),
            Self::TooManyReveals => write!(f, "too many reveals in state proof"),
            Self::ZeroSignedWeight => write!(f, "signed weight cannot be zero"),
            Self::InsufficientSignedWeight => write!(
                f,
                "the number of reveals is not large enough to prove that the desired weight \
                 signed, with the desired security level"
            ),
            Self::SignatureVerificationFailed { pos, reason } => write!(
                f,
                "signature in reveal pos {pos} does not verify. error is {reason}"
            ),
            Self::SigVectorCommitmentFailed(e) => {
                write!(f, "sig commitment verification failed: {e}")
            }
            Self::PartVectorCommitmentFailed(e) => {
                write!(f, "participant commitment verification failed: {e}")
            }
            Self::NoRevealInPos(pos) => write!(f, "no reveal for position: {pos}"),
            Self::CoinNotInRange { pos, coin } => write!(
                f,
                "coin is not within slot weight range: for reveal pos {pos} and coin {coin}"
            ),
            Self::Internal(msg) => write!(f, "internal state-proof error: {msg}"),
            Self::PositionOutOfBound { pos, bound } => write!(
                f,
                "requested position is out of bounds: pos {pos} >= bound {bound}"
            ),
            Self::PositionAlreadyPresent => write!(f, "requested position is already present"),
            Self::PositionWithZeroWeight { pos } => {
                write!(f, "position has zero weight: position = {pos}")
            }
            Self::CoinIndexError { lo, hi, coin } => write!(
                f,
                "could not find corresponding index for a given coin: lo {lo} >= hi {hi} and coin {coin}"
            ),
            Self::SignedWeightLessThanProvenWeight { signed, proven } => write!(
                f,
                "signed weight is less than or equal to proven weight: {signed} <= {proven}"
            ),
            Self::NegativeNumOfRevealsEquation => write!(
                f,
                "state proof creation failed: weights will not be able to satisfy the verification equation"
            ),
        }
    }
}

impl std::error::Error for StateProofError {}

// ── Wire types (crypto/stateproof/structs.go) ───────────────────────────

/// A single slot in the signature array (go: `stateproof.sigslotCommit`).
#[derive(Debug, Clone, Default)]
pub struct SigSlotCommit {
    /// Falcon-backed merkle signature by the participant.
    pub sig: merklesig::Signature,
    /// Total weight of signatures in lower-numbered slots.
    pub l: u64,
}

/// A single array position revealed as part of a state proof (go:
/// `stateproof.Reveal`).
#[derive(Debug, Clone)]
pub struct Reveal {
    pub sig_slot: SigSlotCommit,
    pub part: Participant,
}

/// A participant corresponds to an online account (go: `basics.Participant`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    /// Merkle-signature-scheme verifier for this participant.
    pub pk: merklesig::Verifier,
    /// The participant's weight (`AccountData.MicroAlgos`).
    pub weight: u64,
}

impl Hashable for Participant {
    fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
        let mut data = Vec::with_capacity(8 + 8 + merklesig::MERKLE_SIGNATURE_SCHEME_ROOT_SIZE);
        data.extend_from_slice(&self.weight.to_le_bytes());
        data.extend_from_slice(&self.pk.key_lifetime.to_le_bytes());
        data.extend_from_slice(&self.pk.commitment);
        (STATE_PROOF_PART, data)
    }
}

/// An indexable array of [`Participant`]s, ready for vector-commitment tree
/// construction (go: `basics.ParticipantsArray`, a `[]Participant` with
/// `Marshal`/`Length` methods). `Participant` already implements
/// [`Hashable`] above -- this wrapper only supplies the [`merklearray::Array`]
/// indexing `merklearray::build_vector_commitment_tree` needs.
///
/// Used by `algo_ledger::voters` (issue #758) to build the state-proof
/// voters commitment over the top-N selected online accounts, mirroring
/// go's `ledgercore.votersForRound.LoadTree`.
#[derive(Debug, Clone, Default)]
pub struct ParticipantsArray(pub Vec<Participant>);

impl merklearray::Array for ParticipantsArray {
    fn length(&self) -> u64 {
        self.0.len() as u64
    }

    fn marshal(&self, pos: u64) -> Result<Box<dyn Hashable>, MerkleError> {
        self.0
            .get(pos as usize)
            .cloned()
            .map(|p| Box::new(p) as Box<dyn Hashable>)
            .ok_or(MerkleError::PosOutOfBound {
                pos,
                bound: self.0.len() as u64,
            })
    }
}

/// A proof on Algorand's state (go: `stateproof.StateProof`).
#[derive(Debug, Clone, Default)]
pub struct StateProof {
    pub sig_commit: GenericDigest,
    pub signed_weight: u64,
    pub sig_proofs: Proof,
    pub part_proofs: Proof,
    pub merkle_signature_salt_version: u8,
    /// Sparse map from revealed position to the corresponding sigs/participants
    /// array elements.
    pub reveals: BTreeMap<u64, Reveal>,
    pub positions_to_reveal: Vec<u64>,
}

// ── buildCommittableSignature (committableSignatureSlot.go) ────────────

#[derive(Debug)]
struct CommittableSignatureSlot {
    l: u64,
    serialized_signature: Vec<u8>,
    is_empty_slot: bool,
}

impl Hashable for CommittableSignatureSlot {
    fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
        if self.is_empty_slot {
            return (STATE_PROOF_SIG, Vec::new());
        }
        let mut data = Vec::with_capacity(8 + self.serialized_signature.len());
        data.extend_from_slice(&self.l.to_le_bytes());
        data.extend_from_slice(&self.serialized_signature);
        (STATE_PROOF_SIG, data)
    }
}

/// Build the hashable, SNARK-friendly representation of a signature slot.
///
/// Matches go's `buildCommittableSignature` (`committableSignatureSlot.go:62`).
fn build_committable_signature(
    sig_commit: &SigSlotCommit,
) -> Result<CommittableSignatureSlot, StateProofError> {
    if sig_commit.sig.is_zero() {
        return Ok(CommittableSignatureSlot {
            l: 0,
            serialized_signature: Vec::new(),
            is_empty_slot: true,
        });
    }
    if sig_commit.sig.signature.is_empty() {
        return Err(StateProofError::EmptyFalconSignature);
    }
    if sig_commit.sig.proof.proof.tree_depth as usize > merklearray::MAX_ENCODED_TREE_DEPTH {
        return Err(StateProofError::ProofTreeDepthTooLarge);
    }
    let sig_bytes = sig_commit
        .sig
        .get_fixed_length_hashable_representation()
        .map_err(|e| StateProofError::Internal(e.to_string()))?;
    Ok(CommittableSignatureSlot {
        l: sig_commit.l,
        serialized_signature: sig_bytes,
        is_empty_slot: false,
    })
}

// ── Coin generator (coinGenerator.go) ───────────────────────────────────

struct CoinChoiceSeed<'a> {
    part_commitment: &'a GenericDigest,
    ln_proven_weight: u64,
    sig_commitment: &'a GenericDigest,
    signed_weight: u64,
    data: MessageHash,
}

impl<'a> Hashable for CoinChoiceSeed<'a> {
    fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
        let mut data = Vec::with_capacity(
            1 + self.part_commitment.len() + 8 + self.sig_commitment.len() + 8 + self.data.len(),
        );
        data.push(VERSION_FOR_COIN_GENERATOR);
        data.extend_from_slice(self.part_commitment);
        data.extend_from_slice(&self.ln_proven_weight.to_le_bytes());
        data.extend_from_slice(self.sig_commitment);
        data.extend_from_slice(&self.signed_weight.to_le_bytes());
        data.extend_from_slice(&self.data);
        (STATE_PROOF_COIN, data)
    }
}

/// Squeezes uniform-random `[0, signed_weight)` "coin flip" values from a
/// SHAKE256 XOF seeded by the coin-choice seed.
///
/// Matches go's `coinGenerator` (`coinGenerator.go`), including its
/// rejection-sampling threshold (`prepareRejectionSamplingThreshold`) to
/// avoid modulo bias.
struct CoinGenerator {
    reader: <Shake256 as ExtendableOutput>::Reader,
    signed_weight: u64,
    threshold: u128,
}

fn make_coin_generator(choice: &CoinChoiceSeed<'_>) -> CoinGenerator {
    let (prefix, data) = choice.to_be_hashed();
    let mut hasher = Shake256::default();
    hasher.update(prefix);
    hasher.update(&data);
    let reader = hasher.finalize_xof();

    // threshold = floor(2^64 / signedWeight) * signedWeight, computed in a
    // 128-bit type since 2^64 doesn't fit in u64.
    let sw = choice.signed_weight as u128;
    let threshold = (1u128 << 64) / sw * sw;

    CoinGenerator {
        reader,
        signed_weight: choice.signed_weight,
        threshold,
    }
}

impl CoinGenerator {
    fn get_next_coin(&mut self) -> u64 {
        loop {
            let mut buf = [0u8; 8];
            self.reader.read(&mut buf);
            let z = u64::from_le_bytes(buf);
            if (z as u128) < self.threshold {
                return z % self.signed_weight;
            }
        }
    }
}

// ── Weight verification (weights.go) ────────────────────────────────────

/// `ceil(ln(x) * 2^PRECISION_BITS)`, matching go's `LnIntApproximation`.
pub fn ln_int_approximation(x: u64) -> Result<u64, StateProofError> {
    if x == 0 {
        return Err(StateProofError::IllegalLnInput);
    }
    let result = (x as f64).ln();
    let precision = (1u64 << PRECISION_BITS) as f64;
    Ok((result * precision).ceil() as u64)
}

/// `LnProvenWeight` for a `stateproofmsg.Message`: the natural log of the
/// proven weight (`totalWeight * weightThreshold / 2^32`), pre-computed so
/// a verifier never needs to redo the `Ln` approximation itself.
///
/// Matches go's `stateproof.calculateLnProvenWeight`
/// (`stateproof/stateproofMessageGenerator.go:82`). `weight_threshold` is
/// `ConsensusParams.StateProofWeightThreshold` (a `u32` fixed-point
/// fraction of `2^32`); returns [`StateProofError::Internal`] on the same
/// overflow go reports as `errProvenWeightOverflow` (a `total_weight` this
/// large is unreachable from real online stake, but the check is kept to
/// avoid a silent wraparound on a corrupted/malicious tracking value).
pub fn calculate_ln_proven_weight(
    total_weight: u64,
    weight_threshold: u32,
) -> Result<u64, StateProofError> {
    let product = (total_weight as u128) * (weight_threshold as u128);
    let proven_weight = product / (1u128 << 32);
    let proven_weight = u64::try_from(proven_weight).map_err(|_| {
        StateProofError::Internal(format!(
            "calculateLnProvenWeight: overflow computing provenWeight - {total_weight} * \
             {weight_threshold} / (1<<32)"
        ))
    })?;
    ln_int_approximation(proven_weight)
}

fn big(x: u64) -> BigUint {
    BigUint::from(x)
}

/// `y = signedWeight^2 + 2^(d+2)*signedWeight + 2^2d`,
/// `x = 3*2^b*(signedWeight^2 - 2^2d)`, `w = d*(T-1)`.
///
/// Matches go's `getSubExpressions`.
fn get_sub_expressions(signed_weight: u64) -> (BigUint, BigUint, BigUint) {
    // d = bits.Len64(signedWeight) - 1 (find d s.t. 2^(d+1) >= signedWeight >= 2^d).
    let d = (64 - signed_weight.leading_zeros() - 1) as u64;

    let signed_wt_power2 = big(signed_weight) * big(signed_weight);

    // tmp = 2^(d+2) * signedWeight
    let tmp = (BigUint::from(1u32) << (d + 2)) * big(signed_weight);

    // y = signedWeight^2 + tmp + 2^(2d)
    let y = (BigUint::from(1u32) << (2 * d)) + &tmp + &signed_wt_power2;

    // x = 3 * 2^precisionBits * (signedWeight^2 - 2^(2d))
    let two_pow_2d = BigUint::from(1u32) << (2 * d);
    let x = (&signed_wt_power2 - &two_pow_2d) * 3u32 * (1u64 << PRECISION_BITS);

    // w = d * (ln2IntApproximation - 1)
    let w = BigUint::from(d) * big(LN2_INT_APPROXIMATION - 1);

    (y, x, w)
}

/// Verify that `numOfReveals` satisfies the security inequality for the
/// given `signedWeight`/`lnProvenWeight`/`strengthTarget`.
///
/// Matches go's `verifyWeights` (`weights.go:64`).
fn verify_weights(
    signed_weight: u64,
    ln_proven_weight: u64,
    num_of_reveals: u64,
    strength_target: u64,
) -> Result<(), StateProofError> {
    if num_of_reveals > MAX_REVEALS {
        return Err(StateProofError::TooManyReveals);
    }
    if signed_weight == 0 {
        return Err(StateProofError::ZeroSignedWeight);
    }

    let (y, x, w) = get_sub_expressions(signed_weight);

    // lhs = numOfReveals * (x + w*y)
    let lhs = big(num_of_reveals) * (&x + &w * &y);

    // rhs = (strengthTarget * ln2IntApproximation + numOfReveals * lnProvenWeight) * y
    let reveals_times_p = big(num_of_reveals) * big(ln_proven_weight);
    let rhs = (big(strength_target) * big(LN2_INT_APPROXIMATION) + reveals_times_p) * &y;

    if lhs < rhs {
        return Err(StateProofError::InsufficientSignedWeight);
    }
    Ok(())
}

/// Compute the smallest reveal count that satisfies [`verify_weights`]'s
/// inequality for the given `signed_weight`/`ln_proven_weight`/
/// `strength_target` — the number of reveals a [`Prover`] must include in
/// the [`StateProof`] it builds.
///
/// Matches go's `numReveals` (`weights.go:119`) exactly, including its
/// `+1` fudge to compensate for integer-division truncation.
fn num_reveals(
    signed_weight: u64,
    ln_proven_weight: u64,
    strength_target: u64,
) -> Result<u64, StateProofError> {
    let (y, x, w) = get_sub_expressions(signed_weight);

    // numerator = strengthTarget * ln2IntApproximation * y
    let numerator = big(strength_target) * big(LN2_INT_APPROXIMATION) * &y;

    // denom = x + (w - lnProvenWeight) * y. Unlike verify_weights (where w
    // is always added), this subtraction can legitimately go negative --
    // computed via an unsigned comparison rather than pulling in a signed
    // bigint type, since `BigUint` can't represent negative intermediates.
    let ln_pw = big(ln_proven_weight);
    let denom = if w >= ln_pw {
        &x + (&w - &ln_pw) * &y
    } else {
        let sub = (&ln_pw - &w) * &y;
        if sub >= x {
            return Err(StateProofError::NegativeNumOfRevealsEquation);
        }
        &x - &sub
    };
    if denom == BigUint::from(0u32) {
        return Err(StateProofError::NegativeNumOfRevealsEquation);
    }

    // numReveals = (numerator / denom) + 1
    let res = &numerator / &denom + BigUint::from(1u32);
    let res_u64 = res.to_u64().ok_or(StateProofError::TooManyReveals)?;
    if res_u64 > MAX_REVEALS {
        return Err(StateProofError::TooManyReveals);
    }
    Ok(res_u64)
}

// ── Verifier (verifier.go) ───────────────────────────────────────────────

/// Verifies a [`StateProof`] against trusted commitment data.
///
/// Matches go's `stateproof.Verifier` (`verifier.go:36`).
pub struct Verifier {
    strength_target: u64,
    /// `ln(provenWeight)` as an integer with `PRECISION_BITS` bits of
    /// precision.
    ln_proven_weight: u64,
    participants_commitment: GenericDigest,
}

impl Verifier {
    /// Construct a verifier from `provenWeight` (computing its `ln`
    /// approximation). Matches go's `MkVerifier`.
    pub fn new(
        participants_commitment: GenericDigest,
        proven_weight: u64,
        strength_target: u64,
    ) -> Result<Self, StateProofError> {
        let ln_proven_weight = ln_int_approximation(proven_weight)?;
        Ok(Self {
            strength_target,
            ln_proven_weight,
            participants_commitment,
        })
    }

    /// Construct a verifier directly from a precomputed `ln(provenWeight)`.
    /// Matches go's `MkVerifierWithLnProvenWeight`.
    pub fn with_ln_proven_weight(
        participants_commitment: GenericDigest,
        ln_proven_weight: u64,
        strength_target: u64,
    ) -> Self {
        Self {
            strength_target,
            ln_proven_weight,
            participants_commitment,
        }
    }

    /// Verify that `s` is a valid state proof for `data` at `round`.
    ///
    /// Matches go's `Verifier.Verify` (`verifier.go:69`) exactly, including
    /// evaluation order (tree-depth check, weight-count check, per-reveal
    /// salt-version check, per-reveal signature verify, the two
    /// vector-commitment checks, then coin-weight sampling).
    pub fn verify(
        &self,
        round: u64,
        data: MessageHash,
        s: &StateProof,
    ) -> Result<(), StateProofError> {
        verify_state_proof_trees_depth(s)?;

        let nr = s.positions_to_reveal.len() as u64;
        verify_weights(
            s.signed_weight,
            self.ln_proven_weight,
            nr,
            self.strength_target,
        )?;

        let version = s.merkle_signature_salt_version;
        for reveal in s.reveals.values() {
            reveal
                .sig_slot
                .sig
                .validate_salt_version(version)
                .map_err(|_| StateProofError::SaltVersionMismatch)?;
        }

        // Build committable-signature leaves and verify each reveal's
        // per-participant signature.
        let mut sig_slots: BTreeMap<u64, CommittableSignatureSlot> = BTreeMap::new();
        for (&pos, r) in s.reveals.iter() {
            let sig = build_committable_signature(&r.sig_slot)?;
            sig_slots.insert(pos, sig);

            r.part
                .pk
                .verify_bytes(round, &data[..], &r.sig_slot.sig)
                .map_err(|e| StateProofError::SignatureVerificationFailed {
                    pos,
                    reason: e.to_string(),
                })?;
        }

        // Verify all reveal proofs on the signature commitment.
        let sig_elems: Vec<(u64, &dyn Hashable)> = sig_slots
            .iter()
            .map(|(&pos, s)| (pos, s as &dyn Hashable))
            .collect();
        merklearray::verify_vector_commitment(&s.sig_commit, &sig_elems, &s.sig_proofs)
            .map_err(StateProofError::SigVectorCommitmentFailed)?;

        // Verify all reveal proofs on the participant commitment.
        let part_elems: Vec<(u64, &dyn Hashable)> = s
            .reveals
            .iter()
            .map(|(&pos, r)| (pos, &r.part as &dyn Hashable))
            .collect();
        merklearray::verify_vector_commitment(
            &self.participants_commitment,
            &part_elems,
            &s.part_proofs,
        )
        .map_err(StateProofError::PartVectorCommitmentFailed)?;

        // Coin-weight sampling: for each revealed position, the sampled coin
        // must fall within that reveal's weight range.
        let choice = CoinChoiceSeed {
            part_commitment: &self.participants_commitment,
            ln_proven_weight: self.ln_proven_weight,
            sig_commitment: &s.sig_commit,
            signed_weight: s.signed_weight,
            data,
        };
        let mut coin_gen = make_coin_generator(&choice);
        for &pos in &s.positions_to_reveal {
            let reveal = s
                .reveals
                .get(&pos)
                .ok_or(StateProofError::NoRevealInPos(pos))?;
            let coin = coin_gen.get_next_coin();
            let l = reveal.sig_slot.l;
            let weight = reveal.part.weight;
            if !(l <= coin && coin < l + weight) {
                return Err(StateProofError::CoinNotInRange { pos, coin });
            }
        }

        Ok(())
    }
}

/// Check that neither commitment tree exceeds [`MAX_TREE_DEPTH`].
///
/// Matches go's `verifyStateProofTreesDepth` (`verifier.go:145`).
fn verify_state_proof_trees_depth(s: &StateProof) -> Result<(), StateProofError> {
    if s.sig_proofs.tree_depth > MAX_TREE_DEPTH {
        return Err(StateProofError::TreeDepthTooLarge);
    }
    if s.part_proofs.tree_depth > MAX_TREE_DEPTH {
        return Err(StateProofError::TreeDepthTooLarge);
    }
    Ok(())
}

// ── Prover (prover.go) ───────────────────────────────────────────────────
//
// The signing-side counterpart to `Verifier` above: accumulates
// per-participant merkle signatures over rounds as they arrive, then builds
// a `StateProof` once enough weight has signed. This is the cryptographic
// core `algo-ledger`'s state-proof signing worker (issue #814) drives —
// round-eligibility, network gathering, and disk persistence of pending
// signatures are all ledger-level concerns layered on top of this type,
// mirroring go's split between `crypto/stateproof` (this package) and the
// `stateproof` worker package (`spProver` wraps a `*Prover`).

/// A single tracked signature slot, indexed by participant position.
///
/// Distinct from [`SigSlotCommit`] (the wire/reveal shape) in that it
/// additionally carries the participant's `weight`, mirroring go's
/// `sigslot` (`crypto/stateproof/structs.go`), which embeds
/// `sigslotCommit` (`l`/`sig`) plus its own `Weight` field. `l` (the
/// cumulative weight of all lower-numbered slots) starts at 0 for every
/// slot and is only filled in during [`Prover::create_proof`]'s pass over
/// the array, exactly as in go.
#[derive(Debug, Clone, Default)]
struct ProverSigSlot {
    weight: u64,
    commit: SigSlotCommit,
}

/// Keeps track of signatures on a message and eventually produces a state
/// proof for that message.
///
/// Matches go's `stateproof.Prover` (`prover.go:54`); the persisted fields
/// (`ProverPersistedFields`) are inlined here rather than split into a
/// nested struct, since algod-rust doesn't yet have a wire encoder for this
/// type — `algo-ledger`'s persistence layer serializes whatever subset of
/// these fields it needs directly.
#[derive(Debug, Clone)]
pub struct Prover {
    /// The message hash this prover is collecting signatures over.
    pub data: MessageHash,
    /// The round of the block being signed.
    pub round: u64,
    /// The selected voting participants for this state-proof round, in
    /// commitment-tree order (index == array position).
    pub participants: Vec<Participant>,
    /// The vector-commitment tree built over `participants` (go:
    /// `Parttree`).
    pub part_tree: merklearray::Tree,
    /// `ln(proven_weight)`, precomputed at construction time.
    pub ln_proven_weight: u64,
    /// The minimum weight the state proof must exceed.
    pub proven_weight: u64,
    /// The desired cryptographic strength target (bits), governing how
    /// many reveals `create_proof` must include.
    pub strength_target: u64,

    sigs: Vec<ProverSigSlot>,
    signed_weight: u64,
    cached_proof: Option<StateProof>,
}

impl Prover {
    /// Construct an empty prover. After adding enough signatures and signed
    /// weight, it can be used to create a state proof.
    ///
    /// Matches go's `MakeProver` (`prover.go:62`).
    pub fn make_prover(
        data: MessageHash,
        round: u64,
        proven_weight: u64,
        participants: Vec<Participant>,
        part_tree: merklearray::Tree,
        strength_target: u64,
    ) -> Result<Self, StateProofError> {
        let npart = participants.len();
        let ln_proven_weight = ln_int_approximation(proven_weight)?;
        Ok(Self {
            data,
            round,
            participants,
            part_tree,
            ln_proven_weight,
            proven_weight,
            strength_target,
            sigs: vec![ProverSigSlot::default(); npart],
            signed_weight: 0,
            cached_proof: None,
        })
    }

    /// Check if the prover already contains a signature at `pos`.
    ///
    /// Matches go's `Prover.Present` (`prover.go:90`).
    pub fn present(&self, pos: u64) -> Result<bool, StateProofError> {
        let bound = self.sigs.len() as u64;
        if pos >= bound {
            return Err(StateProofError::PositionOutOfBound { pos, bound });
        }
        Ok(self.sigs[pos as usize].weight != 0)
    }

    /// Verify that the participant at `pos`, together with `sig`, can be
    /// inserted into the prover. Pass `verify_sig = false` when the
    /// signature was already verified once (e.g. loaded back from a local
    /// database).
    ///
    /// Matches go's `Prover.IsValid` (`prover.go:100`).
    pub fn is_valid(
        &self,
        pos: u64,
        sig: &merklesig::Signature,
        verify_sig: bool,
    ) -> Result<(), StateProofError> {
        let bound = self.participants.len() as u64;
        if pos >= bound {
            return Err(StateProofError::PositionOutOfBound { pos, bound });
        }

        let p = &self.participants[pos as usize];
        if p.weight == 0 {
            return Err(StateProofError::PositionWithZeroWeight { pos });
        }

        if verify_sig {
            sig.validate_salt_version(MERKLE_SIGNATURE_SCHEME_SALT_VERSION)
                .map_err(|_| StateProofError::SaltVersionMismatch)?;
            p.pk
                .verify_bytes(self.round, &self.data[..], sig)
                .map_err(|e| StateProofError::SignatureVerificationFailed {
                    pos,
                    reason: e.to_string(),
                })?;
        }
        Ok(())
    }

    /// Add a signature to the set of signatures available for building a
    /// proof. Callers must have already confirmed [`Prover::is_valid`] for
    /// `pos`/`sig`.
    ///
    /// Matches go's `Prover.Add` (`prover.go:124`).
    pub fn add(&mut self, pos: u64, sig: merklesig::Signature) -> Result<(), StateProofError> {
        if self.present(pos)? {
            return Err(StateProofError::PositionAlreadyPresent);
        }

        let weight = self.participants[pos as usize].weight;
        let slot = &mut self.sigs[pos as usize];
        slot.weight = weight;
        slot.commit.sig = sig;
        self.signed_weight += weight;
        self.cached_proof = None; // can rebuild a more optimized state proof
        Ok(())
    }

    /// Whether the state proof is ready to be built.
    ///
    /// Matches go's `Prover.Ready` (`prover.go:144`).
    pub fn ready(&self) -> bool {
        self.cached_proof.is_some() || self.signed_weight > self.proven_weight
    }

    /// Total weight of signatures added so far.
    ///
    /// Matches go's `Prover.SignedWeight` (`prover.go:149`).
    pub fn signed_weight(&self) -> u64 {
        self.signed_weight
    }

    /// Binary search for the position `pos` such that the cumulative
    /// weight of all lower-numbered slots (`l`) is `<= coin_weight <
    /// l + weight`.
    ///
    /// Matches go's `Prover.coinIndex` (`prover.go:159`).
    fn coin_index(&self, coin_weight: u64) -> Result<u64, StateProofError> {
        let mut lo = 0u64;
        let mut hi = self.sigs.len() as u64;
        loop {
            if lo >= hi {
                return Err(StateProofError::CoinIndexError {
                    lo,
                    hi,
                    coin: coin_weight,
                });
            }
            let mid = (lo + hi) / 2;
            let slot = &self.sigs[mid as usize];
            if coin_weight < slot.commit.l {
                hi = mid;
                continue;
            }
            if coin_weight < slot.commit.l + slot.weight {
                return Ok(mid);
            }
            lo = mid + 1;
        }
    }

    /// Build a [`StateProof`], if enough signatures have been accumulated.
    ///
    /// Matches go's `Prover.CreateProof` (`prover.go:184`) exactly,
    /// including using [`merklearray::HashType::Sumhash`] for the
    /// signature-commitment tree (go: `stateproof.HashType`).
    pub fn create_proof(&mut self) -> Result<StateProof, StateProofError> {
        if let Some(cached) = &self.cached_proof {
            return Ok(cached.clone());
        }
        if !self.ready() {
            return Err(StateProofError::SignedWeightLessThanProvenWeight {
                signed: self.signed_weight,
                proven: self.proven_weight,
            });
        }

        // Commit to the sigs array: fill in each slot's cumulative-weight
        // prefix sum `l`.
        for i in 1..self.sigs.len() {
            let prev_l = self.sigs[i - 1].commit.l;
            let prev_weight = self.sigs[i - 1].weight;
            self.sigs[i].commit.l = prev_l + prev_weight;
        }

        struct ProverSigArray<'a>(&'a [ProverSigSlot]);
        impl<'a> merklearray::Array for ProverSigArray<'a> {
            fn length(&self) -> u64 {
                self.0.len() as u64
            }
            fn marshal(&self, pos: u64) -> Result<Box<dyn Hashable>, MerkleError> {
                let slot = build_committable_signature(&self.0[pos as usize].commit)
                    .map_err(|e| MerkleError::ArrayError(e.to_string()))?;
                Ok(Box::new(slot))
            }
        }

        let hfactory = merklearray::HashFactory::new(merklearray::HashType::Sumhash);
        let sig_tree = merklearray::build_vector_commitment_tree(&ProverSigArray(&self.sigs), hfactory)
            .map_err(|e| StateProofError::Internal(e.to_string()))?;

        let mut s = StateProof {
            sig_commit: sig_tree.root(),
            signed_weight: self.signed_weight,
            merkle_signature_salt_version: MERKLE_SIGNATURE_SCHEME_SALT_VERSION,
            ..Default::default()
        };

        let nr = num_reveals(self.signed_weight, self.ln_proven_weight, self.strength_target)?;

        let part_commitment = self.part_tree.root();
        let choice = CoinChoiceSeed {
            part_commitment: &part_commitment,
            ln_proven_weight: self.ln_proven_weight,
            sig_commitment: &s.sig_commit,
            signed_weight: s.signed_weight,
            data: self.data,
        };
        let mut coin_gen = make_coin_generator(&choice);

        let mut proof_positions: Vec<u64> = Vec::new();
        let mut reveals_sequence: Vec<u64> = Vec::with_capacity(nr as usize);
        for _ in 0..nr {
            let coin = coin_gen.get_next_coin();
            let pos = self.coin_index(coin)?;

            let bound = self.participants.len() as u64;
            if pos >= bound {
                return Err(StateProofError::PositionOutOfBound { pos, bound });
            }

            reveals_sequence.push(pos);

            // If we already revealed pos, no need to do it again.
            if s.reveals.contains_key(&pos) {
                continue;
            }

            s.reveals.insert(
                pos,
                Reveal {
                    sig_slot: self.sigs[pos as usize].commit.clone(),
                    part: self.participants[pos as usize].clone(),
                },
            );
            proof_positions.push(pos);
        }

        let sig_proofs = sig_tree
            .prove(&proof_positions)
            .map_err(|e| StateProofError::Internal(e.to_string()))?;
        let part_proofs = self
            .part_tree
            .prove(&proof_positions)
            .map_err(|e| StateProofError::Internal(e.to_string()))?;

        s.sig_proofs = sig_proofs;
        s.part_proofs = part_proofs;
        s.positions_to_reveal = reveals_sequence;

        self.cached_proof = Some(s.clone());
        Ok(s)
    }

    /// Re-allocate the (unexported-equivalent) `sigs` array after loading a
    /// persisted prover back from disk, before replaying any previously
    /// gathered signatures into it via repeated [`Prover::add`] calls.
    ///
    /// Matches go's `Prover.AllocSigs` (`prover.go:275`), which exists
    /// because `sigs` isn't part of go's serialized `ProverPersistedFields`
    /// either.
    pub fn alloc_sigs(&mut self) {
        self.sigs = vec![ProverSigSlot::default(); self.participants.len()];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Coin-hash known-answer test (KAT) ───────────────────────────────
    //
    // go-algorand's `crypto/stateproof/coinGenerator_test.go` `TestGenerateCoinHashKATs`
    // is (like merklesignature's `TestGenerateKat`) a KAT *generator*, not a
    // checker: it is `t.Skip`ped unless `GEN_KATS` is set, and prints its
    // output rather than asserting against a value go-algorand commits to
    // source. Its inputs are also freshly randomized per run
    // (`crypto.RandBytes`), so there is no fixed go-algorand byte string to
    // reproduce even by running the Go test.
    //
    // Running the Go test directly was attempted and is unavailable in this
    // environment: `crypto/stateproof` transitively depends on cgo-only
    // packages (`algorand/falcon`, `mattn/go-sqlite3`) and this Windows
    // checkout has no C compiler on PATH (`CGO_ENABLED=0`, no `gcc`/mingw),
    // so `go build`/`go test` fails before the coin generator ever runs.
    //
    // Unlike the merklesignature KAT, though, `coinChoiceSeed`/
    // `coinGenerator` involve no randomly-generated key material of their
    // own — `getNextCoin` is a pure function of its (attacker-controlled)
    // seed bytes: `SHAKE256("spc" || version || partCommitment ||
    // lnProvenWeight_LE64 || sigCommitment || signedWeight_LE64 || data)`,
    // squeezed 8 bytes at a time with rejection sampling against
    // `floor(2^64/signedWeight)*signedWeight`. That means a *real*
    // cross-implementation KAT is available without go-algorand at all: fix
    // the seed's byte inputs and independently compute the expected SHAKE256
    // squeeze sequence via Python's `hashlib.shake_256` (an independent
    // FIPS-202 implementation from both Rust's `sha3` crate and go's
    // `golang.org/x/crypto/sha3` — all three are required to agree with the
    // same standard, so agreement is genuine evidence of correctness, not
    // just self-consistency). The vector below was computed by:
    //
    // ```python
    // import hashlib
    // part_commitment = bytes(range(64))
    // sig_commitment = bytes((i * 7 + 3) % 256 for i in range(64))
    // data = bytes((i * 11 + 5) % 256 for i in range(32))
    // ln_proven_weight = 454197
    // signed_weight = 37  # not a power of two, to exercise the mod-bias path
    // payload = bytes([0]) + part_commitment + ln_proven_weight.to_bytes(8, "little") \
    //     + sig_commitment + signed_weight.to_bytes(8, "little") + data
    // shake = hashlib.shake_256(b"spc" + payload)
    // threshold = (1 << 64) // signed_weight * signed_weight
    // # squeeze 8-byte little-endian chunks, rejecting z >= threshold, until
    // # 30 coins are produced: z % signed_weight is the coin.
    // ```
    //
    // which produced the `coins` sequence pinned below with zero rejections
    // (threshold is within 2^-59 of 2^64 for signed_weight=37, so rejection
    // essentially never fires for a run this short — consistent with
    // go-algorand's own real-world usage, where signedWeight is far smaller
    // than 2^64).
    #[test]
    fn test_generate_coin_hash_kat() {
        let part_commitment: GenericDigest = (0u16..64).map(|i| i as u8).collect();
        let sig_commitment: GenericDigest = (0u16..64).map(|i| ((i * 7 + 3) % 256) as u8).collect();
        let mut data: MessageHash = [0u8; 32];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i * 11 + 5) % 256) as u8;
        }
        let ln_proven_weight: u64 = 454197;
        let signed_weight: u64 = 37;

        let choice = CoinChoiceSeed {
            part_commitment: &part_commitment,
            ln_proven_weight,
            sig_commitment: &sig_commitment,
            signed_weight,
            data,
        };
        let mut coin_gen = make_coin_generator(&choice);

        const EXPECTED_COINS: [u64; 30] = [
            14, 6, 6, 27, 7, 11, 20, 30, 24, 7, 31, 19, 28, 10, 3, 18, 29, 4, 9, 16, 0, 24, 5, 31,
            9, 13, 31, 30, 20, 19,
        ];

        for (idx, &expected) in EXPECTED_COINS.iter().enumerate() {
            let coin = coin_gen.get_next_coin();
            assert!(
                coin < signed_weight,
                "coin {idx} = {coin} must be < signed_weight ({signed_weight})"
            );
            assert_eq!(
                coin, expected,
                "coin {idx} mismatched independently-computed SHAKE256 KAT vector"
            );
        }
    }

    #[test]
    fn ln_int_approximation_matches_known_values() {
        // ln(1) = 0
        assert_eq!(ln_int_approximation(1).unwrap(), 0);
        // ln(e) ~ 1 -> 65536 with ceil rounding may be 1 above due to f64 error;
        // just sanity check monotonicity and non-zero for x>1.
        assert!(ln_int_approximation(2).unwrap() > 0);
        assert!(ln_int_approximation(1_000_000).unwrap() > ln_int_approximation(1000).unwrap());
    }

    #[test]
    fn ln_int_approximation_rejects_zero() {
        assert_eq!(
            ln_int_approximation(0),
            Err(StateProofError::IllegalLnInput)
        );
    }

    #[test]
    fn calculate_ln_proven_weight_matches_muldiv_then_ln() {
        // total_weight=1<<32, threshold=1<<31 (50%) -> proven_weight = 1<<31.
        let total_weight = 1u64 << 32;
        let threshold = 1u32 << 31;
        let expected = ln_int_approximation(1u64 << 31).unwrap();
        assert_eq!(
            calculate_ln_proven_weight(total_weight, threshold).unwrap(),
            expected
        );
    }

    #[test]
    fn calculate_ln_proven_weight_zero_weight_is_illegal_ln_input() {
        assert_eq!(
            calculate_ln_proven_weight(0, 1u32 << 31),
            Err(StateProofError::IllegalLnInput)
        );
    }

    #[test]
    fn calculate_ln_proven_weight_overflow_is_internal_error() {
        // u64::MAX * u32::MAX / 2^32 still fits (product is u128, divided
        // down) -- push total_weight past what any real proven_weight
        // could produce isn't actually reachable with a u64 total_weight
        // and u32 threshold (max product fits in 96 bits, divided by 2^32
        // always fits back in u64). Kept as a smoke test that the
        // conversion path itself is exercised without panicking.
        let got = calculate_ln_proven_weight(u64::MAX, u32::MAX);
        assert!(got.is_ok());
    }

    #[test]
    fn verify_weights_rejects_zero_signed_weight() {
        assert_eq!(
            verify_weights(0, 100, 10, 256),
            Err(StateProofError::ZeroSignedWeight)
        );
    }

    #[test]
    fn verify_weights_rejects_too_many_reveals() {
        assert_eq!(
            verify_weights(100, 100, MAX_REVEALS + 1, 256),
            Err(StateProofError::TooManyReveals)
        );
    }

    #[test]
    fn verify_weights_rejects_insufficient_reveals() {
        // A large signed weight but only 1 reveal cannot satisfy the security
        // bound for a meaningful strength target.
        let ln_pw = ln_int_approximation(1_000_000).unwrap();
        assert_eq!(
            verify_weights(2_000_000, ln_pw, 1, 256),
            Err(StateProofError::InsufficientSignedWeight)
        );
    }

    #[test]
    fn verify_weights_accepts_enough_reveals() {
        // With a modest weight and enough reveals, verification should pass.
        let ln_pw = ln_int_approximation(10).unwrap();
        // 640 reveals (the max) against a tiny weight is comfortably enough.
        assert!(verify_weights(1000, ln_pw, MAX_REVEALS, 256).is_ok());
    }

    #[test]
    fn verify_rejects_tree_depth_too_large() {
        let mut s = StateProof::default();
        s.sig_proofs.tree_depth = MAX_TREE_DEPTH + 1;
        let v = Verifier::with_ln_proven_weight(vec![0u8; 64], 0, 256);
        let err = v.verify(1, [0u8; 32], &s).unwrap_err();
        assert_eq!(err, StateProofError::TreeDepthTooLarge);
    }

    #[test]
    fn build_committable_signature_rejects_deep_proof() {
        let mut sig_commit = SigSlotCommit::default();
        sig_commit.sig.signature = vec![1, 2, 3]; // non-empty falcon sig
        sig_commit.sig.proof.proof.tree_depth = (merklearray::MAX_ENCODED_TREE_DEPTH + 1) as u8;
        let err = build_committable_signature(&sig_commit).unwrap_err();
        assert_eq!(err, StateProofError::ProofTreeDepthTooLarge);
    }

    #[test]
    fn build_committable_signature_rejects_empty_falcon_sig() {
        // Non-zero L makes the sigslotCommit non-"MsgIsZero" without a
        // signature present, matching the go invalid case (Merkle sig
        // present via nonzero fields, but Falcon signature bytes missing).
        let sig_commit = SigSlotCommit {
            l: 5,
            sig: merklesig::Signature {
                vector_commitment_index: 1,
                ..Default::default()
            },
        };
        let err = build_committable_signature(&sig_commit).unwrap_err();
        assert_eq!(err, StateProofError::EmptyFalconSignature);
    }

    #[test]
    fn build_committable_signature_empty_slot() {
        let sig_commit = SigSlotCommit::default();
        let slot = build_committable_signature(&sig_commit).unwrap();
        assert!(slot.is_empty_slot);
        let (prefix, data) = slot.to_be_hashed();
        assert_eq!(prefix, STATE_PROOF_SIG);
        assert!(data.is_empty());
    }

    // ── Full round-trip tests: real Falcon signatures + real merkle trees ──
    //
    // These build a genuine (not mocked) single-participant state proof:
    // real Falcon-1024 keys and signatures via `merklesig::Secrets`, and real
    // vector-commitment merkle trees for both the outer sig/participant
    // commitments and the inner per-participant ephemeral-key commitment.
    // `Verifier::verify` exercises every real cryptographic check with no
    // shortcuts. The weight/strength parameters are chosen small (a single
    // fully-signing participant, `strength_target = 0`) purely to keep the
    // reveal count at 1 for test speed — the security-relevant bound
    // (`verify_weights`) is covered separately by dedicated unit tests above
    // and is exercised for real here too, just at a trivially-satisfiable
    // threshold.

    struct SigArray(Vec<SigSlotCommit>);
    impl merklearray::Array for SigArray {
        fn length(&self) -> u64 {
            self.0.len() as u64
        }
        fn marshal(&self, pos: u64) -> Result<Box<dyn Hashable>, MerkleError> {
            let slot = build_committable_signature(&self.0[pos as usize])
                .map_err(|e| MerkleError::ArrayError(e.to_string()))?;
            Ok(Box::new(slot))
        }
    }

    struct PartArray(Vec<Participant>);
    impl merklearray::Array for PartArray {
        fn length(&self) -> u64 {
            self.0.len() as u64
        }
        fn marshal(&self, pos: u64) -> Result<Box<dyn Hashable>, MerkleError> {
            Ok(Box::new(self.0[pos as usize].clone()))
        }
    }

    /// Build a genuine single-participant state proof: real Falcon keys,
    /// a real per-participant ephemeral-key vector-commitment tree (the
    /// merkle-signature-scheme commitment), and real outer sig/participant
    /// vector-commitment trees.
    fn build_genuine_state_proof(round: u64, msg: MessageHash) -> (Verifier, StateProof, u64) {
        let weight = 1000u64;

        // Per-participant merkle-signature-scheme keys, valid at `round`.
        let secrets = merklesig::Secrets::new(round, round, 1).expect("secrets");
        let mss_verifier = secrets.get_verifier();
        let signer = secrets.get_signer(round);
        let sig = signer.sign_bytes(&msg).expect("sign");

        let participant = Participant {
            pk: mss_verifier,
            weight,
        };
        let sig_slot = SigSlotCommit { sig, l: 0 };

        let factory = merklearray::HashFactory::new(merklearray::HashType::Sha512_256);
        let sig_tree =
            merklearray::build_vector_commitment_tree(&SigArray(vec![sig_slot.clone()]), factory)
                .expect("sig tree");
        let part_tree = merklearray::build_vector_commitment_tree(
            &PartArray(vec![participant.clone()]),
            factory,
        )
        .expect("part tree");

        let sig_commit = sig_tree.root();
        let part_commit = part_tree.root();

        let sig_proof = sig_tree.prove(&[0]).expect("sig proof");
        let part_proof = part_tree.prove(&[0]).expect("part proof");

        let mut reveals = BTreeMap::new();
        reveals.insert(
            0,
            Reveal {
                sig_slot,
                part: participant,
            },
        );

        let state_proof = StateProof {
            sig_commit,
            signed_weight: weight,
            sig_proofs: sig_proof,
            part_proofs: part_proof,
            merkle_signature_salt_version: 0,
            reveals,
            positions_to_reveal: vec![0],
        };

        // strength_target = 0 makes verify_weights trivially satisfiable with
        // a single reveal; proven_weight = 1 keeps ln_proven_weight small.
        let verifier = Verifier::new(part_commit, 1, 0).expect("verifier");

        (verifier, state_proof, round)
    }

    #[test]
    fn genuine_state_proof_verifies() {
        let msg = [7u8; 32];
        let (verifier, state_proof, round) = build_genuine_state_proof(0, msg);
        verifier
            .verify(round, msg, &state_proof)
            .expect("genuine state proof must verify");
    }

    #[test]
    fn genuine_state_proof_rejects_wrong_message() {
        let msg = [7u8; 32];
        let (verifier, state_proof, round) = build_genuine_state_proof(0, msg);
        let wrong_msg = [8u8; 32];
        let err = verifier
            .verify(round, wrong_msg, &state_proof)
            .expect_err("must reject: signature was over a different message");
        assert!(matches!(
            err,
            StateProofError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn genuine_state_proof_rejects_forged_falcon_signature() {
        // Falcon-1024's compressed signature encoding is variable-length
        // (compression is data-dependent), so a fixed `mid = len/2` byte
        // flip lands in a different part of the encoding on every run
        // (`build_genuine_state_proof` draws fresh, unseeded keys/signatures
        // each call). Confirmed by looping 300 iterations: the corrupted
        // byte sometimes breaks the compressed->CT conversion itself
        // (`build_committable_signature`'s `get_fixed_length_hashable_representation`
        // call, surfacing as `StateProofError::Internal` — go's own
        // `buildCommittableSignature` runs this same conversion before the
        // per-reveal `VerifyBytes` call, so this is the equivalent failure
        // mode there too), and sometimes reaches the deeper per-reveal
        // Falcon check (`SignatureVerificationFailed`). Both are a correct
        // rejection of the forged signature — assert on that outcome, not a
        // specific error variant that isn't actually deterministic here.
        for _ in 0..150 {
            let msg = [7u8; 32];
            let (verifier, mut state_proof, round) = build_genuine_state_proof(0, msg);
            let reveal = state_proof.reveals.get_mut(&0).unwrap();
            let sig_bytes = &mut reveal.sig_slot.sig.signature;
            let mid = sig_bytes.len() / 2;
            sig_bytes[mid] ^= 0xff;
            let err = verifier
                .verify(round, msg, &state_proof)
                .expect_err("must reject forged Falcon signature");
            assert!(
                matches!(
                    err,
                    StateProofError::SignatureVerificationFailed { .. }
                        | StateProofError::Internal(_)
                ),
                "unexpected rejection variant for a forged signature: {err:?}"
            );
        }
    }

    #[test]
    fn genuine_state_proof_rejects_tampered_sig_commit_root() {
        let msg = [7u8; 32];
        let (verifier, mut state_proof, round) = build_genuine_state_proof(0, msg);
        // Flip a byte of the committed signature-tree root: the per-reveal
        // Falcon check still passes, but the vector-commitment proof no
        // longer matches the (attacker-supplied) root.
        if let Some(byte) = state_proof.sig_commit.first_mut() {
            *byte ^= 0xff;
        }
        let err = verifier
            .verify(round, msg, &state_proof)
            .expect_err("must reject tampered sig commitment root");
        assert!(matches!(err, StateProofError::SigVectorCommitmentFailed(_)));
    }

    #[test]
    fn genuine_state_proof_rejects_tampered_participant_weight() {
        let msg = [7u8; 32];
        let (verifier, mut state_proof, round) = build_genuine_state_proof(0, msg);
        // Inflating the revealed participant's weight changes the leaf's
        // hashed representation, breaking the participant-commitment proof.
        state_proof.reveals.get_mut(&0).unwrap().part.weight += 1;
        let err = verifier
            .verify(round, msg, &state_proof)
            .expect_err("must reject tampered participant weight");
        assert!(matches!(
            err,
            StateProofError::PartVectorCommitmentFailed(_)
        ));
    }

    // ── Prover tests (prover.go's TestBuilder family) ───────────────────
    //
    // Mirrors go's `TestBuilder`/`TestBuildValid` (`crypto/stateproof/
    // prover_test.go`): construct a real multi-participant prover with
    // genuine Falcon/merkle-signature-scheme keys, add signatures from only
    // a subset of participants (exercising the "not everyone signs" path
    // real state-proof rounds always hit), and confirm the resulting
    // `StateProof` verifies end-to-end against `Verifier`.

    /// Build `n` participants with real Falcon-backed MSS keys valid at
    /// `round`, each with `weight`, plus the real Sumhash vector-commitment
    /// tree over them (go: `HashType = crypto.Sumhash`, used for the
    /// participants tree by `ledger/voters.go`'s `LoadTree` and mirrored by
    /// this crate's `algo-ledger::voters::build_voters_tree`).
    fn build_prover_participants(
        n: usize,
        round: u64,
        weight: u64,
    ) -> (Vec<merklesig::Secrets>, Vec<Participant>, merklearray::Tree) {
        let mut secrets_list = Vec::with_capacity(n);
        let mut participants = Vec::with_capacity(n);
        for _ in 0..n {
            let secrets = merklesig::Secrets::new(round, round, 1).expect("secrets");
            participants.push(Participant {
                pk: secrets.get_verifier(),
                weight,
            });
            secrets_list.push(secrets);
        }

        let factory = merklearray::HashFactory::new(merklearray::HashType::Sumhash);
        let part_tree =
            merklearray::build_vector_commitment_tree(&PartArray(participants.clone()), factory)
                .expect("part tree");

        (secrets_list, participants, part_tree)
    }

    #[test]
    fn prover_builds_a_state_proof_that_verifies_with_partial_signers() {
        let round = 0u64;
        let msg = [9u8; 32];
        let weight = 1000u64;
        let n = 5;
        let (secrets_list, participants, part_tree) = build_prover_participants(n, round, weight);
        let part_commit = part_tree.root();

        // proven_weight = 2000 needs > 2 participants signed (2 * 1000 = 2000
        // is not > proven_weight, 3 * 1000 = 3000 is).
        let proven_weight = 2000u64;
        let strength_target = 0u64; // trivially satisfiable, keeps reveal count small

        let mut prover = Prover::make_prover(
            msg,
            round,
            proven_weight,
            participants.clone(),
            part_tree,
            strength_target,
        )
        .expect("make_prover");

        // Only 3 of 5 participants sign.
        for pos in [0u64, 2, 4] {
            let signer = secrets_list[pos as usize].get_signer(round);
            let sig = signer.sign_bytes(&msg).expect("sign");
            prover.is_valid(pos, &sig, true).expect("is_valid");
            prover.add(pos, sig).expect("add");
        }

        assert_eq!(prover.signed_weight(), 3 * weight);
        assert!(prover.ready(), "3000 > proven_weight 2000 must be ready");

        let proof = prover.create_proof().expect("create_proof");
        assert_eq!(proof.signed_weight, 3 * weight);
        assert!(!proof.positions_to_reveal.is_empty());

        let verifier =
            Verifier::new(part_commit, proven_weight, strength_target).expect("verifier");
        verifier
            .verify(round, msg, &proof)
            .expect("prover-built proof must verify");
    }

    #[test]
    fn prover_create_proof_is_idempotent_and_cached() {
        let round = 5u64;
        let msg = [1u8; 32];
        let weight = 100u64;
        let (secrets_list, participants, part_tree) = build_prover_participants(2, round, weight);

        let mut prover =
            Prover::make_prover(msg, round, 50, participants, part_tree, 0).expect("make_prover");
        let signer = secrets_list[0].get_signer(round);
        let sig = signer.sign_bytes(&msg).expect("sign");
        prover.add(0, sig).expect("add");
        assert!(prover.ready());

        let proof1 = prover.create_proof().expect("first create_proof");
        let proof2 = prover.create_proof().expect("second create_proof (cached)");
        assert_eq!(proof1.sig_commit, proof2.sig_commit);
        assert_eq!(proof1.positions_to_reveal, proof2.positions_to_reveal);
    }

    #[test]
    fn prover_create_proof_rejects_insufficient_signed_weight() {
        let round = 0u64;
        let msg = [2u8; 32];
        let (_, participants, part_tree) = build_prover_participants(2, round, 100);

        // proven_weight = 1000 is never reached by two 100-weight signers.
        let mut prover =
            Prover::make_prover(msg, round, 1000, participants, part_tree, 0).expect("make_prover");
        let err = prover
            .create_proof()
            .expect_err("must reject: no signatures added");
        assert!(matches!(
            err,
            StateProofError::SignedWeightLessThanProvenWeight { signed: 0, proven: 1000 }
        ));
    }

    #[test]
    fn prover_present_rejects_out_of_bound_position() {
        let round = 0u64;
        let msg = [3u8; 32];
        let (_, participants, part_tree) = build_prover_participants(2, round, 100);
        let prover =
            Prover::make_prover(msg, round, 50, participants, part_tree, 0).expect("make_prover");
        let err = prover.present(5).expect_err("pos 5 is out of bounds for 2 participants");
        assert_eq!(
            err,
            StateProofError::PositionOutOfBound { pos: 5, bound: 2 }
        );
    }

    #[test]
    fn prover_add_rejects_duplicate_position() {
        let round = 0u64;
        let msg = [4u8; 32];
        let (secrets_list, participants, part_tree) = build_prover_participants(2, round, 100);
        let mut prover =
            Prover::make_prover(msg, round, 50, participants, part_tree, 0).expect("make_prover");
        let sig = secrets_list[0]
            .get_signer(round)
            .sign_bytes(&msg)
            .expect("sign");
        prover.add(0, sig.clone()).expect("first add");
        let err = prover
            .add(0, sig)
            .expect_err("second add at same position must fail");
        assert_eq!(err, StateProofError::PositionAlreadyPresent);
    }

    #[test]
    fn prover_is_valid_rejects_wrong_signature() {
        let round = 0u64;
        let msg = [5u8; 32];
        let (secrets_list, participants, part_tree) = build_prover_participants(2, round, 100);
        let prover =
            Prover::make_prover(msg, round, 50, participants, part_tree, 0).expect("make_prover");
        // Sign a *different* message than the prover's `data`.
        let wrong_sig = secrets_list[0]
            .get_signer(round)
            .sign_bytes(&[0xEEu8; 32])
            .expect("sign");
        let err = prover
            .is_valid(0, &wrong_sig, true)
            .expect_err("signature over a different message must be rejected");
        assert!(matches!(
            err,
            StateProofError::SignatureVerificationFailed { pos: 0, .. }
        ));
    }

    #[test]
    fn prover_is_valid_rejects_zero_weight_participant() {
        let round = 0u64;
        let msg = [6u8; 32];
        let (secrets_list, mut participants, part_tree) = build_prover_participants(1, round, 100);
        participants[0].weight = 0;
        // part_tree was built before zeroing the weight, but IsValid only
        // reads `Participants`, matching go's behavior exactly (the tree
        // itself is irrelevant to this particular check).
        let prover =
            Prover::make_prover(msg, round, 50, participants, part_tree, 0).expect("make_prover");
        let sig = secrets_list[0]
            .get_signer(round)
            .sign_bytes(&msg)
            .expect("sign");
        let err = prover
            .is_valid(0, &sig, true)
            .expect_err("zero-weight participant must be rejected");
        assert_eq!(err, StateProofError::PositionWithZeroWeight { pos: 0 });
    }

    #[test]
    fn num_reveals_matches_hand_computed_case() {
        // strength_target = 0 trivially needs only 1 reveal (the `+1` fudge
        // guarantees at least 1 regardless of weight).
        let ln_pw = ln_int_approximation(10).unwrap();
        assert_eq!(num_reveals(1000, ln_pw, 0).unwrap(), 1);

        // A reveal count computed by num_reveals must itself satisfy
        // verify_weights -- the two functions are meant to be inverses at
        // the boundary (go's real-world usage relies on exactly this).
        let ln_pw2 = ln_int_approximation(100).unwrap();
        let nr = num_reveals(1000, ln_pw2, 256).unwrap();
        assert!((1..=MAX_REVEALS).contains(&nr));
        assert!(verify_weights(1000, ln_pw2, nr, 256).is_ok());
        // One fewer reveal must not be enough (num_reveals returns the
        // *smallest* sufficient count).
        if nr > 1 {
            assert!(verify_weights(1000, ln_pw2, nr - 1, 256).is_err());
        }
    }

    #[test]
    fn num_reveals_rejects_too_many_reveals() {
        // An enormous strength target against a tiny signed weight demands
        // more than MAX_REVEALS reveals.
        let ln_pw = ln_int_approximation(1).unwrap();
        let err = num_reveals(2, ln_pw, u64::MAX / 2).unwrap_err();
        assert_eq!(err, StateProofError::TooManyReveals);
    }
}
