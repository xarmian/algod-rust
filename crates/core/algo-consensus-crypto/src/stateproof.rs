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
#[derive(Debug, Clone)]
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
}
