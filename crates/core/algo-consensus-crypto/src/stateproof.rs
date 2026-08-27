//! State proof cryptographic verification — port of go-algorand's
//! `crypto/stateproof.Verifier.Verify`, the piece that actually checks a
//! `StateProof` transaction's signatures instead of trusting it blindly.
//!
//! References (go-algorand @ v4.7.2-stable):
//! - `crypto/stateproof/verifier.go` — `Verifier.Verify` orchestration,
//!   `verifyStateProofTreesDepth`.
//! - `crypto/stateproof/weights.go` — `LnIntApproximation`, `verifyWeights`.
//! - `crypto/stateproof/coinGenerator.go` — `coinChoiceSeed`, `coinGenerator`,
//!   rejection-sampling coin draw.
//! - `crypto/stateproof/committableSignatureSlot.go` — `buildCommittableSignature`,
//!   the SNARK-friendly fixed-length leaf encoding hashed into `SigCommit`.
//! - `crypto/stateproof/const.go` — `MaxTreeDepth`, `VersionForCoinGenerator`,
//!   `MaxReveals`, `ln2IntApproximation`, `precisionBits`.
//! - `data/basics/stateProofParticipant.go` — `Participant.ToBeHashed`.
//! - `crypto/merklesignature/merkleSignatureScheme.go` — `Verifier.VerifyBytes`
//!   (already ported as [`crate::merklesig::Verifier::verify_bytes`] — reused
//!   here rather than reimplemented).
//! - `stateproof/verify/stateproof.go` — `ValidateStateProof` (weight
//!   threshold + proven-weight computation feeding into `Verify`); the ledger
//!   caller in `algo-ledger` is responsible for that outer layer, this module
//!   is the `Verifier.Verify` core.

use num_bigint::BigInt;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::merklearray::{self, GenericDigest, Hashable, MerkleError, Proof, SingleLeafProof};
use crate::merklesig;
use algo_types::{MerkleProof, MerkleSignature, Reveal, StateProofBody};

// ── Constants (crypto/stateproof/const.go) ─────────────────────────────────

/// `MaxTreeDepth` — bound on `SigProofs`/`PartProofs` tree depth.
pub const MAX_TREE_DEPTH: u8 = 20;
/// `VersionForCoinGenerator` — Fiat-Shamir domain-separation byte for coin draws.
const VERSION_FOR_COIN_GENERATOR: u8 = 0;
/// `MaxReveals` — bound on allocation and on `numReveals`.
const MAX_REVEALS: u64 = 640;
/// `precisionBits` — fixed-point precision used by the ln() approximation.
const PRECISION_BITS: u32 = 16;
/// `ln2IntApproximation` = `ceil(2^precisionBits * ln(2))`.
const LN2_INT_APPROXIMATION: u64 = 45427;

// Domain separation prefixes (`protocol/hash.go`).
const STATE_PROOF_SIG: &[u8] = b"sps";
const STATE_PROOF_PART: &[u8] = b"spp";
const STATE_PROOF_COIN: &[u8] = b"spc";

/// Errors from state-proof cryptographic verification. Every variant here
/// means "reject the transaction" — none are recoverable.
#[derive(Debug)]
pub enum StateProofError {
    /// `verifyStateProofTreesDepth`: `SigProofs`/`PartProofs` tree too deep.
    TreeDepthTooLarge { which: &'static str, depth: u8 },
    /// `verifyWeights`: too many reveals (`ErrTooManyReveals`).
    TooManyReveals,
    /// `verifyWeights`: `SignedWeight == 0` (`ErrZeroSignedWeight`).
    ZeroSignedWeight,
    /// `LnIntApproximation`: `provenWeight == 0` (`ErrIllegalInputForLnApprox`).
    IllegalLnInput,
    /// `verifyWeights`: reveal count insufficient for the claimed weight
    /// (`ErrInsufficientSignedWeight`).
    InsufficientSignedWeight,
    /// An unknown/invalid hash type in a `MerkleProof`'s `HashFactory`.
    UnknownHashType(u16),
    /// `buildCommittableSignature`: revealed sigslot has an empty Falcon
    /// signature (malformed — a truly-absent slot has no `Sig` at all).
    EmptyFalconSignature { pos: u64 },
    /// `buildCommittableSignature`: `sig.Proof.TreeDepth` exceeds
    /// `merklearray.MaxEncodedTreeDepth` — the fixed-length leaf encoding
    /// cannot represent it.
    EncodedTreeDepthTooLarge { pos: u64, depth: u8 },
    /// A reveal position present in `PositionsToReveal` has no entry in
    /// `Reveals` (`ErrNoRevealInPos`), or a reveal is missing its
    /// `SigSlot`/`Part`.
    MissingReveal { pos: u64 },
    /// `ValidateSaltVersion`: a revealed signature's salt version does not
    /// match `StateProof.MerkleSignatureSaltVersion`.
    SaltVersionMismatch { pos: u64 },
    /// `r.Part.PK.VerifyBytes`: the per-reveal Falcon/Merkle signature failed.
    SignatureVerificationFailed { pos: u64, reason: String },
    /// A Falcon public key or ephemeral verifying key had the wrong length.
    InvalidFalconKeySize {
        pos: u64,
        expected: usize,
        actual: usize,
    },
    /// Compressed-to-CT Falcon signature conversion failed.
    Falcon { pos: u64, reason: String },
    /// `merklearray.VerifyVectorCommitment` failed for `SigCommit` or the
    /// participants commitment.
    Merkle(MerkleError),
    /// `getNextCoin` produced a coin outside the revealed weight range
    /// (`ErrCoinNotInRange`).
    CoinNotInRange { pos: u64 },
}

impl std::fmt::Display for StateProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TreeDepthTooLarge { which, depth } => {
                write!(f, "{which} tree depth {depth} exceeds maximum {MAX_TREE_DEPTH}")
            }
            Self::TooManyReveals => write!(f, "too many reveals in state proof"),
            Self::ZeroSignedWeight => write!(f, "signed weight cannot be zero"),
            Self::IllegalLnInput => write!(f, "cannot calculate a ln integer value for 0"),
            Self::InsufficientSignedWeight => write!(
                f,
                "the number of reveals is not large enough to prove the desired weight signed, with the desired security level"
            ),
            Self::UnknownHashType(v) => write!(f, "unknown merkle proof hash type {v}"),
            Self::EmptyFalconSignature { pos } => {
                write!(f, "buildCommittableSignature: empty Falcon signature at pos {pos}")
            }
            Self::EncodedTreeDepthTooLarge { pos, depth } => write!(
                f,
                "buildCommittableSignature: proof tree depth {depth} exceeds maximum {} at pos {pos}",
                merklearray::MAX_ENCODED_TREE_DEPTH
            ),
            Self::MissingReveal { pos } => write!(f, "no reveal for position {pos}"),
            Self::SaltVersionMismatch { pos } => {
                write!(f, "signature salt version mismatch at pos {pos}")
            }
            Self::SignatureVerificationFailed { pos, reason } => {
                write!(f, "signature in reveal pos {pos} does not verify: {reason}")
            }
            Self::InvalidFalconKeySize { pos, expected, actual } => write!(
                f,
                "falcon key at pos {pos} has invalid size {actual} (expected {expected})"
            ),
            Self::Falcon { pos, reason } => write!(f, "falcon error at pos {pos}: {reason}"),
            Self::Merkle(e) => write!(f, "{e}"),
            Self::CoinNotInRange { pos } => {
                write!(f, "coin is not within slot weight range for reveal pos {pos}")
            }
        }
    }
}

impl std::error::Error for StateProofError {}

impl From<MerkleError> for StateProofError {
    fn from(e: MerkleError) -> Self {
        Self::Merkle(e)
    }
}

// ── Weight approximation (crypto/stateproof/weights.go) ────────────────────

/// `LnIntApproximation` — `ceil(ln(x) * 2^precisionBits)`.
pub fn ln_int_approximation(x: u64) -> Result<u64, StateProofError> {
    if x == 0 {
        return Err(StateProofError::IllegalLnInput);
    }
    let result = (x as f64).ln();
    let precision = (1u64 << PRECISION_BITS) as f64;
    Ok((result * precision).ceil() as u64)
}

/// `getSubExpressions` — see `weights.go` for the derivation; `y`, `x`, `w`
/// feed the `verifyWeights` inequality. Only called with `signed_weight > 0`.
fn get_sub_expressions(signed_weight: u64) -> (BigInt, BigInt, BigInt) {
    let d: u32 = 63 - signed_weight.leading_zeros(); // bits.Len64(x) - 1
    let big = |v: u64| BigInt::from(v);

    let signed_wt_power2 = big(signed_weight) * big(signed_weight);
    let tmp = (BigInt::from(1u64) << (d + 2)) * big(signed_weight);
    let two_pow_2d = BigInt::from(1u64) << (2 * d);

    let y = &two_pow_2d + &tmp + &signed_wt_power2;
    let x = (&signed_wt_power2 - &two_pow_2d)
        * BigInt::from(3u64)
        * (BigInt::from(1u64) << PRECISION_BITS);
    let w = BigInt::from(d) * BigInt::from(LN2_INT_APPROXIMATION - 1);

    (y, x, w)
}

/// `verifyWeights` — checks that `numOfReveals` is large enough, given
/// `signedWeight` and `lnProvenWeight`, to meet `strengthTarget` bits of
/// security under Fiat-Shamir coin sampling.
pub fn verify_weights(
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
    let lhs = BigInt::from(num_of_reveals) * (&x + &w * &y);

    let reveals_times_p = BigInt::from(num_of_reveals) * BigInt::from(ln_proven_weight);
    let rhs = (BigInt::from(strength_target) * BigInt::from(LN2_INT_APPROXIMATION)
        + reveals_times_p)
        * &y;

    if lhs < rhs {
        return Err(StateProofError::InsufficientSignedWeight);
    }
    Ok(())
}

// ── MerkleProof (wire) → Proof (crypto) conversion ──────────────────────────

fn convert_merkle_proof(mp: Option<&MerkleProof>) -> Result<Proof, StateProofError> {
    let Some(mp) = mp else {
        return Ok(Proof::default());
    };
    let hash_type_raw = mp.hash_factory.as_ref().map(|hf| hf.hash_type).unwrap_or(0);
    let hash_type = merklearray::HashType::from_u16(hash_type_raw)
        .ok_or(StateProofError::UnknownHashType(hash_type_raw))?;
    let path: Vec<GenericDigest> = mp
        .path
        .as_ref()
        .map(|entries| {
            entries
                .iter()
                .map(|e| e.as_ref().map(|b| b.to_vec()).unwrap_or_default())
                .collect()
        })
        .unwrap_or_default();
    Ok(Proof {
        path,
        hash_factory: merklearray::HashFactory::new(hash_type),
        tree_depth: mp.tree_depth,
    })
}

// ── committableSignatureSlot (crypto/stateproof/committableSignatureSlot.go) ─

/// The `Hashable` leaf fed into the `SigCommit` vector-commitment tree for
/// one revealed sigslot. Mirrors `committableSignatureSlot.ToBeHashed`.
enum CommittableSignatureSlot {
    /// `sigCommit.Sig.MsgIsZero()` — an unrevealed/empty slot.
    Empty,
    /// `L` (8 bytes LE) || scheme (2 bytes LE) || CT-format Falcon signature
    /// || raw ephemeral pubkey || vc index (8 bytes LE) || fixed-length proof.
    NonEmpty { l: u64, data: Vec<u8> },
}

impl Hashable for CommittableSignatureSlot {
    fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
        match self {
            Self::Empty => (STATE_PROOF_SIG, Vec::new()),
            Self::NonEmpty { l, data } => {
                let mut out = Vec::with_capacity(8 + data.len());
                out.extend_from_slice(&l.to_le_bytes());
                out.extend_from_slice(data);
                (STATE_PROOF_SIG, out)
            }
        }
    }
}

/// `MerkleSignature`'s wire representation is considered zero (an unrevealed
/// slot) when every field is at its default — mirrors Go's generated
/// `MsgIsZero` for `merklesignature.Signature`.
fn merkle_signature_is_zero(sig: &MerkleSignature) -> bool {
    sig.signature.is_empty()
        && sig.vector_commitment_index == 0
        && sig.proof.is_none()
        && sig.verifying_key.is_none()
}

/// `buildCommittableSignature` — builds the fixed-length hashable leaf for
/// one revealed sigslot, or `Empty` for an unrevealed one.
fn build_committable_signature(
    pos: u64,
    l: u64,
    sig: Option<&MerkleSignature>,
) -> Result<CommittableSignatureSlot, StateProofError> {
    let Some(sig) = sig else {
        return Ok(CommittableSignatureSlot::Empty);
    };
    if merkle_signature_is_zero(sig) {
        return Ok(CommittableSignatureSlot::Empty);
    }
    if sig.signature.is_empty() {
        return Err(StateProofError::EmptyFalconSignature { pos });
    }

    let proof = convert_merkle_proof(sig.proof.as_ref())?;
    if proof.tree_depth as usize > merklearray::MAX_ENCODED_TREE_DEPTH {
        return Err(StateProofError::EncodedTreeDepthTooLarge {
            pos,
            depth: proof.tree_depth,
        });
    }

    let sig_ct = algo_falcon::falcon_convert_compressed_to_ct(&sig.signature).map_err(|e| {
        StateProofError::Falcon {
            pos,
            reason: e.to_string(),
        }
    })?;

    let verifying_key: &[u8] = sig
        .verifying_key
        .as_ref()
        .map(|k| k.public_key.as_slice())
        .unwrap_or(&[]);
    if verifying_key.len() != algo_falcon::FALCON_DET1024_PUBKEY_SIZE {
        return Err(StateProofError::InvalidFalconKeySize {
            pos,
            expected: algo_falcon::FALCON_DET1024_PUBKEY_SIZE,
            actual: verifying_key.len(),
        });
    }

    let single_leaf = SingleLeafProof { proof };
    let proof_bytes = single_leaf.get_fixed_length_hashable_representation();

    let mut data =
        Vec::with_capacity(2 + sig_ct.len() + verifying_key.len() + 8 + proof_bytes.len());
    data.extend_from_slice(&merklesig::CRYPTO_PRIMITIVES_ID.to_le_bytes());
    data.extend_from_slice(&sig_ct);
    data.extend_from_slice(verifying_key);
    data.extend_from_slice(&sig.vector_commitment_index.to_le_bytes());
    data.extend_from_slice(&proof_bytes);

    Ok(CommittableSignatureSlot::NonEmpty { l, data })
}

// ── Participant.ToBeHashed (data/basics/stateProofParticipant.go) ──────────

/// The `Hashable` leaf fed into the participants vector-commitment tree.
struct ParticipantHashable {
    weight: u64,
    key_lifetime: u64,
    commitment: [u8; 64],
}

impl Hashable for ParticipantHashable {
    fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
        let mut data = Vec::with_capacity(8 + 8 + 64);
        data.extend_from_slice(&self.weight.to_le_bytes());
        data.extend_from_slice(&self.key_lifetime.to_le_bytes());
        data.extend_from_slice(&self.commitment);
        (STATE_PROOF_PART, data)
    }
}

// ── Coin generator (crypto/stateproof/coinGenerator.go) ────────────────────

struct CoinChoiceSeed<'a> {
    part_commitment: &'a [u8],
    ln_proven_weight: u64,
    sig_commitment: &'a [u8],
    signed_weight: u64,
    data: &'a [u8; 32],
}

impl<'a> Hashable for CoinChoiceSeed<'a> {
    fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
        let mut bytes = Vec::with_capacity(
            1 + self.part_commitment.len() + 8 + self.sig_commitment.len() + 8 + self.data.len(),
        );
        bytes.push(VERSION_FOR_COIN_GENERATOR);
        bytes.extend_from_slice(self.part_commitment);
        bytes.extend_from_slice(&self.ln_proven_weight.to_le_bytes());
        bytes.extend_from_slice(self.sig_commitment);
        bytes.extend_from_slice(&self.signed_weight.to_le_bytes());
        bytes.extend_from_slice(self.data);
        (STATE_PROOF_COIN, bytes)
    }
}

/// `k = floor(2^64 / signedWeight)`; `threshold = k * signedWeight` — the
/// rejection-sampling threshold from `prepareRejectionSamplingThreshold`.
fn rejection_sampling_threshold(signed_weight: u64) -> u128 {
    let base: u128 = 1u128 << 64;
    let k = base / (signed_weight as u128);
    k * (signed_weight as u128)
}

struct CoinGenerator {
    reader: Box<dyn XofReader>,
    signed_weight: u64,
    threshold: u128,
}

impl CoinGenerator {
    fn new(choice: &CoinChoiceSeed<'_>) -> Self {
        let (prefix, data) = choice.to_be_hashed();
        let mut hasher = Shake256::default();
        Update::update(&mut hasher, prefix);
        Update::update(&mut hasher, &data);
        let reader: Box<dyn XofReader> = Box::new(hasher.finalize_xof());
        Self {
            reader,
            signed_weight: choice.signed_weight,
            threshold: rejection_sampling_threshold(choice.signed_weight),
        }
    }

    /// `getNextCoin` — draws 64 bits from the XOF, rejecting until below the
    /// threshold, then reduces mod `signedWeight` for a uniform coin.
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

// ── Per-reveal signature verification (reuses merklesig::Verifier) ─────────

fn convert_reveal_signature(
    pos: u64,
    sig: &MerkleSignature,
) -> Result<merklesig::Signature, StateProofError> {
    let proof = convert_merkle_proof(sig.proof.as_ref())?;
    let verifying_key_bytes: &[u8] = sig
        .verifying_key
        .as_ref()
        .map(|k| k.public_key.as_slice())
        .unwrap_or(&[]);
    if verifying_key_bytes.len() != algo_falcon::FALCON_DET1024_PUBKEY_SIZE {
        return Err(StateProofError::InvalidFalconKeySize {
            pos,
            expected: algo_falcon::FALCON_DET1024_PUBKEY_SIZE,
            actual: verifying_key_bytes.len(),
        });
    }
    let mut k = [0u8; algo_falcon::FALCON_DET1024_PUBKEY_SIZE];
    k.copy_from_slice(verifying_key_bytes);

    Ok(merklesig::Signature {
        signature: sig.signature.to_vec(),
        vector_commitment_index: sig.vector_commitment_index,
        proof: SingleLeafProof { proof },
        verifying_key: merklesig::FalconVerifier { k },
    })
}

/// Salt version embedded in a compressed-format Falcon signature. Mirrors
/// Go's pure-Go `falcon.CompressedSignature.SaltVersion()` — a signature too
/// short to carry one is malformed and defaults to `0` (still rejected later
/// by the Falcon verify step, this is purely for the salt-version check).
fn compressed_salt_version(sig: &[u8]) -> u8 {
    sig.get(1).copied().unwrap_or(0)
}

// ── Top-level Verify (crypto/stateproof/verifier.go: Verifier.Verify) ──────

/// Port of go-algorand's `Verifier.Verify(round, data, s)`.
///
/// `participants_commitment` and `proven_weight` are the verifier's trusted
/// data (`crypto.GenericDigest` root and `ln(provenWeight)`'s pre-image —
/// callers pass the raw proven weight, not its `ln` approximation, matching
/// `MkVerifier`). `round` and `message_hash` are `atRound`/`msg.Hash()` from
/// the state proof transaction being applied.
pub fn verify(
    participants_commitment: &[u8],
    proven_weight: u64,
    strength_target: u64,
    round: u64,
    message_hash: &[u8; 32],
    proof: &StateProofBody,
) -> Result<(), StateProofError> {
    // 1. verifyStateProofTreesDepth
    let sig_proof = convert_merkle_proof(proof.sig_proofs.as_ref())?;
    let part_proof = convert_merkle_proof(proof.part_proofs.as_ref())?;
    if sig_proof.tree_depth > MAX_TREE_DEPTH {
        return Err(StateProofError::TreeDepthTooLarge {
            which: "sigTree",
            depth: sig_proof.tree_depth,
        });
    }
    if part_proof.tree_depth > MAX_TREE_DEPTH {
        return Err(StateProofError::TreeDepthTooLarge {
            which: "partTree",
            depth: part_proof.tree_depth,
        });
    }

    // 2. verifyWeights
    let ln_proven_weight = ln_int_approximation(proven_weight)?;
    let positions: &[u64] = proof.positions_to_reveal.as_deref().unwrap_or(&[]);
    let nr = positions.len() as u64;
    verify_weights(proof.signed_weight, ln_proven_weight, nr, strength_target)?;

    let empty_reveals = std::collections::BTreeMap::new();
    let reveals: &std::collections::BTreeMap<u64, Reveal> =
        proof.reveals.as_ref().unwrap_or(&empty_reveals);

    // 3. Salt-version check + per-reveal Falcon signature verification +
    //    building the sig/participant commitment-tree leaves, over every
    //    revealed position (not just `positions_to_reveal` — matches Go's
    //    `for pos, r := range s.Reveals`).
    let mut sigs: Vec<(u64, CommittableSignatureSlot)> = Vec::with_capacity(reveals.len());
    let mut parts: Vec<(u64, ParticipantHashable)> = Vec::with_capacity(reveals.len());

    for (&pos, reveal) in reveals.iter() {
        let sig_slot = reveal
            .sig_slot
            .as_ref()
            .ok_or(StateProofError::MissingReveal { pos })?;
        let part = reveal
            .part
            .as_ref()
            .ok_or(StateProofError::MissingReveal { pos })?;
        let pk = part
            .pk
            .as_ref()
            .ok_or(StateProofError::MissingReveal { pos })?;

        if let Some(sig) = sig_slot.sig.as_ref() {
            if compressed_salt_version(&sig.signature) != proof.merkle_signature_salt_version {
                return Err(StateProofError::SaltVersionMismatch { pos });
            }

            let verifier = merklesig::Verifier {
                commitment: pk.commitment,
                key_lifetime: pk.key_lifetime,
            };
            let crypto_sig = convert_reveal_signature(pos, sig)?;
            verifier
                .verify_bytes(round, message_hash, &crypto_sig)
                .map_err(|e| StateProofError::SignatureVerificationFailed {
                    pos,
                    reason: e.to_string(),
                })?;
        }

        let committable = build_committable_signature(pos, sig_slot.l, sig_slot.sig.as_ref())?;
        sigs.push((pos, committable));
        parts.push((
            pos,
            ParticipantHashable {
                weight: part.weight,
                key_lifetime: pk.key_lifetime,
                commitment: pk.commitment,
            },
        ));
    }

    // 4. VerifyVectorCommitment(SigCommit, sigs, SigProofs)
    let sig_elems: Vec<(u64, &dyn Hashable)> =
        sigs.iter().map(|(p, s)| (*p, s as &dyn Hashable)).collect();
    merklearray::verify_vector_commitment(&proof.sig_commit.to_vec(), &sig_elems, &sig_proof)?;

    // 5. VerifyVectorCommitment(participants_commitment, parts, PartProofs)
    let part_elems: Vec<(u64, &dyn Hashable)> = parts
        .iter()
        .map(|(p, s)| (*p, s as &dyn Hashable))
        .collect();
    merklearray::verify_vector_commitment(
        &participants_commitment.to_vec(),
        &part_elems,
        &part_proof,
    )?;

    // 6. Coin-weight sampling — every revealed position must land in-range.
    let choice = CoinChoiceSeed {
        part_commitment: participants_commitment,
        ln_proven_weight,
        sig_commitment: &proof.sig_commit,
        signed_weight: proof.signed_weight,
        data: message_hash,
    };
    let mut coin_gen = CoinGenerator::new(&choice);
    for &pos in positions {
        let reveal = reveals
            .get(&pos)
            .ok_or(StateProofError::MissingReveal { pos })?;
        let sig_slot = reveal
            .sig_slot
            .as_ref()
            .ok_or(StateProofError::MissingReveal { pos })?;
        let part = reveal
            .part
            .as_ref()
            .ok_or(StateProofError::MissingReveal { pos })?;

        let coin = coin_gen.get_next_coin();
        if !(sig_slot.l <= coin && coin < sig_slot.l + part.weight) {
            return Err(StateProofError::CoinNotInRange { pos });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{
        FalconVerifier as WireFalconVerifier, MerkleSignatureVerifier, Participant, SigSlotCommit,
    };
    use serde_bytes::ByteBuf;
    use std::collections::BTreeMap;

    /// A single owned `(prefix, data)` pair, `Hashable` and cloneable, so it
    /// can back a tiny in-test `merklearray::Array` for tree construction.
    /// Owns the prefix too (rather than borrowing `'static` domain-prefix
    /// constants) since `Hashable::to_be_hashed`'s `&self`-tied lifetime
    /// can't be widened to `'static` at the call site.
    #[derive(Clone)]
    struct Leaf(Vec<u8>, Vec<u8>);

    impl Hashable for Leaf {
        fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
            (&self.0, self.1.clone())
        }
    }

    struct LeafArray(Vec<Leaf>);

    impl merklearray::Array for LeafArray {
        fn length(&self) -> u64 {
            self.0.len() as u64
        }
        fn marshal(&self, pos: u64) -> Result<Box<dyn Hashable>, MerkleError> {
            self.0
                .get(pos as usize)
                .map(|l| Box::new(l.clone()) as Box<dyn Hashable>)
                .ok_or(MerkleError::PosOutOfBound {
                    pos,
                    bound: self.0.len() as u64,
                })
        }
    }

    fn wire_merkle_proof(p: &Proof) -> MerkleProof {
        MerkleProof {
            path: Some(
                p.path
                    .iter()
                    .map(|d| Some(ByteBuf::from(d.clone())))
                    .collect(),
            ),
            hash_factory: Some(algo_types::HashFactory {
                hash_type: p.hash_factory.hash_type as u16,
            }),
            tree_depth: p.tree_depth,
        }
    }

    /// A minimal-but-real single-participant state proof: one genuine Falcon
    /// key, one genuine Falcon signature, two genuine (tiny) Merkle trees.
    ///
    /// `proven_weight = 1` (so `ln_proven_weight == 0`) and `strength_target
    /// = 0` are deliberately minimal — with a single reveal, a realistic
    /// strength target (256, matching `config/consensus.go`'s
    /// `v34.StateProofStrengthTarget`) would require hundreds of reveals to
    /// satisfy `verifyWeights`'s coupon-collector bound, which is what a real
    /// network state proof looks like but is impractical to hand-construct
    /// in a unit test. What's under test here — signature verification,
    /// both vector-commitment checks, and coin-weight sampling — doesn't
    /// depend on the reveal count being large; only `verify_weights`'s own
    /// bound does, and that bound is exercised separately in
    /// `test_verify_weights_rejects_insufficient_reveals`.
    struct Fixture {
        participants_commitment: Vec<u8>,
        proven_weight: u64,
        strength_target: u64,
        round: u64,
        message_hash: [u8; 32],
        proof: StateProofBody,
    }

    fn build_fixture() -> Fixture {
        let round = 100u64;
        let message_hash = [7u8; 32];

        // One ephemeral Falcon key valid at `round` (key_lifetime = 1 so
        // `first_round_in_key_lifetime(round, 1) == round`).
        let secrets = merklesig::Secrets::new(round, round, 1).expect("secrets");
        let verifier = secrets.get_verifier(); // { commitment, key_lifetime: 1 }
        let signer = secrets.get_signer(round);
        let sig = signer.sign_bytes(&message_hash).expect("sign_bytes");

        let weight = 100u64;

        // ── Participants tree (one leaf) ────────────────────────────
        let part_leaf = ParticipantHashable {
            weight,
            key_lifetime: verifier.key_lifetime,
            commitment: verifier.commitment,
        };
        let (prefix, data) = part_leaf.to_be_hashed();
        let part_array = LeafArray(vec![Leaf(prefix.to_vec(), data)]);
        let part_tree = merklearray::build_vector_commitment_tree(
            &part_array,
            merklearray::HashFactory::new(merklearray::HashType::Sumhash),
        )
        .expect("part tree");
        let participants_commitment = part_tree.root();
        let part_proof = part_tree.prove_single_leaf(0).expect("part proof");

        // ── Wire-level reveal (Participant + MerkleSignature) ───────
        let wire_verifying_key = WireFalconVerifier {
            public_key: ByteBuf::from(sig.verifying_key.k.to_vec()),
        };
        let wire_sig = MerkleSignature {
            signature: ByteBuf::from(sig.signature.clone()),
            vector_commitment_index: sig.vector_commitment_index,
            proof: Some(wire_merkle_proof(&sig.proof.proof)),
            verifying_key: Some(wire_verifying_key),
        };
        let wire_participant = Participant {
            pk: Some(MerkleSignatureVerifier {
                commitment: verifier.commitment,
                key_lifetime: verifier.key_lifetime,
            }),
            weight,
        };

        // ── Sig-commitment tree (one leaf, built from the SAME logic
        //    `verify()` itself uses via `build_committable_signature`) ──
        let committable = build_committable_signature(0, 0, Some(&wire_sig)).expect("committable");
        let (sig_prefix, sig_data) = committable.to_be_hashed();
        let sig_array = LeafArray(vec![Leaf(sig_prefix.to_vec(), sig_data)]);
        let sig_tree = merklearray::build_vector_commitment_tree(
            &sig_array,
            merklearray::HashFactory::new(merklearray::HashType::Sumhash),
        )
        .expect("sig tree");
        let sig_commit = sig_tree.root();
        let sig_proof = sig_tree.prove_single_leaf(0).expect("sig proof");

        let mut reveals = BTreeMap::new();
        reveals.insert(
            0u64,
            Reveal {
                sig_slot: Some(SigSlotCommit {
                    sig: Some(wire_sig),
                    l: 0,
                }),
                part: Some(wire_participant),
            },
        );

        let proof = StateProofBody {
            sig_commit: ByteBuf::from(sig_commit),
            signed_weight: weight,
            sig_proofs: Some(wire_merkle_proof(&sig_proof.proof)),
            part_proofs: Some(wire_merkle_proof(&part_proof.proof)),
            merkle_signature_salt_version: compressed_salt_version(&sig.signature),
            reveals: Some(reveals),
            positions_to_reveal: Some(vec![0]),
        };

        Fixture {
            participants_commitment,
            proven_weight: 1,
            strength_target: 0,
            round,
            message_hash,
            proof,
        }
    }

    #[test]
    fn test_valid_state_proof_verifies() {
        let f = build_fixture();
        let result = verify(
            &f.participants_commitment,
            f.proven_weight,
            f.strength_target,
            f.round,
            &f.message_hash,
            &f.proof,
        );
        assert!(
            result.is_ok(),
            "expected valid state proof to verify, got {:?}",
            result
        );
    }

    #[test]
    fn test_forged_signature_is_rejected() {
        let mut f = build_fixture();
        let reveal = f.proof.reveals.as_mut().unwrap().get_mut(&0).unwrap();
        let sig = reveal.sig_slot.as_mut().unwrap().sig.as_mut().unwrap();
        let mut forged = sig.signature.to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 0xFF; // flip bits in the Falcon signature itself
        sig.signature = ByteBuf::from(forged);

        let result = verify(
            &f.participants_commitment,
            f.proven_weight,
            f.strength_target,
            f.round,
            &f.message_hash,
            &f.proof,
        );
        assert!(
            matches!(
                result,
                Err(StateProofError::SignatureVerificationFailed { .. })
            ),
            "expected signature verification failure, got {:?}",
            result
        );
    }

    #[test]
    fn test_wrong_message_hash_is_rejected() {
        let f = build_fixture();
        let wrong_hash = [9u8; 32];
        let result = verify(
            &f.participants_commitment,
            f.proven_weight,
            f.strength_target,
            f.round,
            &wrong_hash,
            &f.proof,
        );
        assert!(
            matches!(
                result,
                Err(StateProofError::SignatureVerificationFailed { .. })
            ),
            "expected signature verification failure for wrong message, got {:?}",
            result
        );
    }

    #[test]
    fn test_corrupted_sig_merkle_proof_is_rejected() {
        let mut f = build_fixture();
        let sig_proofs = f.proof.sig_proofs.as_mut().unwrap();
        if let Some(path) = sig_proofs.path.as_mut() {
            if let Some(Some(first)) = path.first_mut() {
                let mut bytes = first.to_vec();
                if !bytes.is_empty() {
                    bytes[0] ^= 0xFF;
                    *first = ByteBuf::from(bytes);
                }
            }
        }
        // A single-leaf tree has an empty proof path; corrupt the commitment
        // itself instead so the test still exercises a real mismatch.
        let mut commit = f.proof.sig_commit.to_vec();
        commit[0] ^= 0xFF;
        f.proof.sig_commit = ByteBuf::from(commit);

        let result = verify(
            &f.participants_commitment,
            f.proven_weight,
            f.strength_target,
            f.round,
            &f.message_hash,
            &f.proof,
        );
        assert!(
            matches!(
                result,
                Err(StateProofError::Merkle(MerkleError::RootMismatch))
            ),
            "expected a Merkle root mismatch, got {:?}",
            result
        );
    }

    #[test]
    fn test_corrupted_participants_commitment_is_rejected() {
        let f = build_fixture();
        let mut bad_commitment = f.participants_commitment.clone();
        bad_commitment[0] ^= 0xFF;

        let result = verify(
            &bad_commitment,
            f.proven_weight,
            f.strength_target,
            f.round,
            &f.message_hash,
            &f.proof,
        );
        assert!(
            matches!(
                result,
                Err(StateProofError::Merkle(MerkleError::RootMismatch))
            ),
            "expected a Merkle root mismatch, got {:?}",
            result
        );
    }

    #[test]
    fn test_tree_depth_exceeding_max_is_rejected() {
        let mut f = build_fixture();
        f.proof.sig_proofs.as_mut().unwrap().tree_depth = MAX_TREE_DEPTH + 1;

        let result = verify(
            &f.participants_commitment,
            f.proven_weight,
            f.strength_target,
            f.round,
            &f.message_hash,
            &f.proof,
        );
        assert!(
            matches!(
                result,
                Err(StateProofError::TreeDepthTooLarge {
                    which: "sigTree",
                    ..
                })
            ),
            "expected sigTree depth rejection, got {:?}",
            result
        );
    }

    #[test]
    fn test_verify_weights_rejects_insufficient_reveals() {
        // Realistic security target (256, matching go's
        // v34.StateProofStrengthTarget) with only one reveal must fail —
        // this is the coupon-collector bound `verify_weights` enforces,
        // deliberately relaxed to 0 in the main fixture above for
        // tractability. A forged proof cannot route around this by simply
        // omitting reveals.
        let f = build_fixture();
        let result = verify(
            &f.participants_commitment,
            f.proven_weight,
            256,
            f.round,
            &f.message_hash,
            &f.proof,
        );
        assert!(
            matches!(result, Err(StateProofError::InsufficientSignedWeight)),
            "expected insufficient-weight rejection at realistic strength target, got {:?}",
            result
        );
    }

    #[test]
    fn test_verify_weights_zero_signed_weight_rejected() {
        let err = verify_weights(0, 0, 1, 0).unwrap_err();
        assert!(matches!(err, StateProofError::ZeroSignedWeight));
    }

    #[test]
    fn test_verify_weights_too_many_reveals_rejected() {
        let err = verify_weights(100, 0, MAX_REVEALS + 1, 0).unwrap_err();
        assert!(matches!(err, StateProofError::TooManyReveals));
    }

    #[test]
    fn test_ln_int_approximation_basic() {
        // ln(1) == 0 exactly.
        assert_eq!(ln_int_approximation(1).unwrap(), 0);
        // ln(0) is illegal.
        assert!(matches!(
            ln_int_approximation(0),
            Err(StateProofError::IllegalLnInput)
        ));
        // ln(2) * 2^16, ceil'd, is exactly `ln2IntApproximation` from
        // crypto/stateproof/const.go — the same constant `verify_weights`
        // hardcodes, so this doubles as a cross-check that the two don't
        // drift apart.
        assert_eq!(ln_int_approximation(2).unwrap(), LN2_INT_APPROXIMATION);
    }

    #[test]
    fn test_missing_reveal_for_declared_position_is_rejected() {
        let mut f = build_fixture();
        f.proof.positions_to_reveal = Some(vec![0, 1]); // position 1 was never revealed
        let result = verify(
            &f.participants_commitment,
            f.proven_weight,
            f.strength_target,
            f.round,
            &f.message_hash,
            &f.proof,
        );
        assert!(
            matches!(result, Err(StateProofError::MissingReveal { pos: 1 })),
            "expected missing-reveal rejection, got {:?}",
            result
        );
    }
}
