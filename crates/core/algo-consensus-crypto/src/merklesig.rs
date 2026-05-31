//! Merkle signature scheme types, operations, and round-to-index arithmetic.
//!
//! Implements the type definitions, canonical msgpack serialization,
//! round-index arithmetic, key generation, signing, and verification from
//! go-algorand's `crypto/merklesignature/` package.
//!
//! # Domain Separation
//!
//! - `"KP"` — `KeyRoundPair` hashable representation (`CommittablePublicKey`)
//!
//! # Constants
//!
//! - `MERKLE_SIGNATURE_SCHEME_ROOT_SIZE = 64` (SumhashDigestSize)
//! - `CRYPTO_PRIMITIVES_ID = 0` (subset-sum hash + falcon)
//! - `KEY_LIFETIME_DEFAULT = 256`

use algo_falcon::{FALCON_DET1024_PRIVKEY_SIZE, FALCON_DET1024_PUBKEY_SIZE};
use zeroize::Zeroize;

use crate::merklearray;

// ── Constants ──────────────────────────────────────────────────────────────

/// Size of the merkle signature scheme root (matches `crypto.SumhashDigestSize = 64`).
pub const MERKLE_SIGNATURE_SCHEME_ROOT_SIZE: usize = 64;

/// Default key lifetime in rounds.
pub const KEY_LIFETIME_DEFAULT: u64 = 256;

/// Identifies the cryptographic primitives used: subset-sum hash + falcon.
pub const CRYPTO_PRIMITIVES_ID: u16 = 0;

/// Domain separation prefix for `CommittablePublicKey` (Go: `protocol.KeysInMSS = "KP"`).
pub const KEYS_IN_MSS: &[u8] = b"KP";

// ── Commitment ─────────────────────────────────────────────────────────────

/// Root of the vector commitment tree built on the MSS ephemeral keys.
///
/// A 64-byte sumhash digest.
pub type Commitment = [u8; MERKLE_SIGNATURE_SCHEME_ROOT_SIZE];

/// Returns `true` if the commitment is all zeros.
pub fn commitment_is_empty(c: &Commitment) -> bool {
    *c == [0u8; MERKLE_SIGNATURE_SCHEME_ROOT_SIZE]
}

// ── FalconSigner ───────────────────────────────────────────────────────────

/// Wrapper around raw Falcon-1024 key bytes for serialization.
///
/// Distinct from the FFI functions in `algo-falcon` — this holds the raw bytes
/// and provides canonical msgpack encoding matching Go's `crypto.FalconSigner`.
///
/// Codec tags: `"pk"` (public key), `"sk"` (private key).
#[derive(Debug, Clone)]
pub struct FalconSigner {
    /// Falcon-1024 public key (1793 bytes).
    pub pk: [u8; FALCON_DET1024_PUBKEY_SIZE],
    /// Falcon-1024 private key (2305 bytes).
    pub sk: [u8; FALCON_DET1024_PRIVKEY_SIZE],
}

impl Default for FalconSigner {
    fn default() -> Self {
        Self {
            pk: [0u8; FALCON_DET1024_PUBKEY_SIZE],
            sk: [0u8; FALCON_DET1024_PRIVKEY_SIZE],
        }
    }
}

impl Drop for FalconSigner {
    fn drop(&mut self) {
        self.sk.zeroize();
    }
}

impl FalconSigner {
    /// Returns `true` if both pk and sk are all zeros.
    pub fn is_zero(&self) -> bool {
        self.pk.iter().all(|&b| b == 0) && self.sk.iter().all(|&b| b == 0)
    }

    /// Get the verifying key (public key wrapper).
    pub fn get_verifying_key(&self) -> FalconVerifier {
        FalconVerifier { k: self.pk }
    }

    /// Encode to canonical msgpack.
    ///
    /// Go field order (alphabetical, omitempty): `"pk"`, `"sk"`.
    pub fn to_msgpack(&self) -> Vec<u8> {
        let pk_zero = self.pk.iter().all(|&b| b == 0);
        let sk_zero = self.sk.iter().all(|&b| b == 0);

        let mut field_count: u8 = 0;
        if !pk_zero {
            field_count += 1;
        }
        if !sk_zero {
            field_count += 1;
        }

        let mut buf = Vec::with_capacity(4200);
        buf.push(0x80 | field_count);

        if !pk_zero {
            // "pk"
            write_fixstr(&mut buf, "pk");
            rmp::encode::write_bin(&mut buf, &self.pk).unwrap();
        }
        if !sk_zero {
            // "sk"
            write_fixstr(&mut buf, "sk");
            rmp::encode::write_bin(&mut buf, &self.sk).unwrap();
        }

        buf
    }

    /// Decode from canonical msgpack.
    pub fn from_msgpack(data: &[u8]) -> Result<(Self, &[u8]), String> {
        let (map_len, mut cur) =
            read_map_header(data).map_err(|e| format!("FalconSigner map header: {e}"))?;

        let mut result = FalconSigner::default();

        for _ in 0..map_len {
            let (key, rest) = read_str(cur).map_err(|e| format!("FalconSigner field key: {e}"))?;
            cur = rest;

            match key {
                "pk" => {
                    let (val, rest) = read_bin(cur).map_err(|e| format!("FalconSigner pk: {e}"))?;
                    if val.len() != FALCON_DET1024_PUBKEY_SIZE {
                        return Err(format!(
                            "FalconSigner pk: expected {} bytes, got {}",
                            FALCON_DET1024_PUBKEY_SIZE,
                            val.len()
                        ));
                    }
                    result.pk.copy_from_slice(val);
                    cur = rest;
                }
                "sk" => {
                    let (val, rest) = read_bin(cur).map_err(|e| format!("FalconSigner sk: {e}"))?;
                    if val.len() != FALCON_DET1024_PRIVKEY_SIZE {
                        return Err(format!(
                            "FalconSigner sk: expected {} bytes, got {}",
                            FALCON_DET1024_PRIVKEY_SIZE,
                            val.len()
                        ));
                    }
                    result.sk.copy_from_slice(val);
                    cur = rest;
                }
                _ => {
                    cur = skip_msgpack_value(cur)
                        .map_err(|e| format!("FalconSigner skip '{key}': {e}"))?;
                }
            }
        }

        Ok((result, cur))
    }
}

/// Decode a `StateProofKeys` wire body (`[]KeyRoundPair`) into a vector of
/// `(round, FalconSigner)` pairs.
///
/// Matches go-algorand's `account.StateProofKeys` = `[]merklesignature.KeyRoundPair`
/// where each pair is `{rnd: uint64, key: *crypto.FalconSigner}`
/// (`crypto/merklesignature/merkleSignatureScheme.go:88`). This is the body
/// POSTed to `/v2/participation/{id}` (AppendKeys); the algod handler decodes
/// it with `protocol.NewDecoder(...).Decode(&keys)`
/// (`daemon/algod/api/server/v2/handlers.go:378`).
///
/// Unknown map fields are skipped (forward-compat with go's canonical encoder,
/// which omits empty fields). A missing `key` yields a default (all-zero)
/// signer for that pair.
pub fn decode_state_proof_keys(data: &[u8]) -> Result<Vec<(u64, FalconSigner)>, String> {
    let (count, mut cur) =
        read_array_header(data).map_err(|e| format!("StateProofKeys array header: {e}"))?;

    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (map_len, rest) =
            read_map_header(cur).map_err(|e| format!("KeyRoundPair map header: {e}"))?;
        cur = rest;

        let mut round: u64 = 0;
        let mut key = FalconSigner::default();
        for _ in 0..map_len {
            let (field, rest) =
                read_str(cur).map_err(|e| format!("KeyRoundPair field key: {e}"))?;
            cur = rest;
            match field {
                "rnd" => {
                    let (r, rest) =
                        read_uint64(cur).map_err(|e| format!("KeyRoundPair rnd: {e}"))?;
                    round = r;
                    cur = rest;
                }
                "key" => {
                    let (signer, rest) = FalconSigner::from_msgpack(cur)
                        .map_err(|e| format!("KeyRoundPair key: {e}"))?;
                    key = signer;
                    cur = rest;
                }
                _ => {
                    cur = skip_msgpack_value(cur)
                        .map_err(|e| format!("KeyRoundPair skip '{field}': {e}"))?;
                }
            }
        }
        out.push((round, key));
    }
    Ok(out)
}

// ── FalconVerifier ─────────────────────────────────────────────────────────

/// Wrapper around a Falcon-1024 public key for verification and serialization.
///
/// Distinct from the FFI in `algo-falcon`. Codec tag: `"k"`.
#[derive(Debug, Clone)]
pub struct FalconVerifier {
    /// Falcon-1024 public key (1793 bytes).
    pub k: [u8; FALCON_DET1024_PUBKEY_SIZE],
}

impl Default for FalconVerifier {
    fn default() -> Self {
        Self {
            k: [0u8; FALCON_DET1024_PUBKEY_SIZE],
        }
    }
}

impl FalconVerifier {
    /// Returns `true` if the public key is all zeros.
    pub fn is_zero(&self) -> bool {
        self.k.iter().all(|&b| b == 0)
    }

    /// Returns the raw public key bytes (for hashing).
    pub fn get_fixed_length_hashable_representation(&self) -> &[u8] {
        &self.k
    }

    /// Encode to canonical msgpack.
    ///
    /// Go field order (omitempty): `"k"`.
    pub fn to_msgpack(&self) -> Vec<u8> {
        let k_zero = self.is_zero();

        let mut field_count: u8 = 0;
        if !k_zero {
            field_count += 1;
        }

        let mut buf = Vec::with_capacity(1800);
        buf.push(0x80 | field_count);

        if !k_zero {
            // "k"
            write_fixstr(&mut buf, "k");
            rmp::encode::write_bin(&mut buf, &self.k).unwrap();
        }

        buf
    }

    /// Decode from canonical msgpack.
    pub fn from_msgpack(data: &[u8]) -> Result<(Self, &[u8]), String> {
        let (map_len, mut cur) =
            read_map_header(data).map_err(|e| format!("FalconVerifier map header: {e}"))?;

        let mut result = FalconVerifier::default();

        for _ in 0..map_len {
            let (key, rest) =
                read_str(cur).map_err(|e| format!("FalconVerifier field key: {e}"))?;
            cur = rest;

            match key {
                "k" => {
                    let (val, rest) =
                        read_bin(cur).map_err(|e| format!("FalconVerifier k: {e}"))?;
                    if val.len() != FALCON_DET1024_PUBKEY_SIZE {
                        return Err(format!(
                            "FalconVerifier k: expected {} bytes, got {}",
                            FALCON_DET1024_PUBKEY_SIZE,
                            val.len()
                        ));
                    }
                    result.k.copy_from_slice(val);
                    cur = rest;
                }
                _ => {
                    cur = skip_msgpack_value(cur)
                        .map_err(|e| format!("FalconVerifier skip '{key}': {e}"))?;
                }
            }
        }

        Ok((result, cur))
    }
}

// ── Verifier ───────────────────────────────────────────────────────────────

/// Used to verify a `Signature` produced by `Secrets`.
///
/// Contains the merkle tree root commitment and the key lifetime.
/// Codec tags: `"cmt"`, `"lf"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verifier {
    /// Root of the vector commitment tree.
    pub commitment: Commitment,
    /// Key lifetime in rounds.
    pub key_lifetime: u64,
}

impl Default for Verifier {
    fn default() -> Self {
        Self {
            commitment: [0u8; MERKLE_SIGNATURE_SCHEME_ROOT_SIZE],
            key_lifetime: 0,
        }
    }
}

impl Verifier {
    /// Returns `true` if all fields are zero.
    pub fn is_zero(&self) -> bool {
        commitment_is_empty(&self.commitment) && self.key_lifetime == 0
    }

    /// Calculate the first round in the key lifetime for a given round.
    pub fn first_round_in_key_lifetime(&self, round: u64) -> Result<u64, &'static str> {
        if self.key_lifetime == 0 {
            return Err("key lifetime is zero");
        }
        Ok(first_round_in_key_lifetime(round, self.key_lifetime))
    }

    /// Encode to canonical msgpack.
    ///
    /// Go field order (alphabetical, omitempty): `"cmt"`, `"lf"`.
    pub fn to_msgpack(&self) -> Vec<u8> {
        let cmt_zero = commitment_is_empty(&self.commitment);
        let lf_zero = self.key_lifetime == 0;

        let mut field_count: u8 = 0;
        if !cmt_zero {
            field_count += 1;
        }
        if !lf_zero {
            field_count += 1;
        }

        let mut buf = Vec::with_capacity(80);
        buf.push(0x80 | field_count);

        if !cmt_zero {
            // "cmt"
            write_fixstr(&mut buf, "cmt");
            rmp::encode::write_bin(&mut buf, &self.commitment).unwrap();
        }
        if !lf_zero {
            // "lf"
            write_fixstr(&mut buf, "lf");
            rmp::encode::write_uint(&mut buf, self.key_lifetime).unwrap();
        }

        buf
    }

    /// Decode from canonical msgpack.
    pub fn from_msgpack(data: &[u8]) -> Result<(Self, &[u8]), String> {
        let (map_len, mut cur) =
            read_map_header(data).map_err(|e| format!("Verifier map header: {e}"))?;

        let mut result = Verifier::default();

        for _ in 0..map_len {
            let (key, rest) = read_str(cur).map_err(|e| format!("Verifier field key: {e}"))?;
            cur = rest;

            match key {
                "cmt" => {
                    let (val, rest) = read_bin(cur).map_err(|e| format!("Verifier cmt: {e}"))?;
                    if val.len() != MERKLE_SIGNATURE_SCHEME_ROOT_SIZE {
                        return Err(format!(
                            "Verifier cmt: expected {} bytes, got {}",
                            MERKLE_SIGNATURE_SCHEME_ROOT_SIZE,
                            val.len()
                        ));
                    }
                    result.commitment.copy_from_slice(val);
                    cur = rest;
                }
                "lf" => {
                    let (val, rest) = read_uint64(cur).map_err(|e| format!("Verifier lf: {e}"))?;
                    result.key_lifetime = val;
                    cur = rest;
                }
                _ => {
                    cur = skip_msgpack_value(cur)
                        .map_err(|e| format!("Verifier skip '{key}': {e}"))?;
                }
            }
        }

        Ok((result, cur))
    }

    /// Verify a merkle signature for the given round and message.
    ///
    /// Matches Go's `Verifier.VerifyBytes()`.
    pub fn verify_bytes(
        &self,
        round: u64,
        msg: &[u8],
        sig: &Signature,
    ) -> Result<(), MerkleSignatureError> {
        if self.key_lifetime == 0 {
            return Err(MerkleSignatureError::KeyLifetimeIsZero);
        }

        let valid_key_round = first_round_in_key_lifetime(round, self.key_lifetime);

        // Build the ephemeral key leaf for merkle verification.
        let ephkey = KeyRoundPair {
            round: valid_key_round,
            key: sig.verifying_key.clone(),
        };

        // Verify the merkle tree verification path.
        merklearray::verify_vector_commitment(
            &self.commitment.to_vec(),
            &[(
                sig.vector_commitment_index,
                &ephkey as &dyn merklearray::Hashable,
            )],
            &sig.proof.proof,
        )
        .map_err(|e| MerkleSignatureError::VerificationFailed(e.to_string()))?;

        // Verify the falcon signature.
        let result = algo_falcon::falcon_verify(&sig.verifying_key.k, &sig.signature, msg)
            .map_err(|e| MerkleSignatureError::FalconError(e.to_string()))?;

        if !result {
            return Err(MerkleSignatureError::VerificationFailed(
                "falcon signature verification failed".to_string(),
            ));
        }

        Ok(())
    }
}

// ── Signature ──────────────────────────────────────────────────────────────

/// A signature in the merkle signature scheme.
///
/// Consists of a falcon signature, a vector commitment index, a merkle proof,
/// and the ephemeral verifying key.
///
/// Codec tags: `"sig"`, `"idx"`, `"prf"`, `"vkey"`.
#[derive(Debug, Clone, Default)]
pub struct Signature {
    /// Falcon signature bytes (variable-length compressed format).
    pub signature: Vec<u8>,
    /// Index in the vector commitment tree.
    pub vector_commitment_index: u64,
    /// Merkle proof for this key's position in the tree.
    pub proof: merklearray::SingleLeafProof,
    /// The ephemeral public key used for this signature.
    pub verifying_key: FalconVerifier,
}

impl Signature {
    /// Returns `true` if all fields are zero/empty.
    pub fn is_zero(&self) -> bool {
        self.signature.is_empty()
            && self.vector_commitment_index == 0
            && self.proof == merklearray::SingleLeafProof::default()
            && self.verifying_key.is_zero()
    }

    /// Encode to canonical msgpack.
    ///
    /// Go field order (alphabetical, omitempty): `"idx"`, `"prf"`, `"sig"`, `"vkey"`.
    pub fn to_msgpack(&self) -> Vec<u8> {
        let idx_zero = self.vector_commitment_index == 0;
        let prf_zero = self.proof == merklearray::SingleLeafProof::default();
        let sig_zero = self.signature.is_empty();
        let vkey_zero = self.verifying_key.is_zero();

        let mut field_count: u8 = 0;
        if !idx_zero {
            field_count += 1;
        }
        if !prf_zero {
            field_count += 1;
        }
        if !sig_zero {
            field_count += 1;
        }
        if !vkey_zero {
            field_count += 1;
        }

        let mut buf = Vec::with_capacity(2048);
        buf.push(0x80 | field_count);

        if !idx_zero {
            // "idx"
            write_fixstr(&mut buf, "idx");
            rmp::encode::write_uint(&mut buf, self.vector_commitment_index).unwrap();
        }
        if !prf_zero {
            // "prf" — SingleLeafProof serialized inline as msgpack map
            write_fixstr(&mut buf, "prf");
            buf.extend_from_slice(&self.proof.encode_msgpack());
        }
        if !sig_zero {
            // "sig" — FalconSignature serialized as bin
            write_fixstr(&mut buf, "sig");
            rmp::encode::write_bin(&mut buf, &self.signature).unwrap();
        }
        if !vkey_zero {
            // "vkey" — FalconVerifier serialized inline
            write_fixstr(&mut buf, "vkey");
            buf.extend_from_slice(&self.verifying_key.to_msgpack());
        }

        buf
    }

    /// Decode from canonical msgpack.
    pub fn from_msgpack(data: &[u8]) -> Result<(Self, &[u8]), String> {
        let (map_len, mut cur) =
            read_map_header(data).map_err(|e| format!("Signature map header: {e}"))?;

        let mut result = Signature::default();

        for _ in 0..map_len {
            let (key, rest) = read_str(cur).map_err(|e| format!("Signature field key: {e}"))?;
            cur = rest;

            match key {
                "idx" => {
                    let (val, rest) =
                        read_uint64(cur).map_err(|e| format!("Signature idx: {e}"))?;
                    result.vector_commitment_index = val;
                    cur = rest;
                }
                "prf" => {
                    let (proof, consumed) = merklearray::SingleLeafProof::decode_msgpack(cur)
                        .map_err(|e| format!("Signature prf: {e}"))?;
                    result.proof = proof;
                    cur = &cur[consumed..];
                }
                "sig" => {
                    let (val, rest) = read_bin(cur).map_err(|e| format!("Signature sig: {e}"))?;
                    result.signature = val.to_vec();
                    cur = rest;
                }
                "vkey" => {
                    let (vk, rest) = FalconVerifier::from_msgpack(cur)
                        .map_err(|e| format!("Signature vkey: {e}"))?;
                    result.verifying_key = vk;
                    cur = rest;
                }
                _ => {
                    cur = skip_msgpack_value(cur)
                        .map_err(|e| format!("Signature skip '{key}': {e}"))?;
                }
            }
        }

        Ok((result, cur))
    }
}

// ── SignerContext ───────────────────────────────────────────────────────────

/// Immutable data and metadata for a merkle signature scheme key set.
///
/// Contains the first valid round, key lifetime, and the merkle tree.
///
/// Codec tags: `"fv"`, `"iv"`, `"tree"`.
#[derive(Debug, Clone, Default)]
pub struct SignerContext {
    /// First valid round for this key set.
    pub first_valid: u64,
    /// Key lifetime in rounds.
    pub key_lifetime: u64,
    /// The vector commitment tree over ephemeral keys.
    pub tree: merklearray::Tree,
}

impl SignerContext {
    /// Returns `true` if all fields are zero/empty.
    pub fn is_zero(&self) -> bool {
        self.first_valid == 0
            && self.key_lifetime == 0
            && self.tree.levels.is_empty()
            && self.tree.num_of_elements == 0
    }

    /// Get a `Verifier` from this context.
    ///
    /// Extracts the tree root as the commitment.
    pub fn get_verifier(&self) -> Verifier {
        let root = self.tree.root();
        let mut commitment = [0u8; MERKLE_SIGNATURE_SCHEME_ROOT_SIZE];
        let len = root.len().min(MERKLE_SIGNATURE_SCHEME_ROOT_SIZE);
        commitment[..len].copy_from_slice(&root[..len]);
        Verifier {
            commitment,
            key_lifetime: self.key_lifetime,
        }
    }

    /// Encode to canonical msgpack.
    ///
    /// Go field order (alphabetical, omitempty): `"fv"`, `"iv"`, `"tree"`.
    pub fn to_msgpack(&self) -> Vec<u8> {
        let fv_zero = self.first_valid == 0;
        let iv_zero = self.key_lifetime == 0;
        let tree_zero = self.tree.levels.is_empty()
            && self.tree.num_of_elements == 0
            && self.tree.hash.is_zero()
            && !self.tree.is_vector_commitment;

        let mut field_count: u8 = 0;
        if !fv_zero {
            field_count += 1;
        }
        if !iv_zero {
            field_count += 1;
        }
        if !tree_zero {
            field_count += 1;
        }

        let mut buf = Vec::with_capacity(64);
        buf.push(0x80 | field_count);

        if !fv_zero {
            // "fv"
            write_fixstr(&mut buf, "fv");
            rmp::encode::write_uint(&mut buf, self.first_valid).unwrap();
        }
        if !iv_zero {
            // "iv"
            write_fixstr(&mut buf, "iv");
            rmp::encode::write_uint(&mut buf, self.key_lifetime).unwrap();
        }
        if !tree_zero {
            // "tree" — Tree serialized inline as msgpack map
            write_fixstr(&mut buf, "tree");
            buf.extend_from_slice(&self.tree.encode_msgpack());
        }

        buf
    }

    /// Decode from canonical msgpack.
    pub fn from_msgpack(data: &[u8]) -> Result<(Self, &[u8]), String> {
        let (map_len, mut cur) =
            read_map_header(data).map_err(|e| format!("SignerContext map header: {e}"))?;

        let mut result = SignerContext::default();

        for _ in 0..map_len {
            let (key, rest) = read_str(cur).map_err(|e| format!("SignerContext field key: {e}"))?;
            cur = rest;

            match key {
                "fv" => {
                    let (val, rest) =
                        read_uint64(cur).map_err(|e| format!("SignerContext fv: {e}"))?;
                    result.first_valid = val;
                    cur = rest;
                }
                "iv" => {
                    let (val, rest) =
                        read_uint64(cur).map_err(|e| format!("SignerContext iv: {e}"))?;
                    result.key_lifetime = val;
                    cur = rest;
                }
                "tree" => {
                    let (tree, consumed) = merklearray::Tree::decode_msgpack(cur)
                        .map_err(|e| format!("SignerContext tree: {e}"))?;
                    result.tree = tree;
                    cur = &cur[consumed..];
                }
                _ => {
                    cur = skip_msgpack_value(cur)
                        .map_err(|e| format!("SignerContext skip '{key}': {e}"))?;
                }
            }
        }

        Ok((result, cur))
    }
}

// ── Secrets ────────────────────────────────────────────────────────────────

/// Private data for the merkle signature scheme.
///
/// Contains the `SignerContext` (serialized) and ephemeral keys (not serialized).
/// Go's `Secrets.MarshalMsg` serializes only the embedded `SignerContext` fields;
/// `ephemeralKeys` are stored separately via SQLite.
#[derive(Debug, Clone, Default)]
pub struct Secrets {
    /// Ephemeral falcon signing keys — NOT serialized.
    pub ephemeral_keys: Vec<FalconSigner>,
    /// Immutable context (first_valid, key_lifetime, tree).
    pub signer_context: SignerContext,
    /// Index offset of the first element in `ephemeral_keys` relative to
    /// the original dense key array (i.e. the array starting at the
    /// `round_to_index(first_valid, …)` zero position).
    ///
    /// After forward-secure deletion / pruning of early-round keys from
    /// the database, restored keys start at a later index.  This offset
    /// lets `get_key()` translate a round-based index to the correct
    /// position in the (now shorter) vector without padding with dummy
    /// entries.
    ///
    /// Default is `0` (no pruning).
    pub first_key_offset: u64,
}

/// Error type for merkle signature scheme operations.
#[derive(Debug)]
pub enum MerkleSignatureError {
    /// End round is smaller than start round.
    StartBiggerThanEndRound,
    /// Key lifetime must not be zero.
    KeyLifetimeIsZero,
    /// No state proof key exists for this round.
    NoStateProofKeyForRound,
    /// Merkle signature verification failed.
    VerificationFailed(String),
    /// Falcon error.
    FalconError(String),
    /// Merkle tree error.
    TreeError(merklearray::MerkleError),
    /// Invalid round.
    InvalidRound(String),
}

impl std::fmt::Display for MerkleSignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StartBiggerThanEndRound => write!(f, "end round is smaller than start round"),
            Self::KeyLifetimeIsZero => write!(f, "key lifetime is zero"),
            Self::NoStateProofKeyForRound => write!(f, "no stateproof key for this round"),
            Self::VerificationFailed(msg) => {
                write!(f, "merkle signature verification failed: {msg}")
            }
            Self::FalconError(msg) => write!(f, "falcon error: {msg}"),
            Self::TreeError(e) => write!(f, "merkle tree error: {e}"),
            Self::InvalidRound(msg) => write!(f, "invalid round: {msg}"),
        }
    }
}

impl std::error::Error for MerkleSignatureError {}

impl Secrets {
    /// Create new secrets for the merkle signature scheme.
    ///
    /// Generates one Falcon key for each round within [first_valid, last_valid]
    /// where round % key_lifetime == 0.
    ///
    /// Matches Go's `merklesignature.New()`.
    pub fn new(
        first_valid: u64,
        last_valid: u64,
        key_lifetime: u64,
    ) -> Result<Self, MerkleSignatureError> {
        if first_valid > last_valid {
            return Err(MerkleSignatureError::StartBiggerThanEndRound);
        }
        if key_lifetime == 0 {
            return Err(MerkleSignatureError::KeyLifetimeIsZero);
        }

        let number_of_keys = num_keys(first_valid, last_valid, key_lifetime);

        // Generate Falcon key pairs.
        let mut keys = Vec::with_capacity(number_of_keys as usize);
        for _ in 0..number_of_keys {
            let mut seed = [0u8; algo_falcon::FALCON_SEED_SIZE];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);

            let (pubkey, privkey) = algo_falcon::falcon_keygen(&seed)
                .map_err(|e| MerkleSignatureError::FalconError(e.to_string()))?;

            let mut signer = FalconSigner::default();
            signer.pk.copy_from_slice(&pubkey);
            signer.sk.copy_from_slice(&privkey);
            keys.push(signer);
        }

        // Build the vector commitment tree over KeyRoundPair leaves.
        let committable_array = CommittablePublicKeyArray {
            keys: &keys,
            first_valid,
            key_lifetime,
        };

        let factory = merklearray::HashFactory::new(merklearray::HashType::Sumhash);
        let tree = merklearray::build_vector_commitment_tree(&committable_array, factory)
            .map_err(MerkleSignatureError::TreeError)?;

        Ok(Secrets {
            ephemeral_keys: keys,
            signer_context: SignerContext {
                first_valid,
                key_lifetime,
                tree,
            },
            first_key_offset: 0,
        })
    }

    /// Get a `Verifier` from this secrets.
    pub fn get_verifier(&self) -> Verifier {
        self.signer_context.get_verifier()
    }

    /// Get a `Signer` for the specified round.
    ///
    /// Matches Go's `Secrets.GetSigner()`.
    pub fn get_signer(&self, round: u64) -> Signer<'_> {
        Signer {
            signing_key: self.get_key(round),
            round,
            signer_context: &self.signer_context,
        }
    }

    /// Encode to canonical msgpack.
    ///
    /// Serializes only the `SignerContext` fields (matching Go's behavior).
    pub fn to_msgpack(&self) -> Vec<u8> {
        self.signer_context.to_msgpack()
    }

    /// Decode from canonical msgpack.
    ///
    /// The `ephemeral_keys` field will be empty after deserialization.
    pub fn from_msgpack(data: &[u8]) -> Result<(Self, &[u8]), String> {
        let (ctx, rest) = SignerContext::from_msgpack(data)?;
        Ok((
            Secrets {
                ephemeral_keys: Vec::new(),
                signer_context: ctx,
                first_key_offset: 0,
            },
            rest,
        ))
    }

    /// Get the signing key for a given round.
    ///
    /// Accounts for `first_key_offset`: after forward-secure pruning the
    /// vector may start at a later index than 0, so the absolute index
    /// produced by `round_to_index` is adjusted by the offset.
    pub fn get_key(&self, round: u64) -> Option<&FalconSigner> {
        if self.signer_context.key_lifetime == 0 {
            return None;
        }
        let key_round = first_round_in_key_lifetime(round, self.signer_context.key_lifetime);
        let idx = round_to_index(
            self.signer_context.first_valid,
            key_round,
            self.signer_context.key_lifetime,
        );
        if idx < self.first_key_offset {
            return None; // key was pruned
        }
        let local_idx = idx - self.first_key_offset;
        if local_idx >= self.ephemeral_keys.len() as u64
            || (key_round % self.signer_context.key_lifetime) != 0
            || key_round < self.signer_context.first_valid
        {
            return None;
        }
        Some(&self.ephemeral_keys[local_idx as usize])
    }

    /// Get all key-round pairs.
    pub fn get_all_keys(&self) -> Vec<KeyRoundPair> {
        self.ephemeral_keys
            .iter()
            .enumerate()
            .map(|(i, key)| KeyRoundPair {
                round: index_to_round(
                    self.signer_context.first_valid,
                    self.signer_context.key_lifetime,
                    i as u64 + self.first_key_offset,
                ),
                key: key.get_verifying_key(),
            })
            .collect()
    }
}

// ── Signer ─────────────────────────────────────────────────────────────────

/// Represents the StateProof signer for a specific round.
///
/// Not serialized (Go: `msgp:ignore Signer`). This is a helper type
/// that bundles a signing key reference with the round and context.
pub struct Signer<'a> {
    /// The falcon signing key for this round (may be `None`).
    pub signing_key: Option<&'a FalconSigner>,
    /// The round for which the signature would be valid.
    pub round: u64,
    /// The signer context (borrowed from `Secrets`).
    pub signer_context: &'a SignerContext,
}

impl<'a> Signer<'a> {
    /// Calculate the first round in the key lifetime for this signer's round.
    pub fn first_round_in_key_lifetime(&self) -> Result<u64, MerkleSignatureError> {
        if self.signer_context.key_lifetime == 0 {
            return Err(MerkleSignatureError::KeyLifetimeIsZero);
        }
        Ok(first_round_in_key_lifetime(
            self.round,
            self.signer_context.key_lifetime,
        ))
    }

    /// Calculate the vector commitment tree index for this signer.
    fn vector_commitment_tree_index(&self) -> Result<u64, MerkleSignatureError> {
        let valid_key_round = self.first_round_in_key_lifetime()?;
        Ok(round_to_index(
            self.signer_context.first_valid,
            valid_key_round,
            self.signer_context.key_lifetime,
        ))
    }

    /// Sign the given message bytes.
    ///
    /// Matches Go's `Signer.SignBytes()`.
    pub fn sign_bytes(&self, msg: &[u8]) -> Result<Signature, MerkleSignatureError> {
        let key = self
            .signing_key
            .ok_or(MerkleSignatureError::NoStateProofKeyForRound)?;

        check_merkle_signature_scheme_params(
            self.signer_context.first_valid,
            self.round,
            self.signer_context.key_lifetime,
        )?;

        let vc_idx = self.vector_commitment_tree_index()?;

        let proof = self
            .signer_context
            .tree
            .prove_single_leaf(vc_idx)
            .map_err(MerkleSignatureError::TreeError)?;

        let sig = algo_falcon::falcon_sign(&key.sk, msg)
            .map_err(|e| MerkleSignatureError::FalconError(e.to_string()))?;

        Ok(Signature {
            signature: sig,
            proof,
            verifying_key: key.get_verifying_key(),
            vector_commitment_index: vc_idx,
        })
    }
}

// ── KeyRoundPair ───────────────────────────────────────────────────────────

/// An ephemeral verifying key paired with its corresponding round.
///
/// Used as a leaf in the merkle tree. Codec tags: `"rnd"`, `"key"`.
#[derive(Debug, Clone)]
pub struct KeyRoundPair {
    /// The round this key is valid for.
    pub round: u64,
    /// The falcon verifying key.
    pub key: FalconVerifier,
}

impl KeyRoundPair {
    /// Returns `true` if both fields are zero.
    pub fn is_zero(&self) -> bool {
        self.round == 0 && self.key.is_zero()
    }

    /// Produce the fixed-length hashable representation for use as a merkle leaf.
    ///
    /// Format: domain prefix "KP" || scheme_id (u16 LE) || round (u64 LE) || falcon_pubkey (1793 bytes)
    ///
    /// This matches Go's `CommittablePublicKey.ToBeHashed()` which returns
    /// `(protocol.KeysInMSS, schemeBytes || roundBytes || pubkeyBytes)`.
    /// The caller must prepend the domain prefix "KP" when hashing.
    /// Produce the fixed-length hashable representation for use as a merkle leaf.
    ///
    /// Format: domain prefix "KP" || scheme_id (u16 LE) || round (u64 LE) || falcon_pubkey (1793 bytes)
    ///
    /// This matches Go's `CommittablePublicKey.ToBeHashed()` which returns
    /// `(protocol.KeysInMSS, schemeBytes || roundBytes || pubkeyBytes)`.
    /// The "KP" prefix is included for backward compatibility.
    pub fn get_fixed_length_hashable_representation(&self) -> Vec<u8> {
        let verifying_raw_key = self.key.get_fixed_length_hashable_representation();

        let mut scheme_bytes = [0u8; 2];
        scheme_bytes.copy_from_slice(&CRYPTO_PRIMITIVES_ID.to_le_bytes());

        let mut round_bytes = [0u8; 8];
        round_bytes.copy_from_slice(&self.round.to_le_bytes());

        let mut result = Vec::with_capacity(KEYS_IN_MSS.len() + 2 + 8 + verifying_raw_key.len());
        result.extend_from_slice(KEYS_IN_MSS);
        result.extend_from_slice(&scheme_bytes);
        result.extend_from_slice(&round_bytes);
        result.extend_from_slice(verifying_raw_key);

        result
    }
}

/// Implement `Hashable` for `KeyRoundPair` so it can be used as a merkle leaf.
///
/// Matches Go's `CommittablePublicKey.ToBeHashed()`:
/// prefix = "KP", data = scheme_id (u16 LE) || round (u64 LE) || falcon_pubkey.
impl merklearray::Hashable for KeyRoundPair {
    fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
        let verifying_raw_key = self.key.get_fixed_length_hashable_representation();

        let mut data = Vec::with_capacity(2 + 8 + verifying_raw_key.len());
        data.extend_from_slice(&CRYPTO_PRIMITIVES_ID.to_le_bytes());
        data.extend_from_slice(&self.round.to_le_bytes());
        data.extend_from_slice(verifying_raw_key);

        (KEYS_IN_MSS, data)
    }
}

// ── CommittablePublicKeyArray ──────────────────────────────────────────────

/// Array adapter for building a merkle tree over Falcon keys.
///
/// Matches Go's `committablePublicKeyArray`.
pub struct CommittablePublicKeyArray<'a> {
    pub keys: &'a [FalconSigner],
    pub first_valid: u64,
    pub key_lifetime: u64,
}

impl<'a> merklearray::Array for CommittablePublicKeyArray<'a> {
    fn length(&self) -> u64 {
        self.keys.len() as u64
    }

    fn marshal(
        &self,
        pos: u64,
    ) -> Result<Box<dyn merklearray::Hashable>, merklearray::MerkleError> {
        if pos >= self.keys.len() as u64 {
            return Err(merklearray::MerkleError::PosOutOfBound {
                pos,
                bound: self.keys.len() as u64,
            });
        }

        let eph_pk = KeyRoundPair {
            round: index_to_round(self.first_valid, self.key_lifetime, pos),
            key: self.keys[pos as usize].get_verifying_key(),
        };

        Ok(Box::new(eph_pk))
    }
}

// ── Validation helpers ─────────────────────────────────────────────────────

/// Check that the round parameters are valid for signing.
///
/// Matches Go's `checkMerkleSignatureSchemeParams`.
fn check_merkle_signature_scheme_params(
    first_valid: u64,
    round: u64,
    key_lifetime: u64,
) -> Result<(), MerkleSignatureError> {
    if key_lifetime == 0 {
        return Err(MerkleSignatureError::KeyLifetimeIsZero);
    }
    if round < first_valid {
        return Err(MerkleSignatureError::InvalidRound(format!(
            "round {round} < first_valid {first_valid}"
        )));
    }
    Ok(())
}

// ── Round-to-index arithmetic ──────────────────────────────────────────────

/// Calculate the round of the first index given first_valid and interval.
///
/// This rounds `first_valid` UP to the nearest multiple of `interval`.
fn round_of_first_index(first_valid: u64, interval: u64) -> u64 {
    first_valid.div_ceil(interval) * interval
}

/// Convert a round number to its index in the key array.
///
/// `first_valid` is the first valid round, `current_round` is the round to
/// convert, and `interval` is the key lifetime.
pub fn round_to_index(first_valid: u64, current_round: u64, interval: u64) -> u64 {
    let rofi = round_of_first_index(first_valid, interval);
    (current_round - rofi) / interval
}

/// Convert an index in the key array back to a round number.
pub fn index_to_round(first_valid: u64, interval: u64, pos: u64) -> u64 {
    round_of_first_index(first_valid, interval) + pos * interval
}

/// Calculate the first round in the key lifetime for a given round.
///
/// Lowers to the closest `key_lifetime` divisor.
/// Assumes `key_lifetime > 0`.
pub fn first_round_in_key_lifetime(round: u64, key_lifetime: u64) -> u64 {
    round - (round % key_lifetime)
}

/// Calculate the number of keys needed for the given range [first_valid, last_valid].
pub fn num_keys(first_valid: u64, last_valid: u64, key_lifetime: u64) -> u64 {
    if first_valid == 0 {
        last_valid / key_lifetime + 1
    } else {
        last_valid / key_lifetime - ((first_valid - 1) / key_lifetime)
    }
}

// ── Msgpack helpers (shared with onetimesig.rs pattern) ────────────────────

/// Write a fixstr (string up to 31 bytes) to a buffer.
fn write_fixstr(buf: &mut Vec<u8>, s: &str) {
    assert!(s.len() <= 31, "fixstr supports up to 31 bytes");
    buf.push(0xa0 | s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
}

/// Read a msgpack map header, returning (length, remaining_bytes).
fn read_map_header(data: &[u8]) -> Result<(u32, &[u8]), String> {
    if data.is_empty() {
        return Err("unexpected end of input".to_string());
    }
    let b = data[0];
    if b & 0xf0 == 0x80 {
        Ok(((b & 0x0f) as u32, &data[1..]))
    } else if b == 0xde {
        if data.len() < 3 {
            return Err("map16: unexpected end".to_string());
        }
        let len = u16::from_be_bytes([data[1], data[2]]) as u32;
        Ok((len, &data[3..]))
    } else if b == 0xdf {
        if data.len() < 5 {
            return Err("map32: unexpected end".to_string());
        }
        let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        Ok((len, &data[5..]))
    } else {
        Err(format!("expected map header, got 0x{b:02x}"))
    }
}

/// Read a msgpack array header, returning (element_count, remaining_bytes).
fn read_array_header(data: &[u8]) -> Result<(u32, &[u8]), String> {
    if data.is_empty() {
        return Err("unexpected end of input".to_string());
    }
    let b = data[0];
    if b & 0xf0 == 0x90 {
        Ok(((b & 0x0f) as u32, &data[1..]))
    } else if b == 0xdc {
        if data.len() < 3 {
            return Err("array16: unexpected end".to_string());
        }
        let len = u16::from_be_bytes([data[1], data[2]]) as u32;
        Ok((len, &data[3..]))
    } else if b == 0xdd {
        if data.len() < 5 {
            return Err("array32: unexpected end".to_string());
        }
        let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        Ok((len, &data[5..]))
    } else {
        Err(format!("expected array header, got 0x{b:02x}"))
    }
}

/// Read a msgpack string, returning (&str, remaining_bytes).
fn read_str(data: &[u8]) -> Result<(&str, &[u8]), String> {
    if data.is_empty() {
        return Err("unexpected end of input".to_string());
    }
    let b = data[0];
    let (len, rest) = if b & 0xe0 == 0xa0 {
        ((b & 0x1f) as usize, &data[1..])
    } else if b == 0xd9 {
        if data.len() < 2 {
            return Err("str8: unexpected end".to_string());
        }
        (data[1] as usize, &data[2..])
    } else if b == 0xda {
        if data.len() < 3 {
            return Err("str16: unexpected end".to_string());
        }
        (u16::from_be_bytes([data[1], data[2]]) as usize, &data[3..])
    } else {
        return Err(format!("expected string, got 0x{b:02x}"));
    };
    if rest.len() < len {
        return Err("string: unexpected end".to_string());
    }
    let s = std::str::from_utf8(&rest[..len]).map_err(|e| format!("invalid utf8: {e}"))?;
    Ok((s, &rest[len..]))
}

/// Read a msgpack binary blob, returning (&[u8], remaining_bytes).
fn read_bin(data: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if data.is_empty() {
        return Err("unexpected end of input".to_string());
    }
    let b = data[0];
    let (len, rest) = if b == 0xc4 {
        if data.len() < 2 {
            return Err("bin8: unexpected end".to_string());
        }
        (data[1] as usize, &data[2..])
    } else if b == 0xc5 {
        if data.len() < 3 {
            return Err("bin16: unexpected end".to_string());
        }
        (u16::from_be_bytes([data[1], data[2]]) as usize, &data[3..])
    } else if b == 0xc6 {
        if data.len() < 5 {
            return Err("bin32: unexpected end".to_string());
        }
        (
            u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize,
            &data[5..],
        )
    } else {
        return Err(format!("expected bin, got 0x{b:02x}"));
    };
    if rest.len() < len {
        return Err("bin: unexpected end".to_string());
    }
    Ok((&rest[..len], &rest[len..]))
}

/// Read a msgpack uint64 (compact encoding).
fn read_uint64(data: &[u8]) -> Result<(u64, &[u8]), String> {
    if data.is_empty() {
        return Err("unexpected end of input".to_string());
    }
    let b = data[0];
    if b <= 0x7f {
        Ok((b as u64, &data[1..]))
    } else if b == 0xcc {
        if data.len() < 2 {
            return Err("uint8: unexpected end".to_string());
        }
        Ok((data[1] as u64, &data[2..]))
    } else if b == 0xcd {
        if data.len() < 3 {
            return Err("uint16: unexpected end".to_string());
        }
        Ok((u16::from_be_bytes([data[1], data[2]]) as u64, &data[3..]))
    } else if b == 0xce {
        if data.len() < 5 {
            return Err("uint32: unexpected end".to_string());
        }
        Ok((
            u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as u64,
            &data[5..],
        ))
    } else if b == 0xcf {
        if data.len() < 9 {
            return Err("uint64: unexpected end".to_string());
        }
        Ok((
            u64::from_be_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]),
            &data[9..],
        ))
    } else {
        Err(format!("expected uint, got 0x{b:02x}"))
    }
}

/// Skip a single msgpack value (any type), returning the remaining bytes.
fn skip_msgpack_value(data: &[u8]) -> Result<&[u8], String> {
    if data.is_empty() {
        return Err("unexpected end of input".to_string());
    }
    let b = data[0];

    // positive fixint
    if b <= 0x7f {
        return Ok(&data[1..]);
    }
    // fixmap
    if b & 0xf0 == 0x80 {
        let count = (b & 0x0f) as u32;
        let mut cur = &data[1..];
        for _ in 0..count * 2 {
            cur = skip_msgpack_value(cur)?;
        }
        return Ok(cur);
    }
    // fixarray
    if b & 0xf0 == 0x90 {
        let count = (b & 0x0f) as u32;
        let mut cur = &data[1..];
        for _ in 0..count {
            cur = skip_msgpack_value(cur)?;
        }
        return Ok(cur);
    }
    // fixstr
    if b & 0xe0 == 0xa0 {
        let len = (b & 0x1f) as usize;
        if data.len() < 1 + len {
            return Err("fixstr: unexpected end".to_string());
        }
        return Ok(&data[1 + len..]);
    }
    // negative fixint
    if b >= 0xe0 {
        return Ok(&data[1..]);
    }

    match b {
        0xc0 => Ok(&data[1..]),        // nil
        0xc2 | 0xc3 => Ok(&data[1..]), // false/true
        // bin8
        0xc4 => {
            if data.len() < 2 {
                return Err("bin8 skip: unexpected end".to_string());
            }
            let len = data[1] as usize;
            if data.len() < 2 + len {
                return Err("bin8 skip: unexpected end".to_string());
            }
            Ok(&data[2 + len..])
        }
        // bin16
        0xc5 => {
            if data.len() < 3 {
                return Err("bin16 skip: unexpected end".to_string());
            }
            let len = u16::from_be_bytes([data[1], data[2]]) as usize;
            if data.len() < 3 + len {
                return Err("bin16 skip: unexpected end".to_string());
            }
            Ok(&data[3 + len..])
        }
        // bin32
        0xc6 => {
            if data.len() < 5 {
                return Err("bin32 skip: unexpected end".to_string());
            }
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            if data.len() < 5 + len {
                return Err("bin32 skip: unexpected end".to_string());
            }
            Ok(&data[5 + len..])
        }
        // float32
        0xca => {
            if data.len() < 5 {
                return Err("float32 skip: unexpected end".to_string());
            }
            Ok(&data[5..])
        }
        // float64
        0xcb => {
            if data.len() < 9 {
                return Err("float64 skip: unexpected end".to_string());
            }
            Ok(&data[9..])
        }
        // uint8
        0xcc => {
            if data.len() < 2 {
                return Err("uint8 skip: unexpected end".to_string());
            }
            Ok(&data[2..])
        }
        // uint16
        0xcd => {
            if data.len() < 3 {
                return Err("uint16 skip: unexpected end".to_string());
            }
            Ok(&data[3..])
        }
        // uint32
        0xce => {
            if data.len() < 5 {
                return Err("uint32 skip: unexpected end".to_string());
            }
            Ok(&data[5..])
        }
        // uint64
        0xcf => {
            if data.len() < 9 {
                return Err("uint64 skip: unexpected end".to_string());
            }
            Ok(&data[9..])
        }
        // int8
        0xd0 => {
            if data.len() < 2 {
                return Err("int8 skip: unexpected end".to_string());
            }
            Ok(&data[2..])
        }
        // int16
        0xd1 => {
            if data.len() < 3 {
                return Err("int16 skip: unexpected end".to_string());
            }
            Ok(&data[3..])
        }
        // int32
        0xd2 => {
            if data.len() < 5 {
                return Err("int32 skip: unexpected end".to_string());
            }
            Ok(&data[5..])
        }
        // int64
        0xd3 => {
            if data.len() < 9 {
                return Err("int64 skip: unexpected end".to_string());
            }
            Ok(&data[9..])
        }
        // str8
        0xd9 => {
            if data.len() < 2 {
                return Err("str8 skip: unexpected end".to_string());
            }
            let len = data[1] as usize;
            if data.len() < 2 + len {
                return Err("str8 skip: unexpected end".to_string());
            }
            Ok(&data[2 + len..])
        }
        // str16
        0xda => {
            if data.len() < 3 {
                return Err("str16 skip: unexpected end".to_string());
            }
            let len = u16::from_be_bytes([data[1], data[2]]) as usize;
            if data.len() < 3 + len {
                return Err("str16 skip: unexpected end".to_string());
            }
            Ok(&data[3 + len..])
        }
        // str32
        0xdb => {
            if data.len() < 5 {
                return Err("str32 skip: unexpected end".to_string());
            }
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            if data.len() < 5 + len {
                return Err("str32 skip: unexpected end".to_string());
            }
            Ok(&data[5 + len..])
        }
        // array16
        0xdc => {
            if data.len() < 3 {
                return Err("array16 skip: unexpected end".to_string());
            }
            let count = u16::from_be_bytes([data[1], data[2]]) as u32;
            let mut cur = &data[3..];
            for _ in 0..count {
                cur = skip_msgpack_value(cur)?;
            }
            Ok(cur)
        }
        // array32
        0xdd => {
            if data.len() < 5 {
                return Err("array32 skip: unexpected end".to_string());
            }
            let count = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            let mut cur = &data[5..];
            for _ in 0..count {
                cur = skip_msgpack_value(cur)?;
            }
            Ok(cur)
        }
        // map16
        0xde => {
            if data.len() < 3 {
                return Err("map16 skip: unexpected end".to_string());
            }
            let count = u16::from_be_bytes([data[1], data[2]]) as u32;
            let mut cur = &data[3..];
            for _ in 0..count * 2 {
                cur = skip_msgpack_value(cur)?;
            }
            Ok(cur)
        }
        // map32
        0xdf => {
            if data.len() < 5 {
                return Err("map32 skip: unexpected end".to_string());
            }
            let count = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            let mut cur = &data[5..];
            for _ in 0..count * 2 {
                cur = skip_msgpack_value(cur)?;
            }
            Ok(cur)
        }
        _ => Err(format!("skip: unknown msgpack type 0x{b:02x}")),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Round arithmetic tests ─────────────────────────────────────────

    #[test]
    fn decode_state_proof_keys_roundtrip() {
        // Build a `[]KeyRoundPair` body the way go's canonical encoder would:
        // a 2-element array of `{rnd, key}` fixmaps. Field order matches go's
        // alphabetical codec ("key" before "rnd").
        let mut signer = FalconSigner::default();
        signer.pk[0] = 0x11;
        signer.sk[0] = 0x22;

        let mut body = Vec::new();
        body.push(0x92); // fixarray of 2
        for (round, r_byte) in [(256u64, 0x33u8), (512u64, 0x44u8)] {
            let mut s = FalconSigner::default();
            s.pk[0] = r_byte;
            s.sk[0] = r_byte;
            body.push(0x82); // fixmap of 2
            write_fixstr(&mut body, "key");
            body.extend_from_slice(&s.to_msgpack());
            write_fixstr(&mut body, "rnd");
            // round is > 0x7f, so encode as uint16 (0xcd) for 256 / 512.
            body.push(0xcd);
            body.extend_from_slice(&(round as u16).to_be_bytes());
        }

        let decoded = decode_state_proof_keys(&body).expect("decode");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].0, 256);
        assert_eq!(decoded[0].1.pk[0], 0x33);
        assert_eq!(decoded[0].1.sk[0], 0x33);
        assert_eq!(decoded[1].0, 512);
        assert_eq!(decoded[1].1.pk[0], 0x44);

        // empty array decodes to empty vec.
        assert!(decode_state_proof_keys(&[0x90]).expect("empty").is_empty());

        // garbage body is rejected, not silently accepted.
        assert!(decode_state_proof_keys(&[0xc0]).is_err());
    }

    #[test]
    fn test_round_to_index_basic() {
        // first_valid=256, current_round=256, interval=256 => index 0
        assert_eq!(round_to_index(256, 256, 256), 0);
        // first_valid=256, current_round=512, interval=256 => index 1
        assert_eq!(round_to_index(256, 512, 256), 1);
        // first_valid=256, current_round=768, interval=256 => index 2
        assert_eq!(round_to_index(256, 768, 256), 2);
    }

    #[test]
    fn test_index_to_round_basic() {
        // first_valid=256, interval=256, pos=0 => round 256
        assert_eq!(index_to_round(256, 256, 0), 256);
        // first_valid=256, interval=256, pos=1 => round 512
        assert_eq!(index_to_round(256, 256, 1), 512);
        // first_valid=256, interval=256, pos=2 => round 768
        assert_eq!(index_to_round(256, 256, 2), 768);
    }

    #[test]
    fn test_round_to_index_and_back() {
        let first_valid = 100u64;
        let interval = 256u64;
        // The first index round is ceil(100/256)*256 = 256
        let first_index_round = round_of_first_index(first_valid, interval);
        assert_eq!(first_index_round, 256);

        for pos in 0..10u64 {
            let round = index_to_round(first_valid, interval, pos);
            let idx = round_to_index(first_valid, round, interval);
            assert_eq!(idx, pos, "roundtrip failed for pos {pos}");
        }
    }

    #[test]
    fn test_first_round_in_key_lifetime() {
        assert_eq!(first_round_in_key_lifetime(256, 256), 256);
        assert_eq!(first_round_in_key_lifetime(257, 256), 256);
        assert_eq!(first_round_in_key_lifetime(511, 256), 256);
        assert_eq!(first_round_in_key_lifetime(512, 256), 512);
        assert_eq!(first_round_in_key_lifetime(0, 256), 0);
        assert_eq!(first_round_in_key_lifetime(1000, 256), 768);
    }

    #[test]
    fn test_num_keys() {
        // Go: numberOfKeys = lastValid/keyLifetime - ((firstValid - 1) / keyLifetime)
        // firstValid=256, lastValid=512: 512/256 - (255/256) = 2 - 0 = 2
        assert_eq!(num_keys(256, 512, 256), 2);
        // firstValid=256, lastValid=768: 768/256 - (255/256) = 3 - 0 = 3
        assert_eq!(num_keys(256, 768, 256), 3);
        // firstValid=1, lastValid=256: 256/256 - (0/256) = 1 - 0 = 1
        assert_eq!(num_keys(1, 256, 256), 1);
        // firstValid=1, lastValid=512: 512/256 - (0/256) = 2 - 0 = 2
        assert_eq!(num_keys(1, 512, 256), 2);
        // firstValid=0 special case: lastValid/keyLifetime + 1
        assert_eq!(num_keys(0, 256, 256), 2); // keys for round 0 and round 256
        assert_eq!(num_keys(0, 255, 256), 1); // only key for round 0
    }

    #[test]
    fn test_num_keys_go_new_logic() {
        // Matching Go's New() logic:
        // firstValid=257, lastValid=258, keyLifetime=256
        // numberOfKeys = 258/256 - ((257-1)/256) = 1 - 1 = 0
        // This means no keys are generated (the range doesn't cross a key boundary)
        let nk = num_keys(257, 258, 256);
        assert_eq!(nk, 0);

        // firstValid=256+1=257, lastValid=256+2=258 with keyLifetime=256
        // Go test: New(KeyLifetimeDefault+1, KeyLifetimeDefault+2, KeyLifetimeDefault) generates 0 keys
        let nk = num_keys(
            KEY_LIFETIME_DEFAULT + 1,
            KEY_LIFETIME_DEFAULT + 2,
            KEY_LIFETIME_DEFAULT,
        );
        assert_eq!(nk, 0);
    }

    #[test]
    fn test_round_of_first_index() {
        assert_eq!(round_of_first_index(0, 256), 0);
        assert_eq!(round_of_first_index(1, 256), 256);
        assert_eq!(round_of_first_index(256, 256), 256);
        assert_eq!(round_of_first_index(257, 256), 512);
    }

    // ── Serialization tests ────────────────────────────────────────────

    #[test]
    fn test_falcon_verifier_roundtrip() {
        let mut fv = FalconVerifier::default();
        fv.k[0] = 0x42;
        fv.k[1792] = 0xFF;

        let encoded = fv.to_msgpack();
        let (decoded, rest) = FalconVerifier::from_msgpack(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.k, fv.k);
    }

    #[test]
    fn test_falcon_verifier_empty_roundtrip() {
        let fv = FalconVerifier::default();
        let encoded = fv.to_msgpack();
        // Empty => fixmap(0) = 0x80
        assert_eq!(encoded, vec![0x80]);
        let (decoded, rest) = FalconVerifier::from_msgpack(&encoded).unwrap();
        assert!(rest.is_empty());
        assert!(decoded.is_zero());
    }

    #[test]
    fn test_falcon_signer_roundtrip() {
        let mut fs = FalconSigner::default();
        fs.pk[0] = 0x01;
        fs.sk[0] = 0x02;

        let encoded = fs.to_msgpack();
        let (decoded, rest) = FalconSigner::from_msgpack(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.pk, fs.pk);
        assert_eq!(decoded.sk, fs.sk);
    }

    #[test]
    fn test_falcon_signer_empty_roundtrip() {
        let fs = FalconSigner::default();
        let encoded = fs.to_msgpack();
        assert_eq!(encoded, vec![0x80]);
        let (decoded, rest) = FalconSigner::from_msgpack(&encoded).unwrap();
        assert!(rest.is_empty());
        assert!(decoded.is_zero());
    }

    #[test]
    fn test_verifier_roundtrip() {
        let mut v = Verifier::default();
        v.commitment[0] = 0xAB;
        v.commitment[63] = 0xCD;
        v.key_lifetime = 256;

        let encoded = v.to_msgpack();
        let (decoded, rest) = Verifier::from_msgpack(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.commitment, v.commitment);
        assert_eq!(decoded.key_lifetime, v.key_lifetime);
    }

    #[test]
    fn test_verifier_empty_roundtrip() {
        let v = Verifier::default();
        let encoded = v.to_msgpack();
        assert_eq!(encoded, vec![0x80]);
        let (decoded, rest) = Verifier::from_msgpack(&encoded).unwrap();
        assert!(rest.is_empty());
        assert!(decoded.is_zero());
    }

    #[test]
    fn test_verifier_field_ordering() {
        // Verify alphabetical field order: "cmt" < "lf"
        let mut v = Verifier::default();
        v.commitment[0] = 1;
        v.key_lifetime = 256;
        let encoded = v.to_msgpack();

        // fixmap(2) = 0x82
        assert_eq!(encoded[0], 0x82);
        // First field key should be "cmt" (0xa3 0x63 0x6d 0x74)
        assert_eq!(&encoded[1..5], &[0xa3, b'c', b'm', b't']);
    }

    #[test]
    fn test_signer_context_roundtrip() {
        // Build a small tree for the context
        let tree = merklearray::Tree {
            levels: vec![vec![vec![1u8; 64]]],
            num_of_elements: 1,
            hash: merklearray::HashFactory::new(merklearray::HashType::Sumhash),
            is_vector_commitment: true,
        };
        let ctx = SignerContext {
            first_valid: 1000,
            key_lifetime: 256,
            tree,
        };

        let encoded = ctx.to_msgpack();
        let (decoded, rest) = SignerContext::from_msgpack(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.first_valid, ctx.first_valid);
        assert_eq!(decoded.key_lifetime, ctx.key_lifetime);
        assert_eq!(decoded.tree.num_of_elements, 1);
        assert!(decoded.tree.is_vector_commitment);
    }

    #[test]
    fn test_signer_context_empty_roundtrip() {
        let ctx = SignerContext::default();
        let encoded = ctx.to_msgpack();
        assert_eq!(encoded, vec![0x80]);
        let (decoded, rest) = SignerContext::from_msgpack(&encoded).unwrap();
        assert!(rest.is_empty());
        assert!(decoded.is_zero());
    }

    #[test]
    fn test_signer_context_field_ordering() {
        // Alphabetical: "fv" < "iv" < "tree"
        let tree = merklearray::Tree {
            levels: vec![vec![vec![1u8; 64]]],
            num_of_elements: 1,
            hash: merklearray::HashFactory::new(merklearray::HashType::Sumhash),
            is_vector_commitment: true,
        };
        let ctx = SignerContext {
            first_valid: 1,
            key_lifetime: 2,
            tree,
        };
        let encoded = ctx.to_msgpack();
        assert_eq!(encoded[0], 0x83); // fixmap(3)
                                      // "fv" = 0xa2 0x66 0x76
        assert_eq!(&encoded[1..4], &[0xa2, b'f', b'v']);
    }

    #[test]
    fn test_secrets_roundtrip() {
        let tree = merklearray::Tree {
            levels: vec![vec![vec![1u8; 64]]],
            num_of_elements: 1,
            hash: merklearray::HashFactory::new(merklearray::HashType::Sumhash),
            is_vector_commitment: true,
        };
        let secrets = Secrets {
            ephemeral_keys: vec![FalconSigner::default()],
            signer_context: SignerContext {
                first_valid: 500,
                key_lifetime: 256,
                tree,
            },
            first_key_offset: 0,
        };

        let encoded = secrets.to_msgpack();
        let (decoded, rest) = Secrets::from_msgpack(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.signer_context.first_valid, 500);
        assert_eq!(decoded.signer_context.key_lifetime, 256);
        // ephemeral_keys are not serialized
        assert!(decoded.ephemeral_keys.is_empty());
    }

    #[test]
    fn test_signature_roundtrip() {
        let mut fv = FalconVerifier::default();
        fv.k[0] = 0x42;

        let proof = merklearray::SingleLeafProof {
            proof: merklearray::Proof {
                path: vec![vec![0xAB; 64]],
                hash_factory: merklearray::HashFactory::new(merklearray::HashType::Sumhash),
                tree_depth: 1,
            },
        };

        let sig = Signature {
            signature: vec![0xBA, 0x01, 0x02, 0x03],
            vector_commitment_index: 7,
            proof,
            verifying_key: fv,
        };

        let encoded = sig.to_msgpack();
        let (decoded, rest) = Signature::from_msgpack(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.signature, sig.signature);
        assert_eq!(decoded.vector_commitment_index, 7);
        assert_eq!(decoded.proof.proof.tree_depth, 1);
        assert_eq!(decoded.proof.proof.path.len(), 1);
        assert_eq!(decoded.verifying_key.k[0], 0x42);
    }

    #[test]
    fn test_signature_empty_roundtrip() {
        let sig = Signature::default();
        let encoded = sig.to_msgpack();
        assert_eq!(encoded, vec![0x80]);
        let (decoded, rest) = Signature::from_msgpack(&encoded).unwrap();
        assert!(rest.is_empty());
        assert!(decoded.is_zero());
    }

    #[test]
    fn test_signature_field_ordering() {
        // Alphabetical: "idx" < "prf" < "sig" < "vkey"
        let mut fv = FalconVerifier::default();
        fv.k[0] = 1;
        let proof = merklearray::SingleLeafProof {
            proof: merklearray::Proof {
                path: vec![vec![0u8; 32]],
                hash_factory: merklearray::HashFactory::default(),
                tree_depth: 1,
            },
        };
        let sig = Signature {
            signature: vec![0xBA],
            vector_commitment_index: 1,
            proof,
            verifying_key: fv,
        };
        let encoded = sig.to_msgpack();
        assert_eq!(encoded[0], 0x84); // fixmap(4)
                                      // First field: "idx" (0xa3 0x69 0x64 0x78)
        assert_eq!(&encoded[1..5], &[0xa3, b'i', b'd', b'x']);
    }

    // ── GetFixedLengthHashableRepresentation test ──────────────────────

    #[test]
    fn test_key_round_pair_hashable_repr() {
        let mut key = FalconVerifier::default();
        key.k[0] = 0xFF;
        key.k[1792] = 0xAA;

        let pair = KeyRoundPair { round: 256, key };

        let repr = pair.get_fixed_length_hashable_representation();

        // Expected format:
        // "KP" (2 bytes) + scheme_id LE (2 bytes) + round LE (8 bytes) + pubkey (1793 bytes)
        assert_eq!(repr.len(), 2 + 2 + 8 + FALCON_DET1024_PUBKEY_SIZE);

        // Check domain prefix
        assert_eq!(&repr[0..2], b"KP");

        // Check scheme_id (0x0000 LE)
        assert_eq!(&repr[2..4], &[0x00, 0x00]);

        // Check round (256 = 0x0100000000000000 LE)
        assert_eq!(&repr[4..12], &256u64.to_le_bytes());

        // Check pubkey starts at offset 12
        assert_eq!(repr[12], 0xFF);
        assert_eq!(repr[12 + 1792], 0xAA);
    }

    #[test]
    fn test_key_round_pair_hashable_repr_zero() {
        let pair = KeyRoundPair {
            round: 0,
            key: FalconVerifier::default(),
        };

        let repr = pair.get_fixed_length_hashable_representation();
        assert_eq!(repr.len(), 2 + 2 + 8 + FALCON_DET1024_PUBKEY_SIZE);

        // Domain prefix
        assert_eq!(&repr[0..2], b"KP");
        // Scheme ID
        assert_eq!(&repr[2..4], &[0x00, 0x00]);
        // Round = 0
        assert_eq!(&repr[4..12], &[0; 8]);
        // All pubkey bytes zero
        assert!(repr[12..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_commitment_is_empty() {
        let empty: Commitment = [0u8; MERKLE_SIGNATURE_SCHEME_ROOT_SIZE];
        assert!(commitment_is_empty(&empty));

        let mut non_empty = empty;
        non_empty[0] = 1;
        assert!(!commitment_is_empty(&non_empty));
    }

    // ── Hashable trait tests ─────────────────────────────────────────

    #[test]
    fn test_key_round_pair_hashable_trait() {
        use crate::merklearray::Hashable;

        let mut key = FalconVerifier::default();
        key.k[0] = 0xFF;

        let pair = KeyRoundPair { round: 256, key };

        let (prefix, data) = pair.to_be_hashed();
        assert_eq!(prefix, b"KP");
        // data = scheme_id (2) + round (8) + pubkey (1793) = 1803
        assert_eq!(data.len(), 2 + 8 + FALCON_DET1024_PUBKEY_SIZE);
        // Check scheme_id
        assert_eq!(&data[0..2], &[0x00, 0x00]);
        // Check round
        assert_eq!(&data[2..10], &256u64.to_le_bytes());
        // Check pubkey
        assert_eq!(data[10], 0xFF);
    }

    // ── Key generation tests ──────────────────────────────────────────

    #[test]
    fn test_secrets_new_basic() {
        // Generate keys for 2 rounds: first_valid=256, last_valid=512, key_lifetime=256
        // Expected keys: 2 (rounds 256 and 512)
        let secrets = Secrets::new(256, 512, 256).expect("Secrets::new should succeed");
        assert_eq!(secrets.ephemeral_keys.len(), 2);
        assert_eq!(secrets.signer_context.first_valid, 256);
        assert_eq!(secrets.signer_context.key_lifetime, 256);
        assert!(secrets.signer_context.tree.is_vector_commitment);
        assert_eq!(secrets.signer_context.tree.num_of_elements, 2);
        // Root should be 64 bytes (sumhash)
        assert_eq!(secrets.signer_context.tree.root().len(), 64);
    }

    #[test]
    fn test_secrets_new_single_key() {
        let secrets = Secrets::new(0, 0, 256).expect("Secrets::new should succeed");
        assert_eq!(secrets.ephemeral_keys.len(), 1);
    }

    #[test]
    fn test_secrets_new_start_bigger_than_end() {
        let result = Secrets::new(512, 256, 256);
        assert!(matches!(
            result,
            Err(MerkleSignatureError::StartBiggerThanEndRound)
        ));
    }

    #[test]
    fn test_secrets_new_zero_key_lifetime() {
        let result = Secrets::new(256, 512, 0);
        assert!(matches!(
            result,
            Err(MerkleSignatureError::KeyLifetimeIsZero)
        ));
    }

    #[test]
    fn test_secrets_new_no_keys_generated() {
        // Range that doesn't cross a key boundary
        let secrets = Secrets::new(257, 258, 256).expect("Secrets::new should succeed");
        assert_eq!(secrets.ephemeral_keys.len(), 0);
    }

    // ── Verifier from secrets ─────────────────────────────────────────

    #[test]
    fn test_get_verifier() {
        let secrets = Secrets::new(256, 512, 256).expect("Secrets::new should succeed");
        let verifier = secrets.get_verifier();
        assert_eq!(verifier.key_lifetime, 256);
        assert!(!commitment_is_empty(&verifier.commitment));
        // Commitment should match tree root
        let root = secrets.signer_context.tree.root();
        assert_eq!(&verifier.commitment[..], &root[..]);
    }

    // ── Sign and verify roundtrip ─────────────────────────────────────

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let secrets = Secrets::new(256, 512, 256).expect("Secrets::new should succeed");
        let verifier = secrets.get_verifier();

        let msg = b"hello merkle signature scheme";
        let round = 256;

        let signer = secrets.get_signer(round);
        let sig = signer.sign_bytes(msg).expect("sign_bytes should succeed");

        // Verify
        verifier
            .verify_bytes(round, msg, &sig)
            .expect("verify_bytes should succeed");
    }

    #[test]
    fn test_sign_and_verify_last_valid_round() {
        let secrets = Secrets::new(256, 512, 256).expect("Secrets::new should succeed");
        let verifier = secrets.get_verifier();

        let msg = b"test at last valid round";
        let round = 512;

        let signer = secrets.get_signer(round);
        let sig = signer.sign_bytes(msg).expect("sign_bytes should succeed");

        verifier
            .verify_bytes(round, msg, &sig)
            .expect("verify_bytes should succeed");
    }

    #[test]
    fn test_sign_and_verify_with_round_in_key_lifetime() {
        // Round 300 should use the key for round 256 (first_round_in_key_lifetime)
        let secrets = Secrets::new(256, 512, 256).expect("Secrets::new should succeed");
        let verifier = secrets.get_verifier();

        let msg = b"test within key lifetime";
        let round = 300;

        let signer = secrets.get_signer(round);
        let sig = signer.sign_bytes(msg).expect("sign_bytes should succeed");

        verifier
            .verify_bytes(round, msg, &sig)
            .expect("verify_bytes should succeed");
    }

    // ── Verification failure tests ────────────────────────────────────

    #[test]
    fn test_verify_wrong_data_fails() {
        let secrets = Secrets::new(256, 512, 256).expect("Secrets::new should succeed");
        let verifier = secrets.get_verifier();

        let msg = b"correct message";
        let signer = secrets.get_signer(256);
        let sig = signer.sign_bytes(msg).expect("sign_bytes should succeed");

        // Verify with wrong message should fail
        let result = verifier.verify_bytes(256, b"wrong message", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_wrong_commitment_fails() {
        let secrets = Secrets::new(256, 512, 256).expect("Secrets::new should succeed");

        let msg = b"test";
        let signer = secrets.get_signer(256);
        let sig = signer.sign_bytes(msg).expect("sign_bytes should succeed");

        // Create a verifier with wrong commitment
        let wrong_verifier = Verifier {
            commitment: [0xFF; MERKLE_SIGNATURE_SCHEME_ROOT_SIZE],
            key_lifetime: 256,
        };

        let result = wrong_verifier.verify_bytes(256, msg, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_no_key_for_round_fails() {
        let secrets = Secrets::new(256, 512, 256).expect("Secrets::new should succeed");

        // Round 1024 is outside the valid range
        let signer = secrets.get_signer(1024);
        let result = signer.sign_bytes(b"test");
        assert!(matches!(
            result,
            Err(MerkleSignatureError::NoStateProofKeyForRound)
        ));
    }

    // ── Serialization roundtrip with real keys ────────────────────────

    #[test]
    fn test_secrets_serialization_with_real_tree() {
        let secrets = Secrets::new(256, 512, 256).expect("Secrets::new should succeed");

        let encoded = secrets.to_msgpack();
        let (decoded, rest) = Secrets::from_msgpack(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.signer_context.first_valid, 256);
        assert_eq!(decoded.signer_context.key_lifetime, 256);
        assert!(decoded.signer_context.tree.is_vector_commitment);
        assert_eq!(decoded.signer_context.tree.num_of_elements, 2);
        // Tree root should survive serialization roundtrip
        assert_eq!(
            decoded.signer_context.tree.root(),
            secrets.signer_context.tree.root()
        );
    }

    #[test]
    fn test_signature_serialization_with_real_proof() {
        let secrets = Secrets::new(256, 512, 256).expect("Secrets::new should succeed");
        let signer = secrets.get_signer(256);
        let sig = signer
            .sign_bytes(b"test serialization")
            .expect("sign_bytes should succeed");

        let encoded = sig.to_msgpack();
        let (decoded, rest) = Signature::from_msgpack(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.signature, sig.signature);
        assert_eq!(decoded.vector_commitment_index, sig.vector_commitment_index);
        assert_eq!(decoded.proof.proof.tree_depth, sig.proof.proof.tree_depth);
        assert_eq!(decoded.proof.proof.path.len(), sig.proof.proof.path.len());
        assert_eq!(decoded.verifying_key.k, sig.verifying_key.k);

        // Verify that the deserialized signature still verifies
        let verifier = secrets.get_verifier();
        verifier
            .verify_bytes(256, b"test serialization", &decoded)
            .expect("deserialized signature should verify");
    }

    // ── Multiple keys tests ──────────────────────────────────────────

    #[test]
    fn test_sign_verify_all_keys() {
        let secrets = Secrets::new(0, 768, 256).expect("Secrets::new should succeed");
        let verifier = secrets.get_verifier();
        let msg = b"sign with every key";

        // Should have keys for rounds 0, 256, 512, 768 = 4 keys
        // num_keys(0, 768, 256) = 768/256 + 1 = 4
        assert_eq!(secrets.ephemeral_keys.len(), 4);

        for round in [0, 256, 512, 768] {
            let signer = secrets.get_signer(round);
            let sig = signer.sign_bytes(msg).expect("sign_bytes should succeed");
            verifier
                .verify_bytes(round, msg, &sig)
                .unwrap_or_else(|_| panic!("verify should succeed for round {round}"));
        }
    }

    #[test]
    fn test_get_all_keys() {
        let secrets = Secrets::new(256, 768, 256).expect("Secrets::new should succeed");
        let all_keys = secrets.get_all_keys();
        assert_eq!(all_keys.len(), 3);
        assert_eq!(all_keys[0].round, 256);
        assert_eq!(all_keys[1].round, 512);
        assert_eq!(all_keys[2].round, 768);
    }
}
