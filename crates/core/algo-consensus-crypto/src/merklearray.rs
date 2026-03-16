//! Merkle array tree implementation matching go-algorand's `crypto/merklearray`.
//!
//! Supports multiple hash functions (SHA-512/256, Sumhash-512) and both
//! regular Merkle trees and vector commitment trees with bit-reversal
//! permutation.
//!
//! References:
//!   - `go-algorand/crypto/merklearray/merkle.go`
//!   - `go-algorand/crypto/merklearray/layer.go`
//!   - `go-algorand/crypto/merklearray/proof.go`
//!   - `go-algorand/crypto/merklearray/vectorCommitmentArray.go`
//!   - `go-algorand/crypto/hashes.go`

use sha2::{Digest as _, Sha512_256};

use crate::sumhash::Sumhash512;

// ── Constants ────────────────────────────────────────────────────────

/// Maximum tree depth for encoded trees.
pub const MAX_ENCODED_TREE_DEPTH: usize = 16;

/// Maximum number of leaves on an encoded tree.
pub const MAX_NUM_LEAVES_ON_ENCODED_TREE: usize = 1 << MAX_ENCODED_TREE_DEPTH;

/// Domain separation prefix for Merkle array internal nodes.
const MA_PREFIX: &[u8] = b"MA";

/// Domain separation prefix for vector commitment bottom (padding) leaves.
const MB_PREFIX: &[u8] = b"MB";

// ── HashType / HashFactory ───────────────────────────────────────────

/// Hash function type, matching go-algorand's `crypto.HashType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u16)]
pub enum HashType {
    /// SHA-512/256 (32-byte output).
    #[default]
    Sha512_256 = 0,
    /// Sumhash-512 (64-byte output).
    Sumhash = 1,
    /// SHA-256 (32-byte output).
    Sha256 = 2,
    /// SHA-512 (64-byte output).
    Sha512 = 3,
}

impl HashType {
    /// Convert from u16, returning None for invalid values.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0 => Some(Self::Sha512_256),
            1 => Some(Self::Sumhash),
            2 => Some(Self::Sha256),
            3 => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Digest size in bytes for this hash type.
    pub fn digest_size(self) -> usize {
        match self {
            Self::Sha512_256 => 32,
            Self::Sumhash => 64,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// Factory for creating hash instances, matching go-algorand's `crypto.HashFactory`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HashFactory {
    pub hash_type: HashType,
}

impl HashFactory {
    /// Create a new `HashFactory` with the given hash type.
    pub fn new(hash_type: HashType) -> Self {
        Self { hash_type }
    }

    /// Compute a domain-separated hash: `H(prefix || data)`.
    pub fn hash_bytes(&self, parts: &[&[u8]]) -> GenericDigest {
        match self.hash_type {
            HashType::Sha512_256 => {
                let mut h = Sha512_256::new();
                for p in parts {
                    h.update(p);
                }
                h.finalize().to_vec()
            }
            HashType::Sumhash => {
                let mut h = Sumhash512::new();
                for p in parts {
                    h.write(p);
                }
                h.finalize().to_vec()
            }
            HashType::Sha256 => {
                use sha2::Sha256;
                let mut h = Sha256::new();
                for p in parts {
                    h.update(p);
                }
                h.finalize().to_vec()
            }
            HashType::Sha512 => {
                use sha2::Sha512;
                let mut h = Sha512::new();
                for p in parts {
                    h.update(p);
                }
                h.finalize().to_vec()
            }
        }
    }

    /// Returns true if this is the zero/default value (used for omitempty).
    pub fn is_zero(&self) -> bool {
        self.hash_type as u16 == 0
    }

    /// Digest size for this factory's hash type.
    pub fn digest_size(&self) -> usize {
        self.hash_type.digest_size()
    }
}

// ── GenericDigest / Layer ────────────────────────────────────────────

/// A variable-length digest, matching go-algorand's `crypto.GenericDigest`.
pub type GenericDigest = Vec<u8>;

/// A layer of the Merkle tree: a dense array of digests at one level.
pub type Layer = Vec<GenericDigest>;

// ── Hashable / Array traits ──────────────────────────────────────────

/// Something that can be hashed with a domain separation prefix.
/// Matches go-algorand's `crypto.Hashable` interface.
pub trait Hashable {
    /// Returns the domain separation prefix and the data bytes.
    fn to_be_hashed(&self) -> (&[u8], Vec<u8>);
}

/// Interface for providing leaves to the tree builder.
/// Matches go-algorand's `merklearray.Array` interface.
pub trait Array {
    /// Number of elements in the array.
    fn length(&self) -> u64;

    /// Return the hashable element at `pos`.
    fn marshal(&self, pos: u64) -> Result<Box<dyn Hashable>, MerkleError>;
}

/// Compute `H(hashid || data)` using the given factory.
fn generic_hash_obj(factory: &HashFactory, h: &dyn Hashable) -> GenericDigest {
    let (prefix, data) = h.to_be_hashed();
    factory.hash_bytes(&[prefix, &data])
}

// ── Errors ───────────────────────────────────────────────────────────

/// Errors from merkle tree operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    RootMismatch,
    ProvingZeroCommitment,
    ProofIsNil,
    NonEmptyProofForEmptyElements,
    UnexpectedTreeDepth,
    PosOutOfBound { pos: u64, bound: u64 },
    ProofLengthDigestSizeMismatch,
    NoMoreSiblingHints,
    LevelBeyondTreeHeight { level: u64, height: usize },
    InternalError(String),
    ArrayError(String),
}

impl std::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootMismatch => write!(f, "root mismatch"),
            Self::ProvingZeroCommitment => write!(f, "proving in zero-length commitment"),
            Self::ProofIsNil => write!(f, "proof should not be nil"),
            Self::NonEmptyProofForEmptyElements => {
                write!(f, "non-empty proof for empty set of elements")
            }
            Self::UnexpectedTreeDepth => write!(f, "unexpected tree depth"),
            Self::PosOutOfBound { pos, bound } => {
                write!(f, "pos {pos} out of bound {bound}")
            }
            Self::ProofLengthDigestSizeMismatch => {
                write!(f, "proof length and digest size mismatched")
            }
            Self::NoMoreSiblingHints => write!(f, "no more sibling hints"),
            Self::LevelBeyondTreeHeight { level, height } => {
                write!(f, "level {level} beyond tree height {height}")
            }
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
            Self::ArrayError(msg) => write!(f, "array error: {msg}"),
        }
    }
}

impl std::error::Error for MerkleError {}

// ── Proof / SingleLeafProof ──────────────────────────────────────────

/// Merkle inclusion proof.
///
/// Serialized with msgpack field ordering: `hsh`, `pth`, `td` (alphabetical).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Proof {
    /// Verification path (sibling hashes).
    pub path: Vec<GenericDigest>,
    /// Hash factory used by the tree.
    pub hash_factory: HashFactory,
    /// Depth of the tree (number of edges from root to leaf).
    pub tree_depth: u8,
}

/// Single-leaf proof — wraps a `Proof` for a single element.
///
/// Serialized identically to `Proof` (Go embeds Proof in SingleLeafProof).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SingleLeafProof {
    pub proof: Proof,
}

impl SingleLeafProof {
    /// Serialize the proof into a fixed-length byte representation.
    ///
    /// Format: 1 byte tree_depth + (MAX_ENCODED_TREE_DEPTH * digest_size) bytes.
    /// Leading zeros fill unused proof positions.
    pub fn get_fixed_length_hashable_representation(&self) -> Vec<u8> {
        let digest_size = self.proof.hash_factory.digest_size();
        let mut bin = Vec::with_capacity(1 + MAX_ENCODED_TREE_DEPTH * digest_size);

        bin.push(self.proof.tree_depth);

        let zero_digest = vec![0u8; digest_size];

        // Leading zeros for unused depth positions.
        for _ in 0..(MAX_ENCODED_TREE_DEPTH as u8 - self.proof.tree_depth) {
            bin.extend_from_slice(&zero_digest);
        }

        // Proof path elements.
        for i in 0..self.proof.tree_depth as usize {
            if i < self.proof.path.len() && !self.proof.path[i].is_empty() {
                bin.extend_from_slice(&self.proof.path[i]);
            } else {
                bin.extend_from_slice(&zero_digest);
            }
        }

        bin
    }

    /// Concatenate the verification path into a single byte slice.
    pub fn get_concatenated_proof(&self) -> Vec<u8> {
        let digest_size = self.proof.hash_factory.digest_size();
        let mut result = vec![0u8; digest_size * self.proof.tree_depth as usize];
        for i in 0..self.proof.tree_depth as usize {
            if i < self.proof.path.len() && !self.proof.path[i].is_empty() {
                let start = i * digest_size;
                result[start..start + digest_size].copy_from_slice(&self.proof.path[i]);
            }
        }
        result
    }
}

// ── Tree ─────────────────────────────────────────────────────────────

/// A Merkle tree, stored as layers of digests bottom-up.
///
/// Serialized with msgpack field ordering: `hsh`, `lvls`, `nl`, `vc` (alphabetical).
#[derive(Debug, Clone, Default)]
pub struct Tree {
    /// Layers of the tree. `levels[0]` = leaves, `levels[len-1]` = root.
    pub levels: Vec<Layer>,
    /// Number of elements in the original array (before VC padding).
    pub num_of_elements: u64,
    /// Hash factory used for this tree.
    pub hash: HashFactory,
    /// Whether this tree was built as a vector commitment.
    pub is_vector_commitment: bool,
}

impl Tree {
    /// Return the root hash. Empty tree returns an empty digest.
    pub fn root(&self) -> GenericDigest {
        if self.levels.is_empty() {
            return Vec::new();
        }
        self.levels.last().unwrap()[0].clone()
    }

    /// Generate a proof for a single leaf at `idx`.
    pub fn prove_single_leaf(&self, idx: u64) -> Result<SingleLeafProof, MerkleError> {
        let proof = self.prove(&[idx])?;
        Ok(SingleLeafProof { proof })
    }

    /// Generate a proof for a set of leaf positions.
    pub fn prove(&self, idxs: &[u64]) -> Result<Proof, MerkleError> {
        if idxs.is_empty() {
            return self.create_empty_proof();
        }

        if self.num_of_elements == 0 {
            return Err(MerkleError::ProvingZeroCommitment);
        }

        // Verify all positions are in range.
        for &idx in idxs {
            if idx >= self.num_of_elements {
                return Err(MerkleError::PosOutOfBound {
                    pos: idx,
                    bound: self.num_of_elements,
                });
            }
        }

        let mut sorted_idxs: Vec<u64> = if self.is_vector_commitment {
            self.convert_leaves_indexes(idxs)?
        } else {
            idxs.to_vec()
        };

        sorted_idxs.sort_unstable();
        self.create_proof(&sorted_idxs)
    }

    fn convert_leaves_indexes(&self, idxs: &[u64]) -> Result<Vec<u64>, MerkleError> {
        let depth = (self.levels.len() - 1) as u8;
        let mut vc_idxs = Vec::with_capacity(idxs.len());
        for &idx in idxs {
            vc_idxs.push(merkle_tree_to_vector_commitment_index(idx, depth)?);
        }
        Ok(vc_idxs)
    }

    fn create_empty_proof(&self) -> Result<Proof, MerkleError> {
        let tree_depth = if self.levels.is_empty() {
            0
        } else {
            (self.levels.len() - 1) as u8
        };
        Ok(Proof {
            path: Vec::new(),
            hash_factory: self.hash,
            tree_depth,
        })
    }

    fn create_proof(&self, idxs: &[u64]) -> Result<Proof, MerkleError> {
        // Build initial partial layer from sorted, deduplicated indices.
        let mut pl: Vec<LayerItem> = Vec::with_capacity(idxs.len());
        for &pos in idxs {
            if !pl.is_empty() && pl.last().unwrap().pos == pos {
                continue; // skip duplicates
            }
            pl.push(LayerItem {
                pos,
                hash: self.levels[0][pos as usize].clone(),
            });
        }

        let mut hints: Vec<GenericDigest> = Vec::new();
        let digest_size = self.hash.digest_size();

        for l in 0..(self.levels.len() - 1) as u64 {
            pl = partial_layer_up(
                pl,
                &mut SiblingsProve {
                    tree: self,
                    hints: &mut hints,
                },
                l,
                false, // doHash=false during proof generation (Go: validateProof=false)
                &self.hash,
                digest_size,
            )?;
        }

        if pl.len() != 1 {
            return Err(MerkleError::InternalError(format!(
                "partial layer produced {} hashes",
                pl.len()
            )));
        }

        Ok(Proof {
            path: hints,
            hash_factory: self.hash,
            tree_depth: (self.levels.len() - 1) as u8,
        })
    }

    fn build_layers(&mut self, leaves: Layer) {
        if leaves.is_empty() {
            return;
        }
        self.levels = vec![leaves];
        while self.levels.last().unwrap().len() > 1 {
            self.build_next_layer();
        }
    }

    fn build_next_layer(&mut self) {
        let top = self.levels.last().unwrap();
        let n = top.len();
        let new_len = n.div_ceil(2);
        let mut new_layer = Vec::with_capacity(new_len);
        let digest_size = self.hash.digest_size();

        let mut i = 0;
        while i < n {
            let left = &top[i];
            let right = if i + 1 < n {
                &top[i + 1]
            } else {
                // Missing child: zero bytes of digest_size length
                &vec![0u8; 0] // placeholder, handled below
            };

            // Build the pair hash: H("MA" || left_padded || right_padded)
            let mut buf = Vec::with_capacity(2 * digest_size);
            // Left child, padded to digest_size
            buf.extend_from_slice(left);
            if left.len() < digest_size {
                buf.resize(digest_size, 0);
            }
            // Right child, padded to digest_size
            if i + 1 < n {
                buf.extend_from_slice(right);
                if right.len() < digest_size {
                    buf.resize(2 * digest_size, 0);
                }
            } else {
                buf.resize(2 * digest_size, 0);
            }

            let hash = self.hash.hash_bytes(&[MA_PREFIX, &buf]);
            new_layer.push(hash);

            i += 2;
        }

        self.levels.push(new_layer);
    }
}

/// Build a Merkle tree from an array of hashable elements.
pub fn build(array: &dyn Array, factory: HashFactory) -> Result<Tree, MerkleError> {
    let array_len = array.length();
    let mut leaves = Vec::with_capacity(array_len as usize);

    for i in 0..array_len {
        let elem = array
            .marshal(i)
            .map_err(|e| MerkleError::ArrayError(e.to_string()))?;
        let hash = generic_hash_obj(&factory, elem.as_ref());
        leaves.push(hash);
    }

    let mut tree = Tree {
        levels: Vec::new(),
        num_of_elements: array_len,
        hash: factory,
        is_vector_commitment: false,
    };

    tree.build_layers(leaves);
    Ok(tree)
}

/// Build a vector commitment tree from an array.
///
/// The tree is padded to the next power of 2, and leaves are placed at
/// bit-reversed indices. This provides position binding.
pub fn build_vector_commitment_tree(
    array: &dyn Array,
    factory: HashFactory,
) -> Result<Tree, MerkleError> {
    let vc_array = VectorCommitmentArray::new(array);
    let mut tree = build(&vc_array, factory)?;
    tree.is_vector_commitment = true;
    tree.num_of_elements = array.length();
    Ok(tree)
}

// ── Vector commitment array ──────────────────────────────────────────

/// Bottom element for padding in vector commitment trees.
/// Hashes to `H("MB")`.
struct BottomElement;

impl Hashable for BottomElement {
    fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
        (MB_PREFIX, Vec::new())
    }
}

/// Wrapper that pads an array to the next power of 2 and applies
/// bit-reversal permutation to indices.
struct VectorCommitmentArray<'a> {
    inner: &'a dyn Array,
    path_len: u8,
    padded_len: u64,
}

impl<'a> VectorCommitmentArray<'a> {
    fn new(inner: &'a dyn Array) -> Self {
        let array_len = inner.length();
        if array_len <= 1 {
            return Self {
                inner,
                path_len: 1,
                padded_len: 1,
            };
        }

        let path = 64 - (array_len - 1).leading_zeros(); // bits.Len64(arrayLen-1)
        let full_size = 1u64 << path;
        Self {
            inner,
            path_len: path as u8,
            padded_len: full_size,
        }
    }
}

impl<'a> Array for VectorCommitmentArray<'a> {
    fn length(&self) -> u64 {
        self.padded_len
    }

    fn marshal(&self, pos: u64) -> Result<Box<dyn Hashable>, MerkleError> {
        let lsb_index = merkle_tree_to_vector_commitment_index(pos, self.path_len)?;
        if lsb_index >= self.padded_len {
            return Err(MerkleError::PosOutOfBound {
                pos,
                bound: self.padded_len,
            });
        }

        if lsb_index < self.inner.length() {
            self.inner.marshal(lsb_index)
        } else {
            Ok(Box::new(BottomElement))
        }
    }
}

/// Translate a Merkle tree index to a vector commitment index via bit reversal.
///
/// `path_len` is the depth of the tree.
pub fn merkle_tree_to_vector_commitment_index(
    msb_index: u64,
    path_len: u8,
) -> Result<u64, MerkleError> {
    if path_len == 0 {
        // Tree depth 0 means only index 0 is valid.
        if msb_index != 0 {
            return Err(MerkleError::PosOutOfBound {
                pos: msb_index,
                bound: 1,
            });
        }
        return Ok(0);
    }
    if msb_index >= (1u64 << path_len) {
        return Err(MerkleError::PosOutOfBound {
            pos: msb_index,
            bound: 1u64 << path_len,
        });
    }
    Ok(msb_index.reverse_bits() >> (64 - path_len))
}

// ── Verification ─────────────────────────────────────────────────────

/// Verify a Merkle proof against a root hash.
pub fn verify(
    root: &GenericDigest,
    elems: &[(u64, &dyn Hashable)],
    proof: &Proof,
) -> Result<(), MerkleError> {
    if elems.is_empty() {
        if !proof.path.is_empty() {
            return Err(MerkleError::NonEmptyProofForEmptyElements);
        }
        return Ok(());
    }

    let digest_size = proof.hash_factory.digest_size();

    // Hash all leaf elements.
    let mut hashed_leaves: Vec<(u64, GenericDigest)> = Vec::with_capacity(elems.len());
    for &(pos, elem) in elems {
        if pos >= (1u64 << proof.tree_depth) {
            return Err(MerkleError::PosOutOfBound {
                pos,
                bound: 1u64 << proof.tree_depth,
            });
        }
        let hash = generic_hash_obj(&proof.hash_factory, elem);
        hashed_leaves.push((pos, hash));
    }

    // Build sorted partial layer.
    hashed_leaves.sort_by_key(|(pos, _)| *pos);
    let pl: Vec<LayerItem> = hashed_leaves
        .into_iter()
        .map(|(pos, hash)| LayerItem { pos, hash })
        .collect();

    verify_path(root, proof, pl, digest_size)
}

/// Verify a vector commitment proof against a root hash.
pub fn verify_vector_commitment(
    root: &GenericDigest,
    elems: &[(u64, &dyn Hashable)],
    proof: &Proof,
) -> Result<(), MerkleError> {
    // Convert indices using bit reversal.
    let mut converted: Vec<(u64, &dyn Hashable)> = Vec::with_capacity(elems.len());
    for &(idx, elem) in elems {
        let vc_idx = merkle_tree_to_vector_commitment_index(idx, proof.tree_depth)?;
        converted.push((vc_idx, elem));
    }
    verify(root, &converted, proof)
}

fn verify_path(
    root: &GenericDigest,
    proof: &Proof,
    mut pl: Vec<LayerItem>,
    digest_size: usize,
) -> Result<(), MerkleError> {
    let mut hint_idx = 0;

    let mut l = 0u64;
    while hint_idx < proof.path.len() || pl.len() > 1 {
        pl = partial_layer_up(
            pl,
            &mut SiblingsVerify {
                hints: &proof.path,
                hint_idx: &mut hint_idx,
            },
            l,
            true,
            &proof.hash_factory,
            digest_size,
        )?;
        l += 1;
    }

    inspect_root(root, &pl)
}

fn inspect_root(root: &GenericDigest, pl: &[LayerItem]) -> Result<(), MerkleError> {
    if pl.is_empty() {
        return Err(MerkleError::InternalError(
            "empty partial layer".to_string(),
        ));
    }
    let computed = &pl[0];
    if computed.pos != 0 || computed.hash != *root {
        return Err(MerkleError::RootMismatch);
    }
    Ok(())
}

// ── Partial layer / siblings ─────────────────────────────────────────

#[derive(Clone)]
struct LayerItem {
    pos: u64,
    hash: GenericDigest,
}

/// Trait for getting sibling hashes (either from tree during prove, or
/// from proof hints during verify).
trait Siblings {
    fn get(&mut self, level: u64, pos: u64) -> Result<GenericDigest, MerkleError>;
}

/// Siblings implementation that reads from the tree (used during proof generation).
struct SiblingsProve<'a> {
    tree: &'a Tree,
    hints: &'a mut Vec<GenericDigest>,
}

impl<'a> Siblings for SiblingsProve<'a> {
    fn get(&mut self, level: u64, pos: u64) -> Result<GenericDigest, MerkleError> {
        if level >= self.tree.levels.len() as u64 {
            return Err(MerkleError::LevelBeyondTreeHeight {
                level,
                height: self.tree.levels.len(),
            });
        }

        let layer = &self.tree.levels[level as usize];
        let result = if (pos as usize) < layer.len() {
            layer[pos as usize].clone()
        } else {
            Vec::new()
        };

        self.hints.push(result.clone());
        Ok(result)
    }
}

/// Siblings implementation that reads from proof hints (used during verification).
struct SiblingsVerify<'a> {
    hints: &'a [GenericDigest],
    hint_idx: &'a mut usize,
}

impl<'a> Siblings for SiblingsVerify<'a> {
    fn get(&mut self, _level: u64, _pos: u64) -> Result<GenericDigest, MerkleError> {
        if *self.hint_idx >= self.hints.len() {
            return Err(MerkleError::NoMoreSiblingHints);
        }
        let result = self.hints[*self.hint_idx].clone();
        *self.hint_idx += 1;
        Ok(result)
    }
}

/// Move a partial layer one level up in the tree.
fn partial_layer_up(
    pl: Vec<LayerItem>,
    siblings: &mut dyn Siblings,
    level: u64,
    do_hash: bool,
    factory: &HashFactory,
    digest_size: usize,
) -> Result<Vec<LayerItem>, MerkleError> {
    let mut result = Vec::new();
    let mut i = 0;

    while i < pl.len() {
        let pos = pl[i].pos;
        let pos_hash = pl[i].hash.clone();

        let sibling_pos = pos ^ 1;
        let sibling_hash;

        if i + 1 < pl.len() && pl[i + 1].pos == sibling_pos {
            // Sibling is in the partial layer.
            sibling_hash = pl[i + 1].hash.clone();
            i += 1;
        } else {
            // Get sibling from tree or proof.
            sibling_hash = siblings.get(level, sibling_pos)?;
        }

        let next_pos = pos / 2;
        let next_hash = if do_hash {
            let (left, right) = if pos & 1 == 0 {
                (&pos_hash, &sibling_hash)
            } else {
                (&sibling_hash, &pos_hash)
            };

            // Hash internal node: H("MA" || left_padded || right_padded)
            let mut buf = Vec::with_capacity(2 * digest_size);
            buf.extend_from_slice(left);
            if left.len() < digest_size {
                buf.resize(digest_size, 0);
            }
            buf.extend_from_slice(right);
            if buf.len() < 2 * digest_size {
                buf.resize(2 * digest_size, 0);
            }

            factory.hash_bytes(&[MA_PREFIX, &buf])
        } else {
            Vec::new()
        };

        result.push(LayerItem {
            pos: next_pos,
            hash: next_hash,
        });

        i += 1;
    }

    Ok(result)
}

// ── Canonical msgpack serialization ──────────────────────────────────

impl HashFactory {
    /// Encode to canonical msgpack matching Go's field ordering.
    ///
    /// Go serialization: map with key `"t"` => uint16, omitempty.
    pub fn encode_msgpack(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        if self.is_zero() {
            // Empty map.
            buf.push(0x80);
        } else {
            // 1-element map.
            buf.push(0x81);
            // Key: "t"
            rmp::encode::write_str(&mut buf, "t").unwrap();
            // Value: uint16
            rmp::encode::write_uint(&mut buf, self.hash_type as u64).unwrap();
        }
        buf
    }

    /// Decode from canonical msgpack.
    pub fn decode_msgpack(data: &[u8]) -> Result<(Self, usize), MerkleError> {
        let mut offset = 0;

        let (map_len, bytes_read) = read_map_header(data)
            .map_err(|e| MerkleError::InternalError(format!("HashFactory decode: {e}")))?;
        offset += bytes_read;

        let mut hash_type = HashType::Sha512_256;

        for _ in 0..map_len {
            let (key, bytes_read) = read_str(&data[offset..])
                .map_err(|e| MerkleError::InternalError(format!("HashFactory key: {e}")))?;
            offset += bytes_read;

            match key.as_str() {
                "t" => {
                    let (val, bytes_read) = read_u16(&data[offset..]).map_err(|e| {
                        MerkleError::InternalError(format!("HashFactory value: {e}"))
                    })?;
                    offset += bytes_read;
                    hash_type = HashType::from_u16(val).ok_or_else(|| {
                        MerkleError::InternalError(format!("unknown hash type: {val}"))
                    })?;
                }
                other => {
                    return Err(MerkleError::InternalError(format!(
                        "unknown HashFactory field: {other}"
                    )));
                }
            }
        }

        Ok((Self { hash_type }, offset))
    }
}

impl Proof {
    /// Encode to canonical msgpack matching Go's field ordering.
    ///
    /// Fields (alphabetical, omitempty): `hsh`, `pth`, `td`.
    pub fn encode_msgpack(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Count non-empty fields.
        let mut count = 0u8;
        let has_hsh = !self.hash_factory.is_zero();
        let has_pth = !self.path.is_empty();
        let has_td = self.tree_depth != 0;
        if has_hsh {
            count += 1;
        }
        if has_pth {
            count += 1;
        }
        if has_td {
            count += 1;
        }

        // Map header.
        buf.push(0x80 | count);

        if has_hsh {
            rmp::encode::write_str(&mut buf, "hsh").unwrap();
            buf.extend_from_slice(&self.hash_factory.encode_msgpack());
        }

        if has_pth {
            rmp::encode::write_str(&mut buf, "pth").unwrap();
            rmp::encode::write_array_len(&mut buf, self.path.len() as u32).unwrap();
            for digest in &self.path {
                encode_generic_digest(&mut buf, digest);
            }
        }

        if has_td {
            rmp::encode::write_str(&mut buf, "td").unwrap();
            rmp::encode::write_uint(&mut buf, self.tree_depth as u64).unwrap();
        }

        buf
    }
}

impl SingleLeafProof {
    /// Encode to canonical msgpack (same as Proof — Go embeds Proof).
    pub fn encode_msgpack(&self) -> Vec<u8> {
        self.proof.encode_msgpack()
    }
}

impl Tree {
    /// Encode to canonical msgpack matching Go's field ordering.
    ///
    /// Fields (alphabetical, omitempty): `hsh`, `lvls`, `nl`, `vc`.
    pub fn encode_msgpack(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        let has_hsh = !self.hash.is_zero();
        let has_lvls = !self.levels.is_empty();
        let has_nl = self.num_of_elements != 0;
        let has_vc = self.is_vector_commitment;

        let mut count = 0u8;
        if has_hsh {
            count += 1;
        }
        if has_lvls {
            count += 1;
        }
        if has_nl {
            count += 1;
        }
        if has_vc {
            count += 1;
        }

        buf.push(0x80 | count);

        if has_hsh {
            rmp::encode::write_str(&mut buf, "hsh").unwrap();
            buf.extend_from_slice(&self.hash.encode_msgpack());
        }

        if has_lvls {
            rmp::encode::write_str(&mut buf, "lvls").unwrap();
            rmp::encode::write_array_len(&mut buf, self.levels.len() as u32).unwrap();
            for layer in &self.levels {
                rmp::encode::write_array_len(&mut buf, layer.len() as u32).unwrap();
                for digest in layer {
                    encode_generic_digest(&mut buf, digest);
                }
            }
        }

        if has_nl {
            rmp::encode::write_str(&mut buf, "nl").unwrap();
            rmp::encode::write_uint(&mut buf, self.num_of_elements).unwrap();
        }

        if has_vc {
            rmp::encode::write_str(&mut buf, "vc").unwrap();
            rmp::encode::write_bool(&mut buf, self.is_vector_commitment).unwrap();
        }

        buf
    }
}

/// Encode a GenericDigest (byte slice) as msgpack bin.
fn encode_generic_digest(buf: &mut Vec<u8>, digest: &GenericDigest) {
    if digest.is_empty() {
        // Go encodes empty/nil GenericDigest as nil.
        buf.push(0xc0);
    } else {
        rmp::encode::write_bin(buf, digest).unwrap();
    }
}

// ── Msgpack decoding helpers ─────────────────────────────────────────

fn read_map_header(data: &[u8]) -> Result<(usize, usize), String> {
    if data.is_empty() {
        return Err("empty data".into());
    }
    let b = data[0];
    if b & 0x80 == 0x80 && b & 0xf0 == 0x80 {
        // fixmap
        Ok(((b & 0x0f) as usize, 1))
    } else {
        Err(format!("expected map header, got 0x{b:02x}"))
    }
}

fn read_str(data: &[u8]) -> Result<(String, usize), String> {
    if data.is_empty() {
        return Err("empty data".into());
    }
    let b = data[0];
    if b & 0xe0 == 0xa0 {
        // fixstr
        let len = (b & 0x1f) as usize;
        if data.len() < 1 + len {
            return Err("str truncated".into());
        }
        let s = std::str::from_utf8(&data[1..1 + len])
            .map_err(|e| format!("invalid utf8: {e}"))?
            .to_string();
        Ok((s, 1 + len))
    } else {
        Err(format!("expected fixstr, got 0x{b:02x}"))
    }
}

fn read_u16(data: &[u8]) -> Result<(u16, usize), String> {
    if data.is_empty() {
        return Err("empty data".into());
    }
    let b = data[0];
    match b {
        // positive fixint
        0x00..=0x7f => Ok((b as u16, 1)),
        // uint8
        0xcc => {
            if data.len() < 2 {
                return Err("u8 truncated".into());
            }
            Ok((data[1] as u16, 2))
        }
        // uint16
        0xcd => {
            if data.len() < 3 {
                return Err("u16 truncated".into());
            }
            Ok((u16::from_be_bytes([data[1], data[2]]), 3))
        }
        _ => Err(format!("expected uint, got 0x{b:02x}")),
    }
}

impl Proof {
    /// Decode from canonical msgpack.
    ///
    /// Returns (Proof, bytes_consumed).
    pub fn decode_msgpack(data: &[u8]) -> Result<(Self, usize), MerkleError> {
        let mut offset = 0;

        let (map_len, bytes_read) = read_map_header(data)
            .map_err(|e| MerkleError::InternalError(format!("Proof map header: {e}")))?;
        offset += bytes_read;

        let mut proof = Proof::default();

        for _ in 0..map_len {
            let (key, bytes_read) = read_str(&data[offset..])
                .map_err(|e| MerkleError::InternalError(format!("Proof key: {e}")))?;
            offset += bytes_read;

            match key.as_str() {
                "hsh" => {
                    let (hf, bytes_read) = HashFactory::decode_msgpack(&data[offset..])?;
                    proof.hash_factory = hf;
                    offset += bytes_read;
                }
                "pth" => {
                    let (arr_len, bytes_read) = read_array_header(&data[offset..])
                        .map_err(|e| MerkleError::InternalError(format!("Proof pth: {e}")))?;
                    offset += bytes_read;
                    let mut path = Vec::with_capacity(arr_len);
                    for _ in 0..arr_len {
                        let (digest, bytes_read) =
                            read_bin_or_nil(&data[offset..]).map_err(|e| {
                                MerkleError::InternalError(format!("Proof pth elem: {e}"))
                            })?;
                        offset += bytes_read;
                        path.push(digest);
                    }
                    proof.path = path;
                }
                "td" => {
                    let (val, bytes_read) = read_u8(&data[offset..])
                        .map_err(|e| MerkleError::InternalError(format!("Proof td: {e}")))?;
                    proof.tree_depth = val;
                    offset += bytes_read;
                }
                _ => {
                    let bytes_read = skip_msgpack_value(&data[offset..])
                        .map_err(|e| MerkleError::InternalError(format!("Proof skip: {e}")))?;
                    offset += bytes_read;
                }
            }
        }

        Ok((proof, offset))
    }
}

impl SingleLeafProof {
    /// Decode from canonical msgpack (same layout as Proof — Go embeds Proof).
    pub fn decode_msgpack(data: &[u8]) -> Result<(Self, usize), MerkleError> {
        let (proof, consumed) = Proof::decode_msgpack(data)?;
        Ok((SingleLeafProof { proof }, consumed))
    }
}

impl Tree {
    /// Decode from canonical msgpack.
    ///
    /// Returns (Tree, bytes_consumed).
    pub fn decode_msgpack(data: &[u8]) -> Result<(Self, usize), MerkleError> {
        let mut offset = 0;

        let (map_len, bytes_read) = read_map_header(data)
            .map_err(|e| MerkleError::InternalError(format!("Tree map header: {e}")))?;
        offset += bytes_read;

        let mut tree = Tree::default();

        for _ in 0..map_len {
            let (key, bytes_read) = read_str(&data[offset..])
                .map_err(|e| MerkleError::InternalError(format!("Tree key: {e}")))?;
            offset += bytes_read;

            match key.as_str() {
                "hsh" => {
                    let (hf, bytes_read) = HashFactory::decode_msgpack(&data[offset..])?;
                    tree.hash = hf;
                    offset += bytes_read;
                }
                "lvls" => {
                    let (arr_len, bytes_read) = read_array_header(&data[offset..])
                        .map_err(|e| MerkleError::InternalError(format!("Tree lvls: {e}")))?;
                    offset += bytes_read;
                    let mut levels = Vec::with_capacity(arr_len);
                    for _ in 0..arr_len {
                        let (inner_len, bytes_read) = read_array_header(&data[offset..])
                            .map_err(|e| MerkleError::InternalError(format!("Tree layer: {e}")))?;
                        offset += bytes_read;
                        let mut layer = Vec::with_capacity(inner_len);
                        for _ in 0..inner_len {
                            let (digest, bytes_read) =
                                read_bin_or_nil(&data[offset..]).map_err(|e| {
                                    MerkleError::InternalError(format!("Tree digest: {e}"))
                                })?;
                            offset += bytes_read;
                            layer.push(digest);
                        }
                        levels.push(layer);
                    }
                    tree.levels = levels;
                }
                "nl" => {
                    let (val, bytes_read) = read_u64(&data[offset..])
                        .map_err(|e| MerkleError::InternalError(format!("Tree nl: {e}")))?;
                    tree.num_of_elements = val;
                    offset += bytes_read;
                }
                "vc" => {
                    let (val, bytes_read) = read_bool(&data[offset..])
                        .map_err(|e| MerkleError::InternalError(format!("Tree vc: {e}")))?;
                    tree.is_vector_commitment = val;
                    offset += bytes_read;
                }
                _ => {
                    let bytes_read = skip_msgpack_value(&data[offset..])
                        .map_err(|e| MerkleError::InternalError(format!("Tree skip: {e}")))?;
                    offset += bytes_read;
                }
            }
        }

        Ok((tree, offset))
    }
}

// ── Additional msgpack reading helpers ───────────────────────────────

fn read_array_header(data: &[u8]) -> Result<(usize, usize), String> {
    if data.is_empty() {
        return Err("empty data".into());
    }
    let b = data[0];
    if b & 0xf0 == 0x90 {
        // fixarray
        Ok(((b & 0x0f) as usize, 1))
    } else if b == 0xdc {
        // array16
        if data.len() < 3 {
            return Err("array16 truncated".into());
        }
        Ok((u16::from_be_bytes([data[1], data[2]]) as usize, 3))
    } else if b == 0xdd {
        // array32
        if data.len() < 5 {
            return Err("array32 truncated".into());
        }
        Ok((
            u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize,
            5,
        ))
    } else if b == 0xc0 {
        // nil => empty array
        Ok((0, 1))
    } else {
        Err(format!("expected array header, got 0x{b:02x}"))
    }
}

fn read_bin_or_nil(data: &[u8]) -> Result<(Vec<u8>, usize), String> {
    if data.is_empty() {
        return Err("empty data".into());
    }
    let b = data[0];
    if b == 0xc0 {
        // nil => empty digest
        return Ok((Vec::new(), 1));
    }
    let (len, hdr_size) = match b {
        0xc4 => {
            if data.len() < 2 {
                return Err("bin8 truncated".into());
            }
            (data[1] as usize, 2)
        }
        0xc5 => {
            if data.len() < 3 {
                return Err("bin16 truncated".into());
            }
            (u16::from_be_bytes([data[1], data[2]]) as usize, 3)
        }
        0xc6 => {
            if data.len() < 5 {
                return Err("bin32 truncated".into());
            }
            (
                u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize,
                5,
            )
        }
        _ => return Err(format!("expected bin or nil, got 0x{b:02x}")),
    };
    if data.len() < hdr_size + len {
        return Err("bin truncated".into());
    }
    Ok((data[hdr_size..hdr_size + len].to_vec(), hdr_size + len))
}

fn read_u8(data: &[u8]) -> Result<(u8, usize), String> {
    if data.is_empty() {
        return Err("empty data".into());
    }
    let b = data[0];
    match b {
        0x00..=0x7f => Ok((b, 1)),
        0xcc => {
            if data.len() < 2 {
                return Err("u8 truncated".into());
            }
            Ok((data[1], 2))
        }
        _ => Err(format!("expected uint8, got 0x{b:02x}")),
    }
}

fn read_u64(data: &[u8]) -> Result<(u64, usize), String> {
    if data.is_empty() {
        return Err("empty data".into());
    }
    let b = data[0];
    match b {
        0x00..=0x7f => Ok((b as u64, 1)),
        0xcc => {
            if data.len() < 2 {
                return Err("u8 truncated".into());
            }
            Ok((data[1] as u64, 2))
        }
        0xcd => {
            if data.len() < 3 {
                return Err("u16 truncated".into());
            }
            Ok((u16::from_be_bytes([data[1], data[2]]) as u64, 3))
        }
        0xce => {
            if data.len() < 5 {
                return Err("u32 truncated".into());
            }
            Ok((
                u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as u64,
                5,
            ))
        }
        0xcf => {
            if data.len() < 9 {
                return Err("u64 truncated".into());
            }
            Ok((
                u64::from_be_bytes([
                    data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
                ]),
                9,
            ))
        }
        _ => Err(format!("expected uint64, got 0x{b:02x}")),
    }
}

fn read_bool(data: &[u8]) -> Result<(bool, usize), String> {
    if data.is_empty() {
        return Err("empty data".into());
    }
    match data[0] {
        0xc2 => Ok((false, 1)),
        0xc3 => Ok((true, 1)),
        b => Err(format!("expected bool, got 0x{b:02x}")),
    }
}

/// Skip a single msgpack value, returning the number of bytes consumed.
fn skip_msgpack_value(data: &[u8]) -> Result<usize, String> {
    if data.is_empty() {
        return Err("empty data".into());
    }
    let b = data[0];
    // positive fixint
    if b <= 0x7f {
        return Ok(1);
    }
    // negative fixint
    if b >= 0xe0 {
        return Ok(1);
    }
    // fixmap
    if b & 0xf0 == 0x80 {
        let count = (b & 0x0f) as usize;
        let mut off = 1;
        for _ in 0..count * 2 {
            off += skip_msgpack_value(&data[off..])?;
        }
        return Ok(off);
    }
    // fixarray
    if b & 0xf0 == 0x90 {
        let count = (b & 0x0f) as usize;
        let mut off = 1;
        for _ in 0..count {
            off += skip_msgpack_value(&data[off..])?;
        }
        return Ok(off);
    }
    // fixstr
    if b & 0xe0 == 0xa0 {
        let len = (b & 0x1f) as usize;
        return Ok(1 + len);
    }
    match b {
        0xc0 | 0xc2 | 0xc3 => Ok(1),
        0xc4 => {
            if data.len() < 2 {
                return Err("truncated".into());
            }
            Ok(2 + data[1] as usize)
        }
        0xc5 => {
            if data.len() < 3 {
                return Err("truncated".into());
            }
            Ok(3 + u16::from_be_bytes([data[1], data[2]]) as usize)
        }
        0xc6 => {
            if data.len() < 5 {
                return Err("truncated".into());
            }
            Ok(5 + u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize)
        }
        0xca => Ok(5),
        0xcb => Ok(9),
        0xcc => Ok(2),
        0xcd => Ok(3),
        0xce => Ok(5),
        0xcf => Ok(9),
        0xd0 => Ok(2),
        0xd1 => Ok(3),
        0xd2 => Ok(5),
        0xd3 => Ok(9),
        0xd9 => {
            if data.len() < 2 {
                return Err("truncated".into());
            }
            Ok(2 + data[1] as usize)
        }
        0xda => {
            if data.len() < 3 {
                return Err("truncated".into());
            }
            Ok(3 + u16::from_be_bytes([data[1], data[2]]) as usize)
        }
        0xdb => {
            if data.len() < 5 {
                return Err("truncated".into());
            }
            Ok(5 + u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize)
        }
        0xdc => {
            if data.len() < 3 {
                return Err("truncated".into());
            }
            let count = u16::from_be_bytes([data[1], data[2]]) as usize;
            let mut off = 3;
            for _ in 0..count {
                off += skip_msgpack_value(&data[off..])?;
            }
            Ok(off)
        }
        0xdd => {
            if data.len() < 5 {
                return Err("truncated".into());
            }
            let count = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            let mut off = 5;
            for _ in 0..count {
                off += skip_msgpack_value(&data[off..])?;
            }
            Ok(off)
        }
        0xde => {
            if data.len() < 3 {
                return Err("truncated".into());
            }
            let count = u16::from_be_bytes([data[1], data[2]]) as usize;
            let mut off = 3;
            for _ in 0..count * 2 {
                off += skip_msgpack_value(&data[off..])?;
            }
            Ok(off)
        }
        0xdf => {
            if data.len() < 5 {
                return Err("truncated".into());
            }
            let count = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            let mut off = 5;
            for _ in 0..count * 2 {
                off += skip_msgpack_value(&data[off..])?;
            }
            Ok(off)
        }
        _ => Err(format!("unknown msgpack type 0x{b:02x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test Hashable / Array implementations ────────────────────────

    /// A test message that hashes with the "MX" (Message) prefix,
    /// matching Go's TestMessage type.
    struct TestMessage(Vec<u8>);

    impl Hashable for TestMessage {
        fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
            (b"MX", self.0.clone())
        }
    }

    /// A test array of byte data.
    struct TestArray(Vec<[u8; 32]>);

    impl Array for TestArray {
        fn length(&self) -> u64 {
            self.0.len() as u64
        }

        fn marshal(&self, pos: u64) -> Result<Box<dyn Hashable>, MerkleError> {
            if pos >= self.0.len() as u64 {
                return Err(MerkleError::PosOutOfBound {
                    pos,
                    bound: self.0.len() as u64,
                });
            }
            Ok(Box::new(TestMessage(self.0[pos as usize].to_vec())))
        }
    }

    // ── Empty tree tests ─────────────────────────────────────────────

    #[test]
    fn empty_tree_has_empty_root() {
        let arr = TestArray(vec![]);
        let tree = build(&arr, HashFactory::new(HashType::Sha512_256)).unwrap();
        assert!(tree.root().is_empty());
        assert!(tree.levels.is_empty());
        assert_eq!(tree.num_of_elements, 0);
    }

    // ── Single leaf tests ────────────────────────────────────────────

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        let data = [0x42u8; 32];
        let arr = TestArray(vec![data]);
        let factory = HashFactory::new(HashType::Sha512_256);
        let tree = build(&arr, factory).unwrap();

        assert_eq!(tree.levels.len(), 1);
        assert_eq!(tree.num_of_elements, 1);

        // Root should be H("MX" || data).
        let expected = factory.hash_bytes(&[b"MX", &data[..]]);
        assert_eq!(tree.root(), expected);
    }

    // ── Two-leaf tree ────────────────────────────────────────────────

    #[test]
    fn two_leaf_tree() {
        let data = [[1u8; 32], [2u8; 32]];
        let arr = TestArray(data.to_vec());
        let factory = HashFactory::new(HashType::Sha512_256);
        let tree = build(&arr, factory).unwrap();

        assert_eq!(tree.levels.len(), 2); // leaves + root
        assert_eq!(tree.levels[0].len(), 2);
        assert_eq!(tree.levels[1].len(), 1);

        let leaf0 = factory.hash_bytes(&[b"MX", &data[0][..]]);
        let leaf1 = factory.hash_bytes(&[b"MX", &data[1][..]]);

        // Internal node: H("MA" || leaf0 || leaf1)
        let mut internal_buf = Vec::new();
        internal_buf.extend_from_slice(&leaf0);
        internal_buf.extend_from_slice(&leaf1);
        let expected_root = factory.hash_bytes(&[MA_PREFIX, &internal_buf]);
        assert_eq!(tree.root(), expected_root);
    }

    // ── Three-leaf tree (odd) ────────────────────────────────────────

    #[test]
    fn three_leaf_tree_odd_count() {
        let data = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let arr = TestArray(data.to_vec());
        let factory = HashFactory::new(HashType::Sha512_256);
        let tree = build(&arr, factory).unwrap();

        assert_eq!(tree.levels.len(), 3); // leaves, internal, root
        assert_eq!(tree.levels[0].len(), 3);
        assert_eq!(tree.levels[1].len(), 2);
        assert_eq!(tree.levels[2].len(), 1);

        let leaf0 = factory.hash_bytes(&[b"MX", &data[0][..]]);
        let leaf1 = factory.hash_bytes(&[b"MX", &data[1][..]]);
        let leaf2 = factory.hash_bytes(&[b"MX", &data[2][..]]);

        let digest_size = factory.digest_size();

        // n0 = H("MA" || leaf0 || leaf1)
        let mut buf01 = Vec::new();
        buf01.extend_from_slice(&leaf0);
        buf01.extend_from_slice(&leaf1);
        let n0 = factory.hash_bytes(&[MA_PREFIX, &buf01]);

        // n1 = H("MA" || leaf2 || zeros) — missing child gets zeros
        let mut buf2z = Vec::new();
        buf2z.extend_from_slice(&leaf2);
        buf2z.resize(2 * digest_size, 0);
        let n1 = factory.hash_bytes(&[MA_PREFIX, &buf2z]);

        // root = H("MA" || n0 || n1)
        let mut buf_root = Vec::new();
        buf_root.extend_from_slice(&n0);
        buf_root.extend_from_slice(&n1);
        let expected_root = factory.hash_bytes(&[MA_PREFIX, &buf_root]);

        assert_eq!(tree.root(), expected_root);
    }

    // ── Prove and verify single leaf ─────────────────────────────────

    #[test]
    fn prove_and_verify_single_leaf() {
        let data: Vec<[u8; 32]> = (0..8u8).map(|i| [i; 32]).collect();
        let arr = TestArray(data.clone());
        let factory = HashFactory::new(HashType::Sha512_256);
        let tree = build(&arr, factory).unwrap();
        let root = tree.root();

        for idx in 0..8u64 {
            let slp = tree.prove_single_leaf(idx).unwrap();
            assert_eq!(slp.proof.tree_depth, 3); // 8 leaves = depth 3

            // Verify the proof.
            let elem = TestMessage(data[idx as usize].to_vec());
            let result = verify(&root, &[(idx, &elem)], &slp.proof);
            assert!(result.is_ok(), "verification failed for idx {idx}");
        }
    }

    #[test]
    fn prove_and_verify_power_of_two() {
        for &n in &[1, 2, 4, 8, 16] {
            let data: Vec<[u8; 32]> = (0..n as u8).map(|i| [i; 32]).collect();
            let arr = TestArray(data.clone());
            let factory = HashFactory::new(HashType::Sha512_256);
            let tree = build(&arr, factory).unwrap();
            let root = tree.root();

            for idx in 0..n as u64 {
                let slp = tree.prove_single_leaf(idx).unwrap();
                let elem = TestMessage(data[idx as usize].to_vec());
                let result = verify(&root, &[(idx, &elem)], &slp.proof);
                assert!(result.is_ok(), "failed n={n} idx={idx}: {:?}", result.err());
            }
        }
    }

    #[test]
    fn prove_and_verify_non_power_of_two() {
        for &n in &[3, 5, 7, 9, 15] {
            let data: Vec<[u8; 32]> = (0..n as u8).map(|i| [i; 32]).collect();
            let arr = TestArray(data.clone());
            let factory = HashFactory::new(HashType::Sha512_256);
            let tree = build(&arr, factory).unwrap();
            let root = tree.root();

            for idx in 0..n as u64 {
                let slp = tree.prove_single_leaf(idx).unwrap();
                let elem = TestMessage(data[idx as usize].to_vec());
                let result = verify(&root, &[(idx, &elem)], &slp.proof);
                assert!(result.is_ok(), "failed n={n} idx={idx}: {:?}", result.err());
            }
        }
    }

    // ── Vector commitment tests ──────────────────────────────────────

    #[test]
    fn vector_commitment_build_and_verify() {
        let data: Vec<[u8; 32]> = (0..5u8).map(|i| [i; 32]).collect();
        let arr = TestArray(data.clone());
        let factory = HashFactory::new(HashType::Sha512_256);
        let tree = build_vector_commitment_tree(&arr, factory).unwrap();

        assert!(tree.is_vector_commitment);
        assert_eq!(tree.num_of_elements, 5);

        let root = tree.root();

        for idx in 0..5u64 {
            let slp = tree.prove_single_leaf(idx).unwrap();
            let elem = TestMessage(data[idx as usize].to_vec());
            let result = verify_vector_commitment(&root, &[(idx, &elem)], &slp.proof);
            assert!(
                result.is_ok(),
                "VC verify failed for idx {idx}: {:?}",
                result.err()
            );
        }
    }

    #[test]
    fn vector_commitment_empty() {
        let arr = TestArray(vec![]);
        let factory = HashFactory::new(HashType::Sha512_256);
        let tree = build_vector_commitment_tree(&arr, factory).unwrap();

        assert!(tree.is_vector_commitment);
        assert_eq!(tree.num_of_elements, 0);
        // Root should be H("MX" prefix applied to BottomElement, which has prefix "MB")
        // Actually for VC empty: the VC array has paddedLen=1, with one BottomElement.
        // BottomElement hashes to H("MB"), where H is SHA-512/256.
        // The tree has 1 leaf, root = that leaf hash.
        let expected = factory.hash_bytes(&[MB_PREFIX]);
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn vector_commitment_single() {
        let data = [[42u8; 32]];
        let arr = TestArray(data.to_vec());
        let factory = HashFactory::new(HashType::Sha512_256);
        let tree = build_vector_commitment_tree(&arr, factory).unwrap();

        assert!(tree.is_vector_commitment);
        assert_eq!(tree.num_of_elements, 1);

        let root = tree.root();
        let slp = tree.prove_single_leaf(0).unwrap();
        let elem = TestMessage(data[0].to_vec());
        let result = verify_vector_commitment(&root, &[(0, &elem)], &slp.proof);
        assert!(result.is_ok());
    }

    // ── Bit reversal tests ───────────────────────────────────────────

    #[test]
    fn bit_reversal_depth_one() {
        assert_eq!(merkle_tree_to_vector_commitment_index(0, 1).unwrap(), 0);
        assert_eq!(merkle_tree_to_vector_commitment_index(1, 1).unwrap(), 1);
    }

    #[test]
    fn bit_reversal_depth_three() {
        // 0(000) -> 0(000), 1(001) -> 4(100), 2(010) -> 2(010), 3(011) -> 6(110)
        assert_eq!(merkle_tree_to_vector_commitment_index(0, 3).unwrap(), 0);
        assert_eq!(merkle_tree_to_vector_commitment_index(1, 3).unwrap(), 4);
        assert_eq!(merkle_tree_to_vector_commitment_index(2, 3).unwrap(), 2);
        assert_eq!(merkle_tree_to_vector_commitment_index(3, 3).unwrap(), 6);
        assert_eq!(merkle_tree_to_vector_commitment_index(4, 3).unwrap(), 1);
        assert_eq!(merkle_tree_to_vector_commitment_index(5, 3).unwrap(), 5);
        assert_eq!(merkle_tree_to_vector_commitment_index(6, 3).unwrap(), 3);
        assert_eq!(merkle_tree_to_vector_commitment_index(7, 3).unwrap(), 7);
    }

    #[test]
    fn bit_reversal_is_involution() {
        for depth in 1..6u8 {
            let size = 1u64 << depth;
            for i in 0..size {
                let reversed = merkle_tree_to_vector_commitment_index(i, depth).unwrap();
                let back = merkle_tree_to_vector_commitment_index(reversed, depth).unwrap();
                assert_eq!(back, i, "involution failed for i={i}, depth={depth}");
            }
        }
    }

    #[test]
    fn bit_reversal_out_of_bounds() {
        assert!(merkle_tree_to_vector_commitment_index(8, 3).is_err());
        assert!(merkle_tree_to_vector_commitment_index(2, 1).is_err());
    }

    // ── Verification failure tests ───────────────────────────────────

    #[test]
    fn verify_wrong_element_fails() {
        let data: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let arr = TestArray(data);
        let factory = HashFactory::new(HashType::Sha512_256);
        let tree = build(&arr, factory).unwrap();
        let root = tree.root();

        let slp = tree.prove_single_leaf(0).unwrap();
        // Verify with wrong data.
        let wrong_elem = TestMessage(vec![0xFF; 32]);
        let result = verify(&root, &[(0, &wrong_elem)], &slp.proof);
        assert!(result.is_err());
    }

    #[test]
    fn verify_wrong_root_fails() {
        let data: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let arr = TestArray(data.clone());
        let factory = HashFactory::new(HashType::Sha512_256);
        let tree = build(&arr, factory).unwrap();

        let slp = tree.prove_single_leaf(0).unwrap();
        let elem = TestMessage(data[0].to_vec());
        let wrong_root = vec![0xFFu8; 32];
        let result = verify(&wrong_root, &[(0, &elem)], &slp.proof);
        assert!(result.is_err());
    }

    #[test]
    fn verify_empty_proof_empty_elems_ok() {
        let proof = Proof {
            path: Vec::new(),
            hash_factory: HashFactory::new(HashType::Sha512_256),
            tree_depth: 3,
        };
        let root = vec![0u8; 32];
        let result = verify(&root, &[], &proof);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_non_empty_proof_empty_elems_fails() {
        let proof = Proof {
            path: vec![vec![0u8; 32]],
            hash_factory: HashFactory::new(HashType::Sha512_256),
            tree_depth: 3,
        };
        let root = vec![0u8; 32];
        let result = verify(&root, &[], &proof);
        assert_eq!(result, Err(MerkleError::NonEmptyProofForEmptyElements));
    }

    // ── Sumhash tree tests ───────────────────────────────────────────

    #[test]
    fn sumhash_tree_build_and_verify() {
        let data: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let arr = TestArray(data.clone());
        let factory = HashFactory::new(HashType::Sumhash);
        let tree = build(&arr, factory).unwrap();

        assert_eq!(tree.root().len(), 64); // Sumhash produces 64-byte digests.

        let root = tree.root();
        for idx in 0..4u64 {
            let slp = tree.prove_single_leaf(idx).unwrap();
            let elem = TestMessage(data[idx as usize].to_vec());
            let result = verify(&root, &[(idx, &elem)], &slp.proof);
            assert!(
                result.is_ok(),
                "Sumhash verify failed for idx {idx}: {:?}",
                result.err()
            );
        }
    }

    // ── Serialization tests ──────────────────────────────────────────

    #[test]
    fn hash_factory_encode_default_is_empty_map() {
        let hf = HashFactory::default(); // Sha512_256 = 0
        let encoded = hf.encode_msgpack();
        // Empty map: 0x80
        assert_eq!(encoded, vec![0x80]);
    }

    #[test]
    fn hash_factory_encode_sumhash() {
        let hf = HashFactory::new(HashType::Sumhash);
        let encoded = hf.encode_msgpack();
        let (decoded, _) = HashFactory::decode_msgpack(&encoded).unwrap();
        assert_eq!(decoded.hash_type, HashType::Sumhash);
    }

    #[test]
    fn hash_factory_roundtrip() {
        for ht in &[
            HashType::Sha512_256,
            HashType::Sumhash,
            HashType::Sha256,
            HashType::Sha512,
        ] {
            let hf = HashFactory::new(*ht);
            let encoded = hf.encode_msgpack();
            let (decoded, _) = HashFactory::decode_msgpack(&encoded).unwrap();
            assert_eq!(decoded, hf);
        }
    }

    #[test]
    fn proof_encode_empty() {
        let proof = Proof::default();
        let encoded = proof.encode_msgpack();
        // All fields empty -> empty map.
        assert_eq!(encoded, vec![0x80]);
    }

    #[test]
    fn tree_encode_empty() {
        let tree = Tree::default();
        let encoded = tree.encode_msgpack();
        assert_eq!(encoded, vec![0x80]);
    }

    #[test]
    fn tree_encode_has_correct_field_order() {
        // Build a small tree and encode it.
        let data = [[1u8; 32]];
        let arr = TestArray(data.to_vec());
        let factory = HashFactory::new(HashType::Sumhash); // non-zero so hsh is present
        let tree = build(&arr, factory).unwrap();
        let encoded = tree.encode_msgpack();

        // The encoded map should have fields in alphabetical order: hsh, lvls, nl.
        // (vc is false, so omitted.)
        // Verify by finding field name positions.
        let encoded_str = String::from_utf8_lossy(&encoded);
        let hsh_pos = encoded.windows(3).position(|w| w == b"hsh");
        let lvls_pos = encoded.windows(4).position(|w| w == b"lvls");
        let nl_pos = encoded.windows(2).position(|w| w == b"nl");

        assert!(hsh_pos.is_some(), "hsh not found in encoding");
        assert!(
            lvls_pos.is_some(),
            "lvls not found in encoding: {encoded_str}"
        );
        assert!(nl_pos.is_some(), "nl not found in encoding");

        assert!(
            hsh_pos.unwrap() < lvls_pos.unwrap(),
            "hsh should come before lvls"
        );
        assert!(
            lvls_pos.unwrap() < nl_pos.unwrap(),
            "lvls should come before nl"
        );
    }

    // ── SingleLeafProof fixed-length representation ──────────────────

    #[test]
    fn single_leaf_proof_fixed_length_representation() {
        let data: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let arr = TestArray(data);
        let factory = HashFactory::new(HashType::Sha512_256);
        let tree = build(&arr, factory).unwrap();

        let slp = tree.prove_single_leaf(0).unwrap();
        let repr = slp.get_fixed_length_hashable_representation();

        // Expected size: 1 + MAX_ENCODED_TREE_DEPTH * 32
        let expected_len = 1 + MAX_ENCODED_TREE_DEPTH * 32;
        assert_eq!(repr.len(), expected_len);
        assert_eq!(repr[0], slp.proof.tree_depth);
    }

    // ── Prove out-of-bounds ──────────────────────────────────────────

    #[test]
    fn prove_out_of_bounds() {
        let data = [[1u8; 32]];
        let arr = TestArray(data.to_vec());
        let factory = HashFactory::new(HashType::Sha512_256);
        let tree = build(&arr, factory).unwrap();

        let result = tree.prove_single_leaf(1);
        assert!(result.is_err());
    }

    #[test]
    fn prove_empty_tree() {
        let arr = TestArray(vec![]);
        let factory = HashFactory::new(HashType::Sha512_256);
        let tree = build(&arr, factory).unwrap();

        let result = tree.prove_single_leaf(0);
        assert!(matches!(result, Err(MerkleError::ProvingZeroCommitment)));
    }

    // ── Empty proof ──────────────────────────────────────────────────

    #[test]
    fn prove_empty_indices() {
        let data = [[1u8; 32]];
        let arr = TestArray(data.to_vec());
        let factory = HashFactory::new(HashType::Sha512_256);
        let tree = build(&arr, factory).unwrap();

        let proof = tree.prove(&[]).unwrap();
        assert!(proof.path.is_empty());
    }

    // ── VC with Sumhash ──────────────────────────────────────────────

    #[test]
    fn vector_commitment_sumhash() {
        let data: Vec<[u8; 32]> = (0..3u8).map(|i| [i; 32]).collect();
        let arr = TestArray(data.clone());
        let factory = HashFactory::new(HashType::Sumhash);
        let tree = build_vector_commitment_tree(&arr, factory).unwrap();

        assert!(tree.is_vector_commitment);
        assert_eq!(tree.root().len(), 64);

        let root = tree.root();
        for idx in 0..3u64 {
            let slp = tree.prove_single_leaf(idx).unwrap();
            let elem = TestMessage(data[idx as usize].to_vec());
            let result = verify_vector_commitment(&root, &[(idx, &elem)], &slp.proof);
            assert!(
                result.is_ok(),
                "Sumhash VC verify failed for idx {idx}: {:?}",
                result.err()
            );
        }
    }

    // ── Determinism ──────────────────────────────────────────────────

    #[test]
    fn tree_build_is_deterministic() {
        let data: Vec<[u8; 32]> = (0..10u8).map(|i| [i; 32]).collect();
        let arr = TestArray(data);
        let factory = HashFactory::new(HashType::Sha512_256);
        let tree1 = build(&arr, factory).unwrap();
        let tree2 = build(&arr, factory).unwrap();
        assert_eq!(tree1.root(), tree2.root());
        assert_eq!(tree1.levels.len(), tree2.levels.len());
    }

    // ── Larger tree tests ────────────────────────────────────────────

    #[test]
    fn prove_verify_large_tree() {
        let n = 100;
        let data: Vec<[u8; 32]> = (0..n)
            .map(|i| {
                let mut d = [0u8; 32];
                d[0] = (i & 0xFF) as u8;
                d[1] = ((i >> 8) & 0xFF) as u8;
                d
            })
            .collect();
        let arr = TestArray(data.clone());
        let factory = HashFactory::new(HashType::Sha512_256);
        let tree = build(&arr, factory).unwrap();
        let root = tree.root();

        // Verify every 10th element.
        for idx in (0..n as u64).step_by(10) {
            let slp = tree.prove_single_leaf(idx).unwrap();
            let elem = TestMessage(data[idx as usize].to_vec());
            let result = verify(&root, &[(idx, &elem)], &slp.proof);
            assert!(result.is_ok(), "failed at idx {idx}: {:?}", result.err());
        }
    }
}
