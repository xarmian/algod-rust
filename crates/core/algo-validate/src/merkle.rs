// Epic 11: Merkle array tree for payset commitment verification.
//
// Implements go-algorand's `crypto/merklearray` construction:
//   - Leaf: SHA512/256("TL" || txid || stib_hash)
//   - Internal node: SHA512/256("MA" || left_hash || right_hash)
//   - Missing children (odd-length layers) are 32 zero bytes.
//   - Empty tree root: 32 zero bytes.
//
// References:
//   - go-algorand/crypto/merklearray/merkle.go (Build, buildLayers)
//   - go-algorand/crypto/merklearray/layer.go (upWorker, pair)
//   - go-algorand/data/bookkeeping/txn_merkle.go (txnMerkleElem)
//   - go-algorand/protocol/hash.go (HashID constants)

use algo_codec::{canonical_encode_signed_txn_in_block, canonical_encode_transaction};
use algo_types::{Block, SignedTransaction};
use sha2::{Digest as _, Sha256, Sha512, Sha512_256};

/// Domain separation prefix for Merkle array internal nodes.
const MA_PREFIX: &[u8] = b"MA";

/// Domain separation prefix for transaction Merkle tree leaves.
const TL_PREFIX: &[u8] = b"TL";

/// Domain separation prefix for transaction ID hashing.
const TX_PREFIX: &[u8] = b"TX";

/// Domain separation prefix for SignedTxnInBlock hashing.
const STIB_PREFIX: &[u8] = b"STIB";

/// Domain separation prefix for vector commitment bottom (padding) leaves.
///
/// go-algorand: `protocol.MerkleVectorCommitmentBottomLeaf = "MB"`.
/// Padded positions in a vector commitment tree hash to H("MB") rather than
/// being zero or empty. This ensures position-binding even for unfilled slots.
const MB_PREFIX: &[u8] = b"MB";

/// A 32-byte hash digest.
type Hash = [u8; 32];

/// The zero hash used for missing children in the Merkle tree.
const ZERO_HASH: Hash = [0u8; 32];

/// Compute the transaction ID: SHA512/256("TX" || canonical_encode(txn)).
///
/// For Merkle commitment, the txid must be computed with genesis fields
/// RESTORED (genesis_id and genesis_hash), matching go-algorand's
/// `DecodeSignedTxn` which restores these before calling `txn.ID()`.
fn compute_txid(txn: &algo_types::Transaction) -> Hash {
    let canonical = canonical_encode_transaction(txn);
    let mut hasher = Sha512_256::new();
    hasher.update(TX_PREFIX);
    hasher.update(&canonical);
    hasher.finalize().into()
}

/// Compute the SignedTxnInBlock hash: SHA512/256("STIB" || canonical_encode(stib)).
fn compute_stib_hash(stx: &SignedTransaction) -> Hash {
    let canonical = canonical_encode_signed_txn_in_block(stx);
    let mut hasher = Sha512_256::new();
    hasher.update(STIB_PREFIX);
    hasher.update(&canonical);
    hasher.finalize().into()
}

/// Compute a Merkle leaf hash: SHA512/256("TL" || txid || stib_hash).
fn compute_leaf_hash(txid: &Hash, stib_hash: &Hash) -> Hash {
    let mut hasher = Sha512_256::new();
    hasher.update(TL_PREFIX);
    hasher.update(txid);
    hasher.update(stib_hash);
    hasher.finalize().into()
}

/// Compute an internal Merkle node hash: SHA512/256("MA" || left || right).
///
/// If one child is missing (odd-length layer), the caller passes `ZERO_HASH`.
fn compute_internal_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha512_256::new();
    hasher.update(MA_PREFIX);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Build a single layer of parent hashes from a child layer.
///
/// Children are paired left-to-right. If the child layer has an odd count,
/// the last child is paired with ZERO_HASH (go-algorand behavior).
fn build_next_layer(children: &[Hash]) -> Vec<Hash> {
    let parent_count = children.len().div_ceil(2);
    let mut parents = Vec::with_capacity(parent_count);

    let mut i = 0;
    while i < children.len() {
        let left = &children[i];
        let right = if i + 1 < children.len() {
            &children[i + 1]
        } else {
            &ZERO_HASH
        };
        parents.push(compute_internal_hash(left, right));
        i += 2;
    }

    parents
}

/// Compute the payset Merkle tree root from a block.
///
/// This matches go-algorand's `TxnMerkleTree().Root()` using SHA512/256.
///
/// For each transaction in the payset:
///   1. Restore genesis fields (genesis_id if hgi=true, genesis_hash always)
///   2. Compute txid = SHA512/256("TX" || canonical_encode(txn_with_genesis))
///   3. Compute stib_hash = SHA512/256("STIB" || canonical_encode(stib_as_in_block))
///   4. Compute leaf = SHA512/256("TL" || txid || stib_hash)
///
/// Then build a binary Merkle tree bottom-up, where internal nodes are
/// SHA512/256("MA" || left || right). Missing children are 32 zero bytes.
///
/// An empty payset returns 32 zero bytes.
///
/// # Genesis field restoration
///
/// go-algorand's `TxnMerkleTree` calls `DecodeSignedTxn` which restores
/// genesis_id and genesis_hash on the inner Transaction before computing
/// `txn.ID()`. The STIB hash, however, uses the payset entry as-is
/// (without genesis restoration) since the STIB encoding matches the
/// block's stored representation.
pub fn compute_payset_merkle_root(block: &Block) -> Hash {
    if block.payset.is_empty() {
        return ZERO_HASH;
    }

    // Build leaf layer.
    let mut layer: Vec<Hash> = block
        .payset
        .iter()
        .map(|stx| {
            // Restore genesis fields for txid computation (matching go-algorand's
            // DecodeSignedTxn behavior).
            let mut restored_txn = stx.txn.clone();
            if stx.has_genesis_id && restored_txn.genesis_id.is_empty() {
                restored_txn.genesis_id.clone_from(&block.genesis_id);
            }
            if restored_txn.genesis_hash == [0u8; 32] {
                restored_txn.genesis_hash = block.genesis_hash;
            }

            let txid = compute_txid(&restored_txn);
            // STIB hash uses the payset entry as stored in the block
            // (without genesis restoration, but WITH ApplyData fields).
            let stib_hash = compute_stib_hash(stx);
            compute_leaf_hash(&txid, &stib_hash)
        })
        .collect();

    // Build tree bottom-up until we have a single root.
    while layer.len() > 1 {
        layer = build_next_layer(&layer);
    }

    layer[0]
}

/// Compute the flat payset commitment: SHA512/256("PF" || canonical_encode(payset)).
///
/// This matches go-algorand's `Payset.CommitFlat()` for older protocol versions
/// that use PaysetCommitFlat (pre-v24). Not used by the current Merkle-based
/// commitment path, but retained for Epic 12 (mainnet block replay) where
/// older protocol versions may be encountered.
///
/// The encoding is `protocol.Encode(payset)`, which for a Payset
/// ([]SignedTxnInBlock) is a msgpack array of SignedTxnInBlock maps.
///
/// Note: for an empty payset, go-algorand encodes nil (0xc0) rather than an
/// empty array (0x90), yielding SHA512/256("PF" || 0xc0).
#[allow(dead_code)]
pub fn compute_payset_flat_commitment(payset: &[SignedTransaction]) -> Hash {
    let mut hasher = Sha512_256::new();
    hasher.update(b"PF");

    if payset.is_empty() {
        // go-algorand: nil slice encodes as msgpack Nil (0xc0).
        hasher.update([0xc0]);
    } else {
        // Encode as msgpack array of canonical SignedTxnInBlock entries.
        let mut buf = Vec::new();
        rmp::encode::write_array_len(
            &mut buf,
            u32::try_from(payset.len()).expect("payset length fits in u32"),
        )
        .unwrap();
        for stx in payset {
            let encoded = canonical_encode_signed_txn_in_block(stx);
            buf.extend_from_slice(&encoded);
        }
        hasher.update(&buf);
    }

    hasher.finalize().into()
}

// ── Vector commitment (txn256 / txn512) ─────────────────────────────
//
// Implements go-algorand's `crypto/merklearray/vectorCommitmentArray`
// construction used for the `txn256` (SHA-256) and `txn512` (SHA-512)
// block header fields.
//
// Differences from the primary Merkle tree (`txn` field):
//   - Hash function is SHA-256 (32-byte) or SHA-512 (64-byte) instead of
//     SHA-512/256.
//   - Leaf count is padded to the next power of 2 with "bottom element"
//     leaves that hash to H("MB") (protocol.MerkleVectorCommitmentBottomLeaf).
//   - Leaves are reordered by bit-reversal permutation before tree
//     construction (`merkleTreeToVectorCommitmentIndex`).
//   - Same domain separation prefixes: "TL" (leaf), "MA" (internal).
//
// References:
//   - go-algorand/crypto/merklearray/merkle.go (Build, merkleTreeToVectorCommitmentIndex)
//   - go-algorand/crypto/compactcert/builder.go (for SHA-512 usage)

/// Which hash function to use for vector commitment computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    /// SHA-256 (32-byte output) — used for `txn256`.
    Sha256,
    /// SHA-512 (64-byte output) — used for `txn512`.
    Sha512,
}

/// Reverse the `depth` least-significant bits of `index`.
///
/// This implements go-algorand's `merkleTreeToVectorCommitmentIndex`
/// which converts a standard Merkle tree index to a vector commitment
/// index via bit-reversal permutation.
///
/// Example (depth=3): index 1 (001) → 4 (100), index 3 (011) → 6 (110).
pub fn bit_reverse(index: usize, depth: u32) -> usize {
    if depth == 0 {
        return 0;
    }
    let mut result: usize = 0;
    let mut val = index;
    for _ in 0..depth {
        result = (result << 1) | (val & 1);
        val >>= 1;
    }
    result
}

/// Generic hash helper that dispatches to SHA-256 or SHA-512.
///
/// Returns a `Vec<u8>` of 32 bytes (SHA-256) or 64 bytes (SHA-512).
fn vc_hash(algo: HashAlgo, parts: &[&[u8]]) -> Vec<u8> {
    match algo {
        HashAlgo::Sha256 => {
            let mut h = Sha256::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().to_vec()
        }
        HashAlgo::Sha512 => {
            let mut h = Sha512::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().to_vec()
        }
    }
}

/// Hash helper that always uses SHA-256.
///
/// go-algorand's `txnMerkleElem.RawLeaf()` uses SHA-256 for leaf DATA
/// (txid and stib_hash) when the tree hash type is either `Sha256` or
/// `Sha512`. Only the `Sha512_256` tree type uses SHA-512/256 for leaf
/// data. See `data/bookkeeping/txn_merkle.go` lines 101-107.
fn vc_hash_sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

/// Return the zero hash for the given algorithm (all-zero bytes of the
/// appropriate digest size).
#[allow(dead_code)]
fn vc_zero_hash(algo: HashAlgo) -> Vec<u8> {
    match algo {
        HashAlgo::Sha256 => vec![0u8; 32],
        HashAlgo::Sha512 => vec![0u8; 64],
    }
}

/// Compute a vector commitment leaf: H("TL" || txid || stib_hash).
fn vc_leaf_hash(algo: HashAlgo, txid: &[u8], stib_hash: &[u8]) -> Vec<u8> {
    vc_hash(algo, &[TL_PREFIX, txid, stib_hash])
}

/// Compute a vector commitment internal node: H("MA" || left || right).
fn vc_internal_hash(algo: HashAlgo, left: &[u8], right: &[u8]) -> Vec<u8> {
    vc_hash(algo, &[MA_PREFIX, left, right])
}

/// Compute the vector commitment root for a block's payset.
///
/// This implements go-algorand's vector commitment tree used for the
/// `txn256` and `txn512` block header fields.
///
/// `stib_encodings` is the list of canonical STIB encodings for each
/// transaction in the payset (same encodings used by the primary Merkle
/// tree). The caller is responsible for producing these.
///
/// Returns 32 bytes for SHA-256 or 64 bytes for SHA-512.
/// An empty payset returns the zero hash of the appropriate size.
pub fn compute_vector_commitment(block: &Block, algo: HashAlgo) -> Vec<u8> {
    if block.payset.is_empty() {
        // go-algorand's generateVectorCommitmentArray returns paddedLen=1 for
        // arrayLen=0, creating a single bottomElement leaf that hashes to H("MB").
        // The tree root is just that one leaf hash.
        return vc_hash(algo, &[MB_PREFIX]);
    }

    let n = block.payset.len();

    // Compute leaf hashes.
    //
    // go-algorand's `txnMerkleElem.RawLeaf()` (data/bookkeeping/txn_merkle.go)
    // determines the hash algorithm for leaf DATA (txid and stib_hash):
    //   - Sha512_256: uses txn.ID() (SHA-512/256) + stib.Hash() (SHA-512/256)
    //   - Sha256 OR Sha512: uses txn.IDSha256() (SHA-256) + stib.HashSHA256() (SHA-256)
    //
    // The TREE construction (TL leaf wrapping, MA internal nodes) always uses
    // the tree's own hash algorithm. So for Sha512 vector commitments, leaf
    // data is SHA-256 but tree hashing is SHA-512.
    let leaf_hashes: Vec<Vec<u8>> = block
        .payset
        .iter()
        .map(|stx| {
            // Restore genesis fields for txid (same as primary Merkle tree).
            let mut restored_txn = stx.txn.clone();
            if stx.has_genesis_id && restored_txn.genesis_id.is_empty() {
                restored_txn.genesis_id.clone_from(&block.genesis_id);
            }
            if restored_txn.genesis_hash == [0u8; 32] {
                restored_txn.genesis_hash = block.genesis_hash;
            }

            let txn_canonical = canonical_encode_transaction(&restored_txn);
            // Leaf data (txid, stib_hash) always uses SHA-256 for both
            // Sha256 and Sha512 vector commitments.
            let txid = vc_hash_sha256(&[TX_PREFIX, &txn_canonical]);

            let stib_canonical = canonical_encode_signed_txn_in_block(stx);
            let stib_hash = vc_hash_sha256(&[STIB_PREFIX, &stib_canonical]);

            vc_leaf_hash(algo, &txid, &stib_hash)
        })
        .collect();

    // Pad to next power of 2.
    let padded_len = n.next_power_of_two();
    let depth = padded_len.trailing_zeros(); // log2(padded_len)

    // Build padded array with bit-reversal permutation.
    // Padded positions use H("MB") — the "bottom element" hash from go-algorand's
    // vectorCommitmentArray. This is NOT zero or empty; it's a real hash that
    // ensures position-binding for unfilled slots in the tree.
    let bottom_hash = vc_hash(algo, &[MB_PREFIX]);
    let mut layer: Vec<Vec<u8>> = vec![bottom_hash; padded_len];
    for (i, leaf) in leaf_hashes.into_iter().enumerate() {
        let vc_index = bit_reverse(i, depth);
        layer[vc_index] = leaf;
    }

    // Build tree bottom-up.
    while layer.len() > 1 {
        let parent_count = layer.len() / 2; // always power of 2
        let mut parents = Vec::with_capacity(parent_count);
        for i in 0..parent_count {
            let left = &layer[i * 2];
            let right = &layer[i * 2 + 1];
            parents.push(vc_internal_hash(algo, left, right));
        }
        layer = parents;
    }

    layer.into_iter().next().unwrap()
}

// ── Raw-passthrough variants (Epic 12a) ─────────────────────────────
//
// These functions use the raw msgpack bytes of each SignedTxnInBlock as
// extracted from the block response, rather than re-encoding from typed
// Rust structs. This preserves any fields our structs don't model,
// producing byte-identical STIB hashes to go-algorand.

/// Compute the STIB hash from raw msgpack bytes: SHA512/256("STIB" || raw_blob).
pub fn compute_stib_hash_raw(raw_blob: &[u8]) -> Hash {
    let mut hasher = Sha512_256::new();
    hasher.update(STIB_PREFIX);
    hasher.update(raw_blob);
    hasher.finalize().into()
}

/// Compute the payset Merkle root using raw STIB blobs for STIB hashing
/// and typed structs for txid computation.
///
/// `raw_blobs` must have the same length as `block.payset` and correspond
/// 1:1 to the payset entries.
pub fn compute_payset_merkle_root_raw(block: &Block, raw_blobs: &[Vec<u8>]) -> Hash {
    assert_eq!(
        block.payset.len(),
        raw_blobs.len(),
        "raw_blobs length must match payset length"
    );

    if block.payset.is_empty() {
        return ZERO_HASH;
    }

    let mut layer: Vec<Hash> = block
        .payset
        .iter()
        .zip(raw_blobs.iter())
        .map(|(stx, raw_blob)| {
            // Restore genesis fields for txid computation (same as typed path).
            let mut restored_txn = stx.txn.clone();
            if stx.has_genesis_id && restored_txn.genesis_id.is_empty() {
                restored_txn.genesis_id.clone_from(&block.genesis_id);
            }
            if restored_txn.genesis_hash == [0u8; 32] {
                restored_txn.genesis_hash = block.genesis_hash;
            }

            let txid = compute_txid(&restored_txn);
            let stib_hash = compute_stib_hash_raw(raw_blob);
            compute_leaf_hash(&txid, &stib_hash)
        })
        .collect();

    while layer.len() > 1 {
        layer = build_next_layer(&layer);
    }

    layer[0]
}

/// Compute the flat payset commitment using raw STIB blobs.
///
/// SHA512/256("PF" || msgpack_array_of_raw_blobs)
///
/// For an empty payset, encodes nil (0xc0) matching go-algorand.
pub fn compute_payset_flat_commitment_raw(raw_blobs: &[Vec<u8>]) -> Hash {
    let mut hasher = Sha512_256::new();
    hasher.update(b"PF");

    if raw_blobs.is_empty() {
        hasher.update([0xc0]);
    } else {
        let mut buf = Vec::new();
        rmp::encode::write_array_len(
            &mut buf,
            u32::try_from(raw_blobs.len()).expect("payset length fits in u32"),
        )
        .unwrap();
        for blob in raw_blobs {
            buf.extend_from_slice(blob);
        }
        hasher.update(&buf);
    }

    hasher.finalize().into()
}

/// Compute the vector commitment root using raw STIB blobs.
///
/// Same algorithm as `compute_vector_commitment` but uses raw bytes for
/// STIB hashing instead of re-encoding from typed structs.
pub fn compute_vector_commitment_raw(
    block: &Block,
    algo: HashAlgo,
    raw_blobs: &[Vec<u8>],
) -> Vec<u8> {
    assert_eq!(
        block.payset.len(),
        raw_blobs.len(),
        "raw_blobs length must match payset length"
    );

    if block.payset.is_empty() {
        // go-algorand's generateVectorCommitmentArray returns paddedLen=1 for
        // arrayLen=0, creating a single bottomElement leaf that hashes to H("MB").
        return vc_hash(algo, &[MB_PREFIX]);
    }

    let n = block.payset.len();

    // go-algorand's RawLeaf() uses SHA-256 for leaf data (txid, stib_hash)
    // when the tree hash type is Sha256 or Sha512. Only Sha512_256 uses
    // SHA-512/256 for leaf data. See data/bookkeeping/txn_merkle.go.
    let leaf_hashes: Vec<Vec<u8>> = block
        .payset
        .iter()
        .zip(raw_blobs.iter())
        .map(|(stx, raw_blob)| {
            // Restore genesis fields for txid (same as typed path).
            let mut restored_txn = stx.txn.clone();
            if stx.has_genesis_id && restored_txn.genesis_id.is_empty() {
                restored_txn.genesis_id.clone_from(&block.genesis_id);
            }
            if restored_txn.genesis_hash == [0u8; 32] {
                restored_txn.genesis_hash = block.genesis_hash;
            }

            let txn_canonical = canonical_encode_transaction(&restored_txn);
            // Leaf data always uses SHA-256 for vector commitments.
            let txid = vc_hash_sha256(&[TX_PREFIX, &txn_canonical]);

            // Use raw blob for stib_hash (preserves unknown fields).
            let stib_hash = vc_hash_sha256(&[STIB_PREFIX, raw_blob]);

            vc_leaf_hash(algo, &txid, &stib_hash)
        })
        .collect();

    // Pad to next power of 2.
    let padded_len = n.next_power_of_two();
    let depth = padded_len.trailing_zeros();

    // Build padded array with bit-reversal permutation.
    // Padded positions use H("MB") — see compute_vector_commitment.
    let bottom_hash = vc_hash(algo, &[MB_PREFIX]);
    let mut layer: Vec<Vec<u8>> = vec![bottom_hash; padded_len];
    for (i, leaf) in leaf_hashes.into_iter().enumerate() {
        let vc_index = bit_reverse(i, depth);
        layer[vc_index] = leaf;
    }

    // Build tree bottom-up.
    while layer.len() > 1 {
        let parent_count = layer.len() / 2;
        let mut parents = Vec::with_capacity(parent_count);
        for i in 0..parent_count {
            let left = &layer[i * 2];
            let right = &layer[i * 2 + 1];
            parents.push(vc_internal_hash(algo, left, right));
        }
        layer = parents;
    }

    layer.into_iter().next().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{Address, Round, Transaction};

    fn minimal_signed_txn(amount: u64) -> SignedTransaction {
        SignedTransaction {
            txn: Transaction {
                txn_type: "pay".into(),
                sender: Address([1u8; 32]),
                fee: 1000,
                first_valid: Round(1),
                last_valid: Round(100),
                amount,
                receiver: Address([2u8; 32]),
                ..Default::default()
            },
            sig: [0xAA; 64],
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: true,
            has_genesis_hash: false,
            closing_amount: 0,
            asset_closing_amount: 0,
            sender_rewards: 0,
            receiver_rewards: 0,
            close_rewards: 0,
            eval_delta: None,
            apply_data_config_asset: 0,
            apply_data_application_id: 0,
        }
    }

    fn minimal_block(payset: Vec<SignedTransaction>) -> Block {
        Block {
            round: Round(1),
            branch: [0u8; 32],
            seed: [0u8; 32],
            txn_commitment: [0u8; 32],
            timestamp: 100,
            genesis_id: "test-v1".into(),
            genesis_hash: [0xBB; 32],
            proposer: Address::default(),
            fee_sink: Address::default(),
            rewards_pool: Address::default(),
            rewards_level: 0,
            rewards_rate: 0,
            rewards_residue: 0,
            rewards_recalculation_round: Round(0),
            current_protocol: "future".into(),
            next_protocol: String::new(),
            next_protocol_approvals: 0,
            next_protocol_switch_on: Round(0),
            next_protocol_vote_before: Round(0),
            txn_counter: 0,
            fees_collected: 0,
            bonus: 0,
            proposer_payout: 0,
            prev512: [0u8; 64],
            txn256: [0u8; 32],
            txn512: [0u8; 64],
            state_proof_tracking: None,
            upgrade_propose: String::new(),
            upgrade_delay: 0,
            upgrade_approve: false,
            expired_participation_accounts: None,
            absent_participation_accounts: None,
            payset,
        }
    }

    #[test]
    fn empty_payset_returns_zero_hash() {
        let block = minimal_block(vec![]);
        let root = compute_payset_merkle_root(&block);
        assert_eq!(root, ZERO_HASH);
    }

    #[test]
    fn single_txn_payset_produces_nonzero_root() {
        let stx = minimal_signed_txn(1000);
        let block = minimal_block(vec![stx]);
        let root = compute_payset_merkle_root(&block);
        assert_ne!(root, ZERO_HASH);
    }

    #[test]
    fn single_txn_root_is_the_leaf_hash() {
        // With 1 leaf, go-algorand's buildLayers stops immediately (top layer
        // has exactly 1 element), so the root IS the leaf hash.
        let stx = minimal_signed_txn(1000);
        let block = minimal_block(vec![stx.clone()]);

        // Compute expected leaf hash with genesis fields restored
        let mut restored_txn = stx.txn.clone();
        restored_txn.genesis_id = "test-v1".into();
        restored_txn.genesis_hash = [0xBB; 32];
        let txid = compute_txid(&restored_txn);
        let stib_hash = compute_stib_hash(&stx);
        let expected_root = compute_leaf_hash(&txid, &stib_hash);

        let root = compute_payset_merkle_root(&block);
        assert_eq!(root, expected_root);
    }

    #[test]
    fn two_txn_payset_root_is_internal_of_two_leaves() {
        let stx1 = minimal_signed_txn(1000);
        let stx2 = minimal_signed_txn(2000);
        let block = minimal_block(vec![stx1.clone(), stx2.clone()]);

        let make_leaf = |stx: &SignedTransaction| {
            let mut restored_txn = stx.txn.clone();
            restored_txn.genesis_id = "test-v1".into();
            restored_txn.genesis_hash = [0xBB; 32];
            let txid = compute_txid(&restored_txn);
            let stib_hash = compute_stib_hash(stx);
            compute_leaf_hash(&txid, &stib_hash)
        };

        let leaf1 = make_leaf(&stx1);
        let leaf2 = make_leaf(&stx2);
        let expected_root = compute_internal_hash(&leaf1, &leaf2);

        let root = compute_payset_merkle_root(&block);
        assert_eq!(root, expected_root);
    }

    #[test]
    fn three_txn_payset_handles_odd_leaves() {
        let stx1 = minimal_signed_txn(1000);
        let stx2 = minimal_signed_txn(2000);
        let stx3 = minimal_signed_txn(3000);
        let block = minimal_block(vec![stx1.clone(), stx2.clone(), stx3.clone()]);

        let make_leaf = |stx: &SignedTransaction| {
            let mut restored_txn = stx.txn.clone();
            restored_txn.genesis_id = "test-v1".into();
            restored_txn.genesis_hash = [0xBB; 32];
            let txid = compute_txid(&restored_txn);
            let stib_hash = compute_stib_hash(stx);
            compute_leaf_hash(&txid, &stib_hash)
        };

        let leaves: Vec<Hash> = [&stx1, &stx2, &stx3]
            .iter()
            .map(|stx| make_leaf(stx))
            .collect();

        // Layer 1: [MA(leaf0, leaf1), MA(leaf2, zero)]
        let n0 = compute_internal_hash(&leaves[0], &leaves[1]);
        let n1 = compute_internal_hash(&leaves[2], &ZERO_HASH);
        // Root: MA(n0, n1)
        let expected_root = compute_internal_hash(&n0, &n1);

        let root = compute_payset_merkle_root(&block);
        assert_eq!(root, expected_root);
    }

    #[test]
    fn deterministic_root() {
        let stx = minimal_signed_txn(42);
        let block = minimal_block(vec![stx]);
        let root1 = compute_payset_merkle_root(&block);
        let root2 = compute_payset_merkle_root(&block);
        assert_eq!(root1, root2);
    }

    #[test]
    fn flat_commitment_empty_payset() {
        let root = compute_payset_flat_commitment(&[]);
        assert_ne!(
            root, ZERO_HASH,
            "flat hash of empty payset should not be all zeros"
        );
    }

    #[test]
    fn flat_commitment_deterministic() {
        let stx = minimal_signed_txn(100);
        let h1 = compute_payset_flat_commitment(std::slice::from_ref(&stx));
        let h2 = compute_payset_flat_commitment(std::slice::from_ref(&stx));
        assert_eq!(h1, h2);
    }

    // ── Vector commitment tests ─────────────────────────────────────

    #[test]
    fn bit_reverse_depth_zero() {
        assert_eq!(bit_reverse(0, 0), 0);
        assert_eq!(bit_reverse(5, 0), 0);
    }

    #[test]
    fn bit_reverse_depth_one() {
        assert_eq!(bit_reverse(0, 1), 0);
        assert_eq!(bit_reverse(1, 1), 1);
    }

    #[test]
    fn bit_reverse_depth_three() {
        // depth=3: 3 bits
        // 0 (000) → 0 (000)
        // 1 (001) → 4 (100)
        // 2 (010) → 2 (010)
        // 3 (011) → 6 (110)
        // 4 (100) → 1 (001)
        // 5 (101) → 5 (101)
        // 6 (110) → 3 (011)
        // 7 (111) → 7 (111)
        assert_eq!(bit_reverse(0, 3), 0);
        assert_eq!(bit_reverse(1, 3), 4);
        assert_eq!(bit_reverse(2, 3), 2);
        assert_eq!(bit_reverse(3, 3), 6);
        assert_eq!(bit_reverse(4, 3), 1);
        assert_eq!(bit_reverse(5, 3), 5);
        assert_eq!(bit_reverse(6, 3), 3);
        assert_eq!(bit_reverse(7, 3), 7);
    }

    #[test]
    fn bit_reverse_is_involution() {
        // Applying bit_reverse twice should return the original index.
        for depth in 0..6 {
            let size = 1usize << depth;
            for i in 0..size {
                assert_eq!(
                    bit_reverse(bit_reverse(i, depth), depth),
                    i,
                    "involution failed for i={i}, depth={depth}"
                );
            }
        }
    }

    #[test]
    fn vc_empty_payset_sha256() {
        // go-algorand: empty payset produces a tree with 1 bottomElement leaf,
        // so the root is SHA256("MB"), NOT zeros.
        let block = minimal_block(vec![]);
        let root = compute_vector_commitment(&block, HashAlgo::Sha256);
        assert_eq!(root.len(), 32);
        let expected = vc_hash(HashAlgo::Sha256, &[MB_PREFIX]);
        assert_eq!(root, expected);
        assert_ne!(
            root,
            vec![0u8; 32],
            "empty VC root should be H(MB), not zeros"
        );
    }

    #[test]
    fn vc_empty_payset_sha512() {
        // go-algorand: empty payset produces a tree with 1 bottomElement leaf,
        // so the root is SHA512("MB"), NOT zeros.
        let block = minimal_block(vec![]);
        let root = compute_vector_commitment(&block, HashAlgo::Sha512);
        assert_eq!(root.len(), 64);
        let expected = vc_hash(HashAlgo::Sha512, &[MB_PREFIX]);
        assert_eq!(root, expected);
        assert_ne!(
            root,
            vec![0u8; 64],
            "empty VC root should be H(MB), not zeros"
        );
    }

    #[test]
    fn vc_single_txn_sha256() {
        let stx = minimal_signed_txn(1000);
        let block = minimal_block(vec![stx]);
        let root = compute_vector_commitment(&block, HashAlgo::Sha256);
        assert_eq!(root.len(), 32);
        // Single txn → padded to 1 (power of 2), depth=0, no bit-reversal needed.
        // Root is just the leaf hash itself.
        assert_ne!(root, vec![0u8; 32]);
    }

    #[test]
    fn vc_single_txn_sha512() {
        let stx = minimal_signed_txn(1000);
        let block = minimal_block(vec![stx]);
        let root = compute_vector_commitment(&block, HashAlgo::Sha512);
        assert_eq!(root.len(), 64);
        assert_ne!(root, vec![0u8; 64]);
    }

    #[test]
    fn vc_deterministic_sha256() {
        let stx = minimal_signed_txn(42);
        let block = minimal_block(vec![stx]);
        let r1 = compute_vector_commitment(&block, HashAlgo::Sha256);
        let r2 = compute_vector_commitment(&block, HashAlgo::Sha256);
        assert_eq!(r1, r2);
    }

    #[test]
    fn vc_deterministic_sha512() {
        let stx = minimal_signed_txn(42);
        let block = minimal_block(vec![stx]);
        let r1 = compute_vector_commitment(&block, HashAlgo::Sha512);
        let r2 = compute_vector_commitment(&block, HashAlgo::Sha512);
        assert_eq!(r1, r2);
    }

    #[test]
    fn vc_sha256_and_sha512_differ() {
        let stx = minimal_signed_txn(1000);
        let block = minimal_block(vec![stx]);
        let r256 = compute_vector_commitment(&block, HashAlgo::Sha256);
        let r512 = compute_vector_commitment(&block, HashAlgo::Sha512);
        // Different hash algorithms must produce different-length outputs.
        assert_ne!(r256.len(), r512.len());
    }

    #[test]
    fn vc_two_txn_uses_bit_reversal() {
        // With 2 txns, padded_len=2, depth=1.
        // bit_reverse(0,1)=0, bit_reverse(1,1)=1 — no change for depth=1.
        // So the tree is just MA(leaf0, leaf1).
        let stx1 = minimal_signed_txn(1000);
        let stx2 = minimal_signed_txn(2000);
        let block = minimal_block(vec![stx1, stx2]);
        let root = compute_vector_commitment(&block, HashAlgo::Sha256);
        assert_eq!(root.len(), 32);
        assert_ne!(root, vec![0u8; 32]);
    }

    #[test]
    fn vc_three_txn_pads_to_four() {
        // 3 txns → padded to 4, depth=2.
        // bit_reverse mappings (depth=2):
        //   0 (00) → 0 (00)
        //   1 (01) → 2 (10)
        //   2 (10) → 1 (01)
        // So leaf order becomes: [leaf0, leaf2, leaf1, zero]
        let stx1 = minimal_signed_txn(1000);
        let stx2 = minimal_signed_txn(2000);
        let stx3 = minimal_signed_txn(3000);
        let block = minimal_block(vec![stx1, stx2, stx3]);
        let root = compute_vector_commitment(&block, HashAlgo::Sha256);
        assert_eq!(root.len(), 32);
        assert_ne!(root, vec![0u8; 32]);
    }

    #[test]
    fn vc_sha512_uses_sha256_for_leaf_data() {
        // go-algorand's txnMerkleElem.RawLeaf() uses SHA-256 for leaf data
        // (txid, stib_hash) when the tree hash type is Sha256 OR Sha512.
        // Only the tree construction (TL wrapping, MA nodes) uses SHA-512.
        //
        // Verify this by manually computing:
        //   txid = SHA256("TX" || canonical_txn)
        //   stib_hash = SHA256("STIB" || canonical_stib)
        //   leaf = SHA512("TL" || txid || stib_hash)
        // and checking the single-txn root matches.
        let stx = minimal_signed_txn(1000);
        let block = minimal_block(vec![stx.clone()]);

        // Restore genesis fields for txid.
        let mut restored_txn = stx.txn.clone();
        restored_txn.genesis_id = "test-v1".into();
        restored_txn.genesis_hash = [0xBB; 32];

        let txn_canonical = canonical_encode_transaction(&restored_txn);
        // Leaf data uses SHA-256.
        let txid = vc_hash_sha256(&[TX_PREFIX, &txn_canonical]);

        let stib_canonical = canonical_encode_signed_txn_in_block(&stx);
        let stib_hash = vc_hash_sha256(&[STIB_PREFIX, &stib_canonical]);

        // Tree construction uses SHA-512.
        let expected_leaf = vc_hash(HashAlgo::Sha512, &[TL_PREFIX, &txid, &stib_hash]);

        let root = compute_vector_commitment(&block, HashAlgo::Sha512);
        assert_eq!(root.len(), 64);
        assert_eq!(
            root, expected_leaf,
            "SHA-512 VC single-txn root should use SHA-256 for leaf data and SHA-512 for tree"
        );
    }

    #[test]
    fn vc_sha256_leaf_data_matches_tree_algo() {
        // For SHA-256 vector commitments, leaf data also uses SHA-256
        // (same algorithm for both). Verify manually.
        let stx = minimal_signed_txn(1000);
        let block = minimal_block(vec![stx.clone()]);

        let mut restored_txn = stx.txn.clone();
        restored_txn.genesis_id = "test-v1".into();
        restored_txn.genesis_hash = [0xBB; 32];

        let txn_canonical = canonical_encode_transaction(&restored_txn);
        let txid = vc_hash_sha256(&[TX_PREFIX, &txn_canonical]);

        let stib_canonical = canonical_encode_signed_txn_in_block(&stx);
        let stib_hash = vc_hash_sha256(&[STIB_PREFIX, &stib_canonical]);

        let expected_leaf = vc_hash(HashAlgo::Sha256, &[TL_PREFIX, &txid, &stib_hash]);

        let root = compute_vector_commitment(&block, HashAlgo::Sha256);
        assert_eq!(root.len(), 32);
        assert_eq!(
            root, expected_leaf,
            "SHA-256 VC single-txn root should use SHA-256 for everything"
        );
    }

    #[test]
    fn vc_raw_sha512_uses_sha256_for_leaf_data() {
        // Same as vc_sha512_uses_sha256_for_leaf_data but for the raw-passthrough path.
        let stx = minimal_signed_txn(1000);
        let block = minimal_block(vec![stx.clone()]);
        let raw_blob = canonical_encode_signed_txn_in_block(&stx);

        let mut restored_txn = stx.txn.clone();
        restored_txn.genesis_id = "test-v1".into();
        restored_txn.genesis_hash = [0xBB; 32];

        let txn_canonical = canonical_encode_transaction(&restored_txn);
        let txid = vc_hash_sha256(&[TX_PREFIX, &txn_canonical]);
        let stib_hash = vc_hash_sha256(&[STIB_PREFIX, &raw_blob]);
        let expected_leaf = vc_hash(HashAlgo::Sha512, &[TL_PREFIX, &txid, &stib_hash]);

        let root = compute_vector_commitment_raw(&block, HashAlgo::Sha512, &[raw_blob]);
        assert_eq!(root, expected_leaf);
    }
}
