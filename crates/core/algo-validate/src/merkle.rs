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
use sha2::{Digest as _, Sha512_256};

/// Domain separation prefix for Merkle array internal nodes.
const MA_PREFIX: &[u8] = b"MA";

/// Domain separation prefix for transaction Merkle tree leaves.
const TL_PREFIX: &[u8] = b"TL";

/// Domain separation prefix for transaction ID hashing.
const TX_PREFIX: &[u8] = b"TX";

/// Domain separation prefix for SignedTxnInBlock hashing.
const STIB_PREFIX: &[u8] = b"STIB";

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
            if restored_txn.genesis_hash.is_empty() {
                restored_txn.genesis_hash = block.genesis_hash.clone();
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

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{Address, Round, Transaction};
    use serde_bytes::ByteBuf;

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
            sig: ByteBuf::from(vec![0xAA; 64]),
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
            branch: ByteBuf::new(),
            seed: ByteBuf::new(),
            txn_commitment: ByteBuf::new(),
            timestamp: 100,
            genesis_id: "test-v1".into(),
            genesis_hash: ByteBuf::from(vec![0xBB; 32]),
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
            prev512: ByteBuf::new(),
            txn256: ByteBuf::new(),
            txn512: ByteBuf::new(),
            state_proof_tracking: None,
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
        restored_txn.genesis_hash = ByteBuf::from(vec![0xBB; 32]);
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
            restored_txn.genesis_hash = ByteBuf::from(vec![0xBB; 32]);
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
            restored_txn.genesis_hash = ByteBuf::from(vec![0xBB; 32]);
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
}
