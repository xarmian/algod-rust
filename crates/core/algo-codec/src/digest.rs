use sha2::Digest as Sha2Digest;
use sha2::{Sha512, Sha512_256};

use algo_types::{Block, BlockHeader, Digest, Transaction};

use crate::canonical::{
    canonical_encode_block_header, canonical_encode_block_header_from_block,
    canonical_encode_transaction,
};

/// Domain separation prefix for transaction hashing.
const TX_HASH_PREFIX: &[u8] = b"TX";

/// Domain separation prefix for block header hashing.
const BH_HASH_PREFIX: &[u8] = b"BH";

/// Compute a transaction ID: SHA512/256("TX" || canonical_encode(txn)).
pub fn compute_txn_id(tx: &Transaction) -> Digest {
    let canonical = canonical_encode_transaction(tx);
    hash_with_prefix(TX_HASH_PREFIX, &canonical)
}

/// Compute the block digest: SHA512/256("BH" || canonical_encode(block_header)).
pub fn compute_block_digest(block: &Block) -> Digest {
    let canonical = canonical_encode_block_header_from_block(block);
    hash_with_prefix(BH_HASH_PREFIX, &canonical)
}

/// Compute a block's digest from its [`BlockHeader`] alone:
/// `SHA512/256("BH" || canonical_encode(header))`.
///
/// This is the value used as the next block's `branch` (go's `prev.Hash()`),
/// computed without needing the full [`Block`]/payset — the block hash is over
/// the header (which already commits to the payset via its txn-commitment
/// fields). It is identical to [`compute_block_digest`] for a block with the
/// same header fields, since both encode the same header map.
pub fn compute_block_header_digest(header: &BlockHeader) -> Digest {
    let canonical = canonical_encode_block_header(header);
    hash_with_prefix(BH_HASH_PREFIX, &canonical)
}

/// Compute a block's full SHA-512 header digest:
/// `SHA-512("BH" || canonical_encode(header))`.
///
/// This is go's `BlockHeader.Hash512()` — the same "BH"-prefixed header
/// encoding as [`compute_block_header_digest`], hashed with SHA-512 instead of
/// SHA-512/256. It is the value stored as the next block's `prev512`
/// (`Branch512`) under protocols with `EnableSha512BlockHash` (v41+).
pub fn compute_block_header_digest_512(header: &BlockHeader) -> [u8; 64] {
    let canonical = canonical_encode_block_header(header);
    let mut hasher = Sha512::new();
    hasher.update(BH_HASH_PREFIX);
    hasher.update(&canonical);
    hasher.finalize().into()
}

fn hash_with_prefix(prefix: &[u8], data: &[u8]) -> Digest {
    let mut hasher = Sha512_256::new();
    hasher.update(prefix);
    hasher.update(data);
    let result = hasher.finalize();
    Digest(result.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::Round;

    #[test]
    fn block_header_digest_matches_block_digest() {
        // A block and a header carrying the same header fields must hash to the
        // same digest — so `compute_block_header_digest` is a valid `prev.Hash()`
        // (next-block `branch`) computed from the header alone.
        let mut block = Block {
            round: Round(5),
            branch: [1u8; 32],
            seed: [2u8; 32],
            rewards_level: 42,
            txn_counter: 7,
            current_protocol: "test-proto".to_string(),
            genesis_id: "net-abc".to_string(),
            txn_commitment: [3u8; 32],
            ..Block::default()
        };
        block.timestamp = 1_700_000_000;

        let header = BlockHeader {
            round: Round(5),
            branch: [1u8; 32],
            seed: [2u8; 32],
            rewards_level: 42,
            txn_counter: 7,
            current_protocol: "test-proto".to_string(),
            genesis_id: "net-abc".to_string(),
            txn_commitment: [3u8; 32],
            timestamp: 1_700_000_000,
            ..BlockHeader::default()
        };

        assert_eq!(
            compute_block_header_digest(&header),
            compute_block_digest(&block),
            "header-only digest must equal the block digest for equivalent header fields",
        );
    }

    #[test]
    fn block_header_digest_512_is_deterministic_and_distinct() {
        let header = BlockHeader {
            round: Round(9),
            branch: [4u8; 32],
            ..BlockHeader::default()
        };
        let a = compute_block_header_digest_512(&header);
        let b = compute_block_header_digest_512(&header);
        assert_eq!(a, b, "512 header digest must be deterministic");
        // The 64-byte SHA-512 digest must not be the 32-byte SHA-512/256 digest
        // zero-extended — its first 32 bytes differ (different hash function).
        assert_ne!(
            &a[..32],
            compute_block_header_digest(&header).0.as_slice(),
            "SHA-512 prefix must differ from the SHA-512/256 digest",
        );
    }

    #[test]
    fn block_header_digest_changes_with_fields() {
        let base = BlockHeader {
            round: Round(1),
            ..BlockHeader::default()
        };
        let other = BlockHeader {
            round: Round(2),
            ..BlockHeader::default()
        };
        assert_ne!(
            compute_block_header_digest(&base),
            compute_block_header_digest(&other),
            "different rounds must hash differently",
        );
    }
}
