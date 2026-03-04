use sha2::Digest as Sha2Digest;
use sha2::Sha512_256;

use algo_types::{Block, Digest, Transaction};

use crate::canonical::{canonical_encode_block_header_from_block, canonical_encode_transaction};

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

fn hash_with_prefix(prefix: &[u8], data: &[u8]) -> Digest {
    let mut hasher = Sha512_256::new();
    hasher.update(prefix);
    hasher.update(data);
    let result = hasher.finalize();
    Digest(result.into())
}
