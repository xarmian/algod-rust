mod canonical;

pub use canonical::{
    canonical_encode_block_header, canonical_encode_block_header_from_block,
    canonical_encode_signed_transaction, canonical_encode_signed_txn_in_block,
    canonical_encode_transaction,
};

use algo_error::{AlgoError, Result};
use algo_types::{Block, BlockResponse};

/// Decode a block response from msgpack bytes (as returned by the REST API).
pub fn decode_block_response(bytes: &[u8]) -> Result<BlockResponse> {
    rmp_serde::from_slice(bytes).map_err(|e| AlgoError::Codec {
        source: Box::new(e),
        context: "failed to decode block response from msgpack".into(),
    })
}

/// Decode a raw block from msgpack bytes.
pub fn decode_block(bytes: &[u8]) -> Result<Block> {
    rmp_serde::from_slice(bytes).map_err(|e| AlgoError::Codec {
        source: Box::new(e),
        context: "failed to decode block from msgpack".into(),
    })
}

/// Encode a block to msgpack bytes.
///
/// Note: Phase 0 uses `rmp-serde` named encoding. This does NOT produce
/// Algorand canonical encoding (sorted keys, omitted zero-values).
/// See `canonical.rs` for the roadmap to canonical encoding.
pub fn encode_block(block: &Block) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(block).map_err(|e| AlgoError::Codec {
        source: Box::new(e),
        context: "failed to encode block to msgpack".into(),
    })
}

/// Decode msgpack bytes into a generic Value for debugging and comparison.
pub fn decode_raw(bytes: &[u8]) -> Result<rmpv::Value> {
    rmpv::decode::read_value(&mut &bytes[..]).map_err(|e| AlgoError::Codec {
        source: Box::new(e),
        context: "failed to decode msgpack value".into(),
    })
}
