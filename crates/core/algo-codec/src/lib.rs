mod canonical;
mod digest;

pub use canonical::{
    canonical_encode_block_header, canonical_encode_block_header_from_block,
    canonical_encode_logicsig, canonical_encode_multisig, canonical_encode_multisig_subsig,
    canonical_encode_signed_transaction, canonical_encode_signed_txn_in_block,
    canonical_encode_transaction, canonical_encode_tx_group,
};
pub use digest::{compute_block_digest, compute_txn_id};

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

/// Extract the raw msgpack bytes for each SignedTxnInBlock entry from a block
/// response's raw bytes.
///
/// This navigates the msgpack structure to find the `block` map → `txns` array,
/// then captures each array element's raw byte span. The returned blobs are the
/// exact bytes go-algorand produced, preserving any fields our typed Rust structs
/// don't model.
///
/// Returns an empty Vec if the block has no `txns` field.
pub fn extract_raw_payset_blobs(response_bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    use std::io::Cursor;

    let mut cursor = Cursor::new(response_bytes);

    // Read the top-level map (BlockResponse: {"block": ..., "cert": ...})
    let top_map_len = rmp::decode::read_map_len(&mut cursor).map_err(|e| AlgoError::Codec {
        source: Box::new(e),
        context: "failed to read top-level map length".into(),
    })?;

    // Find the "block" key in the top-level map
    let mut block_start = None;
    for _ in 0..top_map_len {
        let pos_before_key = cursor.position() as usize;
        let key = rmpv::decode::read_value(&mut cursor).map_err(|e| AlgoError::Codec {
            source: Box::new(e),
            context: "failed to read top-level map key".into(),
        })?;

        let is_block = matches!(&key, rmpv::Value::String(s) if s.as_str() == Some("block"));

        if is_block {
            block_start = Some(cursor.position() as usize);
            // Skip the block value to continue (we'll re-parse it below)
            rmpv::decode::read_value(&mut cursor).map_err(|e| AlgoError::Codec {
                source: Box::new(e),
                context: "failed to skip block value".into(),
            })?;
            break;
        } else {
            // Skip this value
            let _ = pos_before_key; // suppress unused warning
            rmpv::decode::read_value(&mut cursor).map_err(|e| AlgoError::Codec {
                source: Box::new(e),
                context: "failed to skip top-level map value".into(),
            })?;
        }
    }

    let block_start = block_start.ok_or_else(|| AlgoError::Codec {
        source: "block key not found in response".into(),
        context: "extract_raw_payset_blobs".into(),
    })?;

    // Now parse inside the block map to find "txns"
    let mut block_cursor = Cursor::new(response_bytes);
    block_cursor.set_position(block_start as u64);

    let block_map_len =
        rmp::decode::read_map_len(&mut block_cursor).map_err(|e| AlgoError::Codec {
            source: Box::new(e),
            context: "failed to read block map length".into(),
        })?;

    for _ in 0..block_map_len {
        let key = rmpv::decode::read_value(&mut block_cursor).map_err(|e| AlgoError::Codec {
            source: Box::new(e),
            context: "failed to read block map key".into(),
        })?;

        let is_txns = matches!(&key, rmpv::Value::String(s) if s.as_str() == Some("txns"));

        if is_txns {
            // Read the array length
            let array_len =
                rmp::decode::read_array_len(&mut block_cursor).map_err(|e| AlgoError::Codec {
                    source: Box::new(e),
                    context: "failed to read txns array length".into(),
                })?;

            let mut blobs = Vec::with_capacity(array_len as usize);
            for _ in 0..array_len {
                let elem_start = block_cursor.position() as usize;
                rmpv::decode::read_value(&mut block_cursor).map_err(|e| AlgoError::Codec {
                    source: Box::new(e),
                    context: "failed to read txns array element".into(),
                })?;
                let elem_end = block_cursor.position() as usize;
                blobs.push(response_bytes[elem_start..elem_end].to_vec());
            }

            return Ok(blobs);
        } else {
            // Skip this value
            rmpv::decode::read_value(&mut block_cursor).map_err(|e| AlgoError::Codec {
                source: Box::new(e),
                context: "failed to skip block map value".into(),
            })?;
        }
    }

    // No "txns" key found — empty payset
    Ok(Vec::new())
}
