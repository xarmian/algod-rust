mod canonical;
mod digest;

pub use canonical::{
    build_txtail_from_block, canonical_encode_account_application_model,
    canonical_encode_account_asset_model, canonical_encode_account_data,
    canonical_encode_app_local_state, canonical_encode_app_params, canonical_encode_asset_holding,
    canonical_encode_base_account_data, canonical_encode_base_online_account_data,
    canonical_encode_block_header, canonical_encode_block_header_from_block,
    canonical_encode_block_header_response, canonical_encode_ledgercore_account_data,
    canonical_encode_logicsig, canonical_encode_multisig, canonical_encode_multisig_subsig,
    canonical_encode_online_round_params_data, canonical_encode_resources_data,
    canonical_encode_signed_transaction, canonical_encode_signed_txn_in_block,
    canonical_encode_state_proof_verification_context, canonical_encode_state_schema,
    canonical_encode_teal_key_value, canonical_encode_transaction, canonical_encode_tx_group,
    canonical_encode_txtail_round, canonical_encode_txtail_round_lease,
    canonical_encode_unauthenticated_proposal, resource_flags, BaseOnlineAccountData,
    OnlineRoundParamsData, ResourcesData, StateProofVerificationContext,
};
pub use digest::{
    compute_block_digest, compute_block_header_digest, compute_block_header_digest_512,
    compute_group_id, compute_txn_id,
};

use algo_error::{AlgoError, Result};
use algo_types::{Block, BlockResponse, LogicSig, SignedTransaction};

/// Decode a single msgpack-encoded `LogicSig`, as produced by `goal clerk
/// compile -s` (a `protocol.Encode(&LogicSig)` blob). Mirrors `lsigFromArgs`'s
/// `protocol.Decode(lsigBytes, lsig)` (`cmd/goal/clerk.go:753`).
pub fn decode_logicsig(bytes: &[u8]) -> Result<LogicSig> {
    rmp_serde::from_slice(bytes).map_err(|e| AlgoError::Codec {
        source: Box::new(e),
        context: "failed to decode LogicSig from msgpack".into(),
    })
}

/// Decode a stream of one or more concatenated msgpack `SignedTransaction`s,
/// as produced by `goal`'s txn-file writers (`protocol.Encode(&stx)` appended
/// back to back).
///
/// Mirrors go-algorand's `protocol.NewMsgpDecoderBytes(data)` loop used by
/// `clerk inspect` / `group` / `rawsend` / `split` (`cmd/goal/clerk.go`):
/// decode values until the input is fully consumed. An empty input yields an
/// empty vector. A trailing partial value (or any decode failure) is an error.
pub fn decode_signed_txn_stream(mut bytes: &[u8]) -> Result<Vec<SignedTransaction>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let mut cursor = std::io::Cursor::new(bytes);
        let mut de = rmp_serde::Deserializer::new(&mut cursor);
        let stxn: SignedTransaction =
            serde::Deserialize::deserialize(&mut de).map_err(|e| AlgoError::Codec {
                source: Box::new(e),
                context: "failed to decode SignedTransaction from msgpack stream".into(),
            })?;
        let consumed = cursor.position() as usize;
        debug_assert!(consumed > 0, "decoder must advance the stream");
        bytes = &bytes[consumed..];
        out.push(stxn);
    }
    Ok(out)
}

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

/// Decode a Block using the fast rmp-direct path (no serde overhead).
///
/// This calls `Block::decode_from_bytes` which uses raw `rmp` decoding
/// instead of going through serde, avoiding the serde derive machinery.
pub fn decode_block_fast(bytes: &[u8]) -> Result<Block> {
    Block::decode_from_bytes(bytes)
}

/// Decode a BlockResponse using the fast rmp-direct path (no serde overhead).
///
/// This calls `BlockResponse::decode_from_bytes` which uses raw `rmp` decoding
/// instead of going through serde, avoiding the serde derive machinery.
pub fn decode_block_response_fast(bytes: &[u8]) -> Result<BlockResponse> {
    BlockResponse::decode_from_bytes(bytes)
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

    // Delegate to the shared block-map scanner, using a sub-slice starting
    // at the block map but capturing byte spans from the original buffer.
    extract_txns_from_block_map(&response_bytes[block_start..], response_bytes)
}

/// Extract the raw msgpack bytes for each SignedTxnInBlock entry from raw
/// block bytes (not wrapped in a REST/gossip envelope).
///
/// Unlike [`extract_raw_payset_blobs`] which navigates a `{"block": ..., "cert": ...}`
/// envelope first, this function takes the block map bytes directly and scans
/// for the `txns` array.
///
/// Returns an empty Vec if the block has no `txns` field.
pub fn extract_raw_payset_blobs_from_block(block_bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    extract_txns_from_block_map(block_bytes, block_bytes)
}

/// Shared helper: scan a block-level msgpack map starting at position 0 of `cursor_bytes`
/// for a `txns` array and extract each element's raw byte span from `source_bytes`.
///
/// `source_bytes` is the buffer from which byte slices are captured; `cursor_bytes`
/// provides the read cursor (they may be the same buffer or cursor_bytes may be a
/// sub-slice positioned at the block map within a larger buffer).
fn extract_txns_from_block_map(cursor_bytes: &[u8], source_bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    use std::io::Cursor;

    // Compute the offset of cursor_bytes within source_bytes so we can
    // translate cursor positions back to source positions.
    debug_assert!(
        cursor_bytes.as_ptr() >= source_bytes.as_ptr()
            && cursor_bytes.as_ptr() as usize + cursor_bytes.len()
                <= source_bytes.as_ptr() as usize + source_bytes.len(),
        "cursor_bytes must be a sub-slice of source_bytes"
    );
    let base_offset = cursor_bytes.as_ptr() as usize - source_bytes.as_ptr() as usize;

    let mut cursor = Cursor::new(cursor_bytes);

    let block_map_len = rmp::decode::read_map_len(&mut cursor).map_err(|e| AlgoError::Codec {
        source: Box::new(e),
        context: "failed to read block map length".into(),
    })?;

    for _ in 0..block_map_len {
        let key = rmpv::decode::read_value(&mut cursor).map_err(|e| AlgoError::Codec {
            source: Box::new(e),
            context: "failed to read block map key".into(),
        })?;

        let is_txns = matches!(&key, rmpv::Value::String(s) if s.as_str() == Some("txns"));

        if is_txns {
            let array_len =
                rmp::decode::read_array_len(&mut cursor).map_err(|e| AlgoError::Codec {
                    source: Box::new(e),
                    context: "failed to read txns array length".into(),
                })?;

            let mut blobs = Vec::with_capacity(array_len as usize);
            for _ in 0..array_len {
                let elem_start = cursor.position() as usize + base_offset;
                rmpv::decode::read_value(&mut cursor).map_err(|e| AlgoError::Codec {
                    source: Box::new(e),
                    context: "failed to read txns array element".into(),
                })?;
                let elem_end = cursor.position() as usize + base_offset;
                blobs.push(source_bytes[elem_start..elem_end].to_vec());
            }

            return Ok(blobs);
        } else {
            rmpv::decode::read_value(&mut cursor).map_err(|e| AlgoError::Codec {
                source: Box::new(e),
                context: "failed to skip block map value".into(),
            })?;
        }
    }

    // No "txns" key found — empty payset
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal block msgpack map with the given round and optional txns array.
    fn make_block_msgpack_with_txns(round: u64, txns: Option<&[rmpv::Value]>) -> Vec<u8> {
        let mut buf = Vec::new();

        // Determine map size: "rnd" + optionally "txns"
        let map_len: u32 = if txns.is_some() { 2 } else { 1 };
        rmp::encode::write_map_len(&mut buf, map_len).unwrap();

        // "rnd" key
        rmp::encode::write_str(&mut buf, "rnd").unwrap();
        rmpv::encode::write_value(&mut buf, &rmpv::Value::from(round)).unwrap();

        // "txns" key (optional)
        if let Some(txn_values) = txns {
            rmp::encode::write_str(&mut buf, "txns").unwrap();
            rmp::encode::write_array_len(&mut buf, txn_values.len() as u32).unwrap();
            for v in txn_values {
                rmpv::encode::write_value(&mut buf, v).unwrap();
            }
        }

        buf
    }

    #[test]
    fn extract_from_block_empty_payset() {
        // Block with no "txns" key at all.
        let block_bytes = make_block_msgpack_with_txns(1, None);
        let blobs = extract_raw_payset_blobs_from_block(&block_bytes).unwrap();
        assert!(blobs.is_empty());
    }

    #[test]
    fn extract_from_block_empty_txns_array() {
        // Block with an empty "txns" array.
        let block_bytes = make_block_msgpack_with_txns(1, Some(&[]));
        let blobs = extract_raw_payset_blobs_from_block(&block_bytes).unwrap();
        assert!(blobs.is_empty());
    }

    #[test]
    fn extract_from_block_single_txn() {
        // Create a single transaction-like map value.
        let txn = rmpv::Value::Map(vec![(
            rmpv::Value::String("type".into()),
            rmpv::Value::String("pay".into()),
        )]);
        let block_bytes = make_block_msgpack_with_txns(5, Some(std::slice::from_ref(&txn)));
        let blobs = extract_raw_payset_blobs_from_block(&block_bytes).unwrap();
        assert_eq!(blobs.len(), 1);

        // The extracted blob should decode back to the same value.
        let decoded = rmpv::decode::read_value(&mut &blobs[0][..]).unwrap();
        assert_eq!(decoded, txn);
    }

    #[test]
    fn extract_from_block_multiple_txns() {
        let txn1 = rmpv::Value::Map(vec![(
            rmpv::Value::String("type".into()),
            rmpv::Value::String("pay".into()),
        )]);
        let txn2 = rmpv::Value::Map(vec![(
            rmpv::Value::String("type".into()),
            rmpv::Value::String("axfer".into()),
        )]);
        let block_bytes = make_block_msgpack_with_txns(10, Some(&[txn1.clone(), txn2.clone()]));
        let blobs = extract_raw_payset_blobs_from_block(&block_bytes).unwrap();
        assert_eq!(blobs.len(), 2);

        let decoded1 = rmpv::decode::read_value(&mut &blobs[0][..]).unwrap();
        let decoded2 = rmpv::decode::read_value(&mut &blobs[1][..]).unwrap();
        assert_eq!(decoded1, txn1);
        assert_eq!(decoded2, txn2);
    }

    #[test]
    fn extract_from_block_matches_envelope_extraction() {
        // Build a block with txns, then wrap it in a REST envelope.
        // Both extraction methods should produce identical blobs.
        let txn = rmpv::Value::Map(vec![
            (
                rmpv::Value::String("type".into()),
                rmpv::Value::String("pay".into()),
            ),
            (
                rmpv::Value::String("amt".into()),
                rmpv::Value::from(1000u64),
            ),
        ]);
        let block_bytes = make_block_msgpack_with_txns(42, Some(&[txn]));

        // Build envelope: {"block": <block_bytes_as_value>, "cert": {}}
        let block_value = rmpv::decode::read_value(&mut &block_bytes[..]).unwrap();
        let mut envelope = Vec::new();
        rmp::encode::write_map_len(&mut envelope, 2).unwrap();
        rmp::encode::write_str(&mut envelope, "block").unwrap();
        rmpv::encode::write_value(&mut envelope, &block_value).unwrap();
        rmp::encode::write_str(&mut envelope, "cert").unwrap();
        rmpv::encode::write_value(&mut envelope, &rmpv::Value::Map(vec![])).unwrap();

        let blobs_from_block = extract_raw_payset_blobs_from_block(&block_bytes).unwrap();
        let blobs_from_envelope = extract_raw_payset_blobs(&envelope).unwrap();

        assert_eq!(blobs_from_block.len(), blobs_from_envelope.len());
        for (a, b) in blobs_from_block.iter().zip(blobs_from_envelope.iter()) {
            assert_eq!(a, b, "blobs should be byte-identical");
        }
    }

    #[test]
    fn extract_from_block_invalid_bytes() {
        let result = extract_raw_payset_blobs_from_block(b"not-valid-msgpack");
        assert!(result.is_err());
    }
}
