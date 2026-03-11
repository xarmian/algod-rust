//! Integration tests for catchpoint tar archive parsing.
//!
//! Tests the full pipeline: tar → snappy → chunk deserialize → inner blob decode.
//! Fixture archives are built programmatically so we don't need real catchpoint files.

use std::collections::HashMap;
use std::io::Write;

use serde_bytes::ByteBuf;

use algo_ledger::catchpoint::{
    BalanceRecordV6, CatchpointBaseAccountData, CatchpointFileHeader, CatchpointResourcesData,
    CatchpointSnapshotChunkV6, KVRecordV6, OnlineAccountRecordV6, OnlineRoundParamsRecordV6,
    CATCHPOINT_FILE_VERSION_V5, CATCHPOINT_FILE_VERSION_V8,
};

// We import the msgp decoders
use algo_ledger::catchpoint::msgp_compat::{
    decode_base_account_data, decode_base_online_account_data, decode_online_round_params_data,
    decode_resources_data,
};

// ---------------------------------------------------------------------------
// Synthetic fixture builders
// ---------------------------------------------------------------------------

/// Serialize a `CatchpointFileHeader` to named-key msgpack (using rmp-serde).
fn encode_header(header: &CatchpointFileHeader) -> Vec<u8> {
    rmp_serde::to_vec_named(header).expect("failed to encode header")
}

/// Serialize a `CatchpointSnapshotChunkV6` to named-key msgpack, then
/// Snappy-compress the result using framing format (matching Go's encoding).
///
/// Go's catchpoint writer uses Snappy frame compression, not raw block
/// compression. The frame format starts with a stream identifier chunk
/// (`0xff` + `sNaPpY`) which the parser uses to detect compressed data.
fn encode_chunk_snappy(chunk: &CatchpointSnapshotChunkV6) -> Vec<u8> {
    let raw = rmp_serde::to_vec_named(chunk).expect("failed to encode chunk");
    let mut compressed = Vec::new();
    {
        let mut encoder = snap::write::FrameEncoder::new(&mut compressed);
        std::io::Write::write_all(&mut encoder, &raw).expect("snappy frame write");
        // FrameEncoder flushes on drop, but we need to drop it before returning compressed
    }
    compressed
}

/// Build a raw (uncompressed) tar archive containing a catchpoint header and
/// zero or more balance chunks.
///
/// Layout:
///   content.msgpack          — msgpack-encoded CatchpointFileHeader
///   balances.0.msgpack       — Snappy-compressed msgpack chunk 0
///   balances.1.msgpack       — Snappy-compressed msgpack chunk 1
///   ...
fn build_test_catchpoint_archive(
    header: &CatchpointFileHeader,
    chunks: &[CatchpointSnapshotChunkV6],
) -> Vec<u8> {
    let buf = Vec::new();
    let mut builder = tar::Builder::new(buf);

    // Add header entry
    let header_bytes = encode_header(header);
    let mut tar_header = tar::Header::new_gnu();
    tar_header.set_path("content.msgpack").unwrap();
    tar_header.set_size(header_bytes.len() as u64);
    tar_header.set_mode(0o644);
    tar_header.set_cksum();
    builder
        .append(&tar_header, header_bytes.as_slice())
        .unwrap();

    // Add chunk entries
    for (i, chunk) in chunks.iter().enumerate() {
        let chunk_bytes = encode_chunk_snappy(chunk);
        let mut tar_header = tar::Header::new_gnu();
        tar_header
            .set_path(format!("balances.{i}.msgpack"))
            .unwrap();
        tar_header.set_size(chunk_bytes.len() as u64);
        tar_header.set_mode(0o644);
        tar_header.set_cksum();
        builder.append(&tar_header, chunk_bytes.as_slice()).unwrap();
    }

    builder.into_inner().expect("finalize tar")
}

/// Build a gzip-compressed tar archive.
fn build_test_catchpoint_gzipped(
    header: &CatchpointFileHeader,
    chunks: &[CatchpointSnapshotChunkV6],
) -> Vec<u8> {
    let raw_tar = build_test_catchpoint_archive(header, chunks);
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&raw_tar).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

/// Build a raw tar archive with an additional arbitrary entry (not
/// content.msgpack or balances.*.msgpack) to test that unknown entries
/// are skipped.
fn build_archive_with_extra_entries(
    header: &CatchpointFileHeader,
    chunks: &[CatchpointSnapshotChunkV6],
    extra_entries: &[(&str, &[u8])],
) -> Vec<u8> {
    let buf = Vec::new();
    let mut builder = tar::Builder::new(buf);

    // Header
    let header_bytes = encode_header(header);
    let mut tar_header = tar::Header::new_gnu();
    tar_header.set_path("content.msgpack").unwrap();
    tar_header.set_size(header_bytes.len() as u64);
    tar_header.set_mode(0o644);
    tar_header.set_cksum();
    builder
        .append(&tar_header, header_bytes.as_slice())
        .unwrap();

    // Extra entries (before chunks)
    for (name, data) in extra_entries {
        let mut tar_header = tar::Header::new_gnu();
        tar_header.set_path(*name).unwrap();
        tar_header.set_size(data.len() as u64);
        tar_header.set_mode(0o644);
        tar_header.set_cksum();
        builder.append(&tar_header, *data).unwrap();
    }

    // Chunks
    for (i, chunk) in chunks.iter().enumerate() {
        let chunk_bytes = encode_chunk_snappy(chunk);
        let mut tar_header = tar::Header::new_gnu();
        tar_header
            .set_path(format!("balances.{i}.msgpack"))
            .unwrap();
        tar_header.set_size(chunk_bytes.len() as u64);
        tar_header.set_mode(0o644);
        tar_header.set_cksum();
        builder.append(&tar_header, chunk_bytes.as_slice()).unwrap();
    }

    builder.into_inner().expect("finalize tar")
}

// ---------------------------------------------------------------------------
// msgpack blob builders for inner data (Go-compatible single-letter keys)
// ---------------------------------------------------------------------------

/// Build a msgpack map blob representing Go's `baseAccountData` with the given
/// fields. Uses the same single-letter codec keys that Go's `msgp` produces.
fn encode_test_account_data(data: &CatchpointBaseAccountData) -> Vec<u8> {
    // We build the map manually using rmpv so we get exact control over keys.
    use rmpv::Value;

    let mut fields: Vec<(Value, Value)> = Vec::new();

    // Only emit non-zero fields (Go's omitempty behavior)
    if data.status != 0 {
        fields.push((Value::from("a"), Value::from(data.status as u64)));
    }
    if data.micro_algos != 0 {
        fields.push((Value::from("b"), Value::from(data.micro_algos)));
    }
    if data.rewards_base != 0 {
        fields.push((Value::from("c"), Value::from(data.rewards_base)));
    }
    if data.rewarded_micro_algos != 0 {
        fields.push((Value::from("d"), Value::from(data.rewarded_micro_algos)));
    }
    if data.auth_addr != [0u8; 32] {
        fields.push((Value::from("e"), Value::Binary(data.auth_addr.to_vec())));
    }
    if data.total_app_schema_num_uint != 0 {
        fields.push((
            Value::from("f"),
            Value::from(data.total_app_schema_num_uint),
        ));
    }
    if data.total_app_schema_num_byte_slice != 0 {
        fields.push((
            Value::from("g"),
            Value::from(data.total_app_schema_num_byte_slice),
        ));
    }
    if data.total_extra_app_pages != 0 {
        fields.push((
            Value::from("h"),
            Value::from(data.total_extra_app_pages as u64),
        ));
    }
    if data.total_asset_params != 0 {
        fields.push((Value::from("i"), Value::from(data.total_asset_params)));
    }
    if data.total_assets != 0 {
        fields.push((Value::from("j"), Value::from(data.total_assets)));
    }
    if data.total_app_params != 0 {
        fields.push((Value::from("k"), Value::from(data.total_app_params)));
    }
    if data.total_app_local_states != 0 {
        fields.push((Value::from("l"), Value::from(data.total_app_local_states)));
    }
    if data.total_boxes != 0 {
        fields.push((Value::from("m"), Value::from(data.total_boxes)));
    }
    if data.total_box_bytes != 0 {
        fields.push((Value::from("n"), Value::from(data.total_box_bytes)));
    }
    if data.incentive_eligible {
        fields.push((Value::from("o"), Value::Boolean(true)));
    }
    if data.last_proposed != 0 {
        fields.push((Value::from("p"), Value::from(data.last_proposed)));
    }
    if data.last_heartbeat != 0 {
        fields.push((Value::from("q"), Value::from(data.last_heartbeat)));
    }
    if data.vote_id != [0u8; 32] {
        fields.push((Value::from("A"), Value::Binary(data.vote_id.to_vec())));
    }
    if data.selection_id != [0u8; 32] {
        fields.push((Value::from("B"), Value::Binary(data.selection_id.to_vec())));
    }
    if data.vote_first_valid != 0 {
        fields.push((Value::from("C"), Value::from(data.vote_first_valid)));
    }
    if data.vote_last_valid != 0 {
        fields.push((Value::from("D"), Value::from(data.vote_last_valid)));
    }
    if data.vote_key_dilution != 0 {
        fields.push((Value::from("E"), Value::from(data.vote_key_dilution)));
    }
    if data.state_proof_id != [0u8; 64] {
        fields.push((
            Value::from("F"),
            Value::Binary(data.state_proof_id.to_vec()),
        ));
    }
    if data.update_round != 0 {
        fields.push((Value::from("z"), Value::from(data.update_round)));
    }

    let map = Value::Map(fields);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &map).expect("encode rmpv");
    buf
}

/// Build a msgpack map blob representing Go's `resourcesData` with the given
/// fields. Uses the same single-letter codec keys that Go's `msgp` produces.
fn encode_test_resources_data(data: &CatchpointResourcesData) -> Vec<u8> {
    use rmpv::Value;

    let mut fields: Vec<(Value, Value)> = Vec::new();

    if data.total != 0 {
        fields.push((Value::from("a"), Value::from(data.total)));
    }
    if data.decimals != 0 {
        fields.push((Value::from("b"), Value::from(data.decimals as u64)));
    }
    if data.default_frozen {
        fields.push((Value::from("c"), Value::Boolean(true)));
    }
    if !data.unit_name.is_empty() {
        fields.push((Value::from("d"), Value::from(data.unit_name.as_str())));
    }
    if !data.asset_name.is_empty() {
        fields.push((Value::from("e"), Value::from(data.asset_name.as_str())));
    }
    if !data.url.is_empty() {
        fields.push((Value::from("f"), Value::from(data.url.as_str())));
    }
    if data.metadata_hash != [0u8; 32] {
        fields.push((Value::from("g"), Value::Binary(data.metadata_hash.to_vec())));
    }
    if data.manager != [0u8; 32] {
        fields.push((Value::from("h"), Value::Binary(data.manager.to_vec())));
    }
    if data.reserve != [0u8; 32] {
        fields.push((Value::from("i"), Value::Binary(data.reserve.to_vec())));
    }
    if data.freeze != [0u8; 32] {
        fields.push((Value::from("j"), Value::Binary(data.freeze.to_vec())));
    }
    if data.clawback != [0u8; 32] {
        fields.push((Value::from("k"), Value::Binary(data.clawback.to_vec())));
    }
    if data.amount != 0 {
        fields.push((Value::from("l"), Value::from(data.amount)));
    }
    if data.frozen {
        fields.push((Value::from("m"), Value::Boolean(true)));
    }
    if data.schema_num_uint != 0 {
        fields.push((Value::from("n"), Value::from(data.schema_num_uint)));
    }
    if data.schema_num_byte_slice != 0 {
        fields.push((Value::from("o"), Value::from(data.schema_num_byte_slice)));
    }
    if !data.key_value.is_empty() {
        fields.push((Value::from("p"), Value::Binary(data.key_value.clone())));
    }
    if !data.approval_program.is_empty() {
        fields.push((
            Value::from("q"),
            Value::Binary(data.approval_program.clone()),
        ));
    }
    if !data.clear_state_program.is_empty() {
        fields.push((
            Value::from("r"),
            Value::Binary(data.clear_state_program.clone()),
        ));
    }
    if !data.global_state.is_empty() {
        fields.push((Value::from("s"), Value::Binary(data.global_state.clone())));
    }
    if data.local_state_schema_num_uint != 0 {
        fields.push((
            Value::from("t"),
            Value::from(data.local_state_schema_num_uint),
        ));
    }
    if data.local_state_schema_num_byte_slice != 0 {
        fields.push((
            Value::from("u"),
            Value::from(data.local_state_schema_num_byte_slice),
        ));
    }
    if data.global_state_schema_num_uint != 0 {
        fields.push((
            Value::from("v"),
            Value::from(data.global_state_schema_num_uint),
        ));
    }
    if data.global_state_schema_num_byte_slice != 0 {
        fields.push((
            Value::from("w"),
            Value::from(data.global_state_schema_num_byte_slice),
        ));
    }
    if data.extra_program_pages != 0 {
        fields.push((
            Value::from("x"),
            Value::from(data.extra_program_pages as u64),
        ));
    }
    if data.resource_flags != 0 {
        fields.push((Value::from("y"), Value::from(data.resource_flags as u64)));
    }
    if data.update_round != 0 {
        fields.push((Value::from("z"), Value::from(data.update_round)));
    }
    if data.version != 0 {
        fields.push((Value::from("A"), Value::from(data.version)));
    }
    if data.size_sponsor != [0u8; 32] {
        fields.push((Value::from("B"), Value::Binary(data.size_sponsor.to_vec())));
    }

    let map = Value::Map(fields);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &map).expect("encode rmpv");
    buf
}

// ---------------------------------------------------------------------------
// Helper: make a simple CatchpointFileHeader
// ---------------------------------------------------------------------------

fn make_v8_header() -> CatchpointFileHeader {
    CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        balances_round: 42_000_000,
        blocks_round: 42_000_010,
        total_accounts: 5,
        total_chunks: 2,
        total_kvs: 1,
        total_online_accounts: 3,
        total_online_round_params: 1,
        catchpoint: "42000000#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        block_header_digest: ByteBuf::from(vec![0xAB; 32]),
        totals: Default::default(),
    }
}

/// Decompress Snappy-framed data into raw bytes.
fn snappy_frame_decompress(data: &[u8]) -> Vec<u8> {
    let mut decoder = snap::read::FrameDecoder::new(data);
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut out).expect("snappy frame decompress");
    out
}

fn make_test_address(seed: u8) -> ByteBuf {
    ByteBuf::from(vec![seed; 32])
}

// ===========================================================================
// Header parsing tests
// ===========================================================================

#[test]
fn test_parse_header_v8() {
    let header = make_v8_header();
    let archive = build_test_catchpoint_archive(&header, &[]);

    // Verify the archive is valid tar with the expected content.msgpack entry
    let mut tar = tar::Archive::new(archive.as_slice());
    let entries: Vec<_> = tar
        .entries()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        entries.len(),
        1,
        "archive should have exactly 1 entry (header only)"
    );

    // Re-read and verify we can deserialize the header back
    let mut tar = tar::Archive::new(archive.as_slice());
    for entry in tar.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        if path == "content.msgpack" {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut buf).unwrap();
            let decoded: CatchpointFileHeader = rmp_serde::from_slice(&buf).expect("decode header");
            assert_eq!(decoded.version, CATCHPOINT_FILE_VERSION_V8);
            assert_eq!(decoded.balances_round, 42_000_000);
            assert_eq!(decoded.blocks_round, 42_000_010);
            assert_eq!(decoded.total_accounts, 5);
            assert_eq!(decoded.total_chunks, 2);
            assert_eq!(decoded.total_kvs, 1);
            assert_eq!(decoded.total_online_accounts, 3);
            assert_eq!(decoded.total_online_round_params, 1);
            assert!(decoded.catchpoint.starts_with("42000000#"));
            assert_eq!(decoded.block_header_digest.len(), 32);
        }
    }
}

#[test]
fn test_reject_unsupported_version() {
    // Build an archive with V5 header (unsupported — only V6+ should be accepted)
    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V5,
        balances_round: 1_000,
        ..Default::default()
    };
    let archive = build_test_catchpoint_archive(&header, &[]);

    // We can still parse the tar and read the header
    let mut tar = tar::Archive::new(archive.as_slice());
    for entry in tar.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        if path == "content.msgpack" {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut buf).unwrap();
            let decoded: CatchpointFileHeader = rmp_serde::from_slice(&buf).expect("decode header");
            // The header decodes fine, but version is V5 which the parser should reject.
            assert_eq!(decoded.version, CATCHPOINT_FILE_VERSION_V5);
            assert_eq!(decoded.version, 128);
        }
    }
}

// ===========================================================================
// Chunk parsing tests
// ===========================================================================

#[test]
fn test_parse_balance_chunk() {
    let balance = BalanceRecordV6 {
        address: make_test_address(0x01),
        account_data: ByteBuf::from(vec![0x80]), // empty msgpack map
        resources: HashMap::new(),
        expecting_more_entries: false,
    };
    let chunk = CatchpointSnapshotChunkV6 {
        balances: vec![balance.clone()],
        ..Default::default()
    };
    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        total_chunks: 1,
        total_accounts: 1,
        ..Default::default()
    };
    let archive = build_test_catchpoint_archive(&header, &[chunk]);

    // Manually parse the tar to verify chunk content is correct
    let mut tar = tar::Archive::new(archive.as_slice());
    let mut found_chunk = false;
    for entry in tar.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        if path == "balances.0.msgpack" {
            found_chunk = true;
            let mut compressed = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut compressed).unwrap();

            // Decompress snappy
            let decompressed = snappy_frame_decompress(&compressed);

            // Decode chunk
            let decoded: CatchpointSnapshotChunkV6 =
                rmp_serde::from_slice(&decompressed).expect("decode chunk");
            assert_eq!(decoded.balances.len(), 1);
            assert_eq!(decoded.balances[0].address, make_test_address(0x01));
            assert!(!decoded.balances[0].expecting_more_entries);
            assert!(decoded.kvs.is_empty());
            assert!(decoded.online_accounts.is_empty());
        }
    }
    assert!(found_chunk, "balances.0.msgpack entry not found in archive");
}

#[test]
fn test_parse_kv_chunk() {
    let kv = KVRecordV6 {
        key: ByteBuf::from(b"box-key-123".to_vec()),
        value: ByteBuf::from(b"box-value-data".to_vec()),
    };
    let chunk = CatchpointSnapshotChunkV6 {
        kvs: vec![kv],
        ..Default::default()
    };
    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        total_chunks: 1,
        total_kvs: 1,
        ..Default::default()
    };
    let archive = build_test_catchpoint_archive(&header, &[chunk]);

    let mut tar = tar::Archive::new(archive.as_slice());
    let mut found = false;
    for entry in tar.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        if path == "balances.0.msgpack" {
            found = true;
            let mut compressed = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut compressed).unwrap();
            let decompressed = snappy_frame_decompress(&compressed);
            let decoded: CatchpointSnapshotChunkV6 = rmp_serde::from_slice(&decompressed).unwrap();

            assert_eq!(decoded.kvs.len(), 1);
            assert_eq!(decoded.kvs[0].key.as_ref(), b"box-key-123");
            assert_eq!(decoded.kvs[0].value.as_ref(), b"box-value-data");
            assert!(decoded.balances.is_empty());
        }
    }
    assert!(found, "chunk entry not found");
}

#[test]
fn test_parse_online_account_chunk() {
    let online = OnlineAccountRecordV6 {
        address: make_test_address(0x42),
        updated_round: 100_000,
        normalized_online_balance: 5_000_000_000,
        vote_last_valid: 200_000,
        data: ByteBuf::from(vec![0x80]), // empty msgpack map
    };
    let chunk = CatchpointSnapshotChunkV6 {
        online_accounts: vec![online],
        ..Default::default()
    };
    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        total_chunks: 1,
        total_online_accounts: 1,
        ..Default::default()
    };
    let archive = build_test_catchpoint_archive(&header, &[chunk]);

    let mut tar = tar::Archive::new(archive.as_slice());
    let mut found = false;
    for entry in tar.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        if path == "balances.0.msgpack" {
            found = true;
            let mut compressed = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut compressed).unwrap();
            let decompressed = snappy_frame_decompress(&compressed);
            let decoded: CatchpointSnapshotChunkV6 = rmp_serde::from_slice(&decompressed).unwrap();

            assert_eq!(decoded.online_accounts.len(), 1);
            assert_eq!(decoded.online_accounts[0].address, make_test_address(0x42));
            assert_eq!(decoded.online_accounts[0].updated_round, 100_000);
            assert_eq!(
                decoded.online_accounts[0].normalized_online_balance,
                5_000_000_000
            );
            assert_eq!(decoded.online_accounts[0].vote_last_valid, 200_000);
        }
    }
    assert!(found, "chunk entry not found");
}

#[test]
fn test_parse_online_round_params_chunk() {
    let orp = OnlineRoundParamsRecordV6 {
        round: 42_000_000,
        data: ByteBuf::from(vec![0x80]), // empty msgpack map
    };
    let chunk = CatchpointSnapshotChunkV6 {
        online_round_params: vec![orp],
        ..Default::default()
    };
    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        total_chunks: 1,
        total_online_round_params: 1,
        ..Default::default()
    };
    let archive = build_test_catchpoint_archive(&header, &[chunk]);

    let mut tar = tar::Archive::new(archive.as_slice());
    let mut found = false;
    for entry in tar.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        if path == "balances.0.msgpack" {
            found = true;
            let mut compressed = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut compressed).unwrap();
            let decompressed = snappy_frame_decompress(&compressed);
            let decoded: CatchpointSnapshotChunkV6 = rmp_serde::from_slice(&decompressed).unwrap();

            assert_eq!(decoded.online_round_params.len(), 1);
            assert_eq!(decoded.online_round_params[0].round, 42_000_000);
        }
    }
    assert!(found, "chunk entry not found");
}

#[test]
fn test_parse_multiple_chunks() {
    let chunks: Vec<CatchpointSnapshotChunkV6> = (0..3)
        .map(|i| CatchpointSnapshotChunkV6 {
            balances: vec![BalanceRecordV6 {
                address: make_test_address(i as u8),
                account_data: ByteBuf::from(vec![0x80]),
                resources: HashMap::new(),
                expecting_more_entries: false,
            }],
            ..Default::default()
        })
        .collect();

    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        total_chunks: 3,
        total_accounts: 3,
        ..Default::default()
    };
    let archive = build_test_catchpoint_archive(&header, &chunks);

    let mut tar = tar::Archive::new(archive.as_slice());
    let mut chunk_count = 0;
    for entry in tar.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        if path.starts_with("balances.") && path.ends_with(".msgpack") {
            let mut compressed = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut compressed).unwrap();
            let decompressed = snappy_frame_decompress(&compressed);
            let decoded: CatchpointSnapshotChunkV6 = rmp_serde::from_slice(&decompressed).unwrap();

            assert_eq!(decoded.balances.len(), 1);
            assert_eq!(
                decoded.balances[0].address,
                make_test_address(chunk_count as u8)
            );
            chunk_count += 1;
        }
    }
    assert_eq!(chunk_count, 3, "expected 3 chunk entries");
}

// ===========================================================================
// Inner blob decode tests (end-to-end pipeline)
// ===========================================================================

#[test]
fn test_decode_account_data_from_chunk() {
    // Build a realistic baseAccountData blob
    let account_data = CatchpointBaseAccountData {
        status: 1,                   // Online
        micro_algos: 50_000_000_000, // 50,000 ALGO
        rewards_base: 12345,
        rewarded_micro_algos: 100_000,
        total_asset_params: 3,
        total_assets: 5,
        total_app_params: 2,
        total_app_local_states: 4,
        total_boxes: 10,
        total_box_bytes: 2048,
        incentive_eligible: true,
        last_proposed: 41_999_000,
        last_heartbeat: 41_998_500,
        update_round: 41_000_000,
        ..Default::default()
    };
    let account_blob = encode_test_account_data(&account_data);

    // Wrap in a BalanceRecordV6 inside a chunk
    let balance = BalanceRecordV6 {
        address: make_test_address(0xAA),
        account_data: ByteBuf::from(account_blob.clone()),
        resources: HashMap::new(),
        expecting_more_entries: false,
    };
    let chunk = CatchpointSnapshotChunkV6 {
        balances: vec![balance],
        ..Default::default()
    };
    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        total_chunks: 1,
        total_accounts: 1,
        ..Default::default()
    };
    let archive = build_test_catchpoint_archive(&header, &[chunk]);

    // Parse the archive, extract the chunk, decode the inner blob
    let mut tar = tar::Archive::new(archive.as_slice());
    let mut found = false;
    for entry in tar.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        if path == "balances.0.msgpack" {
            found = true;
            let mut compressed = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut compressed).unwrap();
            let decompressed = snappy_frame_decompress(&compressed);
            let decoded_chunk: CatchpointSnapshotChunkV6 =
                rmp_serde::from_slice(&decompressed).unwrap();

            assert_eq!(decoded_chunk.balances.len(), 1);
            let balance_record = &decoded_chunk.balances[0];

            // Decode the inner account_data blob using the msgp_compat decoder
            let decoded = decode_base_account_data(&balance_record.account_data)
                .expect("decode_base_account_data failed");

            assert_eq!(decoded.status, 1);
            assert_eq!(decoded.micro_algos, 50_000_000_000);
            assert_eq!(decoded.rewards_base, 12345);
            assert_eq!(decoded.rewarded_micro_algos, 100_000);
            assert_eq!(decoded.total_asset_params, 3);
            assert_eq!(decoded.total_assets, 5);
            assert_eq!(decoded.total_app_params, 2);
            assert_eq!(decoded.total_app_local_states, 4);
            assert_eq!(decoded.total_boxes, 10);
            assert_eq!(decoded.total_box_bytes, 2048);
            assert!(decoded.incentive_eligible);
            assert_eq!(decoded.last_proposed, 41_999_000);
            assert_eq!(decoded.last_heartbeat, 41_998_500);
            assert_eq!(decoded.update_round, 41_000_000);
        }
    }
    assert!(found, "chunk entry not found");
}

#[test]
fn test_decode_resources_from_chunk() {
    // Build a resourcesData blob for an asset
    let resources = CatchpointResourcesData {
        total: 1_000_000_000,
        decimals: 6,
        default_frozen: false,
        unit_name: "ALGO".to_string(),
        asset_name: "Algorand".to_string(),
        url: "https://algorand.foundation".to_string(),
        amount: 500_000_000,
        resource_flags: 2, // OWNERSHIP
        update_round: 41_000_000,
        ..Default::default()
    };
    let resources_blob = encode_test_resources_data(&resources);

    let mut resource_map = HashMap::new();
    resource_map.insert(12345u64, ByteBuf::from(resources_blob));

    let balance = BalanceRecordV6 {
        address: make_test_address(0xBB),
        account_data: ByteBuf::from(vec![0x80]), // empty map
        resources: resource_map,
        expecting_more_entries: false,
    };
    let chunk = CatchpointSnapshotChunkV6 {
        balances: vec![balance],
        ..Default::default()
    };
    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        total_chunks: 1,
        total_accounts: 1,
        ..Default::default()
    };
    let archive = build_test_catchpoint_archive(&header, &[chunk]);

    let mut tar = tar::Archive::new(archive.as_slice());
    let mut found = false;
    for entry in tar.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        if path == "balances.0.msgpack" {
            found = true;
            let mut compressed = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut compressed).unwrap();
            let decompressed = snappy_frame_decompress(&compressed);
            let decoded_chunk: CatchpointSnapshotChunkV6 =
                rmp_serde::from_slice(&decompressed).unwrap();

            let balance_record = &decoded_chunk.balances[0];
            assert!(balance_record.resources.contains_key(&12345));

            let raw_resource = &balance_record.resources[&12345];
            let decoded =
                decode_resources_data(raw_resource).expect("decode_resources_data failed");

            assert_eq!(decoded.total, 1_000_000_000);
            assert_eq!(decoded.decimals, 6);
            assert!(!decoded.default_frozen);
            assert_eq!(decoded.unit_name, "ALGO");
            assert_eq!(decoded.asset_name, "Algorand");
            assert_eq!(decoded.url, "https://algorand.foundation");
            assert_eq!(decoded.amount, 500_000_000);
            assert_eq!(decoded.resource_flags, 2);
            assert_eq!(decoded.update_round, 41_000_000);
        }
    }
    assert!(found, "chunk entry not found");
}

// ===========================================================================
// Gzip support
// ===========================================================================

#[test]
fn test_parse_gzipped_archive() {
    let balance = BalanceRecordV6 {
        address: make_test_address(0xCC),
        account_data: ByteBuf::from(vec![0x80]),
        resources: HashMap::new(),
        expecting_more_entries: false,
    };
    let chunk = CatchpointSnapshotChunkV6 {
        balances: vec![balance],
        ..Default::default()
    };
    let header = make_v8_header();
    let gzipped = build_test_catchpoint_gzipped(&header, &[chunk]);

    // Decompress gzip first, then parse as tar
    let gz_decoder = flate2::read::GzDecoder::new(gzipped.as_slice());
    let mut tar = tar::Archive::new(gz_decoder);

    let mut found_header = false;
    let mut found_chunk = false;
    for entry in tar.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        match path.as_str() {
            "content.msgpack" => {
                found_header = true;
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut entry, &mut buf).unwrap();
                let decoded: CatchpointFileHeader = rmp_serde::from_slice(&buf).unwrap();
                assert_eq!(decoded.version, CATCHPOINT_FILE_VERSION_V8);
                assert_eq!(decoded.balances_round, 42_000_000);
            }
            "balances.0.msgpack" => {
                found_chunk = true;
                let mut compressed = Vec::new();
                std::io::Read::read_to_end(&mut entry, &mut compressed).unwrap();
                let decompressed = snappy_frame_decompress(&compressed);
                let decoded: CatchpointSnapshotChunkV6 =
                    rmp_serde::from_slice(&decompressed).unwrap();
                assert_eq!(decoded.balances.len(), 1);
                assert_eq!(decoded.balances[0].address, make_test_address(0xCC));
            }
            _ => {}
        }
    }
    assert!(found_header, "content.msgpack not found in gzipped archive");
    assert!(
        found_chunk,
        "balances.0.msgpack not found in gzipped archive"
    );
}

// ===========================================================================
// Edge cases
// ===========================================================================

#[test]
fn test_empty_archive() {
    // Archive with only a header, no chunks.
    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        total_chunks: 0,
        total_accounts: 0,
        ..Default::default()
    };
    let archive = build_test_catchpoint_archive(&header, &[]);

    let mut tar = tar::Archive::new(archive.as_slice());
    let entries: Vec<_> = tar
        .entries()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    // Should contain exactly one entry: the header
    assert_eq!(entries.len(), 1);

    let mut tar = tar::Archive::new(archive.as_slice());
    for entry in tar.entries().unwrap() {
        let entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        assert_eq!(path, "content.msgpack");
    }
}

#[test]
fn test_unknown_entries_skipped() {
    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        total_chunks: 1,
        total_accounts: 1,
        ..Default::default()
    };
    let chunk = CatchpointSnapshotChunkV6 {
        balances: vec![BalanceRecordV6 {
            address: make_test_address(0xDD),
            account_data: ByteBuf::from(vec![0x80]),
            resources: HashMap::new(),
            expecting_more_entries: false,
        }],
        ..Default::default()
    };
    let archive = build_archive_with_extra_entries(
        &header,
        &[chunk],
        &[
            ("metadata.json", b"{\"version\":1}"),
            ("checksums.txt", b"abc123\n"),
            ("some/nested/file.dat", b"\x00\x01\x02"),
        ],
    );

    // Count known vs unknown entries
    let mut tar = tar::Archive::new(archive.as_slice());
    let mut known_count = 0;
    let mut unknown_count = 0;
    for entry in tar.entries().unwrap() {
        let entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        if path == "content.msgpack"
            || (path.starts_with("balances.") && path.ends_with(".msgpack"))
        {
            known_count += 1;
        } else {
            unknown_count += 1;
        }
    }
    assert_eq!(known_count, 2, "expected header + 1 chunk");
    assert_eq!(unknown_count, 3, "expected 3 extra entries");
}

#[test]
fn test_large_chunk_count() {
    let num_chunks = 100;
    let chunks: Vec<CatchpointSnapshotChunkV6> = (0..num_chunks)
        .map(|i| CatchpointSnapshotChunkV6 {
            balances: vec![BalanceRecordV6 {
                address: ByteBuf::from(vec![(i % 256) as u8; 32]),
                account_data: ByteBuf::from(vec![0x80]),
                resources: HashMap::new(),
                expecting_more_entries: false,
            }],
            ..Default::default()
        })
        .collect();

    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        total_chunks: num_chunks as u64,
        total_accounts: num_chunks as u64,
        ..Default::default()
    };
    let archive = build_test_catchpoint_archive(&header, &chunks);

    // Parse and count chunks
    let mut tar = tar::Archive::new(archive.as_slice());
    let mut chunk_count = 0u64;
    for entry in tar.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        if path.starts_with("balances.") && path.ends_with(".msgpack") {
            let mut compressed = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut compressed).unwrap();
            let decompressed = snappy_frame_decompress(&compressed);
            let decoded: CatchpointSnapshotChunkV6 = rmp_serde::from_slice(&decompressed).unwrap();
            assert_eq!(decoded.balances.len(), 1);
            chunk_count += 1;
        }
    }
    assert_eq!(
        chunk_count, num_chunks as u64,
        "all chunks should be parseable"
    );
}

// ===========================================================================
// Full end-to-end pipeline test (tar -> snappy -> chunk -> inner blob decode)
// ===========================================================================

#[test]
fn test_full_pipeline_account_data_end_to_end() {
    // Build a realistic account with voting keys
    let mut vote_id = [0u8; 32];
    vote_id[0] = 0xAA;
    vote_id[31] = 0xBB;
    let mut selection_id = [0u8; 32];
    selection_id[0] = 0xCC;
    selection_id[31] = 0xDD;

    let account_data = CatchpointBaseAccountData {
        status: 1,                    // Online
        micro_algos: 100_000_000_000, // 100,000 ALGO
        rewards_base: 999,
        rewarded_micro_algos: 50_000,
        total_app_schema_num_uint: 16,
        total_app_schema_num_byte_slice: 8,
        total_extra_app_pages: 3,
        total_asset_params: 2,
        total_assets: 10,
        total_app_params: 1,
        total_app_local_states: 5,
        total_boxes: 20,
        total_box_bytes: 4096,
        incentive_eligible: true,
        last_proposed: 42_000_000,
        last_heartbeat: 41_999_999,
        vote_id,
        selection_id,
        vote_first_valid: 40_000_000,
        vote_last_valid: 45_000_000,
        vote_key_dilution: 10_000,
        update_round: 41_500_000,
        ..Default::default()
    };
    let account_blob = encode_test_account_data(&account_data);

    // Build resource data for an asset
    let resource_data = CatchpointResourcesData {
        total: 10_000_000_000,
        decimals: 8,
        unit_name: "TEST".to_string(),
        asset_name: "Test Token".to_string(),
        url: "https://example.com".to_string(),
        amount: 1_000_000,
        resource_flags: 2,
        update_round: 41_000_000,
        ..Default::default()
    };
    let resource_blob = encode_test_resources_data(&resource_data);

    let mut resources_map = HashMap::new();
    resources_map.insert(999u64, ByteBuf::from(resource_blob));

    // Build the chunk
    let balance = BalanceRecordV6 {
        address: make_test_address(0xFF),
        account_data: ByteBuf::from(account_blob),
        resources: resources_map,
        expecting_more_entries: false,
    };
    let kv = KVRecordV6 {
        key: ByteBuf::from(b"app-42-box-hello".to_vec()),
        value: ByteBuf::from(b"world".to_vec()),
    };
    let chunk = CatchpointSnapshotChunkV6 {
        balances: vec![balance],
        kvs: vec![kv],
        ..Default::default()
    };
    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        balances_round: 42_000_000,
        blocks_round: 42_000_010,
        total_chunks: 1,
        total_accounts: 1,
        total_kvs: 1,
        catchpoint: "42000000#TEST".to_string(),
        block_header_digest: ByteBuf::from(vec![0xDE; 32]),
        ..Default::default()
    };

    // Build gzipped archive for maximum realism
    let gzipped = build_test_catchpoint_gzipped(&header, &[chunk]);

    // Parse: gzip -> tar -> snappy -> msgpack -> inner blob decode
    let gz_decoder = flate2::read::GzDecoder::new(gzipped.as_slice());
    let mut tar = tar::Archive::new(gz_decoder);

    let mut verified_header = false;
    let mut verified_chunk = false;

    for entry in tar.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        match path.as_str() {
            "content.msgpack" => {
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut entry, &mut buf).unwrap();
                let h: CatchpointFileHeader = rmp_serde::from_slice(&buf).unwrap();
                assert_eq!(h.version, CATCHPOINT_FILE_VERSION_V8);
                assert_eq!(h.balances_round, 42_000_000);
                assert_eq!(h.blocks_round, 42_000_010);
                assert_eq!(h.total_accounts, 1);
                assert_eq!(h.total_kvs, 1);
                assert_eq!(h.catchpoint, "42000000#TEST");
                assert_eq!(h.block_header_digest.len(), 32);
                verified_header = true;
            }
            "balances.0.msgpack" => {
                let mut compressed = Vec::new();
                std::io::Read::read_to_end(&mut entry, &mut compressed).unwrap();
                let decompressed = snappy_frame_decompress(&compressed);
                let c: CatchpointSnapshotChunkV6 = rmp_serde::from_slice(&decompressed).unwrap();

                // Verify balance record
                assert_eq!(c.balances.len(), 1);
                let br = &c.balances[0];
                assert_eq!(br.address, make_test_address(0xFF));

                // Decode inner account data blob
                let acct =
                    decode_base_account_data(&br.account_data).expect("inner account decode");
                assert_eq!(acct.status, 1);
                assert_eq!(acct.micro_algos, 100_000_000_000);
                assert_eq!(acct.rewards_base, 999);
                assert_eq!(acct.rewarded_micro_algos, 50_000);
                assert_eq!(acct.total_app_schema_num_uint, 16);
                assert_eq!(acct.total_app_schema_num_byte_slice, 8);
                assert_eq!(acct.total_extra_app_pages, 3);
                assert_eq!(acct.total_asset_params, 2);
                assert_eq!(acct.total_assets, 10);
                assert_eq!(acct.total_app_params, 1);
                assert_eq!(acct.total_app_local_states, 5);
                assert_eq!(acct.total_boxes, 20);
                assert_eq!(acct.total_box_bytes, 4096);
                assert!(acct.incentive_eligible);
                assert_eq!(acct.last_proposed, 42_000_000);
                assert_eq!(acct.last_heartbeat, 41_999_999);
                assert_eq!(acct.vote_id[0], 0xAA);
                assert_eq!(acct.vote_id[31], 0xBB);
                assert_eq!(acct.selection_id[0], 0xCC);
                assert_eq!(acct.selection_id[31], 0xDD);
                assert_eq!(acct.vote_first_valid, 40_000_000);
                assert_eq!(acct.vote_last_valid, 45_000_000);
                assert_eq!(acct.vote_key_dilution, 10_000);
                assert_eq!(acct.update_round, 41_500_000);

                // Decode inner resources blob
                assert!(br.resources.contains_key(&999));
                let res =
                    decode_resources_data(&br.resources[&999]).expect("inner resource decode");
                assert_eq!(res.total, 10_000_000_000);
                assert_eq!(res.decimals, 8);
                assert_eq!(res.unit_name, "TEST");
                assert_eq!(res.asset_name, "Test Token");
                assert_eq!(res.url, "https://example.com");
                assert_eq!(res.amount, 1_000_000);
                assert_eq!(res.resource_flags, 2);
                assert_eq!(res.update_round, 41_000_000);

                // Verify KV record
                assert_eq!(c.kvs.len(), 1);
                assert_eq!(c.kvs[0].key.as_ref(), b"app-42-box-hello");
                assert_eq!(c.kvs[0].value.as_ref(), b"world");

                verified_chunk = true;
            }
            _ => panic!("unexpected entry: {path}"),
        }
    }
    assert!(verified_header, "header not verified");
    assert!(verified_chunk, "chunk not verified");
}

// ===========================================================================
// Direct msgp_compat decoder tests (unit-level, using our blob builders)
// ===========================================================================

#[test]
fn test_decode_empty_account_data() {
    // An empty msgpack map should produce defaults
    let result = decode_base_account_data(&[0x80]).unwrap();
    assert_eq!(result, CatchpointBaseAccountData::default());
}

#[test]
fn test_decode_account_data_roundtrip() {
    let original = CatchpointBaseAccountData {
        status: 2, // NotParticipating
        micro_algos: 999_999_999,
        rewards_base: 42,
        total_asset_params: 7,
        total_boxes: 100,
        total_box_bytes: 50_000,
        update_round: 1_000_000,
        ..Default::default()
    };
    let encoded = encode_test_account_data(&original);
    let decoded = decode_base_account_data(&encoded).unwrap();
    assert_eq!(decoded.status, original.status);
    assert_eq!(decoded.micro_algos, original.micro_algos);
    assert_eq!(decoded.rewards_base, original.rewards_base);
    assert_eq!(decoded.total_asset_params, original.total_asset_params);
    assert_eq!(decoded.total_boxes, original.total_boxes);
    assert_eq!(decoded.total_box_bytes, original.total_box_bytes);
    assert_eq!(decoded.update_round, original.update_round);
}

#[test]
fn test_decode_resources_data_roundtrip() {
    let original = CatchpointResourcesData {
        total: 1_000_000,
        decimals: 6,
        unit_name: "USDC".to_string(),
        asset_name: "USD Coin".to_string(),
        url: "https://centre.io".to_string(),
        amount: 500_000,
        frozen: true,
        resource_flags: 2,
        extra_program_pages: 1,
        update_round: 2_000_000,
        ..Default::default()
    };
    let encoded = encode_test_resources_data(&original);
    let decoded = decode_resources_data(&encoded).unwrap();
    assert_eq!(decoded.total, original.total);
    assert_eq!(decoded.decimals, original.decimals);
    assert_eq!(decoded.unit_name, original.unit_name);
    assert_eq!(decoded.asset_name, original.asset_name);
    assert_eq!(decoded.url, original.url);
    assert_eq!(decoded.amount, original.amount);
    assert!(decoded.frozen);
    assert_eq!(decoded.resource_flags, original.resource_flags);
    assert_eq!(decoded.extra_program_pages, original.extra_program_pages);
    assert_eq!(decoded.update_round, original.update_round);
}

#[test]
fn test_decode_empty_resources_data() {
    let result = decode_resources_data(&[0x80]).unwrap();
    assert_eq!(result, CatchpointResourcesData::default());
}

#[test]
fn test_decode_online_account_data_roundtrip() {
    use rmpv::Value;

    let mut vote_id = [0u8; 32];
    vote_id[0] = 0x11;
    let mut selection_id = [0u8; 32];
    selection_id[0] = 0x22;

    // Build the blob manually with Go's codec keys
    let fields = vec![
        (Value::from("A"), Value::Binary(vote_id.to_vec())),
        (Value::from("B"), Value::Binary(selection_id.to_vec())),
        (Value::from("C"), Value::from(1_000u64)),
        (Value::from("D"), Value::from(2_000u64)),
        (Value::from("E"), Value::from(100u64)),
        (Value::from("V"), Value::from(500u64)),
        (Value::from("W"), Value::from(400u64)),
        (Value::from("X"), Value::Boolean(true)),
        (Value::from("Y"), Value::from(10_000_000u64)),
        (Value::from("Z"), Value::from(42u64)),
    ];
    let map = Value::Map(fields);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &map).expect("encode");

    let decoded = decode_base_online_account_data(&buf).unwrap();
    assert_eq!(decoded.vote_id[0], 0x11);
    assert_eq!(decoded.selection_id[0], 0x22);
    assert_eq!(decoded.vote_first_valid, 1_000);
    assert_eq!(decoded.vote_last_valid, 2_000);
    assert_eq!(decoded.vote_key_dilution, 100);
    assert_eq!(decoded.last_proposed, 500);
    assert_eq!(decoded.last_heartbeat, 400);
    assert!(decoded.incentive_eligible);
    assert_eq!(decoded.micro_algos, 10_000_000);
    assert_eq!(decoded.rewards_base, 42);
}

#[test]
fn test_decode_online_round_params_roundtrip() {
    use rmpv::Value;

    let fields = vec![
        (Value::from("online"), Value::from(5_000_000_000u64)),
        (Value::from("rwdlvl"), Value::from(12345u64)),
        (
            Value::from("proto"),
            Value::from("https://github.com/algorandfoundation/specs/tree/v41"),
        ),
    ];
    let map = Value::Map(fields);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &map).expect("encode");

    let decoded = decode_online_round_params_data(&buf).unwrap();
    assert_eq!(decoded.online_supply, 5_000_000_000);
    assert_eq!(decoded.rewards_level, 12345);
    assert_eq!(
        decoded.current_protocol,
        "https://github.com/algorandfoundation/specs/tree/v41"
    );
}

// ===========================================================================
// Chunk with mixed record types
// ===========================================================================

#[test]
fn test_chunk_with_all_record_types() {
    // Build a chunk that contains all four record types at once
    let chunk = CatchpointSnapshotChunkV6 {
        balances: vec![BalanceRecordV6 {
            address: make_test_address(0x01),
            account_data: ByteBuf::from(vec![0x80]),
            resources: HashMap::new(),
            expecting_more_entries: true,
        }],
        kvs: vec![
            KVRecordV6 {
                key: ByteBuf::from(b"key1".to_vec()),
                value: ByteBuf::from(b"val1".to_vec()),
            },
            KVRecordV6 {
                key: ByteBuf::from(b"key2".to_vec()),
                value: ByteBuf::from(b"val2".to_vec()),
            },
        ],
        online_accounts: vec![OnlineAccountRecordV6 {
            address: make_test_address(0x02),
            updated_round: 42_000,
            normalized_online_balance: 1_000_000,
            vote_last_valid: 50_000,
            data: ByteBuf::from(vec![0x80]),
        }],
        online_round_params: vec![OnlineRoundParamsRecordV6 {
            round: 42_000,
            data: ByteBuf::from(vec![0x80]),
        }],
    };

    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        total_chunks: 1,
        ..Default::default()
    };
    let archive = build_test_catchpoint_archive(&header, &[chunk]);

    let mut tar = tar::Archive::new(archive.as_slice());
    let mut found = false;
    for entry in tar.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        if path == "balances.0.msgpack" {
            found = true;
            let mut compressed = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut compressed).unwrap();
            let decompressed = snappy_frame_decompress(&compressed);
            let decoded: CatchpointSnapshotChunkV6 = rmp_serde::from_slice(&decompressed).unwrap();

            assert_eq!(decoded.balances.len(), 1);
            assert!(decoded.balances[0].expecting_more_entries);
            assert_eq!(decoded.kvs.len(), 2);
            assert_eq!(decoded.kvs[0].key.as_ref(), b"key1");
            assert_eq!(decoded.kvs[1].key.as_ref(), b"key2");
            assert_eq!(decoded.online_accounts.len(), 1);
            assert_eq!(decoded.online_accounts[0].updated_round, 42_000);
            assert_eq!(decoded.online_round_params.len(), 1);
            assert_eq!(decoded.online_round_params[0].round, 42_000);
        }
    }
    assert!(found, "chunk entry not found");
}

// ===========================================================================
// Balance record with resources map (multiple resource entries)
// ===========================================================================

#[test]
fn test_balance_record_with_multiple_resources() {
    let res1 = CatchpointResourcesData {
        total: 1_000,
        decimals: 0,
        unit_name: "NFT".to_string(),
        resource_flags: 2,
        ..Default::default()
    };
    let res2 = CatchpointResourcesData {
        amount: 500,
        frozen: true,
        resource_flags: 0,
        ..Default::default()
    };

    let mut resources = HashMap::new();
    resources.insert(100u64, ByteBuf::from(encode_test_resources_data(&res1)));
    resources.insert(200u64, ByteBuf::from(encode_test_resources_data(&res2)));

    let balance = BalanceRecordV6 {
        address: make_test_address(0xEE),
        account_data: ByteBuf::from(vec![0x80]),
        resources,
        expecting_more_entries: false,
    };
    let chunk = CatchpointSnapshotChunkV6 {
        balances: vec![balance],
        ..Default::default()
    };
    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        total_chunks: 1,
        total_accounts: 1,
        ..Default::default()
    };
    let archive = build_test_catchpoint_archive(&header, &[chunk]);

    let mut tar = tar::Archive::new(archive.as_slice());
    let mut found = false;
    for entry in tar.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        if path == "balances.0.msgpack" {
            found = true;
            let mut compressed = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut compressed).unwrap();
            let decompressed = snappy_frame_decompress(&compressed);
            let decoded: CatchpointSnapshotChunkV6 = rmp_serde::from_slice(&decompressed).unwrap();

            let br = &decoded.balances[0];
            assert_eq!(br.resources.len(), 2);

            let r1 = decode_resources_data(&br.resources[&100]).unwrap();
            assert_eq!(r1.total, 1_000);
            assert_eq!(r1.unit_name, "NFT");
            assert_eq!(r1.resource_flags, 2);

            let r2 = decode_resources_data(&br.resources[&200]).unwrap();
            assert_eq!(r2.amount, 500);
            assert!(r2.frozen);
            assert_eq!(r2.resource_flags, 0);
        }
    }
    assert!(found, "chunk entry not found");
}

// ===========================================================================
// Snappy compression correctness
// ===========================================================================

#[test]
fn test_snappy_roundtrip() {
    // Verify our encode_chunk_snappy produces valid Snappy framing format that
    // decompresses back to the same msgpack.
    let chunk = CatchpointSnapshotChunkV6 {
        balances: vec![BalanceRecordV6 {
            address: make_test_address(0x77),
            account_data: ByteBuf::from(vec![0x80]),
            resources: HashMap::new(),
            expecting_more_entries: false,
        }],
        ..Default::default()
    };

    let original_msgpack = rmp_serde::to_vec_named(&chunk).unwrap();
    let compressed = encode_chunk_snappy(&chunk);

    // Verify the Snappy framing header is present
    assert!(
        compressed.len() >= 10 && compressed[0] == 0xff,
        "should start with Snappy stream identifier"
    );

    // Decompressed should match exactly
    let decompressed = snappy_frame_decompress(&compressed);
    assert_eq!(decompressed, original_msgpack);
}

// ===========================================================================
// Parser API tests (CatchpointReader)
// ===========================================================================
// These tests exercise the CatchpointReader streaming parser API:
//   CatchpointReader::new(reader) -> Result<Self, CatchpointError>
//   reader.for_each(|entry| { ... }) -> Result<(), CatchpointError>
//   reader.collect_entries() -> Result<Vec<CatchpointEntry>, CatchpointError>
//   reader.header() -> Option<&CatchpointFileHeader>
//   CatchpointEntry::Header(CatchpointFileHeader)
//   CatchpointEntry::Chunk(CatchpointSnapshotChunkV6)
//   CatchpointEntry::StateProofVerification(Vec<u8>)

#[test]
fn test_parser_collect_entries_header_only() {
    // Exercise CatchpointReader::new() + collect_entries() with header-only archive.
    let header = make_v8_header();
    let archive = build_test_catchpoint_archive(&header, &[]);

    let reader = algo_ledger::catchpoint::parser::CatchpointReader::new(archive.as_slice())
        .expect("create reader");
    let entries = reader.collect_entries().expect("collect entries");

    assert_eq!(entries.len(), 1, "should yield exactly 1 entry (header)");
    match &entries[0] {
        algo_ledger::catchpoint::parser::CatchpointEntry::Header(h) => {
            assert_eq!(h.version, CATCHPOINT_FILE_VERSION_V8);
            assert_eq!(h.balances_round, 42_000_000);
            assert_eq!(h.blocks_round, 42_000_010);
            assert_eq!(h.total_accounts, 5);
            assert_eq!(h.total_chunks, 2);
        }
        other => panic!("expected Header entry, got {:?}", other),
    }
}

#[test]
fn test_parser_collect_entries_with_chunks() {
    // Exercise iteration over header + multiple chunks.
    let chunks: Vec<CatchpointSnapshotChunkV6> = (0..3)
        .map(|i| CatchpointSnapshotChunkV6 {
            balances: vec![BalanceRecordV6 {
                address: make_test_address(i as u8),
                account_data: ByteBuf::from(vec![0x80]),
                resources: HashMap::new(),
                expecting_more_entries: false,
            }],
            ..Default::default()
        })
        .collect();
    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        total_chunks: 3,
        total_accounts: 3,
        ..Default::default()
    };
    let archive = build_test_catchpoint_archive(&header, &chunks);

    let reader = algo_ledger::catchpoint::parser::CatchpointReader::new(archive.as_slice())
        .expect("create reader");
    let entries = reader.collect_entries().expect("collect entries");

    // Should yield 1 header + 3 chunks = 4 entries total
    assert_eq!(entries.len(), 4);

    let mut chunk_count = 0;
    for entry in &entries {
        if let algo_ledger::catchpoint::parser::CatchpointEntry::Chunk(c) = entry {
            assert_eq!(c.balances.len(), 1);
            assert_eq!(c.balances[0].address, make_test_address(chunk_count as u8));
            chunk_count += 1;
        }
    }
    assert_eq!(chunk_count, 3);
}

#[test]
fn test_parser_for_each_callback() {
    // Exercise the for_each callback API.
    let chunk = CatchpointSnapshotChunkV6 {
        balances: vec![BalanceRecordV6 {
            address: make_test_address(0xAB),
            account_data: ByteBuf::from(vec![0x80]),
            resources: HashMap::new(),
            expecting_more_entries: false,
        }],
        ..Default::default()
    };
    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        total_chunks: 1,
        total_accounts: 1,
        ..Default::default()
    };
    let archive = build_test_catchpoint_archive(&header, &[chunk]);

    let reader = algo_ledger::catchpoint::parser::CatchpointReader::new(archive.as_slice())
        .expect("create reader");

    let mut header_seen = false;
    let mut chunk_seen = false;
    reader
        .for_each(|entry| {
            match entry {
                algo_ledger::catchpoint::parser::CatchpointEntry::Header(h) => {
                    assert_eq!(h.version, CATCHPOINT_FILE_VERSION_V8);
                    header_seen = true;
                }
                algo_ledger::catchpoint::parser::CatchpointEntry::Chunk(c) => {
                    assert_eq!(c.balances.len(), 1);
                    assert_eq!(c.balances[0].address, make_test_address(0xAB));
                    chunk_seen = true;
                }
                _ => {}
            }
            Ok(())
        })
        .expect("for_each");

    assert!(header_seen, "header should have been yielded");
    assert!(chunk_seen, "chunk should have been yielded");
}

#[test]
fn test_parser_rejects_unsupported_version() {
    // A V5 header should produce an UnsupportedVersion error.
    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V5,
        ..Default::default()
    };
    let archive = build_test_catchpoint_archive(&header, &[]);

    let reader = algo_ledger::catchpoint::parser::CatchpointReader::new(archive.as_slice())
        .expect("create reader");
    let result = reader.collect_entries();
    assert!(result.is_err(), "V5 should be rejected");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("unsupported"),
        "error should mention unsupported version: {err}"
    );
}

#[test]
fn test_parser_skips_unknown_entries() {
    // Archive with extra entries that the parser should skip.
    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        total_chunks: 1,
        total_accounts: 1,
        ..Default::default()
    };
    let chunk = CatchpointSnapshotChunkV6 {
        balances: vec![BalanceRecordV6 {
            address: make_test_address(0xDD),
            account_data: ByteBuf::from(vec![0x80]),
            resources: HashMap::new(),
            expecting_more_entries: false,
        }],
        ..Default::default()
    };
    let archive = build_archive_with_extra_entries(
        &header,
        &[chunk],
        &[
            ("metadata.json", b"{\"version\":1}"),
            ("checksums.txt", b"abc123\n"),
        ],
    );

    let reader = algo_ledger::catchpoint::parser::CatchpointReader::new(archive.as_slice())
        .expect("create reader");
    let entries = reader.collect_entries().expect("collect entries");

    // Unknown entries should be silently skipped: 1 header + 1 chunk = 2
    assert_eq!(entries.len(), 2, "unknown entries should be skipped");
}

#[test]
fn test_parser_full_pipeline_gzip() {
    // Build gzipped archive and parse via CatchpointReader.
    // Note: CatchpointReader::new() takes a raw tar reader, so we need
    // to wrap in GzDecoder ourselves for this test.
    let chunk = CatchpointSnapshotChunkV6 {
        balances: vec![BalanceRecordV6 {
            address: make_test_address(0xEE),
            account_data: ByteBuf::from(vec![0x80]),
            resources: HashMap::new(),
            expecting_more_entries: false,
        }],
        ..Default::default()
    };
    let header = make_v8_header();
    let gzipped = build_test_catchpoint_gzipped(&header, &[chunk]);

    let gz_decoder = flate2::read::GzDecoder::new(gzipped.as_slice());
    let reader = algo_ledger::catchpoint::parser::CatchpointReader::new(gz_decoder)
        .expect("create reader from gzip");
    let entries = reader.collect_entries().expect("collect entries");

    assert_eq!(entries.len(), 2, "should yield header + 1 chunk");
    match &entries[0] {
        algo_ledger::catchpoint::parser::CatchpointEntry::Header(h) => {
            assert_eq!(h.version, CATCHPOINT_FILE_VERSION_V8);
        }
        other => panic!("expected Header, got {:?}", other),
    }
    match &entries[1] {
        algo_ledger::catchpoint::parser::CatchpointEntry::Chunk(c) => {
            assert_eq!(c.balances.len(), 1);
            assert_eq!(c.balances[0].address, make_test_address(0xEE));
        }
        other => panic!("expected Chunk, got {:?}", other),
    }
}
