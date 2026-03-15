//! Conformance tests verifying that the fast (rmp-direct) decoders produce
//! identical output to the existing serde-based decoders.
//!
//! These tests cover:
//! 1. Serde vs Fast equivalence for all fixtures
//! 2. Round-trip: serde encode -> fast decode produces identical output
//! 3. Edge cases: empty blocks, unknown fields, transactions with extra fields

use algo_codec::{
    decode_block, decode_block_fast, decode_block_response, decode_block_response_fast,
    encode_block,
};
use algo_types::BlockResponse;

// ── Fixture data ──────────────────────────────────────────────────

static FIXTURES: &[(&str, &[u8], u64)] = &[
    ("block_1", include_bytes!("fixtures/block_1.msgpack"), 1),
    ("block_2", include_bytes!("fixtures/block_2.msgpack"), 2),
    ("block_3", include_bytes!("fixtures/block_3.msgpack"), 3),
    ("block_4", include_bytes!("fixtures/block_4.msgpack"), 4),
    ("block_5", include_bytes!("fixtures/block_5.msgpack"), 5),
    ("block_6", include_bytes!("fixtures/block_6.msgpack"), 6),
    ("block_7", include_bytes!("fixtures/block_7.msgpack"), 7),
    ("block_8", include_bytes!("fixtures/block_8.msgpack"), 8),
    ("block_9", include_bytes!("fixtures/block_9.msgpack"), 9),
];

// ════════════════════════════════════════════════════════════════════
// 1. Serde vs Fast equivalence for all fixtures
// ════════════════════════════════════════════════════════════════════

/// Verify that decode_block_response_fast matches decode_block_response
/// for every fixture file.
#[test]
fn fast_decode_matches_serde_all_fixtures_block_response() {
    for (name, bytes, _round) in FIXTURES {
        let serde_result = decode_block_response(bytes)
            .unwrap_or_else(|e| panic!("serde decode failed for {name}: {e}"));
        let fast_result = decode_block_response_fast(bytes)
            .unwrap_or_else(|e| panic!("fast decode failed for {name}: {e}"));
        assert_eq!(
            serde_result, fast_result,
            "block response mismatch on {name}"
        );
    }
}

/// Individually test each fixture for block-response equivalence (for
/// easier failure diagnosis).
macro_rules! block_response_equiv_test {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            let bytes = include_bytes!(concat!("fixtures/", $file));
            let serde_result = decode_block_response(bytes).expect("serde decode failed");
            let fast_result = decode_block_response_fast(bytes).expect("fast decode failed");
            assert_eq!(serde_result, fast_result);
        }
    };
}

block_response_equiv_test!(block_response_equiv_1, "block_1.msgpack");
block_response_equiv_test!(block_response_equiv_2, "block_2.msgpack");
block_response_equiv_test!(block_response_equiv_3, "block_3.msgpack");
block_response_equiv_test!(block_response_equiv_4, "block_4.msgpack");
block_response_equiv_test!(block_response_equiv_5, "block_5.msgpack");
block_response_equiv_test!(block_response_equiv_6, "block_6.msgpack");
block_response_equiv_test!(block_response_equiv_7, "block_7.msgpack");
block_response_equiv_test!(block_response_equiv_8, "block_8.msgpack");
block_response_equiv_test!(block_response_equiv_9, "block_9.msgpack");

/// Verify that decode_block_fast matches decode_block when given the
/// inner block bytes (extracted from the block response via serde
/// encode of the block portion).
#[test]
fn fast_decode_matches_serde_all_fixtures_inner_block() {
    for (name, bytes, _round) in FIXTURES {
        // Decode the response first, then re-encode just the block
        let br: BlockResponse = decode_block_response(bytes)
            .unwrap_or_else(|e| panic!("decode_block_response failed for {name}: {e}"));
        let block_bytes = encode_block(&br.block)
            .unwrap_or_else(|e| panic!("encode_block failed for {name}: {e}"));

        let serde_result = decode_block(&block_bytes)
            .unwrap_or_else(|e| panic!("serde decode_block failed for {name}: {e}"));
        let fast_result = decode_block_fast(&block_bytes)
            .unwrap_or_else(|e| panic!("fast decode_block failed for {name}: {e}"));

        assert_eq!(serde_result, fast_result, "inner block mismatch on {name}");
    }
}

// ════════════════════════════════════════════════════════════════════
// 2. Round-trip: serde encode -> fast decode
// ════════════════════════════════════════════════════════════════════

/// For each fixture: decode with serde, re-encode with serde, decode
/// with fast -- result should equal the original serde decode.
#[test]
fn roundtrip_serde_encode_fast_decode_block_response() {
    for (name, bytes, _round) in FIXTURES {
        // Step 1: decode with serde
        let serde_result = decode_block_response(bytes)
            .unwrap_or_else(|e| panic!("initial serde decode failed for {name}: {e}"));

        // Step 2: re-encode the block with serde
        let re_encoded = encode_block(&serde_result.block)
            .unwrap_or_else(|e| panic!("re-encode failed for {name}: {e}"));

        // Step 3: decode with fast
        let fast_result = decode_block_fast(&re_encoded)
            .unwrap_or_else(|e| panic!("fast decode of re-encoded failed for {name}: {e}"));

        // Compare the block portion
        assert_eq!(
            serde_result.block, fast_result,
            "roundtrip mismatch on {name}"
        );
    }
}

/// For each fixture: decode with serde, re-encode, decode with serde
/// again, then decode the re-encoded with fast -- both should match.
#[test]
fn roundtrip_double_serde_fast_decode() {
    for (name, bytes, _round) in FIXTURES {
        let original = decode_block_response(bytes)
            .unwrap_or_else(|e| panic!("decode failed for {name}: {e}"));

        let re_encoded = encode_block(&original.block)
            .unwrap_or_else(|e| panic!("encode failed for {name}: {e}"));

        let serde_again = decode_block(&re_encoded)
            .unwrap_or_else(|e| panic!("serde re-decode failed for {name}: {e}"));
        let fast_again = decode_block_fast(&re_encoded)
            .unwrap_or_else(|e| panic!("fast re-decode failed for {name}: {e}"));

        assert_eq!(
            serde_again, fast_again,
            "double roundtrip mismatch on {name}"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
// 3. Edge cases
// ════════════════════════════════════════════════════════════════════

/// An empty block (0-element map) is missing required fields. Both
/// decoders should behave consistently -- if serde accepts it, fast
/// should too (and produce the same result); if serde rejects it,
/// fast should also reject it.
#[test]
fn fast_decode_empty_map_block_consistent_behavior() {
    // msgpack fixmap with 0 entries: 0x80
    let empty_map = [0x80u8];
    let serde_result = decode_block(&empty_map);
    let fast_result = decode_block_fast(&empty_map);

    match (serde_result, fast_result) {
        (Ok(s), Ok(f)) => {
            assert_eq!(s, f, "empty map: serde vs fast should be identical");
        }
        (Err(_), Err(_)) => {
            // Both reject -- consistent behavior, test passes.
        }
        (Ok(_), Err(e)) => {
            panic!(
                "serde accepts empty map but fast rejects it: {e} \
                 -- fast decoder is stricter than serde"
            );
        }
        (Err(e), Ok(_)) => {
            panic!(
                "fast accepts empty map but serde rejects it: {e} \
                 -- fast decoder is more lenient than serde"
            );
        }
    }
}

/// A minimal block with only the required "rnd" field should decode
/// identically by both decoders.
#[test]
fn fast_decode_minimal_block_with_rnd() {
    // Build: {"rnd": 0}
    let mut buf = Vec::new();
    rmp::encode::write_map_len(&mut buf, 1).unwrap();
    rmp::encode::write_str(&mut buf, "rnd").unwrap();
    rmp::encode::write_uint(&mut buf, 0).unwrap();

    let serde_result = decode_block(&buf);
    let fast_result = decode_block_fast(&buf);

    assert!(serde_result.is_ok(), "serde: {:?}", serde_result.err());
    assert!(fast_result.is_ok(), "fast: {:?}", fast_result.err());
    assert_eq!(
        serde_result.unwrap(),
        fast_result.unwrap(),
        "minimal block with rnd=0: serde vs fast mismatch"
    );
}

/// A block with unknown fields should have those fields skipped by the
/// fast decoder, producing the same result as serde (which uses
/// `deny_unknown_fields` is NOT set, so it also skips them).
#[test]
fn fast_decode_block_with_unknown_fields() {
    // Build a msgpack map with one known field ("rnd" = 42) and one
    // unknown field ("zzz_unknown" = 99).
    let mut buf = Vec::new();
    // Write map header with 2 entries
    rmp::encode::write_map_len(&mut buf, 2).unwrap();
    // Entry 1: "rnd" => 42
    rmp::encode::write_str(&mut buf, "rnd").unwrap();
    rmp::encode::write_uint(&mut buf, 42).unwrap();
    // Entry 2: "zzz_unknown" => 99
    rmp::encode::write_str(&mut buf, "zzz_unknown").unwrap();
    rmp::encode::write_uint(&mut buf, 99).unwrap();

    let serde_result = decode_block(&buf);
    let fast_result = decode_block_fast(&buf);

    assert!(
        serde_result.is_ok(),
        "serde should handle unknown fields: {:?}",
        serde_result.err()
    );
    assert!(
        fast_result.is_ok(),
        "fast should handle unknown fields: {:?}",
        fast_result.err()
    );

    let serde_block = serde_result.unwrap();
    let fast_block = fast_result.unwrap();

    assert_eq!(serde_block.round.0, 42);
    assert_eq!(fast_block.round.0, 42);
    assert_eq!(
        serde_block, fast_block,
        "block with unknown fields: serde vs fast mismatch"
    );
}

/// A BlockResponse with unknown top-level fields should be handled.
#[test]
fn fast_decode_block_response_with_unknown_fields() {
    // Build: {"block": {rnd: 7}, "extra_field": true}
    let mut buf = Vec::new();
    rmp::encode::write_map_len(&mut buf, 2).unwrap();

    // "block" => {rnd: 7}
    rmp::encode::write_str(&mut buf, "block").unwrap();
    {
        rmp::encode::write_map_len(&mut buf, 1).unwrap();
        rmp::encode::write_str(&mut buf, "rnd").unwrap();
        rmp::encode::write_uint(&mut buf, 7).unwrap();
    }

    // "extra_field" => true
    rmp::encode::write_str(&mut buf, "extra_field").unwrap();
    rmp::encode::write_bool(&mut buf, true).unwrap();

    let serde_result = decode_block_response(&buf);
    let fast_result = decode_block_response_fast(&buf);

    assert!(
        serde_result.is_ok(),
        "serde should handle unknown response fields: {:?}",
        serde_result.err()
    );
    assert!(
        fast_result.is_ok(),
        "fast should handle unknown response fields: {:?}",
        fast_result.err()
    );

    let serde_br = serde_result.unwrap();
    let fast_br = fast_result.unwrap();

    assert_eq!(serde_br.block.round.0, 7);
    assert_eq!(fast_br.block.round.0, 7);
    assert_eq!(
        serde_br, fast_br,
        "block response with unknown fields: serde vs fast mismatch"
    );
}

/// Verify that field-level data is identical between serde and fast
/// decoders by spot-checking specific fields across all transaction types.
#[test]
fn fast_decode_field_level_equivalence() {
    for (name, bytes, round) in FIXTURES {
        let serde_br = decode_block_response(bytes)
            .unwrap_or_else(|e| panic!("serde decode failed for {name}: {e}"));
        let fast_br = decode_block_response_fast(bytes)
            .unwrap_or_else(|e| panic!("fast decode failed for {name}: {e}"));

        // Header fields
        assert_eq!(serde_br.block.round.0, *round, "{name}: unexpected round");
        assert_eq!(
            serde_br.block.round, fast_br.block.round,
            "{name}: round mismatch"
        );
        assert_eq!(
            serde_br.block.genesis_id, fast_br.block.genesis_id,
            "{name}: genesis_id mismatch"
        );
        assert_eq!(
            serde_br.block.genesis_hash, fast_br.block.genesis_hash,
            "{name}: genesis_hash mismatch"
        );
        assert_eq!(
            serde_br.block.timestamp, fast_br.block.timestamp,
            "{name}: timestamp mismatch"
        );
        assert_eq!(
            serde_br.block.current_protocol, fast_br.block.current_protocol,
            "{name}: current_protocol mismatch"
        );
        assert_eq!(
            serde_br.block.fee_sink, fast_br.block.fee_sink,
            "{name}: fee_sink mismatch"
        );
        assert_eq!(
            serde_br.block.rewards_pool, fast_br.block.rewards_pool,
            "{name}: rewards_pool mismatch"
        );
        assert_eq!(
            serde_br.block.branch, fast_br.block.branch,
            "{name}: branch mismatch"
        );
        assert_eq!(
            serde_br.block.seed, fast_br.block.seed,
            "{name}: seed mismatch"
        );

        // Transaction count and per-txn fields
        assert_eq!(
            serde_br.block.payset.len(),
            fast_br.block.payset.len(),
            "{name}: transaction count mismatch"
        );

        for (i, (s_txn, f_txn)) in serde_br
            .block
            .payset
            .iter()
            .zip(fast_br.block.payset.iter())
            .enumerate()
        {
            assert_eq!(
                s_txn.txn.txn_type, f_txn.txn.txn_type,
                "{name} txn[{i}]: type mismatch"
            );
            assert_eq!(
                s_txn.txn.sender, f_txn.txn.sender,
                "{name} txn[{i}]: sender mismatch"
            );
            assert_eq!(
                s_txn.txn.fee, f_txn.txn.fee,
                "{name} txn[{i}]: fee mismatch"
            );
            assert_eq!(
                s_txn.txn.first_valid, f_txn.txn.first_valid,
                "{name} txn[{i}]: first_valid mismatch"
            );
            assert_eq!(
                s_txn.txn.last_valid, f_txn.txn.last_valid,
                "{name} txn[{i}]: last_valid mismatch"
            );
            assert_eq!(
                s_txn.txn.amount, f_txn.txn.amount,
                "{name} txn[{i}]: amount mismatch"
            );
            assert_eq!(
                s_txn.txn.receiver, f_txn.txn.receiver,
                "{name} txn[{i}]: receiver mismatch"
            );
            assert_eq!(s_txn.sig, f_txn.sig, "{name} txn[{i}]: sig mismatch");
            // Full equality (catches any field we might miss above)
            assert_eq!(
                s_txn, f_txn,
                "{name} txn[{i}]: full SignedTransaction mismatch"
            );
        }

        // Certificate field (opaque rmpv::Value)
        assert_eq!(serde_br.cert, fast_br.cert, "{name}: cert mismatch");
    }
}

/// Verify both decoders reject truncated input gracefully.
#[test]
fn both_decoders_reject_truncated_input() {
    for (name, bytes, _round) in FIXTURES {
        // Truncate to half the original size
        let truncated = &bytes[..bytes.len() / 2];

        let serde_result = decode_block_response(truncated);
        let fast_result = decode_block_response_fast(truncated);

        assert!(
            serde_result.is_err(),
            "{name}: serde should reject truncated input"
        );
        assert!(
            fast_result.is_err(),
            "{name}: fast should reject truncated input"
        );
    }
}

/// Verify both decoders reject completely invalid input.
#[test]
fn both_decoders_reject_garbage_input() {
    let garbage = b"this is not msgpack at all!";

    let serde_result = decode_block_response(garbage);
    let fast_result = decode_block_response_fast(garbage);

    assert!(serde_result.is_err(), "serde should reject garbage");
    assert!(fast_result.is_err(), "fast should reject garbage");
}

/// Verify that a block with an empty transaction array is handled
/// identically by both decoders.
#[test]
fn fast_decode_block_with_empty_txns() {
    // Build: {"rnd": 1, "txns": []}
    let mut buf = Vec::new();
    rmp::encode::write_map_len(&mut buf, 2).unwrap();
    rmp::encode::write_str(&mut buf, "rnd").unwrap();
    rmp::encode::write_uint(&mut buf, 1).unwrap();
    rmp::encode::write_str(&mut buf, "txns").unwrap();
    rmp::encode::write_array_len(&mut buf, 0).unwrap();

    let serde_result = decode_block(&buf);
    let fast_result = decode_block_fast(&buf);

    assert!(serde_result.is_ok(), "serde: {:?}", serde_result.err());
    assert!(fast_result.is_ok(), "fast: {:?}", fast_result.err());

    let serde_block = serde_result.unwrap();
    let fast_block = fast_result.unwrap();

    assert!(serde_block.payset.is_empty());
    assert!(fast_block.payset.is_empty());
    assert_eq!(serde_block, fast_block);
}

/// Verify that a block response with nested unknown fields
/// (map-valued unknown) is handled identically by both decoders.
#[test]
fn fast_decode_block_with_nested_unknown_field() {
    // Build: {"rnd": 5, "zzz_nested": {"a": 1, "b": [1,2,3]}}
    let mut buf = Vec::new();
    rmp::encode::write_map_len(&mut buf, 2).unwrap();
    // "rnd" => 5
    rmp::encode::write_str(&mut buf, "rnd").unwrap();
    rmp::encode::write_uint(&mut buf, 5).unwrap();
    // "zzz_nested" => {"a": 1, "b": [1, 2, 3]}
    rmp::encode::write_str(&mut buf, "zzz_nested").unwrap();
    rmp::encode::write_map_len(&mut buf, 2).unwrap();
    rmp::encode::write_str(&mut buf, "a").unwrap();
    rmp::encode::write_uint(&mut buf, 1).unwrap();
    rmp::encode::write_str(&mut buf, "b").unwrap();
    rmp::encode::write_array_len(&mut buf, 3).unwrap();
    rmp::encode::write_uint(&mut buf, 1).unwrap();
    rmp::encode::write_uint(&mut buf, 2).unwrap();
    rmp::encode::write_uint(&mut buf, 3).unwrap();

    let serde_result = decode_block(&buf);
    let fast_result = decode_block_fast(&buf);

    assert!(serde_result.is_ok(), "serde: {:?}", serde_result.err());
    assert!(fast_result.is_ok(), "fast: {:?}", fast_result.err());

    assert_eq!(
        serde_result.unwrap(),
        fast_result.unwrap(),
        "nested unknown field: serde vs fast mismatch"
    );
}

/// Verify that multiple unknown fields of various types are all
/// properly skipped by the fast decoder.
#[test]
fn fast_decode_block_skips_many_unknown_types() {
    // Build a block map with known "rnd" plus unknowns of different types:
    // string, binary, nil, bool, float, array, map
    let mut buf = Vec::new();
    rmp::encode::write_map_len(&mut buf, 8).unwrap();

    // Known field
    rmp::encode::write_str(&mut buf, "rnd").unwrap();
    rmp::encode::write_uint(&mut buf, 100).unwrap();

    // Unknown string
    rmp::encode::write_str(&mut buf, "unk_str").unwrap();
    rmp::encode::write_str(&mut buf, "hello").unwrap();

    // Unknown binary
    rmp::encode::write_str(&mut buf, "unk_bin").unwrap();
    rmp::encode::write_bin(&mut buf, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();

    // Unknown nil
    rmp::encode::write_str(&mut buf, "unk_nil").unwrap();
    rmp::encode::write_nil(&mut buf).unwrap();

    // Unknown bool
    rmp::encode::write_str(&mut buf, "unk_bool").unwrap();
    rmp::encode::write_bool(&mut buf, true).unwrap();

    // Unknown float
    rmp::encode::write_str(&mut buf, "unk_f64").unwrap();
    rmp::encode::write_f64(&mut buf, 3.125).unwrap();

    // Unknown array
    rmp::encode::write_str(&mut buf, "unk_arr").unwrap();
    rmp::encode::write_array_len(&mut buf, 2).unwrap();
    rmp::encode::write_uint(&mut buf, 10).unwrap();
    rmp::encode::write_uint(&mut buf, 20).unwrap();

    // Unknown map
    rmp::encode::write_str(&mut buf, "unk_map").unwrap();
    rmp::encode::write_map_len(&mut buf, 1).unwrap();
    rmp::encode::write_str(&mut buf, "k").unwrap();
    rmp::encode::write_str(&mut buf, "v").unwrap();

    let serde_result = decode_block(&buf);
    let fast_result = decode_block_fast(&buf);

    assert!(serde_result.is_ok(), "serde: {:?}", serde_result.err());
    assert!(fast_result.is_ok(), "fast: {:?}", fast_result.err());

    let serde_block = serde_result.unwrap();
    let fast_block = fast_result.unwrap();

    assert_eq!(serde_block.round.0, 100);
    assert_eq!(fast_block.round.0, 100);
    assert_eq!(serde_block, fast_block, "many unknown types: mismatch");
}

/// Verify both decoders handle an empty byte slice by returning an error.
#[test]
fn both_decoders_reject_empty_input() {
    let empty: &[u8] = &[];

    let serde_result = decode_block(empty);
    let fast_result = decode_block_fast(empty);

    assert!(serde_result.is_err(), "serde should reject empty input");
    assert!(fast_result.is_err(), "fast should reject empty input");

    let serde_result = decode_block_response(empty);
    let fast_result = decode_block_response_fast(empty);

    assert!(
        serde_result.is_err(),
        "serde should reject empty response input"
    );
    assert!(
        fast_result.is_err(),
        "fast should reject empty response input"
    );
}
