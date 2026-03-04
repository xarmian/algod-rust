use algo_codec::{
    canonical_encode_signed_transaction, canonical_encode_transaction, decode_block_response,
};
use algo_types::BlockResponse;

/// Load a Go-generated canonical hex fixture and return raw bytes.
fn load_canonical_hex(name: &str) -> Vec<u8> {
    let hex_str = std::fs::read_to_string(format!(
        "{}/tests/fixtures/canonical/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("failed to read canonical fixture {name}: {e}"));
    hex::decode(hex_str.trim()).unwrap_or_else(|e| panic!("invalid hex in {name}: {e}"))
}

/// Load a block fixture and decode it.
fn load_block(round: u64) -> BlockResponse {
    let path = format!(
        "{}/tests/fixtures/block_{round}.msgpack",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    decode_block_response(&bytes).unwrap_or_else(|e| panic!("decode block {round}: {e}"))
}

// ── Byte-level comparison against Go reference data ─────────────

macro_rules! canonical_txn_test {
    ($name:ident, $round:expr, $txn_idx:expr) => {
        #[test]
        fn $name() {
            let br = load_block($round);
            let stxn = &br.block.payset[$txn_idx];
            let tx = &stxn.txn;

            // Canonical encode in Rust
            let rust_bytes = canonical_encode_transaction(tx);

            // Load Go reference bytes
            let go_bytes =
                load_canonical_hex(&format!("block_{}_txn_{}.canonical.hex", $round, $txn_idx));

            // Byte-level comparison
            if rust_bytes != go_bytes {
                // Decode both for debugging
                let rust_val = rmpv::decode::read_value(&mut &rust_bytes[..]).unwrap();
                let go_val = rmpv::decode::read_value(&mut &go_bytes[..]).unwrap();

                panic!(
                    "Canonical txn encoding mismatch for block {} txn {}!\n\
                     Rust ({} bytes): {}\n\
                     Go   ({} bytes): {}\n\
                     Rust decoded: {:?}\n\
                     Go   decoded: {:?}",
                    $round,
                    $txn_idx,
                    rust_bytes.len(),
                    hex::encode(&rust_bytes),
                    go_bytes.len(),
                    hex::encode(&go_bytes),
                    rust_val,
                    go_val,
                );
            }
        }
    };
}

canonical_txn_test!(canonical_txn_block_1, 1, 0);
canonical_txn_test!(canonical_txn_block_2, 2, 0);
canonical_txn_test!(canonical_txn_block_3, 3, 0);
canonical_txn_test!(canonical_txn_block_4, 4, 0);
canonical_txn_test!(canonical_txn_block_5, 5, 0);

// ── SignedTransaction canonical encoding comparison ─────────────

macro_rules! canonical_stxn_test {
    ($name:ident, $round:expr, $txn_idx:expr) => {
        #[test]
        fn $name() {
            let br = load_block($round);
            let stxn = &br.block.payset[$txn_idx];

            let rust_bytes = canonical_encode_signed_transaction(stxn);
            let go_bytes =
                load_canonical_hex(&format!("block_{}_stxn_{}.canonical.hex", $round, $txn_idx));

            if rust_bytes != go_bytes {
                let rust_val = rmpv::decode::read_value(&mut &rust_bytes[..]).unwrap();
                let go_val = rmpv::decode::read_value(&mut &go_bytes[..]).unwrap();

                panic!(
                    "Canonical stxn encoding mismatch for block {} stxn {}!\n\
                     Rust ({} bytes): {}\n\
                     Go   ({} bytes): {}\n\
                     Rust decoded: {:?}\n\
                     Go   decoded: {:?}",
                    $round,
                    $txn_idx,
                    rust_bytes.len(),
                    hex::encode(&rust_bytes),
                    go_bytes.len(),
                    hex::encode(&go_bytes),
                    rust_val,
                    go_val,
                );
            }
        }
    };
}

canonical_stxn_test!(canonical_stxn_block_1, 1, 0);
canonical_stxn_test!(canonical_stxn_block_2, 2, 0);
canonical_stxn_test!(canonical_stxn_block_3, 3, 0);
canonical_stxn_test!(canonical_stxn_block_4, 4, 0);
canonical_stxn_test!(canonical_stxn_block_5, 5, 0);

// ── Property-based tests ────────────────────────────────────────

#[test]
fn canonical_keys_are_sorted_in_all_fixture_txns() {
    for round in 1..=5 {
        let br = load_block(round);
        for (i, stxn) in br.block.payset.iter().enumerate() {
            let encoded = canonical_encode_transaction(&stxn.txn);
            let val = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
            if let rmpv::Value::Map(pairs) = val {
                let keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str().unwrap()).collect();
                let mut sorted = keys.clone();
                sorted.sort();
                assert_eq!(keys, sorted, "keys not sorted in block {round} txn {i}");
            }
        }
    }
}

#[test]
fn canonical_no_zero_fields_in_fixture_txns() {
    for round in 1..=5 {
        let br = load_block(round);
        for (i, stxn) in br.block.payset.iter().enumerate() {
            let encoded = canonical_encode_transaction(&stxn.txn);
            let val = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
            if let rmpv::Value::Map(pairs) = val {
                for (k, v) in &pairs {
                    let key = k.as_str().unwrap();
                    // No value should be zero/empty (omitempty should have excluded it)
                    match v {
                        rmpv::Value::Integer(n) => {
                            assert_ne!(
                                n.as_u64(),
                                Some(0),
                                "block {round} txn {i}: key '{key}' has zero integer"
                            );
                        }
                        rmpv::Value::String(s) => {
                            assert!(
                                !s.as_str().map_or(true, |s| s.is_empty()),
                                "block {round} txn {i}: key '{key}' has empty string"
                            );
                        }
                        rmpv::Value::Binary(b) => {
                            assert!(
                                !b.is_empty(),
                                "block {round} txn {i}: key '{key}' has empty binary"
                            );
                        }
                        rmpv::Value::Boolean(false) => {
                            panic!("block {round} txn {i}: key '{key}' has false boolean");
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

#[test]
fn canonical_integers_use_compact_encoding() {
    // Verify that our encoder uses the most compact msgpack integer format.
    // A payment with fee=1000 should use uint16 (3 bytes: 0xCD + 2 bytes),
    // not uint32 or uint64.
    let br = load_block(1);
    let tx = &br.block.payset[0].txn;
    let encoded = canonical_encode_transaction(tx);

    // Find the "fee" key and check the value encoding
    // fee=1000 should be: 0xCD 0x03 0xE8 (uint16)
    let fee_pattern: &[u8] = &[0xA3, b'f', b'e', b'e', 0xCD, 0x03, 0xE8];
    assert!(
        contains_subsequence(&encoded, fee_pattern),
        "fee=1000 should be encoded as uint16 (0xCD 0x03 0xE8), got: {}",
        hex::encode(&encoded)
    );
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
