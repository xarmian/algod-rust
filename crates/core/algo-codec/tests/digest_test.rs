use algo_codec::{compute_block_digest, compute_txn_id, decode_block_response};
use algo_types::BlockResponse;

/// Load a Go-generated hex fixture and return raw bytes.
fn load_hex_fixture(name: &str) -> Vec<u8> {
    let hex_str = std::fs::read_to_string(format!(
        "{}/tests/fixtures/canonical/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"));
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

// ── Transaction ID tests ────────────────────────────────────────

macro_rules! txn_id_test {
    ($name:ident, $round:expr, $txn_idx:expr) => {
        #[test]
        fn $name() {
            let br = load_block($round);
            let tx = &br.block.payset[$txn_idx].txn;

            let rust_id = compute_txn_id(tx);

            let go_id_bytes = load_hex_fixture(&format!(
                "block_{}_txn_{}.txid.hex",
                $round, $txn_idx
            ));

            assert_eq!(
                rust_id.as_bytes().as_slice(),
                &go_id_bytes,
                "txn ID mismatch for block {} txn {}\n  Rust: {}\n  Go:   {}",
                $round,
                $txn_idx,
                hex::encode(rust_id.as_bytes()),
                hex::encode(&go_id_bytes),
            );
        }
    };
}

txn_id_test!(txn_id_block_1, 1, 0);
txn_id_test!(txn_id_block_2, 2, 0);
txn_id_test!(txn_id_block_3, 3, 0);
txn_id_test!(txn_id_block_4, 4, 0);
txn_id_test!(txn_id_block_5, 5, 0);

// ── Block digest tests ──────────────────────────────────────────

macro_rules! block_digest_test {
    ($name:ident, $round:expr) => {
        #[test]
        fn $name() {
            let br = load_block($round);

            let rust_digest = compute_block_digest(&br.block);

            let go_digest_bytes =
                load_hex_fixture(&format!("block_{}.digest.hex", $round));

            assert_eq!(
                rust_digest.as_bytes().as_slice(),
                &go_digest_bytes,
                "block digest mismatch for block {}\n  Rust: {}\n  Go:   {}",
                $round,
                hex::encode(rust_digest.as_bytes()),
                hex::encode(&go_digest_bytes),
            );
        }
    };
}

block_digest_test!(block_digest_block_1, 1);
block_digest_test!(block_digest_block_2, 2);
block_digest_test!(block_digest_block_3, 3);
block_digest_test!(block_digest_block_4, 4);
block_digest_test!(block_digest_block_5, 5);

// ── Corruption test ─────────────────────────────────────────────

#[test]
fn mutated_transaction_changes_txn_id() {
    let br = load_block(1);
    let original_tx = &br.block.payset[0].txn;
    let original_id = compute_txn_id(original_tx);

    // Mutate the amount
    let mut mutated_tx = original_tx.clone();
    mutated_tx.amount = original_tx.amount.wrapping_add(1);
    let mutated_id = compute_txn_id(&mutated_tx);

    assert_ne!(
        original_id, mutated_id,
        "txn ID should change when transaction is mutated"
    );
}

// ── Display format test ─────────────────────────────────────────

#[test]
fn txn_id_display_is_base32_nopad() {
    let br = load_block(1);
    let tx = &br.block.payset[0].txn;
    let id = compute_txn_id(tx);

    let display = id.to_string();
    // Base32 of 32 bytes = ceil(32*8/5) = 52 chars, no padding
    assert_eq!(display.len(), 52);
    // Should only contain A-Z and 2-7
    assert!(display.chars().all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)));
}
