// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use algo_codec::{
    canonical_encode_transaction, compute_block_digest, compute_txn_id, decode_block_response,
};
use algo_types::{Address, BlockResponse, Transaction, TxnType};
use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn canonical_dir() -> PathBuf {
    fixture_dir().join("canonical")
}

/// Load a Go-generated hex fixture and return raw bytes.
/// Returns None if the fixture file doesn't exist.
fn load_hex_fixture(name: &str) -> Option<Vec<u8>> {
    let path = canonical_dir().join(name);
    if !path.exists() {
        return None;
    }
    let hex_str = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"));
    Some(hex::decode(hex_str.trim()).unwrap_or_else(|e| panic!("invalid hex in {name}: {e}")))
}

/// Load a block fixture and decode it.
/// Returns None if the fixture file doesn't exist.
fn load_block(round: u64) -> Option<BlockResponse> {
    let path = fixture_dir().join(format!("block_{round}.msgpack"));
    if !path.exists() {
        return None;
    }
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    Some(decode_block_response(&bytes).unwrap_or_else(|e| panic!("decode block {round}: {e}")))
}

/// Skip a test if fixtures are not available, printing a message.
macro_rules! require_fixture {
    ($expr:expr, $msg:expr) => {
        match $expr {
            Some(v) => v,
            None => {
                eprintln!("SKIPPED: {} (run `make fixtures` to generate)", $msg);
                return;
            }
        }
    };
}

// ── Transaction ID tests ────────────────────────────────────────

macro_rules! txn_id_test {
    ($name:ident, $round:expr, $txn_idx:expr) => {
        #[test]
        fn $name() {
            let br = require_fixture!(
                load_block($round),
                concat!("block ", stringify!($round), " fixture missing")
            );
            let tx = &br.block.payset[$txn_idx].txn;

            let rust_id = compute_txn_id(tx);

            let go_id_bytes = require_fixture!(
                load_hex_fixture(&format!("block_{}_txn_{}.txid.hex", $round, $txn_idx)),
                concat!("block ", stringify!($round), " txid fixture missing")
            );

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
txn_id_test!(txn_id_block_6_appl_create, 6, 0);
txn_id_test!(txn_id_block_7_appl_call, 7, 0);
txn_id_test!(txn_id_block_8_keyreg, 8, 0);

// ── Block digest tests ──────────────────────────────────────────

macro_rules! block_digest_test {
    ($name:ident, $round:expr) => {
        #[test]
        fn $name() {
            let br = require_fixture!(
                load_block($round),
                concat!("block ", stringify!($round), " fixture missing")
            );

            let rust_digest = compute_block_digest(&br.block);

            let go_digest_bytes = require_fixture!(
                load_hex_fixture(&format!("block_{}.digest.hex", $round)),
                concat!("block ", stringify!($round), " digest fixture missing")
            );

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
block_digest_test!(block_digest_block_6, 6);
block_digest_test!(block_digest_block_7, 7);
block_digest_test!(block_digest_block_8, 8);

// ── Corruption test ─────────────────────────────────────────────

#[test]
fn mutated_transaction_changes_txn_id() {
    let br = require_fixture!(load_block(1), "block 1 fixture missing");
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

// ── Domain-separation / round-trip test (go: TestEncoding) ───────

/// Mirrors go-algorand's `TestEncoding`
/// (data/transactions/signedtxn_test.go): two zero-valued transactions of
/// different types but the *same* sender must still get distinct txn IDs
/// (type participates in ID domain separation, not just field values),
/// distinct canonical encodings, and each must round-trip through
/// encode/decode preserving its type and sender.
#[test]
fn zero_payment_and_zero_keyreg_have_distinct_ids_and_round_trip() {
    let mut sender_bytes = [0u8; 32];
    sender_bytes[0] = 0x01;
    let sender = Address(sender_bytes);

    let zero_payment = Transaction {
        txn_type: TxnType::Pay,
        sender,
        ..Transaction::default()
    };
    let zero_keyreg = Transaction {
        txn_type: TxnType::Keyreg,
        sender,
        ..Transaction::default()
    };

    let payment_id = compute_txn_id(&zero_payment);
    let keyreg_id = compute_txn_id(&zero_keyreg);
    assert_ne!(
        payment_id, keyreg_id,
        "payment and keyreg with identical header fields must have distinct \
         txn IDs -- type must participate in ID domain separation"
    );

    let payment_bytes = canonical_encode_transaction(&zero_payment);
    let keyreg_bytes = canonical_encode_transaction(&zero_keyreg);
    assert_ne!(
        payment_bytes, keyreg_bytes,
        "canonical encoding of a zero payment and a zero keyreg must differ"
    );

    let decoded_payment = Transaction::decode_from_reader(&mut payment_bytes.as_slice())
        .expect("decoding encoded zero payment must succeed");
    let decoded_keyreg = Transaction::decode_from_reader(&mut keyreg_bytes.as_slice())
        .expect("decoding encoded zero keyreg must succeed");

    assert_eq!(decoded_payment.txn_type, TxnType::Pay);
    assert_eq!(decoded_payment.sender, sender);
    assert_eq!(decoded_keyreg.txn_type, TxnType::Keyreg);
    assert_eq!(decoded_keyreg.sender, sender);

    assert_eq!(
        compute_txn_id(&decoded_payment),
        payment_id,
        "round-tripped payment must hash back to the same txn ID"
    );
    assert_eq!(
        compute_txn_id(&decoded_keyreg),
        keyreg_id,
        "round-tripped keyreg must hash back to the same txn ID"
    );
}

// ── Display format test ─────────────────────────────────────────

#[test]
fn txn_id_display_is_base32_nopad() {
    let br = require_fixture!(load_block(1), "block 1 fixture missing");
    let tx = &br.block.payset[0].txn;
    let id = compute_txn_id(tx);

    let display = id.to_string();
    // Base32 of 32 bytes = ceil(32*8/5) = 52 chars, no padding
    assert_eq!(display.len(), 52);
    // Should only contain A-Z and 2-7
    assert!(display
        .chars()
        .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)));
}
