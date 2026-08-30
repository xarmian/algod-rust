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

//! Byte-level go-algorand oracle parity for `algo_avm::itxn::compute_inner_txn_id`
//! (issue #760, follow-up to #747/PR #759).
//!
//! `compute_inner_txn_id` was verified only by direct comparison against
//! go-algorand's `Transaction.InnerID` source
//! (`data/transactions/transaction.go:297`), never by running go-algorand's
//! own code and diffing real output. `tools/rewards-innertxid-oracle`
//! builds a handful of representative transactions (a plain payment, a
//! payment exercising note/close-remainder-to, an asset transfer, and an
//! application call with argument arrays and foreign-app/-asset
//! references), computes `InnerID(parent, index)` for each against a couple
//! of (parent, index) pairs using real go-algorand, and records the digests
//! in `../algo-ledger/tests/fixtures/rewards_innertxid/oracle.json`'s
//! `inner_id_vectors`. This test rebuilds the identical transactions in
//! Rust and asserts `compute_inner_txn_id` reproduces every recorded digest
//! byte-for-byte.
//!
//! The fixture is shared with (and owned by) `algo-ledger`'s
//! `rewards_state_oracle.rs` -- both are captured by the same Go tool in one
//! run, so this test reads it via a relative path across the two crates'
//! `tests/` directories rather than duplicating the file.
//!
//! Regeneration: see `docs/DEV_WORKFLOW.md` -> "Rewards/InnerTxnID Oracle
//! Regeneration".

use std::path::PathBuf;

use algo_avm::itxn::compute_inner_txn_id;
use algo_types::{Address, Digest, Transaction, TxnType};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct InnerIdVector {
    txn_label: String,
    parent_hex: String,
    index: u64,
    inner_id_hex: String,
}

#[derive(Debug, Deserialize)]
struct Corpus {
    #[allow(dead_code)]
    source: String,
    #[allow(dead_code)]
    go_algorand_pin: String,
    #[allow(dead_code)]
    rewards_vectors: Vec<serde_json::Value>,
    inner_id_vectors: Vec<InnerIdVector>,
}

fn load_corpus() -> Corpus {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../algo-ledger/tests/fixtures/rewards_innertxid/oracle.json");
    let bytes = std::fs::read(&p).unwrap_or_else(|e| {
        panic!(
            "cannot read rewards/inner-txn-id oracle fixture {p:?}: {e}. \
             Run `cd tools/rewards-innertxid-oracle && go run .` to regenerate."
        )
    });
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("malformed oracle fixture {p:?}: {e}"))
}

fn addr(b: u8) -> Address {
    Address([b; 32])
}

/// Rebuilds the exact same fixed transactions
/// `tools/rewards-innertxid-oracle/main.go`'s `innerIDTransactions` sends
/// through go-algorand's real `Transaction.InnerID`, by field-for-field
/// mirroring (see that Go source for the authoritative field values).
fn fixed_transaction(label: &str) -> Transaction {
    let base = || Transaction {
        sender: addr(0x01),
        fee: 1000,
        first_valid: algo_types::Round(100),
        last_valid: algo_types::Round(1100),
        genesis_id: "oracle-test".to_string(),
        genesis_hash: [0x99; 32],
        ..Default::default()
    };

    match label {
        "pay_simple" => Transaction {
            txn_type: TxnType::Pay,
            receiver: addr(0x02),
            amount: 5_000_000,
            ..base()
        },
        "pay_with_extras" => Transaction {
            txn_type: TxnType::Pay,
            receiver: addr(0x02),
            amount: 5_000_000,
            close_remainder_to: addr(0x03),
            note: b"live_rewards_innertxid_oracle".to_vec().into(),
            ..base()
        },
        "axfer" => Transaction {
            txn_type: TxnType::Axfer,
            xaid: 999_999_999,
            asset_amount: 42,
            asset_receiver: Some(addr(0x02)),
            ..base()
        },
        "appl_call" => Transaction {
            txn_type: TxnType::Appl,
            application_id: 123_456_789,
            on_completion: 0, // NoOpOC
            app_arguments: Some(vec![
                Some(serde_bytes::ByteBuf::from(b"hello".to_vec())),
                Some(serde_bytes::ByteBuf::from(vec![0x01, 0x02, 0x03])),
            ]),
            foreign_apps: Some(vec![111, 222]),
            foreign_assets: Some(vec![333]),
            ..base()
        },
        other => panic!("unknown fixed-transaction label {other:?}"),
    }
}

#[test]
fn corpus_has_inner_id_vectors() {
    let corpus = load_corpus();
    assert!(
        !corpus.inner_id_vectors.is_empty(),
        "oracle fixture has no inner_id_vectors -- still the placeholder; \
         run `cd tools/rewards-innertxid-oracle && go run .` against a real \
         go-algorand v5.0.0-stable checkout and commit the result"
    );
    // 4 transaction shapes x 2 parents x 3 indices, per the Go tool.
    assert_eq!(corpus.inner_id_vectors.len(), 4 * 2 * 3);
}

/// Byte-for-byte parity: for every captured (txn shape, parent, index),
/// Rust's `compute_inner_txn_id` must produce go-algorand's real recorded
/// `InnerID` digest exactly.
#[test]
fn rust_matches_go_on_every_captured_vector() {
    let corpus = load_corpus();
    assert!(!corpus.inner_id_vectors.is_empty(), "fixture is empty");

    for v in &corpus.inner_id_vectors {
        let txn = fixed_transaction(&v.txn_label);
        let parent_bytes = hex::decode(&v.parent_hex)
            .unwrap_or_else(|e| panic!("malformed parent_hex {:?}: {e}", v.parent_hex));
        assert_eq!(parent_bytes.len(), 32, "parent_hex must decode to 32 bytes");
        let mut parent_arr = [0u8; 32];
        parent_arr.copy_from_slice(&parent_bytes);
        let parent = Digest(parent_arr);

        let got = compute_inner_txn_id(&parent, v.index as usize, &txn);
        let got_hex = hex::encode(got.0);

        assert_eq!(
            got_hex, v.inner_id_hex,
            "compute_inner_txn_id({}, parent={}, index={}) divergence: Rust={}, Go={}",
            v.txn_label, v.parent_hex, v.index, got_hex, v.inner_id_hex
        );
    }
}
