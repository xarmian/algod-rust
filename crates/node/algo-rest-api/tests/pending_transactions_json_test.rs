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

//! Issue #2304: `GET /v2/transactions/pending` (and the by-address variant)
//! must render each pending transaction in go's JSON form of
//! `transactions.SignedTxn` -- standard base64 for every byte field (`note`,
//! `gh`, `sig`, ...), checksummed base32 for addresses -- not as integer
//! arrays. go: `daemon/algod/api/server/v2/handlers.go`
//! `GetPendingTransactions` encodes `PendingTransactionsResponse.TopTransactions`
//! (`[]transactions.SignedTxn`) with the codec JSON handle. The msgpack form
//! is unchanged.

use algo_rest_api::models::PendingTransactionsResponse;
use algo_types::{Address, SignedTransaction, Transaction, TxnType};
use base64::Engine;
use serde_bytes::ByteBuf;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn signed(note: &[u8]) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: TxnType::Pay,
            sender: Address([1u8; 32]),
            receiver: Address([2u8; 32]),
            fee: 1000,
            first_valid: algo_types::Round(10),
            last_valid: algo_types::Round(1010),
            genesis_hash: [3u8; 32],
            note: ByteBuf::from(note.to_vec()),
            ..Transaction::default()
        },
        sig: [7u8; 64],
        ..SignedTransaction::default()
    }
}

fn response() -> PendingTransactionsResponse {
    PendingTransactionsResponse {
        top_transactions: vec![signed(b"gossip-1"), signed(b"gossip-2")],
        total_transactions: 2,
    }
}

#[test]
fn json_renders_byte_fields_as_base64_and_addresses_as_strings() {
    let v = serde_json::to_value(response()).unwrap();
    assert_eq!(v["total-transactions"], 2);
    let top = v["top-transactions"].as_array().unwrap();
    assert_eq!(top.len(), 2);
    let first = &top[0];
    assert_eq!(first["sig"], b64(&[7u8; 64]));
    let txn = &first["txn"];
    assert_eq!(txn["note"], b64(b"gossip-1"));
    assert_eq!(txn["gh"], b64(&[3u8; 32]));
    assert_eq!(txn["snd"], Address([1u8; 32]).to_string());
    assert_eq!(txn["rcv"], Address([2u8; 32]).to_string());
    assert_eq!(txn["type"], "pay");
    assert_eq!(top[1]["txn"]["note"], b64(b"gossip-2"));
}

#[test]
fn json_has_no_integer_array_byte_fields() {
    let v = serde_json::to_value(response()).unwrap();
    let text = v.to_string();
    // an integer-array rendering would put `[` right after the key
    assert!(
        !text.contains("\"note\":["),
        "note as an integer array: {text}"
    );
    assert!(!text.contains("\"gh\":["), "gh as an integer array: {text}");
}

#[test]
fn json_reads_back_to_the_same_transactions() {
    let original = response();
    let text = serde_json::to_string(&original).unwrap();
    let back: PendingTransactionsResponse = serde_json::from_str(&text).unwrap();
    assert_eq!(back.total_transactions, 2);
    assert_eq!(back.top_transactions.len(), 2);
    assert_eq!(back.top_transactions[0].txn.note.as_ref(), b"gossip-1");
    assert_eq!(back.top_transactions[0].txn.sender, Address([1u8; 32]));
    assert_eq!(back.top_transactions[0].sig, [7u8; 64]);
}

#[test]
fn an_empty_pool_renders_an_empty_list() {
    let v = serde_json::to_value(PendingTransactionsResponse {
        top_transactions: vec![],
        total_transactions: 0,
    })
    .unwrap();
    assert_eq!(v["top-transactions"], serde_json::json!([]));
}

#[test]
fn msgpack_form_is_unchanged_and_round_trips() {
    let original = response();
    let bytes = algo_codec::to_vec_named_str_preserving(&original).unwrap();
    let back: PendingTransactionsResponse = rmp_serde::from_slice(&bytes).unwrap();
    assert_eq!(back.top_transactions.len(), 2);
    assert_eq!(back.top_transactions[1].txn.note.as_ref(), b"gossip-2");
    // byte fields stay msgpack bin, not strings
    let tree = rmpv::decode::read_value(&mut &bytes[..]).unwrap();
    let top = tree
        .as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k.as_str() == Some("top-transactions"))
        .unwrap()
        .1
        .as_array()
        .unwrap()
        .clone();
    let txn = top[0]
        .as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k.as_str() == Some("txn"))
        .unwrap()
        .1
        .as_map()
        .unwrap()
        .clone();
    let note = txn
        .iter()
        .find(|(k, _)| k.as_str() == Some("note"))
        .unwrap();
    assert!(
        note.1.is_bin(),
        "note must stay bin in msgpack: {:?}",
        note.1
    );
}
