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

//! Issue #2160: the signed transaction embedded in `PreEncodedTxInfo` (the
//! simulate `txn-result` and the pending-transaction responses) must render in
//! go's `protocol.JSONStrictHandle` form: every `[]byte` / digest field as
//! standard base64, addresses as checksummed base32, never as an integer array.

use algo_rest_api::models::PreEncodedTxInfo;
use algo_types::{Address, BoxRef, LogicSig, SignedTransaction, Transaction, TxnType};
use base64::Engine;
use serde_bytes::ByteBuf;
use serde_json::Value;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn info(txn: SignedTransaction) -> PreEncodedTxInfo {
    PreEncodedTxInfo {
        txn,
        pool_error: String::new(),
        confirmed_round: None,
        closing_amount: None,
        asset_closing_amount: None,
        sender_rewards: None,
        receiver_rewards: None,
        close_rewards: None,
        asset_index: None,
        application_index: None,
        global_state_delta: None,
        local_state_delta: None,
        logs: None,
        inner_txns: None,
    }
}

fn json_of(i: &PreEncodedTxInfo) -> Value {
    serde_json::to_value(i).expect("serializes")
}

fn base_txn(ty: TxnType) -> Transaction {
    Transaction {
        txn_type: ty,
        sender: Address([1u8; 32]),
        fee: 1000,
        first_valid: algo_types::Round(10),
        last_valid: algo_types::Round(20),
        genesis_hash: [3u8; 32],
        group: [4u8; 32],
        lease: [5u8; 32],
        note: ByteBuf::from(vec![9, 8, 7]),
        rekey_to: Some(Address([6u8; 32])),
        ..Transaction::default()
    }
}

#[test]
fn payment_digests_note_and_addresses_render_like_go() {
    let mut t = base_txn(TxnType::Pay);
    t.receiver = Address([2u8; 32]);
    t.amount = 5;
    let s = SignedTransaction {
        txn: t,
        sig: [7u8; 64],
        ..SignedTransaction::default()
    };
    let v = json_of(&info(s));
    let txn = &v["txn"]["txn"];
    assert_eq!(txn["gh"], b64(&[3u8; 32]));
    assert_eq!(txn["grp"], b64(&[4u8; 32]));
    assert_eq!(txn["lx"], b64(&[5u8; 32]));
    assert_eq!(txn["note"], b64(&[9, 8, 7]));
    assert_eq!(txn["snd"], Address([1u8; 32]).to_string());
    assert_eq!(txn["rcv"], Address([2u8; 32]).to_string());
    assert_eq!(txn["rekey"], Address([6u8; 32]).to_string());
    assert_eq!(v["txn"]["sig"], b64(&[7u8; 64]));
}

#[test]
fn app_call_programs_args_boxes_and_lsig_render_as_base64() {
    let mut t = base_txn(TxnType::Appl);
    t.approval_program = Some(ByteBuf::from(vec![1, 2, 3]));
    t.clear_state_program = Some(ByteBuf::from(vec![4, 5]));
    t.app_arguments = Some(vec![Some(ByteBuf::from(vec![0xaa, 0xbb]))]);
    t.accounts = Some(vec![Address([8u8; 32])]);
    t.boxes = Some(vec![BoxRef {
        index: 0,
        name: Some(ByteBuf::from(vec![0xde, 0xad])),
    }]);
    let s = SignedTransaction {
        txn: t,
        lsig: Some(LogicSig {
            logic: ByteBuf::from(vec![6, 1]),
            args: Some(vec![ByteBuf::from(vec![0xff])]),
            ..LogicSig::default()
        }),
        ..SignedTransaction::default()
    };
    let v = json_of(&info(s));
    let txn = &v["txn"]["txn"];
    assert_eq!(txn["apap"], b64(&[1, 2, 3]));
    assert_eq!(txn["apsu"], b64(&[4, 5]));
    assert_eq!(txn["apaa"], serde_json::json!([b64(&[0xaa, 0xbb])]));
    assert_eq!(
        txn["apat"],
        serde_json::json!([Address([8u8; 32]).to_string()])
    );
    assert_eq!(txn["apbx"][0]["n"], b64(&[0xde, 0xad]));
    assert_eq!(v["txn"]["lsig"]["l"], b64(&[6, 1]));
    assert_eq!(v["txn"]["lsig"]["arg"], serde_json::json!([b64(&[0xff])]));
}

#[test]
fn keyreg_participation_keys_render_as_base64() {
    let mut t = base_txn(TxnType::Keyreg);
    t.vote_pk = Some([0x11; 32]);
    t.selection_pk = Some([0x22; 32]);
    t.state_proof_pk = Some([0x33; 64]);
    t.vote_first = 1;
    t.vote_last = 100;
    t.vote_key_dilution = 10;
    let s = SignedTransaction {
        txn: t,
        ..SignedTransaction::default()
    };
    let v = json_of(&info(s));
    let txn = &v["txn"]["txn"];
    assert_eq!(txn["votekey"], b64(&[0x11; 32]));
    assert_eq!(txn["selkey"], b64(&[0x22; 32]));
    assert_eq!(txn["sprfkey"], b64(&[0x33; 64]));
}

#[test]
fn logs_render_as_base64_strings() {
    let mut i = info(SignedTransaction::default());
    i.logs = Some(vec![vec![1, 2, 3], vec![0xff]]);
    let v = json_of(&i);
    assert_eq!(
        v["logs"],
        serde_json::json!([b64(&[1, 2, 3]), b64(&[0xff])])
    );
}

#[test]
fn inner_transactions_render_like_the_outer_one() {
    let mut inner = info(SignedTransaction::default());
    inner.txn.txn = base_txn(TxnType::Pay);
    let mut outer = info(SignedTransaction::default());
    outer.inner_txns = Some(vec![inner]);
    let v = json_of(&outer);
    assert_eq!(v["inner-txns"][0]["txn"]["txn"]["gh"], b64(&[3u8; 32]));
}
