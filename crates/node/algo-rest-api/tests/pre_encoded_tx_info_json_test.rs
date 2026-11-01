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
use algo_types::{
    Address, AssetParams, BoxRef, LogicSig, MultisigSig, MultisigSubsig, Participant, Reveal,
    SignedTransaction, StateProofBody, Transaction, TxnType,
};
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

const GO_SIGNED_TXN_KEYS: &[&str] = &["sig", "msig", "lsig", "pqsig", "txn", "sgnr"];

#[test]
fn embedded_txn_has_only_signed_txn_keys_never_apply_data_or_block_flags() {
    // A confirmed transaction carries ApplyData and the in-block flags; go's
    // `PreEncodedTxInfo.Txn` is a plain `SignedTxn`, apply data is reported as
    // separate top-level response fields.
    let s = SignedTransaction {
        txn: base_txn(TxnType::Pay),
        sig: [7u8; 64],
        has_genesis_id: true,
        has_genesis_hash: true,
        closing_amount: 5,
        asset_closing_amount: 6,
        sender_rewards: 7,
        receiver_rewards: 8,
        close_rewards: 9,
        apply_data_config_asset: 11,
        apply_data_application_id: 12,
        eval_delta: Some(rmpv::Value::Map(vec![(
            rmpv::Value::from("lg"),
            rmpv::Value::Array(vec![rmpv::Value::Binary(vec![1])]),
        )])),
        ..SignedTransaction::default()
    };
    let v = json_of(&info(s));
    for k in v["txn"].as_object().unwrap().keys() {
        assert!(
            GO_SIGNED_TXN_KEYS.contains(&k.as_str()),
            "unexpected key {k}"
        );
    }
}

#[test]
fn empty_logs_are_omitted_like_go_omitempty() {
    let mut i = info(SignedTransaction::default());
    i.logs = Some(vec![]);
    assert!(json_of(&i).get("logs").is_none());
    i.logs = None;
    assert!(json_of(&i).get("logs").is_none());
}

#[test]
fn multisig_subsig_keys_and_signatures_render_as_base64() {
    let s = SignedTransaction {
        txn: base_txn(TxnType::Pay),
        msig: Some(MultisigSig {
            version: 1,
            threshold: 1,
            subsigs: vec![MultisigSubsig {
                public_key: [0x44; 32],
                signature: [0x55; 64],
            }],
        }),
        ..SignedTransaction::default()
    };
    let v = json_of(&info(s));
    let sub = &v["txn"]["msig"]["subsig"][0];
    assert_eq!(sub["pk"], b64(&[0x44; 32]));
    assert_eq!(sub["s"], b64(&[0x55; 64]));
}

#[test]
fn state_proof_commitment_is_base64_not_an_address() {
    let mut t = base_txn(TxnType::Stpf);
    t.state_proof = Some(StateProofBody {
        sig_commit: ByteBuf::from(vec![0x66; 64]),
        signed_weight: 3,
        reveals: Some(std::collections::BTreeMap::from([(
            3u64,
            Reveal {
                part: Some(Participant {
                    weight: 1,
                    ..Participant::default()
                }),
                ..Reveal::default()
            },
        )])),
        ..StateProofBody::default()
    });
    let s = SignedTransaction {
        txn: t,
        ..SignedTransaction::default()
    };
    let v = json_of(&info(s));
    assert_eq!(v["txn"]["txn"]["sp"]["c"], b64(&[0x66; 64]));
    assert!(v["txn"]["txn"]["sp"]["r"]["3"].is_object());
}

#[test]
fn rendering_is_total_for_non_utf8_text_and_max_integers() {
    let mut t = base_txn(TxnType::Acfg);
    t.amount = u64::MAX;
    t.asset_params = Some(AssetParams {
        asset_name: vec![0xff, 0xfe, b'a'],
        unit_name: b"U".to_vec(),
        ..AssetParams::default()
    });
    let s = SignedTransaction {
        txn: t,
        ..SignedTransaction::default()
    };
    let v = json_of(&info(s));
    assert_eq!(v["txn"]["txn"]["amt"], u64::MAX);
    assert_eq!(v["txn"]["txn"]["apar"]["an"], "\u{fffd}\u{fffd}a");
    assert_eq!(v["txn"]["txn"]["apar"]["un"], "U");
}

#[test]
fn json_round_trips_through_deserialize() {
    let mut t = base_txn(TxnType::Appl);
    t.approval_program = Some(ByteBuf::from(vec![1, 2, 3]));
    t.app_arguments = Some(vec![Some(ByteBuf::from(vec![0xaa]))]);
    let s = SignedTransaction {
        txn: t,
        sig: [7u8; 64],
        ..SignedTransaction::default()
    };
    let mut i = info(s.clone());
    i.logs = Some(vec![vec![1, 2, 3], vec![0xff]]);
    let text = serde_json::to_string(&i).unwrap();
    let back: PreEncodedTxInfo = serde_json::from_str(&text).unwrap();
    assert_eq!(back.txn, s);
    assert_eq!(back.logs, i.logs);
    assert_eq!(serde_json::to_string(&back).unwrap(), text);
}

#[test]
fn older_serde_form_json_still_deserializes() {
    let s = SignedTransaction {
        txn: base_txn(TxnType::Pay),
        ..SignedTransaction::default()
    };
    let old = serde_json::json!({
        "txn": serde_json::to_value(&s).unwrap(),
        "pool-error": "",
        "logs": [[1, 2, 3]],
    });
    let back: PreEncodedTxInfo = serde_json::from_value(old).unwrap();
    assert_eq!(back.txn, s);
    assert_eq!(back.logs, Some(vec![vec![1, 2, 3]]));
}

#[test]
fn msgpack_branch_keeps_binary_logs_and_a_plain_signed_txn() {
    let plain = SignedTransaction {
        txn: base_txn(TxnType::Pay),
        sig: [7u8; 64],
        ..SignedTransaction::default()
    };
    // The stored transaction also carries in-block flags and ApplyData; go's
    // `PreEncodedTxInfo.Txn` is a plain `SignedTxn` in msgpack as well.
    let stored = SignedTransaction {
        has_genesis_id: true,
        has_genesis_hash: true,
        closing_amount: 5,
        asset_closing_amount: 6,
        sender_rewards: 7,
        receiver_rewards: 8,
        close_rewards: 9,
        apply_data_config_asset: 11,
        apply_data_application_id: 12,
        eval_delta: Some(rmpv::Value::Map(vec![])),
        ..plain.clone()
    };
    let mut i = info(stored);
    i.logs = Some(vec![vec![1, 2, 3]]);
    let bytes = rmp_serde::to_vec_named(&i).unwrap();
    let tree = rmpv::decode::read_value(&mut &bytes[..]).unwrap();
    let rmpv::Value::Map(entries) = &tree else {
        panic!("not a map")
    };
    let get = |k: &str| {
        entries
            .iter()
            .find(|(n, _)| n.as_str() == Some(k))
            .unwrap()
            .1
            .clone()
    };
    assert_eq!(
        get("logs"),
        rmpv::Value::Array(vec![rmpv::Value::Binary(vec![1, 2, 3])])
    );
    // the txn is msgpack bin with only SignedTxn's own keys
    let rmpv::Value::Map(txn) = get("txn") else {
        panic!("txn not a map")
    };
    for (k, _) in &txn {
        assert!(GO_SIGNED_TXN_KEYS.contains(&k.as_str().unwrap()), "{k}");
    }
    let plain_bytes = rmp_serde::to_vec_named(&plain).unwrap();
    let plain_tree = rmpv::decode::read_value(&mut &plain_bytes[..]).unwrap();
    assert_eq!(get("txn"), plain_tree, "remaining fields keep their bytes");
    let back: PreEncodedTxInfo = rmp_serde::from_slice(&bytes).unwrap();
    assert_eq!(back.txn, plain);
    assert_eq!(back.logs, i.logs);
}

#[test]
fn float_rendering_matches_go_for_large_negative_and_zero_values() {
    // No float appears in a transaction; this pins the shared renderer.
    use rmpv::Value as M;
    let render = |f: f64| {
        let mut resp = Vec::new();
        let block = M::Map(vec![(M::from("f"), M::F64(f))]);
        rmpv::encode::write_value(&mut resp, &M::Map(vec![(M::from("block"), block)])).unwrap();
        String::from_utf8(algo_rest_api::block_json::encode_block_json(&resp).unwrap()).unwrap()
    };
    let field = |f: f64| {
        let text = render(f);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["block"]["f"].to_string()
    };
    assert_eq!(field(1e19), "10000000000000000000");
    assert_eq!(field(9223372036854775808.0), "9223372036854775808");
    assert_eq!(field(-1.5), "-1.5");
    assert_eq!(field(-0.0), "-0.0");
}
