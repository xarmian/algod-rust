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

//! Issue #2545: app global/local state deltas of go-algorand's block evaluator
//! (`ledger/eval/appcow.go` `delKey` / `storageDelta.applyChild`, v5.1.1)
//! compared row by row with a go-generated fixture.
//!
//! go v5.1.1 stops recording a delete of a key that was absent before the cow
//! touched it (and drops the entry when a child cow merges an absent-to-absent
//! change). The `EvalDelta` written to the block comes from the AVM layer
//! (`opAppGlobalDel` / `opAppLocalDel`), not from `kvCow`, so the change is
//! internal to go's cow; this test pins that the `gd`/`ld` that algod-rust
//! writes equal go's on every scenario, including a delete of a key written
//! earlier in the same call or block.
//!
//! Fixture: `fixtures/eval_delta_state_go.jsonl`, produced by
//! `tools/eval-delta-state-oracle` from `scenarios.json` (the single shared
//! input; header of `oracle_test.go.txt` has the exact command).

use std::collections::BTreeMap;

use algo_ledger::{apply_block_capturing_apply_data, parse_eval_delta, ApplyMode, ValueDelta};
use algo_types::{Address, Block, Round, SignedTransaction, StateSchema};
use serde_json::{json, Value};

const SCENARIOS: &str = include_str!("../../../../tools/eval-delta-state-oracle/scenarios.json");
const GO_FIXTURE: &str = include_str!("fixtures/eval_delta_state_go.jsonl");

fn value(v: &str) -> String {
    if let Some(u) = v.strip_prefix("u:") {
        format!("int {u}")
    } else {
        format!("byte {:?}", &v[2..])
    }
}

/// Same program text the go oracle builds (`oracleSource`).
fn source(calls: &[Value]) -> String {
    let mut b = String::from("#pragma version 8\ntxn NumAppArgs\nbz done\n");
    for (i, c) in calls.iter().enumerate() {
        b += &format!("txn ApplicationArgs 0\nbtoi\nint {i}\n==\nbz next{i}\n");
        for op in c["ops"].as_array().unwrap() {
            let a: Vec<&str> = op
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap())
                .collect();
            match a[0] {
                "gput" => b += &format!("byte {:?}\n{}\napp_global_put\n", a[1], value(a[2])),
                "gdel" => b += &format!("byte {:?}\napp_global_del\n", a[1]),
                "lput" => {
                    b += &format!(
                        "txn Sender\nbyte {:?}\n{}\napp_local_put\n",
                        a[1],
                        value(a[2])
                    )
                }
                "ldel" => b += &format!("txn Sender\nbyte {:?}\napp_local_del\n", a[1]),
                other => panic!("unknown op {other}"),
            }
        }
        b += &format!("b done\nnext{i}:\n");
    }
    b + "done:\nint 1\n"
}

fn block(fee_sink: Address, round: u64, payset: Vec<SignedTransaction>) -> Block {
    Block {
        round: Round(round),
        fee_sink,
        current_protocol: algo_types::consensus::CONSENSUS_V43.to_string(),
        payset,
        ..Default::default()
    }
}

fn normalize(sd: &std::collections::HashMap<Vec<u8>, ValueDelta>) -> Value {
    let m: BTreeMap<String, Value> = sd
        .iter()
        .map(|(k, v)| {
            (
                hex::encode(k),
                json!([
                    u64::from(v.action).to_string(),
                    v.uint.to_string(),
                    hex::encode(&v.bytes)
                ]),
            )
        })
        .collect();
    json!(m)
}

fn run(sc: &Value) -> Value {
    let creator = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let mut state = algo_ledger::apply::pool_fixtures::funded_ledger_state();
    state.fee_sink = fee_sink;
    state.get_or_default_account_mut(&creator).micro_algos = 5_000_000_000;
    let calls = sc["calls"].as_array().unwrap();
    let app_id = 900u64;

    let mut create = SignedTransaction::default();
    create.txn.txn_type = "appl".into();
    create.txn.sender = creator;
    create.txn.fee = 1_000;
    create.txn.approval_program = Some(serde_bytes::ByteBuf::from(
        algo_avm::assembler::assemble_string(&source(calls))
            .expect("assembles")
            .program,
    ));
    create.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(
        algo_avm::assembler::assemble_string("#pragma version 8\nint 1\n")
            .unwrap()
            .program,
    ));
    let schema = StateSchema {
        num_uint: 8,
        num_byte_slice: 8,
    };
    create.txn.global_state_schema = Some(schema.clone());
    create.txn.local_state_schema = Some(schema);
    create.apply_data_application_id = app_id;
    apply_block_capturing_apply_data(
        &mut state,
        &block(fee_sink, 1, vec![create]),
        ApplyMode::Execute,
    )
    .expect("create");

    let txs: Vec<SignedTransaction> = calls
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let mut t = SignedTransaction::default();
            t.txn.txn_type = "appl".into();
            t.txn.sender = creator;
            t.txn.fee = 1_000;
            t.txn.application_id = app_id;
            t.txn.on_completion = u64::from(c["oc"].as_str() == Some("optin"));
            t.txn.app_arguments = Some(vec![Some(serde_bytes::ByteBuf::from(vec![i as u8]))]);
            t
        })
        .collect();
    let groups: Vec<Vec<SignedTransaction>> = if sc["same_block"].as_bool().unwrap() {
        vec![txs]
    } else {
        txs.into_iter().map(|t| vec![t]).collect()
    };
    let mut out = Vec::new();
    for (r, payset) in groups.into_iter().enumerate() {
        let res = apply_block_capturing_apply_data(
            &mut state,
            &block(fee_sink, 2 + r as u64, payset),
            ApplyMode::Execute,
        )
        .unwrap_or_else(|e| panic!("{}: {e}", sc["name"]));
        for ad in res {
            let (gd, ld) = match ad.eval_delta.as_ref() {
                None => (json!({}), json!({})),
                Some(dt) => {
                    let ed = parse_eval_delta(dt).unwrap();
                    let gd = ed.global_delta.as_ref().map(normalize).unwrap_or(json!({}));
                    let ld: BTreeMap<String, Value> = ed
                        .local_deltas
                        .iter()
                        .flatten()
                        .map(|(k, v)| (k.to_string(), normalize(v)))
                        .collect();
                    (gd, json!(ld))
                }
            };
            out.push(json!({"gd": gd, "ld": ld}));
        }
    }
    json!({"name": sc["name"], "calls": out})
}

#[test]
fn state_deltas_match_go_v5_1_1_on_every_scenario() {
    let scenarios: Vec<Value> = serde_json::from_str(SCENARIOS).unwrap();
    let golden: Vec<Value> = GO_FIXTURE
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(scenarios.len(), golden.len());
    for (sc, want) in scenarios.iter().zip(&golden) {
        assert_eq!(&run(sc), want, "scenario {}", sc["name"]);
    }
}
