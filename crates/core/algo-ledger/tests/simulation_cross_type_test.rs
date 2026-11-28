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

//! Simulate's generate-only cross-type lookup check (issue #2606): go
//! v5.1.1's `BlockEvaluator.transaction` refuses, while generating (simulate
//! runs with `Generate: true`), a transaction that looked an app id up as an
//! asset the account holds as of the previous block, or the reverse
//! (`roundCowBase.noteMiss`; `TestCowBaseCrossTypeLookups`).
//!
//! `tests/fixtures/simulate_cross_type.jsonl` is the real go output of
//! `tools/simulate-cross-type-oracle` (go's unmodified `Simulator` on an
//! in-memory ledger; the header of that file has the command): per case the
//! group's failure message (addresses and txids replaced by `$A`, `$B`,
//! `$CREATOR`, `$TXID<n>`) and failed-at path. The same state and groups are
//! built here and compared in full, `transaction <txid>: ` frame included.

use algo_ledger::apply::pool_fixtures::{funded_simulation_state, TEST_GENESIS_HASH};
use algo_ledger::simulation::{SimulationRequest, Simulator};
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParams, AssetParamsRecord,
    SignedTransaction, Transaction,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Row {
    name: String,
    failed_at: Vec<usize>,
    failure_message: String,
}

const A: Address = Address([0xA1; 32]);
const B: Address = Address([0xB2; 32]);
const CREATOR: Address = Address([0xC3; 32]);

// The ids go's oracle gets: 1000 genesis txns, then the setup transactions.
const APP_X: u64 = 1001;
const ASA_S: u64 = 1003;
const CREATED: u64 = 1005;
const PROBE_ASSET: u64 = 1006;
const PROBE_APP: u64 = 1007;

fn program(src: &str) -> Vec<u8> {
    algo_avm::assembler::assemble_string(src)
        .expect("assemble")
        .program
}

/// The state the oracle builds before simulating: A holds app `APP_X` (local
/// state), asset `ASA_S` (holding) and created asset `CREATED`; `CREATOR`
/// made the rest.
fn state() -> LedgerState {
    let mut l = funded_simulation_state();
    for who in [A, B, CREATOR] {
        l.set_account(
            &who,
            AccountData {
                micro_algos: 100_000_000,
                ..Default::default()
            },
        );
    }
    l.set_txn_counter(PROBE_APP);
    let trivial = program("#pragma version 8\nint 1");
    let app = |source: &str| AppParams {
        creator: CREATOR,
        approval_program: program(source),
        clear_state_program: trivial.clone(),
        ..Default::default()
    };
    l.set_app_params(APP_X, app("#pragma version 8\nint 1"));
    l.set_app_params(
        PROBE_ASSET,
        app("#pragma version 8\ntxn ApplicationID\nbz end\ntxn Sender\ntxn Assets 0\nasset_holding_get AssetBalance\npop\npop\nend:\nint 1"),
    );
    l.set_app_params(
        PROBE_APP,
        app("#pragma version 8\ntxn ApplicationID\nbz end\ntxn Sender\ntxn Applications 1\napp_opted_in\npop\nend:\nint 1"),
    );
    l.set_app_local_state(
        &A,
        APP_X,
        AppLocalState {
            schema: Default::default(),
            key_value: Default::default(),
        },
    );
    for (id, creator) in [(ASA_S, CREATOR), (CREATED, A)] {
        l.set_asset_params(
            id,
            AssetParamsRecord {
                params: AssetParams {
                    total: 100,
                    ..Default::default()
                },
                creator,
            },
        );
    }
    for id in [ASA_S, CREATED] {
        l.set_asset_holding(
            &A,
            id,
            AssetHolding {
                amount: if id == CREATED { 1 } else { 0 },
                ..Default::default()
            },
        );
    }
    l
}

fn base_txn(sender: Address, txn_type: &str) -> Transaction {
    Transaction {
        txn_type: txn_type.into(),
        sender,
        fee: 1_000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        genesis_hash: TEST_GENESIS_HASH,
        ..Default::default()
    }
}

fn call(
    sender: Address,
    app: u64,
    on_completion: u64,
    assets: Option<u64>,
    apps: Option<u64>,
) -> Transaction {
    let mut t = base_txn(sender, "appl");
    t.application_id = app;
    t.on_completion = on_completion;
    t.foreign_assets = assets.map(|id| vec![id]);
    t.foreign_apps = apps.map(|id| vec![id]);
    t
}

fn grouped(mut txns: Vec<Transaction>) -> Vec<SignedTransaction> {
    if txns.len() > 1 {
        let gid = algo_codec::compute_group_id(&txns).0;
        for t in &mut txns {
            t.group = gid;
        }
    }
    txns.into_iter()
        .map(|txn| SignedTransaction {
            txn,
            ..Default::default()
        })
        .collect()
}

/// The groups of `tools/simulate-cross-type-oracle`, by case name.
fn group_for(name: &str) -> Vec<SignedTransaction> {
    const CLEAR: u64 = 3;
    let one = |t: Transaction| grouped(vec![t]);
    match name {
        "app_id_looked_up_as_an_asset_it_holds" => one(call(A, PROBE_ASSET, 0, Some(APP_X), None)),
        "asset_id_looked_up_as_an_app_it_holds" => one(call(A, PROBE_APP, 0, None, Some(ASA_S))),
        "asset_id_created_by_the_sender_looked_up_as_an_app" => {
            one(call(A, PROBE_APP, 0, None, Some(CREATED)))
        }
        "id_of_the_type_asked_for_is_an_ordinary_miss" => {
            one(call(B, PROBE_ASSET, 0, Some(ASA_S), None))
        }
        "other_account_does_not_hold_the_id" => one(call(B, PROBE_ASSET, 0, Some(APP_X), None)),
        "held_as_the_type_asked_for_is_a_hit" => one(call(A, PROBE_ASSET, 0, Some(ASA_S), None)),
        "id_above_the_counter" => one(call(A, PROBE_ASSET, 0, Some(1_000_000), None)),
        "second_txn_of_a_group_after_clear_state_removed_the_local_state" => grouped(vec![
            call(A, APP_X, CLEAR, None, None),
            call(A, PROBE_ASSET, 0, Some(APP_X), None),
        ]),
        "second_txn_of_a_group_after_a_clean_first" => {
            let mut pay = base_txn(B, "pay");
            pay.receiver = B;
            grouped(vec![pay, call(A, PROBE_APP, 0, None, Some(ASA_S))])
        }
        other => panic!("unknown oracle case {other}"),
    }
}

#[test]
fn simulate_cross_type_lookups_match_go() {
    let fixture = include_str!("fixtures/simulate_cross_type.jsonl");
    let rows: Vec<Row> = fixture
        .lines()
        .map(|l| serde_json::from_str(l).expect("fixture row"))
        .collect();
    assert_eq!(rows.len(), 9, "the fixture has its cases");
    let mut bad = Vec::new();
    for row in &rows {
        let group = group_for(&row.name);
        let txids: Vec<String> = group
            .iter()
            .map(|s| algo_codec::compute_txn_id(&s.txn).to_string())
            .collect();
        let mut l = state();
        let result = Simulator::new(&mut l)
            .simulate(SimulationRequest {
                txn_groups: vec![group],
                allow_empty_signatures: true,
                ..Default::default()
            })
            .unwrap_or_else(|e| panic!("{}: simulate: {e}", row.name));
        let g = &result.txn_groups[0];
        let mut message = g.failure_message.clone().unwrap_or_default();
        for (i, id) in txids.iter().enumerate() {
            message = message.replace(id, &format!("$TXID{i}"));
        }
        for (who, token) in [(A, "$A"), (B, "$B"), (CREATOR, "$CREATOR")] {
            message = message.replace(&who.to_string(), token);
        }
        let failed_at = g.failed_at.clone().unwrap_or_default();
        if message != row.failure_message || failed_at != row.failed_at {
            bad.push(format!(
                "{}\n    go:   {:?} failed_at={:?}\n    rust: {:?} failed_at={:?}",
                row.name, row.failure_message, row.failed_at, message, failed_at
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "{} of {} cases differ from go-algorand:\n{}",
        bad.len(),
        rows.len(),
        bad.join("\n")
    );
}
