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

//! Issue #1736: before `UnifyInnerTxIDs` (consensus v34) go's `txidCache`
//! lives on the top-level group's single shared `EvalParams`
//! (`data/transactions/logic/eval.go:409`, `getTxIDNotUnified` 3313-3333),
//! so every app call of one top-level group reads and fills the same
//! group-index keyed slots. App 0's `itxn TxID` (inner group index 0) caches
//! the inner txn's plain `txn.ID()` at slot 0; app 1's `gtxn 0 TxID` then
//! hits that slot and observes the inner txn's id -- go's collision bug,
//! reproduced bug-for-bug. Under v34+ the top-level reader never touches the
//! cache, so app 1 sees the real id of txn 0.

use std::collections::BTreeMap;

use algo_ledger::apply::{apply_block_capturing_apply_data, ApplyMode};
use algo_ledger::{parse_eval_delta, LedgerState};
use algo_types::consensus::{CONSENSUS_V33, CONSENSUS_V34};
use algo_types::{Address, AppParams, Block, Round, SignedTransaction, StateSchema, Transaction};

const APP0: u64 = 100;
const APP1: u64 = 101;

fn app0_program() -> Vec<u8> {
    // itxn_begin; int pay; itxn_field TypeEnum; byte <rcv>; itxn_field
    // Receiver; itxn_submit; itxn TxID; log;
    // int 1; return
    let mut c = vec![0x05, 0xb1, 0x81, 0x01, 0xb2, 16, 0x80, 32];
    c.extend([0xBB; 32]);
    c.extend([0xb2, 7, 0xb3, 0xb4, 23, 0xb0, 0x81, 0x01, 0x43]);
    c
}

fn app1_program() -> Vec<u8> {
    // gtxn 0 TxID; log; int 1; return
    vec![0x05, 0x33, 0, 23, 0xb0, 0x81, 0x01, 0x43]
}

fn seed(store: &mut LedgerState, id: u64, program: Vec<u8>) {
    store.app_params.insert(
        id,
        AppParams {
            creator: Address([1u8; 32]),
            approval_program: program,
            clear_state_program: vec![0x05, 0x81, 0x01],
            global_state: BTreeMap::new(),
            local_state_schema: StateSchema::default(),
            global_state_schema: StateSchema::default(),
            ..Default::default()
        },
    );
}

fn call(app_id: u64) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: "appl".into(),
            sender: Address([0xAA; 32]),
            fee: 3000,
            first_valid: Round(1),
            last_valid: Round(1000),
            application_id: app_id,
            group: [7u8; 32],
            ..Default::default()
        },
        has_genesis_id: true,
        ..Default::default()
    }
}

/// Returns (app 0's `itxn TxID` log, app 1's `gtxn 0 TxID` log).
fn run(proto: &str) -> (Vec<u8>, Vec<u8>) {
    let mut s = LedgerState::new();
    s.fee_sink = Address([0xFE; 32]);
    s.get_or_default_account_mut(&Address([0xAA; 32]))
        .micro_algos = 100_000_000;
    s.get_or_default_account_mut(&Address(algo_ledger::avm_context::app_address(APP0)))
        .micro_algos = 10_000_000;
    seed(&mut s, APP0, app0_program());
    seed(&mut s, APP1, app1_program());
    let block = Block {
        round: Round(1),
        genesis_id: "test-net-v1".into(),
        genesis_hash: [7u8; 32],
        fee_sink: Address([0xFE; 32]),
        current_protocol: proto.to_string(),
        txn_counter: 1001,
        payset: vec![call(APP0), call(APP1)],
        ..Block::default()
    };
    let ads = apply_block_capturing_apply_data(&mut s, &block, ApplyMode::Execute).unwrap();
    let log = |i: usize| {
        let ed = parse_eval_delta(ads[i].eval_delta.as_ref().expect("eval delta")).unwrap();
        let logs = ed.logs.expect("logs");
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].len(), 32);
        logs[0].clone()
    };
    (log(0), log(1))
}

#[test]
fn pre_v34_group_shares_txid_cache_across_app_calls() {
    let (inner_id, gtxn0) = run(CONSENSUS_V33);
    assert_eq!(
        gtxn0, inner_id,
        "pre-v34: app 1's `gtxn 0 TxID` must hit the slot app 0's `itxn TxID` \
         cached in the group's shared EvalParams.txidCache"
    );
}

#[test]
fn v34_group_does_not_share_txid_cache() {
    let (inner_id, gtxn0) = run(CONSENSUS_V34);
    assert_ne!(
        gtxn0, inner_id,
        "v34+: top-level reader never uses the cache"
    );
    // The plain, unsalted id of the (genesis-restored) top-level txn 0.
    let mut txn0 = call(APP0).txn;
    txn0.genesis_id = "test-net-v1".into();
    txn0.genesis_hash = [7u8; 32];
    assert_eq!(
        gtxn0,
        algo_codec::compute_txn_id(&txn0).0.to_vec(),
        "v34+: app 1's `gtxn 0 TxID` is txn 0's real id"
    );
}

/// Same two-app group through the simulator: it drives `GroupInfo` itself
/// and must share the cache across the group's app calls too.
fn run_simulated(proto: &str) -> (Vec<u8>, Vec<u8>) {
    use algo_ledger::simulation::{SimulationRequest, Simulator};
    let mut s = LedgerState::new();
    s.fee_sink = Address([0xFE; 32]);
    s.protocol = proto.to_string();
    s.get_or_default_account_mut(&Address([0xAA; 32]))
        .micro_algos = 100_000_000;
    s.get_or_default_account_mut(&Address(algo_ledger::avm_context::app_address(APP0)))
        .micro_algos = 10_000_000;
    seed(&mut s, APP0, app0_program());
    seed(&mut s, APP1, app1_program());
    let request = SimulationRequest {
        txn_groups: vec![vec![call(APP0), call(APP1)]],
        allow_empty_signatures: true,
        ..Default::default()
    };
    let result = Simulator::new(&mut s).simulate(request).expect("simulate");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "{:?}",
        group.failure_message
    );
    let log = |i: usize| {
        let ad = group.txn_results[i]
            .apply_data
            .as_ref()
            .expect("apply data");
        let ed = parse_eval_delta(ad.eval_delta.as_ref().expect("eval delta")).unwrap();
        let logs = ed.logs.expect("logs");
        assert_eq!(logs.len(), 1);
        logs[0].clone()
    };
    (log(0), log(1))
}

#[test]
fn simulate_pre_v34_group_shares_txid_cache_across_app_calls() {
    let (inner_id, gtxn0) = run_simulated(CONSENSUS_V33);
    assert_eq!(gtxn0, inner_id);
}

#[test]
fn simulate_v34_group_does_not_share_txid_cache() {
    let (inner_id, gtxn0) = run_simulated(CONSENSUS_V34);
    assert_ne!(gtxn0, inner_id);
}
