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

//! Issue #2038 (follow-up of #2036/#2037): go-algorand keeps ONE
//! `available.createdApps` set on the group's shared `EvalParams`
//! (`data/transactions/logic/resources.go`, `eval.go`), so an app created at
//! any depth of an earlier top-level member's inner-call tree is an available
//! resource to every later member of the atomic group.
//!
//! Group shape: `[txn0: A -> inner B -> inner create Y; txn1: C references Y]`.
//! Run through both the block-apply path and the simulator.

use std::collections::BTreeMap;

use algo_ledger::apply::{apply_block_capturing_apply_data, ApplyMode};
use algo_ledger::LedgerState;
use algo_types::consensus::CONSENSUS_V34;
use algo_types::{Address, AppParams, Block, Round, SignedTransaction, StateSchema, Transaction};

const A: u64 = 100;
const B: u64 = 101;
const C: u64 = 102;
/// Pre-existing app that no txn in the group created or lists.
const OTHER: u64 = 103;

fn varuint(mut x: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (x & 0x7f) as u8;
        x >>= 7;
        if x == 0 {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

/// `itxn_begin; pushint 6; itxn_field TypeEnum; pushint <app>;
/// itxn_field ApplicationID; itxn_submit; int 1; return`
fn calls_program(app: u64) -> Vec<u8> {
    let mut c = vec![0x06, 0xb1, 0x81, 6, 0xb2, 16, 0x81];
    c.extend(varuint(app));
    c.extend([0xb2, 24, 0xb3, 0x81, 0x01, 0x43]);
    c
}

/// `itxn_begin; TypeEnum=appl; ApprovalProgram=ClearStateProgram=<int 1>;
/// itxn_submit; int 1; return`
fn creates_program() -> Vec<u8> {
    let mut c = vec![0x06, 0xb1, 0x81, 6, 0xb2, 16];
    for field in [30u8, 31u8] {
        c.extend([0x80, 3, 0x06, 0x81, 0x01, 0xb2, field]);
    }
    c.extend([0xb3, 0x81, 0x01, 0x43]);
    c
}

/// `pushint <id>; app_params_get AppCreator; assert; pop; int 1; return`
fn references_program(id: u64) -> Vec<u8> {
    let mut c = vec![0x06, 0x81];
    c.extend(varuint(id));
    c.extend([0x72, 7, 0x44, 0x48, 0x81, 0x01, 0x43]);
    c
}

fn seed(store: &mut LedgerState, id: u64, program: Vec<u8>) {
    store.app_params.insert(
        id,
        AppParams {
            creator: Address([1u8; 32]),
            approval_program: program,
            clear_state_program: vec![0x06, 0x81, 0x01],
            global_state: BTreeMap::new(),
            local_state_schema: StateSchema::default(),
            global_state_schema: StateSchema::default(),
            ..Default::default()
        },
    );
}

fn call(app_id: u64, fee: u64, foreign_apps: Option<Vec<u64>>) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: "appl".into(),
            sender: Address([0xAA; 32]),
            fee,
            first_valid: Round(1),
            last_valid: Round(1000),
            application_id: app_id,
            foreign_apps,
            group: [7u8; 32],
            ..Default::default()
        },
        has_genesis_id: true,
        ..Default::default()
    }
}

fn setup(proto: &str, c_program: Vec<u8>) -> LedgerState {
    let mut s = LedgerState::new();
    s.fee_sink = Address([0xFE; 32]);
    s.protocol = proto.to_string();
    s.get_or_default_account_mut(&Address([0xAA; 32]))
        .micro_algos = 100_000_000;
    for app in [A, B] {
        s.get_or_default_account_mut(&Address(algo_ledger::avm_context::app_address(app)))
            .micro_algos = 10_000_000;
    }
    seed(&mut s, A, calls_program(B));
    seed(&mut s, B, creates_program());
    seed(&mut s, C, c_program);
    seed(&mut s, OTHER, vec![0x06, 0x81, 0x01]);
    s
}

fn txn0() -> SignedTransaction {
    call(A, 3000, Some(vec![B]))
}

fn block(proto: &str, payset: Vec<SignedTransaction>) -> Block {
    Block {
        round: Round(1),
        genesis_id: "test-net-v1".into(),
        genesis_hash: [7u8; 32],
        fee_sink: Address([0xFE; 32]),
        current_protocol: proto.to_string(),
        txn_counter: 1001,
        payset,
        ..Block::default()
    }
}

/// Run `[txn0]` alone to learn the id Y the nested create is assigned (ids
/// come from the txn counter, so adding txn1 later does not change it).
fn discover_y(proto: &str) -> u64 {
    let mut s = setup(proto, references_program(OTHER));
    apply_block_capturing_apply_data(&mut s, &block(proto, vec![txn0()]), ApplyMode::Execute)
        .expect("txn0 alone must apply");
    let y: Vec<u64> = s
        .app_params
        .keys()
        .copied()
        .filter(|id| ![A, B, C, OTHER].contains(id))
        .collect();
    assert_eq!(y.len(), 1, "exactly one nested-created app: {y:?}");
    y[0]
}

fn run_block(proto: &str, referenced: u64) -> Result<(), String> {
    let mut s = setup(proto, references_program(referenced));
    let payset = vec![txn0(), call(C, 1000, None)];
    apply_block_capturing_apply_data(&mut s, &block(proto, payset), ApplyMode::Execute)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn run_simulated(proto: &str, referenced: u64) -> Result<(), String> {
    use algo_ledger::simulation::{SimulationRequest, Simulator};
    let mut s = setup(proto, references_program(referenced));
    let request = SimulationRequest {
        txn_groups: vec![vec![txn0(), call(C, 1000, None)]],
        allow_empty_signatures: true,
        ..Default::default()
    };
    let result = Simulator::new(&mut s).simulate(request).expect("simulate");
    match &result.txn_groups[0].failure_message {
        None => Ok(()),
        Some(m) => Err(m.clone()),
    }
}

#[test]
fn nested_created_app_is_available_to_later_group_member() {
    let y = discover_y(CONSENSUS_V34);
    run_block(CONSENSUS_V34, y).expect("go: Y is in the group-wide createdApps set");
}

#[test]
fn simulate_nested_created_app_is_available_to_later_group_member() {
    let y = discover_y(CONSENSUS_V34);
    run_simulated(CONSENSUS_V34, y).expect("simulate shares the same createdApps set");
}

/// Negative: an app nobody created and nobody listed stays unavailable.
#[test]
fn uncreated_app_stays_unavailable_to_later_group_member() {
    let err = run_block(CONSENSUS_V34, OTHER).expect_err("OTHER is not available");
    assert!(err.contains("unavailable App"), "{err}");
}

#[test]
fn simulate_uncreated_app_stays_unavailable_to_later_group_member() {
    let err = run_simulated(CONSENSUS_V34, OTHER).expect_err("OTHER is not available");
    assert!(err.contains("unavailable App"), "{err}");
}
