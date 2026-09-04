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

//! Integration tests for issue #972 ("track nested inner-txn FailedAt path
//! instead of top-level-only index"):
//!
//! go-algorand's simulate endpoint reports exactly which transaction within
//! a group failed via a "transaction path" (`ledger/simulation/trace.go`'s
//! `TxnPath`, maintained by `cursorEvalTracer` in
//! `ledger/simulation/tracer.go` as it descends into and returns from
//! inner-transaction execution). Before this fix, algod-rust's
//! `group_result.failed_at` was always `Some(vec![i])` — a single top-level
//! index — regardless of how deep inside an inner-transaction tree the
//! actual failure occurred.
//!
//! These tests port the scenario at the heart of go's
//! `TestAppCallInnerTxnApplyDataOnErr` (`ledger/simulation/
//! simulation_eval_test.go`, `FailedAt: simulation.TxnPath{2, 0, 0}`): an
//! outer app call whose inner app call itself makes a further inner app
//! call, and the deepest (grand-inner) call is the one that actually fails.

use std::collections::BTreeMap;

use algo_ledger::simulation::{SimulationRequest, Simulator, SimulatorError};
use algo_ledger::{avm_context::app_address, LedgerState, LedgerStore};
use algo_types::{AccountData, Address, AppParams, SignedTransaction, StateSchema, Transaction};

const FEE_SINK: Address = Address([0xFE; 32]);

fn assemble(source: &str) -> Vec<u8> {
    algo_avm::assembler::assemble_string(source)
        .unwrap_or_else(|e| panic!("assembly failed: {e:?}\nsource:\n{source}"))
        .program
}

fn base_state() -> LedgerState {
    let mut state = LedgerState::new();
    state.fee_sink = FEE_SINK;
    state.protocol = algo_types::consensus::CONSENSUS_V41.to_string();
    state.set_account(
        &FEE_SINK,
        AccountData {
            micro_algos: 0,
            ..Default::default()
        },
    );
    state
}

fn fund(state: &mut LedgerState, addr: Address, micro_algos: u64) {
    let mut acct = state.get_account(&addr).cloned().unwrap_or_default();
    acct.micro_algos = micro_algos;
    state.set_account(&addr, acct);
}

fn register_app(state: &mut LedgerState, creator: Address, app_id: u64, approval: Vec<u8>) {
    let app_params = AppParams {
        creator,
        approval_program: approval,
        clear_state_program: assemble("#pragma version 8\nint 1\n"),
        global_state: BTreeMap::new(),
        local_state_schema: StateSchema::default(),
        global_state_schema: StateSchema::default(),
        extra_program_pages: 0,
        ..Default::default()
    };
    state.set_app_params(app_id, app_params);
    let mut acct = state.get_account(&creator).cloned().unwrap_or_default();
    acct.total_created_apps += 1;
    state.set_account(&creator, acct);
}

fn appl_txn(sender: Address, app_id: u64) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: "appl".into(),
            sender,
            fee: 5000,
            first_valid: 0.into(),
            last_valid: 1000.into(),
            application_id: app_id,
            on_completion: 0, // NoOp
            ..Default::default()
        },
        ..Default::default()
    }
}

fn simulate(
    state: &mut LedgerState,
    request: SimulationRequest,
) -> Result<algo_ledger::simulation::SimulationResult, SimulatorError> {
    let mut simulator = Simulator::new(state);
    simulator.simulate(request)
}

/// Outer app (index 0 in the group) calls App B via inner appl, which itself
/// calls App C via a further inner appl; App C unconditionally errors. The
/// actual failure is two levels deep, so `failed_at` must be `[0, 0, 0]`
/// (top-level index 0, App B is its first/only inner txn, App C is App B's
/// first/only inner txn) — not just `[0]`.
#[test]
fn nested_two_levels_deep_inner_failure_reports_full_path() {
    let sender = Address([0xAA; 32]);
    let (app_a, app_b, app_c) = (100u64, 200u64, 300u64);
    let mut state = base_state();
    fund(&mut state, sender, 20_000_000);

    let hop = |next_app: u64| {
        format!(
            "#pragma version 8
itxn_begin
int appl
itxn_field TypeEnum
int {next_app}
itxn_field ApplicationID
itxn_submit
int 1
"
        )
    };
    let leaf_err = "#pragma version 8\nerr\n";

    let approval_a = assemble(&hop(app_b));
    let approval_b = assemble(&hop(app_c));
    let approval_c = assemble(leaf_err);

    for (id, approval) in [(app_a, approval_a), (app_b, approval_b), (app_c, approval_c)] {
        register_app(&mut state, sender, id, approval);
        fund(&mut state, Address(app_address(id)), 2_000_000);
    }

    let mut stx = appl_txn(sender, app_a);
    stx.txn.foreign_apps = Some(vec![app_b, app_c]);

    let request = SimulationRequest {
        txn_groups: vec![vec![stx]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulate must return a result");
    let group = &result.txn_groups[0];

    assert!(
        group.failure_message.is_some(),
        "App C's `err` opcode must fail the group"
    );
    assert_eq!(
        group.failed_at.as_deref(),
        Some([0usize, 0, 0].as_slice()),
        "failed_at must descend into the nested inner-txn tree, not stop at the top-level index"
    );
}

/// A single level of inner-txn nesting: the outer app's *direct* inner appl
/// call fails. `failed_at` must be `[0, 0]` (the inner call, not just the
/// top-level index `[0]`) — proves the fix also covers the shallow case, not
/// only multi-level descent.
#[test]
fn direct_inner_failure_reports_two_element_path() {
    let sender = Address([0xAA; 32]);
    let (app_a, app_b) = (100u64, 200u64);
    let mut state = base_state();
    fund(&mut state, sender, 20_000_000);

    let a_code = "#pragma version 8
itxn_begin
int appl
itxn_field TypeEnum
int 200
itxn_field ApplicationID
itxn_submit
int 1
";
    let b_code = "#pragma version 8\nerr\n";

    let approval_a = assemble(a_code);
    let approval_b = assemble(b_code);

    for (id, approval) in [(app_a, approval_a), (app_b, approval_b)] {
        register_app(&mut state, sender, id, approval);
        fund(&mut state, Address(app_address(id)), 2_000_000);
    }

    let mut stx = appl_txn(sender, app_a);
    stx.txn.foreign_apps = Some(vec![app_b]);

    let request = SimulationRequest {
        txn_groups: vec![vec![stx]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulate must return a result");
    let group = &result.txn_groups[0];

    assert!(group.failure_message.is_some());
    assert_eq!(group.failed_at.as_deref(), Some([0usize, 0].as_slice()));
}

/// A group of two top-level transactions where the second one's inner app
/// call fails: `failed_at` must be `[1, 0]`, proving the real top-level
/// group index (not always `0`) is correctly used as the path's first
/// element when combined with the descended inner path.
#[test]
fn second_group_member_nested_failure_reports_correct_top_level_index() {
    let sender = Address([0xAA; 32]);
    let (app_a, app_b) = (100u64, 200u64);
    let mut state = base_state();
    fund(&mut state, sender, 20_000_000);

    let a_code = "#pragma version 8
itxn_begin
int appl
itxn_field TypeEnum
int 200
itxn_field ApplicationID
itxn_submit
int 1
";
    let b_code = "#pragma version 8\nerr\n";

    let approval_a = assemble(a_code);
    let approval_b = assemble(b_code);

    for (id, approval) in [(app_a, approval_a), (app_b, approval_b)] {
        register_app(&mut state, sender, id, approval);
        fund(&mut state, Address(app_address(id)), 2_000_000);
    }

    // First group member: an unrelated, successful payment.
    let pay = SignedTransaction {
        txn: Transaction {
            txn_type: "pay".into(),
            sender,
            receiver: sender,
            amount: 0,
            fee: 1000,
            first_valid: 0.into(),
            last_valid: 1000.into(),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut appl = appl_txn(sender, app_a);
    appl.txn.foreign_apps = Some(vec![app_b]);

    let request = SimulationRequest {
        txn_groups: vec![vec![pay, appl]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulate must return a result");
    let group = &result.txn_groups[0];

    assert!(group.failure_message.is_some());
    assert_eq!(group.failed_at.as_deref(), Some([1usize, 0].as_slice()));
}
