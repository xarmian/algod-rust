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

//! Issue #1254: `Simulator::simulate`'s shared app-call opcode budget
//! (`GroupBudget::new(num_app_calls)` in `simulation/mod.rs`) must be gated
//! on `EnableAppCostPooling`, just like the real block-apply path
//! (`apply::apply_group_transactions`, see the sibling regression tests in
//! `apply.rs`'s `mod tests`). Before v30, go-algorand's `NewAppEvalParams`
//! never allocates `PooledApplicationBudget` at all, so each top-level app
//! call in the simulated group gets its own independent `MaxAppProgramCost`
//! budget and the simulate-only `ExtraOpcodeBudget` override -- along with
//! the `AppBudgetAdded` report field it feeds -- is never applied either
//! (`ledger/simulation/tracer.go`'s `evalTracer.BeforeTxnGroup` only acts
//! `if ep.PooledApplicationBudget != nil`).

use algo_ledger::simulation::{SimulationRequest, Simulator};
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::{AccountData, Address, AppParams, SignedTransaction, StateSchema, Transaction};
use std::collections::BTreeMap;

const FEE_SINK: Address = Address([0xFE; 32]);

fn setup_state(sender: Address, current_protocol: &str) -> LedgerState {
    let mut state = LedgerState::new();
    state.fee_sink = FEE_SINK;
    state.protocol = current_protocol.to_string();
    state.set_account(
        &sender,
        AccountData {
            micro_algos: 10_000_000,
            ..Default::default()
        },
    );
    state.set_account(
        &FEE_SINK,
        AccountData {
            micro_algos: 0,
            ..Default::default()
        },
    );
    state
}

fn register_app(state: &mut LedgerState, creator: Address, app_id: u64, approval: Vec<u8>) {
    let app_params = AppParams {
        creator,
        approval_program: approval,
        clear_state_program: vec![0x04, 0x81, 0x01], // v4: pushint 1
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

fn make_appl_txn(sender: Address, app_id: u64) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: "appl".into(),
            sender,
            fee: 1000,
            first_valid: 0.into(),
            last_valid: 1000.into(),
            application_id: app_id,
            on_completion: 0, // NoOp
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Trivial always-approving v4 program (cost ~1, well under any budget).
fn cheap_program() -> Vec<u8> {
    algo_avm::assembler::assemble_string("#pragma version 4\nint 1\n")
        .expect("cheap program must assemble")
        .program
}

/// A backward-branch loop whose total opcode cost (`1 + 180*4 + 1 + 1 =
/// 723`) exceeds a single app call's own 700-opcode budget on its own, but
/// comfortably fits within a 2-call pooled group's 1,400-opcode budget
/// alongside a cheap sibling.
fn expensive_program() -> Vec<u8> {
    let src = "#pragma version 4\nint 180\nloop:\nint 1\n-\ndup\nbnz loop\npop\nint 1\n";
    algo_avm::assembler::assemble_string(src)
        .expect("expensive program must assemble")
        .program
}

fn simulate(
    state: &mut LedgerState,
    request: SimulationRequest,
) -> algo_ledger::simulation::SimulationResult {
    let mut simulator = Simulator::new(state);
    simulator
        .simulate(request)
        .expect("simulate() infra call must succeed (failures surface in the result, not Err)")
}

#[test]
fn issue_1254_app_cost_pooling_disabled_rejects_expensive_sibling() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender, algo_types::consensus::CONSENSUS_V29);
    register_app(&mut state, sender, 100, cheap_program());
    register_app(&mut state, sender, 200, expensive_program());

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100), make_appl_txn(sender, 200)]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request);
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_some(),
        "expensive app call must fail its own independent 700-opcode budget pre-v30, got: {:?}",
        group
    );
    assert!(
        group.failure_message.as_ref().unwrap().contains("budget"),
        "expected a budget-exhaustion failure, got: {:?}",
        group.failure_message
    );
    // go-algorand never allocates `PooledApplicationBudget` when pooling is
    // disabled, so `AppBudgetAdded` (sourced from it) stays 0 rather than
    // reporting a per-call figure -- see `tracer.go`'s `BeforeTxnGroup`.
    assert_eq!(
        group.app_budget_added, 0,
        "AppBudgetAdded must stay 0 pre-v30 (no PooledApplicationBudget to report)"
    );
}

#[test]
fn issue_1254_app_cost_pooling_enabled_lets_expensive_sibling_borrow() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender, algo_types::consensus::CONSENSUS_V41);
    register_app(&mut state, sender, 100, cheap_program());
    register_app(&mut state, sender, 200, expensive_program());

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100), make_appl_txn(sender, 200)]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request);
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "pooled group budget should cover the expensive sibling, got: {:?}",
        group.failure_message
    );
    assert_eq!(
        group.app_budget_added,
        2 * 700,
        "AppBudgetAdded should report the full 2-call pooled allocation when pooling is enabled"
    );
}
