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

//! Integration tests for issue #215 ("EvalDelta preserved on error"):
//!
//! When a top-level `appl` call's approval program rejects or errors mid-
//! execution, the simulation engine must still surface whatever global/local
//! state, logs, and inner transactions the program had already accumulated
//! before the failure — mirroring go-algorand's `evalTracer.saveEvalDelta`
//! (`ledger/simulation/tracer.go`), which snapshots the EvalDelta before
//! every opcode specifically so a failure mid-program doesn't lose it.

use std::collections::BTreeMap;

use algo_ledger::eval_delta::parse_eval_delta;
use algo_ledger::simulation::{SimulationRequest, Simulator, SimulatorError};
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::{AccountData, Address, AppParams, SignedTransaction, StateSchema, Transaction};

const FEE_SINK: Address = Address([0xFE; 32]);

fn setup_state(sender: Address) -> LedgerState {
    let mut state = LedgerState::new();
    state.fee_sink = FEE_SINK;
    state.protocol = algo_types::consensus::CONSENSUS_V41.to_string();

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
        clear_state_program: vec![0x06, 0x81, 0x01, 0x43], // v6: pushint 1; return
        global_state: BTreeMap::new(),
        local_state_schema: StateSchema::default(),
        // NumUint: 1 -- global_put_then_err_program() writes one uint key
        // before erroring; a schema declaring 0 uints would (correctly,
        // per issue #809's StateSchema write-limit enforcement) reject
        // that write itself, which isn't what these tests are about.
        global_state_schema: StateSchema {
            num_uint: 1,
            num_byte_slice: 0,
        },
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

fn simulate(
    state: &mut LedgerState,
    request: SimulationRequest,
) -> Result<algo_ledger::simulation::SimulationResult, SimulatorError> {
    let mut simulator = Simulator::new(state);
    simulator.simulate(request)
}

/// v6 program: write global key "k" = 1, then unconditionally error (`err`
/// opcode). Bytes: pushbytes "k"; pushint 1; app_global_put; err.
fn global_put_then_err_program() -> Vec<u8> {
    vec![
        0x06, // version 6
        0x80, 0x01, b'k', // pushbytes "k"
        0x81, 0x01, // pushint 1
        0x67, // app_global_put
        0x00, // err
    ]
}

#[test]
fn failing_appl_call_preserves_partial_global_state_in_apply_data() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, global_put_then_err_program());

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation returns a result");
    let group = &result.txn_groups[0];

    // The group must report the failure (the approval program's `err`
    // aborts execution)...
    assert!(
        group.failure_message.is_some(),
        "expected the erroring approval program to fail the group"
    );
    assert_eq!(group.failed_at.as_deref(), Some([0].as_slice()));

    // ...but the failing transaction's ApplyData must still carry the
    // global-state write that happened before the `err` opcode, not `None`.
    let txn_result = &group.txn_results[0];
    let apply_data = txn_result
        .apply_data
        .as_ref()
        .expect("partial ApplyData must be preserved on execution failure");
    let eval_delta_wire = apply_data
        .eval_delta
        .as_ref()
        .expect("partial EvalDelta must be preserved on execution failure");
    let delta = parse_eval_delta(eval_delta_wire).expect("eval_delta must decode");
    let global = delta
        .global_delta
        .expect("global_delta must be present: the put happened before `err`");
    let k = global
        .get(b"k".as_slice())
        .expect("key \"k\" must be recorded");
    assert_eq!(k.uint, 1);
}

/// A transaction failing for a reason unrelated to `appl` execution (e.g. an
/// app call to a nonexistent app) must NOT get a synthesized ApplyData —
/// there is no EvalDelta to preserve because the program never ran.
#[test]
fn failing_appl_call_to_nonexistent_app_has_no_apply_data() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);
    // No app registered at id 999.

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 999)]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation returns a result");
    let group = &result.txn_groups[0];
    assert!(group.failure_message.is_some());
    assert!(group.txn_results[0].apply_data.is_none());
}

/// A cleanly-rejecting program (returns 0, no runtime error) hits the same
/// `!result.approved` path in `apply_appl` as a runtime error, so it must
/// preserve its accumulated state too — go-algorand doesn't reset EvalDelta
/// on a clean reject (only on an opcode failure), so the full delta computed
/// before `return` is exactly what should be reported.
#[test]
fn cleanly_rejecting_appl_call_preserves_full_state() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);
    // pushbytes "k"; pushint 1; app_global_put; pushint 0; return (rejects
    // cleanly after the state write, no runtime error).
    let program = vec![0x06, 0x80, 0x01, b'k', 0x81, 0x01, 0x67, 0x81, 0x00, 0x43];
    register_app(&mut state, sender, 100, program);

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation returns a result");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_some(),
        "reject still fails the txn"
    );

    let apply_data = group.txn_results[0]
        .apply_data
        .as_ref()
        .expect("partial ApplyData must be preserved on clean rejection too");
    let delta = parse_eval_delta(apply_data.eval_delta.as_ref().unwrap()).unwrap();
    let global = delta.global_delta.expect("global_delta must be present");
    assert_eq!(global.get(b"k".as_slice()).unwrap().uint, 1);
}
