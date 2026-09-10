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
/// Port of go's `TestErrorAfterClearStateError`
/// (`ledger/simulation/simulation_eval_test.go`): a two-txn group where
/// txn0 is a `ClearState` call whose program errors (swallowed per go's
/// "clearing out is always allowed" rule — no EvalDelta, no group
/// failure from that alone), immediately followed in the *same group* by
/// txn1, an ordinary app call against the same app that itself cleanly
/// rejects. The group's real failure must be attributed to txn1 (`failed_at
/// == [1]`), and txn1's partial EvalDelta (the global-state write it made
/// before rejecting) must still be preserved — proving the ClearState
/// swallow doesn't interfere with normal reject/EvalDelta accounting for
/// the transaction that follows it in the group.
#[test]
fn error_after_clear_state_error_fails_group_at_second_txn_not_first() {
    use algo_types::AppLocalState;

    let sender = Address([0xAA; 32]);
    let user = Address([0xBB; 32]);
    let mut state = setup_state(sender);
    state.set_account(
        &user,
        AccountData {
            micro_algos: 10_000_000,
            ..Default::default()
        },
    );

    // Mirrors go's `returnFirstAppArgProgram`: bump a global "counter" on
    // every call, then (unless this is app creation or an OptIn) return
    // the first application arg as the approval result. With no args at
    // all (the ClearState call below), `txn ApplicationArgs 0` errors.
    let program = algo_avm::assembler::assemble_string(
        "#pragma version 6
byte \"counter\"
dup
app_global_get
int 1
+
app_global_put

txn ApplicationID
bz end

txn OnCompletion
int OptIn
==
bnz end

txn ApplicationArgs 0
btoi
return

end:
int 1
return",
    )
    .expect("program must assemble")
    .program;

    let app_id = 100u64;
    register_app(&mut state, sender, app_id, program.clone());
    // The registered clear_state_program from `register_app` is a plain
    // "int 1; return"; override it to match go's test (same program for
    // both approval and clear state) so the ClearState call actually hits
    // the ApplicationArgs-indexing error.
    let mut app_params = state.get_app_params(app_id).expect("app registered").clone();
    app_params.clear_state_program = program;
    state.set_app_params(app_id, app_params);

    // `user` is already opted in to the app (go's `env.OptIntoApp`) with
    // the schema the program's global writes need.
    state.app_local_states.insert(
        (user, app_id),
        AppLocalState {
            schema: StateSchema {
                num_uint: 1,
                num_byte_slice: 0,
            },
            key_value: BTreeMap::new(),
        },
    );
    let mut user_acct = state.get_account(&user).cloned().unwrap();
    user_acct.total_apps_opted_in = 1;
    state.set_account(&user, user_acct);

    const ON_COMPLETION_CLEAR_STATE: u64 = 3;

    let mut clear_state_txn = make_appl_txn(user, app_id);
    clear_state_txn.txn.on_completion = ON_COMPLETION_CLEAR_STATE;
    clear_state_txn.txn.app_arguments = None; // no app args -> ClearState program errors

    let mut other_appl_call = make_appl_txn(user, app_id);
    other_appl_call.txn.app_arguments = Some(vec![Some(serde_bytes::ByteBuf::from(vec![0u8]))]);

    let request = SimulationRequest {
        txn_groups: vec![vec![clear_state_txn, other_appl_call]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation returns a result");
    let group = &result.txn_groups[0];

    assert!(
        group.failure_message.is_some(),
        "txn1's clean rejection must fail the group"
    );
    assert_eq!(
        group.failed_at.as_deref(),
        Some([1usize].as_slice()),
        "the ClearState error (txn0) is swallowed; the real failure is txn1's reject"
    );

    // txn0 (ClearState): the error is swallowed, so no EvalDelta is
    // preserved -- mirrors go's "No EvalDelta changes because the clear
    // state failed".
    let clear_state_result = &group.txn_results[0];
    if let Some(apply_data) = clear_state_result.apply_data.as_ref() {
        assert!(
            apply_data.eval_delta.is_none()
                || parse_eval_delta(apply_data.eval_delta.as_ref().unwrap())
                    .unwrap()
                    .global_delta
                    .is_none(),
            "a swallowed ClearState error must not surface a global-state EvalDelta"
        );
    }

    // txn1 (ordinary app call, cleanly rejects): its partial global-state
    // write (the "counter" bump) must still be preserved, same as
    // `cleanly_rejecting_appl_call_preserves_full_state` above.
    let other_result = &group.txn_results[1];
    let apply_data = other_result
        .apply_data
        .as_ref()
        .expect("partial ApplyData must be preserved on txn1's clean rejection");
    let delta = parse_eval_delta(apply_data.eval_delta.as_ref().unwrap()).unwrap();
    let global = delta
        .global_delta
        .expect("global_delta must be present: the counter bump happened before reject");
    assert!(
        global.contains_key(b"counter".as_slice()),
        "counter key must be recorded"
    );
}

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
