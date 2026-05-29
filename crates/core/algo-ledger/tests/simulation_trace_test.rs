//! Integration tests for simulation tracing (issue #187).
//!
//! Verifies that the `Simulator` wires the `SimulationTracer` through
//! `apply_transaction_with_tracer` so that execution traces contain
//! opcode-level entries when tracing is enabled.

use std::collections::BTreeMap;

use algo_ledger::simulation::{
    AvmValueTrace, ExecTraceConfig, SimulationRequest, Simulator, SimulatorError, StateChangeKind,
};
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::{
    AccountData, Address, AppParams, LogicSig, SignedTransaction, StateSchema, Transaction,
};
use sha2::{Digest, Sha512_256};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal `LedgerState` with a sender account, fee sink, and an app
/// whose approval program is the given bytecode.
fn setup_state(sender: Address, app_id: u64, approval_program: Vec<u8>) -> LedgerState {
    let fee_sink = Address([0xFE; 32]);

    let mut state = LedgerState::new();
    state.fee_sink = fee_sink;
    state.protocol = algo_types::consensus::CONSENSUS_V41.to_string();

    // Fund the sender so it can pay fees.
    let sender_account = AccountData {
        micro_algos: 10_000_000,
        total_created_apps: 1,
        ..Default::default()
    };
    state.set_account(&sender, sender_account);

    // Fund the fee sink.
    let fee_sink_account = AccountData {
        micro_algos: 0,
        ..Default::default()
    };
    state.set_account(&fee_sink, fee_sink_account);

    // Register the app.
    let app_params = AppParams {
        creator: sender,
        approval_program,
        clear_state_program: vec![0x06, 0x81, 0x01, 0x43], // v6: pushint 1, return
        global_state: BTreeMap::new(),
        local_state_schema: StateSchema::default(),
        global_state_schema: StateSchema::default(),
        extra_program_pages: 0,
    };
    state.set_app_params(app_id, app_params);

    state
}

/// Create an app-call `SignedTransaction`.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// When tracing is enabled the simulation result should contain opcode trace
/// entries for the approval program.
#[test]
fn simulation_trace_captures_approval_opcodes() {
    let sender = Address([0xAA; 32]);
    let app_id = 100;

    // Approval program: version 6, pushint 1, return
    // Bytecode: 0x06 (version), 0x81 0x01 (pushint 1), 0x43 (return)
    let approval = vec![0x06, 0x81, 0x01, 0x43];

    let mut state = setup_state(sender, app_id, approval);
    let txn = make_appl_txn(sender, app_id);

    let request = SimulationRequest {
        txn_groups: vec![vec![txn]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            stack: false,
            scratch: false,
            state: false,
        },
        ..Default::default()
    };

    let mut simulator = Simulator::new(&mut state);
    let result = simulator
        .simulate(request)
        .expect("simulation should succeed");

    // Should have one group with one transaction result.
    assert_eq!(result.txn_groups.len(), 1);
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "simulation should not fail: {:?}",
        group.failure_message
    );
    assert_eq!(group.txn_results.len(), 1);

    // The transaction trace should be present (tracing was enabled).
    let txn_result = &group.txn_results[0];
    let trace = txn_result
        .trace
        .as_ref()
        .expect("trace should be present when tracing is enabled");

    // The approval program trace should have opcode entries.
    let approval_trace = trace
        .approval_program_trace
        .as_ref()
        .expect("approval_program_trace should be present for an app call");

    assert!(
        !approval_trace.opcodes.is_empty(),
        "approval program trace should contain at least one opcode entry"
    );

    // The approval program hash should be captured (SHA-512/256 of the program).
    let expected_hash: [u8; 32] = {
        use sha2::{Digest, Sha512_256};
        let mut h = Sha512_256::new();
        h.update([0x06, 0x81, 0x01, 0x43]);
        h.finalize().into()
    };
    assert_eq!(
        trace.approval_program_hash,
        Some(expected_hash),
        "approval program hash should be the SHA-512/256 of the program bytes"
    );
}

/// When tracing is disabled the transaction trace should be `None`.
#[test]
fn simulation_no_trace_when_disabled() {
    let sender = Address([0xAA; 32]);
    let app_id = 100;

    let approval = vec![0x06, 0x81, 0x01, 0x43];
    let mut state = setup_state(sender, app_id, approval);
    let txn = make_appl_txn(sender, app_id);

    let request = SimulationRequest {
        txn_groups: vec![vec![txn]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: false,
            stack: false,
            scratch: false,
            state: false,
        },
        ..Default::default()
    };

    let mut simulator = Simulator::new(&mut state);
    let result = simulator
        .simulate(request)
        .expect("simulation should succeed");

    let group = &result.txn_groups[0];
    assert!(group.failure_message.is_none());

    let txn_result = &group.txn_results[0];
    assert!(
        txn_result.trace.is_none(),
        "trace should be None when tracing is disabled"
    );
}

/// When stack tracing is enabled, opcode entries should contain stack data.
#[test]
fn simulation_trace_with_stack() {
    let sender = Address([0xAA; 32]);
    let app_id = 100;

    // pushint 1, return — stack should show the push of 1
    let approval = vec![0x06, 0x81, 0x01, 0x43];

    let mut state = setup_state(sender, app_id, approval);
    let txn = make_appl_txn(sender, app_id);

    let request = SimulationRequest {
        txn_groups: vec![vec![txn]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            stack: true,
            scratch: false,
            state: false,
        },
        ..Default::default()
    };

    let mut simulator = Simulator::new(&mut state);
    let result = simulator
        .simulate(request)
        .expect("simulation should succeed");

    let group = &result.txn_groups[0];
    assert!(group.failure_message.is_none());

    let trace = group.txn_results[0]
        .trace
        .as_ref()
        .expect("trace should be present");
    let approval_trace = trace
        .approval_program_trace
        .as_ref()
        .expect("approval trace should be present");

    // The first opcode (pushint 1) should add a value to the stack.
    assert!(!approval_trace.opcodes.is_empty());
    let first_opcode = &approval_trace.opcodes[0];
    assert!(
        !first_opcode.stack_additions.is_empty(),
        "pushint should add a value to the stack trace"
    );
}

/// With state-change tracing on, an app that writes global state should record
/// a per-opcode state change (operation `w`) in the exec trace.
#[test]
fn simulation_captures_state_change_on_global_write() {
    let sender = Address([0xAA; 32]);
    let app_id = 100;
    // v8: pushbytes "w", pushint 42, app_global_put, pushint 1, return
    let approval = vec![0x08, 0x80, 0x01, 0x77, 0x81, 0x2a, 0x67, 0x81, 0x01, 0x43];
    let mut state = setup_state(sender, app_id, approval);
    // Allow one uint global write.
    let mut params = state.get_app_params(app_id).expect("app exists").clone();
    params.global_state_schema = StateSchema {
        num_uint: 1,
        num_byte_slice: 0,
    };
    state.set_app_params(app_id, params);

    let txn = make_appl_txn(sender, app_id);
    let request = SimulationRequest {
        txn_groups: vec![vec![txn]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            stack: false,
            scratch: false,
            state: true,
        },
        ..Default::default()
    };

    let mut simulator = Simulator::new(&mut state);
    let result = simulator
        .simulate(request)
        .expect("simulation should succeed");
    assert!(
        result.txn_groups[0].failure_message.is_none(),
        "simulation should not fail: {:?}",
        result.txn_groups[0].failure_message
    );

    let trace = result.txn_groups[0].txn_results[0]
        .trace
        .as_ref()
        .expect("trace present");
    let approval = trace
        .approval_program_trace
        .as_ref()
        .expect("approval trace present");

    let changes: Vec<_> = approval
        .opcodes
        .iter()
        .flat_map(|u| u.state_changes.iter())
        .collect();
    assert_eq!(changes.len(), 1, "expected exactly one state change");
    assert_eq!(changes[0].kind, StateChangeKind::GlobalState);
    assert_eq!(changes[0].key, b"w");
    assert!(
        matches!(changes[0].new_value, Some(AvmValueTrace::Uint64(42))),
        "expected written value 42, got {:?}",
        changes[0].new_value
    );
}

/// A group whose pooled fees are below the minimum must be rejected by the
/// simulator's check() phase (matching go-algorand's verify.TxnGroup), not
/// silently evaluated.
#[test]
fn simulation_rejects_underpaid_group() {
    let sender = Address([0xAA; 32]);
    let app_id = 100;
    let approval = vec![0x06, 0x81, 0x01, 0x43];
    let mut state = setup_state(sender, app_id, approval);

    // App call with zero fee — below the per-transaction minimum.
    let mut txn = make_appl_txn(sender, app_id);
    txn.txn.fee = 0;

    let request = SimulationRequest {
        txn_groups: vec![vec![txn]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let mut simulator = Simulator::new(&mut state);
    match simulator.simulate(request) {
        Err(SimulatorError::InvalidRequest(e)) => {
            assert!(
                e.message.contains("fees"),
                "expected a group-fee error, got: {}",
                e.message
            );
        }
        other => panic!("expected InvalidRequest fee error, got {other:?}"),
    }
}

/// Approval program (v8) that reads global key "g", pops it, and approves.
/// Bytecode:
///   0x08                version 8
///   0x80 0x01 0x67      pushbytes "g"
///   0x64                app_global_get
///   0x48                pop
///   0x81 0x01           pushint 1
///   0x43                return
fn global_read_program() -> Vec<u8> {
    vec![0x08, 0x80, 0x01, 0x67, 0x64, 0x48, 0x81, 0x01, 0x43]
}

/// Build state with an app whose global state has `"g" => Uint(7)` pre-set, so
/// a read captures a known initial value.
fn setup_state_with_global(sender: Address, app_id: u64, approval_program: Vec<u8>) -> LedgerState {
    let mut state = setup_state(sender, app_id, approval_program);
    let mut params = state.get_app_params(app_id).expect("app exists").clone();
    params
        .global_state
        .insert(b"g".to_vec(), algo_types::TealValue::Uint(7));
    params.global_state_schema = StateSchema {
        num_uint: 1,
        num_byte_slice: 1,
    };
    state.set_app_params(app_id, params);
    state
}

/// With state-change tracing on, simulating an app that reads global state
/// should capture the pre-simulation value under `initial_states`.
#[test]
fn simulation_captures_initial_global_state() {
    let sender = Address([0xAA; 32]);
    let app_id = 100;

    let mut state = setup_state_with_global(sender, app_id, global_read_program());
    let txn = make_appl_txn(sender, app_id);

    let request = SimulationRequest {
        txn_groups: vec![vec![txn]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            stack: false,
            scratch: false,
            state: true,
        },
        ..Default::default()
    };

    let mut simulator = Simulator::new(&mut state);
    let result = simulator
        .simulate(request)
        .expect("simulation should succeed");

    assert!(
        result.txn_groups[0].failure_message.is_none(),
        "simulation should not fail: {:?}",
        result.txn_groups[0].failure_message
    );

    let initial = result
        .initial_states
        .as_ref()
        .expect("initial_states should be present when state tracing is on");
    let app_entry = initial
        .app_initial_states
        .iter()
        .find(|(id, _)| *id == app_id)
        .expect("app should appear in initial states");
    let global = &app_entry.1.global_state;
    assert_eq!(global.len(), 1);
    assert_eq!(global[0].0, b"g");
    assert!(
        matches!(
            global[0].1,
            algo_ledger::simulation::AvmValueTrace::Uint64(7)
        ),
        "captured initial value should be the pre-simulation Uint(7)"
    );
}

/// Without state-change tracing, `initial_states` must be `None` even if the
/// program reads application state.
#[test]
fn simulation_no_initial_states_without_state_config() {
    let sender = Address([0xAA; 32]);
    let app_id = 100;

    let mut state = setup_state_with_global(sender, app_id, global_read_program());
    let txn = make_appl_txn(sender, app_id);

    let request = SimulationRequest {
        txn_groups: vec![vec![txn]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            stack: false,
            scratch: false,
            state: false,
        },
        ..Default::default()
    };

    let mut simulator = Simulator::new(&mut state);
    let result = simulator
        .simulate(request)
        .expect("simulation should succeed");

    assert!(
        result.initial_states.is_none(),
        "initial_states must be None when state tracing is off"
    );
}

// ---------------------------------------------------------------------------
// LogicSig trace capture (TASK-249)
// ---------------------------------------------------------------------------

/// SHA512/256("Program" || program) — the contract-account address.
fn contract_account_address(program: &[u8]) -> Address {
    let mut hasher = Sha512_256::new();
    hasher.update(b"Program");
    hasher.update(program);
    Address(hasher.finalize().into())
}

/// SHA512/256(program) — the LogicSigHash reported in the exec trace.
fn program_hash(program: &[u8]) -> [u8; 32] {
    Sha512_256::digest(program).into()
}

/// A LogicSig-authorized payment, simulated with `exec-trace` enabled, must
/// capture the logic-sig opcode trace and program hash. The LogicSig runs
/// during `check()` (signature verification), so this exercises the tracer
/// threaded through that path.
#[test]
fn simulation_trace_captures_logicsig_program() {
    // v6 program: pushint 1 (approves). The contract account is its hash.
    let program = vec![0x06, 0x81, 0x01];
    let sender = contract_account_address(&program);
    let receiver = Address([0x20; 32]);
    let fee_sink = Address([0xFE; 32]);

    let mut state = LedgerState::new();
    state.fee_sink = fee_sink;
    state.protocol = algo_types::consensus::CONSENSUS_V41.to_string();
    state.set_account(
        &sender,
        AccountData {
            micro_algos: 10_000_000,
            ..Default::default()
        },
    );
    state.set_account(
        &fee_sink,
        AccountData {
            micro_algos: 0,
            ..Default::default()
        },
    );

    let txn = SignedTransaction {
        txn: Transaction {
            txn_type: "pay".into(),
            sender,
            fee: 1000,
            first_valid: 0.into(),
            last_valid: 1000.into(),
            receiver,
            amount: 0,
            ..Default::default()
        },
        lsig: Some(LogicSig {
            logic: serde_bytes::ByteBuf::from(program.clone()),
            sig: [0u8; 64],
            msig: None,
            lmsig: None,
            args: None,
        }),
        ..Default::default()
    };

    let request = SimulationRequest {
        txn_groups: vec![vec![txn]],
        allow_empty_signatures: false,
        trace_config: ExecTraceConfig {
            enable: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut simulator = Simulator::new(&mut state);
    let result = simulator
        .simulate(request)
        .expect("logicsig simulation should succeed");

    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "unexpected failure: {:?}",
        group.failure_message
    );
    let trace = group.txn_results[0]
        .trace
        .as_ref()
        .expect("trace should be present when tracing is enabled");

    let lsig_trace = trace
        .logicsig_trace
        .as_ref()
        .expect("logic-sig trace must be captured");
    assert!(
        !lsig_trace.opcodes.is_empty(),
        "logic-sig trace should contain opcode units"
    );
    assert_eq!(
        trace.logicsig_hash,
        Some(program_hash(&program)),
        "logic-sig hash must be SHA512/256(program)"
    );
    // The payment itself runs no app program, so there is no approval trace.
    assert!(trace.approval_program_trace.is_none());
}

/// An app issuing an inner app call must produce a nested `inner_trace` and the
/// spawning `itxn_submit` opcode must record the inner's index in
/// `spawned_inners` (go-algorand `OpcodeTraceUnit.SpawnedInners`).
#[test]
fn simulation_trace_inner_txn_spawned_inners() {
    let sender = Address([0xAA; 32]);
    let outer_app_id = 100;
    let inner_app_id = 200;

    let inner_approval = vec![0x06, 0x81, 0x01, 0x43]; // v6: pushint 1, return

    // Outer app (v6): itxn_begin; pushint 6 (appl); itxn_field TypeEnum(16);
    // pushint 200; itxn_field ApplicationID(24); itxn_submit; pushint 1; return.
    // Opcodes: itxn_begin=0xb1, itxn_field=0xb2, itxn_submit=0xb3.
    let outer_approval = vec![
        0x06, // version 6
        0xb1, // itxn_begin
        0x81, 0x06, // pushint 6 (appl)
        0xb2, 0x10, // itxn_field TypeEnum (field 16)
        0x81, 0xC8, 0x01, // pushint 200
        0xb2, 0x18, // itxn_field ApplicationID (field 24)
        0xb3, // itxn_submit
        0x81, 0x01, // pushint 1
        0x43, // return
    ];

    let fee_sink = Address([0xFE; 32]);
    let mut state = LedgerState::new();
    state.fee_sink = fee_sink;
    state.protocol = algo_types::consensus::CONSENSUS_V41.to_string();
    state.set_account(
        &sender,
        AccountData {
            micro_algos: 10_000_000,
            total_created_apps: 2,
            ..Default::default()
        },
    );
    state.set_account(
        &fee_sink,
        AccountData {
            micro_algos: 0,
            ..Default::default()
        },
    );
    state.set_app_params(
        outer_app_id,
        AppParams {
            creator: sender,
            approval_program: outer_approval,
            clear_state_program: vec![0x06, 0x81, 0x01, 0x43],
            global_state: BTreeMap::new(),
            local_state_schema: StateSchema::default(),
            global_state_schema: StateSchema::default(),
            extra_program_pages: 0,
        },
    );
    state.set_app_params(
        inner_app_id,
        AppParams {
            creator: sender,
            approval_program: inner_approval,
            clear_state_program: vec![0x06, 0x81, 0x01, 0x43],
            global_state: BTreeMap::new(),
            local_state_schema: StateSchema::default(),
            global_state_schema: StateSchema::default(),
            extra_program_pages: 0,
        },
    );
    // The outer app account must hold a min-balance for the inner app's fee.
    let outer_app_addr = Address(algo_ledger::avm_context::app_address(outer_app_id));
    state.set_account(
        &outer_app_addr,
        AccountData {
            micro_algos: 10_000_000,
            ..Default::default()
        },
    );

    // The inner app must be a referenced resource of the outer call.
    let mut txn = make_appl_txn(sender, outer_app_id);
    txn.txn.foreign_apps = Some(vec![inner_app_id]);
    let request = SimulationRequest {
        txn_groups: vec![vec![txn]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut simulator = Simulator::new(&mut state);
    let result = simulator
        .simulate(request)
        .expect("inner-txn simulation should succeed");

    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "unexpected failure: {:?}",
        group.failure_message
    );
    let trace = group.txn_results[0]
        .trace
        .as_ref()
        .expect("trace should be present");

    // Exactly one inner transaction was spawned.
    assert_eq!(trace.inner_traces.len(), 1, "expected one inner trace");
    assert!(
        trace.inner_traces[0].approval_program_trace.is_some(),
        "inner trace should carry the inner app's approval trace"
    );

    // Exactly one opcode (itxn_submit) records the spawned inner, and its index
    // must point at inner_traces[0].
    let approval = trace
        .approval_program_trace
        .as_ref()
        .expect("approval trace present");
    let spawning: Vec<&Vec<usize>> = approval
        .opcodes
        .iter()
        .map(|u| &u.spawned_inners)
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(
        spawning.len(),
        1,
        "exactly one opcode (itxn_submit) should spawn inners"
    );
    assert_eq!(
        spawning[0],
        &vec![0usize],
        "spawned-inners index must reference inner_traces[0]"
    );
}
