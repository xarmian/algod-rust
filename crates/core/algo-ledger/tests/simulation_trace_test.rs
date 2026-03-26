//! Integration tests for simulation tracing (issue #187).
//!
//! Verifies that the `Simulator` wires the `SimulationTracer` through
//! `apply_transaction_with_tracer` so that execution traces contain
//! opcode-level entries when tracing is enabled.

use std::collections::BTreeMap;

use algo_ledger::simulation::{ExecTraceConfig, SimulationRequest, Simulator};
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::{AccountData, Address, AppParams, SignedTransaction, StateSchema, Transaction};

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
