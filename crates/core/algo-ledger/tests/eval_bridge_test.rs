//! Integration tests for the transaction evaluation bridge (Epic 20b).
//!
//! Tests cover:
//! - W4.1: Approval program gates transaction success in Execute mode
//! - W4.2: ClearState always clears local state regardless of program outcome
//! - W4.3: Pooled budget across app call groups
//! - W4.4: LogicSig mode restrictions (verified via existing tests)
//! - W4.5: Replay mode regression (existing patterns still work)

use std::cell::Cell;
use std::collections::BTreeMap;

use algo_avm::context::NullContext;
use algo_avm::eval::{run_approval_program, AvmResult};
use algo_avm::group::{GroupBudget, GroupContext};
use algo_ledger::{
    apply_block_with_delta, apply_block_with_delta_mode, apply_block_with_mode, apply_transaction,
    ApplyContext, ApplyMode, LedgerState,
};
use algo_types::{
    Address, AppLocalState, AppParams, Block, Round, SignedTransaction, StateSchema, TealValue,
    Transaction,
};

// ===========================================================================
// Constants
// ===========================================================================

/// AVM version 6 byte.
const AVM_V6: u8 = 0x06;

/// `pushint 1` opcode + immediate: approval.
const PUSHINT_1: [u8; 2] = [0x81, 0x01];

/// `pushint 0` opcode + immediate: rejection.
const PUSHINT_0: [u8; 2] = [0x81, 0x00];

/// `err` opcode: always errors.
const ERR_OPCODE: u8 = 0x00;

// ===========================================================================
// Helpers
// ===========================================================================

/// Build a raw AVM program: version byte + code bytes.
fn prog(version: u8, code: &[u8]) -> Vec<u8> {
    let mut p = vec![version];
    p.extend_from_slice(code);
    p
}

/// Build a minimal program that approves (returns 1).
fn approval_program() -> Vec<u8> {
    prog(AVM_V6, &PUSHINT_1)
}

/// Build a minimal program that rejects (returns 0).
fn rejection_program() -> Vec<u8> {
    prog(AVM_V6, &PUSHINT_0)
}

/// Build a minimal program that errors at runtime.
fn error_program() -> Vec<u8> {
    prog(AVM_V6, &[ERR_OPCODE])
}

/// Build a v8 program that `box_put`s `value` under `name` and approves.
/// Requires the caller to supply a matching box reference on the
/// transaction (`appl_noop_txn_with_box`) and pre-existing content of the
/// same length if the box already exists (`box_put` requires an exact-size
/// replacement, matching go-algorand).
fn box_put_program(name: &str, value: &str) -> Vec<u8> {
    let source =
        format!("#pragma version 8\nbyte \"{name}\"\nbyte \"{value}\"\nbox_put\nint 1\nreturn\n");
    algo_avm::assembler::assemble_string(&source)
        .expect("box_put program must assemble")
        .program
}

/// Build a v8 program that `box_del`s `name` and approves.
fn box_del_program(name: &str) -> Vec<u8> {
    let source = format!("#pragma version 8\nbyte \"{name}\"\nbox_del\npop\nint 1\nreturn\n");
    algo_avm::assembler::assemble_string(&source)
        .expect("box_del program must assemble")
        .program
}

/// Create a LedgerState with the given balances and fee sink.
fn make_state(balances: &[(Address, u64)], fee_sink: Address) -> LedgerState {
    let mut state = LedgerState::new();
    state.fee_sink = fee_sink;
    for (addr, bal) in balances {
        let acct = state.get_or_default_account_mut(addr);
        acct.micro_algos = *bal;
    }
    state
}

/// Create an Execute-mode ApplyContext.
fn execute_ctx(fee_sink: Address, round: u64) -> ApplyContext {
    ApplyContext {
        rewards_level: 0,
        fee_sink,
        round,
        mode: ApplyMode::Execute,
        validate: false,
        latest_timestamp: 0,
        genesis_hash: [0u8; 32],
        txn_counter: Cell::new(0),
        fee_credit: Cell::new(0),
        txn_index: Cell::new(0),
        consensus: algo_types::ConsensusParams::default(),
        avm_overrides: Default::default(),
        failed_eval_delta: Cell::new(None),
        kv_mods_recorder: None,
    }
}

/// Create a Replay-mode ApplyContext.
fn replay_ctx(fee_sink: Address, round: u64) -> ApplyContext {
    ApplyContext::new_replay(0, fee_sink, round)
}

/// Create an app in the ledger with given approval and clear-state programs.
fn create_app(
    state: &mut LedgerState,
    app_id: u64,
    creator: Address,
    approval: Vec<u8>,
    clear: Vec<u8>,
) {
    state.app_params.insert(
        app_id,
        AppParams {
            creator,
            approval_program: approval,
            clear_state_program: clear,
            global_state: BTreeMap::new(),
            local_state_schema: StateSchema {
                num_uint: 4,
                num_byte_slice: 4,
            },
            global_state_schema: StateSchema {
                num_uint: 4,
                num_byte_slice: 4,
            },
            extra_program_pages: 0,
            ..Default::default()
        },
    );

    // Increment creator's total_created_apps so min balance checks pass.
    let acct = state.get_or_default_account_mut(&creator);
    acct.total_created_apps += 1;
}

/// Opt an account into an app (set up local state and account counters).
fn opt_in_account(state: &mut LedgerState, addr: &Address, app_id: u64) {
    state.app_local_states.insert(
        (*addr, app_id),
        AppLocalState {
            schema: StateSchema {
                num_uint: 4,
                num_byte_slice: 4,
            },
            key_value: BTreeMap::new(),
        },
    );
    let acct = state.get_or_default_account_mut(addr);
    acct.total_apps_opted_in += 1;
}

/// Build an appl SignedTransaction for an existing app (NoOp on_completion).
fn appl_noop_txn(sender: Address, app_id: u64, fee: u64) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: "appl".into(),
            sender,
            fee,
            first_valid: 1.into(),
            last_valid: 100.into(),
            application_id: app_id,
            on_completion: 0, // NoOp
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Build an appl SignedTransaction for an existing app, with a box reference
/// naming `box_name` on the called app itself (index 0), for tests exercising
/// box opcodes (issue #570).
fn appl_noop_txn_with_box(
    sender: Address,
    app_id: u64,
    fee: u64,
    box_name: &[u8],
) -> SignedTransaction {
    use algo_types::BoxRef;
    use serde_bytes::ByteBuf;
    let mut stx = appl_noop_txn(sender, app_id, fee);
    stx.txn.boxes = Some(vec![BoxRef {
        index: 0,
        name: Some(ByteBuf::from(box_name.to_vec())),
    }]);
    stx
}

/// Build an appl SignedTransaction with ClearState on_completion.
fn appl_clearstate_txn(sender: Address, app_id: u64, fee: u64) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: "appl".into(),
            sender,
            fee,
            first_valid: 1.into(),
            last_valid: 100.into(),
            application_id: app_id,
            on_completion: 3, // ClearState
            ..Default::default()
        },
        ..Default::default()
    }
}

// ===========================================================================
// W4.1: Approval program gates transaction success
// ===========================================================================

/// In Execute mode, when the approval program returns 1 (approve),
/// the app call transaction succeeds.
#[test]
fn execute_mode_approval_program_approves() {
    let creator = Address([1u8; 32]);
    let sender = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (sender, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );

    let app_id = 100u64;
    create_app(
        &mut state,
        app_id,
        creator,
        approval_program(),
        approval_program(),
    );

    let ctx = execute_ctx(fee_sink, 1);
    let stx = appl_noop_txn(sender, app_id, 1_000);

    // Should succeed because the approval program returns 1.
    let result = apply_transaction(&mut state, &stx, &ctx, 0);
    assert!(
        result.is_ok(),
        "approval program that returns 1 should succeed: {:?}",
        result.err()
    );

    // Fee should have been deducted from sender.
    let sender_acct = state.get_account(&sender).unwrap();
    assert_eq!(sender_acct.micro_algos, 50_000_000 - 1_000);
}

/// In Execute mode, when the approval program returns 0 (reject),
/// the app call transaction fails.
#[test]
fn execute_mode_approval_program_rejects() {
    let creator = Address([1u8; 32]);
    let sender = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (sender, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );

    let app_id = 101u64;
    create_app(
        &mut state,
        app_id,
        creator,
        rejection_program(),
        approval_program(),
    );

    let ctx = execute_ctx(fee_sink, 1);
    let stx = appl_noop_txn(sender, app_id, 1_000);

    // Should fail because the approval program returns 0.
    let result = apply_transaction(&mut state, &stx, &ctx, 0);
    assert!(
        result.is_err(),
        "approval program that returns 0 should fail"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("rejected"),
        "error should mention rejection: {}",
        err_msg
    );

    // Transaction rolled back: sender balance unchanged.
    let sender_acct = state.get_account(&sender).unwrap();
    assert_eq!(sender_acct.micro_algos, 50_000_000);
}

/// In Execute mode, when the approval program has a runtime error,
/// the app call transaction fails.
#[test]
fn execute_mode_approval_program_errors() {
    let creator = Address([1u8; 32]);
    let sender = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (sender, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );

    let app_id = 102u64;
    create_app(
        &mut state,
        app_id,
        creator,
        error_program(),
        approval_program(),
    );

    let ctx = execute_ctx(fee_sink, 1);
    let stx = appl_noop_txn(sender, app_id, 1_000);

    // Should fail because the approval program errors.
    let result = apply_transaction(&mut state, &stx, &ctx, 0);
    assert!(
        result.is_err(),
        "approval program that errors should fail the txn"
    );

    // Transaction rolled back: sender balance unchanged.
    let sender_acct = state.get_account(&sender).unwrap();
    assert_eq!(sender_acct.micro_algos, 50_000_000);
}

/// In Execute mode, an app with an empty approval program should fail.
#[test]
fn execute_mode_empty_approval_program_fails() {
    let creator = Address([1u8; 32]);
    let sender = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (sender, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );

    let app_id = 103u64;
    // Create app with empty approval program.
    create_app(&mut state, app_id, creator, vec![], approval_program());

    let ctx = execute_ctx(fee_sink, 1);
    let stx = appl_noop_txn(sender, app_id, 1_000);

    let result = apply_transaction(&mut state, &stx, &ctx, 0);
    assert!(
        result.is_err(),
        "empty approval program should fail in Execute mode"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("empty approval program"),
        "error should mention empty approval program: {}",
        err_msg
    );
}

// ===========================================================================
// W4.2: ClearState always clears local state
// ===========================================================================

/// ClearState in Execute mode where program succeeds -- local state is cleared.
#[test]
fn clearstate_execute_program_succeeds_clears_local_state() {
    let creator = Address([1u8; 32]);
    let sender = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (sender, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );

    let app_id = 200u64;
    create_app(
        &mut state,
        app_id,
        creator,
        approval_program(),
        approval_program(), // clear-state program that approves
    );

    // Opt sender into the app with some local state.
    opt_in_account(&mut state, &sender, app_id);
    {
        let local = state.app_local_states.get_mut(&(sender, app_id)).unwrap();
        local
            .key_value
            .insert(b"mykey".to_vec(), TealValue::Uint(42));
    }

    // Verify local state exists before ClearState.
    assert!(state.get_app_local_state(&sender, app_id).is_some());

    let ctx = execute_ctx(fee_sink, 1);
    let stx = appl_clearstate_txn(sender, app_id, 1_000);

    let result = apply_transaction(&mut state, &stx, &ctx, 0);
    assert!(
        result.is_ok(),
        "ClearState with approving program should succeed: {:?}",
        result.err()
    );

    // Local state should be cleared.
    assert!(
        state.get_app_local_state(&sender, app_id).is_none(),
        "local state should be cleared after ClearState"
    );

    // Account counters should be decremented.
    let sender_acct = state.get_account(&sender).unwrap();
    assert_eq!(sender_acct.total_apps_opted_in, 0);
}

/// ClearState in Execute mode where program rejects -- local state is STILL
/// cleared. This is the key ClearState behavior: the program result does not
/// affect whether local state is removed.
#[test]
fn clearstate_execute_program_rejects_still_clears_local_state() {
    let creator = Address([1u8; 32]);
    let sender = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (sender, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );

    let app_id = 201u64;
    create_app(
        &mut state,
        app_id,
        creator,
        approval_program(),
        rejection_program(), // clear-state program that rejects
    );

    // Opt sender into the app with some local state.
    opt_in_account(&mut state, &sender, app_id);
    {
        let local = state.app_local_states.get_mut(&(sender, app_id)).unwrap();
        local
            .key_value
            .insert(b"mykey".to_vec(), TealValue::Uint(99));
    }

    assert!(state.get_app_local_state(&sender, app_id).is_some());

    let ctx = execute_ctx(fee_sink, 1);
    let stx = appl_clearstate_txn(sender, app_id, 1_000);

    let result = apply_transaction(&mut state, &stx, &ctx, 0);
    assert!(
        result.is_ok(),
        "ClearState should succeed even when program rejects: {:?}",
        result.err()
    );

    // Local state should STILL be cleared despite program rejection.
    assert!(
        state.get_app_local_state(&sender, app_id).is_none(),
        "local state should be cleared even when clear-state program rejects"
    );

    // Account counters should be decremented.
    let sender_acct = state.get_account(&sender).unwrap();
    assert_eq!(sender_acct.total_apps_opted_in, 0);
}

/// ClearState in Execute mode where program errors -- local state is STILL
/// cleared.
#[test]
fn clearstate_execute_program_errors_still_clears_local_state() {
    let creator = Address([1u8; 32]);
    let sender = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (sender, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );

    let app_id = 202u64;
    create_app(
        &mut state,
        app_id,
        creator,
        approval_program(),
        error_program(), // clear-state program that errors
    );

    // Opt sender into the app.
    opt_in_account(&mut state, &sender, app_id);

    assert!(state.get_app_local_state(&sender, app_id).is_some());

    let ctx = execute_ctx(fee_sink, 1);
    let stx = appl_clearstate_txn(sender, app_id, 1_000);

    let result = apply_transaction(&mut state, &stx, &ctx, 0);
    assert!(
        result.is_ok(),
        "ClearState should succeed even when program errors: {:?}",
        result.err()
    );

    // Local state should be cleared even after program error.
    assert!(
        state.get_app_local_state(&sender, app_id).is_none(),
        "local state should be cleared even when clear-state program errors"
    );
}

/// ClearState in Execute mode when the app has been deleted -- local state
/// is still cleared (allows users to reclaim min balance).
#[test]
fn clearstate_execute_deleted_app_clears_local_state() {
    let creator = Address([1u8; 32]);
    let sender = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (sender, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );

    let app_id = 203u64;
    create_app(
        &mut state,
        app_id,
        creator,
        approval_program(),
        approval_program(),
    );

    // Opt sender into the app.
    opt_in_account(&mut state, &sender, app_id);
    assert!(state.get_app_local_state(&sender, app_id).is_some());

    // Simulate app deletion: remove app params.
    state.app_params.remove(&app_id);

    let ctx = execute_ctx(fee_sink, 1);
    let stx = appl_clearstate_txn(sender, app_id, 1_000);

    let result = apply_transaction(&mut state, &stx, &ctx, 0);
    assert!(
        result.is_ok(),
        "ClearState for deleted app should succeed: {:?}",
        result.err()
    );

    // Local state should be cleared.
    assert!(
        state.get_app_local_state(&sender, app_id).is_none(),
        "local state should be cleared for deleted app"
    );
}

// ===========================================================================
// W4.3: Pooled budget across group
// ===========================================================================

/// GroupContext with 2 app calls has budget of 1400 (2 * 700).
#[test]
fn group_context_two_app_calls_budget_is_1400() {
    let ctx = GroupContext::new(2);
    assert_eq!(ctx.budget.remaining(), 1400);
    assert_eq!(ctx.num_app_calls, 2);
    assert_eq!(ctx.app_call_index, 0);
}

/// GroupBudget is consumed across sequential app call executions.
#[test]
fn group_budget_consumed_across_calls() {
    let mut budget = GroupBudget::new(2);
    assert_eq!(budget.remaining(), 1400);

    // First call consumes 3 opcodes (intcblock/intc_0/return each cost 1).
    budget.consume(3).unwrap();
    assert_eq!(budget.remaining(), 1397);

    // Second call consumes 5 more.
    budget.consume(5).unwrap();
    assert_eq!(budget.remaining(), 1392);
}

/// Exceeding pooled budget fails with an error.
#[test]
fn group_budget_exhaustion_fails() {
    let mut budget = GroupBudget::new(1); // 700 total
    assert_eq!(budget.remaining(), 700);

    // Consume most of the budget.
    budget.consume(690).unwrap();
    assert_eq!(budget.remaining(), 10);

    // Trying to consume more than remaining fails.
    let result = budget.consume(11);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("pooled budget exhausted"),
        "error should mention budget exhaustion: {}",
        err_msg
    );

    // Budget should not have changed on failure.
    assert_eq!(budget.remaining(), 10);
}

/// GroupContext tracks app call index advancement.
#[test]
fn group_context_advance_tracks_index() {
    let mut ctx = GroupContext::new(3);
    assert_eq!(ctx.app_call_index, 0);
    ctx.advance_app_call();
    assert_eq!(ctx.app_call_index, 1);
    ctx.advance_app_call();
    assert_eq!(ctx.app_call_index, 2);
}

/// GroupBudget with 0 app calls has 0 budget.
#[test]
fn group_budget_zero_app_calls() {
    let budget = GroupBudget::new(0);
    assert_eq!(budget.remaining(), 0);
}

/// Verify that approval program execution in Execute mode consumes from the
/// group budget (GroupBudget is shared, not per-call).
#[test]
fn execute_mode_consumes_group_budget() {
    // This test verifies budget mechanics at the AVM level.
    // A program with 2 opcodes (pushint 1) consumes 1 unit of budget.
    use algo_avm::context::NullContext;
    use algo_avm::eval::run_approval_program;

    let raw = prog(AVM_V6, &PUSHINT_1); // pushint 1 (1 opcode)
    let mut ctx = NullContext;
    let mut budget = GroupBudget::new(2); // 1400 total

    let before = budget.remaining();
    let result = run_approval_program(&raw, &mut ctx, &mut budget).unwrap();
    assert!(result.approved);

    let after = budget.remaining();
    assert!(
        after < before,
        "budget should decrease after execution: before={before}, after={after}"
    );

    // pushint costs 1 opcode unit.
    assert_eq!(before - after, 1);
}

// ===========================================================================
// W4.5: Replay mode regression
// ===========================================================================

/// Verify that existing Replay-mode app creation + NoOp works exactly as before.
#[test]
fn replay_mode_appl_create_still_works() {
    let creator = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(&[(creator, 50_000_000), (fee_sink, 0)], fee_sink);
    let ctx = replay_ctx(fee_sink, 1);

    let app_id = 500u64;
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "appl".into();
    stx.txn.sender = creator;
    stx.txn.fee = 1_000;
    stx.txn.application_id = 0; // creation
    stx.txn.on_completion = 0; // NoOp
    stx.txn.approval_program = Some(serde_bytes::ByteBuf::from(approval_program()));
    stx.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(approval_program()));
    stx.txn.local_state_schema = Some(StateSchema {
        num_uint: 2,
        num_byte_slice: 1,
    });
    stx.txn.global_state_schema = Some(StateSchema {
        num_uint: 1,
        num_byte_slice: 0,
    });
    stx.apply_data_application_id = app_id;

    let result = apply_transaction(&mut state, &stx, &ctx, 0);
    assert!(
        result.is_ok(),
        "Replay-mode app creation should work: {:?}",
        result.err()
    );

    // App should exist with correct schemas.
    let app = state.get_app_params(app_id).unwrap();
    assert_eq!(app.local_state_schema.num_uint, 2);
    assert_eq!(app.global_state_schema.num_uint, 1);
    assert_eq!(app.creator, creator);
}

/// Verify that Replay-mode ClearState with EvalDelta works correctly.
#[test]
fn replay_mode_clearstate_clears_local_state() {
    let creator = Address([1u8; 32]);
    let sender = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (sender, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );
    let ctx = replay_ctx(fee_sink, 1);

    let app_id = 501u64;

    // Create app in Replay mode.
    let mut create_stx = SignedTransaction::default();
    create_stx.txn.txn_type = "appl".into();
    create_stx.txn.sender = creator;
    create_stx.txn.fee = 1_000;
    create_stx.txn.application_id = 0;
    create_stx.txn.on_completion = 0;
    create_stx.txn.approval_program = Some(serde_bytes::ByteBuf::from(approval_program()));
    create_stx.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(approval_program()));
    create_stx.txn.local_state_schema = Some(StateSchema {
        num_uint: 2,
        num_byte_slice: 1,
    });
    create_stx.txn.global_state_schema = Some(StateSchema {
        num_uint: 1,
        num_byte_slice: 0,
    });
    create_stx.apply_data_application_id = app_id;
    apply_transaction(&mut state, &create_stx, &ctx, 0).unwrap();

    // Opt in sender.
    let mut optin_stx = SignedTransaction::default();
    optin_stx.txn.txn_type = "appl".into();
    optin_stx.txn.sender = sender;
    optin_stx.txn.fee = 1_000;
    optin_stx.txn.application_id = app_id;
    optin_stx.txn.on_completion = 1; // OptIn
    apply_transaction(&mut state, &optin_stx, &ctx, 0).unwrap();

    assert!(state.get_app_local_state(&sender, app_id).is_some());

    // ClearState in Replay mode.
    let clear_stx = appl_clearstate_txn(sender, app_id, 1_000);
    let result = apply_transaction(&mut state, &clear_stx, &ctx, 0);
    assert!(
        result.is_ok(),
        "Replay-mode ClearState should work: {:?}",
        result.err()
    );

    // Local state should be cleared.
    assert!(
        state.get_app_local_state(&sender, app_id).is_none(),
        "local state should be cleared in Replay mode ClearState"
    );
}

/// Verify that Replay mode does NOT run the approval program (uses EvalDelta).
/// An app with a rejection program should succeed in Replay mode because
/// the program is not executed.
#[test]
fn replay_mode_does_not_execute_program() {
    let creator = Address([1u8; 32]);
    let sender = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (sender, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );

    let app_id = 502u64;
    // Create app with a REJECTION approval program.
    create_app(
        &mut state,
        app_id,
        creator,
        rejection_program(),
        approval_program(),
    );

    let ctx = replay_ctx(fee_sink, 1);
    let stx = appl_noop_txn(sender, app_id, 1_000);

    // In Replay mode, the program is NOT executed, so even though the
    // approval program would reject, the transaction should succeed.
    let result = apply_transaction(&mut state, &stx, &ctx, 0);
    assert!(
        result.is_ok(),
        "Replay mode should not execute approval program: {:?}",
        result.err()
    );
}

// ===========================================================================
// Additional Execute mode edge cases
// ===========================================================================

/// Execute mode with app creation (application_id == 0): the approval program
/// from the transaction fields is used, not from existing app params.
#[test]
fn execute_mode_app_creation_runs_approval_program() {
    let creator = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(&[(creator, 50_000_000), (fee_sink, 0)], fee_sink);
    let ctx = execute_ctx(fee_sink, 1);

    let app_id = 600u64;
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "appl".into();
    stx.txn.sender = creator;
    stx.txn.fee = 1_000;
    stx.txn.application_id = 0; // creation
    stx.txn.on_completion = 0; // NoOp
    stx.txn.approval_program = Some(serde_bytes::ByteBuf::from(approval_program()));
    stx.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(approval_program()));
    stx.txn.local_state_schema = Some(StateSchema {
        num_uint: 2,
        num_byte_slice: 1,
    });
    stx.txn.global_state_schema = Some(StateSchema {
        num_uint: 1,
        num_byte_slice: 0,
    });
    stx.apply_data_application_id = app_id;

    let result = apply_transaction(&mut state, &stx, &ctx, 0);
    assert!(
        result.is_ok(),
        "Execute mode app creation with approving program should succeed: {:?}",
        result.err()
    );

    // App should exist.
    let app = state.get_app_params(app_id).unwrap();
    assert_eq!(app.creator, creator);
}

/// Verify that ClearState with an empty clear-state program still clears
/// local state (program is simply not run).
#[test]
fn clearstate_execute_empty_clear_program_still_clears() {
    let creator = Address([1u8; 32]);
    let sender = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (sender, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );

    let app_id = 700u64;
    create_app(
        &mut state,
        app_id,
        creator,
        approval_program(),
        vec![], // empty clear-state program
    );

    opt_in_account(&mut state, &sender, app_id);
    assert!(state.get_app_local_state(&sender, app_id).is_some());

    let ctx = execute_ctx(fee_sink, 1);
    let stx = appl_clearstate_txn(sender, app_id, 1_000);

    let result = apply_transaction(&mut state, &stx, &ctx, 0);
    assert!(
        result.is_ok(),
        "ClearState with empty clear program should still succeed: {:?}",
        result.err()
    );

    // Local state should be cleared even with empty program.
    assert!(
        state.get_app_local_state(&sender, app_id).is_none(),
        "local state should be cleared even with empty clear-state program"
    );
}

// ===========================================================================
// P1: Seed inner creatable counter from block txn_counter
// ===========================================================================

/// Two app calls in the same block both issue inner acfg creates.
/// With the txn_counter properly seeded and incremented, the two inner
/// creates should produce distinct asset IDs (not both ID 1).
#[test]
fn two_app_calls_produce_distinct_inner_asset_ids() {
    use algo_ledger::avm_context::app_address;

    let fee_sink = Address([0xFE; 32]);
    let sender = Address([0x01; 32]);
    let app_id = 100u64;

    // AVM v6 program that creates an inner acfg asset:
    //   itxn_begin
    //   pushint 3          (TypeEnum = acfg)
    //   itxn_field TypeEnum (field 16)
    //   pushint 100        (ConfigAssetTotal)
    //   itxn_field ConfigAssetTotal (field 34)
    //   itxn_submit
    //   pushint 1          (approve)
    //   return
    let inner_acfg_program: Vec<u8> = vec![
        0x06, // version 6
        0xb1, // itxn_begin
        0x81, 0x03, // pushint 3 (acfg)
        0xb2, 0x10, // itxn_field TypeEnum
        0x81, 0x64, // pushint 100 (total)
        0xb2, 0x22, // itxn_field ConfigAssetTotal
        0xb3, // itxn_submit
        0x81, 0x01, // pushint 1
        0x43, // return
    ];

    let mut state = make_state(
        &[
            (sender, 10_000_000),
            (fee_sink, 0),
            // Fund the app address so it can hold created assets.
            (Address(app_address(app_id)), 10_000_000),
        ],
        fee_sink,
    );

    create_app(
        &mut state,
        app_id,
        sender,
        inner_acfg_program.clone(),
        prog(AVM_V6, &PUSHINT_1),
    );

    // Set up the context with a starting txn_counter of 200 (simulating
    // a block where the previous block's counter was 200).
    let ctx = ApplyContext {
        rewards_level: 0,
        fee_sink,
        round: 1,
        mode: ApplyMode::Execute,
        validate: false,
        latest_timestamp: 0,
        genesis_hash: [0u8; 32],
        txn_counter: Cell::new(200),
        fee_credit: Cell::new(0),
        txn_index: Cell::new(0),
        consensus: algo_types::ConsensusParams::default(),
        avm_overrides: Default::default(),
        failed_eval_delta: Cell::new(None),
        kv_mods_recorder: None,
    };

    // First app call: fee=1000 (no overpayment).
    let stx1 = appl_noop_txn(sender, app_id, 1_000);
    // Manually set fee_credit for this single-txn group (no overpayment).
    ctx.fee_credit.set(0);
    let result1 = apply_transaction(&mut state, &stx1, &ctx, 0);
    assert!(
        result1.is_ok(),
        "first app call failed: {:?}",
        result1.err()
    );

    // After first app call: txn_counter should have advanced.
    // base=200, +1 for top-level txn, +1 for inner txn = 202.
    let counter_after_first = ctx.txn_counter.get();
    assert!(
        counter_after_first > 200,
        "txn_counter should have advanced from 200, got {}",
        counter_after_first
    );

    // Second app call: same app, same program.
    let stx2 = appl_noop_txn(sender, app_id, 1_000);
    ctx.fee_credit.set(0);
    let result2 = apply_transaction(&mut state, &stx2, &ctx, 0);
    assert!(
        result2.is_ok(),
        "second app call failed: {:?}",
        result2.err()
    );

    // After second app call: counter advanced further.
    let counter_after_second = ctx.txn_counter.get();
    assert!(
        counter_after_second > counter_after_first,
        "txn_counter should have advanced further, was {} now {}",
        counter_after_first,
        counter_after_second
    );

    // The first inner acfg should have created asset with ID = 201+1 = 202,
    // and the second with a higher ID. They must be distinct.
    // The inner create uses txn_counter+1 where txn_counter was the value
    // at the time of incTxnCount inside itxn_submit.
    // Verify that two different assets exist (not just one).
    let mut created_asset_ids: Vec<u64> = state.asset_params.keys().copied().collect();
    created_asset_ids.sort();
    assert!(
        created_asset_ids.len() >= 2,
        "expected at least 2 created assets, got {:?}",
        created_asset_ids
    );
    assert_ne!(
        created_asset_ids[0], created_asset_ids[1],
        "both inner creates produced the same asset ID: {}",
        created_asset_ids[0]
    );
}

// ===========================================================================
// P2: Initialize AVM fee credit from outer group overpayment
// ===========================================================================

/// App call with fee=2000 issues an inner pay with fee=0.
/// The overpayment (2000 - 1000 = 1000) should provide enough fee credit
/// for the inner transaction (which needs MinTxnFee = 1000).
#[test]
fn fee_credit_from_outer_overpayment_enables_inner_zero_fee() {
    use algo_ledger::avm_context::app_address;

    let fee_sink = Address([0xFE; 32]);
    let sender = Address([0x01; 32]);
    let app_id = 200u64;

    // AVM v6 program that creates an inner pay with explicit fee=0:
    //   itxn_begin
    //   pushint 1          (TypeEnum = pay)
    //   itxn_field TypeEnum
    //   txn Sender          (push outer sender address)
    //   itxn_field Receiver  (field 7)
    //   pushint 0           (Amount = 0)
    //   itxn_field Amount    (field 8)
    //   pushint 0           (Fee = 0)
    //   itxn_field Fee       (field 1)
    //   itxn_submit
    //   pushint 1
    //   return
    let inner_pay_zero_fee: Vec<u8> = vec![
        0x06, // version 6
        0xb1, // itxn_begin
        0x81, 0x01, // pushint 1 (pay)
        0xb2, 0x10, // itxn_field TypeEnum
        0x31, 0x00, // txn Sender
        0xb2, 0x07, // itxn_field Receiver
        0x81, 0x00, // pushint 0 (amount)
        0xb2, 0x08, // itxn_field Amount
        0x81, 0x00, // pushint 0 (fee)
        0xb2, 0x01, // itxn_field Fee
        0xb3, // itxn_submit
        0x81, 0x01, // pushint 1
        0x43, // return
    ];

    let mut state = make_state(
        &[
            (sender, 10_000_000),
            (fee_sink, 0),
            // Fund the app address so min balance checks pass.
            (Address(app_address(app_id)), 10_000_000),
        ],
        fee_sink,
    );

    create_app(
        &mut state,
        app_id,
        sender,
        inner_pay_zero_fee.clone(),
        prog(AVM_V6, &PUSHINT_1),
    );

    // fee=2000, so overpayment = 2000 - 1000 = 1000. This should cover the
    // inner pay's MinTxnFee of 1000 when fee=0.
    let stx = SignedTransaction {
        txn: Transaction {
            txn_type: "appl".into(),
            sender,
            fee: 2_000,
            first_valid: 1.into(),
            last_valid: 100.into(),
            application_id: app_id,
            on_completion: 0,
            ..Default::default()
        },
        ..Default::default()
    };

    // Set fee_credit to simulate group-level overpayment:
    // single txn group, fee=2000, needs MinTxnFee=1000, credit = 1000.
    let ctx = ApplyContext {
        rewards_level: 0,
        fee_sink,
        round: 1,
        mode: ApplyMode::Execute,
        validate: false,
        latest_timestamp: 0,
        genesis_hash: [0u8; 32],
        txn_counter: Cell::new(0),
        fee_credit: Cell::new(2_000 - 1_000), // overpayment
        txn_index: Cell::new(0),
        consensus: algo_types::ConsensusParams::default(),
        avm_overrides: Default::default(),
        failed_eval_delta: Cell::new(None),
        kv_mods_recorder: None,
    };

    let result = apply_transaction(&mut state, &stx, &ctx, 0);
    assert!(
        result.is_ok(),
        "app call with inner fee=0 should succeed with fee credit: {:?}",
        result.err()
    );
}

/// Without fee credit, an inner pay with fee=0 should fail.
#[test]
fn inner_zero_fee_fails_without_fee_credit() {
    use algo_ledger::avm_context::app_address;

    let fee_sink = Address([0xFE; 32]);
    let sender = Address([0x01; 32]);
    let app_id = 300u64;

    // Same inner-pay-with-fee=0 program.
    let inner_pay_zero_fee: Vec<u8> = vec![
        0x06, // version 6
        0xb1, // itxn_begin
        0x81, 0x01, // pushint 1 (pay)
        0xb2, 0x10, // itxn_field TypeEnum
        0x31, 0x00, // txn Sender
        0xb2, 0x07, // itxn_field Receiver
        0x81, 0x00, // pushint 0 (amount)
        0xb2, 0x08, // itxn_field Amount
        0x81, 0x00, // pushint 0 (fee)
        0xb2, 0x01, // itxn_field Fee
        0xb3, // itxn_submit
        0x81, 0x01, // pushint 1
        0x43, // return
    ];

    let mut state = make_state(
        &[
            (sender, 10_000_000),
            (fee_sink, 0),
            (Address(app_address(app_id)), 10_000_000),
        ],
        fee_sink,
    );

    create_app(
        &mut state,
        app_id,
        sender,
        inner_pay_zero_fee.clone(),
        prog(AVM_V6, &PUSHINT_1),
    );

    // fee=1000, no overpayment -> fee_credit = 0.
    let stx = appl_noop_txn(sender, app_id, 1_000);

    let ctx = ApplyContext {
        rewards_level: 0,
        fee_sink,
        round: 1,
        mode: ApplyMode::Execute,
        validate: false,
        latest_timestamp: 0,
        genesis_hash: [0u8; 32],
        txn_counter: Cell::new(0),
        fee_credit: Cell::new(0), // no fee credit
        txn_index: Cell::new(0),
        consensus: algo_types::ConsensusParams::default(),
        avm_overrides: Default::default(),
        failed_eval_delta: Cell::new(None),
        kv_mods_recorder: None,
    };

    let result = apply_transaction(&mut state, &stx, &ctx, 0);
    assert!(
        result.is_err(),
        "inner fee=0 without fee credit should fail"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("fee too small"),
        "error should mention fee: {}",
        err_msg
    );
}

// ===========================================================================
// Block-level Execute mode tests (apply_block_with_mode)
// ===========================================================================

/// Helper: build a minimal Block with given transactions.
fn make_block(
    round: u64,
    fee_sink: Address,
    rewards_pool: Address,
    payset: Vec<SignedTransaction>,
) -> Block {
    Block {
        round: Round(round),
        branch: [0u8; 32],
        seed: [0u8; 32],
        txn_commitment: [0u8; 32],
        timestamp: 1000,
        genesis_id: String::new(),
        genesis_hash: [0u8; 32],
        proposer: Address::ZERO,
        fee_sink,
        rewards_pool,
        rewards_level: 0,
        rewards_rate: 0,
        rewards_residue: 0,
        rewards_recalculation_round: Round(0),
        current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
        next_protocol: String::new(),
        next_protocol_approvals: 0,
        next_protocol_switch_on: Round(0),
        next_protocol_vote_before: Round(0),
        txn_counter: 10,
        fees_collected: 0,
        bonus: 0,
        proposer_payout: 0,
        prev512: [0u8; 64],
        txn256: [0u8; 32],
        txn512: [0u8; 64],
        state_proof_tracking: None,
        upgrade_propose: String::new(),
        upgrade_delay: 0,
        upgrade_approve: false,
        expired_participation_accounts: None,
        absent_participation_accounts: None,
        load: 0,
        congestion_tax: 0,
        payset,
    }
}

/// apply_block_with_mode in Execute mode processes a block containing an
/// app call transaction. The approval program runs and state is updated.
#[test]
fn apply_block_execute_mode_processes_appl_txn() {
    let creator = Address([1u8; 32]);
    let sender = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let rewards_pool = Address([4u8; 32]);

    let mut state = LedgerState::new();
    state.fee_sink = fee_sink;
    state.rewards_pool = rewards_pool;
    // Set current round to 0 so that block round=1 is expected.
    state.current_round = Round(0);

    // Fund accounts.
    state.get_or_default_account_mut(&creator).micro_algos = 50_000_000;
    state.get_or_default_account_mut(&sender).micro_algos = 50_000_000;
    state.get_or_default_account_mut(&fee_sink).micro_algos = 0;
    state.get_or_default_account_mut(&rewards_pool).micro_algos = 0;

    // Create an app with an approval program that returns 1.
    let app_id = 100u64;
    create_app(
        &mut state,
        app_id,
        creator,
        approval_program(),
        approval_program(),
    );

    // Build a block with one app call.
    let stx = appl_noop_txn(sender, app_id, 1_000);
    let block = make_block(1, fee_sink, rewards_pool, vec![stx]);

    let result = apply_block_with_mode(&mut state, &block, ApplyMode::Execute);
    assert!(
        result.is_ok(),
        "apply_block_with_mode Execute should succeed: {:?}",
        result.err()
    );

    // Round should have advanced.
    assert_eq!(state.current_round, Round(1));

    // Fee should have been deducted from sender.
    let sender_acct = state.get_account(&sender).unwrap();
    assert_eq!(sender_acct.micro_algos, 50_000_000 - 1_000);
}

/// apply_block_with_mode in Execute mode rejects when approval program
/// returns 0, causing the entire block application to fail.
#[test]
fn apply_block_execute_mode_rejects_failing_appl() {
    let creator = Address([1u8; 32]);
    let sender = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let rewards_pool = Address([4u8; 32]);

    let mut state = LedgerState::new();
    state.fee_sink = fee_sink;
    state.rewards_pool = rewards_pool;
    state.current_round = Round(0);

    state.get_or_default_account_mut(&creator).micro_algos = 50_000_000;
    state.get_or_default_account_mut(&sender).micro_algos = 50_000_000;
    state.get_or_default_account_mut(&fee_sink).micro_algos = 0;
    state.get_or_default_account_mut(&rewards_pool).micro_algos = 0;

    // App with rejecting approval program.
    let app_id = 101u64;
    create_app(
        &mut state,
        app_id,
        creator,
        rejection_program(),
        approval_program(),
    );

    let stx = appl_noop_txn(sender, app_id, 1_000);
    let block = make_block(1, fee_sink, rewards_pool, vec![stx]);

    let result = apply_block_with_mode(&mut state, &block, ApplyMode::Execute);
    assert!(
        result.is_err(),
        "apply_block_with_mode should fail when approval program rejects"
    );

    // Round should NOT have advanced on error.
    assert_eq!(state.current_round, Round(0));
}

// ===========================================================================
// Issue #570: StateDelta.kv_mods populated during block apply
// ===========================================================================

/// Build the raw KV-store key for a box, matching go-algorand's
/// `apps.MakeBoxKey` / `sqlite.rs`'s `make_box_key`: `"bx:" +
/// big-endian(app_id) + box_name`. Duplicated here (rather than depending on
/// the crate-private helper) since this is a black-box integration test.
fn box_kv_key(app_id: u64, name: &[u8]) -> Vec<u8> {
    let mut key = b"bx:".to_vec();
    key.extend_from_slice(&app_id.to_be_bytes());
    key.extend_from_slice(name);
    key
}

/// TDD regression for issue #570: applying a block whose app call writes a
/// box via `box_put` must populate `StateDelta.kv_mods` with the box's key,
/// new value, and (empty, since the box didn't exist before) old value.
/// `apply_block_with_delta` (Replay mode) cannot observe this -- box
/// mutations only happen inside AVM execution -- so this uses
/// `apply_block_with_delta_mode(.., Execute)`.
#[test]
fn apply_block_with_delta_execute_mode_populates_kv_mods_for_box_put() {
    let creator = Address([1u8; 32]);
    let sender = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let rewards_pool = Address([4u8; 32]);

    let mut state = LedgerState::new();
    state.fee_sink = fee_sink;
    state.rewards_pool = rewards_pool;
    state.current_round = Round(0);

    state.get_or_default_account_mut(&creator).micro_algos = 50_000_000;
    state.get_or_default_account_mut(&sender).micro_algos = 50_000_000;
    state.get_or_default_account_mut(&fee_sink).micro_algos = 0;
    state.get_or_default_account_mut(&rewards_pool).micro_algos = 0;

    let app_id = 200u64;
    create_app(
        &mut state,
        app_id,
        creator,
        box_put_program("mybox", "hello"),
        approval_program(),
    );

    let stx = appl_noop_txn_with_box(sender, app_id, 1_000, b"mybox");
    let block = make_block(1, fee_sink, rewards_pool, vec![stx]);

    let delta = apply_block_with_delta_mode(&mut state, &block, ApplyMode::Execute)
        .expect("apply_block_with_delta_mode(Execute) must succeed");

    let key = box_kv_key(app_id, b"mybox");
    let entry = delta
        .kv_mods
        .get(&key)
        .expect("kv_mods must contain the box_put'd box");
    assert_eq!(entry.data, b"hello");
    assert!(
        entry.old_data.is_empty(),
        "box didn't exist before this round"
    );

    // Confirm the box was really written to the store too (not just recorded).
    assert_eq!(
        algo_ledger::LedgerStore::get_box(&state, app_id, b"mybox"),
        Some(b"hello".to_vec())
    );
}

/// Companion regression: a `box_del` on a pre-existing box records the prior
/// value as `old_data` and empty `data`, and `apply_block_with_delta`
/// (Replay mode, the default) leaves `kv_mods` empty for the same block
/// since it never runs the AVM -- pinning the documented Replay/Execute
/// distinction (see `apply_block_with_delta_mode`'s doc comment).
#[test]
fn apply_block_with_delta_execute_mode_populates_kv_mods_for_box_del_and_replay_mode_does_not() {
    let creator = Address([1u8; 32]);
    let sender = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let rewards_pool = Address([4u8; 32]);

    let make_funded_state_with_box = || {
        let mut state = LedgerState::new();
        state.fee_sink = fee_sink;
        state.rewards_pool = rewards_pool;
        state.current_round = Round(0);
        state.get_or_default_account_mut(&creator).micro_algos = 50_000_000;
        state.get_or_default_account_mut(&sender).micro_algos = 50_000_000;
        state.get_or_default_account_mut(&fee_sink).micro_algos = 0;
        state.get_or_default_account_mut(&rewards_pool).micro_algos = 0;
        algo_ledger::LedgerStore::set_box(&mut state, 201, b"mybox", b"hello".to_vec());
        let acct = state.get_or_default_account_mut(&creator);
        acct.total_boxes = 1;
        acct.total_box_bytes = "mybox".len() as u64 + "hello".len() as u64;
        state
    };

    let app_id = 201u64;

    // Execute mode: box_del actually runs, kv_mods gets the delta.
    let mut exec_state = make_funded_state_with_box();
    create_app(
        &mut exec_state,
        app_id,
        creator,
        box_del_program("mybox"),
        approval_program(),
    );
    let stx = appl_noop_txn_with_box(sender, app_id, 1_000, b"mybox");
    let block = make_block(1, fee_sink, rewards_pool, vec![stx.clone()]);
    let delta = apply_block_with_delta_mode(&mut exec_state, &block, ApplyMode::Execute)
        .expect("Execute-mode apply must succeed");
    let key = box_kv_key(app_id, b"mybox");
    let entry = delta
        .kv_mods
        .get(&key)
        .expect("kv_mods must contain the box_del'd box");
    assert_eq!(entry.old_data, b"hello");
    assert!(entry.data.is_empty());
    assert_eq!(
        algo_ledger::LedgerStore::get_box(&exec_state, app_id, b"mybox"),
        None,
        "box_del must actually remove the box from the store"
    );

    // Replay mode: no AVM execution, so kv_mods must stay empty even though
    // the block "contains" the same box_del-shaped app call (Replay mode
    // never looks at the approval program at all -- it only replays
    // recorded EvalDelta, which never exists on this synthetic block).
    let mut replay_state = make_funded_state_with_box();
    create_app(
        &mut replay_state,
        app_id,
        creator,
        box_del_program("mybox"),
        approval_program(),
    );
    let replay_delta = apply_block_with_delta(&mut replay_state, &block)
        .expect("Replay-mode apply must succeed (no EvalDelta to replay is a no-op, not an error)");
    assert!(
        replay_delta.kv_mods.is_empty(),
        "Replay mode never runs the AVM, so it cannot observe box mutations \
         (documented limitation, issue #570)"
    );
    // The store itself is untouched in Replay mode too.
    assert_eq!(
        algo_ledger::LedgerStore::get_box(&replay_state, app_id, b"mybox"),
        Some(b"hello".to_vec())
    );
}

/// apply_block_with_mode in Execute mode with a mixed block containing
/// a pay + appl transaction correctly processes both.
#[test]
fn apply_block_execute_mode_mixed_pay_and_appl() {
    let creator = Address([1u8; 32]);
    let sender = Address([2u8; 32]);
    let receiver = Address([5u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let rewards_pool = Address([4u8; 32]);

    let mut state = LedgerState::new();
    state.fee_sink = fee_sink;
    state.rewards_pool = rewards_pool;
    state.current_round = Round(0);

    state.get_or_default_account_mut(&creator).micro_algos = 50_000_000;
    state.get_or_default_account_mut(&sender).micro_algos = 50_000_000;
    state.get_or_default_account_mut(&receiver).micro_algos = 1_000_000;
    state.get_or_default_account_mut(&fee_sink).micro_algos = 0;
    state.get_or_default_account_mut(&rewards_pool).micro_algos = 0;

    let app_id = 102u64;
    create_app(
        &mut state,
        app_id,
        creator,
        approval_program(),
        approval_program(),
    );

    // Pay transaction.
    let pay_stx = SignedTransaction {
        txn: Transaction {
            txn_type: "pay".into(),
            sender,
            fee: 1_000,
            first_valid: 1.into(),
            last_valid: 100.into(),
            receiver,
            amount: 5_000,
            ..Default::default()
        },
        ..Default::default()
    };

    // App call transaction.
    let appl_stx = appl_noop_txn(sender, app_id, 1_000);

    let block = make_block(1, fee_sink, rewards_pool, vec![pay_stx, appl_stx]);

    let result = apply_block_with_mode(&mut state, &block, ApplyMode::Execute);
    assert!(
        result.is_ok(),
        "block with pay+appl should succeed in Execute mode: {:?}",
        result.err()
    );

    // Pay should have transferred funds.
    let receiver_acct = state.get_account(&receiver).unwrap();
    assert_eq!(receiver_acct.micro_algos, 1_000_000 + 5_000);

    // Sender should have paid fees for both txns + the pay amount.
    let sender_acct = state.get_account(&sender).unwrap();
    assert_eq!(sender_acct.micro_algos, 50_000_000 - 1_000 - 1_000 - 5_000);
}

// ===========================================================================
// AvmResult extraction tests
// ===========================================================================

/// After running an approval program that approves, AvmResult has approved=true.
#[test]
fn avm_result_approval_program_captures_approved() {
    let raw = prog(AVM_V6, &PUSHINT_1); // pushint 1
    let mut ctx = NullContext;
    let mut budget = GroupBudget::new(1);

    let result = run_approval_program(&raw, &mut ctx, &mut budget).unwrap();
    assert!(result.approved);
    assert!(result.error.is_none());
    assert!(result.logs.is_empty()); // NullContext returns empty logs
    assert!(result.inner_transactions.is_empty());
    assert!(result.global_delta.is_empty());
    assert!(result.local_deltas.is_empty());
}

/// After running an approval program that rejects, AvmResult has approved=false
/// but no error (clean rejection).
#[test]
fn avm_result_rejection_is_clean() {
    let raw = prog(AVM_V6, &PUSHINT_0); // pushint 0
    let mut ctx = NullContext;
    let mut budget = GroupBudget::new(1);

    let result = run_approval_program(&raw, &mut ctx, &mut budget).unwrap();
    assert!(!result.approved);
    assert!(
        result.error.is_none(),
        "clean rejection should have no error"
    );
}

/// After running an approval program that errors, AvmResult has approved=false
/// and an error message.
#[test]
fn avm_result_runtime_error_captures_error_message() {
    let raw = prog(AVM_V6, &[ERR_OPCODE]); // err
    let mut ctx = NullContext;
    let mut budget = GroupBudget::new(1);

    let result = run_approval_program(&raw, &mut ctx, &mut budget).unwrap();
    assert!(!result.approved);
    assert!(
        result.error.is_some(),
        "runtime error should be captured in AvmResult"
    );
}

/// AvmResult.empty() returns a well-formed default result.
#[test]
fn avm_result_empty_is_well_formed() {
    let result = AvmResult::empty();
    assert!(!result.approved);
    assert!(result.error.is_none());
    assert!(result.logs.is_empty());
    assert!(result.inner_transactions.is_empty());
    assert!(result.global_delta.is_empty());
    assert!(result.local_deltas.is_empty());
}

/// NullContext's take_* methods return empty collections (verifying the
/// trait default implementations that feed into AvmResult).
#[test]
fn null_context_take_methods_return_empty() {
    use algo_avm::context::AvmContext;
    let mut ctx = NullContext;
    assert!(ctx.take_logs().is_empty());
    assert!(ctx.take_inner_transactions().is_empty());
    assert!(ctx.take_global_delta().is_empty());
    assert!(ctx.take_local_deltas().is_empty());
}
