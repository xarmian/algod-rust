//! Integration tests for the transaction evaluation bridge (Epic 20b).
//!
//! Tests cover:
//! - W4.1: Approval program gates transaction success in Execute mode
//! - W4.2: ClearState always clears local state regardless of program outcome
//! - W4.3: Pooled budget across app call groups
//! - W4.4: LogicSig mode restrictions (verified via existing tests)
//! - W4.5: Replay mode regression (existing patterns still work)

use std::collections::BTreeMap;

use algo_avm::group::{GroupBudget, GroupContext};
use algo_ledger::{apply_transaction, ApplyContext, ApplyMode, LedgerState};
use algo_types::{
    Address, AppLocalState, AppParams, SignedTransaction, StateSchema, TealValue, Transaction,
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

/// Create a LedgerState with the given balances and fee sink.
fn make_state(balances: &[(Address, u64)], fee_sink: Address) -> LedgerState {
    let mut state = LedgerState::new();
    state.fee_sink = fee_sink;
    for (addr, bal) in balances {
        let acct = state.get_or_default_account(addr);
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
        latest_timestamp: 0,
        genesis_hash: [0u8; 32],
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
        },
    );

    // Increment creator's total_created_apps so min balance checks pass.
    let acct = state.get_or_default_account(&creator);
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
    let acct = state.get_or_default_account(addr);
    acct.total_apps_opted_in += 1;
}

/// Build an appl SignedTransaction for an existing app (NoOp on_completion).
fn appl_noop_txn(sender: Address, app_id: u64, fee: u64) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: "appl".to_string(),
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

/// Build an appl SignedTransaction with ClearState on_completion.
fn appl_clearstate_txn(sender: Address, app_id: u64, fee: u64) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: "appl".to_string(),
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
    stx.txn.txn_type = "appl".to_string();
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
    create_stx.txn.txn_type = "appl".to_string();
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
    optin_stx.txn.txn_type = "appl".to_string();
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
    stx.txn.txn_type = "appl".to_string();
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
