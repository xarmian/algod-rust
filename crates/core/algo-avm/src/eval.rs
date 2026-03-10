//! AVM program evaluation -- result types and execution entry points.
//!
//! Provides `AvmResult` (the output of running an approval or clear-state
//! program) and the execution functions that bridge the gap between the
//! transaction evaluator and the AVM stack machine.

use std::collections::HashMap;

use algo_error::AlgoError;
use algo_types::{Address, SignedTransaction, TealValue};

use crate::bytecode;
use crate::context::AvmContext;
use crate::group::GroupBudget;
use crate::machine::{AvmMachine, ExecMode};

// ---------------------------------------------------------------------------
// Constants (from go-algorand config/consensus.go)
// ---------------------------------------------------------------------------

/// LogicSig budget per transaction (pooled across the group).
pub const LOGICSIG_BUDGET: i64 = 20_000;

/// Application budget added per app call in the group.
pub const APP_BUDGET_PER_CALL: i64 = 700;

/// Maximum cost a single ClearState program may consume.
/// ClearState programs run with an isolated budget capped at this value.
pub const MAX_APP_PROGRAM_COST: i64 = 700;

// ---------------------------------------------------------------------------
// AvmResult
// ---------------------------------------------------------------------------

/// The result of executing an AVM program (approval or clear-state).
#[derive(Debug, Clone)]
pub struct AvmResult {
    /// Changes to the application's global state.
    /// `Some(val)` = set, `None` = delete.
    pub global_delta: HashMap<Vec<u8>, Option<TealValue>>,
    /// Changes to per-account local state, keyed by account address.
    /// Inner values: `Some(val)` = set, `None` = delete.
    pub local_deltas: HashMap<Address, HashMap<Vec<u8>, Option<TealValue>>>,
    /// Inner transactions emitted by the program.
    pub inner_transactions: Vec<SignedTransaction>,
    /// Log messages emitted by the program.
    pub logs: Vec<Vec<u8>>,
    /// Whether the program approved the transaction.
    pub approved: bool,
    /// If set, indicates a runtime error (as opposed to a clean rejection).
    pub error: Option<String>,
}

impl AvmResult {
    /// Create an empty result with `approved = false` and no deltas/logs.
    pub fn empty() -> Self {
        AvmResult {
            global_delta: HashMap::new(),
            local_deltas: HashMap::new(),
            inner_transactions: Vec::new(),
            logs: Vec::new(),
            approved: false,
            error: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Execution entry points
// ---------------------------------------------------------------------------

/// Run an approval program (OptIn, NoOp, CloseOut, Update, Delete).
///
/// Returns `Ok(AvmResult)` with `approved = true/false`, or `Err` on
/// infrastructure failure (e.g. parse error). A program that cleanly rejects
/// (pushes 0 / empty stack) is **not** an `Err` -- it returns `Ok(AvmResult)`
/// with `approved = false`.
///
/// The pooled `GroupBudget` is consumed by the actual opcode cost incurred
/// during execution. The machine runs with the group's remaining budget so
/// that costs are automatically shared across app calls in the group.
pub fn run_approval_program(
    program: &[u8],
    ctx: &mut dyn AvmContext,
    budget: &mut GroupBudget,
) -> Result<AvmResult, AlgoError> {
    let parsed = bytecode::parse(program)?;
    let budget_before = budget.remaining();
    let mut machine = AvmMachine::new(parsed, ExecMode::Application, budget_before);

    match machine.run(ctx) {
        Ok(pass) => {
            // Deduct the actual cost consumed from the pooled budget.
            let cost_used = budget_before - machine.budget;
            budget.consume(cost_used)?;

            // Extract accumulated state from the context into the result.
            let result = AvmResult {
                global_delta: ctx.take_global_delta(),
                local_deltas: ctx.take_local_deltas(),
                inner_transactions: ctx.take_inner_transactions(),
                logs: ctx.take_logs(),
                approved: pass,
                error: None,
            };
            Ok(result)
        }
        Err(e) => {
            // Runtime error -- program did not approve.
            // Still deduct the cost consumed up to the point of failure.
            let cost_used = budget_before - machine.budget;
            // Ignore consume error here -- we already have the real error.
            let _ = budget.consume(cost_used);

            let mut result = AvmResult::empty();
            result.approved = false;
            result.error = Some(e.to_string());
            Ok(result)
        }
    }
}

/// Run a clear-state program (ClearState on-completion).
///
/// Always returns an `AvmResult` (never errors at caller level).
/// On program failure: `approved = false`, no deltas/logs/inner txns are
/// propagated, but local state is still cleared by the caller.
///
/// ClearState budget is capped at `MAX_APP_PROGRAM_COST` (700), independent
/// of the pooled budget. Per go-algorand `IsolateClearState`, this runs with
/// its own isolated budget and does not draw from `GroupBudget`.
pub fn run_clear_state_program(program: &[u8], ctx: &mut dyn AvmContext) -> AvmResult {
    let parsed = match bytecode::parse(program) {
        Ok(p) => p,
        Err(_) => {
            // Parse failure: reject with empty result.
            return AvmResult::empty();
        }
    };

    let mut machine = AvmMachine::new(parsed, ExecMode::Application, MAX_APP_PROGRAM_COST);

    match machine.run(ctx) {
        Ok(true) => {
            // Program approved — extract accumulated state from the context.
            AvmResult {
                global_delta: ctx.take_global_delta(),
                local_deltas: ctx.take_local_deltas(),
                inner_transactions: ctx.take_inner_transactions(),
                logs: ctx.take_logs(),
                approved: true,
                error: None,
            }
        }
        Ok(false) => {
            // Program cleanly rejected: return empty result with no
            // deltas/logs/inner txns (caller handles local state clearing).
            AvmResult::empty()
        }
        Err(e) => {
            // Program errored: return empty result but capture the error
            // message for debugging/conformance reporting.
            let mut result = AvmResult::empty();
            result.error = Some(e.to_string());
            result
        }
    }
}

/// Run a LogicSig program.
///
/// LogicSig programs execute in `ExecMode::LogicSig` mode, which disallows
/// state writes and inner transactions. The program must leave a non-zero
/// value on top of the stack to approve the transaction.
///
/// # Budget
///
/// The caller passes the remaining pooled budget for the transaction group.
/// Each transaction in the group contributes `LOGICSIG_BUDGET` (20,000)
/// opcodes. The actual cost consumed is deducted from `budget` so that the
/// caller can track the shared pool across all LogicSig evaluations in the
/// group.
///
/// # Return value
///
/// Returns `Ok(true)` if the program approved (stack top is non-zero),
/// `Ok(false)` if it cleanly rejected (stack top is zero or stack empty),
/// or `Err` on parse failure or runtime error.
pub fn run_logicsig_program(
    program: &[u8],
    ctx: &mut dyn AvmContext,
    budget: &mut GroupBudget,
) -> Result<bool, AlgoError> {
    let parsed = bytecode::parse(program)?;
    let budget_before = budget.remaining();
    let mut machine = AvmMachine::new(parsed, ExecMode::LogicSig, budget_before);

    match machine.run(ctx) {
        Ok(pass) => {
            // Deduct actual cost consumed from the pooled budget.
            let cost_used = budget_before - machine.budget;
            budget.consume(cost_used)?;
            Ok(pass)
        }
        Err(e) => {
            // Deduct cost consumed up to the point of failure.
            let cost_used = budget_before - machine.budget;
            let _ = budget.consume(cost_used);
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::NullContext;

    /// Build a raw program from version byte + code bytes.
    fn prog(version: u8, code: &[u8]) -> Vec<u8> {
        let mut p = vec![version];
        p.extend_from_slice(code);
        p
    }

    #[test]
    fn test_avm_result_empty() {
        let result = AvmResult::empty();
        assert!(!result.approved);
        assert!(result.error.is_none());
        assert!(result.global_delta.is_empty());
        assert!(result.local_deltas.is_empty());
        assert!(result.inner_transactions.is_empty());
        assert!(result.logs.is_empty());
    }

    #[test]
    fn test_avm_result_construction() {
        let mut global_delta = HashMap::new();
        global_delta.insert(b"key".to_vec(), Some(TealValue::Uint(42)));

        let mut local_deltas = HashMap::new();
        let mut account_delta = HashMap::new();
        account_delta.insert(b"local_key".to_vec(), Some(TealValue::Bytes(b"val".to_vec())));
        local_deltas.insert(Address::ZERO, account_delta);

        let result = AvmResult {
            global_delta,
            local_deltas,
            inner_transactions: vec![],
            logs: vec![b"hello".to_vec()],
            approved: true,
            error: None,
        };

        assert!(result.approved);
        assert_eq!(result.global_delta.len(), 1);
        assert_eq!(
            result.global_delta.get(b"key".as_slice()),
            Some(&Some(TealValue::Uint(42)))
        );
        assert_eq!(result.local_deltas.len(), 1);
        assert_eq!(result.logs.len(), 1);
        assert_eq!(result.logs[0], b"hello");
    }

    #[test]
    fn test_avm_result_with_error() {
        let mut result = AvmResult::empty();
        result.error = Some("runtime panic".to_string());
        assert!(!result.approved);
        assert_eq!(result.error.as_deref(), Some("runtime panic"));
    }

    #[test]
    fn test_constants() {
        assert_eq!(LOGICSIG_BUDGET, 20_000);
        assert_eq!(APP_BUDGET_PER_CALL, 700);
        assert_eq!(MAX_APP_PROGRAM_COST, 700);
    }

    // -----------------------------------------------------------------------
    // run_approval_program tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_approval_program_approves() {
        // pushint 1, return  =>  approves
        let raw = prog(2, &[0x20, 0x01, 0x01, 0x22, 0x43]);
        let mut ctx = NullContext;
        let mut budget = GroupBudget::new(1);

        let result = run_approval_program(&raw, &mut ctx, &mut budget).unwrap();
        assert!(result.approved);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_approval_program_rejects() {
        // intcblock [0], intc_0, return  =>  rejects (top of stack is 0)
        let raw = prog(2, &[0x20, 0x01, 0x00, 0x22, 0x43]);
        let mut ctx = NullContext;
        let mut budget = GroupBudget::new(1);

        let result = run_approval_program(&raw, &mut ctx, &mut budget).unwrap();
        assert!(!result.approved);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_approval_program_runtime_error() {
        // err opcode (0x00) triggers a runtime error
        let raw = prog(1, &[0x00]);
        let mut ctx = NullContext;
        let mut budget = GroupBudget::new(1);

        let result = run_approval_program(&raw, &mut ctx, &mut budget).unwrap();
        assert!(!result.approved);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_approval_program_parse_error() {
        // Empty program bytes should fail to parse
        let result = run_approval_program(&[], &mut NullContext, &mut GroupBudget::new(1));
        assert!(result.is_err());
    }

    #[test]
    fn test_approval_program_consumes_budget() {
        // intcblock [1], intc_0, return  -- a few opcodes each costing 1
        let raw = prog(2, &[0x20, 0x01, 0x01, 0x22, 0x43]);
        let mut ctx = NullContext;
        let mut budget = GroupBudget::new(1);
        let before = budget.remaining();

        let result = run_approval_program(&raw, &mut ctx, &mut budget).unwrap();
        assert!(result.approved);

        // Budget should have decreased by the cost of executed opcodes.
        let after = budget.remaining();
        assert!(
            after < before,
            "budget should decrease: before={before}, after={after}"
        );
        // Each of the 3 instructions costs 1, so 3 total consumed.
        assert_eq!(before - after, 3);
    }

    #[test]
    fn test_approval_program_empty_stack_rejects() {
        // A program with version byte only (no instructions) -- empty stack
        // should reject (approved = false).
        let raw = prog(1, &[]);
        let mut ctx = NullContext;
        let mut budget = GroupBudget::new(1);

        let result = run_approval_program(&raw, &mut ctx, &mut budget).unwrap();
        assert!(!result.approved);
    }

    // -----------------------------------------------------------------------
    // run_clear_state_program tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_clear_state_program_approves() {
        // intcblock [1], intc_0, return  =>  approves
        let raw = prog(2, &[0x20, 0x01, 0x01, 0x22, 0x43]);
        let mut ctx = NullContext;

        let result = run_clear_state_program(&raw, &mut ctx);
        assert!(result.approved);
    }

    #[test]
    fn test_clear_state_program_rejects_returns_empty() {
        // intcblock [0], intc_0, return  =>  rejects
        let raw = prog(2, &[0x20, 0x01, 0x00, 0x22, 0x43]);
        let mut ctx = NullContext;

        let result = run_clear_state_program(&raw, &mut ctx);
        assert!(!result.approved);
        // On rejection, no deltas/logs/inner txns should be propagated.
        assert!(result.global_delta.is_empty());
        assert!(result.local_deltas.is_empty());
        assert!(result.inner_transactions.is_empty());
        assert!(result.logs.is_empty());
    }

    #[test]
    fn test_clear_state_program_error_returns_empty() {
        // err opcode (0x00) -- runtime error, should return empty result
        let raw = prog(1, &[0x00]);
        let mut ctx = NullContext;

        let result = run_clear_state_program(&raw, &mut ctx);
        assert!(!result.approved);
        assert!(result.global_delta.is_empty());
        assert!(result.local_deltas.is_empty());
        assert!(result.inner_transactions.is_empty());
        assert!(result.logs.is_empty());
    }

    #[test]
    fn test_clear_state_program_parse_error_returns_empty() {
        // Empty program bytes -- parse failure returns empty result
        let result = run_clear_state_program(&[], &mut NullContext);
        assert!(!result.approved);
    }

    #[test]
    fn test_clear_state_does_not_consume_group_budget() {
        // Verify that clear-state runs with its own isolated budget and
        // does not draw from GroupBudget.
        let raw = prog(2, &[0x20, 0x01, 0x01, 0x22, 0x43]);
        let budget = GroupBudget::new(1);
        let before = budget.remaining();

        // run_clear_state_program doesn't even take a GroupBudget --
        // this is enforced by the function signature. Just verify the
        // budget we created is untouched.
        let mut ctx = NullContext;
        let result = run_clear_state_program(&raw, &mut ctx);
        assert!(result.approved);
        assert_eq!(budget.remaining(), before);
    }

    // -----------------------------------------------------------------------
    // run_logicsig_program tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_logicsig_program_approves() {
        // intcblock [1], intc_0, return  =>  approves (top of stack is 1)
        let raw = prog(2, &[0x20, 0x01, 0x01, 0x22, 0x43]);
        let mut ctx = NullContext;
        let mut budget = GroupBudget::for_logicsig(1);

        let pass = run_logicsig_program(&raw, &mut ctx, &mut budget).unwrap();
        assert!(pass);
    }

    #[test]
    fn test_logicsig_program_rejects() {
        // intcblock [0], intc_0, return  =>  rejects (top of stack is 0)
        let raw = prog(2, &[0x20, 0x01, 0x00, 0x22, 0x43]);
        let mut ctx = NullContext;
        let mut budget = GroupBudget::for_logicsig(1);

        let pass = run_logicsig_program(&raw, &mut ctx, &mut budget).unwrap();
        assert!(!pass);
    }

    #[test]
    fn test_logicsig_program_runtime_error() {
        // err opcode (0x00) triggers a runtime error
        let raw = prog(1, &[0x00]);
        let mut ctx = NullContext;
        let mut budget = GroupBudget::for_logicsig(1);

        let result = run_logicsig_program(&raw, &mut ctx, &mut budget);
        assert!(result.is_err());
    }

    #[test]
    fn test_logicsig_program_parse_error() {
        // Empty program bytes should fail to parse
        let result = run_logicsig_program(&[], &mut NullContext, &mut GroupBudget::for_logicsig(1));
        assert!(result.is_err());
    }

    #[test]
    fn test_logicsig_program_consumes_budget() {
        // intcblock [1], intc_0, return  -- 3 opcodes each costing 1
        let raw = prog(2, &[0x20, 0x01, 0x01, 0x22, 0x43]);
        let mut ctx = NullContext;
        let mut budget = GroupBudget::for_logicsig(1);
        let before = budget.remaining();

        let pass = run_logicsig_program(&raw, &mut ctx, &mut budget).unwrap();
        assert!(pass);

        let after = budget.remaining();
        assert!(
            after < before,
            "budget should decrease: before={before}, after={after}"
        );
        assert_eq!(before - after, 3);
    }

    #[test]
    fn test_logicsig_program_empty_stack_rejects() {
        // A program with version byte only (no instructions) -- empty stack
        // should reject (pass = false).
        let raw = prog(1, &[]);
        let mut ctx = NullContext;
        let mut budget = GroupBudget::for_logicsig(1);

        let pass = run_logicsig_program(&raw, &mut ctx, &mut budget).unwrap();
        assert!(!pass);
    }

    #[test]
    fn test_logicsig_budget_pooled_across_group() {
        // With group_size=2, the pooled budget should be 2 * LOGICSIG_BUDGET.
        let mut budget = GroupBudget::for_logicsig(2);
        assert_eq!(budget.remaining(), 2 * LOGICSIG_BUDGET);

        // Run a small program and verify budget is deducted from the pool.
        let raw = prog(2, &[0x20, 0x01, 0x01, 0x22, 0x43]);
        let mut ctx = NullContext;
        let pass = run_logicsig_program(&raw, &mut ctx, &mut budget).unwrap();
        assert!(pass);
        assert_eq!(budget.remaining(), 2 * LOGICSIG_BUDGET - 3);
    }
}
