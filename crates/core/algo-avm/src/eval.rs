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

//! AVM program evaluation -- result types and execution entry points.
//!
//! Provides `AvmResult` (the output of running an approval or clear-state
//! program) and the execution functions that bridge the gap between the
//! transaction evaluator and the AVM stack machine.

use std::collections::HashMap;

use algo_error::{AlgoError, AvmDiagnosticValue, AvmEvalStateDump};
use algo_types::consensus::ConsensusParams;
use algo_types::{Address, SignedTransaction, TealValue};

use crate::bytecode;
use crate::context::AvmContext;
use crate::group::GroupBudget;
use crate::machine::{AvmMachine, AvmValue, ExecMode, OpcodeCoverage};
use crate::opcode::{self, CostKind};
use crate::tracer::{EvalTracer, ProgramType};

/// SHA-512/256 hash of program bytes, matching go-algorand's
/// `crypto.Hash(program)` used for exec-trace program-hash fields.
fn program_trace_hash(program: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha512_256};
    let mut hasher = Sha512_256::new();
    hasher.update(program);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Budget constants — sourced from ConsensusParams (V41 defaults).
//
// These are re-exported for backward compatibility with callers that
// reference the named constants.  The authoritative source is now
// `ConsensusParams`; these are simply the V41 default values.
// ---------------------------------------------------------------------------

/// LogicSig budget per transaction (pooled across the group).
/// Sourced from `ConsensusParams::logic_sig_max_cost` (V41 default).
pub const LOGICSIG_BUDGET: i64 = 20_000;

/// Application budget added per app call in the group.
/// Sourced from `ConsensusParams::max_app_program_cost` (V41 default).
pub const APP_BUDGET_PER_CALL: i64 = 700;

/// Maximum cost a single ClearState program may consume.
/// ClearState programs run with an isolated budget capped at this value.
/// Sourced from `ConsensusParams::max_app_program_cost` (V41 default).
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
    /// Opcode coverage from this execution run.
    pub coverage: OpcodeCoverage,
    /// The program's final scratch-space contents (all 256 slots), as left
    /// behind when execution stopped -- whether by clean completion,
    /// rejection, or runtime error. Mirrors go-algorand's `cx.Scratch`,
    /// which a later sibling's `gload`/`gloads`/`gloadss` reads via
    /// `cx.pastScratch[groupIndex]` (`data/transactions/logic/eval.go`): the
    /// pointer is live and reflects whatever `store`/`stores` wrote up to
    /// the point execution stopped, not just a successful run's final
    /// state. Callers that thread real cross-transaction `gload` values
    /// (`algo_ledger::apply`) read this field instead of substituting a
    /// zero-filled placeholder.
    pub scratch: [TealValue; 256],
}

/// Snapshot an `AvmMachine`'s scratch space into `TealValue`s for storage
/// outside the machine (e.g. in `AvmResult`, for cross-transaction `gload`).
fn scratch_snapshot(scratch: &[AvmValue]) -> [TealValue; 256] {
    std::array::from_fn(|i| match &scratch[i] {
        AvmValue::Uint64(v) => TealValue::Uint(*v),
        AvmValue::Bytes(b) => TealValue::Bytes(b.clone()),
    })
}

/// An all-zero scratch row, matching a fresh machine's initial scratch space.
fn empty_scratch() -> [TealValue; 256] {
    std::array::from_fn(|_| TealValue::Uint(0))
}

/// Build the structured `eval-states` diagnostic attribute for a LogicSig
/// evaluation failure, mirroring go-algorand's `cx.evalStates()`
/// (`data/transactions/logic/eval.go`).
///
/// go threads a shared `pastScratch` array across every transaction in the
/// group, so a failure on transaction N can report every sibling's scratch
/// space up through N. algod-rust's LogicSig evaluator verifies each
/// transaction's delegated program independently and does not carry that
/// cross-transaction state, so only the failing transaction's own dump
/// (`group_index`) is populated here; earlier entries are present (to match
/// go's `states[0..=group_index]` shape) but empty.
fn logicsig_eval_states(machine: &AvmMachine, group_index: usize) -> Vec<AvmEvalStateDump> {
    let mut states = vec![AvmEvalStateDump::default(); group_index + 1];
    states[group_index] = dump_eval_state(machine);
    states
}

/// Snapshot a machine's stack and scratch space into structured diagnostic
/// values, trimming the scratch dump to one past the highest non-zero/
/// non-empty slot -- matching go's `evalStates()` trimming so an untouched
/// scratch space reports as empty rather than 256 zero entries.
fn dump_eval_state(machine: &AvmMachine) -> AvmEvalStateDump {
    let stack = machine.stack.iter().map(avm_value_to_diagnostic).collect();

    let mut last_non_empty: Option<usize> = None;
    for (i, v) in machine.scratch.iter().enumerate() {
        let is_empty =
            matches!(v, AvmValue::Uint64(0)) || matches!(v, AvmValue::Bytes(b) if b.is_empty());
        if !is_empty {
            last_non_empty = Some(i);
        }
    }
    let scratch = match last_non_empty {
        Some(last) => machine.scratch[..=last]
            .iter()
            .map(avm_value_to_diagnostic)
            .collect(),
        None => Vec::new(),
    };

    AvmEvalStateDump { scratch, stack }
}

fn avm_value_to_diagnostic(v: &AvmValue) -> AvmDiagnosticValue {
    match v {
        AvmValue::Uint64(u) => AvmDiagnosticValue::Uint(*u),
        AvmValue::Bytes(b) => AvmDiagnosticValue::Bytes(b.clone()),
    }
}

/// Wrap a raw AVM evaluation error with go-algorand-style structured
/// diagnostics (pc, group index, per-transaction eval-state dump) -- mirrors
/// `cx.evalError()` (`data/transactions/logic/eval.go`), which attaches the
/// same attributes to every LogicSig evaluation failure.
fn attach_logicsig_error_details(
    err: AlgoError,
    machine: &AvmMachine,
    group_index: usize,
) -> AlgoError {
    let message = err.to_string();
    AlgoError::AvmLogicSig {
        source: Box::new(err),
        message,
        pc: machine.pc,
        group_index,
        eval_states: logicsig_eval_states(machine, group_index),
    }
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
            coverage: OpcodeCoverage::default(),
            scratch: empty_scratch(),
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
    // Reject programs declaring a version above the active consensus
    // LogicSigVersion ceiling (go-algorand eval.go pre-eval check). Contexts
    // that don't carry consensus (NullContext) return None and skip this.
    if let (Some(ceiling), Some(&version)) = (ctx.consensus_logic_sig_version(), program.first()) {
        crate::validator::check_program_version_allowed(version, ceiling)?;
    }
    // Reject a pre-sharedResources program (version < 9) invoked with a
    // non-empty tx.Access array (go-algorand eval.go `begin()`; see
    // `check_pre_shared_resources_access` doc for the exact go source).
    if let Some(&version) = program.first() {
        crate::validator::check_pre_shared_resources_access(version, ctx.txn_has_access())?;
    }

    let parsed = bytecode::parse(program)?;
    let budget_before = budget.remaining();
    let mut machine = AvmMachine::new(parsed, ExecMode::Application, budget_before);

    match machine.run(ctx) {
        Ok(pass) => {
            // Deduct the actual cost consumed from the pooled budget.
            let cost_used = budget_before - machine.budget;
            budget.consume(cost_used)?;

            let coverage = machine.opcode_coverage();
            let scratch = scratch_snapshot(&machine.scratch);
            // Extract accumulated state from the context into the result.
            let result = AvmResult {
                global_delta: ctx.take_global_delta(),
                local_deltas: ctx.take_local_deltas(),
                inner_transactions: ctx.take_inner_transactions(),
                logs: ctx.take_logs(),
                approved: pass,
                error: None,
                coverage,
                scratch,
            };
            Ok(result)
        }
        Err(e) => {
            // Runtime error -- program did not approve.
            // Still deduct the cost consumed up to the point of failure.
            let cost_used = budget_before - machine.budget;
            // Ignore consume error here -- we already have the real error.
            let _ = budget.consume(cost_used);

            // Preserve whatever global/local state, logs, and inner
            // transactions accumulated before the failing opcode, matching
            // go-algorand's per-opcode `saveEvalDelta` (tracer.go): the
            // ledger never applies a rejected/erroring app call, but the
            // caller (notably simulation) still needs visibility into the
            // partial EvalDelta observed up to the point of failure. The
            // scratch snapshot is preserved the same way, for the same
            // reason `gload` sees it (see the `scratch` field doc).
            let coverage = machine.opcode_coverage();
            let scratch = scratch_snapshot(&machine.scratch);
            let result = AvmResult {
                global_delta: ctx.take_global_delta(),
                local_deltas: ctx.take_local_deltas(),
                inner_transactions: ctx.take_inner_transactions(),
                logs: ctx.take_logs(),
                approved: false,
                error: Some(e.to_string()),
                coverage,
                scratch,
            };
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
/// ClearState budget is capped at `max_app_program_cost` from the consensus
/// params (700 for V41), independent of the pooled budget. Per go-algorand
/// `IsolateClearState`, this runs with its own isolated budget and does not
/// draw from `GroupBudget`.
///
pub fn run_clear_state_program(
    program: &[u8],
    ctx: &mut dyn AvmContext,
    consensus: &ConsensusParams,
) -> AvmResult {
    // Reject programs declaring a version above the active consensus
    // LogicSigVersion ceiling (go-algorand eval.go pre-eval check).
    if !program.is_empty()
        && crate::validator::check_program_version_allowed(program[0], consensus.logic_sig_version)
            .is_err()
    {
        return AvmResult::empty();
    }
    // Reject a pre-sharedResources program (version < 9) invoked with a
    // non-empty tx.Access array (go-algorand eval.go `begin()`; see
    // `check_pre_shared_resources_access` doc for the exact go source).
    if !program.is_empty()
        && crate::validator::check_pre_shared_resources_access(program[0], ctx.txn_has_access())
            .is_err()
    {
        return AvmResult::empty();
    }

    let parsed = match bytecode::parse(program) {
        Ok(p) => p,
        Err(_) => {
            // Parse failure: reject with empty result.
            return AvmResult::empty();
        }
    };

    let clear_budget = consensus.max_app_program_cost as i64;
    let mut machine = AvmMachine::new(parsed, ExecMode::Application, clear_budget);

    match machine.run(ctx) {
        Ok(true) => {
            let coverage = machine.opcode_coverage();
            let scratch = scratch_snapshot(&machine.scratch);
            // Program approved — extract accumulated state from the context.
            AvmResult {
                global_delta: ctx.take_global_delta(),
                local_deltas: ctx.take_local_deltas(),
                inner_transactions: ctx.take_inner_transactions(),
                logs: ctx.take_logs(),
                approved: true,
                error: None,
                coverage,
                scratch,
            }
        }
        Ok(false) => {
            // Program cleanly rejected: return empty result with no
            // deltas/logs/inner txns (caller handles local state clearing).
            // The scratch space is still real -- `gload` visibility into a
            // sibling's writes doesn't depend on that sibling's ClearState
            // program actually approving (see the `scratch` field doc).
            let mut result = AvmResult::empty();
            result.coverage = machine.opcode_coverage();
            result.scratch = scratch_snapshot(&machine.scratch);
            result
        }
        Err(e) => {
            // Program errored: return empty result but capture the error
            // message for debugging/conformance reporting.
            //
            // Unlike `run_approval_program`, this does NOT preserve partial
            // state on error: go-algorand's ClearState handling swallows
            // in-program `logic.EvalError`s entirely (`ledger/apply/
            // application.go`: `if _, ok := evalErr.(logic.EvalError); !ok {
            // return evalErr }`) and never fails the outer transaction for
            // them, so it never hits the tracer's per-opcode EvalDelta
            // substitution — a clear-state failure's `ApplyData.EvalDelta`
            // is empty in go-algorand's simulate response too, both for a
            // clean reject and a runtime error. Scratch space is unaffected
            // by this EvalDelta-suppression rule -- see the `scratch` field
            // doc.
            let mut result = AvmResult::empty();
            result.coverage = machine.opcode_coverage();
            result.scratch = scratch_snapshot(&machine.scratch);
            result.error = Some(e.to_string());
            result
        }
    }
}

/// First TEAL version where back-branches (e.g. a `bnz`/`b` that jumps
/// backward) are allowed. Mirrors go-algorand's `backBranchEnabledVersion`
/// (`data/transactions/logic/opcodes.go:45`), which gates the static-cost
/// preflight below.
const BACK_BRANCH_ENABLED_VERSION: u8 = 4;

/// Static-cost preflight check for pre-v4 LogicSig programs, mirroring
/// go-algorand's `check()`/`checkStep()` (`data/transactions/logic/eval.go`,
/// `check` at ~line 1548 and `checkStep` at ~line 1845).
///
/// Before back-branches were introduced (v0-v3), a TEAL program's control
/// flow could still jump *forward* (`bnz`/`bz`/`b`), so its true dynamic
/// execution cost can be lower than the sum of every opcode in the program.
/// go-algorand nonetheless rejects a pre-v4 program purely on that pessimistic
/// *static* linear-program-order cost sum -- counting even opcodes a taken
/// branch would skip at actual runtime -- because a static cost model can't
/// otherwise guarantee an upper bound once branches exist. From v4
/// (`backBranchEnabledVersion`) on, only the real dynamic execution cost
/// (tracked opcode-by-opcode by `AvmMachine::charge_cost` during `run`) is
/// checked, so this preflight is a no-op for v4+.
///
/// `program.instructions` is already a linear, non-branch-following
/// disassembly (see [`bytecode::parse`]), so this simply walks it in program
/// order and sums each instruction's declared static cost -- exactly what
/// go's `checkStep` does one opcode at a time via `deets.Cost(...)`.
///
/// Returns an error mirroring go's `"pc=%3d static cost budget of %d
/// exceeded"` as soon as the running sum exceeds `max_cost`.
fn static_cost_check(program: &bytecode::Program, max_cost: i64) -> Result<(), AlgoError> {
    if program.version >= BACK_BRANCH_ENABLED_VERSION {
        return Ok(());
    }
    let mut static_cost: i64 = 0;
    for instr in &program.instructions {
        if let Some(spec) = opcode::resolve_spec(instr.opcode, instr.sub_opcode) {
            // Every opcode available before v4 has a static declared cost --
            // dynamic-cost opcodes (e.g. `ec_pairing_check`, `sha512`) were
            // all introduced at v5+ -- so there's nothing to do for the
            // `CostKind::Dynamic` case here; it simply can't occur.
            //
            // `effective_cost` applies go's pre-v2 (`sha256`/`keccak256`/
            // `sha512_256`) static cost bump: those three are cheaper at
            // v0/v1 than the v2+ costs `OPCODE_TABLE` otherwise stores (see
            // `opcode::effective_cost` doc comment / issue #1121).
            if let CostKind::Static(cost) = opcode::effective_cost(spec, program.version) {
                static_cost += cost as i64;
            }
        }
        if static_cost > max_cost {
            return Err(AlgoError::Avm {
                message: format!(
                    "pc={} static cost budget of {max_cost} exceeded",
                    instr.offset
                ),
            });
        }
    }
    Ok(())
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
    // Reject programs declaring a version above the active consensus
    // LogicSigVersion ceiling (go-algorand eval.go pre-eval check).
    if let (Some(ceiling), Some(&version)) = (ctx.consensus_logic_sig_version(), program.first()) {
        crate::validator::check_program_version_allowed(version, ceiling)?;
    }
    // Reject programs below the group's minimum required AVM version
    // (go-algorand's computeMinAvmVersion floor; see AvmContext::min_avm_version).
    if let Some(&version) = program.first() {
        crate::validator::check_min_avm_version(version, ctx.min_avm_version())?;
    }

    let parsed = bytecode::parse(program)?;
    let budget_before = budget.remaining();
    // Pre-v4 static-cost preflight (go's `check()`/`checkStep()`); a no-op
    // for v4+, which relies solely on the dynamic cost tracked below.
    static_cost_check(&parsed, budget_before)?;
    let mut machine = AvmMachine::new(parsed, ExecMode::LogicSig, budget_before);
    let group_index = ctx.group_index();

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
            // Attach go-algorand-style structured diagnostics (pc,
            // group-index, eval-states) -- see `TestLogicErrorDetails`
            // (go's `data/transactions/logic/eval_test.go`).
            Err(attach_logicsig_error_details(e, &machine, group_index))
        }
    }
}

// ---------------------------------------------------------------------------
// Tracer-aware execution entry points
// ---------------------------------------------------------------------------

/// Run an approval program with an [`EvalTracer`] attached.
///
/// Identical to [`run_approval_program`] but invokes tracer callbacks for
/// each opcode and for program lifecycle events.
pub fn run_approval_program_with_tracer(
    program: &[u8],
    ctx: &mut dyn AvmContext,
    budget: &mut GroupBudget,
    tracer: &mut dyn EvalTracer,
) -> Result<AvmResult, AlgoError> {
    // Reject programs declaring a version above the active consensus
    // LogicSigVersion ceiling (go-algorand eval.go pre-eval check).
    if let (Some(ceiling), Some(&version)) = (ctx.consensus_logic_sig_version(), program.first()) {
        if let Err(e) = crate::validator::check_program_version_allowed(version, ceiling) {
            tracer.before_program(ProgramType::Approval, program_trace_hash(program));
            tracer.after_program(ProgramType::Approval, false, Some(&e.to_string()));
            return Err(e);
        }
    }

    let parsed = match bytecode::parse(program) {
        Ok(p) => p,
        Err(e) => {
            // Notify tracer of the failed program so it sees balanced
            // before/after calls even on parse errors.
            tracer.before_program(ProgramType::Approval, program_trace_hash(program));
            tracer.after_program(ProgramType::Approval, false, Some(&e.to_string()));
            return Err(e);
        }
    };
    let budget_before = budget.remaining();
    let mut machine = AvmMachine::new(parsed, ExecMode::Application, budget_before);

    tracer.before_program(ProgramType::Approval, program_trace_hash(program));

    match machine.run_with_tracer(ctx, tracer) {
        Ok(pass) => {
            let cost_used = budget_before - machine.budget;
            budget.consume(cost_used)?;

            tracer.after_program(ProgramType::Approval, pass, None);
            tracer.record_program_cost(ProgramType::Approval, machine.cost);

            let coverage = machine.opcode_coverage();
            let scratch = scratch_snapshot(&machine.scratch);
            let result = AvmResult {
                global_delta: ctx.take_global_delta(),
                local_deltas: ctx.take_local_deltas(),
                inner_transactions: ctx.take_inner_transactions(),
                logs: ctx.take_logs(),
                approved: pass,
                error: None,
                coverage,
                scratch,
            };
            Ok(result)
        }
        Err(e) => {
            let cost_used = budget_before - machine.budget;
            let _ = budget.consume(cost_used);

            let msg = e.to_string();
            tracer.after_program(ProgramType::Approval, false, Some(&msg));
            tracer.record_program_cost(ProgramType::Approval, machine.cost);

            // Preserve partial state accumulated before the failing opcode
            // (see the matching comment in the non-tracer variant above).
            let coverage = machine.opcode_coverage();
            let scratch = scratch_snapshot(&machine.scratch);
            let result = AvmResult {
                global_delta: ctx.take_global_delta(),
                local_deltas: ctx.take_local_deltas(),
                inner_transactions: ctx.take_inner_transactions(),
                logs: ctx.take_logs(),
                approved: false,
                error: Some(msg),
                coverage,
                scratch,
            };
            Ok(result)
        }
    }
}

/// Run a clear-state program with an [`EvalTracer`] attached.
///
/// Identical to [`run_clear_state_program`] but invokes tracer callbacks
/// for each opcode and for program lifecycle events.
pub fn run_clear_state_program_with_tracer(
    program: &[u8],
    ctx: &mut dyn AvmContext,
    consensus: &ConsensusParams,
    tracer: &mut dyn EvalTracer,
) -> AvmResult {
    // Reject programs declaring a version above the active consensus
    // LogicSigVersion ceiling (go-algorand eval.go pre-eval check).
    if !program.is_empty() {
        if let Err(e) =
            crate::validator::check_program_version_allowed(program[0], consensus.logic_sig_version)
        {
            tracer.before_program(ProgramType::ClearState, program_trace_hash(program));
            tracer.after_program(ProgramType::ClearState, false, Some(&e.to_string()));
            return AvmResult::empty();
        }
    }

    let parsed = match bytecode::parse(program) {
        Ok(p) => p,
        Err(e) => {
            // Notify tracer of the failed program so it sees balanced
            // before/after calls even on parse errors.
            tracer.before_program(ProgramType::ClearState, program_trace_hash(program));
            tracer.after_program(ProgramType::ClearState, false, Some(&e.to_string()));
            return AvmResult::empty();
        }
    };

    let clear_budget = consensus.max_app_program_cost as i64;
    let mut machine = AvmMachine::new(parsed, ExecMode::Application, clear_budget);

    tracer.before_program(ProgramType::ClearState, program_trace_hash(program));

    match machine.run_with_tracer(ctx, tracer) {
        Ok(true) => {
            tracer.after_program(ProgramType::ClearState, true, None);
            tracer.record_program_cost(ProgramType::ClearState, machine.cost);
            let coverage = machine.opcode_coverage();
            let scratch = scratch_snapshot(&machine.scratch);
            AvmResult {
                global_delta: ctx.take_global_delta(),
                local_deltas: ctx.take_local_deltas(),
                inner_transactions: ctx.take_inner_transactions(),
                logs: ctx.take_logs(),
                approved: true,
                error: None,
                coverage,
                scratch,
            }
        }
        Ok(false) => {
            tracer.after_program(ProgramType::ClearState, false, None);
            tracer.record_program_cost(ProgramType::ClearState, machine.cost);
            // Scratch space is real even on clean rejection -- see the
            // `scratch` field doc and the matching comment in the
            // non-tracer variant above.
            let mut result = AvmResult::empty();
            result.coverage = machine.opcode_coverage();
            result.scratch = scratch_snapshot(&machine.scratch);
            result
        }
        Err(e) => {
            let msg = e.to_string();
            tracer.after_program(ProgramType::ClearState, false, Some(&msg));
            tracer.record_program_cost(ProgramType::ClearState, machine.cost);
            // Does NOT preserve partial state on error — see the matching
            // comment in the non-tracer variant above (go-algorand never
            // fails the outer transaction for a ClearState program error, so
            // it never substitutes a partial EvalDelta for this case).
            // Scratch space is unaffected by that rule -- see the `scratch`
            // field doc.
            let mut result = AvmResult::empty();
            result.coverage = machine.opcode_coverage();
            result.scratch = scratch_snapshot(&machine.scratch);
            result.error = Some(msg);
            result
        }
    }
}

/// Run a LogicSig program with an [`EvalTracer`] attached.
///
/// Identical to [`run_logicsig_program`] but invokes tracer callbacks for
/// each opcode and for program lifecycle events.
pub fn run_logicsig_program_with_tracer(
    program: &[u8],
    ctx: &mut dyn AvmContext,
    budget: &mut GroupBudget,
    tracer: &mut dyn EvalTracer,
) -> Result<bool, AlgoError> {
    // Reject programs declaring a version above the active consensus
    // LogicSigVersion ceiling (go-algorand eval.go pre-eval check).
    if let (Some(ceiling), Some(&version)) = (ctx.consensus_logic_sig_version(), program.first()) {
        if let Err(e) = crate::validator::check_program_version_allowed(version, ceiling) {
            tracer.before_program(ProgramType::LogicSig, program_trace_hash(program));
            tracer.after_program(ProgramType::LogicSig, false, Some(&e.to_string()));
            return Err(e);
        }
    }
    // Reject programs below the group's minimum required AVM version
    // (go-algorand's computeMinAvmVersion floor; see AvmContext::min_avm_version).
    if let Some(&version) = program.first() {
        if let Err(e) = crate::validator::check_min_avm_version(version, ctx.min_avm_version()) {
            tracer.before_program(ProgramType::LogicSig, program_trace_hash(program));
            tracer.after_program(ProgramType::LogicSig, false, Some(&e.to_string()));
            return Err(e);
        }
    }

    let parsed = match bytecode::parse(program) {
        Ok(p) => p,
        Err(e) => {
            tracer.before_program(ProgramType::LogicSig, program_trace_hash(program));
            tracer.after_program(ProgramType::LogicSig, false, Some(&e.to_string()));
            return Err(e);
        }
    };
    let budget_before = budget.remaining();
    // Pre-v4 static-cost preflight (go's `check()`/`checkStep()`); a no-op
    // for v4+, which relies solely on the dynamic cost tracked below.
    if let Err(e) = static_cost_check(&parsed, budget_before) {
        tracer.before_program(ProgramType::LogicSig, program_trace_hash(program));
        tracer.after_program(ProgramType::LogicSig, false, Some(&e.to_string()));
        return Err(e);
    }
    let mut machine = AvmMachine::new(parsed, ExecMode::LogicSig, budget_before);
    let group_index = ctx.group_index();

    tracer.before_program(ProgramType::LogicSig, program_trace_hash(program));

    match machine.run_with_tracer(ctx, tracer) {
        Ok(pass) => {
            let cost_used = budget_before - machine.budget;
            budget.consume(cost_used)?;
            tracer.after_program(ProgramType::LogicSig, pass, None);
            tracer.record_program_cost(ProgramType::LogicSig, machine.cost);
            Ok(pass)
        }
        Err(e) => {
            let cost_used = budget_before - machine.budget;
            let _ = budget.consume(cost_used);
            let msg = e.to_string();
            tracer.after_program(ProgramType::LogicSig, false, Some(&msg));
            tracer.record_program_cost(ProgramType::LogicSig, machine.cost);
            // Attach go-algorand-style structured diagnostics -- see the
            // matching comment in `run_logicsig_program`.
            Err(attach_logicsig_error_details(e, &machine, group_index))
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

    /// A minimal stateful context that records `log` calls, for testing that
    /// state accumulated before a runtime error is preserved rather than
    /// discarded (issue #215: "EvalDelta preserved on error", mirroring
    /// go-algorand's per-opcode `saveEvalDelta`).
    #[derive(Default)]
    struct LoggingContext {
        logs: Vec<Vec<u8>>,
    }

    impl crate::context::AvmContext for LoggingContext {
        fn log(&mut self, data: Vec<u8>) -> Result<(), AlgoError> {
            self.logs.push(data);
            Ok(())
        }

        fn take_logs(&mut self) -> Vec<Vec<u8>> {
            std::mem::take(&mut self.logs)
        }
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
        account_delta.insert(
            b"local_key".to_vec(),
            Some(TealValue::Bytes(b"val".to_vec())),
        );
        local_deltas.insert(Address::ZERO, account_delta);

        let result = AvmResult {
            global_delta,
            local_deltas,
            inner_transactions: vec![],
            logs: vec![b"hello".to_vec()],
            approved: true,
            error: None,
            coverage: OpcodeCoverage::default(),
            scratch: empty_scratch(),
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
    fn test_approval_program_runtime_error_preserves_partial_state() {
        // pushbytes "hi"; log; err -- the log call succeeds before the
        // program hits the unconditional runtime error. go-algorand's
        // tracer preserves whatever EvalDelta/logs accumulated up to the
        // failing opcode (tracer.go: saveEvalDelta is called before every
        // opcode); the result should carry that partial state rather than
        // discarding it via AvmResult::empty().
        let raw = prog(6, &[0x80, 0x02, b'h', b'i', 0xb0, 0x00]);
        let mut ctx = LoggingContext::default();
        let mut budget = GroupBudget::new(1);

        let result = run_approval_program(&raw, &mut ctx, &mut budget).unwrap();
        assert!(!result.approved);
        assert!(result.error.is_some());
        assert_eq!(result.logs, vec![b"hi".to_vec()]);
    }

    #[test]
    fn test_approval_program_with_tracer_runtime_error_preserves_partial_state() {
        let raw = prog(6, &[0x80, 0x02, b'h', b'i', 0xb0, 0x00]);
        let mut ctx = LoggingContext::default();
        let mut budget = GroupBudget::new(1);
        let mut tracer = crate::tracer::NullTracer;

        let result =
            run_approval_program_with_tracer(&raw, &mut ctx, &mut budget, &mut tracer).unwrap();
        assert!(!result.approved);
        assert!(result.error.is_some());
        assert_eq!(result.logs, vec![b"hi".to_vec()]);
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

        let result = run_clear_state_program(&raw, &mut ctx, &ConsensusParams::default());
        assert!(result.approved);
    }

    #[test]
    fn test_clear_state_program_rejects_returns_empty() {
        // intcblock [0], intc_0, return  =>  rejects
        let raw = prog(2, &[0x20, 0x01, 0x00, 0x22, 0x43]);
        let mut ctx = NullContext;

        let result = run_clear_state_program(&raw, &mut ctx, &ConsensusParams::default());
        assert!(!result.approved);
        // On rejection, no deltas/logs/inner txns should be propagated.
        assert!(result.global_delta.is_empty());
        assert!(result.local_deltas.is_empty());
        assert!(result.inner_transactions.is_empty());
        assert!(result.logs.is_empty());
    }

    #[test]
    fn test_clear_state_program_error_returns_empty() {
        // pushbytes "hi"; log; err -- the log call succeeds before the
        // unconditional runtime error, but the result must still be empty.
        // Unlike approval programs, go-algorand swallows a ClearState
        // program's runtime `logic.EvalError` entirely (`ledger/apply/
        // application.go`) rather than failing the transaction, so it never
        // substitutes a partial EvalDelta for the (always-empty) real one —
        // both a clean reject and a runtime error report nothing.
        let raw = prog(6, &[0x80, 0x02, b'h', b'i', 0xb0, 0x00]);
        let mut ctx = LoggingContext::default();

        let result = run_clear_state_program(&raw, &mut ctx, &ConsensusParams::default());
        assert!(!result.approved);
        assert!(result.error.is_some());
        assert!(result.global_delta.is_empty());
        assert!(result.local_deltas.is_empty());
        assert!(result.inner_transactions.is_empty());
        assert!(result.logs.is_empty());
    }

    #[test]
    fn test_clear_state_program_with_tracer_error_returns_empty() {
        let raw = prog(6, &[0x80, 0x02, b'h', b'i', 0xb0, 0x00]);
        let mut ctx = LoggingContext::default();
        let mut tracer = crate::tracer::NullTracer;

        let result = run_clear_state_program_with_tracer(
            &raw,
            &mut ctx,
            &ConsensusParams::default(),
            &mut tracer,
        );
        assert!(!result.approved);
        assert!(result.error.is_some());
        assert!(result.global_delta.is_empty());
        assert!(result.logs.is_empty());
    }

    #[test]
    fn test_clear_state_program_parse_error_returns_empty() {
        // Empty program bytes -- parse failure returns empty result
        let result = run_clear_state_program(&[], &mut NullContext, &ConsensusParams::default());
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
        let result = run_clear_state_program(&raw, &mut ctx, &ConsensusParams::default());
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

    // ── Static-cost preflight (issue #1118), ported from go-algorand's
    // TestBackwardCompatTEALv1 (`data/transactions/logic/backwardCompat_test.go:253`) ──
    //
    // The pinned program below is the exact `programV1` fixture from that
    // test -- an escrow-style LogicSig exercising a broad slice of v1
    // opcodes (`ed25519verify`, `intcblock`/`bytecblock`, hashing,
    // `gtxn`/`global` field reads, `bnz`). The same fixture is used by
    // `assembler.rs`'s `test_backward_compat_teal_v1_assembly` (issue #1112)
    // to pin assembler byte-parity; here it pins the *cost* boundary instead.
    //
    // go's frozen v0/v1 boundary is 2139 (reject) / 2140 (accept) because
    // pre-v2 TEAL charged the hash opcodes (`sha256`/`keccak256`/
    // `sha512_256`) a *lower* static cost (7/26/9) than v2+ (35/130/45) --
    // see `data/transactions/logic/opcodes.go:535-545`. `opcode::effective_cost`
    // (issue #1121) applies that pre-v2 discount, so the v0/v1 boundary is
    // now reachable with this program -- see `test_static_cost_check_v1_program_frozen_boundary`
    // and `test_static_cost_check_v0_program_matches_v1_boundary` below. The
    // v2/v3 boundary (2307/2308) and the v4 dynamic-cost boundary (2306/2307,
    // checked via ordinary `AvmMachine::charge_cost` during real execution,
    // not the static preflight) already use the v2+ numbers and are pinned
    // below exactly as go pins them.
    const PROGRAM_V1_HEX: &str = "01200500010220ffffffffffffffffff012608014120559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd0142201f675bff07515f5df96737194ea945c36c41e7b4fcef307b7cd4d0e602a6911101432034b99f8dde1ba273c0a28cf5b2e4dbe497f8cb2453de0c8ba6d578c9431a62cb0100200000000000000000000000000000000000000000000000000000000000000000280129122a022b1210270403270512102d2e2f041022082209230a230b240c220d230e230f231022112312231314301525121617182319231a221b21041c1d12222312242512102104231210482829122a2b121027042706121048310031071331013102121022310413103105310613103108311613103109310a1210310b310f1310310c310d1210310e31101310311131121310311331141210311531171210483300003300071333000133000212102233000413103300053300061310330008330016131033000933000a121033000b33000f131033000c33000d121033000e3300101310330011330012131033001333001412103300153300171210483200320112320232041310320327071210350034001040000100234912";

    fn program_v1_bytes(version: u8) -> Vec<u8> {
        let mut program = hex::decode(PROGRAM_V1_HEX).expect("bad pinned program_v1 hex");
        program[0] = version;
        program
    }

    #[test]
    fn test_static_cost_check_v1_program_frozen_boundary() {
        // Go: `err = CheckSignature(0, optSigParams(maxCost(2139), stxn))`
        // -> `"static cost"`; `maxCost(2140)` -> `NoError`
        // (`backwardCompat_test.go:297-300`).
        let program = program_v1_bytes(1);
        let parsed = bytecode::parse(&program).unwrap();
        assert_eq!(parsed.version, 1);

        let err = static_cost_check(&parsed, 2139).unwrap_err();
        assert!(
            err.to_string().contains("static cost"),
            "unexpected error: {err}"
        );
        static_cost_check(&parsed, 2140).expect("2140 must clear the static budget");
    }

    #[test]
    fn test_static_cost_check_v0_program_matches_v1_boundary() {
        // go's `TestBackwardCompatTEALv1` also pins a version-byte-0 program
        // to the same 2139/2140 boundary (`opsByOpcode[0]` is built from the
        // same v1 specs as `opsByOpcode[1]`, `opcodes.go:927,963-967`) --
        // version 0 is go-algorand's backward-compatible alias for v1, not a
        // distinct version. `bytecode::parse` now accepts version 0 as a v1
        // alias (issue #1124) and `effective_cost`'s `version <= 1` guard
        // (issue #1121) already charges it the pre-v2 hash-opcode costs, so
        // the v0 half of go's frozen boundary is reachable here too.
        let program = program_v1_bytes(0);
        let parsed = bytecode::parse(&program).unwrap();
        assert_eq!(parsed.version, 0);

        let err = static_cost_check(&parsed, 2139).unwrap_err();
        assert!(
            err.to_string().contains("static cost"),
            "unexpected error: {err}"
        );
        static_cost_check(&parsed, 2140).expect("2140 must clear the static budget");
    }

    #[test]
    fn test_static_cost_check_v2_program_frozen_boundary() {
        // Go: `testLogicBytes(t, opsV2.Program, optSigParams(maxCost(2307),
        // stxn), "static cost", "")` / `maxCost(2308)` succeeds.
        let program = program_v1_bytes(2);
        let parsed = bytecode::parse(&program).unwrap();
        assert_eq!(parsed.version, 2);

        let err = static_cost_check(&parsed, 2307).unwrap_err();
        assert!(
            err.to_string().contains("static cost"),
            "unexpected error: {err}"
        );
        static_cost_check(&parsed, 2308).expect("2308 must clear the static budget");
    }

    #[test]
    fn test_static_cost_check_v3_program_matches_v2_boundary() {
        // Go's comment: "Costs for v2 programs should be higher... Eval
        // doesn't fail, but it would be ok (better?) if it did" -- v3 has
        // not yet enabled back-branches either, so it is still checked
        // statically and shares v2's cost table.
        let program = program_v1_bytes(3);
        let parsed = bytecode::parse(&program).unwrap();

        assert!(static_cost_check(&parsed, 2307).is_err());
        assert!(static_cost_check(&parsed, 2308).is_ok());
    }

    #[test]
    fn test_static_cost_check_v4_is_noop_relies_on_dynamic_tracking() {
        // Go: from `backBranchEnabledVersion` (4) on, `check()` skips the
        // static-sum rejection entirely -- only real dynamic execution cost
        // (tracked by `AvmMachine::charge_cost`) is checked. A max_cost of 0
        // would fail instantly if the static preflight still applied.
        let program = program_v1_bytes(4);
        let parsed = bytecode::parse(&program).unwrap();
        assert_eq!(parsed.version, 4);

        static_cost_check(&parsed, 0).expect("static preflight must be a no-op for v4+");
    }

    #[test]
    fn test_run_logicsig_program_rejects_pre_v4_static_overrun_before_execution() {
        // End-to-end wiring check: `run_logicsig_program` must reject a
        // pre-v4 program whose static cost sum exceeds the pooled budget
        // *before* running it, exactly mirroring go's two-phase
        // `CheckSignature` (static) then `EvalSignature` (dynamic) -- even
        // though algod-rust merges both phases into one call.
        let program = program_v1_bytes(2);
        let mut ctx = NullContext;

        let mut too_small = GroupBudget::with_remaining(2307);
        let err = run_logicsig_program(&program, &mut ctx, &mut too_small).unwrap_err();
        assert!(
            err.to_string().contains("static cost"),
            "unexpected error: {err}"
        );
        // The static preflight rejects before any opcode executes, so the
        // budget must be untouched (go's `check()` never mutates `cx.cost`
        // it only compares against a separately-computed `staticCost`).
        assert_eq!(too_small.remaining(), 2307);

        let mut just_enough = GroupBudget::with_remaining(2308);
        // This program depends on real ed25519 signature / group-transaction
        // fields to *approve*; NullContext can't satisfy that, so this run
        // is expected to error out during dynamic execution (unresolved
        // txn/global fields) -- what matters here is that it gets *past*
        // the static preflight (a "static cost" error) rather than being
        // rejected by it.
        let result = run_logicsig_program(&program, &mut ctx, &mut just_enough);
        if let Err(e) = result {
            assert!(
                !e.to_string().contains("static cost"),
                "2308 must clear the static preflight, got: {e}"
            );
        }
    }
}
