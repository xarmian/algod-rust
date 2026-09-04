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

//! Simulation tracer implementing `algo_avm::tracer::EvalTracer`.
//!
//! Captures opcode-level execution details (stack changes, scratch changes)
//! according to an [`ExecTraceConfig`] and accumulates them into
//! [`TransactionTrace`] structures for the simulation result.

use algo_avm::machine::AvmValue;
use algo_avm::tracer::{
    AppStateAccess, AppStateOp, AppStateType, EvalTracer, ProgramType, UnnamedResourceAccess,
};
use algo_types::{Address, TealValue};

use super::trace::{
    AvmValueTrace, ExecTraceConfig, InitialStatesAccumulator, OpcodeTraceUnit, ProgramTrace,
    StateChange, StateChangeKind, StateChangeOp, TransactionTrace, UnnamedResourcesAccessed,
};

/// Tracks the "transaction path" (go-algorand's `TxnPath`) pointing at the
/// currently-executing inner transaction, relative to the top-level
/// transaction this tracer instance was created for.
///
/// A direct Rust port of go-algorand's `cursorEvalTracer`
/// (`ledger/simulation/tracer.go`), which maintains this same push-on-enter/
/// pop-on-return bookkeeping across `BeforeTxnGroup`/`BeforeTxn`/`AfterTxn`/
/// `AfterTxnGroup`. One structural difference: go's tracer is shared across
/// the *whole* top-level group and its `BeforeTxnGroup`/`BeforeTxn` hooks
/// fire for the top-level transaction too, so `absolutePath()` returns a
/// fully-absolute path (top-level index included). algod-rust creates one
/// `SimulationTracer` per top-level transaction, and `before_txn_group`/
/// `before_txn` only ever fire for *inner* transaction groups (see
/// `avm_context.rs`) — so this cursor is seeded with one synthetic opening
/// frame (equivalent to go's state immediately after the top-level
/// `BeforeTxnGroup`+`BeforeTxn`) purely to host the sibling-accumulator slot
/// that later inner-group closures need (`AfterTxnGroup`'s
/// `previous_inner_txns[top-1]` bump). `relative_path()` then strips that
/// synthetic leading element, leaving a path relative to the top-level
/// transaction; the caller (the simulation loop in `mod.rs`) prepends the
/// real top-level index.
// Deliberately no `Default` impl: an empty cursor (no seeded base frame)
// would break the accumulator invariant `relative_path` relies on — always
// construct via `new()`.
#[derive(Debug)]
struct TxnCursor {
    /// Mirrors go's `relativeCursor`. Seeded with one entry (`0`) standing in
    /// for the top-level transaction's own (never-materialized) frame.
    relative_cursor: Vec<i64>,
    /// Mirrors go's `previousInnerTxns`. Seeded with one entry (`0`) so the
    /// first real inner-group closure has a slot to accumulate into.
    previous_inner_txns: Vec<i64>,
}

impl TxnCursor {
    fn new() -> Self {
        TxnCursor {
            relative_cursor: vec![0],
            previous_inner_txns: vec![0],
        }
    }

    fn before_txn_group(&mut self) {
        self.relative_cursor.push(-1); // will go to 0 in before_txn
    }

    fn before_txn(&mut self) {
        let top = self.relative_cursor.len() - 1;
        self.relative_cursor[top] += 1;
        self.previous_inner_txns.push(0);
    }

    fn after_txn(&mut self) {
        self.previous_inner_txns.pop();
    }

    fn after_txn_group(&mut self) {
        let top = self.relative_cursor.len() - 1;
        if !self.previous_inner_txns.is_empty() {
            let last = self.previous_inner_txns.len() - 1;
            self.previous_inner_txns[last] += self.relative_cursor[top] + 1;
        }
        self.relative_cursor.pop();
    }

    /// The full path, including the synthetic leading element standing in
    /// for the top-level transaction's own frame (always index 0 relative to
    /// itself).
    fn absolute_path(&self) -> Vec<i64> {
        let mut path = Vec::with_capacity(self.relative_cursor.len());
        for (i, &relative_group_index) in self.relative_cursor.iter().enumerate() {
            let mut absolute_index = relative_group_index;
            if i > 0 {
                absolute_index += self.previous_inner_txns[i - 1];
            }
            path.push(absolute_index);
        }
        path
    }

    /// The path relative to the top-level transaction (the synthetic leading
    /// element stripped off), ready to be appended after the real top-level
    /// index. Returns `None` if any component is negative — which can only
    /// happen if `after_txn_group` fires without a matching `before_txn`
    /// having run first (a pre-existing structural gap in a couple of
    /// early-fee-check error paths in `avm_context.rs`, unrelated to this
    /// path-tracking fix); callers fall back to the top-level-only path in
    /// that case, matching pre-fix behavior.
    fn relative_path(&self) -> Option<Vec<usize>> {
        let absolute = self.absolute_path();
        let mut out = Vec::with_capacity(absolute.len().saturating_sub(1));
        for &v in &absolute[1..] {
            if v < 0 {
                return None;
            }
            out.push(v as usize);
        }
        Some(out)
    }
}

/// Converts an AVM machine value to a trace-friendly representation.
fn to_trace_value(v: &AvmValue) -> AvmValueTrace {
    match v {
        AvmValue::Uint64(n) => AvmValueTrace::Uint64(*n),
        AvmValue::Bytes(b) => AvmValueTrace::Bytes(b.clone()),
    }
}

/// Converts a ledger [`TealValue`] to a trace-friendly representation.
fn teal_to_trace_value(v: &TealValue) -> AvmValueTrace {
    match v {
        TealValue::Uint(n) => AvmValueTrace::Uint64(*n),
        TealValue::Bytes(b) => AvmValueTrace::Bytes(b.clone()),
    }
}

/// State tracked during a single program's execution.
struct ProgramTraceState {
    /// The type of program being traced.
    program_type: ProgramType,
    /// SHA-512/256 hash of the program bytes being executed.
    program_hash: [u8; 32],
    /// Accumulated opcode trace entries.
    trace: ProgramTrace,
    /// Stack snapshot before the current opcode (for computing diffs).
    stack_before: Vec<AvmValueTrace>,
    /// Scratch snapshot before the current opcode (for computing diffs).
    scratch_before: Vec<AvmValueTrace>,
    /// Inner-transaction trace indices spawned by the currently-executing
    /// opcode, buffered between `before_txn` and `after_opcode`. go-algorand
    /// attaches `SpawnedInners` to the opcode unit as inners are created
    /// (`tracer.go:228`); since this tracer flushes opcode units at
    /// `after_opcode` (after inner execution finishes), the indices are
    /// buffered here and drained when the spawning opcode's unit is built.
    pending_spawned_inners: Vec<usize>,
}

/// A tracer that captures execution details for the simulation endpoint.
///
/// Implements [`EvalTracer`] and accumulates trace data into a
/// [`TransactionTrace`]. The tracer is designed to be used for a single
/// transaction; create a new instance for each transaction in the group.
///
/// The [`ExecTraceConfig`] controls which details are captured:
/// - `enable`: must be `true` for any tracing to occur.
/// - `stack`: capture stack additions and pop counts per opcode.
/// - `scratch`: capture scratch space changes per opcode.
/// - `state`: capture initial application state and per-opcode global/local/box
///   state-changes (reported via `record_app_state_access` /
///   `record_box_new_value`).
pub struct SimulationTracer {
    /// Configuration controlling what to capture.
    config: ExecTraceConfig,
    /// Current program execution state (set between before_program/after_program).
    current_program: Option<ProgramTraceState>,
    /// The accumulated transaction trace being built.
    transaction_trace: TransactionTrace,
    /// Path from root to the current active TransactionTrace.
    /// Empty = operating on the root `transaction_trace`.
    /// Each element is an index into `inner_traces` at that depth level.
    trace_path: Vec<usize>,
    /// Saved program states when descending into inner transactions.
    /// When `before_txn` is called, the current program state is pushed here
    /// so it can be restored after the inner transaction completes.
    program_state_stack: Vec<Option<ProgramTraceState>>,
    /// Initial application state captured for this transaction (populated only
    /// when `config.state` is set). The simulation engine drains this after
    /// each transaction and merges it into the simulation-level snapshot.
    initial_states: InitialStatesAccumulator,
    /// State changes (global/local writes/deletes) recorded during the current
    /// opcode, flushed into the opcode's trace unit at `after_opcode`.
    pending_state_changes: Vec<StateChange>,
    /// Total app opcode cost consumed by this transaction — the sum of every
    /// approval and clear-state program run under it, including inner app calls
    /// (which invoke `record_program_cost` on this same tracer). Mirrors
    /// go-algorand's per-transaction `AppBudgetConsumed` roll-up
    /// (`tracer.go:504`). Accumulated even when opcode tracing is disabled,
    /// since per-transaction budget is a standard simulate response field.
    app_cost_consumed: u64,
    /// Unnamed resources reported by the AVM context when the request set
    /// `allow_unnamed_resources`. The simulation engine drains this after
    /// each transaction and merges it into the group-level set.
    unnamed_resources: UnnamedResourcesAccessed,
    /// Number of inner transaction groups submitted under this transaction
    /// (i.e. `itxn_submit` calls, including from nested inner app calls).
    /// The production `before_txn_group` call site
    /// (`avm_context.rs::submit_inner_group`) only fires for inner groups, so
    /// every call here counts one `MaxAppProgramCost` unit toward the group's
    /// `AppBudgetAdded` — mirroring go-algorand's `BeforeTxnGroup`, which adds
    /// `ep.Proto.MaxAppProgramCost` whenever `ep.GetCaller() != nil`
    /// (`tracer.go:156`). Accumulated even when opcode tracing is disabled,
    /// since group budget is a standard simulate response field.
    inner_txn_group_count: u64,
    /// Path/cursor tracking the currently-executing inner transaction,
    /// relative to the top-level transaction (issue #972). Updated
    /// unconditionally (not gated on `config.is_enabled()`) — `failed_at` is
    /// a standard simulate response field, not a trace-capture detail.
    cursor: TxnCursor,
    /// The relative path (see `TxnCursor::relative_path`) to the first
    /// transaction — top-level or nested inner — that failed under this
    /// top-level transaction. `None` until the first failure; mirrors
    /// go-algorand's `evalTracer.handleError`, which only ever sets
    /// `failedAt` once (`tracer.go:114`).
    failed_at: Option<Vec<usize>>,
}

impl SimulationTracer {
    /// Create a new simulation tracer with the given configuration.
    pub fn new(config: ExecTraceConfig) -> Self {
        SimulationTracer {
            config,
            current_program: None,
            transaction_trace: TransactionTrace::default(),
            trace_path: Vec::new(),
            program_state_stack: Vec::new(),
            initial_states: InitialStatesAccumulator::default(),
            pending_state_changes: Vec::new(),
            app_cost_consumed: 0,
            unnamed_resources: UnnamedResourcesAccessed::default(),
            inner_txn_group_count: 0,
            cursor: TxnCursor::new(),
            failed_at: None,
        }
    }

    /// Take the unnamed resources recorded during this transaction, leaving
    /// an empty set behind.
    pub fn take_unnamed_resources(&mut self) -> UnnamedResourcesAccessed {
        std::mem::take(&mut self.unnamed_resources)
    }

    /// Total app opcode cost consumed by this transaction (approval +
    /// clear-state programs, including inner app calls). This is the
    /// per-transaction `AppBudgetConsumed` figure for the simulate response.
    pub fn app_budget_consumed(&self) -> u64 {
        self.app_cost_consumed
    }

    /// Number of inner transaction groups submitted under this transaction
    /// (including nested inner app calls). Each unit contributes one
    /// `MaxAppProgramCost` to the group's `AppBudgetAdded` figure.
    pub fn inner_txn_group_count(&self) -> u64 {
        self.inner_txn_group_count
    }

    /// The path (relative to this tracer's top-level transaction) to the
    /// first inner transaction that failed while this top-level transaction
    /// was executing, if any (issue #972). Empty when the top-level
    /// transaction's own execution failed directly (no inner descent).
    /// `None` only in the rare case a group-level failure fired without a
    /// matching `before_txn` (see `TxnCursor::relative_path`); callers
    /// should fall back to the top-level-only path then.
    pub fn failed_at(&self) -> Option<&[usize]> {
        self.failed_at.as_deref()
    }

    /// Take the initial-state snapshot captured during this transaction,
    /// leaving an empty accumulator behind. Called by the simulation engine
    /// before consuming the tracer for its execution trace.
    pub fn take_initial_states(&mut self) -> InitialStatesAccumulator {
        std::mem::take(&mut self.initial_states)
    }

    /// Seed the created-app exclusion set from apps created by earlier
    /// transactions in the group, so a later transaction that executes as (or
    /// reads the state of) a previously-created app excludes it correctly.
    pub fn seed_created_apps(&mut self, app_ids: &[u64]) {
        for &app_id in app_ids {
            self.initial_states.mark_created_app(app_id);
        }
    }

    /// Consume the tracer and return the accumulated transaction trace.
    ///
    /// Returns `None` if tracing was not enabled.
    pub fn into_transaction_trace(self) -> Option<TransactionTrace> {
        if self.config.is_enabled() {
            Some(self.transaction_trace)
        } else {
            None
        }
    }

    /// Get a reference to the trace config.
    pub fn config(&self) -> &ExecTraceConfig {
        &self.config
    }

    /// Get a mutable reference to the currently active `TransactionTrace`.
    /// When `trace_path` is empty, returns the root trace.
    /// When `trace_path` has entries, follows the path through `inner_traces`.
    fn current_trace_mut(&mut self) -> &mut TransactionTrace {
        let mut trace = &mut self.transaction_trace;
        for &idx in &self.trace_path {
            trace = &mut trace.inner_traces[idx];
        }
        trace
    }
}

impl EvalTracer for SimulationTracer {
    fn before_txn_group(&mut self, _group_size: usize) {
        // The only production call site (avm_context.rs, inner-txn
        // submission) fires this exclusively for inner groups, so every call
        // counts one MaxAppProgramCost unit — see `inner_txn_group_count`
        // doc comment. Counted unconditionally (not gated on
        // `config.is_enabled()`), matching `app_cost_consumed`: group budget
        // is a standard simulate response field, not a trace-capture detail.
        self.inner_txn_group_count += 1;
        self.cursor.before_txn_group();
    }

    fn before_program(&mut self, program_type: ProgramType, program_hash: [u8; 32]) {
        if !self.config.is_enabled() {
            return;
        }

        self.current_program = Some(ProgramTraceState {
            program_type,
            program_hash,
            trace: ProgramTrace::default(),
            stack_before: Vec::new(),
            scratch_before: Vec::new(),
            pending_spawned_inners: Vec::new(),
        });
    }

    fn after_program(&mut self, _program_type: ProgramType, pass: bool, error: Option<&str>) {
        if !self.config.is_enabled() {
            return;
        }

        if let Some(state) = self.current_program.take() {
            let trace = self.current_trace_mut();
            match state.program_type {
                ProgramType::Approval => {
                    trace.approval_program_trace = Some(state.trace);
                    trace.approval_program_hash = Some(state.program_hash);
                }
                ProgramType::ClearState => {
                    trace.clear_state_program_trace = Some(state.trace);
                    trace.clear_state_program_hash = Some(state.program_hash);
                    // A clear-state program that rejected or errored has its
                    // persistent state changes rolled back, but the txn itself
                    // still succeeds (go-algorand `tracer.go:506-513`). Record
                    // the rollback and, when it was an execution error, the
                    // error message.
                    if !pass || error.is_some() {
                        trace.clear_state_rollback = true;
                        if let Some(msg) = error {
                            trace.clear_state_rollback_error = Some(msg.to_string());
                        }
                    }
                }
                ProgramType::LogicSig => {
                    trace.logicsig_trace = Some(state.trace);
                    trace.logicsig_hash = Some(state.program_hash);
                }
            }
        }
    }

    fn before_txn(&mut self, _group_index: usize) {
        // Cursor bookkeeping (issue #972) happens unconditionally, matching
        // `inner_txn_group_count`/`app_cost_consumed`: `failed_at` is a
        // standard simulate response field, not a trace-capture detail.
        self.cursor.before_txn();

        if !self.config.is_enabled() {
            return;
        }
        // Push a new TransactionTrace onto the current trace's inner_traces
        // and record its index.
        let idx = {
            let current = self.current_trace_mut();
            current.inner_traces.push(TransactionTrace::default());
            current.inner_traces.len() - 1
        };
        // Attach this inner's index to the spawning opcode. The spawning
        // opcode's trace unit is flushed at `after_opcode` (after the inner
        // finishes executing), so buffer the index on the parent program state
        // and drain it when that unit is built (go-algorand `tracer.go:224-228`).
        if let Some(parent) = self.current_program.as_mut() {
            parent.pending_spawned_inners.push(idx);
        }
        // Save the current program state (the outer program is mid-execution)
        // and descend into the inner trace.
        self.program_state_stack.push(self.current_program.take());
        self.trace_path.push(idx);
    }

    fn after_txn(&mut self, _group_index: usize, error: Option<&str>) {
        // Capture `failed_at` (issue #972) using the cursor's *current*
        // state — i.e. still including this transaction's own frame — before
        // popping it, so the path points at the actual failing transaction.
        // Mirrors go-algorand's `evalTracer.AfterTxn`, which calls
        // `handleError` before `cursorEvalTracer.AfterTxn` (`tracer.go:250-
        // 251,267`). Only the *first* failure is recorded (`handleError`'s
        // nil-check), since later, outer `AfterTxn`/`AfterTxnGroup` calls see
        // the same error as it propagates back up.
        if error.is_some() && self.failed_at.is_none() {
            self.failed_at = self.cursor.relative_path();
        }
        self.cursor.after_txn();

        if !self.config.is_enabled() {
            return;
        }
        // Pop back to the parent trace.
        self.trace_path.pop();
        // Restore the saved program state.
        self.current_program = self.program_state_stack.pop().flatten();
    }

    fn after_txn_group(&mut self, error: Option<&str>) {
        // See `after_txn`: capture before popping, first-failure-only.
        // Handles group-level failures not attributable to one specific
        // member's `AfterTxn` (e.g. the whole inner group rejected as
        // malformed) — mirrors go's `evalTracer.AfterTxnGroup`
        // (`tracer.go:181-183`).
        if error.is_some() && self.failed_at.is_none() {
            self.failed_at = self.cursor.relative_path();
        }
        self.cursor.after_txn_group();
    }

    fn before_opcode(&mut self, _pc: usize, _opcode: u8) {
        // Snapshot tracking is handled implicitly: stack_before and
        // scratch_before are updated at the end of each after_opcode call,
        // so they always reflect the state just before the next opcode.
    }

    fn after_opcode(
        &mut self,
        pc: usize,
        _opcode: u8,
        stack: &[AvmValue],
        scratch: &[AvmValue],
        _error: Option<&str>,
    ) {
        if !self.config.is_enabled() {
            return;
        }

        // Drain state changes recorded during this opcode before borrowing the
        // current program (avoids a double mutable borrow of `self`). Empty
        // unless `config.state` and a write/delete occurred.
        let state_changes = std::mem::take(&mut self.pending_state_changes);

        let state = match self.current_program.as_mut() {
            Some(s) => s,
            None => return,
        };

        let mut unit = OpcodeTraceUnit {
            pc,
            state_changes,
            // Drain any inner-transaction indices spawned by this opcode.
            spawned_inners: std::mem::take(&mut state.pending_spawned_inners),
            ..Default::default()
        };

        // Compute stack diff if stack tracing is enabled.
        if self.config.stack {
            let before_len = state.stack_before.len();

            // Find the common prefix: values at the bottom of the stack that
            // are unchanged between before and after.
            let mut common = 0;
            let check_len = before_len.min(stack.len());
            for (i, stack_val) in stack.iter().enumerate().take(check_len) {
                let matches = match (&state.stack_before[i], stack_val) {
                    (AvmValueTrace::Uint64(a), AvmValue::Uint64(b)) => *a == *b,
                    (AvmValueTrace::Bytes(a), AvmValue::Bytes(b)) => a == b,
                    _ => false,
                };
                if matches {
                    common = i + 1;
                } else {
                    break;
                }
            }

            // Pops removed from position `common` onward in old stack;
            // additions are from position `common` onward in new stack.
            unit.stack_pop_count = before_len - common;
            unit.stack_additions = stack[common..].iter().map(to_trace_value).collect();

            // Update stack snapshot for next opcode.
            state.stack_before = stack.iter().map(to_trace_value).collect();
        }

        // Compute scratch diff if scratch tracing is enabled.
        if self.config.scratch {
            let scratch_traced: Vec<AvmValueTrace> = scratch.iter().map(to_trace_value).collect();

            for (i, (old, new)) in state
                .scratch_before
                .iter()
                .zip(scratch_traced.iter())
                .enumerate()
            {
                let changed = match (old, new) {
                    (AvmValueTrace::Uint64(a), AvmValueTrace::Uint64(b)) => a != b,
                    (AvmValueTrace::Bytes(a), AvmValueTrace::Bytes(b)) => a != b,
                    _ => true,
                };
                if changed {
                    unit.scratch_changes.push((i, new.clone()));
                }
            }

            // If new scratch is longer (shouldn't normally happen), capture extras.
            for (i, item) in scratch_traced
                .iter()
                .enumerate()
                .skip(state.scratch_before.len())
            {
                unit.scratch_changes.push((i, item.clone()));
            }

            state.scratch_before = scratch_traced;
        }

        state.trace.opcodes.push(unit);
    }

    fn record_app_state_access(&mut self, access: &AppStateAccess<'_>) {
        // Initial-state capture is gated on the state-change trace config,
        // matching go-algorand's `newResourcesInitialStates` (nil unless
        // `TraceConfig.State`).
        if !self.config.state {
            return;
        }
        self.initial_states.record(access);

        // Per-opcode state-change capture (go-algorand `appendStateOperations`):
        // record only write/delete operations, never reads.
        let kind = match (access.op, access.state) {
            (AppStateOp::Write | AppStateOp::Delete, AppStateType::Global) => {
                StateChangeKind::GlobalState
            }
            (AppStateOp::Write | AppStateOp::Delete, AppStateType::Local) => {
                StateChangeKind::LocalState
            }
            (AppStateOp::Write | AppStateOp::Delete, AppStateType::Box) => {
                StateChangeKind::BoxState
            }
            _ => return,
        };
        let op = match access.op {
            AppStateOp::Delete => StateChangeOp::Delete,
            // Reads returned above; only writes reach here.
            _ => StateChangeOp::Write,
        };
        self.pending_state_changes.push(StateChange {
            kind,
            op,
            app_id: access.app_id,
            key: access.key.to_vec(),
            // Global/local writes carry their new value inline. Box writes
            // record `None` here and have it filled by `record_box_new_value`
            // once the write succeeds (the resulting box content is only known
            // post-mutation). Deletes leave `new_value` None (serialized as
            // omitted), matching go-algorand's empty TealValue.
            new_value: access.new_value.as_ref().map(teal_to_trace_value),
            account: access.account.map(Address),
        });
    }

    fn record_box_new_value(&mut self, new_value: Option<TealValue>) {
        if !self.config.state {
            return;
        }
        // Attach the post-write box content to the box state-change just pushed
        // by `record_app_state_access` (go-algorand `updateNewStateValues`).
        // The most recent pending change is this opcode's box write; guard on
        // the kind so a stray call can never corrupt a global/local change.
        if let Some(last) = self.pending_state_changes.last_mut() {
            if last.kind == StateChangeKind::BoxState {
                last.new_value = new_value.as_ref().map(teal_to_trace_value);
            }
        }
    }

    fn record_created_app(&mut self, app_id: u64) {
        if self.config.state {
            self.initial_states.mark_created_app(app_id);
        }
    }

    fn record_program_cost(&mut self, program_type: ProgramType, cost: u64) {
        // Roll approval + clear-state program costs (including inner app calls,
        // which call this on the same tracer) into the transaction's app budget
        // consumed — go-algorand `tracer.go:504`. LogicSig cost is measured
        // separately during signature verification in `Simulator::check()`, so
        // it is not accumulated here. Not gated on trace config: per-transaction
        // budget is always reported.
        match program_type {
            ProgramType::Approval | ProgramType::ClearState => {
                self.app_cost_consumed = self.app_cost_consumed.saturating_add(cost);
            }
            ProgramType::LogicSig => {}
        }
    }

    fn record_unnamed_resource(&mut self, access: &UnnamedResourceAccess) {
        // Not gated on trace config: the AVM context only reports these when
        // the request enabled `allow_unnamed_resources`, and the response
        // field is independent of exec tracing.
        match access {
            UnnamedResourceAccess::Account(addr) => {
                self.unnamed_resources.accounts.insert(Address(*addr));
            }
            UnnamedResourceAccess::Asset(id) => {
                self.unnamed_resources.assets.insert(*id);
            }
            UnnamedResourceAccess::App(id) => {
                self.unnamed_resources.apps.insert(*id);
            }
            UnnamedResourceAccess::Box(app_id, name) => {
                self.unnamed_resources.boxes.insert((*app_id, name.clone()));
            }
            UnnamedResourceAccess::AssetHolding(addr, id) => {
                self.unnamed_resources
                    .asset_holdings
                    .insert((Address(*addr), *id));
            }
            UnnamedResourceAccess::AppLocal(addr, id) => {
                self.unnamed_resources
                    .app_locals
                    .insert((Address(*addr), *id));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulation_tracer_disabled() {
        let config = ExecTraceConfig::default();
        let mut tracer = SimulationTracer::new(config);

        tracer.before_program(ProgramType::Approval, [0u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(1)], &[], None);
        tracer.after_program(ProgramType::Approval, true, None);

        let trace = tracer.into_transaction_trace();
        assert!(trace.is_none());
    }

    #[test]
    fn test_simulation_tracer_enabled_captures_opcodes() {
        let config = ExecTraceConfig {
            enable: true,
            stack: false,
            scratch: false,
            state: false,
        };
        let mut tracer = SimulationTracer::new(config);

        tracer.before_program(ProgramType::Approval, [0u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(1)], &[], None);
        tracer.before_opcode(1, 0x43);
        tracer.after_opcode(1, 0x43, &[AvmValue::Uint64(1)], &[], None);
        tracer.after_program(ProgramType::Approval, true, None);

        let trace = tracer.into_transaction_trace().unwrap();
        let approval = trace.approval_program_trace.unwrap();
        assert_eq!(approval.opcodes.len(), 2);
        assert_eq!(approval.opcodes[0].pc, 0);
        assert_eq!(approval.opcodes[1].pc, 1);
    }

    #[test]
    fn test_seeded_created_app_is_excluded() {
        use algo_avm::tracer::{AppStateAccess, AppStateOp, AppStateType};

        let config = ExecTraceConfig {
            enable: true,
            stack: false,
            scratch: false,
            state: true,
        };
        let mut tracer = SimulationTracer::new(config);
        // Seed an app created by an earlier transaction in the group.
        tracer.seed_created_apps(&[1001]);

        // A later transaction executing as app 1001 reads its own global state.
        let access = AppStateAccess {
            executing_app_id: 1001,
            app_id: 1001,
            state: AppStateType::Global,
            op: AppStateOp::Read,
            account: None,
            key: b"k",
            pre_value: Some(algo_types::TealValue::Uint(7)),
            new_value: None,
        };
        tracer.record_app_state_access(&access);

        // The seeded created app must be excluded from initial states.
        let states = tracer.take_initial_states().into_resources_initial_states();
        assert!(states.app_initial_states.is_empty());
    }

    #[test]
    fn test_simulation_tracer_logicsig() {
        let config = ExecTraceConfig {
            enable: true,
            stack: false,
            scratch: false,
            state: false,
        };
        let mut tracer = SimulationTracer::new(config);

        tracer.before_program(ProgramType::LogicSig, [0u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(1)], &[], None);
        tracer.after_program(ProgramType::LogicSig, true, None);

        let trace = tracer.into_transaction_trace().unwrap();
        assert!(trace.logicsig_trace.is_some());
        assert!(trace.approval_program_trace.is_none());
    }

    #[test]
    fn test_simulation_tracer_stack_tracking() {
        let config = ExecTraceConfig {
            enable: true,
            stack: true,
            scratch: false,
            state: false,
        };
        let mut tracer = SimulationTracer::new(config);

        tracer.before_program(ProgramType::Approval, [0u8; 32]);

        // First opcode pushes 1 value.
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(42)], &[], None);

        let state = tracer.current_program.as_ref().unwrap();
        let unit = &state.trace.opcodes[0];
        assert_eq!(unit.stack_additions.len(), 1);
        assert_eq!(unit.stack_pop_count, 0);

        // Second opcode pops 1, pushes 0 (net decrease by 1).
        tracer.before_opcode(1, 0x43);
        tracer.after_opcode(1, 0x43, &[], &[], None);

        let state = tracer.current_program.as_ref().unwrap();
        let unit = &state.trace.opcodes[1];
        assert_eq!(unit.stack_pop_count, 1);
        assert_eq!(unit.stack_additions.len(), 0);

        tracer.after_program(ProgramType::Approval, true, None);
    }

    #[test]
    fn test_simulation_tracer_inner_txn_traces() {
        let config = ExecTraceConfig {
            enable: true,
            stack: false,
            scratch: false,
            state: false,
        };
        let mut tracer = SimulationTracer::new(config);

        // Top-level approval program begins
        tracer.before_program(ProgramType::Approval, [0u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(1)], &[], None);

        // Inner transaction group (simulating itxn_submit hook calls)
        tracer.before_txn_group(1);
        tracer.before_txn(0);

        // Inner program executes
        tracer.before_program(ProgramType::Approval, [0u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(1)], &[], None);
        tracer.after_program(ProgramType::Approval, true, None);

        tracer.after_txn(0, None);
        tracer.after_txn_group(None);

        // Continue top-level program
        tracer.before_opcode(3, 0x43);
        tracer.after_opcode(3, 0x43, &[AvmValue::Uint64(1)], &[], None);
        tracer.after_program(ProgramType::Approval, true, None);

        let trace = tracer.into_transaction_trace().unwrap();

        // Top-level approval trace should have 2 opcodes
        let approval = trace.approval_program_trace.unwrap();
        assert_eq!(approval.opcodes.len(), 2);

        // Should have one inner trace
        assert_eq!(trace.inner_traces.len(), 1);
        let inner = &trace.inner_traces[0];
        let inner_approval = inner.approval_program_trace.as_ref().unwrap();
        assert_eq!(inner_approval.opcodes.len(), 1);
    }

    #[test]
    fn test_simulation_tracer_nested_inner_txns() {
        let config = ExecTraceConfig {
            enable: true,
            stack: false,
            scratch: false,
            state: false,
        };
        let mut tracer = SimulationTracer::new(config);

        // Top-level program
        tracer.before_program(ProgramType::Approval, [0u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(1)], &[], None);

        // First inner txn
        tracer.before_txn_group(1);
        tracer.before_txn(0);

        tracer.before_program(ProgramType::Approval, [0u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(1)], &[], None);

        // Nested inner txn (depth 2)
        tracer.before_txn_group(1);
        tracer.before_txn(0);

        tracer.before_program(ProgramType::Approval, [0u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(1)], &[], None);
        tracer.after_program(ProgramType::Approval, true, None);

        tracer.after_txn(0, None);
        tracer.after_txn_group(None);

        // Continue first inner program
        tracer.before_opcode(3, 0x43);
        tracer.after_opcode(3, 0x43, &[AvmValue::Uint64(1)], &[], None);
        tracer.after_program(ProgramType::Approval, true, None);

        tracer.after_txn(0, None);
        tracer.after_txn_group(None);

        // Continue top-level
        tracer.before_opcode(3, 0x43);
        tracer.after_opcode(3, 0x43, &[AvmValue::Uint64(1)], &[], None);
        tracer.after_program(ProgramType::Approval, true, None);

        let trace = tracer.into_transaction_trace().unwrap();

        // Top-level: 2 opcodes, 1 inner
        assert_eq!(
            trace.approval_program_trace.as_ref().unwrap().opcodes.len(),
            2
        );
        assert_eq!(trace.inner_traces.len(), 1);

        // First inner: 2 opcodes, 1 nested inner
        let inner = &trace.inner_traces[0];
        assert_eq!(
            inner.approval_program_trace.as_ref().unwrap().opcodes.len(),
            2
        );
        assert_eq!(inner.inner_traces.len(), 1);

        // Nested inner: 1 opcode, no further inners
        let nested = &inner.inner_traces[0];
        assert_eq!(
            nested
                .approval_program_trace
                .as_ref()
                .unwrap()
                .opcodes
                .len(),
            1
        );
        assert_eq!(nested.inner_traces.len(), 0);
    }

    #[test]
    fn test_simulation_tracer_multiple_sibling_inner_txns() {
        let config = ExecTraceConfig {
            enable: true,
            stack: false,
            scratch: false,
            state: false,
        };
        let mut tracer = SimulationTracer::new(config);

        tracer.before_program(ProgramType::Approval, [0u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(1)], &[], None);

        // Inner txn group with 2 siblings
        tracer.before_txn_group(2);

        // Sibling 1
        tracer.before_txn(0);
        tracer.before_program(ProgramType::Approval, [0u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(1)], &[], None);
        tracer.after_program(ProgramType::Approval, true, None);
        tracer.after_txn(0, None);

        // Sibling 2
        tracer.before_txn(1);
        tracer.before_program(ProgramType::Approval, [0u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(2)], &[], None);
        tracer.after_program(ProgramType::Approval, true, None);
        tracer.after_txn(1, None);

        tracer.after_txn_group(None);

        tracer.before_opcode(3, 0x43);
        tracer.after_opcode(3, 0x43, &[AvmValue::Uint64(1)], &[], None);
        tracer.after_program(ProgramType::Approval, true, None);

        let trace = tracer.into_transaction_trace().unwrap();

        assert_eq!(trace.inner_traces.len(), 2);
        assert!(trace.inner_traces[0].approval_program_trace.is_some());
        assert!(trace.inner_traces[1].approval_program_trace.is_some());
    }

    /// When an opcode spawns inner transactions, its trace unit records the
    /// indices of those inners (go-algorand `OpcodeTraceUnit.SpawnedInners`).
    /// The inners spawn *during* the opcode (between `before_opcode` and
    /// `after_opcode`), and the indices must land on that opcode's unit.
    #[test]
    fn test_simulation_tracer_spawned_inners_recorded() {
        let config = ExecTraceConfig {
            enable: true,
            ..Default::default()
        };
        let mut tracer = SimulationTracer::new(config);

        tracer.before_program(ProgramType::Approval, [0u8; 32]);
        // Opcode 0: a plain push (no inners).
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(1)], &[], None);

        // Opcode 1: itxn_submit. Two inners spawn during its execution.
        tracer.before_opcode(1, 0xb6);
        tracer.before_txn_group(2);
        tracer.before_txn(0);
        tracer.before_program(ProgramType::Approval, [0u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(1)], &[], None);
        tracer.after_program(ProgramType::Approval, true, None);
        tracer.after_txn(0, None);
        tracer.before_txn(1);
        tracer.before_program(ProgramType::Approval, [0u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(2)], &[], None);
        tracer.after_program(ProgramType::Approval, true, None);
        tracer.after_txn(1, None);
        tracer.after_txn_group(None);
        // itxn_submit completes — its unit is flushed here with the inners.
        tracer.after_opcode(1, 0xb6, &[], &[], None);

        tracer.after_program(ProgramType::Approval, true, None);

        let trace = tracer.into_transaction_trace().unwrap();
        let approval = trace.approval_program_trace.unwrap();
        assert_eq!(approval.opcodes.len(), 2);
        // The push opcode spawned nothing.
        assert!(approval.opcodes[0].spawned_inners.is_empty());
        // itxn_submit spawned inner traces 0 and 1.
        assert_eq!(approval.opcodes[1].spawned_inners, vec![0, 1]);
        assert_eq!(trace.inner_traces.len(), 2);
    }

    /// A failing clear-state program sets `clear_state_rollback` and, when the
    /// failure is an execution error, `clear_state_rollback_error`
    /// (go-algorand `tracer.go:506-513`).
    #[test]
    fn test_simulation_tracer_clear_state_rollback_on_error() {
        let config = ExecTraceConfig {
            enable: true,
            ..Default::default()
        };
        let mut tracer = SimulationTracer::new(config);

        tracer.before_program(ProgramType::ClearState, [7u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(0)], &[], None);
        tracer.after_program(
            ProgramType::ClearState,
            false,
            Some("logic eval error: assert failed"),
        );

        let trace = tracer.into_transaction_trace().unwrap();
        assert!(trace.clear_state_program_trace.is_some());
        assert!(trace.clear_state_rollback);
        assert_eq!(
            trace.clear_state_rollback_error.as_deref(),
            Some("logic eval error: assert failed")
        );
    }

    /// A clear-state program that merely rejects (returns 0, no error) still
    /// rolls back, but records no rollback error.
    #[test]
    fn test_simulation_tracer_clear_state_rollback_on_reject_no_error() {
        let config = ExecTraceConfig {
            enable: true,
            ..Default::default()
        };
        let mut tracer = SimulationTracer::new(config);

        tracer.before_program(ProgramType::ClearState, [7u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(0)], &[], None);
        tracer.after_program(ProgramType::ClearState, false, None);

        let trace = tracer.into_transaction_trace().unwrap();
        assert!(trace.clear_state_rollback);
        assert!(trace.clear_state_rollback_error.is_none());
    }

    /// A clear-state program that passes records no rollback.
    #[test]
    fn test_simulation_tracer_clear_state_no_rollback_on_pass() {
        let config = ExecTraceConfig {
            enable: true,
            ..Default::default()
        };
        let mut tracer = SimulationTracer::new(config);

        tracer.before_program(ProgramType::ClearState, [7u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(1)], &[], None);
        tracer.after_program(ProgramType::ClearState, true, None);

        let trace = tracer.into_transaction_trace().unwrap();
        assert!(!trace.clear_state_rollback);
        assert!(trace.clear_state_rollback_error.is_none());
    }
}
