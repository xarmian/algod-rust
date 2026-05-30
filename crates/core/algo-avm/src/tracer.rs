//! AVM execution tracer infrastructure.
//!
//! Provides the [`EvalTracer`] trait for observing AVM program execution at
//! the opcode level. Implementations can capture stack snapshots, scratch
//! changes, and program lifecycle events for simulation tracing or debugging.
//!
//! The trait mirrors the program-level subset of go-algorand's
//! `logic.EvalTracer` interface (transaction-group-level hooks live in the
//! simulation layer in `algo-ledger`).

use algo_types::TealValue;

use crate::machine::AvmValue;

/// The type of AVM program being executed.
///
/// Used by [`EvalTracer`] callbacks to distinguish between approval,
/// clear-state, and LogicSig programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramType {
    /// Application approval program.
    Approval,
    /// Application clear-state program.
    ClearState,
    /// LogicSig (stateless signature) program.
    LogicSig,
}

/// The category of application state involved in an access.
///
/// Mirrors the `logic.AppStateEnum` categories used by go-algorand's
/// `OpSpec.AppStateExplain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppStateType {
    /// Application global state.
    Global,
    /// Application local state (tied to an account address).
    Local,
    /// Application box storage.
    Box,
}

/// The kind of operation performed on application state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppStateOp {
    /// A read access (e.g. `app_global_get`, `box_get`).
    Read,
    /// A write access (e.g. `app_global_put`, `box_put`).
    Write,
    /// A delete access (e.g. `app_global_del`, `box_del`).
    Delete,
}

/// A single application-state access reported to an [`EvalTracer`] so that
/// simulation can capture pre-execution ("initial") state.
///
/// Mirrors the inputs go-algorand derives from `OpSpec.AppStateExplain` +
/// `AppStateQuerying` (see `ledger/simulation/initialStates.go`).
pub struct AppStateAccess<'a> {
    /// The currently-executing application (go-algorand's `cx.AppID()`).
    /// Used for the created-app exclusion check.
    pub executing_app_id: u64,
    /// The application whose state is being accessed. Equals
    /// `executing_app_id` for non-`_ex` opcodes; may differ for foreign-app
    /// reads (e.g. `app_global_get_ex`).
    pub app_id: u64,
    /// The category of state being accessed.
    pub state: AppStateType,
    /// The operation kind.
    pub op: AppStateOp,
    /// The account address for local-state accesses; `None` for global/box.
    pub account: Option<[u8; 32]>,
    /// The state key (global/local key, or box name).
    pub key: &'a [u8],
    /// The on-chain value immediately before this operation, or `None` if the
    /// key/box did not exist. Used for initial-state capture.
    pub pre_value: Option<TealValue>,
    /// The value written by this operation (for `Write`), or `None` for reads
    /// and deletes. Used for per-opcode state-change capture.
    pub new_value: Option<TealValue>,
}

/// Trait for observing AVM program execution.
///
/// All methods have no-op default implementations so that callers only need
/// to override the events they care about.
///
/// Lifecycle:
/// 1. `before_program` — called once before the first opcode.
/// 2. For each opcode: `before_opcode` → dispatch → `after_opcode`.
/// 3. `after_program` — called once after execution completes or errors.
pub trait EvalTracer {
    /// Called before a block is evaluated.
    fn before_block(&mut self, _round: u64) {}

    /// Called after a block has been evaluated.
    fn after_block(&mut self, _round: u64) {}

    /// Called before a transaction group is executed (top-level or inner).
    fn before_txn_group(&mut self, _group_size: usize) {}

    /// Called after a transaction group has been executed.
    fn after_txn_group(&mut self, _error: Option<&str>) {}

    /// Called before a transaction within a group is executed.
    /// `group_index` is the index within the current group.
    fn before_txn(&mut self, _group_index: usize) {}

    /// Called after a transaction within a group has been executed.
    fn after_txn(&mut self, _group_index: usize, _error: Option<&str>) {}

    /// Called before a program begins executing.
    ///
    /// `program_hash` is the SHA-512/256 hash of the program bytes about to run
    /// (go-algorand's `crypto.Hash(cx.GetProgram())`), used to populate the
    /// exec-trace program hash fields.
    fn before_program(&mut self, _program_type: ProgramType, _program_hash: [u8; 32]) {}

    /// Called after a program finishes executing.
    ///
    /// `pass` indicates whether the program approved (`true`) or rejected
    /// (`false`). `error` is `Some` if the program terminated with an error.
    fn after_program(&mut self, _program_type: ProgramType, _pass: bool, _error: Option<&str>) {}

    /// Called once a program finishes, reporting the opcode `cost` it consumed
    /// (go-algorand's `cx.Cost()`). Inner app calls invoke this on the same
    /// tracer as their caller, so a tracer can roll the cost up into the
    /// top-level transaction's budget figure (`tracer.go:495,504`). Unlike the
    /// trace-capture callbacks, implementors should record this regardless of
    /// whether opcode tracing is enabled, since per-transaction budget is a
    /// standard simulate response field.
    fn record_program_cost(&mut self, _program_type: ProgramType, _cost: u64) {}

    /// Called before each opcode is dispatched.
    ///
    /// `pc` is the instruction index (not byte offset). `opcode` is the raw
    /// opcode byte.
    fn before_opcode(&mut self, _pc: usize, _opcode: u8) {}

    /// Called after each opcode completes (or errors).
    ///
    /// `stack` and `scratch` are snapshots of the machine state after the
    /// opcode executed. `error` is `Some` if the opcode produced an error.
    fn after_opcode(
        &mut self,
        _pc: usize,
        _opcode: u8,
        _stack: &[AvmValue],
        _scratch: &[AvmValue],
        _error: Option<&str>,
    ) {
    }

    /// Report an application-state access for initial-state capture.
    ///
    /// Called by the ledger AVM context before each application global/local/box
    /// read, write, or delete during simulation. The default is a no-op, so the
    /// consensus apply path (which attaches no tracer) is entirely unaffected.
    fn record_app_state_access(&mut self, _access: &AppStateAccess<'_>) {}

    /// Fill in the *post-write* whole-box content for the box state-change just
    /// recorded via [`record_app_state_access`].
    ///
    /// Box writes (`box_put`/`box_create`/`box_replace`/`box_resize`/
    /// `box_splice`) — unlike global/local writes — produce a new value that is
    /// only known after the mutation (partial writes modify the full box). The
    /// AVM context records the state-change *operation* before mutating (so it
    /// is captured even if the opcode errors, like go-algorand's `BeforeOpcode`
    /// `appendStateOperations`), then calls this once the write succeeds to
    /// attach the box's resulting content — mirroring go-algorand's
    /// `AfterOpcode` → `updateNewStateValues` → `AppStateQuerying` GetBox read
    /// (`ledger/simulation/tracer.go:386`, `opcodeExplain.go:314`). `box_del`
    /// never calls this, leaving the new value empty. The default is a no-op.
    fn record_box_new_value(&mut self, _new_value: Option<TealValue>) {}

    /// Report that an application was created during simulation.
    ///
    /// The initial states of apps created mid-simulation are excluded from
    /// capture (they have no pre-existing on-chain state). Mirrors
    /// go-algorand's `ResourcesInitialStates.CreatedApp` population in
    /// `ledger/simulation/tracer.go`.
    fn record_created_app(&mut self, _app_id: u64) {}
}

/// A no-op tracer that discards all events.
///
/// Used as a placeholder when tracing is not needed. All trait methods use
/// the default no-op implementations.
pub struct NullTracer;

impl EvalTracer for NullTracer {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that NullTracer compiles and can be used as a trait object.
    #[test]
    fn test_null_tracer_is_usable() {
        let mut tracer = NullTracer;
        tracer.before_program(ProgramType::Approval, [0u8; 32]);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[], &[], None);
        tracer.after_program(ProgramType::Approval, true, None);
    }

    /// Verify that a custom tracer can capture events.
    #[test]
    fn test_custom_tracer_captures_events() {
        struct CountingTracer {
            opcode_count: usize,
        }
        impl EvalTracer for CountingTracer {
            fn before_opcode(&mut self, _pc: usize, _opcode: u8) {
                self.opcode_count += 1;
            }
        }

        let mut tracer = CountingTracer { opcode_count: 0 };
        tracer.before_opcode(0, 0x81);
        tracer.before_opcode(1, 0x43);
        assert_eq!(tracer.opcode_count, 2);
    }
}
