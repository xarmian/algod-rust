//! AVM execution tracer infrastructure.
//!
//! Provides the [`EvalTracer`] trait for observing AVM program execution at
//! the opcode level. Implementations can capture stack snapshots, scratch
//! changes, and program lifecycle events for simulation tracing or debugging.
//!
//! The trait mirrors the program-level subset of go-algorand's
//! `logic.EvalTracer` interface (transaction-group-level hooks live in the
//! simulation layer in `algo-ledger`).

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
    /// Called before a program begins executing.
    fn before_program(&mut self, _program_type: ProgramType) {}

    /// Called after a program finishes executing.
    ///
    /// `pass` indicates whether the program approved (`true`) or rejected
    /// (`false`). `error` is `Some` if the program terminated with an error.
    fn after_program(&mut self, _program_type: ProgramType, _pass: bool, _error: Option<&str>) {}

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
        tracer.before_program(ProgramType::Approval);
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
