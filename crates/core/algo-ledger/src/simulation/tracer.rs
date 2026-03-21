//! Simulation tracer implementing `algo_avm::tracer::EvalTracer`.
//!
//! Captures opcode-level execution details (stack changes, scratch changes)
//! according to an [`ExecTraceConfig`] and accumulates them into
//! [`TransactionTrace`] structures for the simulation result.

use algo_avm::machine::AvmValue;
use algo_avm::tracer::EvalTracer;

use super::trace::{
    AvmValueTrace, ExecTraceConfig, OpcodeTraceUnit, ProgramTrace, TransactionTrace,
};

/// Converts an AVM machine value to a trace-friendly representation.
fn to_trace_value(v: &AvmValue) -> AvmValueTrace {
    match v {
        AvmValue::Uint64(n) => AvmValueTrace::Uint64(*n),
        AvmValue::Bytes(b) => AvmValueTrace::Bytes(b.clone()),
    }
}

/// The type of program currently being traced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProgramType {
    Approval,
    ClearState,
    LogicSig,
}

/// State tracked during a single program's execution.
struct ProgramTraceState {
    /// The type of program being traced.
    program_type: ProgramType,
    /// Accumulated opcode trace entries.
    trace: ProgramTrace,
    /// Stack snapshot before the current opcode (for computing diffs).
    stack_before: Vec<AvmValueTrace>,
    /// Scratch snapshot before the current opcode (for computing diffs).
    scratch_before: Vec<AvmValueTrace>,
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
/// - `state`: capture application state changes (not yet implemented at
///   the tracer level — state changes are captured by the simulation engine).
pub struct SimulationTracer {
    /// Configuration controlling what to capture.
    config: ExecTraceConfig,
    /// Current program execution state (set between before_program/after_program).
    current_program: Option<ProgramTraceState>,
    /// The accumulated transaction trace being built.
    transaction_trace: TransactionTrace,
}

impl SimulationTracer {
    /// Create a new simulation tracer with the given configuration.
    pub fn new(config: ExecTraceConfig) -> Self {
        SimulationTracer {
            config,
            current_program: None,
            transaction_trace: TransactionTrace::default(),
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
}

impl EvalTracer for SimulationTracer {
    fn before_program(&mut self, is_logicsig: bool) {
        if !self.config.is_enabled() {
            return;
        }

        let program_type = if is_logicsig {
            ProgramType::LogicSig
        } else {
            // Distinguish approval vs clear-state by checking if the
            // approval trace is already populated. If so, this must be
            // the clear-state program.
            if self.transaction_trace.approval_program_trace.is_some() {
                ProgramType::ClearState
            } else {
                ProgramType::Approval
            }
        };

        self.current_program = Some(ProgramTraceState {
            program_type,
            trace: ProgramTrace::default(),
            stack_before: Vec::new(),
            scratch_before: Vec::new(),
        });
    }

    fn after_program(&mut self, _is_logicsig: bool, _pass: bool, _error: Option<&str>) {
        if !self.config.is_enabled() {
            return;
        }

        if let Some(state) = self.current_program.take() {
            match state.program_type {
                ProgramType::Approval => {
                    self.transaction_trace.approval_program_trace = Some(state.trace);
                }
                ProgramType::ClearState => {
                    self.transaction_trace.clear_state_program_trace = Some(state.trace);
                }
                ProgramType::LogicSig => {
                    self.transaction_trace.logicsig_trace = Some(state.trace);
                }
            }
        }
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

        let state = match self.current_program.as_mut() {
            Some(s) => s,
            None => return,
        };

        let mut unit = OpcodeTraceUnit {
            pc,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulation_tracer_disabled() {
        let config = ExecTraceConfig::default();
        let mut tracer = SimulationTracer::new(config);

        tracer.before_program(false);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(1)], &[], None);
        tracer.after_program(false, true, None);

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

        tracer.before_program(false);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(1)], &[], None);
        tracer.before_opcode(1, 0x43);
        tracer.after_opcode(1, 0x43, &[AvmValue::Uint64(1)], &[], None);
        tracer.after_program(false, true, None);

        let trace = tracer.into_transaction_trace().unwrap();
        let approval = trace.approval_program_trace.unwrap();
        assert_eq!(approval.opcodes.len(), 2);
        assert_eq!(approval.opcodes[0].pc, 0);
        assert_eq!(approval.opcodes[1].pc, 1);
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

        tracer.before_program(true);
        tracer.before_opcode(0, 0x81);
        tracer.after_opcode(0, 0x81, &[AvmValue::Uint64(1)], &[], None);
        tracer.after_program(true, true, None);

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

        tracer.before_program(false);

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

        tracer.after_program(false, true, None);
    }
}
