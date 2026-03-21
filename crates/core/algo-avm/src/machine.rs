//! AVM stack machine -- the runtime execution engine.
//!
//! Provides the `AvmMachine` struct that executes parsed AVM programs
//! instruction by instruction, managing the value stack, call stack,
//! scratch space, and cost budget.

use std::collections::HashMap;

use algo_error::AlgoError;

use crate::bytecode::Program;
use crate::context::AvmContext;
use crate::opcode::{self, CostKind};
use crate::ops;
use crate::tracer::EvalTracer;

/// Maximum stack depth allowed by the AVM.
const MAX_STACK_DEPTH: usize = 1000;

/// Number of scratch space slots.
const SCRATCH_SPACE_SIZE: usize = 256;

/// Maximum call stack depth.
const MAX_CALL_STACK_DEPTH: usize = 256;

/// A value on the AVM stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvmValue {
    /// Unsigned 64-bit integer.
    Uint64(u64),
    /// Byte string.
    Bytes(Vec<u8>),
}

impl AvmValue {
    /// Returns `true` if the value is "truthy" (nonzero uint64 or non-empty bytes).
    pub fn is_truthy(&self) -> bool {
        match self {
            AvmValue::Uint64(v) => *v != 0,
            AvmValue::Bytes(b) => !b.is_empty(),
        }
    }
}

/// Execution mode for the AVM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecMode {
    /// Running as a LogicSig (stateless signature check).
    LogicSig,
    /// Running as an Application (approval/clear-state program).
    Application,
}

/// A frame on the call stack, pushed by `callsub` and popped by `retsub`.
#[derive(Debug, Clone)]
pub struct CallFrame {
    /// Instruction index to return to (the instruction after the callsub).
    pub return_pc: usize,
    /// Stack depth at the call point (for frame_dig/frame_bury).
    pub frame_pointer: usize,
    /// Whether `proto` was used — triggers stack cleanup in `retsub`.
    pub clear: bool,
    /// Number of arguments declared by `proto`.
    pub args: usize,
    /// Number of return values declared by `proto`.
    pub returns: usize,
}

/// Aggregated opcode coverage statistics.
///
/// Tracks which opcode bytes were executed across one or more program runs.
/// Use [`AvmMachine::opcode_coverage`] to retrieve the current snapshot and
/// [`OpcodeCoverage::merge`] to combine coverage across multiple runs.
#[derive(Debug, Clone)]
pub struct OpcodeCoverage {
    /// One flag per opcode byte (0..255). `true` if that opcode was executed.
    pub hit: [bool; 256],
}

impl Default for OpcodeCoverage {
    fn default() -> Self {
        Self { hit: [false; 256] }
    }
}

impl OpcodeCoverage {
    /// Merge another coverage snapshot into this one (union of hits).
    pub fn merge(&mut self, other: &OpcodeCoverage) {
        for i in 0..256 {
            self.hit[i] |= other.hit[i];
        }
    }

    /// Count of defined opcodes that were hit.
    pub fn hit_count(&self) -> usize {
        opcode::all_opcodes()
            .iter()
            .filter(|(byte, _)| self.hit[*byte as usize])
            .count()
    }

    /// Total number of defined opcodes (denominator).
    pub fn total_defined(&self) -> usize {
        opcode::defined_opcode_count()
    }

    /// Return the list of defined opcodes that were NOT hit.
    pub fn missed_opcodes(&self) -> Vec<(u8, &'static str)> {
        opcode::all_opcodes()
            .into_iter()
            .filter(|(byte, _)| !self.hit[*byte as usize])
            .collect()
    }

    /// Return the list of defined opcodes that were hit.
    pub fn hit_opcodes(&self) -> Vec<(u8, &'static str)> {
        opcode::all_opcodes()
            .into_iter()
            .filter(|(byte, _)| self.hit[*byte as usize])
            .collect()
    }

    /// Coverage ratio as a percentage (0.0 - 100.0).
    pub fn coverage_pct(&self) -> f64 {
        let total = self.total_defined();
        if total == 0 {
            return 0.0;
        }
        (self.hit_count() as f64 / total as f64) * 100.0
    }
}

/// The AVM stack machine.
pub struct AvmMachine {
    /// Value stack.
    pub stack: Vec<AvmValue>,
    /// Call stack for callsub/retsub.
    pub call_stack: Vec<CallFrame>,
    /// Scratch space (256 slots).
    pub scratch: Vec<AvmValue>,
    /// Program counter (instruction index, not byte offset).
    pub pc: usize,
    /// Cost budget remaining.
    pub budget: i64,
    /// Execution mode.
    pub mode: ExecMode,
    /// Integer constant pool (set by intcblock).
    pub int_constants: Vec<u64>,
    /// Byte constant pool (set by bytecblock).
    pub byte_constants: Vec<Vec<u8>>,
    /// The parsed program being executed.
    pub program: Program,
    /// Program version (convenience, copied from program.version).
    pub version: u8,
    /// Whether execution has finished.
    pub finished: bool,
    /// Final result: true = pass (approve), false = reject.
    pub pass: bool,
    /// Pre-built map from byte offset to instruction index for O(1) branch resolution.
    pub(crate) offset_to_index: HashMap<usize, usize>,
    /// Byte offset just past the last instruction (valid branch-to-end target).
    pub(crate) end_of_program_offset: usize,
    /// Tracks which opcode bytes have been executed during this run.
    pub opcode_hits: [bool; 256],
    /// Set by `callsub` when the branch target is a `proto` instruction.
    /// Cleared by `proto` after checking. Mirrors Go's `cx.fromCallsub`.
    pub from_callsub: bool,
}

impl AvmMachine {
    /// Create a new AVM machine ready to execute the given program.
    ///
    /// `budget` is the initial cost budget (e.g. 700 for LogicSig, 700 per app call).
    pub fn new(program: Program, mode: ExecMode, budget: i64) -> Self {
        let version = program.version;
        let mut scratch = Vec::with_capacity(SCRATCH_SPACE_SIZE);
        for _ in 0..SCRATCH_SPACE_SIZE {
            scratch.push(AvmValue::Uint64(0));
        }
        let mut offset_to_index = HashMap::with_capacity(program.instructions.len());
        for (idx, instr) in program.instructions.iter().enumerate() {
            offset_to_index.insert(instr.offset, idx);
        }
        // Compute end-of-program byte offset (after last instruction + its immediates).
        let end_of_program_offset = if let Some(last) = program.instructions.last() {
            let imm_len = crate::validator::immediate_byte_len(&last.immediates);
            last.offset + 1 + imm_len
        } else {
            0
        };
        AvmMachine {
            stack: Vec::new(),
            call_stack: Vec::new(),
            scratch,
            pc: 0,
            budget,
            mode,
            int_constants: Vec::new(),
            byte_constants: Vec::new(),
            version,
            program,
            finished: false,
            pass: false,
            offset_to_index,
            end_of_program_offset,
            opcode_hits: [false; 256],
            from_callsub: false,
        }
    }

    /// Execute one instruction and advance the PC.
    ///
    /// `ctx` provides external state access (transaction fields, app state, etc.).
    /// Pure-opcode tests can pass `&mut NullContext`.
    pub fn step(&mut self, ctx: &mut dyn AvmContext) -> Result<(), AlgoError> {
        if self.finished {
            return Err(AlgoError::Avm {
                message: "step called after execution finished".to_string(),
            });
        }

        // If PC is past end of instructions, program finishes.
        if self.pc >= self.program.instructions.len() {
            self.finish_implicit();
            return Ok(());
        }

        let instr = self.program.instructions[self.pc].clone();
        let old_pc = self.pc;

        // Record opcode hit for coverage tracking.
        self.opcode_hits[instr.opcode as usize] = true;

        // Charge static cost.
        if let Some(spec) = opcode::lookup(instr.opcode) {
            if let CostKind::Static(cost) = spec.cost {
                self.charge_cost(cost)?;
            }
            // Dynamic cost is charged by the handler.
        }

        // Dispatch to opcode handler.
        ops::dispatch(self, &instr, ctx)?;

        // If the handler didn't change the PC (no branch), advance by 1.
        if !self.finished && self.pc == old_pc {
            self.pc += 1;
        }

        Ok(())
    }

    /// Run the program to completion. Returns `true` for pass, `false` for reject.
    ///
    /// `ctx` provides external state access (transaction fields, app state, etc.).
    /// Pure-opcode tests can pass `&mut NullContext`.
    pub fn run(&mut self, ctx: &mut dyn AvmContext) -> Result<bool, AlgoError> {
        while !self.finished {
            self.step(ctx)?;
        }
        Ok(self.pass)
    }

    /// Execute one instruction with tracer callbacks.
    ///
    /// Identical to [`step`] but invokes `tracer.before_opcode` before
    /// dispatch and `tracer.after_opcode` after dispatch (or on error).
    pub fn step_with_tracer(
        &mut self,
        ctx: &mut dyn AvmContext,
        tracer: &mut dyn EvalTracer,
    ) -> Result<(), AlgoError> {
        if self.finished {
            return Err(AlgoError::Avm {
                message: "step called after execution finished".to_string(),
            });
        }

        // If PC is past end of instructions, program finishes.
        if self.pc >= self.program.instructions.len() {
            self.finish_implicit();
            return Ok(());
        }

        let instr = self.program.instructions[self.pc].clone();
        let old_pc = self.pc;

        // Record opcode hit for coverage tracking.
        self.opcode_hits[instr.opcode as usize] = true;

        // Tracer: before opcode (called before cost charge so budget-
        // exhaustion opcodes are visible in the trace, matching go-algorand).
        tracer.before_opcode(self.pc, instr.opcode);

        // Charge static cost.
        if let Some(spec) = opcode::lookup(instr.opcode) {
            if let CostKind::Static(cost) = spec.cost {
                if let Err(e) = self.charge_cost(cost) {
                    let msg = e.to_string();
                    tracer.after_opcode(
                        old_pc,
                        instr.opcode,
                        &self.stack,
                        &self.scratch,
                        Some(&msg),
                    );
                    return Err(e);
                }
            }
        }

        // Dispatch to opcode handler.
        let result = ops::dispatch(self, &instr, ctx);

        // Tracer: after opcode (with error if any).
        match &result {
            Ok(()) => {
                tracer.after_opcode(old_pc, instr.opcode, &self.stack, &self.scratch, None);
            }
            Err(e) => {
                let msg = e.to_string();
                tracer.after_opcode(old_pc, instr.opcode, &self.stack, &self.scratch, Some(&msg));
            }
        }

        result?;

        // If the handler didn't change the PC (no branch), advance by 1.
        if !self.finished && self.pc == old_pc {
            self.pc += 1;
        }

        Ok(())
    }

    /// Run the program to completion with tracer callbacks.
    ///
    /// Identical to [`run`] but calls [`step_with_tracer`] so that
    /// `before_opcode` / `after_opcode` events are emitted for each
    /// instruction.
    pub fn run_with_tracer(
        &mut self,
        ctx: &mut dyn AvmContext,
        tracer: &mut dyn EvalTracer,
    ) -> Result<bool, AlgoError> {
        while !self.finished {
            self.step_with_tracer(ctx, tracer)?;
        }
        Ok(self.pass)
    }

    /// Push a value onto the stack.
    pub fn push(&mut self, val: AvmValue) -> Result<(), AlgoError> {
        if self.stack.len() >= MAX_STACK_DEPTH {
            return Err(AlgoError::Avm {
                message: format!("stack overflow: depth exceeds {MAX_STACK_DEPTH}"),
            });
        }
        self.stack.push(val);
        Ok(())
    }

    /// Pop any value from the stack.
    pub fn pop(&mut self) -> Result<AvmValue, AlgoError> {
        self.stack.pop().ok_or_else(|| AlgoError::Avm {
            message: "stack underflow".to_string(),
        })
    }

    /// Pop any value from the stack (alias for `pop`).
    pub fn pop_any(&mut self) -> Result<AvmValue, AlgoError> {
        self.pop()
    }

    /// Pop a uint64 value from the stack.
    ///
    /// Empty bytes are coerced to 0 (matching Go's behavior).
    /// Non-empty bytes produce an error.
    pub fn pop_uint(&mut self) -> Result<u64, AlgoError> {
        match self.pop()? {
            AvmValue::Uint64(v) => Ok(v),
            AvmValue::Bytes(b) if b.is_empty() => Ok(0),
            AvmValue::Bytes(_) => Err(AlgoError::Avm {
                message: "expected uint64 on stack, got non-empty bytes".to_string(),
            }),
        }
    }

    /// Pop a bytes value from the stack. Uint64 values produce an error.
    pub fn pop_bytes(&mut self) -> Result<Vec<u8>, AlgoError> {
        match self.pop()? {
            AvmValue::Bytes(b) => Ok(b),
            AvmValue::Uint64(_) => Err(AlgoError::Avm {
                message: "expected bytes on stack, got uint64".to_string(),
            }),
        }
    }

    /// Deduct cost from the budget. Returns an error if the budget is exceeded.
    pub fn charge_cost(&mut self, cost: u64) -> Result<(), AlgoError> {
        self.budget -= cost as i64;
        if self.budget < 0 {
            Err(AlgoError::Avm {
                message: format!(
                    "cost budget exceeded: budget is {} after charging {cost}",
                    self.budget
                ),
            })
        } else {
            Ok(())
        }
    }

    /// Resolve a branch target from an instruction index + int16 offset.
    ///
    /// The target byte offset = (byte offset after instruction) + int16_value.
    /// This function finds the instruction index at that byte offset.
    pub fn get_branch_target(
        &self,
        from_instruction: usize,
        offset: i16,
    ) -> Result<usize, AlgoError> {
        let instr = &self.program.instructions[from_instruction];
        let imm_len = crate::validator::immediate_byte_len(&instr.immediates);
        let after_instr = instr.offset + 1 + imm_len;
        let target_offset = (after_instr as isize + offset as isize) as usize;

        // Check if target is an instruction boundary.
        if let Some(&idx) = self.offset_to_index.get(&target_offset) {
            return Ok(idx);
        }

        // Allow branching to end-of-program (triggers implicit termination).
        if target_offset == self.end_of_program_offset {
            return Ok(self.program.instructions.len());
        }

        Err(AlgoError::Avm {
            message: format!(
                "branch target byte offset {target_offset} does not match any instruction"
            ),
        })
    }

    /// Push a frame onto the call stack.
    pub fn push_call_frame(&mut self, frame: CallFrame) -> Result<(), AlgoError> {
        if self.call_stack.len() >= MAX_CALL_STACK_DEPTH {
            return Err(AlgoError::Avm {
                message: format!("call stack overflow: depth exceeds {MAX_CALL_STACK_DEPTH}"),
            });
        }
        self.call_stack.push(frame);
        Ok(())
    }

    /// Pop a frame from the call stack.
    pub fn pop_call_frame(&mut self) -> Result<CallFrame, AlgoError> {
        self.call_stack.pop().ok_or_else(|| AlgoError::Avm {
            message: "call stack underflow (retsub without callsub)".to_string(),
        })
    }

    /// Return a coverage snapshot from this machine's execution.
    pub fn opcode_coverage(&self) -> OpcodeCoverage {
        OpcodeCoverage {
            hit: self.opcode_hits,
        }
    }

    /// Handle implicit program termination (PC past end of instructions).
    ///
    /// Pass if top of stack is truthy; reject if stack is empty or top is falsy.
    fn finish_implicit(&mut self) {
        self.finished = true;
        self.pass = self.stack.last().is_some_and(|v| v.is_truthy());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::parse;
    use crate::context::NullContext;

    /// Helper: build a raw program from version + code bytes.
    fn prog(version: u8, code: &[u8]) -> Vec<u8> {
        let mut p = vec![version];
        p.extend_from_slice(code);
        p
    }

    #[test]
    fn test_new_machine() {
        let raw = prog(2, &[0x20, 0x01, 0x01, 0x22, 0x43]);
        let program = parse(&raw).unwrap();
        let machine = AvmMachine::new(program, ExecMode::LogicSig, 700);
        assert_eq!(machine.version, 2);
        assert_eq!(machine.pc, 0);
        assert_eq!(machine.budget, 700);
        assert!(!machine.finished);
        assert!(!machine.pass);
        assert_eq!(machine.stack.len(), 0);
        assert_eq!(machine.scratch.len(), 256);
        assert_eq!(machine.mode, ExecMode::LogicSig);
    }

    #[test]
    fn test_push_pop() {
        let program = Program {
            version: 1,
            instructions: vec![],
        };
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);

        m.push(AvmValue::Uint64(42)).unwrap();
        m.push(AvmValue::Bytes(vec![1, 2, 3])).unwrap();

        let b = m.pop_bytes().unwrap();
        assert_eq!(b, vec![1, 2, 3]);

        let u = m.pop_uint().unwrap();
        assert_eq!(u, 42);
    }

    #[test]
    fn test_pop_empty_bytes_as_uint() {
        let program = Program {
            version: 1,
            instructions: vec![],
        };
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        m.push(AvmValue::Bytes(vec![])).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    #[test]
    fn test_pop_nonempty_bytes_as_uint_fails() {
        let program = Program {
            version: 1,
            instructions: vec![],
        };
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        m.push(AvmValue::Bytes(vec![1])).unwrap();
        assert!(m.pop_uint().is_err());
    }

    #[test]
    fn test_stack_underflow() {
        let program = Program {
            version: 1,
            instructions: vec![],
        };
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        assert!(m.pop().is_err());
    }

    #[test]
    fn test_stack_overflow() {
        let program = Program {
            version: 1,
            instructions: vec![],
        };
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        for i in 0..1000 {
            m.push(AvmValue::Uint64(i)).unwrap();
        }
        // 1001st push should fail.
        assert!(m.push(AvmValue::Uint64(0)).is_err());
    }

    #[test]
    fn test_charge_cost() {
        let program = Program {
            version: 1,
            instructions: vec![],
        };
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 10);
        assert!(m.charge_cost(5).is_ok());
        assert_eq!(m.budget, 5);
        assert!(m.charge_cost(6).is_err());
    }

    #[test]
    fn test_avm_value_truthiness() {
        assert!(AvmValue::Uint64(1).is_truthy());
        assert!(!AvmValue::Uint64(0).is_truthy());
        assert!(AvmValue::Bytes(vec![0]).is_truthy());
        assert!(!AvmValue::Bytes(vec![]).is_truthy());
    }

    #[test]
    fn test_empty_program_rejects() {
        // Empty program (no instructions) should reject (no value on stack).
        let program = Program {
            version: 1,
            instructions: vec![],
        };
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        let result = m.run(&mut NullContext).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_step_after_finished() {
        let program = Program {
            version: 1,
            instructions: vec![],
        };
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        m.run(&mut NullContext).unwrap();
        assert!(m.step(&mut NullContext).is_err());
    }

    #[test]
    fn test_err_opcode() {
        // err (0x00) should return an error.
        let raw = prog(1, &[0x00]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        let result = m.run(&mut NullContext);
        assert!(result.is_err());
    }

    #[test]
    fn test_return_with_truthy_value() {
        // intcblock [1], intc_0, return -> pass
        let raw = prog(2, &[0x20, 0x01, 0x01, 0x22, 0x43]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        let result = m.run(&mut NullContext).unwrap();
        assert!(result);
    }

    #[test]
    fn test_return_with_zero_value() {
        // intcblock [0], intc_0, return -> reject
        let raw = prog(2, &[0x20, 0x01, 0x00, 0x22, 0x43]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        let result = m.run(&mut NullContext).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_assert_with_truthy_value() {
        // pushint 1, assert -> finishes without error, then implicit end
        // But assert doesn't set finished -- it just errors if zero.
        // After assert, PC advances, hits end-of-program with empty stack -> reject.
        let raw = prog(3, &[0x81, 0x01, 0x44]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        let result = m.run(&mut NullContext).unwrap();
        // After assert, stack is empty, program ends -> reject.
        assert!(!result);
    }

    #[test]
    fn test_assert_with_zero_fails() {
        // pushint 0, assert -> error
        let raw = prog(3, &[0x81, 0x00, 0x44]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        assert!(m.run(&mut NullContext).is_err());
    }

    #[test]
    fn test_opcode_coverage_tracking() {
        // intcblock [1], intc_0, return -- opcodes 0x20, 0x22, 0x43
        let raw = prog(2, &[0x20, 0x01, 0x01, 0x22, 0x43]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        m.run(&mut NullContext).unwrap();

        let cov = m.opcode_coverage();
        assert!(cov.hit[0x20]); // intcblock
        assert!(cov.hit[0x22]); // intc_0
        assert!(cov.hit[0x43]); // return
        assert!(!cov.hit[0x00]); // err was not executed
        assert!(!cov.hit[0x01]); // sha256 was not executed

        assert!(cov.hit_count() >= 3);
        assert!(cov.total_defined() >= 140);
        assert!(cov.coverage_pct() > 0.0);
    }

    #[test]
    fn test_opcode_coverage_merge() {
        let mut cov1 = OpcodeCoverage::default();
        cov1.hit[0x20] = true;
        cov1.hit[0x22] = true;

        let mut cov2 = OpcodeCoverage::default();
        cov2.hit[0x43] = true;
        cov2.hit[0x22] = true; // overlap

        cov1.merge(&cov2);
        assert!(cov1.hit[0x20]);
        assert!(cov1.hit[0x22]);
        assert!(cov1.hit[0x43]);
        assert!(!cov1.hit[0x00]);
    }

    /// Test proto/retsub stack cleanup: a subroutine declared with `proto 2 1`
    /// takes 2 args, returns 1. After retsub, the 2 args should be replaced by
    /// the single return value, and any extra values pushed in the subroutine
    /// should be cleaned up.
    ///
    /// Program layout (byte offsets include version byte at offset 0):
    ///   0: version 8
    ///   1-2: pushint 10
    ///   3-4: pushint 20
    ///   5-7: callsub offset=+1  (end of callsub is byte 8, target = byte 9)
    ///   8: return
    ///   9-11: proto 2 1
    ///  12-13: frame_dig -2
    ///  14-15: frame_dig -1
    ///  16: +
    ///  17: retsub
    #[test]
    fn test_retsub_proto_stack_cleanup() {
        let raw = prog(
            8,
            &[
                0x81, 0x0a, // pushint 10
                0x81, 0x14, // pushint 20
                0x88, 0x00, 0x01, // callsub offset=+1 (target byte 9)
                0x43, // return
                0x8a, 0x02, 0x01, // proto 2 1
                0x8b, 0xfe, // frame_dig -2
                0x8b, 0xff, // frame_dig -1
                0x08, // +
                0x89, // retsub
            ],
        );
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700);
        let result = m.run(&mut NullContext).unwrap();
        assert!(result, "program should pass (return 30)");
    }

    /// Test retsub without proto: should NOT do any stack cleanup (backwards compatible).
    #[test]
    fn test_retsub_without_proto_no_cleanup() {
        // Layout:
        //   0: version 8
        //   1-2: pushint 42
        //   3-5: callsub offset=+1 (end of callsub is byte 6, target = byte 7)
        //   6: return
        //   7-8: pushint 1
        //   9: retsub
        let raw = prog(
            8,
            &[
                0x81, 0x2a, // pushint 42
                0x88, 0x00, 0x01, // callsub offset=+1 (target byte 7)
                0x43, // return
                0x81, 0x01, // pushint 1
                0x89, // retsub
            ],
        );
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700);
        let result = m.run(&mut NullContext).unwrap();
        assert!(result, "program should pass (return pops 1)");
    }

    /// Test retsub with proto: not enough return values should error.
    #[test]
    fn test_retsub_proto_insufficient_returns_errors() {
        // Layout:
        //   0: version 8
        //   1-2: pushint 10
        //   3-4: pushint 20
        //   5-7: callsub offset=+1 (target byte 9)
        //   8: return
        //   9-11: proto 2 1
        //  12: retsub
        let raw = prog(
            8,
            &[
                0x81, 0x0a, // pushint 10
                0x81, 0x14, // pushint 20
                0x88, 0x00, 0x01, // callsub offset=+1 (target byte 9)
                0x43, // return
                0x8a, 0x02, 0x01, // proto 2 1
                0x89, // retsub
            ],
        );
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700);
        let result = m.run(&mut NullContext);
        assert!(
            result.is_err(),
            "retsub should error with no return values on stack"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("no return values"),
            "error should mention missing return values: {err}"
        );
    }

    /// Test that `proto` without a preceding `callsub` errors.
    /// Program: pushint 1, proto 0 0 — proto should fail because
    /// there was no callsub to set the from_callsub flag.
    #[test]
    fn test_proto_without_callsub_errors() {
        // Version 8+: proto 0 0, pushint 1
        // But proto is inside a subroutine in normal usage. Let's directly
        // jump into a proto without callsub — use `b` (unconditional branch)
        // to skip to a proto instruction.
        let raw = prog(
            8,
            &[
                0x42, 0x00, 0x00, // b offset=+0 (target byte 3, i.e. next instr)
                0x8a, 0x00, 0x00, // proto 0 0 — should error
                0x81, 0x01, // pushint 1
            ],
        );
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700);
        let result = m.run(&mut NullContext);
        assert!(result.is_err(), "proto without callsub should error");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("proto was executed without a callsub"),
            "unexpected error: {err}"
        );
    }

    /// Test that callsub → proto handshake works correctly (no error).
    #[test]
    fn test_callsub_proto_handshake_ok() {
        // pushint 1, callsub target, return
        // target: proto 0 0, pushint 1, retsub
        let raw = prog(
            8,
            &[
                0x81, 0x01, // pushint 1 (for final return)
                0x88, 0x00, 0x01, // callsub offset=+1 (target = byte 6)
                0x43, // return (uses value left on stack)
                0x8a, 0x00, 0x00, // proto 0 0
                0x89, // retsub
            ],
        );
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700);
        let result = m.run(&mut NullContext);
        assert!(
            result.is_ok(),
            "callsub->proto should succeed: {:?}",
            result.err()
        );
        assert!(result.unwrap(), "program should approve");
    }
}
