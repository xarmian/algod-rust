//! AVM stack machine -- the runtime execution engine.
//!
//! Provides the `AvmMachine` struct that executes parsed AVM programs
//! instruction by instruction, managing the value stack, call stack,
//! scratch space, and cost budget.

use std::collections::HashMap;

use algo_error::AlgoError;

use crate::bytecode::Program;
use crate::opcode::{self, CostKind};
use crate::ops;

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
        }
    }

    /// Execute one instruction and advance the PC.
    pub fn step(&mut self) -> Result<(), AlgoError> {
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

        // Charge static cost.
        if let Some(spec) = opcode::lookup(instr.opcode) {
            if let CostKind::Static(cost) = spec.cost {
                self.charge_cost(cost)?;
            }
            // Dynamic cost is charged by the handler.
        }

        // Dispatch to opcode handler.
        ops::dispatch(self, &instr)?;

        // If the handler didn't change the PC (no branch), advance by 1.
        if !self.finished && self.pc == old_pc {
            self.pc += 1;
        }

        Ok(())
    }

    /// Run the program to completion. Returns `true` for pass, `false` for reject.
    pub fn run(&mut self) -> Result<bool, AlgoError> {
        while !self.finished {
            self.step()?;
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

        self.offset_to_index
            .get(&target_offset)
            .copied()
            .ok_or_else(|| AlgoError::Avm {
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
        let result = m.run().unwrap();
        assert!(!result);
    }

    #[test]
    fn test_step_after_finished() {
        let program = Program {
            version: 1,
            instructions: vec![],
        };
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        m.run().unwrap();
        assert!(m.step().is_err());
    }

    #[test]
    fn test_err_opcode() {
        // err (0x00) should return an error.
        let raw = prog(1, &[0x00]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        let result = m.run();
        assert!(result.is_err());
    }

    #[test]
    fn test_return_with_truthy_value() {
        // intcblock [1], intc_0, return -> pass
        let raw = prog(2, &[0x20, 0x01, 0x01, 0x22, 0x43]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        let result = m.run().unwrap();
        assert!(result);
    }

    #[test]
    fn test_return_with_zero_value() {
        // intcblock [0], intc_0, return -> reject
        let raw = prog(2, &[0x20, 0x01, 0x00, 0x22, 0x43]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        let result = m.run().unwrap();
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
        let result = m.run().unwrap();
        // After assert, stack is empty, program ends -> reject.
        assert!(!result);
    }

    #[test]
    fn test_assert_with_zero_fails() {
        // pushint 0, assert -> error
        let raw = prog(3, &[0x81, 0x00, 0x44]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        assert!(m.run().is_err());
    }
}
