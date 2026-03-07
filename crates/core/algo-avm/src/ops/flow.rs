//! Flow control opcodes: err, bnz, bz, b, return, assert, callsub, retsub,
//! proto, frame_dig, frame_bury, switch, match.

use algo_error::AlgoError;

use crate::bytecode::{Immediates, Instruction};
use crate::machine::{AvmMachine, CallFrame};
use crate::validator::immediate_byte_len;

/// `err` (0x00): always fail.
pub fn op_err(_machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    Err(AlgoError::Avm {
        message: "err opcode executed".to_string(),
    })
}

/// `bnz offset` (0x40): pop top of stack; branch if non-zero.
pub fn op_bnz(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let val = machine.pop_uint()?;
    if val != 0 {
        branch(machine, instruction)
    } else {
        machine.pc += 1;
        Ok(())
    }
}

/// `bz offset` (0x41): pop top of stack; branch if zero.
pub fn op_bz(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let val = machine.pop_uint()?;
    if val == 0 {
        branch(machine, instruction)
    } else {
        machine.pc += 1;
        Ok(())
    }
}

/// `b offset` (0x42): unconditional branch.
pub fn op_b(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    branch(machine, instruction)
}

/// `return` (0x43): pop uint64, finish execution. Non-zero = pass, zero = reject.
pub fn op_return(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let val = machine.pop_uint()?;
    machine.finished = true;
    machine.pass = val != 0;
    Ok(())
}

/// `assert` (0x44): pop uint64, error if zero.
pub fn op_assert(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let val = machine.pop_uint()?;
    if val != 0 {
        Ok(())
    } else {
        Err(AlgoError::Avm {
            message: "assert failed: top of stack is zero".to_string(),
        })
    }
}

/// `callsub offset` (0x88): push return address + frame pointer, branch to target.
pub fn op_callsub(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let return_pc = machine.pc + 1; // return to the instruction after callsub
    let frame_pointer = machine.stack.len();
    machine.push_call_frame(CallFrame {
        return_pc,
        frame_pointer,
    })?;
    branch(machine, instruction)
}

/// `retsub` (0x89): pop call frame and return to saved PC.
pub fn op_retsub(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let frame = machine.pop_call_frame()?;
    machine.pc = frame.return_pc;
    Ok(())
}

/// `proto a r` (0x8a): declare subroutine expects `a` args and returns `r` values.
/// Minimal implementation: validate that the stack has at least `a` values above frame pointer.
pub fn op_proto(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let (num_args, _num_returns) = if let Immediates::Uint8Pair(a, r) = instruction.immediates {
        (a as usize, r as usize)
    } else {
        return Err(AlgoError::Avm {
            message: "proto: expected Uint8Pair immediate".to_string(),
        });
    };

    // Validate stack has at least num_args values above frame pointer.
    let frame_pointer = if let Some(frame) = machine.call_stack.last() {
        frame.frame_pointer
    } else {
        return Err(AlgoError::Avm {
            message: "proto: no call frame (not inside a subroutine)".to_string(),
        });
    };

    let stack_above = machine.stack.len().saturating_sub(frame_pointer);
    if stack_above < num_args {
        return Err(AlgoError::Avm {
            message: format!(
                "proto: expected {num_args} args above frame pointer, but only {stack_above} values"
            ),
        });
    }

    Ok(())
}

/// `frame_dig i` (0x8b): access value relative to frame pointer (signed int8 offset).
pub fn op_frame_dig(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let raw = if let Immediates::Uint8(v) = instruction.immediates {
        v
    } else {
        return Err(AlgoError::Avm {
            message: "frame_dig: expected Uint8 immediate".to_string(),
        });
    };

    let frame_pointer = if let Some(frame) = machine.call_stack.last() {
        frame.frame_pointer
    } else {
        return Err(AlgoError::Avm {
            message: "frame_dig: no call frame".to_string(),
        });
    };

    let idx = frame_index(frame_pointer, raw)?;
    if idx >= machine.stack.len() {
        return Err(AlgoError::Avm {
            message: format!(
                "frame_dig: index {idx} out of range (stack depth {})",
                machine.stack.len()
            ),
        });
    }
    let val = machine.stack[idx].clone();
    machine.push(val)?;
    Ok(())
}

/// `frame_bury i` (0x8c): pop top of stack and write to frame-relative position.
pub fn op_frame_bury(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let raw = if let Immediates::Uint8(v) = instruction.immediates {
        v
    } else {
        return Err(AlgoError::Avm {
            message: "frame_bury: expected Uint8 immediate".to_string(),
        });
    };

    let frame_pointer = if let Some(frame) = machine.call_stack.last() {
        frame.frame_pointer
    } else {
        return Err(AlgoError::Avm {
            message: "frame_bury: no call frame".to_string(),
        });
    };

    let val = machine.pop()?;
    let idx = frame_index(frame_pointer, raw)?;
    if idx >= machine.stack.len() {
        return Err(AlgoError::Avm {
            message: format!(
                "frame_bury: index {idx} out of range (stack depth {})",
                machine.stack.len()
            ),
        });
    }
    machine.stack[idx] = val;
    Ok(())
}

/// `switch` (0x8d): pop uint64 index; if index < n, branch to label[index].
pub fn op_switch(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let offsets = if let Immediates::Labels(ref labels) = instruction.immediates {
        labels.clone()
    } else {
        return Err(AlgoError::Avm {
            message: "switch: expected Labels immediate".to_string(),
        });
    };

    let index = machine.pop_uint()? as usize;

    if index < offsets.len() {
        let target = resolve_label(machine, instruction, offsets[index])?;
        machine.pc = target;
    } else {
        // Fall through.
        machine.pc += 1;
    }
    Ok(())
}

/// `match` (0x8e): pop n values and a target, branch to first matching label.
pub fn op_match(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let offsets = if let Immediates::Labels(ref labels) = instruction.immediates {
        labels.clone()
    } else {
        return Err(AlgoError::Avm {
            message: "match: expected Labels immediate".to_string(),
        });
    };

    let n = offsets.len();
    // Pop n match values (in reverse order since they were pushed first-to-last).
    let mut match_values = Vec::with_capacity(n);
    for _ in 0..n {
        match_values.push(machine.pop()?);
    }
    match_values.reverse(); // Now match_values[i] corresponds to offsets[i].

    // Pop the target value.
    let target_val = machine.pop()?;

    // Find first match.
    for (i, val) in match_values.iter().enumerate() {
        if *val == target_val {
            let target = resolve_label(machine, instruction, offsets[i])?;
            machine.pc = target;
            return Ok(());
        }
    }

    // No match: fall through.
    machine.pc += 1;
    Ok(())
}

/// Compute absolute stack index from frame_pointer and uint8 (interpreted as int8).
fn frame_index(frame_pointer: usize, raw: u8) -> Result<usize, AlgoError> {
    let offset = raw as i8;
    let idx = if offset >= 0 {
        frame_pointer.checked_add(offset as usize)
    } else {
        frame_pointer.checked_sub((-offset) as usize)
    };
    idx.ok_or_else(|| AlgoError::Avm {
        message: format!("frame index overflow: frame_pointer={frame_pointer}, offset={offset}"),
    })
}

/// Resolve a label offset from a Labels immediate to an instruction index.
/// The offset is relative to the end of the current instruction (after all immediates).
fn resolve_label(
    machine: &AvmMachine,
    instruction: &Instruction,
    label_offset: i16,
) -> Result<usize, AlgoError> {
    let imm_len = immediate_byte_len(&instruction.immediates);
    let after_instr = instruction.offset + 1 + imm_len;
    let target_byte_offset = (after_instr as isize + label_offset as isize) as usize;

    machine
        .offset_to_index
        .get(&target_byte_offset)
        .copied()
        .ok_or_else(|| AlgoError::Avm {
            message: format!(
                "switch/match: branch target byte offset {target_byte_offset} does not match any instruction"
            ),
        })
}

/// Helper: resolve Int16 branch offset and set PC.
fn branch(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    if let Immediates::Int16(offset) = instruction.immediates {
        let target = machine.get_branch_target(machine.pc, offset)?;
        machine.pc = target;
        Ok(())
    } else {
        Err(AlgoError::Avm {
            message: "branch: expected Int16 immediate".to_string(),
        })
    }
}
