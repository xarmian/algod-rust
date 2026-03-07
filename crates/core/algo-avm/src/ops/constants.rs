//! Constant-loading opcodes: intcblock, bytecblock, intc, bytec, pushint, pushbytes, etc.

use algo_error::AlgoError;

use crate::bytecode::{Immediates, Instruction};
use crate::machine::{AvmMachine, AvmValue};

/// `intcblock`: load integer constant pool from immediates.
pub fn op_intcblock(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    if let Immediates::IntBlock(values) = &instruction.immediates {
        machine.int_constants = values.clone();
        Ok(())
    } else {
        Err(AlgoError::Avm {
            message: "intcblock: expected IntBlock immediates".to_string(),
        })
    }
}

/// `intc i`: push int_constants[i] onto stack.
pub fn op_intc(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    if let Immediates::Uint8(idx) = instruction.immediates {
        let val = get_int_constant(machine, idx as usize)?;
        machine.push(AvmValue::Uint64(val))
    } else {
        Err(AlgoError::Avm {
            message: "intc: expected Uint8 immediate".to_string(),
        })
    }
}

/// `intc_0` through `intc_3`: push int_constants[N] where N is derived from the opcode.
pub fn op_intc_n(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let idx = (instruction.opcode - 0x22) as usize; // 0x22=0, 0x23=1, 0x24=2, 0x25=3
    let val = get_int_constant(machine, idx)?;
    machine.push(AvmValue::Uint64(val))
}

/// `bytecblock`: load byte constant pool from immediates.
pub fn op_bytecblock(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    if let Immediates::ByteBlock(entries) = &instruction.immediates {
        machine.byte_constants = entries.clone();
        Ok(())
    } else {
        Err(AlgoError::Avm {
            message: "bytecblock: expected ByteBlock immediates".to_string(),
        })
    }
}

/// `bytec i`: push byte_constants[i] onto stack.
pub fn op_bytec(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    if let Immediates::Uint8(idx) = instruction.immediates {
        let val = get_byte_constant(machine, idx as usize)?;
        machine.push(AvmValue::Bytes(val))
    } else {
        Err(AlgoError::Avm {
            message: "bytec: expected Uint8 immediate".to_string(),
        })
    }
}

/// `bytec_0` through `bytec_3`: push byte_constants[N] where N is derived from the opcode.
pub fn op_bytec_n(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let idx = (instruction.opcode - 0x28) as usize; // 0x28=0, 0x29=1, 0x2a=2, 0x2b=3
    let val = get_byte_constant(machine, idx)?;
    machine.push(AvmValue::Bytes(val))
}

/// `pushint v`: push immediate varuint value onto stack.
pub fn op_pushint(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    if let Immediates::Varuint(v) = instruction.immediates {
        machine.push(AvmValue::Uint64(v))
    } else {
        Err(AlgoError::Avm {
            message: "pushint: expected Varuint immediate".to_string(),
        })
    }
}

/// `pushbytes b`: push immediate byte array onto stack.
pub fn op_pushbytes(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    if let Immediates::Bytes(b) = &instruction.immediates {
        machine.push(AvmValue::Bytes(b.clone()))
    } else {
        Err(AlgoError::Avm {
            message: "pushbytes: expected Bytes immediate".to_string(),
        })
    }
}

/// `pushints` (0x83): push each varuint value from the immediate list onto the stack, in order.
pub fn op_pushints(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    if let Immediates::PushInts(values) = &instruction.immediates {
        for &v in values {
            machine.push(AvmValue::Uint64(v))?;
        }
        Ok(())
    } else {
        Err(AlgoError::Avm {
            message: "pushints: expected PushInts immediates".to_string(),
        })
    }
}

/// `pushbytess` (0x82): push each byte array from the immediate list onto the stack, in order.
pub fn op_pushbytess(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    if let Immediates::PushBytess(entries) = &instruction.immediates {
        for entry in entries {
            machine.push(AvmValue::Bytes(entry.clone()))?;
        }
        Ok(())
    } else {
        Err(AlgoError::Avm {
            message: "pushbytess: expected PushBytess immediates".to_string(),
        })
    }
}

fn get_int_constant(machine: &AvmMachine, idx: usize) -> Result<u64, AlgoError> {
    machine
        .int_constants
        .get(idx)
        .copied()
        .ok_or_else(|| AlgoError::Avm {
            message: format!(
                "intc: index {idx} out of range (pool has {} entries)",
                machine.int_constants.len()
            ),
        })
}

fn get_byte_constant(machine: &AvmMachine, idx: usize) -> Result<Vec<u8>, AlgoError> {
    machine
        .byte_constants
        .get(idx)
        .cloned()
        .ok_or_else(|| AlgoError::Avm {
            message: format!(
                "bytec: index {idx} out of range (pool has {} entries)",
                machine.byte_constants.len()
            ),
        })
}
