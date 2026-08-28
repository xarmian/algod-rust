//! Logic and bitwise opcodes: &&, ||, |, &, ^, ~, getbit, setbit, getbyte, setbyte.

use algo_error::AlgoError;

use crate::bytecode::Instruction;
use crate::machine::{AvmMachine, AvmValue};

/// `&&` (0x10): pop b, pop a (uint64), push (a != 0 && b != 0) as 0/1.
pub fn op_and(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    let result = if a != 0 && b != 0 { 1u64 } else { 0u64 };
    machine.push(AvmValue::Uint64(result))
}

/// `||` (0x11): pop b, pop a (uint64), push (a != 0 || b != 0) as 0/1.
pub fn op_or(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    let result = if a != 0 || b != 0 { 1u64 } else { 0u64 };
    machine.push(AvmValue::Uint64(result))
}

/// `|` (0x19): pop b, pop a (uint64), push a | b (bitwise OR).
pub fn op_bitwise_or(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    machine.push(AvmValue::Uint64(a | b))
}

/// `&` (0x1a): pop b, pop a (uint64), push a & b (bitwise AND).
pub fn op_bitwise_and(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    machine.push(AvmValue::Uint64(a & b))
}

/// `^` (0x1b): pop b, pop a (uint64), push a ^ b (bitwise XOR).
pub fn op_bitwise_xor(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    machine.push(AvmValue::Uint64(a ^ b))
}

/// `~` (0x1c): pop a (uint64), push !a (bitwise NOT).
pub fn op_bitwise_not(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
) -> Result<(), AlgoError> {
    let a = machine.pop_uint()?;
    machine.push(AvmValue::Uint64(a ^ u64::MAX))
}

/// `getbit` (0x53): pop n (bit index), pop target (any).
/// For uint64: bit 0 = LSB, bit 63 = MSB.
/// For bytes: bit 0 = MSB of byte[0], bit 7 = LSB of byte[0], etc.
pub fn op_getbit(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let n = machine.pop_uint()?;
    let target = machine.pop_any()?;

    let bit = match &target {
        AvmValue::Uint64(v) => {
            if n >= 64 {
                return Err(AlgoError::Avm {
                    message: format!("getbit: bit index {n} >= 64 for uint64"),
                });
            }
            (v >> n) & 1
        }
        AvmValue::Bytes(bytes) => {
            let total_bits = (bytes.len() as u64) * 8;
            if n >= total_bits {
                return Err(AlgoError::Avm {
                    message: format!(
                        "getbit: bit index {n} >= {total_bits} for bytes of length {}",
                        bytes.len()
                    ),
                });
            }
            let byte_idx = (n / 8) as usize;
            let bit_idx = (n % 8) as u32;
            // MSB-first: bit 0 of a byte is 0x80
            ((bytes[byte_idx] >> (7 - bit_idx)) & 1) as u64
        }
    };

    machine.push(AvmValue::Uint64(bit))
}

/// `setbit` (0x54): pop v (0 or 1), pop n (bit index), pop target (any).
/// Sets the specified bit to v and pushes the result (same type as target).
pub fn op_setbit(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let v = machine.pop_uint()?;
    let n = machine.pop_uint()?;
    let target = machine.pop_any()?;

    if v > 1 {
        return Err(AlgoError::Avm {
            message: format!("setbit: value {v} is not 0 or 1"),
        });
    }

    match target {
        AvmValue::Uint64(val) => {
            if n >= 64 {
                return Err(AlgoError::Avm {
                    message: format!("setbit: bit index {n} >= 64 for uint64"),
                });
            }
            let result = if v == 1 {
                val | (1u64 << n)
            } else {
                val & !(1u64 << n)
            };
            machine.push(AvmValue::Uint64(result))
        }
        AvmValue::Bytes(mut bytes) => {
            let total_bits = (bytes.len() as u64) * 8;
            if n >= total_bits {
                return Err(AlgoError::Avm {
                    message: format!(
                        "setbit: bit index {n} >= {total_bits} for bytes of length {}",
                        bytes.len()
                    ),
                });
            }
            let byte_idx = (n / 8) as usize;
            let bit_idx = (n % 8) as u32;
            // MSB-first: bit 0 of a byte is 0x80
            let mask = 1u8 << (7 - bit_idx);
            if v == 1 {
                bytes[byte_idx] |= mask;
            } else {
                bytes[byte_idx] &= !mask;
            }
            machine.push(AvmValue::Bytes(bytes))
        }
    }
}

/// `getbyte` (0x55): pop n (uint64), pop target (bytes). Push target[n] as uint64.
pub fn op_getbyte(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let n = machine.pop_uint()?;
    let bytes = machine.pop_bytes()?;

    if n >= bytes.len() as u64 {
        return Err(AlgoError::Avm {
            message: format!("getbyte: index {n} >= length {} of bytes", bytes.len()),
        });
    }

    machine.push(AvmValue::Uint64(bytes[n as usize] as u64))
}

/// `setbyte` (0x56): pop v (0-255), pop n (uint64), pop target (bytes). Set target[n] = v.
pub fn op_setbyte(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let v = machine.pop_uint()?;
    let n = machine.pop_uint()?;
    let mut bytes = machine.pop_bytes()?;

    if v > 255 {
        return Err(AlgoError::Avm {
            message: format!("setbyte: value {v} > 255"),
        });
    }

    if n >= bytes.len() as u64 {
        return Err(AlgoError::Avm {
            message: format!("setbyte: index {n} >= length {} of bytes", bytes.len()),
        });
    }

    bytes[n as usize] = v as u8;
    machine.push(AvmValue::Bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::Program;
    use crate::machine::ExecMode;

    /// Helper to create a machine with some values pre-pushed.
    fn make_machine() -> AvmMachine {
        let program = Program {
            version: 6,
            instructions: vec![],
        };
        AvmMachine::new(program, ExecMode::LogicSig, 700)
    }

    fn dummy_instr() -> Instruction {
        Instruction {
            opcode: 0x00,
            sub_opcode: None,
            immediates: crate::bytecode::Immediates::None,
            offset: 0,
        }
    }

    // ---- && (logical AND) ----

    #[test]
    fn test_logical_and_both_nonzero() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(3)).unwrap();
        m.push(AvmValue::Uint64(5)).unwrap();
        op_and(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_logical_and_one_zero() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(5)).unwrap();
        op_and(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    #[test]
    fn test_logical_and_both_zero() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        op_and(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    // ---- || (logical OR) ----

    #[test]
    fn test_logical_or_both_nonzero() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(3)).unwrap();
        m.push(AvmValue::Uint64(5)).unwrap();
        op_or(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_logical_or_one_zero() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(5)).unwrap();
        op_or(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_logical_or_both_zero() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        op_or(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    // ---- | (bitwise OR) ----

    #[test]
    fn test_bitwise_or() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(0x0F)).unwrap();
        m.push(AvmValue::Uint64(0xF0)).unwrap();
        op_bitwise_or(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0xFF);
    }

    // ---- & (bitwise AND) ----

    #[test]
    fn test_bitwise_and() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(0xFF)).unwrap();
        m.push(AvmValue::Uint64(0x0F)).unwrap();
        op_bitwise_and(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0x0F);
    }

    // ---- ^ (bitwise XOR) ----

    #[test]
    fn test_bitwise_xor() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(0xFF)).unwrap();
        m.push(AvmValue::Uint64(0x0F)).unwrap();
        op_bitwise_xor(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0xF0);
    }

    // ---- ~ (bitwise NOT) ----

    #[test]
    fn test_bitwise_not() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(0)).unwrap();
        op_bitwise_not(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), u64::MAX);
    }

    #[test]
    fn test_bitwise_not_max() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(u64::MAX)).unwrap();
        op_bitwise_not(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    // ---- getbit ----

    #[test]
    fn test_getbit_uint64_lsb() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(0b101)).unwrap(); // bits: 0=1, 1=0, 2=1
        m.push(AvmValue::Uint64(0)).unwrap(); // bit index
        op_getbit(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_getbit_uint64_bit1() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(0b101)).unwrap();
        m.push(AvmValue::Uint64(1)).unwrap();
        op_getbit(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    #[test]
    fn test_getbit_uint64_bit2() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(0b101)).unwrap();
        m.push(AvmValue::Uint64(2)).unwrap();
        op_getbit(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_getbit_uint64_bit63() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(1u64 << 63)).unwrap();
        m.push(AvmValue::Uint64(63)).unwrap();
        op_getbit(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_getbit_uint64_out_of_range() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(64)).unwrap();
        assert!(op_getbit(&mut m, &dummy_instr()).is_err());
    }

    #[test]
    fn test_getbit_bytes_msb_first() {
        // byte 0x80 = 10000000
        // bit 0 (MSB of byte 0) = 1
        let mut m = make_machine();
        m.push(AvmValue::Bytes(vec![0x80])).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        op_getbit(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_getbit_bytes_lsb_of_first_byte() {
        // byte 0x01 = 00000001
        // bit 7 (LSB of byte 0) = 1
        let mut m = make_machine();
        m.push(AvmValue::Bytes(vec![0x01])).unwrap();
        m.push(AvmValue::Uint64(7)).unwrap();
        op_getbit(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_getbit_bytes_second_byte() {
        // bytes [0x00, 0x80] -> bit 8 = MSB of byte[1] = 1
        let mut m = make_machine();
        m.push(AvmValue::Bytes(vec![0x00, 0x80])).unwrap();
        m.push(AvmValue::Uint64(8)).unwrap();
        op_getbit(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_getbit_bytes_out_of_range() {
        let mut m = make_machine();
        m.push(AvmValue::Bytes(vec![0xFF])).unwrap();
        m.push(AvmValue::Uint64(8)).unwrap();
        assert!(op_getbit(&mut m, &dummy_instr()).is_err());
    }

    #[test]
    fn test_getbit_empty_bytes_out_of_range() {
        let mut m = make_machine();
        m.push(AvmValue::Bytes(vec![])).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        assert!(op_getbit(&mut m, &dummy_instr()).is_err());
    }

    // ---- setbit ----

    #[test]
    fn test_setbit_uint64_set() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(3)).unwrap(); // bit index
        m.push(AvmValue::Uint64(1)).unwrap(); // value
        op_setbit(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 8); // 1 << 3
    }

    #[test]
    fn test_setbit_uint64_clear() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(0xFF)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap(); // bit index
        m.push(AvmValue::Uint64(0)).unwrap(); // value
        op_setbit(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0xFE);
    }

    #[test]
    fn test_setbit_uint64_out_of_range() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(64)).unwrap();
        m.push(AvmValue::Uint64(1)).unwrap();
        assert!(op_setbit(&mut m, &dummy_instr()).is_err());
    }

    #[test]
    fn test_setbit_invalid_value() {
        let mut m = make_machine();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(2)).unwrap(); // not 0 or 1
        assert!(op_setbit(&mut m, &dummy_instr()).is_err());
    }

    #[test]
    fn test_setbit_bytes_set_msb() {
        // Set bit 0 (MSB of byte 0) on 0x00
        let mut m = make_machine();
        m.push(AvmValue::Bytes(vec![0x00])).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(1)).unwrap();
        op_setbit(&mut m, &dummy_instr()).unwrap();
        match m.pop_any().unwrap() {
            AvmValue::Bytes(b) => assert_eq!(b, vec![0x80]),
            _ => panic!("expected bytes"),
        }
    }

    #[test]
    fn test_setbit_bytes_clear_bit() {
        // Clear bit 7 (LSB of byte 0) on 0xFF
        let mut m = make_machine();
        m.push(AvmValue::Bytes(vec![0xFF])).unwrap();
        m.push(AvmValue::Uint64(7)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        op_setbit(&mut m, &dummy_instr()).unwrap();
        match m.pop_any().unwrap() {
            AvmValue::Bytes(b) => assert_eq!(b, vec![0xFE]),
            _ => panic!("expected bytes"),
        }
    }

    #[test]
    fn test_setbit_bytes_out_of_range() {
        let mut m = make_machine();
        m.push(AvmValue::Bytes(vec![0x00])).unwrap();
        m.push(AvmValue::Uint64(8)).unwrap();
        m.push(AvmValue::Uint64(1)).unwrap();
        assert!(op_setbit(&mut m, &dummy_instr()).is_err());
    }

    // ---- getbyte ----

    #[test]
    fn test_getbyte() {
        let mut m = make_machine();
        m.push(AvmValue::Bytes(vec![0x10, 0x20, 0x30])).unwrap();
        m.push(AvmValue::Uint64(1)).unwrap();
        op_getbyte(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0x20);
    }

    #[test]
    fn test_getbyte_first() {
        let mut m = make_machine();
        m.push(AvmValue::Bytes(vec![0xAB])).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        op_getbyte(&mut m, &dummy_instr()).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0xAB);
    }

    #[test]
    fn test_getbyte_out_of_range() {
        let mut m = make_machine();
        m.push(AvmValue::Bytes(vec![0x10])).unwrap();
        m.push(AvmValue::Uint64(1)).unwrap();
        assert!(op_getbyte(&mut m, &dummy_instr()).is_err());
    }

    #[test]
    fn test_getbyte_empty() {
        let mut m = make_machine();
        m.push(AvmValue::Bytes(vec![])).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        assert!(op_getbyte(&mut m, &dummy_instr()).is_err());
    }

    // ---- setbyte ----

    #[test]
    fn test_setbyte() {
        let mut m = make_machine();
        m.push(AvmValue::Bytes(vec![0x00, 0x00])).unwrap();
        m.push(AvmValue::Uint64(1)).unwrap(); // index
        m.push(AvmValue::Uint64(0xFF)).unwrap(); // value
        op_setbyte(&mut m, &dummy_instr()).unwrap();
        match m.pop_any().unwrap() {
            AvmValue::Bytes(b) => assert_eq!(b, vec![0x00, 0xFF]),
            _ => panic!("expected bytes"),
        }
    }

    #[test]
    fn test_setbyte_out_of_range() {
        let mut m = make_machine();
        m.push(AvmValue::Bytes(vec![0x00])).unwrap();
        m.push(AvmValue::Uint64(1)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        assert!(op_setbyte(&mut m, &dummy_instr()).is_err());
    }

    #[test]
    fn test_setbyte_value_too_large() {
        let mut m = make_machine();
        m.push(AvmValue::Bytes(vec![0x00])).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(256)).unwrap();
        assert!(op_setbyte(&mut m, &dummy_instr()).is_err());
    }
}
