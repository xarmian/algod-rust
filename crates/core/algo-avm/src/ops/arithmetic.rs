//! Arithmetic opcodes: +, -, *, /, %, comparisons, addw, mulw, divmodw, exp, expw, shl, shr, sqrt, bitlen, divw.

use algo_error::AlgoError;

use crate::bytecode::Instruction;
use crate::machine::{AvmMachine, AvmValue};

fn avm_err(msg: impl Into<String>) -> AlgoError {
    AlgoError::Avm {
        message: msg.into(),
    }
}

/// `+` (0x08): pop b, pop a, push a+b. Overflow → error.
pub fn op_add(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    let result = a.checked_add(b).ok_or_else(|| avm_err("+ overflow"))?;
    machine.push(AvmValue::Uint64(result))
}

/// `-` (0x09): pop b, pop a, push a-b. Underflow → error.
pub fn op_sub(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    if a < b {
        return Err(avm_err("- underflow"));
    }
    machine.push(AvmValue::Uint64(a - b))
}

/// `*` (0x0b): pop b, pop a, push a*b. Overflow → error.
pub fn op_mul(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    let result = a.checked_mul(b).ok_or_else(|| avm_err("* overflow"))?;
    machine.push(AvmValue::Uint64(result))
}

/// `/` (0x0a): pop b, pop a, push a/b. Division by zero → error.
pub fn op_div(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    if b == 0 {
        return Err(avm_err("/ division by zero"));
    }
    machine.push(AvmValue::Uint64(a / b))
}

/// `%` (0x18): pop b, pop a, push a%b. Division by zero → error.
pub fn op_modulo(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    if b == 0 {
        return Err(avm_err("% division by zero"));
    }
    machine.push(AvmValue::Uint64(a % b))
}

/// `<` (0x0c): pop b, pop a, push (a < b) as 0/1.
pub fn op_lt(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    machine.push(AvmValue::Uint64(if a < b { 1 } else { 0 }))
}

/// `>` (0x0d): pop b, pop a, push (a > b) as 0/1.
pub fn op_gt(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    machine.push(AvmValue::Uint64(if a > b { 1 } else { 0 }))
}

/// `<=` (0x0e): pop b, pop a, push (a <= b) as 0/1.
pub fn op_le(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    machine.push(AvmValue::Uint64(if a <= b { 1 } else { 0 }))
}

/// `>=` (0x0f): pop b, pop a, push (a >= b) as 0/1.
pub fn op_ge(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    machine.push(AvmValue::Uint64(if a >= b { 1 } else { 0 }))
}

/// `==` (0x12): pop b, pop a — both must be same type. Push (a == b) as 0/1.
pub fn op_eq(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_any()?;
    let a = machine.pop_any()?;
    let result = match (&a, &b) {
        (AvmValue::Uint64(va), AvmValue::Uint64(vb)) => va == vb,
        (AvmValue::Bytes(va), AvmValue::Bytes(vb)) => va == vb,
        _ => {
            return Err(avm_err(
                "== type mismatch: both operands must be the same type",
            ))
        }
    };
    machine.push(AvmValue::Uint64(if result { 1 } else { 0 }))
}

/// `!=` (0x13): pop b, pop a — both must be same type. Push (a != b) as 0/1.
pub fn op_neq(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_any()?;
    let a = machine.pop_any()?;
    let result = match (&a, &b) {
        (AvmValue::Uint64(va), AvmValue::Uint64(vb)) => va != vb,
        (AvmValue::Bytes(va), AvmValue::Bytes(vb)) => va != vb,
        _ => {
            return Err(avm_err(
                "!= type mismatch: both operands must be the same type",
            ))
        }
    };
    machine.push(AvmValue::Uint64(if result { 1 } else { 0 }))
}

/// `!` (0x14): pop a (uint), push (a == 0) as 0/1.
pub fn op_not(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let a = machine.pop_uint()?;
    machine.push(AvmValue::Uint64(if a == 0 { 1 } else { 0 }))
}

/// `addw` (0x1e): pop b, pop a, push (high, low) of 128-bit a+b.
pub fn op_addw(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    let sum = a as u128 + b as u128;
    let high = (sum >> 64) as u64;
    let low = sum as u64;
    machine.push(AvmValue::Uint64(high))?;
    machine.push(AvmValue::Uint64(low))
}

/// `mulw` (0x1d): pop b, pop a, push (high, low) of 128-bit a*b.
pub fn op_mulw(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    let product = a as u128 * b as u128;
    let high = (product >> 64) as u64;
    let low = product as u64;
    machine.push(AvmValue::Uint64(high))?;
    machine.push(AvmValue::Uint64(low))
}

/// `divmodw` (0x1f): pop b_low, b_high, a_low, a_high. Push (q_high, q_low, r_high, r_low).
pub fn op_divmodw(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b_low = machine.pop_uint()?;
    let b_high = machine.pop_uint()?;
    let a_low = machine.pop_uint()?;
    let a_high = machine.pop_uint()?;

    let a = (a_high as u128) << 64 | a_low as u128;
    let b = (b_high as u128) << 64 | b_low as u128;

    if b == 0 {
        return Err(avm_err("divmodw division by zero"));
    }

    let q = a / b;
    let r = a % b;

    machine.push(AvmValue::Uint64((q >> 64) as u64))?;
    machine.push(AvmValue::Uint64(q as u64))?;
    machine.push(AvmValue::Uint64((r >> 64) as u64))?;
    machine.push(AvmValue::Uint64(r as u64))
}

/// `exp` (0x94): pop b, pop a, push a^b. 0^0=1. Overflow → error.
pub fn op_exp(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;

    if b == 0 {
        // a^0 = 1 for all a, including 0^0 = 1
        return machine.push(AvmValue::Uint64(1));
    }
    if a == 0 {
        return machine.push(AvmValue::Uint64(0));
    }

    // Binary exponentiation with u128 intermediate to detect overflow
    let mut result: u128 = 1;
    let mut base: u128 = a as u128;
    let mut exp = b;

    while exp > 0 {
        if exp & 1 == 1 {
            result = result
                .checked_mul(base)
                .ok_or_else(|| avm_err("exp overflow"))?;
            if result > u64::MAX as u128 {
                return Err(avm_err("exp overflow"));
            }
        }
        exp >>= 1;
        if exp > 0 {
            base = base
                .checked_mul(base)
                .ok_or_else(|| avm_err("exp overflow"))?;
        }
    }

    machine.push(AvmValue::Uint64(result as u64))
}

/// `expw` (0x95): pop b, pop a, push (high, low) of a^b as 128-bit.
/// Overflow past 128 bits → error.
pub fn op_expw(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;

    if b == 0 {
        machine.push(AvmValue::Uint64(0))?;
        return machine.push(AvmValue::Uint64(1));
    }
    if a == 0 {
        machine.push(AvmValue::Uint64(0))?;
        return machine.push(AvmValue::Uint64(0));
    }

    // Binary exponentiation with checked 128-bit arithmetic
    let mut result: u128 = 1;
    let mut base: u128 = a as u128;
    let mut exp = b;

    while exp > 0 {
        if exp & 1 == 1 {
            result = result
                .checked_mul(base)
                .ok_or_else(|| avm_err("expw overflow"))?;
        }
        exp >>= 1;
        if exp > 0 {
            base = base
                .checked_mul(base)
                .ok_or_else(|| avm_err("expw overflow"))?;
        }
    }

    let high = (result >> 64) as u64;
    let low = result as u64;
    machine.push(AvmValue::Uint64(high))?;
    machine.push(AvmValue::Uint64(low))
}

/// `shl` (0x90): pop b, pop a. If b >= 64, push 0. Else push a << b.
pub fn op_shl(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    let result = if b >= 64 { 0 } else { a << b };
    machine.push(AvmValue::Uint64(result))
}

/// `shr` (0x91): pop b, pop a. If b >= 64, push 0. Else push a >> b.
pub fn op_shr(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a = machine.pop_uint()?;
    let result = if b >= 64 { 0 } else { a >> b };
    machine.push(AvmValue::Uint64(result))
}

/// `sqrt` (0x92): pop a, push integer square root (floor).
pub fn op_sqrt(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let a = machine.pop_uint()?;
    if a <= 1 {
        return machine.push(AvmValue::Uint64(a));
    }
    // Newton's method for integer square root
    // Start with x = a, y = (a/2 + 1) to avoid overflow on (a+1)/2
    let mut x = a;
    let mut y = a / 2 + 1;
    while y < x {
        x = y;
        y = (x + a / x) / 2;
    }
    machine.push(AvmValue::Uint64(x))
}

/// `bitlen` (0x93): pop any. For uint64: position of highest set bit + 1 (0 for 0).
/// For bytes: effective bit length of the byte array.
pub fn op_bitlen(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let val = machine.pop_any()?;
    let bitlen = match val {
        AvmValue::Uint64(v) => {
            if v == 0 {
                0u64
            } else {
                64 - v.leading_zeros() as u64
            }
        }
        AvmValue::Bytes(b) => {
            if b.is_empty() {
                0u64
            } else {
                // Find the first non-zero byte
                let mut result = 0u64;
                for (i, &byte) in b.iter().enumerate() {
                    if byte != 0 {
                        let remaining_bytes = b.len() - i - 1;
                        result = (remaining_bytes as u64) * 8 + (8 - byte.leading_zeros() as u64);
                        break;
                    }
                }
                result
            }
        }
    };
    machine.push(AvmValue::Uint64(bitlen))
}

/// `divw` (0x97): pop b, pop a_low, pop a_high. Compute (a_high<<64 | a_low) / b.
/// Result must fit in u64. Division by zero or overflow → error.
pub fn op_divw(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_uint()?;
    let a_low = machine.pop_uint()?;
    let a_high = machine.pop_uint()?;

    if b == 0 {
        return Err(avm_err("divw division by zero"));
    }

    let a = (a_high as u128) << 64 | a_low as u128;
    let q = a / b as u128;

    if q > u64::MAX as u128 {
        return Err(avm_err("divw result overflow"));
    }

    machine.push(AvmValue::Uint64(q as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::{Immediates, Program};
    use crate::machine::ExecMode;

    fn make_machine() -> AvmMachine {
        let program = Program {
            version: 6,
            instructions: vec![],
        };
        AvmMachine::new(program, ExecMode::LogicSig, 10000)
    }

    fn dummy_instruction() -> Instruction {
        Instruction {
            opcode: 0x00,
            offset: 0,
            immediates: Immediates::None,
        }
    }

    // ---- Addition ----
    #[test]
    fn test_add_basic() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(3)).unwrap();
        m.push(AvmValue::Uint64(4)).unwrap();
        op_add(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 7);
    }

    #[test]
    fn test_add_overflow() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(u64::MAX)).unwrap();
        m.push(AvmValue::Uint64(1)).unwrap();
        assert!(op_add(&mut m, &instr).is_err());
    }

    // ---- Subtraction ----
    #[test]
    fn test_sub_basic() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(10)).unwrap();
        m.push(AvmValue::Uint64(3)).unwrap();
        op_sub(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 7);
    }

    #[test]
    fn test_sub_underflow() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(3)).unwrap();
        m.push(AvmValue::Uint64(10)).unwrap();
        assert!(op_sub(&mut m, &instr).is_err());
    }

    // ---- Multiplication ----
    #[test]
    fn test_mul_basic() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(6)).unwrap();
        m.push(AvmValue::Uint64(7)).unwrap();
        op_mul(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 42);
    }

    #[test]
    fn test_mul_overflow() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(u64::MAX)).unwrap();
        m.push(AvmValue::Uint64(2)).unwrap();
        assert!(op_mul(&mut m, &instr).is_err());
    }

    // ---- Division ----
    #[test]
    fn test_div_basic() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(42)).unwrap();
        m.push(AvmValue::Uint64(7)).unwrap();
        op_div(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 6);
    }

    #[test]
    fn test_div_truncates() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(10)).unwrap();
        m.push(AvmValue::Uint64(3)).unwrap();
        op_div(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 3);
    }

    #[test]
    fn test_div_by_zero() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(10)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        assert!(op_div(&mut m, &instr).is_err());
    }

    // ---- Modulo ----
    #[test]
    fn test_modulo_basic() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(10)).unwrap();
        m.push(AvmValue::Uint64(3)).unwrap();
        op_modulo(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_modulo_by_zero() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(10)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        assert!(op_modulo(&mut m, &instr).is_err());
    }

    // ---- Comparisons ----
    #[test]
    fn test_lt() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(3)).unwrap();
        m.push(AvmValue::Uint64(5)).unwrap();
        op_lt(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);

        m.push(AvmValue::Uint64(5)).unwrap();
        m.push(AvmValue::Uint64(3)).unwrap();
        op_lt(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);

        m.push(AvmValue::Uint64(3)).unwrap();
        m.push(AvmValue::Uint64(3)).unwrap();
        op_lt(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    #[test]
    fn test_gt() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(5)).unwrap();
        m.push(AvmValue::Uint64(3)).unwrap();
        op_gt(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);

        m.push(AvmValue::Uint64(3)).unwrap();
        m.push(AvmValue::Uint64(5)).unwrap();
        op_gt(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    #[test]
    fn test_le() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(3)).unwrap();
        m.push(AvmValue::Uint64(5)).unwrap();
        op_le(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);

        m.push(AvmValue::Uint64(3)).unwrap();
        m.push(AvmValue::Uint64(3)).unwrap();
        op_le(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);

        m.push(AvmValue::Uint64(5)).unwrap();
        m.push(AvmValue::Uint64(3)).unwrap();
        op_le(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    #[test]
    fn test_ge() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(5)).unwrap();
        m.push(AvmValue::Uint64(3)).unwrap();
        op_ge(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);

        m.push(AvmValue::Uint64(3)).unwrap();
        m.push(AvmValue::Uint64(3)).unwrap();
        op_ge(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);

        m.push(AvmValue::Uint64(3)).unwrap();
        m.push(AvmValue::Uint64(5)).unwrap();
        op_ge(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    // ---- Equality ----
    #[test]
    fn test_eq_uint() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(42)).unwrap();
        m.push(AvmValue::Uint64(42)).unwrap();
        op_eq(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);

        m.push(AvmValue::Uint64(42)).unwrap();
        m.push(AvmValue::Uint64(43)).unwrap();
        op_eq(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    #[test]
    fn test_eq_bytes() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Bytes(vec![1, 2, 3])).unwrap();
        m.push(AvmValue::Bytes(vec![1, 2, 3])).unwrap();
        op_eq(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);

        m.push(AvmValue::Bytes(vec![1, 2])).unwrap();
        m.push(AvmValue::Bytes(vec![1, 2, 3])).unwrap();
        op_eq(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    #[test]
    fn test_eq_type_mismatch() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Bytes(vec![])).unwrap();
        assert!(op_eq(&mut m, &instr).is_err());
    }

    #[test]
    fn test_neq() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(1)).unwrap();
        m.push(AvmValue::Uint64(2)).unwrap();
        op_neq(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);

        m.push(AvmValue::Uint64(1)).unwrap();
        m.push(AvmValue::Uint64(1)).unwrap();
        op_neq(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    // ---- Not ----
    #[test]
    fn test_not() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(0)).unwrap();
        op_not(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);

        m.push(AvmValue::Uint64(42)).unwrap();
        op_not(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    // ---- Addw ----
    #[test]
    fn test_addw_no_carry() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(3)).unwrap();
        m.push(AvmValue::Uint64(4)).unwrap();
        op_addw(&mut m, &instr).unwrap();
        let low = m.pop_uint().unwrap();
        let high = m.pop_uint().unwrap();
        assert_eq!(high, 0);
        assert_eq!(low, 7);
    }

    #[test]
    fn test_addw_with_carry() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(u64::MAX)).unwrap();
        m.push(AvmValue::Uint64(2)).unwrap();
        op_addw(&mut m, &instr).unwrap();
        let low = m.pop_uint().unwrap();
        let high = m.pop_uint().unwrap();
        assert_eq!(high, 1);
        assert_eq!(low, 1);
    }

    // ---- Mulw ----
    #[test]
    fn test_mulw_no_overflow() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(6)).unwrap();
        m.push(AvmValue::Uint64(7)).unwrap();
        op_mulw(&mut m, &instr).unwrap();
        let low = m.pop_uint().unwrap();
        let high = m.pop_uint().unwrap();
        assert_eq!(high, 0);
        assert_eq!(low, 42);
    }

    #[test]
    fn test_mulw_with_overflow() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(u64::MAX)).unwrap();
        m.push(AvmValue::Uint64(u64::MAX)).unwrap();
        op_mulw(&mut m, &instr).unwrap();
        let low = m.pop_uint().unwrap();
        let high = m.pop_uint().unwrap();
        // MAX * MAX = (2^64-1)^2 = 2^128 - 2^65 + 1
        // high = 2^64 - 2 = 0xFFFFFFFFFFFFFFFE
        // low = 1
        assert_eq!(high, u64::MAX - 1);
        assert_eq!(low, 1);
    }

    // ---- Divmodw ----
    #[test]
    fn test_divmodw_basic() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        // a = 10 (a_high=0, a_low=10), b = 3 (b_high=0, b_low=3)
        m.push(AvmValue::Uint64(0)).unwrap(); // a_high
        m.push(AvmValue::Uint64(10)).unwrap(); // a_low
        m.push(AvmValue::Uint64(0)).unwrap(); // b_high
        m.push(AvmValue::Uint64(3)).unwrap(); // b_low
        op_divmodw(&mut m, &instr).unwrap();
        let r_low = m.pop_uint().unwrap();
        let r_high = m.pop_uint().unwrap();
        let q_low = m.pop_uint().unwrap();
        let q_high = m.pop_uint().unwrap();
        assert_eq!(q_high, 0);
        assert_eq!(q_low, 3);
        assert_eq!(r_high, 0);
        assert_eq!(r_low, 1);
    }

    #[test]
    fn test_divmodw_div_by_zero() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(10)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        assert!(op_divmodw(&mut m, &instr).is_err());
    }

    // ---- Exp ----
    #[test]
    fn test_exp_basic() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(2)).unwrap();
        m.push(AvmValue::Uint64(10)).unwrap();
        op_exp(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1024);
    }

    #[test]
    fn test_exp_zero_to_zero() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        op_exp(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_exp_overflow() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(2)).unwrap();
        m.push(AvmValue::Uint64(64)).unwrap();
        assert!(op_exp(&mut m, &instr).is_err());
    }

    #[test]
    fn test_exp_max_no_overflow() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        // 2^63 = 9223372036854775808, fits in u64
        m.push(AvmValue::Uint64(2)).unwrap();
        m.push(AvmValue::Uint64(63)).unwrap();
        op_exp(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1u64 << 63);
    }

    // ---- Expw ----
    #[test]
    fn test_expw_basic() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(2)).unwrap();
        m.push(AvmValue::Uint64(64)).unwrap();
        op_expw(&mut m, &instr).unwrap();
        let low = m.pop_uint().unwrap();
        let high = m.pop_uint().unwrap();
        assert_eq!(high, 1);
        assert_eq!(low, 0);
    }

    #[test]
    fn test_expw_overflow() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(2)).unwrap();
        m.push(AvmValue::Uint64(128)).unwrap();
        assert!(op_expw(&mut m, &instr).is_err());
    }

    // ---- Shl / Shr ----
    #[test]
    fn test_shl() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(1)).unwrap();
        m.push(AvmValue::Uint64(10)).unwrap();
        op_shl(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1024);
    }

    #[test]
    fn test_shl_large_shift() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(1)).unwrap();
        m.push(AvmValue::Uint64(64)).unwrap();
        op_shl(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    #[test]
    fn test_shr() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(1024)).unwrap();
        m.push(AvmValue::Uint64(3)).unwrap();
        op_shr(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 128);
    }

    #[test]
    fn test_shr_large_shift() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(u64::MAX)).unwrap();
        m.push(AvmValue::Uint64(64)).unwrap();
        op_shr(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    // ---- Sqrt ----
    #[test]
    fn test_sqrt_perfect() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(144)).unwrap();
        op_sqrt(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 12);
    }

    #[test]
    fn test_sqrt_non_perfect() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(10)).unwrap();
        op_sqrt(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 3);
    }

    #[test]
    fn test_sqrt_zero() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(0)).unwrap();
        op_sqrt(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    #[test]
    fn test_sqrt_one() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(1)).unwrap();
        op_sqrt(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_sqrt_max() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(u64::MAX)).unwrap();
        op_sqrt(&mut m, &instr).unwrap();
        // isqrt(2^64 - 1) = 2^32 - 1 = 4294967295
        assert_eq!(m.pop_uint().unwrap(), 4294967295);
    }

    // ---- Bitlen ----
    #[test]
    fn test_bitlen_uint() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(0)).unwrap();
        op_bitlen(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);

        m.push(AvmValue::Uint64(1)).unwrap();
        op_bitlen(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);

        m.push(AvmValue::Uint64(255)).unwrap();
        op_bitlen(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 8);

        m.push(AvmValue::Uint64(256)).unwrap();
        op_bitlen(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 9);

        m.push(AvmValue::Uint64(u64::MAX)).unwrap();
        op_bitlen(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 64);
    }

    #[test]
    fn test_bitlen_bytes() {
        let mut m = make_machine();
        let instr = dummy_instruction();

        // Empty bytes
        m.push(AvmValue::Bytes(vec![])).unwrap();
        op_bitlen(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);

        // [0x00] -> bitlen 0
        m.push(AvmValue::Bytes(vec![0x00])).unwrap();
        op_bitlen(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);

        // [0x01] -> bitlen 1
        m.push(AvmValue::Bytes(vec![0x01])).unwrap();
        op_bitlen(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);

        // [0xFF] -> bitlen 8
        m.push(AvmValue::Bytes(vec![0xFF])).unwrap();
        op_bitlen(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 8);

        // [0x01, 0x00] -> bitlen 9
        m.push(AvmValue::Bytes(vec![0x01, 0x00])).unwrap();
        op_bitlen(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 9);

        // [0x00, 0x01] -> bitlen 1
        m.push(AvmValue::Bytes(vec![0x00, 0x01])).unwrap();
        op_bitlen(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    // ---- Divw ----
    #[test]
    fn test_divw_basic() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        // (0 << 64 | 10) / 3 = 3
        m.push(AvmValue::Uint64(0)).unwrap(); // a_high
        m.push(AvmValue::Uint64(10)).unwrap(); // a_low
        m.push(AvmValue::Uint64(3)).unwrap(); // b
        op_divw(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 3);
    }

    #[test]
    fn test_divw_128bit() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        // (1 << 64 | 0) / 2 = 2^63
        m.push(AvmValue::Uint64(1)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(2)).unwrap();
        op_divw(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1u64 << 63);
    }

    #[test]
    fn test_divw_div_by_zero() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(10)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        assert!(op_divw(&mut m, &instr).is_err());
    }

    #[test]
    fn test_divw_overflow() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        // (2 << 64 | 0) / 1 = 2^65, doesn't fit in u64
        m.push(AvmValue::Uint64(2)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(1)).unwrap();
        assert!(op_divw(&mut m, &instr).is_err());
    }

    // ---- Edge cases ----
    #[test]
    fn test_add_zero() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        op_add(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    #[test]
    fn test_sub_zero() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(5)).unwrap();
        m.push(AvmValue::Uint64(5)).unwrap();
        op_sub(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    #[test]
    fn test_mul_by_zero() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(u64::MAX)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        op_mul(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    #[test]
    fn test_exp_one_to_large() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(1)).unwrap();
        m.push(AvmValue::Uint64(u64::MAX)).unwrap();
        op_exp(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_expw_zero_to_zero() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Uint64(0)).unwrap();
        op_expw(&mut m, &instr).unwrap();
        let low = m.pop_uint().unwrap();
        let high = m.pop_uint().unwrap();
        assert_eq!(high, 0);
        assert_eq!(low, 1);
    }

    #[test]
    fn test_neq_bytes() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Bytes(vec![1])).unwrap();
        m.push(AvmValue::Bytes(vec![2])).unwrap();
        op_neq(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_neq_type_mismatch() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(0)).unwrap();
        m.push(AvmValue::Bytes(vec![])).unwrap();
        assert!(op_neq(&mut m, &instr).is_err());
    }

    #[test]
    fn test_modulo_exact() {
        let mut m = make_machine();
        let instr = dummy_instruction();
        m.push(AvmValue::Uint64(10)).unwrap();
        m.push(AvmValue::Uint64(5)).unwrap();
        op_modulo(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }
}
