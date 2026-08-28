//! Byte string opcodes: concat, substring, len, itob, btoi, extract, replace,
//! bzero, and big-integer byte-math (b+, b-, b*, b/, b%, b<, b>, b<=, b>=,
//! b==, b!=, b|, b&, b^, b~, bsqrt).

use algo_error::AlgoError;
use num_bigint::BigUint;

use crate::bytecode::{Immediates, Instruction};
use crate::machine::AvmMachine;

/// Maximum byte string length in the AVM.
const MAX_BYTES_LEN: usize = 4096;

/// Maximum result length for big-int multiplication.
const MAX_BIGINT_MUL_LEN: usize = 128;

/// Maximum result length for other big-int ops.
const MAX_BIGINT_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn avm_err(msg: impl Into<String>) -> AlgoError {
    AlgoError::Avm {
        message: msg.into(),
    }
}

/// Convert a BigUint to big-endian bytes. Zero produces empty bytes,
/// matching Go's `big.Int.Bytes()` semantics used by the AVM.
fn biguint_to_bytes(v: &BigUint) -> Vec<u8> {
    v.to_bytes_be()
}

/// Check that a byte result does not exceed `max_len`.
fn check_len(bytes: &[u8], max_len: usize, op: &str) -> Result<(), AlgoError> {
    if bytes.len() > max_len {
        Err(avm_err(format!(
            "{op}: result length {} exceeds maximum {max_len}",
            bytes.len()
        )))
    } else {
        Ok(())
    }
}

/// Pad the shorter of two byte slices with leading zeros so both are the same length.
/// Returns (a_padded, b_padded).
fn pad_to_same_len(a: &[u8], b: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let max_len = a.len().max(b.len());
    let mut a_padded = vec![0u8; max_len - a.len()];
    a_padded.extend_from_slice(a);
    let mut b_padded = vec![0u8; max_len - b.len()];
    b_padded.extend_from_slice(b);
    (a_padded, b_padded)
}

// ---------------------------------------------------------------------------
// String operations
// ---------------------------------------------------------------------------

/// `len` (0x15): pop a (bytes), push a.len() as uint64.
pub fn op_len(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let a = machine.pop_bytes()?;
    machine.push(crate::machine::AvmValue::Uint64(a.len() as u64))
}

/// `itob` (0x16): pop a (uint64), push as 8-byte big-endian bytes.
pub fn op_itob(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let a = machine.pop_uint()?;
    machine.push(crate::machine::AvmValue::Bytes(a.to_be_bytes().to_vec()))
}

/// `btoi` (0x17): pop a (bytes), convert big-endian to uint64. Max 8 bytes.
pub fn op_btoi(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let a = machine.pop_bytes()?;
    if a.len() > 8 {
        return Err(avm_err(format!(
            "btoi: byte string length {} exceeds 8",
            a.len()
        )));
    }
    let mut val: u64 = 0;
    for &byte in &a {
        val = val << 8 | byte as u64;
    }
    machine.push(crate::machine::AvmValue::Uint64(val))
}

/// `concat` (0x50): pop b, pop a, push a+b. Max 4096 bytes.
pub fn op_concat(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_bytes()?;
    let a = machine.pop_bytes()?;
    let total = a.len() + b.len();
    if total > MAX_BYTES_LEN {
        return Err(avm_err(format!(
            "concat: result length {total} exceeds maximum {MAX_BYTES_LEN}"
        )));
    }
    let mut result = a;
    result.extend_from_slice(&b);
    machine.push(crate::machine::AvmValue::Bytes(result))
}

/// `substring s e` (0x51): immediate Uint8Pair(s, e). Pop a, push a[s..e].
pub fn op_substring(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let (s, e) = match instruction.immediates {
        Immediates::Uint8Pair(s, e) => (s as usize, e as usize),
        _ => return Err(avm_err("substring: expected Uint8Pair immediate")),
    };
    let a = machine.pop_bytes()?;
    if s > e {
        return Err(avm_err(format!("substring: start {s} > end {e}")));
    }
    if e > a.len() {
        return Err(avm_err(format!("substring: end {e} > length {}", a.len())));
    }
    machine.push(crate::machine::AvmValue::Bytes(a[s..e].to_vec()))
}

/// `substring3` (0x52): pop e, pop s, pop a, push a[s..e].
pub fn op_substring3(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
) -> Result<(), AlgoError> {
    let e = machine.pop_uint()? as usize;
    let s = machine.pop_uint()? as usize;
    let a = machine.pop_bytes()?;
    if s > e {
        return Err(avm_err(format!("substring3: start {s} > end {e}")));
    }
    if e > a.len() {
        return Err(avm_err(format!("substring3: end {e} > length {}", a.len())));
    }
    machine.push(crate::machine::AvmValue::Bytes(a[s..e].to_vec()))
}

/// `extract s l` (0x57): immediate Uint8Pair(s, l). Pop a, push a[s..s+l]. If l==0, push a[s..].
pub fn op_extract(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let (s, l) = match instruction.immediates {
        Immediates::Uint8Pair(s, l) => (s as usize, l as usize),
        _ => return Err(avm_err("extract: expected Uint8Pair immediate")),
    };
    let a = machine.pop_bytes()?;
    if s > a.len() {
        return Err(avm_err(format!("extract: start {s} > length {}", a.len())));
    }
    if l == 0 {
        machine.push(crate::machine::AvmValue::Bytes(a[s..].to_vec()))
    } else {
        let end = s + l;
        if end > a.len() {
            return Err(avm_err(format!(
                "extract: start {s} + length {l} > byte length {}",
                a.len()
            )));
        }
        machine.push(crate::machine::AvmValue::Bytes(a[s..end].to_vec()))
    }
}

/// `extract3` (0x58): pop l, pop s, pop a, push a[s..s+l].
pub fn op_extract3(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let l = machine.pop_uint()? as usize;
    let s = machine.pop_uint()? as usize;
    let a = machine.pop_bytes()?;
    let end = s
        .checked_add(l)
        .ok_or_else(|| avm_err(format!("extract3: start {s} + length {l} overflows")))?;
    if end > a.len() {
        return Err(avm_err(format!(
            "extract3: start {s} + length {l} > byte length {}",
            a.len()
        )));
    }
    machine.push(crate::machine::AvmValue::Bytes(a[s..end].to_vec()))
}

/// `extract_uint16` (0x59): pop s (uint), pop a (bytes), read big-endian u16 at a[s..s+2].
pub fn op_extract_uint16(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
) -> Result<(), AlgoError> {
    let s = machine.pop_uint()? as usize;
    let a = machine.pop_bytes()?;
    if s.checked_add(2).map_or(true, |end| end > a.len()) {
        return Err(avm_err(format!(
            "extract_uint16: offset {s} + 2 > length {}",
            a.len()
        )));
    }
    let val = u16::from_be_bytes([a[s], a[s + 1]]);
    machine.push(crate::machine::AvmValue::Uint64(val as u64))
}

/// `extract_uint32` (0x5a): pop s (uint), pop a (bytes), read big-endian u32 at a[s..s+4].
pub fn op_extract_uint32(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
) -> Result<(), AlgoError> {
    let s = machine.pop_uint()? as usize;
    let a = machine.pop_bytes()?;
    if s.checked_add(4).map_or(true, |end| end > a.len()) {
        return Err(avm_err(format!(
            "extract_uint32: offset {s} + 4 > length {}",
            a.len()
        )));
    }
    let val = u32::from_be_bytes([a[s], a[s + 1], a[s + 2], a[s + 3]]);
    machine.push(crate::machine::AvmValue::Uint64(val as u64))
}

/// `extract_uint64` (0x5b): pop s (uint), pop a (bytes), read big-endian u64 at a[s..s+8].
pub fn op_extract_uint64(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
) -> Result<(), AlgoError> {
    let s = machine.pop_uint()? as usize;
    let a = machine.pop_bytes()?;
    if s.checked_add(8).map_or(true, |end| end > a.len()) {
        return Err(avm_err(format!(
            "extract_uint64: offset {s} + 8 > length {}",
            a.len()
        )));
    }
    let val = u64::from_be_bytes([
        a[s],
        a[s + 1],
        a[s + 2],
        a[s + 3],
        a[s + 4],
        a[s + 5],
        a[s + 6],
        a[s + 7],
    ]);
    machine.push(crate::machine::AvmValue::Uint64(val))
}

/// `replace2 s` (0x5c): immediate Uint8(s). Pop b (bytes), pop a (bytes), replace a[s..s+b.len()] with b.
pub fn op_replace2(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let s = match instruction.immediates {
        Immediates::Uint8(s) => s as usize,
        _ => return Err(avm_err("replace2: expected Uint8 immediate")),
    };
    let b = machine.pop_bytes()?;
    let mut a = machine.pop_bytes()?;
    let end = s.checked_add(b.len()).ok_or_else(|| {
        avm_err(format!(
            "replace2: start {s} + replacement length {} overflows",
            b.len()
        ))
    })?;
    if end > a.len() {
        return Err(avm_err(format!(
            "replace2: start {s} + replacement length {} > byte length {}",
            b.len(),
            a.len()
        )));
    }
    a[s..end].copy_from_slice(&b);
    machine.push(crate::machine::AvmValue::Bytes(a))
}

/// `replace3` (0x5d): pop b (bytes), pop s (uint), pop a (bytes), replace a[s..s+b.len()] with b.
pub fn op_replace3(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop_bytes()?;
    let s = machine.pop_uint()? as usize;
    let mut a = machine.pop_bytes()?;
    let end = s.checked_add(b.len()).ok_or_else(|| {
        avm_err(format!(
            "replace3: start {s} + replacement length {} overflows",
            b.len()
        ))
    })?;
    if end > a.len() {
        return Err(avm_err(format!(
            "replace3: start {s} + replacement length {} > byte length {}",
            b.len(),
            a.len()
        )));
    }
    a[s..end].copy_from_slice(&b);
    machine.push(crate::machine::AvmValue::Bytes(a))
}

/// `bzero` (0xaf): pop n (uint64), push n zero bytes. Max 4096.
pub fn op_bzero(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let n = machine.pop_uint()? as usize;
    if n > MAX_BYTES_LEN {
        return Err(avm_err(format!(
            "bzero: length {n} exceeds maximum {MAX_BYTES_LEN}"
        )));
    }
    machine.push(crate::machine::AvmValue::Bytes(vec![0u8; n]))
}

// ---------------------------------------------------------------------------
// Big-integer byte-math operations
// ---------------------------------------------------------------------------

/// `b+` (0xa0): pop b, pop a, push a+b as bytes. Max 64 bytes.
pub fn op_badd(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = BigUint::from_bytes_be(&machine.pop_bytes()?);
    let a = BigUint::from_bytes_be(&machine.pop_bytes()?);
    let result = biguint_to_bytes(&(a + b));
    check_len(&result, MAX_BIGINT_LEN, "b+")?;
    machine.push(crate::machine::AvmValue::Bytes(result))
}

/// `b-` (0xa1): pop b, pop a, push a-b as bytes. Error if a < b.
pub fn op_bsub(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = BigUint::from_bytes_be(&machine.pop_bytes()?);
    let a = BigUint::from_bytes_be(&machine.pop_bytes()?);
    if a < b {
        return Err(avm_err("b-: underflow (a < b)"));
    }
    let result = biguint_to_bytes(&(a - b));
    machine.push(crate::machine::AvmValue::Bytes(result))
}

/// `b/` (0xa2): pop b, pop a, push a/b as bytes. Division by zero → error.
pub fn op_bdiv(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = BigUint::from_bytes_be(&machine.pop_bytes()?);
    let a = BigUint::from_bytes_be(&machine.pop_bytes()?);
    if b == BigUint::ZERO {
        return Err(avm_err("b/: division by zero"));
    }
    let result = biguint_to_bytes(&(a / b));
    machine.push(crate::machine::AvmValue::Bytes(result))
}

/// `b*` (0xa3): pop b, pop a, push a*b as bytes. Max 128 bytes.
pub fn op_bmul(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = BigUint::from_bytes_be(&machine.pop_bytes()?);
    let a = BigUint::from_bytes_be(&machine.pop_bytes()?);
    let result = biguint_to_bytes(&(a * b));
    check_len(&result, MAX_BIGINT_MUL_LEN, "b*")?;
    machine.push(crate::machine::AvmValue::Bytes(result))
}

/// `b%` (0xaa): pop b, pop a, push a%b as bytes. Division by zero → error.
pub fn op_bmod(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = BigUint::from_bytes_be(&machine.pop_bytes()?);
    let a = BigUint::from_bytes_be(&machine.pop_bytes()?);
    if b == BigUint::ZERO {
        return Err(avm_err("b%: division by zero"));
    }
    let result = biguint_to_bytes(&(a % b));
    machine.push(crate::machine::AvmValue::Bytes(result))
}

/// `b<` (0xa4): pop b, pop a, push (a < b) as uint64.
pub fn op_blt(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = BigUint::from_bytes_be(&machine.pop_bytes()?);
    let a = BigUint::from_bytes_be(&machine.pop_bytes()?);
    machine.push(crate::machine::AvmValue::Uint64(if a < b { 1 } else { 0 }))
}

/// `b>` (0xa5): pop b, pop a, push (a > b) as uint64.
pub fn op_bgt(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = BigUint::from_bytes_be(&machine.pop_bytes()?);
    let a = BigUint::from_bytes_be(&machine.pop_bytes()?);
    machine.push(crate::machine::AvmValue::Uint64(if a > b { 1 } else { 0 }))
}

/// `b<=` (0xa6): pop b, pop a, push (a <= b) as uint64.
pub fn op_ble(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = BigUint::from_bytes_be(&machine.pop_bytes()?);
    let a = BigUint::from_bytes_be(&machine.pop_bytes()?);
    machine.push(crate::machine::AvmValue::Uint64(if a <= b { 1 } else { 0 }))
}

/// `b>=` (0xa7): pop b, pop a, push (a >= b) as uint64.
pub fn op_bge(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = BigUint::from_bytes_be(&machine.pop_bytes()?);
    let a = BigUint::from_bytes_be(&machine.pop_bytes()?);
    machine.push(crate::machine::AvmValue::Uint64(if a >= b { 1 } else { 0 }))
}

/// `b==` (0xa8): pop b, pop a, push (a == b) as uint64.
pub fn op_beq(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = BigUint::from_bytes_be(&machine.pop_bytes()?);
    let a = BigUint::from_bytes_be(&machine.pop_bytes()?);
    machine.push(crate::machine::AvmValue::Uint64(if a == b { 1 } else { 0 }))
}

/// `b!=` (0xa9): pop b, pop a, push (a != b) as uint64.
pub fn op_bne(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = BigUint::from_bytes_be(&machine.pop_bytes()?);
    let a = BigUint::from_bytes_be(&machine.pop_bytes()?);
    machine.push(crate::machine::AvmValue::Uint64(if a != b { 1 } else { 0 }))
}

/// `b|` (0xab): pop b, pop a, push bitwise OR (zero-padded to max length).
pub fn op_bbitwise_or(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
) -> Result<(), AlgoError> {
    let b = machine.pop_bytes()?;
    let a = machine.pop_bytes()?;
    let (a_pad, b_pad) = pad_to_same_len(&a, &b);
    let result: Vec<u8> = a_pad.iter().zip(b_pad.iter()).map(|(x, y)| x | y).collect();
    machine.push(crate::machine::AvmValue::Bytes(result))
}

/// `b&` (0xac): pop b, pop a, push bitwise AND (zero-padded to max length).
pub fn op_bbitwise_and(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
) -> Result<(), AlgoError> {
    let b = machine.pop_bytes()?;
    let a = machine.pop_bytes()?;
    let (a_pad, b_pad) = pad_to_same_len(&a, &b);
    let result: Vec<u8> = a_pad.iter().zip(b_pad.iter()).map(|(x, y)| x & y).collect();
    machine.push(crate::machine::AvmValue::Bytes(result))
}

/// `b^` (0xad): pop b, pop a, push bitwise XOR (zero-padded to max length).
pub fn op_bbitwise_xor(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
) -> Result<(), AlgoError> {
    let b = machine.pop_bytes()?;
    let a = machine.pop_bytes()?;
    let (a_pad, b_pad) = pad_to_same_len(&a, &b);
    let result: Vec<u8> = a_pad.iter().zip(b_pad.iter()).map(|(x, y)| x ^ y).collect();
    machine.push(crate::machine::AvmValue::Bytes(result))
}

/// `b~` (0xae): pop a (bytes), push bitwise NOT.
pub fn op_bbitwise_not(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
) -> Result<(), AlgoError> {
    let a = machine.pop_bytes()?;
    let result: Vec<u8> = a.iter().map(|x| !x).collect();
    machine.push(crate::machine::AvmValue::Bytes(result))
}

/// `bsqrt` (0x96): pop a (bytes), push integer square root as bytes.
pub fn op_bsqrt(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let a = BigUint::from_bytes_be(&machine.pop_bytes()?);
    let result = biguint_to_bytes(&a.sqrt());
    machine.push(crate::machine::AvmValue::Bytes(result))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::{Immediates, Instruction, Program};
    use crate::machine::{AvmMachine, AvmValue, ExecMode};

    /// Helper: create a machine with some values pre-pushed on the stack.
    fn machine_with_stack(stack: Vec<AvmValue>) -> AvmMachine {
        let program = Program {
            version: 6,
            instructions: vec![],
        };
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        for v in stack {
            m.push(v).unwrap();
        }
        m
    }

    fn dummy_instr(opcode: u8, immediates: Immediates) -> Instruction {
        Instruction {
            opcode,
            sub_opcode: None,
            offset: 0,
            immediates,
        }
    }

    fn bytes_val(b: &[u8]) -> AvmValue {
        AvmValue::Bytes(b.to_vec())
    }

    fn uint_val(v: u64) -> AvmValue {
        AvmValue::Uint64(v)
    }

    // ---- len ----
    #[test]
    fn test_len() {
        let mut m = machine_with_stack(vec![bytes_val(b"hello")]);
        let instr = dummy_instr(0x15, Immediates::None);
        op_len(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 5);
    }

    #[test]
    fn test_len_empty() {
        let mut m = machine_with_stack(vec![bytes_val(b"")]);
        let instr = dummy_instr(0x15, Immediates::None);
        op_len(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    // ---- itob ----
    #[test]
    fn test_itob() {
        let mut m = machine_with_stack(vec![uint_val(0x0102030405060708)]);
        let instr = dummy_instr(0x16, Immediates::None);
        op_itob(&mut m, &instr).unwrap();
        assert_eq!(
            m.pop_bytes().unwrap(),
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn test_itob_zero() {
        let mut m = machine_with_stack(vec![uint_val(0)]);
        let instr = dummy_instr(0x16, Immediates::None);
        op_itob(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0, 0, 0, 0, 0, 0, 0, 0]);
    }

    // ---- btoi ----
    #[test]
    fn test_btoi() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x00, 0x01])]);
        let instr = dummy_instr(0x17, Immediates::None);
        op_btoi(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_btoi_empty() {
        let mut m = machine_with_stack(vec![bytes_val(b"")]);
        let instr = dummy_instr(0x17, Immediates::None);
        op_btoi(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    #[test]
    fn test_btoi_max() {
        let mut m = machine_with_stack(vec![bytes_val(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ])]);
        let instr = dummy_instr(0x17, Immediates::None);
        op_btoi(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), u64::MAX);
    }

    #[test]
    fn test_btoi_too_long() {
        let mut m = machine_with_stack(vec![bytes_val(&[0; 9])]);
        let instr = dummy_instr(0x17, Immediates::None);
        assert!(op_btoi(&mut m, &instr).is_err());
    }

    // ---- concat ----
    #[test]
    fn test_concat() {
        let mut m = machine_with_stack(vec![bytes_val(b"hello"), bytes_val(b" world")]);
        let instr = dummy_instr(0x50, Immediates::None);
        op_concat(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), b"hello world");
    }

    #[test]
    fn test_concat_empty() {
        let mut m = machine_with_stack(vec![bytes_val(b""), bytes_val(b"abc")]);
        let instr = dummy_instr(0x50, Immediates::None);
        op_concat(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), b"abc");
    }

    #[test]
    fn test_concat_too_long() {
        let a = vec![0u8; 4000];
        let b = vec![0u8; 100];
        let mut m = machine_with_stack(vec![bytes_val(&a), bytes_val(&b)]);
        let instr = dummy_instr(0x50, Immediates::None);
        assert!(op_concat(&mut m, &instr).is_err());
    }

    // ---- substring ----
    #[test]
    fn test_substring() {
        let mut m = machine_with_stack(vec![bytes_val(b"hello")]);
        let instr = dummy_instr(0x51, Immediates::Uint8Pair(1, 4));
        op_substring(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), b"ell");
    }

    #[test]
    fn test_substring_start_gt_end() {
        let mut m = machine_with_stack(vec![bytes_val(b"hello")]);
        let instr = dummy_instr(0x51, Immediates::Uint8Pair(3, 1));
        assert!(op_substring(&mut m, &instr).is_err());
    }

    #[test]
    fn test_substring_out_of_bounds() {
        let mut m = machine_with_stack(vec![bytes_val(b"hi")]);
        let instr = dummy_instr(0x51, Immediates::Uint8Pair(0, 5));
        assert!(op_substring(&mut m, &instr).is_err());
    }

    // ---- substring3 ----
    #[test]
    fn test_substring3() {
        let mut m = machine_with_stack(vec![bytes_val(b"abcdef"), uint_val(2), uint_val(5)]);
        let instr = dummy_instr(0x52, Immediates::None);
        op_substring3(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), b"cde");
    }

    // ---- extract ----
    #[test]
    fn test_extract_with_length() {
        let mut m = machine_with_stack(vec![bytes_val(b"abcdef")]);
        let instr = dummy_instr(0x57, Immediates::Uint8Pair(1, 3));
        op_extract(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), b"bcd");
    }

    #[test]
    fn test_extract_zero_length() {
        let mut m = machine_with_stack(vec![bytes_val(b"abcdef")]);
        let instr = dummy_instr(0x57, Immediates::Uint8Pair(2, 0));
        op_extract(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), b"cdef");
    }

    // ---- extract3 ----
    #[test]
    fn test_extract3() {
        let mut m = machine_with_stack(vec![bytes_val(b"abcdef"), uint_val(1), uint_val(3)]);
        let instr = dummy_instr(0x58, Immediates::None);
        op_extract3(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), b"bcd");
    }

    #[test]
    fn test_extract3_out_of_bounds() {
        let mut m = machine_with_stack(vec![bytes_val(b"ab"), uint_val(0), uint_val(5)]);
        let instr = dummy_instr(0x58, Immediates::None);
        assert!(op_extract3(&mut m, &instr).is_err());
    }

    // ---- extract_uint16 ----
    #[test]
    fn test_extract_uint16() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x00, 0x01, 0x02, 0x03]), uint_val(1)]);
        let instr = dummy_instr(0x59, Immediates::None);
        op_extract_uint16(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0x0102);
    }

    // ---- extract_uint32 ----
    #[test]
    fn test_extract_uint32() {
        let mut m = machine_with_stack(vec![
            bytes_val(&[0x00, 0x01, 0x02, 0x03, 0x04]),
            uint_val(1),
        ]);
        let instr = dummy_instr(0x5a, Immediates::None);
        op_extract_uint32(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0x01020304);
    }

    // ---- extract_uint64 ----
    #[test]
    fn test_extract_uint64() {
        let mut m = machine_with_stack(vec![
            bytes_val(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            uint_val(1),
        ]);
        let instr = dummy_instr(0x5b, Immediates::None);
        op_extract_uint64(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0x0102030405060708);
    }

    // ---- replace2 ----
    #[test]
    fn test_replace2() {
        let mut m = machine_with_stack(vec![bytes_val(b"abcdef"), bytes_val(b"XY")]);
        let instr = dummy_instr(0x5c, Immediates::Uint8(2));
        op_replace2(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), b"abXYef");
    }

    #[test]
    fn test_replace2_out_of_bounds() {
        let mut m = machine_with_stack(vec![bytes_val(b"ab"), bytes_val(b"XYZ")]);
        let instr = dummy_instr(0x5c, Immediates::Uint8(1));
        assert!(op_replace2(&mut m, &instr).is_err());
    }

    // ---- replace3 ----
    #[test]
    fn test_replace3() {
        let mut m = machine_with_stack(vec![bytes_val(b"abcdef"), uint_val(1), bytes_val(b"XY")]);
        let instr = dummy_instr(0x5d, Immediates::None);
        op_replace3(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), b"aXYdef");
    }

    // ---- bzero ----
    #[test]
    fn test_bzero() {
        let mut m = machine_with_stack(vec![uint_val(5)]);
        let instr = dummy_instr(0xaf, Immediates::None);
        op_bzero(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_bzero_too_large() {
        let mut m = machine_with_stack(vec![uint_val(4097)]);
        let instr = dummy_instr(0xaf, Immediates::None);
        assert!(op_bzero(&mut m, &instr).is_err());
    }

    // ---- b+ ----
    #[test]
    fn test_badd() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x01]), bytes_val(&[0x02])]);
        let instr = dummy_instr(0xa0, Immediates::None);
        op_badd(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0x03]);
    }

    #[test]
    fn test_badd_carry() {
        let mut m = machine_with_stack(vec![bytes_val(&[0xFF]), bytes_val(&[0x01])]);
        let instr = dummy_instr(0xa0, Immediates::None);
        op_badd(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0x01, 0x00]);
    }

    // ---- b- ----
    #[test]
    fn test_bsub() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x05]), bytes_val(&[0x03])]);
        let instr = dummy_instr(0xa1, Immediates::None);
        op_bsub(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0x02]);
    }

    #[test]
    fn test_bsub_underflow() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x01]), bytes_val(&[0x02])]);
        let instr = dummy_instr(0xa1, Immediates::None);
        assert!(op_bsub(&mut m, &instr).is_err());
    }

    #[test]
    fn test_bsub_zero() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x05]), bytes_val(&[0x05])]);
        let instr = dummy_instr(0xa1, Immediates::None);
        op_bsub(&mut m, &instr).unwrap();
        // BigUint zero → [0]
        assert_eq!(m.pop_bytes().unwrap(), vec![0x00]);
    }

    // ---- b/ ----
    #[test]
    fn test_bdiv() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x0a]), bytes_val(&[0x03])]);
        let instr = dummy_instr(0xa2, Immediates::None);
        op_bdiv(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0x03]);
    }

    #[test]
    fn test_bdiv_by_zero() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x01]), bytes_val(&[0x00])]);
        let instr = dummy_instr(0xa2, Immediates::None);
        assert!(op_bdiv(&mut m, &instr).is_err());
    }

    // ---- b* ----
    #[test]
    fn test_bmul() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x03]), bytes_val(&[0x04])]);
        let instr = dummy_instr(0xa3, Immediates::None);
        op_bmul(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0x0c]);
    }

    // ---- b% ----
    #[test]
    fn test_bmod() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x0a]), bytes_val(&[0x03])]);
        let instr = dummy_instr(0xaa, Immediates::None);
        op_bmod(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0x01]);
    }

    #[test]
    fn test_bmod_by_zero() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x01]), bytes_val(&[0x00])]);
        let instr = dummy_instr(0xaa, Immediates::None);
        assert!(op_bmod(&mut m, &instr).is_err());
    }

    // ---- comparisons ----
    #[test]
    fn test_blt() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x01]), bytes_val(&[0x02])]);
        let instr = dummy_instr(0xa4, Immediates::None);
        op_blt(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);

        let mut m = machine_with_stack(vec![bytes_val(&[0x02]), bytes_val(&[0x01])]);
        op_blt(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 0);
    }

    #[test]
    fn test_bgt() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x03]), bytes_val(&[0x01])]);
        let instr = dummy_instr(0xa5, Immediates::None);
        op_bgt(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_ble() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x03]), bytes_val(&[0x03])]);
        let instr = dummy_instr(0xa6, Immediates::None);
        op_ble(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);

        let mut m = machine_with_stack(vec![bytes_val(&[0x02]), bytes_val(&[0x03])]);
        op_ble(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_bge() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x03]), bytes_val(&[0x03])]);
        let instr = dummy_instr(0xa7, Immediates::None);
        op_bge(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_beq() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x00, 0x01]), bytes_val(&[0x01])]);
        let instr = dummy_instr(0xa8, Immediates::None);
        op_beq(&mut m, &instr).unwrap();
        // Leading zeros don't matter for BigUint comparison
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    #[test]
    fn test_bne() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x01]), bytes_val(&[0x02])]);
        let instr = dummy_instr(0xa9, Immediates::None);
        op_bne(&mut m, &instr).unwrap();
        assert_eq!(m.pop_uint().unwrap(), 1);
    }

    // ---- bitwise ----
    #[test]
    fn test_bbitwise_or() {
        let mut m = machine_with_stack(vec![bytes_val(&[0xF0]), bytes_val(&[0x0F])]);
        let instr = dummy_instr(0xab, Immediates::None);
        op_bbitwise_or(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0xFF]);
    }

    #[test]
    fn test_bbitwise_or_different_lengths() {
        // a = [0x01, 0xFF], b = [0x0F] → pad b to [0x00, 0x0F]
        let mut m = machine_with_stack(vec![bytes_val(&[0x01, 0xFF]), bytes_val(&[0x0F])]);
        let instr = dummy_instr(0xab, Immediates::None);
        op_bbitwise_or(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0x01, 0xFF]);
    }

    #[test]
    fn test_bbitwise_and() {
        let mut m = machine_with_stack(vec![bytes_val(&[0xFF]), bytes_val(&[0x0F])]);
        let instr = dummy_instr(0xac, Immediates::None);
        op_bbitwise_and(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0x0F]);
    }

    #[test]
    fn test_bbitwise_xor() {
        let mut m = machine_with_stack(vec![bytes_val(&[0xFF]), bytes_val(&[0x0F])]);
        let instr = dummy_instr(0xad, Immediates::None);
        op_bbitwise_xor(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0xF0]);
    }

    #[test]
    fn test_bbitwise_not() {
        let mut m = machine_with_stack(vec![bytes_val(&[0xF0, 0x0F])]);
        let instr = dummy_instr(0xae, Immediates::None);
        op_bbitwise_not(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0x0F, 0xF0]);
    }

    // ---- bsqrt ----
    #[test]
    fn test_bsqrt_perfect() {
        // sqrt(9) = 3
        let mut m = machine_with_stack(vec![bytes_val(&[0x09])]);
        let instr = dummy_instr(0x96, Immediates::None);
        op_bsqrt(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0x03]);
    }

    #[test]
    fn test_bsqrt_non_perfect() {
        // sqrt(10) = 3 (integer part)
        let mut m = machine_with_stack(vec![bytes_val(&[0x0a])]);
        let instr = dummy_instr(0x96, Immediates::None);
        op_bsqrt(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0x03]);
    }

    #[test]
    fn test_bsqrt_zero() {
        let mut m = machine_with_stack(vec![bytes_val(&[0x00])]);
        let instr = dummy_instr(0x96, Immediates::None);
        op_bsqrt(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0x00]);
    }

    #[test]
    fn test_bsqrt_large() {
        // sqrt(256) = 16 = 0x10
        let mut m = machine_with_stack(vec![bytes_val(&[0x01, 0x00])]);
        let instr = dummy_instr(0x96, Immediates::None);
        op_bsqrt(&mut m, &instr).unwrap();
        assert_eq!(m.pop_bytes().unwrap(), vec![0x10]);
    }
}
