//! Stack manipulation opcodes: pop, dup, dup2, dig, swap, select, cover, uncover, bury, popn, dupn.

use algo_error::AlgoError;

use crate::bytecode::{Immediates, Instruction};
use crate::machine::AvmMachine;

/// `pop` (0x48): pop and discard top of stack.
pub fn op_pop(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    machine.pop()?;
    Ok(())
}

/// `dup` (0x49): duplicate top of stack.
pub fn op_dup(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let val = machine.pop()?;
    machine.push(val.clone())?;
    machine.push(val)?;
    Ok(())
}

/// `dup2` (0x4a): duplicate top two values (a, b -> a, b, a, b).
pub fn op_dup2(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let b = machine.pop()?;
    let a = machine.pop()?;
    machine.push(a.clone())?;
    machine.push(b.clone())?;
    machine.push(a)?;
    machine.push(b)?;
    Ok(())
}

/// `dig n` (0x4b): copy the value n positions from top onto top. dig 0 = dup.
pub fn op_dig(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let n = get_uint8(instruction)? as usize;
    let len = machine.stack.len();
    if n >= len {
        return Err(AlgoError::Avm {
            message: format!("dig {n}: stack underflow (stack depth {len})"),
        });
    }
    let val = machine.stack[len - 1 - n].clone();
    machine.push(val)?;
    Ok(())
}

/// `swap` (0x4c): swap top two values.
pub fn op_swap(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let len = machine.stack.len();
    if len < 2 {
        return Err(AlgoError::Avm {
            message: format!("swap: stack underflow (stack depth {len})"),
        });
    }
    machine.stack.swap(len - 1, len - 2);
    Ok(())
}

/// `select` (0x4d): pop c (uint64), pop b, pop a. If c != 0 push b; else push a.
pub fn op_select(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let c = machine.pop_uint()?;
    let b = machine.pop()?;
    let a = machine.pop()?;
    if c != 0 {
        machine.push(b)?;
    } else {
        machine.push(a)?;
    }
    Ok(())
}

/// `cover n` (0x4e): remove top of stack and insert it n positions down.
pub fn op_cover(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let n = get_uint8(instruction)? as usize;
    let len = machine.stack.len();
    if n >= len {
        return Err(AlgoError::Avm {
            message: format!("cover {n}: stack underflow (stack depth {len})"),
        });
    }
    // Remove top and insert at position len-1-n.
    let val = machine.stack.pop().unwrap();
    let insert_pos = len - 1 - n;
    machine.stack.insert(insert_pos, val);
    Ok(())
}

/// `uncover n` (0x4f): remove value n positions from top and put it on top.
pub fn op_uncover(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let n = get_uint8(instruction)? as usize;
    let len = machine.stack.len();
    if n >= len {
        return Err(AlgoError::Avm {
            message: format!("uncover {n}: stack underflow (stack depth {len})"),
        });
    }
    // Remove element at position len-1-n and push it on top.
    let remove_pos = len - 1 - n;
    let val = machine.stack.remove(remove_pos);
    machine.stack.push(val);
    Ok(())
}

/// `bury n` (0x45): pop top and write it n positions from the top of the remaining stack.
pub fn op_bury(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let n = get_uint8(instruction)? as usize;
    let val = machine.pop()?;
    let len = machine.stack.len();
    if n == 0 || n > len {
        return Err(AlgoError::Avm {
            message: format!("bury {n}: invalid depth (remaining stack depth {len})"),
        });
    }
    machine.stack[len - n] = val;
    Ok(())
}

/// `popn n` (0x46): pop n values from stack.
pub fn op_popn(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let n = get_uint8(instruction)? as usize;
    let len = machine.stack.len();
    if n > len {
        return Err(AlgoError::Avm {
            message: format!("popn {n}: stack underflow (stack depth {len})"),
        });
    }
    machine.stack.truncate(len - n);
    Ok(())
}

/// `dupn n` (0x47): duplicate top of stack n additional times (total n+1 copies of top).
pub fn op_dupn(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let n = get_uint8(instruction)? as usize;
    if machine.stack.is_empty() {
        return Err(AlgoError::Avm {
            message: "dupn: stack underflow".to_string(),
        });
    }
    let val = machine.stack.last().unwrap().clone();
    for _ in 0..n {
        machine.push(val.clone())?;
    }
    Ok(())
}

/// `store i` (0x35): pop value from stack, write to scratch[i].
pub fn op_store(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let i = get_uint8(instruction)? as usize;
    let val = machine.pop()?;
    machine.scratch[i] = val;
    Ok(())
}

/// `load i` (0x34): read scratch[i], push clone onto stack.
pub fn op_load(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let i = get_uint8(instruction)? as usize;
    let val = machine.scratch[i].clone();
    machine.push(val)
}

/// `stores` (0x3f): pop value, pop index (uint64), write value to scratch[index].
pub fn op_stores(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let val = machine.pop()?;
    let idx = machine.pop_uint()? as usize;
    if idx >= machine.scratch.len() {
        return Err(AlgoError::Avm {
            message: format!(
                "stores: index {idx} out of range (scratch has {} slots)",
                machine.scratch.len()
            ),
        });
    }
    machine.scratch[idx] = val;
    Ok(())
}

/// `loads` (0x3e): pop index (uint64), push clone of scratch[index].
pub fn op_loads(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let idx = machine.pop_uint()? as usize;
    if idx >= machine.scratch.len() {
        return Err(AlgoError::Avm {
            message: format!(
                "loads: index {idx} out of range (scratch has {} slots)",
                machine.scratch.len()
            ),
        });
    }
    let val = machine.scratch[idx].clone();
    machine.push(val)
}

/// Helper: extract Uint8 immediate from instruction.
fn get_uint8(instruction: &Instruction) -> Result<u8, AlgoError> {
    if let Immediates::Uint8(n) = instruction.immediates {
        Ok(n)
    } else {
        Err(AlgoError::Avm {
            message: format!("expected Uint8 immediate, got {:?}", instruction.immediates),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::bytecode;
    use crate::machine::{AvmMachine, AvmValue, ExecMode};

    /// Build raw program bytes from version + code.
    fn prog(version: u8, code: &[u8]) -> Vec<u8> {
        let mut p = vec![version];
        p.extend_from_slice(code);
        p
    }

    /// Parse and run a program, returning the machine for stack inspection.
    fn run_prog(version: u8, code: &[u8]) -> Result<AvmMachine, algo_error::AlgoError> {
        let raw = prog(version, code);
        let program = bytecode::parse(&raw)?;
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 20000);
        m.run()?;
        Ok(m)
    }

    /// Parse, run, and return the machine (ignoring pass/fail from run).
    fn run_prog_machine(version: u8, code: &[u8]) -> AvmMachine {
        let raw = prog(version, code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 20000);
        let _ = m.run();
        m
    }

    // ---- pop ----
    #[test]
    fn test_pop() {
        // pushint 42, pushint 1, pop -> stack: [42], implicit end -> pass(42 truthy)
        let m = run_prog(3, &[0x81, 0x2a, 0x81, 0x01, 0x48]).unwrap();
        assert!(m.pass);
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(42));
    }

    #[test]
    fn test_pop_underflow() {
        // pop on empty stack
        let raw = prog(3, &[0x48]);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 20000);
        assert!(m.run().is_err());
    }

    // ---- dup ----
    #[test]
    fn test_dup() {
        // pushint 5, dup -> stack: [5, 5]
        let m = run_prog_machine(3, &[0x81, 0x05, 0x49]);
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(5));
        assert_eq!(m.stack[1], AvmValue::Uint64(5));
    }

    // ---- dup2 ----
    #[test]
    fn test_dup2() {
        // pushint 1, pushint 2, dup2 -> stack: [1, 2, 1, 2]
        let m = run_prog_machine(3, &[0x81, 0x01, 0x81, 0x02, 0x4a]);
        assert_eq!(m.stack.len(), 4);
        assert_eq!(m.stack[0], AvmValue::Uint64(1));
        assert_eq!(m.stack[1], AvmValue::Uint64(2));
        assert_eq!(m.stack[2], AvmValue::Uint64(1));
        assert_eq!(m.stack[3], AvmValue::Uint64(2));
    }

    // ---- dig ----
    #[test]
    fn test_dig_0() {
        // pushint 7, dig 0 -> stack: [7, 7]
        let m = run_prog_machine(3, &[0x81, 0x07, 0x4b, 0x00]);
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(7));
        assert_eq!(m.stack[1], AvmValue::Uint64(7));
    }

    #[test]
    fn test_dig_2() {
        // pushint 10, pushint 20, pushint 30, dig 2 -> stack: [10, 20, 30, 10]
        let m = run_prog_machine(3, &[0x81, 0x0a, 0x81, 0x14, 0x81, 0x1e, 0x4b, 0x02]);
        assert_eq!(m.stack.len(), 4);
        assert_eq!(m.stack[3], AvmValue::Uint64(10));
    }

    #[test]
    fn test_dig_underflow() {
        // pushint 1, dig 1 -> underflow
        let raw = prog(3, &[0x81, 0x01, 0x4b, 0x01]);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 20000);
        assert!(m.run().is_err());
    }

    // ---- swap ----
    #[test]
    fn test_swap() {
        // pushint 1, pushint 2, swap -> stack: [2, 1]
        let m = run_prog_machine(3, &[0x81, 0x01, 0x81, 0x02, 0x4c]);
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(2));
        assert_eq!(m.stack[1], AvmValue::Uint64(1));
    }

    // ---- select ----
    #[test]
    fn test_select_true() {
        // pushint 10, pushint 20, pushint 1, select -> 20 (c=1 != 0, push b=20)
        let m = run_prog_machine(3, &[0x81, 0x0a, 0x81, 0x14, 0x81, 0x01, 0x4d]);
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(20));
    }

    #[test]
    fn test_select_false() {
        // pushint 10, pushint 20, pushint 0, select -> 10 (c=0, push a=10)
        let m = run_prog_machine(3, &[0x81, 0x0a, 0x81, 0x14, 0x81, 0x00, 0x4d]);
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(10));
    }

    // ---- cover ----
    #[test]
    fn test_cover_2() {
        // pushint 1, pushint 2, pushint 3, cover 2 -> stack: [3, 1, 2]
        let m = run_prog_machine(5, &[0x81, 0x01, 0x81, 0x02, 0x81, 0x03, 0x4e, 0x02]);
        assert_eq!(m.stack.len(), 3);
        assert_eq!(m.stack[0], AvmValue::Uint64(3));
        assert_eq!(m.stack[1], AvmValue::Uint64(1));
        assert_eq!(m.stack[2], AvmValue::Uint64(2));
    }

    // ---- uncover ----
    #[test]
    fn test_uncover_2() {
        // pushint 1, pushint 2, pushint 3, uncover 2 -> stack: [2, 3, 1]
        let m = run_prog_machine(5, &[0x81, 0x01, 0x81, 0x02, 0x81, 0x03, 0x4f, 0x02]);
        assert_eq!(m.stack.len(), 3);
        assert_eq!(m.stack[0], AvmValue::Uint64(2));
        assert_eq!(m.stack[1], AvmValue::Uint64(3));
        assert_eq!(m.stack[2], AvmValue::Uint64(1));
    }

    // ---- bury ----
    #[test]
    fn test_bury() {
        // pushint 1, pushint 2, pushint 3, pushint 99, bury 2 -> stack: [1, 99, 3]
        // bury 2: pop 99, remaining [1, 2, 3], write at [len-2] = [1] -> [1, 99, 3]
        let m = run_prog_machine(
            8,
            &[
                0x81, 0x01, 0x81, 0x02, 0x81, 0x03, 0x81, 0xe3, 0x00, 0x45, 0x02,
            ],
        );
        assert_eq!(m.stack.len(), 3);
        assert_eq!(m.stack[0], AvmValue::Uint64(1));
        assert_eq!(m.stack[1], AvmValue::Uint64(99));
        assert_eq!(m.stack[2], AvmValue::Uint64(3));
    }

    // ---- popn ----
    #[test]
    fn test_popn() {
        // pushint 1, pushint 2, pushint 3, popn 2 -> stack: [1]
        let m = run_prog_machine(8, &[0x81, 0x01, 0x81, 0x02, 0x81, 0x03, 0x46, 0x02]);
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(1));
    }

    // ---- dupn ----
    #[test]
    fn test_dupn() {
        // pushint 42, dupn 3 -> stack: [42, 42, 42, 42]
        let m = run_prog_machine(8, &[0x81, 0x2a, 0x47, 0x03]);
        assert_eq!(m.stack.len(), 4);
        for v in &m.stack {
            assert_eq!(*v, AvmValue::Uint64(42));
        }
    }

    #[test]
    fn test_dupn_zero() {
        // pushint 42, dupn 0 -> stack: [42] (no additional copies)
        let m = run_prog_machine(8, &[0x81, 0x2a, 0x47, 0x00]);
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(42));
    }

    // ---- select with bytes ----
    #[test]
    fn test_select_with_bytes() {
        // pushbytes "hello", pushbytes "world", pushint 0, select -> "hello"
        let m = run_prog_machine(
            3,
            &[
                0x80, 0x05, b'h', b'e', b'l', b'l', b'o', // pushbytes "hello"
                0x80, 0x05, b'w', b'o', b'r', b'l', b'd', // pushbytes "world"
                0x81, 0x00, // pushint 0
                0x4d, // select
            ],
        );
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"hello".to_vec()));
    }
}
