//! Inner transaction opcodes: construction (`itxn_begin`, `itxn_field`,
//! `itxn_submit`, `itxn_next`) and field access (`itxn`, `itxna`, `gitxn`,
//! `gitxna`, `itxnas`, `gitxnas`).

use algo_error::AlgoError;

use crate::bytecode::Instruction;
use crate::context::AvmContext;
use crate::machine::AvmMachine;

use super::helpers::{avm_to_teal, get_uint8, get_uint8_pair, get_uint8_triple, teal_to_avm};

// ---------------------------------------------------------------------------
// Construction opcodes
// ---------------------------------------------------------------------------

/// `itxn_begin` (0xb1): start building a new inner transaction.
/// No stack args, no immediates.
pub fn op_itxn_begin(
    _machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    ctx.itxn_begin()
}

/// `itxn_field f` (0xb2): set a field on the inner transaction being built.
/// 1 immediate: field byte. Pops one value from the stack.
pub fn op_itxn_field(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let field_byte = get_uint8(instruction)?;
    let value = machine.pop()?;
    ctx.itxn_field(field_byte, avm_to_teal(value))
}

/// `itxn_submit` (0xb3): execute the inner transaction(s) that were built.
/// No stack args, no immediates.
pub fn op_itxn_submit(
    _machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    ctx.itxn_submit()
}

/// `itxn_next` (0xb6): chain another inner transaction in the current group.
/// No stack args, no immediates. AVM v6+.
pub fn op_itxn_next(
    _machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    ctx.itxn_next()
}

// ---------------------------------------------------------------------------
// Field access opcodes (reading results of last executed inner txn)
// ---------------------------------------------------------------------------

/// `itxn f` (0xb4): read a field from the last submitted inner transaction.
/// 1 immediate: field byte. Pushes one value.
pub fn op_itxn(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let field_byte = get_uint8(instruction)?;
    let val = ctx.last_itxn_field(field_byte, None)?;
    machine.push(teal_to_avm(val))
}

/// `itxna f i` (0xb5): read an array field from the last submitted inner transaction.
/// 2 immediates: field byte, array_index. Pushes one value.
pub fn op_itxna(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let (field_byte, array_index) = get_uint8_pair(instruction)?;
    let val = ctx.last_itxn_field(field_byte, Some(array_index as usize))?;
    machine.push(teal_to_avm(val))
}

/// `gitxn t f` (0xb7): read a field from a specific inner transaction in the
/// last submitted inner group.
/// 2 immediates: group_index, field byte. Pushes one value. AVM v6+.
pub fn op_gitxn(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let (group_index, field_byte) = get_uint8_pair(instruction)?;
    let val = ctx.last_itxn_group_field(group_index as usize, field_byte, None)?;
    machine.push(teal_to_avm(val))
}

/// `gitxna t f i` (0xb8): read an array field from a specific inner transaction
/// in the last submitted inner group.
/// 3 immediates: group_index, field byte, array_index. Pushes one value. AVM v6+.
pub fn op_gitxna(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let (group_index, field_byte, array_index) = get_uint8_triple(instruction)?;
    let val =
        ctx.last_itxn_group_field(group_index as usize, field_byte, Some(array_index as usize))?;
    machine.push(teal_to_avm(val))
}

/// `itxnas f` (0xc5): read an array field from the last submitted inner transaction,
/// with the array index popped from the stack.
/// 1 immediate: field byte. Pops array_index, pushes one value. AVM v6+.
pub fn op_itxnas(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let field_byte = get_uint8(instruction)?;
    let array_index = machine.pop_uint()? as usize;
    let val = ctx.last_itxn_field(field_byte, Some(array_index))?;
    machine.push(teal_to_avm(val))
}

/// `gitxnas t f` (0xc6): read an array field from a specific inner transaction
/// in the last submitted inner group, with the array index popped from the stack.
/// 2 immediates: group_index, field byte. Pops array_index, pushes one value. AVM v6+.
pub fn op_gitxnas(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let (group_index, field_byte) = get_uint8_pair(instruction)?;
    let array_index = machine.pop_uint()? as usize;
    let val = ctx.last_itxn_group_field(group_index as usize, field_byte, Some(array_index))?;
    machine.push(teal_to_avm(val))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::bytecode;
    use crate::context::AvmContext;
    use crate::machine::{AvmMachine, AvmValue, ExecMode};
    use crate::ops::helpers::prog;
    use algo_error::AlgoError;
    use algo_types::TealValue;
    use std::cell::Cell;

    // -- Mock context for inner transaction testing --

    /// A test context that tracks inner transaction calls and returns canned
    /// values for field reads. Only overrides the methods it needs.
    struct TestItxnContext {
        itxn_begin_called: Cell<bool>,
        itxn_submit_called: Cell<bool>,
        itxn_next_called: Cell<bool>,
        last_itxn_field_byte: Cell<u8>,
    }

    impl TestItxnContext {
        fn new() -> Self {
            Self {
                itxn_begin_called: Cell::new(false),
                itxn_submit_called: Cell::new(false),
                itxn_next_called: Cell::new(false),
                last_itxn_field_byte: Cell::new(0),
            }
        }
    }

    impl AvmContext for TestItxnContext {
        fn itxn_begin(&mut self) -> Result<(), AlgoError> {
            self.itxn_begin_called.set(true);
            Ok(())
        }

        fn itxn_field(&mut self, f: u8, _v: TealValue) -> Result<(), AlgoError> {
            self.last_itxn_field_byte.set(f);
            Ok(())
        }

        fn itxn_submit(&mut self) -> Result<(), AlgoError> {
            self.itxn_submit_called.set(true);
            Ok(())
        }

        fn itxn_next(&mut self) -> Result<(), AlgoError> {
            self.itxn_next_called.set(true);
            Ok(())
        }

        fn last_itxn_field(
            &self,
            field: u8,
            array_index: Option<usize>,
        ) -> Result<TealValue, AlgoError> {
            let ai = array_index.unwrap_or(0) as u64;
            Ok(TealValue::Uint((field as u64) * 256 + ai))
        }

        fn last_itxn_group_field(
            &self,
            group_index: usize,
            field: u8,
            array_index: Option<usize>,
        ) -> Result<TealValue, AlgoError> {
            let ai = array_index.unwrap_or(0) as u64;
            Ok(TealValue::Uint(
                (group_index as u64) * 65536 + (field as u64) * 256 + ai,
            ))
        }

        fn num_inner_txns(&self) -> usize {
            1
        }
        fn is_app_mode(&self) -> bool {
            true
        }
        fn current_app_id(&self) -> u64 {
            42
        }
    }

    // -- Test helpers --

    /// Parse a program and step through it with the given context, returning the machine.
    fn step_with_ctx(
        version: u8,
        code: &[u8],
        ctx: &mut dyn AvmContext,
    ) -> Result<AvmMachine, AlgoError> {
        let raw = prog(version, code);
        let program = bytecode::parse(&raw)?;
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        m.step(ctx)?;
        Ok(m)
    }

    // -- itxn_begin tests --

    #[test]
    fn test_itxn_begin() {
        // itxn_begin (0xb1)
        let mut ctx = TestItxnContext::new();
        let _m = step_with_ctx(5, &[0xb1], &mut ctx).unwrap();
        assert!(ctx.itxn_begin_called.get());
    }

    // -- itxn_field tests --

    #[test]
    fn test_itxn_field_pops_value_and_calls_ctx() {
        // pushint 42, itxn_field TypeEnum (field 15)
        // 0x81 0x2a = pushint 42, 0xb2 0x0f = itxn_field 15
        let mut ctx = TestItxnContext::new();
        let raw = prog(5, &[0x81, 0x2a, 0xb2, 0x0f]);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        m.step(&mut ctx).unwrap(); // pushint 42
        assert_eq!(m.stack.len(), 1);
        m.step(&mut ctx).unwrap(); // itxn_field 15
        assert_eq!(m.stack.len(), 0); // value was popped
        assert_eq!(ctx.last_itxn_field_byte.get(), 15);
    }

    // -- itxn_submit tests --

    #[test]
    fn test_itxn_submit() {
        // itxn_submit (0xb3)
        let mut ctx = TestItxnContext::new();
        let _m = step_with_ctx(5, &[0xb3], &mut ctx).unwrap();
        assert!(ctx.itxn_submit_called.get());
    }

    // -- itxn_next tests --

    #[test]
    fn test_itxn_next() {
        // itxn_next (0xb6)
        let mut ctx = TestItxnContext::new();
        let _m = step_with_ctx(6, &[0xb6], &mut ctx).unwrap();
        assert!(ctx.itxn_next_called.get());
    }

    // -- itxn field read tests --

    #[test]
    fn test_itxn_field_read() {
        // itxn Sender (field 0) -> 0xb4 0x00
        // Expected: last_itxn_field(0, None) => Uint(0*256 + 0) = 0
        let mut ctx = TestItxnContext::new();
        let m = step_with_ctx(5, &[0xb4, 0x00], &mut ctx).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(0)); // field=0, ai=0

        // itxn Amount (field 7) -> 0xb4 0x07
        // Expected: last_itxn_field(7, None) => Uint(7*256 + 0) = 1792
        let mut ctx2 = TestItxnContext::new();
        let m2 = step_with_ctx(5, &[0xb4, 0x07], &mut ctx2).unwrap();
        assert_eq!(m2.stack[0], AvmValue::Uint64(7 * 256));
    }

    // -- itxna array field read tests --

    #[test]
    fn test_itxna_array_field_read() {
        // itxna ApplicationArgs 2 (field 25, array_index 2) -> 0xb5 0x19 0x02
        // Expected: last_itxn_field(25, Some(2)) => Uint(25*256 + 2) = 6402
        let mut ctx = TestItxnContext::new();
        let m = step_with_ctx(5, &[0xb5, 0x19, 0x02], &mut ctx).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(25 * 256 + 2));
    }

    // -- gitxn group inner txn field tests --

    #[test]
    fn test_gitxn_group_field() {
        // gitxn 1 7 (group_index 1, field 7 Amount) -> 0xb7 0x01 0x07
        // Expected: last_itxn_group_field(1, 7, None) => Uint(1*65536 + 7*256 + 0) = 67328
        let mut ctx = TestItxnContext::new();
        let m = step_with_ctx(6, &[0xb7, 0x01, 0x07], &mut ctx).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(65536 + 7 * 256));
    }

    // -- gitxna tests --

    #[test]
    fn test_gitxna() {
        // gitxna 0 25 3 (group 0, field 25, array_index 3) -> 0xb8 0x00 0x19 0x03
        // Expected: last_itxn_group_field(0, 25, Some(3)) => Uint(0*65536 + 25*256 + 3) = 6403
        let mut ctx = TestItxnContext::new();
        let m = step_with_ctx(6, &[0xb8, 0x00, 0x19, 0x03], &mut ctx).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(25 * 256 + 3));
    }

    // -- itxnas stack-based array index tests --

    #[test]
    fn test_itxnas_stack_array_index() {
        // pushint 4, itxnas ApplicationArgs (field 25) -> 0x81 0x04, 0xc5 0x19
        // Pops array_index=4, calls last_itxn_field(25, Some(4))
        // Expected: Uint(25*256 + 4) = 6404
        let mut ctx = TestItxnContext::new();
        let raw = prog(6, &[0x81, 0x04, 0xc5, 0x19]);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        m.step(&mut ctx).unwrap(); // pushint 4
        m.step(&mut ctx).unwrap(); // itxnas 25
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(25 * 256 + 4));
    }

    // -- gitxnas stack-based array index tests --

    #[test]
    fn test_gitxnas_stack_array_index() {
        // pushint 2, gitxnas 1 25 (group 1, field 25, pop array_index=2) -> 0x81 0x02, 0xc6 0x01 0x19
        // Expected: last_itxn_group_field(1, 25, Some(2)) => Uint(1*65536 + 25*256 + 2) = 72194
        let mut ctx = TestItxnContext::new();
        let raw = prog(6, &[0x81, 0x02, 0xc6, 0x01, 0x19]);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        m.step(&mut ctx).unwrap(); // pushint 2
        m.step(&mut ctx).unwrap(); // gitxnas 1 25
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(65536 + 25 * 256 + 2));
    }
}
