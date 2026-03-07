//! `global` opcode (0x32) — read global fields from the execution context.

use algo_error::AlgoError;

use crate::bytecode::Instruction;
use crate::context::AvmContext;
use crate::fields::GlobalField;
use crate::machine::AvmMachine;

use super::helpers::{get_uint8, teal_to_avm};

/// `global F` — push the value of global field `F` onto the stack.
///
/// The immediate byte selects the field (see [`GlobalField`]).
pub fn op_global(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let field_byte = get_uint8(instruction)?;

    // Validate the field index is known.
    let _field = GlobalField::from_u8(field_byte)?;

    // Delegate to the context for the actual value.
    let value = ctx.global_field(field_byte)?;
    machine.push(teal_to_avm(value))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::parse;
    use crate::context::{AvmContext, NullContext};
    use crate::machine::{AvmValue, ExecMode};
    use crate::ops::helpers::prog;
    use algo_error::AlgoError;
    use algo_types::TealValue;

    // -- Test context that returns specific global field values ---------------

    /// A test context that only overrides `global_field`; all other methods
    /// use the default "context unavailable" implementations.
    struct TestGlobalContext;

    impl AvmContext for TestGlobalContext {
        fn global_field(&self, field: u8) -> Result<TealValue, AlgoError> {
            match GlobalField::from_u8(field)? {
                GlobalField::MinTxnFee => Ok(TealValue::Uint(1000)),
                GlobalField::MinBalance => Ok(TealValue::Uint(100_000)),
                GlobalField::MaxTxnLife => Ok(TealValue::Uint(1000)),
                GlobalField::ZeroAddress => Ok(TealValue::Bytes(vec![0u8; 32])),
                GlobalField::GroupSize => Ok(TealValue::Uint(1)),
                GlobalField::LogicSigVersion => Ok(TealValue::Uint(10)),
                GlobalField::Round => Ok(TealValue::Uint(42)),
                GlobalField::LatestTimestamp => Ok(TealValue::Uint(1_700_000_000)),
                GlobalField::CurrentApplicationID => Ok(TealValue::Uint(123)),
                GlobalField::GenesisHash => Ok(TealValue::Bytes(vec![0xAB; 32])),
                _ => NullContext.global_field(field),
            }
        }
    }

    #[test]
    fn global_min_txn_fee() {
        // Program: global MinTxnFee (field 0), return
        // Bytecode: 0x32 0x00 0x43
        let raw = prog(2, &[0x32, 0x00, 0x43]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        let result = m.run(&mut TestGlobalContext);
        assert!(result.is_ok(), "run failed: {:?}", result.err());
        // MinTxnFee = 1000 which is truthy, so pass = true
        assert!(m.pass);
        // Stack should have been consumed by `return`, but check the machine finished.
        assert!(m.finished);
    }

    #[test]
    fn global_round_value() {
        // Program: global Round (field 6), return
        let raw = prog(2, &[0x32, 0x06, 0x43]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        // Step through manually to inspect the stack.
        m.step(&mut TestGlobalContext).unwrap(); // global Round
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(42));
    }

    #[test]
    fn global_zero_address_returns_bytes() {
        // Program: global ZeroAddress (field 3), pop, pushint 1, return
        // We pop the bytes (can't use return with bytes on AVM v1-style),
        // then push 1 for a truthy exit.
        let raw = prog(3, &[0x32, 0x03, 0x48, 0x81, 0x01, 0x43]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        // Execute the global opcode
        m.step(&mut TestGlobalContext).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(vec![0u8; 32]));
    }

    #[test]
    fn global_invalid_field_index() {
        // Field 99 is invalid — should error
        let raw = prog(2, &[0x32, 0x63]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        let result = m.step(&mut TestGlobalContext);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("GlobalField"),
            "error should mention GlobalField: {msg}"
        );
    }

    #[test]
    fn global_genesis_hash() {
        // Program: global GenesisHash (field 17)
        let raw = prog(2, &[0x32, 0x11]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        m.step(&mut TestGlobalContext).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(vec![0xAB; 32]));
    }

    #[test]
    fn global_with_null_context_errors() {
        // NullContext should return an error for global_field
        let raw = prog(2, &[0x32, 0x00]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        let result = m.step(&mut NullContext);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("context unavailable"),
            "expected context unavailable error: {msg}"
        );
    }

    #[test]
    fn global_multiple_fields_on_stack() {
        // Program: global MinTxnFee, global GroupSize, +, return
        // MinTxnFee=1000, GroupSize=1 => 1001 on stack => truthy => pass
        let raw = prog(2, &[0x32, 0x00, 0x32, 0x04, 0x08, 0x43]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        let result = m.run(&mut TestGlobalContext).unwrap();
        assert!(result);
    }
}
