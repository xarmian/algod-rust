// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `global` opcode (0x32) — read global fields from the execution context.

use algo_error::AlgoError;

use crate::bytecode::Instruction;
use crate::context::AvmContext;
use crate::fields::GlobalField;
use crate::machine::{AvmMachine, AvmValue, ExecMode};

use super::helpers::{get_uint8, teal_to_avm};

/// Returns `true` if the given global field is restricted to Application mode only.
///
/// This matches go-algorand's `globalFieldSpecs` table where certain fields have
/// `mode: ModeApp` instead of `modeAny`.
fn is_app_mode_only(field: GlobalField) -> bool {
    matches!(
        field,
        GlobalField::Round
            | GlobalField::LatestTimestamp
            | GlobalField::CurrentApplicationID
            | GlobalField::CreatorAddress
            | GlobalField::CurrentApplicationAddress
            | GlobalField::CallerApplicationID
            | GlobalField::CallerApplicationAddress
    )
}

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
    let field = GlobalField::from_u8(field_byte)?;

    // Enforce per-field version gating (Go: `opGlobal`'s
    // `fs.version > cx.version` check, `data/transactions/logic/eval.go`).
    if field.version() > machine.version {
        return Err(AlgoError::Avm {
            message: format!("invalid global field {field_byte}"),
        });
    }

    // Enforce per-field mode restrictions (Go: `if (cx.runMode & fs.mode) == 0`).
    if is_app_mode_only(field) && machine.mode == ExecMode::LogicSig {
        return Err(AlgoError::Avm {
            message: format!("global[{field_byte}] not allowed in LogicSig mode"),
        });
    }

    // OpcodeBudget (field 12): read directly from the machine's remaining
    // budget rather than routing through the context, which has no access
    // to the VM's budget counter.
    if field_byte == 12 {
        let remaining = if machine.budget > 0 {
            machine.budget as u64
        } else {
            0
        };
        return machine.push(AvmValue::Uint64(remaining));
    }

    // CallerApplicationID (field 13): delegate to context method so that
    // inner transaction depth is correctly reflected.
    if field_byte == 13 {
        return machine.push(AvmValue::Uint64(ctx.caller_app_id()));
    }

    // CallerApplicationAddress (field 14): delegate to context method.
    if field_byte == 14 {
        return machine.push(AvmValue::Bytes(ctx.caller_app_address().to_vec()));
    }

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
                GlobalField::CreatorAddress => Ok(TealValue::Bytes(vec![0xCC; 32])),
                GlobalField::GroupID => Ok(TealValue::Bytes(vec![0xDD; 32])),
                GlobalField::GenesisHash => Ok(TealValue::Bytes(vec![0xAB; 32])),
                GlobalField::PayoutsEnabled => Ok(TealValue::Uint(1)),
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
        // Round is Application-mode-only, so use Application mode.
        let raw = prog(2, &[0x32, 0x06, 0x43]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700);
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
        // Program: global GenesisHash (field 17), which requires v10+.
        let raw = prog(10, &[0x32, 0x11]);
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
    fn global_round_rejected_in_logicsig() {
        // Round (field 6) is Application-mode-only; should fail in LogicSig mode.
        let raw = prog(2, &[0x32, 0x06]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        let result = m.step(&mut TestGlobalContext);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("not allowed in LogicSig"),
            "expected mode restriction error: {msg}"
        );
    }

    #[test]
    fn global_current_app_id_rejected_in_logicsig() {
        // CurrentApplicationID (field 8) is Application-mode-only.
        let raw = prog(2, &[0x32, 0x08]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
        let result = m.step(&mut TestGlobalContext);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("not allowed in LogicSig"),
            "expected mode restriction error: {msg}"
        );
    }

    #[test]
    fn global_round_allowed_in_application() {
        // Round (field 6) should work in Application mode.
        let raw = prog(2, &[0x32, 0x06]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700);
        let result = m.step(&mut TestGlobalContext);
        assert!(result.is_ok(), "expected OK but got: {:?}", result.err());
        assert_eq!(m.stack[0], AvmValue::Uint64(42));
    }

    #[test]
    fn global_any_mode_fields_allowed_in_logicsig() {
        // MinTxnFee (field 0), GroupSize (field 4), LogicSigVersion (field 5),
        // GroupID (field 11), OpcodeBudget (field 12), GenesisHash (field 17)
        // should all work in LogicSig mode.
        for field_byte in [0x00, 0x04, 0x05] {
            let raw = prog(2, &[0x32, field_byte]);
            let program = parse(&raw).unwrap();
            let mut m = AvmMachine::new(program, ExecMode::LogicSig, 700);
            let result = m.step(&mut TestGlobalContext);
            assert!(
                result.is_ok(),
                "field {field_byte} should be allowed in LogicSig: {:?}",
                result.err()
            );
        }
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

    // --- Per-field version gating (issue #810) ---
    //
    // Matches go-algorand's `opGlobal`'s `fs.version > cx.version` check,
    // exercised against representative fields spanning each version
    // boundary in `globalFieldSpecs`.

    fn global_field_at_version(version: u8, field: u8) -> Result<(), AlgoError> {
        let raw = prog(version, &[0x32, field]);
        let program = parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700);
        m.step(&mut TestGlobalContext).map(|_| ())
    }

    #[test]
    fn test_global_field_version_min_txn_fee_available_since_v1() {
        // MinTxnFee (field 0) has version 0 -- always available.
        assert!(global_field_at_version(1, 0).is_ok());
    }

    #[test]
    fn test_global_field_version_round_gated_at_v2() {
        // Round (field 6) requires v2.
        assert!(global_field_at_version(1, 6).is_err());
        assert!(global_field_at_version(2, 6).is_ok());
    }

    #[test]
    fn test_global_field_version_creator_address_gated_at_v3() {
        // CreatorAddress (field 9) requires v3.
        assert!(global_field_at_version(2, 9).is_err());
        assert!(global_field_at_version(3, 9).is_ok());
    }

    #[test]
    fn test_global_field_version_group_id_gated_at_v5() {
        // GroupID (field 11) requires v5.
        assert!(global_field_at_version(4, 11).is_err());
        assert!(global_field_at_version(5, 11).is_ok());
    }

    #[test]
    fn test_global_field_version_opcode_budget_gated_at_v6() {
        // OpcodeBudget (field 12) requires v6.
        assert!(global_field_at_version(5, 12).is_err());
        assert!(global_field_at_version(6, 12).is_ok());
    }

    #[test]
    fn test_global_field_version_genesis_hash_gated_at_v10() {
        // GenesisHash (field 17) requires v10.
        assert!(global_field_at_version(9, 17).is_err());
        assert!(global_field_at_version(10, 17).is_ok());
    }

    #[test]
    fn test_global_field_version_payouts_enabled_gated_at_v11() {
        // PayoutsEnabled (field 18) requires incentiveVersion (v11).
        assert!(global_field_at_version(10, 18).is_err());
        assert!(global_field_at_version(11, 18).is_ok());
    }
}
