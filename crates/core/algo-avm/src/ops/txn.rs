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

//! Transaction field access opcodes: txn, gtxn, txna, gtxna, gtxns, gtxnsa,
//! txnas, gtxnas, gtxnsas, and LogicSig argument opcodes: arg, arg_0..arg_3, args.

use algo_error::AlgoError;

use crate::bytecode::Instruction;
use crate::context::AvmContext;
use crate::fields::TxnField;
use crate::machine::{AvmMachine, AvmValue};

use super::helpers::{get_uint8, get_uint8_pair, get_uint8_triple, teal_to_avm};

// ---------------------------------------------------------------------------
// Transaction field opcodes
// ---------------------------------------------------------------------------

/// Enforce per-field version gating and array-ness validation shared by
/// every `txn`/`gtxn`/`txna`/etc. opcode. Matches go-algorand's shared
/// `(*EvalContext).fetchField` (`data/transactions/logic/eval.go`):
/// `fs.version > cx.version`, then `expectArray != fs.array` (erroring
/// `"unsupported array field %s"` when an array form is used on a
/// non-array field, or `"invalid txn field %s"` when a scalar form is used
/// on an array-only field).
fn check_txn_field_access(
    field_byte: u8,
    machine_version: u8,
    expect_array: bool,
) -> Result<(), AlgoError> {
    let field = match TxnField::from_u8(field_byte) {
        Ok(field) if field.version() <= machine_version => field,
        Ok(field) => {
            return Err(AlgoError::Avm {
                message: format!("invalid txn field {field}"),
            });
        }
        Err(_) => {
            return Err(AlgoError::Avm {
                message: format!(
                    "invalid txn field {}",
                    TxnField::unknown_display(field_byte)
                ),
            });
        }
    };
    if field.is_array() != expect_array {
        let message = if expect_array {
            format!("unsupported array field {field}")
        } else {
            format!("invalid txn field {field}")
        };
        return Err(AlgoError::Avm { message });
    }
    Ok(())
}

/// `txn f` (0x31): push Txn.Fields[f] for the current transaction.
/// 1 immediate: field byte.
pub fn op_txn(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let field = get_uint8(instruction)?;
    check_txn_field_access(field, machine.version, false)?;
    let group_index = ctx.group_index();
    let val = ctx.txn_field(group_index, field, None)?;
    machine.push(teal_to_avm(val))
}

/// `gtxn t f` (0x33): push GroupTxn[t].Fields[f].
/// 2 immediates: group_index, field byte.
pub fn op_gtxn(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let (group_index, field) = get_uint8_pair(instruction)?;
    check_txn_field_access(field, machine.version, false)?;
    let val = ctx.txn_field(group_index as usize, field, None)?;
    machine.push(teal_to_avm(val))
}

/// `txna f i` (0x36): push Txn.Fields[f][i] (array field access).
/// 2 immediates: field byte, array_index.
pub fn op_txna(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let (field, array_index) = get_uint8_pair(instruction)?;
    check_txn_field_access(field, machine.version, true)?;
    let group_index = ctx.group_index();
    let val = ctx.txn_field(group_index, field, Some(array_index as usize))?;
    machine.push(teal_to_avm(val))
}

/// `gtxna t f i` (0x37): push GroupTxn[t].Fields[f][i] (array field access).
/// 3 immediates: group_index, field byte, array_index.
pub fn op_gtxna(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let (group_index, field, array_index) = get_uint8_triple(instruction)?;
    check_txn_field_access(field, machine.version, true)?;
    let val = ctx.txn_field(group_index as usize, field, Some(array_index as usize))?;
    machine.push(teal_to_avm(val))
}

/// `gtxns f` (0x38): pop group_index from stack, push GroupTxn[group_index].Fields[f].
/// 1 immediate: field byte.
pub fn op_gtxns(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let field = get_uint8(instruction)?;
    check_txn_field_access(field, machine.version, false)?;
    let group_index = machine.pop_uint()? as usize;
    let val = ctx.txn_field(group_index, field, None)?;
    machine.push(teal_to_avm(val))
}

/// `gtxnsa f i` (0x39): pop group_index from stack, push GroupTxn[group_index].Fields[f][i].
/// 2 immediates: field byte, array_index.
pub fn op_gtxnsa(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let (field, array_index) = get_uint8_pair(instruction)?;
    check_txn_field_access(field, machine.version, true)?;
    let group_index = machine.pop_uint()? as usize;
    let val = ctx.txn_field(group_index, field, Some(array_index as usize))?;
    machine.push(teal_to_avm(val))
}

/// `txnas f` (0xc0): pop array_index from stack, push Txn.Fields[f][array_index].
/// 1 immediate: field byte.
pub fn op_txnas(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let field = get_uint8(instruction)?;
    check_txn_field_access(field, machine.version, true)?;
    let array_index = machine.pop_uint()? as usize;
    let group_index = ctx.group_index();
    let val = ctx.txn_field(group_index, field, Some(array_index))?;
    machine.push(teal_to_avm(val))
}

/// `gtxnas t f` (0xc1): pop array_index from stack, push GroupTxn[t].Fields[f][array_index].
/// 2 immediates: group_index, field byte.
pub fn op_gtxnas(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let (group_index, field) = get_uint8_pair(instruction)?;
    check_txn_field_access(field, machine.version, true)?;
    let array_index = machine.pop_uint()? as usize;
    let val = ctx.txn_field(group_index as usize, field, Some(array_index))?;
    machine.push(teal_to_avm(val))
}

/// `gtxnsas f` (0xc2): pop array_index then group_index from stack,
/// push GroupTxn[group_index].Fields[f][array_index].
/// 1 immediate: field byte.
pub fn op_gtxnsas(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let field = get_uint8(instruction)?;
    check_txn_field_access(field, machine.version, true)?;
    let array_index = machine.pop_uint()? as usize;
    let group_index = machine.pop_uint()? as usize;
    let val = ctx.txn_field(group_index, field, Some(array_index))?;
    machine.push(teal_to_avm(val))
}

// ---------------------------------------------------------------------------
// LogicSig argument opcodes
// ---------------------------------------------------------------------------

/// `arg n` (0x2c): push Args[n]. 1 immediate: index.
pub fn op_arg(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let idx = get_uint8(instruction)? as usize;
    let val = ctx.arg(idx)?;
    machine.push(AvmValue::Bytes(val))
}

/// `arg_0` (0x2d) through `arg_3` (0x30): push Args[N] where N is derived from the opcode.
pub fn op_arg_n(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let idx = (instruction.opcode - 0x2d) as usize; // 0x2d=0, 0x2e=1, 0x2f=2, 0x30=3
    let val = ctx.arg(idx)?;
    machine.push(AvmValue::Bytes(val))
}

/// `args` (0xc3): pop index from stack, push Args[index].
pub fn op_args(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let idx = machine.pop_uint()? as usize;
    let val = ctx.arg(idx)?;
    machine.push(AvmValue::Bytes(val))
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

    // --- Test context that provides txn fields and args ---

    struct TestTxnContext {
        /// Current transaction's group index.
        group_idx: usize,
        /// Group size.
        group_sz: usize,
        /// LogicSig arguments.
        args: Vec<Vec<u8>>,
    }

    impl TestTxnContext {
        fn new(group_idx: usize, group_sz: usize, args: Vec<Vec<u8>>) -> Self {
            Self {
                group_idx,
                group_sz,
                args,
            }
        }
    }

    impl AvmContext for TestTxnContext {
        fn txn_field(
            &self,
            group_index: usize,
            field: u8,
            array_index: Option<usize>,
        ) -> Result<TealValue, AlgoError> {
            match array_index {
                None => {
                    let encoded = (group_index as u64) * 256 + (field as u64);
                    Ok(TealValue::Uint(encoded))
                }
                Some(ai) => {
                    let s = format!("{}:{}:{}", group_index, field, ai);
                    Ok(TealValue::Bytes(s.into_bytes()))
                }
            }
        }

        fn group_size(&self) -> usize {
            self.group_sz
        }

        fn group_index(&self) -> usize {
            self.group_idx
        }

        fn arg(&self, index: usize) -> Result<Vec<u8>, AlgoError> {
            self.args.get(index).cloned().ok_or_else(|| AlgoError::Avm {
                message: format!(
                    "arg index {index} out of range (have {} args)",
                    self.args.len()
                ),
            })
        }

        fn num_args(&self) -> usize {
            self.args.len()
        }
    }

    // --- Test helpers ---

    /// Parse and run a program with the given context, returning the machine.
    fn run_with_ctx(
        version: u8,
        code: &[u8],
        ctx: &mut dyn AvmContext,
    ) -> Result<AvmMachine, AlgoError> {
        let raw = prog(version, code);
        let program = bytecode::parse(&raw)?;
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 20000);
        // Step only through the real instructions, stopping short of the
        // implicit-end pass/fail check -- these tests assert on the stack
        // an opcode dispatch left behind, not on program-end acceptance
        // semantics (`AvmMachine::finish_implicit`, which now requires
        // exactly one leftover *int*; many of these fixtures intentionally
        // leave a bytes value or several values on the stack to inspect).
        while !m.finished && m.pc < m.program.instructions.len() {
            m.step(ctx)?;
        }
        Ok(m)
    }

    // --- txn tests ---

    #[test]
    fn test_txn_sender() {
        // txn Sender (field=0), current group_index=1
        // Expected: ctx.txn_field(1, 0, None) => Uint(1*256 + 0) = 256
        let mut ctx = TestTxnContext::new(1, 2, vec![]);
        let m = run_with_ctx(
            1,
            &[
                0x31, 0x00, // txn Sender
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(256)); // group=1, field=0 => 1*256+0
    }

    #[test]
    fn test_txn_fee() {
        // txn Fee (field=1), current group_index=0
        // Expected: ctx.txn_field(0, 1, None) => Uint(0*256 + 1) = 1
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let m = run_with_ctx(
            1,
            &[
                0x31, 0x01, // txn Fee
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(1)); // group=0, field=1 => 0*256+1
    }

    // --- gtxn tests ---

    #[test]
    fn test_gtxn_different_group() {
        // gtxn 2 7 (group=2, field=7 Amount)
        // Expected: ctx.txn_field(2, 7, None) => Uint(2*256 + 7) = 519
        let mut ctx = TestTxnContext::new(0, 3, vec![]);
        let m = run_with_ctx(
            1,
            &[
                0x33, 0x02, 0x07, // gtxn 2 Amount
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(519));
    }

    // --- txna tests ---

    #[test]
    fn test_txna_application_args() {
        // txna ApplicationArgs 2 (field=26, array_index=2), group_index=0
        // Expected: ctx.txn_field(0, 26, Some(2)) => Bytes("0:26:2")
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let m = run_with_ctx(
            2,
            &[
                0x36, 26, 2, // txna ApplicationArgs 2
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"0:26:2".to_vec()));
    }

    // --- gtxna tests ---

    #[test]
    fn test_gtxna() {
        // gtxna 1 26 3 (group=1, field=26, array_index=3)
        // Expected: ctx.txn_field(1, 26, Some(3)) => Bytes("1:26:3")
        let mut ctx = TestTxnContext::new(0, 2, vec![]);
        let m = run_with_ctx(
            2,
            &[
                0x37, 1, 26, 3, // gtxna 1 ApplicationArgs 3
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"1:26:3".to_vec()));
    }

    // --- gtxns tests ---

    #[test]
    fn test_gtxns() {
        // pushint 2, gtxns 7 (pop group_index=2, field=7)
        // Expected: ctx.txn_field(2, 7, None) => Uint(2*256 + 7) = 519
        let mut ctx = TestTxnContext::new(0, 3, vec![]);
        let m = run_with_ctx(
            3,
            &[
                0x81, 0x02, // pushint 2
                0x38, 0x07, // gtxns Amount
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(519));
    }

    // --- gtxnsa tests ---

    #[test]
    fn test_gtxnsa() {
        // pushint 1, gtxnsa 26 0 (pop group_index=1, field=26, array_index=0)
        // Expected: ctx.txn_field(1, 26, Some(0)) => Bytes("1:26:0")
        let mut ctx = TestTxnContext::new(0, 2, vec![]);
        let m = run_with_ctx(
            3,
            &[
                0x81, 0x01, // pushint 1
                0x39, 26, 0, // gtxnsa ApplicationArgs 0
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"1:26:0".to_vec()));
    }

    // --- txnas tests ---

    #[test]
    fn test_txnas() {
        // pushint 3, txnas 26 (pop array_index=3, field=26, group_index=0)
        // Expected: ctx.txn_field(0, 26, Some(3)) => Bytes("0:26:3")
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let m = run_with_ctx(
            5,
            &[
                0x81, 0x03, // pushint 3
                0xc0, 26, // txnas ApplicationArgs
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"0:26:3".to_vec()));
    }

    // --- gtxnas tests ---

    #[test]
    fn test_gtxnas() {
        // pushint 2, gtxnas 1 26 (pop array_index=2, group=1, field=26)
        // Expected: ctx.txn_field(1, 26, Some(2)) => Bytes("1:26:2")
        let mut ctx = TestTxnContext::new(0, 2, vec![]);
        let m = run_with_ctx(
            5,
            &[
                0x81, 0x02, // pushint 2
                0xc1, 1, 26, // gtxnas 1 ApplicationArgs
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"1:26:2".to_vec()));
    }

    // --- gtxnsas tests ---

    #[test]
    fn test_gtxnsas() {
        // pushint 1, pushint 2, gtxnsas 26
        // pop array_index=2, pop group_index=1, field=26
        // Expected: ctx.txn_field(1, 26, Some(2)) => Bytes("1:26:2")
        let mut ctx = TestTxnContext::new(0, 2, vec![]);
        let m = run_with_ctx(
            5,
            &[
                0x81, 0x01, // pushint 1 (group_index)
                0x81, 0x02, // pushint 2 (array_index)
                0xc2, 26, // gtxnsas ApplicationArgs
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"1:26:2".to_vec()));
    }

    // --- arg tests ---

    #[test]
    fn test_arg_immediate() {
        // arg 1 (index=1)
        let mut ctx = TestTxnContext::new(0, 1, vec![b"zero".to_vec(), b"one".to_vec()]);
        let m = run_with_ctx(
            1,
            &[
                0x2c, 0x01, // arg 1
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"one".to_vec()));
    }

    #[test]
    fn test_arg_0() {
        let mut ctx = TestTxnContext::new(0, 1, vec![b"first".to_vec()]);
        let m = run_with_ctx(
            1,
            &[
                0x2d, // arg_0
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"first".to_vec()));
    }

    #[test]
    fn test_arg_3() {
        let mut ctx = TestTxnContext::new(
            0,
            1,
            vec![
                b"a0".to_vec(),
                b"a1".to_vec(),
                b"a2".to_vec(),
                b"a3".to_vec(),
            ],
        );
        let m = run_with_ctx(
            1,
            &[
                0x30, // arg_3
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"a3".to_vec()));
    }

    #[test]
    fn test_args_stack() {
        // pushint 1, args (pop index=1)
        let mut ctx = TestTxnContext::new(0, 1, vec![b"zero".to_vec(), b"one".to_vec()]);
        let m = run_with_ctx(
            5,
            &[
                0x81, 0x01, // pushint 1
                0xc3, // args
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"one".to_vec()));
    }

    #[test]
    fn test_arg_out_of_range() {
        // arg 5 with only 2 args available
        let mut ctx = TestTxnContext::new(0, 1, vec![b"a".to_vec(), b"b".to_vec()]);
        let raw = prog(
            1,
            &[
                0x2c, 0x05, // arg 5
            ],
        );
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 20000);
        assert!(m.run(&mut ctx).is_err());
    }

    #[test]
    fn test_txn_bad_field_index_rejected() {
        // TestTxnBadField: `txn` with an out-of-range raw field index (127,
        // no such TxnField) must error with a message naming it as an
        // invalid txn field, not silently succeed or panic.
        let raw: &[u8] = &[0x01, 0x31, 0x7f]; // version 1, txn, field 127
        let program = bytecode::parse(raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 20000);
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let result = m.run(&mut ctx);
        assert!(result.is_err(), "txn with field 127 should error");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("invalid txn field"),
            "expected an 'invalid txn field' error, got: {msg}"
        );
    }

    #[test]
    fn test_gtxn_bad_field_index_rejected() {
        // TestGtxnBadField: same as above, for `gtxn <index> <field>`.
        let raw: &[u8] = &[0x01, 0x33, 0x00, 0x7f]; // version 1, gtxn 0, field 127
        let program = bytecode::parse(raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 20000);
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let result = m.run(&mut ctx);
        assert!(result.is_err(), "gtxn with field 127 should error");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("invalid txn field"),
            "expected an 'invalid txn field' error, got: {msg}"
        );
    }

    // --- Per-field version gating (issue #810) ---
    //
    // Matches go-algorand's shared `fetchField` check (`fs.version >
    // cx.version`), exercised here via `txn`/`gtxn` (0x31/0x33) directly
    // against representative fields spanning each version boundary in
    // `txnFieldSpecs`.

    fn txn_field_at_version(version: u8, field: u8) -> Result<AvmMachine, AlgoError> {
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        run_with_ctx(version, &[0x31, field], &mut ctx)
    }

    #[test]
    fn test_txn_field_version_application_id_gated_at_v2() {
        // ApplicationID (field 24) requires v2.
        assert!(txn_field_at_version(1, 24).is_err());
        assert!(txn_field_at_version(2, 24).is_ok());
    }

    #[test]
    fn test_txn_field_version_assets_gated_at_v3() {
        // NumAssets (field 49) requires v3. (Not `Assets`/48 itself -- that's
        // an array field and can't be accessed via the scalar `txn` form
        // this helper uses; see issue #1397's array-ness validation.)
        assert!(txn_field_at_version(2, 49).is_err());
        assert!(txn_field_at_version(3, 49).is_ok());
    }

    #[test]
    fn test_txn_field_version_extra_program_pages_gated_at_v4() {
        // ExtraProgramPages (field 56) requires v4.
        assert!(txn_field_at_version(3, 56).is_err());
        assert!(txn_field_at_version(4, 56).is_ok());
    }

    #[test]
    fn test_txn_field_version_nonparticipation_gated_at_v5() {
        // Nonparticipation (field 57) requires v5.
        assert!(txn_field_at_version(4, 57).is_err());
        assert!(txn_field_at_version(5, 57).is_ok());
    }

    #[test]
    fn test_txn_field_version_last_log_gated_at_v6() {
        // LastLog (field 62) requires v6.
        assert!(txn_field_at_version(5, 62).is_err());
        assert!(txn_field_at_version(6, 62).is_ok());
    }

    #[test]
    fn test_txn_field_version_first_valid_time_gated_at_v7() {
        // FirstValidTime (field 3) requires v7 (randomnessVersion).
        assert!(txn_field_at_version(6, 3).is_err());
        assert!(txn_field_at_version(7, 3).is_ok());
    }

    #[test]
    fn test_txn_field_version_reject_version_gated_at_v12() {
        // RejectVersion (field 68) requires v12.
        assert!(txn_field_at_version(11, 68).is_err());
        assert!(txn_field_at_version(12, 68).is_ok());
    }

    #[test]
    fn test_txn_field_version_sender_available_since_v1() {
        // Sender (field 0) has version 0 -- always available.
        assert!(txn_field_at_version(1, 0).is_ok());
    }

    #[test]
    fn test_gtxn_field_version_gating_applies_too() {
        // gtxn (0x33) shares the same per-field version check as txn.
        let mut ctx = TestTxnContext::new(0, 2, vec![]);
        // ApplicationID (field 24) requires v2; gtxn target=0.
        assert!(run_with_ctx(1, &[0x33, 0x00, 24], &mut ctx).is_err());
        assert!(run_with_ctx(2, &[0x33, 0x00, 24], &mut ctx).is_ok());
    }

    // --- Array-ness validation (issue #1397) ---
    //
    // Matches go-algorand's shared `fetchField(field, expectArray)`
    // (`data/transactions/logic/eval.go`): the accessing opcode's
    // array-expectation must match the target field's own `array` metadata
    // (`txnFieldSpecs[].array`), or the access is rejected outright.

    /// Extract the error message from a failing `run_with_ctx` result.
    /// (`AvmMachine` doesn't implement `Debug`, so `Result::unwrap_err`
    /// can't be used directly here.)
    fn expect_err_msg(result: Result<AvmMachine, AlgoError>) -> String {
        match result {
            Ok(_) => panic!("expected an error, but the program succeeded"),
            Err(e) => format!("{e}"),
        }
    }

    #[test]
    fn test_txna_fee_rejected_not_an_array_field() {
        // txna Fee 0 -- Fee (field 1) is not an array field, so the `txna`
        // (array-indexed) form must reject it rather than silently ignoring
        // the index and returning plain Fee.
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let result = run_with_ctx(2, &[0x36, 1, 0], &mut ctx); // txna Fee 0
        let msg = expect_err_msg(result);
        assert!(
            msg.contains("unsupported array field"),
            "expected an 'unsupported array field' error, got: {msg}"
        );
    }

    #[test]
    fn test_txn_application_args_rejected_array_only_field() {
        // txn ApplicationArgs -- ApplicationArgs (field 26) is array-only
        // and must be accessed via `txna`/`txnas`; the scalar `txn` form
        // must reject it rather than silently returning the array length.
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let result = run_with_ctx(2, &[0x31, 26], &mut ctx); // txn ApplicationArgs
        let msg = expect_err_msg(result);
        assert!(
            msg.contains("invalid txn field"),
            "expected an 'invalid txn field' error, got: {msg}"
        );
    }

    #[test]
    fn test_gtxn_application_args_rejected_array_only_field() {
        // gtxn 0 ApplicationArgs -- same as above, via the gtxn scalar form.
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let result = run_with_ctx(2, &[0x33, 0, 26], &mut ctx);
        let msg = expect_err_msg(result);
        assert!(msg.contains("invalid txn field"), "got: {msg}");
    }

    #[test]
    fn test_gtxns_application_args_rejected_array_only_field() {
        // pushint 0, gtxns ApplicationArgs -- same, via gtxns.
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let result = run_with_ctx(3, &[0x81, 0x00, 0x38, 26], &mut ctx);
        let msg = expect_err_msg(result);
        assert!(msg.contains("invalid txn field"), "got: {msg}");
    }

    #[test]
    fn test_gtxna_fee_rejected_not_an_array_field() {
        // gtxna 0 Fee 0 -- Fee is not an array field.
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let result = run_with_ctx(2, &[0x37, 0, 1, 0], &mut ctx);
        let msg = expect_err_msg(result);
        assert!(msg.contains("unsupported array field"), "got: {msg}");
    }

    #[test]
    fn test_gtxnsa_fee_rejected_not_an_array_field() {
        // pushint 0, gtxnsa Fee 0 -- Fee is not an array field.
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let result = run_with_ctx(3, &[0x81, 0x00, 0x39, 1, 0], &mut ctx);
        let msg = expect_err_msg(result);
        assert!(msg.contains("unsupported array field"), "got: {msg}");
    }

    #[test]
    fn test_txnas_fee_rejected_not_an_array_field() {
        // pushint 0, txnas Fee -- Fee is not an array field.
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let result = run_with_ctx(5, &[0x81, 0x00, 0xc0, 1], &mut ctx);
        let msg = expect_err_msg(result);
        assert!(msg.contains("unsupported array field"), "got: {msg}");
    }

    #[test]
    fn test_gtxnas_fee_rejected_not_an_array_field() {
        // pushint 0, gtxnas 0 Fee -- Fee is not an array field.
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let result = run_with_ctx(5, &[0x81, 0x00, 0xc1, 0, 1], &mut ctx);
        let msg = expect_err_msg(result);
        assert!(msg.contains("unsupported array field"), "got: {msg}");
    }

    #[test]
    fn test_gtxnsas_fee_rejected_not_an_array_field() {
        // pushint 0, pushint 0, gtxnsas Fee -- Fee is not an array field.
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let result = run_with_ctx(5, &[0x81, 0x00, 0x81, 0x00, 0xc2, 1], &mut ctx);
        let msg = expect_err_msg(result);
        assert!(msg.contains("unsupported array field"), "got: {msg}");
    }

    #[test]
    fn test_txn_sender_scalar_field_still_works() {
        // Existing valid scalar access (txn Sender) must keep working.
        let mut ctx = TestTxnContext::new(1, 2, vec![]);
        let m = run_with_ctx(2, &[0x31, 0], &mut ctx).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(256));
    }

    #[test]
    fn test_txna_accounts_array_field_still_works() {
        // Existing valid array access (txna Accounts 0) must keep working.
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let m = run_with_ctx(2, &[0x36, 28, 0], &mut ctx).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"0:28:0".to_vec()));
    }
}
