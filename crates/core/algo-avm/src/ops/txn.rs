//! Transaction field access opcodes: txn, gtxn, txna, gtxna, gtxns, gtxnsa,
//! txnas, gtxnas, gtxnsas, and LogicSig argument opcodes: arg, arg_0..arg_3, args.

use algo_error::AlgoError;

use crate::bytecode::Instruction;
use crate::context::AvmContext;
use crate::machine::{AvmMachine, AvmValue};

use super::helpers::{get_uint8, get_uint8_pair, get_uint8_triple, teal_to_avm};

// ---------------------------------------------------------------------------
// Transaction field opcodes
// ---------------------------------------------------------------------------

/// `txn f` (0x31): push Txn.Fields[f] for the current transaction.
/// 1 immediate: field byte.
pub fn op_txn(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let field = get_uint8(instruction)?;
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
        m.run(ctx)?;
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
        // txna ApplicationArgs 2 (field=25, array_index=2), group_index=0
        // Expected: ctx.txn_field(0, 25, Some(2)) => Bytes("0:25:2")
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let m = run_with_ctx(
            2,
            &[
                0x36, 25, 2, // txna ApplicationArgs 2
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"0:25:2".to_vec()));
    }

    // --- gtxna tests ---

    #[test]
    fn test_gtxna() {
        // gtxna 1 25 3 (group=1, field=25, array_index=3)
        // Expected: ctx.txn_field(1, 25, Some(3)) => Bytes("1:25:3")
        let mut ctx = TestTxnContext::new(0, 2, vec![]);
        let m = run_with_ctx(
            2,
            &[
                0x37, 1, 25, 3, // gtxna 1 ApplicationArgs 3
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"1:25:3".to_vec()));
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
        // pushint 1, gtxnsa 25 0 (pop group_index=1, field=25, array_index=0)
        // Expected: ctx.txn_field(1, 25, Some(0)) => Bytes("1:25:0")
        let mut ctx = TestTxnContext::new(0, 2, vec![]);
        let m = run_with_ctx(
            3,
            &[
                0x81, 0x01, // pushint 1
                0x39, 25, 0, // gtxnsa ApplicationArgs 0
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"1:25:0".to_vec()));
    }

    // --- txnas tests ---

    #[test]
    fn test_txnas() {
        // pushint 3, txnas 25 (pop array_index=3, field=25, group_index=0)
        // Expected: ctx.txn_field(0, 25, Some(3)) => Bytes("0:25:3")
        let mut ctx = TestTxnContext::new(0, 1, vec![]);
        let m = run_with_ctx(
            5,
            &[
                0x81, 0x03, // pushint 3
                0xc0, 25, // txnas ApplicationArgs
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"0:25:3".to_vec()));
    }

    // --- gtxnas tests ---

    #[test]
    fn test_gtxnas() {
        // pushint 2, gtxnas 1 25 (pop array_index=2, group=1, field=25)
        // Expected: ctx.txn_field(1, 25, Some(2)) => Bytes("1:25:2")
        let mut ctx = TestTxnContext::new(0, 2, vec![]);
        let m = run_with_ctx(
            5,
            &[
                0x81, 0x02, // pushint 2
                0xc1, 1, 25, // gtxnas 1 ApplicationArgs
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"1:25:2".to_vec()));
    }

    // --- gtxnsas tests ---

    #[test]
    fn test_gtxnsas() {
        // pushint 1, pushint 2, gtxnsas 25
        // pop array_index=2, pop group_index=1, field=25
        // Expected: ctx.txn_field(1, 25, Some(2)) => Bytes("1:25:2")
        let mut ctx = TestTxnContext::new(0, 2, vec![]);
        let m = run_with_ctx(
            5,
            &[
                0x81, 0x01, // pushint 1 (group_index)
                0x81, 0x02, // pushint 2 (array_index)
                0xc2, 25, // gtxnsas ApplicationArgs
            ],
            &mut ctx,
        )
        .unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"1:25:2".to_vec()));
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
}
