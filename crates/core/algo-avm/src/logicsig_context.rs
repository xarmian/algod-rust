//! `AvmContext` implementation for LogicSig evaluation.
//!
//! LogicSig programs run in `ModeSig` mode with access to transaction fields,
//! group transactions, and LogicSig arguments.  State operations (reads, writes,
//! inner transactions, etc.) are not available and return errors via the default
//! `AvmContext` trait implementations.

use algo_error::AlgoError;
use algo_types::{SignedTransaction, TealValue};
use sha2::{Digest, Sha512_256};

use crate::context::AvmContext;
use crate::txn_fields::read_txn_field;

/// Domain separation prefix for program hashing.
const PROGRAM_PREFIX: &[u8] = b"Program";

/// AVM execution context for LogicSig programs.
///
/// Provides transaction field access (`txn`, `gtxn`), LogicSig arguments
/// (`arg`, `args`), group metadata, and the program hash.  All state
/// operations (account/asset/app lookups, state reads/writes, inner
/// transactions, box storage, logging) fall through to the default
/// `AvmContext` implementations which return errors.
pub struct LogicSigAvmContext<'a> {
    /// The transaction group (may be a single-element slice for ungrouped txns).
    group: &'a [SignedTransaction],
    /// Index of the current transaction within the group.
    group_index: usize,
    /// LogicSig arguments for the current transaction.
    args: Vec<Vec<u8>>,
    /// SHA-512/256 hash of `"Program" || program_bytes`.
    program_hash: [u8; 32],
}

impl<'a> LogicSigAvmContext<'a> {
    /// Create a new LogicSig context.
    ///
    /// `group` is the full transaction group.  `group_index` is the index of
    /// the transaction whose LogicSig is being evaluated.  `program` is the
    /// raw TEAL program bytes (used to compute the program hash).
    pub fn new(
        group: &'a [SignedTransaction],
        group_index: usize,
        program: &[u8],
        args: Vec<Vec<u8>>,
    ) -> Self {
        let mut hasher = Sha512_256::new();
        hasher.update(PROGRAM_PREFIX);
        hasher.update(program);
        let hash: [u8; 32] = hasher.finalize().into();

        LogicSigAvmContext {
            group,
            group_index,
            args,
            program_hash: hash,
        }
    }
}

impl<'a> AvmContext for LogicSigAvmContext<'a> {
    // ---- Transaction access ----

    fn txn_field(
        &self,
        group_index: usize,
        field: u8,
        array_index: Option<usize>,
    ) -> Result<TealValue, AlgoError> {
        if group_index >= self.group.len() {
            return Err(AlgoError::Avm {
                message: format!(
                    "group_index {} out of range (group size={})",
                    group_index,
                    self.group.len()
                ),
            });
        }
        let stxn = &self.group[group_index];
        read_txn_field(stxn, field, array_index, group_index)
    }

    fn group_size(&self) -> usize {
        self.group.len()
    }

    fn group_index(&self) -> usize {
        self.group_index
    }

    // ---- LogicSig arguments ----

    fn arg(&self, index: usize) -> Result<Vec<u8>, AlgoError> {
        if index >= self.args.len() {
            return Err(AlgoError::Avm {
                message: format!(
                    "arg index {} out of range (num_args={})",
                    index,
                    self.args.len()
                ),
            });
        }
        Ok(self.args[index].clone())
    }

    fn num_args(&self) -> usize {
        self.args.len()
    }

    // ---- Program hash ----

    fn program_hash(&self) -> [u8; 32] {
        self.program_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{Address, Round, Transaction};

    fn make_pay_stxn(sender: [u8; 32]) -> SignedTransaction {
        SignedTransaction {
            txn: Transaction {
                txn_type: "pay".into(),
                sender: Address(sender),
                fee: 1000,
                first_valid: Round(100),
                last_valid: Round(200),
                receiver: Address([0x20; 32]),
                amount: 5000,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn basic_txn_field_access() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![]);

        // Sender
        let sender = ctx.txn_field(0, 0, None).unwrap();
        assert_eq!(sender, TealValue::Bytes(vec![0x10; 32]));

        // Fee
        let fee = ctx.txn_field(0, 1, None).unwrap();
        assert_eq!(fee, TealValue::Uint(1000));

        // Amount
        let amount = ctx.txn_field(0, 8, None).unwrap();
        assert_eq!(amount, TealValue::Uint(5000));
    }

    #[test]
    fn group_metadata() {
        let stxn1 = make_pay_stxn([0x10; 32]);
        let stxn2 = make_pay_stxn([0x20; 32]);
        let group = vec![stxn1, stxn2];
        let ctx = LogicSigAvmContext::new(&group, 1, &[0x01], vec![]);

        assert_eq!(ctx.group_size(), 2);
        assert_eq!(ctx.group_index(), 1);
    }

    #[test]
    fn arg_access() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let args = vec![b"hello".to_vec(), b"world".to_vec()];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], args);

        assert_eq!(ctx.num_args(), 2);
        assert_eq!(ctx.arg(0).unwrap(), b"hello".to_vec());
        assert_eq!(ctx.arg(1).unwrap(), b"world".to_vec());
        assert!(ctx.arg(2).is_err());
    }

    #[test]
    fn program_hash_computed() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let program = vec![0x06, 0x81, 0x01];
        let ctx = LogicSigAvmContext::new(&group, 0, &program, vec![]);

        // Compute expected hash manually.
        let mut hasher = Sha512_256::new();
        hasher.update(PROGRAM_PREFIX);
        hasher.update(&program);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(ctx.program_hash(), expected);
    }

    #[test]
    fn state_operations_return_errors() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let mut ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![]);

        // State reads should error (default AvmContext implementations).
        assert!(ctx.app_global_get(1, b"key").is_err());
        assert!(ctx.app_local_get(&[0; 32], 1, b"key").is_err());
        assert!(ctx.balance(&[0; 32]).is_err());

        // State writes should error.
        assert!(ctx.app_global_put(1, b"key", TealValue::Uint(1)).is_err());

        // Inner transactions should error.
        assert!(ctx.itxn_begin().is_err());

        // Not app mode.
        assert!(!ctx.is_app_mode());
    }

    #[test]
    fn out_of_range_group_index_errors() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![]);

        assert!(ctx.txn_field(1, 0, None).is_err());
    }
}
