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

//! `AvmContext` implementation for LogicSig evaluation.
//!
//! LogicSig programs run in `ModeSig` mode with access to transaction fields,
//! group transactions, and LogicSig arguments.  State operations (reads, writes,
//! inner transactions, etc.) are not available and return errors via the default
//! `AvmContext` trait implementations.

use algo_error::AlgoError;
use algo_types::consensus::ConsensusParams;
use algo_types::{SignedTransaction, TealValue, TxnType};
use sha2::{Digest, Sha512_256};

use crate::context::AvmContext;
use crate::fields::{BlockField, GlobalField};
use crate::machine::AvmValue;
use crate::txn_fields::{check_available_round, read_txn_field};

/// Block-history lookback source for LogicSig ("stateless") evaluation.
///
/// Mirrors go-algorand's `LedgerForSignature` (`data/transactions/logic/
/// eval.go`): a deliberately narrow view of the ledger -- "it only exposes
/// things that consensus has already agreed upon, so it is 'stateless' for
/// signature purposes" -- that both `txn FirstValidTime` and the `block`
/// opcode's `BlkTimestamp` field read from, regardless of whether the
/// currently-running program is a LogicSig or an application. Only the
/// timestamp field is exposed here because it's the only block-history data
/// `FirstValidTime` needs; the other `block` fields (seed, branch, etc.)
/// remain unavailable in LogicSig mode pending broader wiring (tracked
/// separately -- see issue referenced in `LogicSigAvmContext::block_field`).
pub trait SigBlockSource {
    /// Returns the timestamp of the block at `round`, matching go's
    /// `BlockHeader.TimeStamp`. Errors (e.g. "no block header access",
    /// pruned/unknown round) propagate to the caller as the opcode's error.
    fn block_timestamp(&self, round: u64) -> Result<i64, AlgoError>;
}

/// Domain separation prefix for program hashing.
const PROGRAM_PREFIX: &[u8] = b"Program";

/// Returns `true` for the `TxnField`s go-algorand marks `effects: true` in
/// `txnFieldSpecs` (`data/transactions/logic/fields.go`): Logs (58),
/// NumLogs (59), CreatedAssetID (60), CreatedApplicationID (61), and
/// LastLog (62) -- fields sourced from a transaction's `ApplyData`, which a
/// LogicSig (never applied by an app call) can never legitimately read.
fn is_effects_field(field: u8) -> bool {
    matches!(field, 58..=62)
}

/// AVM version at which `RekeyTo` functionality was introduced.
/// Matches go-algorand's `rekeyingEnabledVersion`
/// (`data/transactions/logic/opcodes.go`).
const REKEYING_ENABLED_VERSION: u64 = 2;

/// AVM version at which `ApplicationCall` transactions were introduced.
/// Matches go-algorand's `appsEnabledVersion`
/// (`data/transactions/logic/opcodes.go`).
const APPS_ENABLED_VERSION: u64 = 2;

/// Compute the minimum safe AVM version that may be used by a program
/// evaluated against this transaction group.
///
/// Matches go-algorand's `computeMinAvmVersion`
/// (`data/transactions/logic/eval.go`): a group containing a `RekeyTo`
/// (rekeying) transaction or an `ApplicationCall` transaction raises the
/// minimum required version for every LogicSig signature in the group, so
/// that older-version programs can't be exposed to transaction fields/types
/// they predate.
fn compute_min_avm_version(group: &[SignedTransaction]) -> u64 {
    let mut min_version = 0u64;
    for stx in group {
        if stx.txn.rekey_to.as_ref().is_some_and(|a| !a.is_zero()) {
            min_version = min_version.max(REKEYING_ENABLED_VERSION);
        }
        if stx.txn.txn_type == TxnType::Appl {
            min_version = min_version.max(APPS_ENABLED_VERSION);
        }
    }
    min_version
}

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
    /// Genesis hash from the transaction header (for `global GenesisHash`).
    genesis_hash: [u8; 32],
    /// Consensus parameters for the current protocol version.
    consensus: ConsensusParams,
    /// Optional block-history lookback source, used by `txn FirstValidTime`
    /// and `block BlkTimestamp`. `None` matches go-algorand's
    /// `NoHeaderLedger` default (no real ledger wired in): both opcodes
    /// error with "no block header access", exactly as go does when no
    /// `LedgerForSignature` is available.
    sig_ledger: Option<&'a dyn SigBlockSource>,
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
        consensus: ConsensusParams,
    ) -> Self {
        let mut hasher = Sha512_256::new();
        hasher.update(PROGRAM_PREFIX);
        hasher.update(program);
        let hash: [u8; 32] = hasher.finalize().into();

        // Extract genesis hash from the current transaction's header.
        let genesis_hash = if group_index < group.len() {
            let gh = &group[group_index].txn.genesis_hash;
            if gh.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(gh);
                arr
            } else {
                [0u8; 32]
            }
        } else {
            [0u8; 32]
        };

        LogicSigAvmContext {
            group,
            group_index,
            args,
            program_hash: hash,
            genesis_hash,
            consensus,
            sig_ledger: None,
        }
    }

    /// Attach a block-history lookback source, enabling `txn FirstValidTime`
    /// and `block BlkTimestamp` for this evaluation. Builder-style so
    /// existing callers that don't need block history (the overwhelming
    /// majority -- most LogicSigs never touch these fields) are unaffected.
    pub fn with_sig_ledger(mut self, sig_ledger: &'a dyn SigBlockSource) -> Self {
        self.sig_ledger = Some(sig_ledger);
        self
    }
}

impl<'a> AvmContext for LogicSigAvmContext<'a> {
    fn consensus_logic_sig_version(&self) -> Option<u64> {
        Some(self.consensus.logic_sig_version)
    }

    fn min_avm_version(&self) -> u64 {
        compute_min_avm_version(self.group)
    }

    // ---- Global fields ----

    fn global_field(&self, field: u8) -> Result<TealValue, AlgoError> {
        let gf = GlobalField::from_u8(field)?;
        match gf {
            // modeAny fields — available in both Sig and App mode.
            GlobalField::MinTxnFee => Ok(TealValue::Uint(self.consensus.min_txn_fee)),
            GlobalField::MinBalance => Ok(TealValue::Uint(self.consensus.min_balance)),
            GlobalField::MaxTxnLife => Ok(TealValue::Uint(self.consensus.max_txn_life)),
            GlobalField::ZeroAddress => Ok(TealValue::Bytes(vec![0u8; 32])),
            GlobalField::GroupSize => Ok(TealValue::Uint(self.group.len() as u64)),
            GlobalField::LogicSigVersion => Ok(TealValue::Uint(self.consensus.logic_sig_version)),
            GlobalField::GroupID => {
                let group_id = if self.group_index < self.group.len() {
                    let g = &self.group[self.group_index].txn.group;
                    if g.is_empty() {
                        vec![0u8; 32]
                    } else {
                        g.to_vec()
                    }
                } else {
                    vec![0u8; 32]
                };
                Ok(TealValue::Bytes(group_id))
            }
            // OpcodeBudget is handled directly by op_global (reads machine.budget);
            // this fallback returns 0 but should not normally be reached.
            GlobalField::OpcodeBudget => Ok(TealValue::Uint(0)),
            GlobalField::AssetCreateMinBalance => Ok(TealValue::Uint(self.consensus.min_balance)),
            GlobalField::AssetOptInMinBalance => Ok(TealValue::Uint(self.consensus.min_balance)),
            GlobalField::GenesisHash => Ok(TealValue::Bytes(self.genesis_hash.to_vec())),
            // Payouts fields — sourced from consensus params.
            GlobalField::PayoutsEnabled => Ok(TealValue::Uint(if self.consensus.payouts_enabled {
                1
            } else {
                0
            })),
            GlobalField::PayoutsGoOnlineFee => {
                Ok(TealValue::Uint(self.consensus.payouts_go_online_fee))
            }
            GlobalField::PayoutsPercent => Ok(TealValue::Uint(self.consensus.payouts_percent)),
            GlobalField::PayoutsMinBalance => {
                Ok(TealValue::Uint(self.consensus.payouts_min_balance))
            }
            GlobalField::PayoutsMaxBalance => {
                Ok(TealValue::Uint(self.consensus.payouts_max_balance))
            }
            // ModeApp-only fields — should never reach here because op_global
            // rejects them in LogicSig mode before calling global_field(), but
            // return an error for completeness.
            GlobalField::Round
            | GlobalField::LatestTimestamp
            | GlobalField::CurrentApplicationID
            | GlobalField::CreatorAddress
            | GlobalField::CurrentApplicationAddress
            | GlobalField::CallerApplicationID
            | GlobalField::CallerApplicationAddress => Err(AlgoError::Avm {
                message: format!("global[{field}] not available in LogicSig mode"),
            }),
        }
    }

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
        // "Effects" fields (Logs, NumLogs, CreatedAssetID,
        // CreatedApplicationID, LastLog) only make sense for a transaction
        // that has actually been applied by an app call, which a LogicSig
        // never is. Go's `txnFieldToStack` (`data/transactions/logic/
        // eval.go`) rejects them unconditionally in `ModeSig`, before any
        // version/array-index check -- `if fs.effects { if cx.runMode ==
        // ModeSig { return sv, fmt.Errorf("txn[%s] not allowed in current
        // mode", fs.field) } ... }`. Mirror that exactly here.
        if is_effects_field(field) {
            let name = crate::fields::txn_field_name(field).unwrap_or("?");
            return Err(AlgoError::Avm {
                message: format!("txn[{name}] not allowed in current mode"),
            });
        }
        // FirstValidTime (field 3): timestamp of block(FirstValid-1). Go's
        // `data/transactions/logic/eval.go` opTxn case reads this via
        // `cx.SigLedger.BlockHdr`, available in *both* App and Sig mode
        // (it's "not really a field of a txn, but ... 'stateless'" -- see
        // go's `TestTxnFirstValidTime`). `read_txn_field` has no ledger
        // access, so intercept here exactly as `LedgerAvmContext` does for
        // App mode, delegating to `block_field` (which applies the same
        // availability-window check against the *currently executing*
        // transaction, not `stxn`, matching go's `cx.txn`-based
        // `availableRound`).
        if field == 3 {
            let round = stxn.txn.first_valid.0.saturating_sub(1);
            let value = self.block_field(round, BlockField::BlkTimestamp as u8)?;
            return match value {
                AvmValue::Uint64(ts) => Ok(TealValue::Uint(ts)),
                AvmValue::Bytes(_) => Err(AlgoError::Avm {
                    message: "internal error: BlkTimestamp returned Bytes".to_string(),
                }),
            };
        }
        read_txn_field(stxn, field, array_index, group_index)
    }

    fn group_size(&self) -> usize {
        self.group.len()
    }

    fn group_index(&self) -> usize {
        self.group_index
    }

    // ---- Block field access ----

    /// Used by `block` (0xd1) and, via `txn_field`, by `txn FirstValidTime`.
    ///
    /// Only `BlkTimestamp` is implemented -- the one field `FirstValidTime`
    /// needs. The other `block` fields (seed, branch, fee sink, etc.) stay
    /// unavailable in LogicSig mode: go-algorand's `block` opcode is
    /// `modeAny` and does support them there too, but wiring full
    /// `BlockHeader` access (not just timestamp) into the LogicSig
    /// evaluation path is tracked as a separate follow-up.
    fn block_field(&self, round: u64, field: u8) -> Result<AvmValue, AlgoError> {
        let bf = BlockField::from_u8(field)?;
        if bf != BlockField::BlkTimestamp {
            return Err(AlgoError::Avm {
                message: format!(
                    "block field {field} not available in LogicSig mode (only BlkTimestamp is)"
                ),
            });
        }
        // Availability window is bounds-checked against the *currently
        // executing* transaction (`self.group_index`), matching go's
        // `cx.txn`-based `availableRound` -- not the (possibly `gtxn`-
        // referenced) transaction whose FirstValidTime is being read.
        let cur_txn = &self.group[self.group_index].txn;
        let checked_round = check_available_round(
            round,
            cur_txn.first_valid.0,
            cur_txn.last_valid.0,
            self.consensus.max_txn_life,
        )?;
        let sig_ledger = self.sig_ledger.ok_or_else(|| AlgoError::Avm {
            message: "no block header access".to_string(),
        })?;
        let ts = sig_ledger.block_timestamp(checked_round)?;
        if ts < 0 {
            return Err(AlgoError::Avm {
                message: format!("block({checked_round}) timestamp {ts} < 0"),
            });
        }
        Ok(AvmValue::Uint64(ts as u64))
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
    use algo_types::consensus::ConsensusParams;
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
    fn min_avm_version_zero_for_plain_group() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());
        assert_eq!(ctx.min_avm_version(), 0);
    }

    #[test]
    fn min_avm_version_raised_by_rekey_to() {
        let mut stxn = make_pay_stxn([0x10; 32]);
        stxn.txn.rekey_to = Some(Address([0x30; 32]));
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());
        assert_eq!(ctx.min_avm_version(), 2);
    }

    #[test]
    fn min_avm_version_zero_address_rekey_to_does_not_raise_floor() {
        // A RekeyTo set to the zero address is a no-op rekey (matches
        // go-algorand's txn.RekeyTo.IsZero() check) and must not raise the
        // floor.
        let mut stxn = make_pay_stxn([0x10; 32]);
        stxn.txn.rekey_to = Some(Address([0x00; 32]));
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());
        assert_eq!(ctx.min_avm_version(), 0);
    }

    #[test]
    fn min_avm_version_raised_by_application_call() {
        let mut stxn = make_pay_stxn([0x10; 32]);
        stxn.txn.txn_type = algo_types::TxnType::Appl;
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());
        assert_eq!(ctx.min_avm_version(), 2);
    }

    #[test]
    fn min_avm_version_raised_by_sibling_in_group() {
        // The floor applies to every LogicSig in the group, not just the
        // transaction that carries the RekeyTo/ApplicationCall itself.
        let pay = make_pay_stxn([0x10; 32]);
        let mut appl = make_pay_stxn([0x20; 32]);
        appl.txn.txn_type = algo_types::TxnType::Appl;
        let group = vec![pay, appl];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());
        assert_eq!(ctx.min_avm_version(), 2);
    }

    #[test]
    fn basic_txn_field_access() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

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
        let ctx = LogicSigAvmContext::new(&group, 1, &[0x01], vec![], ConsensusParams::default());

        assert_eq!(ctx.group_size(), 2);
        assert_eq!(ctx.group_index(), 1);
    }

    #[test]
    fn arg_access() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let args = vec![b"hello".to_vec(), b"world".to_vec()];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], args, ConsensusParams::default());

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
        let ctx = LogicSigAvmContext::new(&group, 0, &program, vec![], ConsensusParams::default());

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
        let mut ctx =
            LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

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

    // ---- "effects" field rejection in Signature mode ----
    //
    // Ported from go-algorand's `TestTxnEffectsAvailable`
    // (`data/transactions/logic/fields_test.go`): "LogicSigs can not use
    // 'effects' fields (ever)". go's `txnFieldToStack`
    // (`data/transactions/logic/eval.go`) rejects any field with
    // `fs.effects == true` when `cx.runMode == ModeSig`, with the error
    // `txn[<FieldName>] not allowed in current mode` -- these fields only
    // make sense for a transaction actually applied by an app call, which a
    // LogicSig never is. The five effect fields (`fs.effects: true` in
    // go's `txnFieldSpecs`) are Logs (58), NumLogs (59), CreatedAssetID
    // (60), CreatedApplicationID (61), and LastLog (62).

    #[test]
    fn effect_fields_rejected_in_signature_mode() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

        for (field_byte, name) in [
            (58u8, "Logs"),
            (59, "NumLogs"),
            (60, "CreatedAssetID"),
            (61, "CreatedApplicationID"),
            (62, "LastLog"),
        ] {
            let result = ctx.txn_field(0, field_byte, None);
            assert!(
                result.is_err(),
                "txn[{name}] (field {field_byte}) should be rejected in Signature mode"
            );
            let msg = format!("{}", result.unwrap_err());
            assert!(
                msg.contains("not allowed in current mode"),
                "unexpected error for field {field_byte} ({name}): {msg}"
            );
            assert!(
                msg.contains(name),
                "error for field {field_byte} should name the field ({name}): {msg}"
            );
        }
    }

    #[test]
    fn effect_field_logs_array_read_also_rejected_in_signature_mode() {
        // Logs is an array field (`gtxn 0 Logs 0`); the rejection must fire
        // regardless of `array_index`, matching go's check running before
        // any array-index bounds check.
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

        let err = ctx.txn_field(0, 58, Some(0)).unwrap_err();
        assert!(format!("{err}").contains("not allowed in current mode"));
    }

    #[test]
    fn out_of_range_group_index_errors() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

        assert!(ctx.txn_field(1, 0, None).is_err());
    }

    // ---- global_field tests ----

    #[test]
    fn global_field_min_txn_fee() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

        assert_eq!(ctx.global_field(0).unwrap(), TealValue::Uint(1000));
    }

    #[test]
    fn global_field_min_balance() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

        assert_eq!(ctx.global_field(1).unwrap(), TealValue::Uint(100_000));
    }

    #[test]
    fn global_field_max_txn_life() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

        assert_eq!(ctx.global_field(2).unwrap(), TealValue::Uint(1000));
    }

    #[test]
    fn global_field_zero_address() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

        assert_eq!(
            ctx.global_field(3).unwrap(),
            TealValue::Bytes(vec![0u8; 32])
        );
    }

    #[test]
    fn global_field_group_size() {
        let stxn1 = make_pay_stxn([0x10; 32]);
        let stxn2 = make_pay_stxn([0x20; 32]);
        let group = vec![stxn1, stxn2];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

        assert_eq!(ctx.global_field(4).unwrap(), TealValue::Uint(2));
    }

    #[test]
    fn global_field_logicsig_version() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let params = ConsensusParams::default();
        let expected_version = params.logic_sig_version;
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], params);

        assert_eq!(
            ctx.global_field(5).unwrap(),
            TealValue::Uint(expected_version)
        );
    }

    #[test]
    fn global_field_group_id() {
        let mut stxn = make_pay_stxn([0x10; 32]);
        stxn.txn.group = [0xAA; 32];
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

        assert_eq!(
            ctx.global_field(11).unwrap(),
            TealValue::Bytes(vec![0xAA; 32])
        );
    }

    #[test]
    fn global_field_group_id_empty() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

        // Empty group field should return 32 zero bytes.
        assert_eq!(
            ctx.global_field(11).unwrap(),
            TealValue::Bytes(vec![0u8; 32])
        );
    }

    #[test]
    fn global_field_asset_min_balances() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

        assert_eq!(ctx.global_field(15).unwrap(), TealValue::Uint(100_000)); // AssetCreateMinBalance
        assert_eq!(ctx.global_field(16).unwrap(), TealValue::Uint(100_000)); // AssetOptInMinBalance
    }

    #[test]
    fn global_field_genesis_hash() {
        let mut stxn = make_pay_stxn([0x10; 32]);
        stxn.txn.genesis_hash = [0xBB; 32];
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

        assert_eq!(
            ctx.global_field(17).unwrap(),
            TealValue::Bytes(vec![0xBB; 32])
        );
    }

    #[test]
    fn global_field_payouts_from_consensus() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        // V41 has payouts enabled with specific values.
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

        // PayoutsEnabled (18): V41 has payouts_enabled=true => 1
        assert_eq!(ctx.global_field(18).unwrap(), TealValue::Uint(1));
        // PayoutsGoOnlineFee (19): V41 = 2_000_000
        assert_eq!(ctx.global_field(19).unwrap(), TealValue::Uint(2_000_000));
        // PayoutsPercent (20): V41 = 50
        assert_eq!(ctx.global_field(20).unwrap(), TealValue::Uint(50));
        // PayoutsMinBalance (21): V41 = 30_000_000_000
        assert_eq!(
            ctx.global_field(21).unwrap(),
            TealValue::Uint(30_000_000_000)
        );
        // PayoutsMaxBalance (22): V41 = 70_000_000_000_000
        assert_eq!(
            ctx.global_field(22).unwrap(),
            TealValue::Uint(70_000_000_000_000)
        );
    }

    #[test]
    fn global_field_app_mode_only_returns_error() {
        let stxn = make_pay_stxn([0x10; 32]);
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

        // Round (6), LatestTimestamp (7), CurrentApplicationID (8),
        // CreatorAddress (9), CurrentApplicationAddress (10)
        for field_byte in [6, 7, 8, 9, 10, 13, 14] {
            let result = ctx.global_field(field_byte);
            assert!(
                result.is_err(),
                "global[{field_byte}] should error in LogicSig mode"
            );
            let msg = format!("{}", result.unwrap_err());
            assert!(
                msg.contains("not available in LogicSig"),
                "unexpected error for field {field_byte}: {msg}"
            );
        }
    }

    // ---- FirstValidTime / block_field tests ----
    //
    // Ported from go-algorand's `TestTxnFirstValidTime`
    // (`data/transactions/logic/eval_test.go#L362`), which deliberately runs
    // in `ModeSig` with the app-mode `Ledger` set to `nil` to prove
    // `FirstValidTime` works from `SigLedger` alone -- "it's not really a
    // field of a txn, but since it looks at the past of the blockchain, it
    // is 'stateless'". `MockSigLedger` here plays the role of go's fake test
    // `Ledger.BlockHdr`, whose `TimeStamp = 100 + 9*round/2` formula is
    // reused verbatim so the `== 104` / `== 109` assertions carry over
    // unchanged.

    /// Test double for [`SigBlockSource`]. Errors for any round with no
    /// stored timestamp, matching go's fake ledger having no header for
    /// round 0 (`BlockHdr` is only ever queried for rounds `>= 1` once
    /// `check_available_round` has run, but this also lets tests simulate
    /// "header missing" independent of the availability window).
    struct MockSigLedger {
        timestamps: std::collections::HashMap<u64, i64>,
    }

    impl MockSigLedger {
        fn new() -> Self {
            MockSigLedger {
                timestamps: std::collections::HashMap::new(),
            }
        }

        /// Seed round -> timestamp using go's fake-ledger formula:
        /// `TimeStamp = 100 + 9*round/2`.
        fn with_formula_rounds(rounds: impl IntoIterator<Item = u64>) -> Self {
            let mut ledger = Self::new();
            for round in rounds {
                ledger
                    .timestamps
                    .insert(round, 100 + (9 * round as i64) / 2);
            }
            ledger
        }
    }

    impl SigBlockSource for MockSigLedger {
        fn block_timestamp(&self, round: u64) -> Result<i64, AlgoError> {
            self.timestamps
                .get(&round)
                .copied()
                .ok_or_else(|| AlgoError::Avm {
                    message: format!("no block header for round {round}"),
                })
        }
    }

    /// FirstValid=current-10, LastValid=current+10: comfortably inside the
    /// availability window.
    #[test]
    fn first_valid_time_basic_window() {
        let current = 1000u64;
        let mut stxn = make_pay_stxn([0x10; 32]);
        stxn.txn.first_valid = algo_types::Round(current - 10);
        stxn.txn.last_valid = algo_types::Round(current + 10);
        let group = vec![stxn];
        let ledger = MockSigLedger::with_formula_rounds([current - 11]);
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default())
            .with_sig_ledger(&ledger);

        assert!(ctx.txn_field(0, 3, None).is_ok());
    }

    /// FirstValid == current: still available (round `current - 1`).
    #[test]
    fn first_valid_time_first_valid_equals_current() {
        let current = 1000u64;
        let mut stxn = make_pay_stxn([0x10; 32]);
        stxn.txn.first_valid = algo_types::Round(current);
        stxn.txn.last_valid = algo_types::Round(current + 10);
        let group = vec![stxn];
        let ledger = MockSigLedger::with_formula_rounds([current - 1]);
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default())
            .with_sig_ledger(&ledger);

        assert!(ctx.txn_field(0, 3, None).is_ok());
    }

    /// FirstValid = current - MaxTxnLife, LastValid = current: exactly at
    /// the oldest edge of the window (still available).
    #[test]
    fn first_valid_time_oldest_edge_of_window() {
        let current = 2000u64;
        let max_txn_life = 1000u64;
        let mut stxn = make_pay_stxn([0x10; 32]);
        stxn.txn.first_valid = algo_types::Round(current - max_txn_life);
        stxn.txn.last_valid = algo_types::Round(current);
        let group = vec![stxn];
        let ledger = MockSigLedger::with_formula_rounds([current - max_txn_life - 1]);
        let consensus = ConsensusParams {
            max_txn_life,
            ..ConsensusParams::default()
        };
        let ctx =
            LogicSigAvmContext::new(&group, 0, &[0x01], vec![], consensus).with_sig_ledger(&ledger);

        assert!(ctx.txn_field(0, 3, None).is_ok());
    }

    /// FirstValid = current - MaxTxnLife, LastValid = current + 1: the
    /// requested round now falls one below `firstAvail`, so it's
    /// unavailable -- go's comment notes this scenario "isn't really even
    /// possible because lifetime is too big" but nothing enforces that, so
    /// the error path is still reachable and must match go's wording.
    #[test]
    fn first_valid_time_errors_is_not_available() {
        let current = 2000u64;
        let max_txn_life = 1000u64;
        let mut stxn = make_pay_stxn([0x10; 32]);
        stxn.txn.first_valid = algo_types::Round(current - max_txn_life);
        stxn.txn.last_valid = algo_types::Round(current + 1);
        let group = vec![stxn];
        let ledger = MockSigLedger::new(); // header shouldn't even be queried
        let consensus = ConsensusParams {
            max_txn_life,
            ..ConsensusParams::default()
        };
        let ctx =
            LogicSigAvmContext::new(&group, 0, &[0x01], vec![], consensus).with_sig_ledger(&ledger);

        let err = ctx.txn_field(0, 3, None).unwrap_err();
        assert!(
            format!("{err}").contains("is not available"),
            "unexpected error: {err}"
        );
    }

    /// Beginning-of-chain-life cases, ported from go's low-round assertions:
    /// `FirstValid=2` -> round 1 -> timestamp 104; `FirstValid=3` -> round 2
    /// -> timestamp 109 (go's fake-ledger formula `100 + 9*round/2`).
    #[test]
    fn first_valid_time_early_chain_life_values() {
        let ledger = MockSigLedger::with_formula_rounds([1, 2]);
        let consensus = ConsensusParams::default();

        let mut stxn = make_pay_stxn([0x10; 32]);
        stxn.txn.first_valid = algo_types::Round(2);
        stxn.txn.last_valid = algo_types::Round(100);
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], consensus.clone())
            .with_sig_ledger(&ledger);
        assert_eq!(ctx.txn_field(0, 3, None).unwrap(), TealValue::Uint(104));

        let mut stxn2 = make_pay_stxn([0x10; 32]);
        stxn2.txn.first_valid = algo_types::Round(3);
        stxn2.txn.last_valid = algo_types::Round(100);
        let group2 = vec![stxn2];
        let ctx2 = LogicSigAvmContext::new(&group2, 0, &[0x01], vec![], consensus)
            .with_sig_ledger(&ledger);
        assert_eq!(ctx2.txn_field(0, 3, None).unwrap(), TealValue::Uint(109));
    }

    /// FirstValid=1 -> requested round 0, which is never available even
    /// though the naive range check would allow it -- "round 0 doesn't
    /// exist!" (go's comment, verbatim rationale).
    #[test]
    fn first_valid_time_round_zero_never_available() {
        let mut stxn = make_pay_stxn([0x10; 32]);
        stxn.txn.first_valid = algo_types::Round(1);
        stxn.txn.last_valid = algo_types::Round(100);
        let group = vec![stxn];
        let ledger = MockSigLedger::new();
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default())
            .with_sig_ledger(&ledger);

        let err = ctx.txn_field(0, 3, None).unwrap_err();
        assert!(
            format!("{err}").contains("round 0 is not available"),
            "unexpected error: {err}"
        );
    }

    /// FirstValid=1, LastValid=1+MaxTxnLife: glassbox case where
    /// `firstAvail` computes to depend on `LastValid - Lifetime - 1`, which
    /// again lands on round 0 -- still must be rejected.
    #[test]
    fn first_valid_time_glassbox_first_avail_zero() {
        let consensus = ConsensusParams::default();
        let mut stxn = make_pay_stxn([0x10; 32]);
        stxn.txn.first_valid = algo_types::Round(1);
        stxn.txn.last_valid = algo_types::Round(1 + consensus.max_txn_life);
        let group = vec![stxn];
        let ledger = MockSigLedger::new();
        let ctx =
            LogicSigAvmContext::new(&group, 0, &[0x01], vec![], consensus).with_sig_ledger(&ledger);

        let err = ctx.txn_field(0, 3, None).unwrap_err();
        assert!(
            format!("{err}").contains("round 0 is not available"),
            "unexpected error: {err}"
        );
    }

    /// No sig-ledger attached at all: matches go's `NoHeaderLedger`
    /// behavior ("no block header access") when a program is evaluated in
    /// true isolation, independent of the availability-window check.
    #[test]
    fn first_valid_time_errors_without_sig_ledger() {
        let mut stxn = make_pay_stxn([0x10; 32]);
        stxn.txn.first_valid = algo_types::Round(100);
        stxn.txn.last_valid = algo_types::Round(200);
        let group = vec![stxn];
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default());

        let err = ctx.txn_field(0, 3, None).unwrap_err();
        assert!(
            format!("{err}").contains("no block header access"),
            "unexpected error: {err}"
        );
    }

    /// `block BlkTimestamp` works the same way as `txn FirstValidTime` in
    /// LogicSig mode (both resolve through `block_field`), but other block
    /// fields remain unavailable.
    #[test]
    fn block_field_timestamp_and_other_fields() {
        let mut stxn = make_pay_stxn([0x10; 32]);
        stxn.txn.first_valid = algo_types::Round(100);
        stxn.txn.last_valid = algo_types::Round(200);
        let group = vec![stxn];
        let ledger = MockSigLedger::with_formula_rounds([50]);
        let ctx = LogicSigAvmContext::new(&group, 0, &[0x01], vec![], ConsensusParams::default())
            .with_sig_ledger(&ledger);

        let ts = ctx.block_field(50, BlockField::BlkTimestamp as u8).unwrap();
        assert_eq!(ts, AvmValue::Uint64(100 + 9 * 50 / 2));

        let err = ctx.block_field(50, BlockField::BlkSeed as u8).unwrap_err();
        assert!(
            format!("{err}").contains("not available in LogicSig mode"),
            "unexpected error: {err}"
        );
    }
}
