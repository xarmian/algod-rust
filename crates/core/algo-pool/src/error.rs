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

use std::fmt;

use algo_types::Digest;
use thiserror::Error;

/// Pool-level errors matching go-algorand's `data/pools/errors.go`.
///
/// Error messages are kept byte-identical to the Go implementation
/// so that conformance tests can compare strings directly.
#[derive(Debug, Error)]
pub enum PoolError {
    /// The transaction pool has reached its maximum capacity.
    ///
    /// Corresponds to `ErrPendingQueueReachedMaxCap` in Go.
    #[error("TransactionPool.checkPendingQueueSize: transaction pool have reached capacity")]
    PendingQueueFull,

    /// No pending block evaluator is available to accept transactions.
    ///
    /// Corresponds to `ErrNoPendingBlockEvaluator` in Go.
    #[error("TransactionPool.ingest: no pending block evaluator")]
    NoPendingBlockEvaluator,

    /// The requested block assembly round is older than the current pool round.
    ///
    /// Corresponds to `ErrStaleBlockAssemblyRequest` in Go.
    #[error("AssembleBlock: requested block assembly specified a round that is older than current transaction pool round")]
    StaleBlockAssemblyRequest,

    /// Transaction fee is below the pool's dynamic fee threshold.
    ///
    /// Corresponds to `ErrTxPoolFeeError` in Go.
    /// Format: `"fee {fee} below threshold {threshold} ({per_byte} per byte * {encoded_len} bytes)"`
    #[error("{}", FeeErrorDisplay { fee: *fee, fee_threshold: *fee_threshold, fee_per_byte: *fee_per_byte, encoded_len: *encoded_len })]
    FeeBelowThreshold {
        fee: u64,
        fee_threshold: u64,
        fee_per_byte: u64,
        encoded_len: u64,
    },

    /// The transaction pool is shutting down.
    ///
    /// Corresponds to `errPoolShutdown` in Go (unexported).
    #[error("transaction pool is shutting down")]
    PoolShutdown,

    /// A transaction with the same ID is already in the pool.
    ///
    /// In go-algorand this is detected by the evaluator's `TransactionGroup`
    /// call, but we also check explicitly in the pool for early rejection.
    #[error("transaction already in the pool: {0}")]
    DuplicateTxn(Digest),

    /// A transaction with the same ID is already confirmed in a
    /// recently-committed block. Mirrors go's
    /// `ledgercore.TransactionInLedgerError` ("transaction already in
    /// ledger: %v"), raised by the evaluator's `TestTransactionGroup` via
    /// the ledger's txtail duplicate check (`ledger/txtail.go`'s
    /// `checkDup`).
    #[error("transaction already in ledger: {0}")]
    AlreadyInLedger(Digest),

    /// Wraps an inner error from the block evaluator.
    #[error("TransactionPool.ingest: {0}")]
    Evaluator(String),

    /// The transaction's lease is already recorded for the sender within
    /// the relevant round window.
    ///
    /// Mirrors go-algorand's `ledgercore.LeaseInLedgerError`. `in_block_evaluator`
    /// mirrors its `InBlockEvaluator` field: `true` when the conflict was
    /// discovered while the pool's block evaluator was being rebuilt during
    /// re-evaluation (`TxPoolErrTagLeaseEval`), `false` when discovered
    /// during a normal `Remember()` (`TxPoolErrTagLease`).
    #[error("TransactionPool.ingest: {message}")]
    LeaseConflict {
        message: String,
        in_block_evaluator: bool,
    },

    /// Wraps an inner error with `"TransactionPool.Remember: "` prefix,
    /// matching Go's `fmt.Errorf("TransactionPool.Remember: %w", err)`.
    #[error("TransactionPool.Remember: {0}")]
    Remember(Box<PoolError>),
}

/// Helper to format the fee error message identically to Go's
/// `fmt.Sprintf("fee %d below threshold %d (%d per byte * %d bytes)", ...)`.
struct FeeErrorDisplay {
    fee: u64,
    fee_threshold: u64,
    fee_per_byte: u64,
    encoded_len: u64,
}

impl fmt::Display for FeeErrorDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fee {} below threshold {} ({} per byte * {} bytes)",
            self.fee, self.fee_threshold, self.fee_per_byte, self.encoded_len
        )
    }
}

/// Error classification tags matching Go's `TxPoolErrTag*` constants.
///
/// Used for metrics and error categorization, mirroring `ClassifyTxPoolError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PoolErrorTag {
    Cap,
    PendingEval,
    NoSpace,
    Fee,
    TxnDead,
    TxnEarly,
    TooLarge,
    GroupId,
    TxId,
    Lease,
    TxIdEval,
    LeaseEval,
    NotWell,
    TealErr,
    TealReject,
    MinBalance,
    Overspend,
    AssetBalance,
    EvalGeneric,
}

impl PoolErrorTag {
    /// Returns the string tag matching Go's constant value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cap => "cap",
            Self::PendingEval => "pending_eval",
            Self::NoSpace => "no_space",
            Self::Fee => "fee",
            Self::TxnDead => "txn_dead",
            Self::TxnEarly => "txn_early",
            Self::TooLarge => "too_large",
            Self::GroupId => "groupid",
            Self::TxId => "txid",
            Self::Lease => "lease",
            Self::TxIdEval => "txid_eval",
            Self::LeaseEval => "lease_eval",
            Self::NotWell => "not_well",
            Self::TealErr => "teal_err",
            Self::TealReject => "teal_reject",
            Self::MinBalance => "min_balance",
            Self::Overspend => "overspend",
            Self::AssetBalance => "asset_bal",
            Self::EvalGeneric => "eval",
        }
    }

    /// All tag variants in the same order as Go's `TxPoolErrTags` slice.
    pub const ALL: &'static [PoolErrorTag] = &[
        Self::Cap,
        Self::PendingEval,
        Self::NoSpace,
        Self::Fee,
        Self::TxnDead,
        Self::TxnEarly,
        Self::TooLarge,
        Self::GroupId,
        Self::TxId,
        Self::Lease,
        Self::TxIdEval,
        Self::LeaseEval,
        Self::NotWell,
        Self::TealErr,
        Self::TealReject,
        Self::MinBalance,
        Self::Overspend,
        Self::AssetBalance,
        Self::EvalGeneric,
    ];
}

impl fmt::Display for PoolErrorTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classify a `PoolError` into a `PoolErrorTag` for metrics.
///
/// This mirrors Go's `ClassifyTxPoolError`. Go dispatches on the concrete
/// Go error type returned by the block evaluator (`errors.As` down the
/// wrapped chain: `OverspendError`, `MinBalanceError`,
/// `AssetBalanceError`, `ApprovalProgramRejectedError`, `logic.EvalError`,
/// etc. — see `data/pools/errors.go`'s `ClassifyTxPoolError`). algod-rust's
/// pool abstracts the evaluator behind `BlockEvaluator::transaction_group`,
/// which returns only a message string (`PoolError::Evaluator`), so the
/// equivalent categories are recovered from the message text produced by
/// `algo-ledger`'s `apply.rs` (each pattern below is quoted verbatim from
/// its source location there).
pub fn classify_pool_error(err: &PoolError) -> PoolErrorTag {
    match err {
        PoolError::PendingQueueFull => PoolErrorTag::Cap,
        PoolError::NoPendingBlockEvaluator => PoolErrorTag::PendingEval,
        PoolError::FeeBelowThreshold { .. } => PoolErrorTag::Fee,
        PoolError::StaleBlockAssemblyRequest => PoolErrorTag::EvalGeneric,
        PoolError::PoolShutdown => PoolErrorTag::EvalGeneric,
        PoolError::DuplicateTxn(_) => PoolErrorTag::TxId,
        PoolError::AlreadyInLedger(_) => PoolErrorTag::TxId,
        PoolError::Evaluator(msg) => classify_evaluator_message(msg),
        PoolError::LeaseConflict {
            in_block_evaluator, ..
        } => {
            if *in_block_evaluator {
                PoolErrorTag::LeaseEval
            } else {
                PoolErrorTag::Lease
            }
        }
        PoolError::Remember(inner) => classify_pool_error(inner),
    }
}

/// Sub-classify a block-evaluator failure message into a `PoolErrorTag`.
///
/// The substrings matched here come from `algo-ledger`'s `apply.rs`:
/// - `"...approval program rejected transaction: <err>"` (has a runtime
///   error appended) => `TealErr`, mirroring Go's `logic.EvalError` case.
/// - `"...approval program rejected transaction"` (no runtime error
///   appended — the program simply returned false) => `TealReject`,
///   mirroring Go's `ledgercore.ApprovalProgramRejectedError` case.
/// - `"...holding ... insufficient for transfer ..."` => `AssetBalance`,
///   mirroring Go's `ledgercore.AssetBalanceError` case.
/// - `"...balance ... below minimum balance ..."` => `MinBalance`,
///   mirroring Go's `ledgercore.MinBalanceError` case.
/// - `"...insufficient balance ... for fee/payment ..."` => `Overspend`,
///   mirroring Go's `ledgercore.OverspendError` case.
fn classify_evaluator_message(msg: &str) -> PoolErrorTag {
    if msg.contains("approval program rejected transaction:") {
        PoolErrorTag::TealErr
    } else if msg.contains("approval program rejected transaction") {
        PoolErrorTag::TealReject
    } else if msg.contains("insufficient for transfer") {
        PoolErrorTag::AssetBalance
    } else if msg.contains("below minimum balance") {
        PoolErrorTag::MinBalance
    } else if msg.contains("insufficient balance") {
        PoolErrorTag::Overspend
    } else {
        PoolErrorTag::EvalGeneric
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_string_pending_queue_full() {
        let err = PoolError::PendingQueueFull;
        assert_eq!(
            err.to_string(),
            "TransactionPool.checkPendingQueueSize: transaction pool have reached capacity"
        );
    }

    #[test]
    fn error_string_no_pending_block_evaluator() {
        let err = PoolError::NoPendingBlockEvaluator;
        assert_eq!(
            err.to_string(),
            "TransactionPool.ingest: no pending block evaluator"
        );
    }

    #[test]
    fn error_string_stale_block_assembly_request() {
        let err = PoolError::StaleBlockAssemblyRequest;
        assert_eq!(
            err.to_string(),
            "AssembleBlock: requested block assembly specified a round that is older than current transaction pool round"
        );
    }

    #[test]
    fn error_string_fee_below_threshold() {
        let err = PoolError::FeeBelowThreshold {
            fee: 100,
            fee_threshold: 200,
            fee_per_byte: 2,
            encoded_len: 100,
        };
        assert_eq!(
            err.to_string(),
            "fee 100 below threshold 200 (2 per byte * 100 bytes)"
        );
    }

    #[test]
    fn error_string_fee_matches_go_format() {
        // Mirrors Go: fmt.Sprintf("fee %d below threshold %d (%d per byte * %d bytes)", 500, 1000, 5, 200)
        let err = PoolError::FeeBelowThreshold {
            fee: 500,
            fee_threshold: 1000,
            fee_per_byte: 5,
            encoded_len: 200,
        };
        assert_eq!(
            err.to_string(),
            "fee 500 below threshold 1000 (5 per byte * 200 bytes)"
        );
    }

    #[test]
    fn error_string_pool_shutdown() {
        let err = PoolError::PoolShutdown;
        assert_eq!(err.to_string(), "transaction pool is shutting down");
    }

    #[test]
    fn error_string_remember_wraps_inner() {
        let inner = PoolError::NoPendingBlockEvaluator;
        let err = PoolError::Remember(Box::new(inner));
        assert_eq!(
            err.to_string(),
            "TransactionPool.Remember: TransactionPool.ingest: no pending block evaluator"
        );
    }

    #[test]
    fn error_string_remember_wraps_fee() {
        let inner = PoolError::FeeBelowThreshold {
            fee: 100,
            fee_threshold: 500,
            fee_per_byte: 5,
            encoded_len: 100,
        };
        let err = PoolError::Remember(Box::new(inner));
        assert_eq!(
            err.to_string(),
            "TransactionPool.Remember: fee 100 below threshold 500 (5 per byte * 100 bytes)"
        );
    }

    #[test]
    fn classify_pool_errors() {
        assert_eq!(
            classify_pool_error(&PoolError::PendingQueueFull),
            PoolErrorTag::Cap
        );
        assert_eq!(
            classify_pool_error(&PoolError::NoPendingBlockEvaluator),
            PoolErrorTag::PendingEval
        );
        assert_eq!(
            classify_pool_error(&PoolError::FeeBelowThreshold {
                fee: 0,
                fee_threshold: 0,
                fee_per_byte: 0,
                encoded_len: 0,
            }),
            PoolErrorTag::Fee
        );
    }

    #[test]
    fn classify_remember_delegates_to_inner() {
        let inner = PoolError::PendingQueueFull;
        let err = PoolError::Remember(Box::new(inner));
        assert_eq!(classify_pool_error(&err), PoolErrorTag::Cap);
    }

    #[test]
    fn pool_error_tag_strings_match_go() {
        assert_eq!(PoolErrorTag::Cap.as_str(), "cap");
        assert_eq!(PoolErrorTag::PendingEval.as_str(), "pending_eval");
        assert_eq!(PoolErrorTag::NoSpace.as_str(), "no_space");
        assert_eq!(PoolErrorTag::Fee.as_str(), "fee");
        assert_eq!(PoolErrorTag::TxnDead.as_str(), "txn_dead");
        assert_eq!(PoolErrorTag::TxnEarly.as_str(), "txn_early");
        assert_eq!(PoolErrorTag::TooLarge.as_str(), "too_large");
        assert_eq!(PoolErrorTag::GroupId.as_str(), "groupid");
        assert_eq!(PoolErrorTag::TxId.as_str(), "txid");
        assert_eq!(PoolErrorTag::Lease.as_str(), "lease");
        assert_eq!(PoolErrorTag::TxIdEval.as_str(), "txid_eval");
        assert_eq!(PoolErrorTag::LeaseEval.as_str(), "lease_eval");
        assert_eq!(PoolErrorTag::NotWell.as_str(), "not_well");
        assert_eq!(PoolErrorTag::TealErr.as_str(), "teal_err");
        assert_eq!(PoolErrorTag::TealReject.as_str(), "teal_reject");
        assert_eq!(PoolErrorTag::MinBalance.as_str(), "min_balance");
        assert_eq!(PoolErrorTag::Overspend.as_str(), "overspend");
        assert_eq!(PoolErrorTag::AssetBalance.as_str(), "asset_bal");
        assert_eq!(PoolErrorTag::EvalGeneric.as_str(), "eval");
    }

    #[test]
    fn pool_error_tag_all_count() {
        // Go has 19 tags in TxPoolErrTags
        assert_eq!(PoolErrorTag::ALL.len(), 19);
    }
}
