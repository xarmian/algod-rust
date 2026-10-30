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

use thiserror::Error;

/// A single AVM value captured for structured diagnostics on a LogicSig
/// evaluation failure. Mirrors go-algorand's untyped `stackValue.asAny()`
/// (`data/transactions/logic/eval.go`), which is always either a uint64 or
/// a byte slice — kept independent of `algo_types::TealValue` to avoid a
/// dependency cycle (`algo-types` already depends on `algo-error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvmDiagnosticValue {
    /// An unsigned 64-bit integer value.
    Uint(u64),
    /// A byte-string value.
    Bytes(Vec<u8>),
}

/// One transaction's scratch space and operand stack, captured at the point
/// of a LogicSig evaluation failure. Mirrors go-algorand's `evalState`
/// struct (`data/transactions/logic/eval.go`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AvmEvalStateDump {
    /// Scratch-space slots, trimmed to one past the highest non-zero/
    /// non-empty index (matching go's `evalStates()` trimming); empty if
    /// every slot is still at its zero value.
    pub scratch: Vec<AvmDiagnosticValue>,
    /// Operand stack contents at the point of failure. Only ever populated
    /// for the failing transaction itself — matching go, which keeps only
    /// the *currently executing* program's stack live in `eval-states`.
    pub stack: Vec<AvmDiagnosticValue>,
}

#[derive(Debug, Error)]
pub enum AlgoError {
    #[error("codec error: {context}")]
    Codec {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        context: String,
    },

    #[error("REST client error: {context}")]
    RestClient {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        context: String,
    },

    /// A peer answered a round-specific block fetch with a block for the
    /// wrong round. Mirrors go's `errWrongBlockFromPeer`
    /// (`catchup/universalFetcher.go`), raised by `processBlockBytes` when
    /// `decodedEntry.Block.Round() != r`.
    #[error("wrong block from peer: requested round {expected}, got block for round {got}")]
    WrongBlockFromPeer {
        /// The round that was requested.
        expected: u64,
        /// The round the peer's block was actually for.
        got: u64,
    },

    /// A peer answered a round-specific block fetch with a certificate for
    /// the wrong round. Mirrors go's `errWrongCertFromPeer`
    /// (`catchup/universalFetcher.go`), raised by `processBlockBytes` when
    /// `decodedEntry.Certificate.Round != r`.
    #[error("wrong cert from peer: requested round {expected}, got cert for round {got}")]
    WrongCertFromPeer {
        /// The round that was requested.
        expected: u64,
        /// The round the peer's certificate was actually for.
        got: u64,
    },

    #[error("conformance error: {message}")]
    Conformance { message: String },

    #[error("not found: {0}")]
    NotFound(String),

    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error("validation error: {message}")]
    Validation { message: String },

    #[error("ledger error: {message}")]
    Ledger { message: String },

    /// go's `validateForPayouts` rejected a block header (fees collected,
    /// proposer or proposer payout fields). A genuine verdict on the block,
    /// kept distinct from every other evaluation failure so it can never be
    /// mistaken for "could not evaluate".
    #[error("{message}")]
    PayoutViolation { message: String },

    #[error("AVM: {message}")]
    Avm { message: String },

    /// A transaction-evaluation failure whose text is go-algorand's verbatim
    /// (`transaction <txid>: <reason>`, as `eval.TransactionGroup` returns
    /// it), with no algod-rust category prefix, so the pool/REST layers can
    /// surface exactly go's `TransactionPool.Remember: ...` message.
    #[error("{message}")]
    Eval { message: String },

    /// An application call to an application that does not exist (and is
    /// not ClearState). go: `ledger/apply/application.go` `ApplicationCall`
    /// (`only ClearState is supported for an application (%d) that does not
    /// exist`). Typed so the pool maps the type, not message text.
    #[error("appl: app {app_id} does not exist")]
    AppDoesNotExist { app_id: u64 },

    /// An approval program rejected the transaction. `reason` is the runtime
    /// error that ended the program, `None` for a clean reject (go:
    /// `ledgercore.ApprovalProgramRejectedError` vs `logic.EvalError`).
    #[error("appl execute: app {app_id} approval program rejected transaction{}", .reason.as_ref().map(|r| format!(": {r}")).unwrap_or_default())]
    ApprovalRejected { app_id: u64, reason: Option<String> },

    /// The pool/proposer evaluator refused a transaction. `message` is go's
    /// `transaction <txid>: <reason>` text verbatim; `class` is the pool
    /// error-tag family; `source` keeps the underlying error (and so any
    /// structured AVM diagnostics, see [`AlgoError::avm_eval_detail`]).
    #[error("{message}")]
    Rejected {
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        message: String,
        class: RejectClass,
    },

    /// An AVM evaluation failure, enriched with go-algorand-style structured
    /// diagnostics (pc, group index, app index, per-transaction
    /// scratch/stack dump). Mirrors go's `basics.SError`/`EvalError`
    /// attributes, attached by `cx.evalError()`
    /// (`data/transactions/logic/eval.go`) — see `TestLogicErrorDetails` in
    /// go's `eval_test.go`. Despite the name (kept for compatibility with
    /// its original LogicSig-only introduction in issue #1113), this variant
    /// now also covers app-call (approval/clear-state program) evaluation
    /// failures (issue #1135) — `app_index` distinguishes the two: `None`
    /// for a LogicSig (`ModeSig`), `Some(app_id)` for an app call
    /// (`ModeApp`), matching go's `if cx.runMode == ModeApp { ... }` gate.
    /// Wraps whatever underlying error the AVM machine raised (usually
    /// [`AlgoError::Avm`]) as its source, so `Error::source()`/`Unwrap()`-style
    /// chaining still reaches the original message.
    #[error("{message}")]
    AvmLogicSig {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        message: String,
        /// Instruction index at which evaluation failed.
        pc: usize,
        /// Index of the failing transaction within its group.
        group_index: usize,
        /// The application ID, when this failure occurred while evaluating
        /// an app-call program (`ModeApp`). `None` for a LogicSig failure
        /// (`ModeSig`), mirroring go's `cx.runMode == ModeApp` gate on
        /// attaching the `app-index` attribute.
        app_index: Option<u64>,
        /// Scratch/stack dumps for transactions `0..=group_index`. Mirrors
        /// go's `eval-states` attribute; unlike go, algod-rust's evaluators
        /// do not thread cross-transaction scratch state across sibling
        /// programs, so entries other than `eval_states[group_index]` carry
        /// an empty dump.
        eval_states: Vec<AvmEvalStateDump>,
    },

    #[error("network error: {message}")]
    Network { message: String },
}

/// Pool error-tag family of an [`AlgoError::Rejected`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectClass {
    /// Any other reason (classified from its text by the pool).
    Other,
    /// Approval program returned false (go `ApprovalProgramRejectedError`).
    TealReject,
    /// Approval program errored (go `logic.EvalError`).
    TealErr,
    /// go `ledgercore.TransactionInLedgerError` from `checkDup`: the txid is
    /// already in the ledger, or (`in_block`, go `InBlockEvaluator`) earlier
    /// in the block being evaluated. go's pool tags it `txid` / `txid_eval`.
    TxidInLedger { in_block: bool },
    /// go `ledgercore.LeaseInLedgerError` from `checkDup` (`in_block` as
    /// above). go's pool tags it `lease` / `lease_eval`.
    LeaseInLedger { in_block: bool },
    /// go `Transaction.Alive` in the validating evaluator's prologue (a
    /// `bookkeeping.TxnDeadError`, or a genesis id / hash mismatch), which
    /// go returns bare, with no `transaction <txid>:` frame. go's pool tags
    /// it from the error (`txn_dead` / `txn_early`, else `eval`).
    Alive,
}

pub type Result<T> = std::result::Result<T, AlgoError>;

/// A plain, `Clone`-able snapshot of [`AlgoError::AvmLogicSig`]'s structured
/// diagnostics, for carrying pc/group-index/app-index/eval-states detail
/// across API boundaries that need `Clone` (e.g. [`AlgoError`] itself is not
/// `Clone` because it wraps a `Box<dyn Error>`) — notably
/// `algo_avm::eval::AvmResult` and the REST API's error responses. Mirrors
/// go's `basics.SError.Attrs`, threaded from `evalError()` through to
/// `returnError()` (`daemon/algod/api/server/v2/utils.go`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AvmErrorDetail {
    /// Instruction index at which evaluation failed.
    pub pc: usize,
    /// Index of the failing transaction within its group.
    pub group_index: usize,
    /// The application ID, for an app-call (`ModeApp`) failure; `None` for
    /// a LogicSig (`ModeSig`) failure.
    pub app_index: Option<u64>,
    /// Scratch/stack dumps for transactions `0..=group_index`.
    pub eval_states: Vec<AvmEvalStateDump>,
}

/// go-algorand's `crypto.ErrBatchHasFailedSigs` text
/// (`crypto/batchverifier.go:70`). go verifies every ed25519 signature of a
/// group through one batch verifier and reports any failure with exactly this
/// message, with no transaction attribution and no wrapping.
pub const BATCH_HAS_FAILED_SIGS: &str = "At least one signature didn't pass verification";

impl AlgoError {
    /// Whether this is go's batch signature-verification failure
    /// ([`BATCH_HAS_FAILED_SIGS`]): a signature (plain, rekeyed, delegated
    /// LogicSig or multisig sub-signature) that does not verify.
    pub fn is_batch_sig_failure(&self) -> bool {
        matches!(self, AlgoError::Validation { message } if message == BATCH_HAS_FAILED_SIGS)
    }

    /// Extract this error's structured AVM diagnostics, if it is (or wraps,
    /// via `source()`) an [`AlgoError::AvmLogicSig`]. Mirrors go's
    /// `errors.As(internal, &se)` unwrap in `returnError()`
    /// (`daemon/algod/api/server/v2/utils.go:51`), which walks the error
    /// chain looking for a `*basics.SError`.
    pub fn avm_eval_detail(&self) -> Option<AvmErrorDetail> {
        let mut cur: &(dyn std::error::Error + 'static) = self;
        loop {
            if let Some(AlgoError::AvmLogicSig {
                pc,
                group_index,
                app_index,
                eval_states,
                ..
            }) = cur.downcast_ref::<AlgoError>()
            {
                return Some(AvmErrorDetail {
                    pc: *pc,
                    group_index: *group_index,
                    app_index: *app_index,
                    eval_states: eval_states.clone(),
                });
            }
            cur = cur.source()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_sig_failure_is_recognised_only_for_gos_exact_text() {
        let e = AlgoError::Validation {
            message: BATCH_HAS_FAILED_SIGS.to_string(),
        };
        assert!(e.is_batch_sig_failure());
        assert_eq!(BATCH_HAS_FAILED_SIGS, "At least one signature didn't pass verification");
        for other in [
            AlgoError::Validation {
                message: "transaction has no signature".into(),
            },
            AlgoError::Ledger {
                message: BATCH_HAS_FAILED_SIGS.to_string(),
            },
        ] {
            assert!(!other.is_batch_sig_failure(), "{other}");
        }
    }
}
