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

    #[error("AVM: {message}")]
    Avm { message: String },

    /// A LogicSig evaluation failure, enriched with go-algorand-style
    /// structured diagnostics (pc, group index, per-transaction
    /// scratch/stack dump). Mirrors go's `EvalError` attributes, attached
    /// by `cx.evalError()` (`data/transactions/logic/eval.go`) — see
    /// `TestLogicErrorDetails` in go's `eval_test.go`. Wraps whatever
    /// underlying error the AVM machine raised (usually [`AlgoError::Avm`])
    /// as its source, so `Error::source()`/`Unwrap()`-style chaining still
    /// reaches the original message.
    #[error("AVM: {message}")]
    AvmLogicSig {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        message: String,
        /// Instruction index at which evaluation failed.
        pc: usize,
        /// Index of the failing transaction within its group.
        group_index: usize,
        /// Scratch/stack dumps for transactions `0..=group_index`. Mirrors
        /// go's `eval-states` attribute; unlike go, algod-rust's LogicSig
        /// evaluator does not thread cross-transaction scratch state across
        /// sibling delegated programs, so entries other than
        /// `eval_states[group_index]` carry an empty dump.
        eval_states: Vec<AvmEvalStateDump>,
    },

    #[error("network error: {message}")]
    Network { message: String },
}

pub type Result<T> = std::result::Result<T, AlgoError>;
