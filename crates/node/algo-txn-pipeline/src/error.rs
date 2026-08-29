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

//! Error type for the transaction pipeline.

use algo_kmd_client::KmdError;

/// Errors produced while building, signing, submitting, or confirming a
/// transaction through the [`TxnPipeline`](crate::TxnPipeline).
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// A keyreg builder input was malformed (e.g. a participation key field of
    /// the wrong size, or a missing state-proof key). Mirrors the validation in
    /// go-algorand's `libgoal.generateRegistrationTransaction`.
    #[error("invalid key registration input: {0}")]
    InvalidKeyreg(String),

    /// The requested validity window is invalid (e.g. `last_valid < first_valid`).
    #[error("invalid transaction validity window: {0}")]
    InvalidValidity(String),

    /// kmd signing requires a kmd client, but the pipeline was built without one.
    #[error("no kmd client configured; cannot sign transactions")]
    NoKmdClient,

    /// The transaction pool rejected the submitted transaction.
    #[error("transaction {txid} rejected by the pool: {pool_error}")]
    PoolRejected {
        /// The transaction id reported by the node.
        txid: String,
        /// The pool's rejection reason.
        pool_error: String,
    },

    /// The transaction was not committed by its last valid round (expired).
    #[error("transaction {txid} expired (not committed by last valid round {last_valid})")]
    NotConfirmed {
        /// The transaction id being awaited.
        txid: String,
        /// The transaction's last valid round.
        last_valid: u64,
    },

    /// An error talking to algod.
    #[error("algod request failed: {0}")]
    Algod(#[from] algo_error::AlgoError),

    /// An error talking to kmd.
    #[error("kmd request failed: {0}")]
    Kmd(#[from] KmdError),
}

/// Convenience result alias for pipeline operations.
pub type Result<T> = std::result::Result<T, PipelineError>;
