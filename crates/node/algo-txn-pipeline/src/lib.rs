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

//! `algo-txn-pipeline` — the shared build → sign → submit → confirm path for
//! the Rust operator toolchain (`goal-rust`, and Phase C `clerk`).
//!
//! This crate composes the algod REST client (`algo-rest-client`) and the kmd
//! wallet client (`algo-kmd-client`) into a single [`TxnPipeline`], plus pure,
//! unit-testable transaction builders. It lives in the node/client layer rather
//! than `core/` because it depends on async networking — `core/*` crates must
//! not (see `docs/CRATE_ARCHITECTURE.md`).
//!
//! Today it ships the [`KeyregBuilder`] (key registration) and
//! [`PaymentBuilder`] (payments); Phase C extends the pipeline with
//! asset-transfer / asset-config / asset-freeze / application builders, each a
//! small follow-on against this same surface.

mod application_call;
mod error;
mod keyreg;
mod payment;
mod pipeline;

pub use application_call::ApplicationCallBuilder;
pub use error::{PipelineError, Result};
pub use keyreg::KeyregBuilder;
pub use payment::PaymentBuilder;
pub use pipeline::{estimate_fee, TxnPipeline};

// Re-export the client-layer types a consumer needs so they don't have to
// depend on `algo-rest-client` directly just to name a pipeline input/output.
pub use algo_rest_client::{AccountParticipation, PendingTxnInfo, SuggestedParams, TxId};
