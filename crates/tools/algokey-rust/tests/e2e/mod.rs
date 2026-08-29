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

//! End-to-end test harness for `algokey-rust` (TASK-184).
//!
//! Drives a live `algod-go` localnet brought up via `make localnet-up`.
//! Used by the smoke test (TASK-184), the headline keyreg flow (TASK-185),
//! and the bidirectional compatibility matrices (TASK-199, TASK-200).
//!
//! All entry points are async on top of `tokio`. The harness intentionally
//! shells out to `make localnet-up` / `make localnet-down` rather than
//! reimplementing docker-compose, and uses `docker exec algod-go goal ...`
//! to extract the genesis-funded mnemonic (the only way to get the secret
//! seed — algod's REST API does not expose it).
//!
//! Default `cargo test -p algokey-rust` does NOT compile this module —
//! it's gated by the `e2e` cargo feature on the test target.

// The re-exports below are the harness's public surface. Not every test
// uses every symbol (the smoke test in TASK-184 exercises a subset; TASK-185
// uses fund_address, TASK-199/200 use ParticipationFields, etc.), so the
// allow keeps the per-test warning surface clean.
#![allow(unused_imports, dead_code)]

pub mod accounts;
pub mod compat_framework;
pub mod localnet;
pub mod submission;

pub use accounts::{discover_faucet, fund_address, FundedAccount};
pub use localnet::Localnet;
pub use submission::{
    get_account_status, submit_raw_txn, wait_for_confirmation, AccountStatus, ConfirmedTxn,
    ParticipationFields,
};
