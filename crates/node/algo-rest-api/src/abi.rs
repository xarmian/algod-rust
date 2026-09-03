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

//! Re-export of the standalone [`algo_abi`] crate.
//!
//! The ARC-4 ABI type system (type parsing, JSON unmarshaling, binary
//! encode/decode, method-selector computation) used to live here as an
//! `algo-rest-api`-private module. It moved to `crates/core/algo-abi`
//! (issue #888) so `goal-rust`'s `app call`/`app method` ABI CLI subcommand
//! can share the same implementation instead of duplicating ~2000 lines of
//! type-system code and its ARC-4-vector-checked tests. This module keeps
//! `super::abi::*` working for existing callers (e.g. `box_name.rs`).

pub use algo_abi::*;
