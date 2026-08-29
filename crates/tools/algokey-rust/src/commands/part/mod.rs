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

//! `algokey part` subcommand implementations.
//!
//! Mirrors `../go-algorand/cmd/algokey/part.go`:
//! - `info` — read partkey + print fields (TASK-179, this PR).
//! - `generate` — full keygen + persist (TASK-180, follow-up).
//! - `reparent` — UPDATE parent column (TASK-181, follow-up).
//!
//! Until TASK-180 / TASK-181 land, dispatch for `generate` / `reparent`
//! still routes through `main.rs`'s `not_implemented` stub.

pub mod generate;
pub mod info;
pub mod print_partkey;
pub mod reparent;
