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

//! `goal ledger` — port of `../go-algorand/cmd/goal/ledger.go`.

use std::process::ExitCode;

use clap::{Args, Subcommand};

#[derive(Subcommand, Debug)]
pub enum LedgerCmd {
    /// Dump a block to a file or stdout.
    Block(BlockArgs),
    /// Show ledger token supply.
    Supply,
}

/// go: `blockCmd`'s flags (`cmd/goal/ledger.go`).
#[derive(Args, Debug)]
pub struct BlockArgs {
    /// The round number.
    pub round: String,
    /// The filename to dump the block to (if not set, use stdout).
    #[arg(short = 'o', long = "out", default_value = "-")]
    pub out: String,
    /// Format block as msgpack.
    #[arg(short = 'r', long = "raw")]
    pub raw: bool,
    /// Encode binary blobs using base32 instead of base64.
    #[arg(long = "b32")]
    pub b32: bool,
    /// Strict JSON decode: turn all keys into strings.
    #[arg(long = "strict")]
    pub strict: bool,
}

pub fn run(cmd: LedgerCmd) -> ExitCode {
    match cmd {
        LedgerCmd::Block(args) => crate::cmd::ledger::run_block(args, crate::cli_state::datadirs()),
        LedgerCmd::Supply => crate::cmd::node::run_ledger_supply(crate::cli_state::datadirs()),
    }
}
