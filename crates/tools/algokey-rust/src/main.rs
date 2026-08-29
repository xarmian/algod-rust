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

//! `algokey-rust` — Rust port of `../go-algorand/cmd/algokey`.
//!
//! Phase A: every subcommand prints "not implemented" to stderr and exits
//! with code 2. TASK-157, TASK-158, TASK-159 fill `generate`, `import`,
//! and `export`. Later phases (B, C) fill `sign`, `multisig`, `part`, and
//! `keyreg`.

mod cli;
mod commands;
mod common;
mod ui;

use std::process::ExitCode;

use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Command, MultisigSub, PartSub};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Generate(args) => commands::generate::run(args),
        Command::Import(args) => commands::import::run(args),
        Command::Export(args) => commands::export::run(args),
        Command::Sign(args) => commands::sign::run(args),
        Command::Multisig(m) => match m.command {
            None => commands::multisig::sign::run(m),
            Some(MultisigSub::AppendAuthAddr(args)) => {
                commands::multisig::append_auth_addr::run(args)
            }
        },
        Command::Part(p) => match p.command {
            // Go's `partCmd.Run` (part.go:43-46) prints help when `part`
            // is invoked with no subcommand. Mirror that exactly.
            None => {
                let mut root = Cli::command();
                let part = root
                    .find_subcommand_mut("part")
                    .expect("`part` is a registered subcommand");
                let _ = part.print_help();
                println!();
                ExitCode::SUCCESS
            }
            Some(PartSub::Keyreg(args)) => commands::keyreg::run(args),
            Some(PartSub::Info(args)) => commands::part::info::run(args),
            Some(PartSub::Generate(args)) => commands::part::generate::run(args),
            Some(PartSub::Reparent(args)) => commands::part::reparent::run(args),
        },
    }
}

// All Phase A stub leaves are now backed by real implementations:
// TASK-157 (generate), TASK-158 (import), TASK-159 (export),
// TASK-167 (sign), TASK-168 (multisig sign),
// TASK-169 (multisig append-auth-addr), TASK-170 (part keyreg),
// TASK-179 (part info), TASK-180 (part generate), and
// TASK-181 (part reparent) — so `not_implemented` is no longer
// referenced and has been removed.
