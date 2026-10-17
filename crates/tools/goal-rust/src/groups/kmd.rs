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

//! `goal kmd` — port of `../go-algorand/cmd/goal/kmd.go`.

use std::process::ExitCode;

use clap::{Args, Subcommand};

#[derive(Subcommand, Debug)]
pub enum KmdCmd {
    /// Start the kmd process, or restart it with an updated timeout.
    Start(StartArgs),
    /// Stop the kmd process if it is running.
    Stop,
}

/// `startKMDCmd` flags (`cmd/goal/kmd.go:31`).
#[derive(Args, Debug, Default)]
pub struct StartArgs {
    /// Number of seconds after which to shut down kmd if there are no
    /// requests; 0 means no timeout.
    #[arg(short = 't', long = "timeout", default_value_t = 0)]
    pub timeout: u64,
}

pub fn run(cmd: KmdCmd) -> ExitCode {
    match cmd {
        KmdCmd::Start(args) => crate::cmd::kmd::run_start(args, crate::cli_state::datadirs(), crate::cli_state::kmddir()),
        KmdCmd::Stop => crate::cmd::kmd::run_stop(crate::cli_state::datadirs(), crate::cli_state::kmddir()),
    }
}
