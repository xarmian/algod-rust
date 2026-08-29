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

use clap::Subcommand;

use crate::unimplemented;

#[derive(Subcommand, Debug)]
pub enum KmdCmd {
    /// Start the kmd process, or restart it with an updated timeout.
    Start,
    /// Stop the kmd process if it is running.
    Stop,
}

pub fn run(cmd: KmdCmd) -> ExitCode {
    let leaf = match cmd {
        KmdCmd::Start => "start",
        KmdCmd::Stop => "stop",
    };
    unimplemented("kmd", leaf)
}
