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

//! `goal network` — port of `../go-algorand/cmd/goal/network.go`.

use std::process::ExitCode;

use clap::Subcommand;

use crate::unimplemented;

#[derive(Subcommand, Debug)]
pub enum NetworkCmd {
    /// Create a private named network from a template.
    Create,
    /// Stops and Deletes a deployed private network.
    Delete,
    /// Pregenerate private network.
    Pregen,
    /// Restart a deployed private network.
    Restart,
    /// Start a deployed private network.
    Start,
    /// Prints status for all nodes in a deployed private network.
    Status,
    /// Stop a deployed private network.
    Stop,
}

pub fn run(cmd: NetworkCmd) -> ExitCode {
    let leaf = match cmd {
        NetworkCmd::Create => "create",
        NetworkCmd::Delete => "delete",
        NetworkCmd::Pregen => "pregen",
        NetworkCmd::Restart => "restart",
        NetworkCmd::Start => "start",
        NetworkCmd::Status => "status",
        NetworkCmd::Stop => "stop",
    };
    unimplemented("network", leaf)
}
