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

//! `goal app` — port of `../go-algorand/cmd/goal/application.go` (+ `box.go`).

use std::process::ExitCode;

use clap::Subcommand;

use crate::unimplemented;

#[derive(Subcommand, Debug)]
pub enum AppCmd {
    /// Read application box data.
    Box {
        #[command(subcommand)]
        cmd: Option<BoxCmd>,
    },
    /// Call an application.
    Call,
    /// Clear out an application's state in your account.
    Clear,
    /// Close out of an application.
    Closeout,
    /// Create an application.
    Create,
    /// Delete an application.
    Delete,
    /// Look up current parameters for an application.
    Info,
    /// Invoke an ABI method.
    Method,
    /// Opt in to an application.
    Optin,
    /// Read local or global state for an application.
    Read,
    /// Update an application's programs.
    Update,
}

#[derive(Subcommand, Debug)]
pub enum BoxCmd {
    /// Retrieve information about an application box.
    Info,
    /// List all application boxes belonging to an application.
    List,
}

pub fn run(cmd: AppCmd) -> ExitCode {
    let leaf: &str = match cmd {
        AppCmd::Box { cmd } => {
            let Some(cmd) = cmd else {
                return crate::print_group_help(&["app", "box"]);
            };
            let leaf = match cmd {
                BoxCmd::Info => "info",
                BoxCmd::List => "list",
            };
            return unimplemented("app box", leaf);
        }
        AppCmd::Call => "call",
        AppCmd::Clear => "clear",
        AppCmd::Closeout => "closeout",
        AppCmd::Create => "create",
        AppCmd::Delete => "delete",
        AppCmd::Info => "info",
        AppCmd::Method => "method",
        AppCmd::Optin => "optin",
        AppCmd::Read => "read",
        AppCmd::Update => "update",
    };
    unimplemented("app", leaf)
}
