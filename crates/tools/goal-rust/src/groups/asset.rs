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

//! `goal asset` — port of `../go-algorand/cmd/goal/asset.go`.

use std::process::ExitCode;

use clap::Subcommand;

use crate::unimplemented;

#[derive(Subcommand, Debug)]
pub enum AssetCmd {
    /// Configure an asset.
    Config,
    /// Create an asset.
    Create,
    /// Destroy an asset.
    Destroy,
    /// Freeze assets.
    Freeze,
    /// Look up current parameters for an asset.
    Info,
    /// Optin to assets.
    Optin,
    /// Transfer assets.
    Send,
}

pub fn run(cmd: AssetCmd) -> ExitCode {
    let leaf = match cmd {
        AssetCmd::Config => "config",
        AssetCmd::Create => "create",
        AssetCmd::Destroy => "destroy",
        AssetCmd::Freeze => "freeze",
        AssetCmd::Info => "info",
        AssetCmd::Optin => "optin",
        AssetCmd::Send => "send",
    };
    unimplemented("asset", leaf)
}
