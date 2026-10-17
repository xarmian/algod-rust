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

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};


#[derive(Subcommand, Debug)]
pub enum NetworkCmd {
    /// Create a private named network from a template.
    ///
    /// Creates a collection of folders under the specified root directory
    /// that make up the entire private network named 'private'
    /// (simplifying cleanup).
    Create(CreateArgs),
    /// Stops and Deletes a deployed private network.
    Delete,
    /// Pregenerate private network.
    ///
    /// Pregenerates the root and participation keys for a private network.
    /// The pregen directory can then be passed to the 'goal network create'
    /// to start the network more quickly.
    Pregen(PregenArgs),
    /// Restart a deployed private network.
    Restart,
    /// Start a deployed private network.
    ///
    /// Start a deployed private network by starting each individual node.
    Start(StartArgs),
    /// Prints status for all nodes in a deployed private network.
    Status,
    /// Stop a deployed private network.
    Stop,
}

/// `networkStartCmd` flags (`cmd/goal/network.go:60`).
#[derive(Args, Debug, Default)]
pub struct StartArgs {
    /// Specify the name of a specific node to start.
    #[arg(short = 'n', long = "node")]
    pub node: Option<String>,
}

/// `networkCreateCmd` flags (`cmd/goal/network.go:40-47`).
#[derive(Args, Debug, Default)]
pub struct CreateArgs {
    /// Specify the name to use for the private network.
    #[arg(short = 'n', long = "network")]
    pub network: Option<String>,
    /// Specify the path to the template file for the network.
    #[arg(short = 't', long = "template")]
    pub template: Option<PathBuf>,
    /// Do not import root keys when creating the network (by default will
    /// import).
    #[arg(short = 'K', long = "noimportkeys")]
    pub noimportkeys: bool,
    /// Prevents auto-cleanup on error - for diagnosing problems.
    #[arg(long = "noclean")]
    pub noclean: bool,
    /// Forces the configuration to enable DevMode, returns an error if the
    /// template is not compatible with DevMode.
    #[arg(long = "devMode")]
    pub dev_mode: bool,
    /// Automatically start the network after creating it.
    #[arg(short = 's', long = "start")]
    pub start: bool,
    /// Specify the path to the directory with pregenerated genesis.json,
    /// root and partkeys to import into the network directory. By default,
    /// the genesis.json and keys will be generated on start. This should
    /// only be used on private networks.
    #[arg(short = 'p', long = "pregendir")]
    pub pregendir: Option<PathBuf>,
}

/// `networkPregenCmd` flags (`cmd/goal/network.go:70-71`).
#[derive(Args, Debug, Default)]
pub struct PregenArgs {
    /// Specify the path to the template file for the network.
    #[arg(short = 't', long = "template")]
    pub template: Option<PathBuf>,
    /// Specify the path to the directory to export genesis.json, root and
    /// partkey files. This should only be used on private networks.
    #[arg(short = 'p', long = "pregendir")]
    pub pregendir: Option<PathBuf>,
}

pub fn run(cmd: NetworkCmd, rootdir: Option<PathBuf>) -> ExitCode {
    match cmd {
        NetworkCmd::Create(args) => crate::cmd::network::run_create(rootdir, args),
        NetworkCmd::Pregen(args) => crate::cmd::network::run_pregen(rootdir, args),
        NetworkCmd::Delete => crate::cmd::network::run_delete(rootdir),
        NetworkCmd::Restart => crate::cmd::network::run_restart(rootdir),
        NetworkCmd::Start(args) => crate::cmd::network::run_start(rootdir, args),
        NetworkCmd::Status => crate::cmd::network::run_status(rootdir),
        NetworkCmd::Stop => crate::cmd::network::run_stop(rootdir),
    }
}
