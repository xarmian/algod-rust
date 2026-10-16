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

//! `goal node` — port of `../go-algorand/cmd/goal/node.go` (+ `p2pid.go`).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};

use crate::unimplemented;

#[derive(Subcommand, Debug)]
pub enum NodeCmd {
    /// Catchup the Algorand node to a specific catchpoint.
    ///
    /// Catchup allows making large jumps over round ranges without the need
    /// to incrementally validate each individual round. Using external
    /// catchpoints is not a secure practice and should not be done for
    /// consensus participating nodes. If no catchpoint is provided, this
    /// command attempts to lookup the latest catchpoint from
    /// algorand-catchpoints.s3.us-east-2.amazonaws.com.
    Catchup(CatchupArgs),
    /// Clone the specified node to create another node.
    Clone,
    /// Create a node at the desired data directory for the desired
    /// network.
    Create,
    /// Generate a new p2p private key.
    #[command(name = "generate-p2pid")]
    GenerateP2pid,
    /// Generate and install a new API token.
    Generatetoken,
    /// Print the last round number.
    Lastround,
    /// Get a snapshot of current pending transactions on this node.
    ///
    /// Cut off at MAX transactions (-m), default 0. If MAX=0, fetches as
    /// many transactions as possible. Transactions are printed in the REST
    /// API's JSON form (DIV-002).
    Pendingtxns(PendingTxnsArgs),
    /// Stop, and then start, the specified Algorand node.
    Restart(StartFlags),
    /// Initialize the specified Algorand node.
    Start(StartFlags),
    /// Get the current node status.
    Status(StatusArgs),
    /// Stop the specified Algorand node.
    Stop,
    /// Waits for the node to make progress, which includes catching up.
    Wait(WaitArgs),
}

/// Flags shared by `goal node start` and `goal node restart`
/// (`cmd/goal/node.go:85-93`).
#[derive(Args, Debug, Default)]
pub struct StartFlags {
    /// Peer address to dial for initial connection.
    #[arg(short = 'p', long = "peer")]
    pub peer: Option<String>,
    /// Endpoint / REST address to listen on.
    #[arg(short = 'l', long = "listen")]
    pub listen: Option<String>,
    /// Run algod hosted by algoh (not available in algod-rust).
    #[arg(short = 'H', long = "hosted")]
    pub hosted: bool,
    /// Enable telemetry if supported (Use "true", "false", "0" or "1").
    #[arg(short = 't', long = "telemetry")]
    pub telemetry: Option<String>,
}

/// `catchupCmd` flags (`cmd/goal/node.go:117-119`).
#[derive(Args, Debug, Default)]
pub struct CatchupArgs {
    /// The catchpoint label (`<round>#<hash>`); looked up when omitted.
    pub catchpoint: Vec<String>,
    /// Aborts the current catchup process.
    #[arg(short = 'x', long = "abort")]
    pub abort: bool,
    /// Forces fast catchup with implicit catchpoint to start without a
    /// consent prompt.
    #[arg(long = "force")]
    pub force: bool,
    /// Catchup only if the catchpoint would advance the node by the
    /// specified minimum number of rounds.
    #[arg(short = 'm', long = "min", default_value_t = 0)]
    pub min: u64,
}

/// `pendingTxnsCmd` flags (`cmd/goal/node.go:113`).
#[derive(Args, Debug, Default)]
pub struct PendingTxnsArgs {
    /// Cap the number of txns to fetch.
    #[arg(short = 'm', long = "maxPendingTxn", default_value_t = 0)]
    pub max: u64,
}

/// `waitCmd` flags (`cmd/goal/node.go:114`).
#[derive(Args, Debug)]
pub struct WaitArgs {
    /// Time (in seconds) to wait for node to make progress.
    #[arg(short = 'w', long = "waittime", default_value_t = 5)]
    pub waittime: u32,
}

#[derive(Args, Debug, Default)]
pub struct StatusArgs {
    /// Repeat poll every N milliseconds; 0 = single shot. Mirrors
    /// Go's `-w, --watch` flag on `goal node status`
    /// (`cmd/goal/node.go` global `watchMillisecond`, registered
    /// with `Uint64VarP(..., "watch", "w", ...)`).
    #[arg(short = 'w', long = "watch", default_value_t = 0)]
    pub watch: u64,
}

pub fn run(cmd: NodeCmd) -> ExitCode {
    match cmd {
        NodeCmd::Catchup(a) => crate::cmd::node::run_catchup(a, datadirs_from_cli()),
        NodeCmd::Clone => unimplemented("node", "clone"),
        NodeCmd::Create => unimplemented("node", "create"),
        NodeCmd::GenerateP2pid => unimplemented("node", "generate-p2pid"),
        NodeCmd::Generatetoken => crate::cmd::node::run_generate_token(datadirs_from_cli()),
        NodeCmd::Lastround => crate::cmd::node::run_lastround(datadirs_from_cli()),
        NodeCmd::Pendingtxns(a) => crate::cmd::node::run_pendingtxns(a, datadirs_from_cli()),
        NodeCmd::Restart(f) => crate::cmd::node::run_restart(f, datadirs_from_cli()),
        NodeCmd::Start(f) => crate::cmd::node::run_start(f, datadirs_from_cli()),
        NodeCmd::Status(args) => crate::cmd::node::run_status(args, datadirs_from_cli()),
        NodeCmd::Stop => crate::cmd::node::run_stop(datadirs_from_cli()),
        NodeCmd::Wait(a) => crate::cmd::node::run_wait(a, datadirs_from_cli()),
    }
}

/// Wire the root `Cli` state into the node-group leaves. clap's
/// `#[arg(global = true)]` doesn't propagate into Subcommand enums by
/// default — we pull the per-process state from a thread-local that
/// `main` populates after parsing.
fn datadirs_from_cli() -> Vec<PathBuf> {
    crate::cli_state::datadirs()
}
