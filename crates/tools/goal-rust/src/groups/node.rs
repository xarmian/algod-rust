//! `goal node` — port of `../go-algorand/cmd/goal/node.go` (+ `p2pid.go`).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};

use crate::unimplemented;

#[derive(Subcommand, Debug)]
pub enum NodeCmd {
    /// Catchup the Algorand node to a specific catchpoint.
    Catchup,
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
    Pendingtxns,
    /// Stop, and then start, the specified Algorand node.
    Restart,
    /// Initialize the specified Algorand node.
    Start,
    /// Get the current node status.
    Status(StatusArgs),
    /// Stop the specified Algorand node.
    Stop,
    /// Waits for the node to make progress.
    Wait,
}

#[derive(Args, Debug, Default)]
pub struct StatusArgs {
    /// Repeat poll every N milliseconds; 0 = single shot. Mirrors
    /// Go's `--watch` flag on `goal node status`
    /// (`cmd/goal/node.go` global `watchMillisecond`).
    #[arg(long = "watch", default_value_t = 0)]
    pub watch: u64,
}

pub fn run(cmd: NodeCmd) -> ExitCode {
    match cmd {
        NodeCmd::Catchup => unimplemented("node", "catchup"),
        NodeCmd::Clone => unimplemented("node", "clone"),
        NodeCmd::Create => unimplemented("node", "create"),
        NodeCmd::GenerateP2pid => unimplemented("node", "generate-p2pid"),
        NodeCmd::Generatetoken => unimplemented("node", "generatetoken"),
        NodeCmd::Lastround => unimplemented("node", "lastround"),
        NodeCmd::Pendingtxns => unimplemented("node", "pendingtxns"),
        NodeCmd::Restart => unimplemented("node", "restart"),
        NodeCmd::Start => unimplemented("node", "start"),
        NodeCmd::Status(args) => crate::cmd::node::run_status(args, datadirs_from_cli()),
        NodeCmd::Stop => unimplemented("node", "stop"),
        NodeCmd::Wait => unimplemented("node", "wait"),
    }
}

/// Wire the root `Cli` state into the node-group leaves. clap's
/// `#[arg(global = true)]` doesn't propagate into Subcommand enums by
/// default — we pull the per-process state from a thread-local that
/// `main` populates after parsing.
fn datadirs_from_cli() -> Vec<PathBuf> {
    crate::cli_state::datadirs()
}
