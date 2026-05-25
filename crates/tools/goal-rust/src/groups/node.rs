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
    ///
    /// Phase A note: process supervision is delegated to the host's
    /// supervisor (systemd, supervisord, etc.); the full Go port of
    /// `restartCmd` is tracked under a later goal-rust phase.
    Restart,
    /// Initialize the specified Algorand node.
    ///
    /// Phase A note: process supervision is delegated to the host's
    /// supervisor (systemd, supervisord, etc.); the full Go port of
    /// `startCmd` is tracked under a later goal-rust phase.
    Start,
    /// Get the current node status.
    Status(StatusArgs),
    /// Stop the specified Algorand node.
    ///
    /// Phase A note: process supervision is delegated to the host's
    /// supervisor (systemd, supervisord, etc.); the full Go port of
    /// `stopCmd` is tracked under a later goal-rust phase.
    Stop,
    /// Waits for the node to make progress.
    Wait,
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
        NodeCmd::Catchup => unimplemented("node", "catchup"),
        NodeCmd::Clone => unimplemented("node", "clone"),
        NodeCmd::Create => unimplemented("node", "create"),
        NodeCmd::GenerateP2pid => unimplemented("node", "generate-p2pid"),
        NodeCmd::Generatetoken => crate::cmd::node::run_generate_token(datadirs_from_cli()),
        NodeCmd::Lastround => crate::cmd::node::run_lastround(datadirs_from_cli()),
        NodeCmd::Pendingtxns => unimplemented("node", "pendingtxns"),
        NodeCmd::Restart => crate::cmd::node::run_restart(datadirs_from_cli()),
        NodeCmd::Start => crate::cmd::node::run_start(datadirs_from_cli()),
        NodeCmd::Status(args) => crate::cmd::node::run_status(args, datadirs_from_cli()),
        NodeCmd::Stop => crate::cmd::node::run_stop(datadirs_from_cli()),
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
