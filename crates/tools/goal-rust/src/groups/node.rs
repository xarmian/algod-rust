//! `goal node` — port of `../go-algorand/cmd/goal/node.go` (+ `p2pid.go`).

use std::process::ExitCode;

use clap::Subcommand;

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
    Status,
    /// Stop the specified Algorand node.
    Stop,
    /// Waits for the node to make progress.
    Wait,
}

pub fn run(cmd: NodeCmd) -> ExitCode {
    let leaf = match cmd {
        NodeCmd::Catchup => "catchup",
        NodeCmd::Clone => "clone",
        NodeCmd::Create => "create",
        NodeCmd::GenerateP2pid => "generate-p2pid",
        NodeCmd::Generatetoken => "generatetoken",
        NodeCmd::Lastround => "lastround",
        NodeCmd::Pendingtxns => "pendingtxns",
        NodeCmd::Restart => "restart",
        NodeCmd::Start => "start",
        NodeCmd::Status => "status",
        NodeCmd::Stop => "stop",
        NodeCmd::Wait => "wait",
    };
    unimplemented("node", leaf)
}
