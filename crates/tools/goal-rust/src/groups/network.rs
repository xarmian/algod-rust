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
