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
