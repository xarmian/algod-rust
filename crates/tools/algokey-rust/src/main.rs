//! `algokey-rust` — Rust port of `../go-algorand/cmd/algokey`.
//!
//! Phase A skeleton (TASK-154): every subcommand prints "not implemented"
//! to stderr and exits with code 2. TASK-155 wires real flags; TASK-157,
//! TASK-158, and TASK-159 fill in `generate`, `import`, and `export`.

mod cli;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Generate
        | Command::Import
        | Command::Export
        | Command::Sign
        | Command::Multisig
        | Command::Part
        | Command::Keyreg => {
            eprintln!("not implemented");
            ExitCode::from(2)
        }
    }
}
