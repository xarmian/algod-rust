//! `algokey-rust` — Rust port of `../go-algorand/cmd/algokey`.
//!
//! Phase A: every subcommand prints "not implemented" to stderr and exits
//! with code 2. TASK-157, TASK-158, TASK-159 fill `generate`, `import`,
//! and `export`. Later phases (B, C) fill `sign`, `multisig`, `part`, and
//! `keyreg`.

mod cli;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command, MultisigSub, PartSub};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Generate(_) | Command::Import(_) | Command::Export(_) | Command::Sign(_) => {
            not_implemented()
        }
        Command::Multisig(m) => match m.command {
            None => not_implemented(),
            Some(MultisigSub::AppendAuthAddr(_)) => not_implemented(),
        },
        Command::Part(p) => match p.command {
            PartSub::Generate(_) | PartSub::Info(_) | PartSub::Reparent(_) | PartSub::Keyreg(_) => {
                not_implemented()
            }
        },
    }
}

/// Stub return matching the contract documented in TASK-154/TASK-155:
/// every Phase A leaf prints `"not implemented"` to stderr and exits 2.
/// TASK-157, TASK-158, TASK-159 replace these with real implementations.
fn not_implemented() -> ExitCode {
    eprintln!("not implemented");
    ExitCode::from(2)
}
