//! `goal ledger` — port of `../go-algorand/cmd/goal/ledger.go`.

use std::process::ExitCode;

use clap::Subcommand;

use crate::unimplemented;

#[derive(Subcommand, Debug)]
pub enum LedgerCmd {
    /// Dump a block to a file or stdout.
    Block,
    /// Show ledger token supply.
    Supply,
}

pub fn run(cmd: LedgerCmd) -> ExitCode {
    let leaf = match cmd {
        LedgerCmd::Block => "block",
        LedgerCmd::Supply => "supply",
    };
    unimplemented("ledger", leaf)
}
