//! `goal wallet` — port of `../go-algorand/cmd/goal/wallet.go`.

use std::process::ExitCode;

use clap::Subcommand;

use crate::unimplemented;

#[derive(Subcommand, Debug)]
pub enum WalletCmd {
    /// List wallets managed by kmd.
    List,
    /// Create a new wallet.
    New,
    /// Rename wallet.
    Rename,
}

pub fn run(cmd: WalletCmd) -> ExitCode {
    let leaf = match cmd {
        WalletCmd::List => "list",
        WalletCmd::New => "new",
        WalletCmd::Rename => "rename",
    };
    unimplemented("wallet", leaf)
}
