//! `goal wallet` — port of `../go-algorand/cmd/goal/wallet.go`.

use std::process::ExitCode;

use clap::{Args, Subcommand};

use crate::unimplemented;

#[derive(Subcommand, Debug)]
pub enum WalletCmd {
    /// List wallets managed by kmd.
    List,
    /// Create a new wallet.
    New(NewArgs),
    /// Rename wallet.
    Rename,
}

#[derive(Args, Debug)]
pub struct NewArgs {
    /// Wallet name. Mirrors Go's `cobra.ExactArgs(1)` positional
    /// (`wallet.go:88`).
    pub name: String,

    /// Wallet password (skip the interactive prompt). When omitted on
    /// a TTY, prompt twice for confirmation; when omitted but stdin
    /// is not a TTY (CI), read one line from stdin.
    #[arg(short = 'w', long = "password")]
    pub password: Option<String>,

    /// Wallet driver. Go only ships "sqlite" today; we keep the flag
    /// to allow future driver names without a CLI break.
    #[arg(long = "driver", default_value = "sqlite")]
    pub driver: String,
}

pub fn run(cmd: WalletCmd) -> ExitCode {
    match cmd {
        WalletCmd::List => unimplemented("wallet", "list"),
        WalletCmd::New(args) => crate::cmd::wallet::run_new(
            args,
            crate::cli_state::datadirs(),
            crate::cli_state::kmddir(),
        ),
        WalletCmd::Rename => unimplemented("wallet", "rename"),
    }
}
