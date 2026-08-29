// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `goal wallet` — port of `../go-algorand/cmd/goal/wallet.go`.

use std::process::ExitCode;

use clap::{Args, Subcommand};

#[derive(Subcommand, Debug)]
pub enum WalletCmd {
    /// List wallets managed by kmd.
    List,
    /// Create a new wallet.
    New(NewArgs),
    /// Rename wallet.
    Rename(RenameArgs),
}

#[derive(Args, Debug)]
pub struct RenameArgs {
    /// Existing wallet name. Mirrors Go's first positional
    /// (`wallet.go:218` `cobra.ExactArgs(2)`).
    pub old_name: String,
    /// New wallet name. Mirrors Go's second positional.
    pub new_name: String,
    /// Wallet password (skip the interactive prompt). Same semantics
    /// as `wallet new --password`: TTY → prompt; non-TTY → one line
    /// from stdin (CI-friendly Phase-A divergence from Go).
    #[arg(short = 'w', long = "password")]
    pub password: Option<String>,
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

    /// Recover a wallet from a 25-word mnemonic instead of generating
    /// a fresh master derivation key. Mirrors Go's `--recover` flag
    /// on `newWalletCmd` (`wallet.go:84-87`, `recoverWallet bool`).
    #[arg(short = 'r', long = "recover")]
    pub recover_mnemonic: bool,

    /// Create an unencrypted wallet (empty password). Mirrors Go's
    /// `--unencrypted` flag (`wallet.go:51` — Go's internal variable
    /// is `createUnencryptedWallet` but the CLI flag is just
    /// `--unencrypted`).
    #[arg(long = "unencrypted")]
    pub unencrypted_wallet: bool,

    /// Suppress the post-create backup-phrase prompt. Mirrors Go's
    /// `--no-display-seed` flag (`wallet.go:86`, `noDisplaySeed bool`).
    #[arg(long = "no-display-seed")]
    pub no_display_seed: bool,
}

pub fn run(cmd: WalletCmd) -> ExitCode {
    match cmd {
        WalletCmd::List => {
            crate::cmd::wallet::run_list(crate::cli_state::datadirs(), crate::cli_state::kmddir())
        }
        WalletCmd::New(args) => crate::cmd::wallet::run_new(
            args,
            crate::cli_state::datadirs(),
            crate::cli_state::kmddir(),
        ),
        WalletCmd::Rename(args) => crate::cmd::wallet::run_rename(
            args,
            crate::cli_state::datadirs(),
            crate::cli_state::kmddir(),
        ),
    }
}
