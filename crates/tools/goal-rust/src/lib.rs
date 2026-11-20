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

//! Library facade for `goal-rust`. The crate also ships a `goal-rust`
//! binary (see `src/main.rs`) which is a thin wrapper around
//! [`run`]; everything else lives here so integration tests can
//! drive pure formatters without spawning the binary
//! (e.g. the parity-harness fixtures under `tests/parity_fixtures.rs`).
//!
//! See `../go-algorand/cmd/goal/commands.go` for the cobra root this
//! mirrors. Pinned to `v4.6.0-stable`.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

pub mod accounts_list;
pub mod cli_state;
pub mod cmd;
pub mod cobra_compat;
mod cobra_usage;
pub mod consensus_json;
pub mod data_dir;
pub mod formatting;
pub mod go_json;
pub mod goal_client;
pub mod groups;
pub mod kmdcontrol;
pub mod nodecontrol;
pub mod resource_resolution;
pub mod transcode;
pub mod wallet_token;

/// goal-rust — CLI for interacting with Algorand.
///
/// Mirrors Go's `goal` binary. See `../go-algorand/cmd/goal/commands.go`
/// (line 100-103) for the Long description ported here.
#[derive(Parser, Debug)]
#[command(
    name = "goal-rust",
    about = "CLI for interacting with Algorand",
    long_about = "GOAL is the CLI for interacting Algorand software instance. \
The binary 'goal' is installed alongside the algod binary and is considered \
an integral part of the complete installation. The binaries should be used \
in tandem - you should not try to use a version of goal with a different \
version of algod.",
    // Go's `goal` binds `-v, --version` (lowercase) to the version flag.
    // clap's default is `-V, --version`. Disable clap's auto-flag and
    // declare our own below to preserve byte-exact help parity.
    disable_version_flag = true,
    disable_help_subcommand = false
)]
pub struct Cli {
    /// Data directory for the node (may be repeated).
    ///
    /// Mirrors Go's `-d, --datadir stringArray` persistent flag
    /// (`commands.go:107`).
    #[arg(
        short = 'd',
        long = "datadir",
        global = true,
        value_name = "PATH",
        value_parser = record_datadir
    )]
    pub datadir: Vec<String>,

    /// Data directory for kmd.
    ///
    /// Mirrors Go's `-k, --kmddir string` persistent flag
    /// (`commands.go:108`).
    #[arg(short = 'k', long = "kmddir", global = true, value_name = "PATH")]
    pub kmddir: Option<String>,

    /// Display and write current build version and exit.
    ///
    /// Mirrors Go's `-v, --version` root flag (set on `rootCmd` in
    /// `commands.go`; the `goal version` subcommand below is a separate
    /// entry point that prints the same thing). The flag is wired
    /// manually because clap's default `version` attribute would emit
    /// `-V` (uppercase) which would break help-parity.
    #[arg(short = 'v', long = "version", action = clap::ArgAction::SetTrue)]
    pub version: bool,

    #[command(subcommand)]
    pub command: Option<RootCommand>,
}

/// Root command set.
///
/// Order and naming mirror `commands.go:56-91` (`rootCmd.AddCommand(...)`):
/// version, license, report, protocols, account, wallet, clerk, asset,
/// node, kmd, network, ledger, completion, app.
// The `Clerk` variant inlines the full `clerk send` flag surface (`SendArgs`),
// which is intentionally larger than the unit/`Option<subcommand>` siblings;
// `ClerkCmd` already opts into the same size disparity (see its `#[allow]`).
// Boxing buys nothing for a short-lived CLI parse, so allow it here too.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
pub enum RootCommand {
    /// Control and manage Algorand accounts.
    Account {
        /// Set the account with this name to be the default account.
        /// Mirrors Go's local `-f, --default` flag on `accountCmd`
        /// (`account.go`); a leaf's own `-f` is a different flag.
        #[arg(short = 'f', long = "default")]
        default: Option<String>,
        #[command(subcommand)]
        cmd: Option<groups::account::AccountCmd>,
    },

    /// Manage applications.
    App {
        /// Wallet to use for the operation. Mirrors Go's *persistent* `-w`
        /// flag on the `app` command group (`application.go:116`).
        #[arg(short = 'w', long = "wallet", global = true)]
        wallet: Option<String>,
        #[command(subcommand)]
        cmd: Option<groups::app::AppCmd>,
    },

    /// Manage assets.
    Asset {
        /// Wallet to use for the operation. Mirrors Go's *persistent* `-w`
        /// flag on the `asset` command group (`asset.go:67`).
        #[arg(short = 'w', long = "wallet", global = true)]
        wallet: Option<String>,
        #[command(subcommand)]
        cmd: Option<groups::asset::AssetCmd>,
    },

    /// Provides the tools to control transactions.
    Clerk {
        /// Wallet to use for the operation. Mirrors Go's *persistent* `-w`
        /// flag on the `clerk` group (clerk.go:101). Declared `global = true`
        /// so both Go orderings parse to the same value: `clerk -w w send ...`
        /// and `clerk send -w w ...`.
        #[arg(short = 'w', long = "wallet", global = true)]
        wallet: Option<String>,
        #[command(subcommand)]
        cmd: Option<groups::clerk::ClerkCmd>,
    },

    /// Shell completion helper.
    Completion {
        #[command(subcommand)]
        cmd: Option<groups::completion::CompletionCmd>,
    },

    /// Interact with kmd, the key management daemon.
    Kmd {
        #[command(subcommand)]
        cmd: Option<groups::kmd::KmdCmd>,
    },

    /// Access ledger-related details.
    Ledger {
        #[command(subcommand)]
        cmd: Option<groups::ledger::LedgerCmd>,
    },

    /// Display license information.
    License,

    /// Create and manage private, multi-node, locally-hosted networks.
    Network {
        /// Root directory for the private network directories.
        #[arg(short = 'r', long = "rootdir", global = true)]
        rootdir: Option<std::path::PathBuf>,
        #[command(subcommand)]
        cmd: Option<groups::network::NetworkCmd>,
    },

    /// Manage a specified algorand node.
    Node {
        #[command(subcommand)]
        cmd: Option<groups::node::NodeCmd>,
    },

    /// Dump standard consensus protocols as json to stdout.
    Protocols,

    /// Produces report helpful for debugging.
    Report,

    /// The current version of the Algorand daemon (algod).
    Version {
        /// Print all version info available.
        #[arg(short = 'v', long = "verbose")]
        verbose: bool,
    },

    /// Manage wallets: encrypted collections of Algorand account keys.
    Wallet {
        /// Set the wallet with this name to be the default wallet.
        /// Mirrors Go's local `-f, --default` flag on `walletCmd`
        /// (`wallet.go`).
        #[arg(short = 'f', long = "default")]
        default: Option<String>,
        #[command(subcommand)]
        cmd: Option<groups::wallet::WalletCmd>,
    },
}

/// Print help for a (possibly nested) subcommand and exit 0, mirroring
/// cobra's no-`Run` fallback for command groups (e.g. `goal app` ⇒
/// help). `path` is the slice walked from the root, e.g. `["app", "box"]`.
pub fn print_group_help(path: &[&str]) -> ExitCode {
    let mut argv: Vec<String> = vec!["goal-rust".to_string()];
    argv.extend(path.iter().map(|s| (*s).to_string()));
    argv.push("--help".to_string());
    match Cli::try_parse_from(&argv) {
        // Unreachable in practice: `--help` always short-circuits to
        // the `Help` error path inside clap.
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => e.exit(),
    }
}

/// "Not yet implemented" stub the Phase-A leaves emit. Exits 2 to
/// mirror cobra's "unknown command" convention.
pub fn unimplemented(group: &str, leaf: &str) -> ExitCode {
    eprintln!("goal-rust: {group} {leaf} is not yet implemented");
    ExitCode::from(2)
}

/// Every `-d` value of the command line, in order, wherever it stands:
/// cobra's persistent `--datadir` string array collects them all (`goal -d
/// a version -d b` is two data dirs), where clap keeps a global argument's
/// values from one command level only. The value parser of `--datadir`
/// records each value as clap meets it.
static DATADIRS_SEEN: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn record_datadir(value: &str) -> Result<String, std::convert::Infallible> {
    DATADIRS_SEEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(value.to_string());
    Ok(value.to_string())
}

/// The `-d` values clap parsed (`seen`, not in command-line order: clap
/// parses a value given before a subcommand after the subcommand's), in
/// the order they stand in `argv`.
fn in_argv_order(mut seen: Vec<String>, argv: &[String]) -> Vec<String> {
    let mut ordered = Vec::with_capacity(seen.len());
    let mut i = 1;
    while i < argv.len() {
        let a = argv[i].as_str();
        let (value, used) = if a == "-d" || a == "--datadir" {
            (argv.get(i + 1).map(String::as_str), 2)
        } else if let Some(v) = a.strip_prefix("--datadir=") {
            (Some(v), 1)
        } else if let Some(v) = a.strip_prefix("-d").filter(|_| !a.starts_with("--")) {
            (Some(v.strip_prefix('=').unwrap_or(v)), 1)
        } else {
            (None, 1)
        };
        if let Some(pos) = value.and_then(|v| seen.iter().position(|s| s == v)) {
            ordered.push(seen.remove(pos));
        }
        i += used;
    }
    ordered.extend(seen);
    ordered
}

/// Main entry. The binary in `src/main.rs` is a one-liner that calls
/// this — keeping the dispatch table here lets integration tests
/// reach the same code path without spawning a subprocess.
pub fn run() -> ExitCode {
    // cobra's lookup of `account` / `wallet` subcommands (issue #2453).
    let args = match cobra_compat::preflight(std::env::args_os().collect()) {
        cobra_compat::Preflight::Run(args) => args,
        cobra_compat::Preflight::Exit(code) => return code,
    };
    DATADIRS_SEEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    let argv: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let cli = Cli::parse_from(args);
    let seen = std::mem::take(
        &mut *DATADIRS_SEEN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    let datadirs: Vec<std::path::PathBuf> = in_argv_order(seen, &argv)
        .into_iter()
        .map(Into::into)
        .collect();
    let kmddir = cli.kmddir.as_ref().map(Into::into);
    cli_state::install(datadirs, kmddir);
    if cli.version {
        return unimplemented("", "version");
    }
    let Some(command) = cli.command else {
        let mut cmd = <Cli as clap::CommandFactory>::command();
        let _ = cmd.print_help();
        println!();
        return ExitCode::SUCCESS;
    };
    match command {
        RootCommand::Account { cmd: Some(c), .. } => groups::account::run(c),
        RootCommand::Account { cmd: None, default } => {
            cmd::account::run_root(default, cli_state::datadirs())
        }
        RootCommand::App {
            cmd: Some(c),
            wallet,
        } => groups::app::run(c, wallet),
        RootCommand::App { cmd: None, .. } => print_group_help(&["app"]),
        RootCommand::Asset {
            cmd: Some(c),
            wallet,
        } => groups::asset::run(c, wallet),
        RootCommand::Asset { cmd: None, .. } => print_group_help(&["asset"]),
        RootCommand::Clerk {
            cmd: Some(c),
            wallet,
        } => groups::clerk::run(c, wallet),
        RootCommand::Clerk { cmd: None, .. } => print_group_help(&["clerk"]),
        RootCommand::Completion { cmd: Some(c) } => groups::completion::run(c),
        RootCommand::Completion { cmd: None } => print_group_help(&["completion"]),
        RootCommand::Kmd { cmd: Some(c) } => groups::kmd::run(c),
        RootCommand::Kmd { cmd: None } => print_group_help(&["kmd"]),
        RootCommand::Ledger { cmd: Some(c) } => groups::ledger::run(c),
        RootCommand::Ledger { cmd: None } => print_group_help(&["ledger"]),
        RootCommand::License => unimplemented("", "license"),
        RootCommand::Network {
            rootdir,
            cmd: Some(c),
        } => groups::network::run(c, rootdir),
        RootCommand::Network { cmd: None, .. } => print_group_help(&["network"]),
        RootCommand::Node { cmd: Some(c) } => groups::node::run(c),
        RootCommand::Node { cmd: None } => print_group_help(&["node"]),
        RootCommand::Protocols => unimplemented("", "protocols"),
        RootCommand::Report => unimplemented("", "report"),
        RootCommand::Version { verbose } => cmd::ledger::run_version(verbose, cli_state::datadirs()),
        RootCommand::Wallet { cmd: Some(c), .. } => groups::wallet::run(c),
        RootCommand::Wallet { cmd: None, default } => {
            cmd::wallet::run_root(default, cli_state::datadirs(), cli_state::kmddir())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dirs_keep_their_command_line_order() {
        let argv = |s: &str| -> Vec<String> { s.split(' ').map(String::from).collect() };
        let seen = |s: &[&str]| -> Vec<String> { s.iter().map(|x| x.to_string()).collect() };
        assert_eq!(
            in_argv_order(seen(&["/b", "/a"]), &argv("goal -d /a node lastround -d /b")),
            seen(&["/a", "/b"])
        );
        assert_eq!(
            in_argv_order(
                seen(&["/c", "/b", "/a"]),
                &argv("goal --datadir=/a node -d/b lastround --datadir /c")
            ),
            seen(&["/a", "/b", "/c"])
        );
        assert_eq!(
            in_argv_order(seen(&["/x", "/x"]), &argv("goal -d /x version -d /x")),
            seen(&["/x", "/x"])
        );
    }
}
