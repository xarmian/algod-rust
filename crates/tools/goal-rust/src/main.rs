//! goal-rust — Rust port of go-algorand's `goal` operator CLI.
//!
//! Phase A (PLAN-152) delivers the **CLI skeleton**: every leaf subcommand
//! Go's `goal` exposes is wired into clap with the same name and `Short`
//! help text, but the body of each leaf is a stub that prints
//! `goal-rust: <group> <leaf> is not yet implemented` and exits 2.
//!
//! Reference: `../go-algorand/cmd/goal/commands.go` (root cobra setup) and
//! the per-group files (`account.go`, `application.go`, `asset.go`,
//! `clerk.go`, `kmd.go`, `ledger.go`, `network.go`, `node.go`, `wallet.go`).
//! Pinned to `v4.5.1-stable`.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod groups;

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
    #[arg(short = 'd', long = "datadir", global = true, value_name = "PATH")]
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
#[derive(Subcommand, Debug)]
pub enum RootCommand {
    /// Control and manage Algorand accounts.
    Account {
        #[command(subcommand)]
        cmd: Option<groups::account::AccountCmd>,
    },

    /// Manage applications.
    App {
        #[command(subcommand)]
        cmd: Option<groups::app::AppCmd>,
    },

    /// Manage assets.
    Asset {
        #[command(subcommand)]
        cmd: Option<groups::asset::AssetCmd>,
    },

    /// Provides the tools to control transactions.
    Clerk {
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
    Version,

    /// Manage wallets: encrypted collections of Algorand account keys.
    Wallet {
        #[command(subcommand)]
        cmd: Option<groups::wallet::WalletCmd>,
    },
}

/// Print help for a (possibly nested) subcommand and exit 0, mirroring
/// cobra's no-`Run` fallback for command groups (e.g. `goal app` ⇒
/// help). `path` is the slice walked from the root, e.g. `["app", "box"]`.
///
/// Implemented by re-parsing `[goal-rust, <path...>, --help]` through
/// the full root parser so the rendered help is byte-identical to what
/// the user would get by typing `goal-rust <path...> --help` directly
/// — same `Usage: goal-rust ... [OPTIONS] ...` line, same global flag
/// list. `try_parse_from` with `--help` returns a `Help` error whose
/// `.exit()` prints to stdout and terminates with exit code 0.
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

/// Print the "not yet implemented" message Go-side never emits but every
/// Phase-A stub does, and signal a non-zero exit so wrapper scripts can
/// detect un-ported behavior. Returns exit code 2 to mirror cobra's
/// "unknown command" convention.
pub fn unimplemented(group: &str, leaf: &str) -> ExitCode {
    eprintln!("goal-rust: {group} {leaf} is not yet implemented");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // `-v, --version` mirrors Go's root flag: print and exit (Phase A
    // stub keeps the "not yet implemented" contract so wrappers can
    // detect un-ported behavior — A2..A11 will fill in the real
    // version string from build metadata).
    if cli.version {
        return unimplemented("", "version");
    }
    let Some(command) = cli.command else {
        // `goal-rust` with no subcommand: print help to stdout and exit
        // 0, matching Go's `goal` (cobra default).
        let mut cmd = <Cli as clap::CommandFactory>::command();
        let _ = cmd.print_help();
        println!();
        return ExitCode::SUCCESS;
    };
    match command {
        RootCommand::Account { cmd: Some(c) } => groups::account::run(c),
        RootCommand::Account { cmd: None } => print_group_help(&["account"]),
        RootCommand::App { cmd: Some(c) } => groups::app::run(c),
        RootCommand::App { cmd: None } => print_group_help(&["app"]),
        RootCommand::Asset { cmd: Some(c) } => groups::asset::run(c),
        RootCommand::Asset { cmd: None } => print_group_help(&["asset"]),
        RootCommand::Clerk { cmd: Some(c) } => groups::clerk::run(c),
        RootCommand::Clerk { cmd: None } => print_group_help(&["clerk"]),
        RootCommand::Completion { cmd: Some(c) } => groups::completion::run(c),
        RootCommand::Completion { cmd: None } => print_group_help(&["completion"]),
        RootCommand::Kmd { cmd: Some(c) } => groups::kmd::run(c),
        RootCommand::Kmd { cmd: None } => print_group_help(&["kmd"]),
        RootCommand::Ledger { cmd: Some(c) } => groups::ledger::run(c),
        RootCommand::Ledger { cmd: None } => print_group_help(&["ledger"]),
        RootCommand::License => unimplemented("", "license"),
        RootCommand::Network { cmd: Some(c) } => groups::network::run(c),
        RootCommand::Network { cmd: None } => print_group_help(&["network"]),
        RootCommand::Node { cmd: Some(c) } => groups::node::run(c),
        RootCommand::Node { cmd: None } => print_group_help(&["node"]),
        RootCommand::Protocols => unimplemented("", "protocols"),
        RootCommand::Report => unimplemented("", "report"),
        RootCommand::Version => unimplemented("", "version"),
        RootCommand::Wallet { cmd: Some(c) } => groups::wallet::run(c),
        RootCommand::Wallet { cmd: None } => print_group_help(&["wallet"]),
    }
}
