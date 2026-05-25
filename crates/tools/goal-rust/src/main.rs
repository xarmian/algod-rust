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
    version,
    about = "CLI for interacting with Algorand",
    long_about = "GOAL is the CLI for interacting Algorand software instance. \
The binary 'goal' is installed alongside the algod binary and is considered \
an integral part of the complete installation. The binaries should be used \
in tandem - you should not try to use a version of goal with a different \
version of algod.",
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

    #[command(subcommand)]
    pub command: RootCommand,
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
        cmd: groups::account::AccountCmd,
    },

    /// Manage applications.
    App {
        #[command(subcommand)]
        cmd: groups::app::AppCmd,
    },

    /// Manage assets.
    Asset {
        #[command(subcommand)]
        cmd: groups::asset::AssetCmd,
    },

    /// Provides the tools to control transactions.
    Clerk {
        #[command(subcommand)]
        cmd: groups::clerk::ClerkCmd,
    },

    /// Shell completion helper.
    Completion {
        #[command(subcommand)]
        cmd: groups::completion::CompletionCmd,
    },

    /// Interact with kmd, the key management daemon.
    Kmd {
        #[command(subcommand)]
        cmd: groups::kmd::KmdCmd,
    },

    /// Access ledger-related details.
    Ledger {
        #[command(subcommand)]
        cmd: groups::ledger::LedgerCmd,
    },

    /// Display license information.
    License,

    /// Create and manage private, multi-node, locally-hosted networks.
    Network {
        #[command(subcommand)]
        cmd: groups::network::NetworkCmd,
    },

    /// Manage a specified algorand node.
    Node {
        #[command(subcommand)]
        cmd: groups::node::NodeCmd,
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
        cmd: groups::wallet::WalletCmd,
    },
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
    match cli.command {
        RootCommand::Account { cmd } => groups::account::run(cmd),
        RootCommand::App { cmd } => groups::app::run(cmd),
        RootCommand::Asset { cmd } => groups::asset::run(cmd),
        RootCommand::Clerk { cmd } => groups::clerk::run(cmd),
        RootCommand::Completion { cmd } => groups::completion::run(cmd),
        RootCommand::Kmd { cmd } => groups::kmd::run(cmd),
        RootCommand::Ledger { cmd } => groups::ledger::run(cmd),
        RootCommand::License => unimplemented("", "license"),
        RootCommand::Network { cmd } => groups::network::run(cmd),
        RootCommand::Node { cmd } => groups::node::run(cmd),
        RootCommand::Protocols => unimplemented("", "protocols"),
        RootCommand::Report => unimplemented("", "report"),
        RootCommand::Version => unimplemented("", "version"),
        RootCommand::Wallet { cmd } => groups::wallet::run(cmd),
    }
}
