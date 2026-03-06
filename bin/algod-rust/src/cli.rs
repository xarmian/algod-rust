use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "algod-rust",
    about = "Algorand Rust node — Phase 0 conformance tools",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

const DEFAULT_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Subcommand)]
pub enum Commands {
    /// Capture block fixtures from a Go algod node.
    Capture {
        /// Base URL of the algod REST API.
        #[arg(long, default_value = "http://localhost:4001")]
        algod_url: String,

        /// API token for the algod node.
        #[arg(long, default_value = DEFAULT_TOKEN)]
        algod_token: String,

        /// First round to capture.
        #[arg(long, default_value = "1")]
        start: u64,

        /// Last round to capture (stops early if block not found).
        #[arg(long, default_value = "5")]
        end: u64,

        /// Output directory for fixtures.
        #[arg(long, default_value = "./fixtures")]
        out: PathBuf,
    },

    /// Validate Rust decoding against live Go blocks.
    Validate {
        /// Base URL of the algod REST API.
        #[arg(long, default_value = "http://localhost:4001")]
        algod_url: String,

        /// API token for the algod node.
        #[arg(long, default_value = DEFAULT_TOKEN)]
        algod_token: String,

        /// First round to validate.
        #[arg(long, default_value = "1")]
        start: u64,

        /// Last round to validate (defaults to current latest round).
        #[arg(long)]
        end: Option<u64>,

        /// Stop on the first failed round.
        #[arg(long)]
        fail_fast: bool,

        /// Path to write the conformance report JSON.
        #[arg(long)]
        report: Option<PathBuf>,
    },

    /// Replay blocks from a remote algod endpoint with stateless validation.
    Replay {
        /// Network preset (mainnet, testnet, or custom).
        #[arg(long, default_value = "custom")]
        network: String,

        /// Base URL of the algod REST API (required for custom network).
        #[arg(long)]
        algod_url: Option<String>,

        /// API token for the algod node (required for custom network).
        #[arg(long, default_value = "")]
        algod_token: String,

        /// First round to replay.
        #[arg(long)]
        start: u64,

        /// Last round to replay.
        #[arg(long)]
        end: u64,

        /// Stop on the first validation failure.
        #[arg(long)]
        fail_fast: bool,

        /// Path to write the replay report JSON.
        #[arg(long)]
        report: Option<PathBuf>,

        /// Enable stateful replay with ledger state tracking.
        #[arg(long)]
        stateful: bool,

        /// Path to genesis.json file (required for stateful replay without existing DB).
        #[arg(long)]
        genesis: Option<PathBuf>,

        /// Enable conformance comparison against a Go node.
        #[arg(long)]
        compare: bool,

        /// Go node URL for conformance comparison.
        #[arg(long, default_value = "http://localhost:4002")]
        compare_url: String,

        /// Go node API token for conformance comparison.
        #[arg(long, default_value = "")]
        compare_token: String,

        /// Compare every Nth block (default: 1).
        #[arg(long, default_value = "1")]
        sample_rate: u64,

        /// SQLite database path for stateful replay.
        #[arg(long, default_value = "./ledger.sqlite")]
        db: PathBuf,
    },

    /// Follow mode: continuously validate new blocks as they arrive.
    Follow {
        /// Base URL of the algod REST API.
        #[arg(long, default_value = "http://localhost:4001")]
        algod_url: String,

        /// API token for the algod node.
        #[arg(long, default_value = DEFAULT_TOKEN)]
        algod_token: String,

        /// Directory to write periodic conformance reports.
        #[arg(long)]
        report_dir: Option<PathBuf>,
    },
}
