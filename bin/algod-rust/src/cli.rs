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
