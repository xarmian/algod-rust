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

        /// Enable Merkle trie state root computation.
        #[arg(long)]
        trie: bool,

        /// Path to Go's tracker.db for trie root conformance comparison.
        #[arg(long)]
        compare_trie_db: Option<PathBuf>,

        /// Enable AVM execution mode (run TEAL programs instead of replaying EvalDeltas).
        #[arg(long)]
        avm_execute: bool,
    },

    /// Sync blocks from a remote algod endpoint using parallel fetching.
    ///
    /// By default, syncs from genesis. Use --catchpoint or --catchpoint-auto
    /// to bootstrap from a catchpoint snapshot instead.
    Sync {
        /// Network preset (mainnet, testnet, or custom).
        #[arg(long, default_value = "custom")]
        network: String,

        /// Base URL of the algod REST API (required for custom network).
        #[arg(long)]
        algod_url: Option<String>,

        /// API token for the algod node.
        #[arg(long, default_value = "")]
        algod_token: String,

        /// Path to genesis.json file (required when starting from round 0 without existing DB).
        #[arg(long)]
        genesis: Option<PathBuf>,

        /// SQLite database path for ledger state.
        #[arg(long, default_value = "./ledger.sqlite")]
        db: PathBuf,

        /// First round to sync (default: 0, or resume from DB).
        #[arg(long, default_value = "0")]
        start: u64,

        /// Last round to sync (default: fetch to chain tip).
        #[arg(long)]
        end: Option<u64>,

        /// Number of concurrent block fetches.
        #[arg(long, default_value = "16")]
        concurrency: usize,

        /// Enable AVM execution mode.
        #[arg(long)]
        avm_execute: bool,

        /// Stop on the first failure.
        #[arg(long)]
        fail_fast: bool,

        /// Enable Merkle trie state root computation.
        #[arg(long)]
        trie: bool,

        // --- Catchpoint sync options ---
        /// Catchpoint label to sync from (e.g. "47000000#HASH").
        /// Triggers catchpoint sync mode instead of genesis sync.
        #[arg(long)]
        catchpoint: Option<String>,

        /// Auto-discover the latest catchpoint from the network.
        /// Triggers catchpoint sync mode instead of genesis sync.
        #[arg(long)]
        catchpoint_auto: bool,

        /// Continue following new blocks after sync completes (catchpoint mode).
        #[arg(long)]
        follow: bool,

        /// Enable conformance comparison during block replay (catchpoint mode).
        #[arg(long)]
        compare: bool,

        /// Path for Merkle trie storage (catchpoint mode).
        #[arg(long)]
        trie_path: Option<PathBuf>,
    },

    /// Catchpoint operations: import, verify, and download catchpoint files.
    Catchpoint {
        #[command(subcommand)]
        action: CatchpointAction,
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

#[derive(Subcommand)]
pub enum CatchpointAction {
    /// Import a catchpoint file into the database.
    Import {
        /// Path to the catchpoint file (tar or tar.gz).
        #[arg(long)]
        file: PathBuf,

        /// SQLite database path.
        #[arg(long, default_value = "./ledger.sqlite")]
        db: PathBuf,

        /// Expected catchpoint label (optional, verified against file header).
        #[arg(long)]
        label: Option<String>,

        /// Reward unit for normalized online balance computation.
        #[arg(long, default_value = "1000000")]
        reward_unit: u64,

        /// Skip verification after import.
        #[arg(long)]
        no_verify: bool,
    },

    /// Verify an already-imported catchpoint database.
    Verify {
        /// SQLite database path to verify.
        #[arg(long, default_value = "./ledger.sqlite")]
        db: PathBuf,

        /// Path to the catchpoint file (required for block header digest).
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Download a catchpoint file from an algod node.
    Download {
        /// Base URL of the algod REST API.
        #[arg(long)]
        url: String,

        /// API token for the algod node.
        #[arg(long, default_value = "")]
        token: String,

        /// Genesis ID (e.g. "mainnet-v1.0").
        #[arg(long)]
        genesis_id: String,

        /// Catchpoint round to download.
        #[arg(long)]
        round: u64,

        /// Output file path.
        #[arg(long)]
        output: PathBuf,
    },
}
