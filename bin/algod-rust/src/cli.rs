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

        /// Use gossip (WebSocket) peers for block fetching instead of REST.
        ///
        /// When enabled, connects to relay peers via WebSocket and fetches
        /// blocks using the WS unicast catchup protocol. Falls back to REST
        /// on per-round gossip failures.
        #[arg(long)]
        gossip: bool,

        /// Override the genesis ID for gossip mode (e.g. "mainnet-v1.0").
        ///
        /// When using --gossip with --network custom, this specifies the
        /// genesis ID for the WebSocket handshake. If not set, the genesis
        /// ID is looked up by network name or fetched from the algod REST
        /// endpoint.
        #[arg(long)]
        genesis_id: Option<String>,

        /// Direct relay address(es) for gossip mode (can be repeated).
        /// When provided, DNS discovery and algod URL auto-seeding are skipped.
        #[arg(long)]
        relay_addr: Vec<String>,
    },

    /// Catchpoint operations: import, verify, and download catchpoint files.
    Catchpoint {
        #[command(subcommand)]
        action: CatchpointAction,
    },

    /// Run a relay node: accept inbound connections and forward gossip messages.
    Relay {
        /// Address to bind for incoming connections (e.g. "0.0.0.0:4160").
        #[arg(long, short = 'b')]
        bind_address: String,

        /// Path to the SQLite ledger database.
        #[arg(long, short = 'l')]
        ledger_path: PathBuf,

        /// Genesis ID string (e.g. "mainnet-v1.0").
        /// If not provided, derived from --network.
        #[arg(long, short = 'g')]
        genesis_id: Option<String>,

        /// Network name (mainnet, testnet, betanet).
        #[arg(long, short = 'n', default_value = "mainnet")]
        network: String,

        /// Comma-separated initial peer addresses to connect to.
        #[arg(long, value_delimiter = ',')]
        peers: Vec<String>,

        /// Maximum incoming connections.
        #[arg(long, default_value = "2400")]
        incoming_limit: u32,

        /// Maximum connections per IP address.
        #[arg(long, default_value = "8")]
        max_per_ip: u32,

        /// Connection rate limit (connections per second per IP).
        #[arg(long, default_value = "60")]
        rate_limit: u32,

        /// Maximum peers per broadcast.
        #[arg(long, default_value = "35")]
        broadcast_limit: u32,

        /// Path to TLS certificate file (optional).
        #[arg(long)]
        tls_cert: Option<String>,

        /// Path to TLS private key file (optional).
        #[arg(long)]
        tls_key: Option<String>,

        /// Block service memory cap in MB.
        #[arg(long, default_value = "500")]
        mem_cap_mb: u64,

        /// Optional path to a genesis.json file. When set, and the local
        /// ledger is empty, the relay seeds genesis accounts + account
        /// totals from this file. Without it the ledger's accountbase
        /// and accounttotals stay empty, which is fine for a pure block
        /// archive but breaks downstream consumers that need full
        /// ledger state (e.g. the TASK-88 cert cross-verify tool).
        /// See PLAN-32 / TASK-95.
        #[arg(long)]
        genesis_json: Option<PathBuf>,
    },

    /// Observe gossip traffic: connect to relay peers and log all messages as JSON lines.
    Observe {
        /// Network preset (mainnet, testnet, devnet, betanet).
        #[arg(long, default_value = "mainnet")]
        network: String,

        /// Direct relay address(es) to connect to (can be repeated).
        /// When provided, DNS discovery is skipped.
        #[arg(long)]
        relay_addr: Vec<String>,

        /// Override the genesis ID (e.g. "mainnet-v1.0").
        #[arg(long)]
        genesis_id: Option<String>,

        /// Override the DNS bootstrap template for peer discovery.
        #[arg(long)]
        dns_bootstrap: Option<String>,
    },

    /// Render an agreement cadaver trace as a round-by-round timeline.
    ///
    /// Reads the binary log produced by `algo_agreement::trace::Cadaver`
    /// (the writer plumbed by the agreement service for post-mortem
    /// debugging) and prints a human-readable transcript of player
    /// transitions, input events, and output actions. If a sibling
    /// `<path>.archive` file is present it is read first, matching
    /// go-algorand's `agreement.PrepareAutopsy` ordering.
    Autopsy {
        /// Path to the active `.cdv` cadaver file (or directly to a
        /// `.cdv.archive` file). When the active file is given and a
        /// sibling `.archive` exists, both are streamed in order.
        #[arg(long)]
        cadaver: PathBuf,

        /// Emit JSON instead of plain text.
        #[arg(long)]
        json: bool,
    },

    /// Capture raw wire-protocol messages from a Go relay for offline regression tests.
    CaptureWire {
        /// WebSocket address of the relay to connect to (e.g. "r-mn.algorand.network:4160").
        #[arg(long)]
        relay_addr: String,

        /// Output directory for captured wire fixtures.
        #[arg(long, default_value = "wire_fixtures")]
        output_dir: PathBuf,

        /// Maximum number of messages to capture.
        #[arg(long, default_value = "100")]
        count: u64,

        /// Maximum seconds to capture before stopping.
        #[arg(long, default_value = "60")]
        duration: u64,

        /// Genesis ID for the WebSocket handshake (e.g. "mainnet-v1.0").
        #[arg(long)]
        genesis_id: Option<String>,
    },

    /// Benchmark tools for measuring decode + validate throughput.
    Bench {
        #[command(subcommand)]
        action: BenchAction,
    },

    /// Participate in consensus: run the agreement protocol with participation keys.
    Participate {
        /// Path to the SQLite ledger database.
        #[arg(long, short = 'l')]
        ledger_path: PathBuf,

        /// Genesis ID string (e.g. "mainnet-v1.0").
        /// If not provided, derived from --network.
        #[arg(long, short = 'g')]
        genesis_id: Option<String>,

        /// Network name (mainnet, testnet, betanet).
        #[arg(long, short = 'n', default_value = "mainnet")]
        network: String,

        /// Comma-separated initial peer addresses to connect to.
        #[arg(long, value_delimiter = ',')]
        peers: Vec<String>,

        /// Path to participation key database file.
        #[arg(long)]
        partkey_path: PathBuf,

        /// Address to bind for incoming connections (e.g. "0.0.0.0:4160").
        #[arg(long, short = 'b')]
        listen_address: Option<String>,

        /// Act as a gossip relay: accept inbound peer dials on
        /// `--listen-address` and allow locally-originated /
        /// consensus-generated messages to be rebroadcast to peers.
        ///
        /// The inbound-listener side is gated on `--listen-address`
        /// being set, mirroring go-algorand's
        /// `is_relay = NetAddress != "" && Relay`. The outbound side
        /// (the broadcast thread + the `broadcast()` path on
        /// `WebsocketNetwork`) is enabled whenever this flag is set,
        /// which is what lets `LocalTxBroadcaster` fan a local txn
        /// out to connected peers — passing `--relay-messages`
        /// without `--listen-address` therefore still has an effect
        /// (though such a node has no way to accept inbound peers
        /// to forward to).
        ///
        /// Note: peer-originated transactions received on the
        /// `Transaction` tag are NOT re-relayed today — the handler
        /// drops them after ingesting into the local pool. Relay
        /// forwarding of third-party TX gossip is a separate
        /// follow-up.
        ///
        /// Required when another participate node needs to connect
        /// to this one over gossip (e.g. in the two-binary
        /// REST-driven propagation integration test).
        #[arg(long)]
        relay_messages: bool,

        /// 32-byte hex genesis hash for block validation.
        #[arg(long)]
        genesis_hash: Option<String>,

        /// Address to bind the REST API (e.g. "127.0.0.1:8080"). When
        /// set via this flag or the `rest.listen` field in the config
        /// file, the node starts the algod v2 REST API server
        /// alongside consensus. Unset means "no REST API", preserving
        /// the pre-TASK-79 behavior.
        #[arg(long)]
        rest_listen: Option<String>,

        /// Data directory used by the REST API server for reading /
        /// writing `algod.net`, `algod.token`, and `algod.admin.token`.
        /// Defaults to the ledger database's parent directory when
        /// `--rest-listen` is set but `--data-dir` is not provided.
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Path to `genesis.json` so the REST API can return its exact
        /// contents from `/genesis`. Defaults to `<data-dir>/genesis.json`
        /// when unset; falls back to a synthesized stub that matches the
        /// configured `genesis_id` + `genesis_hash` when neither exists.
        #[arg(long)]
        genesis_path: Option<PathBuf>,

        /// Optional path to an `algod-rust.toml` file. Populated fields
        /// provide defaults; individual CLI flags override them.
        #[arg(long)]
        config: Option<PathBuf>,
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

#[derive(Subcommand)]
pub enum BenchAction {
    /// Benchmark Rust block replay: end-to-end throughput including HTTP fetch.
    ///
    /// NOTE: This measures end-to-end throughput (network fetch + decode +
    /// validate). Network latency dominates (~99% of wall time). This is
    /// useful for profiling the Rust implementation in isolation but NOT for
    /// Go-vs-Rust comparison. For fair comparison, use `make bench-micro-go`
    /// (same fixture files) or `make bench-cluster` (side-by-side nodes).
    Replay {
        /// Base URL of the algod REST API.
        #[arg(long, default_value = "http://mainnet-api.4160.nodely.dev")]
        algod_url: String,

        /// API token for the algod node.
        #[arg(long, default_value = "")]
        token: String,

        /// First round to replay (required).
        #[arg(long)]
        start_round: u64,

        /// Number of blocks to replay.
        #[arg(long, default_value = "1000")]
        count: u64,

        /// JSON output file path.
        #[arg(long, default_value = "bench-replay-rust.json")]
        output: PathBuf,

        /// Shorthand for --count 100.
        #[arg(long)]
        quick: bool,
    },

    /// Benchmark Rust msgpack decode throughput: end-to-end including HTTP fetch.
    ///
    /// NOTE: This measures end-to-end throughput (network fetch + decode, no
    /// validation). Network latency dominates. This is useful for profiling
    /// the Rust decoder in isolation but NOT for Go-vs-Rust comparison. For
    /// fair comparison, use `make bench-micro-go` (same fixture files) or
    /// `make bench-cluster` (side-by-side nodes).
    Decode {
        /// Base URL of the algod REST API.
        #[arg(long, default_value = "http://mainnet-api.4160.nodely.dev")]
        algod_url: String,

        /// API token for the algod node.
        #[arg(long, default_value = "")]
        token: String,

        /// First round to decode (required).
        #[arg(long)]
        start_round: u64,

        /// Number of blocks to decode.
        #[arg(long, default_value = "1000")]
        count: u64,

        /// JSON output file path.
        #[arg(long, default_value = "bench-decode-rust.json")]
        output: PathBuf,

        /// Shorthand for --count 100.
        #[arg(long)]
        quick: bool,
    },

    /// Compare Rust and Go benchmark results side by side.
    Compare {
        /// Path to the Rust benchmark JSON file.
        #[arg(long)]
        rust_json: PathBuf,

        /// Path to the Go benchmark JSON file.
        #[arg(long)]
        go_json: PathBuf,

        /// Output as markdown instead of terminal table.
        #[arg(long)]
        markdown: bool,
    },
}
