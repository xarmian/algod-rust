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

// `Participate`'s variant has grown large (issue #748 added several new
// `Option<T>` networking-config CLI flags to close its gap with `relay`)
// relative to the smallest variants — clap CLI arg enums are inherently
// heap-adjacent (each match arm is only ever constructed once at
// startup, never in a hot loop), so the size difference clippy flags
// here isn't a real perf concern; boxing individual fields would only
// add noise to every call site.
#[allow(clippy::large_enum_variant)]
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

        /// Ledger prefix for the on-disk database pair (tracker + block
        /// SQLite files). The CLI opens `<prefix>.tracker.sqlite` and
        /// `<prefix>.block.sqlite`, matching go-algorand's layout
        /// (`../go-algorand/ledger/ledger.go:327,336`). Legacy values that
        /// end in `.sqlite` or `.tracker.sqlite` / `.block.sqlite` are
        /// accepted — the suffix is stripped to recover the prefix.
        #[arg(long, alias = "ledger-prefix", default_value = "./ledger")]
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

        /// Ledger prefix for the on-disk database pair (tracker + block
        /// SQLite files). The CLI opens `<prefix>.tracker.sqlite` and
        /// `<prefix>.block.sqlite`, matching go-algorand's layout
        /// (`../go-algorand/ledger/ledger.go:327,336`). Legacy values that
        /// end in `.sqlite` or `.tracker.sqlite` / `.block.sqlite` are
        /// accepted — the suffix is stripped to recover the prefix.
        #[arg(long, alias = "ledger-prefix", default_value = "./ledger")]
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

        /// Override the DNS bootstrap template for gossip-mode peer
        /// discovery (go: `config.Local.DNSBootstrapID`). Generalizes the
        /// `--dns-bootstrap` knob previously confined to `observe`
        /// (issue #748).
        #[arg(long)]
        dns_bootstrap: Option<String>,

        /// Data directory to load `<data-dir>/config.json` from (go-algorand
        /// `config.Local` equivalent, issue #754/epic #745). Currently used
        /// by catchpoint-sync mode for `AccountsRebuildSynchronousMode`
        /// (issue #749): the bulk-import connection's SQLite `synchronous`
        /// pragma, previously hardcoded to `NORMAL` unconditionally. A
        /// missing `--data-dir` (or missing `config.json`) falls back to
        /// go-matching defaults.
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Additional algod REST base URL(s) to consider as candidate
        /// sources for the catchpoint-file download (can be repeated).
        /// Catchpoint mode only. When given, the catchpoint download is
        /// ranked across `--algod-url` plus these peers by historical
        /// download performance (issue #901) instead of using
        /// `--algod-url` alone — a peer that fails is deprioritized in
        /// favor of a better-ranked one on the next retry. Block/status
        /// fetches are unaffected and continue to use `--algod-url`.
        #[arg(long)]
        catchpoint_peer_url: Vec<String>,
    },

    /// Catchpoint operations: import, verify, export, and download catchpoint files.
    Catchpoint {
        #[command(subcommand)]
        action: CatchpointAction,
    },

    /// Run a relay node: accept inbound connections and forward gossip messages.
    Relay {
        /// Address to bind for incoming connections (e.g. "0.0.0.0:4160").
        #[arg(long, short = 'b')]
        bind_address: String,

        /// Ledger prefix for the on-disk database pair (tracker + block
        /// SQLite files). The CLI opens `<prefix>.tracker.sqlite` and
        /// `<prefix>.block.sqlite`, matching go-algorand's layout
        /// (`../go-algorand/ledger/ledger.go:327,336`). Legacy `.sqlite` /
        /// `.tracker.sqlite` / `.block.sqlite` suffixes are stripped to
        /// recover the prefix.
        #[arg(long, short = 'l', alias = "ledger-prefix")]
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

        /// Maximum incoming connections. `None` (the default: no CLI flag
        /// passed) falls back to `<data-dir>/config.json`'s
        /// `IncomingConnectionsLimit` (issue #768 — relay previously had
        /// no `config.json` at all, only this flag's own hardcoded
        /// default, matching go's value coincidentally but with no way to
        /// override it via `config.json` the way `participate` can).
        #[arg(long)]
        incoming_limit: Option<i64>,

        /// Maximum connections per IP address. See `incoming_limit`'s note
        /// — falls back to `config.json`'s `MaxConnectionsPerIP`.
        #[arg(long)]
        max_per_ip: Option<i64>,

        /// Connection rate limit: maximum new connections per window. See
        /// `incoming_limit`'s note — falls back to `config.json`'s
        /// `ConnectionsRateLimitingCount`.
        #[arg(long)]
        rate_limit: Option<u64>,

        /// Connection-rate-limit window, in seconds (go:
        /// `config.Local.ConnectionsRateLimitingWindowSeconds`). See
        /// `incoming_limit`'s note.
        #[arg(long)]
        rate_limit_window_seconds: Option<u64>,

        /// Maximum peers a single broadcast is delivered to. A negative
        /// value means unbounded, matching go's real
        /// `BroadcastConnectionsLimit` default of `-1`. See
        /// `incoming_limit`'s note — falls back to `config.json`'s
        /// `BroadcastConnectionsLimit`.
        #[arg(long, allow_negative_numbers = true)]
        broadcast_limit: Option<i64>,

        /// Path to TLS certificate file (optional). Falls back to
        /// `config.json`'s `TLSCertFile` when not passed.
        #[arg(long)]
        tls_cert: Option<String>,

        /// Path to TLS private key file (optional). Falls back to
        /// `config.json`'s `TLSKeyFile` when not passed.
        #[arg(long)]
        tls_key: Option<String>,

        /// Block service memory cap in MB. See `incoming_limit`'s note —
        /// falls back to `config.json`'s `BlockServiceMemCap` (converted
        /// from bytes to MB).
        #[arg(long)]
        mem_cap_mb: Option<u64>,

        /// Optional path to a genesis.json file. When set, and the local
        /// ledger is empty, the relay seeds genesis accounts + account
        /// totals from this file. Without it the ledger's accountbase
        /// and accounttotals stay empty, which is fine for a pure block
        /// archive but breaks downstream consumers that need full
        /// ledger state (e.g. the TASK-88 cert cross-verify tool).
        /// See PLAN-32 / TASK-95.
        #[arg(long)]
        genesis_json: Option<PathBuf>,

        /// Data directory to load `<data-dir>/config.json` from (issue
        /// #768). Mirrors `participate --data-dir`'s own config-loading
        /// mechanism — a missing directory or missing `config.json`
        /// within it is not an error; every field falls back to its
        /// go-matching built-in default.
        #[arg(long)]
        data_dir: Option<PathBuf>,
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
        /// Ledger prefix for the on-disk database pair (tracker + block
        /// SQLite files). The CLI opens `<prefix>.tracker.sqlite` and
        /// `<prefix>.block.sqlite`, matching go-algorand's layout
        /// (`../go-algorand/ledger/ledger.go:327,336`). Legacy `.sqlite` /
        /// `.tracker.sqlite` / `.block.sqlite` suffixes are stripped to
        /// recover the prefix.
        #[arg(long, short = 'l', alias = "ledger-prefix")]
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

        /// Import one or more go-algorand `.partkey` files into the
        /// `--partkey-path` registry at startup, then participate with them.
        ///
        /// `goal network create` / `algokey part generate` write the
        /// single-account `ParticipationAccount` schema, which is *not* the
        /// multi-key registry schema `--partkey-path` reads. Repeat this flag
        /// (or comma-separate) to bridge them. Re-importing an
        /// already-registered key is a no-op, so restarts against a persistent
        /// volume are safe.
        #[arg(long, value_delimiter = ',')]
        import_partkey: Vec<PathBuf>,

        /// Directory to scan for go-algorand `.partkey` files at startup.
        /// Every entry whose name matches Go's
        /// `<account>.<firstValid>.<lastValid>.partkey` convention is
        /// imported into the `--partkey-path` registry, exactly as
        /// `AlgorandFullNode.loadParticipationKeys` does
        /// (`../go-algorand/node/node.go`).
        ///
        /// Repeat (or comma-separate) for several directories. This is
        /// rarely needed: when `--data-dir` points at a
        /// `goal network create` node directory, its genesis
        /// subdirectory `<data-dir>/<genesis-id>` — where `goal` actually
        /// writes the keys — is scanned automatically.
        #[arg(long, value_delimiter = ',')]
        partkey_dir: Vec<PathBuf>,

        /// Path to `genesis.json` used to seed `accountbase` +
        /// `accounttotals` when the ledger is brand new. Without it a node
        /// joining a fresh private network has no online-stake table and can
        /// neither run sortition nor validate proposals. Mirrors
        /// `relay --genesis-json`; a no-op once the ledger is seeded.
        #[arg(long)]
        genesis_json: Option<PathBuf>,

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

        /// Address to bind the REST API (e.g. "127.0.0.1:8080"). Priority
        /// order: this flag, then the `rest.listen` field in
        /// `algod-rust.toml`, then `<data-dir>/config.json`'s
        /// `EndpointAddress`.
        ///
        /// **Decision recorded (issue #751):** REST now starts by default,
        /// matching go-algorand exactly — go's `EndpointAddress` always
        /// defaults to `"127.0.0.1:0"` (an ephemeral local port) and the
        /// REST API server is unconditionally started
        /// (`daemon/algod/server.go`; there is no "off" switch upstream).
        /// This flag previously defaulted to `None`, meaning "no REST API"
        /// was algod-rust's out-of-the-box behavior — a divergence with no
        /// documented rationale beyond pre-TASK-79 migration inertia (no
        /// deliberate operational-safety argument was ever recorded for
        /// it). As an algod-rust-only affordance beyond go (which has no
        /// real "off" switch — its own empty-`EndpointAddress` fallback
        /// just binds port 80), an *explicit* empty string from any of the
        /// three sources above still disables REST entirely, for
        /// deployments that genuinely want none.
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

        /// Enable the libp2p P2P transport (go: `config.Local.EnableP2P`).
        /// When `--enable-p2p-hybrid-mode` is also set, hybrid mode takes
        /// precedence — matches go-algorand's precedence exactly (see
        /// `EnableP2P`'s doc comment in
        /// `../go-algorand/config/localTemplate.go`).
        #[arg(long)]
        enable_p2p: bool,

        /// Run both the WS-gossip stack and the libp2p P2P stack
        /// simultaneously (go: `config.Local.EnableP2PHybridMode`).
        #[arg(long)]
        enable_p2p_hybrid_mode: bool,

        /// Persist the libp2p node identity's private key to disk so the
        /// PeerId is stable across restarts (go:
        /// `config.Local.P2PPersistPeerID`). Written under `--data-dir`
        /// when set.
        #[arg(long)]
        p2p_persist_peer_id: bool,

        /// Comma-separated libp2p multiaddrs to dial as bootstrap peers
        /// for DHT discovery and gossipsub mesh formation (e.g.
        /// "/ip4/1.2.3.4/tcp/4190/p2p/12D3KooW...").
        #[arg(long, value_delimiter = ',')]
        p2p_bootstrap_peers: Vec<String>,

        /// Listen multiaddr for the libp2p P2P transport (e.g.
        /// "/ip4/0.0.0.0/tcp/4190"). Required for other nodes to dial this
        /// one directly; unset means outbound-only P2P participation.
        #[arg(long)]
        p2p_listen_address: Option<String>,

        /// Maximum connections allowed from a single IP address (go:
        /// `config.Local.MaxConnectionsPerIP`). Previously only available
        /// on `relay`; closes that gap (issue #748). Falls back to
        /// `<data-dir>/config.json`'s value (itself defaulted to go's
        /// current default of 8) when unset.
        #[arg(long)]
        max_per_ip: Option<i64>,

        /// Maximum simultaneous inbound connections (go:
        /// `config.Local.IncomingConnectionsLimit`). Previously only
        /// available on `relay`; closes that gap (issue #748). A negative
        /// value means unbounded, matching go. Falls back to
        /// `<data-dir>/config.json`'s value when unset.
        #[arg(long)]
        incoming_limit: Option<i64>,

        /// Connection-rate limit: maximum new connections per window (go:
        /// `config.Local.ConnectionsRateLimitingCount`). Previously only
        /// available on `relay`; closes that gap (issue #748).
        #[arg(long)]
        rate_limit: Option<u64>,

        /// Connection-rate-limit window, in seconds (go:
        /// `config.Local.ConnectionsRateLimitingWindowSeconds`).
        /// Previously entirely absent from algod-rust, which only modeled
        /// the *count* half of this pair (issue #748).
        #[arg(long)]
        rate_limit_window_seconds: Option<u64>,

        /// Maximum peers a single broadcast is delivered to (go:
        /// `config.Local.BroadcastConnectionsLimit`). A negative value
        /// means unbounded, matching go's real default (issue #748 fixed
        /// algod-rust's prior hardcoded-`35` divergence). Previously only
        /// available on `relay`.
        #[arg(long)]
        broadcast_limit: Option<i64>,

        /// Path to TLS certificate file (go: `config.Local.TLSCertFile`).
        /// Previously only available on `relay`; closes that gap (issue
        /// #748).
        #[arg(long)]
        tls_cert: Option<String>,

        /// Path to TLS private key file (go: `config.Local.TLSKeyFile`).
        /// Previously only available on `relay`.
        #[arg(long)]
        tls_key: Option<String>,

        /// Override the DNS bootstrap template used for peer discovery
        /// when `--peers` is empty (go: `config.Local.DNSBootstrapID`).
        /// Generalizes the `--dns-bootstrap` knob previously confined to
        /// `observe` (issue #748).
        #[arg(long)]
        dns_bootstrap: Option<String>,

        /// REST URL of a peer to fetch catchpoint files and blocks from
        /// for a live `POST /v2/catchup/:catchpoint` request (issue #940).
        ///
        /// Unlike go-algorand's `CatchpointCatchupService` (which fetches
        /// over the same gossip network `--peers` already connects to),
        /// algod-rust's catchup path (`algo_ledger::sync::SyncOrchestrator`,
        /// shared with the standalone `catchpoint_sync`/`sync` subcommand
        /// and `node start --follow`'s live-catchup wiring, issue #937)
        /// fetches over REST, so a participating node needs an explicit
        /// REST peer to catch up *from*. Without this flag,
        /// `start_catchup`/`abort_catchup` report `NotImplemented`, exactly
        /// as before this issue.
        #[arg(long)]
        catchup_peer: Option<String>,

        /// Auth token for `--catchup-peer`.
        #[arg(long, default_value = DEFAULT_TOKEN)]
        catchup_peer_token: String,
    },

    /// Follow mode: continuously validate new blocks as they arrive.
    ///
    /// **Architectural decision recorded (issue #751):** go-algorand's
    /// `EnableFollowMode` is a `config.json` flag on its single node
    /// binary that turns off the agreement service while still serving
    /// the REST API. algod-rust instead implements follower behavior as
    /// this separate subcommand. Investigated whether to unify it into a
    /// `participate --follow` mode flag instead: concluded unification is
    /// not clearly the right call — `follow` has no agreement service, no
    /// participation keys, no transaction pool, and a different
    /// network-attachment path entirely, so collapsing it into
    /// `participate::run` would require threading "agreement service
    /// absent" through code paths that currently assume one exists, for
    /// no behavioral gain (`algod-rust follow` already does everything
    /// `EnableFollowMode` does). `config.json`'s `EnableFollowMode` field
    /// itself round-trips (`algo_config::Local::enable_follow_mode`) for
    /// forward/inspection compatibility but is a documented no-op — this
    /// subcommand remains the one way to run in follower mode.
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

    /// Run a node: serve the algod v2 REST API backed by a local ledger.
    Node {
        #[command(subcommand)]
        cmd: NodeCommands,
    },

    /// Sustained-rate transaction load generator for cluster stress tests.
    Loadgen {
        #[command(subcommand)]
        cmd: LoadgenCommands,
    },

    /// Inspect and edit a node's `config.json` — go-algorand's `algocfg`
    /// tool (`cmd/algocfg`), issue #973.
    Algocfg {
        #[command(subcommand)]
        action: AlgocfgAction,
    },
}

/// Subcommands for `algod-rust algocfg`. Go: `cmd/algocfg`'s `get`/`set`/
/// `reset`/`profile` commands (`getCommand.go`/`setCommand.go`/
/// `resetCommand.go`/`profileCommand.go`), field names matching go's
/// `config.Local` field names exactly (e.g. `EnableP2P`, `GossipFanout`).
#[derive(Subcommand)]
pub enum AlgocfgAction {
    /// Retrieve the current value for the specified parameter.
    Get {
        /// Parameter to query (go's `config.Local` field name, e.g. `EnableP2P`).
        #[arg(long, short = 'p')]
        parameter: String,

        /// Data directory holding `config.json`.
        #[arg(long, short = 'd', default_value = ".")]
        datadir: PathBuf,
    },

    /// Retrieve the current value for the specified parameter as a
    /// shell-quoted string, safe to embed directly in a shell command.
    /// Algod-rust addition beyond go's `algocfg` (issue #973) — `get`
    /// never quotes its output.
    String {
        /// Parameter to query (go's `config.Local` field name).
        #[arg(long, short = 'p')]
        parameter: String,

        /// Data directory holding `config.json`.
        #[arg(long, short = 'd', default_value = ".")]
        datadir: PathBuf,
    },

    /// Update the current value for the specified parameter.
    Set {
        /// Parameter to update (go's `config.Local` field name).
        #[arg(long, short = 'p')]
        parameter: String,

        /// Value to set.
        #[arg(long, short = 'v')]
        value: String,

        /// Data directory holding `config.json`.
        #[arg(long, short = 'd', default_value = ".")]
        datadir: PathBuf,
    },

    /// Reset the specified parameter to its default (delete from
    /// config.json). Go: `algocfg reset`.
    Delete {
        /// Parameter to reset (go's `config.Local` field name).
        #[arg(long, short = 'p')]
        parameter: String,

        /// Data directory holding `config.json`.
        #[arg(long, short = 'd', default_value = ".")]
        datadir: PathBuf,
    },

    /// Generate `config.json` from a named usage profile.
    Profile {
        #[command(subcommand)]
        action: AlgocfgProfileAction,
    },
}

/// Subcommands for `algod-rust algocfg profile`.
#[derive(Subcommand)]
pub enum AlgocfgProfileAction {
    /// A list of valid config profiles and a short description.
    List,

    /// Print the profile's config.json contents to stdout.
    Print {
        /// Profile name (e.g. `participation`, `archival`, `hybridRelay`).
        name: String,
    },

    /// Write `config.json` for the given profile.
    Set {
        /// Profile name (e.g. `participation`, `archival`, `hybridRelay`).
        name: String,

        /// Data directory to write `config.json` into.
        #[arg(long, short = 'd', default_value = ".")]
        datadir: PathBuf,

        /// Force overwrite without prompting if `config.json` already exists.
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// Subcommands for `algod-rust loadgen`.
#[derive(Subcommand)]
pub enum LoadgenCommands {
    /// Generate throwaway generator accounts and write them to a JSON key
    /// file. Fund the printed addresses before running `loadgen run`.
    GenAccounts {
        /// How many accounts to generate.
        #[arg(long, default_value_t = 16)]
        count: usize,

        /// Where to write the key file (contains private keys; 0600 on unix).
        #[arg(long, short = 'o')]
        out: PathBuf,
    },

    /// Drive a cluster at a fixed transaction rate and emit a JSON report.
    Run {
        /// Comma-separated node REST base URLs to round-robin submissions
        /// across (e.g. `http://a:8080,http://b:8080`).
        #[arg(long, value_delimiter = ',')]
        algod_urls: Vec<String>,

        /// API token sent as `X-Algo-API-Token` to every endpoint.
        #[arg(long, default_value = DEFAULT_TOKEN)]
        token: String,

        /// Key file written by `loadgen gen-accounts`.
        #[arg(long)]
        keys: PathBuf,

        /// Steady-state transactions per second.
        #[arg(long, default_value_t = 100.0)]
        target_tps: f64,

        /// Total run length in seconds, ramp included.
        #[arg(long, default_value_t = 60.0)]
        duration_secs: f64,

        /// Linear ramp-up length in seconds at the start of the run.
        #[arg(long, default_value_t = 0.0)]
        ramp_secs: f64,

        /// Transactions per atomic group (1 = singleton payments, max 16).
        #[arg(long, default_value_t = 1)]
        group_size: usize,

        /// Concurrent submitter tasks per endpoint.
        #[arg(long, default_value_t = 8)]
        concurrency: usize,

        /// Multiplier applied to the congestion-adjusted fee. Under sustained
        /// load a node's pool raises its fee floor above the protocol minimum,
        /// and `/v2/transactions/params` is only polled every few seconds, so
        /// paying exactly the last-seen suggested fee loses a race with the
        /// rising floor and the submission is rejected. Values above 1.0 buy
        /// headroom; the extra fee is irrelevant in a benchmark network.
        #[arg(long, default_value_t = 1.0)]
        fee_multiplier: f64,

        /// Sample confirmation latency for every Nth submission (0 disables).
        #[arg(long, default_value_t = 200)]
        confirm_sample: u64,

        /// Give up on a confirmation poll after this many seconds.
        #[arg(long, default_value_t = 30)]
        confirm_timeout_secs: u64,

        /// Write the JSON report here (also printed to stdout).
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

/// Subcommands for `algod-rust node`.
#[derive(Subcommand)]
pub enum NodeCommands {
    /// Start the node: initialize the ledger from `genesis.json` if needed and
    /// serve the REST API so `goal -d <datadir>` can drive it. Read-serving
    /// today (TASK-263); transaction submit/confirm lands in TASK-264.
    Start {
        /// Node data directory (Go layout): holds `genesis.json`, the
        /// per-genesis ledger subdirectory, and the
        /// `algod.net`/`algod.token`/`algod.admin.token` discovery files the
        /// server writes.
        #[arg(long, short = 'd')]
        data_dir: PathBuf,

        /// Address to bind the REST API (default `127.0.0.1:8080`).
        #[arg(long, short = 'l')]
        listen: Option<String>,

        /// Path to `genesis.json` (default `<data-dir>/genesis.json`).
        #[arg(long, short = 'g')]
        genesis: Option<PathBuf>,

        /// Run in dev mode: each submitted transaction group immediately
        /// produces a block (single-node, no agreement), giving instant
        /// submit→confirm. Also enabled automatically when `genesis.json` sets
        /// `"devmode": true`.
        #[arg(long)]
        dev: bool,

        /// Follow (sync from) a remote algod REST peer: fetch each new block
        /// over `/v2/blocks/{round}` and apply it through the same real
        /// sync-path code (`SqliteLedger::apply_block_caching_delta`) that
        /// `algod-rust sync` uses, while this process keeps serving its own
        /// REST API — so `GET /v2/deltas/{round}` can be queried against a
        /// genuinely synced (not dev-mode-produced) block. Mutually
        /// exclusive with `--dev` (issue #612).
        #[arg(long)]
        follow: Option<String>,

        /// API token for the `--follow` peer's REST endpoint.
        #[arg(long, default_value = DEFAULT_TOKEN)]
        follow_token: String,
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

        /// Data directory to load `<data-dir>/config.json` from (issue
        /// #749): `AccountsRebuildSynchronousMode` (SQLite `synchronous`
        /// pragma on the import connection, previously hardcoded to
        /// `NORMAL`) and `OptimizeAccountsDatabaseOnStartup` (runs `VACUUM`
        /// on the imported accounts DB after import). Missing/absent falls
        /// back to go-matching defaults (`NORMAL`, vacuum off).
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },

    /// Verify an already-imported catchpoint database.
    Verify {
        /// SQLite database path to verify.
        #[arg(long, default_value = "./ledger.sqlite")]
        db: PathBuf,

        /// Path to the catchpoint file (required for block header digest).
        #[arg(long)]
        file: Option<PathBuf>,

        /// Data directory to load `<data-dir>/config.json` from (issue
        /// #749): `AccountsRebuildSynchronousMode` for the verify
        /// connection.
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },

    /// Export a catchpoint file from a local ledger database.
    Export {
        /// Ledger path (prefix, or a `.sqlite` / `.tracker.sqlite` path).
        #[arg(long, default_value = "./ledger.sqlite")]
        db: PathBuf,

        /// Output catchpoint file path. Optional when `--data-dir`'s
        /// `config.json` sets a non-empty `CatchpointDir` (issue #749):
        /// defaults to `<CatchpointDir>/<round>.catchpoint(.tar.gz)`.
        /// Required otherwise.
        #[arg(long)]
        output: Option<PathBuf>,

        /// Round of the account snapshot. Defaults to `acctrounds('acctbase')`.
        #[arg(long)]
        round: Option<u64>,

        /// Block round anchoring the label. Defaults to `--round`.
        #[arg(long)]
        blocks_round: Option<u64>,

        /// Hex-encoded 32-byte block header digest for `--blocks-round`.
        /// Defaults to the digest of that block in the ledger's block DB.
        #[arg(long)]
        block_digest: Option<String>,

        /// Skip the onlineaccounts / onlineroundparamstail tables
        /// (pre-consensus-v40 catchpoint contents).
        #[arg(long)]
        no_online_data: bool,

        /// Write an uncompressed tar instead of tar.gz.
        #[arg(long)]
        no_gzip: bool,

        /// Data directory to load `<data-dir>/config.json` from — see
        /// `--output`'s note on `CatchpointDir` (issue #749).
        #[arg(long)]
        data_dir: Option<PathBuf>,
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

        /// Output file path. Optional when `--data-dir`'s `config.json`
        /// sets a non-empty `CatchpointDir` (issue #749): defaults to
        /// `<CatchpointDir>/<round>.catchpoint`. Required otherwise.
        #[arg(long)]
        output: Option<PathBuf>,

        /// Data directory to load `<data-dir>/config.json` from (issue
        /// #749): `CatchpointDir` (default output location, see
        /// `--output`), `MaxCatchpointDownloadDuration` (overall request
        /// timeout, previously hardcoded to 30 minutes, matching neither
        /// of go's real defaults), and
        /// `MinCatchpointFileDownloadBytesPerSecond` (per-chunk stall
        /// detection, previously entirely absent).
        #[arg(long)]
        data_dir: Option<PathBuf>,
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
