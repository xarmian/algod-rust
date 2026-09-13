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

//! WebSocket network coordinator.
//!
//! `WebsocketNetwork` manages multiple [`WsPeer`] connections and implements
//! the [`GossipNode`] trait, providing broadcast/relay message delivery,
//! peer lifecycle management, and background mesh maintenance.
//!
//! This is the Rust equivalent of Go's `WebsocketNetwork` in
//! `go-algorand/network/wsNetwork.go`.
//!
//! # Architecture
//!
//! The network maintains a thread-safe registry of active peers (keyed by
//! remote address).  Background tasks handle:
//!
//! - **Mesh maintenance** — delegated to [`MeshThread`] which periodically
//!   connects to new peers from the phonebook to maintain target connectivity
//!   (gossip fanout), with exponential backoff and deduplication.
//! - **Peer monitoring** — detects idle/disconnected peers and removes them.
//!   Also drains any deferred disconnects that could not be processed
//!   synchronously due to lock contention.
//! - **Receive dispatch** — for each peer added via [`add_peer`], a tokio task
//!   reads incoming messages and dispatches them to the [`Multiplexer`].
//!
//! Shutdown is coordinated via a [`CancellationToken`]; calling [`stop`]
//! cancels all background tasks and disconnects all peers.
//!
//! [`stop`]: WebsocketNetwork::stop
//! [`add_peer`]: WebsocketNetwork::add_peer

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicI32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::ws::WebSocket;
use axum::extract::{ConnectInfo, Path, State, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::Router;
use http::{HeaderMap, HeaderName, StatusCode};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::broadcast::{BroadcastHandle, BroadcastPeer, BroadcastThread};
use crate::conn_perf_monitor::{ConnectionPerformanceMonitor, NetworkAdvanceMonitor};
use crate::connect::{try_connect_with_phonebook, ConnectConfig};
use crate::forwarding_policy::ForwardingPolicy;
use crate::gossip_node::{GossipNode, Peer, PeerOption};
use crate::handler::{Multiplexer, TaggedMessageHandler, TaggedMessageValidatorHandler};
use crate::handshake::{check_protocol_version_match, effective_protocol_versions, VersionMatch};
use crate::health_service::health_router;
use crate::mesh::{ConnectFn, MeshRequest, MeshThread, PeerCounter};
use crate::message::OutgoingMessage;
use crate::message_filter::{
    dedup_safe_tag, generate_message_digest, MessageFilter, MESSAGE_FILTER_SIZE,
};
use crate::msg_of_interest::marshal_msg_of_interest;
use crate::peer_role::{ARCHIVAL_ROLE, RELAY_ROLE};
use crate::phonebook::Phonebook;
use crate::request_response::{encode_uvarint, hash_topics, RESPONSE_HASH_FIELD};
use crate::request_tracker::ConnectionTracker;
use crate::tag::Tag;
use crate::topics::{Topic, Topics};
use crate::ws_peer::{default_send_message_tags, PeerHandle};

// ---------------------------------------------------------------------------
// Constants (matching go-algorand defaults)
// ---------------------------------------------------------------------------

/// Default gossip fanout — target number of outgoing peer connections.
///
/// Matches Go's `GossipFanout` default of 4.
const DEFAULT_GOSSIP_FANOUT: usize = 4;

/// Default interval between mesh maintenance cycles.
///
/// Matches Go's `meshThreadInterval` of 1 minute.
const DEFAULT_MESH_INTERVAL: Duration = Duration::from_secs(60);

/// Default stateful vpack vote-compression table size, advertised on every
/// outbound connection alongside stateless vote compression.
///
/// Matches go-algorand's `config.Local` `StatefulVoteCompressionTableSize:
/// 2048` default (`config/local_defaults.go`). Issue #1239 gave the
/// *enabled/disabled* half of this (`EnableVoteCompression`) a real config
/// knob (see [`WebsocketNetworkConfig::enable_vote_compression`]), but the
/// table *size* itself remains hardcoded to Go's own default — same
/// treatment given to
/// [`crate::peer_features::PeerFeatureFlags::COMPRESSED_PROPOSAL`] (also
/// unconditionally advertised, not config-gated).
const DEFAULT_VOTE_COMPRESSION_TABLE_SIZE: u32 = 2048;

/// Default maximum peer inactivity before disconnection.
///
/// Matches Go's `maxPeerInactivityDuration` of 5 minutes.
const DEFAULT_MAX_PEER_INACTIVITY: Duration = Duration::from_secs(5 * 60);

/// Default slow-write threshold (how long a message can sit in the send queue).
///
/// Matches Go's `maxMessageQueueDuration` of 25 seconds.
const DEFAULT_SLOW_WRITE_THRESHOLD: Duration = Duration::from_secs(25);

/// How long the network must go without an agreement-protocol advance
/// before the clique-resolution fallback disconnects a random outgoing
/// peer (issue #1101). Matches go's `cliqueResolveInterval`
/// (`network/wsNetwork.go`).
const CLIQUE_RESOLVE_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Reserve one slot from a capacity-limited "throttled outgoing connection"
/// counter, mirroring go's decrement-and-restore-on-failure pattern
/// (`wn.throttledOutgoingConnections.Add(int32(-1)) >= 0`,
/// `network/wsNetwork.go:2166-2170`): decrement first, and if that leaves
/// the counter negative, immediately give the slot back and report failure
/// rather than leaving the counter permanently over-drawn.
fn reserve_throttled_slot(counter: &AtomicI32) -> bool {
    if counter.fetch_sub(1, Ordering::SeqCst) > 0 {
        true
    } else {
        counter.fetch_add(1, Ordering::SeqCst);
        false
    }
}

/// Return a peer's throttled-connection slot to the counter when that
/// connection closes, if (and only if) it held one — mirrors go's
/// `if peer.throttledOutgoingConnection { wn.throttledOutgoingConnections.Add(1) }`
/// (`network/wsNetwork.go:2381-2382`).
fn release_throttled_slot(counter: &AtomicI32, entry: &PeerEntry) {
    release_throttled_slot_if_held(counter, entry.throttled_outgoing_connection);
}

/// The pure counter-side logic behind [`release_throttled_slot`], split out
/// so it can be unit-tested without constructing a full [`PeerEntry`]
/// (which needs a live [`PeerHandle`]).
fn release_throttled_slot_if_held(counter: &AtomicI32, held_a_slot: bool) {
    if held_a_slot {
        counter.fetch_add(1, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// wantTXGossip role-transition narrowing (issue #1156)
// ---------------------------------------------------------------------------

/// Reports the node-role facts that drive dynamic transaction-gossip
/// narrowing/widening.
///
/// Mirrors go's `NodeInfo` interface (`network/wsNetwork.go`) — narrowed
/// here to only the one method [`WebsocketNetwork`] actually consults.
/// When no implementation is registered via
/// [`WebsocketNetwork::set_node_info`], the network behaves like go's
/// `nopeNodeInfo` fallback: never participating.
pub trait NodeInfo: Send + Sync {
    /// Returns `true` if this node holds live participation keys and may
    /// vote on blocks or propose blocks — i.e. it needs the transaction
    /// pool populated via gossip even though it isn't a relay.
    fn is_participating(&self) -> bool;
}

/// `wantTXGossip` has not yet been decided — the initial state for a
/// non-relay, non-force-fetch node before its first role-transition
/// refresh. Matches go's `wantTXGossipUnk`.
pub const WANT_TX_GOSSIP_UNK: u8 = 0;
/// This node currently wants (and has registered interest in) `TX` gossip.
/// Matches go's `wantTXGossipYes`.
pub const WANT_TX_GOSSIP_YES: u8 = 1;
/// This node currently does not want `TX` gossip and has deregistered
/// interest in it. Matches go's `wantTXGossipNo`.
pub const WANT_TX_GOSSIP_NO: u8 = 2;

/// Returns the current time as nanoseconds since the Unix epoch, matching
/// the clock [`crate::message::IncomingMessage::received_at`] is stamped
/// with (see `ws_peer.rs`'s `now_ns` construction sites) — the same epoch
/// [`ConnectionPerformanceMonitor`] expects for `reset`/`notify`.
fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for a [`WebsocketNetwork`].
///
/// Provides sensible defaults matching go-algorand's `config.Local` defaults.
#[derive(Debug, Clone)]
pub struct WebsocketNetworkConfig {
    /// Target number of outgoing peer connections (default: 4).
    pub gossip_fanout: usize,

    /// Interval between mesh maintenance cycles (default: 1 min).
    pub mesh_interval: Duration,

    /// Maximum peer inactivity before disconnection (default: 5 min).
    pub max_peer_inactivity: Duration,

    /// How long a message can sit in the send queue before considering
    /// the peer slow (default: 25s).
    pub slow_write_threshold: Duration,

    /// Genesis ID of the network (e.g. "mainnet-v1.0").
    pub genesis_id: String,

    /// Network identifier for phonebook/discovery (e.g. "mainnet").
    pub network_id: String,

    // -------------------------------------------------------------------
    // Relay / listener configuration (Epic 34)
    // -------------------------------------------------------------------
    /// Bind address for relay mode (e.g. `:4160`).  `None` means the node
    /// does not listen for inbound connections.
    ///
    /// Matches Go's `NetAddress` (default `""`).
    pub net_address: Option<String>,

    /// Maximum number of simultaneous inbound connections (default: 2400).
    ///
    /// Matches Go's `IncomingConnectionsLimit`.
    pub incoming_connections_limit: u32,

    /// Whether this node should forward (relay) messages to other peers
    /// (default: `false`).
    ///
    /// Matches Go's `ForceRelayMessages`.
    pub relay_messages: bool,

    /// Maximum connections allowed from a single IP address (default: 8).
    ///
    /// Matches Go's `MaxConnectionsPerIP`.
    pub max_connections_per_ip: u32,

    /// Connection-rate limit: maximum new connections per window (default: 60).
    ///
    /// Matches Go's `ConnectionsRateLimitingCount`.
    pub connections_rate_limiting_count: u32,

    /// Maximum number of peers a single broadcast is delivered to (default:
    /// [`UNBOUNDED_BROADCAST_CONNECTIONS_LIMIT`], i.e. unbounded).
    ///
    /// Matches Go's `BroadcastConnectionsLimit`, whose real default is `-1`
    /// (unbounded) — go's config type is a signed `int` so it can hold that
    /// sentinel directly; this field stays `u32` for the broadcast hot path
    /// (peer counts never approach `u32::MAX`), so callers translate a
    /// negative `config.json`/CLI value to
    /// [`UNBOUNDED_BROADCAST_CONNECTIONS_LIMIT`] before constructing this
    /// config (see `algo_config::Local::broadcast_connections_limit` and its
    /// callers in `bin/algod-rust`). Issue #748 fixed algod-rust's prior
    /// hardcoded default of `35`, which diverged from go's real
    /// unbounded-by-default behavior.
    pub broadcast_connections_limit: u32,

    /// Disables the `gossip_fanout`/relay-mode-derived
    /// `throttled_outgoing_connections` seed, forcing it to `0` (default:
    /// `false`).
    ///
    /// Matches Go's `DisableOutgoingConnectionThrottling`: `Start()`
    /// (`network/wsNetwork.go:711-713`) seeds the counter from
    /// `GossipFanout`/relay-mode exactly like [`Self::gossip_fanout`]/
    /// [`Self::relay_messages`] already drive here (issue #1105), then
    /// unconditionally zeroes it when this flag is set — opting a node out
    /// of the performance-based "disconnect the worst throttled outgoing
    /// peer" mesh-maintenance behavior entirely. Issue #1316 fixed this
    /// field being round-tripped from config.json with no consuming code
    /// path at all.
    pub disable_outgoing_connection_throttling: bool,

    /// Path to TLS certificate file.  `None` means plain HTTP/WS.
    ///
    /// Matches Go's `TLSCertFile`.
    pub tls_cert_file: Option<String>,

    /// Path to TLS private-key file.  `None` means plain HTTP/WS.
    ///
    /// Matches Go's `TLSKeyFile`.
    pub tls_key_file: Option<String>,

    /// Memory cap for the block service cache in bytes (default:
    /// 500,000,000 — see [`DEFAULT_BLOCK_SERVICE_MEM_CAP`]).
    ///
    /// Matches Go's `BlockServiceMemCap` exactly (issue #748 fixed a prior
    /// divergence: this used to default to `500 * 1024 * 1024`
    /// (524,288,000), a binary-MiB approximation rather than go's literal
    /// decimal byte count).
    pub block_service_mem_cap: u64,

    // -------------------------------------------------------------------
    // Message-hash dedup filter sizing (issue #768)
    // -------------------------------------------------------------------
    /// Whether an incoming-message dedup filter is constructed at all
    /// (default: `false`, matching go's `EnableIncomingMessageFilter`).
    pub enable_incoming_message_filter: bool,

    /// Number of ring buckets for the incoming-message filter (default: 5).
    ///
    /// Matches Go's `IncomingMessageFilterBucketCount`.
    pub incoming_message_filter_bucket_count: usize,

    /// Maximum entries per incoming-filter bucket (default: 512).
    ///
    /// Matches Go's `IncomingMessageFilterBucketSize`.
    pub incoming_message_filter_bucket_size: usize,

    /// Whether an outgoing-message dedup filter is constructed at all
    /// (default: `true`, matching go's
    /// `EnableOutgoingNetworkMessageFiltering`).
    pub enable_outgoing_network_message_filtering: bool,

    /// Number of ring buckets for the outgoing-message filter (default: 3).
    ///
    /// Matches Go's `OutgoingMessageFilterBucketCount`.
    pub outgoing_message_filter_bucket_count: usize,

    /// Maximum entries per outgoing-filter bucket (default: 128).
    ///
    /// Matches Go's `OutgoingMessageFilterBucketSize`.
    pub outgoing_message_filter_bucket_size: usize,

    /// Whether inbound connections from loopback addresses are exempted
    /// from the per-IP connection-rate limiter (default: `true`, matching
    /// go's `DisableLocalhostConnectionRateLimit`).
    pub disable_localhost_connection_rate_limit: bool,

    /// Whether the relay router logs every incoming HTTP request (default:
    /// `false`, matching go's `EnableRequestLogger`). See
    /// [`crate::request_logger`] for what gets logged and why.
    pub enable_request_logger: bool,

    /// Force this node to keep subscribing to transaction gossip
    /// (`TX`) even though it is neither a relay nor participating
    /// (default: `false`).
    ///
    /// Matches Go's `ForceFetchTransactions`. Setting this pins
    /// `wantTXGossip` to "yes" at startup and disables the dynamic
    /// role-transition narrowing entirely (`OnNetworkAdvance` never wakes
    /// the refresh loop while this is set — see
    /// [`WebsocketNetwork::on_network_advance`]), the same way go's
    /// `postMessagesOfInterestThread` gates on
    /// `!wn.relayMessages && !wn.config.ForceFetchTransactions`
    /// (`network/wsNetwork.go`).
    pub force_fetch_transactions: bool,

    /// HTTP header field name to trust for the client's real IP address
    /// when this node runs behind a reverse proxy / load balancer (default:
    /// `""`, disabled).
    ///
    /// Matches Go's `UseXForwardedForAddressField`. When non-empty, inbound
    /// connection tracking/rate-limiting (per-IP connection count and
    /// connection-rate window) key on the address extracted from this
    /// header via [`crate::request_tracker::get_forwarded_connection_address`]
    /// instead of the raw socket address, mirroring go's
    /// `RequestTracker.remoteHostProxyFix` (`network/requestTracker.go`).
    pub use_x_forwarded_for_address_field: String,

    /// Whether this node advertises/negotiates stateless+stateful vpack
    /// vote compression at all (default: `true`, matching go's
    /// `EnableVoteCompression`). When `false`, [`advertise_vote_compression`]
    /// is called with `enabled = false` on every handshake this node
    /// participates in, so it negotiates down to the uncompressed
    /// `AgreementVote` wire format — mirroring go's
    /// `network/wsNetwork.go` `setHeaders` gating on
    /// `cfg.EnableVoteCompression`. Issue #1239: previously always `true`
    /// with no config knob (`algo_config::Local::enable_vote_compression`
    /// did not exist). Does not affect
    /// [`DEFAULT_VOTE_COMPRESSION_TABLE_SIZE`], which stays hardcoded.
    pub enable_vote_compression: bool,

    /// `config.Local.NetworkProtocolVersion` override (default: `""`, no
    /// override). When non-empty, pins both outgoing dial headers and
    /// incoming/outgoing version matching to exactly this one protocol
    /// version instead of the full built-in
    /// [`crate::handshake::SUPPORTED_PROTOCOL_VERSIONS`] list — matching
    /// go's `network/wsNetwork.go:665-669`/`network/p2pNetwork.go:289-290`
    /// override. Issue #1320: previously round-tripped from `config.json`
    /// with no consuming code path at all. See
    /// [`crate::handshake::effective_protocol_versions`].
    pub network_protocol_version: String,
}

/// Default block-service memory cap: 500,000,000 bytes.
///
/// Matches Go's `BlockServiceMemCap` literal `"500000000"`
/// (`config/localTemplate.go:616`) exactly. Issue #748 fixed a prior
/// divergence here: this constant used to be `500 * 1024 * 1024`
/// (524,288,000 — a binary-MiB approximation), about 5% larger than go's
/// real decimal byte count.
const DEFAULT_BLOCK_SERVICE_MEM_CAP: u64 = 500_000_000;

/// Sentinel meaning "no cap" for [`WebsocketNetworkConfig::broadcast_connections_limit`].
/// Translates go's `-1` (unbounded) `BroadcastConnectionsLimit` default —
/// see that field's doc comment.
pub const UNBOUNDED_BROADCAST_CONNECTIONS_LIMIT: u32 = u32::MAX;

impl Default for WebsocketNetworkConfig {
    fn default() -> Self {
        Self {
            gossip_fanout: DEFAULT_GOSSIP_FANOUT,
            mesh_interval: DEFAULT_MESH_INTERVAL,
            max_peer_inactivity: DEFAULT_MAX_PEER_INACTIVITY,
            slow_write_threshold: DEFAULT_SLOW_WRITE_THRESHOLD,
            genesis_id: String::new(),
            network_id: String::new(),
            net_address: None,
            incoming_connections_limit: 2400,
            relay_messages: false,
            max_connections_per_ip: 8,
            connections_rate_limiting_count: 60,
            broadcast_connections_limit: UNBOUNDED_BROADCAST_CONNECTIONS_LIMIT,
            disable_outgoing_connection_throttling: false,
            tls_cert_file: None,
            tls_key_file: None,
            block_service_mem_cap: DEFAULT_BLOCK_SERVICE_MEM_CAP,
            enable_incoming_message_filter: false,
            incoming_message_filter_bucket_count: 5,
            incoming_message_filter_bucket_size: 512,
            enable_outgoing_network_message_filtering: true,
            outgoing_message_filter_bucket_count: 3,
            outgoing_message_filter_bucket_size: 128,
            disable_localhost_connection_rate_limit: true,
            enable_request_logger: false,
            force_fetch_transactions: false,
            use_x_forwarded_for_address_field: String::new(),
            enable_vote_compression: true,
            network_protocol_version: String::new(),
        }
    }
}

/// Builds a fresh outgoing-message filter for one new peer connection, or
/// `None` when outgoing filtering is disabled.
///
/// Deliberately a plain function (not cached state): every call site that
/// establishes a real connection — the inbound accept path
/// (`handle_gossip_websocket`) and both outbound-dial paths
/// (`WebsocketNetwork::mesh_connect`, `NetworkConnectFn::try_dial`) — must
/// call this itself to get its *own* instance rather than cloning an `Arc`
/// built once and shared network-wide. See
/// [`WebsocketNetwork::new_outgoing_message_filter`]'s docs for why (issue
/// #803).
fn build_outgoing_message_filter(
    enabled: bool,
    bucket_count: usize,
    bucket_size: usize,
) -> Option<Arc<MessageFilter>> {
    enabled.then(|| Arc::new(MessageFilter::new(bucket_count, bucket_size)))
}

// ---------------------------------------------------------------------------
// Direction tracking
// ---------------------------------------------------------------------------

/// Whether a peer connection was dialed outbound or accepted inbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDirection {
    /// We dialed this peer.
    Outbound,
    /// This peer connected to us.
    Inbound,
}

/// Metadata we track for each active peer alongside the handle.
struct PeerEntry {
    /// The peer handle for sending messages and controlling lifecycle.
    handle: PeerHandle,
    /// Direction of the connection.
    direction: PeerDirection,
    /// This connection's own outgoing-message filter, if outgoing filtering
    /// is enabled — a fresh, independently-owned instance per connection
    /// (issue #803), not shared with any other peer. Kept here (rather than
    /// only inside the connection's read/write tasks) so
    /// [`WebsocketNetwork::peer_outgoing_message_filter`] can expose a
    /// single connection's dedup state for diagnostics/tests without
    /// affecting any other peer's.
    outgoing_filter: Option<Arc<MessageFilter>>,
    /// Whether this connection holds a slot from
    /// [`WebsocketNetwork::throttled_outgoing_connections`], assigned once
    /// at connect time. Mirrors go's `wsPeer.throttledOutgoingConnection`
    /// (`network/wsPeer.go`) — always `false` for inbound connections, since
    /// go only ever assigns this on the outgoing-dial path
    /// (`network/wsNetwork.go:2166-2181`). Only a peer with this flag set is
    /// eligible for a performance-based disconnect in
    /// [`WebsocketNetwork::check_existing_connections_need_disconnecting`]
    /// (issue #1105).
    throttled_outgoing_connection: bool,
    /// Priority weight for this peer, mirroring go's `wsPeer.prioWeight`
    /// (`network/wsPeer.go`), set via
    /// [`WebsocketNetwork::set_peer_priority`] (issue #1428). Defaults to
    /// `0` — the same priority every peer implicitly had before priority
    /// tracking existed, so broadcast fan-out ordering is unaffected until
    /// something actually assigns a weight. An [`AtomicU64`] so it can be
    /// updated without taking the peers map's write lock.
    prio_weight: AtomicU64,
}

// ---------------------------------------------------------------------------
// WebsocketNetwork
// ---------------------------------------------------------------------------

/// Central networking coordinator that manages WebSocket peer connections.
///
/// Implements [`GossipNode`] to provide broadcast, relay, handler dispatch,
/// and mesh maintenance.  Equivalent to Go's `WebsocketNetwork`.
pub struct WebsocketNetwork {
    /// Configuration.
    config: WebsocketNetworkConfig,

    /// Thread-safe registry of active peers, keyed by remote address.
    /// Wrapped in `Arc` so spawned receive tasks can access the map.
    peers: Arc<RwLock<HashMap<String, PeerEntry>>>,

    /// Addresses currently being connected to (prevents duplicate dials).
    connecting: Mutex<HashSet<String>>,

    /// Shared phonebook for peer address management.
    phonebook: Arc<Phonebook>,

    /// Message handler dispatch.
    multiplexer: Arc<Multiplexer>,

    /// Deduplication filter for incoming messages. `None` when
    /// `enable_incoming_message_filter` is off (go's default). This one
    /// *is* correctly shared network-wide — mirroring go's
    /// `wn.incomingMsgFilter` (`network/wsNetwork.go:660`), a single
    /// instance copied by reference into every `wsPeer`.
    incoming_message_filter: Option<Arc<MessageFilter>>,

    /// Cancellation token for coordinated shutdown.
    cancel: CancellationToken,

    /// Sender for on-demand mesh refresh requests (e.g. from `on_network_advance`).
    /// Lazily initialized when `start_arc()` spawns the `MeshThread`.
    mesh_update_tx: Mutex<Option<mpsc::Sender<MeshRequest>>>,

    /// Addresses whose disconnect was deferred due to lock contention.
    /// The monitor task drains this on each cycle.
    pending_disconnects: Arc<std::sync::Mutex<Vec<String>>>,

    /// Background task handles, stored so they are not dropped prematurely.
    tasks: Mutex<Vec<JoinHandle<()>>>,

    // -------------------------------------------------------------------
    // Relay / inbound server state (Epic 34)
    // -------------------------------------------------------------------
    /// Per-node random identifier used for self-loop detection.
    ///
    /// Generated once at construction time.  Sent as
    /// `X-Algorand-NodeRandom` on outgoing connections and checked
    /// against the same header on incoming ones.
    node_random: String,

    /// Per-IP connection tracker for inbound connections.
    connection_tracker: Arc<ConnectionTracker>,

    /// Set once a warning has been logged about
    /// `use_x_forwarded_for_address_field` being configured but not
    /// actually present on inbound request headers. Mirrors go's
    /// `RequestTracker.misconfiguredUseForwardedForAddress` — logs the
    /// warning at most once per node lifetime rather than once per request.
    misconfigured_x_forwarded_for: std::sync::atomic::AtomicBool,

    /// The local listening address of the relay server once started.
    /// `None` when not in relay mode or before `start` completes.
    listen_addr: std::sync::Mutex<Option<SocketAddr>>,

    /// HTTP handlers registered via [`GossipNode::register_http_handler`]
    /// before the server starts.  Collected here and merged into the axum
    /// `Router` at start time.
    registered_handlers: std::sync::Mutex<Vec<(String, Router)>>,

    // -------------------------------------------------------------------
    // Broadcast thread (priority queues, stale dropping)
    // -------------------------------------------------------------------
    /// Background broadcast thread for relay message forwarding.
    ///
    /// Initialized when the network starts in relay mode (`start_arc`).
    /// `None` when relay mode is disabled or the network hasn't started yet.
    /// Background broadcast thread for relay message forwarding.
    ///
    /// Wrapped in `Arc` so it can be shared with the mesh connect adapter
    /// (which needs to relay messages from outbound peers to inbound peers).
    broadcast_thread: Arc<std::sync::Mutex<Option<BroadcastThread>>>,

    // -------------------------------------------------------------------
    // Outgoing-connection performance monitoring (issue #1101, wiring
    // #1088's standalone `conn_perf_monitor` module into a live decision)
    // -------------------------------------------------------------------
    /// Watches outgoing peers' relative `AgreementVote` delivery timing to
    /// find the consistently-slowest one. Mirrors go's
    /// `wn.connPerfMonitor` (`network/wsNetwork.go`), fed by every outgoing
    /// peer's receive loop and consulted by
    /// [`WebsocketNetwork::check_existing_connections_need_disconnecting`].
    conn_perf_monitor: Arc<std::sync::Mutex<ConnectionPerformanceMonitor>>,

    /// Watchdog for detecting that the agreement protocol has stalled
    /// (possible network clique). Mirrors go's
    /// `outgoingConnsCloser.netAdvMonitor`.
    network_advance_monitor: Arc<std::sync::Mutex<NetworkAdvanceMonitor>>,

    /// Capacity-limited counter of outgoing-connection slots still eligible
    /// to be marked `throttled_outgoing_connection` at connect time. Mirrors
    /// go's `wn.throttledOutgoingConnections` (`network/wsNetwork.go:242`),
    /// seeded in [`Self::new`] from `gossip_fanout` and relay-mode exactly
    /// like go's `Start()` (`wsNetwork.go:704-712`): half of `gossip_fanout`
    /// for a relay, all of it for a non-relay. Only a bounded fraction of
    /// outgoing peers can ever be eligible for a performance-based
    /// disconnect (issue #1105) — this is what enforces that bound.
    throttled_outgoing_connections: Arc<AtomicI32>,

    // -------------------------------------------------------------------
    // wantTXGossip role-transition narrowing (issue #1156)
    // -------------------------------------------------------------------
    /// Node-role oracle consulted by the MOI refresh loop. `None` behaves
    /// like go's `nopeNodeInfo` (never participating). Set via
    /// [`Self::set_node_info`].
    node_info: Arc<std::sync::Mutex<Option<Arc<dyn NodeInfo>>>>,

    /// Current transaction-gossip subscription state (one of
    /// [`WANT_TX_GOSSIP_UNK`]/[`WANT_TX_GOSSIP_YES`]/[`WANT_TX_GOSSIP_NO`]).
    /// Mirrors go's `wn.wantTXGossip`.
    want_tx_gossip: Arc<AtomicU8>,

    /// This node's own advertised message-of-interest tag set, sent to
    /// peers whenever it is customized. `None` means "never customized" —
    /// mirrors go's nullable `wn.messagesOfInterest` map, which stays `nil`
    /// (and so nothing gets pushed to peers) until the first
    /// `register_message_interest`/`deregister_message_interest` call.
    messages_of_interest: Arc<RwLock<Option<HashSet<Tag>>>>,

    /// Sender for on-demand MOI-refresh requests (mirrors go's
    /// `wn.messagesOfInterestRefresh`), woken by
    /// [`Self::on_network_advance`]. Lazily initialized when
    /// [`Self::start_arc`] spawns the refresh loop.
    messages_of_interest_refresh_tx: Mutex<Option<mpsc::Sender<()>>>,

    /// Shared per-wire-tag byte/message traffic counters (issue #1425),
    /// mirroring go's process-global `network.TagCounter` vars
    /// (`networkSentBytesByTag` etc., `network/metrics.go`). One instance is
    /// shared across every peer this network accepts or dials, so counts
    /// aggregate node-wide traffic exactly like go's package-level vars.
    network_metrics: Arc<crate::metrics::NetworkTagMetrics>,
}

impl WebsocketNetwork {
    /// Create a new `WebsocketNetwork` with the given configuration and
    /// shared phonebook.
    pub fn new(config: WebsocketNetworkConfig, phonebook: Arc<Phonebook>) -> Self {
        let node_random: u64 = rand::random();
        let incoming_message_filter = config.enable_incoming_message_filter.then(|| {
            Arc::new(MessageFilter::new(
                config.incoming_message_filter_bucket_count,
                config.incoming_message_filter_bucket_size,
            ))
        });
        // Mirrors go's `Start()` seeding of `wn.throttledOutgoingConnections`
        // (`network/wsNetwork.go:704-712`): half of `GossipFanout` for a
        // relay (`net_address` set and `relay_messages` on — go's
        // `wn.relayMessages`, computed the same way as
        // `effective_relay_messages()` below), all of it for a non-relay.
        let effective_relay_messages = config.net_address.is_some() || config.relay_messages;
        let mut throttled_outgoing_connections_seed = if effective_relay_messages {
            (config.gossip_fanout / 2) as i32
        } else {
            config.gossip_fanout as i32
        };
        // Mirrors go's `Start()`: `if wn.config.DisableOutgoingConnectionThrottling
        // { wn.throttledOutgoingConnections.Store(0) }` (`network/wsNetwork.go:711-713`),
        // applied as a post-seed override exactly like go's own two-step
        // structure (issue #1316).
        if config.disable_outgoing_connection_throttling {
            throttled_outgoing_connections_seed = 0;
        }
        // Mirrors go's `setup()`: `if wn.relayMessages || wn.config.ForceFetchTransactions
        // { wn.wantTXGossip.Store(wantTXGossipYes) }` (`network/wsNetwork.go:601-604`).
        // A plain non-relay, non-force node starts "undecided" — its first
        // `OnNetworkAdvance`-triggered refresh decides based on
        // `is_participating()`.
        let want_tx_gossip_seed = if effective_relay_messages || config.force_fetch_transactions {
            WANT_TX_GOSSIP_YES
        } else {
            WANT_TX_GOSSIP_UNK
        };
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            connecting: Mutex::new(HashSet::new()),
            phonebook,
            multiplexer: Arc::new(Multiplexer::new()),
            incoming_message_filter,
            cancel: CancellationToken::new(),
            mesh_update_tx: Mutex::new(None),
            pending_disconnects: Arc::new(std::sync::Mutex::new(Vec::new())),
            tasks: Mutex::new(Vec::new()),
            node_random: node_random.to_string(),
            connection_tracker: Arc::new(ConnectionTracker::new(Duration::from_secs(1))),
            misconfigured_x_forwarded_for: std::sync::atomic::AtomicBool::new(false),
            listen_addr: std::sync::Mutex::new(None),
            registered_handlers: std::sync::Mutex::new(Vec::new()),
            broadcast_thread: Arc::new(std::sync::Mutex::new(None)),
            conn_perf_monitor: Arc::new(std::sync::Mutex::new(ConnectionPerformanceMonitor::new(
                &[Tag::AgreementVote],
            ))),
            network_advance_monitor: Arc::new(std::sync::Mutex::new(NetworkAdvanceMonitor::new())),
            throttled_outgoing_connections: Arc::new(AtomicI32::new(
                throttled_outgoing_connections_seed,
            )),
            node_info: Arc::new(std::sync::Mutex::new(None)),
            want_tx_gossip: Arc::new(AtomicU8::new(want_tx_gossip_seed)),
            messages_of_interest: Arc::new(RwLock::new(None)),
            messages_of_interest_refresh_tx: Mutex::new(None),
            network_metrics: Arc::new(crate::metrics::NetworkTagMetrics::new()),
        }
    }

    /// Shared per-wire-tag byte/message traffic counters (issue #1425).
    ///
    /// Aggregates traffic across every peer this network accepts or dials —
    /// mirrors go's process-global `network.TagCounter` vars. Use this to
    /// expose `to_prometheus_text()` via a `/metrics` endpoint, or to read
    /// individual counts for diagnostics/tests.
    pub fn network_metrics(&self) -> &Arc<crate::metrics::NetworkTagMetrics> {
        &self.network_metrics
    }

    /// Create a `WebsocketNetwork` with default configuration.
    pub fn with_defaults(genesis_id: &str, network_id: &str) -> Self {
        let config = WebsocketNetworkConfig {
            genesis_id: genesis_id.to_string(),
            network_id: network_id.to_string(),
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        Self::new(config, phonebook)
    }

    /// Returns a reference to the shared phonebook.
    pub fn phonebook(&self) -> &Arc<Phonebook> {
        &self.phonebook
    }

    /// Returns a reference to the multiplexer.
    pub fn multiplexer(&self) -> &Arc<Multiplexer> {
        &self.multiplexer
    }

    /// Returns the incoming-message dedup filter, if
    /// `enable_incoming_message_filter` is on (go's default is off).
    pub fn incoming_message_filter(&self) -> Option<&Arc<MessageFilter>> {
        self.incoming_message_filter.as_ref()
    }

    /// Constructs a fresh, independently-owned outgoing-message filter for a
    /// new peer connection, sized from this network's config
    /// (`enable_outgoing_network_message_filtering` /
    /// `outgoing_message_filter_bucket_count` / `_bucket_size`). Returns
    /// `None` when filtering is disabled.
    ///
    /// Every call returns a *new* [`MessageFilter`] instance — deliberately.
    /// Go's `outgoingMsgFilter` is a per-`wsPeer` field, constructed fresh
    /// in `wsPeer.init()` for each connection object
    /// (`network/wsPeer.go:213`, `network/wsPeer.go:469`), populated only by
    /// `MsgDigestSkip` messages *that specific peer* sends, and consulted
    /// only when deciding whether to send *to that specific peer*
    /// (`network/wsPeer.go:932`). Sharing one instance across connections
    /// (this network's behaviour before issue #803) means one peer's
    /// `MsgDigestSkip` claim wrongly suppresses sends to every other peer
    /// too — never clone one call's result into more than one connection's
    /// [`crate::ws_peer::WsPeerConfig::outgoing_filter`].
    pub fn new_outgoing_message_filter(&self) -> Option<Arc<MessageFilter>> {
        build_outgoing_message_filter(
            self.config.enable_outgoing_network_message_filtering,
            self.config.outgoing_message_filter_bucket_count,
            self.config.outgoing_message_filter_bucket_size,
        )
    }

    /// Returns the outgoing-message filter belonging to one specific
    /// connected peer (looked up by remote address), if outgoing filtering
    /// is enabled and that peer is currently connected.
    ///
    /// Each connection owns its own filter instance (issue #803): this is a
    /// per-*connection* view, not a network-wide one. Mainly useful for
    /// diagnostics/tests that need to observe a single connection's dedup
    /// state without that state being (or appearing to be) shared with any
    /// other peer.
    pub async fn peer_outgoing_message_filter(&self, addr: &str) -> Option<Arc<MessageFilter>> {
        let peers = self.peers.read().await;
        peers.get(addr).and_then(|e| e.outgoing_filter.clone())
    }

    /// Registers the [`NodeInfo`] oracle consulted by the `wantTXGossip`
    /// role-transition refresh loop (issue #1156). Mirrors go's
    /// `WebsocketNetwork.nodeInfo` field, normally wired to the node's
    /// participation-key registry. Not calling this leaves the network
    /// behaving like go's `nopeNodeInfo` fallback (never participating).
    pub fn set_node_info(&self, node_info: Arc<dyn NodeInfo>) {
        *self.node_info.lock().expect("node_info lock poisoned") = Some(node_info);
    }

    /// Whether this node currently holds live participation keys, per the
    /// registered [`NodeInfo`] oracle (`false` if none is registered).
    /// Mirrors go's `wn.nodeInfo.IsParticipating()`.
    fn is_participating(&self) -> bool {
        self.node_info
            .lock()
            .expect("node_info lock poisoned")
            .as_ref()
            .is_some_and(|info| info.is_participating())
    }

    /// Current `wantTXGossip` state — one of [`WANT_TX_GOSSIP_UNK`]/
    /// [`WANT_TX_GOSSIP_YES`]/[`WANT_TX_GOSSIP_NO`]. Exposed mainly for
    /// tests; mirrors go's `wn.wantTXGossip.Load()`.
    pub fn want_tx_gossip(&self) -> u8 {
        self.want_tx_gossip.load(Ordering::SeqCst)
    }

    /// Adds `tag` to this node's advertised message-of-interest set and
    /// pushes the updated set to every currently-connected peer. Mirrors
    /// go's `registerMessageInterest` (`network/wsNetwork.go`).
    ///
    /// The first call on a network that has never customized its interest
    /// set seeds it from [`default_send_message_tags`] first (go's
    /// `maps.Copy(wn.messagesOfInterest, defaultSendMessageTags)`).
    async fn register_message_interest(&self, tag: Tag) {
        let encoded = {
            let mut moi = self.messages_of_interest.write().await;
            let set = moi.get_or_insert_with(default_send_message_tags);
            set.insert(tag);
            marshal_msg_of_interest(&set.iter().copied().collect::<Vec<_>>())
        };
        self.push_message_of_interest_update(encoded).await;
    }

    /// Removes `tag` from this node's advertised message-of-interest set
    /// and pushes the updated set to every currently-connected peer.
    /// Mirrors go's `DeregisterMessageInterest`.
    async fn deregister_message_interest(&self, tag: Tag) {
        let encoded = {
            let mut moi = self.messages_of_interest.write().await;
            let set = moi.get_or_insert_with(default_send_message_tags);
            set.remove(&tag);
            marshal_msg_of_interest(&set.iter().copied().collect::<Vec<_>>())
        };
        self.push_message_of_interest_update(encoded).await;
    }

    /// Sends an already-encoded `MI` payload to every currently-connected
    /// peer, high-priority (mirrors go's `updateMessagesOfInterestEnc`
    /// iterating `wn.peerSnapshot` and go's `wsPeer.sendMessagesOfInterest`,
    /// which queues on the peer's high-priority send path).
    async fn push_message_of_interest_update(&self, encoded: Vec<u8>) {
        let peers = self.peers.read().await;
        for entry in peers.values() {
            let msg = OutgoingMessage::new(Tag::MsgOfInterest, encoded.clone());
            if let Err(e) = entry.handle.send_priority(msg) {
                tracing::debug!(error = %e, "failed to push messages-of-interest update to peer");
            }
        }
    }

    /// Runs one `wantTXGossip` role-transition decision — the body of go's
    /// `postMessagesOfInterestThread` loop iteration
    /// (`network/wsNetwork.go`): if this node is now participating and
    /// wasn't already subscribed to `TX` gossip, register interest in it;
    /// if it is no longer participating and was subscribed, deregister it.
    /// A no-op if the state hasn't changed since the last refresh.
    async fn refresh_want_tx_gossip(&self) {
        let participating = self.is_participating();
        let current = self.want_tx_gossip.load(Ordering::SeqCst);
        if participating && current != WANT_TX_GOSSIP_YES {
            self.register_message_interest(Tag::Transaction).await;
            self.want_tx_gossip
                .store(WANT_TX_GOSSIP_YES, Ordering::SeqCst);
        } else if !participating && current != WANT_TX_GOSSIP_NO {
            self.deregister_message_interest(Tag::Transaction).await;
            self.want_tx_gossip
                .store(WANT_TX_GOSSIP_NO, Ordering::SeqCst);
        }
    }

    /// Returns a reference to the connection tracker.
    pub fn connection_tracker(&self) -> &Arc<ConnectionTracker> {
        &self.connection_tracker
    }

    /// Returns the node's random identifier (for self-loop detection).
    pub fn node_random(&self) -> &str {
        &self.node_random
    }

    /// Returns `true` if this network is configured as a relay (has a
    /// listen address and relay_messages is enabled).
    pub fn is_relay(&self) -> bool {
        self.config.net_address.is_some() && self.config.relay_messages
    }

    /// Whether this node should forward (relay) gossip messages to its
    /// peers right now — go's
    /// `wn.relayMessages = wn.config.IsListenServer() || wn.config.ForceRelayMessages`
    /// (`network/wsNetwork.go:601`). Note the `||`: a node that is
    /// listening for inbound connections always forwards, regardless of
    /// `ForceRelayMessages`/`relay_messages`; that config field's only
    /// independent effect is letting a *non-listening* node forward too.
    /// This is deliberately different from [`Self::is_relay`] (which is an
    /// `&&`-based "is this a full listen+relay peer" diagnostic predicate,
    /// unrelated to whether messages actually get forwarded) — see issue
    /// #748, which found the two had been conflated.
    fn effective_relay_messages(&self) -> bool {
        self.config.net_address.is_some() || self.config.relay_messages
    }

    /// Returns the number of currently connected peers.
    pub async fn peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }

    /// Returns the remote addresses of all currently connected peers
    /// (both inbound and outbound), in unspecified order.
    ///
    /// Mainly useful for diagnostics/tests that need to enumerate peer keys
    /// without knowing them in advance (e.g. an accepted inbound
    /// connection's remote address is assigned by the OS, not chosen by
    /// either side).
    pub async fn peer_addresses(&self) -> Vec<String> {
        let peers = self.peers.read().await;
        peers.keys().cloned().collect()
    }

    /// Returns lightweight [`UnicastPeer`] references for all connected
    /// outbound peers.
    ///
    /// These references share the underlying send channels and request
    /// trackers with the real peer handles, so unicast request/response
    /// (e.g. block fetching) works without creating additional TCP
    /// connections.
    pub async fn get_unicast_peers(&self) -> Vec<Arc<dyn crate::gossip_node::UnicastPeer>> {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|e| e.direction == PeerDirection::Outbound && !e.handle.is_closed())
            .map(|e| Arc::new(e.handle.unicast_ref()) as Arc<dyn crate::gossip_node::UnicastPeer>)
            .collect()
    }

    /// Add a peer to the registry.
    ///
    /// Takes the incoming message receiver from the peer handle and spawns
    /// a receive/dispatch loop that reads messages, dispatches them to the
    /// multiplexer, and removes the peer on disconnect or error.  The
    /// receive task respects the network's [`CancellationToken`].
    ///
    /// `outgoing_filter` is the filter this specific connection's
    /// [`WsPeerConfig`](crate::ws_peer::WsPeerConfig) was already
    /// constructed with (see [`Self::new_outgoing_message_filter`]) — it is
    /// recorded here only so [`Self::peer_outgoing_message_filter`] can
    /// expose this one connection's dedup state; it must be a fresh
    /// instance per call, never one shared with another peer (issue #803).
    pub async fn add_peer(
        &self,
        mut handle: PeerHandle,
        direction: PeerDirection,
        outgoing_filter: Option<Arc<MessageFilter>>,
    ) {
        let addr = handle.remote_addr().to_string();

        // Take the incoming receiver before storing the handle.
        let incoming_rx = handle.take_incoming();

        // Clone the peer sender before moving the handle — needed for
        // sending Respond messages back (e.g. UniEnsBlockReq responses).
        let peer_sender = handle.sender();

        // Issue #1105: only outgoing connections are ever eligible to hold a
        // throttled-connection slot (go only assigns
        // `throttledOutgoingConnection` on the outgoing-dial path).
        let throttled_outgoing_connection = direction == PeerDirection::Outbound
            && reserve_throttled_slot(&self.throttled_outgoing_connections);

        // Store the peer entry.
        {
            let mut peers = self.peers.write().await;
            peers.insert(
                addr.clone(),
                PeerEntry {
                    handle,
                    direction,
                    outgoing_filter,
                    throttled_outgoing_connection,
                    prio_weight: AtomicU64::new(0),
                },
            );
        }

        tracing::info!(addr = %addr, direction = ?direction, "peer added to network");

        // Spawn a receive/dispatch loop for this peer.
        if let Some(mut rx) = incoming_rx {
            let multiplexer = Arc::clone(&self.multiplexer);
            let cancel = self.cancel.clone();
            let peers = Arc::clone(&self.peers);
            let peer_addr = addr;
            // Whether *any* outgoing filtering is enabled network-wide —
            // this only gates whether we bother computing a digest and
            // notifying other peers below; it is not any one connection's
            // filter instance (each connection has its own, see
            // `PeerEntry::outgoing_filter` / issue #803).
            let outgoing_filtering_enabled = self.config.enable_outgoing_network_message_filtering;
            let broadcast_handle: Option<BroadcastHandle> = {
                let guard = self
                    .broadcast_thread
                    .lock()
                    .expect("broadcast_thread lock poisoned");
                guard.as_ref().map(|bt| bt.handle())
            };
            // Issue #1101: go only feeds `connPerfMonitor.Notify` from
            // *outgoing* peers (`network/wsPeer.go`'s `connMonitor` field is
            // only set on outbound `wsPeer`s) — `add_peer` handles both
            // directions (the inbound accept path and `mesh_connect`'s
            // outbound dial), so only clone the monitor handle when this
            // connection is outbound.
            let conn_perf_monitor =
                (direction == PeerDirection::Outbound).then(|| Arc::clone(&self.conn_perf_monitor));
            // Issue #1105: needed on every removal path below to release
            // this connection's throttled-connection slot, if it holds one.
            let throttled_outgoing_connections = Arc::clone(&self.throttled_outgoing_connections);

            let recv_task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            tracing::debug!(addr = %peer_addr, "receive loop cancelled");
                            break;
                        }
                        msg = rx.recv() => {
                            match msg {
                                Some(incoming) => {
                                    let tag = incoming.tag;
                                    if let Some(ref mon) = conn_perf_monitor {
                                        mon.lock()
                                            .expect("conn_perf_monitor lock poisoned")
                                            .notify(&incoming);
                                    }
                                    // Save request data for Respond (hash_topics
                                    // needs the original payload).
                                    let request_data = incoming.data.clone();
                                    // Only clone data and sender when relay mode is
                                    // active (broadcast_handle is Some), avoiding the
                                    // allocation on non-relay nodes.
                                    let relay_data = if broadcast_handle.is_some() {
                                        Some((request_data.clone(), incoming.sender.clone()))
                                    } else {
                                        None
                                    };
                                    // Issue #798: tell every *other* connected peer
                                    // "I already have this, don't re-send it" before
                                    // dispatching — mirrors go's messageHandlerThread,
                                    // which calls sendFilterMessage() unconditionally
                                    // for any large dedup-safe message *before*
                                    // wn.Handle() decides what to do with it
                                    // (network/wsNetwork.go:1249-1251).
                                    if outgoing_filtering_enabled
                                        && dedup_safe_tag(&tag)
                                        && request_data.len() >= MESSAGE_FILTER_SIZE
                                    {
                                        let digest =
                                            generate_message_digest(&tag, &request_data);
                                        send_digest_skip_notification(&peers, digest, &peer_addr)
                                            .await;
                                    }
                                    // Dispatch to the multiplexer.
                                    let out = multiplexer.handle(incoming).await;
                                    // Act on forwarding policy.
                                    match out.action {
                                        ForwardingPolicy::Broadcast => {
                                            if let (Some(ref bh), Some((data, sender))) =
                                                (&broadcast_handle, relay_data)
                                            {
                                                if let Err(e) = bh.enqueue(tag, data, Some(sender)) {
                                                    tracing::debug!(
                                                        error = %e,
                                                        "failed to enqueue relay message"
                                                    );
                                                }
                                            }
                                        }
                                        ForwardingPolicy::Respond => {
                                            // Build TopicMsgResp matching Go's
                                            // wsPeer.Respond(): hash the original
                                            // request, append RequestHash topic,
                                            // serialize, and send back to the peer.
                                            let request_hash = hash_topics(&request_data);
                                            let request_hash_data = encode_uvarint(request_hash);
                                            let mut response_topics =
                                                out.topics.unwrap_or_else(Topics::new);
                                            response_topics.0.push(Topic::new(
                                                RESPONSE_HASH_FIELD,
                                                request_hash_data,
                                            ));
                                            let serialized = response_topics.marshal();
                                            let resp_msg = OutgoingMessage {
                                                action: ForwardingPolicy::Respond,
                                                tag: Tag::TopicMsgResp,
                                                payload: serialized,
                                                topics: None,
                                            };
                                            if let Err(e) = peer_sender.send_priority(resp_msg) {
                                                tracing::debug!(
                                                    addr = %peer_addr,
                                                    error = %e,
                                                    "failed to send Respond message"
                                                );
                                            }
                                        }
                                        ForwardingPolicy::Disconnect => {
                                            tracing::info!(addr = %peer_addr, "handler requested disconnect");
                                            let mut guard = peers.write().await;
                                            if let Some(entry) = guard.remove(&peer_addr) {
                                                release_throttled_slot(
                                                    &throttled_outgoing_connections,
                                                    &entry,
                                                );
                                                entry.handle.close();
                                            }
                                            break;
                                        }
                                        _ => { /* Ignore, Accept — no relay action */ }
                                    }
                                }
                                None => {
                                    // Channel closed — peer disconnected.
                                    tracing::info!(addr = %peer_addr, "peer incoming channel closed, removing");
                                    let mut guard = peers.write().await;
                                    if let Some(entry) = guard.remove(&peer_addr) {
                                        release_throttled_slot(
                                            &throttled_outgoing_connections,
                                            &entry,
                                        );
                                        entry.handle.close();
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            });

            let mut tasks = self.tasks.lock().await;
            tasks.push(recv_task);
        }
    }

    /// Remove a peer from the registry by address and close its connection.
    ///
    /// Returns `true` if the peer was found and removed.
    pub async fn remove_peer(&self, addr: &str) -> bool {
        let entry = {
            let mut peers = self.peers.write().await;
            peers.remove(addr)
        };

        if let Some(entry) = entry {
            release_throttled_slot(&self.throttled_outgoing_connections, &entry);
            entry.handle.close();
            tracing::info!(addr = %addr, "peer removed from network");
            true
        } else {
            false
        }
    }

    /// Set a connected peer's broadcast priority weight (issue #1428).
    ///
    /// Mirrors go's `prioTracker.setPriority` (`network/netprio.go`), which
    /// `prioResponseHandler` calls after verifying a `NetPrioResponse` and
    /// looking up the responder's stake weight via
    /// `NetPrioScheme.GetPrioWeight`. algod-rust doesn't yet drive that
    /// challenge/response handshake itself (see `net_prio.rs`'s docs), so
    /// this is a standalone setter any caller with a weight to report can
    /// use — the priority-ordering behavior in [`BroadcastThread`] (via
    /// [`crate::broadcast::BroadcastPeer::prio_weight`]) is wired
    /// unconditionally and doesn't depend on how the weight was computed.
    ///
    /// A no-op (returns `false`) if `addr` isn't currently a connected peer.
    /// Higher weight is preferred: the broadcast thread's `inner_broadcast`
    /// sorts peers by descending `prio_weight` before applying
    /// `BroadcastConnectionsLimit`'s cap, so this peer will be favored over
    /// lower-weight (including default-`0`) peers the next time a broadcast
    /// is capped.
    pub async fn set_peer_priority(&self, addr: &str, weight: u64) -> bool {
        let peers = self.peers.read().await;
        match peers.get(addr) {
            Some(entry) => {
                entry.prio_weight.store(weight, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    /// Send a message to all connected peers, optionally excluding one.
    ///
    /// Note: the `_wait` parameter is accepted for API compatibility with Go's
    /// `Broadcast(tag, data, wait, except)` but is not yet used. When
    /// implemented, `wait=true` would block until all peers have acknowledged
    /// receipt.
    // TODO: implement `wait` semantics (block until peers acknowledge)
    async fn broadcast_inner(
        &self,
        tag: Tag,
        data: Vec<u8>,
        except: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Wire-level capture point (issue #497 debugging): enable with
        // `RUST_LOG=algo_network::wire=trace` to dump every outgoing gossip
        // message's tag and raw payload hex for offline decoding/diffing
        // against go-algorand's encoder.
        tracing::trace!(
            target: "algo_network::wire",
            dir = "send",
            tag = %tag,
            except = except.unwrap_or(""),
            len = data.len(),
            hex = %crate::handler::hex_dump(&data),
            "wire message"
        );
        let peers = self.peers.read().await;
        let msg = OutgoingMessage::new(tag, data);

        for (addr, entry) in peers.iter() {
            if let Some(except_addr) = except {
                if addr == except_addr {
                    continue;
                }
            }
            if let Err(e) = entry.handle.send(msg.clone()) {
                tracing::debug!(
                    addr = %addr,
                    error = %e,
                    "failed to enqueue broadcast message"
                );
            }
        }

        Ok(())
    }

    /// Attempt to connect to peers from the phonebook to reach the gossip
    /// fanout target.
    ///
    /// This is the fallback mesh maintenance logic used by
    /// [`GossipNode::start`] when background tasks are not available.
    /// When `start_arc()` is used, mesh maintenance is delegated to
    /// [`MeshThread`] which provides backoff and deduplication.
    async fn mesh_connect(&self) {
        let current_out = {
            let peers = self.peers.read().await;
            peers
                .values()
                .filter(|e| e.direction == PeerDirection::Outbound)
                .count()
        };

        if current_out >= self.config.gossip_fanout {
            return;
        }

        let needed = self.config.gossip_fanout - current_out;
        let addresses = self.phonebook.get_addresses(needed, RELAY_ROLE);

        for addr in addresses {
            // Skip if already connected or connecting.
            {
                let peers = self.peers.read().await;
                if peers.contains_key(&addr) {
                    continue;
                }
            }

            {
                let mut connecting = self.connecting.lock().await;
                if connecting.contains(&addr) {
                    continue;
                }
                connecting.insert(addr.clone());
            }

            // Issue #789: thread this network's constructed incoming/outgoing
            // MessageFilters into this dial path too. `mesh_connect` is a
            // second, independent outbound-dial code path from
            // `NetworkConnectFn::try_dial` (that one backs the periodic
            // `MeshThread`; this one backs explicit
            // `request_connect_outgoing` calls) — both establish real peer
            // connections, so both must attach the filters or dedup only
            // works depending on which path happened to dial.
            //
            // Issue #803: `outgoing_filter` must be a *fresh* instance per
            // connection, not the (removed) network-wide shared Arc — a
            // `MsgDigestSkip` from one peer must never suppress sends to a
            // different one.
            let outgoing_filter = self.new_outgoing_message_filter();
            let connect_config = ConnectConfig {
                genesis_id: self.config.genesis_id.clone(),
                our_features: crate::peer_features::advertise_vote_compression(
                    self.config.enable_vote_compression,
                    DEFAULT_VOTE_COMPRESSION_TABLE_SIZE,
                ),
                peer_config: Some(crate::ws_peer::WsPeerConfig {
                    incoming_filter: self.incoming_message_filter.clone(),
                    outgoing_filter: outgoing_filter.clone(),
                    // Issue #1425: share this network's single counter
                    // instance, matching the inbound path.
                    network_metrics: Some(self.network_metrics.clone()),
                    ..crate::ws_peer::WsPeerConfig::default()
                }),
                network_protocol_version: self.config.network_protocol_version.clone(),
                ..ConnectConfig::default()
            };

            let addr_clone = addr.clone();
            // Issue #1101: route this real dial through the phonebook's
            // rate limiter too (this is the second real outbound dial path,
            // used by `GossipNode::start()`/`request_connect_outgoing`
            // rather than the periodic `MeshThread`).
            match try_connect_with_phonebook(&addr_clone, &connect_config, &self.phonebook).await {
                Ok(handle) => {
                    self.add_peer(handle, PeerDirection::Outbound, outgoing_filter)
                        .await;
                    tracing::info!(addr = %addr_clone, "outbound connection established");
                }
                Err(e) => {
                    tracing::warn!(
                        addr = %addr_clone,
                        error = %e,
                        "failed to connect to peer"
                    );
                }
            }

            {
                let mut connecting = self.connecting.lock().await;
                connecting.remove(&addr);
            }
        }
    }

    /// Checks whether an existing outgoing connection should be dropped for
    /// being consistently the slowest, or (failing that) whether the
    /// network looks "stuck" and a clique-resolution disconnect is due.
    ///
    /// Mirrors go's `outgoingConnsCloser.checkExistingConnectionsNeedDisconnecting`
    /// (`network/connPerfMon.go`), wiring #1088's standalone
    /// [`ConnectionPerformanceMonitor`] into a real decision (issue #1101),
    /// gated by the `throttled_outgoing_connection` eligibility flag
    /// assigned at connect time from [`Self::throttled_outgoing_connections`]
    /// (issue #1105). Returns `true` if a peer was disconnected.
    ///
    /// Only a peer marked `throttled_outgoing_connection` is eligible for a
    /// performance-based drop — mirroring go's
    /// `if wsPeer.throttledOutgoingConnection && leastPerformingPeer == nil`
    /// loop exactly: `peer_statistics` is sorted worst-first, and the first
    /// *eligible* entry in that order is picked (which is not necessarily
    /// the single worst peer overall, if a worse-but-ineligible peer sorts
    /// ahead of it). Since only a bounded fraction of outgoing slots are
    /// ever throttle-eligible (half of `gossip_fanout` for a relay, all of
    /// it for a non-relay), the node can never shed *every* outgoing peer
    /// this way — falling back to [`Self::check_network_advance_disconnect`]
    /// when no eligible peer is found.
    fn check_existing_connections_need_disconnecting(&self, target_conn_count: usize) -> bool {
        let outgoing_peers = self.get_peers(&[PeerOption::PeersConnectedOut]);

        if outgoing_peers.len() < target_conn_count {
            // Not yet at target — reset monitoring and fall back to the
            // clique-resolution check (go: `cc.connPerfMonitor.Reset(nil)`).
            self.conn_perf_monitor
                .lock()
                .expect("conn_perf_monitor lock poisoned")
                .reset(&[], now_ns());
            return self.check_network_advance_disconnect(&outgoing_peers, CLIQUE_RESOLVE_INTERVAL);
        }

        let addrs: Vec<String> = outgoing_peers
            .iter()
            .map(|p| p.get_address().to_string())
            .collect();

        let stats = {
            let mut mon = self
                .conn_perf_monitor
                .lock()
                .expect("conn_perf_monitor lock poisoned");
            if !mon.compare_peers(&addrs) {
                // Different set of peers than last cycle — restart monitoring.
                mon.reset(&addrs, now_ns());
            }
            mon.get_peers_statistics()
        };

        let stats = match stats {
            Some(s) => s,
            None => {
                // Performance metrics are not yet ready.
                return self
                    .check_network_advance_disconnect(&outgoing_peers, CLIQUE_RESOLVE_INTERVAL);
            }
        };

        // Issue #1105: only a peer holding a throttled-connection slot is
        // eligible for a performance-based disconnect (go:
        // `wsPeer.throttledOutgoingConnection`).
        let throttled_addrs: HashSet<String> = match self.peers.try_read() {
            Ok(peers) => peers
                .iter()
                .filter(|(_, entry)| {
                    entry.direction == PeerDirection::Outbound
                        && entry.throttled_outgoing_connection
                })
                .map(|(addr, _)| addr.clone())
                .collect(),
            Err(_) => HashSet::new(),
        };

        // `peer_statistics` is sorted descending by delay (worst first);
        // pick the first *eligible* entry in that order, matching go's
        // `if wsPeer.throttledOutgoingConnection && leastPerformingPeer == nil`
        // loop.
        let worst = match stats
            .peer_statistics
            .iter()
            .find(|w| w.peer_delay > 0 && throttled_addrs.contains(&w.peer))
        {
            Some(w) => w,
            None => {
                return self
                    .check_network_advance_disconnect(&outgoing_peers, CLIQUE_RESOLVE_INTERVAL)
            }
        };

        match outgoing_peers
            .iter()
            .find(|p| p.get_address() == worst.peer)
        {
            Some(peer) => {
                tracing::info!(
                    addr = %worst.peer,
                    delay_ns = worst.peer_delay,
                    first_message_pct = (worst.peer_first_message * 100.0) as i32,
                    "network performance monitor: disconnecting slowest outgoing peer"
                );
                self.disconnect(Arc::clone(peer));
                self.conn_perf_monitor
                    .lock()
                    .expect("conn_perf_monitor lock poisoned")
                    .reset(&[], now_ns());
                true
            }
            None => false,
        }
    }

    /// Clique-resolution fallback: if the agreement protocol hasn't
    /// advanced within `clique_resolve_interval`, disconnect a randomly
    /// chosen outgoing peer to try to escape a possible network clique.
    ///
    /// Mirrors go's `outgoingConnsCloser.checkNetworkAdvanceDisconnect`. The
    /// interval is a parameter (production always passes
    /// [`CLIQUE_RESOLVE_INTERVAL`] via
    /// [`Self::check_existing_connections_need_disconnecting`]) purely so
    /// tests can exercise this path without a real 5-minute wait.
    fn check_network_advance_disconnect(
        &self,
        outgoing_peers: &[Arc<dyn Peer>],
        clique_resolve_interval: Duration,
    ) -> bool {
        {
            let adv = self
                .network_advance_monitor
                .lock()
                .expect("network_advance_monitor lock poisoned");
            if adv.last_advanced_within(clique_resolve_interval) {
                return false;
            }
        }

        if outgoing_peers.is_empty() {
            return false;
        }

        // Mirrors go's `numOutgoingPending() > 0` guard — don't disconnect
        // while we're already trying to extend the outgoing set.
        if let Ok(connecting) = self.connecting.try_lock() {
            if !connecting.is_empty() {
                return false;
            }
        }

        let idx = (rand::random::<u64>() % outgoing_peers.len() as u64) as usize;
        let victim = &outgoing_peers[idx];
        tracing::info!(
            addr = %victim.get_address(),
            "clique resolution: disconnecting random outgoing peer (no recent network advance)"
        );
        self.disconnect(Arc::clone(victim));
        self.conn_perf_monitor
            .lock()
            .expect("conn_perf_monitor lock poisoned")
            .reset(&[], now_ns());
        // Mirrors go's `cc.net.OnNetworkAdvance()` at the end of
        // `checkNetworkAdvanceDisconnect` — resets the watchdog clock so a
        // single clique-resolution disconnect doesn't immediately repeat
        // next cycle.
        self.on_network_advance();
        true
    }

    /// Build the axum router for relay mode.
    ///
    /// Includes the gossip WebSocket upgrade endpoint, the health service,
    /// and any routes registered via [`GossipNode::register_http_handler`].
    fn build_relay_router(self: &Arc<Self>) -> Router {
        let gossip_path = "/v1/:genesis_id/gossip";

        let mut app = Router::new()
            .route(gossip_path, axum::routing::get(gossip_upgrade_handler))
            .with_state(Arc::clone(self));

        // Merge health service.
        app = app.merge(health_router());

        // Merge any externally registered handlers.
        let handlers = {
            let mut guard = self
                .registered_handlers
                .lock()
                .expect("registered_handlers lock poisoned");
            std::mem::take(&mut *guard)
        };
        for (path, handler) in handlers {
            app = app.nest(&path, handler);
        }

        // Issue #1088 / go's `EnableRequestLogger`: log every incoming HTTP
        // request (method, URI, status, client, instance name, user agent)
        // when explicitly enabled. Applied last so it wraps the whole
        // router, matching go's placement ("place it at the bottom of the
        // http processing" — `network/requestLogger.go`'s doc comment).
        if self.config.enable_request_logger {
            app = app.layer(axum::middleware::from_fn(
                crate::request_logger::request_logger_middleware,
            ));
        }

        app
    }

    /// Build a [`tokio_rustls::TlsAcceptor`] from the configured cert and
    /// key files, if both are present.
    ///
    /// Returns `None` when TLS is not configured.
    fn build_tls_acceptor(
        &self,
    ) -> Result<Option<tokio_rustls::TlsAcceptor>, Box<dyn std::error::Error + Send + Sync>> {
        let (cert_path, key_path) = match (&self.config.tls_cert_file, &self.config.tls_key_file) {
            (Some(c), Some(k)) => (c.clone(), k.clone()),
            _ => return Ok(None),
        };

        let cert_file = &mut std::io::BufReader::new(std::fs::File::open(&cert_path)?);
        let key_file = &mut std::io::BufReader::new(std::fs::File::open(&key_path)?);

        let certs: Vec<_> = rustls_pemfile::certs(cert_file).collect::<Result<_, _>>()?;
        let key =
            rustls_pemfile::private_key(key_file)?.ok_or("no private key found in TLS key file")?;

        let server_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        Ok(Some(tokio_rustls::TlsAcceptor::from(Arc::new(
            server_config,
        ))))
    }

    /// Start the relay HTTP server (listener + axum).
    ///
    /// Binds a TCP listener to `config.net_address`, wraps it with
    /// [`RejectingLimitListener`] to enforce the connection limit, and
    /// spawns a manual accept loop that serves each connection via hyper.
    /// When `tls_cert_file` and `tls_key_file` are both set, each accepted
    /// connection is wrapped with TLS before being handed to the HTTP layer.
    /// The task is cancelled when `self.cancel` fires.
    async fn start_relay_server(
        self: &Arc<Self>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::listener::RejectingLimitListener;
        use tower_service::Service;

        let bind_addr = match &self.config.net_address {
            Some(addr) => addr.clone(),
            None => return Ok(()),
        };

        // NOTE: whether to *bind the listener* depends only on
        // `net_address` being set — matching go's `IsListenServer()`
        // (`NetAddress != ""`), which gates `wsNetwork.go`'s HTTP server
        // startup independent of `ForceRelayMessages`. `relay_messages`
        // (this config's mirror of `ForceRelayMessages`) instead gates
        // *outbound* message forwarding (see `relay()` and the broadcast
        // thread startup below), matching go's
        // `wn.relayMessages = wn.config.IsListenServer() || wn.config.ForceRelayMessages`
        // (`network/wsNetwork.go:601`) — note the `||`, not `&&`: a
        // listening node always forwards, regardless of
        // `ForceRelayMessages`, and `ForceRelayMessages` lets a
        // *non-listening* node forward too. Previously this function also
        // required `relay_messages` to bind at all, which meant a node
        // with a listen address configured but `--relay-messages` unset
        // silently accepted no inbound connections — a real conformance
        // gap (issue #748).
        //
        // Separately, go's `Start()` also skips binding the listener
        // entirely when `IncomingConnectionsLimit == 0`
        // (`wn.relayMessages && wn.config.IncomingConnectionsLimit != 0` —
        // `network/wsNetwork.go:692`, pinned by
        // `TestWebsocketNetworkStartZeroIncomingDoesNotListen`,
        // `network/wsNetwork_test.go:287`): a node configured to accept
        // zero incoming connections doesn't open a listening socket at
        // all, so `Address()` reports not-connected. Mirror that here —
        // this only gates the listener bind, not outbound dialing (see
        // `mesh_connect`/`request_connect_outgoing`, which don't call this
        // function at all) — issue #1155.
        if self.config.incoming_connections_limit == 0 {
            tracing::debug!(
                addr = %bind_addr,
                "incoming_connections_limit is 0; not binding relay listener"
            );
            return Ok(());
        }

        // Build optional TLS acceptor from config.
        let tls_acceptor = self.build_tls_acceptor()?;

        let tcp_listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        let local_addr = tcp_listener.local_addr()?;

        if tls_acceptor.is_some() {
            tracing::info!(
                addr = %local_addr,
                limit = self.config.incoming_connections_limit,
                "relay server listening with TLS (with connection limit)"
            );
        } else {
            tracing::info!(
                addr = %local_addr,
                limit = self.config.incoming_connections_limit,
                "relay server listening (with connection limit)"
            );
        }

        // Store the bound address so `address()` returns it.
        {
            let mut guard = self.listen_addr.lock().expect("listen_addr lock poisoned");
            *guard = Some(local_addr);
        }

        // Wrap the TCP listener with a connection limiter.
        let limit_listener =
            RejectingLimitListener::new(tcp_listener, self.config.incoming_connections_limit);

        let app = self.build_relay_router();
        let mut make_service = app.into_make_service_with_connect_info::<SocketAddr>();
        let cancel = self.cancel.clone();

        let server_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        tracing::debug!("relay server shutting down");
                        break;
                    }
                    result = limit_listener.accept() => {
                        match result {
                            Ok((stream, remote_addr, conn_guard)) => {
                                // Create a per-connection service from the MakeService.
                                // Connected<SocketAddr> is implemented for SocketAddr.
                                let svc = match make_service.call(remote_addr).await {
                                    Ok(svc) => svc,
                                    Err(e) => match e {},
                                };

                                // Wrap the tower service so hyper 1.x can use it.
                                let hyper_svc =
                                    hyper_util::service::TowerToHyperService::new(svc);

                                // Spawn a task to serve this connection.
                                // The conn_guard is moved into the task so the
                                // connection slot is held for its lifetime.
                                let tls = tls_acceptor.clone();
                                tokio::spawn(async move {
                                    if let Some(acceptor) = tls {
                                        // TLS-wrapped connection.
                                        match acceptor.accept(stream).await {
                                            Ok(tls_stream) => {
                                                let io = hyper_util::rt::TokioIo::new(tls_stream);
                                                let conn = hyper::server::conn::http1::Builder::new()
                                                    .serve_connection(io, hyper_svc)
                                                    .with_upgrades();
                                                if let Err(e) = conn.await {
                                                    tracing::debug!(
                                                        addr = %remote_addr,
                                                        error = %e,
                                                        "TLS connection error"
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                tracing::debug!(
                                                    addr = %remote_addr,
                                                    error = %e,
                                                    "TLS handshake failed"
                                                );
                                            }
                                        }
                                    } else {
                                        // Plain TCP connection.
                                        let io = hyper_util::rt::TokioIo::new(stream);
                                        let conn = hyper::server::conn::http1::Builder::new()
                                            .serve_connection(io, hyper_svc)
                                            .with_upgrades();
                                        if let Err(e) = conn.await {
                                            tracing::debug!(
                                                addr = %remote_addr,
                                                error = %e,
                                                "connection error"
                                            );
                                        }
                                    }
                                    drop(conn_guard);
                                });
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "accept error");
                                break;
                            }
                        }
                    }
                }
            }
        });

        let mut tasks = self.tasks.lock().await;
        tasks.push(server_task);

        Ok(())
    }

    /// Spawn the peer monitoring background task.
    ///
    /// Periodically checks all peers for closed connections and removes them.
    /// Also drains any pending disconnects that were deferred due to lock
    /// contention in the synchronous `disconnect()` method.
    fn spawn_monitor_task(self: &Arc<Self>) -> JoinHandle<()> {
        let network = Arc::clone(self);
        // Check every 3 minutes, matching Go's connectionActivityMonitorInterval.
        let check_interval = Duration::from_secs(3 * 60);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = network.cancel.cancelled() => {
                        tracing::debug!("peer monitor task shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(check_interval) => {
                        // Drain pending disconnects first.
                        let pending: Vec<String> = {
                            let mut guard = network.pending_disconnects.lock()
                                .expect("pending_disconnects lock poisoned");
                            guard.drain(..).collect()
                        };
                        for addr in &pending {
                            network.remove_peer(addr).await;
                        }

                        // Collect addresses of closed peers.
                        let to_remove: Vec<String> = {
                            let peers = network.peers.read().await;
                            peers
                                .iter()
                                .filter(|(_, entry)| entry.handle.is_closed())
                                .map(|(addr, _)| addr.clone())
                                .collect()
                        };

                        for addr in to_remove {
                            network.remove_peer(&addr).await;
                        }
                    }
                }
            }
        })
    }

    /// Spawn the outgoing-connection-performance disconnect-check task.
    ///
    /// Periodically calls [`Self::check_existing_connections_need_disconnecting`]
    /// on the same cadence as mesh maintenance (`mesh_interval`), mirroring
    /// go's `meshThreadInner` calling `checkExistingConnectionsNeedDisconnecting`
    /// on every mesh cycle (issue #1101).
    fn spawn_disconnect_check_task(self: &Arc<Self>) -> JoinHandle<()> {
        let network = Arc::clone(self);
        let interval = network.config.mesh_interval;
        let target_conn_count = network.config.gossip_fanout;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = network.cancel.cancelled() => {
                        tracing::debug!("disconnect-check task shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(interval) => {
                        network.check_existing_connections_need_disconnecting(target_conn_count);
                    }
                }
            }
        })
    }
}

/// Broadcast a `MsgDigestSkip` notification (a 32-byte digest) to every
/// connected peer except `except`, telling them "I already have this exact
/// message, don't bother re-sending it to me".
///
/// Mirrors go's `msgHandler.sendFilterMessage()` (`network/wsNetwork.go:1326`),
/// which is invoked from `messageHandlerThread` right after a large
/// (`>= messageFilterSize`) message is pulled off the read buffer —
/// `net.Broadcast(ctx, protocol.MsgDigestSkipTag, digest[:], false, msg.Sender)`.
/// Called from the real peer receive-dispatch loops
/// ([`WebsocketNetwork::add_peer`]'s recv task, covering both the inbound
/// accept path and `mesh_connect`'s outbound dial path, and
/// `NetworkConnectFn::try_dial`'s recv task, covering `MeshThread`'s
/// periodic outbound dial) rather than duplicating the peer-iteration
/// logic in each.
async fn send_digest_skip_notification(
    peers: &Arc<RwLock<HashMap<String, PeerEntry>>>,
    digest: [u8; 32],
    except: &str,
) {
    let msg = OutgoingMessage::new(Tag::MsgDigestSkip, digest.to_vec());
    let peers_guard = peers.read().await;
    for (addr, entry) in peers_guard.iter() {
        if addr == except {
            continue;
        }
        if let Err(e) = entry.handle.send(msg.clone()) {
            tracing::debug!(
                addr = %addr,
                error = %e,
                "failed to enqueue MsgDigestSkip notification"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// GossipNode trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl GossipNode for WebsocketNetwork {
    fn address(&self) -> (String, bool) {
        let guard = self.listen_addr.lock().expect("listen_addr lock poisoned");
        match *guard {
            Some(addr) => (addr.to_string(), true),
            None => (String::new(), false),
        }
    }

    async fn broadcast(
        &self,
        tag: Tag,
        data: Vec<u8>,
        _wait: bool,
        except: Option<Arc<dyn Peer>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // TODO: honour `_wait` parameter — see broadcast_inner doc comment
        let except_addr = except.as_ref().map(|p| p.get_address().to_string());
        self.broadcast_inner(tag, data, except_addr.as_deref())
            .await
    }

    async fn relay(
        &self,
        tag: Tag,
        data: Vec<u8>,
        _wait: bool,
        except: Option<Arc<dyn Peer>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.effective_relay_messages() {
            return Ok(());
        }

        // Try to enqueue via the broadcast thread (lock is held briefly,
        // never across an await point).
        let enqueue_result = {
            let guard = self
                .broadcast_thread
                .lock()
                .expect("broadcast_thread lock poisoned");
            if let Some(ref bt) = *guard {
                let exclude = except.as_ref().map(|p| p.get_address().to_string());
                Some(bt.enqueue(tag, data.clone(), exclude))
            } else {
                None
            }
        };

        match enqueue_result {
            Some(result) => {
                result.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            }
            None => {
                // Fallback: direct broadcast (no priority queues).
                let except_addr = except.as_ref().map(|p| p.get_address().to_string());
                self.broadcast_inner(tag, data, except_addr.as_deref())
                    .await
            }
        }
    }

    fn disconnect(&self, peer: Arc<dyn Peer>) {
        let addr = peer.get_address().to_string();
        let peers = self.peers.try_write();
        if let Ok(mut peers) = peers {
            if let Some(entry) = peers.remove(&addr) {
                release_throttled_slot(&self.throttled_outgoing_connections, &entry);
                entry.handle.close();
                tracing::info!(addr = %addr, "peer disconnected");
            }
        } else {
            // Lock contention — queue for the monitor task to drain.
            let mut pending = self
                .pending_disconnects
                .lock()
                .expect("pending_disconnects lock poisoned");
            pending.push(addr.clone());
            tracing::debug!(addr = %addr, "disconnect deferred to monitor task (lock contention)");
        }
    }

    fn disconnect_peers(&self) {
        if let Ok(mut peers) = self.peers.try_write() {
            for (addr, entry) in peers.drain() {
                release_throttled_slot(&self.throttled_outgoing_connections, &entry);
                entry.handle.close();
                tracing::debug!(addr = %addr, "peer disconnected (disconnect_peers)");
            }
        } else {
            // Lock contention — queue all current peer addresses for removal.
            if let Ok(peers) = self.peers.try_read() {
                let mut pending = self
                    .pending_disconnects
                    .lock()
                    .expect("pending_disconnects lock poisoned");
                for addr in peers.keys() {
                    pending.push(addr.clone());
                }
                tracing::debug!(
                    count = pending.len(),
                    "disconnect_peers deferred to monitor task (lock contention)"
                );
            }
        }
    }

    async fn request_connect_outgoing(&self, replace: bool) {
        if replace {
            self.disconnect_peers();
        }
        self.mesh_connect().await;
    }

    fn get_peers(&self, options: &[PeerOption]) -> Vec<Arc<dyn Peer>> {
        let peers = match self.peers.try_read() {
            Ok(p) => p,
            Err(_) => return vec![],
        };

        let mut result: Vec<Arc<dyn Peer>> = Vec::new();

        for option in options {
            match option {
                PeerOption::PeersConnectedOut => {
                    for (addr, entry) in peers.iter() {
                        if entry.direction == PeerDirection::Outbound && !entry.handle.is_closed() {
                            result.push(Arc::new(PeerRef { addr: addr.clone() }));
                        }
                    }
                }
                PeerOption::PeersConnectedIn => {
                    for (addr, entry) in peers.iter() {
                        if entry.direction == PeerDirection::Inbound && !entry.handle.is_closed() {
                            result.push(Arc::new(PeerRef { addr: addr.clone() }));
                        }
                    }
                }
                PeerOption::PeersPhonebookRelays => {
                    let addrs = self.phonebook.get_addresses(usize::MAX, RELAY_ROLE);
                    for addr in addrs {
                        result.push(Arc::new(PeerRef { addr }));
                    }
                }
                PeerOption::PeersPhonebookArchivalNodes => {
                    let addrs = self.phonebook.get_addresses(usize::MAX, ARCHIVAL_ROLE);
                    for addr in addrs {
                        result.push(Arc::new(PeerRef { addr }));
                    }
                }
            }
        }

        result
    }

    async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(
            genesis_id = %self.config.genesis_id,
            network_id = %self.config.network_id,
            fanout = self.config.gossip_fanout,
            "WebsocketNetwork starting"
        );

        // Note: mesh and monitor tasks are spawned via `start_arc()` which
        // requires an Arc<Self>.  The GossipNode trait's `start(&self)` does
        // not provide Arc access, so callers that need background tasks should
        // use `start_arc()` instead.  This `start` implementation performs
        // an initial mesh connect only.
        self.mesh_connect().await;

        Ok(())
    }

    async fn stop(&self) {
        tracing::info!("WebsocketNetwork stopping");

        // Cancel all background tasks.
        self.cancel.cancel();

        // Stop the broadcast thread if running.
        {
            let mut guard = self
                .broadcast_thread
                .lock()
                .expect("broadcast_thread lock poisoned");
            if let Some(ref mut _bt) = *guard {
                // Cancel is already signalled above; dropping the
                // BroadcastThread closes its channels so the background
                // task will exit on the next iteration.
            }
            *guard = None;
        }

        // Wait for tasks to finish.
        let mut tasks = self.tasks.lock().await;
        for task in tasks.drain(..) {
            let _ = task.await;
        }

        // Disconnect all peers.
        let entries: Vec<(String, PeerEntry)> = {
            let mut peers = self.peers.write().await;
            peers.drain().collect()
        };

        for (addr, entry) in entries {
            entry.handle.close();
            tracing::debug!(addr = %addr, "peer closed during stop");
        }
    }

    fn register_handlers(&self, dispatch: Vec<TaggedMessageHandler>) {
        self.multiplexer.register_handlers(dispatch);
    }

    fn clear_handlers(&self) {
        self.multiplexer.clear_handlers(&[]);
    }

    fn register_validator_handlers(&self, dispatch: Vec<TaggedMessageValidatorHandler>) {
        self.multiplexer.register_validator_handlers(dispatch);
    }

    fn clear_validator_handlers(&self) {
        self.multiplexer.clear_validator_handlers(&[]);
    }

    fn on_network_advance(&self) {
        // Issue #1101: record the advance on the watchdog that
        // `check_existing_connections_need_disconnecting`'s clique-resolution
        // fallback consults, mirroring go's
        // `outgoingConnsCloser.updateLastAdvance()`.
        self.network_advance_monitor
            .lock()
            .expect("network_advance_monitor lock poisoned")
            .update_last_advance();

        // Forward the notification to the MeshThread if it has been spawned.
        let guard = self.mesh_update_tx.try_lock();
        if let Ok(ref opt_tx) = guard {
            if let Some(tx) = opt_tx.as_ref() {
                let _ = tx.try_send(MeshRequest { done: None });
            }
        }

        // Issue #1156: wake the `wantTXGossip` refresh loop — but only for a
        // node that might actually need to narrow/widen its TX-gossip
        // subscription. Mirrors go's exact gate,
        // `!wn.relayMessages && !wn.config.ForceFetchTransactions`
        // (`network/wsNetwork.go`'s `OnNetworkAdvance`): a relay or a
        // force-fetch node already pinned `wantTXGossip` to "yes" at
        // startup and never re-evaluates it.
        if !self.effective_relay_messages() && !self.config.force_fetch_transactions {
            if let Ok(guard) = self.messages_of_interest_refresh_tx.try_lock() {
                if let Some(tx) = guard.as_ref() {
                    let _ = tx.try_send(());
                }
            }
        }
    }

    fn get_genesis_id(&self) -> &str {
        &self.config.genesis_id
    }

    fn register_http_handler(&self, path: &str, handler: Router) {
        let mut guard = self
            .registered_handlers
            .lock()
            .expect("registered_handlers lock poisoned");
        guard.push((path.to_string(), handler));
    }
}

// ---------------------------------------------------------------------------
// ConnectFn / PeerCounter adapters for MeshThread integration
// ---------------------------------------------------------------------------

/// Adapter that implements [`ConnectFn`] by delegating to
/// [`WebsocketNetwork`]'s connection and peer-registration logic.
struct NetworkConnectFn {
    peers: Arc<RwLock<HashMap<String, PeerEntry>>>,
    multiplexer: Arc<Multiplexer>,
    cancel: CancellationToken,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    genesis_id: String,
    broadcast_thread: Arc<std::sync::Mutex<Option<BroadcastThread>>>,
    /// Issue #789: the network's constructed incoming `MessageFilter`,
    /// threaded into every real outbound (mesh-dial) connection's
    /// `WsPeerConfig` so dedup actually runs on the wire — previously
    /// `try_dial` always built `WsPeerConfig::default()`, so this filter
    /// (config-driven since #768) had zero live effect. This one is
    /// legitimately shared network-wide, mirroring go's `wn.incomingMsgFilter`
    /// (see [`WebsocketNetwork`]'s field doc).
    incoming_message_filter: Option<Arc<MessageFilter>>,
    /// Config needed to build a *fresh* outgoing-message filter for each
    /// dial (issue #803): unlike the incoming filter above, go's
    /// `outgoingMsgFilter` is a per-connection instance
    /// (`network/wsPeer.go:213,469`), so this cannot be a single shared
    /// `Arc` — every `try_dial` call must build its own via
    /// [`build_outgoing_message_filter`].
    outgoing_message_filter_enabled: bool,
    outgoing_message_filter_bucket_count: usize,
    outgoing_message_filter_bucket_size: usize,
    /// Issue #1239: whether this node advertises/negotiates vote
    /// compression at all — see
    /// [`WebsocketNetworkConfig::enable_vote_compression`]'s doc comment.
    enable_vote_compression: bool,
    /// Issue #1320: `config.Local.NetworkProtocolVersion` override, threaded
    /// into this dial path's `ConnectConfig` the same way
    /// `enable_vote_compression` is above.
    network_protocol_version: String,
    /// Issue #1101: shared phonebook, threaded into the real dial so it can
    /// go through [`try_connect_with_phonebook`]'s `rate_limited_call`
    /// wrapping — mirroring go's `wn.dialer` (a `limitcaller.Dialer`
    /// wrapping the phonebook's rate limiter) rather than dialing the
    /// socket directly.
    phonebook: Arc<Phonebook>,
    /// Issue #1101: the network's outgoing-connection performance monitor,
    /// fed every `AgreementVote` this dial's peer receives (mirroring go's
    /// `connMonitor` field on outbound `wsPeer`s).
    conn_perf_monitor: Arc<std::sync::Mutex<ConnectionPerformanceMonitor>>,
    /// Issue #1105: the network's shared throttled-outgoing-connection slot
    /// counter (mirrors go's `wn.throttledOutgoingConnections`) — every mesh
    /// dial is an outgoing connection, so `try_dial` reserves a slot for it
    /// on connect and releases it on every removal path below.
    throttled_outgoing_connections: Arc<AtomicI32>,
    /// Issue #1425: the network's shared per-wire-tag traffic-counter
    /// instance, threaded into every mesh-dialed peer's `WsPeerConfig` so
    /// mesh-dial traffic is counted alongside directly-dialed and inbound
    /// peers' — matching go's process-global counters.
    network_metrics: Arc<crate::metrics::NetworkTagMetrics>,
}

impl ConnectFn for NetworkConnectFn {
    fn try_dial(&self, addr: String) -> Pin<Box<dyn Future<Output = bool> + Send + 'static>> {
        let peers = Arc::clone(&self.peers);
        let multiplexer = Arc::clone(&self.multiplexer);
        let cancel = self.cancel.clone();
        let tasks = Arc::clone(&self.tasks);
        let genesis_id = self.genesis_id.clone();
        let broadcast_thread = Arc::clone(&self.broadcast_thread);
        let incoming_message_filter = self.incoming_message_filter.clone();
        let phonebook = Arc::clone(&self.phonebook);
        let conn_perf_monitor = Arc::clone(&self.conn_perf_monitor);
        let throttled_outgoing_connections = Arc::clone(&self.throttled_outgoing_connections);
        let enable_vote_compression = self.enable_vote_compression;
        let network_protocol_version = self.network_protocol_version.clone();
        let network_metrics = Arc::clone(&self.network_metrics);
        // Issue #803: build a fresh outgoing filter for *this* connection —
        // never reuse an instance across dials, or one peer's
        // `MsgDigestSkip` would suppress sends to a different peer.
        let outgoing_message_filter = build_outgoing_message_filter(
            self.outgoing_message_filter_enabled,
            self.outgoing_message_filter_bucket_count,
            self.outgoing_message_filter_bucket_size,
        );

        Box::pin(async move {
            use crate::ws_peer::WsPeerConfig;

            let recv_outgoing_message_filter = outgoing_message_filter.clone();
            let connect_config = ConnectConfig {
                genesis_id,
                our_features: crate::peer_features::advertise_vote_compression(
                    enable_vote_compression,
                    DEFAULT_VOTE_COMPRESSION_TABLE_SIZE,
                ),
                peer_config: Some(WsPeerConfig {
                    request_timeout: Some(Duration::from_secs(5)),
                    incoming_filter: incoming_message_filter,
                    outgoing_filter: outgoing_message_filter.clone(),
                    network_metrics: Some(network_metrics.clone()),
                    ..WsPeerConfig::default()
                }),
                network_protocol_version: network_protocol_version.clone(),
                ..ConnectConfig::default()
            };

            // Issue #1101: route the real dial through the phonebook's rate
            // limiter, mirroring go's `wn.dialer` (`limitcaller.Dialer`).
            match try_connect_with_phonebook(&addr, &connect_config, &phonebook).await {
                Ok(mut handle) => {
                    let peer_addr = handle.remote_addr().to_string();
                    let incoming_rx = handle.take_incoming();

                    // Issue #1105: this dial path is always outbound, so
                    // it's always eligible to reserve a throttled slot.
                    let throttled_outgoing_connection =
                        reserve_throttled_slot(&throttled_outgoing_connections);

                    // Store the peer entry.
                    {
                        let mut guard = peers.write().await;
                        guard.insert(
                            peer_addr.clone(),
                            PeerEntry {
                                handle,
                                direction: PeerDirection::Outbound,
                                outgoing_filter: outgoing_message_filter,
                                throttled_outgoing_connection,
                                prio_weight: AtomicU64::new(0),
                            },
                        );
                    }

                    tracing::info!(addr = %peer_addr, "outbound connection established (mesh)");

                    // Spawn receive/dispatch loop — must relay Broadcast
                    // messages through the BroadcastThread so gossip from
                    // outbound peers reaches inbound peers (e.g. go-relay →
                    // rust-relay → go-nonrelay).
                    if let Some(mut rx) = incoming_rx {
                        let recv_multiplexer = Arc::clone(&multiplexer);
                        let recv_cancel = cancel.clone();
                        let recv_peers = Arc::clone(&peers);
                        let recv_addr = peer_addr;
                        let recv_throttled_outgoing_connections =
                            Arc::clone(&throttled_outgoing_connections);
                        let broadcast_handle: Option<BroadcastHandle> = {
                            let guard = broadcast_thread
                                .lock()
                                .expect("broadcast_thread lock poisoned");
                            guard.as_ref().map(|bt| bt.handle())
                        };

                        let recv_task = tokio::spawn(async move {
                            loop {
                                tokio::select! {
                                    _ = recv_cancel.cancelled() => {
                                        tracing::debug!(addr = %recv_addr, "receive loop cancelled");
                                        break;
                                    }
                                    msg = rx.recv() => {
                                        match msg {
                                            Some(incoming) => {
                                                let tag = incoming.tag;
                                                // Issue #1101: this dial path is always
                                                // outbound, so feed every message to the
                                                // performance monitor unconditionally
                                                // (mirrors go's `connMonitor` on outbound
                                                // `wsPeer`s).
                                                conn_perf_monitor
                                                    .lock()
                                                    .expect("conn_perf_monitor lock poisoned")
                                                    .notify(&incoming);
                                                let request_data = incoming.data.clone();
                                                let relay_data = if broadcast_handle.is_some() {
                                                    Some((request_data.clone(), incoming.sender.clone()))
                                                } else {
                                                    None
                                                };
                                                // Issue #798: broadcast a
                                                // MsgDigestSkip to every other
                                                // connected peer before
                                                // dispatching — see the
                                                // matching comment in
                                                // `add_peer`'s recv task.
                                                if recv_outgoing_message_filter.is_some()
                                                    && dedup_safe_tag(&tag)
                                                    && request_data.len() >= MESSAGE_FILTER_SIZE
                                                {
                                                    let digest = generate_message_digest(
                                                        &tag,
                                                        &request_data,
                                                    );
                                                    send_digest_skip_notification(
                                                        &recv_peers,
                                                        digest,
                                                        &recv_addr,
                                                    )
                                                    .await;
                                                }
                                                let out = recv_multiplexer.handle(incoming).await;
                                                match out.action {
                                                    ForwardingPolicy::Broadcast => {
                                                        if let (Some(ref bh), Some((data, sender))) =
                                                            (&broadcast_handle, relay_data)
                                                        {
                                                            if let Err(e) = bh.enqueue(tag, data, Some(sender)) {
                                                                tracing::debug!(
                                                                    error = %e,
                                                                    "failed to enqueue relay message (mesh)"
                                                                );
                                                            }
                                                        }
                                                    }
                                                    ForwardingPolicy::Disconnect => {
                                                        tracing::info!(addr = %recv_addr, "handler requested disconnect (mesh)");
                                                        let mut guard = recv_peers.write().await;
                                                        if let Some(entry) = guard.remove(&recv_addr) {
                                                            release_throttled_slot(
                                                                &recv_throttled_outgoing_connections,
                                                                &entry,
                                                            );
                                                            entry.handle.close();
                                                        }
                                                        break;
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            None => {
                                                tracing::info!(addr = %recv_addr, "peer incoming channel closed, removing");
                                                let mut guard = recv_peers.write().await;
                                                if let Some(entry) = guard.remove(&recv_addr) {
                                                    release_throttled_slot(
                                                        &recv_throttled_outgoing_connections,
                                                        &entry,
                                                    );
                                                    entry.handle.close();
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        });

                        let mut task_guard = tasks.lock().await;
                        task_guard.push(recv_task);
                    }

                    true
                }
                Err(e) => {
                    tracing::warn!(addr = %addr, error = %e, "failed to connect to peer (mesh)");
                    false
                }
            }
        })
    }
}

/// Adapter that implements [`PeerCounter`] by reading from the shared peer
/// registry.
struct NetworkPeerCounter {
    peers: Arc<RwLock<HashMap<String, PeerEntry>>>,
}

impl PeerCounter for NetworkPeerCounter {
    fn outgoing_peer_info(&self) -> (usize, HashSet<String>) {
        // Use try_read to avoid blocking the mesh thread.
        match self.peers.try_read() {
            Ok(peers) => {
                let mut count = 0;
                let mut addrs = HashSet::new();
                for (addr, entry) in peers.iter() {
                    if entry.direction == PeerDirection::Outbound && !entry.handle.is_closed() {
                        count += 1;
                        addrs.insert(addr.clone());
                    }
                }
                (count, addrs)
            }
            Err(_) => (0, HashSet::new()),
        }
    }
}

impl WebsocketNetwork {
    /// Start the network with background tasks.
    ///
    /// This is the preferred way to start the network when you have an
    /// `Arc<WebsocketNetwork>`.  Unlike the [`GossipNode::start`] trait method,
    /// this spawns the [`MeshThread`] (with backoff and deduplication) and
    /// a peer monitoring task.
    pub async fn start_arc(
        self: &Arc<Self>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(
            genesis_id = %self.config.genesis_id,
            network_id = %self.config.network_id,
            fanout = self.config.gossip_fanout,
            "WebsocketNetwork starting (with background tasks)"
        );

        // Create mesh update channel.
        let (mesh_tx, mesh_rx) = mpsc::channel::<MeshRequest>(8);
        {
            let mut guard = self.mesh_update_tx.lock().await;
            *guard = Some(mesh_tx);
        }

        // Issue #1156: create the `wantTXGossip` refresh channel and spawn
        // its consumer loop, unconditionally — mirrors go's `Start()`
        // (`wn.messagesOfInterestRefresh = make(chan struct{}, 2)` +
        // `go wn.postMessagesOfInterestThread()`, `network/wsNetwork.go`),
        // which always launches the goroutine regardless of relay/force-fetch
        // config; `on_network_advance`'s gate is what makes it a no-op for
        // those roles, not skipping the spawn itself.
        let (moi_tx, mut moi_rx) = mpsc::channel::<()>(2);
        {
            let mut guard = self.messages_of_interest_refresh_tx.lock().await;
            *guard = Some(moi_tx);
        }
        let moi_task = {
            let network = Arc::clone(self);
            let cancel = self.cancel.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        received = moi_rx.recv() => {
                            match received {
                                Some(()) => network.refresh_want_tx_gossip().await,
                                None => break,
                            }
                        }
                    }
                }
            })
        };
        {
            let mut tasks = self.tasks.lock().await;
            tasks.push(moi_task);
        }

        // Build ConnectFn and PeerCounter adapters.
        let connect_fn = NetworkConnectFn {
            peers: Arc::clone(&self.peers),
            multiplexer: Arc::clone(&self.multiplexer),
            cancel: self.cancel.clone(),
            tasks: Arc::new(Mutex::new(Vec::new())),
            genesis_id: self.config.genesis_id.clone(),
            broadcast_thread: Arc::clone(&self.broadcast_thread),
            incoming_message_filter: self.incoming_message_filter.clone(),
            outgoing_message_filter_enabled: self.config.enable_outgoing_network_message_filtering,
            outgoing_message_filter_bucket_count: self.config.outgoing_message_filter_bucket_count,
            outgoing_message_filter_bucket_size: self.config.outgoing_message_filter_bucket_size,
            enable_vote_compression: self.config.enable_vote_compression,
            network_protocol_version: self.config.network_protocol_version.clone(),
            phonebook: Arc::clone(&self.phonebook),
            conn_perf_monitor: Arc::clone(&self.conn_perf_monitor),
            throttled_outgoing_connections: Arc::clone(&self.throttled_outgoing_connections),
            network_metrics: Arc::clone(&self.network_metrics),
        };

        let peer_counter = NetworkPeerCounter {
            peers: Arc::clone(&self.peers),
        };

        // Spawn the MeshThread.
        let mesh_thread = MeshThread::new(
            self.config.gossip_fanout,
            self.config.mesh_interval,
            self.cancel.clone(),
            mesh_rx,
            Arc::clone(&self.phonebook),
            connect_fn,
            peer_counter,
        );
        let mesh_task = tokio::spawn(mesh_thread.run());

        // Spawn the monitor task.
        let monitor_task = self.spawn_monitor_task();
        let disconnect_check_task = self.spawn_disconnect_check_task();

        {
            let mut tasks = self.tasks.lock().await;
            tasks.push(mesh_task);
            tasks.push(monitor_task);
            tasks.push(disconnect_check_task);
        }

        // Start the broadcast thread if relay mode is active.
        if self.effective_relay_messages() {
            let peers_ref = Arc::clone(&self.peers);
            let peers_fn = move || {
                // Use try_read to avoid blocking the broadcast thread.
                match peers_ref.try_read() {
                    Ok(peers) => peers
                        .iter()
                        .filter(|(_, entry)| !entry.handle.is_closed())
                        .map(|(addr, entry)| BroadcastPeer {
                            addr: addr.clone(),
                            handle: Arc::new(entry.handle.sender()),
                            prio_weight: entry.prio_weight.load(Ordering::Relaxed),
                        })
                        .collect(),
                    Err(_) => Vec::new(),
                }
            };

            let bt = BroadcastThread::start(
                peers_fn,
                self.config.broadcast_connections_limit,
                self.cancel.clone(),
            );

            {
                let mut guard = self
                    .broadcast_thread
                    .lock()
                    .expect("broadcast_thread lock poisoned");
                *guard = Some(bt);
            }

            tracing::info!(
                limit = self.config.broadcast_connections_limit,
                "broadcast thread started (relay mode)"
            );
        }

        // Start the relay server if configured.
        self.start_relay_server().await?;

        // Perform initial mesh connect (immediate, before the first MeshThread
        // timer fires).
        self.mesh_connect().await;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PeerRef — lightweight Peer implementation for get_peers results
// ---------------------------------------------------------------------------

/// A lightweight [`Peer`] reference returned by [`WebsocketNetwork::get_peers`].
///
/// This carries only the address string and is used to satisfy the `Peer` trait
/// without requiring a full `PeerHandle`.
struct PeerRef {
    addr: String,
}

impl Peer for PeerRef {
    fn get_address(&self) -> &str {
        &self.addr
    }

    fn get_connection_latency(&self) -> Duration {
        Duration::ZERO
    }

    fn routing_addr(&self) -> &[u8] {
        &[]
    }
}

// ---------------------------------------------------------------------------
// Shared state for the axum gossip handler
// ---------------------------------------------------------------------------

/// Axum handler state, aliased for readability.
type NetworkState = Arc<WebsocketNetwork>;

// ---------------------------------------------------------------------------
// Incoming connection validation
// ---------------------------------------------------------------------------

/// Validation result for an incoming gossip connection.
enum ValidationResult {
    /// Validation passed, with the negotiated protocol version and the
    /// proxy-resolved tracking IP (go's `remoteHost`, before any further
    /// `X-Algorand-Location` precedence is applied — see
    /// [`crate::request_tracker::remote_address`]).
    Ok {
        matched_version: String,
        tracking_ip: std::net::IpAddr,
    },
    /// Validation failed — return this response to the client.
    Rejected(axum::response::Response),
}

/// Validate an incoming gossip WebSocket connection.
///
/// Checks (matching Go's `ServeHTTP` flow):
/// 1. Genesis ID in the URL path matches ours
/// 2. Protocol version is compatible
/// 3. Resolve the tracking address (raw socket, or X-Forwarded-For override)
/// 4. Track the connection (atomically, before limit checks)
/// 5. Per-IP connection limit
/// 6. Per-IP rate limit
/// 7. Self-loop detection (NodeRandom header)
///
/// The connection is tracked at the start of validation so that concurrent
/// handshakes from the same IP cannot all pass stale counters. If validation
/// fails after tracking, [`ConnectionTracker::release_connection`] is called
/// to undo the tracking.
fn validate_incoming_connection(
    network: &WebsocketNetwork,
    genesis_id_from_path: &str,
    headers: &HeaderMap,
    remote_ip: std::net::IpAddr,
) -> ValidationResult {
    // 1. Genesis ID check
    if genesis_id_from_path != network.config.genesis_id {
        tracing::warn!(
            expected = %network.config.genesis_id,
            got = %genesis_id_from_path,
            "incoming connection: genesis ID mismatch"
        );
        return ValidationResult::Rejected(
            (StatusCode::PRECONDITION_FAILED, "mismatching genesis ID").into_response(),
        );
    }

    // 2. Protocol version check — honors `NetworkProtocolVersion`'s override
    // (issue #1320): a non-empty override pins matching to exactly that one
    // version instead of the full built-in list.
    let our_versions = effective_protocol_versions(&network.config.network_protocol_version);
    let matched_version = match check_protocol_version_match(headers, &our_versions) {
        VersionMatch::Matched(v) => v,
        VersionMatch::NoMatch { other_version } => {
            tracing::warn!(
                remote_version = %other_version,
                "incoming connection: protocol version mismatch"
            );
            return ValidationResult::Rejected(
                (StatusCode::PRECONDITION_FAILED, "protocol version mismatch").into_response(),
            );
        }
    };

    // 3. Resolve the tracking address: when `use_x_forwarded_for_address_field`
    // is configured, prefer the client address it names over the raw socket
    // address, mirroring go's `remoteHostProxyFix` (`network/requestTracker.go:473-480`)
    // — go applies this to `trackedRequest.remoteHost` before any of the
    // limit checks below, so the connection-count/rate-limit state (and the
    // localhost-rate-limit exemption) are all keyed on the proxy-reported
    // address, not the load balancer's own socket address.
    let tracking_ip = crate::request_tracker::get_forwarded_connection_address(
        headers,
        &network.config.use_x_forwarded_for_address_field,
        &network.misconfigured_x_forwarded_for,
    )
    .unwrap_or(remote_ip);

    // 4. Track the connection BEFORE checking limits so that concurrent
    //    handshakes from the same IP see each other's counts.
    network.connection_tracker.track_connection(tracking_ip);

    // 5. Per-IP connection limit
    if !network
        .connection_tracker
        .check_connection_limit(tracking_ip, network.config.max_connections_per_ip)
    {
        // Undo tracking — this request will not proceed.
        network.connection_tracker.release_connection(tracking_ip);
        tracing::warn!(
            ip = %tracking_ip,
            limit = network.config.max_connections_per_ip,
            "incoming connection: per-IP connection limit exceeded"
        );
        return ValidationResult::Rejected(
            (StatusCode::FORBIDDEN, "per-IP connection limit exceeded").into_response(),
        );
    }

    // 6. Rate limit — go's `DisableLocalhostConnectionRateLimit`
    // (`network/requestTracker.go:261,450`: `rateLimitedRemoteHost :=
    // (!cfg.DisableLocalhostConnectionRateLimit) || (!isLocalhost(host))`)
    // exempts loopback remotes from the rate limiter specifically (the
    // per-IP *connection-count* limit above still applies to localhost —
    // this only affects the rate-limit check).
    let rate_limited_remote =
        !network.config.disable_localhost_connection_rate_limit || !tracking_ip.is_loopback();
    if rate_limited_remote
        && !network
            .connection_tracker
            .check_rate_limit(tracking_ip, network.config.connections_rate_limiting_count)
    {
        // Undo tracking — this request will not proceed.
        network.connection_tracker.release_connection(tracking_ip);
        tracing::warn!(
            ip = %tracking_ip,
            "incoming connection: rate limit exceeded"
        );
        return ValidationResult::Rejected(
            (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response(),
        );
    }

    // 7. Self-loop detection
    let other_random = headers
        .get(HeaderName::from_static("x-algorand-noderandom"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if other_random.is_empty() {
        // Undo tracking — this request will not proceed.
        network.connection_tracker.release_connection(remote_ip);
        tracing::warn!("incoming connection: missing NodeRandom header");
        return ValidationResult::Rejected(
            (StatusCode::PRECONDITION_FAILED, "missing NodeRandom header").into_response(),
        );
    }

    if other_random == network.node_random {
        // Undo tracking — this request will not proceed.
        network.connection_tracker.release_connection(remote_ip);
        tracing::debug!("incoming connection: self-loop detected");
        // HTTP 508 Loop Detected (matching Go)
        return ValidationResult::Rejected(
            (
                StatusCode::from_u16(508).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                "self-connection detected",
            )
                .into_response(),
        );
    }

    ValidationResult::Ok {
        matched_version,
        tracking_ip,
    }
}

/// Resolves the effective peer address used as an accepted inbound peer's
/// `rootURL` (the key it is stored/re-dialed under), mirroring go's
/// `TrackerRequest.remoteAddress()` (`network/requestTracker.go:94-115`):
/// prefer the peer-reported public address from the `X-Algorand-Location`
/// header only if its hostname matches the (possibly proxy-derived)
/// `tracking_ip`; otherwise fall back to the raw socket address (or the
/// tracking host itself, when it disagrees with the socket address —
/// signalling it came from a trusted proxy). Issue #1421.
fn resolve_incoming_peer_address(
    remote_addr: SocketAddr,
    tracking_ip: std::net::IpAddr,
    headers: &HeaderMap,
) -> String {
    let other_public_addr = headers
        .get(HeaderName::from_static("x-algorand-location"))
        .and_then(|v| v.to_str().ok());
    crate::request_tracker::remote_address(
        &remote_addr.to_string(),
        &tracking_ip.to_string(),
        other_public_addr,
    )
}

// ---------------------------------------------------------------------------
// Gossip WebSocket upgrade handler (axum)
// ---------------------------------------------------------------------------

/// Axum handler for `GET /v1/:genesis_id/gossip`.
///
/// Validates the incoming connection, then upgrades to WebSocket.  On
/// successful upgrade, creates an inbound `WsPeer` and registers it in
/// the peer registry.
///
/// Mirrors Go's `WebsocketNetwork.ServeHTTP`.
async fn gossip_upgrade_handler(
    State(network): State<NetworkState>,
    Path(genesis_id): Path<String>,
    ws: WebSocketUpgrade,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> axum::response::Response {
    let remote_ip = remote_addr.ip();

    // Validate the incoming connection.
    let (matched_version, tracking_ip) =
        match validate_incoming_connection(&network, &genesis_id, &headers, remote_ip) {
            ValidationResult::Ok {
                matched_version,
                tracking_ip,
            } => (matched_version, tracking_ip),
            ValidationResult::Rejected(response) => return response,
        };

    // Resolve the effective peer address used as this peer's rootURL — see
    // `resolve_incoming_peer_address`'s doc comment (issue #1421).
    let resolved_addr = resolve_incoming_peer_address(remote_addr, tracking_ip, &headers);

    // Build response headers (matching Go's setHeaders for server responses).
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        HeaderName::from_static("x-algorand-version"),
        matched_version.parse().expect("valid header value"),
    );
    for v in effective_protocol_versions(&network.config.network_protocol_version) {
        response_headers.append(
            HeaderName::from_static("x-algorand-accept-version"),
            v.parse().expect("valid header value"),
        );
    }
    response_headers.insert(
        HeaderName::from_static("x-algorand-genesis"),
        network
            .config
            .genesis_id
            .parse()
            .expect("valid header value"),
    );
    response_headers.insert(
        HeaderName::from_static("x-algorand-noderandom"),
        network.node_random.parse().expect("valid header value"),
    );

    // vpack vote compression negotiation (issue #817's inbound-path wiring).
    //
    // Mirrors go-algorand's server-side flow (`network/wsNetwork.go`
    // `ServeHTTP`): decode the client's request `X-Algorand-Peer-Features`
    // header against the just-matched protocol version, and always send
    // back our own full advertised feature set on the response header
    // (`setHeaders(responseHeader, matchingVersion, wn)`), regardless of
    // what the client sent.
    //
    // The feature set actually applied to this connection's read/write
    // loops is the intersection of the client's declaration and our own
    // advertised set — following the same established deviation as the
    // outbound path's `connect.rs::try_connect`
    // (`remote_features.intersection(config.our_features)`) and its
    // `peer_features::stateful_table_size` doc comment: go-algorand instead
    // trusts the client's raw declaration for the stateless bit and takes
    // `min(ourConfiguredSize, peerAdvertisedSize)` for the stateful table
    // size independently. Using a single intersected value here keeps the
    // inbound and outbound paths in this crate consistent with each other,
    // and is behaviourally identical to go's approach whenever both sides
    // use the same (default 2048) table size.
    let our_features = crate::peer_features::advertise_vote_compression(
        network.config.enable_vote_compression,
        DEFAULT_VOTE_COMPRESSION_TABLE_SIZE,
    );
    let client_features_header = headers
        .get(HeaderName::from_static("x-algorand-peer-features"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let client_features =
        crate::peer_features::decode_peer_features(&matched_version, client_features_header);
    let negotiated_features = client_features.intersection(our_features);
    tracing::debug!(
        addr = %remote_addr,
        features_raw = %client_features_header,
        features_client = ?client_features,
        features_negotiated = ?negotiated_features,
        "inbound: negotiated peer features"
    );
    response_headers.insert(
        HeaderName::from_static("x-algorand-peer-features"),
        crate::peer_features::encode_peer_features(&our_features)
            .parse()
            .expect("valid header value"),
    );

    // Perform the WebSocket upgrade and attach the response headers
    // to the 101 Switching Protocols response.
    let network_clone = Arc::clone(&network);
    let version_clone = matched_version;
    let addr_str = resolved_addr;

    // Bound the accepted WebSocket connection's message/frame size to the
    // largest legitimate per-tag limit (`Tag::max_message_size()`'s max,
    // currently 6MiB for `VoteBundle`/`TopicMsgResp`, i.e.
    // `tag::MAX_MESSAGE_LENGTH`) rather than relying on axum/tungstenite's
    // own much larger default. Without this, an oversized message is
    // fully buffered by the WS library before `framing::decode_frame`'s
    // per-tag check ever runs (issue #1102) — the memory for it is
    // already spent by the time the application-level check rejects it.
    // Go's `wsPeer.go` readLoop enforces the equivalent bound
    // incrementally via `LimitedReaderSlurper`.
    let ws = ws
        .max_message_size(crate::tag::MAX_MESSAGE_LENGTH)
        .max_frame_size(crate::tag::MAX_MESSAGE_LENGTH);

    let mut response = ws
        .on_upgrade(move |socket| {
            handle_gossip_websocket(
                network_clone,
                socket,
                addr_str,
                version_clone,
                remote_ip,
                negotiated_features,
            )
        })
        .into_response();

    // Inject the Algorand handshake headers into the 101 response.
    let headers_mut = response.headers_mut();
    for (key, value) in response_headers.iter() {
        headers_mut.insert(key, value.clone());
    }

    response
}

/// Post-upgrade WebSocket handler.
///
/// Creates an inbound [`PeerHandle`] via [`PeerHandle::new_inbound`],
/// registers it in the network peer map (so broadcasts/relays reach
/// inbound peers), and tracks the connection in [`ConnectionTracker`].
///
/// On disconnect, the peer is removed from the peer map and the
/// connection tracking slot is released.
async fn handle_gossip_websocket(
    network: Arc<WebsocketNetwork>,
    socket: WebSocket,
    remote_addr: String,
    version: String,
    remote_ip: std::net::IpAddr,
    features: crate::peer_features::PeerFeatureFlags,
) {
    // Connection is already tracked by validate_incoming_connection().

    tracing::info!(
        addr = %remote_addr,
        version = %version,
        "inbound WebSocket connection accepted"
    );

    // Create a proper inbound PeerHandle that wraps the axum WebSocket
    // with read/write loops, so this peer is visible to broadcasts.
    //
    // Issue #789: thread the network's constructed incoming/outgoing
    // MessageFilters into the real inbound connection, matching the
    // outbound-dial path's `WsPeerConfig`. Without this, `WebsocketNetwork`
    // constructs the filters (config-driven since #768) but no accepted
    // connection ever consulted them, so gossip dedup had zero effect.
    //
    // Issue #803: `new_outgoing_message_filter()` builds a *fresh* filter
    // for this one connection — it must never be the same instance handed
    // to any other accepted or dialed peer, or one peer's `MsgDigestSkip`
    // would wrongly suppress sends to a completely different peer.
    let outgoing_filter = network.new_outgoing_message_filter();
    let handle = PeerHandle::new_inbound(
        socket,
        remote_addr.clone(),
        version,
        network.cancel.child_token(),
        network.incoming_message_filter().cloned(),
        outgoing_filter.clone(),
        features,
        // Issue #1425: share this network's single traffic-counter
        // instance so inbound peers' traffic is counted alongside
        // outbound peers', matching go's process-global counters.
        Some(network.network_metrics().clone()),
    );

    // Register the inbound peer in the peer map via add_peer, which
    // also spawns the receive/dispatch loop for multiplexer integration.
    network
        .add_peer(handle, PeerDirection::Inbound, outgoing_filter)
        .await;

    // Wait for the peer to disconnect (watch for removal from the peer map
    // or cancellation).  When it disconnects, release the connection tracker.
    let cancel = network.cancel.clone();
    let cleanup_network = Arc::clone(&network);
    let cleanup_addr = remote_addr;
    tokio::spawn(async move {
        // Poll until the peer is removed or the network shuts down.
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    let peers = cleanup_network.peers.read().await;
                    if !peers.contains_key(&cleanup_addr) {
                        break;
                    }
                    // Check if the peer's handle has been closed.
                    if let Some(entry) = peers.get(&cleanup_addr) {
                        if entry.handle.is_closed() {
                            drop(peers);
                            cleanup_network.remove_peer(&cleanup_addr).await;
                            break;
                        }
                    }
                }
            }
        }

        // Release connection tracking on disconnect.
        cleanup_network
            .connection_tracker
            .release_connection(remote_ip);
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // WebsocketNetworkConfig
    // -----------------------------------------------------------------------

    #[test]
    fn config_default_values() {
        let config = WebsocketNetworkConfig::default();
        assert_eq!(config.gossip_fanout, 4);
        assert_eq!(config.mesh_interval, Duration::from_secs(60));
        assert_eq!(config.max_peer_inactivity, Duration::from_secs(300));
        assert_eq!(config.slow_write_threshold, Duration::from_secs(25));
        assert!(config.genesis_id.is_empty());
        assert!(config.network_id.is_empty());
    }

    #[test]
    fn config_custom_values() {
        let config = WebsocketNetworkConfig {
            gossip_fanout: 8,
            mesh_interval: Duration::from_secs(30),
            max_peer_inactivity: Duration::from_secs(120),
            slow_write_threshold: Duration::from_secs(10),
            genesis_id: "testnet-v1.0".to_string(),
            network_id: "testnet".to_string(),
            ..Default::default()
        };
        assert_eq!(config.gossip_fanout, 8);
        assert_eq!(config.genesis_id, "testnet-v1.0");
    }

    // -----------------------------------------------------------------------
    // WebsocketNetwork creation
    // -----------------------------------------------------------------------

    #[test]
    fn create_with_defaults() {
        let net = WebsocketNetwork::with_defaults("mainnet-v1.0", "mainnet");
        assert_eq!(net.get_genesis_id(), "mainnet-v1.0");
        assert_eq!(net.config.network_id, "mainnet");
        assert_eq!(net.config.gossip_fanout, DEFAULT_GOSSIP_FANOUT);
    }

    #[test]
    fn create_with_custom_config() {
        let config = WebsocketNetworkConfig {
            gossip_fanout: 6,
            genesis_id: "betanet-v1.0".to_string(),
            network_id: "betanet".to_string(),
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(5, Duration::from_secs(30)));
        let net = WebsocketNetwork::new(config, phonebook.clone());

        assert_eq!(net.get_genesis_id(), "betanet-v1.0");
        assert_eq!(net.config.gossip_fanout, 6);
        assert!(Arc::ptr_eq(&net.phonebook, &phonebook));
    }

    // -----------------------------------------------------------------------
    // Peer registry
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn peer_count_initially_zero() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        assert_eq!(net.peer_count().await, 0);
    }

    #[tokio::test]
    async fn remove_nonexistent_peer_returns_false() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        assert!(!net.remove_peer("1.2.3.4:4160").await);
    }

    // -----------------------------------------------------------------------
    // GossipNode trait satisfaction
    // -----------------------------------------------------------------------

    #[test]
    fn gossip_node_trait_object_safety() {
        let net = WebsocketNetwork::with_defaults("testnet-v1.0", "testnet");
        // Verify the trait can be used as a trait object.
        let node: &dyn GossipNode = &net;
        assert_eq!(node.get_genesis_id(), "testnet-v1.0");
    }

    #[test]
    fn address_returns_not_listening() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        let (addr, listening) = net.address();
        assert!(addr.is_empty());
        assert!(!listening);
    }

    #[test]
    fn get_peers_empty_network() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        let peers = net.get_peers(&[PeerOption::PeersConnectedOut]);
        assert!(peers.is_empty());
    }

    #[test]
    fn get_peers_phonebook_relays() {
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        phonebook.replace_peer_list(
            &["relay1:4161".to_string(), "relay2:4161".to_string()],
            "default",
            RELAY_ROLE,
        );

        let config = WebsocketNetworkConfig {
            genesis_id: "test".to_string(),
            ..Default::default()
        };
        let net = WebsocketNetwork::new(config, phonebook);

        let peers = net.get_peers(&[PeerOption::PeersPhonebookRelays]);
        assert_eq!(peers.len(), 2);

        let addrs: HashSet<String> = peers.iter().map(|p| p.get_address().to_string()).collect();
        assert!(addrs.contains("relay1:4161"));
        assert!(addrs.contains("relay2:4161"));
    }

    #[test]
    fn on_network_advance_does_not_panic() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        net.on_network_advance();
    }

    #[test]
    fn register_and_clear_handlers() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        net.register_handlers(vec![]);
        net.clear_handlers();
        net.register_validator_handlers(vec![]);
        net.clear_validator_handlers();
    }

    #[test]
    fn disconnect_peers_on_empty_network() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        // Should not panic.
        net.disconnect_peers();
    }

    #[tokio::test]
    async fn stop_on_empty_network() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        net.stop().await;
        // After stop, the cancel token should be cancelled.
        assert!(net.cancel.is_cancelled());
    }

    #[tokio::test]
    async fn broadcast_on_empty_network() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        let result = net
            .broadcast(Tag::Transaction, vec![1, 2, 3], false, None)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn relay_on_empty_network() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        let result = net.relay(Tag::AgreementVote, vec![4, 5], true, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn start_on_empty_phonebook() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        let result = net.start().await;
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // PeerRef
    // -----------------------------------------------------------------------

    #[test]
    fn peer_ref_implements_peer() {
        let peer_ref = PeerRef {
            addr: "10.0.0.1:4160".to_string(),
        };
        let peer: &dyn Peer = &peer_ref;
        assert_eq!(peer.get_address(), "10.0.0.1:4160");
        assert_eq!(peer.get_connection_latency(), Duration::ZERO);
        assert!(peer.routing_addr().is_empty());
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    #[test]
    fn accessors_return_shared_state() {
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let config = WebsocketNetworkConfig {
            genesis_id: "test".to_string(),
            ..Default::default()
        };
        let net = WebsocketNetwork::new(config, phonebook.clone());

        // Phonebook should be the same Arc.
        assert!(Arc::ptr_eq(net.phonebook(), &phonebook));

        // Multiplexer and message filters should be accessible. The
        // outgoing filter is constructed by default (go's
        // `EnableOutgoingNetworkMessageFiltering` defaults `true`); the
        // incoming filter is not (go's `EnableIncomingMessageFilter`
        // defaults `false`).
        let _mux = net.multiplexer();
        assert!(net.new_outgoing_message_filter().is_some());
        assert!(net.incoming_message_filter().is_none());
    }

    /// Issue #803: unlike `incoming_message_filter()` (one shared instance,
    /// intentionally), `new_outgoing_message_filter()` must hand back a
    /// *different* `MessageFilter` object on every call — that's exactly
    /// what makes each new peer connection's outgoing filter independent of
    /// every other connection's.
    #[test]
    fn new_outgoing_message_filter_returns_independent_instances() {
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let config = WebsocketNetworkConfig {
            genesis_id: "test".to_string(),
            enable_outgoing_network_message_filtering: true,
            ..Default::default()
        };
        let net = WebsocketNetwork::new(config, phonebook);

        let first = net
            .new_outgoing_message_filter()
            .expect("enabled outgoing filter is constructed");
        let second = net
            .new_outgoing_message_filter()
            .expect("enabled outgoing filter is constructed");
        assert!(
            !Arc::ptr_eq(&first, &second),
            "each connection must get its own MessageFilter instance, not a shared one"
        );

        // Recording a digest in one connection's filter must never be
        // visible through a different connection's filter.
        let digest = crate::message_filter::generate_message_digest(&Tag::Transaction, b"m1");
        first.check_digest(&digest, true, true);
        assert!(first.check_digest(&digest, false, false));
        assert!(!second.check_digest(&digest, false, false));
    }

    #[test]
    fn message_filters_sized_from_config() {
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let config = WebsocketNetworkConfig {
            genesis_id: "test".to_string(),
            enable_incoming_message_filter: true,
            incoming_message_filter_bucket_count: 7,
            incoming_message_filter_bucket_size: 3,
            enable_outgoing_network_message_filtering: true,
            outgoing_message_filter_bucket_count: 2,
            outgoing_message_filter_bucket_size: 2,
            ..Default::default()
        };
        let net = WebsocketNetwork::new(config, phonebook);

        let incoming = net
            .incoming_message_filter()
            .expect("enabled incoming filter is constructed");
        let outgoing = net
            .new_outgoing_message_filter()
            .expect("enabled outgoing filter is constructed");

        // Exercise the configured (small) bucket size: inserting 3 distinct
        // digests into a bucket capped at 2 must trigger at least one
        // auto-rotation, evidenced by the first digest still being found
        // (ring-preserved) while the filter keeps functioning.
        let d1 = crate::message_filter::generate_message_digest(&Tag::Transaction, b"m1");
        let d2 = crate::message_filter::generate_message_digest(&Tag::Transaction, b"m2");
        assert!(!outgoing.check_digest(&d1, true, false));
        assert!(!outgoing.check_digest(&d2, true, false));
        assert!(outgoing.check_digest(&d1, false, false));

        assert!(!incoming.check_digest(&d1, true, false));
        assert!(incoming.check_digest(&d1, false, false));
    }

    #[test]
    fn message_filter_disabled_by_default_config_off() {
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let config = WebsocketNetworkConfig {
            genesis_id: "test".to_string(),
            enable_outgoing_network_message_filtering: false,
            ..Default::default()
        };
        let net = WebsocketNetwork::new(config, phonebook);
        assert!(net.incoming_message_filter().is_none());
        assert!(net.new_outgoing_message_filter().is_none());
    }

    // -----------------------------------------------------------------------
    // Pending disconnects
    // -----------------------------------------------------------------------

    #[test]
    fn pending_disconnects_initially_empty() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        let guard = net
            .pending_disconnects
            .lock()
            .expect("pending_disconnects lock poisoned");
        assert!(guard.is_empty());
    }

    // -----------------------------------------------------------------------
    // Relay mode tests (Epic 34 — Wave 2)
    // -----------------------------------------------------------------------

    #[test]
    fn is_relay_false_by_default() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        assert!(!net.is_relay());
    }

    #[test]
    fn is_relay_requires_both_net_address_and_relay_messages() {
        // net_address only — not a relay
        let config = WebsocketNetworkConfig {
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: false,
            genesis_id: "test".to_string(),
            ..Default::default()
        };
        let net = WebsocketNetwork::new(
            config,
            Arc::new(Phonebook::new(10, Duration::from_secs(60))),
        );
        assert!(!net.is_relay());

        // relay_messages only — not a relay
        let config2 = WebsocketNetworkConfig {
            net_address: None,
            relay_messages: true,
            genesis_id: "test".to_string(),
            ..Default::default()
        };
        let net2 = WebsocketNetwork::new(
            config2,
            Arc::new(Phonebook::new(10, Duration::from_secs(60))),
        );
        assert!(!net2.is_relay());

        // Both — is a relay
        let config3 = WebsocketNetworkConfig {
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            genesis_id: "test".to_string(),
            ..Default::default()
        };
        let net3 = WebsocketNetwork::new(
            config3,
            Arc::new(Phonebook::new(10, Duration::from_secs(60))),
        );
        assert!(net3.is_relay());
    }

    #[test]
    fn node_random_is_nonempty() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        assert!(!net.node_random().is_empty());
    }

    #[test]
    fn node_random_differs_between_instances() {
        let net1 = WebsocketNetwork::with_defaults("test", "test");
        let net2 = WebsocketNetwork::with_defaults("test", "test");
        // Very unlikely (1 in 2^64) to collide
        assert_ne!(net1.node_random(), net2.node_random());
    }

    #[test]
    fn register_http_handler_stores_handlers() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        let router = axum::Router::new();
        net.register_http_handler("/blocks", router);

        let guard = net.registered_handlers.lock().unwrap();
        assert_eq!(guard.len(), 1);
        assert_eq!(guard[0].0, "/blocks");
    }

    #[test]
    fn address_returns_empty_when_not_relay() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        let (addr, listening) = net.address();
        assert!(addr.is_empty());
        assert!(!listening);
    }

    // -----------------------------------------------------------------------
    // Connection validation tests
    // -----------------------------------------------------------------------

    fn make_relay_network(genesis_id: &str) -> WebsocketNetwork {
        let config = WebsocketNetworkConfig {
            genesis_id: genesis_id.to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            max_connections_per_ip: 3,
            connections_rate_limiting_count: 10,
            ..Default::default()
        };
        WebsocketNetwork::new(
            config,
            Arc::new(Phonebook::new(10, Duration::from_secs(60))),
        )
    }

    fn valid_incoming_headers(node_random: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("x-algorand-version"),
            "2.2".parse().unwrap(),
        );
        h.append(
            HeaderName::from_static("x-algorand-accept-version"),
            "2.2".parse().unwrap(),
        );
        h.insert(
            HeaderName::from_static("x-algorand-noderandom"),
            node_random.parse().unwrap(),
        );
        h.insert(
            HeaderName::from_static("x-algorand-genesis"),
            "testnet-v1.0".parse().unwrap(),
        );
        h
    }

    #[test]
    fn validate_incoming_genesis_mismatch() {
        let net = make_relay_network("testnet-v1.0");
        let headers = valid_incoming_headers("some-random");
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();

        // Correct genesis
        let result = validate_incoming_connection(&net, "testnet-v1.0", &headers, ip);
        assert!(matches!(result, ValidationResult::Ok { .. }));

        // Wrong genesis
        let result = validate_incoming_connection(&net, "mainnet-v1.0", &headers, ip);
        assert!(matches!(result, ValidationResult::Rejected(_)));
    }

    #[test]
    fn validate_incoming_protocol_version_mismatch() {
        let net = make_relay_network("testnet-v1.0");
        let ip: std::net::IpAddr = "10.0.0.2".parse().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-algorand-version"),
            "1.0".parse().unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-algorand-noderandom"),
            "peer-random".parse().unwrap(),
        );

        let result = validate_incoming_connection(&net, "testnet-v1.0", &headers, ip);
        assert!(matches!(result, ValidationResult::Rejected(_)));
    }

    #[test]
    fn validate_incoming_self_loop_rejected() {
        let net = make_relay_network("testnet-v1.0");
        let ip: std::net::IpAddr = "10.0.0.3".parse().unwrap();

        // Use the network's own node_random
        let headers = valid_incoming_headers(net.node_random());

        let result = validate_incoming_connection(&net, "testnet-v1.0", &headers, ip);
        assert!(matches!(result, ValidationResult::Rejected(_)));
    }

    #[test]
    fn validate_incoming_missing_node_random_rejected() {
        let net = make_relay_network("testnet-v1.0");
        let ip: std::net::IpAddr = "10.0.0.4".parse().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-algorand-version"),
            "2.2".parse().unwrap(),
        );
        // No x-algorand-noderandom header

        let result = validate_incoming_connection(&net, "testnet-v1.0", &headers, ip);
        assert!(matches!(result, ValidationResult::Rejected(_)));
    }

    #[test]
    fn validate_incoming_per_ip_connection_limit() {
        let net = make_relay_network("testnet-v1.0");
        let ip: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let headers = valid_incoming_headers("peer-random-42");

        // Pre-track 3 connections from this IP (max_connections_per_ip is 3).
        // validate_incoming_connection tracks internally, so the count becomes
        // 4 during validation, which exceeds the limit (4 < 3 = false).
        // On rejection the tracker is released back to 3.
        net.connection_tracker.track_connection(ip);
        net.connection_tracker.track_connection(ip);
        net.connection_tracker.track_connection(ip);

        let result = validate_incoming_connection(&net, "testnet-v1.0", &headers, ip);
        assert!(matches!(result, ValidationResult::Rejected(_)));
        // Rejected path releases, so count is back to 3.
        assert_eq!(net.connection_tracker.active_count(ip), 3);

        // Release two connections (count → 1) — validation will track to 2,
        // which is below the limit of 3, so it should be allowed.
        net.connection_tracker.release_connection(ip);
        net.connection_tracker.release_connection(ip);
        let result = validate_incoming_connection(&net, "testnet-v1.0", &headers, ip);
        assert!(matches!(result, ValidationResult::Ok { .. }));
        // Successful validation keeps the tracked connection, so count is 2.
        assert_eq!(net.connection_tracker.active_count(ip), 2);
    }

    #[test]
    fn validate_incoming_rate_limit() {
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            max_connections_per_ip: 100, // High limit so we only test rate
            connections_rate_limiting_count: 3,
            ..Default::default()
        };
        let net = WebsocketNetwork::new(
            config,
            Arc::new(Phonebook::new(10, Duration::from_secs(60))),
        );
        let ip: std::net::IpAddr = "10.0.0.6".parse().unwrap();
        let headers = valid_incoming_headers("peer-random-43");

        // Pre-track 3 connections. validate_incoming_connection will track a
        // 4th internally, making the rate count 4 which exceeds the threshold
        // of 3 (4 <= 3 is false), so it will be rejected.
        net.connection_tracker.track_connection(ip);
        net.connection_tracker.track_connection(ip);
        net.connection_tracker.track_connection(ip);

        let result = validate_incoming_connection(&net, "testnet-v1.0", &headers, ip);
        assert!(matches!(result, ValidationResult::Rejected(_)));
        // Rejected path releases the active count, but the rate-limit
        // timestamps are not removed, ensuring the rate window is enforced.
        assert_eq!(net.connection_tracker.active_count(ip), 3);
    }

    #[test]
    fn validate_incoming_localhost_exempt_from_rate_limit_by_default() {
        // go's `DisableLocalhostConnectionRateLimit` defaults to `true`
        // (issue #768) — a loopback remote must NOT be rate-limited even
        // when it would otherwise exceed `connections_rate_limiting_count`.
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            max_connections_per_ip: 100,
            connections_rate_limiting_count: 3,
            ..Default::default()
        };
        assert!(
            config.disable_localhost_connection_rate_limit,
            "default must match go's true"
        );
        let net = WebsocketNetwork::new(
            config,
            Arc::new(Phonebook::new(10, Duration::from_secs(60))),
        );
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        net.connection_tracker.track_connection(ip);
        net.connection_tracker.track_connection(ip);
        net.connection_tracker.track_connection(ip);

        let headers = valid_incoming_headers("peer-random-loopback");
        let result = validate_incoming_connection(&net, "testnet-v1.0", &headers, ip);
        assert!(
            matches!(result, ValidationResult::Ok { .. }),
            "loopback IP must be exempt from the rate limit"
        );
    }

    #[test]
    fn validate_incoming_localhost_rate_limited_when_exemption_disabled() {
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            max_connections_per_ip: 100,
            connections_rate_limiting_count: 3,
            disable_localhost_connection_rate_limit: false,
            ..Default::default()
        };
        let net = WebsocketNetwork::new(
            config,
            Arc::new(Phonebook::new(10, Duration::from_secs(60))),
        );
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        net.connection_tracker.track_connection(ip);
        net.connection_tracker.track_connection(ip);
        net.connection_tracker.track_connection(ip);

        let headers = valid_incoming_headers("peer-random-loopback-2");
        let result = validate_incoming_connection(&net, "testnet-v1.0", &headers, ip);
        assert!(
            matches!(result, ValidationResult::Rejected(_)),
            "with the exemption off, loopback follows the same rate limit as any IP"
        );
    }

    // -----------------------------------------------------------------------
    // X-Forwarded-For wiring (issue #1157)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_incoming_tracks_forwarded_address_when_configured() {
        // With `use_x_forwarded_for_address_field` set, the per-IP
        // connection tracker must key off the header-provided address
        // rather than the raw socket address — mirroring go's
        // `remoteHostProxyFix`.
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            max_connections_per_ip: 3,
            connections_rate_limiting_count: 10,
            use_x_forwarded_for_address_field: "X-Forwarded-For".to_string(),
            ..Default::default()
        };
        let net = WebsocketNetwork::new(
            config,
            Arc::new(Phonebook::new(10, Duration::from_secs(60))),
        );
        // The load balancer's own socket address...
        let socket_ip: std::net::IpAddr = "10.0.0.100".parse().unwrap();
        // ...but the header names the real client.
        let forwarded_ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();

        let mut headers = valid_incoming_headers("forwarded-random");
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            "203.0.113.7".parse().unwrap(),
        );

        let result = validate_incoming_connection(&net, "testnet-v1.0", &headers, socket_ip);
        assert!(matches!(result, ValidationResult::Ok { .. }));

        // Tracked under the forwarded address, not the socket address.
        assert_eq!(net.connection_tracker.active_count(forwarded_ip), 1);
        assert_eq!(net.connection_tracker.active_count(socket_ip), 0);
    }

    #[test]
    fn validate_incoming_falls_back_to_socket_ip_when_header_absent() {
        // Configured but the proxy didn't actually set the header: falls
        // back to the raw socket address rather than rejecting outright.
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            max_connections_per_ip: 3,
            connections_rate_limiting_count: 10,
            use_x_forwarded_for_address_field: "X-Forwarded-For".to_string(),
            ..Default::default()
        };
        let net = WebsocketNetwork::new(
            config,
            Arc::new(Phonebook::new(10, Duration::from_secs(60))),
        );
        let socket_ip: std::net::IpAddr = "10.0.0.101".parse().unwrap();
        let headers = valid_incoming_headers("forwarded-random-2");

        let result = validate_incoming_connection(&net, "testnet-v1.0", &headers, socket_ip);
        assert!(matches!(result, ValidationResult::Ok { .. }));
        assert_eq!(net.connection_tracker.active_count(socket_ip), 1);
    }

    #[test]
    fn validate_incoming_ignores_forwarded_header_when_unconfigured() {
        // Default config (empty field name): the header must be ignored
        // entirely, even if present — tracking stays on the socket address.
        let net = make_relay_network("testnet-v1.0");
        assert!(net.config.use_x_forwarded_for_address_field.is_empty());

        let socket_ip: std::net::IpAddr = "10.0.0.102".parse().unwrap();
        let mut headers = valid_incoming_headers("forwarded-random-3");
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            "203.0.113.9".parse().unwrap(),
        );

        let result = validate_incoming_connection(&net, "testnet-v1.0", &headers, socket_ip);
        assert!(matches!(result, ValidationResult::Ok { .. }));
        assert_eq!(net.connection_tracker.active_count(socket_ip), 1);
        let forwarded_ip: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(net.connection_tracker.active_count(forwarded_ip), 0);
    }

    #[test]
    fn validate_incoming_per_ip_limit_keyed_on_forwarded_address() {
        // The per-IP connection limit itself must be enforced against the
        // forwarded address, not the (shared, load-balancer) socket
        // address — otherwise many distinct real clients behind one proxy
        // would all collide on a single counter.
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            max_connections_per_ip: 3,
            connections_rate_limiting_count: 100,
            use_x_forwarded_for_address_field: "X-Forwarded-For".to_string(),
            ..Default::default()
        };
        let net = WebsocketNetwork::new(
            config,
            Arc::new(Phonebook::new(10, Duration::from_secs(60))),
        );
        let socket_ip: std::net::IpAddr = "10.0.0.103".parse().unwrap();
        let forwarded_ip: std::net::IpAddr = "203.0.113.8".parse().unwrap();

        // Pre-track 3 connections directly under the forwarded address.
        net.connection_tracker.track_connection(forwarded_ip);
        net.connection_tracker.track_connection(forwarded_ip);
        net.connection_tracker.track_connection(forwarded_ip);

        let mut headers = valid_incoming_headers("forwarded-random-4");
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            "203.0.113.8".parse().unwrap(),
        );

        let result = validate_incoming_connection(&net, "testnet-v1.0", &headers, socket_ip);
        assert!(matches!(result, ValidationResult::Rejected(_)));
        // Rejected path releases the tracked connection back to 3.
        assert_eq!(net.connection_tracker.active_count(forwarded_ip), 3);
        assert_eq!(net.connection_tracker.active_count(socket_ip), 0);
    }

    // -- resolve_incoming_peer_address (issue #1421: X-Algorand-Location
    // header consumed on the incoming-accept path, matching go's
    // TrackerRequest.remoteAddress() precedence) -----------------------

    #[test]
    fn resolve_incoming_peer_address_no_header_uses_socket_addr() {
        let remote_addr: SocketAddr = "127.0.0.1:4444".parse().unwrap();
        let tracking_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let headers = HeaderMap::new();

        assert_eq!(
            resolve_incoming_peer_address(remote_addr, tracking_ip, &headers),
            "127.0.0.1:4444"
        );
    }

    #[test]
    fn resolve_incoming_peer_address_header_used_when_hostname_matches() {
        // The peer's self-reported public address (with its real listening
        // port) is used because its hostname matches the observed remote.
        let remote_addr: SocketAddr = "10.0.0.1:55555".parse().unwrap();
        let tracking_ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-algorand-location"),
            "10.0.0.1:4160".parse().unwrap(),
        );

        assert_eq!(
            resolve_incoming_peer_address(remote_addr, tracking_ip, &headers),
            "10.0.0.1:4160"
        );
    }

    #[test]
    fn resolve_incoming_peer_address_header_ignored_when_hostname_mismatches() {
        // A peer can claim any X-Algorand-Location it likes; it's only
        // trusted when its hostname matches the address it actually
        // connected from.
        let remote_addr: SocketAddr = "10.0.0.1:55555".parse().unwrap();
        let tracking_ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-algorand-location"),
            "203.0.113.5:4160".parse().unwrap(),
        );

        assert_eq!(
            resolve_incoming_peer_address(remote_addr, tracking_ip, &headers),
            "10.0.0.1:55555"
        );
    }

    #[test]
    fn resolve_incoming_peer_address_proxy_tracking_ip_used_when_it_disagrees() {
        // No X-Algorand-Location header, but the tracking IP (resolved via
        // X-Forwarded-For upstream) disagrees with the raw socket address —
        // it came from a trusted proxy, so it's preferred over the socket
        // address (without a port, matching go's `remoteHost` fallback).
        let remote_addr: SocketAddr = "127.0.0.1:4444".parse().unwrap();
        let tracking_ip: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let headers = HeaderMap::new();

        assert_eq!(
            resolve_incoming_peer_address(remote_addr, tracking_ip, &headers),
            "203.0.113.9"
        );
    }

    #[test]
    fn validate_incoming_valid_connection_passes() {
        let net = make_relay_network("testnet-v1.0");
        let ip: std::net::IpAddr = "10.0.0.7".parse().unwrap();
        let headers = valid_incoming_headers("different-random");

        let result = validate_incoming_connection(&net, "testnet-v1.0", &headers, ip);
        match result {
            ValidationResult::Ok {
                matched_version, ..
            } => {
                assert_eq!(matched_version, "2.2");
            }
            ValidationResult::Rejected(_) => {
                panic!("expected Ok, got Rejected");
            }
        }
    }

    // -----------------------------------------------------------------------
    // HTTP server routing tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn relay_server_starts_and_address_updates() {
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            network_id: "testnet".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let net = Arc::new(WebsocketNetwork::new(config, phonebook));

        // Before starting, address should be empty.
        let (addr, listening) = net.address();
        assert!(addr.is_empty());
        assert!(!listening);

        // Start the relay server.
        net.start_relay_server().await.unwrap();

        // After starting, address should be populated.
        let (addr, listening) = net.address();
        assert!(listening);
        assert!(addr.contains("127.0.0.1:"));
        // The port should not be 0 (OS-assigned a real port).
        let port: u16 = addr.split(':').next_back().unwrap().parse().unwrap();
        assert_ne!(port, 0);

        // Cleanup.
        net.stop().await;
    }

    #[tokio::test]
    async fn relay_server_health_endpoint_responds() {
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            network_id: "testnet".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let net = Arc::new(WebsocketNetwork::new(config, phonebook));
        net.start_relay_server().await.unwrap();

        let (addr, _) = net.address();

        // Hit the /status endpoint.
        let url = format!("http://{}/status", addr);
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "ok");

        net.stop().await;
    }

    #[tokio::test]
    async fn relay_server_unknown_path_returns_404() {
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            network_id: "testnet".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let net = Arc::new(WebsocketNetwork::new(config, phonebook));
        net.start_relay_server().await.unwrap();

        let (addr, _) = net.address();

        // Hit an unknown path.
        let url = format!("http://{}/nonexistent", addr);
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), 404);

        net.stop().await;
    }

    #[tokio::test]
    async fn relay_server_gossip_path_without_upgrade_rejected() {
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            network_id: "testnet".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let net = Arc::new(WebsocketNetwork::new(config, phonebook));
        net.start_relay_server().await.unwrap();

        let (addr, _) = net.address();

        // Hit the gossip path without WebSocket upgrade headers.
        // Axum's WebSocket extractor will reject with a 400-level error.
        let url = format!("http://{}/v1/testnet-v1.0/gossip", addr);
        let resp = reqwest::get(&url).await.unwrap();
        // Without proper upgrade headers, axum will return an error.
        assert_ne!(resp.status(), 200);

        net.stop().await;
    }

    #[tokio::test]
    async fn non_relay_start_does_not_listen() {
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            network_id: "testnet".to_string(),
            net_address: None,
            relay_messages: false,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let net = Arc::new(WebsocketNetwork::new(config, phonebook));
        net.start_relay_server().await.unwrap();

        let (addr, listening) = net.address();
        assert!(addr.is_empty());
        assert!(!listening);

        net.stop().await;
    }

    /// Issue #748: a listen address alone must open the listener, matching
    /// go's `IsListenServer()`-only gating (`NetAddress != ""`) — the
    /// listener bind must NOT also require `relay_messages`/
    /// `ForceRelayMessages`. Before the fix, `start_relay_server` silently
    /// refused to bind whenever `relay_messages` was `false`, even with a
    /// listen address configured.
    #[tokio::test]
    async fn net_address_alone_opens_the_listener_without_relay_messages() {
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            network_id: "testnet".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: false,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let net = Arc::new(WebsocketNetwork::new(config, phonebook));
        net.start_relay_server().await.unwrap();

        let (addr, listening) = net.address();
        assert!(
            listening,
            "a configured listen address must open a listener"
        );
        assert!(!addr.is_empty());

        net.stop().await;
    }

    /// Issue #748: go's `relayMessages = IsListenServer() || ForceRelayMessages`
    /// (`network/wsNetwork.go:601`) is an OR, not an AND — a listening node
    /// forwards messages regardless of `ForceRelayMessages`. Verified here
    /// via the `relay()` trait method, which previously dropped messages
    /// silently whenever the (misnamed-in-effect) `relay_messages` config
    /// field was `false`, even for a listening node.
    #[tokio::test]
    async fn listening_node_forwards_messages_even_without_force_relay_messages() {
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            network_id: "testnet".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: false,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let net = Arc::new(WebsocketNetwork::new(config, phonebook));
        assert!(
            net.effective_relay_messages(),
            "a listening node must forward regardless of relay_messages"
        );
        net.stop().await;
    }

    /// A non-listening node with `relay_messages: false` (go's
    /// `ForceRelayMessages: false`) must NOT forward — this is the
    /// "peer, not relay" default participation-node case, unaffected by
    /// issue #748's fix.
    #[tokio::test]
    async fn non_listening_node_without_force_relay_messages_does_not_forward() {
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            network_id: "testnet".to_string(),
            net_address: None,
            relay_messages: false,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let net = Arc::new(WebsocketNetwork::new(config, phonebook));
        assert!(!net.effective_relay_messages());
        net.stop().await;
    }

    /// A non-listening node with `ForceRelayMessages: true` must still
    /// forward — the other half of go's OR semantics.
    #[tokio::test]
    async fn non_listening_node_with_force_relay_messages_still_forwards() {
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            network_id: "testnet".to_string(),
            net_address: None,
            relay_messages: true,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let net = Arc::new(WebsocketNetwork::new(config, phonebook));
        assert!(net.effective_relay_messages());
        net.stop().await;
    }

    /// Issue #748: go's `BroadcastConnectionsLimit` default is `-1`
    /// (unbounded), not algod-rust's old hardcoded `35`.
    #[test]
    fn default_broadcast_connections_limit_is_unbounded() {
        let config = WebsocketNetworkConfig::default();
        assert_eq!(
            config.broadcast_connections_limit,
            UNBOUNDED_BROADCAST_CONNECTIONS_LIMIT
        );
    }

    /// Issue #748: go's `BlockServiceMemCap` default is the literal byte
    /// count `500000000`, not a binary-MiB approximation
    /// (`500 * 1024 * 1024 = 524288000`).
    #[test]
    fn default_block_service_mem_cap_matches_go_byte_count_exactly() {
        let config = WebsocketNetworkConfig::default();
        assert_eq!(config.block_service_mem_cap, 500_000_000);
    }

    // -----------------------------------------------------------------------
    // Issue #817: vpack vote compression on the inbound (axum) path.
    //
    // These tests exercise a *real* accepted connection end-to-end: a real
    // `WebsocketNetwork` relay server (the new inbound path under test) is
    // dialed by a real outbound client via `connect.rs::try_connect` (the
    // already-verified PR #915 outbound path). Because both sides are real,
    // independently-implemented read/write loops, a vote surviving the round
    // trip byte-for-byte is only possible if the inbound side's negotiation
    // and (de)compression genuinely work — it cannot pass by accident the
    // way a "does the raw payload still arrive" test could (an uncompressed
    // passthrough would also satisfy that weaker check).
    // -----------------------------------------------------------------------

    use crate::connect::try_connect;
    use crate::handler::MessageHandler;
    use crate::message::IncomingMessage;
    use crate::peer_features::{advertise_vote_compression, PeerFeatureFlags};

    /// Builds a realistic, deterministic `UnauthenticatedVote` msgpack
    /// payload for compression round-trip tests. Mirrors `ws_peer.rs`'s
    /// private `sample_vote_msgpack` test helper (not reusable across
    /// modules), but a `round` argument keeps successive stateful votes
    /// distinct.
    fn sample_vote_msgpack(round: u64) -> Vec<u8> {
        use algo_agreement::{
            Period, ProposalValue, RawVote, Step, UnauthenticatedCredential, UnauthenticatedVote,
        };
        use algo_consensus_crypto::OneTimeSignature;
        use algo_types::{Address, Digest, Round};

        let vote = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x11; 32]),
                round: Round(round),
                period: Period(0),
                step: Step(1),
                proposal: ProposalValue {
                    original_period: Period(0),
                    original_proposer: Address([0u8; 32]),
                    block_digest: Digest([0x22; 32]),
                    encoding_digest: Digest([0u8; 32]),
                },
            },
            cred: UnauthenticatedCredential::new([0x33; 80]),
            sig: OneTimeSignature {
                sig: [0x44; 64],
                pk: [0x55; 32],
                pk_sig_old: [0u8; 64],
                pk2: [0x66; 32],
                pk1_sig: [0x77; 64],
                pk2_sig: [0x88; 64],
            },
        };
        algo_agreement::codec::encode_vote(&vote)
    }

    /// Test message handler that forwards every received payload onto an
    /// mpsc channel for the test to assert on, and takes no further action
    /// (`ForwardingPolicy::Ignore`) — this is what lets a test observe
    /// exactly what the inbound read loop decoded from the wire.
    struct CaptureHandler {
        tx: mpsc::Sender<Vec<u8>>,
    }

    #[async_trait]
    impl MessageHandler for CaptureHandler {
        async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
            let _ = self.tx.try_send(msg.data.clone());
            OutgoingMessage {
                action: ForwardingPolicy::Ignore,
                tag: msg.tag,
                payload: Vec::new(),
                topics: None,
            }
        }
    }

    /// Spins up a relay `WebsocketNetwork` (server) listening on
    /// `127.0.0.1:0`, registers a [`CaptureHandler`] for `AgreementVote` so
    /// the test can observe what the inbound read loop decoded, and returns
    /// the network plus the capture channel's receiver.
    async fn start_capturing_relay(
        genesis_id: &str,
    ) -> (Arc<WebsocketNetwork>, mpsc::Receiver<Vec<u8>>) {
        let config = WebsocketNetworkConfig {
            genesis_id: genesis_id.to_string(),
            network_id: "testnet".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let net = Arc::new(WebsocketNetwork::new(config, phonebook));

        let (tx, rx) = mpsc::channel(8);
        net.register_handlers(vec![TaggedMessageHandler {
            tag: Tag::AgreementVote,
            handler: Arc::new(CaptureHandler { tx }),
        }]);

        net.start_relay_server().await.expect("relay server starts");
        (net, rx)
    }

    /// Full bidirectional round trip with stateful vote compression
    /// negotiated on both sides (client advertises `avvpack`+`avvpack2048`,
    /// matching the server's own default).
    ///
    /// - **Read direction** (client → server, exercising the new inbound
    ///   read loop): the client's already-verified outbound `write_loop`
    ///   (PR #915) stateful-compresses the vote to a `VP` frame; only a
    ///   correct inbound `decompress_incoming_vote` wiring can recover the
    ///   original bytes for the `CaptureHandler` to observe.
    /// - **Write direction** (server → client, exercising the new inbound
    ///   write loop): `net.broadcast` sends the vote to the inbound peer's
    ///   send channel; only a correct inbound `compress_outgoing_vote`
    ///   wiring produces a `VP` frame the client's already-verified
    ///   outbound `read_loop` can decompress back to the original bytes.
    #[tokio::test]
    async fn inbound_peer_negotiates_and_round_trips_stateful_vote_compression() {
        let (server_net, mut captured) = start_capturing_relay("testnet-v1.0").await;
        let (addr, _) = server_net.address();

        let connect_config = ConnectConfig {
            genesis_id: "testnet-v1.0".to_string(),
            our_features: advertise_vote_compression(true, 2048),
            ..ConnectConfig::default()
        };
        let client_handle = try_connect(&addr, &connect_config)
            .await
            .expect("client connects to inbound relay");

        // The response header wiring (this issue's core fix) must have
        // negotiated the full stateful tier, since both sides advertise
        // the same (2048) table size.
        let features = client_handle.features();
        assert!(
            features.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK),
            "stateless vpack must be negotiated: {features:?}"
        );
        assert!(
            features.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK_STATEFUL_2048),
            "stateful vpack (2048) must be negotiated: {features:?}"
        );

        // --- Read direction: client -> server ---
        let vote_to_server = sample_vote_msgpack(1000);
        client_handle
            .send(OutgoingMessage::new(
                Tag::AgreementVote,
                vote_to_server.clone(),
            ))
            .expect("send from client");

        let received = tokio::time::timeout(Duration::from_secs(5), captured.recv())
            .await
            .expect("server captured a vote before timeout")
            .expect("capture channel open");
        assert_eq!(
            received, vote_to_server,
            "inbound read loop must decompress the client's stateful (VP) vote exactly"
        );

        // --- Write direction: server -> client ---
        let vote_to_client = sample_vote_msgpack(2000);
        server_net
            .broadcast(Tag::AgreementVote, vote_to_client.clone(), false, None)
            .await
            .expect("server broadcast succeeds");

        let mut client_handle = client_handle;
        let incoming = tokio::time::timeout(Duration::from_secs(5), client_handle.recv())
            .await
            .expect("client received a message before timeout")
            .expect("client incoming channel open");
        assert_eq!(incoming.tag, Tag::AgreementVote);
        assert_eq!(
            incoming.data, vote_to_client,
            "outbound (client) read loop must decompress the server's stateful (VP) vote exactly"
        );

        client_handle.close();
        server_net.stop().await;
    }

    /// Same round trip, but the client advertises only the stateless
    /// (`avvpack`) feature, not any stateful tier — the negotiated table
    /// size must be `0` and votes must travel as plain `AV` frames (still
    /// vpack-stateless-compressed, but never re-tagged to `VP`). Verifies
    /// the inbound path's negotiation correctly falls back to
    /// stateless-only, not just the "everything advertised" happy path.
    #[tokio::test]
    async fn inbound_peer_negotiates_stateless_only_when_client_omits_stateful_tier() {
        let (server_net, mut captured) = start_capturing_relay("testnet-v1.0").await;
        let (addr, _) = server_net.address();

        let connect_config = ConnectConfig {
            genesis_id: "testnet-v1.0".to_string(),
            // table_size = 0 -> advertise_vote_compression sets only the
            // stateless COMPRESSED_VOTE_VPACK bit, no stateful tier.
            our_features: advertise_vote_compression(true, 0),
            ..ConnectConfig::default()
        };
        let client_handle = try_connect(&addr, &connect_config)
            .await
            .expect("client connects to inbound relay");

        let features = client_handle.features();
        assert!(features.contains(PeerFeatureFlags::COMPRESSED_VOTE_VPACK));
        assert!(
            !features.has_stateful_vpack(),
            "no stateful tier should be negotiated: {features:?}"
        );

        let vote_to_server = sample_vote_msgpack(3000);
        client_handle
            .send(OutgoingMessage::new(
                Tag::AgreementVote,
                vote_to_server.clone(),
            ))
            .expect("send from client");

        let received = tokio::time::timeout(Duration::from_secs(5), captured.recv())
            .await
            .expect("server captured a vote before timeout")
            .expect("capture channel open");
        assert_eq!(received, vote_to_server);

        server_net.stop().await;
    }

    /// The server's 101 response must always carry the server's own full
    /// advertised feature set on `X-Algorand-Peer-Features`, regardless of
    /// what the client requested — mirrors go-algorand's `ServeHTTP`
    /// (`setHeaders(responseHeader, matchingVersion, wn)`), which is
    /// unconditional on the client's own header. Performs the raw WebSocket
    /// handshake directly (rather than via `try_connect`, which only
    /// exposes the already-intersected feature set) so the response
    /// header's raw content can be inspected.
    #[tokio::test]
    async fn inbound_response_always_advertises_full_server_feature_set() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        let (server_net, _captured) = start_capturing_relay("testnet-v1.0").await;
        let (addr, _) = server_net.address();

        // Client advertises nothing (no `X-Algorand-Peer-Features` header
        // at all) — the server's response must still advertise its own
        // full set unconditionally.
        let url = crate::connect::build_gossip_url(&addr, "testnet-v1.0");
        let mut request = url.into_client_request().expect("valid request");
        request.headers_mut().insert(
            HeaderName::from_static("x-algorand-version"),
            "2.2".parse().unwrap(),
        );
        request.headers_mut().insert(
            HeaderName::from_static("x-algorand-noderandom"),
            "12345".parse().unwrap(),
        );
        request.headers_mut().insert(
            HeaderName::from_static("x-algorand-genesis"),
            "testnet-v1.0".parse().unwrap(),
        );

        let (_ws_stream, response) = tokio_tungstenite::connect_async(request)
            .await
            .expect("raw handshake succeeds");

        let features_header = response
            .headers()
            .get(HeaderName::from_static("x-algorand-peer-features"))
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let expected = crate::peer_features::encode_peer_features(&advertise_vote_compression(
            true,
            DEFAULT_VOTE_COMPRESSION_TABLE_SIZE,
        ));
        assert_eq!(
            features_header, expected,
            "server response must advertise its own full feature set unconditionally"
        );

        server_net.stop().await;
    }

    // -----------------------------------------------------------------------
    // Issue #1102: explicit WebSocket max_message_size/max_frame_size on
    // the server accept path, matching go's per-tag limits.
    //
    // Before this fix, the axum `WebSocketUpgrade` accepted the connection
    // with tungstenite's own (much larger) default message/frame size
    // ceiling, so an oversized message was fully buffered in memory before
    // `framing::decode_frame`'s per-tag check ever ran. This test proves
    // rejection now happens at the WS layer itself: the raw client
    // (configured with a *larger* ceiling than the server, so it is not
    // the one enforcing the limit) sends a single message over
    // `tag::MAX_MESSAGE_LENGTH`, and the server closes the connection
    // before any application-level frame decoding occurs — a
    // `CaptureHandler` registered for the message's own tag never
    // observes it, and the connection is unusable afterwards.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn oversized_message_is_rejected_at_the_ws_layer_not_just_decode_frame() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::protocol::{Message, WebSocketConfig};

        let (server_net, mut captured) = start_capturing_relay("testnet-v1.0").await;
        let (addr, _) = server_net.address();

        let url = crate::connect::build_gossip_url(&addr, "testnet-v1.0");
        let mut request = url.into_client_request().expect("valid request");
        request.headers_mut().insert(
            HeaderName::from_static("x-algorand-version"),
            "2.2".parse().unwrap(),
        );
        request.headers_mut().insert(
            HeaderName::from_static("x-algorand-noderandom"),
            "12345".parse().unwrap(),
        );
        request.headers_mut().insert(
            HeaderName::from_static("x-algorand-genesis"),
            "testnet-v1.0".parse().unwrap(),
        );

        // The client itself must NOT be the one enforcing the limit, so it
        // is deliberately configured with a ceiling well above the
        // server's — proving any rejection observed is the server's doing.
        let client_config = WebSocketConfig {
            max_message_size: Some(crate::tag::MAX_MESSAGE_LENGTH * 4),
            max_frame_size: Some(crate::tag::MAX_MESSAGE_LENGTH * 4),
            ..WebSocketConfig::default()
        };
        let (mut ws_stream, _response) =
            tokio_tungstenite::connect_async_with_config(request, Some(client_config), false)
                .await
                .expect("raw handshake succeeds");

        // Build a single oversized message: a valid "AV" tag followed by
        // enough filler to push the *whole message* just over
        // `MAX_MESSAGE_LENGTH`. (AgreementVote's own per-tag limit is far
        // smaller than this, but that is irrelevant here — the point is
        // that the WS layer must never hand this message to
        // `decode_frame` in the first place.)
        let oversized_len = crate::tag::MAX_MESSAGE_LENGTH + 1024;
        let mut oversized = Vec::with_capacity(oversized_len);
        oversized.extend_from_slice(Tag::AgreementVote.as_bytes().as_slice());
        oversized.resize(oversized_len, 0u8);

        // Sending may itself fail immediately (the client's write erroring
        // out as the server resets the connection), or it may succeed and
        // only the subsequent read observes the rejection — either is
        // consistent with WS-layer enforcement, so only fail the test if
        // the send succeeds *and* is followed by a normally-open
        // connection.
        let send_result = ws_stream.send(Message::Binary(oversized)).await;

        if send_result.is_ok() {
            // The connection must close (Close frame or a hard error) --
            // it must NOT stay open and simply swallow the oversized
            // message while continuing to serve the peer.
            let next = tokio::time::timeout(Duration::from_secs(5), ws_stream.next())
                .await
                .expect("server responds (with a close/error) before timeout");
            match next {
                None => {}                        // connection closed cleanly
                Some(Err(_)) => {}                // protocol error
                Some(Ok(Message::Close(_))) => {} // explicit close frame
                Some(Ok(other)) => panic!(
                    "expected the server to reject the oversized message at the WS layer, \
                     but the connection stayed open and returned: {other:?}"
                ),
            }
        }

        // Regardless of how the rejection surfaced, the oversized message
        // must never have reached the application-level `CaptureHandler`
        // -- proving it was dropped by the WS layer, not merely accepted
        // and then discarded after `decode_frame`.
        let captured_anything = tokio::time::timeout(Duration::from_millis(500), captured.recv())
            .await
            .ok()
            .flatten();
        assert!(
            captured_anything.is_none(),
            "oversized message must never reach the application-level handler"
        );

        server_net.stop().await;
    }

    // -----------------------------------------------------------------------
    // Issue #1101: wiring `rate_limited_call` into the real outbound dial,
    // and `ConnectionPerformanceMonitor`/`NetworkAdvanceMonitor` into a real
    // disconnect decision.
    // -----------------------------------------------------------------------

    use crate::connect::try_connect_with_phonebook;

    /// `try_connect_with_phonebook` must actually consult the phonebook's
    /// rate limiter before dialing — not just accept a `Phonebook` argument
    /// it ignores. A capacity-1 phonebook window forces the second dial to
    /// the same address to measurably wait, exactly like
    /// `limitcaller::rate_limited_call`'s own
    /// `waits_out_the_rate_limit_window_before_calling` unit test, but
    /// exercised through the *real* `connect.rs` dial call site (a bare TCP
    /// port bound with no listener would prove nothing about wiring — this
    /// dials a real, already-verified relay server end to end).
    #[tokio::test]
    async fn try_connect_with_phonebook_applies_rate_limiting_at_the_real_dial_site() {
        let (server_net, _captured) = start_capturing_relay("testnet-v1.0").await;
        let (addr, _) = server_net.address();

        let window = Duration::from_millis(200);
        let phonebook = Phonebook::new(1, window);
        phonebook.replace_peer_list(std::slice::from_ref(&addr), "default", RELAY_ROLE);

        let connect_config = ConnectConfig {
            genesis_id: "testnet-v1.0".to_string(),
            ..ConnectConfig::default()
        };

        let first = try_connect_with_phonebook(&addr, &connect_config, &phonebook)
            .await
            .expect("first dial succeeds immediately");
        drop(first);

        let start = std::time::Instant::now();
        let second = try_connect_with_phonebook(&addr, &connect_config, &phonebook)
            .await
            .expect("second dial eventually succeeds");
        let elapsed = start.elapsed();
        drop(second);

        assert!(
            elapsed >= window / 2,
            "second dial to a rate-limited address must actually wait, got {elapsed:?}"
        );

        server_net.stop().await;
    }

    /// Real integration test for
    /// [`WebsocketNetwork::check_existing_connections_need_disconnecting`]:
    /// four real outbound connections (to four independent relay servers)
    /// are registered as this network's outgoing peers, the performance
    /// monitor is driven (via its real `notify`/presync-penalty path, not a
    /// mocked field) to a `Stopped` conclusion in which exactly one peer
    /// never delivered a message during presync, and the disconnect
    /// decision must remove precisely that peer from the live peer map.
    #[tokio::test]
    async fn check_existing_connections_need_disconnecting_drops_the_slowest_peer() {
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            network_id: "testnet".to_string(),
            gossip_fanout: 4,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let client_net = Arc::new(WebsocketNetwork::new(config, phonebook));

        // Four independent relay servers so each outbound connection has a
        // distinct remote address (the peer map is keyed by address).
        let mut servers = Vec::new();
        let mut addrs = Vec::new();
        for _ in 0..4 {
            let (server, _captured) = start_capturing_relay("testnet-v1.0").await;
            let (addr, _) = server.address();
            addrs.push(addr);
            servers.push(server);
        }

        for addr in &addrs {
            let connect_config = ConnectConfig {
                genesis_id: "testnet-v1.0".to_string(),
                ..ConnectConfig::default()
            };
            let handle = try_connect(addr, &connect_config)
                .await
                .expect("client connects to relay");
            client_net
                .add_peer(handle, PeerDirection::Outbound, None)
                .await;
        }

        // Drive the monitor's presync-penalty path directly: with 4 peers,
        // `no_msg_peers.len() < len/2` (1 < 2) takes the immediate
        // Stopped-with-penalty branch rather than restarting the timer (see
        // `conn_perf_monitor.rs`'s `notify_presync`). `addrs[3]` never sends
        // a message, so it alone gets the undelivered-message penalty and
        // must be the peer picked for disconnection.
        let silent_peer = addrs[3].clone();
        {
            let mut mon = client_net.conn_perf_monitor.lock().unwrap();
            mon.reset(&addrs, 0);
            mon.notify(&IncomingMessage::new(
                Tag::AgreementVote,
                vec![1],
                addrs[0].clone(),
                1_000_000,
            ));
            mon.notify(&IncomingMessage::new(
                Tag::AgreementVote,
                vec![2],
                addrs[1].clone(),
                2_000_000,
            ));
            mon.notify(&IncomingMessage::new(
                Tag::AgreementVote,
                vec![3],
                addrs[2].clone(),
                3_000_000,
            ));
            // This message both crosses the presync deadline (10s in ns)
            // and is itself from an already-seen peer, so `addrs[3]` is the
            // only address whose `last_msg_time` never advanced.
            mon.notify(&IncomingMessage::new(
                Tag::AgreementVote,
                vec![4],
                addrs[0].clone(),
                10_000_000_000,
            ));
            assert_eq!(
                mon.stage(),
                crate::conn_perf_monitor::PmStage::Stopped,
                "synthetic message sequence must reach Stopped"
            );
        }

        let disconnected = client_net.check_existing_connections_need_disconnecting(4);
        assert!(disconnected, "the slowest peer must be disconnected");

        let peers = client_net.peers.read().await;
        assert!(
            !peers.contains_key(&silent_peer),
            "the peer that never sent a message during presync must be removed"
        );
        assert_eq!(
            peers.len(),
            3,
            "exactly one peer should have been disconnected"
        );
        drop(peers);

        for server in servers {
            server.stop().await;
        }
    }

    /// Below `target_conn_count`, the disconnect check must not drop any
    /// peer for performance reasons — it resets the monitor and falls back
    /// to the clique-resolution check, which (with a freshly-created
    /// network-advance monitor) declines to disconnect.
    #[tokio::test]
    async fn check_existing_connections_need_disconnecting_below_target_does_not_drop_peers() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        // No peers at all, but target is the default gossip fanout (4).
        let disconnected = net.check_existing_connections_need_disconnecting(4);
        assert!(!disconnected);
    }

    /// Issue #1105: `check_existing_connections_need_disconnecting` must
    /// only ever disconnect a peer marked `throttled_outgoing_connection`
    /// — mirroring go's
    /// `if wsPeer.throttledOutgoingConnection && leastPerformingPeer == nil`
    /// loop, which walks `peer_statistics` worst-first and picks the first
    /// *eligible* entry, not necessarily the single worst peer overall.
    ///
    /// `gossip_fanout: 2` on a non-relay node seeds
    /// `throttled_outgoing_connections` to 2 (go:
    /// `wsNetwork.go:704-712`), so only the first two of four connected
    /// peers are eligible. [`ConnectionPerformanceMonitor::force_stopped_with_delays`]
    /// deterministically assigns `addrs[3]` (connected 4th, ineligible) the
    /// single worst delay and `addrs[1]` (connected 2nd, eligible) the
    /// second-worst — a real `notify`/presync run can only ever produce one
    /// nonzero delay per cycle, so it can't build this two-distinct-delays
    /// scenario (see
    /// `check_existing_connections_need_disconnecting_drops_the_slowest_peer`
    /// for that simpler, single-delay case).
    #[tokio::test]
    async fn check_existing_connections_need_disconnecting_skips_ineligible_worst_peer() {
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            network_id: "testnet".to_string(),
            gossip_fanout: 2,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let client_net = Arc::new(WebsocketNetwork::new(config, phonebook));

        let mut servers = Vec::new();
        let mut addrs = Vec::new();
        for _ in 0..4 {
            let (server, _captured) = start_capturing_relay("testnet-v1.0").await;
            let (addr, _) = server.address();
            addrs.push(addr);
            servers.push(server);
        }

        for addr in &addrs {
            let connect_config = ConnectConfig {
                genesis_id: "testnet-v1.0".to_string(),
                ..ConnectConfig::default()
            };
            let handle = try_connect(addr, &connect_config)
                .await
                .expect("client connects to relay");
            client_net
                .add_peer(handle, PeerDirection::Outbound, None)
                .await;
        }

        // Sanity-check the eligibility assignment itself before exercising
        // the disconnect decision: only the first two connections reserved
        // a throttled slot.
        {
            let peers = client_net.peers.read().await;
            assert!(peers[&addrs[0]].throttled_outgoing_connection);
            assert!(peers[&addrs[1]].throttled_outgoing_connection);
            assert!(!peers[&addrs[2]].throttled_outgoing_connection);
            assert!(!peers[&addrs[3]].throttled_outgoing_connection);
        }

        let worst_ineligible = addrs[3].clone();
        let second_worst_eligible = addrs[1].clone();
        {
            let mut mon = client_net.conn_perf_monitor.lock().unwrap();
            mon.force_stopped_with_delays(&[
                (addrs[0].clone(), 0),
                (second_worst_eligible.clone(), 5_000_000_000),
                (addrs[2].clone(), 0),
                (worst_ineligible.clone(), 10_000_000_000),
            ]);
        }

        let disconnected = client_net.check_existing_connections_need_disconnecting(4);
        assert!(
            disconnected,
            "an eligible peer must still be disconnected even though the worst \
             overall peer is ineligible"
        );

        let peers = client_net.peers.read().await;
        assert!(
            !peers.contains_key(&second_worst_eligible),
            "the worst *eligible* peer must be the one disconnected"
        );
        assert!(
            peers.contains_key(&worst_ineligible),
            "the worst peer overall must survive — it never held a throttled slot"
        );
        assert_eq!(peers.len(), 3);
        drop(peers);

        for server in servers {
            server.stop().await;
        }
    }

    /// Issue #1105: when *no* outgoing peer is eligible (none hold a
    /// throttled slot), the performance-based disconnect must not fire at
    /// all — even though a peer with a nonzero delay exists — and must fall
    /// back to [`WebsocketNetwork::check_network_advance_disconnect`]
    /// (which itself declines, since the network-advance monitor was just
    /// created).
    #[tokio::test]
    async fn check_existing_connections_need_disconnecting_drops_nobody_when_none_eligible() {
        let config = WebsocketNetworkConfig {
            genesis_id: "testnet-v1.0".to_string(),
            network_id: "testnet".to_string(),
            gossip_fanout: 0,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let client_net = Arc::new(WebsocketNetwork::new(config, phonebook));

        let mut servers = Vec::new();
        let mut addrs = Vec::new();
        for _ in 0..2 {
            let (server, _captured) = start_capturing_relay("testnet-v1.0").await;
            let (addr, _) = server.address();
            addrs.push(addr);
            servers.push(server);
        }

        for addr in &addrs {
            let connect_config = ConnectConfig {
                genesis_id: "testnet-v1.0".to_string(),
                ..ConnectConfig::default()
            };
            let handle = try_connect(addr, &connect_config)
                .await
                .expect("client connects to relay");
            client_net
                .add_peer(handle, PeerDirection::Outbound, None)
                .await;
        }

        {
            let peers = client_net.peers.read().await;
            assert!(
                !peers[&addrs[0]].throttled_outgoing_connection,
                "gossip_fanout: 0 must seed zero throttled slots"
            );
            assert!(!peers[&addrs[1]].throttled_outgoing_connection);
        }

        {
            let mut mon = client_net.conn_perf_monitor.lock().unwrap();
            mon.force_stopped_with_delays(&[
                (addrs[0].clone(), 10_000_000_000),
                (addrs[1].clone(), 0),
            ]);
        }

        let disconnected = client_net.check_existing_connections_need_disconnecting(2);
        assert!(
            !disconnected,
            "no peer is eligible, so nothing should be disconnected"
        );

        let peers = client_net.peers.read().await;
        assert_eq!(peers.len(), 2, "both peers must remain connected");
        drop(peers);

        for server in servers {
            server.stop().await;
        }
    }

    /// Issue #1105: the throttled-slot counter itself must mirror go's
    /// decrement-and-restore-on-failure semantics
    /// (`wn.throttledOutgoingConnections.Add(int32(-1)) >= 0`) — reserving
    /// beyond capacity must not leave the counter permanently negative, and
    /// releasing a slot (peer close) must give it back so a later
    /// connection can reserve it again.
    #[test]
    fn throttled_slot_reserve_and_release_mirrors_go_counter_semantics() {
        let counter = AtomicI32::new(1);

        // First reservation succeeds (counter: 1 -> 0).
        assert!(reserve_throttled_slot(&counter));
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        // Second reservation fails and restores the counter rather than
        // leaving it at -1 (go: `wn.throttledOutgoingConnections.Add(1)` in
        // the `else` branch).
        assert!(!reserve_throttled_slot(&counter));
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        // Releasing a slot that *was* held gives it back.
        release_throttled_slot_if_held(&counter, true);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Releasing a slot that was *not* held is a no-op.
        release_throttled_slot_if_held(&counter, false);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// Issue #1316: `DisableOutgoingConnectionThrottling` overrides the
    /// `gossip_fanout`/relay-mode seed to `0` regardless of its value,
    /// exactly like go's `Start()` (`network/wsNetwork.go:711-713`):
    /// `if wn.config.DisableOutgoingConnectionThrottling {
    /// wn.throttledOutgoingConnections.Store(0) }`, applied *after* the
    /// seeding this same test area's
    /// `throttled_outgoing_connections_seeded_from_gossip_fanout_and_relay_mode`
    /// pins.
    #[test]
    fn disable_outgoing_connection_throttling_forces_seed_to_zero() {
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));

        let non_relay = WebsocketNetwork::new(
            WebsocketNetworkConfig {
                gossip_fanout: 5,
                relay_messages: false,
                net_address: None,
                disable_outgoing_connection_throttling: true,
                ..Default::default()
            },
            Arc::clone(&phonebook),
        );
        assert_eq!(
            non_relay
                .throttled_outgoing_connections
                .load(Ordering::SeqCst),
            0,
            "DisableOutgoingConnectionThrottling must force the seed to 0 even though \
             gossip_fanout alone would seed 5"
        );

        let relay = WebsocketNetwork::new(
            WebsocketNetworkConfig {
                gossip_fanout: 5,
                relay_messages: true,
                net_address: Some("127.0.0.1:0".to_string()),
                disable_outgoing_connection_throttling: true,
                ..Default::default()
            },
            Arc::clone(&phonebook),
        );
        assert_eq!(
            relay.throttled_outgoing_connections.load(Ordering::SeqCst),
            0,
            "DisableOutgoingConnectionThrottling must force the seed to 0 for relays too"
        );
    }

    /// Issue #1105: `throttled_outgoing_connections` must be seeded from
    /// `gossip_fanout` and relay-mode exactly like go's `Start()`
    /// (`network/wsNetwork.go:704-712`): half of `gossip_fanout` (rounded
    /// down) for a relay, all of it for a non-relay.
    #[test]
    fn throttled_outgoing_connections_seeded_from_gossip_fanout_and_relay_mode() {
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));

        let non_relay = WebsocketNetwork::new(
            WebsocketNetworkConfig {
                gossip_fanout: 5,
                relay_messages: false,
                net_address: None,
                ..Default::default()
            },
            Arc::clone(&phonebook),
        );
        assert_eq!(
            non_relay
                .throttled_outgoing_connections
                .load(Ordering::SeqCst),
            5
        );

        let relay = WebsocketNetwork::new(
            WebsocketNetworkConfig {
                gossip_fanout: 5,
                relay_messages: true,
                net_address: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            Arc::clone(&phonebook),
        );
        assert_eq!(
            relay.throttled_outgoing_connections.load(Ordering::SeqCst),
            2,
            "relay seeding must floor-divide gossip_fanout by 2"
        );
    }

    #[test]
    fn check_network_advance_disconnect_no_peers_returns_false() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        let disconnected = net.check_network_advance_disconnect(&[], Duration::from_millis(1));
        assert!(!disconnected);
    }

    #[test]
    fn check_network_advance_disconnect_within_interval_does_not_disconnect() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        let peer: Arc<dyn Peer> = Arc::new(PeerRef {
            addr: "10.0.0.1:4160".to_string(),
        });
        // Freshly constructed NetworkAdvanceMonitor's clock starts "now", so
        // a generous interval must decline to disconnect.
        let disconnected = net.check_network_advance_disconnect(&[peer], Duration::from_secs(300));
        assert!(!disconnected);
    }

    #[tokio::test]
    async fn check_network_advance_disconnect_disconnects_after_interval_elapses() {
        let net = WebsocketNetwork::with_defaults("test", "test");
        let peer_addr = "10.0.0.1:4160".to_string();
        let peer: Arc<dyn Peer> = Arc::new(PeerRef {
            addr: peer_addr.clone(),
        });

        tokio::time::sleep(Duration::from_millis(5)).await;

        let disconnected = net.check_network_advance_disconnect(
            std::slice::from_ref(&peer),
            Duration::from_millis(1),
        );
        assert!(
            disconnected,
            "a tiny interval that has already elapsed must trigger clique resolution"
        );

        // Mirrors go's `cc.net.OnNetworkAdvance()` at the end of the real
        // function — the watchdog clock must be reset so an immediate
        // second call (interval not yet elapsed again) does not repeat.
        let disconnected_again = net.check_network_advance_disconnect(
            std::slice::from_ref(&peer),
            Duration::from_millis(1),
        );
        assert!(!disconnected_again);
    }

    // -----------------------------------------------------------------------
    // Phase 17 (issue #830) missing-test sweep, batch 4 — network/p2p parity.
    // -----------------------------------------------------------------------

    /// Go: `TestIdentityChallengeNoErrorWhenNotParticipating`
    /// (`network/netidentity_test.go`) — a scheme built with a blank
    /// deduplication name is a permanent no-op: attaching/verifying a
    /// challenge, or handling a malformed response, never errors and never
    /// produces a value.
    ///
    /// algod-rust has no separate "scheme" object with an enable/disable
    /// flag — `ConnectConfig::our_identity_key: Option<SigningKey>` plays
    /// that role structurally: `None` means "not participating" and the
    /// entire netidentity challenge/response/verify exchange
    /// (`connect.rs::try_connect_inner`, steps 2 and 10) is skipped
    /// unconditionally. This is the behavioral port of go's invariant: a
    /// client with no identity key must connect to a real relay (which,
    /// same as go's default `wsNetwork`, does not require identity
    /// participation either) without ever raising an identity-related
    /// error, and the resulting peer must report no identity exchange.
    #[tokio::test]
    async fn client_without_identity_key_connects_without_error() {
        let (server_net, _captured) = start_capturing_relay("testnet-v1.0").await;
        let (addr, _) = server_net.address();

        let connect_config = ConnectConfig {
            genesis_id: "testnet-v1.0".to_string(),
            our_identity_key: None,
            ..ConnectConfig::default()
        };

        let handle = try_connect(&addr, &connect_config)
            .await
            .expect("connecting without an identity key must never error");
        assert!(
            !handle.identity_verified(),
            "no identity key means no identity exchange took place"
        );

        handle.close();
        server_net.stop().await;
    }

    /// Go: `TestPeeringSenderIdentityChallengeOnly` (`network/wsNetwork_test.go:1598`)
    /// — "if only the Sender uses Identity, no identity exchange happens in
    /// the connection." go's test gives the dialing side (`netA`) a
    /// `PublicAddress` (enabling identity) while the accepting side (`netB`)
    /// has none, connects them, and asserts neither side's identity map was
    /// ever populated (`getSetCount() == 0` for both).
    ///
    /// This crate's relay/accept path (`WebsocketNetwork::start_relay_server`,
    /// exercised here via `start_capturing_relay`) has no server-side
    /// identity wiring at all (see `client_without_identity_key_connects_without_error`'s
    /// doc comment above and issue #1133's `DualGossipNode` follow-up note in
    /// `docs/phase17/parity_network.md`), so it structurally never responds
    /// to an identity challenge header — the direct counterpart of go's
    /// "receiver does not participate" half. Driving a real dial with
    /// `our_identity_key: Some(..)` (the "sender-only" half) against that
    /// real relay and asserting `identity_verified() == false` reproduces
    /// go's actual observable outcome: a client that is willing to do
    /// identity but whose peer never answers ends up with no identity
    /// exchange, exactly as go's `getSetCount() == 0` proves no identity was
    /// ever recorded.
    #[tokio::test]
    async fn sender_only_identity_key_yields_no_identity_exchange() {
        let (server_net, _captured) = start_capturing_relay("testnet-v1.0").await;
        let (addr, _) = server_net.address();

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let connect_config = ConnectConfig {
            genesis_id: "testnet-v1.0".to_string(),
            our_identity_key: Some(signing_key),
            ..ConnectConfig::default()
        };

        let handle = try_connect(&addr, &connect_config)
            .await
            .expect("a relay that ignores the identity challenge must not fail the handshake");
        assert!(
            !handle.identity_verified(),
            "sender-only identity (relay never answers the challenge) must not yield a \
             verified identity, mirroring go's getSetCount() == 0 on both sides"
        );
        assert!(handle.identity().is_none());

        handle.close();
        server_net.stop().await;
    }

    /// Go: `TestMaxHeaderSize` (`network/wsNetwork_test.go:4077`) —
    /// `ConnectConfig::max_header_bytes` caps the HTTP upgrade response
    /// header size on the outbound dial (issue #1158). Ported as three
    /// phases against a real relay, exactly like go's test: the default cap
    /// connects fine, a too-small cap rejects the same connection, and `0`
    /// disables the check again.
    #[tokio::test]
    async fn max_header_size_caps_outbound_dial_header_bytes() {
        let (server_net, _captured) = start_capturing_relay("testnet-v1.0").await;
        let (addr, _) = server_net.address();

        // Phase 1: the default cap (matching go's real default) connects
        // normally — a real relay's handshake response headers are far
        // smaller than 4096 bytes.
        let default_config = ConnectConfig {
            genesis_id: "testnet-v1.0".to_string(),
            ..ConnectConfig::default()
        };
        let handle = try_connect(&addr, &default_config)
            .await
            .expect("default max_header_bytes must not reject a normal handshake");
        handle.close();

        // Phase 2: a cap far smaller than any real handshake response's
        // headers must reject the connection (go: `netA.wsMaxHeaderBytes =
        // 128`).
        // Even a bare `HTTP/1.1 101 Switching Protocols\r\n` status line
        // alone is 35 bytes, well before any of the mandatory `Upgrade`/
        // `Connection`/`Sec-WebSocket-Accept` headers or algod-rust's own
        // Algorand handshake headers (genesis ID, node random, peer
        // features, ...) are even counted — so 16 bytes is well below what
        // any real relay response can possibly fit under, unlike go's test
        // (128 bytes), which only needs to beat gorilla's default response
        // shape.
        let tiny_cap_config = ConnectConfig {
            genesis_id: "testnet-v1.0".to_string(),
            max_header_bytes: 16,
            ..ConnectConfig::default()
        };
        let result = try_connect(&addr, &tiny_cap_config).await;
        match result {
            Err(crate::errors::WsConnectError::HeaderTooLarge { max: 16 }) => {}
            Err(e) => panic!("expected HeaderTooLarge {{ max: 16 }}, got a different error: {e}"),
            Ok(handle) => {
                handle.close();
                panic!(
                    "a 16-byte cap must reject a real relay's handshake headers, but it connected"
                )
            }
        }

        // Phase 3: `max_header_bytes = 0` disables the check again (go:
        // `netA.wsMaxHeaderBytes = 0`), so the same relay connects fine.
        let disabled_config = ConnectConfig {
            genesis_id: "testnet-v1.0".to_string(),
            max_header_bytes: 0,
            ..ConnectConfig::default()
        };
        let handle = try_connect(&addr, &disabled_config)
            .await
            .expect("max_header_bytes = 0 must disable the cap");
        handle.close();

        server_net.stop().await;
    }

    /// Go: `TestGetPeersFiltersSelf` (`network/p2pNetwork_test.go`) — a
    /// node's own address, even if present in its peer store, must never
    /// come back out of `GetPeers`.
    ///
    /// algod-rust's `WebsocketNetwork` enforces this earlier and more
    /// strongly than go's phonebook-level filter: a connection whose
    /// advertised `NodeRandom` matches our own is rejected outright at the
    /// handshake (`WsConnectError::SelfLoop`, HTTP 508 — already unit
    /// tested for the header-validation layer by
    /// `validate_incoming_self_loop_rejected`), so a self-dial can never
    /// reach the point of being registered as a peer in the first place.
    /// This test proves that end-to-end: dialing a relay using that same
    /// relay's own `node_random` is rejected, and `get_peers` for every
    /// connected-peer option stays empty afterward — self can never appear
    /// in the result, matching go's guarantee via a different mechanism.
    #[tokio::test]
    async fn self_dial_is_rejected_and_never_appears_in_get_peers() {
        let (server_net, _captured) = start_capturing_relay("testnet-v1.0").await;
        let (addr, _) = server_net.address();

        let self_node_random: u64 = server_net
            .node_random()
            .parse()
            .expect("node_random is always a valid u64 string");

        let connect_config = ConnectConfig {
            genesis_id: "testnet-v1.0".to_string(),
            node_random: self_node_random,
            ..ConnectConfig::default()
        };

        let result = try_connect(&addr, &connect_config).await;
        assert!(
            matches!(result, Err(crate::errors::WsConnectError::SelfLoop)),
            "a self-dial (matching NodeRandom) must be rejected as a loop, got: {:?}",
            result.is_ok()
        );

        for option in [PeerOption::PeersConnectedIn, PeerOption::PeersConnectedOut] {
            let peers = server_net.get_peers(&[option]);
            assert!(
                peers.is_empty(),
                "self must never appear among {option:?}, got {} entries",
                peers.len()
            );
        }

        server_net.stop().await;
    }

    /// Go: `TestNumOutgoingPending` (`network/wsNetwork_test.go`) — the
    /// `tryConnectAddrs` reservation map dedupes concurrent outbound dial
    /// attempts to the same address: a second reservation for an address
    /// already being dialed fails, and `numOutgoingPending()` only counts
    /// distinct in-flight addresses.
    ///
    /// algod-rust's `mesh_connect` (`ws_network.rs`) uses the equivalent
    /// `connecting: Mutex<HashSet<String>>` guard directly (see the "Skip
    /// if already connected or connecting" check just above where
    /// addresses are reserved for dialing) rather than exposing a separate
    /// reserve/release API, so this test exercises the underlying
    /// `HashSet` invariant it relies on: inserting the same address twice
    /// is a no-op (the second `insert` call reports "already present"),
    /// and removing it makes room for a fresh reservation again — the same
    /// dedup guarantee go's paired map entries provide.
    #[tokio::test]
    async fn connecting_set_dedupes_pending_outgoing_reservations() {
        let net = WebsocketNetwork::with_defaults("test", "test");

        {
            let mut connecting = net.connecting.lock().await;
            assert!(connecting.is_empty());

            assert!(
                connecting.insert("127.0.0.1:4161".to_string()),
                "first reservation for an address must succeed"
            );
            assert_eq!(connecting.len(), 1);

            assert!(
                connecting.insert("127.0.0.1:4162".to_string()),
                "reservation for a distinct address must succeed independently"
            );
            assert_eq!(connecting.len(), 2);

            // Re-reserving an address already being dialed must fail --
            // `HashSet::insert` returns false without inserting a duplicate.
            assert!(
                !connecting.insert("127.0.0.1:4161".to_string()),
                "re-reserving an address already being dialed must not succeed"
            );
            assert_eq!(
                connecting.len(),
                2,
                "count must not change after a failed reservation"
            );
        }

        {
            let mut connecting = net.connecting.lock().await;
            assert!(connecting.remove("127.0.0.1:4161"));
            assert_eq!(connecting.len(), 1);
            assert!(connecting.remove("127.0.0.1:4162"));
            assert!(
                connecting.is_empty(),
                "map must be empty after all releases"
            );
        }
    }

    /// Go: `TestWebsocketNetworkStartZeroIncomingDoesNotListen`
    /// (`network/wsNetwork_test.go:287`) — with `IncomingConnectionsLimit
    /// == 0`, go's `wsNetwork.Start()` never binds a TCP listener at all
    /// (`netA.listener` stays `nil`, `Address()` reports `connected ==
    /// false`).
    ///
    /// Previously (issue #1155) `start_relay_server` bound the listener
    /// whenever `net_address` was set, independent of
    /// `incoming_connections_limit`, so a node configured for zero
    /// incoming connections still opened and reported a listening socket
    /// — a real divergence from go's exact behavior. Now the listener
    /// bind is additionally gated on `incoming_connections_limit != 0`,
    /// matching `wn.relayMessages && wn.config.IncomingConnectionsLimit !=
    /// 0` (`network/wsNetwork.go:692`).
    #[tokio::test]
    async fn zero_incoming_connections_limit_does_not_bind_listener() {
        let config = WebsocketNetworkConfig {
            genesis_id: "test".to_string(),
            network_id: "testnet".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            incoming_connections_limit: 0,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let net = Arc::new(WebsocketNetwork::new(config, phonebook));
        net.start_relay_server().await.expect("relay server starts");

        // Matching go: no listener bound, so `Address()` reports
        // not-connected.
        let (_addr, connected) = net.address();
        assert!(
            !connected,
            "algod-rust must not bind a listener when incoming_connections_limit == 0, matching go"
        );

        net.stop().await;
    }

    /// Companion to the test above (issue #1155 acceptance criteria):
    /// `incoming_connections_limit == 0` gates the *listener* only —
    /// outbound dialing must still work normally. `start_relay_server`
    /// returning early doesn't touch `mesh_connect`/
    /// `request_connect_outgoing`, which are the outbound-dial path and
    /// don't call `start_relay_server` at all; this test just pins that a
    /// zero-limit, listen-configured network still reports itself ready to
    /// dial out (no listener needed for outbound connections) and that
    /// `net_address` alone doesn't get cleared by the early return.
    #[tokio::test]
    async fn zero_incoming_connections_limit_leaves_outbound_dialing_unaffected() {
        let config = WebsocketNetworkConfig {
            genesis_id: "test".to_string(),
            network_id: "testnet".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            incoming_connections_limit: 0,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        let net = Arc::new(WebsocketNetwork::new(config, phonebook));
        net.start_relay_server().await.expect("relay server starts");

        // No listener bound...
        let (_addr, connected) = net.address();
        assert!(!connected);

        // ...but the config driving outbound dialing (mesh_connect) is
        // untouched: relay_messages / incoming_connections_limit are still
        // exactly what the caller configured, and the network is not in
        // any error/stopped state that would block `mesh_connect`.
        assert!(net.effective_relay_messages());
        assert_eq!(net.config.incoming_connections_limit, 0);

        net.stop().await;
    }

    // -----------------------------------------------------------------------
    // wantTXGossip role-transition narrowing (issue #1156)
    //
    // Ports go's TestWebsocketNetworkTXMessageOfInterestForceTx/_NPN/_PN
    // (network/wsNetwork_test.go:3286,3369,3474). netA is a plain listening
    // node that broadcasts a handful of AV/PP/TX/VB messages; netB is the
    // dialing side under test, whose TX-gossip subscription this issue's fix
    // narrows/widens based on role. Verified via netB's *own* received
    // message counts, mirroring go's approach of counting what actually
    // arrived rather than inspecting internal filter state directly.
    // -----------------------------------------------------------------------
    mod want_tx_gossip_tests {
        use super::*;
        use crate::connect::try_connect_with_phonebook;
        use crate::handler::MessageHandler;
        use crate::message::IncomingMessage;
        use std::collections::HashMap as StdHashMap;
        use std::sync::atomic::AtomicU32;
        use std::sync::Mutex as StdMutex;

        /// Counts arrivals per tag and notifies `done` once `expected_total`
        /// messages have arrived (any tag) — mirrors go's `msgCounters` map
        /// + `messageArriveWg` pairing.
        struct CountingHandler {
            counts: Arc<StdMutex<StdHashMap<Tag, u32>>>,
            remaining: Arc<AtomicU32>,
            done: Arc<tokio::sync::Notify>,
        }

        #[async_trait]
        impl MessageHandler for CountingHandler {
            async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
                {
                    let mut counts = self.counts.lock().expect("counts lock poisoned");
                    *counts.entry(msg.tag).or_insert(0) += 1;
                }
                if self.remaining.fetch_sub(1, Ordering::SeqCst) == 1 {
                    self.done.notify_one();
                }
                OutgoingMessage {
                    action: ForwardingPolicy::Ignore,
                    tag: msg.tag,
                    payload: Vec::new(),
                    topics: None,
                }
            }
        }

        /// Starts a plain listening `WebsocketNetwork` that netB will dial
        /// into — matches go's `netA := makeTestWebsocketNode(t)`.
        async fn start_net_a(genesis_id: &str) -> Arc<WebsocketNetwork> {
            let config = WebsocketNetworkConfig {
                genesis_id: genesis_id.to_string(),
                network_id: "testnet".to_string(),
                net_address: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            };
            let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
            let net = Arc::new(WebsocketNetwork::new(config, phonebook));
            net.start_relay_server()
                .await
                .expect("netA relay server starts");
            net
        }

        /// Connects `net_b` out to `addr_a` and registers the resulting
        /// peer in `net_b`'s own peer table — the dialing side of go's
        /// `netB.Start()` (whose mesh thread would otherwise perform this
        /// dial), done explicitly so the test doesn't depend on mesh-thread
        /// timing.
        async fn connect_b_to_a(net_b: &Arc<WebsocketNetwork>, addr_a: &str) {
            let connect_config = ConnectConfig {
                genesis_id: net_b.config.genesis_id.clone(),
                ..ConnectConfig::default()
            };
            let handle = try_connect_with_phonebook(addr_a, &connect_config, net_b.phonebook())
                .await
                .expect("netB connects to netA");
            net_b.add_peer(handle, PeerDirection::Outbound, None).await;
        }

        /// Registers a [`CountingHandler`] on `net` for every default
        /// send-message tag (mirrors go's
        /// `for tag := range defaultSendMessageTags { ... }`), returning
        /// the shared counts map and a `Notify` fired once
        /// `expected_total` messages have arrived.
        fn register_counting_handlers(
            net: &Arc<WebsocketNetwork>,
            expected_total: u32,
        ) -> (
            Arc<StdMutex<StdHashMap<Tag, u32>>>,
            Arc<tokio::sync::Notify>,
        ) {
            let counts = Arc::new(StdMutex::new(StdHashMap::new()));
            let done = Arc::new(tokio::sync::Notify::new());
            let remaining = Arc::new(AtomicU32::new(expected_total));
            let dispatch: Vec<TaggedMessageHandler> = default_send_message_tags()
                .into_iter()
                .map(|tag| TaggedMessageHandler {
                    tag,
                    handler: Arc::new(CountingHandler {
                        counts: Arc::clone(&counts),
                        remaining: Arc::clone(&remaining),
                        done: Arc::clone(&done),
                    }),
                })
                .collect();
            net.register_handlers(dispatch);
            (counts, done)
        }

        /// Notifies once, on the first message it handles — used as a
        /// one-shot arrival fence.
        struct NotifyHandler {
            notify: Arc<tokio::sync::Notify>,
        }

        #[async_trait]
        impl MessageHandler for NotifyHandler {
            async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
                self.notify.notify_one();
                OutgoingMessage {
                    action: ForwardingPolicy::Ignore,
                    tag: msg.tag,
                    payload: Vec::new(),
                    topics: None,
                }
            }
        }

        /// Fences on netA having actually applied netB's latest
        /// message-of-interest update, mirroring go's own synchronization
        /// idiom in these tests (`netB.Broadcast(AgreementVoteTag, ...)`
        /// then `messageFilterArriveWg.Wait()`, `network/wsNetwork_test.go`):
        /// `register_message_interest`/`deregister_message_interest` push
        /// the `MI` update on netB's *high-priority* send queue, and the
        /// write loop always drains high-priority before bulk — so an
        /// `AgreementVote` marker broadcast queued (bulk) *after* the MI
        /// update is guaranteed to leave netB, and be processed by netA's
        /// single-threaded read loop, strictly after that update. Once
        /// netA's handler observes the marker, its per-peer
        /// `send_message_tags` for netB is already up to date.
        async fn wait_for_moi_propagation(
            net_a: &Arc<WebsocketNetwork>,
            net_b: &Arc<WebsocketNetwork>,
        ) {
            let notify = Arc::new(tokio::sync::Notify::new());
            net_a.register_handlers(vec![TaggedMessageHandler {
                tag: Tag::AgreementVote,
                handler: Arc::new(NotifyHandler {
                    notify: Arc::clone(&notify),
                }),
            }]);
            net_b
                .broadcast(Tag::AgreementVote, vec![9, 9, 9, 9, 9], false, None)
                .await
                .expect("netB can broadcast the fence marker");
            tokio::time::timeout(Duration::from_secs(5), notify.notified())
                .await
                .expect("netA observed the MOI-fence marker");
        }

        /// Broadcasts `tag` from `net_a` and yields briefly afterward.
        ///
        /// This crate's inbound read loop drains incoming frames into a
        /// small (10-slot, [`crate::ws_peer::MSGS_IN_READ_BUFFER_PER_PEER`]
        /// is private but this mirrors its size) per-peer channel and
        /// drops on backpressure rather than blocking — a deliberate
        /// bounded-buffer choice, not a bug this issue is about. A tight
        /// loop of 20 unpaced broadcasts can fill that buffer faster than
        /// the consumer task drains it; go's equivalent test does not hit
        /// this because go's channel is far larger. Pacing sends keeps
        /// this test about `wantTXGossip` narrowing, not about buffer
        /// sizing.
        async fn broadcast_paced(net_a: &Arc<WebsocketNetwork>, tag: Tag) {
            net_a
                .broadcast(tag, vec![0, 1, 2, 3, 4], false, None)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        /// Waits (bounded) for `net`'s peer count to reach at least
        /// `expected` — `handle_gossip_websocket` registers an accepted
        /// inbound peer asynchronously (spawned off the axum handshake
        /// task), so a broadcast issued right after the dialing side's
        /// `try_connect` returns can otherwise race ahead of netA's own
        /// peer-table update.
        async fn wait_for_peer_count(net: &Arc<WebsocketNetwork>, expected: usize) {
            for _ in 0..100 {
                if net.peer_count().await >= expected {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("peer count did not reach {expected} in time");
        }

        /// Waits (bounded) for `net`'s `want_tx_gossip()` to reach
        /// `expected`, mirroring go's 100x10ms poll loop in the NPN/PN
        /// tests.
        async fn wait_for_want_tx_gossip(net: &Arc<WebsocketNetwork>, expected: u8) {
            for _ in 0..100 {
                if net.want_tx_gossip() == expected {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!(
                "want_tx_gossip did not reach {expected} in time (last seen {})",
                net.want_tx_gossip()
            );
        }

        /// A [`NodeInfo`] stub that always reports participating — mirrors
        /// go's `participatingNodeInfo`.
        struct ParticipatingNodeInfo;
        impl NodeInfo for ParticipatingNodeInfo {
            fn is_participating(&self) -> bool {
                true
            }
        }

        /// go: `TestWebsocketNetworkTXMessageOfInterestForceTx`
        /// (`network/wsNetwork_test.go:3286`). `ForceFetchTransactions`
        /// pins `wantTXGossip` to "yes" at startup and disables the
        /// refresh loop entirely — netB must receive every broadcast tag,
        /// TX included, and `OnNetworkAdvance` must not change that.
        #[tokio::test]
        async fn force_fetch_transactions_always_receives_tx() {
            let net_a = start_net_a("testnet-v1.0").await;
            let (addr_a, listening) = net_a.address();
            assert!(listening);

            let config_b = WebsocketNetworkConfig {
                genesis_id: "testnet-v1.0".to_string(),
                network_id: "testnet".to_string(),
                force_fetch_transactions: true,
                ..Default::default()
            };
            let phonebook_b = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
            let net_b = Arc::new(WebsocketNetwork::new(config_b, phonebook_b));
            net_b.start_arc().await.expect("netB starts");
            assert_eq!(net_b.want_tx_gossip(), WANT_TX_GOSSIP_YES);

            connect_b_to_a(&net_b, &addr_a).await;
            wait_for_peer_count(&net_a, 1).await;

            let (counts, done) = register_counting_handlers(&net_b, 5 * 4);

            // OnNetworkAdvance is a no-op for a force-fetch node (the
            // refresh gate excludes it) — call it anyway to prove that.
            net_b.on_network_advance();
            assert_eq!(net_b.want_tx_gossip(), WANT_TX_GOSSIP_YES);

            for _ in 0..5 {
                broadcast_paced(&net_a, Tag::AgreementVote).await;
                broadcast_paced(&net_a, Tag::Transaction).await;
                broadcast_paced(&net_a, Tag::ProposalPayload).await;
                broadcast_paced(&net_a, Tag::VoteBundle).await;
            }

            tokio::time::timeout(Duration::from_secs(5), done.notified())
                .await
                .expect("all 20 messages arrived at netB");

            {
                let counts = counts.lock().expect("counts lock poisoned");
                assert_eq!(counts.len(), 4, "{counts:?}");
                for count in counts.values() {
                    assert_eq!(*count, 5);
                }
            }

            net_a.stop().await;
            net_b.stop().await;
        }

        /// go: `TestWebsocketNetworkTXMessageOfInterestRelay`
        /// (`network/wsNetwork_test.go:3202`). netB is a non-listening
        /// node with `ForceRelayMessages: true` (go's `bConfig.NetAddress =
        /// ""`, `bConfig.ForceRelayMessages = true`) — `relay_messages`
        /// alone (independent of `IsListenServer()`/`net_address`) must
        /// seed `wantTXGossip` to "yes" at startup and `OnNetworkAdvance`
        /// must not narrow it, so netB receives every broadcast tag,
        /// TX included. Closes the Phase 17 parity gap: previously only
        /// `want_tx_gossip_seeded_yes_for_relay` (a unit-level, no-sockets
        /// check of the seed value alone) existed for the relay case —
        /// this proves it end-to-end against live delivery counts exactly
        /// as go's test does.
        #[tokio::test]
        async fn force_relay_messages_always_receives_tx() {
            let net_a = start_net_a("testnet-v1.0").await;
            let (addr_a, listening) = net_a.address();
            assert!(listening);

            let config_b = WebsocketNetworkConfig {
                genesis_id: "testnet-v1.0".to_string(),
                network_id: "testnet".to_string(),
                net_address: None,
                relay_messages: true,
                ..Default::default()
            };
            let phonebook_b = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
            let net_b = Arc::new(WebsocketNetwork::new(config_b, phonebook_b));
            net_b.start_arc().await.expect("netB starts");
            assert!(net_b.effective_relay_messages());
            assert_eq!(net_b.want_tx_gossip(), WANT_TX_GOSSIP_YES);

            connect_b_to_a(&net_b, &addr_a).await;
            wait_for_peer_count(&net_a, 1).await;

            let (counts, done) = register_counting_handlers(&net_b, 5 * 4);

            // OnNetworkAdvance must not narrow a force-relay node's TX
            // interest away — mirrors go's assertion that A->B still
            // follows MOI with all 4 tags after this call.
            net_b.on_network_advance();
            assert_eq!(net_b.want_tx_gossip(), WANT_TX_GOSSIP_YES);

            for _ in 0..5 {
                broadcast_paced(&net_a, Tag::AgreementVote).await;
                broadcast_paced(&net_a, Tag::Transaction).await;
                broadcast_paced(&net_a, Tag::ProposalPayload).await;
                broadcast_paced(&net_a, Tag::VoteBundle).await;
            }

            tokio::time::timeout(Duration::from_secs(5), done.notified())
                .await
                .expect("all 20 messages arrived at netB");

            {
                let counts = counts.lock().expect("counts lock poisoned");
                assert_eq!(counts.len(), 4, "{counts:?}");
                for count in counts.values() {
                    assert_eq!(*count, 5);
                }
            }

            net_a.stop().await;
            net_b.stop().await;
        }

        /// go: `TestWebsocketNetworkTXMessageOfInterestNPN`
        /// (`network/wsNetwork_test.go:3369`). A plain non-relay,
        /// non-force-fetch, non-participating node must deregister TX
        /// interest once `OnNetworkAdvance` triggers the first refresh —
        /// `TX` broadcasts from netA must be dropped, every other default
        /// tag must still arrive.
        #[tokio::test]
        async fn npn_narrows_and_drops_tx() {
            let net_a = start_net_a("testnet-v1.0").await;
            let (addr_a, listening) = net_a.address();
            assert!(listening);

            let config_b = WebsocketNetworkConfig {
                genesis_id: "testnet-v1.0".to_string(),
                network_id: "testnet".to_string(),
                ..Default::default()
            };
            let phonebook_b = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
            let net_b = Arc::new(WebsocketNetwork::new(config_b, phonebook_b));
            net_b.start_arc().await.expect("netB starts");
            assert!(!net_b.effective_relay_messages());
            assert_eq!(net_b.want_tx_gossip(), WANT_TX_GOSSIP_UNK);

            connect_b_to_a(&net_b, &addr_a).await;
            wait_for_peer_count(&net_a, 1).await;

            let (counts, done) = register_counting_handlers(&net_b, 5 * 3);

            net_b.on_network_advance();
            wait_for_want_tx_gossip(&net_b, WANT_TX_GOSSIP_NO).await;
            wait_for_moi_propagation(&net_a, &net_b).await;

            for _ in 0..5 {
                broadcast_paced(&net_a, Tag::AgreementVote).await;
                broadcast_paced(&net_a, Tag::Transaction).await; // dropped
                broadcast_paced(&net_a, Tag::ProposalPayload).await;
                broadcast_paced(&net_a, Tag::VoteBundle).await;
            }

            tokio::time::timeout(Duration::from_secs(5), done.notified())
                .await
                .expect("all 15 non-TX messages arrived at netB");

            // Give any stray TX delivery a moment to show up before asserting.
            tokio::time::sleep(Duration::from_millis(100)).await;

            {
                let counts = counts.lock().expect("counts lock poisoned");
                assert_eq!(counts.len(), 3, "{counts:?}");
                assert!(
                    !counts.contains_key(&Tag::Transaction),
                    "TX must be dropped: {counts:?}"
                );
                for count in counts.values() {
                    assert_eq!(*count, 5);
                }
            }

            net_a.stop().await;
            net_b.stop().await;
        }

        /// go: `TestWebsocketNetworkTXMessageOfInterestPN`
        /// (`network/wsNetwork_test.go:3474`). A non-relay,
        /// non-force-fetch node whose [`NodeInfo`] reports participating
        /// must (re)register TX interest on the first refresh —
        /// `wantTXGossip` transitions Unk -> Yes and every default tag,
        /// TX included, arrives.
        #[tokio::test]
        async fn pn_participating_receives_tx() {
            let net_a = start_net_a("testnet-v1.0").await;
            let (addr_a, listening) = net_a.address();
            assert!(listening);

            let config_b = WebsocketNetworkConfig {
                genesis_id: "testnet-v1.0".to_string(),
                network_id: "testnet".to_string(),
                ..Default::default()
            };
            let phonebook_b = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
            let net_b = Arc::new(WebsocketNetwork::new(config_b, phonebook_b));
            net_b.set_node_info(Arc::new(ParticipatingNodeInfo));
            net_b.start_arc().await.expect("netB starts");
            assert!(!net_b.effective_relay_messages());
            assert_eq!(net_b.want_tx_gossip(), WANT_TX_GOSSIP_UNK);

            connect_b_to_a(&net_b, &addr_a).await;
            wait_for_peer_count(&net_a, 1).await;

            let (counts, done) = register_counting_handlers(&net_b, 5 * 4);

            net_b.on_network_advance();
            wait_for_want_tx_gossip(&net_b, WANT_TX_GOSSIP_YES).await;
            wait_for_moi_propagation(&net_a, &net_b).await;

            for _ in 0..5 {
                broadcast_paced(&net_a, Tag::AgreementVote).await;
                broadcast_paced(&net_a, Tag::Transaction).await;
                broadcast_paced(&net_a, Tag::ProposalPayload).await;
                broadcast_paced(&net_a, Tag::VoteBundle).await;
            }

            tokio::time::timeout(Duration::from_secs(5), done.notified())
                .await
                .expect("all 20 messages arrived at netB");

            {
                let counts = counts.lock().expect("counts lock poisoned");
                assert_eq!(counts.len(), 4, "{counts:?}");
                for count in counts.values() {
                    assert_eq!(*count, 5);
                }
            }

            net_a.stop().await;
            net_b.stop().await;
        }

        // -------------------------------------------------------------
        // Startup seeding / NodeInfo plumbing (unit-level, no sockets)
        // -------------------------------------------------------------

        #[test]
        fn want_tx_gossip_seeded_yes_for_relay() {
            let config = WebsocketNetworkConfig {
                genesis_id: "test".to_string(),
                net_address: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            };
            let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
            let net = WebsocketNetwork::new(config, phonebook);
            assert_eq!(net.want_tx_gossip(), WANT_TX_GOSSIP_YES);
        }

        #[test]
        fn want_tx_gossip_seeded_yes_for_force_fetch_transactions() {
            let config = WebsocketNetworkConfig {
                genesis_id: "test".to_string(),
                force_fetch_transactions: true,
                ..Default::default()
            };
            let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
            let net = WebsocketNetwork::new(config, phonebook);
            assert_eq!(net.want_tx_gossip(), WANT_TX_GOSSIP_YES);
        }

        #[test]
        fn want_tx_gossip_seeded_unk_for_plain_non_relay() {
            let config = WebsocketNetworkConfig {
                genesis_id: "test".to_string(),
                ..Default::default()
            };
            let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
            let net = WebsocketNetwork::new(config, phonebook);
            assert_eq!(net.want_tx_gossip(), WANT_TX_GOSSIP_UNK);
        }

        #[test]
        fn is_participating_false_without_node_info() {
            let net = WebsocketNetwork::with_defaults("test", "test");
            assert!(!net.is_participating());
        }

        #[test]
        fn is_participating_true_with_registered_node_info() {
            let net = WebsocketNetwork::with_defaults("test", "test");
            net.set_node_info(Arc::new(ParticipatingNodeInfo));
            assert!(net.is_participating());
        }
    }
}
