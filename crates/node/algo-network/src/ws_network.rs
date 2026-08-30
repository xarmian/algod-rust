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
use crate::connect::{try_connect, ConnectConfig};
use crate::forwarding_policy::ForwardingPolicy;
use crate::gossip_node::{GossipNode, Peer, PeerOption};
use crate::handler::{Multiplexer, TaggedMessageHandler, TaggedMessageValidatorHandler};
use crate::handshake::{check_protocol_version_match, VersionMatch, SUPPORTED_PROTOCOL_VERSIONS};
use crate::health_service::health_router;
use crate::mesh::{ConnectFn, MeshRequest, MeshThread, PeerCounter};
use crate::message::OutgoingMessage;
use crate::message_filter::MessageFilter;
use crate::peer_role::{ARCHIVAL_ROLE, RELAY_ROLE};
use crate::phonebook::Phonebook;
use crate::request_response::{encode_uvarint, hash_topics, RESPONSE_HASH_FIELD};
use crate::request_tracker::ConnectionTracker;
use crate::tag::Tag;
use crate::topics::{Topic, Topics};
use crate::ws_peer::PeerHandle;

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

/// Default maximum peer inactivity before disconnection.
///
/// Matches Go's `maxPeerInactivityDuration` of 5 minutes.
const DEFAULT_MAX_PEER_INACTIVITY: Duration = Duration::from_secs(5 * 60);

/// Default slow-write threshold (how long a message can sit in the send queue).
///
/// Matches Go's `maxMessageQueueDuration` of 25 seconds.
const DEFAULT_SLOW_WRITE_THRESHOLD: Duration = Duration::from_secs(25);

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
        }
    }
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
    /// `enable_incoming_message_filter` is off (go's default).
    incoming_message_filter: Option<Arc<MessageFilter>>,

    /// Deduplication filter for outgoing messages (`MsgDigestSkip`
    /// tracking). `None` when `enable_outgoing_network_message_filtering`
    /// is off.
    outgoing_message_filter: Option<Arc<MessageFilter>>,

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
        let outgoing_message_filter = config.enable_outgoing_network_message_filtering.then(|| {
            Arc::new(MessageFilter::new(
                config.outgoing_message_filter_bucket_count,
                config.outgoing_message_filter_bucket_size,
            ))
        });
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            connecting: Mutex::new(HashSet::new()),
            phonebook,
            multiplexer: Arc::new(Multiplexer::new()),
            incoming_message_filter,
            outgoing_message_filter,
            cancel: CancellationToken::new(),
            mesh_update_tx: Mutex::new(None),
            pending_disconnects: Arc::new(std::sync::Mutex::new(Vec::new())),
            tasks: Mutex::new(Vec::new()),
            node_random: node_random.to_string(),
            connection_tracker: Arc::new(ConnectionTracker::new(Duration::from_secs(1))),
            listen_addr: std::sync::Mutex::new(None),
            registered_handlers: std::sync::Mutex::new(Vec::new()),
            broadcast_thread: Arc::new(std::sync::Mutex::new(None)),
        }
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

    /// Returns the outgoing-message dedup filter, if
    /// `enable_outgoing_network_message_filtering` is on (go's default).
    pub fn outgoing_message_filter(&self) -> Option<&Arc<MessageFilter>> {
        self.outgoing_message_filter.as_ref()
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
    pub async fn add_peer(&self, mut handle: PeerHandle, direction: PeerDirection) {
        let addr = handle.remote_addr().to_string();

        // Take the incoming receiver before storing the handle.
        let incoming_rx = handle.take_incoming();

        // Clone the peer sender before moving the handle — needed for
        // sending Respond messages back (e.g. UniEnsBlockReq responses).
        let peer_sender = handle.sender();

        // Store the peer entry.
        {
            let mut peers = self.peers.write().await;
            peers.insert(addr.clone(), PeerEntry { handle, direction });
        }

        tracing::info!(addr = %addr, direction = ?direction, "peer added to network");

        // Spawn a receive/dispatch loop for this peer.
        if let Some(mut rx) = incoming_rx {
            let multiplexer = Arc::clone(&self.multiplexer);
            let cancel = self.cancel.clone();
            let peers = Arc::clone(&self.peers);
            let peer_addr = addr;
            let broadcast_handle: Option<BroadcastHandle> = {
                let guard = self
                    .broadcast_thread
                    .lock()
                    .expect("broadcast_thread lock poisoned");
                guard.as_ref().map(|bt| bt.handle())
            };

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
            entry.handle.close();
            tracing::info!(addr = %addr, "peer removed from network");
            true
        } else {
            false
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
            let connect_config = ConnectConfig {
                genesis_id: self.config.genesis_id.clone(),
                peer_config: Some(crate::ws_peer::WsPeerConfig {
                    incoming_filter: self.incoming_message_filter.clone(),
                    outgoing_filter: self.outgoing_message_filter.clone(),
                    ..crate::ws_peer::WsPeerConfig::default()
                }),
                ..ConnectConfig::default()
            };

            let addr_clone = addr.clone();
            match try_connect(&addr_clone, &connect_config).await {
                Ok(handle) => {
                    self.add_peer(handle, PeerDirection::Outbound).await;
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
        // Forward the notification to the MeshThread if it has been spawned.
        let guard = self.mesh_update_tx.try_lock();
        if let Ok(ref opt_tx) = guard {
            if let Some(tx) = opt_tx.as_ref() {
                let _ = tx.try_send(MeshRequest { done: None });
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
    /// Issue #789: the network's constructed incoming/outgoing
    /// `MessageFilter`s, threaded into every real outbound (mesh-dial)
    /// connection's `WsPeerConfig` so dedup actually runs on the wire —
    /// previously `try_dial` always built `WsPeerConfig::default()`, so
    /// these filters (config-driven since #768) had zero live effect.
    incoming_message_filter: Option<Arc<MessageFilter>>,
    outgoing_message_filter: Option<Arc<MessageFilter>>,
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
        let outgoing_message_filter = self.outgoing_message_filter.clone();

        Box::pin(async move {
            use crate::ws_peer::WsPeerConfig;

            let connect_config = ConnectConfig {
                genesis_id,
                peer_config: Some(WsPeerConfig {
                    request_timeout: Some(Duration::from_secs(5)),
                    incoming_filter: incoming_message_filter,
                    outgoing_filter: outgoing_message_filter,
                    ..WsPeerConfig::default()
                }),
                ..ConnectConfig::default()
            };

            match try_connect(&addr, &connect_config).await {
                Ok(mut handle) => {
                    let peer_addr = handle.remote_addr().to_string();
                    let incoming_rx = handle.take_incoming();

                    // Store the peer entry.
                    {
                        let mut guard = peers.write().await;
                        guard.insert(
                            peer_addr.clone(),
                            PeerEntry {
                                handle,
                                direction: PeerDirection::Outbound,
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
                                                let relay_data = if broadcast_handle.is_some() {
                                                    Some((incoming.data.clone(), incoming.sender.clone()))
                                                } else {
                                                    None
                                                };
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

        // Build ConnectFn and PeerCounter adapters.
        let connect_fn = NetworkConnectFn {
            peers: Arc::clone(&self.peers),
            multiplexer: Arc::clone(&self.multiplexer),
            cancel: self.cancel.clone(),
            tasks: Arc::new(Mutex::new(Vec::new())),
            genesis_id: self.config.genesis_id.clone(),
            broadcast_thread: Arc::clone(&self.broadcast_thread),
            incoming_message_filter: self.incoming_message_filter.clone(),
            outgoing_message_filter: self.outgoing_message_filter.clone(),
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

        {
            let mut tasks = self.tasks.lock().await;
            tasks.push(mesh_task);
            tasks.push(monitor_task);
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
    /// Validation passed, with the negotiated protocol version.
    Ok { matched_version: String },
    /// Validation failed — return this response to the client.
    Rejected(axum::response::Response),
}

/// Validate an incoming gossip WebSocket connection.
///
/// Checks (matching Go's `ServeHTTP` flow):
/// 1. Genesis ID in the URL path matches ours
/// 2. Protocol version is compatible
/// 3. Track the connection (atomically, before limit checks)
/// 4. Per-IP connection limit
/// 5. Per-IP rate limit
/// 6. Self-loop detection (NodeRandom header)
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

    // 2. Protocol version check
    let matched_version = match check_protocol_version_match(headers, SUPPORTED_PROTOCOL_VERSIONS) {
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

    // 3. Track the connection BEFORE checking limits so that concurrent
    //    handshakes from the same IP see each other's counts.
    network.connection_tracker.track_connection(remote_ip);

    // 4. Per-IP connection limit
    if !network
        .connection_tracker
        .check_connection_limit(remote_ip, network.config.max_connections_per_ip)
    {
        // Undo tracking — this request will not proceed.
        network.connection_tracker.release_connection(remote_ip);
        tracing::warn!(
            ip = %remote_ip,
            limit = network.config.max_connections_per_ip,
            "incoming connection: per-IP connection limit exceeded"
        );
        return ValidationResult::Rejected(
            (StatusCode::FORBIDDEN, "per-IP connection limit exceeded").into_response(),
        );
    }

    // 5. Rate limit — go's `DisableLocalhostConnectionRateLimit`
    // (`network/requestTracker.go:261,450`: `rateLimitedRemoteHost :=
    // (!cfg.DisableLocalhostConnectionRateLimit) || (!isLocalhost(host))`)
    // exempts loopback remotes from the rate limiter specifically (the
    // per-IP *connection-count* limit above still applies to localhost —
    // this only affects the rate-limit check).
    let rate_limited_remote =
        !network.config.disable_localhost_connection_rate_limit || !remote_ip.is_loopback();
    if rate_limited_remote
        && !network
            .connection_tracker
            .check_rate_limit(remote_ip, network.config.connections_rate_limiting_count)
    {
        // Undo tracking — this request will not proceed.
        network.connection_tracker.release_connection(remote_ip);
        tracing::warn!(
            ip = %remote_ip,
            "incoming connection: rate limit exceeded"
        );
        return ValidationResult::Rejected(
            (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response(),
        );
    }

    // 6. Self-loop detection
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

    ValidationResult::Ok { matched_version }
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
    let matched_version =
        match validate_incoming_connection(&network, &genesis_id, &headers, remote_ip) {
            ValidationResult::Ok { matched_version } => matched_version,
            ValidationResult::Rejected(response) => return response,
        };

    // Build response headers (matching Go's setHeaders for server responses).
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        HeaderName::from_static("x-algorand-version"),
        matched_version.parse().expect("valid header value"),
    );
    for v in SUPPORTED_PROTOCOL_VERSIONS {
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

    // Perform the WebSocket upgrade and attach the response headers
    // to the 101 Switching Protocols response.
    let network_clone = Arc::clone(&network);
    let version_clone = matched_version;
    let addr_str = remote_addr.to_string();

    let mut response = ws
        .on_upgrade(move |socket| {
            handle_gossip_websocket(network_clone, socket, addr_str, version_clone, remote_ip)
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
    let handle = PeerHandle::new_inbound(
        socket,
        remote_addr.clone(),
        version,
        network.cancel.child_token(),
        network.incoming_message_filter().cloned(),
        network.outgoing_message_filter().cloned(),
    );

    // Register the inbound peer in the peer map via add_peer, which
    // also spawns the receive/dispatch loop for multiplexer integration.
    network.add_peer(handle, PeerDirection::Inbound).await;

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
        assert!(net.outgoing_message_filter().is_some());
        assert!(net.incoming_message_filter().is_none());
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
            .outgoing_message_filter()
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
        assert!(net.outgoing_message_filter().is_none());
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

    #[test]
    fn validate_incoming_valid_connection_passes() {
        let net = make_relay_network("testnet-v1.0");
        let ip: std::net::IpAddr = "10.0.0.7".parse().unwrap();
        let headers = valid_incoming_headers("different-random");

        let result = validate_incoming_connection(&net, "testnet-v1.0", &headers, ip);
        match result {
            ValidationResult::Ok { matched_version } => {
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
}
