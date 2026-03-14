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
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::connect::{try_connect, ConnectConfig};
use crate::gossip_node::{GossipNode, Peer, PeerOption};
use crate::handler::{Multiplexer, TaggedMessageHandler, TaggedMessageValidatorHandler};
use crate::mesh::{ConnectFn, MeshRequest, MeshThread, PeerCounter};
use crate::message::OutgoingMessage;
use crate::message_filter::MessageFilter;
use crate::peer_role::{ARCHIVAL_ROLE, RELAY_ROLE};
use crate::phonebook::Phonebook;
use crate::tag::Tag;
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
}

impl Default for WebsocketNetworkConfig {
    fn default() -> Self {
        Self {
            gossip_fanout: DEFAULT_GOSSIP_FANOUT,
            mesh_interval: DEFAULT_MESH_INTERVAL,
            max_peer_inactivity: DEFAULT_MAX_PEER_INACTIVITY,
            slow_write_threshold: DEFAULT_SLOW_WRITE_THRESHOLD,
            genesis_id: String::new(),
            network_id: String::new(),
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

    /// Deduplication filter for incoming messages.
    message_filter: Arc<MessageFilter>,

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
}

impl WebsocketNetwork {
    /// Create a new `WebsocketNetwork` with the given configuration and
    /// shared phonebook.
    pub fn new(config: WebsocketNetworkConfig, phonebook: Arc<Phonebook>) -> Self {
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            connecting: Mutex::new(HashSet::new()),
            phonebook,
            multiplexer: Arc::new(Multiplexer::new()),
            message_filter: Arc::new(MessageFilter::new(
                crate::message_filter::MESSAGE_FILTER_SIZE,
            )),
            cancel: CancellationToken::new(),
            mesh_update_tx: Mutex::new(None),
            pending_disconnects: Arc::new(std::sync::Mutex::new(Vec::new())),
            tasks: Mutex::new(Vec::new()),
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

    /// Returns a reference to the message filter.
    pub fn message_filter(&self) -> &Arc<MessageFilter> {
        &self.message_filter
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
                                    // Dispatch to the multiplexer.
                                    let _out = multiplexer.handle(incoming).await;
                                    // TODO: act on forwarding policy (broadcast/relay/disconnect)
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

            let connect_config = ConnectConfig {
                genesis_id: self.config.genesis_id.clone(),
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
        // WebsocketNetwork does not currently listen for inbound connections.
        // This will be implemented when the server-side listener is added.
        (String::new(), false)
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
        wait: bool,
        except: Option<Arc<dyn Peer>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Relay is semantically identical to broadcast with an exclusion.
        self.broadcast(tag, data, wait, except).await
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
}

impl ConnectFn for NetworkConnectFn {
    fn try_dial(&self, addr: String) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async move {
            let connect_config = ConnectConfig {
                genesis_id: self.genesis_id.clone(),
                ..ConnectConfig::default()
            };

            match try_connect(&addr, &connect_config).await {
                Ok(mut handle) => {
                    let peer_addr = handle.remote_addr().to_string();
                    let incoming_rx = handle.take_incoming();

                    // Store the peer entry.
                    {
                        let mut peers = self.peers.write().await;
                        peers.insert(
                            peer_addr.clone(),
                            PeerEntry {
                                handle,
                                direction: PeerDirection::Outbound,
                            },
                        );
                    }

                    tracing::info!(addr = %peer_addr, "outbound connection established (mesh)");

                    // Spawn receive/dispatch loop.
                    if let Some(mut rx) = incoming_rx {
                        let multiplexer = Arc::clone(&self.multiplexer);
                        let cancel = self.cancel.clone();
                        let peers = Arc::clone(&self.peers);
                        let recv_addr = peer_addr;

                        let recv_task = tokio::spawn(async move {
                            loop {
                                tokio::select! {
                                    _ = cancel.cancelled() => {
                                        tracing::debug!(addr = %recv_addr, "receive loop cancelled");
                                        break;
                                    }
                                    msg = rx.recv() => {
                                        match msg {
                                            Some(incoming) => {
                                                let _out = multiplexer.handle(incoming).await;
                                            }
                                            None => {
                                                tracing::info!(addr = %recv_addr, "peer incoming channel closed, removing");
                                                let mut guard = peers.write().await;
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

                        let mut tasks = self.tasks.lock().await;
                        tasks.push(recv_task);
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

        // Multiplexer and message filter should be accessible.
        let _mux = net.multiplexer();
        let _filter = net.message_filter();
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
}
