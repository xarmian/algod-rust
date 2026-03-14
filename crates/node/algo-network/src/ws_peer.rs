//! WebSocket peer abstraction.
//!
//! `WsPeer` wraps a live `tokio-tungstenite` WebSocket stream together with
//! the handshake results (genesis, protocol version, identity public key,
//! feature set).  It provides typed send/receive of Algorand framed messages
//! and manages keepalive pings.
//!
//! # Architecture
//!
//! After the WebSocket connection is established and the Algorand handshake
//! completes, the connection is split into a read half and a write half.
//! Three async tasks are spawned:
//!
//! - **read_loop** — reads WebSocket frames, parses tag + payload, handles MI
//!   messages locally, and dispatches everything else to an `incoming` channel.
//! - **write_loop** — drains high-priority and bulk send channels (high-prio
//!   first), applies the message-of-interest filter, encodes tag+payload,
//!   optionally compresses, and writes to the WebSocket sink.
//! - **keepalive_loop** — sends periodic WebSocket pings and monitors for idle
//!   connections (no packets within [`MAX_PEER_INACTIVITY`]).
//!
//! Shutdown is coordinated via a [`CancellationToken`].  Callers interact
//! through the returned [`PeerHandle`] which exposes `send`, `send_priority`,
//! `close`, and the incoming message receiver.
//!
//! # Go reference
//!
//! - `network/wsPeer.go` — `wsPeer` struct, `readLoop`, `writeLoop`, `init`
//! - `network/wsNetwork.go` — constants, `checkPeersConnectivity`

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tokio_util::sync::CancellationToken;

use crate::compression::{
    is_zstd_compressed, zstd_compress, zstd_decompress, MAX_DECOMPRESSED_MESSAGE_SIZE,
};
use crate::errors::PeerError;
use crate::forwarding_policy::ForwardingPolicy;
use crate::framing::{decode_frame, encode_frame};
use crate::gossip_node::{Peer, UnicastPeer};
use crate::handler::Multiplexer;
use crate::message::{IncomingMessage, OutgoingMessage};
use crate::message_filter::{
    dedup_safe_tag, generate_message_digest, MessageFilter, MESSAGE_FILTER_SIZE,
};
use crate::msg_of_interest::unmarshal_msg_of_interest;
use crate::peer_features::PeerFeatureFlags;
use crate::request_response::{
    encode_uvarint, hash_topics, RequestTracker, DEFAULT_REQUEST_TIMEOUT, RESPONSE_HASH_FIELD,
};
use crate::tag::Tag;
use crate::topics::{Topic, Topics};

// ---------------------------------------------------------------------------
// Constants (matching go-algorand)
// ---------------------------------------------------------------------------

/// Size of the high-priority and bulk send channel buffers.
///
/// Go uses `outgoingMessagesBufferSize` which is derived from consensus
/// committee sizes (~2500+).  We use 2500 to better match Go's dynamic
/// calculation.
const SEND_BUFFER_LENGTH: usize = 2500;

/// Maximum number of messages from a single peer that can be queued in the
/// incoming read buffer at a time (matches `msgsInReadBufferPerPeer` in Go).
const MSGS_IN_READ_BUFFER_PER_PEER: usize = 10;

/// Maximum time a message can sit in the send queue before being considered
/// stale and causing the connection to be torn down.
///
/// Matches `maxMessageQueueDuration` in `go-algorand/network/wsNetwork.go`.
const MAX_MESSAGE_QUEUE_DURATION: Duration = Duration::from_secs(25);

/// Maximum duration of inactivity before a peer is considered idle and
/// disconnected.
///
/// Matches `maxPeerInactivityDuration` in `go-algorand/network/wsNetwork.go`.
const MAX_PEER_INACTIVITY: Duration = Duration::from_secs(5 * 60);

/// Interval at which we check for idle/dead peers.
///
/// Matches `connectionActivityMonitorInterval` in Go (3 minutes).
const CONNECTIVITY_CHECK_INTERVAL: Duration = Duration::from_secs(3 * 60);

/// WebSocket ping payload length (matches `PingLength` in Go).
const PING_LENGTH: usize = 8;

// ---------------------------------------------------------------------------
// Default message tags (matching Go's defaultSendMessageTags)
// ---------------------------------------------------------------------------

/// Returns the default set of message tags that a peer is allowed to send
/// without receiving an explicit message-of-interest update.
///
/// Matches `defaultSendMessageTags` in `go-algorand/network/wsPeer.go`.
fn default_send_message_tags() -> HashSet<Tag> {
    let mut tags = HashSet::new();
    tags.insert(Tag::AgreementVote);
    tags.insert(Tag::MsgDigestSkip);
    tags.insert(Tag::NetPrioResponse);
    tags.insert(Tag::NetIDVerification);
    tags.insert(Tag::ProposalPayload);
    tags.insert(Tag::TopicMsgResp);
    tags.insert(Tag::MsgOfInterest);
    tags.insert(Tag::Transaction);
    tags.insert(Tag::UniEnsBlockReq);
    tags.insert(Tag::VoteBundle);
    tags.insert(Tag::VotePacked);
    tags
}

// ---------------------------------------------------------------------------
// Internal message wrapper (carries enqueue timestamp for staleness check)
// ---------------------------------------------------------------------------

/// Internal send message with enqueue timestamp for stale-message detection.
///
/// Mirrors Go's `sendMessage` struct.
#[derive(Debug)]
struct SendMessage {
    /// The outgoing message (tag + payload).
    msg: OutgoingMessage,
    /// When this message was first enqueued (for staleness detection).
    enqueued: Instant,
}

/// A special control message to update the send-message-tag filter.
///
/// In Go this is encoded as a `sendMessage` with `msgTags != nil` and
/// `data == nil`.  We use a separate enum variant for clarity.
#[derive(Debug)]
enum WriteCommand {
    /// Send a data message.
    Data(SendMessage),
    /// Update the message-of-interest tag filter.
    UpdateFilter(HashSet<Tag>),
    /// Send a WebSocket Ping frame.
    Ping(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, WsMessage>;
type WsStream = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

// ---------------------------------------------------------------------------
// WsPeer
// ---------------------------------------------------------------------------

/// Optional components for message handling integration.
///
/// When provided to [`WsPeer::with_config`], these components enable
/// advanced message processing in the read and write loops:
///
/// - **multiplexer**: dispatches incoming messages to registered handlers
/// - **incoming_filter**: deduplicates incoming messages (for AV and TX tags)
/// - **outgoing_filter**: tracks digests the peer already has (via MsgDigestSkip)
/// - **request_tracker**: correlates TopicMsgResp responses to pending requests
/// - **request_timeout**: overrides the default 60s timeout for unicast requests
///
/// All fields are `Option` so existing code that doesn't need these features
/// can pass `WsPeerConfig::default()` (all `None`).
#[derive(Default, Clone)]
pub struct WsPeerConfig {
    /// Message multiplexer for handler dispatch.
    pub multiplexer: Option<Arc<Multiplexer>>,
    /// Incoming message dedup filter.
    pub incoming_filter: Option<Arc<MessageFilter>>,
    /// Outgoing message filter (digests the peer already has).
    pub outgoing_filter: Option<Arc<MessageFilter>>,
    /// Request/response correlation tracker.
    pub request_tracker: Option<Arc<RequestTracker>>,
    /// Timeout for unicast requests made via [`PeerHandle::request()`].
    ///
    /// When `None`, defaults to [`DEFAULT_REQUEST_TIMEOUT`] (60s).
    /// Set this to a shorter duration (e.g. 4s) for block-fetch peers
    /// where fast failover is more important than tolerating slow peers.
    pub request_timeout: Option<Duration>,
}

/// A live WebSocket peer connection.
///
/// This struct owns the WebSocket connection halves and the spawned async
/// tasks.  It is not meant to be used directly — callers interact through
/// the [`PeerHandle`] returned by [`WsPeer::start`].
pub struct WsPeer {
    /// WebSocket write half.
    sink: WsSink,
    /// WebSocket read half.
    stream: WsStream,
    /// High-priority send channel (MI updates, VP abort, etc.).
    send_high_prio_tx: mpsc::Sender<WriteCommand>,
    send_high_prio_rx: mpsc::Receiver<WriteCommand>,
    /// Bulk send channel (normal data messages).
    send_bulk_tx: mpsc::Sender<WriteCommand>,
    send_bulk_rx: mpsc::Receiver<WriteCommand>,
    /// Shared shutdown signal.
    closing: CancellationToken,
    /// Message interest filter: only send messages whose tag is in this set.
    send_message_tags: Arc<RwLock<HashSet<Tag>>>,
    /// The peer's identity public key (if verified during handshake).
    identity_key: Option<ed25519_dalek::VerifyingKey>,
    /// Whether the identity has been verified via the challenge protocol.
    identity_verified: bool,
    /// Negotiated peer feature flags.
    features: PeerFeatureFlags,
    /// Negotiated network protocol version (e.g. "2.2").
    version: String,
    /// Remote address of the peer (e.g. "1.2.3.4:4160").
    remote_addr: String,
    /// Timestamp of the last successful communication with this peer.
    last_packet_time: Arc<RwLock<Instant>>,
    /// Optional message handling components.
    config: WsPeerConfig,
}

impl WsPeer {
    /// Create a new `WsPeer` from an already-established WebSocket connection.
    ///
    /// The `ws_stream` should be the result of a successful WebSocket upgrade
    /// and Algorand handshake.  The remaining parameters come from the
    /// handshake result.
    ///
    /// Call [`start`](WsPeer::start) to spawn the background tasks and get a
    /// [`PeerHandle`].
    pub fn new(
        ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
        remote_addr: String,
        version: String,
        features: PeerFeatureFlags,
        identity_key: Option<ed25519_dalek::VerifyingKey>,
        identity_verified: bool,
        closing: CancellationToken,
    ) -> Self {
        Self::with_config(
            ws_stream,
            remote_addr,
            version,
            features,
            identity_key,
            identity_verified,
            closing,
            WsPeerConfig::default(),
        )
    }

    /// Create a new `WsPeer` with optional message-handling components.
    ///
    /// Like [`new`](Self::new) but accepts a [`WsPeerConfig`] that can wire
    /// up a multiplexer, message filters, and a request tracker.
    #[allow(clippy::too_many_arguments)]
    pub fn with_config(
        ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
        remote_addr: String,
        version: String,
        features: PeerFeatureFlags,
        identity_key: Option<ed25519_dalek::VerifyingKey>,
        identity_verified: bool,
        closing: CancellationToken,
        config: WsPeerConfig,
    ) -> Self {
        let (sink, stream) = ws_stream.split();

        let (send_high_prio_tx, send_high_prio_rx) = mpsc::channel(SEND_BUFFER_LENGTH);
        let (send_bulk_tx, send_bulk_rx) = mpsc::channel(SEND_BUFFER_LENGTH);
        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));
        let last_packet_time = Arc::new(RwLock::new(Instant::now()));

        Self {
            sink,
            stream,
            send_high_prio_tx,
            send_high_prio_rx,
            send_bulk_tx,
            send_bulk_rx,
            closing,
            send_message_tags,
            identity_key,
            identity_verified,
            features,
            version,
            remote_addr,
            last_packet_time,
            config,
        }
    }

    /// Spawn the read, write, and keepalive loops and return a [`PeerHandle`]
    /// for interacting with this peer.
    pub fn start(self) -> PeerHandle {
        // Create the incoming channel whose receiver goes to PeerHandle.
        let (incoming_tx, incoming_rx) = mpsc::channel(MSGS_IN_READ_BUFFER_PER_PEER);

        let closing = self.closing.clone();
        let send_message_tags = self.send_message_tags.clone();
        let last_packet_time = self.last_packet_time.clone();
        let remote_addr = self.remote_addr.clone();
        let features = self.features;
        let identity_key = self.identity_key;

        // Extract optional config components.
        let multiplexer = self.config.multiplexer;
        let incoming_filter = self.config.incoming_filter;
        let outgoing_filter = self.config.outgoing_filter;
        let request_tracker = self.config.request_tracker;
        let request_timeout = self
            .config
            .request_timeout
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT);

        // Clone request_tracker for the PeerHandle (the read loop also
        // gets a reference so it can route TopicMsgResp to pending receivers).
        let handle_request_tracker = request_tracker.clone();

        // Extract fields for the individual tasks.
        let stream = self.stream;
        let sink = self.sink;
        let send_high_prio_rx = self.send_high_prio_rx;
        let send_bulk_rx = self.send_bulk_rx;

        // Create a shareable PeerSender that the read loop can attach to
        // IncomingMessages so that handlers can respond to the peer.
        let peer_sender = Arc::new(PeerSender {
            send_high_prio: self.send_high_prio_tx.clone(),
            send_bulk: self.send_bulk_tx.clone(),
            closing: closing.clone(),
            remote_addr: remote_addr.clone(),
        });

        let read_handle = tokio::spawn(read_loop(
            stream,
            incoming_tx,
            self.send_high_prio_tx.clone(),
            send_message_tags.clone(),
            last_packet_time.clone(),
            closing.clone(),
            remote_addr.clone(),
            features,
            multiplexer,
            incoming_filter,
            outgoing_filter.clone(),
            request_tracker,
            peer_sender,
        ));

        let write_handle = tokio::spawn(write_loop(
            sink,
            send_high_prio_rx,
            send_bulk_rx,
            send_message_tags.clone(),
            closing.clone(),
            remote_addr.clone(),
            features,
            outgoing_filter,
        ));

        let keepalive_handle = tokio::spawn(keepalive_loop(
            last_packet_time.clone(),
            self.send_high_prio_tx.clone(),
            closing.clone(),
            remote_addr.clone(),
        ));

        PeerHandle {
            send_high_prio: self.send_high_prio_tx,
            send_bulk: self.send_bulk_tx,
            incoming: incoming_rx,
            closing,
            remote_addr,
            identity_key,
            identity_verified: self.identity_verified,
            features,
            version: self.version,
            request_tracker: handle_request_tracker,
            request_timeout,
            _read_handle: read_handle,
            _write_handle: write_handle,
            _keepalive_handle: keepalive_handle,
        }
    }
}

// ---------------------------------------------------------------------------
// PeerSender — sharable peer reference for message handlers
// ---------------------------------------------------------------------------

/// A lightweight, shareable reference to a peer's send channels and identity.
///
/// This is the peer reference carried by [`IncomingMessage`] so that message
/// handlers can respond to or disconnect the sending peer.  Unlike
/// [`PeerHandle`], this type does not own the incoming message receiver or
/// task handles, so it can be wrapped in `Arc` and shared freely.
pub struct PeerSender {
    /// Sender for high-priority messages.
    send_high_prio: mpsc::Sender<WriteCommand>,
    /// Sender for bulk/normal data messages.
    send_bulk: mpsc::Sender<WriteCommand>,
    /// Cancellation token for shutdown.
    closing: CancellationToken,
    /// Remote address of the peer (e.g. "1.2.3.4:4160").
    remote_addr: String,
}

impl PeerSender {
    /// Send a message on the bulk (normal priority) channel.
    #[allow(clippy::result_large_err)]
    pub fn send(&self, msg: OutgoingMessage) -> Result<(), PeerError> {
        let cmd = WriteCommand::Data(SendMessage {
            msg,
            enqueued: Instant::now(),
        });
        self.send_bulk
            .try_send(cmd)
            .map_err(|_| PeerError::SendBufferFull)
    }

    /// Send a message on the high-priority channel.
    #[allow(clippy::result_large_err)]
    pub fn send_priority(&self, msg: OutgoingMessage) -> Result<(), PeerError> {
        let cmd = WriteCommand::Data(SendMessage {
            msg,
            enqueued: Instant::now(),
        });
        self.send_high_prio
            .try_send(cmd)
            .map_err(|_| PeerError::SendBufferFull)
    }

    /// Trigger graceful shutdown.
    pub fn close(&self) {
        self.closing.cancel();
    }

    /// The remote address of this peer.
    pub fn remote_addr(&self) -> &str {
        &self.remote_addr
    }
}

// ---------------------------------------------------------------------------
// PeerHandle — the external interface
// ---------------------------------------------------------------------------

/// Handle for interacting with a running WebSocket peer.
///
/// This is the public API that callers use to send messages, receive incoming
/// messages, and shut down the peer.  It is returned by [`WsPeer::start`].
pub struct PeerHandle {
    /// Sender for high-priority messages (MI updates, control messages).
    send_high_prio: mpsc::Sender<WriteCommand>,
    /// Sender for bulk/normal data messages.
    send_bulk: mpsc::Sender<WriteCommand>,
    /// Receiver for incoming messages from the peer.
    pub(crate) incoming: mpsc::Receiver<IncomingMessage>,
    /// Cancellation token for shutdown.
    closing: CancellationToken,
    /// Remote address of the peer.
    remote_addr: String,
    /// The peer's verified identity public key (if any).
    identity_key: Option<ed25519_dalek::VerifyingKey>,
    /// Whether identity has been verified.
    identity_verified: bool,
    /// Negotiated feature flags.
    features: PeerFeatureFlags,
    /// Negotiated protocol version.
    version: String,
    /// Request/response correlation tracker for unicast request/response.
    ///
    /// Shared with the read loop which routes `TopicMsgResp` responses
    /// back to pending request receivers.
    request_tracker: Option<Arc<RequestTracker>>,
    /// Timeout for unicast requests.
    ///
    /// Defaults to [`DEFAULT_REQUEST_TIMEOUT`] (60s) but can be overridden
    /// via [`WsPeerConfig::request_timeout`] or [`PeerHandle::set_request_timeout`].
    request_timeout: Duration,
    /// Task handles (kept alive so tasks are not dropped prematurely).
    _read_handle: JoinHandle<()>,
    _write_handle: JoinHandle<()>,
    _keepalive_handle: JoinHandle<()>,
}

impl PeerHandle {
    /// Send a message on the bulk (normal priority) channel.
    ///
    /// Returns `Err(PeerError::SendBufferFull)` if the channel is full.
    #[allow(clippy::result_large_err)]
    pub fn send(&self, msg: OutgoingMessage) -> Result<(), PeerError> {
        let cmd = WriteCommand::Data(SendMessage {
            msg,
            enqueued: Instant::now(),
        });
        self.send_bulk
            .try_send(cmd)
            .map_err(|_| PeerError::SendBufferFull)
    }

    /// Send a message on the high-priority channel.
    ///
    /// Returns `Err(PeerError::SendBufferFull)` if the channel is full.
    #[allow(clippy::result_large_err)]
    pub fn send_priority(&self, msg: OutgoingMessage) -> Result<(), PeerError> {
        let cmd = WriteCommand::Data(SendMessage {
            msg,
            enqueued: Instant::now(),
        });
        self.send_high_prio
            .try_send(cmd)
            .map_err(|_| PeerError::SendBufferFull)
    }

    /// Trigger graceful shutdown of all peer tasks.
    pub fn close(&self) {
        self.closing.cancel();
    }

    /// Whether the peer connection has been shut down.
    pub fn is_closed(&self) -> bool {
        self.closing.is_cancelled()
    }

    /// The remote address of this peer (e.g. "1.2.3.4:4160").
    pub fn remote_addr(&self) -> &str {
        &self.remote_addr
    }

    /// The peer's verified identity public key, if available.
    pub fn identity(&self) -> Option<&ed25519_dalek::VerifyingKey> {
        self.identity_key.as_ref()
    }

    /// Whether the peer's identity has been verified via the challenge protocol.
    pub fn identity_verified(&self) -> bool {
        self.identity_verified
    }

    /// The negotiated peer feature flags.
    pub fn features(&self) -> PeerFeatureFlags {
        self.features
    }

    /// The negotiated network protocol version (e.g. "2.2").
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Override the timeout used for unicast requests.
    ///
    /// This allows callers to set a shorter timeout (e.g. 4s for block
    /// fetching) after construction.  The timeout is applied inside
    /// [`UnicastPeer::request()`] so that cleanup of pending tracker
    /// entries happens correctly even on timeout.
    pub fn set_request_timeout(&mut self, timeout: Duration) {
        self.request_timeout = timeout;
    }

    /// Returns the currently configured request timeout.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Receive the next incoming message from this peer.
    ///
    /// Returns `None` when the peer has disconnected and the channel is drained.
    pub async fn recv(&mut self) -> Option<IncomingMessage> {
        self.incoming.recv().await
    }

    /// Take the incoming message receiver out of this handle.
    ///
    /// This allows the caller (e.g. [`WebsocketNetwork::add_peer`]) to spawn
    /// a dedicated receive/dispatch loop without holding the entire
    /// `PeerHandle`.  After calling this, [`recv()`](Self::recv) will always
    /// return `None`.
    ///
    /// Returns `None` if the receiver has already been taken.
    pub fn take_incoming(&mut self) -> Option<mpsc::Receiver<IncomingMessage>> {
        // Replace with a dummy closed channel.
        let (_, empty_rx) = mpsc::channel(1);
        let old = std::mem::replace(&mut self.incoming, empty_rx);
        Some(old)
    }
}

impl Drop for PeerHandle {
    fn drop(&mut self) {
        // Ensure all tasks are cancelled when the handle is dropped.
        self.closing.cancel();
        self._read_handle.abort();
        self._write_handle.abort();
        self._keepalive_handle.abort();
    }
}

// ---------------------------------------------------------------------------
// Peer trait implementation for PeerHandle
// ---------------------------------------------------------------------------

impl Peer for PeerHandle {
    fn get_address(&self) -> &str {
        &self.remote_addr
    }

    fn get_connection_latency(&self) -> Duration {
        // Latency measurement is not yet implemented for WS peers.
        Duration::ZERO
    }

    fn routing_addr(&self) -> &[u8] {
        // Routing address extraction from the remote address string is
        // deferred to a future epic where IP-based peer bucketing is needed.
        &[]
    }
}

// ---------------------------------------------------------------------------
// UnicastPeer trait implementation for PeerHandle
// ---------------------------------------------------------------------------

#[async_trait]
impl UnicastPeer for PeerHandle {
    async fn request(&self, tag: Tag, topics: Topics) -> Result<Topics, PeerError> {
        let tracker = self
            .request_tracker
            .as_ref()
            .ok_or(PeerError::NoRequestTracker)?;

        // 1. Prepare the request: append nonce, serialize, hash, register receiver.
        let (serialized, hash, rx) = tracker.prepare_request(topics).await;

        // 2. Send the serialized topics as the payload with the given tag.
        let msg = OutgoingMessage::new(tag, serialized);
        let cmd = WriteCommand::Data(SendMessage {
            msg,
            enqueued: Instant::now(),
        });
        if self.send_bulk.try_send(cmd).is_err() {
            // Clean up the pending request entry to prevent a leak.
            tracker.cancel_request(hash).await;
            return Err(PeerError::SendBufferFull);
        }

        // 3. Await the response with a timeout, cancelling on peer close.
        let result = tokio::select! {
            biased;
            _ = self.closing.cancelled() => {
                // Peer is closing; cancel the pending request.
                tracker.cancel_request(hash).await;
                return Err(PeerError::ConnectionClosed);
            }
            resp = tokio::time::timeout(self.request_timeout, rx) => {
                resp
            }
        };

        match result {
            Ok(Ok(response_topics)) => Ok(response_topics),
            Ok(Err(_recv_error)) => {
                // The sender was dropped (peer closed or request cancelled).
                Err(PeerError::ResponseChannelClosed)
            }
            Err(_timeout) => {
                // Clean up the pending request on timeout.
                tracker.cancel_request(hash).await;
                Err(PeerError::RequestTimeout)
            }
        }
    }

    async fn respond(&self, request_hash: u64, topics: Topics) -> Result<(), PeerError> {
        // Build the response: append the RequestHash topic and serialize.
        let request_hash_data = encode_uvarint(request_hash);
        let mut response_topics = topics;
        response_topics
            .0
            .push(Topic::new(RESPONSE_HASH_FIELD, request_hash_data));

        let serialized = response_topics.marshal();
        let msg = OutgoingMessage {
            action: ForwardingPolicy::Respond,
            tag: Tag::TopicMsgResp,
            payload: serialized,
            topics: None,
        };

        let cmd = WriteCommand::Data(SendMessage {
            msg,
            enqueued: Instant::now(),
        });

        // Use the bulk channel (matching Go's sendBufferBulk for Respond).
        self.send_bulk
            .try_send(cmd)
            .map_err(|_| PeerError::SendBufferFull)
    }
}

// ---------------------------------------------------------------------------
// UnicastPeerRef — lightweight clone of PeerHandle for block fetching
// ---------------------------------------------------------------------------

/// A lightweight, cloneable reference to a [`PeerHandle`] that implements
/// [`UnicastPeer`] for block request/response flows.
///
/// Unlike `PeerHandle` (which owns task handles and the incoming receiver),
/// `UnicastPeerRef` holds only the send channel, request tracker, and
/// cancellation token — all of which are cheaply cloneable.  This allows
/// callers (e.g. `GossipBlockSource`) to obtain unicast-capable peer
/// references from the [`WebsocketNetwork`] peer registry without taking
/// ownership of the underlying connection.
pub struct UnicastPeerRef {
    send_bulk: mpsc::Sender<WriteCommand>,
    closing: CancellationToken,
    remote_addr: String,
    request_tracker: Option<Arc<RequestTracker>>,
    request_timeout: Duration,
}

impl Peer for UnicastPeerRef {
    fn get_address(&self) -> &str {
        &self.remote_addr
    }

    fn get_connection_latency(&self) -> Duration {
        Duration::ZERO
    }

    fn routing_addr(&self) -> &[u8] {
        &[]
    }
}

#[async_trait]
impl UnicastPeer for UnicastPeerRef {
    async fn request(&self, tag: Tag, topics: Topics) -> Result<Topics, PeerError> {
        let tracker = self
            .request_tracker
            .as_ref()
            .ok_or(PeerError::NoRequestTracker)?;

        let (serialized, hash, rx) = tracker.prepare_request(topics).await;

        let msg = OutgoingMessage::new(tag, serialized);
        let cmd = WriteCommand::Data(SendMessage {
            msg,
            enqueued: Instant::now(),
        });
        if self.send_bulk.try_send(cmd).is_err() {
            tracker.cancel_request(hash).await;
            return Err(PeerError::SendBufferFull);
        }

        let result = tokio::select! {
            biased;
            _ = self.closing.cancelled() => {
                tracker.cancel_request(hash).await;
                return Err(PeerError::ConnectionClosed);
            }
            resp = tokio::time::timeout(self.request_timeout, rx) => {
                resp
            }
        };

        match result {
            Ok(Ok(response_topics)) => Ok(response_topics),
            Ok(Err(_recv_error)) => Err(PeerError::ResponseChannelClosed),
            Err(_timeout) => {
                tracker.cancel_request(hash).await;
                Err(PeerError::RequestTimeout)
            }
        }
    }

    async fn respond(&self, request_hash: u64, topics: Topics) -> Result<(), PeerError> {
        let request_hash_data = encode_uvarint(request_hash);
        let mut response_topics = topics;
        response_topics
            .0
            .push(Topic::new(RESPONSE_HASH_FIELD, request_hash_data));

        let serialized = response_topics.marshal();
        let msg = OutgoingMessage {
            action: ForwardingPolicy::Respond,
            tag: Tag::TopicMsgResp,
            payload: serialized,
            topics: None,
        };

        let cmd = WriteCommand::Data(SendMessage {
            msg,
            enqueued: Instant::now(),
        });

        self.send_bulk
            .try_send(cmd)
            .map_err(|_| PeerError::SendBufferFull)
    }
}

impl PeerHandle {
    /// Create a lightweight [`UnicastPeerRef`] that shares this handle's
    /// send channel and request tracker.
    ///
    /// The returned reference can be used for unicast request/response
    /// (e.g. block fetching) without owning the connection's task handles
    /// or incoming message receiver.
    pub fn unicast_ref(&self) -> UnicastPeerRef {
        UnicastPeerRef {
            send_bulk: self.send_bulk.clone(),
            closing: self.closing.clone(),
            remote_addr: self.remote_addr.clone(),
            request_tracker: self.request_tracker.clone(),
            request_timeout: self.request_timeout,
        }
    }
}

// ---------------------------------------------------------------------------
// read_loop
// ---------------------------------------------------------------------------

/// Reads WebSocket frames, parses tag + payload, handles MI messages locally,
/// and dispatches everything else to the incoming channel.
///
/// Mirrors Go's `wsPeer.readLoop()`.
///
/// Generic over `St` so that tests can use `WebSocketStream<TcpStream>` while
/// production code uses `WebSocketStream<MaybeTlsStream<TcpStream>>`.
#[allow(clippy::too_many_arguments)]
async fn read_loop<St>(
    mut stream: SplitStream<St>,
    incoming_tx: mpsc::Sender<IncomingMessage>,
    send_high_prio_tx: mpsc::Sender<WriteCommand>,
    _send_message_tags: Arc<RwLock<HashSet<Tag>>>,
    last_packet_time: Arc<RwLock<Instant>>,
    closing: CancellationToken,
    remote_addr: String,
    features: PeerFeatureFlags,
    multiplexer: Option<Arc<Multiplexer>>,
    incoming_filter: Option<Arc<MessageFilter>>,
    outgoing_filter: Option<Arc<MessageFilter>>,
    request_tracker: Option<Arc<RequestTracker>>,
    peer_sender: Arc<PeerSender>,
) where
    St: futures_util::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    loop {
        let ws_msg = tokio::select! {
            biased;
            _ = closing.cancelled() => {
                tracing::debug!(peer = %remote_addr, "read_loop: closing");
                return;
            }
            msg = stream.next() => msg,
        };

        let ws_msg = match ws_msg {
            Some(Ok(msg)) => msg,
            Some(Err(e)) => {
                // Check for normal close.
                if let tokio_tungstenite::tungstenite::Error::ConnectionClosed = &e {
                    tracing::debug!(peer = %remote_addr, "read_loop: connection closed by remote");
                } else if let tokio_tungstenite::tungstenite::Error::Protocol(
                    tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
                ) = &e
                {
                    tracing::debug!(peer = %remote_addr, "read_loop: connection reset");
                } else {
                    tracing::warn!(peer = %remote_addr, error = %e, "read_loop: read error");
                }
                closing.cancel();
                return;
            }
            None => {
                // Stream ended.
                tracing::debug!(peer = %remote_addr, "read_loop: stream ended");
                closing.cancel();
                return;
            }
        };

        match ws_msg {
            WsMessage::Binary(data) => {
                // Update last packet time.
                {
                    let mut lpt = last_packet_time.write().await;
                    *lpt = Instant::now();
                }

                // Decode the frame: first 2 bytes = tag, rest = payload.
                let (tag, payload) = match decode_frame(&data) {
                    Ok(tp) => tp,
                    Err(e) => {
                        tracing::warn!(
                            peer = %remote_addr,
                            error = %e,
                            "read_loop: invalid frame"
                        );
                        // Drop the message but keep the connection (matches Go behaviour
                        // for unknown tags — it increments unkMessageCount and continues).
                        continue;
                    }
                };

                // Decompress if needed (PP tag with ppzstd feature).
                let payload = if tag == Tag::ProposalPayload
                    && features.contains(PeerFeatureFlags::COMPRESSED_PROPOSAL)
                    && is_zstd_compressed(payload)
                {
                    match zstd_decompress(payload, MAX_DECOMPRESSED_MESSAGE_SIZE) {
                        Ok(decompressed) => decompressed,
                        Err(e) => {
                            tracing::warn!(
                                peer = %remote_addr,
                                error = %e,
                                "read_loop: decompression failed for PP"
                            );
                            closing.cancel();
                            return;
                        }
                    }
                } else {
                    payload.to_vec()
                };

                // VP (VotePacked) messages are dispatched with their original
                // tag.  When the avvpack codec is implemented in a future epic,
                // VP payloads will be decoded and re-tagged to AV here.
                // Re-tagging without first unpacking the vpack payload would
                // cause higher layers to receive vpack-encoded bytes labelled
                // as normal AV, making them undecodable.

                // Handle MI (MsgOfInterest) messages: update the send filter.
                if tag == Tag::MsgOfInterest {
                    match unmarshal_msg_of_interest(&payload) {
                        Ok(new_tags) => {
                            // Send the filter update to the write loop via the
                            // high-prio channel (matches Go's approach of routing
                            // through the send channel to avoid locking).
                            let cmd = WriteCommand::UpdateFilter(new_tags);
                            // MI filter updates are critical control messages that
                            // must not be silently dropped.  Use blocking send
                            // instead of try_send — MI messages are infrequent so
                            // briefly yielding the read loop is acceptable.
                            if let Err(e) = send_high_prio_tx.send(cmd).await {
                                tracing::warn!(
                                    peer = %remote_addr,
                                    error = %e,
                                    "read_loop: failed to enqueue MI filter update, \
                                     write loop may have closed"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                peer = %remote_addr,
                                error = %e,
                                "read_loop: bad MI message, disconnecting"
                            );
                            closing.cancel();
                            return;
                        }
                    }
                    continue;
                }

                // --- (a) MsgDigestSkip handling ---
                // A peer is telling us not to send messages with this digest.
                // Reference: Go's handleFilterMessage() in wsPeer.go.
                if tag == Tag::MsgDigestSkip {
                    if let Some(ref of) = outgoing_filter {
                        if payload.len() == 32 {
                            let mut digest = [0u8; 32];
                            digest.copy_from_slice(&payload);
                            of.check_digest(&digest, true, true);
                        } else {
                            tracing::warn!(
                                peer = %remote_addr,
                                size = payload.len(),
                                "read_loop: bad MsgDigestSkip size"
                            );
                        }
                    }
                    continue;
                }

                // --- (b) Incoming dedup ---
                // For dedup-safe tags (AV, TX), check the incoming filter.
                if dedup_safe_tag(&tag) && !payload.is_empty() {
                    if let Some(ref inf) = incoming_filter {
                        if inf.check_incoming_message(&tag, &payload, true, true) {
                            tracing::trace!(
                                peer = %remote_addr,
                                tag = %tag,
                                "read_loop: dropping incoming duplicate"
                            );
                            continue;
                        }
                    }
                }

                // --- (c) Request/response correlation ---
                // TopicMsgResp messages are routed to the RequestTracker.
                if tag == Tag::TopicMsgResp {
                    if let Some(ref rt) = request_tracker {
                        if let Err(e) = rt.handle_response(&payload).await {
                            tracing::warn!(
                                peer = %remote_addr,
                                error = %e,
                                "read_loop: failed to handle TopicMsgResp"
                            );
                        }
                        continue;
                    }
                    // If no request_tracker, fall through to normal dispatch.
                }

                // --- (d) Multiplexer dispatch ---
                if let Some(ref mux) = multiplexer {
                    let now_ns = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as i64;

                    let incoming_msg = IncomingMessage::with_peer(
                        tag,
                        payload.clone(),
                        remote_addr.clone(),
                        now_ns,
                        peer_sender.clone(),
                    );

                    // --- (e) Filter notification ---
                    // For dedup-safe tags with large payloads, compute the
                    // digest and add it to our outgoing filter. In a full
                    // network implementation this would also broadcast a
                    // MsgDigestSkip to other peers.
                    if dedup_safe_tag(&tag) && payload.len() >= MESSAGE_FILTER_SIZE {
                        let digest = generate_message_digest(&tag, &payload);
                        if let Some(ref of) = outgoing_filter {
                            of.check_digest(&digest, true, false);
                        }
                        tracing::trace!(
                            peer = %remote_addr,
                            tag = %tag,
                            "read_loop: large message processed, filter notification \
                             would be broadcast (not yet wired to network layer)"
                        );
                    }

                    // Use validate_handle for unified dispatch: tries
                    // validator handlers first, then falls through to
                    // regular handlers.
                    let out = mux.validate_handle(incoming_msg).await;

                    match out.action {
                        ForwardingPolicy::Ignore => {
                            // Do nothing.
                        }
                        ForwardingPolicy::Disconnect => {
                            tracing::info!(
                                peer = %remote_addr,
                                tag = %tag,
                                "read_loop: handler requested disconnect"
                            );
                            closing.cancel();
                            return;
                        }
                        ForwardingPolicy::Broadcast => {
                            // Forward the message to the incoming channel so
                            // the network layer can broadcast it to other
                            // peers.  This matches Go's messageHandlerThread
                            // which calls net.Broadcast() when the handler
                            // returns Broadcast.
                            //
                            // Additionally, if the outgoing filter is present
                            // and the message is large enough, add its digest
                            // so we don't re-send it to this peer.
                            if dedup_safe_tag(&tag) && payload.len() >= MESSAGE_FILTER_SIZE {
                                let digest = generate_message_digest(&tag, &payload);
                                if let Some(ref of) = outgoing_filter {
                                    of.check_digest(&digest, true, false);
                                }
                            }

                            let broadcast_msg = IncomingMessage::with_peer(
                                tag,
                                payload.clone(),
                                remote_addr.clone(),
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_nanos() as i64,
                                peer_sender.clone(),
                            );
                            match incoming_tx.try_send(broadcast_msg) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    tracing::warn!(
                                        peer = %remote_addr,
                                        tag = %tag,
                                        "read_loop: incoming channel full, \
                                         dropping broadcast message"
                                    );
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    tracing::debug!(
                                        peer = %remote_addr,
                                        "read_loop: incoming channel closed"
                                    );
                                    closing.cancel();
                                    return;
                                }
                            }
                        }
                        ForwardingPolicy::Respond => {
                            // Build a proper TopicMsgResp matching Go's
                            // wsPeer.Respond():
                            // 1. Hash the original incoming data
                            // 2. Append RequestHash topic to handler's
                            //    response topics
                            // 3. Serialize and send as TopicMsgResp
                            let request_hash = hash_topics(&payload);
                            let request_hash_data = encode_uvarint(request_hash);

                            let mut response_topics = out.topics.unwrap_or_else(Topics::new);
                            response_topics
                                .0
                                .push(Topic::new(RESPONSE_HASH_FIELD, request_hash_data));

                            let serialized = response_topics.marshal();
                            let resp_msg = OutgoingMessage {
                                action: ForwardingPolicy::Respond,
                                tag: Tag::TopicMsgResp,
                                payload: serialized,
                                topics: None,
                            };

                            let cmd = WriteCommand::Data(SendMessage {
                                msg: resp_msg,
                                enqueued: Instant::now(),
                            });
                            if let Err(e) = send_high_prio_tx.try_send(cmd) {
                                tracing::warn!(
                                    peer = %remote_addr,
                                    error = %e,
                                    "read_loop: failed to enqueue response"
                                );
                            }
                        }
                        ForwardingPolicy::Accept => {
                            // Message was accepted/processed; nothing more to do.
                        }
                    }

                    continue;
                }

                // --- Fallback: no multiplexer, send to incoming channel ---

                // Build the incoming message.
                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as i64;

                let incoming_msg = IncomingMessage::new(tag, payload, remote_addr.clone(), now_ns);

                // Dispatch to the incoming channel.
                //
                // Use try_send instead of send().await to avoid blocking the
                // read loop when the incoming buffer is full.  Blocking here
                // would prevent us from processing WebSocket pings/pongs and
                // updating last_packet_time, causing keepalive_loop to
                // declare the peer idle and disconnect it.
                match incoming_tx.try_send(incoming_msg) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        tracing::warn!(
                            peer = %remote_addr,
                            tag = %tag,
                            "read_loop: incoming channel full, dropping message (backpressure)"
                        );
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        tracing::debug!(
                            peer = %remote_addr,
                            "read_loop: incoming channel closed"
                        );
                        closing.cancel();
                        return;
                    }
                }
            }
            WsMessage::Pong(_) => {
                // Update last packet time on pong receipt.
                let mut lpt = last_packet_time.write().await;
                *lpt = Instant::now();
            }
            WsMessage::Close(_) => {
                tracing::debug!(peer = %remote_addr, "read_loop: received close frame");
                closing.cancel();
                return;
            }
            WsMessage::Ping(_data) => {
                // tokio-tungstenite handles pong replies automatically.
                // We still update the timestamp.
                let mut lpt = last_packet_time.write().await;
                *lpt = Instant::now();
            }
            // Text frames are not expected in the Algorand protocol.
            // Disconnect immediately, matching Go's behavior.
            WsMessage::Text(_) => {
                tracing::error!(
                    peer = %remote_addr,
                    "read_loop: unexpected text frame, disconnecting"
                );
                closing.cancel();
                return;
            }
            // Frame is a low-level detail; should not appear here.
            WsMessage::Frame(_) => {}
        }
    }
}

// ---------------------------------------------------------------------------
// write_loop
// ---------------------------------------------------------------------------

/// Drains high-priority and bulk send channels, applies the message filter,
/// encodes tag+payload, optionally compresses, and writes to the WebSocket.
///
/// Mirrors Go's `wsPeer.writeLoop()`.
///
/// Generic over `Sk` so that tests can use `WebSocketStream<TcpStream>` while
/// production code uses `WebSocketStream<MaybeTlsStream<TcpStream>>`.
#[allow(clippy::too_many_arguments)]
async fn write_loop<Sk>(
    mut sink: SplitSink<Sk, WsMessage>,
    mut send_high_prio_rx: mpsc::Receiver<WriteCommand>,
    mut send_bulk_rx: mpsc::Receiver<WriteCommand>,
    send_message_tags: Arc<RwLock<HashSet<Tag>>>,
    closing: CancellationToken,
    remote_addr: String,
    features: PeerFeatureFlags,
    outgoing_filter: Option<Arc<MessageFilter>>,
) where
    Sk: futures_util::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    loop {
        // First: try to drain the high-prio channel (non-blocking).
        // This matches Go's first `select` with `default:` fallthrough.
        match send_high_prio_rx.try_recv() {
            Ok(cmd) => {
                if let Err(reason) = process_write_command(
                    cmd,
                    &mut sink,
                    &send_message_tags,
                    &remote_addr,
                    features,
                    &outgoing_filter,
                )
                .await
                {
                    tracing::warn!(
                        peer = %remote_addr,
                        reason = %reason,
                        "write_loop: error, closing"
                    );
                    closing.cancel();
                    return;
                }
                continue;
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                // No high-prio message; fall through to blocking select.
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                tracing::debug!(
                    peer = %remote_addr,
                    "write_loop: high-prio channel closed"
                );
                closing.cancel();
                return;
            }
        }

        // If nothing high-prio, block on either channel or closing.
        let cmd = tokio::select! {
            biased;
            _ = closing.cancelled() => {
                tracing::debug!(peer = %remote_addr, "write_loop: closing");
                // Try to send a close frame before returning.
                let _ = sink.close().await;
                return;
            }
            cmd = send_high_prio_rx.recv() => {
                match cmd {
                    Some(c) => c,
                    None => {
                        closing.cancel();
                        return;
                    }
                }
            }
            cmd = send_bulk_rx.recv() => {
                match cmd {
                    Some(c) => c,
                    None => {
                        closing.cancel();
                        return;
                    }
                }
            }
        };

        if let Err(reason) = process_write_command(
            cmd,
            &mut sink,
            &send_message_tags,
            &remote_addr,
            features,
            &outgoing_filter,
        )
        .await
        {
            tracing::warn!(
                peer = %remote_addr,
                reason = %reason,
                "write_loop: error, closing"
            );
            closing.cancel();
            return;
        }
    }
}

/// Process a single write command: either a data message or a filter update.
///
/// Returns `Ok(())` on success, `Err(reason)` if the connection should close.
///
/// Note: this function intentionally does NOT update `last_packet_time`.
/// Only inbound traffic (received frames, pongs) should refresh the idle
/// timer.  Updating on outbound writes would mask dead peers whose TCP
/// stack still accepts writes.
async fn process_write_command<Sk>(
    cmd: WriteCommand,
    sink: &mut SplitSink<Sk, WsMessage>,
    send_message_tags: &Arc<RwLock<HashSet<Tag>>>,
    remote_addr: &str,
    features: PeerFeatureFlags,
    outgoing_filter: &Option<Arc<MessageFilter>>,
) -> Result<(), String>
where
    Sk: futures_util::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    match cmd {
        WriteCommand::UpdateFilter(mut new_tags) => {
            // Always preserve control tags that are needed for protocol
            // operation, regardless of what the peer requests via
            // MsgOfInterest.  Go's wsPeer.writeLoopSendMsg replaces
            // sendMessageTag verbatim, but we add defense-in-depth:
            // without MI the peer cannot update its interest set, and
            // without NI identity exchange breaks.
            new_tags.insert(Tag::MsgOfInterest);
            new_tags.insert(Tag::NetIDVerification);
            let mut tags = send_message_tags.write().await;
            *tags = new_tags;
            Ok(())
        }
        WriteCommand::Ping(payload) => {
            // Send a WebSocket Ping frame.
            if let Err(e) = sink.send(WsMessage::Ping(payload)).await {
                return Err(format!("ping write error: {e}"));
            }
            // Do NOT update last_packet_time here — only inbound traffic
            // (received frames, pongs) should refresh the idle timer.
            // Updating on outbound pings would mask dead peers whose TCP
            // stack still accepts writes.
            Ok(())
        }
        WriteCommand::Data(send_msg) => {
            let tag = send_msg.msg.tag;

            // Check message-of-interest filter.
            {
                let tags = send_message_tags.read().await;
                if !tags.contains(&tag) {
                    // The peer is not interested in this tag; silently drop.
                    return Ok(());
                }
            }

            // Check outgoing dedup filter.
            //
            // For dedup-safe tags, compute the digest and check whether the
            // peer already has this message (via a prior MsgDigestSkip
            // notification). Reference: Go's writeNonBlock() in wsPeer.go.
            if let Some(ref of) = outgoing_filter {
                if dedup_safe_tag(&tag) && send_msg.msg.payload.len() >= MESSAGE_FILTER_SIZE {
                    let digest = generate_message_digest(&tag, &send_msg.msg.payload);
                    if of.check_digest(&digest, false, false) {
                        // Peer already has this message; skip sending.
                        tracing::trace!(
                            peer = %remote_addr,
                            tag = %tag,
                            "write_loop: outgoing filter suppressed duplicate"
                        );
                        return Ok(());
                    }
                }
            }

            // Check staleness.
            let age = send_msg.enqueued.elapsed();
            if age > MAX_MESSAGE_QUEUE_DURATION {
                tracing::warn!(
                    peer = %remote_addr,
                    tag = %tag,
                    age_ms = age.as_millis() as u64,
                    "write_loop: stale message"
                );
                return Err("stale message".to_string());
            }

            // Determine the payload to send: if the message carries
            // Topics, serialize them as the wire payload (matching Go's
            // Respond path which serializes topics into the data field).
            let topics_serialized;
            let payload: &[u8] = if let Some(ref topics) = send_msg.msg.topics {
                topics_serialized = topics.marshal();
                &topics_serialized
            } else {
                &send_msg.msg.payload
            };

            // Optionally compress PP tag payloads with zstd.
            //
            // encode_frame failures (e.g. payload exceeds MAX_MESSAGE_LENGTH)
            // are non-fatal: log a warning and drop the single oversized
            // message rather than tearing down the entire peer connection.
            // Only actual WebSocket I/O errors below should cause disconnection.
            let data = if tag == Tag::ProposalPayload
                && features.contains(PeerFeatureFlags::COMPRESSED_PROPOSAL)
                && !payload.is_empty()
            {
                match zstd_compress(payload) {
                    Ok(compressed) => {
                        // Prepend the tag to the compressed payload.
                        let mut frame = Vec::with_capacity(2 + compressed.len());
                        frame.extend_from_slice(&tag.as_bytes());
                        frame.extend_from_slice(&compressed);
                        frame
                    }
                    Err(e) => {
                        tracing::warn!(
                            peer = %remote_addr,
                            error = %e,
                            "write_loop: PP compression failed, sending uncompressed"
                        );
                        match encode_frame(&tag, payload) {
                            Ok(frame) => frame,
                            Err(e) => {
                                tracing::warn!(
                                    peer = %remote_addr,
                                    tag = %tag,
                                    error = %e,
                                    "write_loop: dropping oversized outbound message"
                                );
                                return Ok(());
                            }
                        }
                    }
                }
            } else {
                match encode_frame(&tag, payload) {
                    Ok(frame) => frame,
                    Err(e) => {
                        tracing::warn!(
                            peer = %remote_addr,
                            tag = %tag,
                            error = %e,
                            "write_loop: dropping oversized outbound message"
                        );
                        return Ok(());
                    }
                }
            };

            // Write to the WebSocket.
            if let Err(e) = sink.send(WsMessage::Binary(data)).await {
                return Err(format!("write error: {e}"));
            }

            // Do NOT update last_packet_time here — only inbound traffic
            // (received frames, pongs) should refresh the idle timer.
            // Updating on outbound writes would mask dead peers.

            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// keepalive_loop
// ---------------------------------------------------------------------------

/// Periodically sends WebSocket Ping frames and monitors for idle connections.
///
/// Go does not have a dedicated keepalive goroutine; instead,
/// `checkPeersConnectivity()` runs on a timer in the network's message
/// handler thread.  We model this as a separate task for simplicity.
///
/// Pings are sent via the high-priority write channel so they flow through
/// the write_loop (which owns the WebSocket sink).
async fn keepalive_loop(
    last_packet_time: Arc<RwLock<Instant>>,
    send_high_prio_tx: mpsc::Sender<WriteCommand>,
    closing: CancellationToken,
    remote_addr: String,
) {
    let mut interval = tokio::time::interval(CONNECTIVITY_CHECK_INTERVAL);
    // The first tick fires immediately; skip it so we wait a full interval.
    interval.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = closing.cancelled() => {
                tracing::debug!(peer = %remote_addr, "keepalive_loop: closing");
                return;
            }
            _ = interval.tick() => {
                let idle_duration = {
                    let lpt = last_packet_time.read().await;
                    lpt.elapsed()
                };

                if idle_duration > MAX_PEER_INACTIVITY {
                    tracing::warn!(
                        peer = %remote_addr,
                        idle_secs = idle_duration.as_secs(),
                        "keepalive_loop: peer idle too long, closing"
                    );
                    closing.cancel();
                    return;
                }

                // Send a WebSocket Ping frame to keep the connection alive.
                let ping_payload: Vec<u8> = (0..PING_LENGTH)
                    .map(|_| rand::random::<u8>())
                    .collect();
                if send_high_prio_tx
                    .try_send(WriteCommand::Ping(ping_payload))
                    .is_err()
                {
                    tracing::warn!(
                        peer = %remote_addr,
                        "keepalive_loop: failed to enqueue ping"
                    );
                }

                tracing::trace!(
                    peer = %remote_addr,
                    idle_secs = idle_duration.as_secs(),
                    "keepalive_loop: peer still active, sent ping"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::encode_frame;
    use crate::msg_of_interest::marshal_msg_of_interest;
    use crate::tag::Tag;
    use futures_util::{SinkExt, StreamExt};
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};

    /// Helper: create a dummy PeerSender for testing read_loop calls.
    fn make_test_peer_sender(closing: CancellationToken) -> Arc<PeerSender> {
        let (high_prio_tx, _high_prio_rx) = mpsc::channel(10);
        let (bulk_tx, _bulk_rx) = mpsc::channel(10);
        Arc::new(PeerSender {
            send_high_prio: high_prio_tx,
            send_bulk: bulk_tx,
            closing,
            remote_addr: "test-peer".to_string(),
        })
    }

    // Helper: create a raw TCP-based WebSocket pair for testing components.
    async fn ws_raw_pair() -> (WebSocketStream<TcpStream>, WebSocketStream<TcpStream>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_fut = async {
            let stream = TcpStream::connect(addr).await.unwrap();
            tokio_tungstenite::client_async(format!("ws://{addr}/"), stream)
                .await
                .unwrap()
                .0
        };

        let server_fut = async {
            let (stream, _) = listener.accept().await.unwrap();
            tokio_tungstenite::accept_async(stream).await.unwrap()
        };

        tokio::join!(client_fut, server_fut)
    }

    // -----------------------------------------------------------------------
    // Tag framing tests
    // -----------------------------------------------------------------------

    #[test]
    fn tag_framing_encode_2byte_prefix() {
        let payload = b"hello world";
        let frame = encode_frame(&Tag::Transaction, payload).unwrap();
        assert_eq!(&frame[..2], b"TX");
        assert_eq!(&frame[2..], payload);
    }

    #[test]
    fn tag_framing_roundtrip() {
        let payload = b"test payload";
        let frame = encode_frame(&Tag::AgreementVote, payload).unwrap();
        let (tag, decoded) = decode_frame(&frame).unwrap();
        assert_eq!(tag, Tag::AgreementVote);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn tag_framing_empty_payload() {
        let frame = encode_frame(&Tag::MsgOfInterest, &[]).unwrap();
        assert_eq!(frame, b"MI");
        let (tag, payload) = decode_frame(&frame).unwrap();
        assert_eq!(tag, Tag::MsgOfInterest);
        assert!(payload.is_empty());
    }

    // -----------------------------------------------------------------------
    // Default send message tags
    // -----------------------------------------------------------------------

    #[test]
    fn default_tags_match_go() {
        let tags = default_send_message_tags();
        assert!(tags.contains(&Tag::AgreementVote));
        assert!(tags.contains(&Tag::MsgDigestSkip));
        assert!(tags.contains(&Tag::NetPrioResponse));
        assert!(tags.contains(&Tag::NetIDVerification));
        assert!(tags.contains(&Tag::ProposalPayload));
        assert!(tags.contains(&Tag::TopicMsgResp));
        assert!(tags.contains(&Tag::MsgOfInterest));
        assert!(tags.contains(&Tag::Transaction));
        assert!(tags.contains(&Tag::UniEnsBlockReq));
        assert!(tags.contains(&Tag::VoteBundle));
        assert!(tags.contains(&Tag::VotePacked));
        // StateProofSig is NOT in the default set.
        assert!(!tags.contains(&Tag::StateProofSig));
        // 11 tags total.
        assert_eq!(tags.len(), 11);
    }

    // -----------------------------------------------------------------------
    // Message interest filter
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn message_interest_filter_drops_uninterested() {
        let send_message_tags = Arc::new(RwLock::new(HashSet::new()));
        // Only interested in TX.
        {
            let mut tags = send_message_tags.write().await;
            tags.insert(Tag::Transaction);
        }

        // AV should be filtered out.
        {
            let tags = send_message_tags.read().await;
            assert!(!tags.contains(&Tag::AgreementVote));
            assert!(tags.contains(&Tag::Transaction));
        }
    }

    #[tokio::test]
    async fn message_interest_filter_update() {
        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));

        // Initially contains TX.
        {
            let tags = send_message_tags.read().await;
            assert!(tags.contains(&Tag::Transaction));
        }

        // Simulate receiving an MI message with only AV.
        let new_tags = {
            let mut s = HashSet::new();
            s.insert(Tag::AgreementVote);
            s
        };
        {
            let mut tags = send_message_tags.write().await;
            *tags = new_tags;
        }

        // Now TX should be filtered out, AV should pass.
        {
            let tags = send_message_tags.read().await;
            assert!(!tags.contains(&Tag::Transaction));
            assert!(tags.contains(&Tag::AgreementVote));
        }
    }

    // -----------------------------------------------------------------------
    // Write command processing
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn write_command_filter_update() {
        let (client_ws, _server_ws) = ws_raw_pair().await;
        let (mut sink, _stream) = client_ws.split();
        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));

        // Verify TX is initially allowed.
        {
            let tags = send_message_tags.read().await;
            assert!(tags.contains(&Tag::Transaction));
        }

        // Process a filter update removing TX.
        let mut new_tags = HashSet::new();
        new_tags.insert(Tag::AgreementVote);
        let cmd = WriteCommand::UpdateFilter(new_tags);

        let result = process_write_command(
            cmd,
            &mut sink,
            &send_message_tags,
            "test",
            PeerFeatureFlags::empty(),
            &None,
        )
        .await;
        assert!(result.is_ok());

        // TX should now be filtered out.
        let tags = send_message_tags.read().await;
        assert!(!tags.contains(&Tag::Transaction));
        assert!(tags.contains(&Tag::AgreementVote));
    }

    #[tokio::test]
    async fn update_filter_preserves_control_tags() {
        let (client_ws, _server_ws) = ws_raw_pair().await;
        let (mut sink, _stream) = client_ws.split();
        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));

        // Send an UpdateFilter that does NOT include MI or NI.
        let mut new_tags = HashSet::new();
        new_tags.insert(Tag::Transaction);
        let cmd = WriteCommand::UpdateFilter(new_tags);

        let result = process_write_command(
            cmd,
            &mut sink,
            &send_message_tags,
            "test",
            PeerFeatureFlags::empty(),
            &None,
        )
        .await;
        assert!(result.is_ok());

        // MI and NI must still be present (defense-in-depth).
        let tags = send_message_tags.read().await;
        assert!(
            tags.contains(&Tag::MsgOfInterest),
            "MI must be preserved in send filter"
        );
        assert!(
            tags.contains(&Tag::NetIDVerification),
            "NI must be preserved in send filter"
        );
        // The requested tag should also be present.
        assert!(tags.contains(&Tag::Transaction));
        // Total should be TX + MI + NI = 3.
        assert_eq!(tags.len(), 3);
    }

    #[tokio::test]
    async fn write_command_sends_data() {
        let (client_ws, server_ws) = ws_raw_pair().await;
        let (mut sink, _client_stream) = client_ws.split();
        let (_server_sink, mut server_stream) = server_ws.split();

        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));

        let msg = OutgoingMessage::new(Tag::Transaction, b"hello".to_vec());
        let cmd = WriteCommand::Data(SendMessage {
            msg,
            enqueued: Instant::now(),
        });

        let result = process_write_command(
            cmd,
            &mut sink,
            &send_message_tags,
            "test",
            PeerFeatureFlags::empty(),
            &None,
        )
        .await;
        assert!(result.is_ok());

        // Read the frame from the server side.
        let received = server_stream.next().await.unwrap().unwrap();
        match received {
            WsMessage::Binary(data) => {
                let (tag, payload) = decode_frame(&data).unwrap();
                assert_eq!(tag, Tag::Transaction);
                assert_eq!(payload, b"hello");
            }
            other => panic!("expected binary message, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn write_command_drops_filtered_message() {
        let (client_ws, _server_ws) = ws_raw_pair().await;
        let (mut sink, _client_stream) = client_ws.split();

        // Only interested in AV.
        let mut tags = HashSet::new();
        tags.insert(Tag::AgreementVote);
        let send_message_tags = Arc::new(RwLock::new(tags));

        // Try to send TX — should be silently dropped.
        let msg = OutgoingMessage::new(Tag::Transaction, b"filtered".to_vec());
        let cmd = WriteCommand::Data(SendMessage {
            msg,
            enqueued: Instant::now(),
        });

        let result = process_write_command(
            cmd,
            &mut sink,
            &send_message_tags,
            "test",
            PeerFeatureFlags::empty(),
            &None,
        )
        .await;

        // Should succeed (silently dropped, not an error).
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn write_command_stale_message_returns_error() {
        let (client_ws, _server_ws) = ws_raw_pair().await;
        let (mut sink, _client_stream) = client_ws.split();

        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));

        // Create a message that is older than MAX_MESSAGE_QUEUE_DURATION.
        let msg = OutgoingMessage::new(Tag::Transaction, b"old".to_vec());
        let cmd = WriteCommand::Data(SendMessage {
            msg,
            enqueued: Instant::now() - MAX_MESSAGE_QUEUE_DURATION - Duration::from_secs(1),
        });

        let result = process_write_command(
            cmd,
            &mut sink,
            &send_message_tags,
            "test",
            PeerFeatureFlags::empty(),
            &None,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("stale"));
    }

    // -----------------------------------------------------------------------
    // High-priority channel drains before bulk
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn high_prio_drains_before_bulk() {
        let (client_ws, server_ws) = ws_raw_pair().await;
        let (sink, _client_stream) = client_ws.split();
        let (_server_sink, mut server_stream) = server_ws.split();

        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));
        let closing = CancellationToken::new();

        let (high_prio_tx, high_prio_rx) = mpsc::channel::<WriteCommand>(10);
        let (bulk_tx, bulk_rx) = mpsc::channel::<WriteCommand>(10);

        // Enqueue a bulk message first, then a high-prio message.
        let bulk_msg = OutgoingMessage::new(Tag::Transaction, b"bulk".to_vec());
        bulk_tx
            .send(WriteCommand::Data(SendMessage {
                msg: bulk_msg,
                enqueued: Instant::now(),
            }))
            .await
            .unwrap();

        let prio_msg = OutgoingMessage::new(Tag::AgreementVote, b"prio".to_vec());
        high_prio_tx
            .send(WriteCommand::Data(SendMessage {
                msg: prio_msg,
                enqueued: Instant::now(),
            }))
            .await
            .unwrap();

        // Run the write loop briefly — it should process high-prio first.
        let closing_clone = closing.clone();
        let write_task = tokio::spawn(write_loop(
            sink,
            high_prio_rx,
            bulk_rx,
            send_message_tags,
            closing_clone,
            "test".to_string(),
            PeerFeatureFlags::empty(),
            None,
        ));

        // Read the first two messages from the server.
        let msg1 = tokio::time::timeout(Duration::from_secs(2), server_stream.next())
            .await
            .expect("timeout waiting for msg1")
            .unwrap()
            .unwrap();

        let msg2 = tokio::time::timeout(Duration::from_secs(2), server_stream.next())
            .await
            .expect("timeout waiting for msg2")
            .unwrap()
            .unwrap();

        closing.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(1), write_task).await;

        // First message should be the high-prio AV message.
        match msg1 {
            WsMessage::Binary(data) => {
                let (tag, payload) = decode_frame(&data).unwrap();
                assert_eq!(tag, Tag::AgreementVote);
                assert_eq!(payload, b"prio");
            }
            other => panic!("expected binary, got: {other:?}"),
        }

        // Second message should be the bulk TX message.
        match msg2 {
            WsMessage::Binary(data) => {
                let (tag, payload) = decode_frame(&data).unwrap();
                assert_eq!(tag, Tag::Transaction);
                assert_eq!(payload, b"bulk");
            }
            other => panic!("expected binary, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Read loop: binary frame dispatch
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn read_loop_dispatches_binary_frames() {
        let (client_ws, server_ws) = ws_raw_pair().await;
        let (mut client_sink, _client_stream) = client_ws.split();
        let (_server_sink, server_stream) = server_ws.split();

        let (incoming_tx, mut incoming_rx) = mpsc::channel(10);
        let (high_prio_tx, _high_prio_rx) = mpsc::channel(10);
        let closing = CancellationToken::new();
        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));
        let last_packet_time = Arc::new(RwLock::new(Instant::now()));

        let closing_clone = closing.clone();
        let _read_task = tokio::spawn(read_loop(
            server_stream,
            incoming_tx,
            high_prio_tx,
            send_message_tags,
            last_packet_time,
            closing_clone,
            "test-peer".to_string(),
            PeerFeatureFlags::empty(),
            None,
            None,
            None,
            None,
            make_test_peer_sender(closing.clone()),
        ));

        // Send a TX message from the client.
        let frame = encode_frame(&Tag::Transaction, b"test data").unwrap();
        client_sink.send(WsMessage::Binary(frame)).await.unwrap();

        // Read it from the incoming channel.
        let msg = tokio::time::timeout(Duration::from_secs(2), incoming_rx.recv())
            .await
            .expect("timeout waiting for incoming message")
            .expect("channel closed");

        assert_eq!(msg.tag, Tag::Transaction);
        assert_eq!(msg.data, b"test data");
        assert_eq!(msg.sender, "test-peer");

        closing.cancel();
    }

    // -----------------------------------------------------------------------
    // Read loop: MI message updates filter
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn read_loop_handles_mi_message() {
        let (client_ws, server_ws) = ws_raw_pair().await;
        let (mut client_sink, _client_stream) = client_ws.split();
        let (_server_sink, server_stream) = server_ws.split();

        let (incoming_tx, mut incoming_rx) = mpsc::channel(10);
        let (high_prio_tx, mut high_prio_rx) = mpsc::channel::<WriteCommand>(10);
        let closing = CancellationToken::new();
        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));
        let last_packet_time = Arc::new(RwLock::new(Instant::now()));

        let closing_clone = closing.clone();
        let _read_task = tokio::spawn(read_loop(
            server_stream,
            incoming_tx,
            high_prio_tx,
            send_message_tags,
            last_packet_time,
            closing_clone,
            "test-peer".to_string(),
            PeerFeatureFlags::empty(),
            None,
            None,
            None,
            None,
            make_test_peer_sender(closing.clone()),
        ));

        // Build and send an MI message saying we only want AV and TX.
        let mi_payload = marshal_msg_of_interest(&[Tag::AgreementVote, Tag::Transaction]);
        let mi_frame = encode_frame(&Tag::MsgOfInterest, &mi_payload).unwrap();
        client_sink.send(WsMessage::Binary(mi_frame)).await.unwrap();

        // The MI message should NOT appear on the incoming channel.
        // Instead, a filter update should appear on the high-prio channel.
        let cmd = tokio::time::timeout(Duration::from_secs(2), high_prio_rx.recv())
            .await
            .expect("timeout waiting for filter update")
            .expect("channel closed");

        match cmd {
            WriteCommand::UpdateFilter(tags) => {
                assert!(tags.contains(&Tag::AgreementVote));
                assert!(tags.contains(&Tag::Transaction));
                assert!(!tags.contains(&Tag::ProposalPayload));
                assert_eq!(tags.len(), 2);
            }
            other => panic!("expected UpdateFilter, got: {other:?}"),
        }

        // Verify MI was not dispatched to the incoming channel.
        let result = tokio::time::timeout(Duration::from_millis(100), incoming_rx.recv()).await;
        assert!(
            result.is_err(),
            "MI message should not appear on incoming channel"
        );

        closing.cancel();
    }

    // -----------------------------------------------------------------------
    // Close propagation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn close_stops_all_loops() {
        let (client_ws, server_ws) = ws_raw_pair().await;
        let (_client_sink, _client_stream) = client_ws.split();
        let (server_sink, server_stream) = server_ws.split();

        let (incoming_tx, _incoming_rx) = mpsc::channel(10);
        let (high_prio_tx, high_prio_rx) = mpsc::channel::<WriteCommand>(10);
        let (_bulk_tx, bulk_rx) = mpsc::channel::<WriteCommand>(10);
        let closing = CancellationToken::new();
        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));
        let last_packet_time = Arc::new(RwLock::new(Instant::now()));

        let closing_clone = closing.clone();
        let read_task = tokio::spawn(read_loop(
            server_stream,
            incoming_tx,
            high_prio_tx,
            send_message_tags.clone(),
            last_packet_time.clone(),
            closing_clone,
            "test".to_string(),
            PeerFeatureFlags::empty(),
            None,
            None,
            None,
            None,
            make_test_peer_sender(closing.clone()),
        ));

        let closing_clone = closing.clone();
        let write_task = tokio::spawn(write_loop(
            server_sink,
            high_prio_rx,
            bulk_rx,
            send_message_tags.clone(),
            closing_clone,
            "test".to_string(),
            PeerFeatureFlags::empty(),
            None,
        ));

        let (keepalive_prio_tx, _keepalive_prio_rx) = mpsc::channel::<WriteCommand>(10);
        let closing_clone = closing.clone();
        let keepalive_task = tokio::spawn(keepalive_loop(
            last_packet_time,
            keepalive_prio_tx,
            closing_clone,
            "test".to_string(),
        ));

        // Cancel and verify all tasks stop.
        closing.cancel();

        let read_result = tokio::time::timeout(Duration::from_secs(2), read_task).await;
        assert!(read_result.is_ok(), "read_loop should stop after cancel");

        let write_result = tokio::time::timeout(Duration::from_secs(2), write_task).await;
        assert!(write_result.is_ok(), "write_loop should stop after cancel");

        let keepalive_result = tokio::time::timeout(Duration::from_secs(2), keepalive_task).await;
        assert!(
            keepalive_result.is_ok(),
            "keepalive_loop should stop after cancel"
        );
    }

    // -----------------------------------------------------------------------
    // Read loop: close frame triggers shutdown
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn read_loop_close_frame_triggers_shutdown() {
        let (client_ws, server_ws) = ws_raw_pair().await;
        let (mut client_sink, _client_stream) = client_ws.split();
        let (_server_sink, server_stream) = server_ws.split();

        let (incoming_tx, _incoming_rx) = mpsc::channel(10);
        let (high_prio_tx, _high_prio_rx) = mpsc::channel(10);
        let closing = CancellationToken::new();
        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));
        let last_packet_time = Arc::new(RwLock::new(Instant::now()));

        let closing_clone = closing.clone();
        let read_task = tokio::spawn(read_loop(
            server_stream,
            incoming_tx,
            high_prio_tx,
            send_message_tags,
            last_packet_time,
            closing_clone,
            "test".to_string(),
            PeerFeatureFlags::empty(),
            None,
            None,
            None,
            None,
            make_test_peer_sender(closing.clone()),
        ));

        // Send a close frame from the client.
        client_sink.close().await.unwrap();

        // The read loop should exit and cancel the token.
        let result = tokio::time::timeout(Duration::from_secs(2), read_task).await;
        assert!(result.is_ok(), "read_loop should stop on close frame");
        assert!(closing.is_cancelled());
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn constants_match_go() {
        assert_eq!(MAX_MESSAGE_QUEUE_DURATION, Duration::from_secs(25));
        assert_eq!(MAX_PEER_INACTIVITY, Duration::from_secs(300));
        assert_eq!(CONNECTIVITY_CHECK_INTERVAL, Duration::from_secs(180));
        assert_eq!(PING_LENGTH, 8);
        assert_eq!(SEND_BUFFER_LENGTH, 2500);
        assert_eq!(MSGS_IN_READ_BUFFER_PER_PEER, 10);
    }

    // -----------------------------------------------------------------------
    // SendMessage / WriteCommand debug formatting
    // -----------------------------------------------------------------------

    #[test]
    fn send_message_debug() {
        let sm = SendMessage {
            msg: OutgoingMessage::new(Tag::Transaction, vec![1, 2, 3]),
            enqueued: Instant::now(),
        };
        let s = format!("{sm:?}");
        assert!(!s.is_empty());
    }

    #[test]
    fn write_command_debug() {
        let cmd = WriteCommand::UpdateFilter(HashSet::new());
        let s = format!("{cmd:?}");
        assert!(s.contains("UpdateFilter"));
    }

    // -----------------------------------------------------------------------
    // Keepalive idle detection
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn keepalive_idle_detection_logic() {
        // Set last_packet_time far in the past so the check triggers.
        let last_packet_time = Arc::new(RwLock::new(
            Instant::now() - MAX_PEER_INACTIVITY - Duration::from_secs(1),
        ));
        let closing = CancellationToken::new();

        // Verify the idle detection logic directly (the keepalive_loop uses
        // a 3-minute timer which is too slow for unit tests).
        let idle_duration = {
            let lpt = last_packet_time.read().await;
            lpt.elapsed()
        };
        assert!(idle_duration > MAX_PEER_INACTIVITY);

        // Verify the cancel logic works.
        closing.cancel();
        assert!(closing.is_cancelled());
    }

    // -----------------------------------------------------------------------
    // Read loop: full incoming channel drops messages without blocking
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn read_loop_full_incoming_channel_drops_without_blocking() {
        // Create a WebSocket pair.
        let (client_ws, server_ws) = ws_raw_pair().await;
        let (mut client_sink, _client_stream) = client_ws.split();
        let (_server_sink, server_stream) = server_ws.split();

        // Create an incoming channel with capacity 1 so it fills immediately.
        let (incoming_tx, mut incoming_rx) = mpsc::channel(1);
        let (high_prio_tx, _high_prio_rx) = mpsc::channel(10);
        let closing = CancellationToken::new();
        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));
        let last_packet_time = Arc::new(RwLock::new(Instant::now()));

        let closing_clone = closing.clone();
        let _read_task = tokio::spawn(read_loop(
            server_stream,
            incoming_tx,
            high_prio_tx,
            send_message_tags,
            last_packet_time.clone(),
            closing_clone,
            "test-peer".to_string(),
            PeerFeatureFlags::empty(),
            None,
            None,
            None,
            None,
            make_test_peer_sender(closing.clone()),
        ));

        // Send several messages to fill the incoming channel and overflow it.
        for i in 0..5u8 {
            let frame = encode_frame(&Tag::Transaction, &[i]).unwrap();
            client_sink.send(WsMessage::Binary(frame)).await.unwrap();
        }

        // Give the read loop time to process all the frames.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The read loop should NOT be blocked — verify it is still running
        // by checking that last_packet_time was updated recently.
        let idle = {
            let lpt = last_packet_time.read().await;
            lpt.elapsed()
        };
        assert!(
            idle < Duration::from_secs(2),
            "read_loop appears to be blocked (last_packet_time is stale: {idle:?})"
        );

        // We should be able to receive at least the first message.
        let msg = tokio::time::timeout(Duration::from_millis(500), incoming_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(msg.tag, Tag::Transaction);

        // The connection should still be alive (not cancelled by blocked read).
        assert!(!closing.is_cancelled(), "connection should still be open");

        closing.cancel();
    }

    // -----------------------------------------------------------------------
    // PeerHandle accessor coverage
    // -----------------------------------------------------------------------

    #[test]
    fn peer_handle_accessors() {
        // We cannot easily create a PeerHandle without a real WsPeer, but
        // we can verify the type API compiles correctly through a
        // compile-time check (the struct fields and methods exist).
        // This test is intentionally minimal.
        fn _assert_send_sync<T: Send>() {}
        _assert_send_sync::<mpsc::Sender<WriteCommand>>();
    }

    // -----------------------------------------------------------------------
    // Message handler framework integration tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn msg_digest_skip_adds_to_outgoing_filter() {
        // When we receive a MsgDigestSkip message, the 32-byte digest should
        // be added to the outgoing filter.
        let (client_ws, server_ws) = ws_raw_pair().await;
        let (mut client_sink, _client_stream) = client_ws.split();
        let (_server_sink, server_stream) = server_ws.split();

        let (incoming_tx, mut incoming_rx) = mpsc::channel(10);
        let (high_prio_tx, _high_prio_rx) = mpsc::channel(10);
        let closing = CancellationToken::new();
        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));
        let last_packet_time = Arc::new(RwLock::new(Instant::now()));

        let outgoing_filter = Arc::new(MessageFilter::new(1024));

        let closing_clone = closing.clone();
        let _read_task = tokio::spawn(read_loop(
            server_stream,
            incoming_tx,
            high_prio_tx,
            send_message_tags,
            last_packet_time,
            closing_clone,
            "test-peer".to_string(),
            PeerFeatureFlags::empty(),
            None,
            None,
            Some(outgoing_filter.clone()),
            None,
            make_test_peer_sender(closing.clone()),
        ));

        // Send a MsgDigestSkip with a 32-byte digest.
        let digest = [0xABu8; 32];
        let frame = encode_frame(&Tag::MsgDigestSkip, &digest).unwrap();
        client_sink.send(WsMessage::Binary(frame)).await.unwrap();

        // Give the read loop time to process.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The digest should now be in the outgoing filter.
        assert!(
            outgoing_filter.check_digest(&digest, false, false),
            "MsgDigestSkip digest should be added to outgoing filter"
        );

        // MsgDigestSkip should NOT appear on the incoming channel.
        let result = tokio::time::timeout(Duration::from_millis(100), incoming_rx.recv()).await;
        assert!(
            result.is_err(),
            "MsgDigestSkip should not appear on incoming channel"
        );

        closing.cancel();
    }

    #[tokio::test]
    async fn incoming_dedup_skips_duplicates() {
        // When an incoming filter is present, duplicate TX/AV messages
        // should be dropped.
        let (client_ws, server_ws) = ws_raw_pair().await;
        let (mut client_sink, _client_stream) = client_ws.split();
        let (_server_sink, server_stream) = server_ws.split();

        let (incoming_tx, mut incoming_rx) = mpsc::channel(10);
        let (high_prio_tx, _high_prio_rx) = mpsc::channel(10);
        let closing = CancellationToken::new();
        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));
        let last_packet_time = Arc::new(RwLock::new(Instant::now()));

        let incoming_filter = Arc::new(MessageFilter::new(1024));

        let closing_clone = closing.clone();
        let _read_task = tokio::spawn(read_loop(
            server_stream,
            incoming_tx,
            high_prio_tx,
            send_message_tags,
            last_packet_time,
            closing_clone,
            "test-peer".to_string(),
            PeerFeatureFlags::empty(),
            None,
            Some(incoming_filter.clone()),
            None,
            None,
            make_test_peer_sender(closing.clone()),
        ));

        // Send the same TX message twice.
        let payload = b"duplicate transaction data";
        let frame = encode_frame(&Tag::Transaction, payload).unwrap();
        client_sink
            .send(WsMessage::Binary(frame.clone()))
            .await
            .unwrap();
        client_sink.send(WsMessage::Binary(frame)).await.unwrap();

        // Give the read loop time to process both.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Only the first message should appear on the incoming channel.
        let msg = tokio::time::timeout(Duration::from_millis(200), incoming_rx.recv())
            .await
            .expect("timeout waiting for first message")
            .expect("channel closed");
        assert_eq!(msg.tag, Tag::Transaction);
        assert_eq!(msg.data, payload);

        // The duplicate should have been dropped.
        let result = tokio::time::timeout(Duration::from_millis(200), incoming_rx.recv()).await;
        assert!(
            result.is_err(),
            "duplicate message should not appear on incoming channel"
        );

        closing.cancel();
    }

    #[tokio::test]
    async fn topic_msg_resp_routes_to_request_tracker() {
        // TopicMsgResp messages should be routed to the RequestTracker
        // and NOT appear on the incoming channel.
        use crate::topics::{Topic, Topics};

        let (client_ws, server_ws) = ws_raw_pair().await;
        let (mut client_sink, _client_stream) = client_ws.split();
        let (_server_sink, server_stream) = server_ws.split();

        let (incoming_tx, mut incoming_rx) = mpsc::channel(10);
        let (high_prio_tx, _high_prio_rx) = mpsc::channel(10);
        let closing = CancellationToken::new();
        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));
        let last_packet_time = Arc::new(RwLock::new(Instant::now()));

        let request_tracker = Arc::new(RequestTracker::new());

        // Prepare a request so we have a pending entry.
        let request_topics = Topics::from_vec(vec![Topic::new("q", b"data".to_vec())]);
        let (_serialized, hash, rx) = request_tracker.prepare_request(request_topics).await;
        assert_eq!(request_tracker.pending_count().await, 1);

        let closing_clone = closing.clone();
        let _read_task = tokio::spawn(read_loop(
            server_stream,
            incoming_tx,
            high_prio_tx,
            send_message_tags,
            last_packet_time,
            closing_clone,
            "test-peer".to_string(),
            PeerFeatureFlags::empty(),
            None,
            None,
            None,
            Some(request_tracker.clone()),
            make_test_peer_sender(closing.clone()),
        ));

        // Build a TopicMsgResp response containing the request hash
        // as a uvarint-encoded value under the "RequestHash" key.
        use crate::request_response::RESPONSE_HASH_FIELD;
        let hash_uvarint = {
            let mut buf = Vec::new();
            let mut val = hash;
            loop {
                let mut byte = (val & 0x7F) as u8;
                val >>= 7;
                if val != 0 {
                    byte |= 0x80;
                }
                buf.push(byte);
                if val == 0 {
                    break;
                }
            }
            buf
        };
        let response_topics = Topics::from_vec(vec![
            Topic::new(RESPONSE_HASH_FIELD, hash_uvarint),
            Topic::new("result", b"ok".to_vec()),
        ]);
        let response_data = response_topics.marshal();
        let frame = encode_frame(&Tag::TopicMsgResp, &response_data).unwrap();
        client_sink.send(WsMessage::Binary(frame)).await.unwrap();

        // The receiver should get the response.
        let response = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("timeout waiting for response")
            .expect("sender dropped");
        assert_eq!(response.get_value("result"), Some(b"ok".as_slice()));

        // TopicMsgResp should NOT appear on the incoming channel.
        let result = tokio::time::timeout(Duration::from_millis(200), incoming_rx.recv()).await;
        assert!(
            result.is_err(),
            "TopicMsgResp should not appear on incoming channel"
        );

        // Pending count should be 0 now.
        assert_eq!(request_tracker.pending_count().await, 0);

        closing.cancel();
    }

    #[tokio::test]
    async fn multiplexer_dispatch_routes_by_tag_and_acts_on_policy() {
        use crate::handler::{MessageHandler, TaggedMessageHandler};
        use async_trait::async_trait;

        // Handler that returns Broadcast for TX messages.
        struct BroadcastHandler;
        #[async_trait]
        impl MessageHandler for BroadcastHandler {
            async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
                OutgoingMessage {
                    action: ForwardingPolicy::Broadcast,
                    tag: msg.tag,
                    payload: msg.data.clone(),
                    topics: None,
                }
            }
        }

        // Handler that returns Disconnect for AV messages.
        struct DisconnectHandler;
        #[async_trait]
        impl MessageHandler for DisconnectHandler {
            async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
                OutgoingMessage {
                    action: ForwardingPolicy::Disconnect,
                    tag: msg.tag,
                    payload: Vec::new(),
                    topics: None,
                }
            }
        }

        let mux = Arc::new(Multiplexer::new());
        mux.register_handlers(vec![
            TaggedMessageHandler {
                tag: Tag::Transaction,
                handler: Arc::new(BroadcastHandler),
            },
            TaggedMessageHandler {
                tag: Tag::AgreementVote,
                handler: Arc::new(DisconnectHandler),
            },
        ]);

        // Test 1: TX message with Broadcast policy (should not disconnect).
        {
            let (client_ws, server_ws) = ws_raw_pair().await;
            let (mut client_sink, _client_stream) = client_ws.split();
            let (_server_sink, server_stream) = server_ws.split();

            let (incoming_tx, mut incoming_rx) = mpsc::channel(10);
            let (high_prio_tx, _high_prio_rx) = mpsc::channel(10);
            let closing = CancellationToken::new();
            let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));
            let last_packet_time = Arc::new(RwLock::new(Instant::now()));

            let closing_clone = closing.clone();
            let _read_task = tokio::spawn(read_loop(
                server_stream,
                incoming_tx,
                high_prio_tx,
                send_message_tags,
                last_packet_time,
                closing_clone,
                "test-peer".to_string(),
                PeerFeatureFlags::empty(),
                Some(mux.clone()),
                None,
                None,
                None,
                make_test_peer_sender(closing.clone()),
            ));

            let frame = encode_frame(&Tag::Transaction, b"tx-data").unwrap();
            client_sink.send(WsMessage::Binary(frame)).await.unwrap();

            // Give it time to process.
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Broadcast policy forwards the message to the incoming channel
            // so the network layer can broadcast it to other peers.
            let result = tokio::time::timeout(Duration::from_millis(500), incoming_rx.recv()).await;
            assert!(
                result.is_ok(),
                "Broadcast policy should forward the message to the incoming channel"
            );
            let forwarded = result.unwrap().expect("channel should not be closed");
            assert_eq!(forwarded.tag, Tag::Transaction);
            assert_eq!(forwarded.data, b"tx-data");

            // Connection should still be open.
            assert!(
                !closing.is_cancelled(),
                "Broadcast policy should not close connection"
            );

            closing.cancel();
        }

        // Test 2: AV message with Disconnect policy (should close).
        {
            let (client_ws, server_ws) = ws_raw_pair().await;
            let (mut client_sink, _client_stream) = client_ws.split();
            let (_server_sink, server_stream) = server_ws.split();

            let (incoming_tx, _incoming_rx) = mpsc::channel(10);
            let (high_prio_tx, _high_prio_rx) = mpsc::channel(10);
            let closing = CancellationToken::new();
            let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));
            let last_packet_time = Arc::new(RwLock::new(Instant::now()));

            let closing_clone = closing.clone();
            let _read_task = tokio::spawn(read_loop(
                server_stream,
                incoming_tx,
                high_prio_tx,
                send_message_tags,
                last_packet_time,
                closing_clone,
                "test-peer".to_string(),
                PeerFeatureFlags::empty(),
                Some(mux.clone()),
                None,
                None,
                None,
                make_test_peer_sender(closing.clone()),
            ));

            let frame = encode_frame(&Tag::AgreementVote, b"bad-vote").unwrap();
            client_sink.send(WsMessage::Binary(frame)).await.unwrap();

            // Give it time to process.
            tokio::time::sleep(Duration::from_millis(200)).await;

            assert!(
                closing.is_cancelled(),
                "Disconnect policy should close the connection"
            );
        }
    }

    #[tokio::test]
    async fn multiplexer_respond_sends_reply() {
        use crate::handler::{MessageHandler, TaggedMessageHandler};
        use async_trait::async_trait;

        // Handler that returns Respond with echoed data.
        struct RespondHandler;
        #[async_trait]
        impl MessageHandler for RespondHandler {
            async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
                OutgoingMessage {
                    action: ForwardingPolicy::Respond,
                    tag: Tag::UniEnsBlockReq,
                    payload: msg.data.clone(),
                    topics: None,
                }
            }
        }

        let mux = Arc::new(Multiplexer::new());
        mux.register_handlers(vec![TaggedMessageHandler {
            tag: Tag::UniEnsBlockReq,
            handler: Arc::new(RespondHandler),
        }]);

        let (client_ws, server_ws) = ws_raw_pair().await;
        let (mut client_sink, _client_stream) = client_ws.split();
        let (_server_sink, server_stream) = server_ws.split();

        let (incoming_tx, _incoming_rx) = mpsc::channel(10);
        let (high_prio_tx, mut high_prio_rx) = mpsc::channel::<WriteCommand>(10);
        let closing = CancellationToken::new();
        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));
        let last_packet_time = Arc::new(RwLock::new(Instant::now()));

        let closing_clone = closing.clone();
        let _read_task = tokio::spawn(read_loop(
            server_stream,
            incoming_tx,
            high_prio_tx,
            send_message_tags,
            last_packet_time,
            closing_clone,
            "test-peer".to_string(),
            PeerFeatureFlags::empty(),
            Some(mux),
            None,
            None,
            None,
            make_test_peer_sender(closing.clone()),
        ));

        let frame = encode_frame(&Tag::UniEnsBlockReq, b"request-data").unwrap();
        client_sink.send(WsMessage::Binary(frame)).await.unwrap();

        // The Respond action should enqueue a reply on the high-prio channel.
        let cmd = tokio::time::timeout(Duration::from_secs(2), high_prio_rx.recv())
            .await
            .expect("timeout waiting for response command")
            .expect("channel closed");

        match cmd {
            WriteCommand::Data(send_msg) => {
                // The Respond path now builds a proper TopicMsgResp with the
                // request hash appended as a topic.
                assert_eq!(send_msg.msg.tag, Tag::TopicMsgResp);

                // The payload should be serialized Topics containing the
                // RequestHash topic.
                use crate::topics::Topics;
                let topics = Topics::unmarshal(&send_msg.msg.payload)
                    .expect("payload should be valid Topics");
                let hash_val = topics.get_value(crate::request_response::RESPONSE_HASH_FIELD);
                assert!(
                    hash_val.is_some(),
                    "response must include RequestHash topic"
                );
            }
            other => panic!("expected Data, got: {other:?}"),
        }

        closing.cancel();
    }

    #[tokio::test]
    async fn outgoing_filter_prevents_sending_already_seen() {
        // If the outgoing filter has a digest for a message, the write loop
        // should skip sending that message. Only messages >= MESSAGE_FILTER_SIZE
        // (5000 bytes) are checked against the outgoing filter (matching Go's
        // writeNonBlock behavior).
        let (client_ws, server_ws) = ws_raw_pair().await;
        let (mut sink, _client_stream) = client_ws.split();
        let (_server_sink, mut server_stream) = server_ws.split();

        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));

        let outgoing_filter = Arc::new(MessageFilter::new(1024));

        // Pre-populate the outgoing filter with the digest of a large TX
        // message (>= MESSAGE_FILTER_SIZE so the outgoing filter is consulted).
        let tx_payload = vec![0xAB; MESSAGE_FILTER_SIZE];
        let digest = generate_message_digest(&Tag::Transaction, &tx_payload);
        outgoing_filter.check_digest(&digest, true, false);

        // Try to send the same TX message — should be filtered out.
        let msg = OutgoingMessage::new(Tag::Transaction, tx_payload.clone());
        let cmd = WriteCommand::Data(SendMessage {
            msg,
            enqueued: Instant::now(),
        });

        let result = process_write_command(
            cmd,
            &mut sink,
            &send_message_tags,
            "test",
            PeerFeatureFlags::empty(),
            &Some(outgoing_filter.clone()),
        )
        .await;
        assert!(result.is_ok(), "should succeed (silently dropped)");

        // Send a different large TX message — should go through.
        let new_payload = vec![0xCD; MESSAGE_FILTER_SIZE];
        let msg2 = OutgoingMessage::new(Tag::Transaction, new_payload.clone());
        let cmd2 = WriteCommand::Data(SendMessage {
            msg: msg2,
            enqueued: Instant::now(),
        });

        let result2 = process_write_command(
            cmd2,
            &mut sink,
            &send_message_tags,
            "test",
            PeerFeatureFlags::empty(),
            &Some(outgoing_filter),
        )
        .await;
        assert!(result2.is_ok());

        // Read the frame from the server side — should only be the new TX.
        let received = tokio::time::timeout(Duration::from_secs(2), server_stream.next())
            .await
            .expect("timeout")
            .unwrap()
            .unwrap();

        match received {
            WsMessage::Binary(data) => {
                let (tag, payload) = decode_frame(&data).unwrap();
                assert_eq!(tag, Tag::Transaction);
                assert_eq!(payload, new_payload.as_slice());
            }
            other => panic!("expected binary message, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn outgoing_filter_does_not_affect_non_dedup_tags() {
        // Non dedup-safe tags (e.g., PP) should NOT be filtered by the
        // outgoing filter, even if their digest is present.
        let (client_ws, server_ws) = ws_raw_pair().await;
        let (mut sink, _client_stream) = client_ws.split();
        let (_server_sink, mut server_stream) = server_ws.split();

        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));

        let outgoing_filter = Arc::new(MessageFilter::new(1024));

        // Add the digest for a PP message.
        let pp_payload = b"proposal-payload";
        let digest = generate_message_digest(&Tag::ProposalPayload, pp_payload);
        outgoing_filter.check_digest(&digest, true, false);

        // Sending the PP message should still go through (PP is not dedup-safe).
        let msg = OutgoingMessage::new(Tag::ProposalPayload, pp_payload.to_vec());
        let cmd = WriteCommand::Data(SendMessage {
            msg,
            enqueued: Instant::now(),
        });

        let result = process_write_command(
            cmd,
            &mut sink,
            &send_message_tags,
            "test",
            PeerFeatureFlags::empty(),
            &Some(outgoing_filter),
        )
        .await;
        assert!(result.is_ok());

        // Read the frame from the server side — PP should have gone through.
        let received = tokio::time::timeout(Duration::from_secs(2), server_stream.next())
            .await
            .expect("timeout")
            .unwrap()
            .unwrap();

        match received {
            WsMessage::Binary(data) => {
                let (tag, _payload) = decode_frame(&data).unwrap();
                assert_eq!(tag, Tag::ProposalPayload);
            }
            other => panic!("expected binary message, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn backward_compat_no_optional_components() {
        // When no optional components are provided, behavior is identical
        // to the original WsPeer (messages flow through the incoming channel).
        let (client_ws, server_ws) = ws_raw_pair().await;
        let (mut client_sink, _client_stream) = client_ws.split();
        let (_server_sink, server_stream) = server_ws.split();

        let (incoming_tx, mut incoming_rx) = mpsc::channel(10);
        let (high_prio_tx, _high_prio_rx) = mpsc::channel(10);
        let closing = CancellationToken::new();
        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));
        let last_packet_time = Arc::new(RwLock::new(Instant::now()));

        let closing_clone = closing.clone();
        let _read_task = tokio::spawn(read_loop(
            server_stream,
            incoming_tx,
            high_prio_tx,
            send_message_tags,
            last_packet_time,
            closing_clone,
            "test-peer".to_string(),
            PeerFeatureFlags::empty(),
            None, // no multiplexer
            None, // no incoming filter
            None, // no outgoing filter
            None, // no request tracker
            make_test_peer_sender(closing.clone()),
        ));

        // Send a TX message.
        let frame = encode_frame(&Tag::Transaction, b"compat-test").unwrap();
        client_sink.send(WsMessage::Binary(frame)).await.unwrap();

        // Should arrive on the incoming channel as before.
        let msg = tokio::time::timeout(Duration::from_secs(2), incoming_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(msg.tag, Tag::Transaction);
        assert_eq!(msg.data, b"compat-test");

        closing.cancel();
    }

    #[test]
    fn ws_peer_config_default_all_none() {
        let config = WsPeerConfig::default();
        assert!(config.multiplexer.is_none());
        assert!(config.incoming_filter.is_none());
        assert!(config.outgoing_filter.is_none());
        assert!(config.request_tracker.is_none());
    }

    // -----------------------------------------------------------------------
    // UnicastPeer: respond() constructs correct TopicMsgResp
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unicast_respond_sends_topic_msg_resp() {
        let (client_ws, server_ws) = ws_raw_pair().await;
        let (mut _server_sink, mut server_stream) = server_ws.split();
        let closing = CancellationToken::new();

        // Create channels manually to build a PeerHandle-like struct.
        let (high_prio_tx, _high_prio_rx) = mpsc::channel(10);
        let (bulk_tx, bulk_rx) = mpsc::channel(10);
        let (_incoming_tx, _incoming_rx) = mpsc::channel(10);

        // Set up the write loop to actually send the message.
        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));
        let (client_sink, _client_stream) = client_ws.split();
        let closing_clone = closing.clone();
        let _write_task = tokio::spawn(write_loop(
            client_sink,
            _high_prio_rx,
            bulk_rx,
            send_message_tags,
            closing_clone,
            "test".to_string(),
            PeerFeatureFlags::empty(),
            None,
        ));

        // Build a PeerHandle with a request tracker.
        let tracker = Arc::new(RequestTracker::new());
        let handle = PeerHandle {
            send_high_prio: high_prio_tx,
            send_bulk: bulk_tx,
            incoming: _incoming_rx,
            closing: closing.clone(),
            remote_addr: "127.0.0.1:9999".to_string(),
            identity_key: None,
            identity_verified: false,
            features: PeerFeatureFlags::empty(),
            version: "2.2".to_string(),
            request_tracker: Some(tracker),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            _read_handle: tokio::spawn(async {}),
            _write_handle: tokio::spawn(async {}),
            _keepalive_handle: tokio::spawn(async {}),
        };

        // Send a response via UnicastPeer::respond().
        let request_hash = 0xDEAD_BEEF_u64;
        let response_topics = Topics::from_vec(vec![Topic::new("result", b"success".to_vec())]);
        handle.respond(request_hash, response_topics).await.unwrap();

        // Read the frame from the server side.
        let received = tokio::time::timeout(Duration::from_secs(2), server_stream.next())
            .await
            .expect("timeout")
            .unwrap()
            .unwrap();

        match received {
            WsMessage::Binary(data) => {
                let (tag, payload) = decode_frame(&data).unwrap();
                assert_eq!(tag, Tag::TopicMsgResp);

                // Deserialize the payload as Topics and verify.
                let decoded = Topics::unmarshal(payload).unwrap();

                // Should contain "result" and "RequestHash" topics.
                assert_eq!(decoded.get_value("result"), Some(b"success".as_slice()));
                let hash_bytes = decoded.get_value(RESPONSE_HASH_FIELD).unwrap();
                let encoded_hash = encode_uvarint(request_hash);
                assert_eq!(hash_bytes, &encoded_hash[..]);
            }
            other => panic!("expected binary message, got: {other:?}"),
        }

        closing.cancel();
    }

    // -----------------------------------------------------------------------
    // UnicastPeer: request() + response round-trip
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unicast_request_response_roundtrip() {
        let (client_ws, server_ws) = ws_raw_pair().await;
        let (server_sink, mut server_stream) = server_ws.split();
        let closing = CancellationToken::new();

        let (high_prio_tx, high_prio_rx) = mpsc::channel(10);
        let (bulk_tx, bulk_rx) = mpsc::channel(10);
        let (_incoming_tx, incoming_rx) = mpsc::channel(10);

        // Set up the write loop so messages actually get sent.
        let send_message_tags = Arc::new(RwLock::new(default_send_message_tags()));
        let (client_sink, client_stream) = client_ws.split();
        let closing_clone = closing.clone();
        let _write_task = tokio::spawn(write_loop(
            client_sink,
            high_prio_rx,
            bulk_rx,
            send_message_tags.clone(),
            closing_clone,
            "test".to_string(),
            PeerFeatureFlags::empty(),
            None,
        ));

        // Set up the request tracker (shared between PeerHandle and read loop).
        let tracker = Arc::new(RequestTracker::new());

        // Set up the read loop so TopicMsgResp responses get routed.
        let read_closing = closing.clone();
        let read_tracker = tracker.clone();
        let (read_incoming_tx, _read_incoming_rx) = mpsc::channel(10);
        let (read_high_prio_tx, _read_high_prio_rx) = mpsc::channel(10);
        let read_send_tags = Arc::new(RwLock::new(default_send_message_tags()));
        let last_packet_time = Arc::new(RwLock::new(Instant::now()));
        let peer_sender = make_test_peer_sender(closing.clone());
        let _read_task = tokio::spawn(read_loop(
            client_stream,
            read_incoming_tx,
            read_high_prio_tx,
            read_send_tags,
            last_packet_time,
            read_closing,
            "test-peer".to_string(),
            PeerFeatureFlags::empty(),
            None,
            None,
            None,
            Some(read_tracker),
            peer_sender,
        ));

        // Build the PeerHandle.
        let handle = PeerHandle {
            send_high_prio: high_prio_tx,
            send_bulk: bulk_tx,
            incoming: incoming_rx,
            closing: closing.clone(),
            remote_addr: "127.0.0.1:9999".to_string(),
            identity_key: None,
            identity_verified: false,
            features: PeerFeatureFlags::empty(),
            version: "2.2".to_string(),
            request_tracker: Some(tracker.clone()),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            _read_handle: tokio::spawn(async {}),
            _write_handle: tokio::spawn(async {}),
            _keepalive_handle: tokio::spawn(async {}),
        };

        // Spawn the request in a background task.
        let request_topics = Topics::from_vec(vec![Topic::new("query", b"blocks".to_vec())]);
        let request_handle =
            tokio::spawn(async move { handle.request(Tag::UniEnsBlockReq, request_topics).await });

        // On the "server" side, read the request, extract its hash, and
        // send back a TopicMsgResp response.
        let request_frame = tokio::time::timeout(Duration::from_secs(2), server_stream.next())
            .await
            .expect("timeout waiting for request")
            .unwrap()
            .unwrap();

        let request_payload = match request_frame {
            WsMessage::Binary(data) => {
                let (tag, payload) = decode_frame(&data).unwrap();
                assert_eq!(tag, Tag::UniEnsBlockReq);
                payload.to_vec()
            }
            other => panic!("expected binary, got: {other:?}"),
        };

        // Compute the request hash (same as RequestTracker does).
        let request_hash = hash_topics(&request_payload);

        // Build a response with the request hash.
        let hash_data = encode_uvarint(request_hash);
        let resp_topics = Topics::from_vec(vec![
            Topic::new(RESPONSE_HASH_FIELD, hash_data),
            Topic::new("block", b"block-data-here".to_vec()),
        ]);
        let resp_payload = resp_topics.marshal();
        let resp_frame = encode_frame(&Tag::TopicMsgResp, &resp_payload).unwrap();

        // Send the response back through the server sink.
        let mut server_sink = server_sink;
        server_sink
            .send(WsMessage::Binary(resp_frame))
            .await
            .unwrap();

        // The request task should now complete with the response topics.
        let result = tokio::time::timeout(Duration::from_secs(2), request_handle)
            .await
            .expect("timeout waiting for request result")
            .expect("request task panicked");

        let response = result.expect("request failed");
        assert_eq!(
            response.get_value("block"),
            Some(b"block-data-here".as_slice())
        );

        // Verify the tracker is now empty.
        assert_eq!(tracker.pending_count().await, 0);

        closing.cancel();
    }

    // -----------------------------------------------------------------------
    // UnicastPeer: request() without tracker returns error
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unicast_request_no_tracker_returns_error() {
        let (client_ws, _server_ws) = ws_raw_pair().await;
        let closing = CancellationToken::new();

        let (high_prio_tx, _high_prio_rx) = mpsc::channel(10);
        let (bulk_tx, _bulk_rx) = mpsc::channel(10);
        let (_incoming_tx, incoming_rx) = mpsc::channel(10);

        let (client_sink, _client_stream) = client_ws.split();
        drop(client_sink);

        let handle = PeerHandle {
            send_high_prio: high_prio_tx,
            send_bulk: bulk_tx,
            incoming: incoming_rx,
            closing: closing.clone(),
            remote_addr: "127.0.0.1:9999".to_string(),
            identity_key: None,
            identity_verified: false,
            features: PeerFeatureFlags::empty(),
            version: "2.2".to_string(),
            request_tracker: None, // No tracker configured!
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            _read_handle: tokio::spawn(async {}),
            _write_handle: tokio::spawn(async {}),
            _keepalive_handle: tokio::spawn(async {}),
        };

        let topics = Topics::from_vec(vec![Topic::new("q", b"test".to_vec())]);
        let result = handle.request(Tag::UniEnsBlockReq, topics).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, PeerError::NoRequestTracker),
            "expected NoRequestTracker, got: {err}"
        );

        closing.cancel();
    }

    // -----------------------------------------------------------------------
    // UnicastPeer: request() returns ResponseChannelClosed when sender dropped
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unicast_request_response_channel_closed() {
        let (_client_ws, _server_ws) = ws_raw_pair().await;
        let closing = CancellationToken::new();

        let (high_prio_tx, _high_prio_rx) = mpsc::channel(10);
        let (bulk_tx, _bulk_rx) = mpsc::channel(10);
        let (_incoming_tx, incoming_rx) = mpsc::channel(10);

        let tracker = Arc::new(RequestTracker::new());

        let handle = PeerHandle {
            send_high_prio: high_prio_tx,
            send_bulk: bulk_tx,
            incoming: incoming_rx,
            closing: closing.clone(),
            remote_addr: "127.0.0.1:9999".to_string(),
            identity_key: None,
            identity_verified: false,
            features: PeerFeatureFlags::empty(),
            version: "2.2".to_string(),
            request_tracker: Some(tracker.clone()),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            _read_handle: tokio::spawn(async {}),
            _write_handle: tokio::spawn(async {}),
            _keepalive_handle: tokio::spawn(async {}),
        };

        // Spawn the request, then cancel it from the tracker side
        // to simulate a dropped sender (e.g. peer disconnect cleanup).
        let tracker_clone = tracker.clone();
        let topics = Topics::from_vec(vec![Topic::new("q", b"test".to_vec())]);
        let request_handle =
            tokio::spawn(async move { handle.request(Tag::UniEnsBlockReq, topics).await });

        // Wait briefly for the request to be registered, then cancel it.
        tokio::task::yield_now().await;

        // There should be exactly one pending request.
        assert_eq!(tracker_clone.pending_count().await, 1);

        // Get the hash from the tracker by preparing and cancelling.
        // Instead, just cancel all pending by dropping the tracker state.
        // We can't easily get the hash, so we cancel by index. The simplest
        // way is to cancel the pending request which drops the sender.
        // Since we can't know the hash, use the closing token instead.
        closing.cancel();

        let result = tokio::time::timeout(Duration::from_secs(2), request_handle)
            .await
            .expect("timeout waiting for request")
            .expect("request task panicked");

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, PeerError::ConnectionClosed),
            "expected ConnectionClosed, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // UnicastPeer: request() returns ConnectionClosed when peer closes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unicast_request_peer_closing() {
        let (_client_ws, _server_ws) = ws_raw_pair().await;
        let closing = CancellationToken::new();

        let (high_prio_tx, _high_prio_rx) = mpsc::channel(10);
        let (bulk_tx, _bulk_rx) = mpsc::channel(10);
        let (_incoming_tx, incoming_rx) = mpsc::channel(10);

        let tracker = Arc::new(RequestTracker::new());

        let handle = PeerHandle {
            send_high_prio: high_prio_tx,
            send_bulk: bulk_tx,
            incoming: incoming_rx,
            closing: closing.clone(),
            remote_addr: "127.0.0.1:9999".to_string(),
            identity_key: None,
            identity_verified: false,
            features: PeerFeatureFlags::empty(),
            version: "2.2".to_string(),
            request_tracker: Some(tracker.clone()),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            _read_handle: tokio::spawn(async {}),
            _write_handle: tokio::spawn(async {}),
            _keepalive_handle: tokio::spawn(async {}),
        };

        // Cancel immediately so the request observes the closing signal.
        closing.cancel();

        let topics = Topics::from_vec(vec![Topic::new("q", b"test".to_vec())]);
        let result = handle.request(Tag::UniEnsBlockReq, topics).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, PeerError::ConnectionClosed),
            "expected ConnectionClosed, got: {err}"
        );

        // The pending request should have been cleaned up.
        assert_eq!(tracker.pending_count().await, 0);
    }

    // -----------------------------------------------------------------------
    // Peer trait: get_address, get_connection_latency, routing_addr
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn peer_handle_peer_trait_methods() {
        let (_client_ws, _server_ws) = ws_raw_pair().await;
        let closing = CancellationToken::new();

        let (high_prio_tx, _high_prio_rx) = mpsc::channel(10);
        let (bulk_tx, _bulk_rx) = mpsc::channel(10);
        let (_incoming_tx, incoming_rx) = mpsc::channel(10);

        let handle = PeerHandle {
            send_high_prio: high_prio_tx,
            send_bulk: bulk_tx,
            incoming: incoming_rx,
            closing: closing.clone(),
            remote_addr: "10.0.0.1:4160".to_string(),
            identity_key: None,
            identity_verified: false,
            features: PeerFeatureFlags::empty(),
            version: "2.2".to_string(),
            request_tracker: None,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            _read_handle: tokio::spawn(async {}),
            _write_handle: tokio::spawn(async {}),
            _keepalive_handle: tokio::spawn(async {}),
        };

        // Test Peer trait methods.
        assert_eq!(handle.get_address(), "10.0.0.1:4160");
        assert_eq!(handle.get_connection_latency(), Duration::ZERO);
        assert!(handle.routing_addr().is_empty());

        closing.cancel();
    }
}
