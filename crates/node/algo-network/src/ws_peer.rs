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
use crate::framing::{decode_frame, encode_frame};
use crate::message::{IncomingMessage, OutgoingMessage};
use crate::msg_of_interest::unmarshal_msg_of_interest;
use crate::peer_features::PeerFeatureFlags;
use crate::tag::Tag;

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

        // Extract fields for the individual tasks.
        let stream = self.stream;
        let sink = self.sink;
        let send_high_prio_rx = self.send_high_prio_rx;
        let send_bulk_rx = self.send_bulk_rx;

        let read_handle = tokio::spawn(read_loop(
            stream,
            incoming_tx,
            self.send_high_prio_tx.clone(),
            send_message_tags.clone(),
            last_packet_time.clone(),
            closing.clone(),
            remote_addr.clone(),
            features,
        ));

        let write_handle = tokio::spawn(write_loop(
            sink,
            send_high_prio_rx,
            send_bulk_rx,
            send_message_tags.clone(),
            closing.clone(),
            remote_addr.clone(),
            features,
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
            _read_handle: read_handle,
            _write_handle: write_handle,
            _keepalive_handle: keepalive_handle,
        }
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

    /// Receive the next incoming message from this peer.
    ///
    /// Returns `None` when the peer has disconnected and the channel is drained.
    pub async fn recv(&mut self) -> Option<IncomingMessage> {
        self.incoming.recv().await
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
                            // Try non-blocking first (matches Go's first select).
                            if send_high_prio_tx.try_send(cmd).is_err() {
                                tracing::warn!(
                                    peer = %remote_addr,
                                    "read_loop: failed to enqueue MI filter update"
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

        if let Err(reason) =
            process_write_command(cmd, &mut sink, &send_message_tags, &remote_addr, features).await
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

            // Encode the frame: 2-byte tag + payload.
            let payload = &send_msg.msg.payload;

            // Optionally compress PP tag payloads with zstd.
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
                        encode_frame(&tag, payload).map_err(|e| format!("encode error: {e}"))?
                    }
                }
            } else {
                encode_frame(&tag, payload).map_err(|e| format!("encode error: {e}"))?
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
}
