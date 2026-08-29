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

//! Background broadcast thread with priority queues.
//!
//! `BroadcastThread` manages two MPSC channels — one high-priority (for
//! agreement votes and proposal payloads) and one bulk (everything else).
//! A background tokio task drains the high-priority queue first (all pending
//! messages), then processes one bulk message, matching the priority-drain
//! semantics of Go's `broadcastThread` in `network/wsNetwork.go`.
//!
//! # Stale Message Dropping
//!
//! Each enqueued message is timestamped with [`Instant::now()`].  Before
//! sending, the broadcast loop checks whether the message has been queued
//! longer than [`MAX_MESSAGE_QUEUE_DURATION`] (25 seconds).  Stale messages
//! are dropped and logged at debug level.
//!
//! # BroadcastConnectionsLimit
//!
//! When broadcasting, at most `broadcast_connections_limit` peers receive
//! each message.  Peers are iterated in the order returned by the `peers_fn`
//! closure (matching Go's linear scan with early break).
//!
//! # Go reference
//!
//! - `network/wsNetwork.go` — `broadcastThread()` (lines 1315-1429)
//! - `network/wsNetwork.go` — `innerBroadcast()` (lines 1495-1536)
//! - `network/gossipNode.go` — `highPriorityTag()`, `Relay()`

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::message::OutgoingMessage;
use crate::tag::Tag;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum time a message can sit in the broadcast queue before being
/// considered stale and dropped.
///
/// Matches `maxMessageQueueDuration` in `go-algorand/network/wsNetwork.go`.
pub const MAX_MESSAGE_QUEUE_DURATION: Duration = Duration::from_secs(25);

/// Channel buffer size for the high-priority broadcast queue.
///
/// Go sizes `broadcastQueueHighPrio` to `outgoingMessagesBufferSize` which is
/// derived from consensus committee sizes (~2500).  We use the same value.
const HIGH_PRIO_BUFFER: usize = 2500;

/// Channel buffer size for the bulk broadcast queue.
///
/// Matches Go's `broadcastQueueBulk` buffer of 100.
const BULK_BUFFER: usize = 100;

// ---------------------------------------------------------------------------
// Broadcast request
// ---------------------------------------------------------------------------

/// A message queued for broadcast, carrying enqueue timestamp and an
/// optional peer address to exclude from delivery.
#[derive(Debug)]
struct BroadcastRequest {
    /// The outgoing message (tag + payload).
    msg: OutgoingMessage,
    /// When the message was enqueued (for stale detection).
    enqueued: Instant,
    /// Remote address of the peer to exclude (the originator).
    exclude_peer: Option<String>,
}

// ---------------------------------------------------------------------------
// Priority classification
// ---------------------------------------------------------------------------

/// Returns `true` if the given tag should be routed to the high-priority
/// broadcast queue.
///
/// Matches Go's `highPriorityTag()` in `network/gossipNode.go`:
/// AgreementVote ("AV") and ProposalPayload ("PP") are high-priority.
pub fn is_high_priority_tag(tag: &Tag) -> bool {
    matches!(tag, Tag::AgreementVote | Tag::ProposalPayload)
}

// ---------------------------------------------------------------------------
// Peer provider trait
// ---------------------------------------------------------------------------

/// A snapshot of connected peers for broadcasting.
///
/// The broadcast thread calls this on each broadcast cycle to get the
/// current set of peers.  The implementor is expected to return a
/// lightweight list (address + send handle) that can be iterated.
#[derive(Clone)]
pub struct BroadcastPeer {
    /// Remote address of the peer.
    pub addr: String,
    /// Send handle for delivering messages.
    pub handle: Arc<dyn PeerSendRef>,
}

/// Trait-object-safe interface for sending a message to a peer.
///
/// This wraps `PeerHandle::send` so the broadcast module doesn't need
/// to depend on the full `PeerHandle` directly (useful for testing).
pub trait PeerSendRef: Send + Sync {
    /// Send an outgoing message to this peer (bulk channel).
    #[allow(clippy::result_large_err)]
    fn send(&self, msg: OutgoingMessage) -> Result<(), crate::errors::PeerError>;
}

// ---------------------------------------------------------------------------
// BroadcastHandle — cloneable sender-side reference
// ---------------------------------------------------------------------------

/// A lightweight, cloneable handle for enqueuing broadcast messages.
///
/// Obtained via [`BroadcastThread::handle()`] and can be passed to tasks
/// that need to enqueue relay messages (e.g. the receive/dispatch loop).
#[derive(Clone)]
pub struct BroadcastHandle {
    tx_high: mpsc::Sender<BroadcastRequest>,
    tx_bulk: mpsc::Sender<BroadcastRequest>,
}

impl BroadcastHandle {
    /// Enqueue a message for broadcast (routes by tag priority).
    pub fn enqueue(
        &self,
        tag: Tag,
        data: Vec<u8>,
        exclude_peer: Option<String>,
    ) -> Result<(), BroadcastError> {
        let request = BroadcastRequest {
            msg: OutgoingMessage::new(tag, data),
            enqueued: Instant::now(),
            exclude_peer,
        };

        if is_high_priority_tag(&tag) {
            self.tx_high
                .try_send(request)
                .map_err(|_| BroadcastError::QueueFull)
        } else {
            self.tx_bulk
                .try_send(request)
                .map_err(|_| BroadcastError::QueueFull)
        }
    }
}

// ---------------------------------------------------------------------------
// BroadcastThread
// ---------------------------------------------------------------------------

/// Background broadcast thread with priority queues.
///
/// Manages two MPSC channels (high-priority and bulk), drains them in
/// priority order, drops stale messages, and delivers each message to
/// at most `broadcast_connections_limit` connected peers.
pub struct BroadcastThread {
    /// Sender for the high-priority queue.
    tx_high: mpsc::Sender<BroadcastRequest>,
    /// Sender for the bulk queue.
    tx_bulk: mpsc::Sender<BroadcastRequest>,
    /// Handle to the background task (for shutdown awaiting).
    task: Option<JoinHandle<()>>,
    /// Cancellation token for coordinated shutdown.
    cancel: CancellationToken,
}

impl BroadcastThread {
    /// Create and start a new `BroadcastThread`.
    ///
    /// # Arguments
    ///
    /// * `peers_fn` — closure called each broadcast cycle to obtain the
    ///   current list of connected peers.  Called from the background task.
    /// * `broadcast_connections_limit` — maximum number of peers to send
    ///   each broadcast message to.
    /// * `cancel` — cancellation token for coordinated shutdown.
    pub fn start<F>(
        peers_fn: F,
        broadcast_connections_limit: u32,
        cancel: CancellationToken,
    ) -> Self
    where
        F: Fn() -> Vec<BroadcastPeer> + Send + 'static,
    {
        let (tx_high, rx_high) = mpsc::channel(HIGH_PRIO_BUFFER);
        let (tx_bulk, rx_bulk) = mpsc::channel(BULK_BUFFER);

        let inner_cancel = cancel.clone();
        let task = tokio::spawn(broadcast_loop(
            rx_high,
            rx_bulk,
            peers_fn,
            broadcast_connections_limit,
            inner_cancel,
        ));

        Self {
            tx_high,
            tx_bulk,
            task: Some(task),
            cancel,
        }
    }

    /// Enqueue a message for broadcast.
    ///
    /// Routes to the high-priority or bulk channel based on the message tag.
    /// Returns `Err` if the appropriate channel is full (non-blocking send).
    pub fn enqueue(
        &self,
        tag: Tag,
        data: Vec<u8>,
        exclude_peer: Option<String>,
    ) -> Result<(), BroadcastError> {
        let request = BroadcastRequest {
            msg: OutgoingMessage::new(tag, data),
            enqueued: Instant::now(),
            exclude_peer,
        };

        if is_high_priority_tag(&tag) {
            self.tx_high
                .try_send(request)
                .map_err(|_| BroadcastError::QueueFull)
        } else {
            self.tx_bulk
                .try_send(request)
                .map_err(|_| BroadcastError::QueueFull)
        }
    }

    /// Get a cloneable handle for enqueuing broadcast messages.
    ///
    /// The returned [`BroadcastHandle`] can be cloned and passed to
    /// background tasks (e.g. receive/dispatch loops) that need to
    /// relay messages.
    pub fn handle(&self) -> BroadcastHandle {
        BroadcastHandle {
            tx_high: self.tx_high.clone(),
            tx_bulk: self.tx_bulk.clone(),
        }
    }

    /// Signal shutdown and await the background task.
    pub async fn stop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the broadcast subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastError {
    /// The broadcast queue is full.
    QueueFull,
}

impl std::fmt::Display for BroadcastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BroadcastError::QueueFull => write!(f, "broadcast queue full"),
        }
    }
}

impl std::error::Error for BroadcastError {}

// ---------------------------------------------------------------------------
// Background task
// ---------------------------------------------------------------------------

/// The main broadcast loop.
///
/// Priority drain semantics (matching Go's `broadcastThread`):
/// 1. Drain all pending high-priority messages (non-blocking).
/// 2. Try both queues non-blocking (high-prio first).
/// 3. If nothing available, block until a message arrives on either queue
///    or cancellation fires.
async fn broadcast_loop<F>(
    mut rx_high: mpsc::Receiver<BroadcastRequest>,
    mut rx_bulk: mpsc::Receiver<BroadcastRequest>,
    peers_fn: F,
    broadcast_connections_limit: u32,
    cancel: CancellationToken,
) where
    F: Fn() -> Vec<BroadcastPeer> + Send + 'static,
{
    loop {
        // Phase 1: drain all pending high-priority messages.
        while let Ok(request) = rx_high.try_recv() {
            let peers = peers_fn();
            inner_broadcast(request, &peers, broadcast_connections_limit);
        }

        // Phase 2: try both queues non-blocking.
        let mut got_message = false;
        if let Ok(request) = rx_high.try_recv() {
            let peers = peers_fn();
            inner_broadcast(request, &peers, broadcast_connections_limit);
            got_message = true;
        }
        if !got_message {
            if let Ok(request) = rx_bulk.try_recv() {
                let peers = peers_fn();
                inner_broadcast(request, &peers, broadcast_connections_limit);
                got_message = true;
            }
        }

        if got_message {
            continue;
        }

        // Phase 3: block until a message arrives or cancellation fires.
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("broadcast thread shutting down");
                return;
            }
            Some(request) = rx_high.recv() => {
                let peers = peers_fn();
                inner_broadcast(request, &peers, broadcast_connections_limit);
            }
            Some(request) = rx_bulk.recv() => {
                let peers = peers_fn();
                inner_broadcast(request, &peers, broadcast_connections_limit);
            }
        }
    }
}

/// Deliver a single broadcast request to peers.
///
/// - Drops the message if it has been queued longer than
///   [`MAX_MESSAGE_QUEUE_DURATION`].
/// - Skips the excluded peer (the originator).
/// - Sends to at most `broadcast_connections_limit` peers.
fn inner_broadcast(
    request: BroadcastRequest,
    peers: &[BroadcastPeer],
    broadcast_connections_limit: u32,
) {
    let elapsed = request.enqueued.elapsed();
    if elapsed > MAX_MESSAGE_QUEUE_DURATION {
        tracing::debug!(
            tag = %request.msg.tag,
            age_ms = elapsed.as_millis(),
            "dropping stale broadcast message (queued > 25s)"
        );
        return;
    }

    let mut sent_count: u32 = 0;
    for peer in peers {
        if sent_count >= broadcast_connections_limit {
            break;
        }
        // Skip the originating peer.
        if let Some(ref exclude) = request.exclude_peer {
            if peer.addr == *exclude {
                continue;
            }
        }
        if let Err(e) = peer.handle.send(request.msg.clone()) {
            tracing::debug!(
                addr = %peer.addr,
                error = %e,
                "failed to send broadcast to peer"
            );
        } else {
            sent_count += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // -----------------------------------------------------------------------
    // Mock peer sender
    // -----------------------------------------------------------------------

    /// A mock peer sender that records all messages sent to it.
    #[derive(Default, Clone)]
    struct MockPeerSender {
        messages: Arc<Mutex<Vec<OutgoingMessage>>>,
    }

    impl PeerSendRef for MockPeerSender {
        fn send(&self, msg: OutgoingMessage) -> Result<(), crate::errors::PeerError> {
            self.messages.lock().unwrap().push(msg);
            Ok(())
        }
    }

    fn make_mock_peer(addr: &str) -> (BroadcastPeer, MockPeerSender) {
        let sender = MockPeerSender::default();
        let peer = BroadcastPeer {
            addr: addr.to_string(),
            handle: Arc::new(sender.clone()),
        };
        (peer, sender)
    }

    // -----------------------------------------------------------------------
    // Priority tag classification
    // -----------------------------------------------------------------------

    #[test]
    fn high_priority_tags() {
        assert!(is_high_priority_tag(&Tag::AgreementVote));
        assert!(is_high_priority_tag(&Tag::ProposalPayload));
    }

    #[test]
    fn bulk_tags() {
        assert!(!is_high_priority_tag(&Tag::Transaction));
        assert!(!is_high_priority_tag(&Tag::MsgOfInterest));
        assert!(!is_high_priority_tag(&Tag::StateProofSig));
        assert!(!is_high_priority_tag(&Tag::VoteBundle));
        assert!(!is_high_priority_tag(&Tag::VotePacked));
    }

    // -----------------------------------------------------------------------
    // Enqueue routing: AV/PP go to high-priority, others to bulk
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn enqueue_routes_av_to_high_priority() {
        let cancel = CancellationToken::new();
        let (peer, sender) = make_mock_peer("10.0.0.1:4160");
        let peers = vec![peer];
        let peers_arc = Arc::new(Mutex::new(peers));

        let peers_fn = {
            let p = peers_arc.clone();
            move || p.lock().unwrap().clone()
        };

        let mut bt = BroadcastThread::start(peers_fn, 35, cancel.clone());

        bt.enqueue(Tag::AgreementVote, vec![1, 2, 3], None).unwrap();

        // Give the background task time to process.
        tokio::time::sleep(Duration::from_millis(50)).await;

        {
            let msgs = sender.messages.lock().unwrap();
            assert_eq!(msgs.len(), 1);
            assert_eq!(msgs[0].tag, Tag::AgreementVote);
            assert_eq!(msgs[0].payload, vec![1, 2, 3]);
        }

        bt.stop().await;
    }

    #[tokio::test]
    async fn enqueue_routes_pp_to_high_priority() {
        let cancel = CancellationToken::new();
        let (peer, sender) = make_mock_peer("10.0.0.1:4160");
        let peers = vec![peer];
        let peers_arc = Arc::new(Mutex::new(peers));

        let peers_fn = {
            let p = peers_arc.clone();
            move || p.lock().unwrap().clone()
        };

        let mut bt = BroadcastThread::start(peers_fn, 35, cancel.clone());

        bt.enqueue(Tag::ProposalPayload, vec![4, 5], None).unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        {
            let msgs = sender.messages.lock().unwrap();
            assert_eq!(msgs.len(), 1);
            assert_eq!(msgs[0].tag, Tag::ProposalPayload);
        }

        bt.stop().await;
    }

    #[tokio::test]
    async fn enqueue_routes_tx_to_bulk() {
        let cancel = CancellationToken::new();
        let (peer, sender) = make_mock_peer("10.0.0.1:4160");
        let peers = vec![peer];
        let peers_arc = Arc::new(Mutex::new(peers));

        let peers_fn = {
            let p = peers_arc.clone();
            move || p.lock().unwrap().clone()
        };

        let mut bt = BroadcastThread::start(peers_fn, 35, cancel.clone());

        bt.enqueue(Tag::Transaction, vec![6, 7], None).unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        {
            let msgs = sender.messages.lock().unwrap();
            assert_eq!(msgs.len(), 1);
            assert_eq!(msgs[0].tag, Tag::Transaction);
        }

        bt.stop().await;
    }

    // -----------------------------------------------------------------------
    // Priority ordering: AV/PP messages sent before bulk messages
    // -----------------------------------------------------------------------

    /// Log entry: (tag, payload).
    type BroadcastLogEntry = (Tag, Vec<u8>);

    #[tokio::test]
    async fn priority_messages_sent_before_bulk() {
        let cancel = CancellationToken::new();

        // We'll use an ordered log of (tag, payload) tuples.
        let log: Arc<Mutex<Vec<BroadcastLogEntry>>> = Arc::new(Mutex::new(Vec::new()));

        // Custom sender that logs to the shared log.
        #[derive(Clone)]
        struct LoggingSender {
            log: Arc<Mutex<Vec<BroadcastLogEntry>>>,
        }

        impl PeerSendRef for LoggingSender {
            fn send(&self, msg: OutgoingMessage) -> Result<(), crate::errors::PeerError> {
                self.log.lock().unwrap().push((msg.tag, msg.payload));
                Ok(())
            }
        }

        let sender = LoggingSender { log: log.clone() };
        let peer = BroadcastPeer {
            addr: "10.0.0.1:4160".to_string(),
            handle: Arc::new(sender),
        };
        let peers = vec![peer];
        let peers_arc = Arc::new(Mutex::new(peers));

        // Don't start the broadcast thread yet — enqueue messages first, then
        // start so they're all queued when the thread begins processing.
        let (tx_high, rx_high) = mpsc::channel(HIGH_PRIO_BUFFER);
        let (tx_bulk, rx_bulk) = mpsc::channel(BULK_BUFFER);

        // Enqueue a bulk message first, then two high-priority messages.
        tx_bulk
            .try_send(BroadcastRequest {
                msg: OutgoingMessage::new(Tag::Transaction, vec![1]),
                enqueued: Instant::now(),
                exclude_peer: None,
            })
            .unwrap();

        tx_high
            .try_send(BroadcastRequest {
                msg: OutgoingMessage::new(Tag::AgreementVote, vec![2]),
                enqueued: Instant::now(),
                exclude_peer: None,
            })
            .unwrap();

        tx_high
            .try_send(BroadcastRequest {
                msg: OutgoingMessage::new(Tag::ProposalPayload, vec![3]),
                enqueued: Instant::now(),
                exclude_peer: None,
            })
            .unwrap();

        let inner_cancel = cancel.clone();
        let peers_fn = {
            let p = peers_arc.clone();
            move || p.lock().unwrap().clone()
        };

        let task = tokio::spawn(broadcast_loop(rx_high, rx_bulk, peers_fn, 35, inner_cancel));

        // Wait for processing.
        tokio::time::sleep(Duration::from_millis(100)).await;

        cancel.cancel();
        let _ = task.await;

        let entries = log.lock().unwrap();
        assert_eq!(
            entries.len(),
            3,
            "expected 3 messages, got {}",
            entries.len()
        );

        // Both high-priority messages should appear before the bulk message.
        // The first two should be AV and PP (order between them may vary
        // depending on channel scheduling, but both must precede TX).
        let high_prio_tags: Vec<Tag> = entries[..2].iter().map(|(t, _)| *t).collect();
        assert!(
            high_prio_tags.contains(&Tag::AgreementVote),
            "AV should be in first two"
        );
        assert!(
            high_prio_tags.contains(&Tag::ProposalPayload),
            "PP should be in first two"
        );
        assert_eq!(entries[2].0, Tag::Transaction, "TX should be last");
    }

    // -----------------------------------------------------------------------
    // Stale message dropping
    // -----------------------------------------------------------------------

    #[test]
    fn stale_message_is_dropped() {
        let (peer, sender) = make_mock_peer("10.0.0.1:4160");
        let peers = vec![peer];

        let stale_request = BroadcastRequest {
            msg: OutgoingMessage::new(Tag::Transaction, vec![99]),
            // Enqueued 30 seconds ago — older than 25s threshold.
            enqueued: Instant::now() - Duration::from_secs(30),
            exclude_peer: None,
        };

        inner_broadcast(stale_request, &peers, 35);

        let msgs = sender.messages.lock().unwrap();
        assert!(msgs.is_empty(), "stale message should have been dropped");
    }

    #[test]
    fn fresh_message_is_not_dropped() {
        let (peer, sender) = make_mock_peer("10.0.0.1:4160");
        let peers = vec![peer];

        let fresh_request = BroadcastRequest {
            msg: OutgoingMessage::new(Tag::Transaction, vec![42]),
            enqueued: Instant::now(),
            exclude_peer: None,
        };

        inner_broadcast(fresh_request, &peers, 35);

        let msgs = sender.messages.lock().unwrap();
        assert_eq!(msgs.len(), 1);
    }

    // -----------------------------------------------------------------------
    // BroadcastConnectionsLimit: only N peers receive each broadcast
    // -----------------------------------------------------------------------

    #[test]
    fn broadcast_connections_limit_caps_delivery() {
        let mut peers = Vec::new();
        let mut senders = Vec::new();
        for i in 0..5 {
            let (peer, sender) = make_mock_peer(&format!("10.0.0.{}:4160", i + 1));
            peers.push(peer);
            senders.push(sender);
        }

        let request = BroadcastRequest {
            msg: OutgoingMessage::new(Tag::Transaction, vec![1]),
            enqueued: Instant::now(),
            exclude_peer: None,
        };

        // Limit to 3 peers.
        inner_broadcast(request, &peers, 3);

        let total_sent: usize = senders
            .iter()
            .map(|s| s.messages.lock().unwrap().len())
            .sum();
        assert_eq!(total_sent, 3, "should send to exactly 3 peers");
    }

    #[test]
    fn broadcast_connections_limit_zero_sends_to_none() {
        let (peer, sender) = make_mock_peer("10.0.0.1:4160");
        let peers = vec![peer];

        let request = BroadcastRequest {
            msg: OutgoingMessage::new(Tag::Transaction, vec![1]),
            enqueued: Instant::now(),
            exclude_peer: None,
        };

        // Limit of 0 — no peers should receive.
        // Note: Go checks `BroadcastConnectionsLimit >= 0 && sentMessageCount >= limit`,
        // but with u32 this is always >= 0, and sentCount 0 >= 0, so none are sent.
        // Actually Go: `if wn.config.BroadcastConnectionsLimit >= 0 && sentMessageCount >= wn.config.BroadcastConnectionsLimit`
        // With limit=0, 0 >= 0 is true, so break immediately.
        inner_broadcast(request, &peers, 0);

        let msgs = sender.messages.lock().unwrap();
        assert!(msgs.is_empty(), "limit=0 should send to no peers");
    }

    // -----------------------------------------------------------------------
    // Exclude peer: originating peer doesn't receive the relayed message
    // -----------------------------------------------------------------------

    #[test]
    fn exclude_peer_skips_originator() {
        let (peer1, sender1) = make_mock_peer("10.0.0.1:4160");
        let (peer2, sender2) = make_mock_peer("10.0.0.2:4160");
        let (peer3, sender3) = make_mock_peer("10.0.0.3:4160");
        let peers = vec![peer1, peer2, peer3];

        let request = BroadcastRequest {
            msg: OutgoingMessage::new(Tag::AgreementVote, vec![5]),
            enqueued: Instant::now(),
            exclude_peer: Some("10.0.0.2:4160".to_string()),
        };

        inner_broadcast(request, &peers, 35);

        assert_eq!(
            sender1.messages.lock().unwrap().len(),
            1,
            "peer 1 should receive"
        );
        assert_eq!(
            sender2.messages.lock().unwrap().len(),
            0,
            "peer 2 (excluded) should NOT receive"
        );
        assert_eq!(
            sender3.messages.lock().unwrap().len(),
            1,
            "peer 3 should receive"
        );
    }

    #[test]
    fn exclude_peer_not_counted_against_limit() {
        // With 3 peers and limit=2, excluding one peer should still allow
        // 2 other peers to receive the message.
        let (peer1, sender1) = make_mock_peer("10.0.0.1:4160");
        let (peer2, sender2) = make_mock_peer("10.0.0.2:4160");
        let (peer3, sender3) = make_mock_peer("10.0.0.3:4160");
        let peers = vec![peer1, peer2, peer3];

        let request = BroadcastRequest {
            msg: OutgoingMessage::new(Tag::Transaction, vec![9]),
            enqueued: Instant::now(),
            exclude_peer: Some("10.0.0.2:4160".to_string()),
        };

        inner_broadcast(request, &peers, 2);

        // Peer 2 is skipped, peers 1 and 3 receive (limit = 2).
        assert_eq!(sender1.messages.lock().unwrap().len(), 1);
        assert_eq!(sender2.messages.lock().unwrap().len(), 0);
        assert_eq!(sender3.messages.lock().unwrap().len(), 1);
    }

    // -----------------------------------------------------------------------
    // Start / stop lifecycle
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn start_and_stop() {
        let cancel = CancellationToken::new();
        let mut bt = BroadcastThread::start(Vec::new, 35, cancel);
        bt.stop().await;
    }

    #[tokio::test]
    async fn enqueue_after_stop_returns_error() {
        let cancel = CancellationToken::new();
        let mut bt = BroadcastThread::start(Vec::new, 35, cancel);
        bt.stop().await;

        // After stop, channels are closed, so enqueue should fail.
        // Actually tx channels are still alive since BroadcastThread owns them.
        // But the receiver is dropped, so try_send will fail.
        let result = bt.enqueue(Tag::Transaction, vec![1], None);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Edge case: broadcast with no peers
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn broadcast_with_no_peers() {
        let cancel = CancellationToken::new();
        let mut bt = BroadcastThread::start(Vec::new, 35, cancel.clone());

        // Should not panic or hang.
        bt.enqueue(Tag::Transaction, vec![1], None).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        bt.stop().await;
    }
}
