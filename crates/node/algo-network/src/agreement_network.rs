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

//! Bridges the gossip network to the agreement protocol's `AgreementNetwork` trait.
//!
//! This module adapts `GossipNode` (the network-layer abstraction) into
//! `AgreementNetwork` (the agreement-layer abstraction), mirroring Go's
//! `agreement/gossip/network.go` which wraps `network.GossipNode` into
//! `agreement.Network`.
//!
//! # Architecture
//!
//! `AgreementNetworkBridge` holds an `Arc<dyn GossipNode>` and creates bounded
//! `crossbeam_channel` channels for each agreement message tag (AV, PP, VB).
//! On [`start`](AgreementNetworkBridge::start), it registers message handlers
//! with the gossip node that forward incoming messages into the appropriate
//! channel.  The agreement service consumes these via [`messages`](AgreementNetwork::messages).
//!
//! Outgoing operations (`broadcast`, `relay`, `disconnect`) delegate to the
//! underlying `GossipNode`, blocking the caller via
//! `tokio::runtime::Handle::block_on` for the async gossip node methods.
//!
//! # Go reference
//!
//! - `agreement/gossip/network.go` — `networkImpl`, `WrapNetwork`, `Start`,
//!   `Messages`, `Broadcast`, `Relay`, `Disconnect`

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tracing::warn;

use algo_agreement::traits::{
    AgreementError, AgreementNetwork, Message, MessageHandle, Tag as AgreementTag,
    AGREEMENT_VOTE_TAG, PROPOSAL_PAYLOAD_TAG, VOTE_BUNDLE_TAG,
};

use crate::forwarding_policy::ForwardingPolicy;
use crate::gossip_node::{GossipNode, Peer};
use crate::handler::{MessageHandler, TaggedMessageHandler};
use crate::message::{IncomingMessage, OutgoingMessage};
use crate::tag::Tag;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default channel capacity for agreement vote messages.
///
/// Mirrors Go's `config.Local.AgreementIncomingVotesQueueLength` (default 20000).
pub const DEFAULT_VOTE_QUEUE_LEN: usize = 20_000;

/// Default channel capacity for proposal payload messages.
///
/// Mirrors Go's `config.Local.AgreementIncomingProposalsQueueLength` (default 25).
pub const DEFAULT_PROPOSAL_QUEUE_LEN: usize = 25;

/// Default channel capacity for vote bundle messages.
///
/// Mirrors Go's `config.Local.AgreementIncomingBundlesQueueLength` (default 7).
pub const DEFAULT_BUNDLE_QUEUE_LEN: usize = 7;

// ---------------------------------------------------------------------------
// PeerRef — lightweight Peer wrapper for message handles
// ---------------------------------------------------------------------------

/// A lightweight `Peer` implementation that wraps only the sender's address.
///
/// Used inside `MessageMetadata` so the agreement service can pass peer
/// references back to `GossipNode::relay` and `GossipNode::disconnect`
/// without requiring a full `PeerHandle` or `PeerSender`.
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
// MessageMetadata — opaque handle stored inside agreement Message
// ---------------------------------------------------------------------------

/// Metadata attached to each inbound agreement message, stored as the
/// `MessageHandle` (an opaque `Arc<dyn Any + Send + Sync>`).
///
/// This mirrors Go's `messageMetadata` struct in `agreement/gossip/network.go`,
/// which stores the original `network.IncomingMessage` so that `Relay` and
/// `Disconnect` can reference the sending peer.
struct MessageMetadata {
    /// The peer that sent this message, as a `dyn Peer` reference.
    sender_peer: Option<Arc<dyn Peer>>,
}

/// Extract `MessageMetadata` from an `agreement::MessageHandle`.
fn metadata_from_handle(handle: &MessageHandle) -> Option<&MessageMetadata> {
    handle
        .as_ref()
        .and_then(|arced| arced.downcast_ref::<MessageMetadata>())
}

// ---------------------------------------------------------------------------
// Tag mapping
// ---------------------------------------------------------------------------

/// Maps an agreement-layer tag string to the network-layer `Tag` enum.
///
/// Returns `None` for unrecognised tag codes.
pub fn agreement_tag_to_network_tag(tag: &AgreementTag) -> Option<Tag> {
    match tag.0 {
        AGREEMENT_VOTE_TAG => Some(Tag::AgreementVote),
        PROPOSAL_PAYLOAD_TAG => Some(Tag::ProposalPayload),
        VOTE_BUNDLE_TAG => Some(Tag::VoteBundle),
        _ => None,
    }
}

/// Maps a network-layer `Tag` enum to the agreement-layer `Tag` string.
///
/// Returns `None` for tags that are not agreement-related.
pub fn network_tag_to_agreement_tag(tag: &Tag) -> Option<AgreementTag> {
    match tag {
        Tag::AgreementVote => Some(AgreementTag(AGREEMENT_VOTE_TAG)),
        Tag::ProposalPayload => Some(AgreementTag(PROPOSAL_PAYLOAD_TAG)),
        Tag::VoteBundle => Some(AgreementTag(VOTE_BUNDLE_TAG)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Channel handler — forwards incoming gossip messages into mpsc channels
// ---------------------------------------------------------------------------

/// A `MessageHandler` that forwards incoming messages into a bounded
/// crossbeam channel for consumption by the agreement service.
///
/// Mirrors Go's `processVoteMessage` / `processProposalMessage` /
/// `processBundleMessage` functions in `agreement/gossip/network.go`.
///
/// If the channel is full, the message is silently dropped (matching Go's
/// `select { case submit <- msg: ... default: dropped++ }` pattern).
struct ChannelForwarder {
    sender: crossbeam_channel::Sender<Message>,
}

impl ChannelForwarder {
    fn new(sender: crossbeam_channel::Sender<Message>) -> Self {
        Self { sender }
    }
}

#[async_trait]
impl MessageHandler for ChannelForwarder {
    async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
        let sender_peer: Option<Arc<dyn Peer>> = if !msg.sender.is_empty() {
            Some(Arc::new(PeerRef {
                addr: msg.sender.clone(),
            }))
        } else {
            None
        };

        let agreement_msg = Message {
            handle: Some(Arc::new(MessageMetadata { sender_peer })),
            data: msg.data.clone(),
        };

        // Non-blocking send — drop if channel is full (matches Go behavior).
        let _ = self.sender.try_send(agreement_msg);

        // Always return Ignore — agreement handles relay/broadcast decisions
        // itself through the AgreementNetwork trait methods.
        OutgoingMessage {
            action: ForwardingPolicy::Ignore,
            tag: msg.tag,
            payload: Vec::new(),
            topics: None,
        }
    }
}

// ---------------------------------------------------------------------------
// AgreementNetworkBridge
// ---------------------------------------------------------------------------

/// Configuration for `AgreementNetworkBridge` channel capacities.
#[derive(Debug, Clone)]
pub struct AgreementNetworkConfig {
    /// Capacity of the vote message channel.
    pub vote_queue_len: usize,
    /// Capacity of the proposal message channel.
    pub proposal_queue_len: usize,
    /// Capacity of the bundle message channel.
    pub bundle_queue_len: usize,
}

impl Default for AgreementNetworkConfig {
    fn default() -> Self {
        Self {
            vote_queue_len: DEFAULT_VOTE_QUEUE_LEN,
            proposal_queue_len: DEFAULT_PROPOSAL_QUEUE_LEN,
            bundle_queue_len: DEFAULT_BUNDLE_QUEUE_LEN,
        }
    }
}

/// Bridges `GossipNode` to `AgreementNetwork`.
///
/// Mirrors Go's `networkImpl` struct in `agreement/gossip/network.go`.
///
/// Created via [`AgreementNetworkBridge::new`], which sets up the internal
/// channels. Call [`start`](AgreementNetwork::start) to register message
/// handlers with the gossip node.
pub struct AgreementNetworkBridge {
    /// The underlying gossip network node.
    net: Arc<dyn GossipNode>,

    /// Tokio runtime handle for blocking on async gossip methods.
    rt_handle: tokio::runtime::Handle,

    /// Receiver end of the vote channel (AV tag).
    vote_rx: Mutex<Option<crossbeam_channel::Receiver<Message>>>,
    /// Receiver end of the proposal channel (PP tag).
    proposal_rx: Mutex<Option<crossbeam_channel::Receiver<Message>>>,
    /// Receiver end of the bundle channel (VB tag).
    bundle_rx: Mutex<Option<crossbeam_channel::Receiver<Message>>>,

    /// Sender end of the vote channel (kept for handler registration).
    vote_tx: crossbeam_channel::Sender<Message>,
    /// Sender end of the proposal channel.
    proposal_tx: crossbeam_channel::Sender<Message>,
    /// Sender end of the bundle channel.
    bundle_tx: crossbeam_channel::Sender<Message>,
}

impl AgreementNetworkBridge {
    /// Creates a new `AgreementNetworkBridge` wrapping the given gossip node.
    ///
    /// Mirrors Go's `WrapNetwork(net, log, cfg)`.
    ///
    /// The `rt_handle` is used to block on async gossip node methods from
    /// the synchronous `AgreementNetwork` trait methods.
    pub fn new(
        net: Arc<dyn GossipNode>,
        rt_handle: tokio::runtime::Handle,
        config: AgreementNetworkConfig,
    ) -> Self {
        let (vote_tx, vote_rx) = crossbeam_channel::bounded(config.vote_queue_len);
        let (proposal_tx, proposal_rx) = crossbeam_channel::bounded(config.proposal_queue_len);
        let (bundle_tx, bundle_rx) = crossbeam_channel::bounded(config.bundle_queue_len);

        Self {
            net,
            rt_handle,
            vote_rx: Mutex::new(Some(vote_rx)),
            proposal_rx: Mutex::new(Some(proposal_rx)),
            bundle_rx: Mutex::new(Some(bundle_rx)),
            vote_tx,
            proposal_tx,
            bundle_tx,
        }
    }

    /// Creates a new bridge with default queue lengths.
    pub fn with_defaults(net: Arc<dyn GossipNode>, rt_handle: tokio::runtime::Handle) -> Self {
        Self::new(net, rt_handle, AgreementNetworkConfig::default())
    }
}

impl AgreementNetwork for AgreementNetworkBridge {
    fn messages(&self, tag: &AgreementTag) -> crossbeam_channel::Receiver<Message> {
        let mutex = match tag.0 {
            AGREEMENT_VOTE_TAG => &self.vote_rx,
            PROPOSAL_PAYLOAD_TAG => &self.proposal_rx,
            VOTE_BUNDLE_TAG => &self.bundle_rx,
            other => {
                warn!(
                    "AgreementNetworkBridge::messages called with unknown tag: {other}; \
                     returning immediately-closed channel"
                );
                let (tx, rx) = crossbeam_channel::bounded(0);
                drop(tx);
                return rx;
            }
        };

        let mut guard = match mutex.lock() {
            Ok(g) => g,
            Err(_) => {
                warn!("messages lock poisoned for tag {}", tag.0);
                let (_tx, rx) = crossbeam_channel::bounded(0);
                return rx;
            }
        };
        match guard.take() {
            Some(rx) => rx,
            None => {
                // Channel was already consumed. Create a new one (the previous
                // receiver is lost, matching Go's semantics).
                let (tx, rx) = crossbeam_channel::bounded(match tag.0 {
                    AGREEMENT_VOTE_TAG => DEFAULT_VOTE_QUEUE_LEN,
                    PROPOSAL_PAYLOAD_TAG => DEFAULT_PROPOSAL_QUEUE_LEN,
                    VOTE_BUNDLE_TAG => DEFAULT_BUNDLE_QUEUE_LEN,
                    _ => unreachable!(),
                });
                // Note: the new sender is not connected to any handler. This
                // is intentional — matching Go's behavior where calling
                // Messages() again creates a new channel and old messages
                // are lost. The caller would need to call start() again to
                // reconnect handlers.
                drop(tx);
                rx
            }
        }
    }

    fn broadcast(&self, tag: &AgreementTag, data: &[u8]) -> Result<(), AgreementError> {
        let net_tag = agreement_tag_to_network_tag(tag)
            .ok_or_else(|| AgreementError::Other(format!("unknown tag: {}", tag.0)))?;

        let net = self.net.clone();
        let data = data.to_vec();

        // Use Handle::block_on to drive the async broadcast from the
        // synchronous agreement thread.  Unlike block_in_place, this works
        // from *any* thread (std::thread or tokio task).
        self.rt_handle
            .block_on(async move { net.broadcast(net_tag, data, false, None).await })
            .map_err(|e| AgreementError::Other(format!("broadcast failed: {e}")))?;

        Ok(())
    }

    fn relay(
        &self,
        handle: &MessageHandle,
        tag: &AgreementTag,
        data: &[u8],
    ) -> Result<(), AgreementError> {
        let net_tag = agreement_tag_to_network_tag(tag)
            .ok_or_else(|| AgreementError::Other(format!("unknown tag: {}", tag.0)))?;

        let net = self.net.clone();
        let data = data.to_vec();

        let metadata = metadata_from_handle(handle);

        match metadata.and_then(|m| m.sender_peer.clone()) {
            Some(sender) => {
                // Relay to all peers except the original sender.
                self.rt_handle
                    .block_on(async move { net.relay(net_tag, data, false, Some(sender)).await })
                    .map_err(|e| AgreementError::Other(format!("relay failed: {e}")))?;
            }
            None => {
                // Synthetic/loopback message — broadcast to all (matches Go behavior).
                self.rt_handle
                    .block_on(async move { net.broadcast(net_tag, data, false, None).await })
                    .map_err(|e| {
                        AgreementError::Other(format!("relay (pseudo-broadcast) failed: {e}"))
                    })?;
            }
        }

        Ok(())
    }

    fn disconnect(&self, handle: &MessageHandle) {
        let metadata = metadata_from_handle(handle);
        if let Some(sender) = metadata.and_then(|m| m.sender_peer.clone()) {
            self.net.disconnect(sender);
        }
        // If handle is None or has no peer (synthetic loopback), do nothing
        // (matches Go's behavior).
    }

    fn start(&self) {
        let handlers = vec![
            TaggedMessageHandler {
                tag: Tag::AgreementVote,
                handler: Arc::new(ChannelForwarder::new(self.vote_tx.clone())),
            },
            TaggedMessageHandler {
                tag: Tag::ProposalPayload,
                handler: Arc::new(ChannelForwarder::new(self.proposal_tx.clone())),
            },
            TaggedMessageHandler {
                tag: Tag::VoteBundle,
                handler: Arc::new(ChannelForwarder::new(self.bundle_tx.clone())),
            },
        ];

        self.net.register_handlers(handlers);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    use algo_agreement::traits::{
        Tag as AgreementTag, AGREEMENT_VOTE_TAG, PROPOSAL_PAYLOAD_TAG, VOTE_BUNDLE_TAG,
    };

    // -- Tag mapping tests ---------------------------------------------------

    #[test]
    fn agreement_tag_to_network_roundtrip() {
        let cases = [
            (AGREEMENT_VOTE_TAG, Tag::AgreementVote),
            (PROPOSAL_PAYLOAD_TAG, Tag::ProposalPayload),
            (VOTE_BUNDLE_TAG, Tag::VoteBundle),
        ];

        for (tag_str, expected_net_tag) in &cases {
            let agreement_tag = AgreementTag(tag_str);
            let net_tag = agreement_tag_to_network_tag(&agreement_tag);
            assert_eq!(
                net_tag,
                Some(*expected_net_tag),
                "agreement tag '{}' should map to {:?}",
                tag_str,
                expected_net_tag
            );

            // Reverse mapping
            let back = network_tag_to_agreement_tag(expected_net_tag);
            assert!(back.is_some());
            assert_eq!(back.unwrap().0, *tag_str);
        }
    }

    #[test]
    fn unknown_agreement_tag_returns_none() {
        let tag = AgreementTag("XX");
        assert_eq!(agreement_tag_to_network_tag(&tag), None);
    }

    #[test]
    fn non_agreement_network_tag_returns_none() {
        let non_agreement_tags = [
            Tag::Transaction,
            Tag::MsgOfInterest,
            Tag::TopicMsgResp,
            Tag::UniEnsBlockReq,
            Tag::StateProofSig,
        ];
        for tag in &non_agreement_tags {
            assert_eq!(
                network_tag_to_agreement_tag(tag),
                None,
                "{:?} should not map to an agreement tag",
                tag
            );
        }
    }

    // -- Channel forwarder tests ---------------------------------------------

    #[tokio::test]
    async fn channel_forwarder_delivers_message() {
        let (tx, rx) = crossbeam_channel::bounded(10);
        let forwarder = ChannelForwarder::new(tx);

        let incoming = IncomingMessage::new(
            Tag::AgreementVote,
            vec![1, 2, 3],
            "10.0.0.1:4160".to_string(),
            1_000_000,
        );

        let out = forwarder.handle(incoming).await;

        // Handler always returns Ignore
        assert_eq!(out.action, ForwardingPolicy::Ignore);

        // Message should be in the channel
        let msg = rx.try_recv().expect("should have received a message");
        assert_eq!(msg.data, vec![1, 2, 3]);
        assert!(msg.handle.is_some(), "handle should contain metadata");
    }

    #[tokio::test]
    async fn channel_forwarder_drops_when_full() {
        // Channel with capacity 1
        let (tx, rx) = crossbeam_channel::bounded(1);
        let forwarder = ChannelForwarder::new(tx);

        // Fill the channel
        let msg1 =
            IncomingMessage::new(Tag::AgreementVote, vec![1], "10.0.0.1:4160".to_string(), 1);
        forwarder.handle(msg1).await;

        // This should be silently dropped (channel full)
        let msg2 =
            IncomingMessage::new(Tag::AgreementVote, vec![2], "10.0.0.1:4160".to_string(), 2);
        let out = forwarder.handle(msg2).await;
        assert_eq!(out.action, ForwardingPolicy::Ignore);

        // Only the first message should be in the channel
        let received = rx.try_recv().expect("should have first message");
        assert_eq!(received.data, vec![1]);
        assert!(
            rx.try_recv().is_err(),
            "second message should have been dropped"
        );
    }

    // -- MessageMetadata extraction tests ------------------------------------

    #[test]
    fn metadata_from_handle_with_metadata() {
        let peer: Arc<dyn Peer> = Arc::new(PeerRef {
            addr: "1.2.3.4:4160".to_string(),
        });
        let handle: MessageHandle = Some(Arc::new(MessageMetadata {
            sender_peer: Some(peer),
        }));
        let meta = metadata_from_handle(&handle);
        assert!(meta.is_some());
        let sender = meta.unwrap().sender_peer.as_ref().unwrap();
        assert_eq!(sender.get_address(), "1.2.3.4:4160");
    }

    #[test]
    fn metadata_from_handle_with_none() {
        let handle: MessageHandle = None;
        assert!(metadata_from_handle(&handle).is_none());
    }

    #[test]
    fn metadata_from_handle_with_wrong_type() {
        let handle: MessageHandle = Some(Arc::new(42u32));
        assert!(metadata_from_handle(&handle).is_none());
    }

    // -- Mock GossipNode for bridge tests ------------------------------------

    struct MockGossipNode {
        started: AtomicBool,
        registered_handlers: Mutex<Vec<Tag>>,
        broadcasts: Mutex<Vec<(Tag, Vec<u8>)>>,
        relays: Mutex<Vec<(Tag, Vec<u8>)>>,
        disconnects: Mutex<Vec<String>>,
    }

    impl MockGossipNode {
        fn new() -> Self {
            Self {
                started: AtomicBool::new(false),
                registered_handlers: Mutex::new(Vec::new()),
                broadcasts: Mutex::new(Vec::new()),
                relays: Mutex::new(Vec::new()),
                disconnects: Mutex::new(Vec::new()),
            }
        }

        fn get_broadcasts(&self) -> Vec<(Tag, Vec<u8>)> {
            self.broadcasts.lock().unwrap().clone()
        }

        fn get_registered_tags(&self) -> Vec<Tag> {
            self.registered_handlers.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl GossipNode for MockGossipNode {
        fn address(&self) -> (String, bool) {
            (
                "127.0.0.1:4160".to_string(),
                self.started.load(Ordering::SeqCst),
            )
        }

        async fn broadcast(
            &self,
            tag: Tag,
            data: Vec<u8>,
            _wait: bool,
            _except: Option<Arc<dyn Peer>>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.broadcasts.lock().unwrap().push((tag, data));
            Ok(())
        }

        async fn relay(
            &self,
            tag: Tag,
            data: Vec<u8>,
            _wait: bool,
            _except: Option<Arc<dyn Peer>>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.relays.lock().unwrap().push((tag, data));
            Ok(())
        }

        fn disconnect(&self, peer: Arc<dyn Peer>) {
            self.disconnects
                .lock()
                .unwrap()
                .push(peer.get_address().to_string());
        }

        fn disconnect_peers(&self) {}

        async fn request_connect_outgoing(&self, _replace: bool) {}

        fn get_peers(&self, _options: &[crate::gossip_node::PeerOption]) -> Vec<Arc<dyn Peer>> {
            vec![]
        }

        async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.started.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn stop(&self) {
            self.started.store(false, Ordering::SeqCst);
        }

        fn register_handlers(&self, dispatch: Vec<crate::handler::TaggedMessageHandler>) {
            let mut handlers = self.registered_handlers.lock().unwrap();
            for h in dispatch {
                handlers.push(h.tag);
            }
        }

        fn clear_handlers(&self) {}

        fn register_validator_handlers(
            &self,
            _dispatch: Vec<crate::handler::TaggedMessageValidatorHandler>,
        ) {
        }

        fn clear_validator_handlers(&self) {}

        fn on_network_advance(&self) {}

        fn get_genesis_id(&self) -> &str {
            "test-v1.0"
        }

        fn register_http_handler(&self, _path: &str, _handler: axum::Router) {}
    }

    // -- AgreementNetworkBridge integration tests ----------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_start_registers_handlers() {
        let gossip = Arc::new(MockGossipNode::new());
        let bridge = AgreementNetworkBridge::with_defaults(
            gossip.clone(),
            tokio::runtime::Handle::current(),
        );

        bridge.start();

        let tags = gossip.get_registered_tags();
        assert_eq!(tags.len(), 3);
        assert!(tags.contains(&Tag::AgreementVote));
        assert!(tags.contains(&Tag::ProposalPayload));
        assert!(tags.contains(&Tag::VoteBundle));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_broadcast_delegates_to_gossip() {
        let gossip = Arc::new(MockGossipNode::new());
        let bridge = Arc::new(AgreementNetworkBridge::with_defaults(
            gossip.clone(),
            tokio::runtime::Handle::current(),
        ));

        // Call from a std::thread, mirroring production usage where the
        // agreement demux loop runs outside the tokio runtime.
        let bridge2 = bridge.clone();
        tokio::task::spawn_blocking(move || {
            let tag = AgreementTag(AGREEMENT_VOTE_TAG);
            let result = bridge2.broadcast(&tag, &[0xAB, 0xCD]);
            assert!(result.is_ok());
        })
        .await
        .unwrap();

        let broadcasts = gossip.get_broadcasts();
        assert_eq!(broadcasts.len(), 1);
        assert_eq!(broadcasts[0].0, Tag::AgreementVote);
        assert_eq!(broadcasts[0].1, vec![0xAB, 0xCD]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_broadcast_unknown_tag_returns_error() {
        let gossip = Arc::new(MockGossipNode::new());
        let bridge = Arc::new(AgreementNetworkBridge::with_defaults(
            gossip.clone(),
            tokio::runtime::Handle::current(),
        ));

        let bridge2 = bridge.clone();
        tokio::task::spawn_blocking(move || {
            let tag = AgreementTag("XX");
            let result = bridge2.broadcast(&tag, &[1, 2, 3]);
            assert!(result.is_err());
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_relay_without_handle_broadcasts() {
        let gossip = Arc::new(MockGossipNode::new());
        let bridge = Arc::new(AgreementNetworkBridge::with_defaults(
            gossip.clone(),
            tokio::runtime::Handle::current(),
        ));

        let bridge2 = bridge.clone();
        tokio::task::spawn_blocking(move || {
            let handle: MessageHandle = None;
            let tag = AgreementTag(PROPOSAL_PAYLOAD_TAG);
            let result = bridge2.relay(&handle, &tag, &[1, 2, 3]);
            assert!(result.is_ok());
        })
        .await
        .unwrap();

        // Should have broadcast (pseudo-relay) since handle is None
        let broadcasts = gossip.get_broadcasts();
        assert_eq!(broadcasts.len(), 1);
        assert_eq!(broadcasts[0].0, Tag::ProposalPayload);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_disconnect_with_no_handle_is_noop() {
        let gossip = Arc::new(MockGossipNode::new());
        let bridge = AgreementNetworkBridge::with_defaults(
            gossip.clone(),
            tokio::runtime::Handle::current(),
        );

        let handle: MessageHandle = None;
        bridge.disconnect(&handle);

        // No disconnect should have been called
        assert!(gossip.disconnects.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_messages_returns_receiver() {
        let gossip = Arc::new(MockGossipNode::new());
        let bridge = AgreementNetworkBridge::with_defaults(
            gossip.clone(),
            tokio::runtime::Handle::current(),
        );

        let tag = AgreementTag(AGREEMENT_VOTE_TAG);
        let rx = bridge.messages(&tag);

        // Channel should be empty initially
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_messages_unknown_tag_returns_closed_channel() {
        let gossip = Arc::new(MockGossipNode::new());
        let bridge = AgreementNetworkBridge::with_defaults(
            gossip.clone(),
            tokio::runtime::Handle::current(),
        );

        let tag = AgreementTag("ZZ");
        let rx = bridge.messages(&tag);
        // The returned channel should be immediately closed (sender dropped).
        assert!(
            rx.try_recv().is_err(),
            "unknown tag should return a closed channel"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_messages_second_call_creates_new_channel() {
        let gossip = Arc::new(MockGossipNode::new());
        let bridge = AgreementNetworkBridge::with_defaults(
            gossip.clone(),
            tokio::runtime::Handle::current(),
        );

        let tag = AgreementTag(VOTE_BUNDLE_TAG);

        // First call takes the receiver
        let _rx1 = bridge.messages(&tag);

        // Second call should still work (creates a disconnected channel)
        let rx2 = bridge.messages(&tag);
        assert!(
            rx2.try_recv().is_err(),
            "second receiver should be disconnected"
        );
    }

    #[test]
    fn config_default_values() {
        let config = AgreementNetworkConfig::default();
        assert_eq!(config.vote_queue_len, DEFAULT_VOTE_QUEUE_LEN);
        assert_eq!(config.proposal_queue_len, DEFAULT_PROPOSAL_QUEUE_LEN);
        assert_eq!(config.bundle_queue_len, DEFAULT_BUNDLE_QUEUE_LEN);
    }
}
