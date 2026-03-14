//! GossipNode trait and supporting types.
//!
//! Defines the primary network abstraction for gossip-based communication
//! between Algorand nodes.  The [`GossipNode`] trait mirrors Go's
//! `network.GossipNode` interface from `go-algorand/network/gossipNode.go`.
//!
//! Also defines the [`Peer`] trait (combining Go's `Peer`,
//! `DisconnectablePeer`, and `IPAddressable` interfaces), the
//! [`UnicastPeer`] trait (extending `Peer` with request/response methods),
//! and the [`PeerOption`] enum for filtering peer queries.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::errors::PeerError;
use crate::handler::{TaggedMessageHandler, TaggedMessageValidatorHandler};
use crate::tag::Tag;
use crate::topics::Topics;

// ---------------------------------------------------------------------------
// Peer trait
// ---------------------------------------------------------------------------

/// Abstraction over a connected network peer.
///
/// Combines the semantics of Go's `Peer` (opaque reference), `DisconnectablePeer`
/// (has a network reference), and `IPAddressable` (has a routing address) into
/// a single Rust trait.
///
/// Object-safe so it can be used as `dyn Peer`.
pub trait Peer: Send + Sync {
    /// Returns the remote address of this peer (e.g. "1.2.3.4:4160").
    ///
    /// Mirrors Go's implicit address access via `wsPeer.GetAddress()`.
    fn get_address(&self) -> &str;

    /// Returns the measured connection latency to this peer.
    ///
    /// Returns `Duration::ZERO` if no latency measurement is available.
    fn get_connection_latency(&self) -> Duration;

    /// Returns the IP routing address as raw bytes (IPv4 or IPv6).
    ///
    /// Mirrors Go's `IPAddressable.RoutingAddr()`.  Returns an empty slice
    /// if the routing address is not known.
    fn routing_addr(&self) -> &[u8];
}

// ---------------------------------------------------------------------------
// UnicastPeer trait
// ---------------------------------------------------------------------------

/// A peer that supports request/response (unicast) communication.
///
/// Extends [`Peer`] with the ability to send a topic-based request and
/// await a correlated response, or to send a response to an incoming
/// request.
///
/// Mirrors Go's `UnicastPeer` interface from
/// `go-algorand/network/wsPeer.go`:
///
/// ```go
/// type UnicastPeer interface {
///     GetAddress() string
///     Request(ctx context.Context, tag Tag, topics Topics) (resp *Response, e error)
///     Respond(ctx context.Context, reqMsg IncomingMessage, outMsg OutgoingMessage) (e error)
/// }
/// ```
#[async_trait]
pub trait UnicastPeer: Peer {
    /// Send a topic-based request and await the correlated response.
    ///
    /// The implementation appends a unique nonce, serializes the topics,
    /// sends the message with the given tag, and waits for the matching
    /// `TopicMsgResp` response (correlated by SHA-512/256 hash of the
    /// serialized request).
    ///
    /// Returns the response [`Topics`] or a [`PeerError`] on failure
    /// (timeout, send buffer full, peer closed, etc.).
    async fn request(&self, tag: Tag, topics: Topics) -> Result<Topics, PeerError>;

    /// Send a response to a previously received request.
    ///
    /// `request_hash` is the SHA-512/256-truncated-to-u64 hash of the
    /// original request's serialized topics.  The response topics are
    /// augmented with a `RequestHash` field containing this value and
    /// sent as a `TopicMsgResp` message.
    async fn respond(&self, request_hash: u64, topics: Topics) -> Result<(), PeerError>;
}

// ---------------------------------------------------------------------------
// PeerOption
// ---------------------------------------------------------------------------

/// Specifies a subset of peers to query from [`GossipNode::get_peers`].
///
/// Mirrors Go's `PeerOption` iota enum from `network/gossipNode.go`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerOption {
    /// All peers with outgoing (dialed-out) connections.
    PeersConnectedOut,
    /// All peers with inbound (accepted) connections.
    PeersConnectedIn,
    /// All relays in the phonebook.
    PeersPhonebookRelays,
    /// All archival nodes (relay or p2p) in the phonebook.
    PeersPhonebookArchivalNodes,
}

impl fmt::Display for PeerOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerOption::PeersConnectedOut => write!(f, "ConnectedOut"),
            PeerOption::PeersConnectedIn => write!(f, "ConnectedIn"),
            PeerOption::PeersPhonebookRelays => write!(f, "PhonebookRelays"),
            PeerOption::PeersPhonebookArchivalNodes => write!(f, "PhonebookArchivalNodes"),
        }
    }
}

// ---------------------------------------------------------------------------
// GossipNode trait
// ---------------------------------------------------------------------------

/// Primary network abstraction for gossip-based communication.
///
/// Mirrors Go's `network.GossipNode` interface.  Implementations manage peer
/// connections, message broadcasting/relaying, handler dispatch, and lifecycle
/// control.
///
/// All async methods use `async_trait` and the trait is object-safe
/// (`Send + Sync`).
#[async_trait]
pub trait GossipNode: Send + Sync {
    /// Returns the listening address and whether the node is currently
    /// listening.
    ///
    /// Mirrors Go's `Address() (string, bool)`.
    fn address(&self) -> (String, bool);

    /// Broadcast a message to all connected peers.
    ///
    /// - `tag`: the protocol message tag.
    /// - `data`: the raw payload bytes.
    /// - `wait`: if `true`, block until the message has been enqueued on all
    ///   peer send buffers.
    /// - `except`: optionally exclude one peer from the broadcast (typically
    ///   the sender of a message being relayed).
    ///
    /// Mirrors Go's `Broadcast(ctx, tag, data, wait, except)`.
    async fn broadcast(
        &self,
        tag: Tag,
        data: Vec<u8>,
        wait: bool,
        except: Option<Arc<dyn Peer>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Relay a message to all connected peers except the sender.
    ///
    /// Semantically identical to [`broadcast`](GossipNode::broadcast) but
    /// called from within a message handler to re-propagate a received message.
    ///
    /// Mirrors Go's `Relay(ctx, tag, data, wait, except)`.
    async fn relay(
        &self,
        tag: Tag,
        data: Vec<u8>,
        wait: bool,
        except: Option<Arc<dyn Peer>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Disconnect a misbehaving or stale peer.
    ///
    /// Mirrors Go's `Disconnect(badnode)`.
    fn disconnect(&self, peer: Arc<dyn Peer>);

    /// Disconnect all peers.  Primarily used in testing.
    ///
    /// Mirrors Go's `DisconnectPeers()`.
    fn disconnect_peers(&self);

    /// Request that the node establish outgoing connections to peers from
    /// the phonebook.
    ///
    /// If `replace` is `true`, existing outgoing connections are dropped first.
    ///
    /// Mirrors Go's `RequestConnectOutgoing(replace, quit)`.
    async fn request_connect_outgoing(&self, replace: bool);

    /// Returns the set of connected peers matching the given options.
    ///
    /// Mirrors Go's `GetPeers(options ...PeerOption) []Peer`.
    fn get_peers(&self, options: &[PeerOption]) -> Vec<Arc<dyn Peer>>;

    /// Start the network node: begin listening on sockets and spawn
    /// background tasks.
    ///
    /// Mirrors Go's `Start() error`.
    async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Stop the network node: close sockets and shut down all background tasks.
    ///
    /// Mirrors Go's `Stop()`.
    async fn stop(&self);

    /// Register message handlers that will be dispatched by tag.
    ///
    /// Mirrors Go's `RegisterHandlers([]TaggedMessageHandler)`.
    fn register_handlers(&self, dispatch: Vec<TaggedMessageHandler>);

    /// Remove all registered message handlers.
    ///
    /// Mirrors Go's `ClearHandlers()`.
    fn clear_handlers(&self);

    /// Register validator handlers for two-phase (validate-then-handle)
    /// message processing.
    ///
    /// Mirrors Go's `RegisterValidatorHandlers([]TaggedMessageValidatorHandler)`.
    fn register_validator_handlers(&self, dispatch: Vec<TaggedMessageValidatorHandler>);

    /// Remove all registered validator handlers.
    ///
    /// Mirrors Go's `ClearValidatorHandlers()`.
    fn clear_validator_handlers(&self);

    /// Notify the network that the agreement protocol has advanced.
    ///
    /// This acts as a watchdog-like signal indicating the node is making
    /// progress and has not formed a clique.
    ///
    /// Mirrors Go's `OnNetworkAdvance()`.
    fn on_network_advance(&self);

    /// Returns the network-specific genesis ID string.
    ///
    /// Mirrors Go's `GetGenesisID() string`.
    fn get_genesis_id(&self) -> &str;
}

/// Substitute `{genesisID}` placeholders in a URL with the node's actual
/// genesis ID.
///
/// Mirrors Go's `SubstituteGenesisID(net, rawURL)`.
pub fn substitute_genesis_id(net: &dyn GossipNode, raw_url: &str) -> String {
    raw_url.replace("{genesisID}", net.get_genesis_id())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    // -- PeerOption ----------------------------------------------------------

    #[test]
    fn peer_option_all_variants_exist() {
        let variants = [
            PeerOption::PeersConnectedOut,
            PeerOption::PeersConnectedIn,
            PeerOption::PeersPhonebookRelays,
            PeerOption::PeersPhonebookArchivalNodes,
        ];
        // All variants are distinct
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn peer_option_display() {
        assert_eq!(PeerOption::PeersConnectedOut.to_string(), "ConnectedOut");
        assert_eq!(PeerOption::PeersConnectedIn.to_string(), "ConnectedIn");
        assert_eq!(
            PeerOption::PeersPhonebookRelays.to_string(),
            "PhonebookRelays"
        );
        assert_eq!(
            PeerOption::PeersPhonebookArchivalNodes.to_string(),
            "PhonebookArchivalNodes"
        );
    }

    #[test]
    fn peer_option_clone_copy() {
        let opt = PeerOption::PeersConnectedOut;
        let copied = opt;
        assert_eq!(opt, copied);
        // Verify Clone is implemented (via Copy).
        let cloned: PeerOption = { opt };
        assert_eq!(opt, cloned);
    }

    #[test]
    fn peer_option_debug() {
        let s = format!("{:?}", PeerOption::PeersConnectedIn);
        assert!(s.contains("PeersConnectedIn"));
    }

    #[test]
    fn peer_option_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(PeerOption::PeersConnectedOut);
        set.insert(PeerOption::PeersConnectedIn);
        set.insert(PeerOption::PeersConnectedOut); // duplicate
        assert_eq!(set.len(), 2);
    }

    // -- Mock Peer for trait object safety -----------------------------------

    struct MockPeer {
        addr: String,
        routing: Vec<u8>,
        latency: Duration,
    }

    impl MockPeer {
        fn new(addr: &str) -> Self {
            Self {
                addr: addr.to_string(),
                routing: vec![127, 0, 0, 1],
                latency: Duration::from_millis(42),
            }
        }
    }

    impl Peer for MockPeer {
        fn get_address(&self) -> &str {
            &self.addr
        }

        fn get_connection_latency(&self) -> Duration {
            self.latency
        }

        fn routing_addr(&self) -> &[u8] {
            &self.routing
        }
    }

    #[test]
    fn peer_trait_object_safety() {
        let peer: Arc<dyn Peer> = Arc::new(MockPeer::new("1.2.3.4:4160"));
        assert_eq!(peer.get_address(), "1.2.3.4:4160");
        assert_eq!(peer.get_connection_latency(), Duration::from_millis(42));
        assert_eq!(peer.routing_addr(), &[127, 0, 0, 1]);
    }

    // -- Mock GossipNode for trait object safety -----------------------------

    struct MockGossipNode {
        genesis_id: String,
        started: AtomicBool,
    }

    impl MockGossipNode {
        fn new(genesis_id: &str) -> Self {
            Self {
                genesis_id: genesis_id.to_string(),
                started: AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl GossipNode for MockGossipNode {
        fn address(&self) -> (String, bool) {
            if self.started.load(Ordering::SeqCst) {
                ("127.0.0.1:4160".to_string(), true)
            } else {
                (String::new(), false)
            }
        }

        async fn broadcast(
            &self,
            _tag: Tag,
            _data: Vec<u8>,
            _wait: bool,
            _except: Option<Arc<dyn Peer>>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }

        async fn relay(
            &self,
            _tag: Tag,
            _data: Vec<u8>,
            _wait: bool,
            _except: Option<Arc<dyn Peer>>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }

        fn disconnect(&self, _peer: Arc<dyn Peer>) {}

        fn disconnect_peers(&self) {}

        async fn request_connect_outgoing(&self, _replace: bool) {}

        fn get_peers(&self, _options: &[PeerOption]) -> Vec<Arc<dyn Peer>> {
            vec![Arc::new(MockPeer::new("10.0.0.1:4160"))]
        }

        async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.started.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn stop(&self) {
            self.started.store(false, Ordering::SeqCst);
        }

        fn register_handlers(&self, _dispatch: Vec<TaggedMessageHandler>) {}

        fn clear_handlers(&self) {}

        fn register_validator_handlers(&self, _dispatch: Vec<TaggedMessageValidatorHandler>) {}

        fn clear_validator_handlers(&self) {}

        fn on_network_advance(&self) {}

        fn get_genesis_id(&self) -> &str {
            &self.genesis_id
        }
    }

    #[test]
    fn gossip_node_trait_object_safety() {
        // Verify that GossipNode can be used as a trait object.
        let node: Arc<dyn GossipNode> = Arc::new(MockGossipNode::new("testnet-v1.0"));
        assert_eq!(node.get_genesis_id(), "testnet-v1.0");
        let (addr, listening) = node.address();
        assert_eq!(addr, "");
        assert!(!listening);
    }

    #[tokio::test]
    async fn mock_gossip_node_lifecycle() {
        let node = MockGossipNode::new("mainnet-v1.0");

        // Before start
        let (_, listening) = node.address();
        assert!(!listening);

        // Start
        node.start().await.unwrap();
        let (addr, listening) = node.address();
        assert_eq!(addr, "127.0.0.1:4160");
        assert!(listening);

        // Get peers
        let peers = node.get_peers(&[PeerOption::PeersConnectedOut]);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].get_address(), "10.0.0.1:4160");

        // Stop
        node.stop().await;
        let (_, listening) = node.address();
        assert!(!listening);
    }

    #[tokio::test]
    async fn broadcast_and_relay() {
        let node = MockGossipNode::new("test");
        node.start().await.unwrap();

        let result = node
            .broadcast(Tag::Transaction, vec![1, 2, 3], false, None)
            .await;
        assert!(result.is_ok());

        let except: Arc<dyn Peer> = Arc::new(MockPeer::new("10.0.0.2:4160"));
        let result = node
            .relay(Tag::AgreementVote, vec![4, 5], true, Some(except))
            .await;
        assert!(result.is_ok());
    }

    #[test]
    fn disconnect_and_disconnect_peers() {
        let node = MockGossipNode::new("test");
        let peer: Arc<dyn Peer> = Arc::new(MockPeer::new("10.0.0.1:4160"));
        // Should not panic.
        node.disconnect(peer);
        node.disconnect_peers();
    }

    #[test]
    fn register_and_clear_handlers() {
        let node = MockGossipNode::new("test");
        // Should not panic with empty vectors.
        node.register_handlers(vec![]);
        node.clear_handlers();
        node.register_validator_handlers(vec![]);
        node.clear_validator_handlers();
    }

    #[test]
    fn on_network_advance_does_not_panic() {
        let node = MockGossipNode::new("test");
        node.on_network_advance();
    }

    #[test]
    fn substitute_genesis_id_replaces_placeholder() {
        let node = MockGossipNode::new("mainnet-v1.0");
        let url = substitute_genesis_id(&node, "https://relay.example.com/{genesisID}/v2/status");
        assert_eq!(url, "https://relay.example.com/mainnet-v1.0/v2/status");
    }

    #[test]
    fn substitute_genesis_id_no_placeholder() {
        let node = MockGossipNode::new("mainnet-v1.0");
        let url = substitute_genesis_id(&node, "https://relay.example.com/v2/status");
        assert_eq!(url, "https://relay.example.com/v2/status");
    }

    #[test]
    fn substitute_genesis_id_multiple_placeholders() {
        let node = MockGossipNode::new("testnet-v1.0");
        let url = substitute_genesis_id(&node, "/{genesisID}/blocks/{genesisID}");
        assert_eq!(url, "/testnet-v1.0/blocks/testnet-v1.0");
    }
}
