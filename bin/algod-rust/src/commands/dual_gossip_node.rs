//! [`DualGossipNode`] — composes two [`GossipNode`] implementations
//! (the WS-gossip node and the P2P transport) into one, for `Hybrid` mode.
//!
//! [`AgreementNetworkBridge`](algo_network::AgreementNetworkBridge) and
//! [`LocalTxBroadcaster`](algo_network::local_tx_broadcast::LocalTxBroadcaster)
//! both only depend on a single `Arc<dyn GossipNode>`. In `Hybrid` mode
//! both the WS-gossip stack and the libp2p P2P stack are active
//! simultaneously, and go-algorand's own `EnableP2PHybridMode` intent is
//! that traffic flows over *both* transports — so this type fans a single
//! logical `GossipNode` call out to both underlying implementations,
//! rather than requiring every traffic-routing consumer to special-case
//! `Hybrid` mode itself.
//!
//! Registration methods (`register_handlers` etc.) register the same
//! handler `Arc`s on both underlying nodes, so a message arriving over
//! either transport reaches the same handler set. Lifecycle/diagnostic
//! methods that don't have an obvious "both" semantics (address,
//! genesis ID, on-network-advance, HTTP handler registration,
//! disconnect/reconnect) delegate to the WS node as the "primary" —
//! mirroring which transport already owns those concerns exclusively
//! elsewhere in `participate.rs` (the WS node is always constructed and
//! always serves the block-service HTTP router, even in `Hybrid` mode).

use std::sync::Arc;

use algo_network::handler::{TaggedMessageHandler, TaggedMessageValidatorHandler};
use algo_network::{GossipNode, Peer, PeerOption, Router, Tag};
use async_trait::async_trait;
use tracing::debug;

/// Composes two [`GossipNode`]s so traffic flows over both. See this
/// module's doc comment for per-method delegation semantics.
pub struct DualGossipNode {
    primary: Arc<dyn GossipNode>,
    secondary: Arc<dyn GossipNode>,
}

impl DualGossipNode {
    /// `primary` should be the WS-gossip node (owns address/genesis-ID/HTTP
    /// concerns); `secondary` the P2P transport.
    pub fn new(primary: Arc<dyn GossipNode>, secondary: Arc<dyn GossipNode>) -> Self {
        Self { primary, secondary }
    }
}

#[async_trait]
impl GossipNode for DualGossipNode {
    fn address(&self) -> (String, bool) {
        self.primary.address()
    }

    async fn broadcast(
        &self,
        tag: Tag,
        data: Vec<u8>,
        wait: bool,
        except: Option<Arc<dyn Peer>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Best-effort on both: a transport-specific failure (e.g. the P2P
        // topic mapping not covering some tag) shouldn't sink the other
        // transport's otherwise-successful broadcast. Only fail the call if
        // BOTH transports failed to deliver.
        let primary_result = self
            .primary
            .broadcast(tag, data.clone(), wait, except.clone())
            .await;
        let secondary_result = self.secondary.broadcast(tag, data, wait, except).await;
        match (primary_result, secondary_result) {
            (Ok(()), _) | (_, Ok(())) => Ok(()),
            (Err(e1), Err(e2)) => Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                "both transports failed to broadcast: primary: {e1}; secondary: {e2}"
            ))),
        }
    }

    async fn relay(
        &self,
        tag: Tag,
        data: Vec<u8>,
        wait: bool,
        except: Option<Arc<dyn Peer>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let primary_result = self
            .primary
            .relay(tag, data.clone(), wait, except.clone())
            .await;
        let secondary_result = self.secondary.relay(tag, data, wait, except).await;
        match (primary_result, secondary_result) {
            (Ok(()), _) | (_, Ok(())) => Ok(()),
            (Err(e1), Err(e2)) => Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                "both transports failed to relay: primary: {e1}; secondary: {e2}"
            ))),
        }
    }

    fn disconnect(&self, peer: Arc<dyn Peer>) {
        self.primary.disconnect(peer);
    }

    fn disconnect_peers(&self) {
        self.primary.disconnect_peers();
        self.secondary.disconnect_peers();
    }

    async fn request_connect_outgoing(&self, replace: bool) {
        self.primary.request_connect_outgoing(replace).await;
    }

    fn get_peers(&self, options: &[PeerOption]) -> Vec<Arc<dyn Peer>> {
        let mut peers = self.primary.get_peers(options);
        peers.extend(self.secondary.get_peers(options));
        peers
    }

    async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.primary.start().await?;
        self.secondary.start().await
    }

    async fn stop(&self) {
        self.primary.stop().await;
        self.secondary.stop().await;
    }

    fn register_handlers(&self, dispatch: Vec<TaggedMessageHandler>) {
        // TaggedMessageHandler isn't Clone (its `handler: Arc<dyn
        // MessageHandler>` is, but the wrapper struct itself isn't
        // derived), so rebuild one copy per underlying node from the same
        // `Arc` clones — cheap, and keeps a single logical handler set
        // dispatched to regardless of which transport delivered a message.
        let primary_dispatch: Vec<TaggedMessageHandler> = dispatch
            .iter()
            .map(|h| TaggedMessageHandler {
                tag: h.tag,
                handler: h.handler.clone(),
            })
            .collect();
        self.primary.register_handlers(primary_dispatch);
        self.secondary.register_handlers(dispatch);
    }

    fn clear_handlers(&self) {
        self.primary.clear_handlers();
        self.secondary.clear_handlers();
    }

    fn register_validator_handlers(&self, dispatch: Vec<TaggedMessageValidatorHandler>) {
        let primary_dispatch: Vec<TaggedMessageValidatorHandler> = dispatch
            .iter()
            .map(|h| TaggedMessageValidatorHandler {
                tag: h.tag,
                handler: h.handler.clone(),
            })
            .collect();
        self.primary.register_validator_handlers(primary_dispatch);
        self.secondary.register_validator_handlers(dispatch);
    }

    fn clear_validator_handlers(&self) {
        self.primary.clear_validator_handlers();
        self.secondary.clear_validator_handlers();
    }

    fn on_network_advance(&self) {
        self.primary.on_network_advance();
        self.secondary.on_network_advance();
    }

    fn get_genesis_id(&self) -> &str {
        self.primary.get_genesis_id()
    }

    fn register_http_handler(&self, path: &str, handler: Router) {
        debug!(
            path,
            "DualGossipNode: registering HTTP handler on primary (WS) node only"
        );
        self.primary.register_http_handler(path, handler);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_network::message::{IncomingMessage, OutgoingMessage};
    use algo_network::ForwardingPolicy;
    use std::sync::Mutex;
    use std::time::Duration;

    struct RecordingPeer {
        addr: String,
    }
    impl Peer for RecordingPeer {
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

    struct MockNode {
        name: &'static str,
        genesis_id: &'static str,
        broadcasts: Mutex<Vec<(Tag, Vec<u8>)>>,
        broadcast_fails: bool,
        registered_tags: Mutex<Vec<Tag>>,
        peers: Vec<&'static str>,
    }

    impl MockNode {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                genesis_id: "test-genesis",
                broadcasts: Mutex::new(Vec::new()),
                broadcast_fails: false,
                registered_tags: Mutex::new(Vec::new()),
                peers: Vec::new(),
            }
        }

        fn failing(name: &'static str) -> Self {
            Self {
                broadcast_fails: true,
                ..Self::new(name)
            }
        }
    }

    #[async_trait]
    impl GossipNode for MockNode {
        fn address(&self) -> (String, bool) {
            (self.name.to_string(), true)
        }

        async fn broadcast(
            &self,
            tag: Tag,
            data: Vec<u8>,
            _wait: bool,
            _except: Option<Arc<dyn Peer>>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            if self.broadcast_fails {
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                    "{} refuses to broadcast",
                    self.name
                )));
            }
            self.broadcasts.lock().unwrap().push((tag, data));
            Ok(())
        }

        async fn relay(
            &self,
            tag: Tag,
            data: Vec<u8>,
            wait: bool,
            except: Option<Arc<dyn Peer>>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.broadcast(tag, data, wait, except).await
        }

        fn disconnect(&self, _peer: Arc<dyn Peer>) {}
        fn disconnect_peers(&self) {}
        async fn request_connect_outgoing(&self, _replace: bool) {}

        fn get_peers(&self, _options: &[PeerOption]) -> Vec<Arc<dyn Peer>> {
            self.peers
                .iter()
                .map(|p| {
                    Arc::new(RecordingPeer {
                        addr: p.to_string(),
                    }) as Arc<dyn Peer>
                })
                .collect()
        }

        async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn stop(&self) {}

        fn register_handlers(&self, dispatch: Vec<TaggedMessageHandler>) {
            self.registered_tags
                .lock()
                .unwrap()
                .extend(dispatch.iter().map(|h| h.tag));
        }
        fn clear_handlers(&self) {}
        fn register_validator_handlers(&self, _dispatch: Vec<TaggedMessageValidatorHandler>) {}
        fn clear_validator_handlers(&self) {}
        fn on_network_advance(&self) {}
        fn get_genesis_id(&self) -> &str {
            self.genesis_id
        }
        fn register_http_handler(&self, _path: &str, _handler: Router) {}
    }

    struct EchoHandler;
    #[async_trait]
    impl algo_network::handler::MessageHandler for EchoHandler {
        async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
            OutgoingMessage {
                action: ForwardingPolicy::Ignore,
                tag: msg.tag,
                payload: Vec::new(),
                topics: None,
            }
        }
    }

    #[tokio::test]
    async fn broadcast_reaches_both_transports() {
        let primary = Arc::new(MockNode::new("ws"));
        let secondary = Arc::new(MockNode::new("p2p"));
        let dual = DualGossipNode::new(primary.clone(), secondary.clone());

        dual.broadcast(Tag::Transaction, vec![1, 2, 3], false, None)
            .await
            .expect("broadcast should succeed");

        assert_eq!(primary.broadcasts.lock().unwrap().len(), 1);
        assert_eq!(secondary.broadcasts.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn broadcast_succeeds_if_only_one_transport_succeeds() {
        let primary = Arc::new(MockNode::failing("ws"));
        let secondary = Arc::new(MockNode::new("p2p"));
        let dual = DualGossipNode::new(primary.clone(), secondary.clone());

        dual.broadcast(Tag::AgreementVote, vec![9], false, None)
            .await
            .expect("broadcast should succeed via the surviving transport");
        assert_eq!(secondary.broadcasts.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn broadcast_fails_only_if_both_transports_fail() {
        let primary = Arc::new(MockNode::failing("ws"));
        let secondary = Arc::new(MockNode::failing("p2p"));
        let dual = DualGossipNode::new(primary, secondary);

        let err = dual
            .broadcast(Tag::VoteBundle, vec![1], false, None)
            .await
            .expect_err("both transports failing should fail the call");
        assert!(err.to_string().contains("both transports failed"));
    }

    #[test]
    fn register_handlers_registers_on_both() {
        let primary = Arc::new(MockNode::new("ws"));
        let secondary = Arc::new(MockNode::new("p2p"));
        let dual = DualGossipNode::new(primary.clone(), secondary.clone());

        dual.register_handlers(vec![TaggedMessageHandler {
            tag: Tag::ProposalPayload,
            handler: Arc::new(EchoHandler),
        }]);

        assert_eq!(
            primary.registered_tags.lock().unwrap().as_slice(),
            &[Tag::ProposalPayload]
        );
        assert_eq!(
            secondary.registered_tags.lock().unwrap().as_slice(),
            &[Tag::ProposalPayload]
        );
    }

    #[test]
    fn get_peers_concatenates_both_transports() {
        let mut primary = MockNode::new("ws");
        primary.peers = vec!["1.2.3.4:4160"];
        let mut secondary = MockNode::new("p2p");
        secondary.peers = vec!["QmPeerId"];
        let dual = DualGossipNode::new(Arc::new(primary), Arc::new(secondary));

        let peers = dual.get_peers(&[]);
        assert_eq!(peers.len(), 2);
        let addrs: Vec<&str> = peers.iter().map(|p| p.get_address()).collect();
        assert!(addrs.contains(&"1.2.3.4:4160"));
        assert!(addrs.contains(&"QmPeerId"));
    }

    #[test]
    fn address_and_genesis_id_delegate_to_primary() {
        let primary = Arc::new(MockNode::new("ws"));
        let secondary = Arc::new(MockNode::new("p2p"));
        let dual = DualGossipNode::new(primary, secondary);

        assert_eq!(dual.address().0, "ws");
        assert_eq!(dual.get_genesis_id(), "test-genesis");
    }
}
