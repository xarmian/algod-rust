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
//!
//! ## Cross-transport identity (issue #1133)
//!
//! Go's hybrid-mode network additionally runs `algo_network`'s netidentity
//! challenge/response/verification exchange (`network/netidentity.go`) on
//! its WS-gossip leg, signed with the *same* key its P2P `PeerId` is
//! derived from (`NewHybridP2PNetwork`'s
//! `NewIdentityChallengeScheme(..., NetIdentitySigner(p2pnet.PeerIDSigner()))`,
//! `network/hybridNetwork.go:73`). Because a remote peer running the same
//! scheme presents that identical key on both legs if it connects over
//! both, a shared [`algo_p2p::IdentityTracker`] can recognize the second
//! connection as a duplicate of the first and let the caller close it —
//! `TestHybridNetwork_DuplicateConn`'s scenario.
//!
//! [`DualGossipNode`] owns exactly that: a [`HybridIdentityCoordinator`]
//! constructed from the P2P transport's own
//! [`ed25519_dalek::SigningKey`](algo_p2p::to_identity_signing_key) so both
//! legs' identity material derives from one key, plus the shared
//! [`algo_p2p::IdentityTracker`] used to detect the duplicate. See
//! [`HybridIdentityCoordinator`]'s doc comment for what "runs the exchange"
//! means precisely and what live-connection wiring remains open.

use std::sync::{Arc, Mutex};

use algo_network::handler::{TaggedMessageHandler, TaggedMessageValidatorHandler};
use algo_network::identity::IdentityChallengeValue;
use algo_network::{
    GossipNode, IdentityChallengeResponseSigned, IdentityChallengeSigned, IdentityError, Peer,
    PeerIdentity, PeerOption, Router, Tag,
};
use algo_p2p::IdentityTracker;
use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
use tracing::debug;

/// Composes two [`GossipNode`]s so traffic flows over both. See this
/// module's doc comment for per-method delegation semantics.
pub struct DualGossipNode {
    primary: Arc<dyn GossipNode>,
    secondary: Arc<dyn GossipNode>,
    /// Not read by any production call site yet — see
    /// [`HybridIdentityCoordinator`]'s doc comment on what remains for
    /// live-connection wiring. Exercised directly by this module's tests.
    #[cfg_attr(not(test), allow(dead_code))]
    identity: HybridIdentityCoordinator,
}

impl DualGossipNode {
    /// `primary` should be the WS-gossip node (owns address/genesis-ID/HTTP
    /// concerns); `secondary` the P2P transport. `identity_signing_key` is
    /// the P2P transport's own identity key (`algo_p2p::P2pTransport::identity_signing_key`),
    /// reused as the signer for the WS leg's netidentity challenges — see
    /// this module's doc comment.
    pub fn new(
        primary: Arc<dyn GossipNode>,
        secondary: Arc<dyn GossipNode>,
        identity_signing_key: SigningKey,
    ) -> Self {
        Self {
            primary,
            secondary,
            identity: HybridIdentityCoordinator::new(identity_signing_key),
        }
    }

    /// The cross-transport identity-challenge coordinator shared by this
    /// node's WS and P2P legs. See [`HybridIdentityCoordinator`].
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn identity(&self) -> &HybridIdentityCoordinator {
        &self.identity
    }
}

// ---------------------------------------------------------------------------
// Cross-transport identity coordinator (issue #1133)
// ---------------------------------------------------------------------------

/// Which of [`DualGossipNode`]'s two transports an identity claim came
/// from. Go has no equivalent type — `HybridP2PNetwork`'s two child
/// networks are simply two different callers of the same shared
/// `identityTracker`; this enum exists because [`algo_p2p::IdentityTracker`]
/// is generic over an opaque peer-handle type `P`, and pairing the leg with
/// a connection id is the simplest `P` that (a) can never accidentally
/// collide between the two legs and (b) is `Send + Sync + 'static` without
/// borrowing a live connection object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityLeg {
    /// The classic WS-gossip transport.
    #[cfg_attr(not(test), allow(dead_code))]
    Ws,
    /// The libp2p P2P transport.
    #[cfg_attr(not(test), allow(dead_code))]
    P2p,
}

/// Identifies one connection on one transport leg — the "peer handle" type
/// [`algo_p2p::IdentityTracker`] is generic over. A WS connection's remote
/// address or a P2P connection's `PeerId`/`ConnectionId` (stringified) both
/// work equally well here; what matters is that the *same* remote peer
/// connecting over both legs produces two different [`IdentityConnId`]s
/// (different `leg`), so claiming the same identity key from both is
/// recognized as two distinct connections racing for one identity, not a
/// single connection re-claiming its own slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityConnId {
    pub leg: IdentityLeg,
    pub conn: String,
}

/// Drives go-algorand's hybrid-mode netidentity challenge/response/
/// verification exchange (`network/netidentity.go`, see
/// `algo_network::identity`'s module doc comment for the full 3-message
/// protocol) using the P2P transport's own key as signer, and tracks
/// claimed identities across both legs to detect a duplicate connection —
/// mirroring `NewHybridP2PNetwork`'s shared `identityTracker` (see this
/// module's doc comment).
///
/// ## What this proves vs. what remains
///
/// This coordinator implements the *mechanism* end to end and is directly
/// tested: [`HybridIdentityCoordinator::generate_challenge`]/
/// [`verify_challenge_and_respond`](HybridIdentityCoordinator::verify_challenge_and_respond)/
/// [`verify_challenge_response`](HybridIdentityCoordinator::verify_challenge_response)
/// drive the real 3-message exchange (byte-identical to
/// `algo_network::identity`'s Go-conformance implementation) using the
/// shared P2P-derived key, and [`claim_identity`](HybridIdentityCoordinator::claim_identity)
/// reproduces go's `identityVerificationHandler` duplicate-connection
/// decision via the shared [`algo_p2p::IdentityTracker`].
///
/// What is *not* included here — matching this codebase's existing,
/// explicitly-scoped precedent in `algo_p2p::identity_tracker`'s own doc
/// comment — is wiring this coordinator into `ws_network.rs`'s live
/// connection-accept/-dial path so a real inbound/outbound WS handshake
/// actually carries an `X-Algorand-IdentityChallenge` header. Today no
/// production code path sets `algo_network::ConnectConfig::our_identity_key`
/// at all (WS-gossip's identity exchange is exercised only by
/// `algo-network`'s own tests), so wiring *this* coordinator's key into
/// live WS connections is a materially larger, pre-existing gap than
/// hybrid-mode cross-transport dedup specifically — tracked as a follow-up
/// rather than folded into this issue.
pub struct HybridIdentityCoordinator {
    #[cfg_attr(not(test), allow(dead_code))]
    signing_key: SigningKey,
    #[cfg_attr(not(test), allow(dead_code))]
    tracker: Mutex<IdentityTracker<VerifyingKey, IdentityConnId>>,
}

// Not called by any production code path yet — see this type's doc comment
// on what remains for live-connection wiring. Exercised directly by this
// module's tests.
#[cfg_attr(not(test), allow(dead_code))]
impl HybridIdentityCoordinator {
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            signing_key,
            tracker: Mutex::new(IdentityTracker::new()),
        }
    }

    /// This node's own verified identity public key — the same key both
    /// legs' identity material derives from.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Message 1 (initiator side): build a signed identity challenge to
    /// attach to an outbound connection attempt on either leg. Go:
    /// `identityChallengePublicKeyScheme.AttachChallenge`.
    pub fn generate_challenge(
        &self,
        public_address: &str,
    ) -> (IdentityChallengeSigned, IdentityChallengeValue) {
        algo_network::generate_challenge(&self.signing_key, public_address)
    }

    /// Message 2 (responder side): verify an inbound challenge and build
    /// the signed response. Go:
    /// `identityChallengePublicKeyScheme.VerifyRequestAndAttachResponse`.
    pub fn verify_challenge_and_respond(
        &self,
        header_value: &str,
        our_addresses: &[&str],
    ) -> Result<
        (
            IdentityChallengeResponseSigned,
            IdentityChallengeValue,
            VerifyingKey,
        ),
        IdentityError,
    > {
        algo_network::verify_challenge_and_respond(header_value, &self.signing_key, our_addresses)
    }

    /// Message 2 verification (initiator side): verify the responder's
    /// signed response and build Message 3. Go:
    /// `identityChallengePublicKeyScheme.VerifyResponse`.
    pub fn verify_challenge_response(
        &self,
        response_header: &str,
        expected_challenge: &IdentityChallengeValue,
    ) -> Result<
        (
            PeerIdentity,
            algo_network::IdentityVerificationMessageSigned,
        ),
        IdentityError,
    > {
        algo_network::verify_challenge_response(
            response_header,
            expected_challenge,
            &self.signing_key,
        )
    }

    /// Claim `identity` for the connection `conn` on leg `leg`, once its
    /// challenge/response exchange has verified that key. Returns `false`
    /// if a *different* connection — whether on the same or the other
    /// transport leg — already holds this identity: the signal go's
    /// `identityVerificationHandler` uses to disconnect the newer,
    /// redundant connection. This is what actually detects "the same peer
    /// connected over both WS and P2P": the WS leg and the P2P leg report
    /// the same [`VerifyingKey`] (the remote peer's one signing key) but
    /// different [`IdentityConnId`]s, so the second `claim_identity` call
    /// returns `false`. Go: `publicKeyIdentTracker.setIdentity`.
    pub fn claim_identity(
        &self,
        leg: IdentityLeg,
        conn: impl Into<String>,
        identity: VerifyingKey,
    ) -> bool {
        let conn_id = IdentityConnId {
            leg,
            conn: conn.into(),
        };
        self.tracker
            .lock()
            .expect("identity tracker mutex poisoned")
            .set_identity(identity, conn_id)
    }

    /// Release `conn`'s claim on `identity`, but only if it is still held
    /// by exactly this connection — mirrors go's `removeIdentity`'s own
    /// `t.peersByID[p.identity] == p` guard, so a connection that already
    /// lost a [`claim_identity`](Self::claim_identity) race can't evict
    /// whichever connection *did* win it. Go:
    /// `publicKeyIdentTracker.removeIdentity`.
    pub fn release_identity(
        &self,
        leg: IdentityLeg,
        conn: impl Into<String>,
        identity: &VerifyingKey,
    ) {
        let conn_id = IdentityConnId {
            leg,
            conn: conn.into(),
        };
        self.tracker
            .lock()
            .expect("identity tracker mutex poisoned")
            .remove_identity(identity, &conn_id);
    }

    /// The connection currently holding `identity`, if any. Exposed for
    /// tests/diagnostics.
    pub fn claimant(&self, identity: &VerifyingKey) -> Option<IdentityConnId> {
        self.tracker
            .lock()
            .expect("identity tracker mutex poisoned")
            .get(identity)
            .cloned()
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

    /// Deterministic signing key for tests that don't care about a
    /// specific identity, just that `DualGossipNode::new` has one.
    fn test_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[tokio::test]
    async fn broadcast_reaches_both_transports() {
        let primary = Arc::new(MockNode::new("ws"));
        let secondary = Arc::new(MockNode::new("p2p"));
        let dual = DualGossipNode::new(primary.clone(), secondary.clone(), test_signing_key(1));

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
        let dual = DualGossipNode::new(primary.clone(), secondary.clone(), test_signing_key(2));

        dual.broadcast(Tag::AgreementVote, vec![9], false, None)
            .await
            .expect("broadcast should succeed via the surviving transport");
        assert_eq!(secondary.broadcasts.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn broadcast_fails_only_if_both_transports_fail() {
        let primary = Arc::new(MockNode::failing("ws"));
        let secondary = Arc::new(MockNode::failing("p2p"));
        let dual = DualGossipNode::new(primary, secondary, test_signing_key(3));

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
        let dual = DualGossipNode::new(primary.clone(), secondary.clone(), test_signing_key(4));

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
        let dual = DualGossipNode::new(Arc::new(primary), Arc::new(secondary), test_signing_key(5));

        let peers = dual.get_peers(&[]);
        assert_eq!(peers.len(), 2);
        let addrs: Vec<&str> = peers.iter().map(|p| p.get_address()).collect();
        assert!(addrs.contains(&"1.2.3.4:4160"));
        assert!(addrs.contains(&"QmPeerId"));
    }

    #[test]
    fn identity_accessor_exposes_the_coordinator_built_from_the_ctor_key() {
        let primary = Arc::new(MockNode::new("ws"));
        let secondary = Arc::new(MockNode::new("p2p"));
        let key = test_signing_key(7);
        let dual = DualGossipNode::new(primary, secondary, key.clone());

        assert_eq!(dual.identity().public_key(), key.verifying_key());
    }

    #[test]
    fn address_and_genesis_id_delegate_to_primary() {
        let primary = Arc::new(MockNode::new("ws"));
        let secondary = Arc::new(MockNode::new("p2p"));
        let dual = DualGossipNode::new(primary, secondary, test_signing_key(6));

        assert_eq!(dual.address().0, "ws");
        assert_eq!(dual.get_genesis_id(), "test-genesis");
    }

    // -----------------------------------------------------------------------
    // HybridIdentityCoordinator (issue #1133)
    // -----------------------------------------------------------------------

    /// Full 3-message exchange between two coordinators (mirrors
    /// `algo_network::identity`'s own `full_3_message_roundtrip`, but
    /// driven through `HybridIdentityCoordinator` rather than the raw
    /// functions directly) proves the coordinator actually runs go's
    /// netidentity scheme end to end, not just holds a key.
    #[test]
    fn coordinator_runs_full_challenge_response_exchange() {
        let initiator = HybridIdentityCoordinator::new(test_signing_key(10));
        let responder = HybridIdentityCoordinator::new(test_signing_key(20));

        let (challenge_signed, orig_challenge) =
            initiator.generate_challenge("responder.example.com:4160");
        let header = algo_network::attach_challenge_header(&challenge_signed);

        let (response_signed, response_challenge, peer_pk) = responder
            .verify_challenge_and_respond(&header, &["responder.example.com:4160"])
            .expect("responder should verify the initiator's challenge");
        assert_eq!(peer_pk, initiator.public_key());

        let response_header = algo_network::attach_response_header(&response_signed);
        let (identity, verification_signed) = initiator
            .verify_challenge_response(&response_header, &orig_challenge)
            .expect("initiator should verify the responder's response");
        assert_eq!(identity.public_key, responder.public_key());

        let wire = algo_network::build_identity_verification(&verification_signed);
        let payload = &wire[b"NI".len()..];
        // Message 3 is signed by the initiator, and `peer_pk` (what the
        // responder learned Message 1 came from) is the initiator's key —
        // this is exactly what the responder checks it against in a real
        // exchange.
        algo_network::verify_identity_verification(payload, &response_challenge, &peer_pk)
            .expect("verification message should be valid against the initiator's key");
    }

    /// `TestHybridNetwork_DuplicateConn`'s scenario: the same remote peer
    /// connects over both the WS leg and the P2P leg. Both legs verify the
    /// same underlying identity key (as they would in go, since both
    /// derive from `p2pnet.PeerIDSigner()`), so the WS leg claims it first
    /// and the P2P leg's later claim of the *same* identity must be
    /// rejected as a duplicate.
    #[test]
    fn claim_identity_detects_same_peer_on_both_transports() {
        let coordinator = HybridIdentityCoordinator::new(test_signing_key(30));
        let remote_identity = test_signing_key(99).verifying_key();

        assert!(
            coordinator.claim_identity(IdentityLeg::Ws, "1.2.3.4:4160", remote_identity),
            "first connection (WS) should claim the identity"
        );
        assert!(
            !coordinator.claim_identity(IdentityLeg::P2p, "QmRemotePeerId", remote_identity),
            "second connection (P2P), same remote identity, must be rejected as a duplicate"
        );

        // The WS leg's connection is still the recognized owner.
        assert_eq!(
            coordinator.claimant(&remote_identity),
            Some(IdentityConnId {
                leg: IdentityLeg::Ws,
                conn: "1.2.3.4:4160".to_string(),
            })
        );
    }

    /// Re-claiming from the *same* connection (e.g. re-verifying after a
    /// reconnect with the same identity/conn id) is idempotent, matching
    /// `IdentityTracker::set_identity`'s contract.
    #[test]
    fn claim_identity_is_idempotent_for_the_same_connection() {
        let coordinator = HybridIdentityCoordinator::new(test_signing_key(31));
        let identity = test_signing_key(98).verifying_key();

        assert!(coordinator.claim_identity(IdentityLeg::P2p, "QmPeer", identity));
        assert!(coordinator.claim_identity(IdentityLeg::P2p, "QmPeer", identity));
    }

    /// Different remote identities on each leg must not collide — only a
    /// *shared* identity key triggers dedup.
    #[test]
    fn claim_identity_allows_distinct_peers_on_each_transport() {
        let coordinator = HybridIdentityCoordinator::new(test_signing_key(32));
        let peer_a = test_signing_key(40).verifying_key();
        let peer_b = test_signing_key(41).verifying_key();

        assert!(coordinator.claim_identity(IdentityLeg::Ws, "peer-a:4160", peer_a));
        assert!(coordinator.claim_identity(IdentityLeg::P2p, "QmPeerB", peer_b));
    }

    /// `release_identity` only evicts the connection that actually holds
    /// the claim — a connection that already lost the race must not be
    /// able to evict the winner (mirrors `algo_p2p::IdentityTracker`'s own
    /// `remove_identity_only_evicts_the_owning_peer`).
    #[test]
    fn release_identity_only_evicts_the_owning_connection() {
        let coordinator = HybridIdentityCoordinator::new(test_signing_key(33));
        let identity = test_signing_key(97).verifying_key();

        assert!(coordinator.claim_identity(IdentityLeg::Ws, "ws-conn", identity));
        assert!(!coordinator.claim_identity(IdentityLeg::P2p, "p2p-conn", identity));

        // The loser releasing its (never-granted) claim must not evict the winner.
        coordinator.release_identity(IdentityLeg::P2p, "p2p-conn", &identity);
        assert!(coordinator.claimant(&identity).is_some());

        coordinator.release_identity(IdentityLeg::Ws, "ws-conn", &identity);
        assert!(coordinator.claimant(&identity).is_none());

        // Now the P2P leg can claim it.
        assert!(coordinator.claim_identity(IdentityLeg::P2p, "p2p-conn", identity));
    }

    /// End-to-end: run the real challenge/response exchange between two
    /// coordinators (as `coordinator_runs_full_challenge_response_exchange`
    /// does), then feed the *verified* peer identity into `claim_identity`
    /// from both transport legs, proving the whole pipeline — sign, verify,
    /// dedupe — works together, not just each piece in isolation.
    #[test]
    fn full_exchange_then_duplicate_connection_is_rejected() {
        let local = HybridIdentityCoordinator::new(test_signing_key(50));
        let remote = HybridIdentityCoordinator::new(test_signing_key(51));

        // Remote connects to us over WS first: remote is the initiator.
        let (challenge_signed, orig_challenge) = remote.generate_challenge("local:4160");
        let header = algo_network::attach_challenge_header(&challenge_signed);
        let (response_signed, _response_challenge, verified_over_ws) = local
            .verify_challenge_and_respond(&header, &["local:4160"])
            .expect("local should verify remote's WS-leg challenge");
        let response_header = algo_network::attach_response_header(&response_signed);
        remote
            .verify_challenge_response(&response_header, &orig_challenge)
            .expect("remote should verify local's response");

        assert!(local.claim_identity(IdentityLeg::Ws, "remote-ws-addr:4160", verified_over_ws));

        // The same remote peer's P2P connection presents the identical
        // key (its `PeerId` derives from the same signer) — recognized as
        // the same identity, over a different connection: a duplicate.
        let verified_over_p2p = remote.public_key();
        assert_eq!(verified_over_ws, verified_over_p2p);
        assert!(!local.claim_identity(IdentityLeg::P2p, "QmRemotePeerId", verified_over_p2p));
    }
}
