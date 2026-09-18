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
use std::time::Duration;

use algo_network::handler::{TaggedMessageHandler, TaggedMessageValidatorHandler};
use algo_network::identity::IdentityChallengeValue;
use algo_network::mesh::{DEFAULT_GOSSIP_FANOUT, DEFAULT_MESH_INTERVAL};
use algo_network::{
    GossipNode, IdentityChallengeResponseSigned, IdentityChallengeSigned, IdentityError, Peer,
    PeerIdentity, PeerOption, Router, Tag,
};
use algo_p2p::IdentityTracker;
use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio_util::sync::CancellationToken;
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
    /// Overall target outgoing connection count the hybrid mesh scheduler
    /// (issue #1441) drives `primary`/`secondary` toward each cycle. See
    /// [`Self::with_mesh_target_conn_count`].
    mesh_target_conn_count: usize,
    /// How often [`Self::start`] re-runs the mesh scheduler. See
    /// [`Self::with_mesh_interval`].
    mesh_interval: Duration,
    /// Cancels the mesh-scheduler background task on [`Self::stop`].
    mesh_cancel: CancellationToken,
    /// The spawned mesh-scheduler loop, if [`Self::start`] has run.
    mesh_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
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
            mesh_target_conn_count: DEFAULT_GOSSIP_FANOUT,
            mesh_interval: DEFAULT_MESH_INTERVAL,
            mesh_cancel: CancellationToken::new(),
            mesh_task: Mutex::new(None),
        }
    }

    /// Override the overall target outgoing connection count the hybrid
    /// mesh scheduler drives `primary`(WS)/`secondary`(P2P) toward each
    /// cycle — go's `wsnet.config.GossipFanout`
    /// (`hybridRelayMeshCreator.create`, `withTargetConnCount`,
    /// `network/mesh.go`). Defaults to
    /// [`DEFAULT_GOSSIP_FANOUT`](algo_network::mesh::DEFAULT_GOSSIP_FANOUT)
    /// (4), matching both go's and this codebase's own WS
    /// [`MeshThread`](algo_network::mesh::MeshThread) default.
    pub fn with_mesh_target_conn_count(mut self, target_conn_count: usize) -> Self {
        self.mesh_target_conn_count = target_conn_count;
        self
    }

    /// Override how often the hybrid mesh scheduler re-runs — go's
    /// `meshThreadInterval` (`network/mesh.go`, default 1 minute, same as
    /// [`DEFAULT_MESH_INTERVAL`](algo_network::mesh::DEFAULT_MESH_INTERVAL)).
    /// Not called by any production call site yet (`participate.rs` keeps
    /// go's default interval); exercised by this module's own tests, which
    /// need a short interval to observe a scheduled cycle within a test
    /// timeout.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_mesh_interval(mut self, interval: Duration) -> Self {
        self.mesh_interval = interval;
        self
    }

    /// The cross-transport identity-challenge coordinator shared by this
    /// node's WS and P2P legs. See [`HybridIdentityCoordinator`].
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn identity(&self) -> &HybridIdentityCoordinator {
        &self.identity
    }
}

// ---------------------------------------------------------------------------
// WS-priority hybrid mesh scheduler (issue #1441)
// ---------------------------------------------------------------------------

/// WS-priority hybrid mesh scheduler — algod-rust's port of go's
/// `hybridRelayMeshCreator.meshFn` (`network/mesh.go`, introduced by
/// go-algorand commit 8e6354c79 / PR #6391, "network: wsnet with p2p
/// backup meshing strategy", first released v4.4.1-beta).
///
/// ## The decision go makes, mirrored exactly
///
/// Each mesh cycle, given an overall `target_conn_count`:
/// 1. Compute `ws_target`: normally `target_conn_count`, but if the
///    *previous* cycle's P2P leg reported `prev_p2p` connections and
///    `target_conn_count > prev_p2p`, reduce it to
///    `target_conn_count - prev_p2p` — don't re-ask WS to (re-)cover
///    ground P2P already held last cycle. (`prev_p2p` starts as "not
///    initialized" — the first cycle always asks WS for the *full*
///    target, exactly mirroring go's `prevP2PConnections != -1` guard and
///    its "skip p2p mesh reduction for the first time to give wsnet to
///    establish connections" comment.)
/// 2. Run the WS leg's mesh cycle with `ws_target`
///    ([`GossipNode::mesh_cycle`]), getting back `ws_connections` — WS's
///    *total* outgoing connection count after the attempt, not just
///    newly-dialed connections (matches go's `meshThreadInner` return
///    semantics exactly).
/// 3. If `ws_connections < target_conn_count`, ask P2P to cover the
///    shortfall: `p2p_target = target_conn_count - ws_connections`.
///    Otherwise `p2p_target = 0` — but P2P's mesh cycle still runs (go's
///    comment: "even if p2pTarget is zero it makes sense to call p2p
///    meshThreadInner to fetch DHT peers").
/// 4. Remember this cycle's `p2p_connections` as `prev_p2p` for next time.
///
/// The net effect: WS is *always* given first claim on the full target
/// (or whatever P2P didn't already prove it could hold), and P2P is asked
/// only to make up the shortfall left after WS's attempt — the two legs
/// never compete for the same slice of the target in the same cycle, and
/// P2P capacity is used only once WS capacity for that peer set is
/// exhausted.
///
/// ## Where this is driven from
///
/// [`DualGossipNode::start`] spawns a background task that calls
/// [`HybridMeshScheduler::mesh_cycle`] on a timer
/// ([`DualGossipNode::mesh_interval`], go's `meshThreadInterval`),
/// against `primary` (WS) as the WS leg and `secondary` (P2P) as the P2P
/// leg — mirroring `baseMesher.meshThread`'s periodic-timer/backoff loop
/// (`network/mesh.go`) minus its exponential-backoff-on-empty-phonebook
/// refinement, which is a smaller, separately addressable gap (this
/// scheduler always re-tries on the fixed interval rather than backing
/// off when a cycle finds nothing) rather than a scheduling-*decision*
/// divergence from `hybridRelayMeshCreator` itself.
pub struct HybridMeshScheduler {
    target_conn_count: usize,
    /// `None` == go's `prevP2PConnections == -1` ("not initialized").
    prev_p2p_connections: Option<usize>,
}

impl HybridMeshScheduler {
    pub fn new(target_conn_count: usize) -> Self {
        Self {
            target_conn_count,
            prev_p2p_connections: None,
        }
    }

    /// This scheduler's configured overall target outgoing connection
    /// count.
    pub fn target_conn_count(&self) -> usize {
        self.target_conn_count
    }

    /// Run one WS-priority/P2P-fallback mesh cycle over `ws` (the WS-leg
    /// [`GossipNode`]) and `p2p` (the P2P-leg [`GossipNode`]). Returns
    /// `(ws_connections, p2p_connections)` — go's `meshFn` sums these into
    /// the single `int` its caller (`baseMesher.meshThread`) uses for
    /// backoff-reset decisions; callers here can do the same
    /// (`ws + p2p > 0` mirrors go's `numOutgoing > 0`).
    pub async fn mesh_cycle(
        &mut self,
        ws: &Arc<dyn GossipNode>,
        p2p: &Arc<dyn GossipNode>,
    ) -> (usize, usize) {
        let ws_target = match self.prev_p2p_connections {
            Some(prev) if self.target_conn_count > prev => self.target_conn_count - prev,
            _ => self.target_conn_count,
        };
        let ws_connections = ws.mesh_cycle(ws_target).await;

        // Go: `if wsConnections < targetConnCount { p2pTarget = targetConnCount - wsConnections }`
        // (else `p2pTarget` stays its zero-initialized value) — equivalent
        // to `saturating_sub` since `ws_connections >= target_conn_count`
        // is exactly the case this would otherwise underflow.
        let p2p_target = self.target_conn_count.saturating_sub(ws_connections);
        let p2p_connections = p2p.mesh_cycle(p2p_target).await;

        self.prev_p2p_connections = Some(p2p_connections);
        (ws_connections, p2p_connections)
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
        self.secondary.start().await?;

        // Issue #1441: drive the WS-priority/P2P-fallback hybrid mesh
        // scheduler on a periodic timer, mirroring
        // `baseMesher.meshThread`'s ticker loop (`network/mesh.go`). Each
        // tick runs one `HybridMeshScheduler::mesh_cycle` against the two
        // legs. `primary`/`secondary` are cheap `Arc` clones, so the
        // spawned task doesn't borrow `self`.
        let primary = Arc::clone(&self.primary);
        let secondary = Arc::clone(&self.secondary);
        let mut scheduler = HybridMeshScheduler::new(self.mesh_target_conn_count);
        let mesh_interval = self.mesh_interval;
        let cancel = self.mesh_cancel.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(mesh_interval);
            // Consume the immediate first tick — go's ticker-driven mesh
            // thread doesn't fire on construction either, and the WS/P2P
            // legs each already ran their own startup mesh connect from
            // `self.primary.start()`/`self.secondary.start()` above.
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        debug!("hybrid mesh scheduler shutting down");
                        return;
                    }
                    _ = interval.tick() => {}
                }
                let (ws, p2p) = scheduler.mesh_cycle(&primary, &secondary).await;
                debug!(
                    ws,
                    p2p,
                    target = scheduler.target_conn_count(),
                    "hybrid mesh cycle"
                );
            }
        });
        *self.mesh_task.lock().expect("mesh_task mutex poisoned") = Some(handle);

        Ok(())
    }

    async fn stop(&self) {
        self.mesh_cancel.cancel();
        let handle = self
            .mesh_task
            .lock()
            .expect("mesh_task mutex poisoned")
            .take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
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

    // -----------------------------------------------------------------------
    // HybridMeshScheduler (issue #1441)
    // -----------------------------------------------------------------------

    /// A [`GossipNode`] test double whose `mesh_cycle` records every
    /// `target_conn_count` it was called with and returns a pre-scripted
    /// sequence of connection counts (one per call; the last value repeats
    /// once the script is exhausted) — lets a test pin exactly what target
    /// [`HybridMeshScheduler`] computed for each leg on each cycle, not
    /// just the final summed total.
    struct MeshTrackingNode {
        name: &'static str,
        targets_seen: Mutex<Vec<usize>>,
        script: Mutex<Vec<usize>>,
    }

    impl MeshTrackingNode {
        fn new(name: &'static str, script: Vec<usize>) -> Self {
            Self {
                name,
                targets_seen: Mutex::new(Vec::new()),
                script: Mutex::new(script),
            }
        }

        fn targets_seen(&self) -> Vec<usize> {
            self.targets_seen.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl GossipNode for MeshTrackingNode {
        fn address(&self) -> (String, bool) {
            (self.name.to_string(), true)
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

        async fn mesh_cycle(&self, target_conn_count: usize) -> usize {
            self.targets_seen.lock().unwrap().push(target_conn_count);
            let mut script = self.script.lock().unwrap();
            if script.len() > 1 {
                script.remove(0)
            } else {
                *script.first().unwrap_or(&0)
            }
        }

        fn get_peers(&self, _options: &[PeerOption]) -> Vec<Arc<dyn Peer>> {
            Vec::new()
        }
        async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn stop(&self) {}
        fn register_handlers(&self, _dispatch: Vec<TaggedMessageHandler>) {}
        fn clear_handlers(&self) {}
        fn register_validator_handlers(&self, _dispatch: Vec<TaggedMessageValidatorHandler>) {}
        fn clear_validator_handlers(&self) {}
        fn on_network_advance(&self) {}
        fn get_genesis_id(&self) -> &str {
            "test-genesis"
        }
        fn register_http_handler(&self, _path: &str, _handler: Router) {}
    }

    /// Core WS-priority behavior: when WS alone can fill the entire
    /// target, P2P must be asked for `0` — WS connections are preferred
    /// over P2P whenever both are available for the same peer-count slot.
    #[tokio::test]
    async fn ws_covers_full_target_p2p_gets_zero_target() {
        let ws_node = Arc::new(MeshTrackingNode::new("ws", vec![4]));
        let p2p_node = Arc::new(MeshTrackingNode::new("p2p", vec![0]));
        let ws: Arc<dyn GossipNode> = ws_node.clone();
        let p2p: Arc<dyn GossipNode> = p2p_node.clone();
        let mut scheduler = HybridMeshScheduler::new(4);

        let (ws_conns, p2p_conns) = scheduler.mesh_cycle(&ws, &p2p).await;

        assert_eq!(ws_conns, 4);
        assert_eq!(p2p_conns, 0);
        // WS was asked for the full target on the first cycle...
        assert_eq!(
            ws_node.targets_seen(),
            vec![4],
            "WS should always be asked for the full target first"
        );
        // ...and P2P was still invoked (to fetch DHT peers per go's
        // comment) but with target 0, since WS already met the target.
        assert_eq!(
            p2p_node.targets_seen(),
            vec![0],
            "P2P must be asked for 0 once WS alone meets the target"
        );
    }

    /// P2P fallback: when WS can only cover part of the target, P2P must
    /// be asked for exactly the shortfall (`target - ws_connections`) —
    /// P2P is used only as fallback once WS capacity is exhausted.
    #[tokio::test]
    async fn p2p_covers_shortfall_when_ws_capacity_exhausted() {
        let ws_node = Arc::new(MeshTrackingNode::new("ws", vec![1]));
        let p2p_node = Arc::new(MeshTrackingNode::new("p2p", vec![3]));
        let ws: Arc<dyn GossipNode> = ws_node.clone();
        let p2p: Arc<dyn GossipNode> = p2p_node.clone();
        let mut scheduler = HybridMeshScheduler::new(4);

        let (ws_conns, p2p_conns) = scheduler.mesh_cycle(&ws, &p2p).await;

        assert_eq!(ws_conns, 1);
        assert_eq!(p2p_conns, 3);
        assert_eq!(ws_node.targets_seen(), vec![4]);
        // Shortfall = target(4) - ws_connections(1) = 3.
        assert_eq!(p2p_node.targets_seen(), vec![3]);
    }

    /// The `prevP2PConnections` carry-over: once P2P has proven it can
    /// hold `prev_p2p` connections, the *next* cycle's WS target is
    /// reduced by that amount (`target - prev_p2p`), so WS isn't re-asked
    /// to cover ground P2P already has — go's
    /// "skip p2p mesh reduction... to give wsnet to establish connections"
    /// comment, applied from the second cycle onward.
    #[tokio::test]
    async fn ws_target_reduced_by_prior_cycles_p2p_connections() {
        // Cycle 1: WS only manages 1 of 4; P2P covers the other 3.
        let ws_node = Arc::new(MeshTrackingNode::new("ws", vec![1, 1]));
        let p2p_node = Arc::new(MeshTrackingNode::new("p2p", vec![3, 3]));
        let ws: Arc<dyn GossipNode> = ws_node.clone();
        let p2p: Arc<dyn GossipNode> = p2p_node.clone();
        let mut scheduler = HybridMeshScheduler::new(4);

        let _ = scheduler.mesh_cycle(&ws, &p2p).await;
        // Cycle 2: prev_p2p = 3, target(4) > 3, so ws_target = 4 - 3 = 1.
        let _ = scheduler.mesh_cycle(&ws, &p2p).await;

        assert_eq!(ws_node.targets_seen(), vec![4, 1]);
    }

    /// First cycle always asks WS for the *full* target — go's
    /// `prevP2PConnections != -1` guard means the reduction only applies
    /// from the second cycle onward, so a brand-new hybrid node's first
    /// mesh cycle doesn't shortchange WS before P2P has proven anything.
    #[tokio::test]
    async fn first_cycle_asks_ws_for_full_target_uninfluenced_by_p2p() {
        let ws_node = Arc::new(MeshTrackingNode::new("ws", vec![0]));
        let p2p_node = Arc::new(MeshTrackingNode::new("p2p", vec![4]));
        let ws: Arc<dyn GossipNode> = ws_node.clone();
        let p2p: Arc<dyn GossipNode> = p2p_node.clone();
        let mut scheduler = HybridMeshScheduler::new(4);

        let _ = scheduler.mesh_cycle(&ws, &p2p).await;

        assert_eq!(ws_node.targets_seen(), vec![4]);
    }

    /// When WS already meets or exceeds the target, P2P's mesh cycle is
    /// still *invoked* (target 0) rather than skipped entirely — matching
    /// go's explicit comment that a zero p2p target still fetches DHT
    /// peers.
    #[tokio::test]
    async fn p2p_still_invoked_with_zero_target_when_ws_exceeds_target() {
        let ws_node = Arc::new(MeshTrackingNode::new("ws", vec![5]));
        let p2p_node = Arc::new(MeshTrackingNode::new("p2p", vec![0]));
        let ws: Arc<dyn GossipNode> = ws_node.clone();
        let p2p: Arc<dyn GossipNode> = p2p_node.clone();
        let mut scheduler = HybridMeshScheduler::new(4);

        let (ws_conns, p2p_conns) = scheduler.mesh_cycle(&ws, &p2p).await;

        assert_eq!(ws_conns, 5);
        assert_eq!(p2p_conns, 0);
        assert_eq!(
            p2p_node.targets_seen().len(),
            1,
            "p2p.mesh_cycle must still be called even with target 0"
        );
        assert_eq!(p2p_node.targets_seen(), vec![0]);
    }

    /// The default `GossipNode::mesh_cycle` (used by transports that
    /// aren't a hybrid-mesh leg — bridges, mocks) returns 0 and does
    /// nothing; the scheduler must not panic or misbehave when driven
    /// against such a no-op leg, it just gets 0 back like any other
    /// result.
    #[tokio::test]
    async fn scheduler_tolerates_default_zero_mesh_cycle_leg() {
        let noop: Arc<dyn GossipNode> = Arc::new(MockNode::new("noop"));
        let p2p_node = Arc::new(MeshTrackingNode::new("p2p", vec![2]));
        let p2p: Arc<dyn GossipNode> = p2p_node.clone();
        let mut scheduler = HybridMeshScheduler::new(4);

        let (ws_conns, p2p_conns) = scheduler.mesh_cycle(&noop, &p2p).await;

        assert_eq!(ws_conns, 0);
        assert_eq!(p2p_conns, 2);
        assert_eq!(p2p_node.targets_seen(), vec![4]);
    }

    /// `DualGossipNode::start` actually spawns and drives the hybrid mesh
    /// scheduler — not just that `HybridMeshScheduler` exists in
    /// isolation. Uses a short mesh interval so at least one scheduled
    /// cycle runs within the test's timeout.
    #[tokio::test]
    async fn start_drives_at_least_one_scheduled_mesh_cycle() {
        let primary: Arc<dyn GossipNode> = Arc::new(MockNode::new("ws"));
        let secondary_tracking = Arc::new(MeshTrackingNode::new("p2p", vec![0]));
        let secondary: Arc<dyn GossipNode> = secondary_tracking.clone();

        let dual = DualGossipNode::new(primary, secondary, test_signing_key(60))
            .with_mesh_target_conn_count(4)
            .with_mesh_interval(Duration::from_millis(10));

        dual.start().await.expect("start should succeed");

        // Give the spawned scheduler task a couple of ticks to run.
        tokio::time::sleep(Duration::from_millis(60)).await;
        dual.stop().await;

        assert!(
            !secondary_tracking.targets_seen().is_empty(),
            "hybrid mesh scheduler should have run at least one cycle by now"
        );
    }
}
