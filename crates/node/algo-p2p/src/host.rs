//! libp2p host construction, listen, dial, and DHT peer discovery.
//!
//! Mirrors go-algorand's `network/p2p/p2p.go` `MakeHost` / `MakeService` /
//! `Start` / `dialNode` for the transport foundation (#538), plus
//! `network/p2p/dht/dht.go` `MakeDHT` and
//! `network/p2p/capabilities.go`'s `CapabilitiesDiscovery` for Kademlia DHT
//! peer discovery (#539): a libp2p `Swarm` secured with Noise over TCP,
//! composed with rust-libp2p's `kad` `NetworkBehaviour` for DHT routing,
//! plus `gossipsub` (#540) for block/vote/tx propagation pubsub.
//!
//! `rust-libp2p` performs the Noise handshake and yamux stream-muxer
//! upgrade as part of establishing a connection, before the connection is
//! handed to the [`libp2p::swarm::Swarm`] as [`SwarmEvent::ConnectionEstablished`].
//! Observing that event is therefore sufficient proof that a *secure*
//! (Noise-authenticated) libp2p connection exists — no application-level
//! protocol handshake is required for that guarantee.
//!
//! This host also composes rust-libp2p's `identify` `NetworkBehaviour`
//! alongside `kad`. This is not go-algorand-specific config (go-algorand's
//! `MakeHost` builds a plain `libp2p.New(...)` host with no explicit
//! Identify wiring) — it is present because go-libp2p (the Go
//! implementation) runs Identify as an always-on core protocol of every
//! host, and its `go-libp2p-kad-dht` internally subscribes to Identify's
//! address-learned events to populate its own routing table. rust-libp2p
//! makes this explicit rather than implicit (see [`libp2p::kad`]'s own
//! module docs: "the Identify protocol must be manually hooked up to
//! Kademlia through calls to `Behaviour::add_address`" — without it, a
//! Kademlia node cannot learn a newly-connected peer's actual *listen*
//! address, only the ephemeral address of whichever side dialed).
//!
//! Finally, this host composes rust-libp2p's `gossipsub` `NetworkBehaviour`
//! (#540) for block/vote/tx propagation — see the [`crate::pubsub`] module
//! for topic naming. Mirrors go-algorand's `network/p2p/pubsub.go`
//! `makePubSub`:
//! - `pubsub.WithMessageSignaturePolicy(pubsub.StrictNoSign)` — go publishes
//!   messages with no signature, sequence number, or `from` field, and
//!   rejects any inbound message that carries one. rust-libp2p's equivalent
//!   is [`gossipsub::MessageAuthenticity::Anonymous`] combined with
//!   [`gossipsub::ValidationMode::Anonymous`].
//! - go enables asynchronous per-message validation (the tag handler
//!   decides Accept/Reject/Ignore before a message is allowed to
//!   re-propagate) via `pubsub.ValidatorEx` registered per topic in
//!   `Subscribe`. rust-libp2p's equivalent is
//!   `gossipsub::ConfigBuilder::validate_messages(true)` plus
//!   [`P2pHost::report_message_validation_result`] — the caller must report
//!   a result for every [`gossipsub::Event::Message`] it receives via
//!   [`P2pHost::next_event`], or that message is held back from
//!   re-propagation indefinitely.

use std::time::Duration;

use libp2p::gossipsub::{self, MessageId, TopicHash};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, kad, noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};

use crate::dht;
use crate::errors::P2pError;
use crate::identity::IdentityConfig;

/// Default timeout applied to an outbound dial attempt.
///
/// Go: `network/p2p/p2p.go` `dialTimeout = 30 * time.Second`.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Default deadline applied to a single DHT closest-peers routing lookup
/// ([`P2pHost::find_closest_peers`]).
///
/// Not present verbatim in go — the closest analogue is
/// `network/p2p/capabilities.go`'s `operationTimeout = time.Second * 5`,
/// the context deadline `CapabilitiesDiscovery.PeersForCapability` applies
/// to its own DHT `FindPeers` call. Reused here for the same purpose: a
/// lookup that hasn't produced a final result within this window degrades
/// to "no result yet" (an empty peer list) rather than blocking the caller
/// forever or propagating an error — the go-algorand #6581 fix
/// ("dht: do not err on context deadline") this issue folds in.
pub const DHT_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// The `identify` protocol-version string this host advertises. Purely
/// informational (part of the `Info` payload, not the wire protocol name
/// used for negotiation) — go-algorand does not customize this either.
const IDENTIFY_PROTOCOL_VERSION: &str = "/algorand/id/1.0.0";

/// This host's composed `NetworkBehaviour`: Kademlia DHT peer routing on
/// top of the bare transport foundation from #538, plus `identify` so
/// `kad` can learn a connecting peer's real listen address (see this
/// module's doc comment).
#[derive(NetworkBehaviour)]
pub struct P2pBehaviour {
    kad: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
    gossipsub: gossipsub::Behaviour,
}

/// Outcome a caller reports for a received gossipsub message, mirroring
/// go-algorand's `pubsub.ValidationResult` (`ValidationAccept` /
/// `ValidationReject` / `ValidationIgnore`, as returned by e.g.
/// `P2PNetwork.txTopicValidator`):
/// - `Accept` — well-formed and passed application-level checks (e.g.
///   signature/format validation on untrusted gossip input); re-propagate
///   to the mesh.
/// - `Reject` — malformed or otherwise invalid; do not re-propagate, and
///   penalize the sending peer's gossipsub score.
/// - `Ignore` — valid enough not to penalize the sender (e.g. a duplicate
///   already known through another path) but not worth re-propagating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageValidationResult {
    Accept,
    Reject,
    Ignore,
}

impl From<MessageValidationResult> for gossipsub::MessageAcceptance {
    fn from(value: MessageValidationResult) -> Self {
        match value {
            MessageValidationResult::Accept => gossipsub::MessageAcceptance::Accept,
            MessageValidationResult::Reject => gossipsub::MessageAcceptance::Reject,
            MessageValidationResult::Ignore => gossipsub::MessageAcceptance::Ignore,
        }
    }
}

/// A libp2p host for the algod-rust P2P transport, with Kademlia DHT peer
/// discovery.
pub struct P2pHost {
    swarm: Swarm<P2pBehaviour>,
}

impl P2pHost {
    /// Build a new host from the given identity configuration and
    /// Algorand network ID (used to derive this DHT's protocol name — see
    /// [`dht::dht_protocol_name`]). Does not start listening — call
    /// [`P2pHost::listen`] to do so.
    ///
    /// Go: `MakeHost` (creates the libp2p host but does not listen) +
    /// `MakeDHT` (attaches the DHT behaviour).
    pub fn new(identity_cfg: &IdentityConfig, network_id: &str) -> Result<Self, P2pError> {
        let keypair = crate::identity::get_or_create_keypair(identity_cfg)?;
        let local_peer_id = keypair.public().to_peer_id();
        let kad_config = dht::dht_config(network_id);

        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| P2pError::SwarmBuild(e.to_string()))?
            .with_behaviour(|key| {
                let store = kad::store::MemoryStore::new(local_peer_id);
                let kad = kad::Behaviour::with_config(local_peer_id, store, kad_config);
                let identify = identify::Behaviour::new(identify::Config::new(
                    IDENTIFY_PROTOCOL_VERSION.to_string(),
                    key.public(),
                ));
                // Go: `makePubSub`'s `pubsub.WithMessageSignaturePolicy(pubsub.StrictNoSign)`
                // — no per-message signature/seqno/from, and
                // `pubsub.WithValidateQueueSize`+async `ValidatorEx` per topic —
                // `validate_messages(true)` is rust-libp2p's equivalent (see
                // this module's doc comment).
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .validation_mode(gossipsub::ValidationMode::Anonymous)
                    .validate_messages()
                    .build()
                    .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e.to_string()))?;
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Anonymous,
                    gossipsub_config,
                )
                .map_err(Box::<dyn std::error::Error + Send + Sync>::from)?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(P2pBehaviour {
                    kad,
                    identify,
                    gossipsub,
                })
            })
            .map_err(|e| P2pError::SwarmBuild(e.to_string()))?
            // The composed behaviour's connections stay alive through DHT
            // traffic once queries are running, but a freshly established
            // connection with no query in flight yet still benefits from a
            // grace period before rust-libp2p tears it back down — mirrors
            // the same reasoning as the #538 foundation's idle timeout.
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        Ok(Self { swarm })
    }

    /// This host's [`PeerId`], derived from its identity keypair's public
    /// key. Go: `serviceImpl.ID()`.
    pub fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Start listening on `addr`. Go: `serviceImpl.Start()`.
    pub fn listen(&mut self, addr: Multiaddr) -> Result<(), P2pError> {
        self.swarm
            .listen_on(addr.clone())
            .map(|_| ())
            .map_err(|source| P2pError::Listen {
                addr: addr.to_string(),
                source: Box::new(source),
            })
    }

    /// The addresses this host is actually listening on, once the
    /// transport has confirmed them (i.e. after at least one
    /// `SwarmEvent::NewListenAddr` has been observed via [`P2pHost::next_event`]).
    pub fn listen_addrs(&self) -> Vec<Multiaddr> {
        self.swarm.listeners().cloned().collect()
    }

    /// Dial a peer at the given multiaddr. This only initiates the dial;
    /// await [`P2pHost::next_event`] for the resulting
    /// `SwarmEvent::ConnectionEstablished` (or `OutgoingConnectionError`).
    ///
    /// Go: `serviceImpl.dialNode` (minus connection-manager protection,
    /// which belongs to the mesh-maintenance logic added by later sub-issues).
    pub fn dial(&mut self, addr: Multiaddr) -> Result<(), P2pError> {
        self.swarm
            .dial(addr.clone())
            .map_err(|source| P2pError::Dial {
                addr: addr.to_string(),
                source: Box::new(source),
            })
    }

    /// Await and return the next swarm event. Drives the underlying
    /// transport (handshakes, dial attempts, incoming connections) and the
    /// DHT behaviour's own query state machine.
    pub async fn next_event(&mut self) -> SwarmEvent<P2pBehaviourEvent> {
        use futures_util::StreamExt;
        let event = self.swarm.select_next_some().await;

        // Feed a newly-established connection's observed remote address
        // into the DHT routing table immediately, so a peer is at least
        // minimally routable (e.g. for the side that dialed it, where the
        // remote address dialed *is* a real listen address) even before
        // `identify` completes its own round-trip.
        if let SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } = &event
        {
            self.swarm
                .behaviour_mut()
                .kad
                .add_address(peer_id, endpoint.get_remote_address().clone());
        }

        // Once `identify` completes for a peer, replace that provisional
        // knowledge with its actual advertised listen addresses — this is
        // what lets a *third* node (one that only learned about this peer
        // secondhand, via a DHT `FIND_NODE` response) dial it successfully.
        // See this module's doc comment for why `identify` is needed here
        // at all: `kad` does not learn listen addresses on its own.
        if let SwarmEvent::Behaviour(P2pBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) = &event
        {
            for addr in &info.listen_addrs {
                self.swarm
                    .behaviour_mut()
                    .kad
                    .add_address(peer_id, addr.clone());
            }
        }

        event
    }

    /// Currently connected peers.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().copied().collect()
    }

    /// Subscribe to a gossipsub topic by name (see [`crate::pubsub`] for the
    /// topic names this crate defines). Idempotent: subscribing to a topic
    /// this host is already subscribed to is a no-op that returns `Ok(())`.
    ///
    /// Go: `serviceImpl.Subscribe`, called by e.g. `txTopicHandleLoop` for
    /// [`crate::pubsub::TX_TOPIC`].
    pub fn gossipsub_subscribe(&mut self, topic_name: &str) -> Result<(), P2pError> {
        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&crate::pubsub::ident_topic(topic_name))
            .map(|_| ())
            .map_err(|source| P2pError::GossipsubSubscribe {
                topic: topic_name.to_string(),
                source: Box::new(source),
            })
    }

    /// Unsubscribe from a gossipsub topic previously joined via
    /// [`P2pHost::gossipsub_subscribe`].
    pub fn gossipsub_unsubscribe(&mut self, topic_name: &str) -> Result<(), P2pError> {
        self.swarm
            .behaviour_mut()
            .gossipsub
            .unsubscribe(&crate::pubsub::ident_topic(topic_name))
            .map(|_| ())
            .map_err(|source| P2pError::GossipsubPublish {
                topic: topic_name.to_string(),
                source: Box::new(source),
            })
    }

    /// Publish `data` to a gossipsub topic. `data` is the raw tag payload,
    /// unwrapped — the topic name itself conveys the message tag, mirroring
    /// go-algorand's `serviceImpl.Publish` (`network/p2p/pubsub.go`), which
    /// likewise publishes the tag-specific payload bytes verbatim with no
    /// additional envelope.
    ///
    /// Returns the resulting [`MessageId`] so a caller that also wants to
    /// exclude/track its own publish (e.g. for de-duplication bookkeeping)
    /// can do so; most callers can ignore it.
    pub fn gossipsub_publish(
        &mut self,
        topic_name: &str,
        data: Vec<u8>,
    ) -> Result<MessageId, P2pError> {
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(crate::pubsub::ident_topic(topic_name), data)
            .map_err(|source| P2pError::GossipsubPublish {
                topic: topic_name.to_string(),
                source: Box::new(source),
            })
    }

    /// Report the outcome of validating a received gossipsub message
    /// ([`gossipsub::Event::Message`], surfaced via [`P2pHost::next_event`]).
    ///
    /// Must be called exactly once per received message — with
    /// `validate_messages(true)` (this host's config; see this module's
    /// doc comment), a message is held back from re-propagation until its
    /// validation result is reported. Mirrors go-algorand's
    /// `pubsub.ValidatorEx` callback return value
    /// (`txTopicValidator`'s `ValidationAccept` / `ValidationReject` /
    /// `ValidationIgnore`).
    pub fn report_message_validation_result(
        &mut self,
        msg_id: &MessageId,
        propagation_source: &PeerId,
        result: MessageValidationResult,
    ) {
        // A `false` return (message no longer in the validation cache —
        // e.g. reported twice, or reported after the cache evicted it) is
        // not actionable by the caller and mirrors go's own
        // `report_message_validation_result` semantics of being advisory
        // only; `PublishError` here would indicate an internal gossipsub
        // state issue, not an untrusted-input problem, so it is logged
        // rather than propagated as a caller-facing error.
        if let Err(e) = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(msg_id, propagation_source, result.into())
        {
            tracing::debug!(
                error = %e,
                "failed to report gossipsub message validation result"
            );
        }
    }

    /// Peers this host has in its gossipsub mesh for `topic_name` (i.e.
    /// peers messages on this topic are actively forwarded to/from, as
    /// opposed to merely being subscribed peers known via metadata
    /// exchange). Useful for tests and diagnostics.
    pub fn gossipsub_mesh_peers(&self, topic_name: &str) -> Vec<PeerId> {
        let hash: TopicHash = crate::pubsub::ident_topic(topic_name).hash();
        self.swarm
            .behaviour()
            .gossipsub
            .mesh_peers(&hash)
            .copied()
            .collect()
    }

    /// Explicitly set this host's DHT mode, or `None` to return to
    /// rust-libp2p's automatic mode-switching (client until an external
    /// address is confirmed reachable, then server).
    ///
    /// Go: `network/p2p/dht/dht.go` `dhtMode` — server if the node has a
    /// configured listen address (`cfg.IsListenServer()`) or `cfg.DHTMode`
    /// is explicitly `"server"`; client otherwise. This crate does not yet
    /// run Identify/AutoNAT to confirm external reachability (out of scope
    /// for DHT discovery itself), so rust-libp2p's automatic promotion to
    /// `Server` mode never fires on its own; a node meant to be
    /// discoverable (i.e. one with a listen address, mirroring go's
    /// default) should call this explicitly with `Some(kad::Mode::Server)`
    /// once it starts listening.
    pub fn set_dht_mode(&mut self, mode: Option<kad::Mode>) {
        self.swarm.behaviour_mut().kad.set_mode(mode);
    }

    /// Seed the DHT routing table with a known bootstrap peer's address.
    ///
    /// `addr` should be the peer's dialable transport address (i.e.
    /// without a trailing `/p2p/<peer-id>` component) — matching
    /// [`libp2p::kad::Behaviour::add_address`]'s expectations. Go:
    /// `dht.BootstrapPeersFunc`, sourced from the phonebook or `dnsaddr`
    /// DNS resolution (see [`crate::dnsaddr::resolve_multiaddrs`]).
    pub fn add_bootstrap_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.swarm.behaviour_mut().kad.add_address(&peer_id, addr);
    }

    /// Start (or restart) the DHT's self-lookup bootstrap process against
    /// whatever peers are currently in the routing table.
    ///
    /// A `NoKnownPeers` error (empty routing table — e.g. no bootstrap
    /// peers have been added yet via [`P2pHost::add_bootstrap_peer`], or
    /// none have been observed via [`P2pHost::next_event`]) is swallowed
    /// rather than surfaced: this mirrors the same "no result yet, not
    /// fatal" treatment this issue's #6581 fix applies to DHT operations
    /// that simply can't make progress yet.
    pub fn bootstrap_dht(&mut self) {
        let _ = self.swarm.behaviour_mut().kad.bootstrap();
    }

    /// Look up the peers closest to `target` via the Kademlia DHT.
    ///
    /// Degrades to "no result yet" (an empty list) rather than erroring out
    /// when the lookup does not produce a final result within `deadline` —
    /// this ports go-algorand's #6581 fix ("dht: do not err on context
    /// deadline", `network/p2p/capabilities.go`'s `advertiseCaps`): a DHT
    /// query hitting its deadline is business-as-usual, not a hard
    /// failure, since the caller (e.g. future capability-advertisement
    /// code, #541) should simply retry rather than treat it as an error
    /// condition. Both manifestations of "deadline" are handled the same
    /// way here:
    /// - `rust-libp2p`'s own internal per-query timeout
    ///   (`kad::GetClosestPeersError::Timeout`), which still carries
    ///   whatever partial peer set the query collected before it expired;
    /// - this function's own `deadline` parameter, for a caller-imposed
    ///   ceiling on how long it is willing to wait for a final result.
    pub async fn find_closest_peers(
        &mut self,
        target: PeerId,
        deadline: Duration,
    ) -> Vec<kad::PeerInfo> {
        let query_id = self.swarm.behaviour_mut().kad.get_closest_peers(target);
        let sleep = tokio::time::sleep(deadline);
        tokio::pin!(sleep);

        loop {
            tokio::select! {
                event = self.next_event() => {
                    if let SwarmEvent::Behaviour(P2pBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetClosestPeers(result),
                        step,
                        ..
                    })) = event
                    {
                        if id == query_id && step.last {
                            return match result {
                                Ok(ok) => ok.peers,
                                // go-algorand #6581: a query that only got as far as its
                                // internal context-deadline timeout still reports whatever
                                // partial peer set it collected, not an error.
                                Err(kad::GetClosestPeersError::Timeout { peers, .. }) => peers,
                            };
                        }
                    }
                }
                _ = &mut sleep => {
                    // Caller-side deadline elapsed before the query reached a final
                    // result. Same treatment as the internal-timeout case above:
                    // "no result yet", not an error.
                    return Vec::new();
                }
            }
        }
    }

    /// Advertise that this node offers `capability`, via the DHT's provider
    /// record mechanism (see [`crate::capabilities`]'s doc comment for why
    /// that is a distinct mechanism from the peer-routing DHT queries
    /// elsewhere in this module).
    ///
    /// Only a local-store failure (e.g. the provider-record store is at
    /// capacity) is surfaced as an `Err`. A query that does not reach a
    /// final `StartProviding` result within [`DHT_LOOKUP_TIMEOUT`] returns
    /// `Ok(())` anyway — this folds in both go-algorand's #6581 fix ("dht:
    /// do not err on context deadline") and #6595 ("chore: better error
    /// handling in fast catchup mode", the `capabilities.go` hunk that
    /// skips error-reporting once the surrounding context is already
    /// done): whether the operation timed out or the caller is shutting
    /// down, "advertisement didn't confirm yet" is not a condition the
    /// caller (e.g. a periodic re-advertisement loop) should treat as
    /// fatal — it should simply retry, mirroring go's
    /// `AdvertiseCapabilities` retry-with-backoff loop.
    pub async fn advertise_capability(
        &mut self,
        capability: crate::capabilities::Capability,
    ) -> Result<(), P2pError> {
        let query_id = self
            .swarm
            .behaviour_mut()
            .kad
            .start_providing(capability.record_key())
            .map_err(|source| P2pError::CapabilityAdvertise {
                capability: capability.namespace(),
                source,
            })?;

        let sleep = tokio::time::sleep(DHT_LOOKUP_TIMEOUT);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                event = self.next_event() => {
                    if let SwarmEvent::Behaviour(P2pBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::StartProviding(_),
                        ..
                    })) = event
                    {
                        if id == query_id {
                            return Ok(());
                        }
                    }
                }
                _ = &mut sleep => {
                    return Ok(());
                }
            }
        }
    }

    /// Look up up to `n` peers advertising `capability`, via the DHT's
    /// provider record mechanism. Excludes this host itself from the
    /// result (matching go's `PeersForCapability`, which explicitly
    /// excludes self so as not to confuse a caller looking for a *remote*
    /// peer with the capability).
    ///
    /// Degrades to "no result yet" (an empty list) rather than erroring
    /// out when the lookup does not produce a final result within
    /// `deadline` — same "no capable peer found yet, not a hard failure"
    /// treatment as [`P2pHost::find_closest_peers`] and
    /// [`P2pHost::advertise_capability`] (folding in go's #6581/#6595
    /// fixes); a node with no matching capability among its known peers
    /// naturally falls out of this as an empty `Vec`; too.
    pub async fn find_peers_for_capability(
        &mut self,
        capability: crate::capabilities::Capability,
        n: usize,
        deadline: Duration,
    ) -> Vec<PeerId> {
        let local_peer_id = self.peer_id();
        let key = capability.record_key();
        let query_id = self.swarm.behaviour_mut().kad.get_providers(key);

        let sleep = tokio::time::sleep(deadline);
        tokio::pin!(sleep);
        let mut found: Vec<PeerId> = Vec::new();

        loop {
            tokio::select! {
                event = self.next_event() => {
                    if let SwarmEvent::Behaviour(P2pBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetProviders(result),
                        step,
                        ..
                    })) = event
                    {
                        if id == query_id {
                            if let Ok(kad::GetProvidersOk::FoundProviders { providers, .. }) = &result {
                                for peer in providers {
                                    if *peer != local_peer_id && !found.contains(peer) {
                                        found.push(*peer);
                                    }
                                }
                            }
                            if found.len() >= n || step.last {
                                found.truncate(n);
                                return found;
                            }
                        }
                    }
                }
                _ = &mut sleep => {
                    found.truncate(n);
                    return found;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    /// Test network ID: keeps the DHT protocol name distinct from any real
    /// Algorand network, and stable across a test run.
    const TEST_NETWORK_ID: &str = "test-v1";

    fn loopback_identity() -> IdentityConfig {
        IdentityConfig::default()
    }

    fn new_test_host() -> P2pHost {
        P2pHost::new(&loopback_identity(), TEST_NETWORK_ID).expect("host")
    }

    async fn start_listening(host: &mut P2pHost) -> Multiaddr {
        host.listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .expect("listen");
        loop {
            match timeout(Duration::from_secs(5), host.next_event())
                .await
                .expect("timed out waiting for NewListenAddr")
            {
                SwarmEvent::NewListenAddr { address, .. } => break address,
                _ => continue,
            }
        }
    }

    /// TDD anchor for the transport foundation (#538): two independent
    /// `P2pHost`s, each with its own generated identity, dial each other
    /// over TCP+Noise+yamux and reach `ConnectionEstablished` on both
    /// sides.
    #[tokio::test]
    async fn two_nodes_dial_and_establish_secure_connection() {
        let mut listener = new_test_host();
        let mut dialer = new_test_host();

        let listen_addr = start_listening(&mut listener).await;

        let listener_peer_id = listener.peer_id();
        let dial_addr = listen_addr.with(libp2p::multiaddr::Protocol::P2p(listener_peer_id));
        dialer.dial(dial_addr).expect("dial should be accepted");

        let mut dialer_connected = false;
        let mut listener_connected = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

        while !(dialer_connected && listener_connected) {
            tokio::select! {
                ev = dialer.next_event() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = ev {
                        assert_eq!(peer_id, listener_peer_id);
                        dialer_connected = true;
                    }
                }
                ev = listener.next_event() => {
                    if let SwarmEvent::ConnectionEstablished { .. } = ev {
                        listener_connected = true;
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    panic!("timed out before both sides observed ConnectionEstablished");
                }
            }
        }

        assert!(dialer.connected_peers().contains(&listener_peer_id));
    }

    #[test]
    fn peer_id_is_derived_from_identity_and_stable() {
        let host = new_test_host();
        let id1 = host.peer_id();
        let id2 = host.peer_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn two_hosts_get_distinct_peer_ids() {
        let host_a = new_test_host();
        let host_b = new_test_host();
        assert_ne!(host_a.peer_id(), host_b.peer_id());
    }

    /// TDD anchor for this issue (#539): 3+ nodes bootstrap via the
    /// Kademlia DHT and can route-lookup each other's `PeerId` without any
    /// WS-gossip involvement. A "bootstrap" node (B) is the only address
    /// each of two other nodes (N1, N2) is seeded with; N1 and N2 never
    /// learn about each other directly. After both dial B and B's routing
    /// table observes both of them (via the `ConnectionEstablished` wiring
    /// in `next_event`), N1 performs a genuine DHT `get_closest_peers`
    /// lookup for N2's `PeerId` — routed through B — and must find N2's
    /// address, proving real DHT-based routing rather than direct
    /// knowledge.
    #[tokio::test]
    async fn three_nodes_bootstrap_via_dht_and_route_lookup_peer() {
        let mut bootstrap = new_test_host();
        let mut node1 = new_test_host();
        let mut node2 = new_test_host();

        // This crate has no AutoNAT wired up yet to auto-confirm external
        // reachability, so a node meant to answer DHT queries needs Server
        // mode set explicitly — see `set_dht_mode`'s doc comment. Both the
        // bootstrap node (queried by node1 directly) and node2 (queried by
        // node1 as the DHT lookup's second hop, once discovered via the
        // bootstrap node) need to be discoverable/queryable this way.
        bootstrap.set_dht_mode(Some(kad::Mode::Server));
        node2.set_dht_mode(Some(kad::Mode::Server));

        let bootstrap_addr = start_listening(&mut bootstrap).await;
        let bootstrap_peer_id = bootstrap.peer_id();
        // node2 also needs its own listen address so `identify` can report
        // a real, dialable address for it to the bootstrap node (and, from
        // there, to node1) — see this module's doc comment on why `identify`
        // is composed alongside `kad` at all.
        start_listening(&mut node2).await;

        let bootstrap_dial_addr = bootstrap_addr
            .clone()
            .with(libp2p::multiaddr::Protocol::P2p(bootstrap_peer_id));

        node1.add_bootstrap_peer(bootstrap_peer_id, bootstrap_addr.clone());
        node2.add_bootstrap_peer(bootstrap_peer_id, bootstrap_addr.clone());

        node1
            .dial(bootstrap_dial_addr.clone())
            .expect("node1 dial bootstrap");
        node2
            .dial(bootstrap_dial_addr)
            .expect("node2 dial bootstrap");

        // Drive all three swarms until the bootstrap node has both
        // connected to, and completed an `identify` exchange with, node1
        // and node2 — the latter is what actually populates bootstrap's
        // DHT routing table with node2's *real* (dialable) listen address
        // rather than just the ephemeral address node2 happened to dial
        // out from (see this module's doc comment on why `identify` is
        // composed alongside `kad`).
        let mut node1_identified = false;
        let mut node2_identified = false;
        let node1_peer_id = node1.peer_id();
        let node2_peer_id = node2.peer_id();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);

        while !(node1_identified && node2_identified) {
            tokio::select! {
                ev = bootstrap.next_event() => {
                    if let SwarmEvent::Behaviour(P2pBehaviourEvent::Identify(identify::Event::Received { peer_id, .. })) = ev {
                        if peer_id == node1_peer_id { node1_identified = true; }
                        if peer_id == node2_peer_id { node2_identified = true; }
                    }
                }
                _ = node1.next_event() => {}
                _ = node2.next_event() => {}
                _ = tokio::time::sleep_until(deadline) => {
                    panic!("timed out waiting for bootstrap to identify both nodes");
                }
            }
        }

        node1.bootstrap_dht();

        // Keep pumping bootstrap's and node2's swarm events in the
        // background while node1 runs its DHT lookup below — the lookup is
        // routed through the bootstrap node, which must still be
        // processing FIND_NODE requests/responses on the wire, and node2
        // must still be reachable for its address to be dialable.
        let bootstrap_pump = tokio::spawn(async move {
            loop {
                bootstrap.next_event().await;
            }
        });
        let node2_pump = tokio::spawn(async move {
            loop {
                node2.next_event().await;
            }
        });

        let found = node1
            .find_closest_peers(node2_peer_id, Duration::from_secs(10))
            .await;

        bootstrap_pump.abort();
        node2_pump.abort();

        assert!(
            found.iter().any(|p| p.peer_id == node2_peer_id),
            "expected node1's DHT route-lookup to find node2's PeerId via the bootstrap node, got: {found:?}"
        );
    }

    /// TDD anchor for the folded-in go-algorand #6581 fix: a DHT
    /// `get_closest_peers` lookup that never reaches a final result within
    /// its deadline must return an empty (no result yet) list, not an
    /// `Err` that would fail the caller. Uses an isolated host with an
    /// empty routing table and a deliberately tiny deadline so the lookup
    /// cannot possibly complete in time.
    #[tokio::test]
    async fn dht_lookup_hitting_deadline_does_not_error_out_caller() {
        let mut host = new_test_host();
        let target = PeerId::random();

        // 1 nanosecond: guaranteed to elapse before even a single swarm
        // event can be produced, forcing the deadline path.
        let found = host
            .find_closest_peers(target, Duration::from_nanos(1))
            .await;

        // The important assertion is not *that* an empty list is returned
        // (an empty routing table would do that anyway) but that this is
        // an infallible `Vec`, not a `Result` the caller could be forced
        // to propagate/log as an error — the type signature itself is the
        // regression guard for #6581's "do not err on context deadline".
        assert!(found.is_empty());
    }

    // -----------------------------------------------------------------------
    // gossipsub (#540)
    // -----------------------------------------------------------------------

    /// TDD anchor for this issue (#540): a block/vote/tx-shaped message
    /// published by one Rust `P2pHost` on a gossipsub topic reaches another
    /// Rust `P2pHost` subscribed to the same topic, and the receiving side
    /// can report a validation result for it (mirroring go-algorand's
    /// `pubsub.ValidatorEx` callback contract — see this module's doc
    /// comment on why `validate_messages(true)` requires that report).
    ///
    /// Two directly-connected peers subscribe to
    /// [`crate::pubsub::PROPOSAL_PAYLOAD_TOPIC`] (chosen instead of the TX
    /// topic to exercise a topic go-algorand itself does not yet gossip —
    /// see the `pubsub` module doc comment) and wait for gossipsub's own
    /// heartbeat to graft each other into the topic mesh before publishing,
    /// since a freshly-subscribed peer is not immediately meshed.
    #[tokio::test]
    async fn published_message_reaches_subscribed_peer_via_gossipsub() {
        let mut publisher = new_test_host();
        let mut subscriber = new_test_host();

        let listen_addr = start_listening(&mut subscriber).await;
        let subscriber_peer_id = subscriber.peer_id();
        let dial_addr = listen_addr.with(libp2p::multiaddr::Protocol::P2p(subscriber_peer_id));

        publisher
            .gossipsub_subscribe(crate::pubsub::PROPOSAL_PAYLOAD_TOPIC)
            .expect("publisher subscribe");
        subscriber
            .gossipsub_subscribe(crate::pubsub::PROPOSAL_PAYLOAD_TOPIC)
            .expect("subscriber subscribe");

        publisher.dial(dial_addr).expect("dial should be accepted");

        // Drive both swarms until each has seen the other's `Subscribed`
        // notification for the topic — proof both sides know about a
        // shared-topic peer, a precondition for gossipsub's heartbeat to
        // graft them into each other's mesh.
        let mut publisher_saw_subscriber = false;
        let mut subscriber_saw_publisher = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !(publisher_saw_subscriber && subscriber_saw_publisher) {
            tokio::select! {
                ev = publisher.next_event() => {
                    if let SwarmEvent::Behaviour(P2pBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, .. })) = ev {
                        if peer_id == subscriber_peer_id { publisher_saw_subscriber = true; }
                    }
                }
                ev = subscriber.next_event() => {
                    if let SwarmEvent::Behaviour(P2pBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, .. })) = ev {
                        subscriber_saw_publisher = true;
                        let _ = peer_id;
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    panic!("timed out before both sides observed Subscribed");
                }
            }
        }

        // Keep pumping the subscriber's swarm (heartbeats, mesh grafts) in
        // the background while the publisher waits out a couple of
        // gossipsub heartbeat intervals (default: 1s) so both sides graft
        // each other into the topic mesh before the publish below.
        let subscriber_task = tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
            loop {
                tokio::select! {
                    ev = subscriber.next_event() => {
                        if let SwarmEvent::Behaviour(P2pBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                            propagation_source,
                            message_id,
                            message,
                        })) = ev
                        {
                            subscriber.report_message_validation_result(
                                &message_id,
                                &propagation_source,
                                MessageValidationResult::Accept,
                            );
                            return (subscriber, message.data);
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        return (subscriber, Vec::new());
                    }
                }
            }
        });

        // Pump the publisher's swarm while waiting for mesh formation;
        // gossipsub's heartbeat runs on its own timer independent of
        // `next_event` being polled promptly, but connection-level
        // keepalive traffic still needs the swarm driven.
        let mesh_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < mesh_deadline {
            tokio::select! {
                _ = publisher.next_event() => {}
                _ = tokio::time::sleep_until(mesh_deadline) => {}
            }
        }

        let payload = b"block proposal payload bytes".to_vec();
        publisher
            .gossipsub_publish(crate::pubsub::PROPOSAL_PAYLOAD_TOPIC, payload.clone())
            .expect("publish should be accepted by a meshed topic");

        // Keep the publisher's swarm alive (gossipsub needs both sides
        // driven to actually push bytes over the wire) while awaiting the
        // subscriber's result.
        let publisher_pump = tokio::spawn(async move {
            loop {
                publisher.next_event().await;
            }
        });

        let (_, received) = tokio::time::timeout(Duration::from_secs(15), subscriber_task)
            .await
            .expect("subscriber task timed out")
            .expect("subscriber task panicked");

        publisher_pump.abort();

        assert_eq!(
            received, payload,
            "expected the subscriber to receive the publisher's exact payload bytes via gossipsub"
        );
    }

    /// The transaction topic name must be byte-for-byte identical to
    /// go-algorand's `network/p2p.TXTopicName` for real interop — this is
    /// a regression guard at the `P2pHost` API boundary (the constant
    /// itself is unit-tested directly in [`crate::pubsub`]).
    #[test]
    fn gossipsub_subscribe_accepts_the_go_compatible_tx_topic_name() {
        let mut host = new_test_host();
        assert_eq!(crate::pubsub::TX_TOPIC, "algotx01");
        host.gossipsub_subscribe(crate::pubsub::TX_TOPIC)
            .expect("subscribe to the go-compatible TX topic name");
    }

    // -----------------------------------------------------------------------
    // capability advertisement (#541)
    // -----------------------------------------------------------------------

    /// TDD anchor for this issue (#541): a node advertising the archival
    /// capability is discoverable via capability lookup by another node.
    ///
    /// Both sides need Kademlia `Server` mode (mirroring
    /// `three_nodes_bootstrap_via_dht_and_route_lookup_peer`'s reasoning):
    /// the provider must answer the seeker's inbound `GET_PROVIDERS` RPC,
    /// and the seeker must answer the provider's inbound `ADD_PROVIDER`
    /// RPC (issued while advertising) — each side is queried by the other
    /// at some point in this exchange.
    #[tokio::test]
    async fn capability_advertised_by_one_node_is_discoverable_by_another() {
        let mut provider = new_test_host();
        let mut seeker = new_test_host();

        provider.set_dht_mode(Some(kad::Mode::Server));
        seeker.set_dht_mode(Some(kad::Mode::Server));

        let listen_addr = start_listening(&mut seeker).await;
        let seeker_peer_id = seeker.peer_id();
        let dial_addr = listen_addr.with(libp2p::multiaddr::Protocol::P2p(seeker_peer_id));

        provider.dial(dial_addr).expect("dial should be accepted");

        let mut provider_connected = false;
        let mut seeker_connected = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !(provider_connected && seeker_connected) {
            tokio::select! {
                ev = provider.next_event() => {
                    if let SwarmEvent::ConnectionEstablished { .. } = ev { provider_connected = true; }
                }
                ev = seeker.next_event() => {
                    if let SwarmEvent::ConnectionEstablished { .. } = ev { seeker_connected = true; }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    panic!("timed out before both sides observed ConnectionEstablished");
                }
            }
        }

        let provider_peer_id = provider.peer_id();

        provider
            .advertise_capability(crate::capabilities::Capability::Archival)
            .await
            .expect("advertise should succeed against a store with capacity");

        // Keep the provider's swarm driven in the background while the
        // seeker looks it up — the seeker's `get_providers` query needs
        // the provider to be online to answer the inbound RPC.
        let provider_task = tokio::spawn(async move {
            loop {
                provider.next_event().await;
            }
        });

        let found = seeker
            .find_peers_for_capability(
                crate::capabilities::Capability::Archival,
                5,
                Duration::from_secs(10),
            )
            .await;

        provider_task.abort();

        assert!(
            found.contains(&provider_peer_id),
            "expected the seeker to discover the provider as an Archival-capability peer, got: {found:?}"
        );
    }

    /// TDD anchor for this issue (#541): a node with no matching
    /// capability among its known peers returns "not found" (an empty
    /// list), not an error — the infallible `Vec` return type of
    /// [`P2pHost::find_peers_for_capability`] is itself the regression
    /// guard, mirroring [`P2pHost::find_closest_peers`]'s same treatment.
    #[tokio::test]
    async fn capability_lookup_with_no_provider_returns_empty_not_error() {
        let mut host = new_test_host();

        let found = host
            .find_peers_for_capability(
                crate::capabilities::Capability::Catchpoints,
                5,
                Duration::from_millis(200),
            )
            .await;

        assert!(found.is_empty());
    }
}
