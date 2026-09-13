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

use ed25519_dalek::SigningKey;
use libp2p::connection_limits::{self, ConnectionLimits};
use libp2p::gossipsub::{self, MessageId, TopicHash};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, kad, noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};

use crate::conn_limits::{derive_conn_limits, ConnLimitConfig};
use crate::dht;
use crate::errors::P2pError;
use crate::identity::{to_identity_signing_key, IdentityConfig};
use crate::metrics::GossipsubMetrics;
use crate::pubsub::{derive_algorand_gossipsub_params, GossipsubMeshParams, IWANT_FOLLOWUP_TIME};

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
/// top of the bare transport foundation from #538, `identify` so
/// `kad` can learn a connecting peer's real listen address (see this
/// module's doc comment), `gossipsub` for TX propagation (the only tag
/// go-algorand itself gossips over pubsub in P2P mode — see
/// `crate::wsproto`'s doc comment), and `stream` (`libp2p-stream`) for
/// opening/accepting the raw `/algorand-ws/2.2.0` bidirectional streams
/// go-algorand actually uses for proposal/vote/bundle traffic.
#[derive(NetworkBehaviour)]
pub struct P2pBehaviour {
    kad: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
    gossipsub: gossipsub::Behaviour,
    stream: libp2p_stream::Behaviour,
    /// Enforces [`derive_conn_limits`]'s output as hard admission control on
    /// established connections. Go: `network/p2p/p2p.go` `MakeHost`'s
    /// `libp2p.ResourceManager(rm)` (`configureResourceManager`) — see
    /// [`P2pHostConfig`]'s doc comment for the scope this behaviour actually
    /// covers versus go's fuller resource-manager/connection-manager split.
    connection_limits: connection_limits::Behaviour,
}

/// Node-mode/config inputs [`P2pHost::new`] needs to derive live connection
/// limits and gossipsub mesh parameters, mirroring the subset of go's
/// `config.Local` that `deriveConnLimits`/`deriveAlgorandGossipSubParams`
/// consume (see `crate::conn_limits`/`crate::pubsub` for the derivation
/// logic itself). `Default` mirrors go's own `config/local_defaults.go`
/// (`GossipFanout: 4`) for every field except `incoming_connections_limit`
/// — go's shipped default there (`2400`) only means something once
/// `is_listen_server` is `true` (see [`derive_conn_limits`]'s doc comment:
/// the field is not consulted at all for a client), so this `Default`
/// mirrors go's own "unbounded/unused" client shape (`is_listen_server:
/// false`) rather than a listen-server value nothing here defaults to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P2pHostConfig {
    /// Go: `cfg.GossipFanout`. Feeds both [`derive_conn_limits`] and
    /// [`derive_algorand_gossipsub_params`].
    pub gossip_fanout: i64,
    /// Go: `cfg.IncomingConnectionsLimit`. Only consulted when
    /// `is_listen_server` is `true`.
    pub incoming_connections_limit: i64,
    /// Go: `cfg.IsListenServer()`.
    pub is_listen_server: bool,
    /// Go: `cfg.EnableDHTProviders`.
    pub enable_dht_providers: bool,
}

impl Default for P2pHostConfig {
    fn default() -> Self {
        Self {
            gossip_fanout: 4,
            incoming_connections_limit: -1,
            is_listen_server: false,
            enable_dht_providers: false,
        }
    }
}

/// Convert a possibly-unbounded `i64` limit from [`ConnLimitConfig`] (which
/// mirrors go's `int`/`math.MaxInt` "unbounded" convention) into the
/// `Option<u32>` shape `libp2p-connection-limits`'s [`ConnectionLimits`]
/// expects (`None` meaning "no limit"). Any non-positive value is also
/// treated as "no limit" here — [`derive_conn_limits`] only ever produces
/// `0` for a field that is genuinely inapplicable in that mode (e.g.
/// `rcmgr_conns_inbound` for a pure client), never as a real "deny
/// everything" limit, matching go's own `configureResourceManager`, which
/// likewise only sets a `rcmgr.LimitVal` override when the derived value is
/// `> 0`.
fn to_connection_limit(value: i64) -> Option<u32> {
    u32::try_from(value).ok().filter(|&v| v > 0)
}

/// Map [`derive_conn_limits`]'s output onto `libp2p-connection-limits`'s
/// [`ConnectionLimits`]. Only the three fields go's own
/// `configureResourceManager` actually overrides on top of
/// `rcmgr.DefaultLimits`'s auto-scaled per-scope defaults
/// (`system.Conns`/`ConnsInbound`/`ConnsOutbound`) have a mapping here;
/// `libp2p-connection-limits` has no per-peer/pending-connection
/// counterparts to those go leaves at their scaled defaults either, so
/// `max_pending_*`/`max_established_per_peer` are left unset (`None`).
fn conn_limits_to_libp2p(limits: ConnLimitConfig) -> ConnectionLimits {
    ConnectionLimits::default()
        .with_max_established(to_connection_limit(limits.rcmgr_conns))
        .with_max_established_incoming(to_connection_limit(limits.rcmgr_conns_inbound))
        .with_max_established_outgoing(to_connection_limit(limits.rcmgr_conns_outbound))
}

/// Map [`derive_algorand_gossipsub_params`]'s output onto a
/// [`gossipsub::ConfigBuilder`] — see [`GossipsubMeshParams`]'s doc comment
/// for the field-name mapping this follows. `DirectConnectInitialDelay`
/// (go's other non-D-family field this crate's `pubsub` module also
/// derives) has no equivalent knob on `libp2p-gossipsub`'s `ConfigBuilder`
/// — direct-peer connection maintenance is handled structurally differently
/// there (`explicit_peers`, which this crate does not use) — so it is not
/// applied here.
fn apply_gossipsub_mesh_params(
    builder: &mut gossipsub::ConfigBuilder,
    params: GossipsubMeshParams,
) {
    builder
        .mesh_n(params.d)
        .mesh_n_low(params.dlo)
        .mesh_n_high(params.dhi)
        .retain_scores(params.dscore)
        .mesh_outbound_min(params.dout)
        .gossip_lazy(params.dlazy)
        .history_length(params.history_length)
        .gossip_factor(params.gossip_factor)
        .iwant_followup_time(IWANT_FOLLOWUP_TIME);
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
    /// The connection limits actually derived and applied to
    /// `connection_limits::Behaviour` at construction time — kept for
    /// [`P2pHost::applied_connection_limits`] (tests/diagnostics), since
    /// `libp2p-connection-limits`'s own `ConnectionLimits` exposes no
    /// getters to read this back off the live behaviour.
    applied_connection_limits: ConnLimitConfig,
    /// The gossipsub mesh-degree parameters actually derived and applied to
    /// the `gossipsub::Behaviour`'s config at construction time — kept for
    /// [`P2pHost::applied_gossipsub_params`] (tests/diagnostics), for the
    /// same reason as `applied_connection_limits` above.
    applied_gossipsub_params: GossipsubMeshParams,
    /// Per-Algorand-tag gossipsub send/receive counters — see
    /// [`crate::metrics::GossipsubMetrics`] for why this lives here rather
    /// than on `gossipsub::Behaviour` itself (issue #1085).
    gossipsub_metrics: GossipsubMetrics,
    /// The raw Ed25519 signing key underlying this host's identity
    /// keypair (`identity::to_identity_signing_key`), kept alongside the
    /// swarm — which takes ownership of the `Keypair` itself — so a
    /// hybrid-mode caller can drive `algo_network::identity`'s netidentity
    /// challenge scheme with this same key (issue #1133), mirroring go's
    /// `P2PNetwork.PeerIDSigner()`.
    identity_signing_key: SigningKey,
}

impl P2pHost {
    /// Build a new host from the given identity configuration, Algorand
    /// network ID (used to derive this DHT's protocol name — see
    /// [`dht::dht_protocol_name`]), and node-mode config (connection-limit
    /// and gossipsub mesh-parameter derivation inputs — see
    /// [`P2pHostConfig`]). Does not start listening — call
    /// [`P2pHost::listen`] to do so.
    ///
    /// Go: `MakeHost` (creates the libp2p host but does not listen) +
    /// `MakeDHT` (attaches the DHT behaviour).
    pub fn new(
        identity_cfg: &IdentityConfig,
        network_id: &str,
        host_cfg: &P2pHostConfig,
    ) -> Result<Self, P2pError> {
        let keypair = crate::identity::get_or_create_keypair(identity_cfg)?;
        let local_peer_id = keypair.public().to_peer_id();
        // Captured before `keypair` is moved into `SwarmBuilder` below —
        // the swarm takes ownership of it and exposes no way to read it
        // back out, so this is this host's only chance to derive the
        // netidentity-scheme signer (issue #1133).
        let identity_signing_key = to_identity_signing_key(&keypair)?;
        let kad_config = dht::dht_config(network_id);
        let host_cfg = *host_cfg;

        let conn_limits_cfg = derive_conn_limits(
            host_cfg.gossip_fanout,
            host_cfg.incoming_connections_limit,
            host_cfg.is_listen_server,
            host_cfg.enable_dht_providers,
        );
        let gossipsub_params = derive_algorand_gossipsub_params(host_cfg.gossip_fanout);

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
                // this module's doc comment). Mesh-degree parameters are
                // go's `deriveAlgorandGossipSubParams(cfg.GossipFanout)`,
                // applied here in place of `libp2p-gossipsub`'s own
                // (unrelated) library defaults — see
                // `apply_gossipsub_mesh_params`.
                let mut gossipsub_config_builder = gossipsub::ConfigBuilder::default();
                gossipsub_config_builder
                    .validation_mode(gossipsub::ValidationMode::Anonymous)
                    .validate_messages();
                apply_gossipsub_mesh_params(&mut gossipsub_config_builder, gossipsub_params);
                let gossipsub_config = gossipsub_config_builder
                    .build()
                    .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e.to_string()))?;
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Anonymous,
                    gossipsub_config,
                )
                .map_err(Box::<dyn std::error::Error + Send + Sync>::from)?;
                let stream = libp2p_stream::Behaviour::new();
                // Go: `MakeHost`'s `libp2p.ResourceManager(rm)`
                // (`configureResourceManager(deriveConnLimits(cfg))`) — see
                // `conn_limits_to_libp2p` for the field mapping and its
                // scope-of-coverage caveat versus go's fuller
                // resource-manager/connection-manager split.
                let connection_limits =
                    connection_limits::Behaviour::new(conn_limits_to_libp2p(conn_limits_cfg));
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(P2pBehaviour {
                    kad,
                    identify,
                    gossipsub,
                    stream,
                    connection_limits,
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

        Ok(Self {
            swarm,
            applied_connection_limits: conn_limits_cfg,
            applied_gossipsub_params: gossipsub_params,
            gossipsub_metrics: GossipsubMetrics::new(),
            identity_signing_key,
        })
    }

    /// The connection-manager/resource-manager limits actually derived and
    /// enforced by this host's `connection_limits::Behaviour`, from the
    /// [`P2pHostConfig`] passed to [`P2pHost::new`]. Exposed for tests and
    /// diagnostics — see [`derive_conn_limits`].
    pub fn applied_connection_limits(&self) -> ConnLimitConfig {
        self.applied_connection_limits
    }

    /// The gossipsub mesh-degree parameters actually derived and applied to
    /// this host's gossipsub config, from the [`P2pHostConfig`] passed to
    /// [`P2pHost::new`]. Exposed for tests and diagnostics — see
    /// [`derive_algorand_gossipsub_params`].
    pub fn applied_gossipsub_params(&self) -> GossipsubMeshParams {
        self.applied_gossipsub_params
    }

    /// Per-Algorand-tag gossipsub send/receive counters recorded so far —
    /// see [`crate::metrics::GossipsubMetrics`]. Go: the per-tag Prometheus
    /// series `pubsubMetricsTracer` (`network/metrics.go`) maintains.
    pub fn gossipsub_metrics(&self) -> &GossipsubMetrics {
        &self.gossipsub_metrics
    }

    /// This host's [`PeerId`], derived from its identity keypair's public
    /// key. Go: `serviceImpl.ID()`.
    pub fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// This host's Ed25519 identity-signing key, i.e. the same key
    /// [`P2pHost::peer_id`] is derived from — see
    /// [`crate::identity::to_identity_signing_key`]. Exposed so a
    /// hybrid-mode caller (issue #1133) can drive
    /// `algo_network::identity`'s netidentity challenge/response/
    /// verification scheme with this transport's own peer identity,
    /// mirroring go's `P2PNetwork.PeerIDSigner()`.
    pub fn identity_signing_key(&self) -> &SigningKey {
        &self.identity_signing_key
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

    /// A cheap-to-clone handle for opening outbound `/algorand-ws/*` streams
    /// (or any other raw libp2p-stream protocol) and registering acceptors
    /// for inbound ones. See `crate::wsproto` for the framing/handshake run
    /// over the streams this produces.
    pub fn stream_control(&self) -> libp2p_stream::Control {
        self.swarm.behaviour().stream.new_control()
    }

    /// Dial a peer at the given multiaddr. This only initiates the dial;
    /// await [`P2pHost::next_event`] for the resulting
    /// `SwarmEvent::ConnectionEstablished` (or `OutgoingConnectionError`).
    ///
    /// Always allocates a fresh local port for the outbound connection
    /// (see [`DialOpts::allocate_new_port`]) rather than rust-libp2p's own
    /// default of best-effort reusing this host's *listening* port as the
    /// dial's local source port (`PortUse::Reuse` —
    /// `libp2p_swarm::dial_opts::WithoutPeerIdWithAddress`'s/
    /// `WithPeerId`'s default, since neither `P2pHost::new` nor this
    /// method ever opts into port reuse itself). That default exists to
    /// support NAT hole-punching (DCUtR: reusing the externally-mapped
    /// listen port lets a peer behind a NAT dial out using the same
    /// mapping a remote peer's simultaneous-connect attempt targets) —
    /// this crate does not implement AutoNAT/DCUtR (see this module's
    /// `set_dht_mode` doc comment), so nothing here needs it, and it is
    /// actively harmful in the meantime: when two `P2pHost`s configured as
    /// mutual bootstrap peers (issue #1067) dial each other at close to
    /// the same instant, both sides' outbound sockets bind to their own
    /// listen port before connecting, so the resulting connection is
    /// `local_listen_port <-> remote_listen_port` on *both* sides — the
    /// same 4-tuple from each host's perspective. The two dial attempts
    /// then race as a genuine TCP simultaneous-open on that shared
    /// 4-tuple, and each side's Noise/multistream-select stack proceeds
    /// as the *initiator* on what the OS has collapsed into one shared
    /// TCP stream, corrupting the handshake on both sides (`Handshake
    /// failed: input error` — reproduced by
    /// `tests::mutual_simultaneous_dial_still_establishes_a_secure_connection`).
    /// Forcing a fresh ephemeral port per dial (mirroring go-algorand's
    /// own `dialNode`, which never reuses its listen socket for outbound
    /// dials either) keeps every outbound connection's local port
    /// disjoint from this host's listen port, so a mutual dial always
    /// produces two independent 4-tuples — exactly like two peers dialing
    /// in only one direction, which this crate's other tests already
    /// cover.
    ///
    /// Go: `serviceImpl.dialNode` (minus connection-manager protection,
    /// which belongs to the mesh-maintenance logic added by later sub-issues).
    pub fn dial(&mut self, addr: Multiaddr) -> Result<(), P2pError> {
        let dial_opts = libp2p::swarm::dial_opts::DialOpts::unknown_peer_id()
            .address(addr.clone())
            .allocate_new_port()
            .build();
        self.swarm.dial(dial_opts).map_err(|source| P2pError::Dial {
            addr: addr.to_string(),
            source: Box::new(source),
        })
    }

    /// Dial a peer known only by its [`PeerId`] — no explicit [`Multiaddr`]
    /// required — resolving its dialable address(es) from whatever this
    /// host's `NetworkBehaviour`s already know about it.
    ///
    /// This is the piece [`P2pHost::dial`] can't provide: a peer discovered
    /// purely via [`P2pHost::find_closest_peers`]/
    /// [`P2pHost::find_peers_for_capability`] (issue #1073, mirroring go's
    /// periodic `meshThreadInner`/`refreshPeerStoreAddresses` mesh thread,
    /// `network/p2pNetwork.go`) is known only by `PeerId` — a DHT lookup's
    /// result is a set of `PeerId`s (or `PeerInfo`, whose addresses are
    /// already folded into the routing table as they're learned, see
    /// [`P2pHost::next_event`]'s `ConnectionEstablished`/`identify`
    /// handling), not a caller-supplied dial target.
    ///
    /// Building [`libp2p::swarm::dial_opts::DialOpts::peer_id`] with no
    /// explicit `.addresses(..)` sets
    /// `extend_addresses_through_behaviour: true` (`WithPeerId::build`,
    /// `libp2p-swarm`'s `dial_opts.rs`), which makes the `Swarm` ask every
    /// composed `NetworkBehaviour` — `kad` included — for addresses via
    /// `NetworkBehaviour::handle_pending_outbound_connection`.
    /// `kad::Behaviour`'s implementation returns that peer's k-bucket
    /// addresses (`libp2p-kad`'s `behaviour.rs`), the same addresses a
    /// `find_closest_peers`/`find_peers_for_capability` query (or a prior
    /// `ConnectionEstablished`/`identify::Event::Received`) already fed into
    /// the routing table via [`kad::Behaviour::add_address`] — this is what
    /// lets a peer this host has *never* directly connected to, but only
    /// learned about secondhand through the DHT, still be dialable here.
    /// Mirrors go's `dialNode`, which resolves a `peer.AddrInfo`'s addresses
    /// from its own libp2p peerstore the same way.
    ///
    /// The default [`libp2p::swarm::dial_opts::PeerCondition`]
    /// (`DisconnectedAndNotDialing`) is left as-is rather than overridden:
    /// it already skips the dial as a no-op when this peer is already
    /// connected or has an outbound dial attempt in flight, so a caller
    /// re-running periodic discovery does not need its own
    /// already-connected/already-dialing bookkeeping to avoid a redundant
    /// dial — the same property [`P2pHost::dial`]'s bootstrap-peer callers
    /// get implicitly today.
    pub fn dial_peer(&mut self, peer_id: PeerId) -> Result<(), P2pError> {
        let dial_opts = libp2p::swarm::dial_opts::DialOpts::peer_id(peer_id)
            .allocate_new_port()
            .build();
        self.swarm.dial(dial_opts).map_err(|source| P2pError::Dial {
            addr: peer_id.to_string(),
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

        // Feed every peer address a `get_closest_peers` query result
        // carries into this host's own DHT routing table (issue #1073's
        // mesh-discovery wiring) — generic over *any* such query, not just
        // ones issued through [`P2pHost::find_closest_peers`], so a
        // non-blocking caller driving its own event loop directly (e.g.
        // `bin/algod-rust`'s periodic mesh-discovery task, which cannot
        // block its shared swarm loop awaiting a whole query the way
        // [`P2pHost::find_closest_peers`]'s own callers can) still gets the
        // same registration as a side effect of simply observing this
        // event. Without this, a peer learned about purely through such a
        // query — never directly connected to, never `identify`-d (the
        // other two paths that call `add_address` above) — has no address
        // [`P2pHost::dial_peer`] can resolve via
        // `extend_addresses_through_behaviour`, even though the query just
        // received exactly that address from a peer that does know it.
        if let SwarmEvent::Behaviour(P2pBehaviourEvent::Kad(
            kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::GetClosestPeers(result),
                ..
            },
        )) = &event
        {
            let peers = match result {
                Ok(ok) => &ok.peers,
                // go-algorand #6581: a query that only got as far as its
                // internal context-deadline timeout still reports whatever
                // partial peer set it collected, not an error — still
                // worth registering.
                Err(kad::GetClosestPeersError::Timeout { peers, .. }) => peers,
            };
            for info in peers {
                for addr in &info.addrs {
                    self.swarm
                        .behaviour_mut()
                        .kad
                        .add_address(&info.peer_id, addr.clone());
                }
            }
        }

        // Go: `pubsubMetricsTracer.RecvRPC`, which counts an incoming
        // message's bytes against its topic's tag as soon as the RPC
        // carrying it is received — before the message is handed to the
        // application's own validator (reported back separately via
        // `report_message_validation_result`). `gossipsub::Event::Message`
        // is rust-libp2p's equivalent per-message (already unwrapped from
        // its RPC) observation point.
        if let SwarmEvent::Behaviour(P2pBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            message,
            ..
        })) = &event
        {
            if let Some(tag) = crate::pubsub::tag_code_for_topic_name(message.topic.as_str()) {
                self.gossipsub_metrics
                    .record_received(tag, message.data.len());
            }
        }

        event
    }

    /// Start a (non-blocking) DHT lookup for peers advertising `capability`,
    /// via the provider-record mechanism — the non-blocking counterpart of
    /// [`P2pHost::find_peers_for_capability`] for a caller that cannot await
    /// a whole query without starving its own shared event loop of every
    /// *other* event in the meantime (issue #1073: `bin/algod-rust`'s
    /// `P2pTransport::start` background task is exactly such a caller — it
    /// must keep processing `ConnectionEstablished`/gossipsub/stream events
    /// concurrently with a periodic capability lookup, which
    /// [`P2pHost::find_peers_for_capability`]'s own internal
    /// `self.next_event()` loop cannot do since it owns `&mut self`
    /// exclusively until the whole query resolves).
    ///
    /// Returns the [`kad::QueryId`] to correlate against this same query's
    /// own `kad::Event::OutboundQueryProgressed{result: GetProviders(_),
    /// ..}` events as they arrive through the caller's own
    /// [`P2pHost::next_event`] polling.
    pub fn start_capability_discovery(
        &mut self,
        capability: crate::capabilities::Capability,
    ) -> kad::QueryId {
        self.swarm
            .behaviour_mut()
            .kad
            .get_providers(capability.record_key())
    }

    /// Start a (non-blocking) DHT closest-peers lookup for `target` — the
    /// non-blocking counterpart of [`P2pHost::find_closest_peers`], for the
    /// same reason [`P2pHost::start_capability_discovery`] exists (issue
    /// #1073).
    ///
    /// The caller does not need to inspect this query's own result to
    /// benefit from it: [`P2pHost::next_event`] already registers every
    /// returned peer's address into this host's routing table as a generic
    /// side effect of observing the event at all (see its doc comment) —
    /// the returned [`kad::QueryId`] exists only so the caller can tell
    /// *when* that has happened (the query's `step.last` event) in order to
    /// then dial the peer via [`P2pHost::dial_peer`].
    pub fn start_closest_peers_lookup(&mut self, target: PeerId) -> kad::QueryId {
        self.swarm.behaviour_mut().kad.get_closest_peers(target)
    }

    /// Currently connected peers.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().copied().collect()
    }

    /// Forcibly close one specific established connection, identified by
    /// its [`libp2p::swarm::ConnectionId`] (from a previously observed
    /// `SwarmEvent::ConnectionEstablished`/`ConnectionClosed`). Returns
    /// `true` if a connection with that id was found and is now closing.
    ///
    /// Used by [`crate::identity_tracker`]'s live wiring (issue #952): when
    /// two connections to the same peer identity race (both established
    /// before either side's redundant-connection dedup could prevent it —
    /// mirroring go's `identityTracker`/`p2pNetwork.go`'s
    /// `stream.Close()` on the loser), the connection that lost the
    /// [`crate::identity_tracker::IdentityTracker::set_identity`] race is
    /// closed via this method rather than left to linger as a second,
    /// redundant transport-level connection to the same logical peer.
    pub fn close_connection(&mut self, connection_id: libp2p::swarm::ConnectionId) -> bool {
        self.swarm.close_connection(connection_id)
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

    /// Whether this host currently holds a live gossipsub subscription to
    /// `topic_name`. Exercised by tests (issue #1221's `P2pTransport`
    /// TX-topic gating) to observe the actual gossipsub subscription state
    /// this host's underlying `gossipsub::Behaviour` tracks, rather than
    /// only a caller-side bookkeeping flag.
    pub fn gossipsub_is_subscribed(&self, topic_name: &str) -> bool {
        let target = crate::pubsub::ident_topic(topic_name).hash();
        self.swarm
            .behaviour()
            .gossipsub
            .topics()
            .any(|t| *t == target)
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
        let payload_len = data.len();
        let result = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(crate::pubsub::ident_topic(topic_name), data)
            .map_err(|source| P2pError::GossipsubPublish {
                topic: topic_name.to_string(),
                source: Box::new(source),
            });
        // Go: `pubsubMetricsTracer.SendRPC`, called for every RPC gossipsub
        // actually hands to a peer connection. `publish()` fans the message
        // out to this host's whole mesh in one call rather than per-peer
        // RPCs, so — unlike go, which increments once per outbound RPC (one
        // per mesh peer) — this counts once per logical publish; the
        // byte/message-count *shape* (one series per tag) still matches,
        // just not the exact multiplier for a multi-peer mesh.
        if result.is_ok() {
            if let Some(tag) = crate::pubsub::tag_code_for_topic_name(topic_name) {
                self.gossipsub_metrics.record_sent(tag, payload_len);
            }
        }
        result
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
                            // `self.next_event()` above already fed every
                            // returned peer's address into this host's own
                            // DHT routing table as a generic side effect of
                            // observing this same event (see its doc
                            // comment) — nothing further to do here beyond
                            // returning the peer list itself.
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
    ///
    /// Every returned `PeerId` is also address-resolvable via
    /// [`P2pHost::dial_peer`] afterward (issue #1073): unlike
    /// [`P2pHost::find_closest_peers`]'s `kad::PeerInfo` result,
    /// `kad::GetProvidersOk::FoundProviders` carries only bare `PeerId`s —
    /// `kad::Behaviour`'s own conversion discards the wire-level
    /// `KadPeer.multiaddrs` for this particular event (`libp2p-kad`'s
    /// `behaviour.rs`) — so each discovered provider's address is resolved
    /// (and, as a side effect, registered into this host's own DHT routing
    /// table) via a follow-up [`P2pHost::find_closest_peers`] call, whose
    /// result type does carry addresses. Mirrors go's `PeersForCapability`,
    /// which returns `peer.AddrInfo` (identity + addresses) rather than a
    /// bare `peer.ID`, because go-libp2p's `RoutingDiscovery.FindPeers`
    /// folds in its own peerstore's address knowledge that rust-libp2p's
    /// public `GetProvidersOk` event does not expose.
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
                                break;
                            }
                        }
                    }
                }
                _ = &mut sleep => {
                    found.truncate(n);
                    break;
                }
            }
        }

        for peer in &found {
            self.find_closest_peers(*peer, deadline).await;
        }

        found
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
        P2pHost::new(
            &loopback_identity(),
            TEST_NETWORK_ID,
            &P2pHostConfig::default(),
        )
        .expect("host")
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

    /// Go: `TestP2PGetPeersTransportConnections` (`network/p2pNetwork_test.go`)
    /// — asserts a "transport connections" view distinct from the
    /// gossip-peer view: exactly one connection is enumerated per side,
    /// each carrying the correct direction (in on the listener, out on the
    /// dialer), and the count is zero before the connection exists.
    ///
    /// `algo-p2p` has no separate gossip-peer abstraction of its own (that
    /// layer lives above this crate, in the daemon's dual-transport
    /// wiring), so [`P2pHost::connected_peers`] *is* this crate's
    /// transport-connections accessor — this test is its dedicated unit
    /// test: empty before dialing, and after a real connection is
    /// established, each side's `connected_peers()` contains exactly the
    /// other side's `PeerId` and nothing else.
    #[tokio::test]
    async fn connected_peers_reflects_established_connection_symmetrically() {
        let mut listener = new_test_host();
        let mut dialer = new_test_host();

        assert!(listener.connected_peers().is_empty());
        assert!(dialer.connected_peers().is_empty());

        let listen_addr = start_listening(&mut listener).await;
        let listener_peer_id = listener.peer_id();
        let dialer_peer_id = dialer.peer_id();
        let dial_addr = listen_addr.with(libp2p::multiaddr::Protocol::P2p(listener_peer_id));
        dialer.dial(dial_addr).expect("dial should be accepted");

        let mut dialer_connected = false;
        let mut listener_connected = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !(dialer_connected && listener_connected) {
            tokio::select! {
                ev = dialer.next_event() => {
                    if let SwarmEvent::ConnectionEstablished { .. } = ev { dialer_connected = true; }
                }
                ev = listener.next_event() => {
                    if let SwarmEvent::ConnectionEstablished { .. } = ev { listener_connected = true; }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    panic!("timed out before both sides observed ConnectionEstablished");
                }
            }
        }

        assert_eq!(
            dialer.connected_peers(),
            vec![listener_peer_id],
            "the dialer's transport-connections view must contain exactly the listener"
        );
        assert_eq!(
            listener.connected_peers(),
            vec![dialer_peer_id],
            "the listener's transport-connections view must contain exactly the dialer"
        );
    }

    /// TDD anchor for issue #1067: two `P2pHost`s that **each** dial the
    /// other at (effectively) the same instant — mirroring
    /// `--p2p-bootstrap-peers` configuring both sides of a pair to list
    /// each other, as `bin/algod-rust/tests/p2p_multi_node_consensus.rs`
    /// does for issue #827's harness — must both still reach a secure
    /// `ConnectionEstablished` on at least one resulting connection, not
    /// fail the underlying Noise handshake on either side.
    ///
    /// Every other test in this module (`two_nodes_dial_and_establish_secure_connection`
    /// included) only ever dials in one direction, so this is the first
    /// coverage of the simultaneous/mutual-dial path at all. Each side is
    /// driven on its own spawned task on a genuinely multi-threaded
    /// runtime (real OS-thread parallelism, not single-task cooperative
    /// polling) — the failure reported in #1067 is a race that needs true
    /// simultaneity between both sides' dial and handshake I/O, which a
    /// single task round-robining two futures via `tokio::select!` does
    /// not reliably reproduce. A single attempt is deliberate: looping
    /// this same-process race dozens of times in a tight loop was found
    /// to manufacture its own, unrelated flakiness on this crate's
    /// Windows dev environment (rapid-fire loopback socket churn
    /// exhausting the ephemeral port range into `WSAECONNABORTED`, a
    /// Windows-loopback-only artifact of the stress rather than of
    /// #1067's actual bug — a single iteration in a fresh process never
    /// reproduced it across 15/15 runs, while 5 iterations in one process
    /// did in 4/15). One real attempt per test run is enough to catch the
    /// regression (confirmed failing against the pre-fix code) without
    /// that self-inflicted noise.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mutual_simultaneous_dial_still_establishes_a_secure_connection() {
        let mut host_a = new_test_host();
        let mut host_b = new_test_host();

        let addr_a = start_listening(&mut host_a).await;
        let addr_b = start_listening(&mut host_b).await;

        let peer_a = host_a.peer_id();
        let peer_b = host_b.peer_id();

        let dial_a_to_b = addr_b.with(libp2p::multiaddr::Protocol::P2p(peer_b));
        let dial_b_to_a = addr_a.with(libp2p::multiaddr::Protocol::P2p(peer_a));

        host_a.dial(dial_a_to_b).expect("a dials b");
        host_b.dial(dial_b_to_a).expect("b dials a");

        let task_a = tokio::spawn(async move {
            let mut connected = false;
            let mut errors: Vec<String> = Vec::new();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
            while !connected {
                tokio::select! {
                    ev = host_a.next_event() => {
                        match ev {
                            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer_b => {
                                connected = true;
                            }
                            SwarmEvent::OutgoingConnectionError { error, .. } => {
                                errors.push(format!("outgoing: {error}"));
                            }
                            SwarmEvent::IncomingConnectionError { error, .. } => {
                                errors.push(format!("incoming: {error}"));
                            }
                            _ => {}
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => break,
                }
            }
            (connected, errors)
        });
        let task_b = tokio::spawn(async move {
            let mut connected = false;
            let mut errors: Vec<String> = Vec::new();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
            while !connected {
                tokio::select! {
                    ev = host_b.next_event() => {
                        match ev {
                            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer_a => {
                                connected = true;
                            }
                            SwarmEvent::OutgoingConnectionError { error, .. } => {
                                errors.push(format!("outgoing: {error}"));
                            }
                            SwarmEvent::IncomingConnectionError { error, .. } => {
                                errors.push(format!("incoming: {error}"));
                            }
                            _ => {}
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => break,
                }
            }
            (connected, errors)
        });

        let (a_connected, a_dial_errors) = task_a.await.expect("task a panicked");
        let (b_connected, b_dial_errors) = task_b.await.expect("task b panicked");

        assert!(
            a_connected && b_connected,
            "timed out waiting for both sides to establish a secure connection under mutual dial \
             (a_connected={a_connected}, b_connected={b_connected}, \
             a_dial_errors={a_dial_errors:?}, b_dial_errors={b_dial_errors:?})"
        );
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

    /// TDD anchor for issue #1085: sending and receiving a `TX`-tagged
    /// gossipsub message updates both sides' per-tag counters
    /// ([`crate::metrics::GossipsubMetrics`]), mirroring go-algorand's
    /// `pubsubMetricsTracer` (`network/metrics.go`) — the publisher's
    /// `SendRPC`-equivalent count and the subscriber's `RecvRPC`-equivalent
    /// count, both keyed by the `TX` tag derived from
    /// [`crate::pubsub::TX_TOPIC`]. Uses the real TX topic (rather than
    /// [`crate::pubsub::PROPOSAL_PAYLOAD_TOPIC`], as
    /// [`published_message_reaches_subscribed_peer_via_gossipsub`] does)
    /// since `TX` is the one tag go-algorand v5.0.0-stable itself gossips
    /// and tracks metrics for.
    #[tokio::test]
    async fn gossipsub_publish_and_receive_update_per_tag_metrics() {
        let mut publisher = new_test_host();
        let mut subscriber = new_test_host();

        let listen_addr = start_listening(&mut subscriber).await;
        let subscriber_peer_id = subscriber.peer_id();
        let dial_addr = listen_addr.with(libp2p::multiaddr::Protocol::P2p(subscriber_peer_id));

        publisher
            .gossipsub_subscribe(crate::pubsub::TX_TOPIC)
            .expect("publisher subscribe");
        subscriber
            .gossipsub_subscribe(crate::pubsub::TX_TOPIC)
            .expect("subscriber subscribe");

        publisher.dial(dial_addr).expect("dial should be accepted");

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

        // Before anything is published, both sides' TX counters are zero —
        // proof the test below is measuring an actual increment, not a
        // pre-existing nonzero baseline.
        assert_eq!(
            publisher.gossipsub_metrics().sent_for_tag("TX"),
            crate::metrics::GossipsubTagCounts::default()
        );
        assert_eq!(
            subscriber.gossipsub_metrics().received_for_tag("TX"),
            crate::metrics::GossipsubTagCounts::default()
        );

        let subscriber_task = tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
            loop {
                tokio::select! {
                    ev = subscriber.next_event() => {
                        if let SwarmEvent::Behaviour(P2pBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                            propagation_source,
                            message_id,
                            ..
                        })) = ev
                        {
                            subscriber.report_message_validation_result(
                                &message_id,
                                &propagation_source,
                                MessageValidationResult::Accept,
                            );
                            return subscriber.gossipsub_metrics().received_for_tag("TX");
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        return subscriber.gossipsub_metrics().received_for_tag("TX");
                    }
                }
            }
        });

        let mesh_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < mesh_deadline {
            tokio::select! {
                _ = publisher.next_event() => {}
                _ = tokio::time::sleep_until(mesh_deadline) => {}
            }
        }

        let payload = b"serialized SignedTxn bytes".to_vec();
        publisher
            .gossipsub_publish(crate::pubsub::TX_TOPIC, payload.clone())
            .expect("publish should be accepted by a meshed topic");

        assert_eq!(
            publisher.gossipsub_metrics().sent_for_tag("TX"),
            crate::metrics::GossipsubTagCounts {
                messages: 1,
                bytes: payload.len() as u64,
            },
            "publisher's own sent-side counter should update synchronously on a successful publish"
        );

        let publisher_pump = tokio::spawn(async move {
            loop {
                publisher.next_event().await;
            }
        });

        let received_counts = tokio::time::timeout(Duration::from_secs(15), subscriber_task)
            .await
            .expect("subscriber task timed out")
            .expect("subscriber task panicked");

        publisher_pump.abort();

        assert_eq!(
            received_counts,
            crate::metrics::GossipsubTagCounts {
                messages: 1,
                bytes: payload.len() as u64,
            },
            "expected the subscriber's TX receive-side counter to record exactly one message of the published size"
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

    /// Go: `TestCapabilities_Varying` (`network/p2p/capabilities_test.go`) —
    /// scaled down from go's 10-node cluster (which additionally sweeps a
    /// "bootstrap through only 2 of them" topology variant) to a star of 4
    /// directly-connected hosts, but exercising the same property go's test
    /// name describes: distinct peers advertising *different, overlapping*
    /// capability sets are each found only under the capability they
    /// actually advertised, not lumped into a single always-both scenario.
    /// `archival_only` and `catchpoints_only` each advertise one capability;
    /// `both` advertises both; a `seeker` (advertising neither) looks up
    /// each capability and expects exactly the two peers that advertised it.
    #[tokio::test]
    async fn capability_advertised_by_varying_peers_is_found_by_matching_capability_only() {
        use crate::capabilities::Capability;

        let mut seeker = new_test_host();
        let mut archival_only = new_test_host();
        let mut catchpoints_only = new_test_host();
        let mut both = new_test_host();
        for h in [
            &mut seeker,
            &mut archival_only,
            &mut catchpoints_only,
            &mut both,
        ] {
            h.set_dht_mode(Some(kad::Mode::Server));
        }

        let seeker_listen_addr = start_listening(&mut seeker).await;
        let seeker_peer_id = seeker.peer_id();
        let dial_addr = seeker_listen_addr.with(libp2p::multiaddr::Protocol::P2p(seeker_peer_id));

        archival_only
            .dial(dial_addr.clone())
            .expect("dial should be accepted");
        catchpoints_only
            .dial(dial_addr.clone())
            .expect("dial should be accepted");
        both.dial(dial_addr).expect("dial should be accepted");

        // Drive all four swarms until the seeker has observed a
        // ConnectionEstablished from each of the three providers.
        let mut connected = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while connected < 3 {
            tokio::select! {
                ev = seeker.next_event() => {
                    if let SwarmEvent::ConnectionEstablished { .. } = ev { connected += 1; }
                }
                _ = archival_only.next_event() => {}
                _ = catchpoints_only.next_event() => {}
                _ = both.next_event() => {}
                _ = tokio::time::sleep_until(deadline) => {
                    panic!("timed out before seeker observed all 3 connections");
                }
            }
        }

        let archival_peer_id = archival_only.peer_id();
        let catchpoints_peer_id = catchpoints_only.peer_id();
        let both_peer_id = both.peer_id();

        archival_only
            .advertise_capability(Capability::Archival)
            .await
            .expect("advertise should succeed");
        catchpoints_only
            .advertise_capability(Capability::Catchpoints)
            .await
            .expect("advertise should succeed");
        both.advertise_capability(Capability::Archival)
            .await
            .expect("advertise should succeed");
        both.advertise_capability(Capability::Catchpoints)
            .await
            .expect("advertise should succeed");

        // Keep the three providers' swarms driven in the background while
        // the seeker performs its lookups (their DHT records need to be
        // reachable to answer the seeker's queries).
        let providers_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = archival_only.next_event() => {}
                    _ = catchpoints_only.next_event() => {}
                    _ = both.next_event() => {}
                }
            }
        });

        let archival_found = seeker
            .find_peers_for_capability(Capability::Archival, 5, Duration::from_secs(10))
            .await;
        let catchpoints_found = seeker
            .find_peers_for_capability(Capability::Catchpoints, 5, Duration::from_secs(10))
            .await;

        providers_task.abort();

        assert!(
            archival_found.contains(&archival_peer_id) && archival_found.contains(&both_peer_id),
            "expected exactly the archival-advertising peers, got: {archival_found:?}"
        );
        assert!(
            !archival_found.contains(&catchpoints_peer_id),
            "catchpoints-only peer must not appear under Archival: {archival_found:?}"
        );
        assert!(
            catchpoints_found.contains(&catchpoints_peer_id)
                && catchpoints_found.contains(&both_peer_id),
            "expected exactly the catchpoints-advertising peers, got: {catchpoints_found:?}"
        );
        assert!(
            !catchpoints_found.contains(&archival_peer_id),
            "archival-only peer must not appear under Catchpoints: {catchpoints_found:?}"
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

    /// Go: `TestCapabilities_ExcludesSelf` (`network/p2p/capabilities_test.go`)
    /// — a node performing a capability lookup never finds itself among the
    /// results, even when it is itself a provider for that capability.
    ///
    /// Rather than go's two-node cluster (a peer discovers a real remote
    /// provider, and separately never finds itself), this exercises the
    /// exclusion directly and more strongly: a single host both advertises
    /// and immediately queries the *same* capability against itself.
    /// `start_providing` populates this host's own local Kademlia provider
    /// store, so `get_providers`'s first (local) answer would include our
    /// own `PeerId` if [`P2pHost::find_peers_for_capability`]'s
    /// `*peer != local_peer_id` filter (`host.rs`, the loop over
    /// `FoundProviders`) were ever removed or broken — this is the direct
    /// regression guard for that filter.
    #[tokio::test]
    async fn find_peers_for_capability_excludes_self() {
        let mut host = new_test_host();
        host.set_dht_mode(Some(kad::Mode::Server));
        let self_peer_id = host.peer_id();

        host.advertise_capability(crate::capabilities::Capability::Archival)
            .await
            .expect("advertise should succeed against a store with capacity");

        let found = host
            .find_peers_for_capability(
                crate::capabilities::Capability::Archival,
                5,
                Duration::from_millis(500),
            )
            .await;

        assert!(
            !found.contains(&self_peer_id),
            "a node must never find itself when searching for a capability it advertises, got: {found:?}"
        );
    }

    // -----------------------------------------------------------------------
    // DHT-driven mesh discovery / auto-dial (#1073)
    // -----------------------------------------------------------------------

    /// TDD anchor for this issue (#1073): a node dials a peer it only ever
    /// learned about via a DHT capability lookup, never a configured
    /// bootstrap address — the exact topology behind go's
    /// `TestNodeP2PRelays`/`TestNodeHybridTopology`
    /// (`../go-algorand/node/node_test.go`): `n` ("the node") is seeded only
    /// with `bootstrap`'s ("R2's") address; `relay` ("R1") is also only
    /// seeded with `bootstrap`'s address, and separately advertises the
    /// `Gossip` capability. `n` never receives `relay`'s multiaddr from any
    /// out-of-band source (CLI flag, config, or direct dial) — the only way
    /// it can end up connected to `relay` is by discovering its `PeerId` via
    /// [`P2pHost::find_peers_for_capability`] (routed through `bootstrap`'s
    /// DHT knowledge, mirroring `three_nodes_bootstrap_via_dht_and_route_lookup_peer`'s
    /// topology for plain routing) and then dialing that bare `PeerId` via
    /// [`P2pHost::dial_peer`] — proving `dial_peer`'s
    /// `extend_addresses_through_behaviour` resolution of a DHT-learned
    /// peer's address actually works end-to-end, not just that the lookup
    /// itself succeeds (already proven by
    /// `capability_advertised_by_one_node_is_discoverable_by_another`).
    #[tokio::test]
    async fn dial_peer_connects_to_peer_discovered_only_via_dht_capability_lookup() {
        let mut bootstrap = new_test_host();
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        use std::sync::Arc;

        let mut relay = new_test_host();
        let mut n = new_test_host();

        // Server mode needed on every node that must answer another's
        // inbound DHT RPC (mirrors `three_nodes_bootstrap_via_dht_and_route_lookup_peer`'s
        // and `capability_advertised_by_one_node_is_discoverable_by_another`'s
        // reasoning): `bootstrap` answers both `relay` and `n`'s routing
        // RPCs, and `relay` must answer `n`'s `GET_PROVIDERS` RPC once `n`'s
        // lookup reaches it via `bootstrap`.
        bootstrap.set_dht_mode(Some(kad::Mode::Server));
        relay.set_dht_mode(Some(kad::Mode::Server));

        let bootstrap_addr = start_listening(&mut bootstrap).await;
        let bootstrap_peer_id = bootstrap.peer_id();
        // `relay` needs its own listen address so `identify` can report a
        // real, dialable address for it to `bootstrap` (and, from there, to
        // `n` once its DHT lookup reaches `relay`'s k-bucket entry) — same
        // reasoning as `three_nodes_bootstrap_via_dht_and_route_lookup_peer`.
        start_listening(&mut relay).await;

        let relay_peer_id = relay.peer_id();
        let n_peer_id = n.peer_id();

        let bootstrap_dial_addr = bootstrap_addr
            .clone()
            .with(libp2p::multiaddr::Protocol::P2p(bootstrap_peer_id));

        // Both `relay` and `n` are seeded with ONLY `bootstrap`'s address —
        // neither is ever given the other's multiaddr directly.
        relay.add_bootstrap_peer(bootstrap_peer_id, bootstrap_addr.clone());
        n.add_bootstrap_peer(bootstrap_peer_id, bootstrap_addr.clone());
        relay
            .dial(bootstrap_dial_addr.clone())
            .expect("relay dial bootstrap");
        n.dial(bootstrap_dial_addr).expect("n dial bootstrap");

        // Drive all three until `bootstrap` has identified both `relay` and
        // `n` — this is what populates `bootstrap`'s DHT routing table with
        // each one's real (dialable) listen address, not just the ephemeral
        // address it happened to dial out from.
        let mut relay_identified = false;
        let mut n_identified = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while !(relay_identified && n_identified) {
            tokio::select! {
                ev = bootstrap.next_event() => {
                    if let SwarmEvent::Behaviour(P2pBehaviourEvent::Identify(identify::Event::Received { peer_id, .. })) = ev {
                        if peer_id == relay_peer_id { relay_identified = true; }
                        if peer_id == n_peer_id { n_identified = true; }
                    }
                }
                _ = relay.next_event() => {}
                _ = n.next_event() => {}
                _ = tokio::time::sleep_until(deadline) => {
                    panic!("timed out waiting for bootstrap to identify both relay and n");
                }
            }
        }

        // `relay` advertises the Gossip capability (mirrors go's
        // `node.Capabilities()` including `p2p.Gossip` for a listen-server
        // node — see `p2p_transport.rs`'s live wiring of this).
        relay
            .advertise_capability(crate::capabilities::Capability::Gossip)
            .await
            .expect("relay should be able to advertise Gossip capability");

        // `advertise_capability` degrades to `Ok(())` after its own internal
        // `DHT_LOOKUP_TIMEOUT` (5s) even if the remote `ADD_PROVIDER` push
        // hasn't actually reached `bootstrap` yet (the go-algorand
        // #6581/#6595 "do not err on deadline" folding its doc comment
        // describes) — so its return alone does not prove `bootstrap` has
        // stored the record. Explicitly wait for `bootstrap` to observe the
        // inbound `AddProvider` request (driving both `bootstrap` and
        // `relay` concurrently, since `relay`'s own outbound push needs its
        // event loop still running) before letting `n`'s lookup race ahead
        // of it — a real deployment would simply retry a too-early lookup,
        // but a single deterministic lookup attempt here needs the
        // propagation to have actually landed first.
        let mut bootstrap_saw_add_provider = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while !bootstrap_saw_add_provider {
            tokio::select! {
                ev = bootstrap.next_event() => {
                    if let SwarmEvent::Behaviour(P2pBehaviourEvent::Kad(kad::Event::InboundRequest {
                        request: kad::InboundRequest::AddProvider { .. },
                    })) = ev
                    {
                        bootstrap_saw_add_provider = true;
                    }
                }
                _ = relay.next_event() => {}
                _ = n.next_event() => {}
                _ = tokio::time::sleep_until(deadline) => {
                    panic!("timed out waiting for bootstrap to observe relay's AddProvider request");
                }
            }
        }

        let bootstrap_pump = tokio::spawn(async move {
            loop {
                bootstrap.next_event().await;
            }
        });

        // Keep `relay` driven in the background too, both so it can answer
        // `n`'s inbound `GET_PROVIDERS` RPC below, and so it can complete
        // the inbound side of `n`'s dial once `n` discovers and dials it.
        //
        // Must keep driving `relay` for the *entire* remaining test, not
        // just until the first `ConnectionEstablished` — exiting the task
        // early would drop `relay` (and thus close its listener), so any
        // later dial attempt to it (e.g. a retry after a raced/stale
        // address) would see a real "connection refused," not a test bug.
        let relay_saw_n_connect = Arc::new(AtomicBool::new(
            relay.connected_peers().contains(&n_peer_id),
        ));
        let relay_saw_n_connect_writer = Arc::clone(&relay_saw_n_connect);
        let relay_pump = tokio::spawn(async move {
            loop {
                if let SwarmEvent::ConnectionEstablished { peer_id, .. } = relay.next_event().await
                {
                    if peer_id == n_peer_id {
                        relay_saw_n_connect_writer.store(true, AtomicOrdering::Relaxed);
                    }
                }
            }
        });

        // Seed `n`'s own DHT routing table via a real self-lookup bootstrap
        // pass (mirrors `three_nodes_bootstrap_via_dht_and_route_lookup_peer`,
        // and go's own periodic DHT self-healing) before the capability
        // lookup: this is what causes `n` to actually dial/connect to any
        // peer discovered along the way (`relay` included) and, via
        // `next_event`'s `ConnectionEstablished` interception, register its
        // real address into `n`'s *persistent* routing table — not just the
        // ephemeral per-query cache a bare `get_providers` response alone
        // populates.
        n.bootstrap_dht();

        // `n` discovers `relay`'s `PeerId` purely via DHT capability lookup
        // — it was never given `relay`'s multiaddr (or even `PeerId`) any
        // other way. A single lookup pass in a toy 3-node network can race
        // an in-progress DHT self-heal (the iterative query's own
        // continuation dialing a newly discovered candidate to keep
        // querying it takes a real, if small, amount of wall-clock time),
        // so retry `bootstrap_dht` + the capability lookup a bounded number
        // of times — mirroring how go's own periodic mesh thread simply
        // tries again next tick rather than treating one miss as fatal —
        // instead of demanding a single attempt converge deterministically.
        let mut discovered = Vec::new();
        for _ in 0..5 {
            n.bootstrap_dht();
            discovered = n
                .find_peers_for_capability(
                    crate::capabilities::Capability::Gossip,
                    5,
                    Duration::from_secs(10),
                )
                .await;
            if discovered.contains(&relay_peer_id) {
                break;
            }
        }
        assert!(
            discovered.contains(&relay_peer_id),
            "expected n's DHT capability lookup to discover relay's PeerId via bootstrap, got: {discovered:?}"
        );

        // The actual regression guard: dial the bare `PeerId` (no
        // `Multiaddr` supplied by the caller) and confirm a real connection
        // comes up — proving `dial_peer`'s
        // `extend_addresses_through_behaviour` resolution of `relay`'s
        // DHT-learned address actually works, not just that the lookup
        // above returned the right `PeerId`.
        //
        // `n` may already be connected to (or mid-dialing) `relay` as a side
        // effect of `bootstrap_dht`'s own iterative self-lookup continuing
        // on to directly dial a newly discovered candidate to keep querying
        // it — itself proof the DHT-learned address is real and dialable,
        // and exactly the kind of connectivity a periodic
        // `bootstrap_dht`-refresh (mirroring go's own DHT self-healing)
        // would produce in production too. `dial_peer`'s default
        // `PeerCondition::DisconnectedAndNotDialing` correctly refuses a
        // redundant dial in either case (already connected, or an
        // in-flight attempt from that self-lookup not yet resolved) — treat
        // that refusal the same way the production periodic-discovery
        // wiring will (log and move on, not a fatal error) rather than
        // asserting this call must always be the one that dials, and let
        // the wait loop below observe whichever attempt (this one or the
        // self-lookup's own) actually completes the connection.
        let mut dial_errors: Vec<String> = Vec::new();
        // A stale/no-longer-reachable cached address (e.g. an in-flight
        // dial from `bootstrap_dht`'s own self-heal that raced this one and
        // lost) can make a single dial attempt fail — retry a bounded
        // number of times rather than treating one failed address as
        // conclusive, mirroring go's own periodic mesh thread simply trying
        // again next tick.
        for attempt in 0..5 {
            if n.connected_peers().contains(&relay_peer_id) {
                break;
            }
            let _ = n.dial_peer(relay_peer_id);

            let mut n_connected_to_relay = false;
            let mut attempt_failed = false;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            while !n_connected_to_relay && !attempt_failed {
                tokio::select! {
                    ev = n.next_event() => {
                        match ev {
                            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                if peer_id == relay_peer_id { n_connected_to_relay = true; }
                            }
                            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                                dial_errors.push(format!("{error}"));
                                if peer_id == Some(relay_peer_id) { attempt_failed = true; }
                            }
                            _ => {}
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        attempt_failed = true;
                    }
                }
            }
            if n_connected_to_relay {
                break;
            }
            assert!(
                attempt < 4,
                "timed out waiting for n to connect to relay via a DHT-resolved address after 5 attempts; dial_errors={dial_errors:?}"
            );
        }
        let n_connected_to_relay = n.connected_peers().contains(&relay_peer_id);

        let relay_connected_to_n = relay_saw_n_connect.load(AtomicOrdering::Relaxed);
        bootstrap_pump.abort();
        relay_pump.abort();

        assert!(n_connected_to_relay, "n must connect to relay");
        assert!(
            relay_connected_to_n,
            "relay must observe n's inbound connection"
        );
    }

    // -----------------------------------------------------------------------
    // conn-limit / gossipsub-param live wiring (#952)
    // -----------------------------------------------------------------------

    /// TDD anchor for #952: `P2pHost::new` must actually call
    /// `derive_algorand_gossipsub_params` with the configured
    /// `gossip_fanout` and apply the result to the live gossipsub config —
    /// not just build with `libp2p-gossipsub`'s unrelated library defaults.
    /// `gossipsub::Behaviour` exposes no getter to read its applied config
    /// back, so this checks the value `P2pHost` itself recorded at
    /// construction time (see `applied_gossipsub_params`'s doc comment).
    #[test]
    fn p2p_host_applies_derived_gossipsub_params_from_config() {
        for gossip_fanout in [0, 3, 9, 20] {
            let host_cfg = P2pHostConfig {
                gossip_fanout,
                ..P2pHostConfig::default()
            };
            let host = P2pHost::new(&loopback_identity(), TEST_NETWORK_ID, &host_cfg)
                .expect("host with custom gossip_fanout");
            assert_eq!(
                host.applied_gossipsub_params(),
                derive_algorand_gossipsub_params(gossip_fanout),
                "gossip_fanout={gossip_fanout}"
            );
        }
    }

    /// TDD anchor for #952: `P2pHost::new` must actually call
    /// `derive_conn_limits` with the configured mode inputs and record the
    /// result that gets applied to `connection_limits::Behaviour` — see
    /// `p2p_host_enforces_derived_max_established_incoming_limit` below for
    /// proof it is also *enforced*, not just recorded.
    #[test]
    fn p2p_host_applies_derived_connection_limits_from_config() {
        let host_cfg = P2pHostConfig {
            gossip_fanout: 4,
            incoming_connections_limit: 2400,
            is_listen_server: true,
            enable_dht_providers: false,
        };
        let host = P2pHost::new(&loopback_identity(), TEST_NETWORK_ID, &host_cfg)
            .expect("host with listen-server config");
        assert_eq!(
            host.applied_connection_limits(),
            derive_conn_limits(4, 2400, true, false)
        );
    }

    /// A restrictive `P2pHostConfig` (a listen server with
    /// `incoming_connections_limit: 1`, no gossip fanout) derives a
    /// `rcmgr_conns_inbound` of `1` (see `conn_limits::derive_conn_limits`'s
    /// `derive_conn_limits_server`-style math). Proves the derived limit is
    /// actually *enforced* by a live `connection_limits::Behaviour`, not
    /// merely computed: a second inbound dial while the first is still
    /// established is denied.
    #[tokio::test]
    async fn p2p_host_enforces_derived_max_established_incoming_limit() {
        let restrictive_cfg = P2pHostConfig {
            gossip_fanout: 0,
            incoming_connections_limit: 1,
            is_listen_server: true,
            enable_dht_providers: false,
        };
        assert_eq!(
            derive_conn_limits(0, 1, true, false).rcmgr_conns_inbound,
            1,
            "test setup sanity check"
        );

        let mut listener = P2pHost::new(&loopback_identity(), TEST_NETWORK_ID, &restrictive_cfg)
            .expect("restrictive listener host");
        let mut first_dialer = new_test_host();
        let mut second_dialer = new_test_host();

        let listen_addr = start_listening(&mut listener).await;
        let listener_peer_id = listener.peer_id();

        first_dialer
            .dial(
                listen_addr
                    .clone()
                    .with(libp2p::multiaddr::Protocol::P2p(listener_peer_id)),
            )
            .expect("first dial should be accepted for opening");

        // Drive both sides until the first connection is fully established.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut first_established = false;
        while !first_established {
            tokio::select! {
                ev = listener.next_event() => {
                    if let SwarmEvent::ConnectionEstablished { .. } = ev { first_established = true; }
                }
                _ = first_dialer.next_event() => {}
                _ = tokio::time::sleep_until(deadline) => {
                    panic!("timed out before the first connection established");
                }
            }
        }

        // A second, independent peer dials in while the first connection is
        // still up — the derived `max_established_incoming: 1` must deny
        // it.
        second_dialer
            .dial(listen_addr.with(libp2p::multiaddr::Protocol::P2p(listener_peer_id)))
            .expect("second dial should be accepted for opening");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut second_denied = false;
        loop {
            tokio::select! {
                ev = listener.next_event() => {
                    if let SwarmEvent::IncomingConnectionError { .. } = ev {
                        second_denied = true;
                        break;
                    }
                }
                _ = second_dialer.next_event() => {}
                _ = first_dialer.next_event() => {}
                _ = tokio::time::sleep_until(deadline) => {
                    break;
                }
            }
        }

        assert!(
            second_denied,
            "expected the listener's derived max_established_incoming: 1 limit to deny a second inbound connection"
        );
        assert_eq!(
            listener.connected_peers().len(),
            1,
            "listener should still have exactly the first connection established"
        );
    }
}
