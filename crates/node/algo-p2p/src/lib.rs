//! `algo-p2p` — libp2p-based P2P transport foundation for algod-rust.
//!
//! This crate is the Rust counterpart to go-algorand's `network/p2p/`
//! package: a libp2p [`Swarm`](libp2p::Swarm) host secured with Noise over
//! TCP, a persisted-or-ephemeral peer identity, and basic dial/listen.
//!
//! It is **additive and alternate** to `algo-network`'s existing WebSocket
//! gossip stack, not a replacement — nothing here is wired into that stack.
//! Kademlia DHT peer discovery, a persistent peer cache, and `dnsaddr`
//! DNS-based bootstrap resolution are implemented here (#539), and so is
//! gossipsub-based publish/subscribe pubsub for block/vote/tx propagation
//! (#540, see the [`pubsub`] module for topic naming) and DHT-based peer
//! capability advertisement (#541, see the [`capabilities`] module).
//! WS/P2P transport-mode selection (wiring this crate's pubsub and
//! capability discovery into `algo-network`'s broadcast/consume interfaces
//! and node startup so the running node can actually use them) is a later,
//! separate sub-issue of the P2P epic (#544, see #542) and is deliberately
//! out of scope for this crate so far.
//!
//! Reference: `../go-algorand/network/p2p/` at `v4.7.3-stable`
//! (`p2p.go`, `peerID.go`, `streams.go`, `http.go`, `dht/dht.go`,
//! `dnsaddr/resolve.go`, `peerstore/peerstore.go`, `pubsub.go`,
//! `capabilities.go`).

pub mod capabilities;
pub mod dht;
pub mod dnsaddr;
pub mod errors;
pub mod host;
pub mod identity;
pub mod peerstore;
pub mod pubsub;
pub mod streams;
pub mod wsproto;

pub use capabilities::Capability;
pub use dht::dht_protocol_name;
pub use dnsaddr::{resolve_multiaddrs, DnsaddrError, DnsaddrResolver, HickoryDnsaddrResolver};
pub use errors::P2pError;
pub use host::{
    MessageValidationResult, P2pBehaviour, P2pBehaviourEvent, P2pHost, DHT_LOOKUP_TIMEOUT,
    DIAL_TIMEOUT,
};
pub use identity::{get_or_create_keypair, IdentityConfig, DEFAULT_PRIV_KEY_FILENAME};
pub use peerstore::{PersistentPeerStore, DEFAULT_PEERSTORE_FILENAME};
pub use pubsub::{
    ident_topic, topic_name_for_tag_code, AGREEMENT_VOTE_TOPIC, ALL_TOPICS, PROPOSAL_PAYLOAD_TOPIC,
    TX_TOPIC, VOTE_BUNDLE_TOPIC,
};
pub use wsproto::{
    build_headers, handshake_inbound, handshake_outbound, read_frame, write_frame, PeerMeta,
    PeerMetaHeaders, WsProtoError, ALGORAND_WS_PROTOCOL_V1, ALGORAND_WS_PROTOCOL_V22,
};

/// Re-exported so downstream crates (e.g. `bin/algod-rust`'s `p2p_transport`)
/// can name [`libp2p_stream::Control`]/[`libp2p_stream::Stream`] without
/// adding a direct `libp2p-stream` dependency of their own (version-pinning
/// it against the exact `libp2p-swarm` this crate's `libp2p` facade uses is
/// this crate's job — see this crate's `Cargo.toml` comment on
/// `libp2p-stream`).
pub use libp2p_stream;
