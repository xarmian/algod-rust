//! `algo-p2p` — libp2p-based P2P transport foundation for algod-rust.
//!
//! This crate is the Rust counterpart to go-algorand's `network/p2p/`
//! package: a libp2p [`Swarm`](libp2p::Swarm) host secured with Noise over
//! TCP, a persisted-or-ephemeral peer identity, and basic dial/listen.
//!
//! It is **additive and alternate** to `algo-network`'s existing WebSocket
//! gossip stack, not a replacement — nothing here is wired into that stack.
//! Peer discovery (Kademlia DHT), gossipsub-based message propagation,
//! capability advertisement, and WS/P2P transport-mode selection are later,
//! separate sub-issues of the P2P epic (#544) and are deliberately out of
//! scope for this foundation.
//!
//! Reference: `../go-algorand/network/p2p/` at `v4.7.0-stable`
//! (`p2p.go`, `peerID.go`, `streams.go`, `http.go`).

pub mod errors;
pub mod host;
pub mod identity;
pub mod streams;

pub use errors::P2pError;
pub use host::{P2pHost, DIAL_TIMEOUT};
pub use identity::{get_or_create_keypair, IdentityConfig, DEFAULT_PRIV_KEY_FILENAME};
