//! Error types for the libp2p P2P transport foundation.

use std::io;

/// Errors that can occur while building or operating the P2P host.
#[derive(Debug, thiserror::Error)]
pub enum P2pError {
    /// Filesystem I/O failure while loading or persisting the peer identity key.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// The on-disk (or user-supplied) private key could not be decoded.
    #[error("failed to decode peer identity private key: {0}")]
    KeyDecode(String),

    /// Multiaddr parsing failed.
    #[error("invalid multiaddr: {0}")]
    InvalidMultiaddr(String),

    /// Swarm/transport construction failed.
    #[error("failed to build libp2p swarm: {0}")]
    SwarmBuild(String),

    /// Listening on the configured address failed.
    #[error("failed to listen on {addr}: {source}")]
    Listen {
        addr: String,
        source: Box<libp2p::TransportError<io::Error>>,
    },

    /// Dialing a peer failed.
    #[error("failed to dial {addr}: {source}")]
    Dial {
        addr: String,
        source: Box<libp2p::swarm::DialError>,
    },

    /// The on-disk persistent peerstore cache could not be decoded.
    #[error("failed to decode persistent peerstore cache: {0}")]
    PeerstoreDecode(String),

    /// Subscribing to a gossipsub topic failed.
    #[error("failed to subscribe to gossipsub topic {topic}: {source}")]
    GossipsubSubscribe {
        topic: String,
        source: Box<libp2p::gossipsub::SubscriptionError>,
    },

    /// Publishing to (or unsubscribing from) a gossipsub topic failed.
    #[error("failed to publish/unsubscribe on gossipsub topic {topic}: {source}")]
    GossipsubPublish {
        topic: String,
        source: Box<libp2p::gossipsub::PublishError>,
    },

    /// Advertising a DHT capability provider record failed at the local
    /// record store (e.g. the provider-record store is at capacity) —
    /// distinct from a query simply not completing within its deadline,
    /// which this crate treats as "not yet advertised," not an error (see
    /// [`crate::host::P2pHost::advertise_capability`]).
    #[error("failed to advertise capability {capability}: {source}")]
    CapabilityAdvertise {
        capability: &'static str,
        source: libp2p::kad::store::Error,
    },
}
