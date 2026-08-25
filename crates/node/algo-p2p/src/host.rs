//! libp2p host construction, listen, and dial — the foundation of the P2P
//! transport.
//!
//! Mirrors go-algorand's `network/p2p/p2p.go` `MakeHost` / `MakeService` /
//! `Start` / `dialNode`, scoped down to what this issue asks for: a libp2p
//! `Swarm` secured with Noise over TCP, multistream-select negotiation
//! (handled internally by `rust-libp2p`'s transport upgrade), and plain
//! dial-out / listen-in — no peer discovery (DHT) and no pubsub, both of
//! which are later sub-issues (#539, #540).
//!
//! `rust-libp2p` performs the Noise handshake and yamux stream-muxer
//! upgrade as part of establishing a connection, before the connection is
//! handed to the [`libp2p::swarm::Swarm`] as [`SwarmEvent::ConnectionEstablished`].
//! Observing that event is therefore sufficient proof that a *secure*
//! (Noise-authenticated) libp2p connection exists — no application-level
//! protocol handshake is required for that guarantee.

use std::time::Duration;

use libp2p::swarm::dummy;
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};

use crate::errors::P2pError;
use crate::identity::IdentityConfig;

/// Default timeout applied to an outbound dial attempt.
///
/// Go: `network/p2p/p2p.go` `dialTimeout = 30 * time.Second`.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// A libp2p host for the algod-rust P2P transport foundation.
///
/// Currently runs an empty ([`dummy::Behaviour`]) `NetworkBehaviour` — this
/// issue only establishes the secured transport (dial/listen); gossipsub and
/// DHT behaviours are wired in by later sub-issues (#539, #540) which will
/// replace `dummy::Behaviour` with a real composed behaviour.
pub struct P2pHost {
    swarm: Swarm<dummy::Behaviour>,
}

impl P2pHost {
    /// Build a new host from the given identity configuration. Does not
    /// start listening — call [`P2pHost::listen`] to do so.
    ///
    /// Go: `MakeHost` (creates the libp2p host but does not listen).
    pub fn new(identity_cfg: &IdentityConfig) -> Result<Self, P2pError> {
        let keypair = crate::identity::get_or_create_keypair(identity_cfg)?;

        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| P2pError::SwarmBuild(e.to_string()))?
            .with_behaviour(|_key| dummy::Behaviour)
            .map_err(|e| P2pError::SwarmBuild(e.to_string()))?
            // The foundation's `dummy::Behaviour` never keeps a connection
            // alive on its own (it opens no substreams), so without an
            // explicit idle timeout `rust-libp2p` tears a freshly
            // established connection back down almost immediately — before
            // the other side can even finish its own transport upgrade.
            // Later sub-issues that add real protocols (gossipsub, DHT)
            // will keep connections alive through actual traffic instead;
            // this generous timeout only exists so this bare foundation is
            // usable for dial/listen on its own.
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
    /// transport (handshakes, dial attempts, incoming connections).
    pub async fn next_event(&mut self) -> libp2p::swarm::SwarmEvent<void::Void> {
        use futures_util::StreamExt;
        self.swarm.select_next_some().await
    }

    /// Currently connected peers.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::swarm::SwarmEvent;
    use std::time::Duration;
    use tokio::time::timeout;

    fn loopback_identity() -> IdentityConfig {
        IdentityConfig::default()
    }

    /// TDD anchor for this issue: two independent `P2pHost`s, each with its
    /// own generated identity, dial each other over TCP+Noise+yamux and
    /// reach `ConnectionEstablished` on both sides. Before `P2pHost`
    /// existed, this test could not even compile — now it pins the
    /// behavioral contract the whole foundation exists to satisfy.
    #[tokio::test]
    async fn two_nodes_dial_and_establish_secure_connection() {
        let mut listener = P2pHost::new(&loopback_identity()).expect("listener host");
        let mut dialer = P2pHost::new(&loopback_identity()).expect("dialer host");

        listener
            .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .expect("listen");

        // Wait for the listener to confirm its bound address.
        let listen_addr = loop {
            match timeout(Duration::from_secs(5), listener.next_event())
                .await
                .expect("timed out waiting for NewListenAddr")
            {
                SwarmEvent::NewListenAddr { address, .. } => break address,
                _ => continue,
            }
        };

        let listener_peer_id = listener.peer_id();
        let dial_addr = listen_addr.with(libp2p::multiaddr::Protocol::P2p(listener_peer_id));
        dialer.dial(dial_addr).expect("dial should be accepted");

        // Drive both swarms concurrently until each has observed a secure
        // connection established with the other.
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
        let host = P2pHost::new(&loopback_identity()).expect("host");
        let id1 = host.peer_id();
        let id2 = host.peer_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn two_hosts_get_distinct_peer_ids() {
        let host_a = P2pHost::new(&loopback_identity()).expect("host a");
        let host_b = P2pHost::new(&loopback_identity()).expect("host b");
        assert_ne!(host_a.peer_id(), host_b.peer_id());
    }
}
