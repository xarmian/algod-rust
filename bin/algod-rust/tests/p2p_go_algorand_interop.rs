//! Live P2P transport interop test (issue #543).
//!
//! Dials a real go-algorand v4.7.0-stable node running in plain P2P mode
//! (`EnableP2P: true`, no WS-gossip listener) with algod-rust's own
//! `algo-p2p` libp2p host, and asserts a secure (Noise-authenticated)
//! TCP connection is established — proof that `algo-p2p`'s transport
//! foundation (rust-libp2p: TCP + Noise + yamux, `crates/node/algo-p2p`)
//! actually interoperates with go-libp2p, not just with itself (unlike
//! `algo_p2p::host`'s own tests, which only ever dial another `P2pHost`).
//!
//! This is the transport-connectivity slice of #543's full scope. Full
//! consensus round-trip over a multi-node P2P mesh, bidirectional
//! gossipsub block/vote/tx propagation, and cross-implementation
//! capability-advertisement lookup are tracked as follow-up work — see
//! `docs/MIXED_CLUSTER_HARNESS.md`'s "P2P interop harness" section for
//! the current scope and what's left.
//!
//! Bring up the target node first:
//!
//! ```text
//! ops/mixed-cluster-p2p/scripts/start.sh
//! ALGOD_RUST_P2P_GO_MULTIADDR="$(cat ops/mixed-cluster-p2p/netroot/.p2p-multiaddr)" \
//!     cargo test --package algod-rust --test p2p_go_algorand_interop -- --ignored --nocapture
//! ops/mixed-cluster-p2p/scripts/stop.sh
//! ```

use std::time::Duration;

use algo_p2p::{IdentityConfig, P2pHost};
use libp2p::swarm::SwarmEvent;
use libp2p::Multiaddr;

fn go_node_multiaddr() -> Option<Multiaddr> {
    std::env::var("ALGOD_RUST_P2P_GO_MULTIADDR")
        .ok()
        .and_then(|s| s.parse().ok())
}

#[tokio::test]
#[ignore = "requires a live go-algorand v4.7.0-stable node in P2P mode — see ops/mixed-cluster-p2p/scripts/start.sh"]
async fn dials_real_go_algorand_p2p_host_and_establishes_secure_connection() {
    let Some(target) = go_node_multiaddr() else {
        panic!(
            "ALGOD_RUST_P2P_GO_MULTIADDR is not set or not a valid multiaddr — \
             run ops/mixed-cluster-p2p/scripts/start.sh first and export its output"
        );
    };

    let identity = IdentityConfig::default();
    // Network ID is irrelevant here: this test only proves the raw
    // transport (TCP + Noise + yamux) interoperates, not the DHT — a
    // mismatched `dht_protocol_name` would not prevent
    // `ConnectionEstablished` from firing, since that happens before any
    // DHT-specific protocol negotiation.
    let mut host = P2pHost::new(&identity, "p2pinterop-v1").expect("build P2P host");

    host.dial(target.clone())
        .unwrap_or_else(|e| panic!("dial to {target} rejected before it even started: {e}"));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        tokio::select! {
            event = host.next_event() => {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("secure connection established with real go-algorand P2P host {peer_id}");
                        return;
                    }
                    SwarmEvent::OutgoingConnectionError { error, .. } => {
                        panic!(
                            "dial to real go-algorand P2P host at {target} failed: {error} \
                             (this is the real interop signal — a transport-level mismatch \
                             between rust-libp2p and go-libp2p would surface here)"
                        );
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                panic!(
                    "timed out after 20s waiting for ConnectionEstablished against real \
                     go-algorand P2P host at {target}"
                );
            }
        }
    }
}
