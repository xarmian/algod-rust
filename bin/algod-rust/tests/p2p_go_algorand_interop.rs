//! Live P2P transport interop test (issue #543), plus issue #560/#564's
//! DHT wire-protocol investigation.
//!
//! Dials a real go-algorand v5.0.0-stable node running in plain P2P mode
//! (`EnableP2P: true`, no WS-gossip listener) with algod-rust's own
//! `algo-p2p` libp2p host, and asserts a secure (Noise-authenticated)
//! TCP connection is established — proof that `algo-p2p`'s transport
//! foundation (rust-libp2p: TCP + Noise + yamux, `crates/node/algo-p2p`)
//! actually interoperates with go-libp2p, not just with itself (unlike
//! `algo_p2p::host`'s own tests, which only ever dial another `P2pHost`).
//!
//! This is the transport-connectivity slice of #543's full scope.
//!
//! ## Issue #560/#564 investigation status
//!
//! Building a multi-node cross-implementation DHT-routing test against
//! `ops/mixed-cluster-p2p`'s new 3-node chain-bootstrapped go-algorand
//! harness (1 <- 2 <- 3 — go-node-2 is only ever told go-node-1's
//! multiaddr; go-node-3 only go-node-2's) found and fixed two real,
//! previously-undetected bugs:
//!
//! 1. (#560/#563) `algo_p2p::dht::dht_protocol_name` omitted the
//!    `/kad/1.0.0` suffix `go-libp2p-kad-dht`'s `makeDHT`
//!    (`v1proto := cfg.ProtocolPrefix + kad1`) always appends to whatever
//!    prefix go-algorand configures — so a rust host's DHT queries
//!    against a real go-algorand peer previously negotiated no shared
//!    protocol at all and returned instantly empty. Fixed and
//!    regression-tested in `crates/node/algo-p2p/src/dht.rs`.
//! 2. (#564) `algo_p2p::capabilities::Capability::record_key` used the
//!    raw namespace bytes (e.g. `b"gossip"`) as the DHT provider-record
//!    key, instead of go's actual derivation
//!    (`go-libp2p`'s `p2p/discovery/routing.nsToCid(ns).Hash()` — a
//!    34-byte SHA-256 multihash) — a completely different,
//!    non-overlapping DHT key from what any real go-algorand peer
//!    advertises under or looks up, silently breaking
//!    `start_providing`/`get_providers` interop the same way (1) broke
//!    `get_closest_peers` interop. Fixed and regression-tested in
//!    `crates/node/algo-p2p/src/capabilities.rs`.
//!
//! With both fixes applied, a rust host's DHT round trip against a real
//! go-algorand node genuinely works — see
//! [`discovers_go_algorand_peer_via_gossip_capability_provider_records`]
//! below — but **not** via `get_closest_peers`/`find_closest_peers`
//! (rust-libp2p's `kad::Behaviour::get_closest_peers`, go's `FIND_NODE`).
//! Investigating #564 live against this harness established that
//! `get_closest_peers` cannot surface a directly-connected go-algorand
//! peer's address, *by go-algorand's own design*, not as a remaining
//! wire-format bug:
//!
//! - go's `handleFindPeer` (`go-libp2p-kad-dht@v0.38.0/handlers.go`)
//!   only includes a `CloserPeers` entry for peers its **peerstore**
//!   already has an address for (`if len(pi.Addrs) > 0`) — even the
//!   literal queried target peer is dropped from the response if the
//!   peerstore has no address for it, regardless of whether the
//!   responding node is *currently connected* to that peer.
//! - go's custom peerstore (`network/p2p/peerstore.PeerStore`, shared
//!   with the DHT via `dht.MakeDHT`'s `libp2p.Peerstore(pstore)`) is
//!   populated *exclusively* by `P2PNetwork.refreshPeerStoreAddresses`
//!   (`network/p2pNetwork.go`) — itself fed by DNS bootstrap and DHT
//!   **provider records** (`capabilitiesDiscovery.PeersForCapability`,
//!   the "gossip"/"archival" namespace mechanism this crate's
//!   `capabilities.rs` mirrors) — never by `FIND_NODE` responses, and
//!   never by vanilla libp2p Identify: go's `MakeHost`
//!   (`network/p2p/p2p.go`) passes `libp2p.NoListenAddrs`, which this
//!   harness confirmed live — a direct connection's `identify::Received`
//!   event from a real go-algorand node reports `listen_addrs: []`
//!   unconditionally.
//!
//! In short: `get_closest_peers` genuinely has nothing useful to return
//! against a real go-algorand peer for third-party address discovery —
//! that job belongs to `find_peers_for_capability` (provider records),
//! which is what fix (2) above makes actually interoperate. #564's
//! originally-scoped acceptance criteria (a `find_closest_peers`-based
//! single-hop/2-hop discovery test) are therefore not met by design; see
//! #564's own comment thread for the full disposition.
//!
//! ## Issue #566: multi-hop provider-record propagation
//!
//! A real go-algorand node reporting *another* go-algorand node as a
//! provider (not just itself) did not initially propagate within this
//! harness — [`provider_record_advertised_by_neighbor_propagates_to_queried_node`]
//! below pins the fix. Root cause was **not** a wire-format or
//! `algo-p2p` bug: this harness originally bound each go-algorand node's
//! `NetAddress` to the unspecified address (`0.0.0.0:<port>`), which
//! triggers go-algorand's own `network/p2p.addressFilter`
//! (`network/p2p/p2p.go`) to strip every candidate advertised address —
//! in an all-private-IP Docker network, that left every node with zero
//! addresses to announce, so `go-libp2p-kad-dht@v0.38.0`'s
//! `ProtocolMessenger.PutProviderAddrs` silently skipped sending the
//! `ADD_PROVIDER` RPC at all ("no known addresses for self, cannot put
//! provider", confirmed via live debug-level log capture). Fixed
//! entirely in `ops/mixed-cluster-p2p` (static per-node Docker IPs +
//! `NetAddress` bound to that specific IP instead of `0.0.0.0`) — see
//! that harness's `README.md` for the full writeup.
//!
//! Bring up the target node first:
//!
//! ```text
//! ops/mixed-cluster-p2p/scripts/start.sh
//! ALGOD_RUST_P2P_GO_MULTIADDR="$(cat ops/mixed-cluster-p2p/netroot/.p2p-multiaddr-1)" \
//!     cargo test --package algod-rust --test p2p_go_algorand_interop -- --ignored --nocapture
//! ops/mixed-cluster-p2p/scripts/stop.sh
//! ```

use std::time::Duration;

use algo_p2p::{
    build_headers, handshake_outbound, Capability, IdentityConfig, P2pHost,
    ALGORAND_WS_PROTOCOL_V22,
};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId};

fn go_node_multiaddr() -> Option<Multiaddr> {
    std::env::var("ALGOD_RUST_P2P_GO_MULTIADDR")
        .ok()
        .and_then(|s| s.parse().ok())
}

/// The go-algorand network ID `ops/mixed-cluster-p2p`'s `start.sh` names
/// its `goal network create -n p2pinterop` network — must match exactly
/// for `algo_p2p::dht::dht_protocol_name`'s `/algorand/kad/<id>/kad/1.0.0`
/// to negotiate a shared DHT protocol with the real go-algorand nodes.
const P2PINTEROP_NETWORK_ID: &str = "p2pinterop";

#[tokio::test]
#[ignore = "requires a live go-algorand v5.0.0-stable node in P2P mode — see ops/mixed-cluster-p2p/scripts/start.sh"]
async fn dials_real_go_algorand_p2p_host_and_establishes_secure_connection() {
    let Some(target) = go_node_multiaddr() else {
        panic!(
            "ALGOD_RUST_P2P_GO_MULTIADDR is not set or not a valid multiaddr — \
             run ops/mixed-cluster-p2p/scripts/start.sh first and export its output \
             (netroot/.p2p-multiaddr-1)"
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

/// Regression test for issue #564's fix: a rust host's `find_peers_for_capability`
/// (DHT provider records — `kad::Behaviour::start_providing`/`get_providers`)
/// query against a real go-algorand node now returns that node itself as
/// a "gossip" capability provider — proof `algo_p2p::capabilities::Capability::record_key`'s
/// key now matches go's actual `nsToCid(ns).Hash()` derivation
/// (`go-libp2p`'s `p2p/discovery/routing.go`), rather than the raw
/// namespace bytes the old (buggy) key used, which negotiated no shared
/// DHT key with any real go-algorand peer at all.
///
/// This module's doc comment explains why this — not
/// `find_closest_peers` — is the DHT primitive that actually round-trips
/// against go-algorand for peer discovery.
#[tokio::test]
#[ignore = "requires a live go-algorand v5.0.0-stable node in P2P mode — see ops/mixed-cluster-p2p/scripts/start.sh"]
async fn discovers_go_algorand_peer_via_gossip_capability_provider_records() {
    let Some(target) = go_node_multiaddr() else {
        panic!(
            "ALGOD_RUST_P2P_GO_MULTIADDR is not set or not a valid multiaddr — \
             run ops/mixed-cluster-p2p/scripts/start.sh first and export its output \
             (netroot/.p2p-multiaddr-1)"
        );
    };
    let target_peer_id = match target.iter().last() {
        Some(libp2p::multiaddr::Protocol::P2p(id)) => id,
        _ => panic!("ALGOD_RUST_P2P_GO_MULTIADDR must end in a /p2p/<peer-id> component"),
    };

    let identity = IdentityConfig::default();
    let mut host = P2pHost::new(&identity, P2PINTEROP_NETWORK_ID).expect("build P2P host");

    host.dial(target.clone())
        .unwrap_or_else(|e| panic!("dial to {target} rejected before it even started: {e}"));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        tokio::select! {
            event = host.next_event() => {
                match event {
                    SwarmEvent::ConnectionEstablished { .. } => break,
                    SwarmEvent::OutgoingConnectionError { error, .. } => {
                        panic!("dial to real go-algorand P2P host at {target} failed: {error}");
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                panic!("timed out after 20s waiting for ConnectionEstablished against {target}");
            }
        }
    }

    let providers: Vec<PeerId> = host
        .find_peers_for_capability(Capability::Gossip, 10, Duration::from_secs(15))
        .await;

    assert!(
        providers.contains(&target_peer_id),
        "expected the dialed go-algorand node ({target_peer_id}) to report itself as a \
         'gossip' capability DHT provider (it always adds itself locally on Provide — see \
         go-libp2p-kad-dht's IpfsDHT.Provide), got providers = {providers:?}. If this \
         regresses, algo_p2p::capabilities::Capability::record_key likely stopped matching \
         go's nsToCid(ns).Hash() derivation again."
    );
}

/// TDD anchor for issue #566: a "gossip" provider record advertised by
/// go-node-2 (or go-node-3) must propagate through the DHT such that
/// querying **go-node-1 alone** — the only node this test ever dials —
/// surfaces go-node-2 as a provider too, not just go-node-1 itself.
///
/// Root cause (confirmed live against `ops/mixed-cluster-p2p`, with
/// `BaseLoggerDebugLevel` raised to `5` to observe go's own DHT debug
/// logs): **not** a wire-format/key-derivation bug (already fixed twice,
/// #563 and #565) and **not** a rust-libp2p/`algo-p2p` bug — it was a
/// harness configuration gap in how the go-algorand nodes were told to
/// bind. `ops/mixed-cluster-p2p` originally set each node's `NetAddress`
/// to the unspecified address (`0.0.0.0:<port>`). go-algorand's own
/// `network/p2p.addressFilter` (`network/p2p/p2p.go`) strips *every*
/// candidate advertised address whenever `NetAddress` binds an
/// unspecified address (`manet.IsIPUnspecified` — a real-deployment
/// safeguard against advertising unroutable private addresses to a
/// public DHT), which in this all-private-IP Docker network left every
/// node with zero addresses to advertise. `go-libp2p-kad-dht@v0.38.0`'s
/// `ProtocolMessenger.PutProviderAddrs` correctly detects this and
/// silently skips sending the `ADD_PROVIDER` RPC entirely (observed
/// verbatim in all three nodes' debug logs, once per every single
/// `Provide` attempt: `"no known addresses for self, cannot put
/// provider"`) — so a node's own provider record for itself never left
/// its local store and reached *no* other node's provider store, no
/// matter how long a test waited (this was not a timing/backoff issue —
/// each node's `AdvertiseCapabilities` retry loop correctly classifies
/// the *earlier*, and harmless, empty-routing-table race
/// (`kbucket.ErrLookupFailure`, "failed to find any peer in table") as
/// retryable and converges within seconds once a routing-table peer is
/// known; the address-filter failure is a *separate*, silent,
/// non-retried failure inside a "successful" advertisement).
///
/// Fixed entirely in the harness (`ops/mixed-cluster-p2p/docker-compose.yml`
/// + `scripts/start.sh`): each node now gets a static, non-zero Docker
/// bridge IP and binds `NetAddress` to that specific address instead of
/// `0.0.0.0`, which keeps `needAddressFilter` false so go-algorand never
/// installs the stripping `addrFactory` — see that harness's `README.md`
/// for the full writeup. No `algo-p2p` production code change was
/// needed; this test pins the now-correctly-working behavior as a live
/// regression guard, with [`PROPAGATION_WAIT`] sized generously above the
/// observed few-seconds convergence time.
#[tokio::test]
#[ignore = "requires the live 3-node go-algorand v5.0.0-stable chain — see ops/mixed-cluster-p2p/scripts/start.sh"]
async fn provider_record_advertised_by_neighbor_propagates_to_queried_node() {
    let Some(target) = go_node_multiaddr() else {
        panic!(
            "ALGOD_RUST_P2P_GO_MULTIADDR is not set or not a valid multiaddr — \
             run ops/mixed-cluster-p2p/scripts/start.sh first and export its output \
             (netroot/.p2p-multiaddr-1)"
        );
    };
    let Some(neighbor) = std::env::var("ALGOD_RUST_P2P_GO_MULTIADDR_2")
        .ok()
        .and_then(|s| s.parse::<Multiaddr>().ok())
    else {
        panic!(
            "ALGOD_RUST_P2P_GO_MULTIADDR_2 is not set or not a valid multiaddr — export \
             ops/mixed-cluster-p2p/netroot/.p2p-multiaddr-2 (go-node-1's DHT-connected \
             neighbor; this test never dials it directly, only checks it is discoverable \
             via go-node-1)"
        );
    };
    let neighbor_peer_id = match neighbor.iter().last() {
        Some(libp2p::multiaddr::Protocol::P2p(id)) => id,
        _ => panic!("ALGOD_RUST_P2P_GO_MULTIADDR_2 must end in a /p2p/<peer-id> component"),
    };

    // go's exponential-decorrelated-jitter retry backoff for a failed
    // advertisement starts at 1s and caps at 100s (capabilities.go's
    // `ebf`); observed live convergence in this harness is ~1-4s, so this
    // is a generous ceiling, not a tight one.
    const PROPAGATION_WAIT: Duration = Duration::from_secs(20);

    let identity = IdentityConfig::default();
    let mut host = P2pHost::new(&identity, P2PINTEROP_NETWORK_ID).expect("build P2P host");

    // Only ever dial go-node-1 — go-node-2's providership must be learned
    // purely through the DHT provider-record mechanism relayed via
    // go-node-1, not via a direct connection.
    host.dial(target.clone())
        .unwrap_or_else(|e| panic!("dial to {target} rejected before it even started: {e}"));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        tokio::select! {
            event = host.next_event() => {
                match event {
                    SwarmEvent::ConnectionEstablished { .. } => break,
                    SwarmEvent::OutgoingConnectionError { error, .. } => {
                        panic!("dial to real go-algorand P2P host at {target} failed: {error}");
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                panic!("timed out after 20s waiting for ConnectionEstablished against {target}");
            }
        }
    }

    let providers: Vec<PeerId> = host
        .find_peers_for_capability(Capability::Gossip, 10, PROPAGATION_WAIT)
        .await;

    assert!(
        providers.contains(&neighbor_peer_id),
        "expected go-node-1's own 'gossip' provider records to include its DHT neighbor \
         go-node-2 ({neighbor_peer_id}), reached only by querying go-node-1 (never dialed \
         directly) — got providers = {providers:?}. If this regresses, go-node-2's \
         provider-record advertisement is no longer propagating to go-node-1 within \
         {PROPAGATION_WAIT:?} — see this test's doc comment for the timing this pins."
    );
}

/// Issue #560's actual remaining blocker, closed by this test: proves the
/// `/algorand-ws/2.2.0` raw-libp2p-stream handshake (`algo_p2p::wsproto`)
/// — go-algorand's real wire protocol for proposal/vote/bundle traffic in
/// P2P mode, since go's own gossipsub wiring only ever carries the `TX`
/// tag (see `wsproto`'s doc comment for the full go-source citation) —
/// actually interoperates byte-for-byte with a real go-algorand node, not
/// just with another `algo-p2p` host (unlike this crate's own
/// `wsproto::tests`, which only ever exercise both sides of the handshake
/// with the *same* Rust implementation).
///
/// This is the novel, highest-risk-of-a-wire-format-bug part of #560's
/// fix: the length-prefixed msgpack `peerMetaHeaders` encoding
/// (`network/p2pMetainfo.go`) has no existing algod-rust test coverage
/// against a real peer before this. A successful [`handshake_outbound`]
/// here means a real go-algorand node read our msgpack-encoded headers,
/// matched a protocol version, and wrote back its own — round-tripping
/// through go's actual `wsStreamHandlerV22`/`baseWsStreamHandler`, which
/// (per that function's own logic) also means go now holds a live `wsPeer`
/// for this connection in its peer table, precisely the missing piece
/// `bin/algod-rust/src/commands/p2p_transport.rs`'s `P2pTransport` now
/// uses to carry AV/PP/VB traffic to real go-algorand peers.
#[tokio::test]
#[ignore = "requires a live go-algorand v5.0.0-stable node in P2P mode — see ops/mixed-cluster-p2p/scripts/start.sh"]
async fn algorand_ws_stream_handshake_round_trips_with_real_go_algorand_node() {
    let Some(target) = go_node_multiaddr() else {
        panic!(
            "ALGOD_RUST_P2P_GO_MULTIADDR is not set or not a valid multiaddr — \
             run ops/mixed-cluster-p2p/scripts/start.sh first and export its output \
             (netroot/.p2p-multiaddr-1)"
        );
    };

    let identity = IdentityConfig::default();
    let mut host = P2pHost::new(&identity, P2PINTEROP_NETWORK_ID).expect("build P2P host");
    let mut control = host.stream_control();

    host.dial(target.clone())
        .unwrap_or_else(|e| panic!("dial to {target} rejected before it even started: {e}"));

    let peer_id = loop {
        tokio::select! {
            event = host.next_event() => {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => break peer_id,
                    SwarmEvent::OutgoingConnectionError { error, .. } => {
                        panic!("dial to real go-algorand P2P host at {target} failed: {error}");
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(20)) => {
                panic!("timed out after 20s waiting for ConnectionEstablished against {target}");
            }
        }
    };

    // Drive the swarm in the background so the outbound stream's protocol
    // negotiation (multistream-select over the already-established
    // connection) actually progresses while we await `open_stream` below.
    tokio::spawn(async move {
        loop {
            host.next_event().await;
        }
    });

    let stream = tokio::time::timeout(
        Duration::from_secs(15),
        control.open_stream(peer_id, ALGORAND_WS_PROTOCOL_V22),
    )
    .await
    .expect("timed out opening the algorand-ws stream")
    .unwrap_or_else(|e| {
        panic!(
            "failed to open /algorand-ws/2.2.0 stream to real go-algorand node {peer_id}: {e} \
             (if this regresses, go stopped accepting this protocol ID, or multistream-select \
             negotiation itself broke)"
        )
    });

    let our_headers = build_headers(
        P2PINTEROP_NETWORK_ID,
        "",
        "algod-rust-interop-test",
        "",
        &["2.2"],
    );
    let mut stream = stream;
    let meta = tokio::time::timeout(
        Duration::from_secs(15),
        handshake_outbound(&mut stream, &our_headers, &["2.2"]),
    )
    .await
    .expect("timed out waiting for go-algorand's peerMetaHeaders handshake response")
    .unwrap_or_else(|e| {
        panic!(
            "algorand-ws handshake with real go-algorand node {peer_id} failed: {e} (if this \
             regresses, algo_p2p::wsproto's msgpack peerMetaHeaders encoding or length-prefix \
             framing stopped matching go's network/p2pMetainfo.go byte-for-byte)"
        )
    });

    assert_eq!(
        meta.version, "2.2",
        "expected go-algorand to negotiate protocol version 2.2 (its own \
         SupportedProtocolVersions), got {meta:?}"
    );
}
