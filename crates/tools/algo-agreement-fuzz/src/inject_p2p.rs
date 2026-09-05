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

//! P2P-speaking single-message injection: negative Layer-9 conformance over
//! the raw `/algorand-ws/2.2.0` libp2p stream (issue #597).
//!
//! Sibling to [`crate::inject`], which speaks go-algorand's **WS-gossip**
//! handshake (`/v1/{genesisID}/gossip`) and framing. `ops/mixed-cluster-p2p/`
//! runs go-algorand nodes with `EnableP2P=true`, which never opens a
//! WS-gossip listener at all (see `algo_p2p::wsproto`'s doc comment for the
//! full citation): AV/PP/VB agreement traffic there travels *exclusively*
//! over a raw, bidirectional `/algorand-ws/2.2.0` libp2p stream per peer, so
//! [`crate::inject`]'s WS-gossip injector cannot reach it at all — there is
//! no listener for it to connect to.
//!
//! This module reuses the fault-construction logic in [`crate`] (`build_vote`,
//! `corrupt_proposal`, `baseline_and_faulted`, …) completely unchanged — the
//! malformed *content* is identical to issue #472's cases. Only the
//! transport is new, and even that is not reinvented here: dialing,
//! handshaking, and framing are all delegated to `algo_p2p::{P2pHost, wsproto}`,
//! the exact same building blocks `bin/algod-rust/src/commands/p2p_transport.rs`
//! uses to drive a real node's `/algorand-ws/2.2.0` stream. This module's own
//! job is just the single-shot "dial one peer, send one message, observe"
//! glue — no protocol logic lives here.
//!
//! # What counts as "Go rejected it"
//!
//! go-algorand's P2P peer wraps a raw libp2p stream
//! (`network/p2pPeer.go`'s `wsPeerConnP2P`). A `disconnectAction` from the
//! agreement player (the same rejection path [`crate::inject`]'s doc comment
//! describes) still calls `wsPeerConnP2P.CloseWithoutFlush`, which resets the
//! underlying libp2p stream (`c.stream.Reset()`) — unlike the WS-gossip
//! transport, where "peer" and "connection" are the same object and a
//! rejection tears down the whole socket, here only *this stream* is reset;
//! the underlying libp2p connection (and any other protocol running on it)
//! is untouched. So the observable, in-band signal is: **our read side of
//! the stream errors out (reset/EOF) shortly after we send the message, and
//! we sent nothing else on it.**
//!
//! Attribution again comes from the Go node's own log line
//! (`agreement/trace.go`'s "malformed vote…"/"rejected message…"), which the
//! shell driver greps for, exactly as [`crate::inject`]'s doc comment
//! describes for the WS-gossip case.

use std::time::{Duration, Instant};

use algo_network::framing;
use algo_network::tag::Tag;
use algo_p2p::{
    build_headers, handshake_outbound, read_frame, write_frame, IdentityConfig, P2pHost,
    P2pHostConfig, ALGORAND_WS_PROTOCOL_V22,
};
use anyhow::{anyhow, bail, Context, Result};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub use crate::inject::InjectionOutcome;

/// go's `SupportedProtocolVersions` for the `/algorand-ws/2.2.0` handshake —
/// kept as a literal here (rather than importing it) for the same reason
/// `p2p_transport.rs` does: `algo-p2p` deliberately has no `algo-network`
/// dependency (see `algo_p2p::wsproto`'s doc comment).
pub const ALGORAND_WS_SUPPORTED_VERSIONS: &[&str] = &["2.2"];

/// How the P2P injector should identify itself and where it should dial.
#[derive(Debug, Clone)]
pub struct P2pInjectorConfig {
    /// The target go-algorand node's dialable P2P multiaddr, including its
    /// trailing `/p2p/<peer-id>` component (e.g.
    /// `/ip4/127.0.0.1/tcp/4190/p2p/12D3Koo...`).
    pub peer_multiaddr: Multiaddr,
    /// Algorand network/genesis ID, e.g. `phase6net-v1`. Used both to derive
    /// this throwaway host's DHT protocol name (irrelevant here beyond
    /// keeping it distinct — no DHT operation is performed) and as the
    /// `X-Algorand-Genesis` handshake header value.
    pub genesis_id: String,
    /// How long to wait after sending before declaring "not reset".
    pub observe: Duration,
    /// How long to wait for the libp2p dial to establish a secure
    /// connection before giving up.
    pub dial_timeout: Duration,
}

impl P2pInjectorConfig {
    /// A config with the usual timeouts.
    pub fn new(peer_multiaddr: Multiaddr, genesis_id: impl Into<String>) -> Self {
        Self {
            peer_multiaddr,
            genesis_id: genesis_id.into(),
            observe: Duration::from_secs(20),
            dial_timeout: Duration::from_secs(30),
        }
    }
}

/// Split `addr`'s trailing `/p2p/<peer-id>` component off, returning the
/// `PeerId` it names. Every dial target must carry one — unlike the
/// WS-gossip transport's plain `host:port`, a libp2p dial has no way to
/// confirm which peer answered without it.
fn target_peer_id(addr: &Multiaddr) -> Result<PeerId> {
    addr.iter()
        .find_map(|p| match p {
            Protocol::P2p(peer_id) => Some(peer_id),
            _ => None,
        })
        .ok_or_else(|| {
            anyhow!("P2P injector target multiaddr {addr} has no trailing /p2p/<peer-id>")
        })
}

/// Build a throwaway, purely in-memory P2P identity. Nothing about it is
/// registered anywhere — a fresh Ed25519 keypair, never persisted — mirroring
/// [`crate::inject`]'s `throwaway_config`'s "plain gossip client, exactly
/// like an observer node" identity for the WS-gossip transport.
fn throwaway_identity() -> IdentityConfig {
    IdentityConfig {
        private_key_path: None,
        data_dir: None,
        persist_peer_id: false,
    }
}

/// Dial `cfg.peer_multiaddr`, open one `/algorand-ws/2.2.0` stream to it, and
/// complete the outbound handshake.
///
/// Returns a background task handle that must be kept alive (and aborted by
/// the caller once done with the stream) — it owns the `P2pHost` and drives
/// its swarm for the lifetime of the connection, since `open_stream`'s (and
/// the connection dial's) resolution both depend on the swarm being polled.
/// Mirrors the pump/foreground split `algo_p2p::host`'s own tests use for the
/// same reason.
async fn connect(cfg: &P2pInjectorConfig) -> Result<(JoinHandle<()>, libp2p::swarm::Stream)> {
    let target_peer = target_peer_id(&cfg.peer_multiaddr)?;

    let mut host = P2pHost::new(
        &throwaway_identity(),
        &cfg.genesis_id,
        &P2pHostConfig::default(),
    )
    .map_err(|e| anyhow!("failed to build P2P host: {e}"))?;
    let mut stream_control = host.stream_control();

    host.dial(cfg.peer_multiaddr.clone())
        .with_context(|| format!("dialing {}", cfg.peer_multiaddr))?;

    let (conn_tx, conn_rx) = oneshot::channel::<std::result::Result<(), String>>();
    let pump = tokio::spawn(async move {
        let mut conn_tx = Some(conn_tx);
        loop {
            match host.next_event().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == target_peer => {
                    if let Some(tx) = conn_tx.take() {
                        let _ = tx.send(Ok(()));
                    }
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    if let Some(tx) = conn_tx.take() {
                        let _ = tx.send(Err(error.to_string()));
                    }
                }
                _ => {}
            }
        }
    });

    let dial_result = tokio::time::timeout(cfg.dial_timeout, conn_rx).await;
    match dial_result {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => {
            pump.abort();
            bail!("P2P dial to {} failed: {e}", cfg.peer_multiaddr);
        }
        Ok(Err(_)) => {
            pump.abort();
            bail!(
                "P2P dial task for {} ended before establishing a connection",
                cfg.peer_multiaddr
            );
        }
        Err(_) => {
            pump.abort();
            bail!(
                "timed out dialing {} within {:?}",
                cfg.peer_multiaddr,
                cfg.dial_timeout
            );
        }
    }

    let stream = match stream_control
        .open_stream(target_peer, ALGORAND_WS_PROTOCOL_V22)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            pump.abort();
            bail!("failed to open /algorand-ws/2.2.0 stream to {target_peer}: {e}");
        }
    };

    let mut stream = stream;
    let our_headers = build_headers(
        &cfg.genesis_id,
        "",
        "algo-agreement-fuzz",
        "",
        ALGORAND_WS_SUPPORTED_VERSIONS,
    );
    if let Err(e) =
        handshake_outbound(&mut stream, &our_headers, ALGORAND_WS_SUPPORTED_VERSIONS).await
    {
        pump.abort();
        bail!("algorand-ws handshake with {target_peer} failed: {e}");
    }

    Ok((pump, stream))
}

/// Connect over `/algorand-ws/2.2.0`, send exactly one tagged message, and
/// observe.
///
/// Sends nothing else on the stream — no votes, no proposals, no relayed
/// traffic — so any reset is a response to this single message. The P2P
/// analogue of [`crate::inject::inject_one`]; see this module's doc comment
/// for what "Go rejected it" means on this transport.
pub async fn inject_one_p2p(
    cfg: &P2pInjectorConfig,
    tag: Tag,
    payload: Vec<u8>,
) -> Result<InjectionOutcome> {
    let (pump, mut stream) = connect(cfg).await?;

    let frame = framing::encode_frame(&tag, &payload)
        .map_err(|e| anyhow!("failed to encode injected frame: {e}"))?;

    tracing::info!(
        peer = %cfg.peer_multiaddr,
        "algorand-ws handshake complete; injecting one {} message ({} bytes)",
        tag.as_str(),
        payload.len()
    );

    let sent_at = Instant::now();
    if let Err(e) = write_frame(&mut stream, &frame).await {
        pump.abort();
        bail!("failed to write injected frame: {e}");
    }

    let mut frames = Vec::new();
    let deadline = sent_at + cfg.observe;
    let disconnected = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break false;
        }
        match tokio::time::timeout(remaining, read_frame(&mut stream)).await {
            // A frame we can't even decode still proves the stream is alive;
            // keep waiting rather than treating it as a reset.
            Ok(Ok(body)) => {
                if let Ok((t, _payload)) = framing::decode_frame(&body) {
                    frames.push(t.as_str().to_string());
                }
            }
            // Read error (EOF / reset) ⇒ Go closed our stream.
            Ok(Err(_)) => break true,
            Err(_) => break false,
        }
    };

    let elapsed_ms = sent_at.elapsed().as_millis();
    pump.abort();

    Ok(InjectionOutcome {
        disconnected,
        elapsed_ms,
        frames_received: frames,
    })
}

/// Connect as a plain observer over `/algorand-ws/2.2.0` and return the
/// first proposal payload (`PP`) the node relays to us.
///
/// The P2P analogue of [`crate::inject::capture_proposal`] — see that
/// function's doc comment for why capturing rather than assembling is
/// necessary. Nothing is sent on this stream beyond the handshake.
///
/// Unlike the WS-gossip transport, go-algorand compresses *every* proposal
/// it sends on `/algorand-ws/2.2.0` unconditionally once the negotiated
/// wsnet protocol version is 2.2 (`network/wsNetwork.go`'s
/// `msgBroadcaster.preparePeerData`: "Compress proposals -- all proposals
/// are compressed as of wsnet 2.2", which runs before any per-peer feature
/// negotiation — this stream is always negotiated at exactly that version,
/// see [`ALGORAND_WS_SUPPORTED_VERSIONS`]), so a captured `PP` payload here
/// is zstd-compressed on the wire and must be decompressed before decoding
/// — the same fix issue #478 applied to `ws_peer.rs`'s WS-gossip read loop
/// and `bin/algod-rust/src/commands/p2p_transport.rs`'s `spawn_ws_peer`
/// applied to this stream for a live node's own inbound path; this
/// stand-alone capture path needed the identical fix, found live while
/// verifying this injector against `ops/mixed-cluster-p2p/` (issue #597).
pub async fn capture_proposal_p2p(cfg: &P2pInjectorConfig) -> Result<Vec<u8>> {
    let (pump, mut stream) = connect(cfg).await?;

    let deadline = Instant::now() + cfg.observe;
    let result = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break Err(anyhow!(
                "no proposal payload seen on {} within {:?}",
                cfg.peer_multiaddr,
                cfg.observe
            ));
        }
        match tokio::time::timeout(remaining, read_frame(&mut stream)).await {
            Ok(Ok(body)) => match framing::decode_frame(&body) {
                Ok((Tag::ProposalPayload, payload)) => {
                    let payload = if algo_network::compression::is_zstd_compressed(payload) {
                        match algo_network::compression::zstd_decompress(
                            payload,
                            algo_network::compression::MAX_DECOMPRESSED_MESSAGE_SIZE,
                        ) {
                            Ok(d) => d,
                            Err(e) => {
                                break Err(anyhow!(
                                    "captured PP payload failed zstd decompression: {e}"
                                ))
                            }
                        }
                    } else {
                        payload.to_vec()
                    };
                    break Ok(payload);
                }
                _ => continue,
            },
            Ok(Err(e)) => {
                break Err(anyhow!(
                    "peer {} closed its stream before relaying a proposal: {e}",
                    cfg.peer_multiaddr
                ))
            }
            Err(_) => {
                break Err(anyhow!(
                    "no proposal payload seen on {} within {:?}",
                    cfg.peer_multiaddr,
                    cfg.observe
                ))
            }
        }
    };

    pump.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_p2p::handshake_inbound;
    use libp2p::futures::StreamExt as _;

    fn test_identity() -> IdentityConfig {
        IdentityConfig::default()
    }

    #[test]
    fn config_defaults_are_sane() {
        let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/4190/p2p/{}", PeerId::random())
            .parse()
            .unwrap();
        let c = P2pInjectorConfig::new(addr, "phase6net-v1");
        assert_eq!(c.genesis_id, "phase6net-v1");
        assert!(c.observe >= Duration::from_secs(5));
        assert!(c.dial_timeout >= c.observe / 2);
    }

    #[test]
    fn target_peer_id_extracts_the_trailing_p2p_component() {
        let peer = PeerId::random();
        let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/4190/p2p/{peer}")
            .parse()
            .unwrap();
        assert_eq!(target_peer_id(&addr).unwrap(), peer);
    }

    #[test]
    fn target_peer_id_rejects_an_addr_without_one() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4190".parse().unwrap();
        assert!(target_peer_id(&addr).is_err());
    }

    /// A minimal mock of a go-algorand P2P peer: accepts one
    /// `/algorand-ws/2.2.0` stream, completes the inbound handshake, and
    /// hands the injected frame's raw bytes plus the still-open stream back
    /// to the caller so a test can script what the "peer" does next
    /// (reset it — case 1 below — or keep gossiping on it — case 2).
    async fn accept_one_handshaked_stream(
        listener_genesis_id: &str,
    ) -> (
        JoinHandle<()>,
        Multiaddr,
        JoinHandle<(Vec<u8>, libp2p::swarm::Stream)>,
    ) {
        let mut host = P2pHost::new(
            &test_identity(),
            listener_genesis_id,
            &P2pHostConfig::default(),
        )
        .expect("host");
        host.listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .expect("listen");
        let mut stream_control = host.stream_control();
        let mut incoming = stream_control
            .accept(ALGORAND_WS_PROTOCOL_V22)
            .expect("register algorand-ws acceptor");

        let listen_addr = loop {
            match host.next_event().await {
                SwarmEvent::NewListenAddr { address, .. } => break address,
                _ => continue,
            }
        };
        let listener_peer_id = host.peer_id();
        let dial_addr = listen_addr.with(Protocol::P2p(listener_peer_id));

        let pump = tokio::spawn(async move {
            loop {
                host.next_event().await;
            }
        });

        let genesis_id = listener_genesis_id.to_string();
        let accept_task = tokio::spawn(async move {
            let (_peer_id, mut stream) = incoming
                .next()
                .await
                .expect("expected the injector to open an inbound stream");
            let our_headers = build_headers(
                &genesis_id,
                "",
                "mock-go-algorand",
                "",
                ALGORAND_WS_SUPPORTED_VERSIONS,
            );
            handshake_inbound(&mut stream, &our_headers, ALGORAND_WS_SUPPORTED_VERSIONS)
                .await
                .expect("inbound algorand-ws handshake");
            let body = read_frame(&mut stream)
                .await
                .expect("expected the injected frame");
            let (_tag, payload) = framing::decode_frame(&body).expect("must decode tag+payload");
            (payload.to_vec(), stream)
        });

        (pump, dial_addr, accept_task)
    }

    /// TDD anchor for issue #597: the injector can complete a real
    /// `/algorand-ws/2.2.0` handshake and deliver a tagged frame to a peer,
    /// and correctly reports a reset (Go's `wsPeerConnP2P.CloseWithoutFlush`
    /// — see this module's doc comment) as `disconnected: true` — without
    /// touching a live go-algorand node at all.
    #[tokio::test]
    async fn injects_one_message_and_observes_stream_reset() {
        let (listener_pump, dial_addr, accept_task) =
            accept_one_handshaked_stream("test-597").await;

        let mut cfg = P2pInjectorConfig::new(dial_addr, "test-597");
        cfg.observe = Duration::from_millis(800);

        let inject_task = tokio::spawn(async move {
            inject_one_p2p(&cfg, Tag::AgreementVote, b"a malformed vote".to_vec()).await
        });

        let (received_body, stream) = tokio::time::timeout(Duration::from_secs(10), accept_task)
            .await
            .expect("accept task timed out")
            .expect("accept task panicked");
        assert_eq!(received_body, b"a malformed vote");
        // Simulate go-algorand's rejection: reset the stream without
        // writing anything back.
        drop(stream);

        let outcome = tokio::time::timeout(Duration::from_secs(10), inject_task)
            .await
            .expect("inject task timed out")
            .expect("inject task panicked")
            .expect("injection should complete without error");

        listener_pump.abort();

        assert!(
            outcome.disconnected,
            "a peer resetting the stream after the injected message must be observed as disconnected"
        );
        assert!(outcome.frames_received.is_empty());
    }

    /// The converse of the above: a peer that stays alive and keeps sending
    /// frames on the stream must be reported as *not* disconnected, with the
    /// frames it sent recorded — proving a healthy peer isn't misreported as
    /// having rejected the message.
    #[tokio::test]
    async fn injects_one_message_and_observes_frames_when_peer_stays_healthy() {
        let (listener_pump, dial_addr, accept_task) =
            accept_one_handshaked_stream("test-597b").await;

        let mut cfg = P2pInjectorConfig::new(dial_addr, "test-597b");
        cfg.observe = Duration::from_millis(500);

        let inject_task = tokio::spawn(async move {
            inject_one_p2p(&cfg, Tag::AgreementVote, b"an honest-looking vote".to_vec()).await
        });

        let keep_alive_task = tokio::spawn(async move {
            let (received_body, mut stream) = accept_task.await.expect("accept task panicked");
            assert_eq!(received_body, b"an honest-looking vote");
            // A healthy peer keeps gossiping: reply with one more frame,
            // then hold the stream open past the injector's observe window
            // before letting it drop.
            let reply = framing::encode_frame(&Tag::AgreementVote, b"unrelated gossip").unwrap();
            write_frame(&mut stream, &reply)
                .await
                .expect("write reply frame");
            tokio::time::sleep(Duration::from_millis(900)).await;
            drop(stream);
        });

        let outcome = tokio::time::timeout(Duration::from_secs(10), inject_task)
            .await
            .expect("inject task timed out")
            .expect("inject task panicked")
            .expect("injection should complete without error");

        keep_alive_task.await.expect("keep-alive task panicked");
        listener_pump.abort();

        assert!(
            !outcome.disconnected,
            "a peer that keeps the stream open must not be reported as disconnected"
        );
        assert_eq!(outcome.frames_received, vec!["AV".to_string()]);
    }

    /// TDD anchor for issue #597 (found live against `ops/mixed-cluster-p2p/`):
    /// go-algorand compresses every proposal it relays on
    /// `/algorand-ws/2.2.0` (see [`capture_proposal_p2p`]'s doc comment), so
    /// a mock peer that sends a zstd-compressed `PP` frame — exactly what a
    /// real go-algorand node does — must still be captured and decompressed
    /// correctly, without a live node.
    #[tokio::test]
    async fn capture_proposal_p2p_decompresses_a_zstd_compressed_payload() {
        let mut host =
            P2pHost::new(&test_identity(), "test-597c", &P2pHostConfig::default()).expect("host");
        host.listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .expect("listen");
        let mut stream_control = host.stream_control();
        let mut incoming = stream_control
            .accept(ALGORAND_WS_PROTOCOL_V22)
            .expect("register algorand-ws acceptor");

        let listen_addr = loop {
            match host.next_event().await {
                SwarmEvent::NewListenAddr { address, .. } => break address,
                _ => continue,
            }
        };
        let listener_peer_id = host.peer_id();
        let dial_addr = listen_addr.with(Protocol::P2p(listener_peer_id));

        let pump = tokio::spawn(async move {
            loop {
                host.next_event().await;
            }
        });

        let genesis_id = "test-597c".to_string();
        let raw_proposal = b"a genuine msgpack-encoded compound-message payload".to_vec();
        let accept_task = tokio::spawn(async move {
            let (_peer_id, mut stream) = incoming
                .next()
                .await
                .expect("expected the observer to open an inbound stream");
            let our_headers = build_headers(
                &genesis_id,
                "",
                "mock-go-algorand",
                "",
                ALGORAND_WS_SUPPORTED_VERSIONS,
            );
            handshake_inbound(&mut stream, &our_headers, ALGORAND_WS_SUPPORTED_VERSIONS)
                .await
                .expect("inbound algorand-ws handshake");
            let compressed =
                algo_network::compression::zstd_compress(&raw_proposal).expect("compress proposal");
            let frame = framing::encode_frame(&Tag::ProposalPayload, &compressed).unwrap();
            write_frame(&mut stream, &frame)
                .await
                .expect("write compressed PP frame");
            // Keep the stream open until the observer has read it.
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let mut cfg = P2pInjectorConfig::new(dial_addr, "test-597c");
        cfg.observe = Duration::from_secs(5);
        let captured = capture_proposal_p2p(&cfg)
            .await
            .expect("capture should succeed and decompress transparently");

        accept_task.await.expect("accept task panicked");
        pump.abort();

        assert_eq!(
            captured,
            b"a genuine msgpack-encoded compound-message payload"
        );
    }
}
