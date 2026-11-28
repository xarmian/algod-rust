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

//! go v5.1.1 `wsPeer.readLoop` per-message read deadline
//! (`maxMessageReadDuration`, issue #2612): a peer that sends the first frame
//! of a message and stalls is dropped once the deadline passes; an idle peer, a
//! slow but progressing message and a stalled control frame are kept. Both
//! stacks: the outbound tokio-tungstenite read loop and the inbound axum one.

use std::sync::Arc;
use std::time::{Duration, Instant};

use algo_network::handshake::PROTOCOL_VERSION;
use algo_network::peer_features::PeerFeatureFlags;
use algo_network::phonebook::Phonebook;
use algo_network::read_progress::{ProgressIo, ProgressTap};
use algo_network::ws_network::{WebsocketNetwork, WebsocketNetworkConfig};
use algo_network::ws_peer::{PeerHandle, WsPeer, WsPeerConfig};
use algo_network::GossipNode;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite;
use tokio_util::sync::CancellationToken;

/// The read duration the tests give the peer (go's is 50 s).
const MAX: Duration = Duration::from_millis(1500);

/// First 12 bytes of a 256-byte binary frame (server to client, unmasked).
fn partial_binary_frame() -> Vec<u8> {
    let mut f = vec![0x82, 126, 0x01, 0x00];
    f.extend_from_slice(&[b'X'; 8]);
    f
}

/// A whole small binary frame (an unknown tag, which the loops skip).
fn whole_binary_frame(masked: bool) -> Vec<u8> {
    let payload = b"XXabc";
    let mut f = vec![0x82, if masked { 0x80 } else { 0 } | payload.len() as u8];
    if masked {
        f.extend_from_slice(&[0, 0, 0, 0]);
    }
    f.extend_from_slice(payload);
    f
}

/// An outbound `WsPeer` whose read loop follows its socket, and the server's
/// raw TCP side (after the websocket handshake) to write bytes to.
async fn outbound_pair() -> (PeerHandle, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        tokio_tungstenite::accept_async(tcp).await.unwrap()
    });
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (tap, progress) = ProgressTap::new(MAX, false);
    let io = ProgressIo::with_tap(tcp, tap);
    let progress = Some(progress);
    let (ws, _) = tokio_tungstenite::client_async(
        format!("ws://{addr}/"),
        tokio_tungstenite::MaybeTlsStream::Plain(io),
    )
    .await
    .unwrap();
    // the handshake is done: the server sends nothing until we do
    if let Some(p) = &progress {
        p.arm();
    }
    let peer = WsPeer::with_config(
        ws,
        addr.to_string(),
        "2.1".to_string(),
        PeerFeatureFlags::empty(),
        None,
        false,
        CancellationToken::new(),
        WsPeerConfig {
            read_progress: progress,
            ..WsPeerConfig::default()
        },
    );
    let handle = peer.start();
    let server_ws = server.await.unwrap();
    // the raw socket under the server's websocket
    (handle, server_ws.into_inner())
}

async fn wait_until(what: &str, limit: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn outbound_peer_that_stalls_a_message_is_dropped() {
    let (handle, mut server) = outbound_pair().await;
    let started = Instant::now();
    server.write_all(&partial_binary_frame()).await.unwrap();
    wait_until(
        "the stalled peer is dropped",
        Duration::from_secs(10),
        || handle.is_closed(),
    )
    .await;
    assert!(started.elapsed() >= MAX, "not before the read duration");
}

#[tokio::test]
async fn outbound_idle_peer_and_progressing_message_are_kept() {
    let (handle, mut server) = outbound_pair().await;
    // idle for well over the read duration
    tokio::time::sleep(MAX * 3).await;
    assert!(!handle.is_closed(), "an idle peer is kept");

    // a message delivered in two pieces inside the duration
    let frame = whole_binary_frame(false);
    server.write_all(&frame[..3]).await.unwrap();
    tokio::time::sleep(MAX / 4).await;
    server.write_all(&frame[3..]).await.unwrap();
    // and the next message starts only later: nothing is carried over
    tokio::time::sleep(MAX * 3).await;
    assert!(!handle.is_closed(), "a completed message is not dropped");

    // a partial ping is not a message (go handles control frames in NextReader)
    server.write_all(&[0x89, 8, 1, 2, 3]).await.unwrap();
    tokio::time::sleep(MAX * 3).await;
    assert!(
        !handle.is_closed(),
        "a stalled control frame is not bounded"
    );
}

/// The relay, and a raw client past the Algorand handshake.
async fn inbound_pair() -> (Arc<WebsocketNetwork>, TcpStream) {
    let relay = Arc::new(WebsocketNetwork::new(
        WebsocketNetworkConfig {
            genesis_id: "test-v1.0".to_string(),
            network_id: "test".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            mesh_interval: Duration::from_secs(3600),
            max_message_read_duration: MAX,
            ..Default::default()
        },
        Arc::new(Phonebook::new(10, Duration::from_secs(60))),
    ));
    relay.start_arc().await.expect("relay start");
    let (addr, _) = relay.address();
    let request = tungstenite::handshake::client::Request::builder()
        .uri(format!("ws://{addr}/v1/test-v1.0/gossip"))
        .header("Host", &addr)
        .header("X-Algorand-Version", PROTOCOL_VERSION)
        .header("X-Algorand-Accept-Version", PROTOCOL_VERSION)
        .header("X-Algorand-NodeRandom", "read-deadline-client")
        .header("X-Algorand-Genesis", "test-v1.0")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .body(())
        .unwrap();
    let (ws, response) = tokio_tungstenite::connect_async(request).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);
    // the test talks raw bytes on the socket under the websocket
    let tcp = match ws.into_inner() {
        tokio_tungstenite::MaybeTlsStream::Plain(tcp) => tcp,
        _ => unreachable!("a plain connection"),
    };
    wait_for_peers(&relay, 1).await;
    (relay, tcp)
}

async fn wait_for_peers(relay: &WebsocketNetwork, n: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while relay.peer_count().await != n {
        assert!(
            Instant::now() < deadline,
            "relay peer count never reached {n}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn inbound_peer_that_stalls_a_message_is_dropped() {
    let (relay, mut client) = inbound_pair().await;
    let started = Instant::now();
    // a masked client frame: header with mask bit, then a few payload bytes
    let mut f = vec![0x82, 0x80 | 126, 0x01, 0x00, 1, 2, 3, 4];
    f.extend_from_slice(&[7u8; 8]);
    client.write_all(&f).await.unwrap();
    wait_for_peers(&relay, 0).await;
    assert!(started.elapsed() >= MAX, "not before the read duration");
    relay.stop().await;
}

#[tokio::test]
async fn inbound_idle_peer_and_progressing_message_are_kept() {
    let (relay, mut client) = inbound_pair().await;
    tokio::time::sleep(MAX * 3).await;
    assert_eq!(relay.peer_count().await, 1, "an idle peer is kept");

    let frame = whole_binary_frame(true);
    client.write_all(&frame[..5]).await.unwrap();
    tokio::time::sleep(MAX / 4).await;
    client.write_all(&frame[5..]).await.unwrap();
    tokio::time::sleep(MAX * 3).await;
    assert_eq!(
        relay.peer_count().await,
        1,
        "a message completed in time is not dropped"
    );
    relay.stop().await;
}
