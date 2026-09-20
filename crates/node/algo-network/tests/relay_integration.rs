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

//! Integration tests for the relay functionality in WebsocketNetwork.
//!
//! These tests start a local relay server (no external dependencies) and
//! verify that it binds, responds to HTTP health checks, accepts and
//! rejects gossip WebSocket connections, enforces connection limits, serves
//! blocks via a registered HTTP handler, and forwards messages between peers.
//!
//! # Running
//!
//! ```bash
//! cargo test -p algo-network --test relay_integration -- --nocapture
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use algo_network::block_service::{BlockService, BlockServiceError, LedgerForBlockService};
use algo_network::framing::encode_frame;
use algo_network::gossip_node::GossipNode;
use algo_network::handshake::PROTOCOL_VERSION;
use algo_network::phonebook::Phonebook;
use algo_network::tag::Tag;
use algo_network::ws_network::{WebsocketNetwork, WebsocketNetworkConfig};

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Initialise tracing (idempotent).
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("algo_network=debug,relay_integration=debug")
        .with_test_writer()
        .try_init();
}

/// Build a relay-mode `WebsocketNetwork` bound to an OS-assigned port.
///
/// Returns the network wrapped in `Arc`, ready for `start_arc()`.
fn build_relay_network(genesis_id: &str, conn_limit: u32) -> Arc<WebsocketNetwork> {
    let config = WebsocketNetworkConfig {
        genesis_id: genesis_id.to_string(),
        network_id: "test".to_string(),
        net_address: Some("127.0.0.1:0".to_string()),
        incoming_connections_limit: conn_limit,
        relay_messages: true,
        max_connections_per_ip: 100,              // generous for tests
        connections_rate_limiting_count: 1000,    // generous for tests
        mesh_interval: Duration::from_secs(3600), // no periodic mesh
        ..Default::default()
    };
    let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
    Arc::new(WebsocketNetwork::new(config, phonebook))
}

/// Return the `host:port` string of the relay's bound address.
///
/// Panics if the relay is not listening.
fn relay_host_port(net: &WebsocketNetwork) -> String {
    let (addr, listening) = net.address();
    assert!(listening, "relay should be listening");
    assert!(!addr.is_empty(), "address should be non-empty");
    addr
}

/// Build the base HTTP URL (e.g. `http://127.0.0.1:12345`) from the relay.
fn relay_http_base(net: &WebsocketNetwork) -> String {
    let hp = relay_host_port(net);
    format!("http://{hp}")
}

/// Build a gossip request for a relay with default test values.
fn default_gossip_request(net: &WebsocketNetwork) -> tungstenite::handshake::client::Request {
    gossip_request(&relay_host_port(net), "test-v1.0", "12345678")
}

/// Create a `tokio_tungstenite` connection request with the required
/// Algorand handshake headers.
fn gossip_request(
    host_port: &str,
    genesis_id: &str,
    node_random: &str,
) -> tungstenite::handshake::client::Request {
    let url = format!("ws://{host_port}/v1/{genesis_id}/gossip");
    tungstenite::handshake::client::Request::builder()
        .uri(&url)
        .header("Host", host_port)
        .header("X-Algorand-Version", PROTOCOL_VERSION)
        .header("X-Algorand-Accept-Version", PROTOCOL_VERSION)
        .header("X-Algorand-NodeRandom", node_random)
        .header("X-Algorand-Genesis", genesis_id)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .body(())
        .expect("valid request")
}

// ---------------------------------------------------------------------------
// Test 1: relay_starts_and_binds
// ---------------------------------------------------------------------------

/// Create a WebsocketNetwork in relay mode, start it, verify `address()`
/// returns a real address, and stop it.
#[tokio::test]
async fn relay_starts_and_binds() {
    init_tracing();

    let net = build_relay_network("test-v1.0", 100);

    // Before start: not listening.
    let (addr_before, listening_before) = net.address();
    assert!(!listening_before, "should not be listening before start");
    assert!(addr_before.is_empty());

    // Start the relay.
    net.start_arc()
        .await
        .expect("relay should start successfully");

    // After start: listening on a real address.
    let (addr, listening) = net.address();
    assert!(listening, "should be listening after start");
    assert!(!addr.is_empty(), "bound address should be non-empty");

    // Verify the address looks like `ip:port`.
    assert!(
        addr.contains(':'),
        "address should contain ':' — got {addr}"
    );
    let port_str = addr.rsplit(':').next().unwrap();
    let port: u16 = port_str
        .parse()
        .unwrap_or_else(|_| panic!("port should be a u16, got: {port_str}"));
    assert!(port > 0, "OS-assigned port should be > 0");

    // Stop cleanly.
    net.stop().await;
}

// ---------------------------------------------------------------------------
// Test 2: health_endpoint_responds
// ---------------------------------------------------------------------------

/// Start a relay, make an HTTP GET to `/status`, verify 200 with
/// `{"status":"ok"}`.
#[tokio::test]
async fn health_endpoint_responds() {
    init_tracing();

    let net = build_relay_network("test-v1.0", 100);
    net.start_arc()
        .await
        .expect("relay should start successfully");

    let base = relay_http_base(&net);
    let url = format!("{base}/status");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http client");

    let resp = client
        .get(&url)
        .send()
        .await
        .expect("GET /status should succeed");

    assert_eq!(resp.status(), 200, "health endpoint should return 200");

    let body: serde_json::Value = resp.json().await.expect("body should be valid JSON");
    assert_eq!(body["status"], "ok", "body should have status=ok");

    net.stop().await;
}

// ---------------------------------------------------------------------------
// Test 3: gossip_websocket_upgrade
// ---------------------------------------------------------------------------

/// Start a relay, connect via WebSocket to the gossip endpoint with proper
/// handshake headers, verify the connection is established.
#[tokio::test]
async fn gossip_websocket_upgrade() {
    init_tracing();

    let net = build_relay_network("test-v1.0", 100);
    net.start_arc()
        .await
        .expect("relay should start successfully");

    let request = default_gossip_request(&net);

    let (ws_stream, response) = tokio_tungstenite::connect_async(request)
        .await
        .expect("WebSocket upgrade should succeed");

    // The upgrade response should be 101 Switching Protocols.
    assert_eq!(
        response.status(),
        http::StatusCode::SWITCHING_PROTOCOLS,
        "should get 101 on upgrade"
    );

    // The connection should be usable — just close it cleanly.
    let (mut _write, mut _read) = ws_stream.split();

    net.stop().await;
}

// ---------------------------------------------------------------------------
// Test 4: gossip_rejects_wrong_genesis
// ---------------------------------------------------------------------------

/// Start a relay with genesis_id "test-v1.0", attempt to connect to
/// `/v1/wrong-genesis/gossip`, verify rejection (non-101 response).
#[tokio::test]
async fn gossip_rejects_wrong_genesis() {
    init_tracing();

    let net = build_relay_network("test-v1.0", 100);
    net.start_arc()
        .await
        .expect("relay should start successfully");

    let hp = relay_host_port(&net);
    let request = gossip_request(&hp, "wrong-genesis", "12345678");

    let result = tokio_tungstenite::connect_async(request).await;

    match result {
        Ok((_ws, resp)) => {
            // Should not get a successful upgrade for wrong genesis.
            panic!(
                "expected WebSocket upgrade to fail for wrong genesis, got status {}",
                resp.status()
            );
        }
        Err(e) => {
            // Expected: the server should reject the upgrade.
            // tungstenite returns an Http error with the status code.
            let msg = format!("{e}");
            // The server should return 412 (Precondition Failed) for genesis
            // mismatch, which tungstenite reports as an HTTP error.
            assert!(
                msg.contains("412") || msg.contains("Precondition") || msg.contains("HTTP error"),
                "expected genesis mismatch rejection (412), got: {msg}"
            );
        }
    }

    net.stop().await;
}

// ---------------------------------------------------------------------------
// Test 5: connection_limit_enforcement
// ---------------------------------------------------------------------------

/// Start a relay with a very low `incoming_connections_limit`, connect
/// many clients via plain TCP + WebSocket, and verify the per-IP limit
/// (max_connections_per_ip) eventually rejects new connections.
///
/// Note: The WebsocketNetwork uses `max_connections_per_ip` for per-IP
/// limiting in `validate_incoming_connection`.  We set it low (2) and
/// connect more clients than allowed.
#[tokio::test]
async fn connection_limit_enforcement() {
    init_tracing();

    // Use a very restrictive per-IP limit (2 connections from one IP).
    let config = WebsocketNetworkConfig {
        genesis_id: "test-v1.0".to_string(),
        network_id: "test".to_string(),
        net_address: Some("127.0.0.1:0".to_string()),
        incoming_connections_limit: 100, // TCP-level limit is generous
        relay_messages: true,
        max_connections_per_ip: 2,             // per-IP limit is strict
        connections_rate_limiting_count: 1000, // rate limit is generous
        mesh_interval: Duration::from_secs(3600),
        ..Default::default()
    };
    let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
    let net = Arc::new(WebsocketNetwork::new(config, phonebook));
    net.start_arc()
        .await
        .expect("relay should start successfully");

    let hp = relay_host_port(&net);

    // Connect the first two clients — should succeed.
    // Use different NodeRandom values so the relay sees distinct peers.
    let mut connections = Vec::new();
    for i in 0..2 {
        let node_random = format!("peer{i}random");
        let request = gossip_request(&hp, "test-v1.0", &node_random);
        let result = tokio_tungstenite::connect_async(request).await;
        match result {
            Ok((ws, _resp)) => {
                connections.push(ws);
            }
            Err(e) => {
                panic!("connection {i} should succeed, got: {e}");
            }
        }
    }

    // Give the relay a moment to track the connections.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Third connection should be rejected due to per-IP limit.
    let request = gossip_request(&hp, "test-v1.0", "peer2random");
    let result = tokio_tungstenite::connect_async(request).await;

    match result {
        Ok((_ws, resp)) => {
            // Some implementations might accept the TCP connection but
            // reject at the application level. That is also acceptable.
            // The key assertion is that it is NOT a normal 101 upgrade
            // (or if it is, the relay immediately closes it).
            // If the server accepted, it should have sent a non-101 status.
            assert_ne!(
                resp.status(),
                http::StatusCode::SWITCHING_PROTOCOLS,
                "third connection from same IP should be rejected"
            );
        }
        Err(_e) => {
            // Expected: the server rejected the connection.
            // This is the normal path.
        }
    }

    // Clean up connections.
    drop(connections);
    net.stop().await;
}

// ---------------------------------------------------------------------------
// Test 6: block_service_http_endpoint
// ---------------------------------------------------------------------------

/// A simple mock ledger that returns fixed block data.
struct MockLedger;

impl LedgerForBlockService for MockLedger {
    fn encoded_block_cert(&self, round: u64) -> Result<(Vec<u8>, Vec<u8>), BlockServiceError> {
        if round == 0 {
            Ok((b"mock-block-data".to_vec(), b"mock-cert-data".to_vec()))
        } else {
            Err(BlockServiceError::BlockNotAvailable {
                round,
                latest_round: Some(0),
            })
        }
    }

    fn latest_round(&self) -> u64 {
        0
    }
}

/// Start a relay with a mock ledger registered via `register_http_handler`,
/// make an HTTP GET to the block endpoint, and verify the response.
#[tokio::test]
async fn block_service_http_endpoint() {
    init_tracing();

    let net = build_relay_network("test-v1.0", 100);

    // Create a BlockService with our mock ledger and register it.
    let ledger: Arc<dyn LedgerForBlockService> = Arc::new(MockLedger);
    let block_service = BlockService::new(ledger, "test-v1.0".to_string(), 500 * 1024 * 1024);
    let router = block_service.http_router();

    // Register the block service router at the root path.
    // The block service router already includes the full path pattern.
    net.register_http_handler("/", router);

    // Start after registering handlers.
    net.start_arc()
        .await
        .expect("relay should start successfully");

    let base = relay_http_base(&net);

    // Round 0 encoded in base-36 is "0".
    let url = format!("{base}/v1/test-v1.0/block/0");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http client");

    let resp = client
        .get(&url)
        .send()
        .await
        .expect("GET /v1/.../block/0 should succeed");

    assert_eq!(
        resp.status(),
        200,
        "block endpoint should return 200 for round 0"
    );

    // Verify content type.
    let ct = resp
        .headers()
        .get("content-type")
        .expect("content-type header present")
        .to_str()
        .unwrap();
    assert!(
        ct.contains("application/x-algorand-block-v1"),
        "expected block content type, got: {ct}"
    );

    // Verify we got some body data.
    let body = resp.bytes().await.expect("body should be readable");
    assert!(!body.is_empty(), "body should not be empty");

    // Verify that a missing block returns 404 or 503.
    // Round 1 in base-36 is "1".
    let url_missing = format!("{base}/v1/test-v1.0/block/1");
    let resp_missing = client
        .get(&url_missing)
        .send()
        .await
        .expect("GET for missing block should get a response");
    let status = resp_missing.status().as_u16();
    assert!(
        status == 404 || status == 503,
        "missing block should return 404 or 503, got: {status}"
    );

    net.stop().await;
}

// ---------------------------------------------------------------------------
// Test 7: relay_forwards_messages (single relay, two directly-connected
// peers, raw framed WebSocket clients)
// ---------------------------------------------------------------------------

/// Start a relay with `relay_messages=true`, connect two WebSocket peers,
/// have peer A send a framed message, and verify peer B receives it
/// (via the broadcast/relay thread).
///
/// This registers the same kind of forwarding handler the real `relay`
/// command wires up in production (`bin/algod-rust/src/commands/relay.rs`'s
/// `BlockNotifyHandler`, which returns `ForwardingPolicy::Broadcast` for
/// `AgreementVote`/`ProposalPayload`/`VoteBundle`/etc.) — so this is a real,
/// exact-outcome assertion, not an "any outcome passes" stub.
#[tokio::test]
async fn relay_forwards_messages() {
    use algo_network::forwarding_policy::ForwardingPolicy;
    use algo_network::handler::{MessageHandler, TaggedMessageHandler};
    use algo_network::message::{IncomingMessage, OutgoingMessage};

    init_tracing();

    struct EchoBroadcast;

    #[async_trait::async_trait]
    impl MessageHandler for EchoBroadcast {
        async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
            OutgoingMessage {
                action: ForwardingPolicy::Broadcast,
                tag: msg.tag,
                payload: msg.data,
                topics: None,
            }
        }
    }

    let net = build_relay_network("test-v1.0", 100);
    net.register_handlers(vec![TaggedMessageHandler {
        tag: Tag::AgreementVote,
        handler: Arc::new(EchoBroadcast),
    }]);
    net.start_arc()
        .await
        .expect("relay should start successfully");

    let hp = relay_host_port(&net);

    // Connect peer A.
    let request_a = gossip_request(&hp, "test-v1.0", "peer_a_random");
    let (ws_a, _) = tokio_tungstenite::connect_async(request_a)
        .await
        .expect("peer A should connect");
    let (mut write_a, mut _read_a) = ws_a.split();

    // Connect peer B with a different NodeRandom.
    let request_b = gossip_request(&hp, "test-v1.0", "peer_b_random");
    let (ws_b, _) = tokio_tungstenite::connect_async(request_b)
        .await
        .expect("peer B should connect");
    let (mut _write_b, mut read_b) = ws_b.split();

    // Give the relay a moment to register both peers.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Peer A sends a binary message (tag + payload).
    // Use the AgreementVote tag ("AV") since the relay should forward it.
    let frame = encode_frame(&Tag::AgreementVote, b"hello-from-peer-a")
        .expect("frame encode should succeed");
    write_a
        .send(tungstenite::Message::Binary(frame))
        .await
        .expect("peer A should be able to send");

    // Peer B must receive the forwarded message — this handler is
    // registered and returns `ForwardingPolicy::Broadcast`, so the relay
    // has no excuse not to forward. Exact-outcome assertion (not "any
    // outcome passes").
    let receive_result = tokio::time::timeout(Duration::from_secs(3), read_b.next())
        .await
        .expect("peer B should receive the forwarded message within 3s")
        .expect("read should not error")
        .expect("read should produce a message");

    match receive_result {
        tungstenite::Message::Binary(data) => {
            let (tag, payload) =
                algo_network::framing::decode_frame(&data).expect("forwarded frame should decode");
            assert_eq!(tag, Tag::AgreementVote, "forwarded tag should be preserved");
            assert_eq!(
                payload,
                b"hello-from-peer-a".as_slice(),
                "forwarded payload should be preserved byte-for-byte"
            );
        }
        other => panic!("expected a binary forwarded frame, got: {other:?}"),
    }

    net.stop().await;
}

// ---------------------------------------------------------------------------
// Test 7b: relay_forwards_agreement_tags_across_a_three_node_mesh_with_exact_counts
// ---------------------------------------------------------------------------
//
// go-algorand's `TestNetworkImplFullStackQuick`/`TestNetworkImpl`
// (`agreement/gossip/networkFull_test.go`, `agreement/gossip/network_test.go`)
// build several real nodes over a real gossip mesh, broadcast each of
// `AgreementVoteTag`/`ProposalPayloadTag`/`VoteBundleTag`/mixed tags from
// node 0, and assert every OTHER node's relay-forwarded receive count
// matches exactly — proving N-node relay forwarding actually works, not
// just single-hop delivery.
//
// This proves the same property with a genuine in-process, three-`Websocket
// Network` chain: A (relay, origin) — B (relay, dials A) — C (participant,
// dials B only, never talks to A). Each node registers the same shape of
// forwarding handler the real `relay` command wires in production
// (`bin/algod-rust/src/commands/relay.rs`'s `BlockNotifyHandler`, which
// returns `ForwardingPolicy::Broadcast` for `AgreementVote`/
// `ProposalPayload`/`VoteBundle`), so this is proving the actual
// production-shaped forwarding path, not a bespoke test-only shortcut.
//
// A broadcasts one message per tag (`AgreementVote`, `ProposalPayload`,
// `VoteBundle` — the mixed-tag case). C can only see any of them if B
// actually re-broadcasts what it received from A onward — the same thing
// go's test exists to catch (a relay that receives but never re-forwards).
// Counts are asserted exactly: each downstream node must see each message
// exactly once, no more, no fewer, and the originator must never see its
// own broadcast echoed back.

/// Build a mesh-capable `WebsocketNetwork` node: `relay = true` binds a
/// listener (so other nodes can dial in); `relay = false` is a
/// non-listening participant that only dials out.
fn build_mesh_node(genesis_id: &str, relay: bool) -> Arc<WebsocketNetwork> {
    let config = WebsocketNetworkConfig {
        genesis_id: genesis_id.to_string(),
        network_id: "test".to_string(),
        net_address: if relay {
            Some("127.0.0.1:0".to_string())
        } else {
            None
        },
        relay_messages: relay,
        gossip_fanout: 2,
        // Long mesh interval so the periodic mesh thread doesn't interfere;
        // connectivity is driven explicitly by the test.
        mesh_interval: Duration::from_secs(3600),
        max_connections_per_ip: 100,
        connections_rate_limiting_count: 1000,
        ..Default::default()
    };
    let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
    Arc::new(WebsocketNetwork::new(config, phonebook))
}

/// Seed `dialer`'s phonebook with `target_addr` and trigger an outgoing
/// connection attempt.
async fn dial(dialer: &Arc<WebsocketNetwork>, target_addr: &str) {
    use algo_network::peer_role::RELAY_ROLE;
    dialer
        .phonebook()
        .replace_peer_list(&[target_addr.to_string()], "test", RELAY_ROLE);
    dialer.request_connect_outgoing(false).await;
}

/// Wait until `got.len() == n` or `timeout` elapses; returns whatever was
/// collected (possibly short).
async fn collect_n(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<(Tag, Vec<u8>)>,
    n: usize,
    timeout: Duration,
) -> Vec<(Tag, Vec<u8>)> {
    let deadline = Instant::now() + timeout;
    let mut got = Vec::new();
    while got.len() < n {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(item)) => got.push(item),
            _ => break,
        }
    }
    got
}

/// Assert that nothing further arrives on `rx` within `window` — used to
/// prove an exact count (no stray duplicate forwards).
async fn assert_no_more(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<(Tag, Vec<u8>)>,
    window: Duration,
) {
    if let Ok(Some(extra)) = tokio::time::timeout(window, rx.recv()).await {
        panic!("expected no further messages, but got an extra one: {extra:?}");
    }
}

#[tokio::test]
async fn relay_forwards_agreement_tags_across_a_three_node_mesh_with_exact_counts() {
    use algo_network::forwarding_policy::ForwardingPolicy;
    use algo_network::handler::{MessageHandler, TaggedMessageHandler};
    use algo_network::message::{IncomingMessage, OutgoingMessage};
    use tokio::sync::mpsc;

    init_tracing();

    /// Mirrors production's `BlockNotifyHandler`
    /// (`bin/algod-rust/src/commands/relay.rs`): records every inbound
    /// message it sees and always returns `ForwardingPolicy::Broadcast` so
    /// the network layer re-forwards it to this node's other peers.
    struct RecordAndForward {
        tx: mpsc::UnboundedSender<(Tag, Vec<u8>)>,
    }

    #[async_trait::async_trait]
    impl MessageHandler for RecordAndForward {
        async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
            let _ = self.tx.send((msg.tag, msg.data.clone()));
            OutgoingMessage {
                action: ForwardingPolicy::Broadcast,
                tag: msg.tag,
                payload: msg.data,
                topics: None,
            }
        }
    }

    fn wire_agreement_handlers(
        net: &Arc<WebsocketNetwork>,
    ) -> mpsc::UnboundedReceiver<(Tag, Vec<u8>)> {
        let (tx, rx) = mpsc::unbounded_channel();
        let handler: Arc<dyn MessageHandler> = Arc::new(RecordAndForward { tx });
        net.register_handlers(vec![
            TaggedMessageHandler {
                tag: Tag::AgreementVote,
                handler: Arc::clone(&handler),
            },
            TaggedMessageHandler {
                tag: Tag::ProposalPayload,
                handler: Arc::clone(&handler),
            },
            TaggedMessageHandler {
                tag: Tag::VoteBundle,
                handler,
            },
        ]);
        rx
    }

    // Node A: relay, the mesh's origin — never receives anything (it only
    // broadcasts).
    let net_a = build_mesh_node("test-v1.0", true);
    let mut rx_a = wire_agreement_handlers(&net_a);
    net_a.start_arc().await.expect("node A start");
    let (a_addr, listening_a) = net_a.address();
    assert!(listening_a, "node A should be listening");

    // Node B: relay, dials A. Must forward A's broadcasts to C.
    let net_b = build_mesh_node("test-v1.0", true);
    let mut rx_b = wire_agreement_handlers(&net_b);
    net_b.start_arc().await.expect("node B start");
    dial(&net_b, &a_addr).await;
    let (b_addr, listening_b) = net_b.address();
    assert!(listening_b, "node B should be listening");

    // Node C: non-relay participant, dials B only — never learns about A
    // directly. Can only see A's messages via B's re-broadcast.
    let net_c = build_mesh_node("test-v1.0", false);
    let mut rx_c = wire_agreement_handlers(&net_c);
    net_c.start_arc().await.expect("node C start");
    dial(&net_c, &b_addr).await;

    // Wait for the full chain to connect: A<->B and B<->C.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if net_a.peer_count().await >= 1
            && net_b.peer_count().await >= 2
            && net_c.peer_count().await >= 1
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(net_a.peer_count().await >= 1, "A should have peer B");
    assert!(net_b.peer_count().await >= 2, "B should have peers A and C");
    assert!(net_c.peer_count().await >= 1, "C should have peer B");

    // Broadcast one message per tag from A — mirrors go's "broadcast each
    // of AgreementVoteTag/ProposalPayloadTag/VoteBundleTag/mixed tags from
    // node 0" scenario.
    let expected: Vec<(Tag, Vec<u8>)> = vec![
        (Tag::AgreementVote, b"agreement-vote-payload-0".to_vec()),
        (Tag::ProposalPayload, b"proposal-payload-payload-0".to_vec()),
        (Tag::VoteBundle, b"vote-bundle-payload-0".to_vec()),
    ];
    for (tag, payload) in &expected {
        net_a
            .broadcast(*tag, payload.clone(), true, None)
            .await
            .expect("A's broadcast should succeed");
    }

    // B (one hop from A, direct gossip) must see exactly the three
    // messages.
    let got_b = collect_n(&mut rx_b, expected.len(), Duration::from_secs(5)).await;
    assert_eq!(
        got_b, expected,
        "node B should receive exactly A's three broadcast messages, in order, unmodified"
    );
    assert_no_more(&mut rx_b, Duration::from_millis(500)).await;

    // C (two hops from A, never directly connected to A) must receive all
    // three via B's re-broadcast — the actual multi-hop relay-forwarding
    // assertion this test exists to make, matching go's exact-count
    // property.
    let got_c = collect_n(&mut rx_c, expected.len(), Duration::from_secs(5)).await;
    assert_eq!(
        got_c, expected,
        "node C should receive exactly A's three broadcast messages via B's relay-forwarding, \
         in order, unmodified — despite never connecting to A directly"
    );
    assert_no_more(&mut rx_c, Duration::from_millis(500)).await;

    // A must never see its own broadcasts echoed back (broadcast excludes
    // the exclusion peer / never loops to self).
    assert_no_more(&mut rx_a, Duration::from_millis(500)).await;

    net_c.stop().await;
    net_b.stop().await;
    net_a.stop().await;
}

// ---------------------------------------------------------------------------
// Test 7c: ring_relay_propagates_agreement_votes_around_a_five_node_ring
// ---------------------------------------------------------------------------
//
// go-algorand's `TestCircularNetworkTopology`
// (`agreement/fuzzer/tests_test.go:107`) runs a live 9/14-node
// `Fuzzer`+`Service` cluster restricted to a ring topology
// (`TopologyFilterConfig`, each node connected to only its two ring
// neighbors) for 50 run + 20 recovery ticks, and asserts the cluster still
// reaches BFT consensus (converges on the same certified chain) despite the
// restricted connectivity.
//
// algod-rust's fuzzer harness has no live multi-`Service` integration and no
// `TopologyFilter` port (documented in
// `crates/core/algo-agreement/tests/fuzzer/mod.rs`'s "Out of scope" note),
// so this test does NOT attempt to reproduce that — it does not run the
// agreement `Service`/`Player` state machine at all, and proves nothing
// about BFT convergence under restricted connectivity.
//
// What it DOES prove, honestly and narrowly: the network/gossip layer
// (`WebsocketNetwork`) that a live ring-restricted agreement cluster would
// have to run on top of actually propagates a message end-to-end around a
// literal ring — no node dialing or being dialed by more than its two ring
// neighbors — via multi-hop relay, with an exact per-node receive count
// (each non-origin node sees the vote exactly once, via
// `enable_incoming_message_filter`'s AV/TX dedup preventing the two
// counter-rotating flood waves from double-delivering or looping forever).
// This is the network-layer precondition for go's consensus-convergence
// property, not the property itself.
#[tokio::test]
async fn ring_relay_propagates_agreement_votes_around_a_five_node_ring() {
    use algo_network::forwarding_policy::ForwardingPolicy;
    use algo_network::handler::{MessageHandler, TaggedMessageHandler};
    use algo_network::message::{IncomingMessage, OutgoingMessage};
    use tokio::sync::mpsc;

    init_tracing();

    const RING_SIZE: usize = 5;

    /// Records every inbound `AV` message and always re-broadcasts it —
    /// the same forwarding shape as production's `BlockNotifyHandler`
    /// (`bin/algod-rust/src/commands/relay.rs`).
    struct RecordAndForward {
        tx: mpsc::UnboundedSender<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl MessageHandler for RecordAndForward {
        async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
            let _ = self.tx.send(msg.data.clone());
            OutgoingMessage {
                action: ForwardingPolicy::Broadcast,
                tag: msg.tag,
                payload: msg.data,
                topics: None,
            }
        }
    }

    /// Build a ring-capable node. `enable_incoming_message_filter` is
    /// required: without it, a message flooded around a literal ring (every
    /// node relays every inbound message onward, and a ring node has no
    /// third connection to simply not re-send on) produces two
    /// counter-rotating waves that circle forever — this is the same
    /// AV/TX-scoped dedup go-algorand's real network relies on
    /// (`network/wsNetwork.go`), not a test-only workaround.
    fn build_ring_node(genesis_id: &str) -> Arc<WebsocketNetwork> {
        let config = WebsocketNetworkConfig {
            genesis_id: genesis_id.to_string(),
            network_id: "test".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            gossip_fanout: 2,
            mesh_interval: Duration::from_secs(3600),
            max_connections_per_ip: 100,
            connections_rate_limiting_count: 1000,
            enable_incoming_message_filter: true,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        Arc::new(WebsocketNetwork::new(config, phonebook))
    }

    // Build the ring: node i dials node (i+1) % RING_SIZE. Each node ends up
    // with exactly one inbound connection (from its predecessor) and one
    // outbound connection (to its successor) -- degree 2, no shortcuts.
    let mut nodes = Vec::with_capacity(RING_SIZE);
    let mut receivers = Vec::with_capacity(RING_SIZE);
    for _ in 0..RING_SIZE {
        let net = build_ring_node("test-v1.0");
        let (tx, rx) = mpsc::unbounded_channel();
        net.register_handlers(vec![TaggedMessageHandler {
            tag: Tag::AgreementVote,
            handler: Arc::new(RecordAndForward { tx }),
        }]);
        net.start_arc().await.expect("ring node should start");
        nodes.push(net);
        receivers.push(rx);
    }

    let addrs: Vec<String> = nodes
        .iter()
        .map(|n| {
            let (addr, listening) = n.address();
            assert!(listening, "ring node should be listening");
            addr
        })
        .collect();

    // Two different indices (i and (i+1)%RING_SIZE) are needed at once to
    // wire each node to its ring successor, so a plain iterator/enumerate
    // doesn't fit here.
    #[allow(clippy::needless_range_loop)]
    for i in 0..RING_SIZE {
        let next = (i + 1) % RING_SIZE;
        dial(&nodes[i], &addrs[next]).await;
    }

    // Wait for the ring to fully connect: every node should reach exactly
    // 2 peers (one inbound from its predecessor, one outbound to its
    // successor).
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut all_connected = true;
        for n in &nodes {
            if n.peer_count().await < 2 {
                all_connected = false;
                break;
            }
        }
        if all_connected || Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for (i, n) in nodes.iter().enumerate() {
        let count = n.peer_count().await;
        assert_eq!(
            count, 2,
            "ring node {i} should have exactly 2 peers (its ring neighbors only), got {count}"
        );
    }

    // Broadcast one AgreementVote from node 0 -- the origin.
    let payload = b"ring-agreement-vote-payload".to_vec();
    nodes[0]
        .broadcast(Tag::AgreementVote, payload.clone(), true, None)
        .await
        .expect("origin broadcast should succeed");

    // Every OTHER node in the ring must receive the vote exactly once, via
    // multi-hop relay -- none of them dialed or were dialed by node 0
    // directly except nodes 1 and 4 (its immediate ring neighbors); nodes 2
    // and 3 are two hops away and can only see it via relay.
    for (i, rx) in receivers.iter_mut().enumerate().skip(1) {
        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("node {i} should receive the vote within 5s"))
            .unwrap_or_else(|| panic!("node {i}'s channel closed unexpectedly"));
        assert_eq!(
            got, payload,
            "node {i} should receive the vote byte-for-byte unmodified"
        );
        // Exact count: the dedup filter must prevent the two
        // counter-rotating flood waves from delivering it twice.
        assert!(
            tokio::time::timeout(Duration::from_millis(500), rx.recv())
                .await
                .is_err(),
            "node {i} should receive the vote exactly once, not a second time \
             from the other direction around the ring"
        );
    }

    // The origin must never see its own broadcast echoed back around the
    // ring.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), receivers[0].recv())
            .await
            .is_err(),
        "origin node 0 should never receive its own broadcast back"
    );

    for n in nodes.iter().rev() {
        n.stop().await;
    }
}

// ---------------------------------------------------------------------------
// Test 7d: ring_relay_isolated_without_forwarding (negative control for
// ring_relay_propagates_agreement_votes_around_a_five_node_ring)
// ---------------------------------------------------------------------------
//
// Sanity check proving the ring test above is actually exercising relay,
// not silently passing because of some hidden direct connection: break
// forwarding at BOTH of the origin's immediate ring neighbors (nodes 1 and
// 4), so neither of the two flood waves leaving the origin can propagate
// past its first hop. The two farthest nodes (2 and 3), each two hops away,
// must then receive nothing at all.
//
// (Breaking only a single node's forwarding is not a useful negative check
// here: a ring gives every node two independent paths from the origin, so
// disabling relay at one node alone does not isolate anything -- the other
// direction still delivers. Breaking both of the origin's neighbors closes
// both paths at once.)
#[tokio::test]
async fn ring_relay_isolated_without_forwarding() {
    use algo_network::forwarding_policy::ForwardingPolicy;
    use algo_network::handler::{MessageHandler, TaggedMessageHandler};
    use algo_network::message::{IncomingMessage, OutgoingMessage};
    use tokio::sync::mpsc;

    init_tracing();

    const RING_SIZE: usize = 5;

    struct RecordAndForward {
        tx: mpsc::UnboundedSender<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl MessageHandler for RecordAndForward {
        async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
            let _ = self.tx.send(msg.data.clone());
            OutgoingMessage {
                action: ForwardingPolicy::Broadcast,
                tag: msg.tag,
                payload: msg.data,
                topics: None,
            }
        }
    }

    /// Records inbound messages but never forwards them (`Ignore`) --
    /// simulates a broken/missing relay handler.
    struct RecordOnlyNoForward {
        tx: mpsc::UnboundedSender<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl MessageHandler for RecordOnlyNoForward {
        async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
            let _ = self.tx.send(msg.data.clone());
            OutgoingMessage {
                action: ForwardingPolicy::Ignore,
                tag: msg.tag,
                payload: Vec::new(),
                topics: None,
            }
        }
    }

    fn build_ring_node(genesis_id: &str) -> Arc<WebsocketNetwork> {
        let config = WebsocketNetworkConfig {
            genesis_id: genesis_id.to_string(),
            network_id: "test".to_string(),
            net_address: Some("127.0.0.1:0".to_string()),
            relay_messages: true,
            gossip_fanout: 2,
            mesh_interval: Duration::from_secs(3600),
            max_connections_per_ip: 100,
            connections_rate_limiting_count: 1000,
            enable_incoming_message_filter: true,
            ..Default::default()
        };
        let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
        Arc::new(WebsocketNetwork::new(config, phonebook))
    }

    let mut nodes = Vec::with_capacity(RING_SIZE);
    let mut receivers = Vec::with_capacity(RING_SIZE);
    for i in 0..RING_SIZE {
        let net = build_ring_node("test-v1.0");
        let (tx, rx) = mpsc::unbounded_channel();
        // Nodes 1 and 4 (origin's immediate neighbors) do NOT forward.
        let handler: Arc<dyn MessageHandler> = if i == 1 || i == 4 {
            Arc::new(RecordOnlyNoForward { tx })
        } else {
            Arc::new(RecordAndForward { tx })
        };
        net.register_handlers(vec![TaggedMessageHandler {
            tag: Tag::AgreementVote,
            handler,
        }]);
        net.start_arc().await.expect("ring node should start");
        nodes.push(net);
        receivers.push(rx);
    }

    let addrs: Vec<String> = nodes
        .iter()
        .map(|n| {
            let (addr, listening) = n.address();
            assert!(listening, "ring node should be listening");
            addr
        })
        .collect();

    #[allow(clippy::needless_range_loop)]
    for i in 0..RING_SIZE {
        let next = (i + 1) % RING_SIZE;
        dial(&nodes[i], &addrs[next]).await;
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut all_connected = true;
        for n in &nodes {
            if n.peer_count().await < 2 {
                all_connected = false;
                break;
            }
        }
        if all_connected || Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for n in &nodes {
        assert_eq!(n.peer_count().await, 2, "ring should still be fully wired");
    }

    let payload = b"ring-agreement-vote-payload".to_vec();
    nodes[0]
        .broadcast(Tag::AgreementVote, payload.clone(), true, None)
        .await
        .expect("origin broadcast should succeed");

    // Nodes 1 and 4 still receive it directly (they're the origin's direct
    // peers -- direct delivery doesn't need relay).
    for i in [1usize, 4usize] {
        let got = tokio::time::timeout(Duration::from_secs(5), receivers[i].recv())
            .await
            .unwrap_or_else(|_| panic!("node {i} should still receive the vote directly"))
            .unwrap_or_else(|| panic!("node {i}'s channel closed unexpectedly"));
        assert_eq!(got, payload);
    }

    // Nodes 2 and 3 are two hops away and depend entirely on relay through
    // 1 or 4 respectively -- with both neighbors' forwarding disabled, they
    // must receive NOTHING.
    for i in [2usize, 3usize] {
        let result = tokio::time::timeout(Duration::from_millis(800), receivers[i].recv()).await;
        assert!(
            result.is_err(),
            "node {i} should receive nothing -- both of the origin's neighbors have \
             forwarding disabled, so no path can reach it, proving the passing ring test's \
             delivery to 2-hop nodes genuinely depends on relay"
        );
    }

    for n in nodes.iter().rev() {
        n.stop().await;
    }
}

// ---------------------------------------------------------------------------
// Test 7: inbound_zstd_proposal_is_decompressed (regression: issue #478)
// ---------------------------------------------------------------------------

/// go-algorand compresses **every** `PP` broadcast with zstd once the wsnet
/// protocol version is 2.2 — `msgBroadcaster.preparePeerData`
/// (`network/wsNetwork.go:1471`) does it before any per-peer feature check,
/// and the per-peer codec explicitly does not implement outgoing PP
/// compression (`network/msgCompressor.go:94`). Its receive path
/// correspondingly always installs the PP decompressor and decides purely on
/// the zstd frame magic (`network/msgCompressor.go:206,281`).
///
/// The Rust inbound-peer read loop used to skip decompression entirely, and
/// the outbound one gated it on the negotiated `ppzstd` feature. A Go relay
/// that dialed a Rust node therefore delivered raw zstd bytes to
/// `agreement::demux`, which failed to msgpack-decode them and disconnected
/// the peer — the Rust node never accepted a single proposal and never left
/// round 0 (issue #478).
///
/// This test drives the real inbound path: a client connects to a relay-mode
/// `WebsocketNetwork` without advertising any peer features, sends a
/// zstd-compressed `PP` frame, and the registered handler must observe the
/// *decompressed* payload.
#[tokio::test]
async fn inbound_zstd_proposal_is_decompressed() {
    use algo_network::compression::zstd_compress;
    use algo_network::forwarding_policy::ForwardingPolicy;
    use algo_network::handler::{MessageHandler, TaggedMessageHandler};
    use algo_network::message::{IncomingMessage, OutgoingMessage};
    use tokio::sync::mpsc;

    init_tracing();

    struct Capture {
        tx: mpsc::UnboundedSender<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl MessageHandler for Capture {
        async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
            let _ = self.tx.send(msg.data);
            OutgoingMessage {
                action: ForwardingPolicy::Ignore,
                tag: Tag::ProposalPayload,
                payload: Vec::new(),
                topics: None,
            }
        }
    }

    let (tx, mut rx) = mpsc::unbounded_channel();
    let net = build_relay_network("test-v1.0", 100);
    net.register_handlers(vec![TaggedMessageHandler {
        tag: Tag::ProposalPayload,
        handler: Arc::new(Capture { tx }),
    }]);
    net.start_arc().await.expect("relay should start");

    let hp = relay_host_port(&net);
    let request = gossip_request(&hp, "test-v1.0", "zstd_pp_peer");
    let (ws, _) = tokio_tungstenite::connect_async(request)
        .await
        .expect("peer should connect");
    let (mut write, _read) = ws.split();

    // A payload that is unambiguously not a zstd frame itself, and big
    // enough that zstd actually produces a frame header.
    let plain: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let compressed = zstd_compress(&plain).expect("compression should succeed");
    assert_ne!(compressed, plain, "payload must actually be compressed");

    let mut frame = Vec::with_capacity(2 + compressed.len());
    frame.extend_from_slice(&Tag::ProposalPayload.as_bytes());
    frame.extend_from_slice(&compressed);
    write
        .send(tungstenite::Message::Binary(frame))
        .await
        .expect("peer should be able to send");

    let received = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("handler should be invoked before the timeout")
        .expect("handler channel should stay open");

    assert_eq!(
        received, plain,
        "inbound PP must reach the handler decompressed, regardless of \
         whether the peer negotiated the ppzstd feature"
    );

    net.stop().await;
}
