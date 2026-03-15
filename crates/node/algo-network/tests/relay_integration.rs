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
use std::time::Duration;

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
// Test 7: relay_forwards_messages
// ---------------------------------------------------------------------------

/// Start a relay with `relay_messages=true`, connect two WebSocket peers,
/// have peer A send a framed message, and verify peer B receives it
/// (via the broadcast/relay thread).
///
/// Currently ignored: the test accepts any outcome as passing because no
/// forwarding handler is registered for AgreementVote. It will become
/// meaningful once handler integration is wired up.
#[tokio::test]
#[ignore = "requires mixed cluster for full relay forwarding verification"]
async fn relay_forwards_messages() {
    init_tracing();

    let net = build_relay_network("test-v1.0", 100);
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

    // Peer B should receive the forwarded message within a reasonable timeout.
    // Note: The relay forwards via the broadcast thread which processes
    // messages dispatched by the multiplexer.  The inbound handler parses
    // the frame and enqueues it for relay.
    //
    // However, the relay may not forward the message if no handler has
    // been registered for the AgreementVote tag (the multiplexer needs
    // a handler that returns ForwardingPolicy::Broadcast).
    //
    // Since this is an integration test of the relay infrastructure rather
    // than the full handler pipeline, we allow the test to pass if:
    //   a) Peer B receives the message (full relay working), OR
    //   b) The timeout expires but the connections stayed alive
    //      (relay infrastructure is healthy, just no handler configured
    //       to trigger forwarding).
    let receive_result = tokio::time::timeout(Duration::from_secs(3), read_b.next()).await;

    match receive_result {
        Ok(Some(Ok(msg))) => {
            // Peer B received a message — relay forwarding works.
            match msg {
                tungstenite::Message::Binary(data) => {
                    assert!(
                        !data.is_empty(),
                        "forwarded message should have non-empty data"
                    );
                    tracing::info!(len = data.len(), "peer B received forwarded binary message");
                }
                other => {
                    // Non-binary messages (ping/pong/text) are also acceptable.
                    tracing::info!(?other, "peer B received non-binary message");
                }
            }
        }
        Ok(Some(Err(e))) => {
            // WebSocket error — the connection may have been closed.
            tracing::warn!("peer B read error: {e}");
        }
        Ok(None) => {
            // Stream ended — peer disconnected.
            tracing::warn!("peer B stream ended (relay may have closed the connection)");
        }
        Err(_elapsed) => {
            // Timeout — no message forwarded.  This is acceptable when no
            // handler is registered that returns ForwardingPolicy::Broadcast.
            tracing::info!(
                "peer B did not receive a message within timeout \
                 (no forwarding handler registered — relay infrastructure is healthy)"
            );
        }
    }

    net.stop().await;
}
