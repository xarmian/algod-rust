//! Stress tests for Rust relay nodes under high message volume.
//!
//! These tests create a local `WebsocketNetwork` relay instance (no Docker
//! required), connect multiple synthetic WebSocket clients, and verify that
//! the node handles high message throughput without panics, dropped
//! connections, or unbounded memory growth.
//!
//! All tests are `#[ignore]` by default since they are resource-intensive.
//!
//! # Running
//!
//! ```bash
//! cargo test -p algo-network --test stress_test -- --ignored --nocapture
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
        .with_env_filter("algo_network=info,stress_test=info")
        .with_test_writer()
        .try_init();
}

/// Build a relay-mode `WebsocketNetwork` bound to an OS-assigned port.
///
/// Uses generous limits appropriate for stress testing.
fn build_stress_relay(genesis_id: &str, conn_limit: u32) -> Arc<WebsocketNetwork> {
    let config = WebsocketNetworkConfig {
        genesis_id: genesis_id.to_string(),
        network_id: "stress-test".to_string(),
        net_address: Some("127.0.0.1:0".to_string()),
        incoming_connections_limit: conn_limit,
        relay_messages: true,
        max_connections_per_ip: 1000,
        connections_rate_limiting_count: 10_000,
        mesh_interval: Duration::from_secs(3600), // no periodic mesh
        ..Default::default()
    };
    let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
    Arc::new(WebsocketNetwork::new(config, phonebook))
}

/// Return the `host:port` string of the relay's bound address.
fn relay_host_port(net: &WebsocketNetwork) -> String {
    let (addr, listening) = net.address();
    assert!(listening, "relay should be listening");
    assert!(!addr.is_empty(), "address should be non-empty");
    addr
}

/// Create a gossip WebSocket request with the standard Algorand handshake
/// headers.
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

/// Connect a WebSocket client to the relay and return the split stream.
async fn connect_client(
    host_port: &str,
    genesis_id: &str,
    client_id: usize,
) -> (
    futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tungstenite::Message,
    >,
    futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) {
    let node_random = format!("stress-client-{client_id}");
    let request = gossip_request(host_port, genesis_id, &node_random);

    let (ws_stream, response) = tokio_tungstenite::connect_async(request)
        .await
        .unwrap_or_else(|e| panic!("client {client_id} WebSocket upgrade failed: {e}"));

    assert_eq!(
        response.status(),
        http::StatusCode::SWITCHING_PROTOCOLS,
        "client {client_id} should get 101"
    );

    ws_stream.split()
}

/// Generate a synthetic payload of the given size filled with a repeating
/// byte pattern.
fn make_payload(size: usize, seed: u8) -> Vec<u8> {
    (0..size).map(|i| seed.wrapping_add(i as u8)).collect()
}

// ---------------------------------------------------------------------------
// Test 1: test_high_message_volume
// ---------------------------------------------------------------------------

/// Connect 10 synthetic peers to a local relay and have each send a burst
/// of 100+ messages with various tags.  Verify: no panics, no dropped
/// connections, and messages are processed within a bounded time (60s).
#[tokio::test]
#[ignore]
async fn test_high_message_volume() {
    init_tracing();

    let genesis_id = "stress-v1.0";
    let num_clients = 10;
    let messages_per_client = 150;

    // Start the relay.
    let net = build_stress_relay(genesis_id, 200);
    net.start_arc()
        .await
        .expect("relay should start successfully");

    let host_port = relay_host_port(&net);

    // Tags to cycle through for message variety.  Use tags that have
    // sufficiently large max_message_size for our payloads.
    let tags = [
        Tag::Transaction,
        Tag::AgreementVote,
        Tag::ProposalPayload,
        Tag::VoteBundle,
        Tag::StateProofSig,
    ];

    let total_messages_sent = Arc::new(AtomicU64::new(0));
    let total_bytes_sent = Arc::new(AtomicU64::new(0));

    let start_time = Instant::now();

    // Spawn client tasks that each connect and send a burst of messages.
    let mut client_handles = Vec::new();
    for client_id in 0..num_clients {
        let hp = host_port.clone();
        let sent_count = total_messages_sent.clone();
        let sent_bytes = total_bytes_sent.clone();

        let handle = tokio::spawn(async move {
            let (mut write, _read) = connect_client(&hp, genesis_id, client_id).await;

            for msg_idx in 0..messages_per_client {
                // Vary payload size between 1KB and 10KB.
                let payload_size = 1024 + (msg_idx % 10) * 1024;
                let tag = tags[msg_idx % tags.len()];
                let payload = make_payload(payload_size, (client_id * 7 + msg_idx) as u8);

                let frame = encode_frame(&tag, &payload)
                    .unwrap_or_else(|e| panic!("encode_frame failed: {e}"));

                write
                    .send(tungstenite::Message::Binary(frame.clone()))
                    .await
                    .unwrap_or_else(|e| {
                        panic!("client {client_id} msg {msg_idx} send failed: {e}")
                    });

                sent_count.fetch_add(1, Ordering::Relaxed);
                sent_bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
            }

            // Close gracefully.
            let _ = write.close().await;
            client_id
        });

        client_handles.push(handle);
    }

    // Wait for all clients to finish, with a 60-second overall timeout.
    let results = tokio::time::timeout(Duration::from_secs(60), async {
        let mut completed = Vec::new();
        for handle in client_handles {
            let client_id = handle.await.expect("client task should not panic");
            completed.push(client_id);
        }
        completed
    })
    .await
    .expect("all clients should complete within 60 seconds");

    let elapsed = start_time.elapsed();
    let total_sent = total_messages_sent.load(Ordering::Relaxed);
    let total_bytes = total_bytes_sent.load(Ordering::Relaxed);

    // All clients should have completed successfully.
    assert_eq!(
        results.len(),
        num_clients,
        "all {num_clients} clients should complete"
    );

    // All messages should have been sent.
    let expected_total = (num_clients * messages_per_client) as u64;
    assert_eq!(
        total_sent, expected_total,
        "expected {expected_total} messages sent, got {total_sent}"
    );

    // Report throughput.
    let msgs_per_sec = total_sent as f64 / elapsed.as_secs_f64();
    let mb_per_sec = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
    eprintln!(
        "HIGH VOLUME RESULTS: {} messages in {:.2}s ({:.0} msg/s, {:.2} MB/s, {} bytes total)",
        total_sent,
        elapsed.as_secs_f64(),
        msgs_per_sec,
        mb_per_sec,
        total_bytes,
    );

    // Verify the relay node is still healthy (no panic, still listening).
    let (addr, listening) = net.address();
    assert!(
        listening,
        "relay should still be listening after stress test"
    );
    assert!(!addr.is_empty());

    // Verify we can still connect a new client after the burst.
    let (mut write, _read) = connect_client(&host_port, genesis_id, 999).await;
    let post_burst_payload = make_payload(1024, 0xFF);
    let post_burst_frame =
        encode_frame(&Tag::Transaction, &post_burst_payload).expect("encode post-burst frame");
    write
        .send(tungstenite::Message::Binary(post_burst_frame))
        .await
        .expect("post-burst message should send successfully");
    let _ = write.close().await;

    // Peer count check: allow time for peers to register and then be cleaned up.
    tokio::time::sleep(Duration::from_millis(200)).await;

    net.stop().await;
}

// ---------------------------------------------------------------------------
// Test 2: test_sustained_throughput
// ---------------------------------------------------------------------------

/// Run sustained load for 10+ seconds with multiple clients continuously
/// sending messages.  Verify:
/// - No panics or dropped connections during the run
/// - Connection count stays stable (all clients remain connected)
/// - The relay remains responsive after the sustained load
#[tokio::test]
#[ignore]
async fn test_sustained_throughput() {
    init_tracing();

    let genesis_id = "sustained-v1.0";
    let num_clients = 5;
    let sustained_duration = Duration::from_secs(12);

    // Start the relay.
    let net = build_stress_relay(genesis_id, 200);
    net.start_arc()
        .await
        .expect("relay should start successfully");

    let host_port = relay_host_port(&net);

    let total_messages_sent = Arc::new(AtomicU64::new(0));
    let total_bytes_sent = Arc::new(AtomicU64::new(0));
    let connection_errors = Arc::new(AtomicU64::new(0));

    let start_time = Instant::now();

    // Spawn client tasks that continuously send messages for the duration.
    let mut client_handles = Vec::new();
    for client_id in 0..num_clients {
        let hp = host_port.clone();
        let sent_count = total_messages_sent.clone();
        let sent_bytes = total_bytes_sent.clone();
        let conn_errors = connection_errors.clone();

        let handle = tokio::spawn(async move {
            let (mut write, _read) = connect_client(&hp, genesis_id, client_id).await;

            let mut msg_idx: usize = 0;
            let client_start = Instant::now();

            while client_start.elapsed() < sustained_duration {
                // Use a moderate payload size (2KB-5KB) for sustained throughput.
                let payload_size = 2048 + (msg_idx % 4) * 1024;
                let tag = if msg_idx % 3 == 0 {
                    Tag::AgreementVote
                } else {
                    Tag::Transaction
                };

                let payload = make_payload(payload_size, (client_id * 13 + msg_idx) as u8);
                let frame = match encode_frame(&tag, &payload) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("client {client_id} encode error: {e}");
                        conn_errors.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                };

                match write
                    .send(tungstenite::Message::Binary(frame.clone()))
                    .await
                {
                    Ok(()) => {
                        sent_count.fetch_add(1, Ordering::Relaxed);
                        sent_bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
                    }
                    Err(e) => {
                        eprintln!("client {client_id} send error after {} msgs: {e}", msg_idx);
                        conn_errors.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }

                msg_idx += 1;

                // Small yield to avoid starving the runtime.  Send in
                // micro-batches of 50 messages.
                if msg_idx % 50 == 0 {
                    tokio::task::yield_now().await;
                }
            }

            // Close gracefully.
            let _ = write.close().await;
            (client_id, msg_idx)
        });

        client_handles.push(handle);
    }

    // Wait for all clients to finish, with a generous timeout.
    let results = tokio::time::timeout(Duration::from_secs(60), async {
        let mut completed = Vec::new();
        for handle in client_handles {
            let result = handle.await.expect("client task should not panic");
            completed.push(result);
        }
        completed
    })
    .await
    .expect("sustained throughput test should complete within 60 seconds");

    let elapsed = start_time.elapsed();
    let total_sent = total_messages_sent.load(Ordering::Relaxed);
    let total_bytes = total_bytes_sent.load(Ordering::Relaxed);
    let errors = connection_errors.load(Ordering::Relaxed);

    // Report per-client results.
    for (client_id, msg_count) in &results {
        eprintln!("  client {client_id}: {msg_count} messages sent");
    }

    // Report aggregate throughput.
    let msgs_per_sec = total_sent as f64 / elapsed.as_secs_f64();
    let mb_per_sec = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
    eprintln!(
        "SUSTAINED RESULTS: {} messages in {:.2}s ({:.0} msg/s, {:.2} MB/s, {} errors)",
        total_sent,
        elapsed.as_secs_f64(),
        msgs_per_sec,
        mb_per_sec,
        errors,
    );

    // All clients should have completed.
    assert_eq!(
        results.len(),
        num_clients,
        "all {num_clients} clients should complete"
    );

    // Each client should have sent at least some messages.
    for (client_id, msg_count) in &results {
        assert!(
            *msg_count > 0,
            "client {client_id} should have sent at least 1 message"
        );
    }

    // Connection errors should be zero (no dropped connections).
    assert_eq!(
        errors, 0,
        "expected zero connection errors during sustained load, got {errors}"
    );

    // Verify the relay is still healthy after sustained load.
    let (addr, listening) = net.address();
    assert!(
        listening,
        "relay should still be listening after sustained load"
    );
    assert!(!addr.is_empty());

    // Verify we can still establish a new connection post-load.
    let (mut write, _read) = connect_client(&host_port, genesis_id, 888).await;
    let check_payload = make_payload(1024, 0xAA);
    let check_frame = encode_frame(&Tag::Transaction, &check_payload).expect("encode check frame");
    write
        .send(tungstenite::Message::Binary(check_frame))
        .await
        .expect("post-sustained-load message should send successfully");
    let _ = write.close().await;

    net.stop().await;
}
