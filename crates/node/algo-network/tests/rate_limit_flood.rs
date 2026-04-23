//! End-to-end flood coverage for the per-IP rate-limit gate.
//!
//! Extends [`relay_integration.rs`][ri], which covers per-IP **connection**
//! limits via `max_connections_per_ip`. This suite targets the
//! **rate-limit** path — `connections_rate_limiting_count` inside the
//! sliding window — by rapidly re-dialling from a single loopback source
//! and asserting the rejection fires.
//!
//! Audited in [`docs/NETWORK_RATE_LIMITING.md`][audit] (TASK-72).
//!
//! [ri]: ./relay_integration.rs
//! [audit]: ../../../docs/NETWORK_RATE_LIMITING.md

use std::sync::Arc;
use std::time::Duration;

use algo_network::gossip_node::GossipNode;
use algo_network::handshake::PROTOCOL_VERSION;
use algo_network::phonebook::Phonebook;
use algo_network::ws_network::{WebsocketNetwork, WebsocketNetworkConfig};

use tokio_tungstenite::tungstenite;

// ---------------------------------------------------------------------------
// Helpers (mirroring relay_integration.rs — kept local so this file can run
// in isolation)
// ---------------------------------------------------------------------------

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("algo_network=debug,rate_limit_flood=debug")
        .with_test_writer()
        .try_init();
}

fn relay_host_port(net: &WebsocketNetwork) -> String {
    let (addr, listening) = net.address();
    assert!(listening, "relay should be listening");
    assert!(!addr.is_empty(), "address should be non-empty");
    addr
}

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
// Test: per_ip_rate_limit_rejects_rapid_redial
// ---------------------------------------------------------------------------

/// Rapid re-dial from a single loopback source exceeds the per-IP rate
/// limit (`connections_rate_limiting_count`) and gets rejected.
///
/// Test shape:
///
/// - Relay configured with generous `max_connections_per_ip = 100` (so the
///   per-IP **connection** gate never fires — we're isolating the rate
///   gate).
/// - `connections_rate_limiting_count = 2`: at most two dials per sliding
///   window are permitted.
/// - Dial, drop immediately, dial again, drop, dial a third time — the
///   third dial should not complete the WS upgrade. `validate_incoming_
///   connection` returns 429 Too Many Requests; `connect_async` either
///   fails or returns a non-101 response.
///
/// Each dial uses a unique NodeRandom so the handshake passes the
/// self-loop check (`validate_incoming_connection` step 6) and we
/// actually reach the rate-limit gate (step 5).
///
/// Why three dials is enough: `validate_incoming_connection` calls
/// `track_connection` *before* the rate-limit check. So the Nth live
/// dial compares `tracked_attempts == N` vs `count == 2`:
///
/// | Dial | tracked_attempts after | rate check |
/// |------|-----------------------:|-----------:|
/// | 1    | 1                      | 1 ≤ 2 → ok |
/// | 2    | 2                      | 2 ≤ 2 → ok |
/// | 3    | 3                      | 3 ≤ 2 → **reject** |
#[tokio::test]
async fn per_ip_rate_limit_rejects_rapid_redial() {
    init_tracing();

    let config = WebsocketNetworkConfig {
        genesis_id: "test-v1.0".to_string(),
        network_id: "test".to_string(),
        net_address: Some("127.0.0.1:0".to_string()),
        incoming_connections_limit: 100, // TCP-level limit is generous
        relay_messages: true,
        max_connections_per_ip: 100,        // per-IP connection gate lax
        connections_rate_limiting_count: 2, // per-IP rate gate strict
        mesh_interval: Duration::from_secs(3600),
        ..Default::default()
    };
    let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
    let net = Arc::new(WebsocketNetwork::new(config, phonebook));
    net.start_arc().await.expect("relay should start");

    let hp = relay_host_port(&net);

    // Rapid re-dial. Each dial uses a unique NodeRandom so it is not
    // classified as a self-loop (which would reject for a different
    // reason and confound the test).
    //
    // We disconnect immediately so the per-IP connection-count drops back
    // but the rate-window timestamps remain — that is exactly the
    // attacker model the rate gate defends against.
    let mut outcomes: Vec<Result<(), String>> = Vec::new();
    for i in 0..3 {
        let req = gossip_request(&hp, "test-v1.0", &format!("rate-test-{i}"));
        match tokio_tungstenite::connect_async(req).await {
            Ok((ws, _resp)) => {
                outcomes.push(Ok(()));
                drop(ws); // close TCP immediately to release the active count
            }
            Err(tungstenite::Error::Http(resp)) => {
                outcomes.push(Err(format!("http {}", resp.status())));
            }
            Err(e) => {
                outcomes.push(Err(format!("other: {e}")));
            }
        }
    }

    // Dials 1 and 2 must succeed.
    assert!(
        outcomes[0].is_ok(),
        "dial 1 should succeed: got {:?}",
        outcomes[0],
    );
    assert!(
        outcomes[1].is_ok(),
        "dial 2 should succeed: got {:?}",
        outcomes[1],
    );

    // Dial 3 must be rejected. We accept either the `Err(Http(429))` path
    // or any other `Err(...)` — tokio-tungstenite's behaviour on a
    // rejected upgrade depends on timing (the server may close the TCP
    // socket before finishing the HTTP response).
    assert!(
        outcomes[2].is_err(),
        "dial 3 should be rejected by the rate-limit gate, got {:?}",
        outcomes[2],
    );
    if let Err(msg) = &outcomes[2] {
        // When we *do* get a status code back, it must be 429.
        if let Some(stripped) = msg.strip_prefix("http ") {
            assert!(
                stripped.starts_with("429"),
                "expected HTTP 429 Too Many Requests for rate-limit rejection, got {msg}",
            );
        }
    }

    net.stop().await;
}

// ---------------------------------------------------------------------------
// Test: tcp_connection_limit_rejects_over_capacity
// ---------------------------------------------------------------------------

/// The TCP-level `RejectingLimitListener` closes connections that would
/// exceed the total (`incoming_connections_limit` + reserved health
/// slots) capacity.
///
/// Sanity check at the **TCP listener** layer — distinct from the
/// axum/handshake layer exercised in the rate-limit test above. We hold
/// N long-lived TCP connections open (each occupying one semaphore
/// permit via the connection guard held in the relay's accept loop),
/// then verify the (N+1)th connection gets promptly closed by the
/// server rather than entering a serve loop.
///
/// Keeping the test *short-and-loud*: we don't attempt to count the
/// reserved-health slots; instead we configure `incoming_connections_
/// limit = 1` (total semaphore capacity becomes 11). We open 11
/// long-lived connections to saturate it, then an additional connection
/// whose read-side should EOF quickly.
#[tokio::test]
async fn tcp_connection_limit_rejects_over_capacity() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    init_tracing();

    let config = WebsocketNetworkConfig {
        genesis_id: "test-v1.0".to_string(),
        network_id: "test".to_string(),
        net_address: Some("127.0.0.1:0".to_string()),
        incoming_connections_limit: 1, // TCP cap: 1 + 10 reserved = 11 permits
        relay_messages: true,
        // Make every *other* gate generous so we isolate Gate 1.
        max_connections_per_ip: 10_000,
        connections_rate_limiting_count: 10_000,
        mesh_interval: Duration::from_secs(3600),
        ..Default::default()
    };
    let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
    let net = Arc::new(WebsocketNetwork::new(config, phonebook));
    net.start_arc().await.expect("relay should start");

    let hp = relay_host_port(&net);

    // Saturate the semaphore: open 11 long-lived plain TCP connections.
    // We deliberately do not send any HTTP bytes — the connection guard
    // is acquired by `RejectingLimitListener::accept` before axum ever
    // sees the socket, so these dangling sockets are enough to drain
    // the permit pool.
    let mut holders: Vec<TcpStream> = Vec::new();
    for _ in 0..11 {
        let s = TcpStream::connect(&hp).await.expect("baseline dial");
        holders.push(s);
    }

    // Give the accept loop a moment to assign permits.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The (11+1)th connection. Expected behaviour: the `RejectingLimit
    // Listener` accepts at the OS level and immediately drops the stream.
    // Our client sees a cleanly-closed peer either via a 0-byte read or
    // an immediate EOF when trying to write + read.
    let mut rejected = TcpStream::connect(&hp)
        .await
        .expect("TCP-level dial itself should succeed");
    // The server-side drop should propagate as EOF on read within a short
    // window. Writing tiny bytes first flushes any lingering state.
    let _ = rejected
        .write_all(b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n")
        .await;

    let mut buf = [0u8; 64];
    let read_result = tokio::time::timeout(Duration::from_secs(2), rejected.read(&mut buf)).await;

    // We expect either an EOF (0 bytes) or a read error within the 2 s
    // window. We do NOT expect a full HTTP response, because the permit
    // was exhausted before axum could serve the request.
    match read_result {
        Ok(Ok(0)) => { /* ok — server closed cleanly */ }
        Ok(Ok(n)) => {
            // If the server *did* respond, the permit must have freed up
            // (one of the holders' sockets closed mid-test, perhaps due
            // to an OS quirk). Accept this only if the response is a
            // 5xx/4xx indicating some rejection — not a 200.
            let body = std::str::from_utf8(&buf[..n]).unwrap_or("");
            assert!(
                !body.starts_with("HTTP/1.1 200") && !body.starts_with("HTTP/1.1 101"),
                "unexpected full success response from saturated listener: {body:?}",
            );
        }
        Ok(Err(_)) => { /* ok — read error after server close */ }
        Err(_) => panic!("read did not complete within 2 s — the server never closed the rejected connection, suggesting the TCP cap is not enforced"),
    }

    // Free a permit: drop one of the holders. A subsequent dial should
    // now make it through the listener gate (proving the semaphore is
    // being released, not just permanently exhausted).
    drop(holders.pop().expect("holder list non-empty"));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut fresh = TcpStream::connect(&hp).await.expect("post-release dial");
    let _ = fresh
        .write_all(b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n")
        .await;
    let mut buf2 = [0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(2), fresh.read(&mut buf2))
        .await
        .expect("post-release read within timeout")
        .expect("post-release read should not error");
    let body = std::str::from_utf8(&buf2[..n]).unwrap_or("");
    assert!(
        body.starts_with("HTTP/1.1 200"),
        "post-release /status should return 200, got: {body:?}",
    );

    // Cleanup.
    drop(holders);
    net.stop().await;
}
