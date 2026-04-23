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

    // Fire all 3 dials concurrently. This is the crucial timing
    // guarantee: because `connections_rate_limiting_window` is fixed at
    // 1 s in `WebsocketNetwork::new`, any approach that serializes the
    // dials is vulnerable to the first timestamp aging out before the
    // third dial reaches `validate_incoming_connection` on a slow CI
    // runner. Running them as futures in `join_all` ensures all three
    // are in-flight (and therefore all three `track_connection`
    // timestamps are inside the same window) by the time the server
    // begins evaluating them.
    //
    // Each dial uses a unique NodeRandom so the handshake passes the
    // self-loop check and actually reaches the rate-limit gate.
    //
    // We disconnect immediately on success so the per-IP connection
    // count drops back — but rate-window timestamps persist, which is
    // exactly the attacker model the rate gate defends against.
    let hp_clone = hp.clone();
    let futures: Vec<_> = (0..3)
        .map(|i| {
            let hp = hp_clone.clone();
            async move {
                let req = gossip_request(&hp, "test-v1.0", &format!("rate-test-{i}"));
                match tokio_tungstenite::connect_async(req).await {
                    Ok((ws, _resp)) => {
                        drop(ws);
                        Ok::<(), String>(())
                    }
                    Err(tungstenite::Error::Http(resp)) => Err(format!("http {}", resp.status())),
                    Err(e) => Err(format!("other: {e}")),
                }
            }
        })
        .collect();

    let outcomes: Vec<Result<(), String>> = futures_util::future::join_all(futures).await;

    // Because dials are concurrent, the order in which the server
    // processes them is nondeterministic. The deterministic property
    // is the *count*: with `connections_rate_limiting_count = 2`,
    // exactly 2 of 3 dials pass the gate and exactly 1 is rejected.
    let ok_count = outcomes.iter().filter(|r| r.is_ok()).count();
    let err_count = outcomes.iter().filter(|r| r.is_err()).count();
    assert_eq!(
        ok_count, 2,
        "expected exactly 2 of 3 concurrent dials to succeed, got {ok_count}. outcomes: {outcomes:?}",
    );
    assert_eq!(
        err_count, 1,
        "expected exactly 1 of 3 concurrent dials to be rejected, got {err_count}. outcomes: {outcomes:?}",
    );

    // When we *do* get a status code back, it must be 429.
    for o in &outcomes {
        if let Err(msg) = o {
            if let Some(stripped) = msg.strip_prefix("http ") {
                assert!(
                    stripped.starts_with("429"),
                    "expected HTTP 429 Too Many Requests for rate-limit rejection, got {msg}",
                );
            }
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
/// axum/handshake layer exercised in the rate-limit test above.
///
/// Approach (avoids wall-clock races): fire `TOTAL_DIALS` concurrent
/// TCP connections (deliberately more than the semaphore cap of
/// `incoming_connections_limit + reserved_health = 11`), wait for the
/// accept loop to drain the backlog, then probe each one with a small
/// `/status` request and classify the response. Because we dial past
/// the cap by a safe margin, at least `TOTAL_DIALS − cap` connections
/// are guaranteed to be closed by the listener — regardless of
/// scheduling jitter. If the cap were not enforced, every connection
/// would return a 200.
#[tokio::test]
async fn tcp_connection_limit_rejects_over_capacity() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    init_tracing();

    // Cap: 1 + 10 reserved = 11 permits.
    const LIMIT: u32 = 1;
    const RESERVED: u32 = 10;
    const CAP: usize = (LIMIT + RESERVED) as usize;
    // Dial well past the cap so rejections are inevitable on any
    // scheduler.
    const TOTAL_DIALS: usize = 25;

    let config = WebsocketNetworkConfig {
        genesis_id: "test-v1.0".to_string(),
        network_id: "test".to_string(),
        net_address: Some("127.0.0.1:0".to_string()),
        incoming_connections_limit: LIMIT,
        relay_messages: true,
        // Make every *other* gate generous so we isolate Gate 1.
        max_connections_per_ip: u32::MAX,
        connections_rate_limiting_count: u32::MAX,
        mesh_interval: Duration::from_secs(3600),
        ..Default::default()
    };
    let phonebook = Arc::new(Phonebook::new(10, Duration::from_secs(60)));
    let net = Arc::new(WebsocketNetwork::new(config, phonebook));
    net.start_arc().await.expect("relay should start");

    let hp = relay_host_port(&net);

    // Open TOTAL_DIALS concurrent TCP connections.
    let mut clients: Vec<TcpStream> = Vec::with_capacity(TOTAL_DIALS);
    for _ in 0..TOTAL_DIALS {
        clients.push(
            TcpStream::connect(&hp)
                .await
                .expect("TCP-level dial should always succeed (the kernel accepts)"),
        );
    }

    // Poll until every dial is either Accepted or Rejected — no
    // Pending entries left. A tri-state is required here: if we used
    // a boolean initialized to `false`, every as-yet-unclassified
    // entry would look like a rejection on the first pass, and the
    // settle condition could fire before the listener has actually
    // drained the backlog.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum DialState {
        Pending,
        Accepted,
        Rejected,
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut states: Vec<DialState> = vec![DialState::Pending; TOTAL_DIALS];
    loop {
        for (i, c) in clients.iter_mut().enumerate() {
            if states[i] != DialState::Pending {
                continue;
            }
            // Non-destructive probe via `peek`. If the server closed the
            // socket we get `Ok(0)` or a read error; otherwise `peek`
            // blocks (the server is holding an accepted connection
            // open, waiting for us to speak HTTP).
            let mut buf = [0u8; 1];
            match tokio::time::timeout(Duration::from_millis(20), c.peek(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => states[i] = DialState::Rejected,
                Err(_) => states[i] = DialState::Accepted, // read timed out → held open
                Ok(Ok(_)) => { /* unexpected data; leave as Pending and retry */ }
            }
        }

        let pending = states.iter().filter(|s| **s == DialState::Pending).count();
        let accepted = states.iter().filter(|s| **s == DialState::Accepted).count();
        let rejected = states.iter().filter(|s| **s == DialState::Rejected).count();

        // Settle condition: no Pending entries AND the rejection count
        // meets the lower bound implied by the cap. Both clauses are
        // needed — `rejected >= TOTAL_DIALS - CAP` alone is
        // vulnerable to a scheduling delay that leaves many entries
        // still Pending on the first pass.
        if pending == 0 && rejected >= TOTAL_DIALS - CAP {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "listener never reached steady state after 5 s \
                 (pending={pending}, accepted={accepted}, rejected={rejected})",
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let accepted_count = states.iter().filter(|s| **s == DialState::Accepted).count();
    let rejected_count = states.iter().filter(|s| **s == DialState::Rejected).count();

    // Cap invariant: at most CAP connections are accepted.
    assert!(
        accepted_count <= CAP,
        "accepted {accepted_count} > cap {CAP} — listener is not enforcing limit",
    );
    // Flood invariant: if we dial past the cap, some are rejected.
    assert!(
        rejected_count >= TOTAL_DIALS - CAP,
        "expected at least {} rejections, got {rejected_count} (accepted: {accepted_count})",
        TOTAL_DIALS - CAP,
    );

    // Sanity: drop every holder and verify the listener resumes
    // serving. If the semaphore were permanently exhausted this would
    // time out.
    drop(clients);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut fresh = TcpStream::connect(&hp)
        .await
        .expect("post-release TCP dial");
    let _ = fresh
        .write_all(b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n")
        .await;
    let mut resp_buf = [0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(2), fresh.read(&mut resp_buf))
        .await
        .expect("post-release read within timeout")
        .expect("post-release read should not error");
    let body = std::str::from_utf8(&resp_buf[..n]).unwrap_or("");
    assert!(
        body.starts_with("HTTP/1.1 200"),
        "post-release /status should return 200, got: {body:?}",
    );

    net.stop().await;
}
