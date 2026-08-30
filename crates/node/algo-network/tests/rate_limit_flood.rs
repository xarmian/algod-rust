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
        // This test dials the relay from 127.0.0.1 specifically to
        // exercise the rate-limit gate — go's real
        // `DisableLocalhostConnectionRateLimit` default (`true`, issue
        // #768) would otherwise exempt every dial here from the rate
        // limiter regardless of `connections_rate_limiting_count`, which
        // is the localhost-*convenience* behavior go intends, not a bug
        // this test should be defeated by.
        disable_localhost_connection_rate_limit: false,
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

    // Because dials are concurrent and `validate_incoming_connection`
    // performs `track_connection` and the rate-limit check in separate
    // critical sections, multiple concurrent dials can legitimately
    // observe the over-limit state at once — so we can't pin down an
    // exact pass/fail split. The deterministic properties we *can*
    // rely on:
    //
    //   * at least 1 dial succeeds (gate lets valid traffic through),
    //   * at least 1 dial is rejected (gate fires when the threshold
    //     is exceeded).
    let ok_count = outcomes.iter().filter(|r| r.is_ok()).count();
    let err_count = outcomes.iter().filter(|r| r.is_err()).count();
    assert!(
        ok_count >= 1,
        "at least one of 3 concurrent dials should succeed (gate shouldn't reject valid traffic). outcomes: {outcomes:?}",
    );
    assert!(
        err_count >= 1,
        "at least one of 3 concurrent dials should be rejected (rate-limit gate should fire). outcomes: {outcomes:?}",
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

    // Open TOTAL_DIALS concurrent TCP connections and immediately send
    // an HTTP `/status` request on each.
    //
    // Classifying by probe-response (rather than by peek-timeout) is
    // important: a `peek` timeout cannot distinguish "accepted by the
    // listener, held open by axum" from "still sitting in the kernel
    // backlog, not yet processed by accept()". Sending a real request
    // forces each connection to one of three terminal observations:
    //
    //   * HTTP/1.x response ...... Accepted (axum served us)
    //   * EOF / read error ....... Rejected (listener dropped the stream)
    //   * no response yet ........ Pending  (stay in the poll loop)
    //
    // Crucially, we do NOT send `Connection: close`: that would let
    // axum finish the response and release its `ConnectionGuard` back
    // to the semaphore, causing the accept loop to then admit the
    // next backlog entry. With HTTP/1.1 keep-alive (the default) each
    // accepted connection holds its permit for the full lifetime of
    // the TCP stream we own — which is what we need to observe
    // saturation.
    const REQ: &[u8] = b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n";
    let mut clients: Vec<TcpStream> = Vec::with_capacity(TOTAL_DIALS);
    for _ in 0..TOTAL_DIALS {
        let mut s = TcpStream::connect(&hp)
            .await
            .expect("TCP-level dial should always succeed (the kernel accepts)");
        let _ = s.write_all(REQ).await;
        clients.push(s);
    }

    // Poll until every dial is either Accepted or Rejected — no
    // Pending entries left. A boolean initialised to `false` would
    // conflate pending/rejected on the first pass and let the settle
    // condition fire before the listener has drained the backlog.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum DialState {
        Pending,
        Accepted,
        Rejected,
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut states: Vec<DialState> = vec![DialState::Pending; TOTAL_DIALS];
    let mut buf = [0u8; 64];
    loop {
        for (i, c) in clients.iter_mut().enumerate() {
            if states[i] != DialState::Pending {
                continue;
            }
            // Non-destructive probe: `peek` returns bytes the client
            // has received on the socket. We look for the HTTP status
            // line, or for a closed socket.
            match tokio::time::timeout(Duration::from_millis(20), c.peek(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => states[i] = DialState::Rejected,
                Ok(Ok(n)) => {
                    let head = std::str::from_utf8(&buf[..n]).unwrap_or("");
                    // HTTP status line starts with "HTTP/1.1 XXX ".
                    // 2xx → axum served the request → Accepted.
                    // anything else (4xx/5xx) also implies the
                    // listener permitted the connection through to
                    // axum — still counts as Accepted at Gate 1.
                    if head.starts_with("HTTP/1.") {
                        states[i] = DialState::Accepted;
                    }
                    // otherwise stay Pending — we may have received
                    // partial bytes that happen not to start with
                    // "HTTP/1.".
                }
                Err(_) => { /* no bytes yet — stay Pending */ }
            }
        }

        let pending = states.iter().filter(|s| **s == DialState::Pending).count();
        let accepted = states.iter().filter(|s| **s == DialState::Accepted).count();
        let rejected = states.iter().filter(|s| **s == DialState::Rejected).count();

        if pending == 0 {
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
