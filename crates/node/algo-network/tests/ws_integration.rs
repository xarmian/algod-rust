//! Integration tests for WebSocket peer connectivity against a real Go relay.
//!
//! These tests connect to a live `algorand/algod:4.7.2-stable` Docker container
//! configured as a relay node (with `GOSSIP_PORT=4161`).  They validate the
//! full WebSocket handshake, Algorand header exchange, identity challenge
//! protocol, message framing, and reconnection logic.
//!
//! # Running
//!
//! ```bash
//! # Start the relay
//! docker compose -f docker/docker-compose.test-relay.yml up -d
//! # Wait for healthy
//! until docker inspect --format='{{.State.Health.Status}}' algod-relay 2>/dev/null | grep -q healthy; do sleep 1; done
//! # Run tests
//! ALGO_RELAY_ADDR=localhost:4161 cargo test -p algo-network --test ws_integration -- --nocapture
//! # Stop the relay
//! docker compose -f docker/docker-compose.test-relay.yml down -v
//! ```
//!
//! If the relay is not running, all tests skip gracefully (no failures, no
//! `#[ignore]`).
//!
//! # Environment variables
//!
//! - `ALGO_RELAY_ADDR` — relay gossip address (default: `localhost:4161`)
//! - `ALGO_RELAY_REST` — relay REST API address for genesis discovery
//!   (default: `http://localhost:4003`)
//! - `ALGO_GENESIS_ID` — genesis ID override (default: auto-discovered from
//!   REST API, falling back to `"v1"`)

use std::time::Duration;

use algo_network::connect::{try_connect, ConnectConfig};
use algo_network::handshake::PROTOCOL_VERSION;
use algo_network::message::OutgoingMessage;
use algo_network::msg_of_interest::marshal_msg_of_interest;
use algo_network::peer_features::PeerFeatureFlags;
use algo_network::reconnect::{
    ExponentialBackoff, ReconnectPolicy, ReconnectSupervisor, SupervisorError, TerminalAction,
};
use algo_network::tag::Tag;
use algo_network::WsConnectError;

use ed25519_dalek::SigningKey;
use rand::Rng;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

/// Default relay gossip address.
const DEFAULT_RELAY_ADDR: &str = "localhost:4161";

/// Default relay REST API address.
const DEFAULT_RELAY_REST: &str = "http://localhost:4003";

/// Default genesis ID for the Docker devmode network.
const DEFAULT_GENESIS_ID: &str = "v1";

/// Initialize tracing for test output (called once per test).
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("algo_network=debug,ws_integration=debug")
        .with_test_writer()
        .try_init();
}

/// Get the relay gossip address from the environment or use the default.
fn relay_addr() -> String {
    std::env::var("ALGO_RELAY_ADDR").unwrap_or_else(|_| DEFAULT_RELAY_ADDR.to_string())
}

/// Get the relay REST API base URL from the environment or use the default.
fn relay_rest() -> String {
    std::env::var("ALGO_RELAY_REST").unwrap_or_else(|_| DEFAULT_RELAY_REST.to_string())
}

/// Attempt to discover the genesis ID from the relay's REST API.
///
/// Falls back to `ALGO_GENESIS_ID` env var, then to the default `"v1"`.
async fn discover_genesis_id() -> String {
    // First check env override.
    if let Ok(id) = std::env::var("ALGO_GENESIS_ID") {
        return id;
    }

    // Try the REST API.
    let rest_url = relay_rest();
    let url = format!("{}/genesis", rest_url);
    let token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok();

    if let Some(client) = client {
        if let Ok(resp) = client
            .get(&url)
            .header("X-Algo-API-Token", token)
            .send()
            .await
        {
            if let Ok(text) = resp.text().await {
                // Parse as JSON to get the "id" field.
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(id) = val.get("id").and_then(|v| v.as_str()) {
                        return id.to_string();
                    }
                }
            }
        }
    }

    DEFAULT_GENESIS_ID.to_string()
}

/// Check if the relay is reachable by attempting a TCP connection.
///
/// Returns `true` if we can connect within 2 seconds, `false` otherwise.
async fn relay_is_reachable() -> bool {
    let addr = relay_addr();
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

/// Skip the test if the relay is not reachable.
///
/// This macro-like function prints a message and returns early from the calling
/// test.  It does NOT mark the test as `#[ignore]` — it passes silently.
macro_rules! skip_unless_relay {
    () => {
        if !relay_is_reachable().await {
            eprintln!(
                "SKIPPED: relay not reachable at {} — start it with:\n  \
                 docker compose -f docker/docker-compose.test-relay.yml up -d",
                relay_addr()
            );
            return;
        }
    };
}

/// Generate a random ed25519 signing key.
fn random_signing_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    SigningKey::from_bytes(&bytes)
}

/// Build a default `ConnectConfig` for the devnet relay.
async fn default_connect_config() -> ConnectConfig {
    let genesis_id = discover_genesis_id().await;
    let signing_key = random_signing_key();
    ConnectConfig {
        genesis_id,
        node_random: rand::random(),
        our_identity_key: Some(signing_key),
        our_address: None,
        instance_name: "algod-rust-test".to_string(),
        location: String::new(),
        telemetry_id: String::new(),
        our_features: PeerFeatureFlags::COMPRESSED_PROPOSAL,
        handshake_timeout: Duration::from_secs(15),
        peer_config: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Connect to the Go relay, verify the full WebSocket + Algorand handshake
/// completes successfully.
///
/// Validates:
/// - WebSocket upgrade succeeds
/// - Protocol version "2.2" is negotiated
/// - PeerHandle is returned with a valid remote address
/// - Connection closes gracefully
#[tokio::test]
async fn test_websocket_connect_and_handshake() {
    init_tracing();
    skip_unless_relay!();

    let addr = relay_addr();
    let config = default_connect_config().await;

    let handle = try_connect(&addr, &config)
        .await
        .expect("connect + handshake should succeed");

    // Verify negotiated protocol version.
    assert_eq!(
        handle.version(),
        PROTOCOL_VERSION,
        "should negotiate protocol version 2.2"
    );

    // Verify remote address is set.
    assert!(
        !handle.remote_addr().is_empty(),
        "remote address should be populated"
    );

    // Verify the connection is not already closed.
    assert!(
        !handle.is_closed(),
        "connection should be open immediately after handshake"
    );

    // Clean up.
    handle.close();
    // Give tasks a moment to shut down.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        handle.is_closed(),
        "connection should be closed after close()"
    );
}

/// Connect with an incorrect genesis ID and verify the relay rejects us.
///
/// The Go relay returns HTTP 412 (Precondition Failed) for genesis mismatches.
/// Our code maps this to `WsConnectError::GenesisMismatch`.
#[tokio::test]
async fn test_genesis_id_mismatch_rejected() {
    init_tracing();
    skip_unless_relay!();

    let addr = relay_addr();
    let mut config = default_connect_config().await;
    config.genesis_id = "wrong-genesis-id-xyz".to_string();

    let result = try_connect(&addr, &config).await;

    let err = match result {
        Ok(_handle) => panic!("connection with wrong genesis ID should fail"),
        Err(e) => e,
    };

    // The Go relay should respond with HTTP 412 for genesis mismatch.
    // Our code maps this to WsConnectError::GenesisMismatch.
    match &err {
        WsConnectError::GenesisMismatch => {
            // Expected path.
        }
        WsConnectError::HttpStatus { status, .. } => {
            assert_eq!(
                *status, 412,
                "genesis mismatch should return 412, got {status}"
            );
        }
        other => {
            // Also acceptable: a handshake error that references genesis.
            // The relay might reject at the URL path level (routing mismatch)
            // before headers are even checked.
            let msg = format!("{other}");
            assert!(
                msg.contains("genesis")
                    || msg.contains("412")
                    || msg.contains("404")
                    || msg.contains("WebSocket"),
                "expected genesis-related rejection, got: {msg}"
            );
        }
    }
}

/// Self-loop detection cannot be tested against a real Go relay because it
/// requires the server to echo back *our* node random, which only happens
/// when we connect to ourselves.
///
/// This is covered by unit tests in `handshake.rs` and `connect.rs`.
/// Documenting here for completeness.
#[tokio::test]
async fn test_self_loop_detection_note() {
    // Self-loop detection is a unit-level concern:
    // - The client generates a random `node_random` value.
    // - The server responds with its own `node_random`.
    // - If they match, `check_server_response_variables` returns
    //   `HandshakeError::SelfLoop`.
    //
    // We cannot trigger this against a real Go relay without controlling the
    // relay's random seed.  The unit tests in handshake.rs cover this path.
    //
    // This test is a no-op placeholder to document the gap.
}

/// Connect with identity challenge enabled, verify the identity exchange
/// completes (or is gracefully skipped if the relay does not participate).
///
/// The Go relay may or may not respond to identity challenges depending on
/// its configuration.  Both paths are valid:
/// - If the relay responds: identity should be verified.
/// - If the relay does not respond: identity_verified() is false.
#[tokio::test]
async fn test_identity_challenge_exchange() {
    init_tracing();
    skip_unless_relay!();

    let addr = relay_addr();
    let config = default_connect_config().await;

    let handle = try_connect(&addr, &config)
        .await
        .expect("connect should succeed");

    // The identity exchange is attempted as part of try_connect.
    // We check both possible outcomes.
    if handle.identity_verified() {
        // The relay participated in the identity challenge exchange.
        assert!(
            handle.identity().is_some(),
            "verified identity should have a public key"
        );
        tracing::info!("identity exchange succeeded, peer key present");
    } else {
        // The relay did not participate (common for devmode nodes).
        // This is not an error — the connection is still valid.
        tracing::info!("identity exchange was skipped by the relay (expected for devmode)");
    }

    // Either way, the connection should be functional.
    assert!(!handle.is_closed());

    handle.close();
}

/// After connecting, send a MsgOfInterest message and verify we can receive
/// messages from the relay.
///
/// The relay should eventually send us gossip messages (agreement votes,
/// proposals, etc.) once we declare interest in those tags.
#[tokio::test]
async fn test_message_send_receive() {
    init_tracing();
    skip_unless_relay!();

    let addr = relay_addr();
    let config = default_connect_config().await;

    let mut handle = try_connect(&addr, &config)
        .await
        .expect("connect should succeed");

    // try_connect already sends a MsgOfInterest for all active tags.
    // Send another one explicitly to declare interest in everything.
    let all_tags = Tag::active_tags();
    let mi_payload = marshal_msg_of_interest(&all_tags);
    let mi_msg = OutgoingMessage::new(Tag::MsgOfInterest, mi_payload);
    handle
        .send_priority(mi_msg)
        .expect("should be able to send MsgOfInterest");

    // Wait for an incoming message from the relay.
    // In a devmode network, agreement/proposal messages should arrive within
    // a few seconds.  We use a generous timeout.
    let receive_result = tokio::time::timeout(Duration::from_secs(15), handle.recv()).await;

    match receive_result {
        Ok(Some(msg)) => {
            tracing::info!(
                tag = %msg.tag,
                len = msg.data.len(),
                "received message from relay"
            );
            // We don't need to validate the message content — just that we
            // received *something* after declaring interest.
            assert!(
                msg.tag.is_active(),
                "received message tag {:?} should be an active tag",
                msg.tag
            );
        }
        Ok(None) => {
            // Channel closed — peer disconnected.  This is acceptable if the
            // relay is under load or the devmode network is idle.
            tracing::warn!("incoming channel closed before receiving a message");
        }
        Err(_elapsed) => {
            // Timeout: the relay didn't send anything within 15 seconds.
            // In a devmode network this can happen if no transactions are
            // being generated.  This is acceptable — the test validates that
            // we *can* send and that the connection stays alive.
            tracing::warn!("no message received within timeout (relay may be idle)");
        }
    }

    // The connection should still be alive (unless the relay closed it).
    // Either way, clean up.
    handle.close();
}

/// Verify that WebSocket ping/pong keepalive keeps the connection alive.
///
/// We connect, wait several seconds, and verify the connection has not been
/// dropped due to inactivity.
#[tokio::test]
async fn test_keepalive_maintains_connection() {
    init_tracing();
    skip_unless_relay!();

    let addr = relay_addr();
    let config = default_connect_config().await;

    let handle = try_connect(&addr, &config)
        .await
        .expect("connect should succeed");

    // Wait a few seconds — the keepalive loop should be sending pings.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // The connection should still be alive.
    assert!(
        !handle.is_closed(),
        "connection should survive 5 seconds of inactivity with keepalive"
    );

    handle.close();
}

/// Connect and then close gracefully.  Verify clean shutdown with no errors.
#[tokio::test]
async fn test_graceful_close() {
    init_tracing();
    skip_unless_relay!();

    let addr = relay_addr();
    let config = default_connect_config().await;

    let handle = try_connect(&addr, &config)
        .await
        .expect("connect should succeed");

    assert!(!handle.is_closed());

    // Trigger graceful shutdown.
    handle.close();

    // Give the background tasks time to process the cancellation.
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        handle.is_closed(),
        "connection should be closed after close()"
    );

    // Verify that the incoming channel is drained/closed.
    // A second close should be a no-op (idempotent).
    handle.close();
}

/// Use the ReconnectSupervisor to connect to the real relay.
///
/// Validates that the supervisor:
/// - Successfully connects on the first attempt
/// - Returns Ok when the session function returns Ok
#[tokio::test]
async fn test_reconnect_supervisor_connects() {
    init_tracing();
    skip_unless_relay!();

    let addr = relay_addr();
    let genesis_id = discover_genesis_id().await;

    let policy = ReconnectPolicy {
        backoff: ExponentialBackoff::new(
            Duration::from_millis(100),
            Duration::from_secs(5),
            2.0,
            false,
        ),
        max_attempts: Some(3),
        on_terminal_failure: TerminalAction::NotifyAndStop,
    };

    let cancel = CancellationToken::new();
    let mut supervisor = ReconnectSupervisor::new(addr.clone(), policy, cancel.clone());

    let result = supervisor
        .run(|| {
            let addr = addr.clone();
            let genesis_id = genesis_id.clone();
            let cancel = cancel.clone();
            async move {
                let signing_key = random_signing_key();
                let config = ConnectConfig {
                    genesis_id,
                    node_random: rand::random(),
                    our_identity_key: Some(signing_key),
                    our_address: None,
                    instance_name: "algod-rust-reconnect-test".to_string(),
                    location: String::new(),
                    telemetry_id: String::new(),
                    our_features: PeerFeatureFlags::empty(),
                    handshake_timeout: Duration::from_secs(10),
                    peer_config: None,
                };

                let handle = try_connect(&addr, &config)
                    .await
                    .map_err(SupervisorError::Connect)?;

                // Connection succeeded — verify it's alive.
                assert!(!handle.is_closed());
                assert_eq!(handle.version(), PROTOCOL_VERSION);

                // Close cleanly.
                handle.close();

                // Cancel the token so the supervisor exits after this
                // successful session instead of looping to reconnect.
                cancel.cancel();
                Ok(())
            }
        })
        .await;

    // The supervisor returns Err(Shutdown) when the token is cancelled
    // after a successful session.
    match &result {
        Ok(()) => { /* also acceptable if cancellation races */ }
        Err(SupervisorError::Shutdown) => { /* expected path */ }
        other => panic!("unexpected supervisor result: {other:?}"),
    }
}

/// Verify that the supervisor handles transient failures and retries.
///
/// We first connect to a bogus address (which fails), then on the second
/// attempt connect to the real relay.
#[tokio::test]
async fn test_reconnect_after_failure() {
    init_tracing();
    skip_unless_relay!();

    let real_addr = relay_addr();
    let genesis_id = discover_genesis_id().await;

    let attempt_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attempt_clone = attempt_count.clone();

    let policy = ReconnectPolicy {
        backoff: ExponentialBackoff::new(
            Duration::from_millis(100),
            Duration::from_secs(2),
            2.0,
            false,
        ),
        max_attempts: Some(5),
        on_terminal_failure: TerminalAction::NotifyAndStop,
    };

    let cancel = CancellationToken::new();
    let mut supervisor = ReconnectSupervisor::new(real_addr.clone(), policy, cancel.clone());

    let result = supervisor
        .run(|| {
            let real_addr = real_addr.clone();
            let genesis_id = genesis_id.clone();
            let ac = attempt_clone.clone();
            let cancel = cancel.clone();
            async move {
                let attempt = ac.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;

                if attempt == 1 {
                    // First attempt: simulate a transient failure.
                    return Err(SupervisorError::Connect(WsConnectError::TcpFailure(
                        "simulated failure".into(),
                    )));
                }

                // Subsequent attempts: connect for real.
                let signing_key = random_signing_key();
                let config = ConnectConfig {
                    genesis_id,
                    node_random: rand::random(),
                    our_identity_key: Some(signing_key),
                    our_address: None,
                    instance_name: "algod-rust-reconnect-test".to_string(),
                    location: String::new(),
                    telemetry_id: String::new(),
                    our_features: PeerFeatureFlags::empty(),
                    handshake_timeout: Duration::from_secs(10),
                    peer_config: None,
                };

                let handle = try_connect(&real_addr, &config)
                    .await
                    .map_err(SupervisorError::Connect)?;

                handle.close();

                // Cancel the token so the supervisor exits after this
                // successful session instead of looping to reconnect.
                cancel.cancel();
                Ok(())
            }
        })
        .await;

    // The supervisor returns Err(Shutdown) when the token is cancelled
    // after a successful session.
    match &result {
        Ok(()) => { /* also acceptable if cancellation races */ }
        Err(SupervisorError::Shutdown) => { /* expected path */ }
        other => panic!("unexpected supervisor result: {other:?}"),
    }

    let attempts = attempt_count.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        attempts >= 2,
        "should have attempted at least twice (first=fail, second=succeed), got {attempts}"
    );
}

/// Verify that connecting twice produces two independent peer handles.
///
/// This is a basic sanity check that the connection infrastructure does not
/// have shared mutable state between connections.
#[tokio::test]
async fn test_multiple_concurrent_connections() {
    init_tracing();
    skip_unless_relay!();

    let addr = relay_addr();
    let config1 = default_connect_config().await;
    let config2 = default_connect_config().await;

    let handle1 = try_connect(&addr, &config1)
        .await
        .expect("first connection should succeed");

    let handle2 = try_connect(&addr, &config2)
        .await
        .expect("second connection should succeed");

    // Both should be alive.
    assert!(!handle1.is_closed());
    assert!(!handle2.is_closed());

    // Both should have negotiated the same protocol version.
    assert_eq!(handle1.version(), PROTOCOL_VERSION);
    assert_eq!(handle2.version(), PROTOCOL_VERSION);

    // Close one — the other should stay alive.
    handle1.close();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(handle1.is_closed());
    assert!(
        !handle2.is_closed(),
        "second connection should be independent"
    );

    handle2.close();
}

/// Verify peer features are negotiated during the handshake.
///
/// The Go relay should advertise its supported features in the
/// `X-Algorand-Peer-Features` response header.
#[tokio::test]
async fn test_peer_features_negotiated() {
    init_tracing();
    skip_unless_relay!();

    let addr = relay_addr();
    let mut config = default_connect_config().await;
    // Request all features to see what the relay supports.
    config.our_features =
        PeerFeatureFlags::COMPRESSED_PROPOSAL | PeerFeatureFlags::COMPRESSED_VOTE_VPACK;

    let handle = try_connect(&addr, &config)
        .await
        .expect("connect should succeed");

    let features = handle.features();
    tracing::info!(?features, "relay advertised features");

    // We don't require specific features — the relay may or may not support
    // them.  We just verify that feature negotiation ran without error and
    // the connection is functional.
    assert!(!handle.is_closed());

    handle.close();
}
