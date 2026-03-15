//! Shared test helpers for mixed-cluster integration tests.
//!
//! Provides environment detection, address resolution, and service-readiness
//! utilities for tests that run against the Docker mixed-cluster topology
//! defined in `docker/docker-compose.mixed-cluster.yml`.

#![allow(dead_code)]

use std::time::Duration;

// ---------------------------------------------------------------------------
// Environment / cluster detection
// ---------------------------------------------------------------------------

/// Returns `true` if the mixed Docker cluster is believed to be running.
///
/// Checks for the `MIXED_CLUSTER` environment variable first (any non-empty
/// value counts as "yes").  If not set, probes the go-relay gossip port to
/// see if something is listening.
pub async fn is_mixed_cluster_running() -> bool {
    // Fast path: explicit env var.
    if let Ok(val) = std::env::var("MIXED_CLUSTER") {
        if !val.is_empty() && val != "0" {
            return true;
        }
    }

    // Slow path: probe the go-relay gossip port.
    let addr = go_relay_gossip_addr();
    // Strip the ws:// prefix to get host:port for TCP probe.
    let host_port = addr.strip_prefix("ws://").unwrap_or(&addr);
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(host_port),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Address helpers
// ---------------------------------------------------------------------------

/// Go relay gossip WebSocket address (default: `ws://localhost:4161`).
pub fn go_relay_gossip_addr() -> String {
    std::env::var("GO_RELAY_GOSSIP_ADDR").unwrap_or_else(|_| "ws://localhost:4161".to_string())
}

/// Rust relay gossip WebSocket address (default: `ws://localhost:4160`).
pub fn rust_relay_gossip_addr() -> String {
    std::env::var("RUST_RELAY_GOSSIP_ADDR").unwrap_or_else(|_| "ws://localhost:4160".to_string())
}

/// Go relay REST API address (default: `http://localhost:4001`).
pub fn go_relay_rest_addr() -> String {
    std::env::var("GO_RELAY_REST_ADDR").unwrap_or_else(|_| "http://localhost:4001".to_string())
}

/// Go non-relay REST API address (default: `http://localhost:4002`).
pub fn go_nonrelay_rest_addr() -> String {
    std::env::var("GO_NONRELAY_REST_ADDR").unwrap_or_else(|_| "http://localhost:4002".to_string())
}

// ---------------------------------------------------------------------------
// Service readiness
// ---------------------------------------------------------------------------

/// Poll a TCP address until it accepts a connection or the timeout expires.
///
/// `addr` should be a bare `host:port` string (no scheme).
/// Returns `Ok(())` on success, `Err(reason)` on timeout.
pub async fn wait_for_service(addr: &str, timeout: Duration) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr))
            .await
        {
            Ok(Ok(_)) => return Ok(()),
            _ => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!(
                        "service at {addr} not reachable within {}s",
                        timeout.as_secs()
                    ));
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Skip macro
// ---------------------------------------------------------------------------

/// Skip the calling test if the mixed cluster is not running.
///
/// Prints a message and returns early (test passes silently).
#[macro_export]
macro_rules! skip_unless_mixed_cluster {
    () => {
        if !test_helpers::is_mixed_cluster_running().await {
            eprintln!(
                "SKIPPED: mixed cluster not running — start it with:\n  \
                 docker compose -f docker/docker-compose.mixed-cluster.yml up -d"
            );
            return;
        }
    };
}

// ---------------------------------------------------------------------------
// Common constants
// ---------------------------------------------------------------------------

/// The algod API token used by all containers in the mixed cluster.
pub const API_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/// Build an HTTP client with the Algorand API token header.
pub fn algod_client() -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "X-Algo-API-Token",
        reqwest::header::HeaderValue::from_static(API_TOKEN),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(15))
        .build()
        .expect("http client")
}

/// Fetch `/v2/status` from the given REST base URL and return the JSON body.
pub async fn get_status(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<serde_json::Value, String> {
    let url = format!("{base_url}/v2/status");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("GET {url} failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("GET {url} returned {status}"));
    }
    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("parse JSON from {url}: {e}"))
}

/// Extract the `last-round` field from a `/v2/status` response.
pub fn extract_last_round(status: &serde_json::Value) -> Option<u64> {
    status.get("last-round").and_then(|v| v.as_u64())
}

/// Fetch a block by round from the given REST base URL.
pub async fn get_block(
    client: &reqwest::Client,
    base_url: &str,
    round: u64,
) -> Result<serde_json::Value, String> {
    let url = format!("{base_url}/v2/blocks/{round}");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("GET {url} failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("GET {url} returned {status}"));
    }
    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("parse JSON from {url}: {e}"))
}
