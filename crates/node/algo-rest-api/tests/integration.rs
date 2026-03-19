//! Integration tests for the Algorand REST API.
//!
//! These tests start a real HTTP server on localhost:0 and send requests
//! using `reqwest`, exercising the full request/response pipeline including
//! routing, auth middleware, and handler logic.

use std::net::SocketAddr;
use std::sync::Arc;

use algo_rest_api::auth::generate_token;
use algo_rest_api::node::{BuildVersion, NodeInterface, NodeStatus};
use algo_rest_api::router::{build_router, TokenConfig};
use algo_types::Digest;
use async_trait::async_trait;
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Mock node implementation
// ---------------------------------------------------------------------------

/// A configurable mock implementation of `NodeInterface` for testing.
#[derive(Debug, Clone)]
struct MockNode {
    genesis_id: String,
    genesis_hash: Digest,
    genesis_json: String,
    status: MockStatus,
    suggested_fee: u64,
    min_txn_fee: u64,
    build_version: BuildVersion,
}

/// Controls how `MockNode::status()` behaves.
#[derive(Debug, Clone)]
enum MockStatus {
    /// Return a successful `NodeStatus` with the given values.
    Ok(NodeStatus),
    /// Return an error (simulating a node failure).
    Err(String),
}

impl MockNode {
    /// Create a mock node in a "synced and healthy" state with sensible defaults.
    fn synced() -> Self {
        Self {
            genesis_id: "testnet-v1.0".to_string(),
            genesis_hash: Digest([0xAB; 32]),
            genesis_json: r#"{"network":"testnet"}"#.to_string(),
            status: MockStatus::Ok(NodeStatus {
                last_round: 1000,
                time_since_last_round: 2_000_000_000, // 2 seconds in ns
                catchup_time: 0,
                last_version: "https://github.com/algorandfoundation/specs/tree/abc/v41"
                    .to_string(),
                next_version: "https://github.com/algorandfoundation/specs/tree/abc/v41"
                    .to_string(),
                next_version_round: 1001,
                next_version_supported: true,
                stopped_at_unsupported_round: false,
                catchpoint: String::new(),
                last_catchpoint: String::new(),
            }),
            suggested_fee: 1000,
            min_txn_fee: 1000,
            build_version: BuildVersion {
                major: 0,
                minor: 1,
                build_number: 0,
                commit_hash: "abc123".to_string(),
                branch: "main".to_string(),
                channel: "dev".to_string(),
            },
        }
    }

    /// Return a mock node that is catching up (non-zero catchup_time).
    fn catching_up() -> Self {
        let mut node = Self::synced();
        node.status = MockStatus::Ok(NodeStatus {
            last_round: 500,
            time_since_last_round: 30_000_000_000, // 30 seconds in ns
            catchup_time: 5_000_000_000,           // 5 seconds in ns
            last_version: "v41".to_string(),
            next_version: "v41".to_string(),
            next_version_round: 501,
            next_version_supported: true,
            stopped_at_unsupported_round: false,
            catchpoint: String::new(),
            last_catchpoint: String::new(),
        });
        node
    }

    /// Return a mock node that has stopped at an unsupported round.
    fn stopped_at_unsupported() -> Self {
        let mut node = Self::synced();
        node.status = MockStatus::Ok(NodeStatus {
            last_round: 999,
            time_since_last_round: 1_000_000_000,
            catchup_time: 0,
            last_version: "v40".to_string(),
            next_version: "v41".to_string(),
            next_version_round: 1000,
            next_version_supported: false,
            stopped_at_unsupported_round: true,
            catchpoint: String::new(),
            last_catchpoint: String::new(),
        });
        node
    }

    /// Return a mock node whose `status()` returns an error.
    fn status_error() -> Self {
        let mut node = Self::synced();
        node.status = MockStatus::Err("node database unavailable".to_string());
        node
    }

    /// Return a mock node that is catching up to a catchpoint.
    fn catchpoint_catchup() -> Self {
        let mut node = Self::synced();
        node.status = MockStatus::Ok(NodeStatus {
            last_round: 100,
            time_since_last_round: 1_000_000_000,
            catchup_time: 0,
            last_version: "v41".to_string(),
            next_version: "v41".to_string(),
            next_version_round: 101,
            next_version_supported: true,
            stopped_at_unsupported_round: false,
            catchpoint: "1000#ABCDEF".to_string(),
            last_catchpoint: String::new(),
        });
        node
    }
}

#[async_trait]
impl NodeInterface for MockNode {
    fn genesis_id(&self) -> &str {
        &self.genesis_id
    }

    fn genesis_hash(&self) -> &Digest {
        &self.genesis_hash
    }

    fn genesis_json(&self) -> &str {
        &self.genesis_json
    }

    async fn status(&self) -> Result<NodeStatus, Box<dyn std::error::Error + Send + Sync>> {
        match &self.status {
            MockStatus::Ok(s) => Ok(s.clone()),
            MockStatus::Err(msg) => Err(msg.clone().into()),
        }
    }

    async fn suggested_fee(&self) -> u64 {
        self.suggested_fee
    }

    async fn min_txn_fee(&self) -> u64 {
        self.min_txn_fee
    }

    fn build_version(&self) -> &BuildVersion {
        &self.build_version
    }
}

// ---------------------------------------------------------------------------
// Test helper: start a server and return address + token
// ---------------------------------------------------------------------------

struct TestServer {
    addr: SocketAddr,
    api_token: String,
    admin_token: String,
    client: reqwest::Client,
}

impl TestServer {
    /// Start a test server with the given mock node and return the test context.
    async fn start(node: MockNode) -> Self {
        let api_token = generate_token();
        let admin_token = generate_token();

        let tokens = TokenConfig {
            api_token: api_token.clone(),
            admin_token: admin_token.clone(),
        };

        let router = build_router(Arc::new(node), tokens);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });

        Self {
            addr,
            api_token,
            admin_token,
            client: reqwest::Client::new(),
        }
    }

    /// Build a URL for the given path.
    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

// ===========================================================================
// Health endpoint tests
// ===========================================================================

#[tokio::test]
async fn health_returns_200_with_null_body() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body = resp.text().await.unwrap();
    assert_eq!(body, "null\n");
}

#[tokio::test]
async fn health_works_without_auth_token() {
    let server = TestServer::start(MockNode::synced()).await;

    // No auth header at all -- should still succeed
    let resp = server
        .client
        .get(server.url("/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

// ===========================================================================
// Ready endpoint tests
// ===========================================================================

#[tokio::test]
async fn ready_returns_200_when_synced() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body = resp.text().await.unwrap();
    assert_eq!(body, "null\n");
}

#[tokio::test]
async fn ready_returns_503_when_catching_up() {
    let server = TestServer::start(MockNode::catching_up()).await;

    let resp = server
        .client
        .get(server.url("/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);

    let body = resp.text().await.unwrap();
    assert_eq!(body, "null\n");
}

#[tokio::test]
async fn ready_returns_500_when_status_errors() {
    let server = TestServer::start(MockNode::status_error()).await;

    let resp = server
        .client
        .get(server.url("/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 500);

    let body = resp.text().await.unwrap();
    assert_eq!(body, "null\n");
}

#[tokio::test]
async fn ready_returns_500_when_stopped_at_unsupported_round() {
    let server = TestServer::start(MockNode::stopped_at_unsupported()).await;

    let resp = server
        .client
        .get(server.url("/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 500);

    let body = resp.text().await.unwrap();
    assert_eq!(body, "null\n");
}

// ---------------------------------------------------------------------------
// LOW 7: /ready returns 503 when catchpoint is non-empty
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ready_returns_503_when_catchpoint_catchup() {
    let server = TestServer::start(MockNode::catchpoint_catchup()).await;

    let resp = server
        .client
        .get(server.url("/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);

    let body = resp.text().await.unwrap();
    assert_eq!(body, "null\n");
}

// ===========================================================================
// Versions endpoint tests
// ===========================================================================

#[tokio::test]
async fn versions_returns_200_with_correct_structure() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/versions"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // versions array contains "v2"
    let versions = body["versions"].as_array().unwrap();
    assert!(
        versions.iter().any(|v| v.as_str() == Some("v2")),
        "versions array should contain 'v2'"
    );
}

#[tokio::test]
async fn versions_includes_genesis_and_build_info() {
    let server = TestServer::start(MockNode::synced()).await;

    let body: serde_json::Value = server
        .client
        .get(server.url("/versions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // genesis_id should match mock
    assert_eq!(body["genesis_id"].as_str().unwrap(), "testnet-v1.0");

    // genesis_hash_b64 should be a non-empty base64 string
    let gh = body["genesis_hash_b64"].as_str().unwrap();
    assert!(!gh.is_empty(), "genesis_hash_b64 should be non-empty");

    // build version fields
    let build = &body["build"];
    assert_eq!(build["major"].as_u64().unwrap(), 0);
    assert_eq!(build["minor"].as_u64().unwrap(), 1);
    assert_eq!(build["build_number"].as_u64().unwrap(), 0);
    assert_eq!(build["commit_hash"].as_str().unwrap(), "abc123");
    assert_eq!(build["branch"].as_str().unwrap(), "main");
    assert_eq!(build["channel"].as_str().unwrap(), "dev");
}

// ===========================================================================
// Genesis endpoint tests
// ===========================================================================

#[tokio::test]
async fn genesis_returns_200_with_json_content() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/genesis"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["network"].as_str().unwrap(), "testnet");
}

// ===========================================================================
// Swagger endpoint tests
// ===========================================================================

#[tokio::test]
async fn swagger_json_returns_200_with_json_content() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/swagger.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Should be valid JSON
    let body: serde_json::Value = resp.json().await.unwrap();
    // The swagger spec should have some basic structure
    assert!(body.is_object(), "swagger spec should be a JSON object");
}

// ===========================================================================
// Transaction params endpoint tests
// ===========================================================================

#[tokio::test]
async fn transaction_params_returns_200_with_correct_fields() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/params"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // Field names use hyphens (matching go-algorand JSON tags)
    assert!(
        body.get("consensus-version").is_some(),
        "should have consensus-version field"
    );
    assert!(body.get("fee").is_some(), "should have fee field");
    assert!(
        body.get("genesis-hash").is_some(),
        "should have genesis-hash field"
    );
    assert!(
        body.get("genesis-id").is_some(),
        "should have genesis-id field"
    );
    assert!(
        body.get("last-round").is_some(),
        "should have last-round field"
    );
    assert!(body.get("min-fee").is_some(), "should have min-fee field");
}

#[tokio::test]
async fn transaction_params_field_values_match_node() {
    let server = TestServer::start(MockNode::synced()).await;

    let body: serde_json::Value = server
        .client
        .get(server.url("/v2/transactions/params"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(body["fee"].as_u64().unwrap(), 1000);
    assert_eq!(body["min-fee"].as_u64().unwrap(), 1000);
    assert_eq!(body["last-round"].as_u64().unwrap(), 1000);
    assert_eq!(body["genesis-id"].as_str().unwrap(), "testnet-v1.0");
    assert!(!body["genesis-hash"].as_str().unwrap().is_empty());
    assert!(!body["consensus-version"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn transaction_params_returns_503_when_catchpoint_catchup() {
    let server = TestServer::start(MockNode::catchpoint_catchup()).await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/params"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);
}

#[tokio::test]
async fn transaction_params_returns_500_when_status_errors() {
    let server = TestServer::start(MockNode::status_error()).await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/params"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 500);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["message"].as_str().unwrap(),
        "failed retrieving node status"
    );
}

#[tokio::test]
async fn transaction_params_requires_auth_token() {
    let server = TestServer::start(MockNode::synced()).await;

    // No token
    let resp = server
        .client
        .get(server.url("/v2/transactions/params"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn transaction_params_works_with_x_algo_api_token() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/params"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn transaction_params_works_with_bearer_token() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/params"))
        .header("Authorization", format!("Bearer {}", server.api_token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

// ===========================================================================
// Auth middleware tests
// ===========================================================================

#[tokio::test]
async fn public_routes_work_without_token() {
    let server = TestServer::start(MockNode::synced()).await;

    for path in &[
        "/health",
        "/ready",
        "/versions",
        "/genesis",
        "/swagger.json",
    ] {
        let resp = server.client.get(server.url(path)).send().await.unwrap();
        assert!(
            resp.status().is_success() || resp.status() == 503,
            "public route {path} should not require auth, got {}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn authenticated_route_returns_401_without_token() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/params"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Body should contain the error message
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"].as_str().unwrap(), "Invalid API Token");
}

#[tokio::test]
async fn authenticated_route_returns_401_with_invalid_token() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/params"))
        .header("X-Algo-API-Token", "invalid_token_value")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn authenticated_route_returns_200_with_valid_token() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/params"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn admin_token_does_not_work_on_public_token_routes() {
    let server = TestServer::start(MockNode::synced()).await;

    // The admin token is different from the api_token. The authenticated routes
    // use the api_token specifically, so admin_token should not grant access
    // to standard v2 endpoints (unless they happen to match, which they won't
    // since both are randomly generated).
    let resp = server
        .client
        .get(server.url("/v2/transactions/params"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    // Admin token is not the api token, so it should be rejected
    assert_eq!(resp.status(), 401);
}

// ===========================================================================
// Transaction params always returns JSON (no format negotiation)
// ===========================================================================

#[tokio::test]
async fn transaction_params_always_returns_json() {
    let server = TestServer::start(MockNode::synced()).await;

    // go-algorand's TransactionParams does not support format negotiation.
    // Query params like ?format=json are simply ignored; the response is
    // always JSON.
    let resp = server
        .client
        .get(server.url("/v2/transactions/params?format=json"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(content_type, "application/json");

    // Should parse as valid JSON
    let _body: serde_json::Value = resp.json().await.unwrap();
}
