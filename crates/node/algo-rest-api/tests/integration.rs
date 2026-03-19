//! Integration tests for the Algorand REST API.
//!
//! These tests start a real HTTP server on localhost:0 and send requests
//! using `reqwest`, exercising the full request/response pipeline including
//! routing, auth middleware, and handler logic.

use std::net::SocketAddr;
use std::sync::Arc;

use algo_rest_api::auth::generate_token;
use algo_rest_api::node::{BuildVersion, NodeInterface, NodeStatus, ProtocolSwitchInfo};
use algo_rest_api::router::{build_router, TokenConfig};
use algo_types::Digest;
use async_trait::async_trait;
use tokio::net::TcpListener;
use tokio::sync::Notify;

// ---------------------------------------------------------------------------
// Mock node implementation
// ---------------------------------------------------------------------------

/// Controls how `MockNode::wait_for_round()` behaves.
#[derive(Debug, Clone)]
enum MockWaitBehavior {
    /// Return immediately (round already available).
    Immediate,
    /// Wait on a `Notify` (caller signals when ready; used for timeout tests).
    WaitForever,
    /// Return an error immediately.
    Error(String),
}

/// Controls how `MockNode::latest_block_header_protocol_info()` behaves.
#[derive(Debug, Clone)]
enum MockProtocolInfoBehavior {
    /// Return the configured `ProtocolSwitchInfo`.
    Ok,
    /// Return an error.
    Err(String),
}

/// A configurable mock implementation of `NodeInterface` for testing.
#[derive(Debug)]
struct MockNode {
    genesis_id: String,
    genesis_hash: Digest,
    genesis_json: String,
    status: MockStatus,
    suggested_fee: u64,
    min_txn_fee: u64,
    build_version: BuildVersion,
    upgrade_vote_rounds: u64,
    upgrade_threshold: u64,
    wait_behavior: MockWaitBehavior,
    /// Notify used when `wait_behavior` is `WaitForever`.
    wait_notify: Arc<Notify>,
    protocol_switch_info: ProtocolSwitchInfo,
    protocol_info_behavior: MockProtocolInfoBehavior,
}

impl Clone for MockNode {
    fn clone(&self) -> Self {
        Self {
            genesis_id: self.genesis_id.clone(),
            genesis_hash: self.genesis_hash,
            genesis_json: self.genesis_json.clone(),
            status: self.status.clone(),
            suggested_fee: self.suggested_fee,
            min_txn_fee: self.min_txn_fee,
            build_version: self.build_version.clone(),
            upgrade_vote_rounds: self.upgrade_vote_rounds,
            upgrade_threshold: self.upgrade_threshold,
            wait_behavior: self.wait_behavior.clone(),
            wait_notify: Arc::clone(&self.wait_notify),
            protocol_switch_info: self.protocol_switch_info.clone(),
            protocol_info_behavior: self.protocol_info_behavior.clone(),
        }
    }
}

/// Controls how `MockNode::status()` behaves.
#[derive(Debug, Clone)]
enum MockStatus {
    /// Return a successful `NodeStatus` with the given values.
    Ok(Box<NodeStatus>),
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
            status: MockStatus::Ok(Box::new(NodeStatus {
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
                catchpoint_total_accounts: 0,
                catchpoint_processed_accounts: 0,
                catchpoint_verified_accounts: 0,
                catchpoint_total_kvs: 0,
                catchpoint_processed_kvs: 0,
                catchpoint_verified_kvs: 0,
                catchpoint_total_blocks: 0,
                catchpoint_acquired_blocks: 0,
                next_protocol_vote_before: 0,
                next_protocol_approvals: 0,
                upgrade_approve: false,
                upgrade_delay: 0,
                upgrade_propose: String::new(),
            })),
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
            upgrade_vote_rounds: 10000,
            upgrade_threshold: 9000,
            wait_behavior: MockWaitBehavior::Immediate,
            wait_notify: Arc::new(Notify::new()),
            protocol_switch_info: ProtocolSwitchInfo {
                next_protocol: String::new(),
                next_protocol_supported: true,
                next_protocol_switch_on: 0,
            },
            protocol_info_behavior: MockProtocolInfoBehavior::Ok,
        }
    }

    /// Return a mock node that is catching up (non-zero catchup_time).
    fn catching_up() -> Self {
        let mut node = Self::synced();
        node.status = MockStatus::Ok(Box::new(NodeStatus {
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
            catchpoint_total_accounts: 0,
            catchpoint_processed_accounts: 0,
            catchpoint_verified_accounts: 0,
            catchpoint_total_kvs: 0,
            catchpoint_processed_kvs: 0,
            catchpoint_verified_kvs: 0,
            catchpoint_total_blocks: 0,
            catchpoint_acquired_blocks: 0,
            next_protocol_vote_before: 0,
            next_protocol_approvals: 0,
            upgrade_approve: false,
            upgrade_delay: 0,
            upgrade_propose: String::new(),
        }));
        node
    }

    /// Return a mock node that has stopped at an unsupported round.
    fn stopped_at_unsupported() -> Self {
        let mut node = Self::synced();
        node.status = MockStatus::Ok(Box::new(NodeStatus {
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
            catchpoint_total_accounts: 0,
            catchpoint_processed_accounts: 0,
            catchpoint_verified_accounts: 0,
            catchpoint_total_kvs: 0,
            catchpoint_processed_kvs: 0,
            catchpoint_verified_kvs: 0,
            catchpoint_total_blocks: 0,
            catchpoint_acquired_blocks: 0,
            next_protocol_vote_before: 0,
            next_protocol_approvals: 0,
            upgrade_approve: false,
            upgrade_delay: 0,
            upgrade_propose: String::new(),
        }));
        node
    }

    /// Return a mock node that is in the middle of an upgrade vote.
    fn upgrading() -> Self {
        let mut node = Self::synced();
        node.status = MockStatus::Ok(Box::new(NodeStatus {
            last_round: 5000,
            time_since_last_round: 3_000_000_000, // 3 seconds in ns
            catchup_time: 0,
            last_version: "v41".to_string(),
            next_version: "v42".to_string(),
            next_version_round: 15000,
            next_version_supported: true,
            stopped_at_unsupported_round: false,
            catchpoint: String::new(),
            last_catchpoint: "4000#DEADBEEF".to_string(),
            catchpoint_total_accounts: 0,
            catchpoint_processed_accounts: 0,
            catchpoint_verified_accounts: 0,
            catchpoint_total_kvs: 0,
            catchpoint_processed_kvs: 0,
            catchpoint_verified_kvs: 0,
            catchpoint_total_blocks: 0,
            catchpoint_acquired_blocks: 0,
            next_protocol_vote_before: 10000,
            next_protocol_approvals: 3500,
            upgrade_approve: true,
            upgrade_delay: 100,
            upgrade_propose: "v42".to_string(),
        }));
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
        node.status = MockStatus::Ok(Box::new(NodeStatus {
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
            catchpoint_total_accounts: 5000,
            catchpoint_processed_accounts: 2500,
            catchpoint_verified_accounts: 2000,
            catchpoint_total_kvs: 1000,
            catchpoint_processed_kvs: 500,
            catchpoint_verified_kvs: 400,
            catchpoint_total_blocks: 100,
            catchpoint_acquired_blocks: 50,
            next_protocol_vote_before: 0,
            next_protocol_approvals: 0,
            upgrade_approve: false,
            upgrade_delay: 0,
            upgrade_propose: String::new(),
        }));
        node
    }

    /// Return a mock node with an upcoming unsupported protocol switch.
    ///
    /// The switch happens at round 1005, and the next protocol is not supported.
    fn unsupported_protocol_switch() -> Self {
        let mut node = Self::synced();
        node.protocol_switch_info = ProtocolSwitchInfo {
            next_protocol: "future-v99".to_string(),
            next_protocol_supported: false,
            next_protocol_switch_on: 1005,
        };
        node
    }

    /// Return a mock node whose `wait_for_round` blocks forever
    /// (until the notify is signalled).
    fn wait_forever() -> Self {
        let mut node = Self::synced();
        node.wait_behavior = MockWaitBehavior::WaitForever;
        node
    }

    /// Return a mock node whose `latest_block_header_protocol_info()` returns an error.
    fn protocol_info_error() -> Self {
        let mut node = Self::synced();
        node.protocol_info_behavior =
            MockProtocolInfoBehavior::Err("ledger unavailable".to_string());
        node
    }

    /// Return a mock node whose `wait_for_round()` returns an error.
    fn wait_error() -> Self {
        let mut node = Self::synced();
        node.wait_behavior = MockWaitBehavior::Error("ledger read failed".to_string());
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
            MockStatus::Ok(s) => Ok(*s.clone()),
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

    fn upgrade_vote_rounds(&self) -> u64 {
        self.upgrade_vote_rounds
    }

    fn upgrade_threshold(&self) -> u64 {
        self.upgrade_threshold
    }

    async fn wait_for_round(
        &self,
        _round: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match &self.wait_behavior {
            MockWaitBehavior::Immediate => Ok(()),
            MockWaitBehavior::WaitForever => {
                self.wait_notify.notified().await;
                Ok(())
            }
            MockWaitBehavior::Error(msg) => Err(msg.clone().into()),
        }
    }

    async fn latest_block_header_protocol_info(
        &self,
    ) -> Result<ProtocolSwitchInfo, Box<dyn std::error::Error + Send + Sync>> {
        match &self.protocol_info_behavior {
            MockProtocolInfoBehavior::Ok => Ok(self.protocol_switch_info.clone()),
            MockProtocolInfoBehavior::Err(msg) => Err(msg.clone().into()),
        }
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

// ===========================================================================
// Status endpoint tests
// ===========================================================================

#[tokio::test]
async fn status_returns_200_with_correct_fields() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/status"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // Always-present fields
    assert_eq!(body["last-round"].as_u64().unwrap(), 1000);
    assert_eq!(
        body["time-since-last-round"].as_i64().unwrap(),
        2_000_000_000
    );
    assert_eq!(body["catchup-time"].as_i64().unwrap(), 0);
    assert_eq!(
        body["last-version"].as_str().unwrap(),
        "https://github.com/algorandfoundation/specs/tree/abc/v41"
    );
    assert_eq!(
        body["next-version"].as_str().unwrap(),
        "https://github.com/algorandfoundation/specs/tree/abc/v41"
    );
    assert_eq!(body["next-version-round"].as_u64().unwrap(), 1001);
    assert!(body["next-version-supported"].as_bool().unwrap());
    assert!(!body["stopped-at-unsupported-round"].as_bool().unwrap());

    // Catchpoint string fields (always present even when empty)
    assert!(
        body.get("catchpoint").is_some(),
        "should have catchpoint field"
    );
    assert!(
        body.get("last-catchpoint").is_some(),
        "should have last-catchpoint field"
    );
}

#[tokio::test]
async fn status_returns_correct_catchpoint_fields() {
    let server = TestServer::start(MockNode::catchpoint_catchup()).await;

    let resp = server
        .client
        .get(server.url("/v2/status"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // All catchpoint fields should be present with their mock values
    assert_eq!(body["catchpoint-total-accounts"].as_u64().unwrap(), 5000);
    assert_eq!(
        body["catchpoint-processed-accounts"].as_u64().unwrap(),
        2500
    );
    assert_eq!(body["catchpoint-verified-accounts"].as_u64().unwrap(), 2000);
    assert_eq!(body["catchpoint-total-kvs"].as_u64().unwrap(), 1000);
    assert_eq!(body["catchpoint-processed-kvs"].as_u64().unwrap(), 500);
    assert_eq!(body["catchpoint-verified-kvs"].as_u64().unwrap(), 400);
    assert_eq!(body["catchpoint-total-blocks"].as_u64().unwrap(), 100);
    assert_eq!(body["catchpoint-acquired-blocks"].as_u64().unwrap(), 50);

    // Catchpoint fields should also be present when zero (synced node)
    let server2 = TestServer::start(MockNode::synced()).await;
    let body2: serde_json::Value = server2
        .client
        .get(server2.url("/v2/status"))
        .header("X-Algo-API-Token", &server2.api_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Even when zero, these fields should be present (matching go-algorand)
    assert!(
        body2.get("catchpoint-total-accounts").is_some(),
        "catchpoint-total-accounts should be present even when zero"
    );
    assert_eq!(body2["catchpoint-total-accounts"].as_u64().unwrap(), 0);
}

#[tokio::test]
async fn status_omits_upgrade_fields_when_no_upgrade() {
    let server = TestServer::start(MockNode::synced()).await;

    let body: serde_json::Value = server
        .client
        .get(server.url("/v2/status"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // When next_protocol_vote_before == 0, all upgrade-* fields should be absent
    assert!(
        body.get("upgrade-delay").is_none(),
        "upgrade-delay should be absent when no upgrade"
    );
    assert!(
        body.get("upgrade-next-protocol-vote-before").is_none(),
        "upgrade-next-protocol-vote-before should be absent when no upgrade"
    );
    assert!(
        body.get("upgrade-no-votes").is_none(),
        "upgrade-no-votes should be absent when no upgrade"
    );
    assert!(
        body.get("upgrade-node-vote").is_none(),
        "upgrade-node-vote should be absent when no upgrade"
    );
    assert!(
        body.get("upgrade-vote-rounds").is_none(),
        "upgrade-vote-rounds should be absent when no upgrade"
    );
    assert!(
        body.get("upgrade-votes").is_none(),
        "upgrade-votes should be absent when no upgrade"
    );
    assert!(
        body.get("upgrade-votes-required").is_none(),
        "upgrade-votes-required should be absent when no upgrade"
    );
    assert!(
        body.get("upgrade-yes-votes").is_none(),
        "upgrade-yes-votes should be absent when no upgrade"
    );
    assert!(
        body.get("upgrade-propose").is_none(),
        "upgrade-propose should be absent when no upgrade"
    );
}

#[tokio::test]
async fn status_includes_upgrade_fields_during_upgrade() {
    let server = TestServer::start(MockNode::upgrading()).await;

    let body: serde_json::Value = server
        .client
        .get(server.url("/v2/status"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // With next_protocol_vote_before = 10000 and last_round = 5000:
    // votes_to_go = 10000 - 5000 - 1 = 4999
    // votes = upgrade_vote_rounds - votes_to_go = 10000 - 4999 = 5001
    // votes_yes = next_protocol_approvals = 3500
    // votes_no = votes - votes_yes = 5001 - 3500 = 1501
    assert_eq!(
        body["upgrade-votes-required"].as_u64().unwrap(),
        9000,
        "upgrade-votes-required should be upgrade_threshold"
    );
    assert_eq!(
        body["upgrade-vote-rounds"].as_u64().unwrap(),
        10000,
        "upgrade-vote-rounds should be upgrade_vote_rounds"
    );
    assert!(
        body["upgrade-node-vote"].as_bool().unwrap(),
        "upgrade-node-vote should match upgrade_approve"
    );
    assert_eq!(
        body["upgrade-delay"].as_u64().unwrap(),
        100,
        "upgrade-delay should match upgrade_delay"
    );
    assert_eq!(
        body["upgrade-votes"].as_u64().unwrap(),
        5001,
        "upgrade-votes should be total votes cast"
    );
    assert_eq!(
        body["upgrade-yes-votes"].as_u64().unwrap(),
        3500,
        "upgrade-yes-votes should be next_protocol_approvals"
    );
    assert_eq!(
        body["upgrade-no-votes"].as_u64().unwrap(),
        1501,
        "upgrade-no-votes should be votes - yes_votes"
    );
    assert_eq!(
        body["upgrade-next-protocol-vote-before"].as_u64().unwrap(),
        10000,
        "upgrade-next-protocol-vote-before should be set"
    );
    assert_eq!(
        body["upgrade-propose"].as_str().unwrap(),
        "v42",
        "upgrade-propose should be the proposed protocol version"
    );
}

#[tokio::test]
async fn status_requires_auth_token() {
    let server = TestServer::start(MockNode::synced()).await;

    // No token
    let resp = server
        .client
        .get(server.url("/v2/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn status_returns_500_on_error() {
    let server = TestServer::start(MockNode::status_error()).await;

    let resp = server
        .client
        .get(server.url("/v2/status"))
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

// ===========================================================================
// Wait-for-block-after endpoint tests
// ===========================================================================

#[tokio::test]
async fn wait_for_block_returns_200_immediately_when_round_passed() {
    let server = TestServer::start(MockNode::synced()).await;

    // last_round is 1000, so requesting wait after round 999 should return immediately
    let resp = server
        .client
        .get(server.url("/v2/status/wait-for-block-after/999"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["last-round"].as_u64().unwrap(), 1000);
    // Verify it has the full NodeStatusResponse structure
    assert!(body.get("last-version").is_some());
    assert!(body.get("next-version").is_some());
    assert!(body.get("catchup-time").is_some());
}

#[tokio::test]
async fn wait_for_block_returns_200_on_timeout() {
    // Use a wait_forever mock so the wait never completes.
    // The handler will time out after WAIT_FOR_BLOCK_TIMEOUT and still return 200.
    // We use tokio::time::pause to avoid actually waiting 60s.
    tokio::time::pause();

    let node = MockNode::wait_forever();
    let server = TestServer::start(node).await;

    // Spawn the request in a task
    let client = server.client.clone();
    let url = server.url("/v2/status/wait-for-block-after/9999");
    let token = server.api_token.clone();

    let handle = tokio::spawn(async move {
        client
            .get(url)
            .header("X-Algo-API-Token", token)
            .send()
            .await
            .unwrap()
    });

    // Advance time past the 60s timeout
    tokio::time::advance(std::time::Duration::from_secs(61)).await;

    let resp = handle.await.unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    // Should still return a valid NodeStatusResponse
    assert_eq!(body["last-round"].as_u64().unwrap(), 1000);
}

#[tokio::test]
async fn wait_for_block_returns_400_when_stopped_at_unsupported() {
    let server = TestServer::start(MockNode::stopped_at_unsupported()).await;

    let resp = server
        .client
        .get(server.url("/v2/status/wait-for-block-after/1000"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["message"].as_str().unwrap(),
        "requested round would reach only after the protocol upgrade which isn't supported"
    );
}

#[tokio::test]
async fn wait_for_block_returns_503_during_catchup() {
    let server = TestServer::start(MockNode::catchpoint_catchup()).await;

    let resp = server
        .client
        .get(server.url("/v2/status/wait-for-block-after/500"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["message"].as_str().unwrap(),
        "operation not available during catchup"
    );
}

#[tokio::test]
async fn wait_for_block_returns_400_for_unsupported_protocol_switch() {
    let server = TestServer::start(MockNode::unsupported_protocol_switch()).await;

    // protocol_switch_on is 1005; requesting round 1004 means we wait for
    // round 1005, which is >= next_protocol_switch_on (1005), so 400.
    let resp = server
        .client
        .get(server.url("/v2/status/wait-for-block-after/1004"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["message"].as_str().unwrap(),
        "requested round would reach only after the protocol upgrade which isn't supported"
    );
}

#[tokio::test]
async fn wait_for_block_allows_round_before_unsupported_protocol_switch() {
    let server = TestServer::start(MockNode::unsupported_protocol_switch()).await;

    // protocol_switch_on is 1005; requesting round 1003 means we wait for
    // round 1004, which is < next_protocol_switch_on (1005), so 200.
    let resp = server
        .client
        .get(server.url("/v2/status/wait-for-block-after/1003"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn wait_for_block_requires_auth_token() {
    let server = TestServer::start(MockNode::synced()).await;

    // No token
    let resp = server
        .client
        .get(server.url("/v2/status/wait-for-block-after/999"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn wait_for_block_returns_500_when_status_errors() {
    let server = TestServer::start(MockNode::status_error()).await;

    let resp = server
        .client
        .get(server.url("/v2/status/wait-for-block-after/100"))
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
async fn wait_for_block_returns_200_when_round_notified() {
    let node = MockNode::wait_forever();
    let notify = Arc::clone(&node.wait_notify);
    let server = TestServer::start(node).await;

    let client = server.client.clone();
    let url = server.url("/v2/status/wait-for-block-after/9999");
    let token = server.api_token.clone();

    // Spawn the request in a task
    let handle = tokio::spawn(async move {
        client
            .get(url)
            .header("X-Algo-API-Token", token)
            .send()
            .await
            .unwrap()
    });

    // Give the handler time to start waiting, then signal the notify
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    notify.notify_one();

    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
        .await
        .expect("handler should return promptly after notify")
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["last-round"].as_u64().unwrap(), 1000);
}

#[tokio::test]
async fn wait_for_block_returns_500_when_protocol_info_errors() {
    let server = TestServer::start(MockNode::protocol_info_error()).await;

    let resp = server
        .client
        .get(server.url("/v2/status/wait-for-block-after/100"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 500);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["message"].as_str().unwrap(),
        "failed retrieving latest block header"
    );
}

#[tokio::test]
async fn wait_for_block_returns_500_when_wait_for_round_errors() {
    let server = TestServer::start(MockNode::wait_error()).await;

    let resp = server
        .client
        .get(server.url("/v2/status/wait-for-block-after/100"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 500);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("waiting for round failed"),
        "expected error message about wait failure, got: {}",
        body["message"]
    );
}

#[tokio::test]
async fn wait_for_block_returns_400_on_round_overflow() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/status/wait-for-block-after/{}", u64::MAX)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"].as_str().unwrap(), "round overflow");
}
