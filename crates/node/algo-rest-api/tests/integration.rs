//! Integration tests for the Algorand REST API.
//!
//! These tests start a real HTTP server on localhost:0 and send requests
//! using `reqwest`, exercising the full request/response pipeline including
//! routing, auth middleware, and handler logic.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use algo_rest_api::auth::generate_token;
use algo_rest_api::node::{
    AccountLookup, AppResourceLookup, ApplicationLookup, AssetLookup, AssetResourceLookup,
    BuildVersion, NodeInterface, NodeStatus, ProtocolSwitchInfo,
};
use algo_rest_api::router::{build_router, TokenConfig};
use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParams, ConsensusParams,
    Digest, StateSchema,
};
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
#[allow(clippy::type_complexity)]
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
    /// Account lookup result. Keyed by address bytes for per-address control.
    account_lookup: Option<AccountLookup>,
    /// Asset resource lookup results, keyed by (address, asset_id).
    asset_resource_lookups: BTreeMap<([u8; 32], u64), AssetResourceLookup>,
    /// App resource lookup results, keyed by (address, app_id).
    app_resource_lookups: BTreeMap<([u8; 32], u64), AppResourceLookup>,
    /// Consensus params to return.
    consensus_params: ConsensusParams,
    /// Max API resources per account.
    max_api_resources: u64,
    /// Application lookup results, keyed by app_id.
    application_lookups: BTreeMap<u64, ApplicationLookup>,
    /// Asset lookup results, keyed by asset_id.
    asset_lookups: BTreeMap<u64, AssetLookup>,
    /// KV lookup results, keyed by (app_id, key).
    kv_lookups: BTreeMap<(u64, Vec<u8>), (Option<Vec<u8>>, u64)>,
    /// Keys-by-prefix results, keyed by app_id.
    keys_by_prefix: BTreeMap<u64, (Vec<Vec<u8>>, u64)>,
    /// Total boxes count results, keyed by app_id. Returns (total_boxes, round).
    total_boxes_map: BTreeMap<u64, (u64, u64)>,
    /// Max API boxes per application.
    max_api_boxes: u64,
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
            account_lookup: self.account_lookup.clone(),
            asset_resource_lookups: self.asset_resource_lookups.clone(),
            app_resource_lookups: self.app_resource_lookups.clone(),
            consensus_params: self.consensus_params.clone(),
            max_api_resources: self.max_api_resources,
            application_lookups: self.application_lookups.clone(),
            asset_lookups: self.asset_lookups.clone(),
            kv_lookups: self.kv_lookups.clone(),
            keys_by_prefix: self.keys_by_prefix.clone(),
            total_boxes_map: self.total_boxes_map.clone(),
            max_api_boxes: self.max_api_boxes,
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
            account_lookup: None,
            asset_resource_lookups: BTreeMap::new(),
            app_resource_lookups: BTreeMap::new(),
            consensus_params: ConsensusParams::default(),
            max_api_resources: 100_000,
            application_lookups: BTreeMap::new(),
            asset_lookups: BTreeMap::new(),
            kv_lookups: BTreeMap::new(),
            keys_by_prefix: BTreeMap::new(),
            total_boxes_map: BTreeMap::new(),
            max_api_boxes: 100_000,
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

    async fn lookup_account(
        &self,
        _addr: &Address,
    ) -> Result<AccountLookup, Box<dyn std::error::Error + Send + Sync>> {
        match &self.account_lookup {
            Some(lookup) => Ok(lookup.clone()),
            None => {
                // Return zeroed account (matching go-algorand: non-existent accounts
                // return zero values, not an error).
                Ok(AccountLookup {
                    account_data: AccountData::default(),
                    last_round: 1000,
                    amount_without_pending_rewards: 0,
                    assets: BTreeMap::new(),
                    created_assets: BTreeMap::new(),
                    app_local_states: BTreeMap::new(),
                    created_apps: BTreeMap::new(),
                })
            }
        }
    }

    async fn lookup_asset_resource(
        &self,
        addr: &Address,
        asset_id: u64,
    ) -> Result<AssetResourceLookup, Box<dyn std::error::Error + Send + Sync>> {
        let key = (addr.0, asset_id);
        match self.asset_resource_lookups.get(&key) {
            Some(lookup) => Ok(lookup.clone()),
            None => Ok(AssetResourceLookup {
                asset_holding: None,
                asset_params: None,
                last_round: 1000,
            }),
        }
    }

    async fn lookup_app_resource(
        &self,
        addr: &Address,
        app_id: u64,
    ) -> Result<AppResourceLookup, Box<dyn std::error::Error + Send + Sync>> {
        let key = (addr.0, app_id);
        match self.app_resource_lookups.get(&key) {
            Some(lookup) => Ok(lookup.clone()),
            None => Ok(AppResourceLookup {
                app_local_state: None,
                app_params: None,
                last_round: 1000,
            }),
        }
    }

    async fn consensus_params(
        &self,
    ) -> Result<ConsensusParams, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.consensus_params.clone())
    }

    fn max_api_resources_per_account(&self) -> u64 {
        self.max_api_resources
    }

    async fn lookup_application(
        &self,
        app_id: u64,
    ) -> Result<ApplicationLookup, Box<dyn std::error::Error + Send + Sync>> {
        match self.application_lookups.get(&app_id) {
            Some(lookup) => Ok(lookup.clone()),
            None => Ok(ApplicationLookup {
                app_params: None,
                creator: Address([0u8; 32]),
                last_round: 1000,
            }),
        }
    }

    async fn lookup_asset_by_id(
        &self,
        asset_id: u64,
    ) -> Result<AssetLookup, Box<dyn std::error::Error + Send + Sync>> {
        match self.asset_lookups.get(&asset_id) {
            Some(lookup) => Ok(lookup.clone()),
            None => Ok(AssetLookup {
                asset_params: None,
                creator: Address([0u8; 32]),
                last_round: 1000,
            }),
        }
    }

    async fn lookup_kv(
        &self,
        app_id: u64,
        key: &[u8],
    ) -> Result<(Option<Vec<u8>>, u64), Box<dyn std::error::Error + Send + Sync>> {
        match self.kv_lookups.get(&(app_id, key.to_vec())) {
            Some(result) => Ok(result.clone()),
            None => Ok((None, 1000)),
        }
    }

    async fn lookup_keys_by_prefix(
        &self,
        app_id: u64,
        _prefix: &[u8],
    ) -> Result<(Vec<Vec<u8>>, u64), Box<dyn std::error::Error + Send + Sync>> {
        match self.keys_by_prefix.get(&app_id) {
            Some(result) => Ok(result.clone()),
            None => Ok((vec![], 1000)),
        }
    }

    async fn total_boxes(
        &self,
        app_id: u64,
    ) -> Result<(u64, u64), Box<dyn std::error::Error + Send + Sync>> {
        match self.total_boxes_map.get(&app_id) {
            Some(result) => Ok(*result),
            None => Ok((0, 1000)),
        }
    }

    fn max_api_box_per_application(&self) -> u64 {
        self.max_api_boxes
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

// ===========================================================================
// Account information endpoint tests (GET /v2/accounts/:address)
// ===========================================================================

/// Helper: a valid Algorand address string for use in tests.
/// This is the zero address (all zeros + valid checksum).
const TEST_ADDR: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ";

/// Helper: create a MockNode with a configured account lookup.
fn mock_node_with_account(lookup: AccountLookup) -> MockNode {
    let mut node = MockNode::synced();
    node.account_lookup = Some(lookup);
    node
}

/// Helper: create a MockNode with an asset resource lookup for (addr, asset_id).
fn mock_node_with_asset_resource(
    addr: &Address,
    asset_id: u64,
    lookup: AssetResourceLookup,
) -> MockNode {
    let mut node = MockNode::synced();
    node.asset_resource_lookups
        .insert((addr.0, asset_id), lookup);
    node
}

/// Helper: create a MockNode with an app resource lookup for (addr, app_id).
fn mock_node_with_app_resource(addr: &Address, app_id: u64, lookup: AppResourceLookup) -> MockNode {
    let mut node = MockNode::synced();
    node.app_resource_lookups.insert((addr.0, app_id), lookup);
    node
}

#[tokio::test]
async fn account_info_returns_200_with_correct_fields() {
    let lookup = AccountLookup {
        account_data: AccountData {
            micro_algos: 5_000_000,
            rewards_base: 100,
            rewarded_micro_algos: 500,
            status: algo_types::AccountStatus::Online,
            total_assets_opted_in: 2,
            total_created_assets: 1,
            total_apps_opted_in: 1,
            total_created_apps: 0,
            ..AccountData::default()
        },
        last_round: 1000,
        amount_without_pending_rewards: 4_999_500,
        assets: BTreeMap::new(),
        created_assets: BTreeMap::new(),
        app_local_states: BTreeMap::new(),
        created_apps: BTreeMap::new(),
    };
    let server = TestServer::start(mock_node_with_account(lookup)).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // Verify key fields
    assert_eq!(body["address"].as_str().unwrap(), TEST_ADDR);
    assert_eq!(body["amount"].as_u64().unwrap(), 5_000_000);
    assert_eq!(
        body["amount-without-pending-rewards"].as_u64().unwrap(),
        4_999_500
    );
    assert_eq!(body["pending-rewards"].as_u64().unwrap(), 500);
    assert_eq!(body["rewards"].as_u64().unwrap(), 500);
    assert_eq!(body["status"].as_str().unwrap(), "Online");
    assert_eq!(body["round"].as_u64().unwrap(), 1000);
    assert_eq!(body["total-assets-opted-in"].as_u64().unwrap(), 2);
    assert_eq!(body["total-created-assets"].as_u64().unwrap(), 1);
    assert_eq!(body["total-apps-opted-in"].as_u64().unwrap(), 1);
    assert_eq!(body["total-created-apps"].as_u64().unwrap(), 0);
    // min-balance should be present
    assert!(
        body.get("min-balance").is_some(),
        "should have min-balance field"
    );
}

#[tokio::test]
async fn account_info_nonexistent_account_returns_200_with_zeros() {
    // MockNode with no account_lookup configured returns zeroed AccountData
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    // Non-existent accounts return 200 with zero values, NOT 404
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["amount"].as_u64().unwrap(), 0);
    assert_eq!(body["status"].as_str().unwrap(), "Offline");
    assert_eq!(body["round"].as_u64().unwrap(), 1000);
}

#[tokio::test]
async fn account_info_exclude_all_omits_resource_lists() {
    let lookup = AccountLookup {
        account_data: AccountData {
            micro_algos: 1_000_000,
            total_assets_opted_in: 1,
            total_created_assets: 1,
            total_apps_opted_in: 1,
            total_created_apps: 1,
            ..AccountData::default()
        },
        last_round: 1000,
        amount_without_pending_rewards: 1_000_000,
        assets: BTreeMap::new(),
        created_assets: BTreeMap::new(),
        app_local_states: BTreeMap::new(),
        created_apps: BTreeMap::new(),
    };
    let server = TestServer::start(mock_node_with_account(lookup)).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}?exclude=all", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // Resource lists should be absent with exclude=all
    assert!(
        body.get("assets").is_none(),
        "assets should be absent with exclude=all"
    );
    assert!(
        body.get("created-assets").is_none(),
        "created-assets should be absent with exclude=all"
    );
    assert!(
        body.get("apps-local-state").is_none(),
        "apps-local-state should be absent with exclude=all"
    );
    assert!(
        body.get("created-apps").is_none(),
        "created-apps should be absent with exclude=all"
    );

    // But counts should still be present
    assert_eq!(body["total-assets-opted-in"].as_u64().unwrap(), 1);
    assert_eq!(body["total-created-assets"].as_u64().unwrap(), 1);
    assert_eq!(body["total-apps-opted-in"].as_u64().unwrap(), 1);
    assert_eq!(body["total-created-apps"].as_u64().unwrap(), 1);
}

#[tokio::test]
async fn account_info_exclude_none_returns_full_info() {
    let lookup = AccountLookup {
        account_data: AccountData {
            micro_algos: 1_000_000,
            ..AccountData::default()
        },
        last_round: 1000,
        amount_without_pending_rewards: 1_000_000,
        assets: BTreeMap::new(),
        created_assets: BTreeMap::new(),
        app_local_states: BTreeMap::new(),
        created_apps: BTreeMap::new(),
    };
    let server = TestServer::start(mock_node_with_account(lookup)).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}?exclude=none", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // Resource lists should be present (as empty arrays) with exclude=none
    assert!(
        body.get("assets").is_some(),
        "assets should be present with exclude=none"
    );
    assert!(
        body.get("created-assets").is_some(),
        "created-assets should be present with exclude=none"
    );
    assert!(
        body.get("apps-local-state").is_some(),
        "apps-local-state should be present with exclude=none"
    );
    assert!(
        body.get("created-apps").is_some(),
        "created-apps should be present with exclude=none"
    );
}

#[tokio::test]
async fn account_info_invalid_exclude_returns_400() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}?exclude=invalid", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"].as_str().unwrap(), "failed to parse exclude");
}

#[tokio::test]
async fn account_info_invalid_address_returns_400() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/accounts/not-a-valid-address"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["message"].as_str().unwrap(),
        "failed to parse the address"
    );
}

#[tokio::test]
async fn account_info_msgpack_format_returns_msgpack_content_type() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}?format=msgpack", TEST_ADDR)))
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
    assert_eq!(content_type, "application/msgpack");
}

#[tokio::test]
async fn account_info_requires_auth_token() {
    let server = TestServer::start(MockNode::synced()).await;

    // No token
    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}", TEST_ADDR)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ===========================================================================
// Account asset information endpoint tests
// (GET /v2/accounts/:address/assets/:asset-id)
// ===========================================================================

#[tokio::test]
async fn account_asset_info_returns_200_with_valid_holding() {
    let addr: Address = TEST_ADDR.parse().unwrap();
    let lookup = AssetResourceLookup {
        asset_holding: Some(AssetHolding {
            amount: 1000,
            frozen: false,
        }),
        asset_params: None,
        last_round: 1000,
    };
    let server = TestServer::start(mock_node_with_asset_resource(&addr, 42, lookup)).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}/assets/42", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["round"].as_u64().unwrap(), 1000);

    // asset-holding should be present
    let holding = &body["asset-holding"];
    assert_eq!(holding["amount"].as_u64().unwrap(), 1000);
    assert_eq!(holding["asset-id"].as_u64().unwrap(), 42);
    assert!(!holding["is-frozen"].as_bool().unwrap());
}

#[tokio::test]
async fn account_asset_info_returns_404_when_not_found() {
    // No asset resource configured for the (address, asset_id) pair
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}/assets/999", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["message"].as_str().unwrap(),
        "account asset info not found"
    );
}

#[tokio::test]
async fn account_asset_info_invalid_address_returns_400() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/accounts/not-valid/assets/42"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["message"].as_str().unwrap(),
        "failed to parse the address"
    );
}

// ===========================================================================
// Account application information endpoint tests
// (GET /v2/accounts/:address/applications/:application-id)
// ===========================================================================

#[tokio::test]
async fn account_app_info_returns_200_with_valid_local_state() {
    let addr: Address = TEST_ADDR.parse().unwrap();
    let lookup = AppResourceLookup {
        app_local_state: Some(AppLocalState {
            schema: StateSchema {
                num_uint: 2,
                num_byte_slice: 1,
            },
            key_value: BTreeMap::new(),
        }),
        app_params: None,
        last_round: 1000,
    };
    let server = TestServer::start(mock_node_with_app_resource(&addr, 100, lookup)).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}/applications/100", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["round"].as_u64().unwrap(), 1000);

    // app-local-state should be present
    let local_state = &body["app-local-state"];
    assert_eq!(local_state["id"].as_u64().unwrap(), 100);
    assert_eq!(local_state["schema"]["num-uint"].as_u64().unwrap(), 2);
    assert_eq!(local_state["schema"]["num-byte-slice"].as_u64().unwrap(), 1);
}

#[tokio::test]
async fn account_app_info_returns_404_when_not_found() {
    // No app resource configured for the (address, app_id) pair
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}/applications/999", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["message"].as_str().unwrap(),
        "account application info not found"
    );
}

#[tokio::test]
async fn account_app_info_invalid_address_returns_400() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/accounts/not-valid/applications/100"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["message"].as_str().unwrap(),
        "failed to parse the address"
    );
}

// ===========================================================================
// Account information: resource data population tests (FIX 1 / FIX 10)
// ===========================================================================

#[tokio::test]
async fn account_info_returns_populated_asset_holdings() {
    let mut assets = BTreeMap::new();
    assets.insert(
        42,
        AssetHolding {
            amount: 1000,
            frozen: false,
        },
    );
    assets.insert(
        99,
        AssetHolding {
            amount: 500,
            frozen: true,
        },
    );

    let lookup = AccountLookup {
        account_data: AccountData {
            micro_algos: 2_000_000,
            total_assets_opted_in: 2,
            ..AccountData::default()
        },
        last_round: 1000,
        amount_without_pending_rewards: 2_000_000,
        assets,
        created_assets: BTreeMap::new(),
        app_local_states: BTreeMap::new(),
        created_apps: BTreeMap::new(),
    };
    let server = TestServer::start(mock_node_with_account(lookup)).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let assets_arr = body["assets"].as_array().unwrap();
    assert_eq!(assets_arr.len(), 2);

    // Should be sorted by asset-id
    assert_eq!(assets_arr[0]["asset-id"].as_u64().unwrap(), 42);
    assert_eq!(assets_arr[0]["amount"].as_u64().unwrap(), 1000);
    assert!(!assets_arr[0]["is-frozen"].as_bool().unwrap());
    assert_eq!(assets_arr[1]["asset-id"].as_u64().unwrap(), 99);
    assert_eq!(assets_arr[1]["amount"].as_u64().unwrap(), 500);
    assert!(assets_arr[1]["is-frozen"].as_bool().unwrap());
}

#[tokio::test]
async fn account_info_returns_populated_created_assets() {
    let mut created_assets = BTreeMap::new();
    created_assets.insert(
        10,
        AssetParams {
            total: 1_000_000,
            decimals: 6,
            asset_name: "TestCoin".to_string(),
            unit_name: "TC".to_string(),
            ..AssetParams::default()
        },
    );

    let lookup = AccountLookup {
        account_data: AccountData {
            micro_algos: 1_000_000,
            total_created_assets: 1,
            ..AccountData::default()
        },
        last_round: 1000,
        amount_without_pending_rewards: 1_000_000,
        assets: BTreeMap::new(),
        created_assets,
        app_local_states: BTreeMap::new(),
        created_apps: BTreeMap::new(),
    };
    let server = TestServer::start(mock_node_with_account(lookup)).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let created = body["created-assets"].as_array().unwrap();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0]["index"].as_u64().unwrap(), 10);
    assert_eq!(created[0]["params"]["total"].as_u64().unwrap(), 1_000_000);
    assert_eq!(created[0]["params"]["decimals"].as_u64().unwrap(), 6);
    assert_eq!(created[0]["params"]["name"].as_str().unwrap(), "TestCoin");
    assert_eq!(created[0]["params"]["unit-name"].as_str().unwrap(), "TC");
}

#[tokio::test]
async fn account_info_returns_populated_app_local_states() {
    let mut app_local_states = BTreeMap::new();
    app_local_states.insert(
        100,
        AppLocalState {
            schema: StateSchema {
                num_uint: 3,
                num_byte_slice: 1,
            },
            key_value: BTreeMap::new(),
        },
    );

    let lookup = AccountLookup {
        account_data: AccountData {
            micro_algos: 1_000_000,
            total_apps_opted_in: 1,
            ..AccountData::default()
        },
        last_round: 1000,
        amount_without_pending_rewards: 1_000_000,
        assets: BTreeMap::new(),
        created_assets: BTreeMap::new(),
        app_local_states,
        created_apps: BTreeMap::new(),
    };
    let server = TestServer::start(mock_node_with_account(lookup)).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let local_states = body["apps-local-state"].as_array().unwrap();
    assert_eq!(local_states.len(), 1);
    assert_eq!(local_states[0]["id"].as_u64().unwrap(), 100);
    assert_eq!(local_states[0]["schema"]["num-uint"].as_u64().unwrap(), 3);
    assert_eq!(
        local_states[0]["schema"]["num-byte-slice"]
            .as_u64()
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn account_info_returns_populated_created_apps() {
    let mut created_apps = BTreeMap::new();
    created_apps.insert(
        200,
        AppParams {
            creator: Address([0u8; 32]),
            approval_program: vec![0x06, 0x81, 0x01],
            clear_state_program: vec![0x06, 0x81, 0x01],
            global_state: BTreeMap::new(),
            local_state_schema: StateSchema {
                num_uint: 0,
                num_byte_slice: 0,
            },
            global_state_schema: StateSchema {
                num_uint: 1,
                num_byte_slice: 0,
            },
            extra_program_pages: 0,
        },
    );

    let lookup = AccountLookup {
        account_data: AccountData {
            micro_algos: 1_000_000,
            total_created_apps: 1,
            ..AccountData::default()
        },
        last_round: 1000,
        amount_without_pending_rewards: 1_000_000,
        assets: BTreeMap::new(),
        created_assets: BTreeMap::new(),
        app_local_states: BTreeMap::new(),
        created_apps,
    };
    let server = TestServer::start(mock_node_with_account(lookup)).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let apps = body["created-apps"].as_array().unwrap();
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0]["id"].as_u64().unwrap(), 200);
    assert!(
        apps[0]["params"]["approval-program"].is_string(),
        "approval-program should be base64 string"
    );
}

// ===========================================================================
// Resource limit exceeded test (FIX 4 / FIX 10)
// ===========================================================================

#[tokio::test]
async fn account_info_resource_limit_exceeded_returns_400_with_data() {
    let mut node = MockNode::synced();
    // Set a low resource limit
    node.max_api_resources = 5;
    // Configure an account that exceeds the limit
    node.account_lookup = Some(AccountLookup {
        account_data: AccountData {
            micro_algos: 1_000_000,
            total_assets_opted_in: 3,
            total_created_assets: 2,
            total_apps_opted_in: 2,
            total_created_apps: 1,
            ..AccountData::default()
        },
        last_round: 1000,
        amount_without_pending_rewards: 1_000_000,
        assets: BTreeMap::new(),
        created_assets: BTreeMap::new(),
        app_local_states: BTreeMap::new(),
        created_apps: BTreeMap::new(),
    });

    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"].as_str().unwrap(), "Result limit exceeded");

    // Verify data field is present with the right keys
    let data = body["data"].as_object().expect("data should be an object");
    assert_eq!(data["max-results"].as_u64().unwrap(), 5);
    assert_eq!(data["total-assets-opted-in"].as_u64().unwrap(), 3);
    assert_eq!(data["total-created-assets"].as_u64().unwrap(), 2);
    assert_eq!(data["total-apps-opted-in"].as_u64().unwrap(), 2);
    assert_eq!(data["total-created-apps"].as_u64().unwrap(), 1);
}

// ===========================================================================
// Min-balance specific value test (FIX 10)
// ===========================================================================

#[tokio::test]
async fn account_info_min_balance_has_expected_value() {
    let mut node = MockNode::synced();
    // Set consensus params with known values
    node.consensus_params = ConsensusParams {
        min_balance: 100_000,
        app_flat_params_min_balance: 100_000,
        app_flat_opt_in_min_balance: 100_000,
        schema_min_balance_per_entry: 25_000,
        schema_uint_min_balance: 3_500,
        schema_bytes_min_balance: 25_000,
        box_flat_min_balance: 2_500,
        box_byte_min_balance: 400,
        ..ConsensusParams::default()
    };
    node.account_lookup = Some(AccountLookup {
        account_data: AccountData {
            micro_algos: 10_000_000,
            total_assets_opted_in: 2,
            total_created_assets: 0,
            total_apps_opted_in: 1,
            total_created_apps: 0,
            total_app_schema: StateSchema {
                num_uint: 2,
                num_byte_slice: 1,
            },
            ..AccountData::default()
        },
        last_round: 1000,
        amount_without_pending_rewards: 10_000_000,
        assets: BTreeMap::new(),
        created_assets: BTreeMap::new(),
        app_local_states: BTreeMap::new(),
        created_apps: BTreeMap::new(),
    });

    let server = TestServer::start(node).await;

    let body: serde_json::Value = server
        .client
        .get(server.url(&format!("/v2/accounts/{}", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Expected min balance:
    // base: 100_000
    // + 2 assets * 100_000 = 200_000
    // + 0 created apps * 100_000 = 0
    // + 1 opted-in app * 100_000 = 100_000
    // + schema: 3 entries * 25_000 = 75_000
    //         + 2 uints * 3_500 = 7_000
    //         + 1 bytes * 25_000 = 25_000
    // + 0 extra pages * 100_000 = 0
    // + 0 boxes * 2_500 = 0
    // + 0 box bytes * 400 = 0
    // Total: 100_000 + 200_000 + 0 + 100_000 + 75_000 + 7_000 + 25_000 = 507_000
    assert_eq!(body["min-balance"].as_u64().unwrap(), 507_000);
}

// ===========================================================================
// FIX 6: Min-balance with created assets should not double-count
// ===========================================================================

#[tokio::test]
async fn account_info_min_balance_does_not_double_count_created_assets() {
    let mut node = MockNode::synced();
    node.consensus_params = ConsensusParams {
        min_balance: 100_000,
        app_flat_params_min_balance: 100_000,
        app_flat_opt_in_min_balance: 100_000,
        schema_min_balance_per_entry: 25_000,
        schema_uint_min_balance: 3_500,
        schema_bytes_min_balance: 25_000,
        box_flat_min_balance: 2_500,
        box_byte_min_balance: 400,
        ..ConsensusParams::default()
    };
    // Account with 3 asset holdings, 2 of which are created assets.
    // In go-algorand, TotalAssets (= total_assets_opted_in) already includes
    // created assets, so min-balance should only count holdings once.
    node.account_lookup = Some(AccountLookup {
        account_data: AccountData {
            micro_algos: 10_000_000,
            total_assets_opted_in: 3,
            total_created_assets: 2,
            total_apps_opted_in: 0,
            total_created_apps: 0,
            ..AccountData::default()
        },
        last_round: 1000,
        amount_without_pending_rewards: 10_000_000,
        assets: BTreeMap::new(),
        created_assets: BTreeMap::new(),
        app_local_states: BTreeMap::new(),
        created_apps: BTreeMap::new(),
    });

    let server = TestServer::start(node).await;

    let body: serde_json::Value = server
        .client
        .get(server.url(&format!("/v2/accounts/{}", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Expected min balance:
    // base: 100_000
    // + 3 asset holdings * 100_000 = 300_000  (NOT + 2 * 100_000 extra for created)
    // Total: 100_000 + 300_000 = 400_000
    assert_eq!(
        body["min-balance"].as_u64().unwrap(),
        400_000,
        "min-balance should not double-count created assets; \
         expected base (100k) + 3 holdings (300k) = 400k"
    );
}

// ===========================================================================
// FIX 7: Participation key serialization test
// ===========================================================================

#[tokio::test]
async fn account_info_includes_participation_keys() {
    let mut vote_id = [0u8; 32];
    vote_id[0] = 0xAA;
    vote_id[31] = 0xBB;

    let mut selection_id = [0u8; 32];
    selection_id[0] = 0xCC;

    let mut state_proof_id = [0u8; 64];
    state_proof_id[0] = 0xDD;

    let lookup = AccountLookup {
        account_data: AccountData {
            micro_algos: 5_000_000,
            status: algo_types::AccountStatus::Online,
            vote_id: Some(vote_id),
            selection_id: Some(selection_id),
            state_proof_id: Some(state_proof_id),
            vote_first_valid: 1000,
            vote_last_valid: 2000,
            vote_key_dilution: 100,
            ..AccountData::default()
        },
        last_round: 1000,
        amount_without_pending_rewards: 5_000_000,
        assets: BTreeMap::new(),
        created_assets: BTreeMap::new(),
        app_local_states: BTreeMap::new(),
        created_apps: BTreeMap::new(),
    };
    let server = TestServer::start(mock_node_with_account(lookup)).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // participation object should be present
    let participation = body
        .get("participation")
        .expect("participation should be present for online account with vote_id");
    assert!(
        participation.is_object(),
        "participation should be an object"
    );

    // Check field names match go-algorand's hyphenated JSON names
    assert!(
        participation.get("vote-participation-key").is_some(),
        "should have vote-participation-key"
    );
    assert!(
        participation.get("selection-participation-key").is_some(),
        "should have selection-participation-key"
    );
    assert!(
        participation.get("state-proof-key").is_some(),
        "should have state-proof-key"
    );
    assert_eq!(
        participation["vote-first-valid"].as_u64().unwrap(),
        1000,
        "vote-first-valid should be 1000"
    );
    assert_eq!(
        participation["vote-last-valid"].as_u64().unwrap(),
        2000,
        "vote-last-valid should be 2000"
    );
    assert_eq!(
        participation["vote-key-dilution"].as_u64().unwrap(),
        100,
        "vote-key-dilution should be 100"
    );

    // Keys should be base64-encoded strings
    let vote_key = participation["vote-participation-key"]
        .as_str()
        .expect("vote key should be a string");
    assert!(!vote_key.is_empty(), "vote key should be non-empty");

    let selection_key = participation["selection-participation-key"]
        .as_str()
        .expect("selection key should be a string");
    assert!(
        !selection_key.is_empty(),
        "selection key should be non-empty"
    );

    let state_proof_key = participation["state-proof-key"]
        .as_str()
        .expect("state proof key should be a string");
    assert!(
        !state_proof_key.is_empty(),
        "state proof key should be non-empty"
    );
}

// ===========================================================================
// Application query endpoint tests (GET /v2/applications/:application-id)
// ===========================================================================

/// Helper: create a MockNode with an application lookup configured.
fn mock_node_with_application(app_id: u64, lookup: ApplicationLookup) -> MockNode {
    let mut node = MockNode::synced();
    node.application_lookups.insert(app_id, lookup);
    node
}

/// Helper: create a MockNode with an asset lookup configured.
fn mock_node_with_asset(asset_id: u64, lookup: AssetLookup) -> MockNode {
    let mut node = MockNode::synced();
    node.asset_lookups.insert(asset_id, lookup);
    node
}

#[tokio::test]
async fn get_application_returns_200_with_correct_json() {
    let creator = Address([0xAA; 32]);
    let lookup = ApplicationLookup {
        app_params: Some(AppParams {
            creator,
            approval_program: vec![0x06, 0x81, 0x01],
            clear_state_program: vec![0x06, 0x81, 0x01],
            global_state: BTreeMap::new(),
            local_state_schema: StateSchema {
                num_uint: 2,
                num_byte_slice: 1,
            },
            global_state_schema: StateSchema {
                num_uint: 4,
                num_byte_slice: 2,
            },
            extra_program_pages: 0,
        }),
        creator,
        last_round: 1000,
    };
    let server = TestServer::start(mock_node_with_application(123, lookup)).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/123"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["id"].as_u64().unwrap(), 123);
    assert!(
        body["params"]["approval-program"].is_string(),
        "approval-program should be base64 string"
    );
    assert!(
        body["params"]["clear-state-program"].is_string(),
        "clear-state-program should be base64 string"
    );
    assert!(
        body["params"]["creator"].is_string(),
        "creator should be a string"
    );
    assert_eq!(
        body["params"]["local-state-schema"]["num-uint"]
            .as_u64()
            .unwrap(),
        2
    );
    assert_eq!(
        body["params"]["local-state-schema"]["num-byte-slice"]
            .as_u64()
            .unwrap(),
        1
    );
    assert_eq!(
        body["params"]["global-state-schema"]["num-uint"]
            .as_u64()
            .unwrap(),
        4
    );
    assert_eq!(
        body["params"]["global-state-schema"]["num-byte-slice"]
            .as_u64()
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn get_application_returns_404_when_not_found() {
    // No application configured for app_id 999
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/999"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["message"].as_str().unwrap(),
        "application does not exist"
    );
}

#[tokio::test]
async fn get_application_requires_auth_token() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/123"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ===========================================================================
// Asset query endpoint tests (GET /v2/assets/:asset-id)
// ===========================================================================

#[tokio::test]
async fn get_asset_returns_200_with_correct_json() {
    let creator = Address([0xBB; 32]);
    let lookup = AssetLookup {
        asset_params: Some(AssetParams {
            total: 1_000_000,
            decimals: 6,
            default_frozen: false,
            asset_name: "TestCoin".to_string(),
            unit_name: "TC".to_string(),
            url: "https://example.com".to_string(),
            metadata_hash: None,
            manager: None,
            reserve: None,
            freeze: None,
            clawback: None,
        }),
        creator,
        last_round: 1000,
    };
    let server = TestServer::start(mock_node_with_asset(456, lookup)).await;

    let resp = server
        .client
        .get(server.url("/v2/assets/456"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["index"].as_u64().unwrap(), 456);
    assert_eq!(body["params"]["total"].as_u64().unwrap(), 1_000_000);
    assert_eq!(body["params"]["decimals"].as_u64().unwrap(), 6);
    assert_eq!(body["params"]["name"].as_str().unwrap(), "TestCoin");
    assert_eq!(body["params"]["unit-name"].as_str().unwrap(), "TC");
    assert!(
        body["params"]["creator"].is_string(),
        "creator should be a string"
    );
}

#[tokio::test]
async fn get_asset_returns_404_when_not_found() {
    // No asset configured for asset_id 999
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/assets/999"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"].as_str().unwrap(), "asset does not exist");
}

#[tokio::test]
async fn get_asset_requires_auth_token() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/assets/456"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ===========================================================================
// Application box endpoint tests (GET /v2/applications/:id/box)
// ===========================================================================

#[tokio::test]
async fn get_application_box_returns_200_with_box_value() {
    let mut node = MockNode::synced();
    // Box name "mybox" encoded as raw bytes
    let box_name = b"mybox".to_vec();
    let box_value = b"hello world".to_vec();
    node.kv_lookups
        .insert((123, box_name), (Some(box_value), 1000));
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/123/box?name=str:mybox"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    // name and value should be base64-encoded strings
    assert!(body["name"].is_string(), "name should be a base64 string");
    assert!(body["value"].is_string(), "value should be a base64 string");
    assert_eq!(body["round"].as_u64().unwrap(), 1000);

    // Decode and verify the value
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let decoded_value = STANDARD.decode(body["value"].as_str().unwrap()).unwrap();
    assert_eq!(decoded_value, b"hello world");
}

#[tokio::test]
async fn get_application_box_returns_404_when_not_found() {
    // No box configured for this app_id/name
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/123/box?name=str:nonexistent"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"].as_str().unwrap(), "box not found");
}

#[tokio::test]
async fn get_application_box_requires_auth_token() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/123/box?name=str:mybox"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ===========================================================================
// Application boxes endpoint tests (GET /v2/applications/:id/boxes)
// ===========================================================================

#[tokio::test]
async fn get_application_boxes_returns_200_with_box_list() {
    let mut node = MockNode::synced();
    let box_names = vec![b"box1".to_vec(), b"box2".to_vec(), b"box3".to_vec()];
    node.keys_by_prefix.insert(123, (box_names, 1000));
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/123/boxes"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let boxes = body["boxes"].as_array().unwrap();
    assert_eq!(boxes.len(), 3);
    // Each box descriptor should have a "name" field (base64 encoded)
    for b in boxes {
        assert!(
            b["name"].is_string(),
            "box descriptor name should be a string"
        );
    }
}

#[tokio::test]
async fn get_application_boxes_returns_400_when_limit_exceeded() {
    let mut node = MockNode::synced();
    // Set a low limit: algod_max = 2
    // With requested_max = 0 (no query param), application_boxes_max_keys
    // returns algod_max + 1 = 3. So we need > 3 boxes to trigger the error.
    node.max_api_boxes = 2;
    // The handler checks total_boxes() first (O(1) lookup) before scanning keys.
    node.total_boxes_map.insert(123, (4, 1000));
    let box_names = vec![
        b"box1".to_vec(),
        b"box2".to_vec(),
        b"box3".to_vec(),
        b"box4".to_vec(),
    ];
    node.keys_by_prefix.insert(123, (box_names, 1000));
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/123/boxes"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"].as_str().unwrap(), "Result limit exceeded");
}

#[tokio::test]
async fn get_application_boxes_requires_auth_token() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/123/boxes"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn get_application_box_with_int_encoding() {
    let mut node = MockNode::synced();
    // int:42 encodes as 8-byte big-endian
    let box_name = 42u64.to_be_bytes().to_vec();
    let box_value = b"int-box-value".to_vec();
    node.kv_lookups
        .insert((100, box_name), (Some(box_value), 1000));
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/100/box?name=int:42"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let decoded_value = STANDARD.decode(body["value"].as_str().unwrap()).unwrap();
    assert_eq!(decoded_value, b"int-box-value");
}

#[tokio::test]
async fn get_application_box_invalid_encoding_returns_400() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/100/box?name=bogus:value"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn get_application_boxes_empty_list() {
    // App with zero boxes returns an empty array
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/999/boxes"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let boxes = body["boxes"].as_array().unwrap();
    assert!(boxes.is_empty(), "expected empty boxes array");
}

#[tokio::test]
async fn get_application_boxes_with_max_query_param() {
    let mut node = MockNode::synced();
    // Set total_boxes and actual box keys
    node.total_boxes_map.insert(200, (2, 1000));
    let box_names = vec![b"a".to_vec(), b"b".to_vec()];
    node.keys_by_prefix.insert(200, (box_names, 1000));
    // algod_max is large (default 100_000), requested_max=5 dominates
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/200/boxes?max=5"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let boxes = body["boxes"].as_array().unwrap();
    assert_eq!(boxes.len(), 2);
}

#[tokio::test]
async fn get_application_boxes_max_param_triggers_limit() {
    let mut node = MockNode::synced();
    // Set max=1 query param, total_boxes=3; since requested_max(1) <= algod_max(100000),
    // effective max = 1. total_boxes(3) > 1 triggers the limit.
    node.total_boxes_map.insert(300, (3, 1000));
    let box_names = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
    node.keys_by_prefix.insert(300, (box_names, 1000));
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/300/boxes?max=1"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"].as_str().unwrap(), "Result limit exceeded");
    // Verify the data includes total-boxes from the O(1) lookup
    let data = &body["data"];
    assert_eq!(data["total-boxes"].as_u64().unwrap(), 3);
    assert_eq!(data["max"].as_u64().unwrap(), 1);
}
