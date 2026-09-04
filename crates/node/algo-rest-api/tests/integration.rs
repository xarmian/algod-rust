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

//! Integration tests for the Algorand REST API.
//!
//! These tests start a real HTTP server on localhost:0 and send requests
//! using `reqwest`, exercising the full request/response pipeline including
//! routing, auth middleware, and handler logic.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use algo_ledger::participation::{ParticipationID, ParticipationRecord};
use algo_ledger::{StateDelta, StateDeltaSubset};
use algo_rest_api::auth::generate_token;
use algo_rest_api::node::{
    AccountLookup, AppResourceLookup, AppResourceWithIDs, ApplicationLookup, AssetLookup,
    AssetResourceLookup, AssetResourceWithIDs, BuildVersion, NodeError, NodeInterface, NodeStatus,
    ProtocolSwitchInfo, StateProofData, SupplyInfo, TxnGroupDeltaWithIds, TxnWithStatus,
};
use algo_rest_api::router::{build_router, TokenConfig};
use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParams, Block, BlockHeader,
    ConsensusParams, Digest, Round, SignedTransaction, StateSchema, Transaction, TxnType,
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
    /// Backing box store for `lookup_kv_pairs_by_prefix` (cursor pagination,
    /// issue #536), keyed by app_id -> box name -> value. Real prefix
    /// filtering, cursor exclusion, sorting, and limiting are applied by
    /// the mock (unlike `keys_by_prefix` above, which ignores its prefix
    /// argument), so pagination tests exercise real handler behavior.
    box_store: BTreeMap<u64, BTreeMap<Vec<u8>, Vec<u8>>>,
    /// Historical box state for `lookup_kv_pairs_by_prefix_at_round`
    /// (issue #570), keyed by (app_id, round) -> box name -> value. A
    /// missing (app_id, round) entry simulates "round outside the node's
    /// retained lookback window" (`Ok(None)`), matching
    /// `SqliteLedger::reconstruct_box_state_at_round`'s real contract.
    historical_box_store: BTreeMap<(u64, u64), BTreeMap<Vec<u8>, Vec<u8>>>,
    /// Total boxes count results, keyed by app_id. Returns (total_boxes, round).
    total_boxes_map: BTreeMap<u64, (u64, u64)>,
    /// Max API boxes per application.
    max_api_boxes: u64,
    /// Block lookup results, keyed by round.
    blocks: BTreeMap<u64, Block>,
    /// Block header lookup results, keyed by round.
    block_headers: BTreeMap<u64, BlockHeader>,
    /// Block hash lookup results, keyed by round.
    block_hashes: BTreeMap<u64, Digest>,
    /// Raw msgpack block bytes, keyed by round.
    block_raw_msgpack: BTreeMap<u64, Vec<u8>>,
    /// Per-transaction-group deltas keyed by round. `None` = tracer disabled
    /// (endpoints 501); `Some` = enabled (round→deltas, txn/group ids searched
    /// across all rounds for the by-id endpoint).
    txn_group_deltas: Option<BTreeMap<u64, Vec<algo_rest_api::node::TxnGroupDeltaWithIds>>>,
    /// State proof transaction results, keyed by round. Returns (first_attested, last_attested).
    state_proof_txns: BTreeMap<u64, (u64, u64)>,
    /// Supply info to return from get_supply().
    supply_info: Option<SupplyInfo>,
    /// State proof data results, keyed by round.
    state_proof_data: BTreeMap<u64, StateProofData>,
    /// Pending transactions in the pool (for get_pending_txns_from_pool).
    pending_txns: Vec<SignedTransaction>,
    /// Pending transaction lookup (for get_pending_transaction), keyed by txid bytes.
    pending_txn_lookup: BTreeMap<[u8; 32], TxnWithStatus>,
    /// Broadcast result: None = success, Some(msg) = error.
    broadcast_result: Option<String>,
    /// Simulate result to return (None = use default NotImplemented).
    simulate_result: Option<algo_rest_api::models::SimulateResponse>,
    /// State deltas by round.
    state_deltas: BTreeMap<u64, StateDelta>,
    /// Whether the developer API is enabled.
    enable_developer_api: bool,
    /// Whether the experimental API is enabled.
    enable_experimental_api: bool,
    /// Mirrors go's `config.Local.DisableAPIAuth` (issue #748).
    disable_api_auth: bool,
    /// Asset resource records for lookup_assets, keyed by address bytes.
    asset_resources_by_addr: BTreeMap<[u8; 32], Vec<AssetResourceWithIDs>>,
    /// App resource records for lookup_applications, keyed by address bytes.
    app_resources_by_addr: BTreeMap<[u8; 32], Vec<AppResourceWithIDs>>,
    /// Participation records to return from list/get.
    participation_records: Vec<ParticipationRecord>,
    /// Install result: None = return new ID, Some(msg) = error.
    install_result: Option<String>,
    /// Remove result: None = success, Some(msg) = error (use "not found" for NotFound variant).
    remove_result: Option<String>,
    /// Append result: None = success, Some(msg) = error.
    append_result: Option<String>,
    /// Catchup start result (None = use default NotImplemented).
    catchup_start_result: Option<algo_rest_api::node::CatchupStartResult>,
    /// Catchup abort result: None = success, Some(msg) = error.
    catchup_abort_result: Option<String>,
    /// Whether dev mode is enabled.
    is_dev_mode: bool,
    /// Whether follower mode is enabled.
    is_follower_mode: bool,
    /// Block timestamp offset (None = never set, Some = set).
    block_timestamp_offset: Option<u64>,
    /// Sync round (0 = not set).
    sync_round: u64,
    /// Config JSON to return.
    config_json: Option<serde_json::Value>,
    /// Debug profiling rates: (mutex_rate, block_rate).
    debug_prof_rates: (u64, u64),
    /// Latest round for catchup min-rounds check.
    latest_round_for_catchup: u64,
    /// Set sync round result: None = success, Some(msg) = error.
    set_sync_round_result: Option<String>,
    /// Consensus-participation metrics JSON (None = not participating).
    participation_status: Option<serde_json::Value>,
    /// Prometheus exposition text (None = not participating).
    metrics_exposition: Option<String>,
    /// Peers result: `(inbound, outbound)`. `None` = use default
    /// `NotImplemented`.
    peers_result: Option<(
        Vec<algo_rest_api::node::PeerInfo>,
        Vec<algo_rest_api::node::PeerInfo>,
    )>,
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
            box_store: self.box_store.clone(),
            historical_box_store: self.historical_box_store.clone(),
            total_boxes_map: self.total_boxes_map.clone(),
            max_api_boxes: self.max_api_boxes,
            blocks: self.blocks.clone(),
            block_headers: self.block_headers.clone(),
            block_hashes: self.block_hashes.clone(),
            block_raw_msgpack: self.block_raw_msgpack.clone(),
            txn_group_deltas: self.txn_group_deltas.clone(),
            state_proof_txns: self.state_proof_txns.clone(),
            supply_info: self.supply_info.clone(),
            state_proof_data: self.state_proof_data.clone(),
            pending_txns: self.pending_txns.clone(),
            pending_txn_lookup: self.pending_txn_lookup.clone(),
            broadcast_result: self.broadcast_result.clone(),
            simulate_result: self.simulate_result.clone(),
            state_deltas: self.state_deltas.clone(),
            enable_developer_api: self.enable_developer_api,
            enable_experimental_api: self.enable_experimental_api,
            disable_api_auth: self.disable_api_auth,
            asset_resources_by_addr: self.asset_resources_by_addr.clone(),
            app_resources_by_addr: self.app_resources_by_addr.clone(),
            participation_records: self.participation_records.clone(),
            install_result: self.install_result.clone(),
            remove_result: self.remove_result.clone(),
            append_result: self.append_result.clone(),
            catchup_start_result: self.catchup_start_result.clone(),
            catchup_abort_result: self.catchup_abort_result.clone(),
            is_dev_mode: self.is_dev_mode,
            is_follower_mode: self.is_follower_mode,
            block_timestamp_offset: self.block_timestamp_offset,
            sync_round: self.sync_round,
            config_json: self.config_json.clone(),
            debug_prof_rates: self.debug_prof_rates,
            latest_round_for_catchup: self.latest_round_for_catchup,
            set_sync_round_result: self.set_sync_round_result.clone(),
            participation_status: self.participation_status.clone(),
            metrics_exposition: self.metrics_exposition.clone(),
            peers_result: self.peers_result.clone(),
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
            box_store: BTreeMap::new(),
            historical_box_store: BTreeMap::new(),
            total_boxes_map: BTreeMap::new(),
            max_api_boxes: 100_000,
            blocks: BTreeMap::new(),
            block_headers: BTreeMap::new(),
            block_hashes: BTreeMap::new(),
            block_raw_msgpack: BTreeMap::new(),
            txn_group_deltas: None,
            state_proof_txns: BTreeMap::new(),
            supply_info: None,
            state_proof_data: BTreeMap::new(),
            pending_txns: Vec::new(),
            pending_txn_lookup: BTreeMap::new(),
            broadcast_result: None,
            simulate_result: None,
            state_deltas: BTreeMap::new(),
            enable_developer_api: false,
            enable_experimental_api: false,
            disable_api_auth: false,
            asset_resources_by_addr: BTreeMap::new(),
            app_resources_by_addr: BTreeMap::new(),
            participation_records: Vec::new(),
            install_result: None,
            remove_result: None,
            append_result: None,
            catchup_start_result: None,
            catchup_abort_result: None,
            is_dev_mode: false,
            is_follower_mode: false,
            block_timestamp_offset: None,
            sync_round: 0,
            config_json: None,
            debug_prof_rates: (0, 0),
            latest_round_for_catchup: 0,
            set_sync_round_result: None,
            // Default mock is a non-participating node, so both #473
            // endpoints answer 404 unless a test opts in.
            participation_status: None,
            metrics_exposition: None,
            peers_result: None,
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

    async fn status(&self) -> Result<NodeStatus, NodeError> {
        match &self.status {
            MockStatus::Ok(s) => Ok(*s.clone()),
            MockStatus::Err(msg) => Err(NodeError::Internal(msg.clone())),
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

    async fn wait_for_round(&self, _round: u64) -> Result<(), NodeError> {
        match &self.wait_behavior {
            MockWaitBehavior::Immediate => Ok(()),
            MockWaitBehavior::WaitForever => {
                self.wait_notify.notified().await;
                Ok(())
            }
            MockWaitBehavior::Error(msg) => Err(NodeError::Internal(msg.clone())),
        }
    }

    async fn latest_block_header_protocol_info(&self) -> Result<ProtocolSwitchInfo, NodeError> {
        match &self.protocol_info_behavior {
            MockProtocolInfoBehavior::Ok => Ok(self.protocol_switch_info.clone()),
            MockProtocolInfoBehavior::Err(msg) => Err(NodeError::Internal(msg.clone())),
        }
    }

    async fn lookup_account(&self, _addr: &Address) -> Result<AccountLookup, NodeError> {
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

    async fn lookup_account_basic(&self, _addr: &Address) -> Result<AccountLookup, NodeError> {
        match &self.account_lookup {
            Some(lookup) => Ok(AccountLookup {
                account_data: lookup.account_data.clone(),
                last_round: lookup.last_round,
                amount_without_pending_rewards: lookup.amount_without_pending_rewards,
                assets: BTreeMap::new(),
                created_assets: BTreeMap::new(),
                app_local_states: BTreeMap::new(),
                created_apps: BTreeMap::new(),
            }),
            None => Ok(AccountLookup {
                account_data: AccountData::default(),
                last_round: 1000,
                amount_without_pending_rewards: 0,
                assets: BTreeMap::new(),
                created_assets: BTreeMap::new(),
                app_local_states: BTreeMap::new(),
                created_apps: BTreeMap::new(),
            }),
        }
    }

    async fn lookup_asset_resource(
        &self,
        addr: &Address,
        asset_id: u64,
    ) -> Result<AssetResourceLookup, NodeError> {
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
    ) -> Result<AppResourceLookup, NodeError> {
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

    async fn consensus_params(&self) -> Result<ConsensusParams, NodeError> {
        Ok(self.consensus_params.clone())
    }

    fn max_api_resources_per_account(&self) -> u64 {
        self.max_api_resources
    }

    async fn lookup_application(&self, app_id: u64) -> Result<ApplicationLookup, NodeError> {
        match self.application_lookups.get(&app_id) {
            Some(lookup) => Ok(lookup.clone()),
            None => Ok(ApplicationLookup {
                app_params: None,
                creator: Address([0u8; 32]),
                last_round: 1000,
            }),
        }
    }

    async fn lookup_asset_by_id(&self, asset_id: u64) -> Result<AssetLookup, NodeError> {
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
    ) -> Result<(Option<Vec<u8>>, u64), NodeError> {
        match self.kv_lookups.get(&(app_id, key.to_vec())) {
            Some(result) => Ok(result.clone()),
            None => Ok((None, 1000)),
        }
    }

    async fn lookup_keys_by_prefix(
        &self,
        app_id: u64,
        _prefix: &[u8],
    ) -> Result<(Vec<Vec<u8>>, u64), NodeError> {
        match self.keys_by_prefix.get(&app_id) {
            Some(result) => Ok(result.clone()),
            None => Ok((vec![], 1000)),
        }
    }

    async fn lookup_kv_pairs_by_prefix(
        &self,
        app_id: u64,
        prefix: &[u8],
        cursor: Option<&[u8]>,
        limit: Option<u64>,
        include_values: bool,
    ) -> Result<(algo_ledger::store_trait::BoxPage, u64, bool), NodeError> {
        let mut names: Vec<Vec<u8>> = match self.box_store.get(&app_id) {
            Some(boxes) => boxes
                .keys()
                .filter(|name| name.starts_with(prefix))
                .filter(|name| match cursor {
                    Some(c) => name.as_slice() > c,
                    None => true,
                })
                .cloned()
                .collect(),
            None => Vec::new(),
        };
        names.sort();

        let more_data = match limit {
            Some(l) => (names.len() as u64) > l,
            None => false,
        };
        if let Some(l) = limit {
            names.truncate(l as usize);
        }

        let boxes = self.box_store.get(&app_id);
        let results = names
            .into_iter()
            .map(|name| {
                let value = if include_values {
                    boxes.and_then(|b| b.get(&name)).cloned()
                } else {
                    None
                };
                (name, value)
            })
            .collect();

        Ok((results, 1000, more_data))
    }

    async fn lookup_kv_pairs_by_prefix_at_round(
        &self,
        app_id: u64,
        round: u64,
        prefix: &[u8],
        cursor: Option<&[u8]>,
        limit: Option<u64>,
        include_values: bool,
    ) -> Result<Option<(algo_ledger::store_trait::BoxPage, bool)>, NodeError> {
        let Some(boxes) = self.historical_box_store.get(&(app_id, round)) else {
            return Ok(None);
        };
        let mut names: Vec<Vec<u8>> = boxes
            .keys()
            .filter(|name| name.starts_with(prefix))
            .filter(|name| match cursor {
                Some(c) => name.as_slice() > c,
                None => true,
            })
            .cloned()
            .collect();
        names.sort();

        let more_data = match limit {
            Some(l) => (names.len() as u64) > l,
            None => false,
        };
        if let Some(l) = limit {
            names.truncate(l as usize);
        }

        let results = names
            .into_iter()
            .map(|name| {
                let value = if include_values {
                    boxes.get(&name).cloned()
                } else {
                    None
                };
                (name, value)
            })
            .collect();

        Ok(Some((results, more_data)))
    }

    async fn total_boxes(&self, app_id: u64) -> Result<(u64, u64), NodeError> {
        match self.total_boxes_map.get(&app_id) {
            Some(result) => Ok(*result),
            None => Ok((0, 1000)),
        }
    }

    fn max_api_box_per_application(&self) -> u64 {
        self.max_api_boxes
    }

    async fn get_block(&self, round: u64) -> Result<Block, NodeError> {
        match self.blocks.get(&round) {
            Some(block) => Ok(block.clone()),
            None => Err(NodeError::NotFound("block not found".to_string())),
        }
    }

    async fn get_block_header(&self, round: u64) -> Result<BlockHeader, NodeError> {
        match self.block_headers.get(&round) {
            Some(header) => Ok(header.clone()),
            None => Err(NodeError::NotFound("block header not found".to_string())),
        }
    }

    async fn get_block_hash(&self, round: u64) -> Result<Option<Digest>, NodeError> {
        Ok(self.block_hashes.get(&round).copied())
    }

    async fn get_block_raw_msgpack(&self, round: u64) -> Result<Vec<u8>, NodeError> {
        if let Some(bytes) = self.block_raw_msgpack.get(&round) {
            return Ok(bytes.clone());
        }
        // Fall back to synthesizing the `{"block": <block>}` envelope from a
        // typed block, mirroring the real node's hand-built map. Lets tests that
        // populate `blocks` exercise the canonical block-JSON path.
        if let Some(block) = self.blocks.get(&round) {
            let block_bytes = algo_codec::encode_block(block)
                .map_err(|e| NodeError::Internal(format!("encode block: {e}")))?;
            let mut buf = Vec::with_capacity(block_bytes.len() + 8);
            buf.push(0x81); // fixmap(1)
            buf.push(0xa5); // fixstr(5)
            buf.extend_from_slice(b"block");
            buf.extend_from_slice(&block_bytes);
            return Ok(buf);
        }
        Err(NodeError::NotFound("block not found".to_string()))
    }

    async fn get_txn_group_delta(&self, id: &Digest) -> Result<StateDeltaSubset, NodeError> {
        match &self.txn_group_deltas {
            None => Err(NodeError::NotImplemented("get_txn_group_delta")),
            Some(by_round) => {
                let id_str = id.to_string();
                for deltas in by_round.values() {
                    for d in deltas {
                        if d.ids.contains(&id_str) {
                            return Ok(d.delta.clone());
                        }
                    }
                }
                Err(NodeError::NotFound(format!("no delta for {id_str}")))
            }
        }
    }

    async fn get_txn_group_deltas_for_round(
        &self,
        round: u64,
    ) -> Result<Vec<TxnGroupDeltaWithIds>, NodeError> {
        match &self.txn_group_deltas {
            None => Err(NodeError::NotImplemented("get_txn_group_deltas_for_round")),
            Some(by_round) => by_round
                .get(&round)
                .cloned()
                .ok_or_else(|| NodeError::NotFound(format!("round {round} not found"))),
        }
    }

    async fn get_state_proof_transaction_for_round(
        &self,
        round: u64,
    ) -> Result<(u64, u64), NodeError> {
        match self.state_proof_txns.get(&round) {
            Some(result) => Ok(*result),
            None => Err(NodeError::NotFound(
                "no state proof found for round".to_string(),
            )),
        }
    }

    async fn get_supply(&self) -> Result<SupplyInfo, NodeError> {
        match &self.supply_info {
            Some(info) => Ok(info.clone()),
            None => Err(NodeError::NotImplemented("get_supply")),
        }
    }

    async fn get_state_proof_for_round(&self, round: u64) -> Result<StateProofData, NodeError> {
        match self.state_proof_data.get(&round) {
            Some(data) => Ok(data.clone()),
            None => Err(NodeError::NotFound(
                "no state proof found for round".to_string(),
            )),
        }
    }

    async fn broadcast_signed_tx_group(
        &self,
        _tx_group: Vec<SignedTransaction>,
    ) -> Result<(), NodeError> {
        match &self.broadcast_result {
            None => Ok(()),
            Some(msg) => Err(NodeError::Internal(msg.clone())),
        }
    }

    async fn get_pending_transaction(
        &self,
        txid: &Digest,
    ) -> Result<Option<TxnWithStatus>, NodeError> {
        Ok(self.pending_txn_lookup.get(&txid.0).cloned())
    }

    async fn get_pending_txns_from_pool(&self) -> Result<Vec<SignedTransaction>, NodeError> {
        Ok(self.pending_txns.clone())
    }

    async fn simulate(
        &self,
        _request: algo_rest_api::models::SimulateRequest,
    ) -> Result<algo_rest_api::models::SimulateResponse, NodeError> {
        match &self.simulate_result {
            Some(resp) => Ok(resp.clone()),
            None => Err(NodeError::NotImplemented("simulate")),
        }
    }

    async fn get_state_delta_for_round(&self, round: u64) -> Result<StateDelta, NodeError> {
        match self.state_deltas.get(&round) {
            Some(delta) => Ok(delta.clone()),
            None => Err(NodeError::NotFound(format!("no delta for round {round}"))),
        }
    }

    fn enable_developer_api(&self) -> bool {
        self.enable_developer_api
    }

    fn enable_experimental_api(&self) -> bool {
        self.enable_experimental_api
    }

    async fn async_broadcast_signed_tx_group(
        &self,
        _tx_group: Vec<SignedTransaction>,
    ) -> Result<(), NodeError> {
        match &self.broadcast_result {
            None => Ok(()),
            Some(msg) => Err(NodeError::Internal(msg.clone())),
        }
    }

    async fn lookup_assets(
        &self,
        addr: &Address,
        asset_id_gt: u64,
        limit: u64,
    ) -> Result<(Vec<AssetResourceWithIDs>, u64), NodeError> {
        let records = match self.asset_resources_by_addr.get(&addr.0) {
            Some(r) => r
                .iter()
                .filter(|r| r.asset_id > asset_id_gt)
                .take(limit as usize)
                .cloned()
                .collect(),
            None => vec![],
        };
        Ok((records, 1000))
    }

    async fn lookup_applications(
        &self,
        addr: &Address,
        app_id_gt: u64,
        limit: u64,
        include_params: bool,
    ) -> Result<(Vec<AppResourceWithIDs>, u64), NodeError> {
        let records = match self.app_resources_by_addr.get(&addr.0) {
            Some(r) => r
                .iter()
                .filter(|r| r.app_id > app_id_gt)
                .take(limit as usize)
                .cloned()
                .map(|mut rec| {
                    if !include_params {
                        rec.app_params = None;
                    }
                    rec
                })
                .collect(),
            None => vec![],
        };
        Ok((records, 1000))
    }

    async fn list_participation_keys(&self) -> Result<Vec<ParticipationRecord>, NodeError> {
        Ok(self.participation_records.clone())
    }

    async fn get_participation_key(
        &self,
        id: &ParticipationID,
    ) -> Result<ParticipationRecord, NodeError> {
        for record in &self.participation_records {
            if record.participation_id.0 == id.0 {
                return Ok(record.clone());
            }
        }
        // Return a zero record (handler converts to 404).
        Ok(ParticipationRecord {
            participation_id: ParticipationID([0u8; 32]),
            account: Address([0u8; 32]),
            first_valid: Round(0),
            last_valid: Round(0),
            key_dilution: 0,
            last_vote: Round(0),
            last_block_proposal: Round(0),
            last_state_proof: Round(0),
            effective_first: Round(0),
            effective_last: Round(0),
            vrf_public_key: None,
            vote_id: None,
            state_proof_verifier: None,
        })
    }

    async fn install_participation_key(
        &self,
        _data: Vec<u8>,
    ) -> Result<ParticipationID, NodeError> {
        match &self.install_result {
            Some(msg) => Err(NodeError::Internal(msg.clone())),
            None => Ok(ParticipationID([0x42; 32])),
        }
    }

    async fn remove_participation_key(&self, _id: &ParticipationID) -> Result<(), NodeError> {
        match &self.remove_result {
            Some(msg) if msg.contains("not found") => Err(NodeError::NotFound(msg.clone())),
            Some(msg) => Err(NodeError::Internal(msg.clone())),
            None => Ok(()),
        }
    }

    async fn append_participation_keys(
        &self,
        _id: &ParticipationID,
        _keys: Vec<u8>,
    ) -> Result<(), NodeError> {
        match &self.append_result {
            Some(msg) => Err(NodeError::Internal(msg.clone())),
            None => Ok(()),
        }
    }

    async fn generate_participation_keys(
        &self,
        _address: Address,
        _first: u64,
        _last: u64,
        _dilution: Option<u64>,
    ) -> Result<ParticipationID, NodeError> {
        Ok(ParticipationID([0x42; 32]))
    }

    async fn start_catchup(
        &self,
        _catchpoint: &str,
        _min_rounds: u64,
    ) -> Result<algo_rest_api::node::CatchupStartResult, NodeError> {
        match &self.catchup_start_result {
            Some(result) => Ok(result.clone()),
            None => Err(NodeError::NotImplemented("start_catchup")),
        }
    }

    async fn abort_catchup(&self, _catchpoint: &str) -> Result<(), NodeError> {
        match &self.catchup_abort_result {
            Some(msg) => Err(NodeError::Internal(msg.clone())),
            None => Ok(()),
        }
    }

    fn is_dev_mode(&self) -> bool {
        self.is_dev_mode
    }

    fn is_follower_mode(&self) -> bool {
        self.is_follower_mode
    }

    fn participation_status(&self) -> Option<serde_json::Value> {
        self.participation_status.clone()
    }

    fn metrics_exposition(&self) -> Option<String> {
        self.metrics_exposition.clone()
    }

    async fn get_block_timestamp_offset(&self) -> Result<Option<u64>, NodeError> {
        if !self.is_dev_mode {
            return Err(NodeError::Internal("not in dev mode".to_string()));
        }
        Ok(self.block_timestamp_offset)
    }

    async fn set_block_timestamp_offset(&self, _offset: i64) -> Result<(), NodeError> {
        if !self.is_dev_mode {
            return Err(NodeError::Internal("not in dev mode".to_string()));
        }
        Ok(())
    }

    async fn get_sync_round(&self) -> Result<u64, NodeError> {
        Ok(self.sync_round)
    }

    async fn set_sync_round(&self, _round: u64) -> Result<(), NodeError> {
        match &self.set_sync_round_result {
            Some(msg) => Err(NodeError::Internal(msg.clone())),
            None => Ok(()),
        }
    }

    async fn unset_sync_round(&self) -> Result<(), NodeError> {
        Ok(())
    }

    async fn get_config_json(&self) -> Result<serde_json::Value, NodeError> {
        match &self.config_json {
            Some(json) => Ok(json.clone()),
            None => Ok(serde_json::json!({})),
        }
    }

    async fn get_debug_settings_prof(&self) -> Result<(u64, u64), NodeError> {
        Ok(self.debug_prof_rates)
    }

    async fn set_debug_settings_prof(
        &self,
        _mutex_rate: Option<u64>,
        _block_rate: Option<u64>,
    ) -> Result<(Option<u64>, Option<u64>), NodeError> {
        let (old_mutex, old_block) = self.debug_prof_rates;
        Ok((Some(old_mutex), Some(old_block)))
    }

    fn latest_round_for_catchup(&self) -> u64 {
        self.latest_round_for_catchup
    }

    async fn get_peers(
        &self,
    ) -> Result<
        (
            Vec<algo_rest_api::node::PeerInfo>,
            Vec<algo_rest_api::node::PeerInfo>,
        ),
        NodeError,
    > {
        match &self.peers_result {
            Some(result) => Ok(result.clone()),
            None => Err(NodeError::NotImplemented("get_peers")),
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
        let enable_experimental_api = node.enable_experimental_api;
        let disable_api_auth = node.disable_api_auth;

        let tokens = TokenConfig {
            api_token: api_token.clone(),
            admin_token: admin_token.clone(),
            enable_experimental_api,
            disable_api_auth,
            enable_private_network_access_header: false,
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

/// AGPL section 13 source-availability pointer (issue #742): the
/// `X-Algod-Rust-Source` header must be present on every response,
/// regardless of endpoint or auth tier, without perturbing the response
/// body. `/health` (no-auth) and `/versions` (whose body is byte-for-byte
/// parity-tested against go-algorand) are representative of both.
#[tokio::test]
async fn source_header_present_and_body_untouched() {
    let server = TestServer::start(MockNode::synced()).await;

    let health = server
        .client
        .get(server.url("/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        health.headers().get("x-algod-rust-source").unwrap(),
        "https://github.com/xarmian/algod-rust"
    );

    let versions = server
        .client
        .get(server.url("/versions"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        versions.headers().get("x-algod-rust-source").unwrap(),
        "https://github.com/xarmian/algod-rust"
    );
    let body: serde_json::Value = versions.json().await.unwrap();
    assert!(
        body.get("x-algod-rust-source").is_none(),
        "the source pointer must be a header only, never leak into the JSON body"
    );
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

/// Issue #748: `DisableAPIAuth` (go: `config.Local.DisableAPIAuth`) skips
/// the token check on public (non-admin) routes entirely — a request with
/// NO token at all must succeed.
#[tokio::test]
async fn disable_api_auth_allows_public_route_without_any_token() {
    let server = TestServer::start(MockNode {
        disable_api_auth: true,
        ..MockNode::synced()
    })
    .await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/params"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "DisableAPIAuth must allow public routes through with no token"
    );
}

/// Issue #748: `DisableAPIAuth`'s doc comment scopes it to "public
/// (non-admin)" endpoints only — admin routes must still reject a request
/// with no token even when it's set.
#[tokio::test]
async fn disable_api_auth_does_not_affect_admin_routes() {
    let server = TestServer::start(MockNode {
        disable_api_auth: true,
        ..MockNode::synced()
    })
    .await;

    let resp = server
        .client
        .get(server.url("/v2/participation"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "DisableAPIAuth must not weaken admin-route authentication"
    );
}

#[tokio::test]
async fn admin_token_works_on_public_routes_but_api_token_does_not_work_on_admin_routes() {
    let server = TestServer::start(MockNode::synced()).await;

    // The admin token is accepted on public/authenticated routes — go-algorand
    // wires the public middleware with `[adminToken, apiToken]`
    // (`daemon/algod/api/server/router.go:96`), so the admin token is valid
    // everywhere. This is what lets `goal` (which prefers the admin token) drive
    // standard v2 endpoints. (TASK-261/263.)
    let resp = server
        .client
        .get(server.url("/v2/transactions/params"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        401,
        "admin token must be accepted on public routes (go router.go:96)"
    );

    // The asymmetry holds: the public/api token does NOT grant access to
    // admin-only routes, which go wires with `[adminToken]` only (router.go:83).
    let resp = server
        .client
        .get(server.url("/v2/participation"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "public token must be rejected on admin-only routes (go router.go:83)"
    );
}

// ===========================================================================
// JSON error envelope conformance (issue #129)
//
// Verified live against go-algorand v4.6.0-stable: a request to an unmatched
// route returns `{"message":"Not Found"}` (Echo's default JSON error
// handler), and a malformed path parameter (e.g. a non-numeric round) returns
// a 400 with `{"message": "Invalid format for parameter ...: ..."}`. Every
// go-algorand error response, with no exception, is a JSON object carrying a
// `message` key (`returnError`, `daemon/algod/api/server/v2/utils.go`).
//
// Before this fix, axum's default extractor-rejection and no-route-matched
// responses bypassed the JSON envelope entirely: an unmatched route returned
// an empty body, and a malformed numeric path segment (e.g.
// `/v2/blocks/notanumber`) returned axum's plain-text rejection message
// ("Invalid URL: Cannot parse ...") with no `message` key at all -- silently
// breaking any client that unconditionally reads `response.json()["message"]`
// on a 4xx/5xx response, as go-algorand's OpenAPI error schema promises.
// ===========================================================================

#[tokio::test]
async fn unmatched_route_returns_json_not_found_envelope() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/this-route-does-not-exist"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("application/json"),
        "unmatched-route 404 must be JSON, got content-type {content_type:?}"
    );

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["message"], "Not Found",
        "must match go-algorand's Echo default 404 body"
    );
}

/// go-algorand's router returns 404 for an unmatched path *before* any
/// per-route auth middleware runs — Echo's routing determines there is no
/// matching handler (and therefore no middleware chain to invoke) prior to
/// dispatch. Verified live against go-algorand v4.6.0-stable: a completely
/// unauthenticated request to a bogus path still returns
/// `404 {"message":"Not Found"}`, never `401`.
///
/// Before this fix, an unmatched route in algod-rust was accidentally
/// funneled through whichever sub-router's auth layer happened to be merged
/// last (the admin-only tier), so an unauthenticated (or public-token-only)
/// request to a bogus path incorrectly returned `401 Invalid API Token`
/// instead of `404 Not Found` — a materially misleading error that could send
/// a client chasing an auth problem that doesn't exist. Issue #129.
#[tokio::test]
async fn unmatched_route_requires_no_auth() {
    let server = TestServer::start(MockNode::synced()).await;

    // No token at all.
    let resp = server
        .client
        .get(server.url("/v2/this-route-does-not-exist"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "unmatched route must 404 without requiring any auth token"
    );

    // The plain public token (not the admin token) must also reach the same
    // 404 — regression coverage for the admin-tier-fallback bug specifically.
    let resp = server
        .client
        .get(server.url("/v2/this-route-does-not-exist"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn malformed_numeric_path_param_returns_json_error_envelope() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/notanumber"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("application/json"),
        "extractor-rejection response must be JSON, got content-type {content_type:?}"
    );

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["message"].is_string() && !body["message"].as_str().unwrap().is_empty(),
        "response must carry a non-empty message field: {body:?}"
    );
}

// ===========================================================================
// CORS conformance (issue #129)
//
// Verified live against go-algorand v4.6.0-stable: `middlewares.MakeCORS`
// (`daemon/algod/api/server/lib/middlewares/cors.go`) configures Echo's CORS
// middleware with `AllowOrigins: ["*"]`, `AllowHeaders: [TokenHeader,
// "Content-Type"]`, `AllowMethods: [GET, POST, PUT, DELETE, OPTIONS]`, applied
// globally to every route (including `/health` and friends) before auth.
//
// Before this fix, algod-rust had no CORS support at all: a simple GET with
// an `Origin` header carried no `Access-Control-*` headers, and — more
// seriously — an OPTIONS preflight request returned axum's default
// `405 Method Not Allowed` (no route registers OPTIONS explicitly) instead of
// go's `204 No Content` with the preflight headers a browser requires to
// proceed. That failure mode silently breaks every browser-based dApp/wallet
// calling algod-rust directly for any request needing a preflight (a custom
// header like `X-Algo-API-Token`, or a non-simple method) — the actual
// request is never sent because the preflight itself fails.
// ===========================================================================

#[tokio::test]
async fn simple_request_with_origin_carries_cors_headers() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/params"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Origin", "https://example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*"),
        "must match go's AllowOrigins: [\"*\"] (cors.go)"
    );
}

#[tokio::test]
async fn options_preflight_returns_204_with_cors_headers() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .request(
            reqwest::Method::OPTIONS,
            server.url("/v2/transactions/params"),
        )
        .header("Origin", "https://example.com")
        .header("Access-Control-Request-Method", "GET")
        .header("Access-Control-Request-Headers", "X-Algo-API-Token")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        204,
        "preflight must succeed without any auth token (go: CORS runs before auth)"
    );

    let headers = resp.headers();
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );

    let allow_headers = headers
        .get("access-control-allow-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    assert!(
        allow_headers.contains("x-algo-api-token"),
        "must allow the token header for preflight, got {allow_headers:?}"
    );
    assert!(
        allow_headers.contains("content-type"),
        "must allow Content-Type for preflight, got {allow_headers:?}"
    );

    let allow_methods = headers
        .get("access-control-allow-methods")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_uppercase();
    for m in ["GET", "POST", "PUT", "DELETE", "OPTIONS"] {
        assert!(
            allow_methods.contains(m),
            "AllowMethods must include {m} (cors.go), got {allow_methods:?}"
        );
    }
}

/// Preflight must never require an auth token — go-algorand's CORS
/// middleware runs before the auth middleware chain, and a real browser
/// preflight never sends `X-Algo-API-Token`.
#[tokio::test]
async fn options_preflight_requires_no_auth_even_on_admin_routes() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .request(reqwest::Method::OPTIONS, server.url("/v2/participation"))
        .header("Origin", "https://example.com")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

// ===========================================================================
// Response compression (issue #129)
//
// go-algorand applies Echo's `middleware.Gzip()` globally (`router.go:110`),
// compressing any response when the client sends `Accept-Encoding: gzip` and
// adding `Vary: Accept-Encoding`. algod-rust had no compression support at
// all before this fix.
// ===========================================================================

#[tokio::test]
async fn gzip_accepted_response_is_compressed_and_round_trips() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/params"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-encoding")
            .and_then(|v| v.to_str().ok()),
        Some("gzip"),
        "response must be gzip-compressed when the client accepts it"
    );
    assert!(
        resp.headers()
            .get_all("vary")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.eq_ignore_ascii_case("accept-encoding")),
        "must advertise Vary: Accept-Encoding (go: middleware.Gzip)"
    );

    let compressed = resp.bytes().await.unwrap();
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed).unwrap();
    let body: serde_json::Value = serde_json::from_str(&decompressed).unwrap();
    assert!(body.get("min-fee").is_some());
}

#[tokio::test]
async fn response_uncompressed_without_accept_encoding() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/params"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers().get("content-encoding").is_none(),
        "must not compress when the client didn't send Accept-Encoding"
    );
    // Body is still valid, plain JSON.
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.get("min-fee").is_some());
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

/// go's `round basics.Round` (`uint64`) computes `round+1` with plain
/// unsigned wraparound and no overflow check at all -- verified live
/// against go-algorand v4.6.0-stable (issue #450):
/// `wait-for-block-after/{u64::MAX}` returns 200 immediately, since
/// `round+1` wraps to 0 and round 0 is always already committed. A prior
/// version of this test asserted an explicit 400 "round overflow" here,
/// which was itself the conformance bug.
#[tokio::test]
async fn wait_for_block_round_overflow_wraps_and_returns_200() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/status/wait-for-block-after/{}", u64::MAX)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
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
    // Populate one of each resource so the lists appear. go (and now the Rust
    // response) omits *empty* resource lists, so a fully-empty account would
    // have them absent — to verify exclude=none includes resources, the account
    // must actually hold some.
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
        assets: BTreeMap::from([(
            1,
            AssetHolding {
                amount: 5,
                frozen: false,
            },
        )]),
        created_assets: BTreeMap::from([(2, AssetParams::default())]),
        app_local_states: BTreeMap::from([(
            3,
            AppLocalState {
                schema: Default::default(),
                key_value: BTreeMap::new(),
            },
        )]),
        created_apps: BTreeMap::from([(
            4,
            AppParams {
                creator: Address::ZERO,
                approval_program: vec![0x06],
                clear_state_program: vec![0x06],
                global_state: BTreeMap::new(),
                local_state_schema: Default::default(),
                global_state_schema: Default::default(),
                extra_program_pages: 0,
                ..Default::default()
            },
        )]),
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

    // Resource lists should be present with exclude=none
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

/// Builds the same populated lookup as `account_info_exclude_none_returns_full_info`,
/// reused by issue #507's granular-exclude tests below.
fn lookup_with_one_of_each_resource() -> AccountLookup {
    AccountLookup {
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
        assets: BTreeMap::from([(
            1,
            AssetHolding {
                amount: 5,
                frozen: false,
            },
        )]),
        created_assets: BTreeMap::from([(2, AssetParams::default())]),
        app_local_states: BTreeMap::from([(
            3,
            AppLocalState {
                schema: Default::default(),
                key_value: BTreeMap::new(),
            },
        )]),
        created_apps: BTreeMap::from([(
            4,
            AppParams {
                creator: Address::ZERO,
                approval_program: vec![0x06],
                clear_state_program: vec![0x06],
                global_state: BTreeMap::new(),
                local_state_schema: Default::default(),
                global_state_schema: Default::default(),
                extra_program_pages: 0,
                ..Default::default()
            },
        )]),
    }
}

/// Issue #507 (go-algorand v4.6.0-stable, PR #6547): `exclude=created-assets-params`
/// must still list the created asset (by index) but omit its `params` object
/// entirely — not a null/empty params, an absent key.
#[tokio::test]
async fn account_info_exclude_created_assets_params_omits_only_params() {
    let server =
        TestServer::start(mock_node_with_account(lookup_with_one_of_each_resource())).await;

    let resp = server
        .client
        .get(server.url(&format!(
            "/v2/accounts/{}?exclude=created-assets-params",
            TEST_ADDR
        )))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    let created_assets = body["created-assets"]
        .as_array()
        .expect("created-assets must still be present");
    assert_eq!(created_assets.len(), 1);
    assert_eq!(created_assets[0]["index"].as_u64(), Some(2));
    assert!(
        created_assets[0].get("params").is_none(),
        "params key must be entirely absent, not null: {:?}",
        created_assets[0]
    );

    // Other resource lists (created-apps, assets, apps-local-state) are
    // unaffected by this single granular exclusion.
    assert!(body.get("created-apps").is_some());
    assert!(
        body["created-apps"][0].get("params").is_some(),
        "created-apps params must still be present — only assets params were excluded"
    );
}

/// Mirrors the assets test above for `exclude=created-apps-params`.
#[tokio::test]
async fn account_info_exclude_created_apps_params_omits_only_params() {
    let server =
        TestServer::start(mock_node_with_account(lookup_with_one_of_each_resource())).await;

    let resp = server
        .client
        .get(server.url(&format!(
            "/v2/accounts/{}?exclude=created-apps-params",
            TEST_ADDR
        )))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    let created_apps = body["created-apps"]
        .as_array()
        .expect("created-apps must still be present");
    assert_eq!(created_apps.len(), 1);
    assert_eq!(created_apps[0]["id"].as_u64(), Some(4));
    assert!(
        created_apps[0].get("params").is_none(),
        "params key must be entirely absent, not null: {:?}",
        created_apps[0]
    );

    assert!(body.get("created-assets").is_some());
    assert!(
        body["created-assets"][0].get("params").is_some(),
        "created-assets params must still be present — only apps params were excluded"
    );
}

/// Both granular values combine (comma-separated, `collectionFormat: csv`
/// per `algod.oas2.json`) to exclude both at once.
#[tokio::test]
async fn account_info_exclude_both_granular_values_combine() {
    let server =
        TestServer::start(mock_node_with_account(lookup_with_one_of_each_resource())).await;

    let resp = server
        .client
        .get(server.url(&format!(
            "/v2/accounts/{}?exclude=created-apps-params,created-assets-params",
            TEST_ADDR
        )))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    assert!(body["created-apps"][0].get("params").is_none());
    assert!(body["created-assets"][0].get("params").is_none());
    // The resources themselves are still listed by ID/index.
    assert_eq!(body["created-apps"][0]["id"].as_u64(), Some(4));
    assert_eq!(body["created-assets"][0]["index"].as_u64(), Some(2));
}

/// `all`/`none` must not combine with other values or with each other —
/// go-algorand v4.6.0-stable's handler rejects this explicitly.
#[tokio::test]
async fn account_info_exclude_all_cannot_combine_with_other_values() {
    let server = TestServer::start(MockNode::synced()).await;

    for combo in [
        "all,created-apps-params",
        "none,created-apps-params",
        "all,none",
    ] {
        let resp = server
            .client
            .get(server.url(&format!("/v2/accounts/{}?exclude={}", TEST_ADDR, combo)))
            .header("X-Algo-API-Token", &server.api_token)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            400,
            "exclude={combo} should be rejected as invalid"
        );
    }
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

/// A mutated/tampered address: same length (58 chars) and valid base32
/// alphabet as `TEST_ADDR`, but with the first payload character flipped
/// (`A` -> `B`), which changes the encoded public key without updating the
/// trailing 4-byte checksum. This must be rejected exactly like a
/// structurally malformed address (issue #827 theme 1): go-algorand's
/// generated router binds the `address` path param via
/// `runtime.BindStyledParameterWithOptions` -> `basics.Address.UnmarshalText`
/// -> `UnmarshalChecksumAddress`, which recomputes
/// `SHA512/256(pubkey)[28..32]` and compares it to the trailing 4 bytes
/// (`daemon/algod/api/server/v2/generated/.../routes.go` +
/// `data/basics/address.go`), returning 400
/// "Invalid format for parameter address: ..." on any mismatch -- it does
/// not distinguish "garbage string" from "right shape, wrong checksum".
/// algod-rust's `Address::from_str` (`crates/core/algo-types/src/address.rs`)
/// performs the identical checksum recomputation and is exercised by the
/// same handler-level parse-failure path as `account_info_invalid_address_returns_400`.
#[tokio::test]
async fn account_info_mutated_checksum_address_returns_400() {
    let server = TestServer::start(MockNode::synced()).await;

    let mut mutated: Vec<char> = TEST_ADDR.chars().collect();
    assert_eq!(mutated.len(), 58, "TEST_ADDR must be a full-length address");
    mutated[0] = if mutated[0] == 'A' { 'B' } else { 'A' };
    let mutated_addr: String = mutated.into_iter().collect();
    assert_ne!(mutated_addr, TEST_ADDR);
    // Sanity check: the mutation really does break the checksum, not just
    // the test's own bookkeeping.
    assert!(
        mutated_addr.parse::<Address>().is_err(),
        "mutated address should fail checksum validation"
    );

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}", mutated_addr)))
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
            ..Default::default()
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

/// Matches go-algorand's `TestNilStateProofInParticipationInfo`
/// (`test/e2e-go/restAPI/stateproof/stateproofRestAPI_test.go`): an account
/// that has registered participation keys (via keyreg) without a
/// `StateProofKey` must report `participation` with `state-proof-key`
/// entirely absent, not present-but-null or present-but-empty.
#[tokio::test]
async fn account_info_participation_without_state_proof_key_omits_field() {
    let mut vote_id = [0u8; 32];
    vote_id[0] = 0xAA;
    vote_id[31] = 0xBB;

    let mut selection_id = [0u8; 32];
    selection_id[0] = 0xCC;

    let lookup = AccountLookup {
        account_data: AccountData {
            micro_algos: 5_000_000,
            status: algo_types::AccountStatus::Online,
            vote_id: Some(vote_id),
            selection_id: Some(selection_id),
            state_proof_id: None,
            vote_first_valid: 1,
            vote_last_valid: 20,
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

    let participation = body
        .get("participation")
        .expect("participation should be present for online account with vote_id");
    assert!(
        participation.get("state-proof-key").is_none(),
        "state-proof-key must be entirely absent when the account has no state proof key, \
         got: {participation:?}"
    );

    // Sanity: the other participation fields are still present.
    assert!(participation.get("vote-participation-key").is_some());
    assert!(participation.get("selection-participation-key").is_some());
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
            ..Default::default()
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

// ---------------------------------------------------------------------------
// Application boxes cursor pagination + prefix tests (issue #536)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_application_boxes_paginates_across_multiple_pages_without_dup_or_gap() {
    let mut node = MockNode::synced();
    let mut boxes = BTreeMap::new();
    for i in 0..5u8 {
        boxes.insert(vec![b'a' + i], vec![i]);
    }
    node.box_store.insert(400, boxes);
    let server = TestServer::start(node).await;

    // Page 1: limit=2.
    let resp = server
        .client
        .get(server.url("/v2/applications/400/boxes?limit=2"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let page1: Vec<String> = body["boxes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(page1.len(), 2);
    let next_token = body["next-token"]
        .as_str()
        .expect("expected next-token on non-final page")
        .to_string();
    assert_eq!(body["round"].as_u64().unwrap(), 1000);

    // Page 2: use next-token from page 1.
    let resp = server
        .client
        .get(server.url(&format!(
            "/v2/applications/400/boxes?limit=2&next={}",
            urlencoding_encode(&next_token)
        )))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let page2: Vec<String> = body["boxes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(page2.len(), 2);
    let next_token2 = body["next-token"]
        .as_str()
        .expect("expected next-token on non-final page")
        .to_string();

    // Page 3: final page, no more data -> no next-token.
    let resp = server
        .client
        .get(server.url(&format!(
            "/v2/applications/400/boxes?limit=2&next={}",
            urlencoding_encode(&next_token2)
        )))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let page3: Vec<String> = body["boxes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(page3.len(), 1);
    assert!(
        body.get("next-token").is_none(),
        "final page must not carry a next-token"
    );

    // Concatenating all pages must reproduce all 5 boxes, in ascending
    // order, with no duplicates and no gaps.
    let mut all = page1;
    all.extend(page2);
    all.extend(page3);
    let expected: Vec<String> = (0..5u8)
        .map(|i| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, vec![b'a' + i]))
        .collect();
    assert_eq!(all, expected);
}

#[tokio::test]
async fn get_application_boxes_filters_by_prefix() {
    let mut node = MockNode::synced();
    let mut boxes = BTreeMap::new();
    boxes.insert(b"foo1".to_vec(), b"v1".to_vec());
    boxes.insert(b"foo2".to_vec(), b"v2".to_vec());
    boxes.insert(b"bar1".to_vec(), b"v3".to_vec());
    node.box_store.insert(401, boxes);
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/401/boxes?prefix=str:foo"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let names: Vec<Vec<u8>> = body["boxes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                b["name"].as_str().unwrap(),
            )
            .unwrap()
        })
        .collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&b"foo1".to_vec()));
    assert!(names.contains(&b"foo2".to_vec()));
    assert!(!names.contains(&b"bar1".to_vec()));
}

#[tokio::test]
async fn get_application_boxes_include_values_returns_box_values() {
    let mut node = MockNode::synced();
    let mut boxes = BTreeMap::new();
    boxes.insert(b"mybox".to_vec(), b"myvalue".to_vec());
    node.box_store.insert(402, boxes);
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/402/boxes?include=values"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let boxes = body["boxes"].as_array().unwrap();
    assert_eq!(boxes.len(), 1);
    let value = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        boxes[0]["value"].as_str().expect("value field present"),
    )
    .unwrap();
    assert_eq!(value, b"myvalue");
}

#[tokio::test]
async fn get_application_boxes_without_include_values_omits_value_field() {
    let mut node = MockNode::synced();
    let mut boxes = BTreeMap::new();
    boxes.insert(b"mybox".to_vec(), b"myvalue".to_vec());
    node.box_store.insert(403, boxes);
    let server = TestServer::start(node).await;

    // `limit` alone (no `include`) opts into pagination mode, but values
    // must stay absent from the response.
    let resp = server
        .client
        .get(server.url("/v2/applications/403/boxes?limit=10"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let boxes = body["boxes"].as_array().unwrap();
    assert_eq!(boxes.len(), 1);
    assert!(
        boxes[0].get("value").is_none(),
        "value field must be omitted when `values` isn't requested"
    );
}

#[tokio::test]
async fn get_application_boxes_legacy_call_shape_unaffected_by_pagination_feature() {
    // No pagination params at all: response must match the pre-#536 shape
    // exactly -- no "next-token"/"round" fields, and box descriptors carry
    // no "value" field.
    let mut node = MockNode::synced();
    let box_names = vec![b"box1".to_vec(), b"box2".to_vec(), b"box3".to_vec()];
    node.keys_by_prefix.insert(404, (box_names, 1000));
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/404/boxes"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["boxes"].as_array().unwrap().len(), 3);
    assert!(
        body.get("next-token").is_none(),
        "legacy call shape must not include next-token"
    );
    assert!(
        body.get("round").is_none(),
        "legacy call shape must not include round"
    );
    for b in body["boxes"].as_array().unwrap() {
        assert!(b.get("value").is_none());
    }
}

#[tokio::test]
async fn get_application_boxes_round_greater_than_latest_returns_400() {
    let node = MockNode::synced(); // status.last_round == 1000
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/405/boxes?round=1001"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["message"].as_str().unwrap(),
        "given round is greater than the latest round"
    );
}

/// Issue #570: a `round` strictly older than latest, but within the node's
/// retained lookback window, now serves real historical box data instead
/// of the old blanket 400 (issue #552's investigated finding, resolved by
/// wiring `StateDelta.kv_mods` through to `lookup_kv_pairs_by_prefix_at_round`).
#[tokio::test]
async fn get_application_boxes_round_older_than_latest_serves_historical_data() {
    let mut node = MockNode::synced(); // status.last_round == 1000
    node.historical_box_store.insert(
        (406, 999),
        BTreeMap::from([(b"mybox".to_vec(), b"historical-value".to_vec())]),
    );
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/406/boxes?round=999&include=values"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["round"].as_u64().unwrap(), 999);
    let boxes = body["boxes"].as_array().unwrap();
    assert_eq!(boxes.len(), 1);

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let name = STANDARD.decode(boxes[0]["name"].as_str().unwrap()).unwrap();
    assert_eq!(name, b"mybox");
    let value = STANDARD
        .decode(boxes[0]["value"].as_str().unwrap())
        .unwrap();
    assert_eq!(value, b"historical-value");
}

/// A `round` strictly older than latest that the node cannot reconstruct
/// (outside its retained delta-cache lookback window, or the round was
/// never cached) still 400s, but for the window-boundary reason rather
/// than a blanket "not supported" -- mirroring go-algorand's own
/// `RoundOffsetError` for a round older than `accountUpdates.deltas`'
/// bounded lookback (issue #570's acceptance criterion).
#[tokio::test]
async fn get_application_boxes_round_outside_lookback_window_returns_400() {
    let node = MockNode::synced(); // status.last_round == 1000, no historical_box_store entry
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/applications/406/boxes?round=1"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    let message = body["message"].as_str().unwrap();
    assert!(
        message.contains("lookback window") || message.contains("outside"),
        "expected a window-boundary-specific message, got: {message}"
    );
}

/// Minimal percent-encoding for a `next-token` string (contains only
/// base64 alphabet characters plus `:` and possibly `+`, `/`, `=`) when
/// used as a raw query-string value in these tests.
fn urlencoding_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '+' => "%2B".to_string(),
            '/' => "%2F".to_string(),
            '=' => "%3D".to_string(),
            ':' => "%3A".to_string(),
            c => c.to_string(),
        })
        .collect()
}

// ===========================================================================
// Block endpoint tests: GET /v2/blocks/{round}
// ===========================================================================

/// Helper: create a minimal mock block at the given round with optional transactions.
fn make_test_block(round: u64, txns: Vec<SignedTransaction>) -> Block {
    Block {
        round: Round(round),
        genesis_id: "testnet-v1.0".to_string(),
        genesis_hash: [0xAB; 32],
        current_protocol: algo_types::CONSENSUS_V41.to_string(),
        timestamp: 1_700_000_000,
        payset: txns,
        ..Block::default()
    }
}

/// Helper: create a minimal mock block header at the given round.
fn make_test_block_header(round: u64) -> BlockHeader {
    BlockHeader {
        round: Round(round),
        genesis_id: "testnet-v1.0".to_string(),
        genesis_hash: [0xAB; 32],
        current_protocol: algo_types::CONSENSUS_V41.to_string(),
        timestamp: 1_700_000_000,
        ..BlockHeader::default()
    }
}

/// Helper: create a simple payment transaction for testing.
fn make_test_signed_txn() -> SignedTransaction {
    let txn = Transaction {
        txn_type: TxnType::Pay,
        sender: Address([1u8; 32]),
        fee: 1000,
        first_valid: Round(1),
        last_valid: Round(1000),
        genesis_id: "testnet-v1.0".to_string(),
        genesis_hash: [0xAB; 32],
        ..Transaction::default()
    };

    SignedTransaction {
        txn,
        has_genesis_id: true,
        has_genesis_hash: true,
        ..SignedTransaction::default()
    }
}

#[tokio::test]
async fn get_block_json_happy_path() {
    let mut node = MockNode::synced();
    let block = make_test_block(1, vec![make_test_signed_txn()]);
    node.blocks.insert(1, block);
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/1"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    // Response has a "block" envelope
    assert!(
        body.get("block").is_some(),
        "response should have 'block' field"
    );
    let block_val = &body["block"];
    assert_eq!(block_val["rnd"].as_u64().unwrap(), 1);
    assert_eq!(block_val["gen"].as_str().unwrap(), "testnet-v1.0");

    // go-algorand only includes the certificate in msgpack format responses.
    // JSON responses must NOT have a "cert" field (see BlockResponseJSON in handlers.go).
    assert!(
        body.get("cert").is_none(),
        "JSON response should NOT contain 'cert' -- cert is only in msgpack format"
    );
}

#[tokio::test]
async fn get_block_header_only() {
    let mut node = MockNode::synced();
    let header = make_test_block_header(1);
    node.block_headers.insert(1, header);
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/1?header-only=true"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("block").is_some(),
        "response should have 'block' field"
    );
    let block_val = &body["block"];
    assert_eq!(block_val["rnd"].as_u64().unwrap(), 1);
    // Header-only should not have "txns" (payset)
    assert!(
        block_val.get("txns").is_none(),
        "header-only response should not have 'txns'"
    );
}

#[tokio::test]
async fn get_block_msgpack_format() {
    let mut node = MockNode::synced();
    let raw_bytes = vec![0x82, 0xa5, 0x62, 0x6c, 0x6f, 0x63, 0x6b]; // some raw msgpack bytes
    node.block_raw_msgpack.insert(1, raw_bytes.clone());
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/1?format=msgpack"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Check content-type and X-Algorand-Struct headers
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/msgpack"
    );
    assert_eq!(
        resp.headers()
            .get("X-Algorand-Struct")
            .unwrap()
            .to_str()
            .unwrap(),
        "block-v1"
    );

    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), raw_bytes.as_slice());
}

#[tokio::test]
async fn get_block_not_found() {
    let node = MockNode::synced();
    // No blocks inserted -- round 999 does not exist
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/999"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn get_block_requires_auth() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/1"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ===========================================================================
// Block hash endpoint tests: GET /v2/blocks/{round}/hash
// ===========================================================================

#[tokio::test]
async fn get_block_hash_happy_path() {
    let mut node = MockNode::synced();
    let digest = Digest([0xDE; 32]);
    node.block_hashes.insert(1, digest);
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/1/hash"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let hash_str = body["blockHash"].as_str().unwrap();
    // Should be base32-no-pad encoding of [0xDE; 32]
    let expected = data_encoding::BASE32_NOPAD.encode(&[0xDE; 32]);
    assert_eq!(hash_str, expected);
}

#[tokio::test]
async fn get_block_hash_not_found() {
    let node = MockNode::synced();
    // No block hashes inserted
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/999/hash"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn get_block_hash_requires_auth() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/1/hash"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ===========================================================================
// Block txids endpoint tests: GET /v2/blocks/{round}/txids
// ===========================================================================

#[tokio::test]
async fn get_block_txids_happy_path() {
    let mut node = MockNode::synced();
    let stxn = make_test_signed_txn();
    let block = make_test_block(1, vec![stxn.clone()]);
    node.blocks.insert(1, block);
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/1/txids"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let txids = body["blockTxids"].as_array().unwrap();
    assert_eq!(txids.len(), 1);
    // Each txid should be a base32-encoded string
    let txid_str = txids[0].as_str().unwrap();
    assert!(!txid_str.is_empty(), "txid should be non-empty");
    // Verify it's valid base32 (no padding)
    assert!(
        data_encoding::BASE32_NOPAD
            .decode(txid_str.as_bytes())
            .is_ok(),
        "txid should be valid base32"
    );
}

#[tokio::test]
async fn get_block_txids_empty_block() {
    let mut node = MockNode::synced();
    let block = make_test_block(1, vec![]);
    node.blocks.insert(1, block);
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/1/txids"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let txids = body["blockTxids"].as_array().unwrap();
    assert!(txids.is_empty(), "empty block should have no txids");
}

#[tokio::test]
async fn get_block_txids_requires_auth() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/1/txids"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ===========================================================================
// Block logs endpoint tests: GET /v2/blocks/{round}/logs
// ===========================================================================

#[tokio::test]
async fn get_block_logs_happy_path() {
    let mut node = MockNode::synced();

    // Create an app call transaction with logs in eval_delta
    let mut stxn = make_test_signed_txn();
    stxn.txn.txn_type = TxnType::Appl;
    stxn.txn.application_id = 42;

    // Build an eval_delta with "lg" (logs) array
    let log_entry = rmpv::Value::Binary(b"hello world".to_vec());
    let eval_delta = rmpv::Value::Map(vec![(
        rmpv::Value::String("lg".into()),
        rmpv::Value::Array(vec![log_entry]),
    )]);
    stxn.eval_delta = Some(eval_delta);

    let block = make_test_block(1, vec![stxn]);
    node.blocks.insert(1, block);
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/1/logs"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let logs = body["logs"].as_array().unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0]["application-index"].as_u64().unwrap(), 42);
    assert!(!logs[0]["txId"].as_str().unwrap().is_empty());
    // logs[0]["logs"] should be an array with one base64-encoded entry
    let log_entries = logs[0]["logs"].as_array().unwrap();
    assert_eq!(log_entries.len(), 1);
}

#[tokio::test]
async fn get_block_logs_no_logs() {
    let mut node = MockNode::synced();

    // Create a payment transaction (no logs)
    let stxn = make_test_signed_txn();
    let block = make_test_block(1, vec![stxn]);
    node.blocks.insert(1, block);
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/1/logs"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let logs = body["logs"].as_array().unwrap();
    assert!(
        logs.is_empty(),
        "block with no app calls should have empty logs"
    );
}

#[tokio::test]
async fn get_block_logs_requires_auth() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/1/logs"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ===========================================================================
// Transaction proof endpoint tests: GET /v2/blocks/{round}/transactions/{txid}/proof
// ===========================================================================

#[tokio::test]
async fn get_transaction_proof_happy_path() {
    let mut node = MockNode::synced();

    let stxn = make_test_signed_txn();

    // Compute the expected transaction ID so we can request the proof.
    let txid = algo_codec::compute_txn_id(&stxn.txn);
    let txid_str = txid.to_string();

    let block = make_test_block(1, vec![stxn]);
    node.blocks.insert(1, block);
    let server = TestServer::start(node).await;

    let url = format!("/v2/blocks/1/transactions/{}/proof", txid_str);
    let resp = server
        .client
        .get(server.url(&url))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["idx"].as_u64().unwrap(), 0);
    assert!(body.get("proof").is_some(), "should have 'proof' field");
    assert!(
        body.get("stibhash").is_some(),
        "should have 'stibhash' field"
    );
    assert!(
        body.get("treedepth").is_some(),
        "should have 'treedepth' field"
    );
    assert_eq!(body["hashtype"].as_str().unwrap(), "sha512_256");
}

#[tokio::test]
async fn get_transaction_proof_txid_not_found() {
    let mut node = MockNode::synced();

    let stxn = make_test_signed_txn();
    let block = make_test_block(1, vec![stxn]);
    node.blocks.insert(1, block);
    let server = TestServer::start(node).await;

    // Use a txid that doesn't match any transaction in the block
    let fake_txid = data_encoding::BASE32_NOPAD.encode(&[0xFF; 32]);
    let url = format!("/v2/blocks/1/transactions/{}/proof", fake_txid);
    let resp = server
        .client
        .get(server.url(&url))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("could not find the transaction"),
        "error should mention transaction not found"
    );
}

#[tokio::test]
async fn get_transaction_proof_requires_auth() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let fake_txid = data_encoding::BASE32_NOPAD.encode(&[0xFF; 32]);
    let url = format!("/v2/blocks/1/transactions/{}/proof", fake_txid);
    let resp = server.client.get(server.url(&url)).send().await.unwrap();
    assert_eq!(resp.status(), 401);
}

// Mirrors go-algorand's TestTxnMerkleProof, which — in addition to the
// default sha512_256 proof (covered by get_transaction_proof_happy_path
// above) — requests a `?hashtype=sha256` proof and verifies it against
// `merklearray.VerifyVectorCommitment`. At the algod-rust reference pin
// (v5.0.0-stable / consensus V42), `EnableSHA256TxnCommitmentHeader` has
// been true since V34, so this is a happy-path 200, not a rejection.
#[tokio::test]
async fn get_transaction_proof_sha256_happy_path() {
    let mut node = MockNode::synced();

    let stxn = make_test_signed_txn();
    let txid = algo_codec::compute_txn_id(&stxn.txn);
    let txid_str = txid.to_string();

    let block = make_test_block(1, vec![stxn]);
    node.blocks.insert(1, block);
    let server = TestServer::start(node).await;

    let url = format!(
        "/v2/blocks/1/transactions/{}/proof?hashtype=sha256",
        txid_str
    );
    let resp = server
        .client
        .get(server.url(&url))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["idx"].as_u64().unwrap(), 0);
    assert!(body.get("proof").is_some(), "should have 'proof' field");
    assert_eq!(body["hashtype"].as_str().unwrap(), "sha256");
}

// Mirrors go-algorand's TestTxnMerkleProofSHA256, which uses an older
// network template (pre-V34 consensus, before EnableSHA256TxnCommitmentHeader
// existed) and asserts the block's Sha256Commitment stays empty. The
// closest algod-rust equivalent is requesting `?hashtype=sha256` against a
// block on a consensus version that predates V34 and confirming the
// handler rejects it (`proto.enable_sha256_txn_commitment_header == false`).
#[tokio::test]
async fn get_transaction_proof_sha256_rejected_on_pre_v34_protocol() {
    let mut node = MockNode::synced();

    let stxn = make_test_signed_txn();
    let txid = algo_codec::compute_txn_id(&stxn.txn);
    let txid_str = txid.to_string();

    let mut block = make_test_block(1, vec![stxn]);
    block.current_protocol = algo_types::consensus::CONSENSUS_V32.to_string();
    node.blocks.insert(1, block);
    let server = TestServer::start(node).await;

    let url = format!(
        "/v2/blocks/1/transactions/{}/proof?hashtype=sha256",
        txid_str
    );
    let resp = server
        .client
        .get(server.url(&url))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("sha256 vector commitment"),
        "message: {}",
        body["message"]
    );
}

// ===========================================================================
// Light block header proof endpoint tests: GET /v2/blocks/{round}/lightheader/proof
// ===========================================================================

#[tokio::test]
async fn get_light_block_header_proof_happy_path() {
    let mut node = MockNode::synced();

    // Set up state proof transaction covering rounds 1-4
    node.state_proof_txns.insert(2, (1, 4));

    // Add block headers for all rounds in the range
    for r in 1..=4 {
        node.block_headers.insert(r, make_test_block_header(r));
    }

    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/2/lightheader/proof"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.get("index").is_some(), "should have 'index' field");
    assert!(body.get("proof").is_some(), "should have 'proof' field");
    assert!(
        body.get("treedepth").is_some(),
        "should have 'treedepth' field"
    );
    // index should be relative to first_attested_round
    assert_eq!(body["index"].as_u64().unwrap(), 1); // round 2 - first_attested 1 = 1
}

#[tokio::test]
async fn get_light_block_header_proof_no_state_proof() {
    let node = MockNode::synced();
    // No state proof transaction configured for any round
    // But status.last_round is 1000, so round 5 is valid
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/5/lightheader/proof"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    // Should return an error (no state proof found)
    assert!(
        resp.status() == 404 || resp.status() == 500,
        "should return error when no state proof is available, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn get_light_block_header_proof_requires_auth() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/1/lightheader/proof"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ===========================================================================
// Protocol-codec msgpack integration tests
// ===========================================================================

/// Helper: extract the top-level map keys from an rmpv Value.
fn extract_map_keys(val: &rmpv::Value) -> Vec<String> {
    match val {
        rmpv::Value::Map(entries) => entries
            .iter()
            .filter_map(|(k, _)| match k {
                rmpv::Value::String(s) => s.as_str().map(|s| s.to_string()),
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

/// Helper: find a nested map value by key in an rmpv Value.
fn find_map_value<'a>(val: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    match val {
        rmpv::Value::Map(entries) => entries.iter().find_map(|(k, v)| match k {
            rmpv::Value::String(s) if s.as_str() == Some(key) => Some(v),
            _ => None,
        }),
        _ => None,
    }
}

#[tokio::test]
async fn account_msgpack_uses_protocol_codec_tags() {
    // Set up account with non-zero balance so "algo" field is present
    let lookup = AccountLookup {
        account_data: AccountData {
            micro_algos: 5_000_000,
            status: algo_types::AccountStatus::Online,
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
        .get(server.url(&format!("/v2/accounts/{}?format=msgpack", TEST_ADDR)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/msgpack"
    );

    let body = resp.bytes().await.unwrap();
    let val = rmpv::decode::read_value(&mut &body[..]).expect("valid msgpack");

    let keys = extract_map_keys(&val);
    // Protocol-codec short tag "algo" must be present (non-zero balance)
    assert!(
        keys.contains(&"algo".to_string()),
        "protocol-codec account msgpack should contain 'algo' field, got keys: {:?}",
        keys
    );
    // Protocol-codec short tag "onl" for status (Online = 1, non-zero so present)
    assert!(
        keys.contains(&"onl".to_string()),
        "protocol-codec account msgpack should contain 'onl' field, got keys: {:?}",
        keys
    );
    // Verify long serde names are NOT present
    assert!(
        !keys.contains(&"amount".to_string()),
        "protocol-codec account msgpack should NOT contain serde 'amount' field"
    );
    assert!(
        !keys.contains(&"status".to_string()),
        "protocol-codec account msgpack should NOT contain serde 'status' field"
    );
}

#[tokio::test]
async fn account_asset_msgpack_uses_protocol_codec_tags() {
    let addr: Address = TEST_ADDR.parse().unwrap();
    let lookup = AssetResourceLookup {
        asset_holding: Some(AssetHolding {
            amount: 1000,
            frozen: true,
        }),
        asset_params: Some(AssetParams {
            total: 1_000_000,
            unit_name: "TST".to_string(),
            asset_name: "TestAsset".to_string(),
            ..AssetParams::default()
        }),
        last_round: 1000,
    };
    let server = TestServer::start(mock_node_with_asset_resource(&addr, 42, lookup)).await;

    let resp = server
        .client
        .get(server.url(&format!(
            "/v2/accounts/{}/assets/42?format=msgpack",
            TEST_ADDR
        )))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/msgpack"
    );

    let body = resp.bytes().await.unwrap();
    let val = rmpv::decode::read_value(&mut &body[..]).expect("valid msgpack");

    let keys = extract_map_keys(&val);
    // Protocol-codec model uses "asset-holding" and "asset-params" as envelope keys
    assert!(
        keys.contains(&"asset-holding".to_string()),
        "account asset msgpack should contain 'asset-holding' key, got: {:?}",
        keys
    );
    assert!(
        keys.contains(&"asset-params".to_string()),
        "account asset msgpack should contain 'asset-params' key, got: {:?}",
        keys
    );

    // Verify the nested holding uses protocol-codec short tags ("a", "f")
    let holding_val = find_map_value(&val, "asset-holding").unwrap();
    let holding_keys = extract_map_keys(holding_val);
    assert!(
        holding_keys.contains(&"a".to_string()),
        "asset-holding should have 'a' (amount) key, got: {:?}",
        holding_keys
    );
    assert!(
        holding_keys.contains(&"f".to_string()),
        "asset-holding should have 'f' (frozen) key, got: {:?}",
        holding_keys
    );

    // Verify the nested params uses protocol-codec short tags ("an", "t", "un")
    let params_val = find_map_value(&val, "asset-params").unwrap();
    let params_keys = extract_map_keys(params_val);
    assert!(
        params_keys.contains(&"an".to_string()),
        "asset-params should have 'an' (asset name) key, got: {:?}",
        params_keys
    );
    assert!(
        params_keys.contains(&"t".to_string()),
        "asset-params should have 't' (total) key, got: {:?}",
        params_keys
    );
    assert!(
        params_keys.contains(&"un".to_string()),
        "asset-params should have 'un' (unit name) key, got: {:?}",
        params_keys
    );
}

#[tokio::test]
async fn account_app_msgpack_uses_protocol_codec_tags() {
    let addr: Address = TEST_ADDR.parse().unwrap();
    let lookup = AppResourceLookup {
        app_local_state: Some(AppLocalState {
            schema: StateSchema {
                num_uint: 2,
                num_byte_slice: 1,
            },
            key_value: BTreeMap::new(),
        }),
        app_params: Some(AppParams {
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
            creator: Address([0u8; 32]),
            ..Default::default()
        }),
        last_round: 1000,
    };
    let server = TestServer::start(mock_node_with_app_resource(&addr, 100, lookup)).await;

    let resp = server
        .client
        .get(server.url(&format!(
            "/v2/accounts/{}/applications/100?format=msgpack",
            TEST_ADDR
        )))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/msgpack"
    );

    let body = resp.bytes().await.unwrap();
    let val = rmpv::decode::read_value(&mut &body[..]).expect("valid msgpack");

    let keys = extract_map_keys(&val);
    // Protocol-codec model uses "app-local-state" and "app-params" as envelope keys
    assert!(
        keys.contains(&"app-local-state".to_string()),
        "account app msgpack should contain 'app-local-state' key, got: {:?}",
        keys
    );
    assert!(
        keys.contains(&"app-params".to_string()),
        "account app msgpack should contain 'app-params' key, got: {:?}",
        keys
    );

    // Verify nested app-params uses protocol-codec short tags
    let app_params_val = find_map_value(&val, "app-params").unwrap();
    let app_keys = extract_map_keys(app_params_val);
    assert!(
        app_keys.contains(&"approv".to_string()),
        "app-params should have 'approv' key, got: {:?}",
        app_keys
    );
    assert!(
        app_keys.contains(&"clearp".to_string()),
        "app-params should have 'clearp' key, got: {:?}",
        app_keys
    );

    // Verify nested app-local-state uses protocol-codec short tags
    let als_val = find_map_value(&val, "app-local-state").unwrap();
    let als_keys = extract_map_keys(als_val);
    assert!(
        als_keys.contains(&"hsch".to_string()),
        "app-local-state should have 'hsch' (schema) key, got: {:?}",
        als_keys
    );
}

#[tokio::test]
async fn block_header_only_msgpack_uses_protocol_codec_tags() {
    let mut node = MockNode::synced();
    let header = make_test_block_header(1);
    node.block_headers.insert(1, header);
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/blocks/1?format=msgpack&header-only=true"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/msgpack"
    );

    let body = resp.bytes().await.unwrap();
    let val = rmpv::decode::read_value(&mut &body[..]).expect("valid msgpack");

    // Top-level should be a map with a "block" key (envelope)
    let keys = extract_map_keys(&val);
    assert!(
        keys.contains(&"block".to_string()),
        "block header-only msgpack should have 'block' envelope key, got: {:?}",
        keys
    );

    // Inside the "block" envelope, verify protocol-codec short tags
    let block_val = find_map_value(&val, "block").unwrap();
    let block_keys = extract_map_keys(block_val);
    // "rnd" should be present (round = 1, non-zero)
    assert!(
        block_keys.contains(&"rnd".to_string()),
        "block header should have 'rnd' key, got: {:?}",
        block_keys
    );
    // "gen" should be present (genesis_id is non-empty)
    assert!(
        block_keys.contains(&"gen".to_string()),
        "block header should have 'gen' key, got: {:?}",
        block_keys
    );
    // "proto" should be present (current_protocol is non-empty)
    assert!(
        block_keys.contains(&"proto".to_string()),
        "block header should have 'proto' key, got: {:?}",
        block_keys
    );
    // "gh" should be present (genesis_hash is non-zero)
    assert!(
        block_keys.contains(&"gh".to_string()),
        "block header should have 'gh' key, got: {:?}",
        block_keys
    );
    // Verify long serde names are NOT present
    assert!(
        !block_keys.contains(&"round".to_string()),
        "block header should NOT have serde 'round' field"
    );
    assert!(
        !block_keys.contains(&"genesis-id".to_string()),
        "block header should NOT have serde 'genesis-id' field"
    );
}

// ===========================================================================
// Supply endpoint tests
// ===========================================================================

#[tokio::test]
async fn supply_success() {
    let mut node = MockNode::synced();
    node.supply_info = Some(SupplyInfo {
        round: 42,
        total_money: 10_000_000_000,
        online_money: 5_000_000_000,
        online_stake: 4_500_000_000,
    });
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/ledger/supply"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["current_round"], 42);
    assert_eq!(body["online-money"], 5_000_000_000u64);
    assert_eq!(body["total-money"], 10_000_000_000u64);
    // `online-stake` (go-algorand v4.6.0-stable, issue #508) is the
    // lookback-round online circulation, distinct from `online-money`
    // (the current round's online total) -- assert both are surfaced and
    // can genuinely differ.
    assert_eq!(body["online-stake"], 4_500_000_000u64);
    assert_ne!(body["online-stake"], body["online-money"]);
}

#[tokio::test]
async fn supply_error() {
    // supply_info is None so get_supply() will return an error
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/ledger/supply"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 500);
}

#[tokio::test]
async fn supply_requires_auth() {
    let mut node = MockNode::synced();
    node.supply_info = Some(SupplyInfo {
        round: 1,
        total_money: 100,
        online_money: 50,
        online_stake: 50,
    });
    let server = TestServer::start(node).await;

    // No auth header
    let resp = server
        .client
        .get(server.url("/v2/ledger/supply"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ===========================================================================
// State proof endpoint tests
// ===========================================================================

#[tokio::test]
async fn state_proof_success() {
    let mut node = MockNode::synced();
    node.state_proof_data.insert(
        100,
        StateProofData {
            state_proof: vec![1, 2, 3, 4],
            block_headers_commitment: vec![0xAA, 0xBB],
            voters_commitment: vec![0xCC, 0xDD],
            ln_proven_weight: 12345,
            first_attested_round: 90,
            last_attested_round: 110,
        },
    );
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/stateproofs/100"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    // PascalCase keys
    assert!(body.get("Message").is_some());
    assert!(body.get("StateProof").is_some());

    let msg = &body["Message"];
    assert_eq!(msg["FirstAttestedRound"], 90);
    assert_eq!(msg["LastAttestedRound"], 110);
    assert_eq!(msg["LnProvenWeight"], 12345);

    // StateProof and byte fields should be base64 strings
    assert!(body["StateProof"].is_string());
    assert!(msg["BlockHeadersCommitment"].is_string());
    assert!(msg["VotersCommitment"].is_string());

    // Verify base64 content
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let sp_bytes = STANDARD
        .decode(body["StateProof"].as_str().unwrap())
        .unwrap();
    assert_eq!(sp_bytes, vec![1, 2, 3, 4]);
}

#[tokio::test]
async fn state_proof_round_too_high() {
    // MockNode last_round = 1000, request round 2000
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/stateproofs/2000"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 500);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("given round is greater than the latest round"),);
}

#[tokio::test]
async fn state_proof_not_found() {
    // Round 100 is within range but no state proof data configured
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/stateproofs/100"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["message"].as_str().unwrap().contains("no state proof"));
}

#[tokio::test]
async fn state_proof_requires_auth() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/stateproofs/100"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ===========================================================================
// Transaction submission and pending transaction endpoint tests
// ===========================================================================

/// Helper: encode a SignedTransaction to canonical msgpack bytes suitable for
/// POST /v2/transactions.
fn encode_signed_txn_for_post(stxn: &SignedTransaction) -> Vec<u8> {
    algo_codec::canonical_encode_signed_transaction(stxn)
}

// ---------------------------------------------------------------------------
// POST /v2/transactions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn raw_transaction_returns_txid() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let stxn = make_test_signed_txn();
    let expected_txid = algo_codec::compute_txn_id(&stxn.txn).to_string();
    let body = encode_signed_txn_for_post(&stxn);

    let resp = server
        .client
        .post(server.url("/v2/transactions"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/x-binary")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["txId"].as_str().unwrap(), expected_txid);
}

#[tokio::test]
async fn raw_transaction_requires_auth() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let stxn = make_test_signed_txn();
    let body = encode_signed_txn_for_post(&stxn);

    let resp = server
        .client
        .post(server.url("/v2/transactions"))
        .header("Content-Type", "application/x-binary")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn raw_transaction_empty_body_returns_400() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .post(server.url("/v2/transactions"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/x-binary")
        .body(Vec::<u8>::new())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(
        json["message"].as_str().unwrap().contains("empty txgroup"),
        "error should contain 'empty txgroup', got: {}",
        json["message"]
    );
}

#[tokio::test]
async fn raw_transaction_invalid_msgpack_returns_400() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .post(server.url("/v2/transactions"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/x-binary")
        .body(vec![0xFF, 0xFE, 0xFD])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .contains("could not decode transaction"),
        "error should mention decode failure, got: {}",
        json["message"]
    );
}

#[tokio::test]
async fn raw_transaction_catchpoint_returns_503() {
    let node = MockNode::catchpoint_catchup();
    let server = TestServer::start(node).await;

    let stxn = make_test_signed_txn();
    let body = encode_signed_txn_for_post(&stxn);

    let resp = server
        .client
        .post(server.url("/v2/transactions"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/x-binary")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .contains("operation not available during catchup"),
        "error should mention catchup, got: {}",
        json["message"]
    );
}

#[tokio::test]
async fn raw_transaction_broadcast_error_returns_400() {
    let mut node = MockNode::synced();
    node.broadcast_result = Some("transaction already in pool".to_string());
    let server = TestServer::start(node).await;

    let stxn = make_test_signed_txn();
    let body = encode_signed_txn_for_post(&stxn);

    let resp = server
        .client
        .post(server.url("/v2/transactions"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/x-binary")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .contains("transaction already in pool"),
        "error should contain broadcast error message, got: {}",
        json["message"]
    );
}

/// An oversized transaction group: go-algorand's `decodeTxGroup`
/// (`daemon/algod/api/server/v2/handlers.go`) decodes concatenated msgpack
/// `SignedTxn`s one at a time and rejects as soon as the running count
/// exceeds `proto.MaxTxGroupSize` (16 for the current consensus version),
/// with the exact message `fmt.Errorf("max group size is %d", maxTxGroupSize)`
/// -- byte-identical to algod-rust's `raw_transaction` handler
/// (`crates/node/algo-rest-api/src/handlers.rs`:
/// `error::bad_request(format!("max group size is {}", max_group_size))`).
/// `MockNode` doesn't override `max_tx_group_size()`, so the
/// `NodeInterface` default (16, matching go-algorand's consensus default)
/// applies -- 17 valid, independently-encoded transactions must trip it.
#[tokio::test]
async fn raw_transaction_oversized_group_returns_400() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let mut body = Vec::new();
    for i in 0..17u64 {
        let mut stxn = make_test_signed_txn();
        stxn.txn.fee = 1000 + i; // distinct txids, not that it matters here
        body.extend_from_slice(&encode_signed_txn_for_post(&stxn));
    }

    let resp = server
        .client
        .post(server.url("/v2/transactions"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/x-binary")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["message"].as_str().unwrap(), "max group size is 16");
}

/// A transaction group at exactly the group-size limit (16) must still be
/// accepted at the decode stage -- the boundary go-algorand draws is
/// `len(txgroup) > maxTxGroupSize`, i.e. 16 is fine and 17 is not.
#[tokio::test]
async fn raw_transaction_at_group_size_limit_is_accepted() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let mut body = Vec::new();
    for i in 0..16u64 {
        let mut stxn = make_test_signed_txn();
        stxn.txn.fee = 1000 + i;
        body.extend_from_slice(&encode_signed_txn_for_post(&stxn));
    }

    let resp = server
        .client
        .post(server.url("/v2/transactions"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/x-binary")
        .body(body)
        .send()
        .await
        .unwrap();
    // Decoding succeeds (16 == limit); MockNode's default broadcast then
    // accepts, returning the txid of the first transaction in the group.
    assert_eq!(resp.status(), 200);
}

/// A transaction whose fee is below `MinTxnFee` must be rejected as a
/// broadcast (pool/validation) error, surfaced as 400 with the underlying
/// message intact -- exactly like go-algorand's `RawTransaction` handler,
/// which wraps any `Node.BroadcastSignedTxGroup` error as
/// `badRequest(ctx, err, err.Error(), ...)` (`handlers.go`:1273-1276) with
/// no special-casing of *which* validation rule failed. In algod-rust the
/// real (non-mock) fee check lives in
/// `crates/core/algo-validate/src/rules.rs` (`validate_transaction_wellformed`),
/// which produces `"transaction fee {fee} is below minimum {required}"` --
/// this test pins that the REST layer forwards such an error verbatim as
/// 400, using `MockNode.broadcast_result` to stand in for the real
/// pool/validate rejection without needing a live ledger.
#[tokio::test]
async fn raw_transaction_fee_below_minimum_returns_400() {
    let mut node = MockNode::synced();
    node.broadcast_result = Some("transaction fee 1 is below minimum 1000".to_string());
    let server = TestServer::start(node).await;

    let mut stxn = make_test_signed_txn();
    stxn.txn.fee = 1; // well below MinTxnFee (1000)
    let body = encode_signed_txn_for_post(&stxn);

    let resp = server
        .client
        .post(server.url("/v2/transactions"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/x-binary")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(
        json["message"].as_str().unwrap().contains("below minimum"),
        "error should mention the fee being below minimum, got: {}",
        json["message"]
    );
}

/// A transaction from an account without enough balance to cover the
/// payment (and/or fee) must be rejected as a broadcast error, surfaced as
/// 400 -- matching go-algorand's `ledgercore.OverspendError`
/// (`ledger/ledgercore/error.go`: `"overspend (account %v, data %+v, tried
/// to spend %v)"`), which bubbles out of `Node.BroadcastSignedTxGroup` the
/// same way any other pool-remember error does. algod-rust's real ledger
/// apply layer (`crates/core/algo-ledger/src/apply.rs`) produces
/// `"sender {} has insufficient balance {} for payment {}"` for the
/// equivalent case; this test pins that the REST layer forwards that
/// message verbatim as 400 (same passthrough mechanism as the fee-too-low
/// and group-size tests above -- there is no special HTTP status or body
/// shape for insufficient balance specifically, in either implementation).
#[tokio::test]
async fn raw_transaction_insufficient_balance_returns_400() {
    let mut node = MockNode::synced();
    node.broadcast_result = Some(format!(
        "sender {TEST_ADDR} has insufficient balance 0 for payment 5000000"
    ));
    let server = TestServer::start(node).await;

    let stxn = make_test_signed_txn();
    let body = encode_signed_txn_for_post(&stxn);

    let resp = server
        .client
        .post(server.url("/v2/transactions"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/x-binary")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .contains("insufficient balance"),
        "error should mention insufficient balance, got: {}",
        json["message"]
    );
}

// ---------------------------------------------------------------------------
// GET /v2/transactions/pending
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_pending_transactions_returns_list() {
    let mut node = MockNode::synced();
    let stxn1 = make_test_signed_txn();
    let mut stxn2 = make_test_signed_txn();
    stxn2.txn.fee = 2000; // make it distinct
    node.pending_txns = vec![stxn1, stxn2];
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/pending"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["total-transactions"].as_u64().unwrap(), 2);
    let top = json["top-transactions"].as_array().unwrap();
    assert_eq!(top.len(), 2);
}

#[tokio::test]
async fn get_pending_transactions_with_max() {
    let mut node = MockNode::synced();
    let stxn1 = make_test_signed_txn();
    let mut stxn2 = make_test_signed_txn();
    stxn2.txn.fee = 2000;
    node.pending_txns = vec![stxn1, stxn2];
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/pending?max=1"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    // total-transactions reflects full pool size
    assert_eq!(json["total-transactions"].as_u64().unwrap(), 2);
    // but only 1 returned due to max
    let top = json["top-transactions"].as_array().unwrap();
    assert_eq!(top.len(), 1);
}

#[tokio::test]
async fn get_pending_transactions_empty_pool() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/pending"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["total-transactions"].as_u64().unwrap(), 0);
    let top = json["top-transactions"].as_array().unwrap();
    assert_eq!(top.len(), 0);
}

#[tokio::test]
async fn get_pending_transactions_requires_auth() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/pending"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ---------------------------------------------------------------------------
// GET /v2/transactions/pending/:txid
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pending_transaction_info_found() {
    let mut node = MockNode::synced();
    let stxn = make_test_signed_txn();
    let txid = algo_codec::compute_txn_id(&stxn.txn);
    let txid_str = txid.to_string();

    node.pending_txn_lookup.insert(
        txid.0,
        TxnWithStatus {
            txn: stxn,
            confirmed_round: 0,
            pool_error: String::new(),
            closing_amount: 0,
            asset_closing_amount: 0,
            sender_rewards: 0,
            receiver_rewards: 0,
            close_rewards: 0,
            asset_index: None,
            application_index: None,
            eval_delta: None,
            logs: None,
            inner_txns: None,
        },
    );
    let server = TestServer::start(node).await;

    let url = format!("/v2/transactions/pending/{}", txid_str);
    let resp = server
        .client
        .get(server.url(&url))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(
        json.get("txn").is_some(),
        "response should have 'txn' field"
    );
    assert!(
        json.get("pool-error").is_some(),
        "response should have 'pool-error' field"
    );
}

#[tokio::test]
async fn pending_transaction_info_not_found() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let fake_txid = data_encoding::BASE32_NOPAD.encode(&[0xAA; 32]);
    let url = format!("/v2/transactions/pending/{}", fake_txid);
    let resp = server
        .client
        .get(server.url(&url))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .contains("could not find the transaction in the transaction pool"),
        "error should mention transaction not found, got: {}",
        json["message"]
    );
}

#[tokio::test]
async fn pending_transaction_info_invalid_txid() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/transactions/pending/not-a-valid-txid"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .contains("no valid transaction ID was specified"),
        "error should mention invalid txid, got: {}",
        json["message"]
    );
}

// ---------------------------------------------------------------------------
// GET /v2/accounts/:address/transactions/pending
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pending_transactions_by_address_filters() {
    let mut node = MockNode::synced();

    // Create two transactions with different senders
    let mut stxn1 = make_test_signed_txn();
    stxn1.txn.sender = Address([0x01; 32]);

    let mut stxn2 = make_test_signed_txn();
    stxn2.txn.sender = Address([0x02; 32]);

    node.pending_txns = vec![stxn1.clone(), stxn2];
    let server = TestServer::start(node).await;

    // Filter by the first sender's address
    let addr_str = Address([0x01; 32]).to_string();
    let url = format!("/v2/accounts/{}/transactions/pending", addr_str);
    let resp = server
        .client
        .get(server.url(&url))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    // total-transactions is the full pool size (unfiltered)
    assert_eq!(json["total-transactions"].as_u64().unwrap(), 2);
    // but top-transactions should only contain the matching one
    let top = json["top-transactions"].as_array().unwrap();
    assert_eq!(
        top.len(),
        1,
        "should only return transactions matching the address filter"
    );
}

// ---------------------------------------------------------------------------
// Pending transaction eval delta tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pending_transaction_info_with_global_state_delta() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let mut node = MockNode::synced();
    let stxn = make_test_signed_txn();
    let txid = algo_codec::compute_txn_id(&stxn.txn);
    let txid_str = txid.to_string();

    // Build an eval_delta with a global state delta: key="counter", action=1 (SetUint), ui=42
    let eval_delta = rmpv::Value::Map(vec![(
        rmpv::Value::String("gd".into()),
        rmpv::Value::Map(vec![(
            rmpv::Value::Binary(b"counter".to_vec()),
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::String("at".into()),
                    rmpv::Value::Integer(1.into()),
                ),
                (
                    rmpv::Value::String("ui".into()),
                    rmpv::Value::Integer(42.into()),
                ),
            ]),
        )]),
    )]);

    node.pending_txn_lookup.insert(
        txid.0,
        TxnWithStatus {
            txn: stxn,
            confirmed_round: 100,
            pool_error: String::new(),
            closing_amount: 0,
            asset_closing_amount: 0,
            sender_rewards: 0,
            receiver_rewards: 0,
            close_rewards: 0,
            asset_index: None,
            application_index: None,
            eval_delta: Some(eval_delta),
            logs: None,
            inner_txns: None,
        },
    );
    let server = TestServer::start(node).await;

    let url = format!("/v2/transactions/pending/{}", txid_str);
    let resp = server
        .client
        .get(server.url(&url))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    let gsd = json
        .get("global-state-delta")
        .expect("should have global-state-delta");
    let gsd_arr = gsd.as_array().expect("global-state-delta should be array");
    assert_eq!(gsd_arr.len(), 1);

    let entry = &gsd_arr[0];
    assert_eq!(entry["key"].as_str().unwrap(), STANDARD.encode(b"counter"));
    assert_eq!(entry["value"]["action"].as_u64().unwrap(), 1);
    assert_eq!(entry["value"]["uint"].as_u64().unwrap(), 42);
    // bytes should be omitted when empty
    assert!(entry["value"].get("bytes").is_none());
}

#[tokio::test]
async fn pending_transaction_info_with_local_state_delta() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let mut node = MockNode::synced();

    // Create a txn with accounts so local delta address resolution works
    let mut stxn = make_test_signed_txn();
    let account1 = Address([0x02; 32]);
    stxn.txn.accounts = Some(vec![account1]);
    let txid = algo_codec::compute_txn_id(&stxn.txn);
    let txid_str = txid.to_string();

    // Build an eval_delta with local state delta: index=1 (first account), key="balance", action=1, ui=100
    let eval_delta = rmpv::Value::Map(vec![(
        rmpv::Value::String("ld".into()),
        rmpv::Value::Map(vec![(
            rmpv::Value::Integer(1.into()),
            rmpv::Value::Map(vec![(
                rmpv::Value::Binary(b"balance".to_vec()),
                rmpv::Value::Map(vec![
                    (
                        rmpv::Value::String("at".into()),
                        rmpv::Value::Integer(1.into()),
                    ),
                    (
                        rmpv::Value::String("ui".into()),
                        rmpv::Value::Integer(100.into()),
                    ),
                ]),
            )]),
        )]),
    )]);

    node.pending_txn_lookup.insert(
        txid.0,
        TxnWithStatus {
            txn: stxn,
            confirmed_round: 100,
            pool_error: String::new(),
            closing_amount: 0,
            asset_closing_amount: 0,
            sender_rewards: 0,
            receiver_rewards: 0,
            close_rewards: 0,
            asset_index: None,
            application_index: None,
            eval_delta: Some(eval_delta),
            logs: None,
            inner_txns: None,
        },
    );
    let server = TestServer::start(node).await;

    let url = format!("/v2/transactions/pending/{}", txid_str);
    let resp = server
        .client
        .get(server.url(&url))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    let lsd = json
        .get("local-state-delta")
        .expect("should have local-state-delta");
    let lsd_arr = lsd.as_array().expect("local-state-delta should be array");
    assert_eq!(lsd_arr.len(), 1);

    let entry = &lsd_arr[0];
    // Index 1 should resolve to account1 (the first in the accounts array)
    assert_eq!(entry["address"].as_str().unwrap(), account1.to_string());
    let delta = entry["delta"].as_array().unwrap();
    assert_eq!(delta.len(), 1);
    assert_eq!(
        delta[0]["key"].as_str().unwrap(),
        STANDARD.encode(b"balance")
    );
    assert_eq!(delta[0]["value"]["action"].as_u64().unwrap(), 1);
    assert_eq!(delta[0]["value"]["uint"].as_u64().unwrap(), 100);
}

#[tokio::test]
async fn pending_transaction_info_with_logs_from_eval_delta() {
    let mut node = MockNode::synced();
    let stxn = make_test_signed_txn();
    let txid = algo_codec::compute_txn_id(&stxn.txn);
    let txid_str = txid.to_string();

    // Build an eval_delta with logs
    let eval_delta = rmpv::Value::Map(vec![(
        rmpv::Value::String("lg".into()),
        rmpv::Value::Array(vec![
            rmpv::Value::Binary(b"hello".to_vec()),
            rmpv::Value::Binary(b"world".to_vec()),
        ]),
    )]);

    node.pending_txn_lookup.insert(
        txid.0,
        TxnWithStatus {
            txn: stxn,
            confirmed_round: 100,
            pool_error: String::new(),
            closing_amount: 0,
            asset_closing_amount: 0,
            sender_rewards: 0,
            receiver_rewards: 0,
            close_rewards: 0,
            asset_index: None,
            application_index: None,
            eval_delta: Some(eval_delta),
            logs: None, // logs not set directly, should come from eval_delta
            inner_txns: None,
        },
    );
    let server = TestServer::start(node).await;

    let url = format!("/v2/transactions/pending/{}", txid_str);
    let resp = server
        .client
        .get(server.url(&url))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    let logs = json.get("logs").expect("should have logs");
    let logs_arr = logs.as_array().expect("logs should be array");
    assert_eq!(logs_arr.len(), 2);
}

#[tokio::test]
async fn pending_transaction_info_with_bytes_state_delta() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let mut node = MockNode::synced();
    let stxn = make_test_signed_txn();
    let txid = algo_codec::compute_txn_id(&stxn.txn);
    let txid_str = txid.to_string();

    // Build an eval_delta with a global state delta: action=2 (SetBytes), bs=b"data"
    let eval_delta = rmpv::Value::Map(vec![(
        rmpv::Value::String("gd".into()),
        rmpv::Value::Map(vec![(
            rmpv::Value::Binary(b"mykey".to_vec()),
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::String("at".into()),
                    rmpv::Value::Integer(2.into()),
                ),
                (
                    rmpv::Value::String("bs".into()),
                    rmpv::Value::Binary(b"data".to_vec()),
                ),
            ]),
        )]),
    )]);

    node.pending_txn_lookup.insert(
        txid.0,
        TxnWithStatus {
            txn: stxn,
            confirmed_round: 100,
            pool_error: String::new(),
            closing_amount: 0,
            asset_closing_amount: 0,
            sender_rewards: 0,
            receiver_rewards: 0,
            close_rewards: 0,
            asset_index: None,
            application_index: None,
            eval_delta: Some(eval_delta),
            logs: None,
            inner_txns: None,
        },
    );
    let server = TestServer::start(node).await;

    let url = format!("/v2/transactions/pending/{}", txid_str);
    let resp = server
        .client
        .get(server.url(&url))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    let gsd = json
        .get("global-state-delta")
        .expect("should have global-state-delta");
    let entry = &gsd.as_array().unwrap()[0];
    assert_eq!(entry["value"]["action"].as_u64().unwrap(), 2);
    assert_eq!(
        entry["value"]["bytes"].as_str().unwrap(),
        STANDARD.encode(b"data")
    );
    // uint should be omitted when 0
    assert!(entry["value"].get("uint").is_none());
}

#[tokio::test]
async fn pending_transaction_info_no_eval_delta_when_unconfirmed() {
    let mut node = MockNode::synced();
    let stxn = make_test_signed_txn();
    let txid = algo_codec::compute_txn_id(&stxn.txn);
    let txid_str = txid.to_string();

    // Build an eval_delta, but confirmed_round=0 (unconfirmed)
    let eval_delta = rmpv::Value::Map(vec![(
        rmpv::Value::String("gd".into()),
        rmpv::Value::Map(vec![(
            rmpv::Value::Binary(b"counter".to_vec()),
            rmpv::Value::Map(vec![(
                rmpv::Value::String("at".into()),
                rmpv::Value::Integer(1.into()),
            )]),
        )]),
    )]);

    node.pending_txn_lookup.insert(
        txid.0,
        TxnWithStatus {
            txn: stxn,
            confirmed_round: 0, // unconfirmed
            pool_error: String::new(),
            closing_amount: 0,
            asset_closing_amount: 0,
            sender_rewards: 0,
            receiver_rewards: 0,
            close_rewards: 0,
            asset_index: None,
            application_index: None,
            eval_delta: Some(eval_delta),
            logs: None,
            inner_txns: None,
        },
    );
    let server = TestServer::start(node).await;

    let url = format!("/v2/transactions/pending/{}", txid_str);
    let resp = server
        .client
        .get(server.url(&url))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    // Unconfirmed txns should not have eval delta fields
    assert!(
        json.get("global-state-delta").is_none(),
        "unconfirmed txn should not have global-state-delta"
    );
    assert!(
        json.get("local-state-delta").is_none(),
        "unconfirmed txn should not have local-state-delta"
    );
    assert!(
        json.get("logs").is_none(),
        "unconfirmed txn should not have logs"
    );
}

// ===========================================================================
// Simulate endpoint tests (POST /v2/transactions/simulate)
// ===========================================================================

#[tokio::test]
async fn simulate_requires_auth() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let request_json = serde_json::json!({
        "txn-groups": [{
            "txns": [{"txn": {"type": "pay"}}]
        }]
    });
    let body = serde_json::to_vec(&request_json).unwrap();

    let resp = server
        .client
        .post(server.url("/v2/transactions/simulate"))
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn simulate_empty_body_returns_400() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .post(server.url("/v2/transactions/simulate"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/json")
        .body(Vec::<u8>::new())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn simulate_empty_txn_groups_returns_400() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let request_json = serde_json::json!({
        "txn-groups": []
    });
    let body = serde_json::to_vec(&request_json).unwrap();

    let resp = server
        .client
        .post(server.url("/v2/transactions/simulate"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn simulate_catchpoint_returns_503() {
    let node = MockNode::catchpoint_catchup();
    let server = TestServer::start(node).await;

    let request_json = serde_json::json!({
        "txn-groups": [{
            "txns": [{"txn": {"type": "pay"}}]
        }]
    });
    let body = serde_json::to_vec(&request_json).unwrap();

    let resp = server
        .client
        .post(server.url("/v2/transactions/simulate"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);
}

#[tokio::test]
async fn simulate_not_implemented_returns_500() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let stx_val = serde_json::to_value(SignedTransaction::default()).unwrap();
    let request_json = serde_json::json!({
        "txn-groups": [{
            "txns": [stx_val]
        }]
    });
    let body = serde_json::to_vec(&request_json).unwrap();

    let resp = server
        .client
        .post(server.url("/v2/transactions/simulate"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 500);
    let text = resp.text().await.unwrap();
    assert!(
        text.contains("not implemented"),
        "expected 'not implemented' in response body, got: {text}"
    );
}

#[tokio::test]
async fn simulate_returns_response() {
    use algo_rest_api::models::{
        PreEncodedTxInfo, SimulateResponse, SimulateTransactionGroupResult,
        SimulateTransactionResult,
    };

    let mut node = MockNode::synced();
    node.simulate_result = Some(SimulateResponse {
        version: 2,
        last_round: 1000,
        txn_groups: vec![SimulateTransactionGroupResult {
            txn_results: vec![SimulateTransactionResult {
                txn_result: PreEncodedTxInfo {
                    txn: SignedTransaction::default(),
                    pool_error: String::new(),
                    confirmed_round: None,
                    closing_amount: None,
                    asset_closing_amount: None,
                    sender_rewards: None,
                    receiver_rewards: None,
                    close_rewards: None,
                    asset_index: None,
                    application_index: None,
                    global_state_delta: None,
                    local_state_delta: None,
                    logs: None,
                    inner_txns: None,
                },
                app_budget_consumed: None,
                exec_trace: None,
                fees_paid: None,
                fixed_signer: None,
                logic_sig_budget_consumed: None,
                unnamed_resources_accessed: None,
            }],
            app_budget_added: None,
            app_budget_consumed: None,
            failed_at: None,
            failure_message: None,
            group_usage: None,
            group_fees_paid: None,
            unnamed_resources_accessed: None,
        }],
        eval_overrides: None,
        exec_trace_config: None,
        initial_states: None,
    });
    let server = TestServer::start(node).await;

    let stx_val = serde_json::to_value(SignedTransaction::default()).unwrap();
    let request_json = serde_json::json!({
        "txn-groups": [{
            "txns": [stx_val]
        }]
    });
    let body = serde_json::to_vec(&request_json).unwrap();

    let resp = server
        .client
        .post(server.url("/v2/transactions/simulate"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["version"], 2);
    assert_eq!(json["last-round"], 1000);
    assert!(json["txn-groups"].is_array());
    assert_eq!(json["txn-groups"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn simulate_format_msgpack() {
    use algo_rest_api::models::{
        PreEncodedTxInfo, SimulateResponse, SimulateTransactionGroupResult,
        SimulateTransactionResult,
    };

    let mut node = MockNode::synced();
    node.simulate_result = Some(SimulateResponse {
        version: 2,
        last_round: 1000,
        txn_groups: vec![SimulateTransactionGroupResult {
            txn_results: vec![SimulateTransactionResult {
                txn_result: PreEncodedTxInfo {
                    txn: SignedTransaction::default(),
                    pool_error: String::new(),
                    confirmed_round: None,
                    closing_amount: None,
                    asset_closing_amount: None,
                    sender_rewards: None,
                    receiver_rewards: None,
                    close_rewards: None,
                    asset_index: None,
                    application_index: None,
                    global_state_delta: None,
                    local_state_delta: None,
                    logs: None,
                    inner_txns: None,
                },
                app_budget_consumed: None,
                exec_trace: None,
                fees_paid: None,
                fixed_signer: None,
                logic_sig_budget_consumed: None,
                unnamed_resources_accessed: None,
            }],
            app_budget_added: None,
            app_budget_consumed: None,
            failed_at: None,
            failure_message: None,
            group_usage: None,
            group_fees_paid: None,
            unnamed_resources_accessed: None,
        }],
        eval_overrides: None,
        exec_trace_config: None,
        initial_states: None,
    });
    let server = TestServer::start(node).await;

    let stx_val = serde_json::to_value(SignedTransaction::default()).unwrap();
    let request_json = serde_json::json!({
        "txn-groups": [{
            "txns": [stx_val]
        }]
    });
    let body = serde_json::to_vec(&request_json).unwrap();

    let resp = server
        .client
        .post(server.url("/v2/transactions/simulate?format=msgpack"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        content_type.contains("application/msgpack"),
        "expected msgpack content type, got: {content_type}"
    );
}

#[tokio::test]
async fn simulate_invalid_format_returns_400() {
    let node = MockNode::synced();
    let server = TestServer::start(node).await;

    let request_json = serde_json::json!({
        "txn-groups": [{
            "txns": [{"txn": {"type": "pay"}}]
        }]
    });
    let body = serde_json::to_vec(&request_json).unwrap();

    let resp = server
        .client
        .post(server.url("/v2/transactions/simulate?format=xml"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

/// The simulate endpoint enforces go-algorand's 1MB request body limit
/// (`MaxSimulateBytes`, renamed from `MaxTealDryrunBytes` when dryrun was
/// removed — see issue #674): an otherwise-valid request padded past the
/// limit must be rejected with 400 before decoding.
#[tokio::test]
async fn simulate_body_too_large_returns_400() {
    let server = TestServer::start(MockNode::synced()).await;

    // A structurally valid JSON request padded with trailing whitespace
    // (still valid JSON) so only the size check can reject it.
    let stx_val = serde_json::to_value(SignedTransaction::default()).unwrap();
    let request_json = serde_json::json!({
        "txn-groups": [{
            "txns": [stx_val]
        }]
    });
    let mut body = serde_json::to_vec(&request_json).unwrap();
    body.resize(1_000_001, b' ');

    let resp = server
        .client
        .post(server.url("/v2/transactions/simulate"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(
        json["message"]
            .as_str()
            .unwrap_or_default()
            .contains("request body too large"),
        "expected body-too-large message, got {json}"
    );
}

// ===========================================================================
// Ledger state delta endpoint tests
// ===========================================================================

#[tokio::test]
async fn get_state_delta_requires_auth() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/deltas/1"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn get_state_delta_invalid_format_returns_400() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/deltas/1?format=xml"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn get_state_delta_unknown_round_returns_404() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/deltas/1"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let body: serde_json::Value = resp.json().await.unwrap();
    let msg = body["message"].as_str().unwrap();
    assert!(
        msg.contains("failed retrieving State Delta"),
        "unexpected error message: {msg}"
    );
}

#[tokio::test]
async fn get_txn_group_delta_requires_auth() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(
            server.url("/v2/deltas/txn/group/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn get_txn_group_delta_invalid_format_returns_400() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url(
            "/v2/deltas/txn/group/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA?format=xml",
        ))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn get_txn_group_delta_returns_501() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(
            server.url("/v2/deltas/txn/group/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        )
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 501);

    let body: serde_json::Value = resp.json().await.unwrap();
    let msg = body["message"].as_str().unwrap();
    assert_eq!(msg, "failed retrieving the expected tracer from ledger");
}

/// With the tracer enabled, both group-delta endpoints return data (no 501),
/// and unknown ids/rounds return 404 — matching go-algorand.
#[tokio::test]
async fn get_txn_group_delta_endpoints_return_data_when_enabled() {
    let txn_id = Digest([0x11u8; 32]);
    let id_str = txn_id.to_string();
    let group = TxnGroupDeltaWithIds {
        ids: vec![id_str.clone()],
        delta: StateDeltaSubset::default(),
    };
    let mut node = MockNode::synced();
    let mut by_round = BTreeMap::new();
    by_round.insert(1u64, vec![group]);
    node.txn_group_deltas = Some(by_round);
    let server = TestServer::start(node).await;

    let get = |path: String| {
        let c = server.client.clone();
        let url = server.url(&path);
        let tok = server.api_token.clone();
        async move {
            c.get(url)
                .header("X-Algo-API-Token", &tok)
                .send()
                .await
                .unwrap()
        }
    };

    // by-round → 200 with the `{ "Deltas": [...] }` wrapper.
    let resp = get("/v2/deltas/1/txn/group".into()).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["Deltas"].as_array().unwrap().len(), 1);
    assert_eq!(body["Deltas"][0]["Ids"][0].as_str().unwrap(), id_str);

    // by-id → 200. The response must never carry a "Totals" key: go-algorand's
    // group-delta endpoints return `eval.StateDeltaSubset`, which has no
    // Totals/StateProofNext/PrevTimestamp fields at all (unlike the
    // round-level `GET /v2/deltas/{round}` response). Issue #191.
    let resp = get(format!("/v2/deltas/txn/group/{id_str}")).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let obj = body.as_object().expect("response is a JSON object");
    assert!(
        !obj.contains_key("Totals"),
        "group-delta response must not include Totals (go's StateDeltaSubset \
         has no such field): {obj:?}"
    );
    assert!(
        !obj.contains_key("StateProofNext"),
        "group-delta response must not include StateProofNext: {obj:?}"
    );
    assert!(
        !obj.contains_key("PrevTimestamp"),
        "group-delta response must not include PrevTimestamp: {obj:?}"
    );

    // Unknown round → 404.
    let resp = get("/v2/deltas/2/txn/group".into()).await;
    assert_eq!(resp.status(), 404);

    // Unknown id → 404.
    let other = Digest([0x99u8; 32]).to_string();
    let resp = get(format!("/v2/deltas/txn/group/{other}")).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn get_txn_group_deltas_for_round_requires_auth() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/deltas/1/txn/group"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn get_txn_group_deltas_for_round_invalid_format_returns_400() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/deltas/1/txn/group?format=xml"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn get_txn_group_deltas_for_round_returns_501() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/deltas/1/txn/group"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 501);

    let body: serde_json::Value = resp.json().await.unwrap();
    let msg = body["message"].as_str().unwrap();
    assert_eq!(msg, "failed retrieving the expected tracer from ledger");
}

// ===========================================================================
// State delta endpoint tests — typed StateDelta responses
// ===========================================================================

/// Helper: build a MockNode with a StateDelta pre-loaded for round 42.
fn mock_with_delta() -> MockNode {
    use algo_ledger::state_delta::{
        AccountDeltas, AccountTotals, BalanceRecord, LedgercoreAccountData, Txlease,
    };
    use std::collections::HashMap;

    let mut node = MockNode::synced();

    let delta = StateDelta {
        accts: AccountDeltas {
            accts: vec![BalanceRecord {
                addr: Address([1u8; 32]),
                account_data: LedgercoreAccountData::default(),
            }],
            app_resources: Vec::new(),
            asset_resources: Vec::new(),
        },
        kv_mods: HashMap::new(),
        txids: HashMap::new(),
        txleases: Some(vec![(
            Txlease {
                sender: Address([2u8; 32]),
                lease: [3u8; 32],
            },
            Round(100),
        )]),
        creatables: HashMap::new(),
        hdr: None,
        state_proof_next: Round(0),
        prev_timestamp: 0,
        totals: AccountTotals::default(),
    };
    node.state_deltas.insert(42, delta);
    node
}

#[tokio::test]
async fn get_state_delta_json_returns_200() {
    let server = TestServer::start(mock_with_delta()).await;

    let resp = server
        .client
        .get(server.url("/v2/deltas/42"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "application/json");

    let body: serde_json::Value = resp.json().await.unwrap();
    // Txleases is zeroed out (None) in JSON responses (Txlease can't be a
    // JSON map key), but issue #576 established that `ledgercore.StateDelta`
    // carries no `_struct codec:",omitempty,omitemptyarray"` marker, so the
    // key itself is never omitted -- it's `null`, not absent.
    assert_eq!(
        body.get("Txleases"),
        Some(&serde_json::Value::Null),
        "Txleases should be present as null (not absent) in JSON: {body}"
    );
    // Accts should be present.
    assert!(
        body.get("Accts").is_some(),
        "Accts should be present in JSON"
    );
}

#[tokio::test]
async fn get_state_delta_msgpack_returns_200_with_txleases() {
    let server = TestServer::start(mock_with_delta()).await;

    let resp = server
        .client
        .get(server.url("/v2/deltas/42?format=msgpack"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "application/msgpack");

    let body = resp.bytes().await.unwrap();
    let decoded: StateDelta = rmp_serde::from_slice(&body).unwrap();
    // Txleases should be PRESENT in msgpack responses.
    assert!(
        decoded.txleases.is_some(),
        "Txleases should be present in msgpack"
    );
    assert_eq!(decoded.txleases.as_ref().unwrap().len(), 1);
}

#[tokio::test]
async fn get_state_delta_not_found_returns_404() {
    let server = TestServer::start(mock_with_delta()).await;

    let resp = server
        .client
        .get(server.url("/v2/deltas/999"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ===========================================================================
// TEAL compile / disassemble endpoint tests
// ===========================================================================

/// Create a mock node with developer API enabled.
fn mock_with_developer_api() -> MockNode {
    let mut node = MockNode::synced();
    node.enable_developer_api = true;
    node
}

#[tokio::test]
async fn teal_compile_happy_path() {
    let server = TestServer::start(mock_with_developer_api()).await;

    let source = "#pragma version 2\nint 1\n";
    let resp = server
        .client
        .post(server.url("/v2/teal/compile"))
        .header("X-Algo-API-Token", &server.api_token)
        .body(source)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    // Should have hash and result fields
    assert!(body["hash"].is_string(), "response should have hash field");
    assert!(
        body["result"].is_string(),
        "response should have result field"
    );
    // result should be valid base64
    let result_b64 = body["result"].as_str().unwrap();
    let program_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, result_b64)
            .expect("result should be valid base64");
    // Program should start with version byte 2
    assert_eq!(
        program_bytes[0], 0x02,
        "program should start with version 2"
    );
    // hash should be a 58-char Algorand address
    let hash_str = body["hash"].as_str().unwrap();
    assert_eq!(
        hash_str.len(),
        58,
        "hash should be 58-char Algorand address"
    );
    // sourcemap should not be present by default
    assert!(
        body.get("sourcemap").is_none(),
        "sourcemap should not be present by default"
    );
}

#[tokio::test]
async fn teal_compile_with_sourcemap() {
    let server = TestServer::start(mock_with_developer_api()).await;

    let source = "#pragma version 2\nint 1\n";
    let resp = server
        .client
        .post(server.url("/v2/teal/compile?sourcemap=true"))
        .header("X-Algo-API-Token", &server.api_token)
        .body(source)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["hash"].is_string());
    assert!(body["result"].is_string());
    // sourcemap should be present
    assert!(
        body["sourcemap"].is_object(),
        "sourcemap should be present when requested"
    );
    assert!(body["sourcemap"]["version"].is_number());
    assert!(body["sourcemap"]["mappings"].is_string());
}

#[tokio::test]
async fn teal_compile_error_returns_400() {
    let server = TestServer::start(mock_with_developer_api()).await;

    let source = "this is not valid TEAL";
    let resp = server
        .client
        .post(server.url("/v2/teal/compile"))
        .header("X-Algo-API-Token", &server.api_token)
        .body(source)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn teal_disassemble_happy_path() {
    let server = TestServer::start(mock_with_developer_api()).await;

    // First compile a program, then disassemble it
    let source = "#pragma version 2\nint 1\n";
    let compile_resp = server
        .client
        .post(server.url("/v2/teal/compile"))
        .header("X-Algo-API-Token", &server.api_token)
        .body(source)
        .send()
        .await
        .unwrap();
    assert_eq!(compile_resp.status(), 200);
    let compile_body: serde_json::Value = compile_resp.json().await.unwrap();
    let result_b64 = compile_body["result"].as_str().unwrap();
    let program_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, result_b64).unwrap();

    // Now disassemble
    let resp = server
        .client
        .post(server.url("/v2/teal/disassemble"))
        .header("X-Algo-API-Token", &server.api_token)
        .body(program_bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["result"].is_string());
    let result = body["result"].as_str().unwrap();
    // Disassembler outputs raw opcodes: intcblock/intc_0 rather than "int 1"
    assert!(
        result.contains("intc") || result.contains("pushint") || result.contains("#pragma version"),
        "disassembled output should contain valid TEAL instructions, got: {result}"
    );
}

#[tokio::test]
async fn teal_disassemble_error_returns_400() {
    let server = TestServer::start(mock_with_developer_api()).await;

    // Send invalid bytecode
    let resp = server
        .client
        .post(server.url("/v2/teal/disassemble"))
        .header("X-Algo-API-Token", &server.api_token)
        .body(vec![0xFF, 0xFF])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn teal_compile_disabled_returns_404() {
    // Default MockNode has enable_developer_api = false
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .post(server.url("/v2/teal/compile"))
        .header("X-Algo-API-Token", &server.api_token)
        .body("#pragma version 2\nint 1\n")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("EnableDeveloperAPI"),
        "404 message should mention EnableDeveloperAPI"
    );
}

#[tokio::test]
async fn teal_disassemble_disabled_returns_404() {
    // Default MockNode has enable_developer_api = false
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .post(server.url("/v2/teal/disassemble"))
        .header("X-Algo-API-Token", &server.api_token)
        .body(vec![0x02, 0x20, 0x01, 0x01, 0x22])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("EnableDeveloperAPI"),
        "404 message should mention EnableDeveloperAPI"
    );
}

/// Issue #674: go-algorand v5.0.0-stable removes `POST /v2/teal/dryrun`
/// entirely (PR #6651, "Chore: Remove dryrun and tealdbg", v5.0.0-beta) in
/// favor of `simulate`. The route must be gone from algod-rust too — a
/// generic "no route matched" 404 via the router fallback, not the
/// EnableDeveloperAPI-disabled 404 the endpoint used to return, and
/// unconditionally so (even with the developer API enabled).
#[tokio::test]
async fn teal_dryrun_route_removed_returns_404() {
    let server = TestServer::start(mock_with_developer_api()).await;

    let resp = server
        .client
        .post(server.url("/v2/teal/dryrun"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ===========================================================================
// Participation key endpoint tests
// ===========================================================================

fn mock_participation_record() -> ParticipationRecord {
    let mut id_bytes = [0u8; 32];
    id_bytes[0] = 0x01;
    id_bytes[1] = 0x02;

    let mut account_bytes = [0u8; 32];
    account_bytes[0] = 0xAA;

    ParticipationRecord {
        participation_id: ParticipationID(id_bytes),
        account: Address(account_bytes),
        first_valid: Round(100),
        last_valid: Round(3_000_000),
        key_dilution: 1000,
        last_vote: Round(50),
        last_block_proposal: Round(40),
        last_state_proof: Round(30),
        effective_first: Round(100),
        effective_last: Round(200),
        vrf_public_key: None,
        vote_id: Some([0xBB; 32]),
        state_proof_verifier: None,
    }
}

#[tokio::test]
async fn participation_list_empty() {
    let server = TestServer::start(MockNode::synced()).await;
    let resp = server
        .client
        .get(server.url("/v2/participation"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    // Go returns null for a nil/empty slice, not [].
    assert_eq!(body, "null\n");
}

#[tokio::test]
async fn participation_list_with_records() {
    let mut node = MockNode::synced();
    let record = mock_participation_record();
    let expected_id = record.participation_id.to_base32();
    node.participation_records.push(record);

    let server = TestServer::start(node).await;
    let resp = server
        .client
        .get(server.url("/v2/participation"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let arr: serde_json::Value = serde_json::from_str(&body).unwrap();
    let arr = arr.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    let obj = &arr[0];
    assert_eq!(obj["id"].as_str().unwrap(), expected_id);
    // Check key fields
    assert_eq!(obj["key"]["vote-first-valid"].as_u64().unwrap(), 100);
    assert_eq!(obj["key"]["vote-last-valid"].as_u64().unwrap(), 3_000_000);
    assert_eq!(obj["key"]["vote-key-dilution"].as_u64().unwrap(), 1000);
}

#[tokio::test]
async fn participation_effective_first_special_case() {
    // When effective_last != 0 && effective_first == 0, Go returns effective-first-valid: 0
    // (not omitted). This tests the special case in convertParticipationRecord.
    let mut node = MockNode::synced();
    let mut record = mock_participation_record();
    record.effective_first = Round(0);
    record.effective_last = Round(200);
    node.participation_records.push(record);

    let server = TestServer::start(node).await;
    let resp = server
        .client
        .get(server.url("/v2/participation"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let arr: serde_json::Value = serde_json::from_str(&body).unwrap();
    let obj = &arr.as_array().unwrap()[0];
    // effective-first-valid should be present and 0, NOT omitted
    assert_eq!(obj["effective-first-valid"].as_u64().unwrap(), 0);
    assert_eq!(obj["effective-last-valid"].as_u64().unwrap(), 200);
}

#[tokio::test]
async fn participation_list_requires_admin_token() {
    let server = TestServer::start(MockNode::synced()).await;

    // API token should be rejected (admin-only endpoint)
    let resp = server
        .client
        .get(server.url("/v2/participation"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // No token at all should also be rejected
    let resp = server
        .client
        .get(server.url("/v2/participation"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn participation_get_by_id_found() {
    let mut node = MockNode::synced();
    let record = mock_participation_record();
    let id_base32 = record.participation_id.to_base32();
    node.participation_records.push(record);

    let server = TestServer::start(node).await;
    let resp = server
        .client
        .get(server.url(&format!("/v2/participation/{id_base32}")))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let obj: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(obj["id"].as_str().unwrap(), id_base32);
    assert_eq!(obj["key"]["vote-first-valid"].as_u64().unwrap(), 100);
}

#[tokio::test]
async fn participation_get_by_id_not_found() {
    let server = TestServer::start(MockNode::synced()).await;
    // Use a valid base32 ID that doesn't match any record
    let id = ParticipationID([0xFF; 32]);
    let id_base32 = id.to_base32();

    let resp = server
        .client
        .get(server.url(&format!("/v2/participation/{id_base32}")))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn participation_get_by_id_invalid_id() {
    let server = TestServer::start(MockNode::synced()).await;
    let resp = server
        .client
        .get(server.url("/v2/participation/INVALID!!!"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn participation_add_key_success() {
    let server = TestServer::start(MockNode::synced()).await;
    let resp = server
        .client
        .post(server.url("/v2/participation"))
        .header("X-Algo-API-Token", &server.admin_token)
        .body(vec![0x01, 0x02, 0x03])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let obj: serde_json::Value = serde_json::from_str(&body).unwrap();
    // The mock returns ParticipationID([0x42; 32])
    let expected_id = ParticipationID([0x42; 32]).to_base32();
    assert_eq!(obj["partId"].as_str().unwrap(), expected_id);
}

#[tokio::test]
async fn participation_add_key_error() {
    let mut node = MockNode::synced();
    node.install_result = Some("invalid key data".to_string());
    let server = TestServer::start(node).await;
    let resp = server
        .client
        .post(server.url("/v2/participation"))
        .header("X-Algo-API-Token", &server.admin_token)
        .body(vec![0x01, 0x02, 0x03])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn participation_add_key_empty_body() {
    let server = TestServer::start(MockNode::synced()).await;
    let resp = server
        .client
        .post(server.url("/v2/participation"))
        .header("X-Algo-API-Token", &server.admin_token)
        .body(Vec::<u8>::new())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn participation_delete_success() {
    let server = TestServer::start(MockNode::synced()).await;
    let id = ParticipationID([0x01; 32]);
    let id_base32 = id.to_base32();

    let resp = server
        .client
        .delete(server.url(&format!("/v2/participation/{id_base32}")))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn participation_delete_not_found() {
    let mut node = MockNode::synced();
    node.remove_result = Some("not found".to_string());

    let server = TestServer::start(node).await;
    let id = ParticipationID([0x01; 32]);
    let id_base32 = id.to_base32();

    let resp = server
        .client
        .delete(server.url(&format!("/v2/participation/{id_base32}")))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn participation_generate_returns_200() {
    let server = TestServer::start(MockNode::synced()).await;
    // Use a valid Algorand address (all zeros with correct checksum)
    let addr = Address([0u8; 32]);
    let addr_str = addr.to_algorand_string();

    let resp = server
        .client
        .post(server.url(&format!(
            "/v2/participation/generate/{addr_str}?first=1&last=100"
        )))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "{}");
}

#[tokio::test]
async fn participation_generate_missing_params_returns_400() {
    let server = TestServer::start(MockNode::synced()).await;
    let addr = Address([0u8; 32]);
    let addr_str = addr.to_algorand_string();

    // Missing required 'first' and 'last' query params
    let resp = server
        .client
        .post(server.url(&format!("/v2/participation/generate/{addr_str}")))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn participation_append_keys_success() {
    let server = TestServer::start(MockNode::synced()).await;
    let id = ParticipationID([0x01; 32]);
    let id_base32 = id.to_base32();

    let resp = server
        .client
        .post(server.url(&format!("/v2/participation/{id_base32}")))
        .header("X-Algo-API-Token", &server.admin_token)
        .body(vec![0xAA, 0xBB, 0xCC])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn participation_append_keys_empty_body() {
    let server = TestServer::start(MockNode::synced()).await;
    let id = ParticipationID([0x01; 32]);
    let id_base32 = id.to_base32();

    let resp = server
        .client
        .post(server.url(&format!("/v2/participation/{id_base32}")))
        .header("X-Algo-API-Token", &server.admin_token)
        .body(Vec::<u8>::new())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

// ===========================================================================
// Catchup endpoint tests
// ===========================================================================

#[tokio::test]
async fn start_catchup_created() {
    let mut node = MockNode::synced();
    node.catchup_start_result = Some(algo_rest_api::node::CatchupStartResult::Created);
    let server = TestServer::start(node).await;

    // Valid catchpoint: round#base32hash (32 bytes = 52 chars base32 no-pad)
    let hash = data_encoding::BASE32_NOPAD.encode(&[0xAB; 32]);
    let catchpoint_url = format!("1000%23{hash}");
    let catchpoint_decoded = format!("1000#{hash}");

    let resp = server
        .client
        .post(server.url(&format!("/v2/catchup/{catchpoint_url}")))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["catchup-message"], catchpoint_decoded);
}

#[tokio::test]
async fn start_catchup_already_in_progress() {
    let mut node = MockNode::synced();
    node.catchup_start_result = Some(algo_rest_api::node::CatchupStartResult::AlreadyInProgress);
    let server = TestServer::start(node).await;

    let hash = data_encoding::BASE32_NOPAD.encode(&[0xAB; 32]);
    let catchpoint_url = format!("1000%23{hash}");

    let resp = server
        .client
        .post(server.url(&format!("/v2/catchup/{catchpoint_url}")))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn start_catchup_invalid_label() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .post(server.url("/v2/catchup/invalid-label"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn abort_catchup_success() {
    let server = TestServer::start(MockNode::synced()).await;

    let hash = data_encoding::BASE32_NOPAD.encode(&[0xAB; 32]);
    let catchpoint_url = format!("1000%23{hash}");
    let catchpoint_decoded = format!("1000#{hash}");

    let resp = server
        .client
        .delete(server.url(&format!("/v2/catchup/{catchpoint_url}")))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["catchup-message"], catchpoint_decoded);
}

#[tokio::test]
async fn abort_catchup_invalid_label() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .delete(server.url("/v2/catchup/bad"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

// ===========================================================================
// Shutdown endpoint tests
// ===========================================================================

#[tokio::test]
async fn shutdown_returns_501() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .post(server.url("/v2/shutdown"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 501);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "Endpoint not implemented.");
}

#[tokio::test]
async fn shutdown_node_canonical_route_returns_identical_response() {
    // go-algorand PR #6674 adds the canonical `POST /v2/node/shutdown`
    // route (`ShutdownNode2`); the deprecated `/v2/shutdown` delegates to
    // it. Both are still upstream 501 stubs, so both routes here must
    // return byte-identical responses (issue #673).
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .post(server.url("/v2/node/shutdown"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 501);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "Endpoint not implemented.");
}

#[tokio::test]
async fn shutdown_node_canonical_route_accepts_timeout_query_param() {
    // Both routes accept the same `timeout` query param (OAS3
    // `algod.oas3.yml` ~line 5963); the stub ignores it but must not reject
    // the request for carrying it.
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .post(server.url("/v2/node/shutdown?timeout=5"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 501);
}

#[tokio::test]
async fn shutdown_node_canonical_route_requires_admin_token() {
    // `/v2/node/shutdown` is tagged `private` upstream (admin-only), same
    // tier as `/v2/shutdown` and `/v2/catchup/*`.
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .post(server.url("/v2/node/shutdown"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ===========================================================================
// GET /v2/node/peers
// ===========================================================================

#[tokio::test]
async fn get_peers_empty() {
    let mut node = MockNode::synced();
    node.peers_result = Some((Vec::new(), Vec::new()));
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/node/peers"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    // Top-level key is capitalized "Peers" per go-algorand's OAS3 schema —
    // NOT lowercase, unlike the rest of this API's convention.
    assert_eq!(body["Peers"], serde_json::json!([]));
    assert!(body.get("peers").is_none());
}

#[tokio::test]
async fn get_peers_mixed_inbound_outbound_ws_p2p_sorted() {
    use algo_rest_api::node::{PeerInfo, PeerNetworkType};

    let mut node = MockNode::synced();
    node.peers_result = Some((
        // Inbound: intentionally out of address order to verify sorting.
        vec![
            PeerInfo {
                network_address: "10.0.0.9:4160".to_string(),
                network_type: PeerNetworkType::Ws,
            },
            PeerInfo {
                network_address: "10.0.0.2:4160".to_string(),
                network_type: PeerNetworkType::P2p,
            },
        ],
        // Outbound: also out of order.
        vec![
            PeerInfo {
                network_address: "10.0.0.5:4160".to_string(),
                network_type: PeerNetworkType::P2p,
            },
            PeerInfo {
                network_address: "10.0.0.1:4160".to_string(),
                network_type: PeerNetworkType::Ws,
            },
        ],
    ));
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/node/peers"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let peers = body["Peers"].as_array().unwrap();
    assert_eq!(peers.len(), 4);

    // Inbound peers come first (sorted by address), then outbound (sorted
    // by address) — go's `convertPeers` sorts each direction's slice
    // independently, not the combined list (`handlers.go:1031-1033`).
    assert_eq!(peers[0]["network-address"], "10.0.0.2:4160");
    assert_eq!(peers[0]["connection-type"], "inbound");
    assert_eq!(peers[0]["network-type"], "p2p");

    assert_eq!(peers[1]["network-address"], "10.0.0.9:4160");
    assert_eq!(peers[1]["connection-type"], "inbound");
    assert_eq!(peers[1]["network-type"], "ws");

    assert_eq!(peers[2]["network-address"], "10.0.0.1:4160");
    assert_eq!(peers[2]["connection-type"], "outbound");
    assert_eq!(peers[2]["network-type"], "ws");

    assert_eq!(peers[3]["network-address"], "10.0.0.5:4160");
    assert_eq!(peers[3]["connection-type"], "outbound");
    assert_eq!(peers[3]["network-type"], "p2p");
}

#[tokio::test]
async fn get_peers_not_implemented_returns_500() {
    // Default MockNode has no peers_result configured.
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/node/peers"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 500);
}

#[tokio::test]
async fn get_peers_requires_admin_token() {
    // Tagged `private` (admin-only) upstream — the public API token must be
    // rejected, matching go's `adminMiddleware`-only registration
    // (router.go:144/146) and this endpoint's sensitivity: it reveals live
    // peer network topology.
    let mut node = MockNode::synced();
    node.peers_result = Some((Vec::new(), Vec::new()));
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/node/peers"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn get_peers_rejects_missing_token() {
    let mut node = MockNode::synced();
    node.peers_result = Some((Vec::new(), Vec::new()));
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/node/peers"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ===========================================================================
// Dev-mode block timestamp offset tests
// ===========================================================================

#[tokio::test]
async fn get_block_timestamp_offset_success() {
    let mut node = MockNode::synced();
    node.is_dev_mode = true;
    node.block_timestamp_offset = Some(42);
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/devmode/blocks/offset"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["offset"], 42);
}

#[tokio::test]
async fn get_block_timestamp_offset_not_dev_mode() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/devmode/blocks/offset"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn get_block_timestamp_offset_never_set() {
    let mut node = MockNode::synced();
    node.is_dev_mode = true;
    // block_timestamp_offset is None by default
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/devmode/blocks/offset"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn set_block_timestamp_offset_success() {
    let mut node = MockNode::synced();
    node.is_dev_mode = true;
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .post(server.url("/v2/devmode/blocks/offset/100"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn set_block_timestamp_offset_too_large() {
    let mut node = MockNode::synced();
    node.is_dev_mode = true;
    let server = TestServer::start(node).await;

    // i64::MAX + 1 = 9223372036854775808
    let resp = server
        .client
        .post(server.url("/v2/devmode/blocks/offset/9223372036854775808"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

// ===========================================================================
// Debug profiling settings tests
// ===========================================================================

#[tokio::test]
async fn get_debug_settings_prof_success() {
    let mut node = MockNode::synced();
    node.debug_prof_rates = (10, 20);
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/debug/settings/pprof"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["mutex-rate"], 10);
    assert_eq!(body["block-rate"], 20);
}

#[tokio::test]
async fn put_debug_settings_prof_success() {
    let mut node = MockNode::synced();
    node.debug_prof_rates = (5, 15);
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .put(server.url("/debug/settings/pprof"))
        .header("X-Algo-API-Token", &server.admin_token)
        .header("content-type", "application/json")
        .body(r#"{"mutex-rate": 100, "block-rate": 200}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    // Returns old values
    assert_eq!(body["mutex-rate"], 5);
    assert_eq!(body["block-rate"], 15);
}

#[tokio::test]
async fn put_debug_settings_prof_rate_too_large() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .put(server.url("/debug/settings/pprof"))
        .header("X-Algo-API-Token", &server.admin_token)
        .header("content-type", "application/json")
        .body(r#"{"block-rate": 2147483648}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

// ===========================================================================
// Config endpoint tests
// ===========================================================================

#[tokio::test]
async fn get_config_success() {
    let mut node = MockNode::synced();
    node.config_json = Some(serde_json::json!({"key": "value"}));
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/debug/settings/config"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["key"], "value");
}

// ===========================================================================
// Ledger sync round tests
// ===========================================================================

#[tokio::test]
async fn get_sync_round_success() {
    let mut node = MockNode::synced();
    node.is_follower_mode = true;
    node.sync_round = 500;
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/ledger/sync"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["round"], 500);
}

#[tokio::test]
async fn get_sync_round_not_set() {
    let mut node = MockNode::synced();
    node.is_follower_mode = true;
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/ledger/sync"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn sync_endpoints_absent_when_not_follower() {
    // go-algorand registers the data API (/v2/ledger/sync) only in follower
    // mode; a non-follower node must not expose these routes (404).
    let node = MockNode::synced();
    assert!(!node.is_follower_mode);
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/ledger/sync"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    let sync_status = resp.status();
    // Compare to a path that is definitely not registered: the sync endpoint
    // must behave identically (i.e. not be exposed) in non-follower mode.
    let bogus = server
        .client
        .get(server.url("/v2/ledger/definitely-not-a-route"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        sync_status,
        bogus.status(),
        "sync endpoint should be as unavailable as an unregistered path in non-follower mode"
    );
    assert_ne!(
        sync_status, 200,
        "sync must not succeed outside follower mode"
    );
}

#[tokio::test]
async fn set_sync_round_success() {
    let mut node = MockNode::synced();
    node.is_follower_mode = true;
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .post(server.url("/v2/ledger/sync/100"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn set_sync_round_invalid() {
    let mut node = MockNode::synced();
    node.is_follower_mode = true;
    node.set_sync_round_result = Some("sync round invalid".to_string());
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .post(server.url("/v2/ledger/sync/100"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn unset_sync_round_success() {
    let mut node = MockNode::synced();
    node.is_follower_mode = true;
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .delete(server.url("/v2/ledger/sync"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

/// `/v2/ledger/sync` must reject unauthenticated requests exactly like any
/// other authenticated v2 route — there is no separate "data API" token to
/// omit here, go-algorand wires the sync routes with the same public
/// middleware used everywhere else (`data.RegisterHandlers(e, &v2Handler,
/// publicMiddleware...)`, `router.go:150`). Issue #206.
#[tokio::test]
async fn sync_endpoints_return_401_without_token() {
    let mut node = MockNode::synced();
    node.is_follower_mode = true;
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/ledger/sync"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let resp = server
        .client
        .post(server.url("/v2/ledger/sync/100"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let resp = server
        .client
        .delete(server.url("/v2/ledger/sync"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

/// The admin token must also grant access to `/v2/ledger/sync`, proving these
/// endpoints sit on the same public tier (`[adminToken, apiToken]`,
/// `router.go:96`) as ordinary authenticated routes rather than requiring a
/// distinct "data API" credential. go-algorand has no separate data-API
/// token: `generated/data/routes.go`'s "data" grouping is an OpenAPI-spec
/// route category, not an auth tier — its handlers are registered with the
/// exact same `publicMiddleware` as `/v2/status`, `/v2/accounts/...`, etc.
/// (`router.go:150`). Issue #206.
#[tokio::test]
async fn admin_token_works_on_sync_endpoints() {
    let mut node = MockNode::synced();
    node.is_follower_mode = true;
    node.sync_round = 500;
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url("/v2/ledger/sync"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "admin token must be accepted on the sync endpoints (go router.go:96)"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["round"], 500);
}

// ===========================================================================
// Follower-mode operation rejection (issue #827 theme 4; go-algorand's
// `node/follower_node_test.go`'s `TestErrors`).
//
// go's `AlgorandFollowerNode` overrides `BroadcastSignedTxGroup`,
// `BroadcastInternalSignedTxGroup`, `GetParticipationKey`,
// `RemoveParticipationKey`, `AppendParticipationKeys`, and
// `InstallParticipationKey` to unconditionally return an error in follower
// mode (`node/follower_node.go`) -- broadcasting txns and mutating
// participation keys make no sense on a node with no agreement service and
// no transaction pool. (`Simulate` is deliberately excluded here: go's own
// `AlgorandFollowerNode.Simulate` does *not* reject in follower mode --
// `TestErrors`'s `Simulate(simulation.Request{})` call only errors because
// an empty request has no txn groups, and `TestSimulate` in the same file
// proves a real simulate request succeeds in follower mode.)
//
// algod-rust has no in-process node type analogous to
// `AlgorandFollowerNode` -- `NodeInterface` is the trait every node
// implementation (participate, follow, mock) sits behind -- so the
// equivalent guard lives at the REST handler layer, gated on
// `NodeInterface::is_follower_mode()`, matching how the sync-round
// endpoints are already gated at the router layer just above.
// ===========================================================================

#[tokio::test]
async fn raw_transaction_rejected_in_follower_mode() {
    let mut node = MockNode::synced();
    node.is_follower_mode = true;
    let server = TestServer::start(node).await;

    let stxn = make_test_signed_txn();
    let body = encode_signed_txn_for_post(&stxn);

    let resp = server
        .client
        .post(server.url("/v2/transactions"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/x-binary")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(
        json["message"].as_str().unwrap().contains("follower mode"),
        "error should mention follower mode, got: {}",
        json["message"]
    );
}

#[tokio::test]
async fn raw_transaction_async_rejected_in_follower_mode() {
    let mut node = mock_with_experimental_and_developer_api();
    node.is_follower_mode = true;
    let server = TestServer::start(node).await;

    let stxn = make_test_signed_txn();
    let body = encode_signed_txn_for_post(&stxn);

    let resp = server
        .client
        .post(server.url("/v2/transactions/async"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/x-binary")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn participation_add_key_rejected_in_follower_mode() {
    let mut node = MockNode::synced();
    node.is_follower_mode = true;
    let server = TestServer::start(node).await;
    let resp = server
        .client
        .post(server.url("/v2/participation"))
        .header("X-Algo-API-Token", &server.admin_token)
        .body(vec![0x01, 0x02, 0x03])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(
        json["message"].as_str().unwrap().contains("follower mode"),
        "error should mention follower mode, got: {}",
        json["message"]
    );
}

#[tokio::test]
async fn participation_get_by_id_rejected_in_follower_mode() {
    let mut node = MockNode::synced();
    node.is_follower_mode = true;
    let record = mock_participation_record();
    let id_base32 = record.participation_id.to_base32();
    node.participation_records.push(record);

    let server = TestServer::start(node).await;
    let resp = server
        .client
        .get(server.url(&format!("/v2/participation/{id_base32}")))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    // Rejected before the (found) record is even looked up.
    assert_ne!(resp.status(), 200);
}

#[tokio::test]
async fn participation_delete_rejected_in_follower_mode() {
    let mut node = MockNode::synced();
    node.is_follower_mode = true;
    let server = TestServer::start(node).await;
    let id = ParticipationID([0x01; 32]);
    let id_base32 = id.to_base32();

    let resp = server
        .client
        .delete(server.url(&format!("/v2/participation/{id_base32}")))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 200);
}

#[tokio::test]
async fn participation_append_keys_rejected_in_follower_mode() {
    let mut node = MockNode::synced();
    node.is_follower_mode = true;
    let server = TestServer::start(node).await;
    let id = ParticipationID([0x01; 32]);
    let id_base32 = id.to_base32();

    let resp = server
        .client
        .post(server.url(&format!("/v2/participation/{id_base32}")))
        .header("X-Algo-API-Token", &server.admin_token)
        .body(vec![0xAA, 0xBB, 0xCC])
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 200);
}

// ===========================================================================
// Min-rounds catchup check test
// ===========================================================================

#[tokio::test]
async fn start_catchup_min_rounds_skip() {
    let mut node = MockNode::synced();
    node.latest_round_for_catchup = 900;
    node.catchup_start_result = Some(algo_rest_api::node::CatchupStartResult::Created);
    let server = TestServer::start(node).await;

    let hash = data_encoding::BASE32_NOPAD.encode(&[0xAB; 32]);
    let catchpoint_url = format!("1000%23{hash}");

    // min=200 means we need catchpoint round >= ledger_round + 200 = 1100
    // But catchpoint round is 1000, so this should return 200 with skip message
    let resp = server
        .client
        .post(server.url(&format!("/v2/catchup/{catchpoint_url}?min=200")))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["catchup-message"].as_str().unwrap(),
        "the node has already been initialized"
    );
}

// ===========================================================================
// Experimental API tests
// ===========================================================================

fn mock_with_experimental_api() -> MockNode {
    let mut node = MockNode::synced();
    node.enable_experimental_api = true;
    node
}

fn mock_with_experimental_and_developer_api() -> MockNode {
    let mut node = MockNode::synced();
    node.enable_experimental_api = true;
    node.enable_developer_api = true;
    node
}

#[tokio::test]
async fn experimental_check_enabled_returns_200() {
    let server = TestServer::start(mock_with_experimental_api()).await;

    let resp = server
        .client
        .get(server.url("/v2/experimental"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body.trim(), "true");
}

#[tokio::test]
async fn experimental_check_disabled_not_accessible() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/experimental"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    // Route not registered — axum returns 404 or auth middleware returns 401
    let status = resp.status().as_u16();
    assert!(
        status == 404 || status == 401,
        "expected 404 or 401 when experimental is disabled, got {status}"
    );
}

#[tokio::test]
async fn account_assets_information_enabled_returns_200() {
    let addr = Address([0x01; 32]);
    let mut node = mock_with_experimental_api();
    node.asset_resources_by_addr.insert(
        addr.0,
        vec![AssetResourceWithIDs {
            asset_id: 42,
            asset_holding: Some(AssetHolding {
                amount: 100,
                frozen: false,
            }),
            creator: Address([0u8; 32]),
            asset_params: None,
        }],
    );

    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}/assets", addr)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["round"], 1000);
    let holdings = body["asset-holdings"].as_array().unwrap();
    assert_eq!(holdings.len(), 1);
    assert_eq!(holdings[0]["asset-holding"]["asset-id"], 42);
    assert_eq!(holdings[0]["asset-holding"]["amount"], 100);
}

#[tokio::test]
async fn account_assets_information_accessible_without_experimental_api() {
    // Issue #506: go-algorand v4.6.0-stable (PR #6559) moved this endpoint
    // out of the experimental route group into the always-registered
    // nonparticipating/public group, so `EnableExperimentalAPI` no longer
    // gates it. `MockNode::synced()` leaves the experimental flag unset,
    // pinning that the route is still registered/reachable and returns a
    // normal 200 (an empty page, since no holdings are seeded for `addr`)
    // rather than the old 404/401 experimental-disabled response.
    let addr = Address([0x01; 32]);
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}/assets", addr)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let holdings = body["asset-holdings"].as_array().unwrap();
    assert!(holdings.is_empty());
}

#[tokio::test]
async fn account_assets_information_pagination() {
    let addr = Address([0x01; 32]);
    let mut node = mock_with_experimental_api();

    // Create 3 assets
    let assets: Vec<AssetResourceWithIDs> = (1..=3)
        .map(|i| AssetResourceWithIDs {
            asset_id: i,
            asset_holding: Some(AssetHolding {
                amount: i * 10,
                frozen: false,
            }),
            creator: Address([0u8; 32]),
            asset_params: None,
        })
        .collect();
    node.asset_resources_by_addr.insert(addr.0, assets);

    let server = TestServer::start(node).await;

    // Request with limit=2 — should get 2 results and a next-token
    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}/assets?limit=2", addr)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let holdings = body["asset-holdings"].as_array().unwrap();
    assert_eq!(holdings.len(), 2);
    assert!(
        body["next-token"].is_string(),
        "should have next-token for pagination"
    );

    // Request second page using the next token
    let next_token = body["next-token"].as_str().unwrap();
    let resp = server
        .client
        .get(server.url(&format!(
            "/v2/accounts/{}/assets?limit=2&next={}",
            addr, next_token
        )))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let holdings = body["asset-holdings"].as_array().unwrap();
    assert_eq!(holdings.len(), 1);
    assert!(
        body["next-token"].is_null(),
        "should not have next-token on last page"
    );
}

#[tokio::test]
async fn account_assets_information_limit_exceeds_max() {
    let addr = Address([0x01; 32]);
    let server = TestServer::start(mock_with_experimental_api()).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}/assets?limit=1001", addr)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("exceeds max"),
        "error should mention exceeds max"
    );
}

// ---------------------------------------------------------------------------
// GET /v2/accounts/:address/applications  (issue #505)
// ---------------------------------------------------------------------------

fn sample_app_params(creator: Address) -> AppParams {
    AppParams {
        creator,
        approval_program: vec![0x06],
        clear_state_program: vec![0x06],
        global_state: Default::default(),
        local_state_schema: StateSchema::default(),
        global_state_schema: StateSchema::default(),
        extra_program_pages: 0,
        ..Default::default()
    }
}

#[tokio::test]
async fn account_applications_information_accessible_without_experimental_api() {
    // Unlike the pre-#506 `/assets` endpoint, this is a brand-new
    // go-algorand v4.6.0-stable endpoint and was never gated behind
    // EnableExperimentalAPI — `MockNode::synced()` leaves that flag unset,
    // pinning that the route is reachable and returns a normal 200 (empty
    // page, no resources seeded) rather than 404/401.
    let addr = Address([0x01; 32]);
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}/applications", addr)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["round"], 1000);
    let resources = body["application-resources"].as_array().unwrap();
    assert!(resources.is_empty());
}

#[tokio::test]
async fn account_applications_information_returns_local_state_and_params() {
    let addr = Address([0x02; 32]);
    let mut node = MockNode::synced();
    node.app_resources_by_addr.insert(
        addr.0,
        vec![AppResourceWithIDs {
            app_id: 42,
            app_local_state: Some(AppLocalState {
                schema: StateSchema::default(),
                key_value: Default::default(),
            }),
            creator: addr,
            app_params: Some(sample_app_params(addr)),
        }],
    );
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url(&format!(
            "/v2/accounts/{}/applications?include=params",
            addr
        )))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let resources = body["application-resources"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["id"], 42);
    assert!(resources[0]["app-local-state"].is_object());
    assert!(
        resources[0]["params"].is_object(),
        "params must be present when include=params is passed: {resources:?}"
    );
    assert!(resources[0]["deleted"].is_null());
}

#[tokio::test]
async fn account_applications_information_omits_params_without_include() {
    // Default behavior (no `include=params`): params must be omitted even
    // though the account is the creator, matching go-algorand's
    // bandwidth-saving default.
    let addr = Address([0x03; 32]);
    let mut node = MockNode::synced();
    node.app_resources_by_addr.insert(
        addr.0,
        vec![AppResourceWithIDs {
            app_id: 7,
            app_local_state: None,
            creator: addr,
            app_params: Some(sample_app_params(addr)),
        }],
    );
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}/applications", addr)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let resources = body["application-resources"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    assert!(
        resources[0]["params"].is_null(),
        "params must be omitted without include=params: {resources:?}"
    );
    assert!(resources[0]["app-local-state"].is_null());
}

#[tokio::test]
async fn account_applications_information_creator_only_row_survives_without_include() {
    // Issue #535 (go-algorand v4.7.0-beta / PR #6588 "API: Deal with
    // params that are in deltas"): the handler.go workaround this PR
    // removed used to skip any record with *both* `AppLocalState == nil`
    // and `AppParams == nil` — but a legitimate creator-only row (the
    // account created the app, has no local state, and the caller did not
    // pass `include=params`) has exactly that shape, since `AppParams`
    // stays intentionally nil when params aren't requested. That old go
    // check would have silently dropped a real resource. algod-rust's
    // handler (`account_applications_information` in `handlers.rs`) adds a
    // third `creator.is_zero()` condition to its analogous defensive
    // skip, so a live creator-only row (non-zero creator) is never
    // dropped by it — this pins that at the REST layer: the record must
    // still appear, unmarked as deleted, with `app-local-state` and
    // `params` both absent.
    let addr = Address([0x05; 32]);
    let mut node = MockNode::synced();
    node.app_resources_by_addr.insert(
        addr.0,
        vec![AppResourceWithIDs {
            app_id: 11,
            app_local_state: None,
            creator: addr,
            app_params: None,
        }],
    );
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}/applications", addr)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let resources = body["application-resources"].as_array().unwrap();
    assert_eq!(
        resources.len(),
        1,
        "a creator-only row must not be dropped just because params weren't requested: {body:?}"
    );
    assert!(resources[0]["app-local-state"].is_null());
    assert!(resources[0]["params"].is_null());
    assert!(
        resources[0]["deleted"].is_null(),
        "a live creator-only row must not be marked deleted: {resources:?}"
    );
}

#[tokio::test]
async fn account_applications_information_marks_deleted_app() {
    // A record whose creator resolves to the zero address (app no longer
    // exists) must surface `deleted: true`, matching go's handler branch.
    let addr = Address([0x04; 32]);
    let mut node = MockNode::synced();
    node.app_resources_by_addr.insert(
        addr.0,
        vec![AppResourceWithIDs {
            app_id: 9,
            app_local_state: Some(AppLocalState {
                schema: StateSchema::default(),
                key_value: Default::default(),
            }),
            creator: Address([0u8; 32]),
            app_params: None,
        }],
    );
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}/applications", addr)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let resources = body["application-resources"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["deleted"], true);
    assert!(resources[0]["app-local-state"].is_object());
}

#[tokio::test]
async fn account_applications_information_pagination() {
    let addr = Address([0x05; 32]);
    let mut node = MockNode::synced();
    let apps: Vec<AppResourceWithIDs> = (1..=3)
        .map(|i| AppResourceWithIDs {
            app_id: i,
            app_local_state: Some(AppLocalState {
                schema: StateSchema::default(),
                key_value: Default::default(),
            }),
            creator: Address([0u8; 32]),
            app_params: None,
        })
        .collect();
    node.app_resources_by_addr.insert(addr.0, apps);
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}/applications?limit=2", addr)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let resources = body["application-resources"].as_array().unwrap();
    assert_eq!(resources.len(), 2);
    assert!(
        body["next-token"].is_string(),
        "should have next-token for pagination"
    );

    let next_token = body["next-token"].as_str().unwrap();
    let resp = server
        .client
        .get(server.url(&format!(
            "/v2/accounts/{}/applications?limit=2&next={}",
            addr, next_token
        )))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let resources = body["application-resources"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    assert!(
        body["next-token"].is_null(),
        "should not have next-token on last page"
    );
}

#[tokio::test]
async fn account_applications_information_limit_exceeds_max_without_params() {
    // Without include=params the higher (100x) limit applies — 1001 must
    // still be rejected only once past MaxApplicationResultsWithoutParams
    // (100_000), while it's well within bounds here so the request should
    // succeed (empty page, no resources seeded).
    let addr = Address([0x06; 32]);
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}/applications?limit=1001", addr)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "1001 is within the without-params limit (100_000)"
    );

    // With include=params, the lower (1000) limit applies — 1001 must be
    // rejected.
    let resp = server
        .client
        .get(server.url(&format!(
            "/v2/accounts/{}/applications?limit=1001&include=params",
            addr
        )))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("exceeds max"),
        "error should mention exceeds max"
    );
}

#[tokio::test]
async fn account_applications_information_bad_address() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/accounts/not-an-address/applications"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn raw_transaction_async_enabled_returns_200() {
    let node = mock_with_experimental_and_developer_api();
    let server = TestServer::start(node).await;

    let stxn = make_test_signed_txn();
    let body = encode_signed_txn_for_post(&stxn);

    let resp = server
        .client
        .post(server.url("/v2/transactions/async"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/x-binary")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // Should have empty body (NoContent equivalent)
    let resp_body = resp.text().await.unwrap();
    assert!(
        resp_body.is_empty(),
        "async endpoint should return empty body on success"
    );
}

#[tokio::test]
async fn raw_transaction_async_disabled_not_accessible() {
    // experimental disabled (default)
    let server = TestServer::start(MockNode::synced()).await;

    let stxn = make_test_signed_txn();
    let body = encode_signed_txn_for_post(&stxn);

    let resp = server
        .client
        .post(server.url("/v2/transactions/async"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/x-binary")
        .body(body)
        .send()
        .await
        .unwrap();
    // Route not registered — axum returns 404 or auth middleware returns 401
    let status = resp.status().as_u16();
    assert!(
        status == 404 || status == 401,
        "expected 404 or 401 when experimental is disabled, got {status}"
    );
}

#[tokio::test]
async fn raw_transaction_async_developer_disabled_returns_404() {
    // experimental enabled but developer disabled
    let node = mock_with_experimental_api();
    let server = TestServer::start(node).await;

    let stxn = make_test_signed_txn();
    let body = encode_signed_txn_for_post(&stxn);

    let resp = server
        .client
        .post(server.url("/v2/transactions/async"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/x-binary")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let resp_body = resp.text().await.unwrap();
    assert!(
        resp_body.contains("EnableDeveloperAPI"),
        "404 message should mention EnableDeveloperAPI"
    );
}

#[tokio::test]
async fn raw_transaction_async_broadcast_error_returns_503() {
    let mut node = mock_with_experimental_and_developer_api();
    node.broadcast_result = Some("pool full".to_string());
    let server = TestServer::start(node).await;

    let stxn = make_test_signed_txn();
    let body = encode_signed_txn_for_post(&stxn);

    let resp = server
        .client
        .post(server.url("/v2/transactions/async"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/x-binary")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);
}

#[tokio::test]
async fn account_assets_information_limit_zero_returns_400() {
    let addr = Address([0x01; 32]);
    let server = TestServer::start(mock_with_experimental_api()).await;

    let resp = server
        .client
        .get(server.url(&format!("/v2/accounts/{}/assets?limit=0", addr)))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("positive"),
        "error should mention positive: {body}"
    );
}

#[tokio::test]
async fn raw_transaction_async_empty_body_returns_400() {
    let node = mock_with_experimental_and_developer_api();
    let server = TestServer::start(node).await;

    let resp = server
        .client
        .post(server.url("/v2/transactions/async"))
        .header("X-Algo-API-Token", &server.api_token)
        .header("Content-Type", "application/x-binary")
        .body(Vec::<u8>::new())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("empty txgroup"),
        "error should mention empty txgroup: {body}"
    );
}

// ===========================================================================
// Consensus participation metrics (issue #473)
// ===========================================================================

/// A mock node instrumented as if it had been participating for a while.
fn mock_participating() -> MockNode {
    let mut node = MockNode::synced();
    node.participation_status = Some(serde_json::json!({
        "votes_cast_total": 42,
        "votes_cast_by_step": {"soft": 21, "cert": 21},
        "proposals_made": 3,
        "last_committed_round": 1000,
        "recent_rounds": [{"round": 1000, "start_to_commit_ms": 2800}],
    }));
    node.metrics_exposition = Some(
        "# HELP algod_rust_agreement_votes_total Total agreement votes cast by this node.\n\
         # TYPE algod_rust_agreement_votes_total counter\n\
         algod_rust_agreement_votes_total 42\n"
            .to_string(),
    );
    node
}

#[tokio::test]
async fn participation_status_returns_metrics_json() {
    let server = TestServer::start(mock_participating()).await;

    let resp = server
        .client
        .get(server.url("/v2/participation/status"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("application/json"));

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["votes_cast_total"], 42);
    assert_eq!(body["votes_cast_by_step"]["soft"], 21);
    assert_eq!(body["last_committed_round"], 1000);
}

#[tokio::test]
async fn participation_status_requires_a_token() {
    let server = TestServer::start(mock_participating()).await;

    let resp = server
        .client
        .get(server.url("/v2/participation/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn participation_status_accepts_the_admin_token() {
    let server = TestServer::start(mock_participating()).await;

    let resp = server
        .client
        .get(server.url("/v2/participation/status"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

/// The endpoint-not-configured case: a node that is not participating must
/// 404 rather than report a zeroed document, so a scraper can tell the two
/// apart.
#[tokio::test]
async fn participation_status_404s_when_not_participating() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/v2/participation/status"))
        .header("X-Algo-API-Token", &server.api_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("not participating in consensus"),
        "unexpected body: {body}"
    );
}

/// `/v2/participation/status` must not be swallowed by the admin group's
/// `/v2/participation/:participation-id` route.
#[tokio::test]
async fn participation_status_route_does_not_shadow_key_lookup() {
    let server = TestServer::start(mock_participating()).await;

    // A real participation ID still reaches the admin key-lookup handler
    // (which 404s for an unknown id) rather than the metrics handler.
    let resp = server
        .client
        .get(server.url("/v2/participation/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
        .header("X-Algo-API-Token", &server.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("not participating in consensus"),
        "id lookup must not hit the metrics handler: {body}"
    );
}

#[tokio::test]
async fn metrics_endpoint_returns_prometheus_text_without_auth() {
    let server = TestServer::start(mock_participating()).await;

    // No token header at all: `/metrics` is public, like go-algorand's.
    let resp = server
        .client
        .get(server.url("/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        content_type.starts_with("text/plain"),
        "unexpected content-type: {content_type}"
    );

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("algod_rust_agreement_votes_total 42"),
        "{body}"
    );
    assert!(body.contains("# TYPE algod_rust_agreement_votes_total counter"));
}

#[tokio::test]
async fn metrics_endpoint_404s_when_not_participating() {
    let server = TestServer::start(MockNode::synced()).await;

    let resp = server
        .client
        .get(server.url("/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ===========================================================================
// Max request body size (issue #953)
// ===========================================================================

/// Builds a router directly (no real TCP listener) and dispatches a raw
/// request via `tower::ServiceExt::oneshot` — mirroring go's own
/// `TestRouterRequestBody`, which dispatches through `e.ServeHTTP(rec,
/// req)` in-process rather than over a real socket. A real
/// `reqwest`-over-TCP round trip (like every other test in this file uses)
/// is unsuitable here specifically: once the server-side body extractor
/// rejects a request for exceeding the size limit, hyper's h1 server can
/// abort the still-uploading connection before the client finishes writing
/// an 11MB body, which surfaces to `reqwest` as a transport-level
/// "connection reset" error instead of a clean `413` response — a known
/// interaction between axum's `DefaultBodyLimit` and streamed uploads, not
/// a bug in the body-limit logic under test.
async fn oneshot_request(
    node: MockNode,
    method: &str,
    path: &str,
    token: &str,
    body: Vec<u8>,
) -> axum::response::Response {
    use tower::ServiceExt;

    let tokens = TokenConfig {
        api_token: generate_token(),
        admin_token: generate_token(),
        enable_experimental_api: node.enable_experimental_api,
        disable_api_auth: node.disable_api_auth,
        enable_private_network_access_header: false,
    };
    // Route the caller-supplied token through whichever tier it names, so
    // callers can pass either the freshly generated api_token or
    // admin_token below.
    let (api_token, admin_token) = (tokens.api_token.clone(), tokens.admin_token.clone());
    let effective_token = if token == "API" {
        api_token
    } else {
        admin_token
    };

    let router = build_router(Arc::new(node), tokens);
    let request = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("X-Algo-API-Token", effective_token)
        .header("Content-Type", "application/x-binary")
        .body(axum::body::Body::from(body))
        .unwrap();
    router.oneshot(request).await.unwrap()
}

/// TDD anchor for issue #953, mirroring go-algorand's
/// `TestRouterRequestBody` (`daemon/algod/api/server/v2/test/handlers_test.go`):
/// a request body larger than `MaxRequestBodyBytes` ("10MB") on the
/// authenticated (public-token) tier must be rejected with `413 Payload Too
/// Large`, closing a real DoS-hardening gap where algod-rust previously
/// enforced no explicit body-size limit at all on this tier (only axum's
/// undocumented implicit 2MB default, which is narrower than go's 10MB and
/// not something any code here declared on purpose).
#[tokio::test]
async fn oversized_body_on_authenticated_route_is_rejected_with_413() {
    let oversized_body = vec![b'a'; 11 * 1024 * 1024]; // 11MB > the 10MB limit
    let resp = oneshot_request(
        MockNode::synced(),
        "POST",
        "/v2/transactions",
        "API",
        oversized_body,
    )
    .await;
    assert_eq!(
        resp.status(),
        413,
        "oversized authenticated-tier body must be rejected"
    );
}

/// TDD anchor for issue #953: a body at or under the 10MB limit on the
/// authenticated tier must NOT be rejected on size grounds alone (it may
/// still fail with a different status once the handler actually inspects
/// the — here deliberately garbage — payload, but never `413`).
#[tokio::test]
async fn body_at_the_limit_on_authenticated_route_is_not_413() {
    let body_at_limit = vec![b'a'; 10 * 1024 * 1024]; // exactly the 10MB limit
    let resp = oneshot_request(
        MockNode::synced(),
        "POST",
        "/v2/transactions",
        "API",
        body_at_limit,
    )
    .await;
    assert_ne!(
        resp.status(),
        413,
        "a body at (not over) the limit must not be size-rejected"
    );
}

/// TDD anchor for issue #953, mirroring go-algorand's
/// `TestRouterRequestBody`: go's admin tier (`adminMiddleware`) never gets
/// `publicMiddleware`'s `BodyLimit`, so an admin-token POST larger than
/// `MaxRequestBodyBytes` still succeeds. `MockNode::install_participation_key`
/// ignores its payload and always returns `Ok`, so this proves the body was
/// never truncated/rejected on size grounds — only a genuine size-unrelated
/// failure (never `413`) would indicate a regression here.
#[tokio::test]
async fn oversized_body_on_admin_route_is_not_size_limited() {
    let oversized_body = vec![b'a'; 11 * 1024 * 1024]; // 11MB > the public tier's 10MB limit
    let resp = oneshot_request(
        MockNode::synced(),
        "POST",
        "/v2/participation",
        "ADMIN",
        oversized_body,
    )
    .await;
    assert_eq!(
        resp.status(),
        200,
        "admin-tier body size must be unbounded, matching go's adminMiddleware (no BodyLimit)"
    );
}
