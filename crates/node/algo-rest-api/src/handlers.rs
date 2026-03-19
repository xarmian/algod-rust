//! HTTP request handlers for the Algorand REST API.
//!
//! Each handler corresponds to an endpoint from go-algorand's algod API.
//! Handlers are kept thin: they extract parameters, call into the
//! `NodeInterface`, and format the response.
//!
//! Endpoints implemented here:
//! - `GET /health` -- health check (no auth required)
//! - `GET /ready` -- readiness probe (no auth required)
//! - `GET /versions` -- API version and build info (no auth required)
//! - `GET /genesis` -- genesis JSON (no auth required)
//! - `GET /swagger.json` -- OpenAPI spec (no auth required)
//! - `GET /v2/transactions/params` -- suggested transaction parameters
//! - `GET /v2/accounts/:address` -- account information
//! - `GET /v2/accounts/:address/assets/:asset-id` -- account asset information
//! - `GET /v2/accounts/:address/applications/:application-id` -- account application information

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use algo_types::Address;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::error;
use crate::format::{self, FormatParams};
use crate::models;
use crate::node::NodeInterface;

/// Shared application state threaded through axum handlers.
pub type AppState<N> = Arc<N>;

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------

/// Health check endpoint. Returns 200 OK if the node process is alive.
///
/// Matches go-algorand: returns 200 with `null` JSON body.
pub async fn health<N: NodeInterface>() -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        "null\n",
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// GET /ready
// ---------------------------------------------------------------------------

/// Readiness probe. Returns 200 when the node is healthy and fully caught up.
///
/// Conditions (matching go-algorand):
/// 1. No fast-catchup in progress (catchpoint is empty).
/// 2. `time_since_last_round` is in [0, 17_000ms) (agreement deadline).
/// 3. `catchup_time` is 0.
/// 4. Node has not stopped at an unsupported round.
pub async fn ready<N: NodeInterface>(State(node): State<AppState<N>>) -> Response {
    let status_code = match node.status().await {
        Ok(status) => {
            if status.stopped_at_unsupported_round {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                // Agreement deadline timeout is 17 seconds = 17_000 ms.
                const DEADLINE_TIMEOUT_MS: i64 = 17_000;
                let time_since_last_ms = status.time_since_last_round / 1_000_000; // ns -> ms

                let is_ready = status.catchpoint.is_empty()
                    && (0..DEADLINE_TIMEOUT_MS).contains(&time_since_last_ms)
                    && status.catchup_time / 1_000_000 == 0;

                if is_ready {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            }
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };

    (
        status_code,
        [("content-type", "application/json")],
        "null\n",
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// GET /versions
// ---------------------------------------------------------------------------

/// Response body for the `/versions` endpoint, matching go-algorand's
/// `common.Version` JSON structure.
#[derive(Debug, Serialize)]
pub struct VersionsResponse {
    /// Supported API versions (always `["v2"]`).
    pub versions: Vec<String>,

    /// Genesis ID string.
    pub genesis_id: String,

    /// Genesis hash, base64-encoded in JSON.
    #[serde(with = "base64_bytes")]
    pub genesis_hash_b64: Vec<u8>,

    /// Build version information.
    pub build: BuildVersionResponse,
}

/// Build version in the versions response.
#[derive(Debug, Serialize)]
pub struct BuildVersionResponse {
    pub major: u32,
    pub minor: u32,
    pub build_number: u32,
    pub commit_hash: String,
    pub branch: String,
    pub channel: String,
}

/// Returns API version info, genesis ID/hash, and build version.
pub async fn versions<N: NodeInterface>(State(node): State<AppState<N>>) -> Response {
    let bv = node.build_version();
    let gh = node.genesis_hash();

    let response = VersionsResponse {
        versions: vec!["v2".to_string()],
        genesis_id: node.genesis_id().to_string(),
        genesis_hash_b64: gh.as_bytes().to_vec(),
        build: BuildVersionResponse {
            major: bv.major,
            minor: bv.minor,
            build_number: bv.build_number,
            commit_hash: bv.commit_hash.clone(),
            branch: bv.branch.clone(),
            channel: bv.channel.clone(),
        },
    };

    match serde_json::to_vec(&response) {
        Ok(body) => (StatusCode::OK, [("content-type", "application/json")], body).into_response(),
        Err(_) => error::internal_error("failed to encode versions response"),
    }
}

// ---------------------------------------------------------------------------
// GET /genesis
// ---------------------------------------------------------------------------

/// Returns the full genesis file as JSON.
pub async fn genesis<N: NodeInterface>(State(node): State<AppState<N>>) -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        node.genesis_json().to_string(),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// GET /swagger.json
// ---------------------------------------------------------------------------

/// The embedded OpenAPI spec (OAS2/Swagger) JSON, matching go-algorand's
/// `api.SwaggerSpecJSONEmbed`. This is the same `algod.oas2.json` file that
/// go-algorand serves at `/swagger.json`.
const SWAGGER_SPEC_JSON: &str = include_str!("../resources/algod.oas2.json");

/// Returns the full Algorand algod OpenAPI specification as JSON.
///
/// Matches go-algorand's `SwaggerJSON` handler in
/// `daemon/algod/api/server/common/handlers.go`.
pub async fn swagger_json() -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        SWAGGER_SPEC_JSON,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// GET /v2/transactions/params
// ---------------------------------------------------------------------------

/// Response body for `GET /v2/transactions/params`, matching go-algorand's
/// `model.TransactionParametersResponse`.
///
/// Field names use hyphens in JSON to match the Go struct tags.
#[derive(Debug, Serialize)]
pub struct TransactionParametersResponse {
    /// Consensus protocol version as of `last-round`.
    #[serde(rename = "consensus-version")]
    pub consensus_version: String,

    /// Suggested transaction fee in units of micro-Algos per byte.
    pub fee: u64,

    /// Hash of the genesis block, base64-encoded.
    #[serde(rename = "genesis-hash", with = "base64_bytes")]
    pub genesis_hash: Vec<u8>,

    /// Genesis ID string.
    #[serde(rename = "genesis-id")]
    pub genesis_id: String,

    /// Last committed round number.
    #[serde(rename = "last-round")]
    pub last_round: u64,

    /// Minimum transaction fee (not per byte) for the current protocol.
    #[serde(rename = "min-fee")]
    pub min_fee: u64,
}

/// Returns suggested parameters for constructing a new transaction.
///
/// Matches go-algorand's `Handlers.TransactionParams` in
/// `daemon/algod/api/server/v2/handlers.go`.
///
/// Always returns JSON (go-algorand does not support format negotiation
/// on this endpoint -- it uses `ctx.JSON()` directly).
///
/// Returns 503 if the node is currently catching up to a catchpoint.
pub async fn transaction_params<N: NodeInterface>(State(node): State<AppState<N>>) -> Response {
    let status = match node.status().await {
        Ok(s) => s,
        Err(_) => return error::internal_error("failed retrieving node status"),
    };

    if !status.catchpoint.is_empty() {
        return error::service_unavailable("operation not available during catchup");
    }

    let gh = node.genesis_hash();
    let fee = node.suggested_fee().await;
    let min_fee = node.min_txn_fee().await;

    let response = TransactionParametersResponse {
        consensus_version: status.last_version,
        fee,
        genesis_hash: gh.as_bytes().to_vec(),
        genesis_id: node.genesis_id().to_string(),
        last_round: status.last_round,
        min_fee,
    };

    match serde_json::to_vec(&response) {
        Ok(body) => (StatusCode::OK, [("content-type", "application/json")], body).into_response(),
        Err(_) => error::internal_error("failed to encode response"),
    }
}

// ---------------------------------------------------------------------------
// GET /v2/status
// ---------------------------------------------------------------------------

/// Response body for `GET /v2/status`, matching go-algorand's
/// `model.NodeStatusResponse`.
///
/// Field names use hyphens in JSON to match the Go struct tags.
/// Fields that are pointer types with `omitempty` in Go are represented as
/// `Option<T>` and skipped when `None`.
///
/// Note: In go-algorand's `GetStatus` handler, catchpoint-related pointer
/// fields are **always** set (even when zero), so they always appear in the
/// response. Upgrade-related fields are only set when `NextProtocolVoteBefore > 0`.
#[derive(Debug, Serialize)]
pub struct NodeStatusResponse {
    /// The current catchpoint that is being caught up to.
    #[serde(rename = "catchpoint", skip_serializing_if = "Option::is_none")]
    pub catchpoint: Option<String>,

    /// The number of blocks acquired as part of catchpoint catchup.
    #[serde(
        rename = "catchpoint-acquired-blocks",
        skip_serializing_if = "Option::is_none"
    )]
    pub catchpoint_acquired_blocks: Option<u64>,

    /// The number of accounts processed during catchpoint catchup.
    #[serde(
        rename = "catchpoint-processed-accounts",
        skip_serializing_if = "Option::is_none"
    )]
    pub catchpoint_processed_accounts: Option<u64>,

    /// The number of KVs processed during catchpoint catchup.
    #[serde(
        rename = "catchpoint-processed-kvs",
        skip_serializing_if = "Option::is_none"
    )]
    pub catchpoint_processed_kvs: Option<u64>,

    /// The total number of accounts in the current catchpoint.
    #[serde(
        rename = "catchpoint-total-accounts",
        skip_serializing_if = "Option::is_none"
    )]
    pub catchpoint_total_accounts: Option<u64>,

    /// The total number of blocks required for catchpoint catchup.
    #[serde(
        rename = "catchpoint-total-blocks",
        skip_serializing_if = "Option::is_none"
    )]
    pub catchpoint_total_blocks: Option<u64>,

    /// The total number of KVs in the current catchpoint.
    #[serde(
        rename = "catchpoint-total-kvs",
        skip_serializing_if = "Option::is_none"
    )]
    pub catchpoint_total_kvs: Option<u64>,

    /// The number of accounts verified during catchpoint catchup.
    #[serde(
        rename = "catchpoint-verified-accounts",
        skip_serializing_if = "Option::is_none"
    )]
    pub catchpoint_verified_accounts: Option<u64>,

    /// The number of KVs verified during catchpoint catchup.
    #[serde(
        rename = "catchpoint-verified-kvs",
        skip_serializing_if = "Option::is_none"
    )]
    pub catchpoint_verified_kvs: Option<u64>,

    /// CatchupTime in nanoseconds.
    #[serde(rename = "catchup-time")]
    pub catchup_time: i64,

    /// The last catchpoint seen by the node.
    #[serde(rename = "last-catchpoint", skip_serializing_if = "Option::is_none")]
    pub last_catchpoint: Option<String>,

    /// Last round seen.
    #[serde(rename = "last-round")]
    pub last_round: u64,

    /// Last consensus version supported.
    #[serde(rename = "last-version")]
    pub last_version: String,

    /// Next consensus protocol version to use.
    #[serde(rename = "next-version")]
    pub next_version: String,

    /// Round at which the next consensus version will apply.
    #[serde(rename = "next-version-round")]
    pub next_version_round: u64,

    /// Whether the next consensus version is supported by this node.
    #[serde(rename = "next-version-supported")]
    pub next_version_supported: bool,

    /// Whether the node has stopped at an unsupported round.
    #[serde(rename = "stopped-at-unsupported-round")]
    pub stopped_at_unsupported_round: bool,

    /// TimeSinceLastRound in nanoseconds.
    #[serde(rename = "time-since-last-round")]
    pub time_since_last_round: i64,

    /// Upgrade delay.
    #[serde(rename = "upgrade-delay", skip_serializing_if = "Option::is_none")]
    pub upgrade_delay: Option<u64>,

    /// Next protocol round (vote-before).
    #[serde(
        rename = "upgrade-next-protocol-vote-before",
        skip_serializing_if = "Option::is_none"
    )]
    pub upgrade_next_protocol_vote_before: Option<u64>,

    /// No-votes cast for consensus upgrade.
    #[serde(rename = "upgrade-no-votes", skip_serializing_if = "Option::is_none")]
    pub upgrade_no_votes: Option<u64>,

    /// This node's upgrade vote.
    #[serde(rename = "upgrade-node-vote", skip_serializing_if = "Option::is_none")]
    pub upgrade_node_vote: Option<bool>,

    /// Total voting rounds for current upgrade.
    #[serde(
        rename = "upgrade-vote-rounds",
        skip_serializing_if = "Option::is_none"
    )]
    pub upgrade_vote_rounds: Option<u64>,

    /// Total votes cast for consensus upgrade.
    #[serde(rename = "upgrade-votes", skip_serializing_if = "Option::is_none")]
    pub upgrade_votes: Option<u64>,

    /// Yes votes required for consensus upgrade.
    #[serde(
        rename = "upgrade-votes-required",
        skip_serializing_if = "Option::is_none"
    )]
    pub upgrade_votes_required: Option<u64>,

    /// Yes votes cast for consensus upgrade.
    #[serde(rename = "upgrade-yes-votes", skip_serializing_if = "Option::is_none")]
    pub upgrade_yes_votes: Option<u64>,
}

/// Returns the full node status.
///
/// Matches go-algorand's `Handlers.GetStatus` in
/// `daemon/algod/api/server/v2/handlers.go`.
///
/// Always returns JSON. Returns 500 if the node status cannot be retrieved.
pub async fn get_status<N: NodeInterface>(State(node): State<AppState<N>>) -> Response {
    let status = match node.status().await {
        Ok(s) => s,
        Err(_) => return error::internal_error("failed retrieving node status"),
    };

    let mut response = NodeStatusResponse {
        last_round: status.last_round,
        last_version: status.last_version,
        next_version: status.next_version,
        next_version_round: status.next_version_round,
        next_version_supported: status.next_version_supported,
        time_since_last_round: status.time_since_last_round,
        catchup_time: status.catchup_time,
        stopped_at_unsupported_round: status.stopped_at_unsupported_round,
        // Catchpoint fields: always set (matching go-algorand which always assigns &stat.*)
        last_catchpoint: Some(status.last_catchpoint),
        catchpoint: Some(status.catchpoint),
        catchpoint_total_accounts: Some(status.catchpoint_total_accounts),
        catchpoint_processed_accounts: Some(status.catchpoint_processed_accounts),
        catchpoint_verified_accounts: Some(status.catchpoint_verified_accounts),
        catchpoint_total_kvs: Some(status.catchpoint_total_kvs),
        catchpoint_processed_kvs: Some(status.catchpoint_processed_kvs),
        catchpoint_verified_kvs: Some(status.catchpoint_verified_kvs),
        catchpoint_total_blocks: Some(status.catchpoint_total_blocks),
        catchpoint_acquired_blocks: Some(status.catchpoint_acquired_blocks),
        // Upgrade fields: conditionally set below
        upgrade_delay: None,
        upgrade_next_protocol_vote_before: None,
        upgrade_no_votes: None,
        upgrade_node_vote: None,
        upgrade_vote_rounds: None,
        upgrade_votes: None,
        upgrade_votes_required: None,
        upgrade_yes_votes: None,
    };

    // Set upgrade fields only when a vote is happening
    // (matching go-algorand: `if stat.NextProtocolVoteBefore > 0`)
    if status.next_protocol_vote_before > 0 {
        let votes_to_go = if status.next_protocol_vote_before > status.last_round {
            // subtract 1 because the variables refer to "Last" round and "VoteBefore"
            status.next_protocol_vote_before - status.last_round - 1
        } else {
            0
        };

        let upgrade_vote_rounds = node.upgrade_vote_rounds();
        let upgrade_threshold = node.upgrade_threshold();
        let votes = upgrade_vote_rounds.saturating_sub(votes_to_go);
        let votes_yes = status.next_protocol_approvals;
        let votes_no = votes.saturating_sub(votes_yes);

        response.upgrade_votes_required = Some(upgrade_threshold);
        response.upgrade_node_vote = Some(status.upgrade_approve);
        response.upgrade_delay = Some(status.upgrade_delay);
        response.upgrade_votes = Some(votes);
        response.upgrade_yes_votes = Some(votes_yes);
        response.upgrade_no_votes = Some(votes_no);
        response.upgrade_vote_rounds = Some(upgrade_vote_rounds);
        response.upgrade_next_protocol_vote_before = Some(status.next_protocol_vote_before);
    }

    match serde_json::to_vec(&response) {
        Ok(body) => (StatusCode::OK, [("content-type", "application/json")], body).into_response(),
        Err(_) => error::internal_error("failed to encode response"),
    }
}

// ---------------------------------------------------------------------------
// GET /v2/status/wait-for-block-after/:round
// ---------------------------------------------------------------------------

/// Timeout for the wait-for-block-after endpoint, matching go-algorand's
/// `WaitForBlockTimeout` of 1 minute.
const WAIT_FOR_BLOCK_TIMEOUT: Duration = Duration::from_secs(60);

/// Waits for the node to reach the round *after* `round`, then returns
/// the current `NodeStatusResponse`.
///
/// Matches go-algorand's `Handlers.WaitForBlock` in
/// `daemon/algod/api/server/v2/handlers.go`.
///
/// Behaviour:
/// - Returns 400 if the node is stopped at an unsupported round.
/// - Returns 503 if the node is performing catchpoint catchup.
/// - Returns 400 if an upcoming unsupported protocol switch would be reached.
/// - Otherwise waits (up to 1 minute) for round+1, then returns 200 with
///   the current node status.
/// - On timeout, returns 200 with current status (matching go-algorand).
pub async fn wait_for_block<N: NodeInterface>(
    State(node): State<AppState<N>>,
    Path(round): Path<u64>,
) -> Response {
    // 0. Guard against round+1 overflow
    let next_round = match round.checked_add(1) {
        Some(r) => r,
        None => return error::bad_request("round overflow"),
    };

    // 1. Get current status
    let status = match node.status().await {
        Ok(s) => s,
        Err(_) => return error::internal_error("failed retrieving node status"),
    };

    // 2. Check stopped at unsupported round
    if status.stopped_at_unsupported_round {
        return error::bad_request(
            "requested round would reach only after the protocol upgrade which isn't supported",
        );
    }

    // 3. Check catchpoint catchup
    if !status.catchpoint.is_empty() {
        return error::service_unavailable("operation not available during catchup");
    }

    // 4. Check for upcoming unsupported protocol switch
    match node.latest_block_header_protocol_info().await {
        Ok(info) => {
            if !info.next_protocol.is_empty()
                && !info.next_protocol_supported
                && info.next_protocol_switch_on <= next_round
            {
                return error::bad_request(
                    "requested round would reach only after the protocol upgrade which isn't supported",
                );
            }
        }
        Err(_) => {
            return error::internal_error("failed retrieving latest block header");
        }
    }

    // 5. Wait for round+1 with timeout.
    //
    // Cancel-safety: when the client disconnects, axum drops the handler
    // future, which drops this `tokio::select!`, cancelling both branches.
    // `wait_for_round` is cancel-safe (it only waits on a Notify/channel).
    tokio::select! {
        _ = tokio::time::sleep(WAIT_FOR_BLOCK_TIMEOUT) => {},
        result = node.wait_for_round(next_round) => {
            if let Err(e) = result {
                tracing::warn!("wait_for_round error: {}", e);
                return error::internal_error(format!("waiting for round failed: {e}"));
            }
        },
    }

    // 6. Return status after wait (re-fetch to get the latest)
    get_status(State(node)).await
}

// ---------------------------------------------------------------------------
// GET /v2/accounts/:address
// ---------------------------------------------------------------------------

/// Query parameters for the account information endpoint.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AccountInfoParams {
    /// Response format: "json" (default) or "msgpack"/"msgp".
    pub format: Option<String>,
    /// Exclude resources: "all", "none", or absent.
    pub exclude: Option<String>,
}

/// Returns account information for the given address.
///
/// Matches go-algorand's `Handlers.AccountInformation` in
/// `daemon/algod/api/server/v2/handlers.go`.
///
/// Non-existent accounts return 200 with zero balances (not 404).
/// The `exclude` query parameter controls whether resource lists
/// (assets, apps) are included. Only "all" and "none" are valid.
pub async fn account_information<N: NodeInterface>(
    State(node): State<AppState<N>>,
    Path(address): Path<String>,
    Query(params): Query<AccountInfoParams>,
) -> Response {
    // Negotiate response format
    let fmt_params = FormatParams {
        format: params.format,
    };
    let resp_format = match format::negotiate_format(&fmt_params) {
        Ok(f) => f,
        Err(resp) => return *resp,
    };

    // Validate address
    let addr = match Address::from_str(&address) {
        Ok(a) => a,
        Err(_) => return error::bad_request("failed to parse the address"),
    };

    // Validate exclude parameter
    let exclude = params.exclude.as_deref().unwrap_or("");
    match exclude {
        "all" | "none" | "" => {}
        _ => return error::bad_request("failed to parse exclude"),
    }

    // Look up account (single call, reused for resource count check and response)
    let lookup = match node.lookup_account(&addr).await {
        Ok(l) => l,
        Err(_) => return error::internal_error("failed looking up account"),
    };

    // Check resource count vs max limit (when not excluding and max is set)
    if exclude != "all" {
        let max_results = node.max_api_resources_per_account();
        if max_results != 0 {
            let record = &lookup.account_data;
            let total_results = record.total_assets_opted_in
                + record.total_created_assets
                + record.total_apps_opted_in
                + record.total_created_apps;
            if total_results > max_results {
                // Return structured error with data matching go-algorand
                let mut data = serde_json::Map::new();
                data.insert(
                    "max-results".to_string(),
                    serde_json::Value::Number(max_results.into()),
                );
                data.insert(
                    "total-assets-opted-in".to_string(),
                    serde_json::Value::Number(record.total_assets_opted_in.into()),
                );
                data.insert(
                    "total-created-assets".to_string(),
                    serde_json::Value::Number(record.total_created_assets.into()),
                );
                data.insert(
                    "total-apps-opted-in".to_string(),
                    serde_json::Value::Number(record.total_apps_opted_in.into()),
                );
                data.insert(
                    "total-created-apps".to_string(),
                    serde_json::Value::Number(record.total_created_apps.into()),
                );
                let body = error::ErrorResponse {
                    message: "Result limit exceeded".to_string(),
                    data: Some(data),
                };
                let json = serde_json::to_string(&body)
                    .unwrap_or_else(|_| r#"{"message":"Result limit exceeded"}"#.to_string());
                return (
                    StatusCode::BAD_REQUEST,
                    [("content-type", "application/json")],
                    json,
                )
                    .into_response();
            }
        }
    }

    // Get consensus params for min balance computation
    let consensus = match node.consensus_params().await {
        Ok(c) => c,
        Err(_) => return error::internal_error("failed retrieving consensus params"),
    };

    // Convert to API response
    let response = models::account_data_to_response(&lookup, &addr, exclude, &consensus);
    format::encode_response(&response, resp_format)
}

// ---------------------------------------------------------------------------
// GET /v2/accounts/:address/assets/:asset-id
// ---------------------------------------------------------------------------

/// Returns asset information for the given account and asset ID.
///
/// Matches go-algorand's `Handlers.AccountAssetInformation` in
/// `daemon/algod/api/server/v2/handlers.go`.
///
/// Returns 404 if neither a holding nor asset params exist for this
/// address/asset pair.
pub async fn account_asset_information<N: NodeInterface>(
    State(node): State<AppState<N>>,
    Path((address, asset_id)): Path<(String, u64)>,
    Query(params): Query<FormatParams>,
) -> Response {
    // Negotiate response format
    let resp_format = match format::negotiate_format(&params) {
        Ok(f) => f,
        Err(resp) => return *resp,
    };

    // Validate address
    let addr = match Address::from_str(&address) {
        Ok(a) => a,
        Err(_) => return error::bad_request("failed to parse the address"),
    };

    // Look up asset resource
    let lookup = match node.lookup_asset_resource(&addr, asset_id).await {
        Ok(l) => l,
        Err(_) => return error::internal_error("failed looking up asset resource"),
    };

    // If neither holding nor params exist → 404
    if lookup.asset_holding.is_none() && lookup.asset_params.is_none() {
        return error::not_found("account asset info not found");
    }

    // Build response
    let mut response = models::AccountAssetResponse {
        round: lookup.last_round,
        asset_holding: None,
        created_asset: None,
    };

    if let Some(ref holding) = lookup.asset_holding {
        response.asset_holding = Some(models::asset_holding_to_api(asset_id, holding));
    }

    if let Some(ref params) = lookup.asset_params {
        let asset = models::asset_params_to_api(asset_id, &addr.to_algorand_string(), params);
        response.created_asset = Some(asset.params);
    }

    format::encode_response(&response, resp_format)
}

// ---------------------------------------------------------------------------
// GET /v2/accounts/:address/applications/:application-id
// ---------------------------------------------------------------------------

/// Returns application information for the given account and application ID.
///
/// Matches go-algorand's `Handlers.AccountApplicationInformation` in
/// `daemon/algod/api/server/v2/handlers.go`.
///
/// Returns 404 if neither local state nor app params exist for this
/// address/app pair.
pub async fn account_application_information<N: NodeInterface>(
    State(node): State<AppState<N>>,
    Path((address, app_id)): Path<(String, u64)>,
    Query(params): Query<FormatParams>,
) -> Response {
    // Negotiate response format
    let resp_format = match format::negotiate_format(&params) {
        Ok(f) => f,
        Err(resp) => return *resp,
    };

    // Validate address
    let addr = match Address::from_str(&address) {
        Ok(a) => a,
        Err(_) => return error::bad_request("failed to parse the address"),
    };

    // Look up app resource
    let lookup = match node.lookup_app_resource(&addr, app_id).await {
        Ok(l) => l,
        Err(_) => return error::internal_error("failed looking up app resource"),
    };

    // If neither local state nor params exist → 404
    if lookup.app_local_state.is_none() && lookup.app_params.is_none() {
        return error::not_found("account application info not found");
    }

    // Build response
    let mut response = models::AccountApplicationResponse {
        round: lookup.last_round,
        app_local_state: None,
        created_app: None,
    };

    if let Some(ref app_params) = lookup.app_params {
        let app = models::app_params_to_api(app_id, app_params);
        response.created_app = Some(app.params);
    }

    if let Some(ref local_state) = lookup.app_local_state {
        response.app_local_state = Some(models::app_local_state_to_api(app_id, local_state));
    }

    format::encode_response(&response, resp_format)
}

// ---------------------------------------------------------------------------
// Base64 serialization helper
// ---------------------------------------------------------------------------

/// Serde helper module for serializing `Vec<u8>` as standard base64.
///
/// go-algorand uses `genesis_hash_b64` with standard base64 encoding.
mod base64_bytes {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::Serializer;

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }
}
