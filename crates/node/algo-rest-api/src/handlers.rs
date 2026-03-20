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
//! - `GET /v2/applications/:application-id` -- application information by ID
//! - `GET /v2/assets/:asset-id` -- asset information by ID
//! - `GET /v2/applications/:application-id/box` -- application box by name
//! - `GET /v2/applications/:application-id/boxes` -- application box descriptors
//! - `GET /v2/blocks/:round` -- block data by round
//! - `GET /v2/blocks/:round/hash` -- block hash by round
//! - `GET /v2/blocks/:round/txids` -- transaction IDs in a block
//! - `GET /v2/blocks/:round/transactions/:txid/proof` -- Merkle proof for a transaction
//! - `GET /v2/blocks/:round/logs` -- app call logs from a block
//! - `GET /v2/blocks/:round/lightheader/proof` -- light block header proof for state proofs

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
    #[serde(with = "models::base64_bytes")]
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
    #[serde(rename = "genesis-hash", with = "models::base64_bytes")]
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
        Err(_) => return error::internal_error("failed to retrieve information from the ledger"),
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

    // Msgpack path: canonical-encode the raw AccountData (matching go-algorand)
    if resp_format == format::ResponseFormat::Msgpack {
        if exclude == "all" {
            // No resource maps needed — encode directly without cloning
            let bytes = algo_codec::canonical_encode_account_data(&lookup.account_data);
            return format::encode_protocol_codec_response(bytes);
        } else {
            let mut account_data = lookup.account_data.clone();
            account_data.asset_params = lookup.created_assets.clone();
            account_data.assets = lookup.assets.clone();
            account_data.app_local_states = lookup.app_local_states.clone();
            account_data.app_params = lookup.created_apps.clone();
            let bytes = algo_codec::canonical_encode_account_data(&account_data);
            return format::encode_protocol_codec_response(bytes);
        }
    }

    // Get consensus params for min balance computation
    let consensus = match node.consensus_params().await {
        Ok(c) => c,
        Err(_) => return error::internal_error("failed retrieving consensus params"),
    };

    // Convert to API response (JSON path)
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
        Err(_) => return error::internal_error("failed to retrieve information from the ledger"),
    };

    // If neither holding nor params exist → 404
    if lookup.asset_holding.is_none() && lookup.asset_params.is_none() {
        return error::not_found("account asset info not found");
    }

    // Msgpack path: canonical-encode the AccountAssetModel (matching go-algorand's
    // AssetResourceToAccountAssetModel)
    if resp_format == format::ResponseFormat::Msgpack {
        let bytes = algo_codec::canonical_encode_account_asset_model(
            lookup.asset_params.as_ref(),
            lookup.asset_holding.as_ref(),
        );
        return format::encode_protocol_codec_response(bytes);
    }

    // Build JSON response
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
        Err(_) => return error::internal_error("failed to retrieve information from the ledger"),
    };

    // If neither local state nor params exist → 404
    if lookup.app_local_state.is_none() && lookup.app_params.is_none() {
        return error::not_found("account application info not found");
    }

    // Msgpack path: canonical-encode the AccountApplicationModel (matching go-algorand's
    // AppResourceToAccountApplicationModel)
    if resp_format == format::ResponseFormat::Msgpack {
        let bytes = algo_codec::canonical_encode_account_application_model(
            lookup.app_params.as_ref(),
            lookup.app_local_state.as_ref(),
        );
        return format::encode_protocol_codec_response(bytes);
    }

    // Build JSON response
    let mut response = models::AccountApplicationResponse {
        round: lookup.last_round,
        app_local_state: None,
        created_app: None,
    };

    if let Some(ref app_params) = lookup.app_params {
        let app = models::app_params_to_api(app_id, &addr.to_algorand_string(), app_params);
        response.created_app = Some(app.params);
    }

    if let Some(ref local_state) = lookup.app_local_state {
        response.app_local_state = Some(models::app_local_state_to_api(app_id, local_state));
    }

    format::encode_response(&response, resp_format)
}

// ---------------------------------------------------------------------------
// GET /v2/applications/:application-id
// ---------------------------------------------------------------------------

/// Query parameters for the `get_application_box_by_name` endpoint.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BoxNameParams {
    /// Box name in goal-style encoding (e.g. "str:hello", "b64:AQID").
    pub name: String,
}

/// Query parameters for the `get_application_boxes` endpoint.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BoxesParams {
    /// Maximum number of box descriptors to return.
    pub max: Option<u64>,
}

/// Returns application information for the given application ID.
///
/// Matches go-algorand's `Handlers.GetApplicationByID` in
/// `daemon/algod/api/server/v2/handlers.go`.
///
/// Returns 404 if the application does not exist.
pub async fn get_application_by_id<N: NodeInterface>(
    State(node): State<AppState<N>>,
    Path(app_id): Path<u64>,
) -> Response {
    let lookup = match node.lookup_application(app_id).await {
        Ok(l) => l,
        Err(_) => return error::internal_error("failed to retrieve information from the ledger"),
    };

    let app_params = match lookup.app_params {
        Some(params) => params,
        None => return error::not_found("application does not exist"),
    };

    let response =
        models::app_params_to_api(app_id, &lookup.creator.to_algorand_string(), &app_params);

    match serde_json::to_vec(&response) {
        Ok(body) => (StatusCode::OK, [("content-type", "application/json")], body).into_response(),
        Err(_) => error::internal_error("failed to encode response"),
    }
}

// ---------------------------------------------------------------------------
// GET /v2/assets/:asset-id
// ---------------------------------------------------------------------------

/// Returns asset information for the given asset ID.
///
/// Matches go-algorand's `Handlers.GetAssetByID` in
/// `daemon/algod/api/server/v2/handlers.go`.
///
/// Returns 404 if the asset does not exist.
pub async fn get_asset_by_id<N: NodeInterface>(
    State(node): State<AppState<N>>,
    Path(asset_id): Path<u64>,
) -> Response {
    let lookup = match node.lookup_asset_by_id(asset_id).await {
        Ok(l) => l,
        Err(_) => return error::internal_error("failed to retrieve information from the ledger"),
    };

    let asset_params = match lookup.asset_params {
        Some(params) => params,
        None => return error::not_found("asset does not exist"),
    };

    let creator = lookup.creator.to_algorand_string();
    let response = models::asset_params_to_api(asset_id, &creator, &asset_params);

    match serde_json::to_vec(&response) {
        Ok(body) => (StatusCode::OK, [("content-type", "application/json")], body).into_response(),
        Err(_) => error::internal_error("failed to encode response"),
    }
}

// ---------------------------------------------------------------------------
// GET /v2/applications/:application-id/box
// ---------------------------------------------------------------------------

/// Returns the value of an application's box by name.
///
/// Matches go-algorand's `Handlers.GetApplicationBoxByName` in
/// `daemon/algod/api/server/v2/handlers.go`.
///
/// Returns 404 if the box does not exist.
pub async fn get_application_box_by_name<N: NodeInterface>(
    State(node): State<AppState<N>>,
    Path(app_id): Path<u64>,
    Query(params): Query<BoxNameParams>,
) -> Response {
    use crate::box_name;

    // Parse the goal-style encoded box name
    let box_name = match box_name::parse_box_name(&params.name) {
        Ok(name) => name,
        Err(e) => return error::bad_request(e.to_string()),
    };

    // Look up the box value
    let (value, last_round) = match node.lookup_kv(app_id, &box_name).await {
        Ok(result) => result,
        Err(_) => return error::internal_error("failed to retrieve information from the ledger"),
    };

    let value = match value {
        Some(v) => v,
        None => return error::not_found("box not found"),
    };

    let response = models::BoxResponse {
        name: box_name,
        round: last_round,
        value,
    };

    match serde_json::to_vec(&response) {
        Ok(body) => (StatusCode::OK, [("content-type", "application/json")], body).into_response(),
        Err(_) => error::internal_error("failed to encode response"),
    }
}

// ---------------------------------------------------------------------------
// GET /v2/applications/:application-id/boxes
// ---------------------------------------------------------------------------

/// Returns the box descriptors for an application.
///
/// Matches go-algorand's `Handlers.GetApplicationBoxes` in
/// `daemon/algod/api/server/v2/handlers.go`.
///
/// Returns 400 if the result limit is exceeded.
pub async fn get_application_boxes<N: NodeInterface>(
    State(node): State<AppState<N>>,
    Path(app_id): Path<u64>,
    Query(params): Query<BoxesParams>,
) -> Response {
    let requested_max = params.max.unwrap_or(0);
    let algod_max = node.max_api_box_per_application();

    // Compute effective max using the same logic as go-algorand's
    // applicationBoxesMaxKeys function.
    let max = application_boxes_max_keys(requested_max, algod_max);

    // If max is not unlimited, check total boxes against the limit via an
    // O(1) account record lookup BEFORE scanning all box keys. This matches
    // go-algorand's approach of checking `record.TotalBoxes > max` first
    // (handlers.go:1746). The `max` value from `application_boxes_max_keys`
    // may include a +1 sentinel for overflow detection, which is intentional.
    if max != u64::MAX {
        let (total_box_count, _round) = match node.total_boxes(app_id).await {
            Ok(result) => result,
            Err(_) => {
                return error::internal_error("failed to retrieve information from the ledger")
            }
        };

        if total_box_count > max {
            let mut data = serde_json::Map::new();
            data.insert(
                "max-api-box-per-application".to_string(),
                serde_json::Value::Number(algod_max.into()),
            );
            data.insert(
                "max".to_string(),
                serde_json::Value::Number(requested_max.into()),
            );
            data.insert(
                "total-boxes".to_string(),
                serde_json::Value::Number(total_box_count.into()),
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

    // Look up all box keys for the application (only reached if limit is
    // not exceeded or max is unlimited).
    let (box_keys, _last_round) = match node.lookup_keys_by_prefix(app_id, &[]).await {
        Ok(result) => result,
        Err(_) => return error::internal_error("failed to retrieve information from the ledger"),
    };

    // Build response: box_keys from lookup_keys_by_prefix are already the
    // raw box names (the node implementation handles prefix stripping).
    let boxes: Vec<models::BoxDescriptor> = box_keys
        .into_iter()
        .map(|name| models::BoxDescriptor { name })
        .collect();

    let response = models::BoxesResponse { boxes };

    match serde_json::to_vec(&response) {
        Ok(body) => (StatusCode::OK, [("content-type", "application/json")], body).into_response(),
        Err(_) => error::internal_error("failed to encode response"),
    }
}

// ---------------------------------------------------------------------------
// GET /v2/blocks/:round
// ---------------------------------------------------------------------------

/// Query parameters for the `GET /v2/blocks/:round` endpoint.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct GetBlockParams {
    /// Response format: "json" (default) or "msgpack"/"msgp".
    pub format: Option<String>,
    /// If true, return only the block header (no payset or certificate).
    #[serde(rename = "header-only")]
    pub header_only: Option<bool>,
}

/// Returns the block for the given round.
///
/// Matches go-algorand's `Handlers.GetBlock` in
/// `daemon/algod/api/server/v2/handlers.go`.
///
/// Behaviour:
/// - `header-only=true`: returns only the block header in a `{"block": ...}`
///   envelope (both JSON and msgpack).
/// - `format=msgpack` (full block): returns raw block bytes with
///   `X-Algorand-Struct: block-v1` header (pass-through from storage).
/// - `format=json` (full block, default): returns the block wrapped in
///   `{"block": ...}` as JSON.
/// - Returns 404 if the round is not available.
pub async fn get_block<N: NodeInterface>(
    State(node): State<AppState<N>>,
    Path(round): Path<u64>,
    Query(params): Query<GetBlockParams>,
) -> Response {
    // Negotiate response format
    let fmt_params = FormatParams {
        format: params.format,
    };
    let resp_format = match format::negotiate_format(&fmt_params) {
        Ok(f) => f,
        Err(resp) => return *resp,
    };

    // If header-only is requested, handle that path
    if params.header_only.unwrap_or(false) {
        return get_block_header_response(&node, round, resp_format).await;
    }

    // For msgpack full-block: raw pass-through with X-Algorand-Struct header
    if resp_format == format::ResponseFormat::Msgpack {
        match node.get_block_raw_msgpack(round).await {
            Ok(raw_bytes) => {
                return (
                    StatusCode::OK,
                    [
                        ("content-type", "application/msgpack"),
                        ("X-Algorand-Struct", "block-v1"),
                    ],
                    raw_bytes,
                )
                    .into_response();
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("not found") || msg.contains("no entry") {
                    return error::not_found("failed to retrieve information from the ledger");
                }
                return error::internal_error("failed to retrieve information from the ledger");
            }
        }
    }

    // For JSON full-block: parse and re-encode
    match node.get_block(round).await {
        Ok(block) => {
            let response = models::BlockJsonResponse { block };
            format::encode_response(&response, resp_format)
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") || msg.contains("no entry") {
                error::not_found("failed to retrieve information from the ledger")
            } else {
                error::internal_error("failed to retrieve information from the ledger")
            }
        }
    }
}

/// Handle the header-only block response for both JSON and msgpack.
///
/// Matches go-algorand's `getBlockHeader` helper which encodes a
/// `struct { Block bookkeeping.BlockHeader "codec:\"block\"" }` in the
/// requested format.
///
/// For msgpack: uses canonical encoding to produce `{"block": <header>}`.
/// For JSON: uses serde serialization of the typed response struct.
async fn get_block_header_response<N: NodeInterface>(
    node: &AppState<N>,
    round: u64,
    resp_format: format::ResponseFormat,
) -> Response {
    match node.get_block_header(round).await {
        Ok(header) => {
            if resp_format == format::ResponseFormat::Msgpack {
                // Canonical-encode: wrap in {"block": <header>} envelope
                let bytes = algo_codec::canonical_encode_block_header_response(&header);
                return format::encode_protocol_codec_response(bytes);
            }
            let response = models::BlockHeaderJsonResponse { block: header };
            format::encode_response(&response, resp_format)
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") || msg.contains("no entry") {
                error::not_found("failed to retrieve information from the ledger")
            } else {
                error::internal_error("failed to retrieve information from the ledger")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GET /v2/blocks/:round/hash
// ---------------------------------------------------------------------------

/// Returns the block hash for the given round.
///
/// Matches go-algorand's `Handlers.GetBlockHash` in
/// `daemon/algod/api/server/v2/handlers.go`.
///
/// The response is `{"blockHash": "<base32-encoded-digest>"}`.
/// Returns 404 if the round does not exist, 500 on internal error.
pub async fn get_block_hash<N: NodeInterface>(
    State(node): State<AppState<N>>,
    Path(round): Path<u64>,
) -> Response {
    match node.get_block_hash(round).await {
        Ok(Some(digest)) => {
            let response = models::BlockHashResponse {
                block_hash: digest.to_string(),
            };
            match serde_json::to_vec(&response) {
                Ok(body) => {
                    (StatusCode::OK, [("content-type", "application/json")], body).into_response()
                }
                Err(_) => error::internal_error("failed to encode response"),
            }
        }
        Ok(None) => error::not_found("failed to retrieve information from the ledger"),
        Err(_) => error::internal_error("failed to retrieve information from the ledger"),
    }
}

// ---------------------------------------------------------------------------
// Shared genesis field restoration helper
// ---------------------------------------------------------------------------

/// Restore genesis fields on a transaction, matching go-algorand's
/// `DecodeSignedTxn` behavior.
///
/// When `has_genesis_id` is true, the block's genesis ID is copied into the
/// transaction. When `has_genesis_hash` is true or the transaction's genesis
/// hash is all-zeros, the block's genesis hash is copied in.
fn restore_genesis_fields(
    stxn: &algo_types::SignedTransaction,
    block: &algo_types::Block,
) -> algo_types::Transaction {
    let mut txn = stxn.txn.clone();
    if stxn.has_genesis_id {
        txn.genesis_id.clone_from(&block.genesis_id);
    }
    if stxn.has_genesis_hash || txn.genesis_hash == [0u8; 32] {
        txn.genesis_hash = block.genesis_hash;
    }
    txn
}

// ---------------------------------------------------------------------------
// GET /v2/blocks/:round/txids
// ---------------------------------------------------------------------------

/// Returns the transaction IDs for the given block round.
///
/// Matches go-algorand's `Handlers.GetBlockTxids` in
/// `daemon/algod/api/server/v2/handlers.go`.
///
/// The handler fetches the block, restores genesis fields on each transaction
/// (matching go-algorand's `DecodePaysetFlat` → `DecodeSignedTxn`), computes
/// each transaction ID via SHA512/256("TX" || canonical(txn)), and returns
/// them as base32-encoded strings (no padding).
///
/// The response is `{"blockTxids": ["<txid>", ...]}`.
/// Returns 404 if the round does not exist, 500 on internal error.
pub async fn get_block_txids<N: NodeInterface>(
    State(node): State<AppState<N>>,
    Path(round): Path<u64>,
) -> Response {
    let block = match node.get_block(round).await {
        Ok(b) => b,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") || msg.contains("no entry") {
                return error::not_found("failed to retrieve information from the ledger");
            }
            return error::internal_error("failed to retrieve information from the ledger");
        }
    };

    // Compute transaction IDs, restoring genesis fields as go-algorand's
    // DecodeSignedTxn does before computing the ID.
    let txids: Vec<String> = block
        .payset
        .iter()
        .map(|stxn| {
            let txn = restore_genesis_fields(stxn, &block);
            algo_codec::compute_txn_id(&txn).to_string()
        })
        .collect();

    let response = models::BlockTxidsResponse { block_txids: txids };

    match serde_json::to_vec(&response) {
        Ok(body) => (StatusCode::OK, [("content-type", "application/json")], body).into_response(),
        Err(_) => error::internal_error("failed to encode response"),
    }
}

// ---------------------------------------------------------------------------
// GET /v2/blocks/:round/logs
// ---------------------------------------------------------------------------

/// Returns the logs from all app calls in a block, including inner transactions.
///
/// Matches go-algorand's `Handlers.GetBlockLogs` in
/// `daemon/algod/api/server/v2/handlers.go`.
///
/// The response is `{"logs": [AppCallLogs...]}` where each entry has:
/// - `txId`: the outer transaction ID (base32-encoded)
/// - `logs`: array of base64-encoded log byte arrays
/// - `application-index`: the app ID that emitted the logs
///
/// Returns 404 if the round does not exist, 500 on internal error.
pub async fn get_block_logs<N: NodeInterface>(
    State(node): State<AppState<N>>,
    Path(round): Path<u64>,
) -> Response {
    let block = match node.get_block(round).await {
        Ok(b) => b,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") || msg.contains("no entry") {
                return error::not_found("failed to retrieve information from the ledger");
            }
            return error::internal_error("failed to retrieve information from the ledger");
        }
    };

    let mut block_logs: Vec<models::AppCallLogs> = Vec::new();

    for stxn in &block.payset {
        // Compute the outer txn ID (restoring genesis fields as in get_block_txids).
        let txn = restore_genesis_fields(stxn, &block);
        let outer_txid = algo_codec::compute_txn_id(&txn).to_string();

        // Walk the eval_delta rmpv tree to collect logs.
        if let Some(ref eval_delta) = stxn.eval_delta {
            let app_index = get_app_index_from_stxn(stxn);
            collect_logs_from_eval_delta(eval_delta, &outer_txid, app_index, &mut block_logs);
        }
    }

    let response = models::BlockLogsResponse { logs: block_logs };

    match serde_json::to_vec(&response) {
        Ok(body) => (StatusCode::OK, [("content-type", "application/json")], body).into_response(),
        Err(_) => error::internal_error("failed to encode response"),
    }
}

// ---------------------------------------------------------------------------
// GET /v2/blocks/:round/transactions/:txid/proof
// ---------------------------------------------------------------------------

/// Query parameters for the transaction proof endpoint.
#[derive(Debug, Deserialize)]
pub struct TransactionProofParams {
    /// The hash function used to create the proof. Must be "sha256" or
    /// "sha512_256". Default: "sha512_256".
    pub hashtype: Option<String>,
}

/// Path parameters for the transaction proof endpoint.
#[derive(Debug, Deserialize)]
pub struct TransactionProofPath {
    pub round: u64,
    pub txid: String,
}

/// Generates a Merkle proof for a transaction in a block.
///
/// Matches go-algorand's `Handlers.GetTransactionProof` in
/// `daemon/algod/api/server/v2/handlers.go`.
///
/// The handler:
/// 1. Gets the block via `node.get_block(round)`
/// 2. Validates the `hashtype` query param (default: "sha512_256")
/// 3. Checks that the protocol supports Merkle proofs (`payset_commit == 2`)
/// 4. Builds a Merkle tree from the block's payset
/// 5. Finds the transaction index by matching txid
/// 6. Generates a single-leaf Merkle proof
/// 7. Returns `TransactionProofResponse` with: idx, proof, stibhash, treedepth, hashtype
pub async fn get_transaction_proof<N: NodeInterface>(
    State(node): State<AppState<N>>,
    Path(path): Path<TransactionProofPath>,
    Query(params): Query<TransactionProofParams>,
) -> Response {
    // Parse the transaction ID from the path first (matching go-algorand's validation order).
    let txid_bytes = match data_encoding::BASE32_NOPAD.decode(path.txid.as_bytes()) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return error::bad_request("no valid transaction ID was specified");
        }
    };

    // Validate hashtype query parameter (after txid, matching go-algorand's order).
    let hashtype = params.hashtype.as_deref().unwrap_or("sha512_256");
    if hashtype != "sha512_256" && hashtype != "sha256" {
        return error::bad_request("invalid hash type");
    }

    // Fetch the block. go-algorand always returns 500 (internalError) on
    // block lookup failures, regardless of the underlying cause.
    let block = match node.get_block(path.round).await {
        Ok(b) => b,
        Err(_) => {
            return error::internal_error("failed to retrieve information from the ledger");
        }
    };

    // Look up consensus params for this block's protocol version to check
    // whether Merkle proofs are supported and whether SHA-256 VC is enabled.
    let proto = match algo_types::consensus_params_for_version(&block.current_protocol) {
        Some(p) => p,
        None => {
            return error::internal_error("could not find consensus params for block protocol");
        }
    };

    // PAYSET_COMMIT_MERKLE = 2 (from algo_types::consensus)
    const PAYSET_COMMIT_MERKLE: u8 = 2;
    if proto.payset_commit != PAYSET_COMMIT_MERKLE {
        return error::not_found("protocol does not support Merkle proofs");
    }

    if hashtype == "sha256" && !proto.enable_sha256_txn_commitment_header {
        return error::bad_request("protocol does not support sha256 vector commitment proofs");
    }

    // Find the transaction index by matching txid.
    // We must restore genesis fields before computing the ID (matching
    // go-algorand's DecodePaysetFlat → DecodeSignedTxn).
    let mut found_idx = None;
    for (i, stxn) in block.payset.iter().enumerate() {
        let txn = restore_genesis_fields(stxn, &block);
        let computed_id = algo_codec::compute_txn_id(&txn);
        if computed_id.0 == txid_bytes {
            found_idx = Some(i);
            break;
        }
    }

    let idx = match found_idx {
        Some(i) => i,
        None => {
            return error::not_found("could not find the transaction in the transaction pool or in the last 1000 confirmed rounds");
        }
    };

    // Build the Merkle tree and compute the stibhash.
    // The tree leaf data is: H("TL" || txid || stib_hash), where H depends
    // on the hash type, and txid/stib_hash are also computed with the
    // corresponding hash function.
    let payset_array = TxnMerkleArray {
        block: &block,
        hash_type: hashtype,
    };

    let (tree, stibhash) = match hashtype {
        "sha256" => {
            use algo_consensus_crypto::merklearray::{
                build_vector_commitment_tree, HashFactory, HashType,
            };
            let factory = HashFactory::new(HashType::Sha256);
            let tree = match build_vector_commitment_tree(&payset_array, factory) {
                Ok(t) => t,
                Err(e) => {
                    return error::internal_error(format!(
                        "building Vector Commitment (SHA256): {e}"
                    ));
                }
            };
            let stibhash = compute_stib_hash_sha256(&block.payset[idx]);
            (tree, stibhash.to_vec())
        }
        _ => {
            // sha512_256
            use algo_consensus_crypto::merklearray::{build, HashFactory, HashType};
            let factory = HashFactory::new(HashType::Sha512_256);
            let tree = match build(&payset_array, factory) {
                Ok(t) => t,
                Err(e) => {
                    return error::internal_error(format!("building Merkle tree: {e}"));
                }
            };
            let stibhash = compute_stib_hash_sha512_256(&block.payset[idx]);
            (tree, stibhash.to_vec())
        }
    };

    // Generate a single-leaf proof for the transaction.
    let proof = match tree.prove_single_leaf(idx as u64) {
        Ok(p) => p,
        Err(e) => {
            return error::internal_error(format!("generating proof: {e}"));
        }
    };

    let response = models::TransactionProofResponse {
        hashtype: hashtype.to_string(),
        idx: idx as u64,
        proof: proof.get_concatenated_proof(),
        stibhash,
        treedepth: proof.proof.tree_depth as u64,
    };

    match serde_json::to_vec(&response) {
        Ok(body) => (StatusCode::OK, [("content-type", "application/json")], body).into_response(),
        Err(_) => error::internal_error("failed to encode response"),
    }
}

/// Domain separation prefix for transaction ID hashing.
const TX_HASH_PREFIX: &[u8] = b"TX";

/// Domain separation prefix for SignedTxnInBlock hashing.
const STIB_HASH_PREFIX: &[u8] = b"STIB";

/// Domain separation prefix for transaction Merkle tree leaves.
const TL_PREFIX: &[u8] = b"TL";

/// Compute the SignedTxnInBlock hash using SHA-512/256.
///
/// SHA512/256("STIB" || canonical_encode(stib))
fn compute_stib_hash_sha512_256(stx: &algo_types::SignedTransaction) -> [u8; 32] {
    use sha2::{Digest as _, Sha512_256};
    let canonical = algo_codec::canonical_encode_signed_txn_in_block(stx);
    let mut hasher = Sha512_256::new();
    hasher.update(STIB_HASH_PREFIX);
    hasher.update(&canonical);
    hasher.finalize().into()
}

/// Compute the SignedTxnInBlock hash using SHA-256.
///
/// SHA256("STIB" || canonical_encode(stib))
fn compute_stib_hash_sha256(stx: &algo_types::SignedTransaction) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let canonical = algo_codec::canonical_encode_signed_txn_in_block(stx);
    let mut hasher = Sha256::new();
    hasher.update(STIB_HASH_PREFIX);
    hasher.update(&canonical);
    hasher.finalize().into()
}

/// Compute the transaction ID using SHA-256.
///
/// SHA256("TX" || canonical_encode(txn))
fn compute_txn_id_sha256(txn: &algo_types::Transaction) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let canonical = algo_codec::canonical_encode_transaction(txn);
    let mut hasher = Sha256::new();
    hasher.update(TX_HASH_PREFIX);
    hasher.update(&canonical);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// GET /v2/blocks/:round/lightheader/proof
// ---------------------------------------------------------------------------

/// Write an unsigned integer in the most compact msgpack representation.
///
/// Matches go-algorand's codec encoding with `PositiveIntUnsigned=true`:
/// - 0-127: single byte (positive fixint)
/// - 128-255: 0xcc + 1 byte
/// - 256-65535: 0xcd + 2 bytes
/// - 65536-4294967295: 0xce + 4 bytes
/// - larger: 0xcf + 8 bytes
fn write_compact_uint(buf: &mut Vec<u8>, val: u64) {
    if val <= 127 {
        buf.push(val as u8);
    } else if val <= 0xFF {
        buf.push(0xcc);
        buf.push(val as u8);
    } else if val <= 0xFFFF {
        buf.push(0xcd);
        buf.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= 0xFFFF_FFFF {
        buf.push(0xce);
        buf.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        buf.push(0xcf);
        buf.extend_from_slice(&val.to_be_bytes());
    }
}

/// Domain separation prefix for LightBlockHeader hashing (SHA-256).
///
/// Matches go-algorand's `protocol.BlockHeader256` hash ID = "B256".
const LIGHT_BLOCK_HEADER_HASH_PREFIX: &[u8] = b"B256";

/// A lightweight representation of a block header used in state proofs.
///
/// Matches go-algorand's `bookkeeping.LightBlockHeader`.
/// Fields are ordered by their codec tags: "0", "1", "gh", "r", "tc".
struct LightBlockHeader {
    /// Sortition seed (codec "0"). Used when `StateProofBlockHashInLightHeader` is false.
    seed: [u8; 32],
    /// Block hash (codec "1"). Used when `StateProofBlockHashInLightHeader` is true.
    block_hash: [u8; 32],
    /// Round number (codec "r").
    round: u64,
    /// Genesis hash (codec "gh").
    genesis_hash: [u8; 32],
    /// SHA-256 transaction commitment (codec "tc").
    sha256_txn_commitment: Vec<u8>,
}

impl algo_consensus_crypto::merklearray::Hashable for LightBlockHeader {
    fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
        // Canonical msgpack encoding matching go-algorand's `protocol.Encode(&lbh)`.
        // The LightBlockHeader struct uses codec tags: "0", "1", "gh", "r", "tc"
        // with `omitempty`. We encode it manually in sorted key order.
        let mut data = Vec::with_capacity(128);

        // Count non-empty fields for the map header.
        let mut field_count: u32 = 0;
        let has_seed = self.seed != [0u8; 32];
        let has_block_hash = self.block_hash != [0u8; 32];
        let has_genesis_hash = self.genesis_hash != [0u8; 32];
        let has_round = self.round != 0;
        let has_tc = !self.sha256_txn_commitment.is_empty();

        if has_seed {
            field_count += 1;
        }
        if has_block_hash {
            field_count += 1;
        }
        if has_genesis_hash {
            field_count += 1;
        }
        if has_round {
            field_count += 1;
        }
        if has_tc {
            field_count += 1;
        }

        // Write map header (fixmap for <= 15 fields).
        if field_count <= 15 {
            data.push(0x80 | field_count as u8);
        } else {
            data.push(0xde);
            data.extend_from_slice(&(field_count as u16).to_be_bytes());
        }

        // Fields in sorted codec key order: "0", "1", "gh", "r", "tc"
        if has_seed {
            // Key "0" (fixstr 1)
            data.push(0xa1);
            data.push(b'0');
            // Value: bin 32
            data.push(0xc4);
            data.push(32);
            data.extend_from_slice(&self.seed);
        }

        if has_block_hash {
            // Key "1" (fixstr 1)
            data.push(0xa1);
            data.push(b'1');
            // Value: bin 32
            data.push(0xc4);
            data.push(32);
            data.extend_from_slice(&self.block_hash);
        }

        if has_genesis_hash {
            // Key "gh" (fixstr 2)
            data.push(0xa2);
            data.extend_from_slice(b"gh");
            // Value: bin 32
            data.push(0xc4);
            data.push(32);
            data.extend_from_slice(&self.genesis_hash);
        }

        if has_round {
            // Key "r" (fixstr 1)
            data.push(0xa1);
            data.push(b'r');
            // Value: compact unsigned integer (matching go-algorand's codec
            // which uses PositiveIntUnsigned=true compact encoding).
            write_compact_uint(&mut data, self.round);
        }

        if has_tc {
            // Key "tc" (fixstr 2)
            data.push(0xa2);
            data.extend_from_slice(b"tc");
            // Value: bin N
            let tc_len = self.sha256_txn_commitment.len();
            if tc_len <= 255 {
                data.push(0xc4);
                data.push(tc_len as u8);
            } else {
                data.push(0xc5);
                data.extend_from_slice(&(tc_len as u16).to_be_bytes());
            }
            data.extend_from_slice(&self.sha256_txn_commitment);
        }

        (LIGHT_BLOCK_HEADER_HASH_PREFIX, data)
    }
}

/// Array adapter for building a vector commitment tree over light block headers.
///
/// Matches go-algorand's `lightBlockHeaders` type in
/// `stateproof/stateproofMessageGenerator.go`.
struct LightBlockHeaderArray {
    headers: Vec<LightBlockHeader>,
}

impl algo_consensus_crypto::merklearray::Array for LightBlockHeaderArray {
    fn length(&self) -> u64 {
        self.headers.len() as u64
    }

    fn marshal(
        &self,
        pos: u64,
    ) -> Result<
        Box<dyn algo_consensus_crypto::merklearray::Hashable>,
        algo_consensus_crypto::merklearray::MerkleError,
    > {
        let pos = pos as usize;
        if pos >= self.headers.len() {
            return Err(
                algo_consensus_crypto::merklearray::MerkleError::PosOutOfBound {
                    pos: pos as u64,
                    bound: self.headers.len() as u64,
                },
            );
        }

        // We need to return an owned Hashable. Clone the header data into a
        // new LightBlockHeader.
        let hdr = &self.headers[pos];
        Ok(Box::new(LightBlockHeader {
            seed: hdr.seed,
            block_hash: hdr.block_hash,
            round: hdr.round,
            genesis_hash: hdr.genesis_hash,
            sha256_txn_commitment: hdr.sha256_txn_commitment.clone(),
        }))
    }
}

/// Convert a `BlockHeader` into a `LightBlockHeader`.
///
/// Matches go-algorand's `BlockHeader.ToLightBlockHeader()`.
fn to_light_block_header(
    bh: &algo_types::BlockHeader,
    state_proof_block_hash_in_light_header: bool,
) -> LightBlockHeader {
    let mut lbh = LightBlockHeader {
        seed: [0u8; 32],
        block_hash: [0u8; 32],
        round: bh.round.0,
        genesis_hash: bh.genesis_hash,
        sha256_txn_commitment: bh.txn256.to_vec(),
    };

    if state_proof_block_hash_in_light_header {
        // Use block hash: SHA-512/256("BH" || canonical_encode(block_header)).
        // This matches go-algorand's `bh.Hash()` which uses `crypto.HashObj(bh)`.
        use sha2::{Digest as _, Sha512_256};
        let canonical = algo_codec::canonical_encode_block_header(bh);
        let mut hasher = Sha512_256::new();
        hasher.update(b"BH");
        hasher.update(&canonical);
        lbh.block_hash = hasher.finalize().into();
    } else {
        lbh.seed = bh.seed;
    }

    lbh
}

/// Handler for `GET /v2/blocks/{round}/lightheader/proof`.
///
/// Returns a Merkle proof of the light block header for the given round
/// within the state proof interval that covers it.
///
/// Matches go-algorand's `GetLightBlockHeaderProof` handler.
pub async fn get_light_block_header_proof<N: NodeInterface>(
    State(node): State<AppState<N>>,
    Path(round): Path<u64>,
) -> Response {
    // Check that the requested round is not beyond the latest round.
    let status = match node.status().await {
        Ok(s) => s,
        Err(e) => {
            return error::internal_error(format!("could not get node status: {e}"));
        }
    };

    if round > status.last_round {
        return error::internal_error("given round is greater than the latest round");
    }

    // Get the state proof transaction that covers this round.
    let (first_attested_round, last_attested_round) =
        match node.get_state_proof_transaction_for_round(round).await {
            Ok(range) => range,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("no state proof") || msg.contains("not found") {
                    return error::not_found(msg);
                }
                return error::internal_error(msg);
            }
        };

    let state_proof_interval = last_attested_round
        .saturating_sub(first_attested_round)
        .saturating_add(1);

    if state_proof_interval > 1_000_000 {
        return error::internal_error("state proof interval exceeds reasonable bounds");
    }

    // Fetch all block headers in the attested range and convert to light headers.
    let mut light_headers = Vec::with_capacity(state_proof_interval as usize);
    for r in first_attested_round..=last_attested_round {
        let hdr = match node.get_block_header(r).await {
            Ok(h) => h,
            Err(e) => {
                return error::not_found(format!(
                    "could not retrieve block header for round {r}: {e}"
                ));
            }
        };

        // Look up consensus params to determine if block hash should be
        // used in the light header (vs seed).
        let proto = match algo_types::consensus_params_for_version(&hdr.current_protocol) {
            Some(p) => p,
            None => {
                return error::internal_error(format!(
                    "could not find consensus params for protocol version: {}",
                    hdr.current_protocol
                ));
            }
        };

        light_headers.push(to_light_block_header(
            &hdr,
            proto.state_proof_block_hash_in_light_header,
        ));
    }

    let block_index = round - first_attested_round;

    // Build the vector commitment tree and generate a proof.
    let array = LightBlockHeaderArray {
        headers: light_headers,
    };

    use algo_consensus_crypto::merklearray::{build_vector_commitment_tree, HashFactory, HashType};
    let factory = HashFactory::new(HashType::Sha256);
    let tree = match build_vector_commitment_tree(&array, factory) {
        Ok(t) => t,
        Err(e) => {
            return error::internal_error(format!(
                "building vector commitment tree for light block headers: {e}"
            ));
        }
    };

    let proof = match tree.prove_single_leaf(block_index) {
        Ok(p) => p,
        Err(e) => {
            return error::internal_error(format!("generating proof: {e}"));
        }
    };

    let response = models::LightBlockHeaderProofResponse {
        index: block_index,
        proof: proof.get_concatenated_proof(),
        treedepth: proof.proof.tree_depth as u64,
    };

    match serde_json::to_vec(&response) {
        Ok(body) => (StatusCode::OK, [("content-type", "application/json")], body).into_response(),
        Err(_) => error::internal_error("failed to encode response"),
    }
}

/// Array adapter for building a Merkle tree from a block's payset.
///
/// Implements the `merklearray::Array` trait, matching go-algorand's
/// `txnMerkleArray` in `data/bookkeeping/txn_merkle.go`.
struct TxnMerkleArray<'a> {
    block: &'a algo_types::Block,
    hash_type: &'a str,
}

/// A single element of the txn Merkle tree, representing the leaf data.
///
/// Implements the `merklearray::Hashable` trait, matching go-algorand's
/// `txnMerkleElem` in `data/bookkeeping/txn_merkle.go`.
///
/// The leaf value is: `HashID("TL") || txid || stib_hash`
struct TxnMerkleElem {
    txid: [u8; 32],
    stib_hash: [u8; 32],
}

impl algo_consensus_crypto::merklearray::Hashable for TxnMerkleElem {
    fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&self.txid);
        data.extend_from_slice(&self.stib_hash);
        (TL_PREFIX, data)
    }
}

impl algo_consensus_crypto::merklearray::Array for TxnMerkleArray<'_> {
    fn length(&self) -> u64 {
        self.block.payset.len() as u64
    }

    fn marshal(
        &self,
        pos: u64,
    ) -> Result<
        Box<dyn algo_consensus_crypto::merklearray::Hashable>,
        algo_consensus_crypto::merklearray::MerkleError,
    > {
        let pos = pos as usize;
        if pos >= self.block.payset.len() {
            return Err(
                algo_consensus_crypto::merklearray::MerkleError::PosOutOfBound {
                    pos: pos as u64,
                    bound: self.block.payset.len() as u64,
                },
            );
        }

        let stxn = &self.block.payset[pos];

        // Restore genesis fields for txid computation (matching go-algorand's
        // DecodeSignedTxn behavior).
        let restored_txn = restore_genesis_fields(stxn, self.block);

        let (txid, stib_hash) = match self.hash_type {
            "sha256" => {
                let txid = compute_txn_id_sha256(&restored_txn);
                let stib_hash = compute_stib_hash_sha256(stxn);
                (txid, stib_hash)
            }
            _ => {
                // sha512_256
                let txid = algo_codec::compute_txn_id(&restored_txn).0;
                let stib_hash = compute_stib_hash_sha512_256(stxn);
                (txid, stib_hash)
            }
        };

        Ok(Box::new(TxnMerkleElem { txid, stib_hash }))
    }
}

/// Get the effective application index from a signed transaction.
///
/// Matches go-algorand's `getAppIndexFromTxn`: uses `txn.ApplicationID` unless
/// it is 0 (app creation), in which case uses `ApplyData.ApplicationID`.
fn get_app_index_from_stxn(stxn: &algo_types::SignedTransaction) -> u64 {
    let app_id = stxn.txn.application_id;
    if app_id == 0 {
        stxn.apply_data_application_id
    } else {
        app_id
    }
}

/// Collect logs from an eval_delta rmpv::Value tree.
///
/// This mirrors go-algorand's `appendLogsFromTxns` but operates on the raw
/// rmpv::Value tree instead of fully decoded structs. The eval_delta is
/// expected to be a Map with:
/// - "lg": array of log byte values
/// - "itx": array of inner transaction maps (each with their own eval_delta)
fn collect_logs_from_eval_delta(
    eval_delta: &rmpv::Value,
    outer_txid: &str,
    app_index: u64,
    block_logs: &mut Vec<models::AppCallLogs>,
) {
    let map = match eval_delta {
        rmpv::Value::Map(m) => m,
        _ => return,
    };

    let mut logs_val: Option<&rmpv::Value> = None;
    let mut itx_val: Option<&rmpv::Value> = None;

    for (k, v) in map {
        if let Some(key) = rmpv_key_str(k) {
            match key {
                "lg" => logs_val = Some(v),
                "itx" => itx_val = Some(v),
                _ => {}
            }
        }
    }

    // Collect logs from this eval_delta (outer or inner txn).
    if let Some(rmpv::Value::Array(lg_arr)) = logs_val {
        if !lg_arr.is_empty() {
            let logs: Vec<Vec<u8>> = lg_arr.iter().filter_map(rmpv_as_bytes).collect();
            if !logs.is_empty() {
                block_logs.push(models::AppCallLogs {
                    application_index: app_index,
                    logs,
                    tx_id: outer_txid.to_string(),
                });
            }
        }
    }

    // Recurse into inner transactions.
    if let Some(rmpv::Value::Array(itx_arr)) = itx_val {
        for inner in itx_arr {
            if let rmpv::Value::Map(inner_map) = inner {
                let inner_app_index = get_app_index_from_rmpv_map(inner_map);
                // Find the inner txn's eval_delta ("dt" key).
                let inner_eval_delta = inner_map.iter().find_map(|(k, v)| {
                    if rmpv_key_str(k) == Some("dt") {
                        Some(v)
                    } else {
                        None
                    }
                });
                if let Some(dt) = inner_eval_delta {
                    collect_logs_from_eval_delta(dt, outer_txid, inner_app_index, block_logs);
                }
            }
        }
    }
}

/// Get the app index from an inner transaction rmpv::Value map.
///
/// Looks for "txn" -> "apid" (application_id) and falls back to
/// "apid" at the top level (apply_data_application_id for app creates).
fn get_app_index_from_rmpv_map(map: &[(rmpv::Value, rmpv::Value)]) -> u64 {
    let mut txn_app_id: u64 = 0;
    let mut apply_data_app_id: u64 = 0;

    for (k, v) in map {
        if let Some(key) = rmpv_key_str(k) {
            match key {
                "txn" => {
                    // Look for "apid" inside the txn map.
                    if let rmpv::Value::Map(txn_map) = v {
                        for (tk, tv) in txn_map {
                            if rmpv_key_str(tk) == Some("apid") {
                                txn_app_id = rmpv_as_u64(tv).unwrap_or(0);
                            }
                        }
                    }
                }
                "apid" => {
                    apply_data_app_id = rmpv_as_u64(v).unwrap_or(0);
                }
                _ => {}
            }
        }
    }

    if txn_app_id != 0 {
        txn_app_id
    } else {
        apply_data_app_id
    }
}

/// Helper: extract a string from an rmpv key value.
fn rmpv_key_str(val: &rmpv::Value) -> Option<&str> {
    match val {
        rmpv::Value::String(s) => s.as_str(),
        _ => None,
    }
}

/// Helper: extract bytes from an rmpv::Value (Binary or String).
fn rmpv_as_bytes(val: &rmpv::Value) -> Option<Vec<u8>> {
    match val {
        rmpv::Value::Binary(b) => Some(b.clone()),
        rmpv::Value::String(s) => Some(s.as_bytes().to_vec()),
        _ => None,
    }
}

/// Helper: extract a u64 from an rmpv::Value.
fn rmpv_as_u64(val: &rmpv::Value) -> Option<u64> {
    match val {
        rmpv::Value::Integer(i) => i.as_u64(),
        _ => None,
    }
}

/// Compute the effective max keys for the application boxes endpoint,
/// matching go-algorand's `applicationBoxesMaxKeys` function.
fn application_boxes_max_keys(requested_max: u64, algod_max: u64) -> u64 {
    if requested_max == 0 {
        if algod_max == 0 {
            return u64::MAX; // unlimited results when both requested and algod max are 0
        }
        return algod_max.saturating_add(1); // API limit dominates. Increments by 1 to test if more than max supported results exist.
    }

    if requested_max <= algod_max || algod_max == 0 {
        return requested_max; // requested limit dominates
    }

    algod_max.saturating_add(1) // API limit dominates. Increments by 1 to test if more than max supported results exist.
}
