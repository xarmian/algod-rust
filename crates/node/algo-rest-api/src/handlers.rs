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

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::error;
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
                    && status.catchup_time == 0;

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
pub async fn transaction_params<N: NodeInterface>(
    State(node): State<AppState<N>>,
) -> Response {
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
