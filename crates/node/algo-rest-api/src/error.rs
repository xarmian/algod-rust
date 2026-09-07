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

//! Error response types matching go-algorand's REST API error format.
//!
//! go-algorand returns errors as JSON with a `message` field and an optional
//! `data` map (only populated for structured `SError` values). For our initial
//! implementation we include `message` and `data` to match the wire format.

use algo_error::{AvmDiagnosticValue, AvmErrorDetail, AvmEvalStateDump};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// JSON error response body matching go-algorand's `model.ErrorResponse`.
///
/// ```json
/// {"message": "human-readable error description", "data": null}
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    /// Optional structured error data. Matches go-algorand's
    /// `Data *map[string]interface{}` field -- almost always `None`/null.
    /// Placed before `message` to match go-algorand's field ordering
    /// (serde serializes in declaration order).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Map<String, serde_json::Value>>,

    /// Human-readable error message.
    pub message: String,
}

impl ErrorResponse {
    /// Create an error response with only a message (no data).
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            data: None,
        }
    }
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        // Default to 500; callers should use the helper functions instead
        // which attach the correct status code.
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", "application/json")],
            serde_json::to_string(&self)
                .unwrap_or_else(|_| r#"{"message":"internal error"}"#.to_string()),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// Helper functions that return axum Responses with the correct status code
// ---------------------------------------------------------------------------

/// Return a 400 Bad Request JSON error response.
pub fn bad_request(msg: impl Into<String>) -> Response {
    error_response(StatusCode::BAD_REQUEST, msg)
}

/// Return a 404 Not Found JSON error response.
pub fn not_found(msg: impl Into<String>) -> Response {
    error_response(StatusCode::NOT_FOUND, msg)
}

/// Return a 500 Internal Server Error JSON error response.
pub fn internal_error(msg: impl Into<String>) -> Response {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, msg)
}

/// Return a 408 Request Timeout JSON error response.
pub fn timeout(msg: impl Into<String>) -> Response {
    error_response(StatusCode::REQUEST_TIMEOUT, msg)
}

/// Return a 501 Not Implemented JSON error response.
pub fn not_implemented(msg: impl Into<String>) -> Response {
    error_response(StatusCode::NOT_IMPLEMENTED, msg)
}

/// Return a 503 Service Unavailable JSON error response.
pub fn service_unavailable(msg: impl Into<String>) -> Response {
    error_response(StatusCode::SERVICE_UNAVAILABLE, msg)
}

/// Build a JSON error response for an arbitrary status code and message.
///
/// Used by [`crate::error_envelope`] to rewrite non-JSON error responses
/// (e.g. axum's default extractor-rejection bodies) into go-algorand's
/// envelope while preserving the original status code.
pub fn error_response_for_status(status: StatusCode, msg: impl Into<String>) -> Response {
    error_response(status, msg)
}

/// Build a JSON error response with the given status code and message.
fn error_response(status: StatusCode, msg: impl Into<String>) -> Response {
    let body = ErrorResponse::new(msg);
    let json = serde_json::to_string(&body)
        .unwrap_or_else(|_| r#"{"message":"internal error"}"#.to_string());
    (status, [("content-type", "application/json")], json).into_response()
}

// ---------------------------------------------------------------------------
// Structured AVM eval diagnostics (issue #1135)
// ---------------------------------------------------------------------------

/// Return a 400 Bad Request JSON error response carrying structured AVM
/// eval diagnostics in `data`, matching go-algorand's `returnError()`
/// (`daemon/algod/api/server/v2/utils.go:51`), which copies a
/// `*basics.SError`'s `Attrs` map into `ErrorResponse.Data` when the
/// internal error is (or wraps) one.
pub fn bad_request_with_detail(msg: impl Into<String>, detail: &AvmErrorDetail) -> Response {
    error_response_with_data(
        StatusCode::BAD_REQUEST,
        msg,
        avm_error_detail_to_data(detail),
    )
}

/// Build a JSON error response with the given status code, message, and
/// structured `data` map.
fn error_response_with_data(
    status: StatusCode,
    msg: impl Into<String>,
    data: serde_json::Map<String, serde_json::Value>,
) -> Response {
    let body = ErrorResponse {
        data: Some(data),
        message: msg.into(),
    };
    let json = serde_json::to_string(&body)
        .unwrap_or_else(|_| r#"{"message":"internal error"}"#.to_string());
    (status, [("content-type", "application/json")], json).into_response()
}

/// Convert an [`AvmErrorDetail`] into go-algorand's exact
/// `basics.SError.Attrs` JSON shape: `pc`, `group-index`, `app-index`
/// (only when set), and `eval-states` (an array of per-transaction
/// `{"scratch": [...], "stack": [...]}` dumps, mirroring go's `evalState`
/// struct -- see `cx.evalStates()`, `data/transactions/logic/eval.go`).
pub fn avm_error_detail_to_data(
    detail: &AvmErrorDetail,
) -> serde_json::Map<String, serde_json::Value> {
    let mut data = serde_json::Map::new();
    data.insert("pc".to_string(), serde_json::json!(detail.pc));
    data.insert(
        "group-index".to_string(),
        serde_json::json!(detail.group_index),
    );
    if let Some(app_index) = detail.app_index {
        data.insert("app-index".to_string(), serde_json::json!(app_index));
    }
    let states: Vec<serde_json::Value> = detail
        .eval_states
        .iter()
        .map(avm_eval_state_dump_to_json)
        .collect();
    data.insert("eval-states".to_string(), serde_json::Value::Array(states));
    data
}

/// Convert one [`AvmEvalStateDump`] into go's `evalState` JSON shape.
/// `scratch`/`stack` are omitted entirely when empty, matching go's
/// `json:"scratch,omitempty"`/`json:"stack,omitempty"` struct tags.
fn avm_eval_state_dump_to_json(dump: &AvmEvalStateDump) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    if !dump.scratch.is_empty() {
        obj.insert(
            "scratch".to_string(),
            serde_json::Value::Array(
                dump.scratch
                    .iter()
                    .map(avm_diagnostic_value_to_json)
                    .collect(),
            ),
        );
    }
    if !dump.stack.is_empty() {
        obj.insert(
            "stack".to_string(),
            serde_json::Value::Array(
                dump.stack
                    .iter()
                    .map(avm_diagnostic_value_to_json)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(obj)
}

/// Convert a single [`AvmDiagnosticValue`] into go's untyped
/// `stackValue.asAny()` JSON encoding: a `uint64` stays a JSON number; a
/// byte slice is base64-encoded, matching `encoding/json`'s default
/// `[]byte` handling (which is what go's `ctx.JSON` uses to marshal the
/// `Attrs map[string]any` values).
fn avm_diagnostic_value_to_json(v: &AvmDiagnosticValue) -> serde_json::Value {
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;
    match v {
        AvmDiagnosticValue::Uint(u) => serde_json::json!(u),
        AvmDiagnosticValue::Bytes(b) => serde_json::Value::String(BASE64_STANDARD.encode(b)),
    }
}

// ---------------------------------------------------------------------------
// Typed-error helpers
// ---------------------------------------------------------------------------

use crate::node::NodeError;

/// Map a `NodeError` from a ledger lookup to an HTTP error response.
///
/// Used by block-related handlers where the error message is always
/// "failed to retrieve information from the ledger".
pub fn ledger_error_response(e: NodeError) -> Response {
    match e {
        NodeError::NotFound(_) => not_found("failed to retrieve information from the ledger"),
        NodeError::BadRequest(msg) => bad_request(msg),
        NodeError::BadRequestWithDetail(msg, detail) => bad_request_with_detail(msg, &detail),
        NodeError::Timeout(_) | NodeError::NotImplemented(_) | NodeError::Internal(_) => {
            internal_error("failed to retrieve information from the ledger")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn bad_request_returns_400() {
        let resp = bad_request("invalid parameter");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["message"], "invalid parameter");
    }

    #[tokio::test]
    async fn not_found_returns_404() {
        let resp = not_found("resource not found");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn internal_error_returns_500() {
        let resp = internal_error("something broke");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn service_unavailable_returns_503() {
        let resp = service_unavailable("node is catching up");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn not_implemented_returns_501() {
        let resp = not_implemented("not supported");
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn timeout_returns_408() {
        let resp = timeout("operation timed out");
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn error_response_omits_null_data() {
        let body = ErrorResponse::new("test");
        let json = serde_json::to_string(&body).unwrap();
        // data should be omitted entirely when None
        assert!(!json.contains("data"));
    }

    // -----------------------------------------------------------------------
    // Structured AVM eval diagnostics (issue #1135)
    // -----------------------------------------------------------------------

    /// TDD pin for issue #1135: `bad_request_with_detail` must populate
    /// `ErrorResponse.data` with go-algorand's exact `basics.SError.Attrs`
    /// key names (`pc`, `group-index`, `app-index`, `eval-states`) --
    /// matching `returnError()` (`daemon/algod/api/server/v2/utils.go:51`).
    #[tokio::test]
    async fn bad_request_with_detail_populates_data_with_go_key_names() {
        let detail = AvmErrorDetail {
            pc: 7,
            group_index: 0,
            app_index: Some(1234),
            eval_states: vec![AvmEvalStateDump {
                scratch: vec![AvmDiagnosticValue::Uint(5)],
                stack: vec![
                    AvmDiagnosticValue::Uint(100),
                    AvmDiagnosticValue::Bytes(vec![0x02, 0x01]),
                ],
            }],
        };

        let resp = bad_request_with_detail("app 1234 approval program rejected", &detail);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let data = &parsed["data"];

        assert_eq!(data["pc"], 7);
        assert_eq!(data["group-index"], 0);
        assert_eq!(data["app-index"], 1234);

        let states = data["eval-states"].as_array().expect("eval-states array");
        assert_eq!(states.len(), 1);
        assert_eq!(states[0]["scratch"], serde_json::json!([5]));
        assert_eq!(states[0]["stack"], serde_json::json!([100, "AgE="])); // base64(0x02, 0x01)

        assert_eq!(
            parsed["message"],
            "app 1234 approval program rejected"
        );
    }

    /// A LogicSig failure (no app-index) must omit the `app-index` key
    /// entirely rather than emitting `null`, matching go's `if cx.runMode
    /// == ModeApp` gate on attaching that attribute at all.
    #[tokio::test]
    async fn bad_request_with_detail_omits_app_index_for_logicsig() {
        let detail = AvmErrorDetail {
            pc: 3,
            group_index: 0,
            app_index: None,
            eval_states: vec![AvmEvalStateDump::default()],
        };

        let resp = bad_request_with_detail("logic eval error", &detail);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let data = &parsed["data"];

        assert!(data.get("app-index").is_none());
        // An empty scratch/stack dump omits both keys (go's `omitempty`).
        assert_eq!(data["eval-states"][0], serde_json::json!({}));
    }
}
