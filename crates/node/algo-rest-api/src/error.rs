//! Error response types matching go-algorand's REST API error format.
//!
//! go-algorand returns errors as JSON with a `message` field and an optional
//! `data` map (only populated for structured `SError` values). For our initial
//! implementation we include `message` and `data` to match the wire format.

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
    /// Human-readable error message.
    pub message: String,

    /// Optional structured error data. Matches go-algorand's
    /// `Data *map[string]interface{}` field -- almost always `None`/null.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Map<String, serde_json::Value>>,
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

/// Return a 503 Service Unavailable JSON error response.
pub fn service_unavailable(msg: impl Into<String>) -> Response {
    error_response(StatusCode::SERVICE_UNAVAILABLE, msg)
}

/// Build a JSON error response with the given status code and message.
fn error_response(status: StatusCode, msg: impl Into<String>) -> Response {
    let body = ErrorResponse::new(msg);
    let json = serde_json::to_string(&body)
        .unwrap_or_else(|_| r#"{"message":"internal error"}"#.to_string());
    (status, [("content-type", "application/json")], json).into_response()
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
    async fn error_response_omits_null_data() {
        let body = ErrorResponse::new("test");
        let json = serde_json::to_string(&body).unwrap();
        // data should be omitted entirely when None
        assert!(!json.contains("data"));
    }
}
