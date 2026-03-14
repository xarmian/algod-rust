//! Health check HTTP endpoint.
//!
//! Mirrors go-algorand's `rpcs/healthService.go` which registers a `GET /status`
//! handler that returns HTTP 200 to indicate the node is reachable.  Our Rust
//! version enriches the response with a small JSON body for convenience.

use axum::{routing::get, Json, Router};
use serde::Serialize;

/// Path for the health-check endpoint (matches go-algorand's
/// `HealthServiceStatusPath`).
pub const HEALTH_SERVICE_STATUS_PATH: &str = "/status";

/// JSON payload returned by the health endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

/// Axum handler that returns HTTP 200 with `{"status":"ok"}`.
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// Build an [`axum::Router`] with `GET /status` mapped to [`health_check`].
pub fn health_router() -> Router {
    Router::new().route(HEALTH_SERVICE_STATUS_PATH, get(health_check))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::{Request, StatusCode};
    use tower::ServiceExt; // for `oneshot`

    /// Helper: send a GET /status to the health router and return (status, body bytes).
    async fn do_health_request() -> (StatusCode, Vec<u8>) {
        let app = health_router();
        let req = Request::builder()
            .uri("/status")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, body.to_vec())
    }

    #[tokio::test]
    async fn health_returns_200() {
        let (status, _) = do_health_request().await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn health_returns_expected_json() {
        let (_, body) = do_health_request().await;
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], "ok");
    }

    #[tokio::test]
    async fn health_response_content_type_is_json() {
        let app = health_router();
        let req = Request::builder()
            .uri("/status")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        let ct = response
            .headers()
            .get("content-type")
            .expect("content-type header present")
            .to_str()
            .unwrap();
        assert!(
            ct.contains("application/json"),
            "expected application/json, got {ct}"
        );
    }
}
