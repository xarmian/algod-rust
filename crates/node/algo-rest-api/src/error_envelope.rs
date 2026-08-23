//! Router-level guarantees that every error response carries go-algorand's
//! JSON error envelope (`{"message": "...", "data": null}`).
//!
//! go-algorand's `returnError` (`daemon/algod/api/server/v2/utils.go`) is the
//! single choke point for every handler-level error, so every 4xx/5xx
//! response it produces is unconditionally JSON with a `message` field. Two
//! response sources in the Rust router sit outside that guarantee because
//! they never reach a handler at all:
//!
//! - **No route matched.** axum's built-in fallback returns an empty body.
//!   [`unmatched_route_fallback`] replaces it with go's exact
//!   `404 {"message":"Not Found"}` (Echo's default `HTTPErrorHandler` for a
//!   404), and — critically — requires no authentication, matching go's
//!   routing-before-middleware order: Echo determines there is no matching
//!   route (and therefore no middleware chain to run) before any auth check.
//! - **Extractor rejections.** A malformed path/query parameter (e.g.
//!   `GET /v2/blocks/notanumber`) fails inside axum's `Path`/`Query`
//!   extractors before the handler body runs, producing axum's default
//!   `text/plain` rejection body. [`json_envelope_layer`] rewrites any
//!   non-JSON 4xx/5xx response into the same envelope, using the rejection's
//!   own message text.
//!
//! Verified live against go-algorand v4.6.0-stable — see issue #129.

use axum::body::to_bytes;
use axum::extract::Request;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error;

/// Router fallback for requests that matched no registered route.
///
/// Registered via `Router::fallback` on the fully-merged router (after every
/// sub-router's `.layer(...)` auth middleware has already been applied), so
/// it is reached directly without passing through any tier's token check —
/// matching go-algorand, where an unmatched path 404s before routing even
/// selects a middleware chain to run.
pub async fn unmatched_route_fallback() -> Response {
    error::not_found("Not Found")
}

/// Build a plain-text response opted out of the JSON-envelope rewrite.
///
/// For the handful of go-algorand handlers that intentionally respond with
/// plain text (`ctx.String(...)`) instead of the JSON error envelope — the
/// `EnableDeveloperAPI`/`EnableExperimentalAPI`-disabled 404s for
/// `/teal/compile`, `/teal/disassemble`, `/teal/dryrun`,
/// `/v2/accounts/{address}/assets`, and `/v2/transactions/async`, plus
/// `ShutdownNode`'s 501 — so the router's blanket JSON-envelope rewrite
/// doesn't make them diverge from the real go-algorand response they
/// deliberately match.
pub fn plain_text_response(status: StatusCode, body: &'static str) -> Response {
    let mut response = (status, body).into_response();
    response.extensions_mut().insert(SkipEnvelopeRewrite);
    response
}

/// Maximum rejection-body size to buffer for rewriting. Extractor rejection
/// messages are always short, human-readable strings; this is a generous
/// defensive ceiling, not a realistic expected size.
const MAX_REWRAP_BODY_BYTES: usize = 8192;

/// Marker inserted into a handler's response extensions to opt it out of the
/// JSON-envelope rewrite.
///
/// Reserved for the rare handler that intentionally mirrors a go-algorand
/// endpoint whose own implementation returns plain text instead of the
/// standard envelope — e.g. `ShutdownNode`'s `ctx.String(501, "Endpoint not
/// implemented.")` (`handlers.go:407`), rather than the usual
/// `returnError`/`ctx.JSON` path every other handler uses. Without this
/// opt-out the rewrite would make that one endpoint *more* correct in
/// isolation but *less* conformant with the real go-algorand response it is
/// deliberately matching.
#[derive(Clone, Copy)]
pub struct SkipEnvelopeRewrite;

/// Middleware that rewrites any non-JSON 4xx/5xx response into go-algorand's
/// `{"message": "..."}` envelope.
///
/// Every error path that already runs through a handler (including this
/// crate's [`error`] helpers) already emits `application/json`, so this is a
/// no-op for them; it only rewrites responses this router never intended to
/// author itself — chiefly axum's default extractor-rejection bodies. A
/// handler can opt out entirely by inserting [`SkipEnvelopeRewrite`] into its
/// response extensions.
pub async fn json_envelope_layer(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    let status = response.status();
    if !status.is_client_error() && !status.is_server_error() {
        return response;
    }
    if response.extensions().get::<SkipEnvelopeRewrite>().is_some() {
        return response;
    }

    let already_json = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/json"))
        .unwrap_or(false);
    if already_json {
        return response;
    }

    let (parts, body) = response.into_parts();
    let message = match to_bytes(body, MAX_REWRAP_BODY_BYTES).await {
        Ok(bytes) if !bytes.is_empty() => String::from_utf8_lossy(&bytes).into_owned(),
        _ => parts
            .status
            .canonical_reason()
            .unwrap_or("error")
            .to_string(),
    };

    let mut rewritten = error::error_response_for_status(parts.status, message);
    // Preserve any non-Content-Type headers the original response carried
    // (e.g. `Allow` on a 405), then force the envelope's own Content-Type.
    for (name, value) in parts.headers.iter() {
        if name != CONTENT_TYPE {
            rewritten.headers_mut().insert(name.clone(), value.clone());
        }
    }
    rewritten
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes as body_to_bytes, Body};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    async fn text_rejection() -> Response {
        (StatusCode::BAD_REQUEST, "plain text rejection").into_response()
    }

    async fn json_error() -> Response {
        error::bad_request("already json")
    }

    async fn ok_handler() -> &'static str {
        "fine"
    }

    fn test_router() -> Router {
        Router::new()
            .route("/text", get(text_rejection))
            .route("/json", get(json_error))
            .route("/ok", get(ok_handler))
            .layer(axum::middleware::from_fn(json_envelope_layer))
            .fallback(unmatched_route_fallback)
    }

    #[tokio::test]
    async fn rewrites_plain_text_error_to_json_envelope() {
        let resp = test_router()
            .oneshot(Request::get("/text").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(ct.starts_with("application/json"));
        let body = body_to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "plain text rejection");
    }

    #[tokio::test]
    async fn leaves_existing_json_error_untouched() {
        let resp = test_router()
            .oneshot(Request::get("/json").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "already json");
    }

    #[tokio::test]
    async fn leaves_success_responses_untouched() {
        let resp = test_router()
            .oneshot(Request::get("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"fine");
    }

    #[tokio::test]
    async fn fallback_returns_json_not_found() {
        let resp = test_router()
            .oneshot(Request::get("/nope").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = body_to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "Not Found");
    }
}
