//! Response format negotiation for the Algorand REST API.
//!
//! go-algorand supports `?format=json` (default) and `?format=msgpack` (or `msgp`).
//! Invalid format values return 400 Bad Request.

use axum::body::to_bytes;
use axum::extract::Request;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::error;

/// Query parameter struct for endpoints that support format negotiation.
///
/// Use as `axum::extract::Query<FormatParams>` in handler signatures.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FormatParams {
    /// Response format: "json" (default) or "msgpack"/"msgp".
    pub format: Option<String>,
}

/// The resolved response encoding format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseFormat {
    /// JSON encoding (Content-Type: application/json).
    Json,
    /// MessagePack encoding (Content-Type: application/msgpack).
    Msgpack,
}

impl ResponseFormat {
    /// Content-Type header value for this format.
    pub fn content_type(&self) -> &'static str {
        match self {
            ResponseFormat::Json => "application/json",
            ResponseFormat::Msgpack => "application/msgpack",
        }
    }
}

/// Parse a `FormatParams` into a `ResponseFormat`.
///
/// Returns `Err(Response)` with a 400 status if the format value is invalid.
pub fn negotiate_format(params: &FormatParams) -> Result<ResponseFormat, Box<Response>> {
    match params.format.as_deref() {
        None | Some("json") => Ok(ResponseFormat::Json),
        Some("msgpack") | Some("msgp") => Ok(ResponseFormat::Msgpack),
        Some(other) => Err(Box::new(error::bad_request(format!(
            "invalid format: {other}"
        )))),
    }
}

/// Encode a serializable value in the negotiated format and return a full
/// axum `Response` with the correct Content-Type header.
///
/// Returns a 500 error response if encoding fails.
pub fn encode_response<T: Serialize>(value: &T, format: ResponseFormat) -> Response {
    match format {
        ResponseFormat::Json => match serde_json::to_vec(value) {
            Ok(bytes) => (
                StatusCode::OK,
                [("content-type", ResponseFormat::Json.content_type())],
                bytes,
            )
                .into_response(),
            Err(e) => {
                tracing::error!(err = %e, "failed to encode JSON response");
                error::internal_error("failed to encode response")
            }
        },
        ResponseFormat::Msgpack => match rmp_serde::to_vec_named(value) {
            Ok(bytes) => (
                StatusCode::OK,
                [("content-type", ResponseFormat::Msgpack.content_type())],
                bytes,
            )
                .into_response(),
            Err(e) => {
                tracing::error!(err = %e, "failed to encode msgpack response");
                error::internal_error("failed to encode response")
            }
        },
    }
}

/// Build a response from pre-encoded protocol-codec (canonical) msgpack bytes.
///
/// This is used when the handler has already produced canonical msgpack via
/// `algo_codec::canonical_encode_*` and needs to return raw bytes with the
/// correct `application/msgpack` content type. No further encoding is applied.
pub fn encode_protocol_codec_response(bytes: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [("content-type", ResponseFormat::Msgpack.content_type())],
        bytes,
    )
        .into_response()
}

/// Maximum body size to buffer for the trailing-newline check. JSON API
/// responses here are small (status/account/block metadata); this is a
/// generous defensive ceiling, not a realistic expected size.
const MAX_JSON_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Middleware ensuring every `application/json` response body ends with a
/// trailing `\n`, matching go-algorand's wire format byte-for-byte.
///
/// go's Echo `ctx.JSON(...)` writes via `json.NewEncoder(w).Encode(v)`
/// (`encoding/json`), which — unlike `json.Marshal` — always appends a `\n`
/// after the encoded value. This is a real, systemic difference: verified
/// live against go-algorand v4.5.1-stable, every JSON response (`/v2/status`,
/// `/v2/ledger/supply`, `/genesis`, `/versions`, ...) carries this trailing
/// byte; algod-rust's `serde_json`-based responses did not, a one-byte
/// mismatch present on effectively every JSON endpoint. Applied as an
/// outermost router layer (like [`crate::error_envelope::json_envelope_layer`])
/// rather than patched into each call site, since the gap is systemic rather
/// than handler-specific.
///
/// Msgpack responses are untouched — go's msgpack codec has no equivalent
/// trailing-byte convention.
pub async fn json_trailing_newline_layer(request: Request, next: Next) -> Response {
    let response = next.run(request).await;

    let is_json = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/json"))
        .unwrap_or(false);
    if !is_json {
        return response;
    }

    let (parts, body) = response.into_parts();
    let bytes = match to_bytes(body, MAX_JSON_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return Response::from_parts(parts, axum::body::Body::empty()),
    };
    if bytes.is_empty() || bytes.last() == Some(&b'\n') {
        return Response::from_parts(parts, axum::body::Body::from(bytes));
    }

    let mut out = bytes.to_vec();
    out.push(b'\n');
    let mut response = Response::from_parts(parts, axum::body::Body::from(out));
    // Content-Length must track the now-longer body, or clients that trust
    // the header over the actual byte stream will truncate the trailing
    // newline right back off.
    response
        .headers_mut()
        .remove(axum::http::header::CONTENT_LENGTH);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct TestData {
        value: u64,
    }

    #[test]
    fn negotiate_defaults_to_json() {
        let params = FormatParams { format: None };
        assert_eq!(negotiate_format(&params).unwrap(), ResponseFormat::Json);
    }

    #[test]
    fn negotiate_json_explicit() {
        let params = FormatParams {
            format: Some("json".into()),
        };
        assert_eq!(negotiate_format(&params).unwrap(), ResponseFormat::Json);
    }

    #[test]
    fn negotiate_msgpack() {
        let params = FormatParams {
            format: Some("msgpack".into()),
        };
        assert_eq!(negotiate_format(&params).unwrap(), ResponseFormat::Msgpack);
    }

    #[test]
    fn negotiate_msgp() {
        let params = FormatParams {
            format: Some("msgp".into()),
        };
        assert_eq!(negotiate_format(&params).unwrap(), ResponseFormat::Msgpack);
    }

    #[test]
    fn negotiate_invalid_returns_err() {
        let params = FormatParams {
            format: Some("xml".into()),
        };
        assert!(negotiate_format(&params).is_err());
    }

    #[tokio::test]
    async fn encode_json_response() {
        let data = TestData { value: 42 };
        let resp = encode_response(&data, ResponseFormat::Json);
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["value"], 42);
    }

    #[tokio::test]
    async fn encode_msgpack_response() {
        let data = TestData { value: 42 };
        let resp = encode_response(&data, ResponseFormat::Msgpack);
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let decoded: TestData = rmp_serde::from_slice(&body).unwrap();
        assert_eq!(decoded.value, 42);
    }

    #[tokio::test]
    async fn trailing_newline_layer_appends_newline_to_json() {
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        async fn handler() -> Response {
            encode_response(&TestData { value: 1 }, ResponseFormat::Json)
        }
        let router = Router::new()
            .route("/x", get(handler))
            .layer(axum::middleware::from_fn(json_trailing_newline_layer));

        let resp = router
            .oneshot(
                axum::http::Request::get("/x")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert!(
            body.ends_with(b"\n"),
            "body must end with newline: {body:?}"
        );
        // The rest of the body is still valid JSON once the newline is trimmed.
        let trimmed = &body[..body.len() - 1];
        let parsed: serde_json::Value = serde_json::from_slice(trimmed).unwrap();
        assert_eq!(parsed["value"], 1);
    }

    #[tokio::test]
    async fn trailing_newline_layer_is_idempotent() {
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        async fn handler() -> Response {
            let mut resp = encode_response(&TestData { value: 1 }, ResponseFormat::Json);
            let body = to_bytes(std::mem::take(resp.body_mut()), 1024)
                .await
                .unwrap();
            let mut with_newline = body.to_vec();
            with_newline.push(b'\n');
            *resp.body_mut() = axum::body::Body::from(with_newline);
            resp
        }
        let router = Router::new()
            .route("/x", get(handler))
            .layer(axum::middleware::from_fn(json_trailing_newline_layer));

        let resp = router
            .oneshot(
                axum::http::Request::get("/x")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert!(!body.ends_with(b"\n\n"), "must not double the newline");
        assert!(body.ends_with(b"\n"));
    }

    #[tokio::test]
    async fn trailing_newline_layer_ignores_msgpack() {
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        async fn handler() -> Response {
            encode_response(&TestData { value: 1 }, ResponseFormat::Msgpack)
        }
        let router = Router::new()
            .route("/x", get(handler))
            .layer(axum::middleware::from_fn(json_trailing_newline_layer));

        let resp = router
            .oneshot(
                axum::http::Request::get("/x")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let decoded: TestData = rmp_serde::from_slice(&body).unwrap();
        assert_eq!(decoded.value, 1);
        assert!(
            !body.ends_with(b"\n"),
            "msgpack must not gain a trailing newline"
        );
    }
}
