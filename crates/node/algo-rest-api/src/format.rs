//! Response format negotiation for the Algorand REST API.
//!
//! go-algorand supports `?format=json` (default) and `?format=msgpack` (or `msgp`).
//! Invalid format values return 400 Bad Request.

use axum::http::StatusCode;
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
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
}
