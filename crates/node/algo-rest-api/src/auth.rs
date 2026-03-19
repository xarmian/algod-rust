//! API token authentication middleware.
//!
//! go-algorand uses a 64-character hex token stored in `algod.token`. Requests
//! must include this token in the `X-Algo-API-Token` header or as a
//! `Authorization: Bearer <token>` fallback. Some endpoints (`/health`,
//! `/versions`, `/genesis`, `/ready`, `/swagger.json`) are exempt from auth
//! by being placed on a separate router without this middleware.
//!
//! Token comparison uses constant-time equality to prevent timing attacks.

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

/// HTTP header name for the API authentication token.
pub const API_TOKEN_HEADER: &str = "X-Algo-API-Token";

/// HTTP Authorization header name (fallback).
const AUTHORIZATION_HEADER: &str = "Authorization";

/// Length of a valid API token in hex characters.
pub const API_TOKEN_HEX_LEN: usize = 64;

/// Error message matching go-algorand's `InvalidTokenMessage`.
const INVALID_TOKEN_MESSAGE: &str = "Invalid API Token";

/// Axum middleware that validates the API token.
///
/// This function is designed to be used with `axum::middleware::from_fn_with_state`:
///
/// ```ignore
/// use axum::middleware;
/// let layer = middleware::from_fn_with_state(
///     token_string,
///     require_token,
/// );
/// ```
///
/// The middleware checks (in order, matching go-algorand):
/// 1. The `X-Algo-API-Token` header
/// 2. The `Authorization: Bearer <token>` header (fallback)
///
/// OPTIONS requests are always allowed through without auth (matching go-algorand).
pub async fn require_token(
    axum::extract::State(expected_token): axum::extract::State<String>,
    request: Request,
    next: Next,
) -> Response {
    // OPTIONS responses never require auth (matching go-algorand)
    if request.method() == axum::http::Method::OPTIONS {
        return next.run(request).await;
    }

    // Try X-Algo-API-Token header first
    let mut provided = request
        .headers()
        .get(API_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Fallback: Accept tokens provided in Authorization: Bearer <token> format
    if provided.is_empty() {
        if let Some(auth_value) = request
            .headers()
            .get(AUTHORIZATION_HEADER)
            .and_then(|v| v.to_str().ok())
        {
            if let Some((bearer, token)) = auth_value.split_once(' ') {
                if bearer.eq_ignore_ascii_case("Bearer") {
                    provided = token.to_string();
                }
            }
        }
    }

    // Constant-time comparison to prevent timing side-channels.
    if provided.as_bytes().ct_eq(expected_token.as_bytes()).into() {
        next.run(request).await
    } else {
        let body = crate::error::ErrorResponse::new(INVALID_TOKEN_MESSAGE);
        let json = serde_json::to_string(&body)
            .unwrap_or_else(|_| r#"{"message":"internal error"}"#.to_string());
        (
            StatusCode::UNAUTHORIZED,
            [("content-type", "application/json")],
            json,
        )
            .into_response()
    }
}

/// Generate a new random 64-character hex API token.
///
/// Uses `rand::thread_rng()` which is backed by the ChaCha12 CSPRNG,
/// making the output suitable for cryptographic token generation.
pub fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_has_correct_length() {
        let token = generate_token();
        assert_eq!(token.len(), API_TOKEN_HEX_LEN);
        // Should be valid hex
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generated_tokens_are_unique() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn invalid_token_message_matches_go_algorand() {
        assert_eq!(INVALID_TOKEN_MESSAGE, "Invalid API Token");
    }
}
