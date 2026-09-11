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

//! HTTP block fetch client for the Algorand catchup protocol.
//!
//! Implements the client side of the HTTP block service defined in
//! `go-algorand/rpcs/blockService.go`. Peers expose blocks at
//! `/v1/{genesisID}/block/{round_base36}` where the round number is
//! base-36 encoded.
//!
//! The response body is a single msgpack blob containing both the block
//! and its agreement certificate (matching Go's `PreEncodedBlockCert`).

use std::time::Duration;

use algo_network::format_round_base36;
use reqwest::header::{HeaderValue, ACCEPT, USER_AGENT};
use tracing::debug;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The expected `Content-Type` of a successful block response.
pub const BLOCK_RESPONSE_CONTENT_TYPE: &str = "application/x-algorand-block-v1";

/// Legacy content type accepted for backwards compatibility with older peers.
const BLOCK_RESPONSE_CONTENT_TYPE_OLD: &str = "application/algorand-block-v1";

/// Header returned on 404 responses indicating the peer's latest round.
const LATEST_ROUND_HEADER: &str = "X-Latest-Round";

/// Default timeout for HTTP block fetch requests (30 seconds).
const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum response body size (10 MB, matching Go's `fetcherMaxBlockBytes`).
const MAX_BLOCK_BYTES: usize = 10 << 20;

/// User-Agent string identifying this implementation.
const USER_AGENT_VALUE: &str = "algod-rust/0.1";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by [`HttpBlockFetcher`].
#[derive(Debug, thiserror::Error)]
pub enum HttpBlockFetchError {
    /// The peer does not have the requested block (HTTP 404).
    #[error("block not available (latest round: {latest_round:?})")]
    BlockNotAvailable {
        /// The peer's latest available round, if the `X-Latest-Round`
        /// header was present.
        latest_round: Option<u64>,
    },

    /// The peer is overloaded and requests a retry (HTTP 503).
    #[error("service unavailable (retry after: {retry_after:?}s)")]
    ServiceUnavailable {
        /// Suggested retry delay in seconds from the `Retry-After` header.
        retry_after: Option<u64>,
    },

    /// The response had an unexpected or missing `Content-Type`.
    #[error("invalid content type: {got}")]
    InvalidContentType {
        /// The content type string the server returned.
        got: String,
    },

    /// The response body exceeds the maximum allowed size.
    #[error("response body too large (> {MAX_BLOCK_BYTES} bytes)")]
    ResponseTooLarge,

    /// An unexpected HTTP status code was returned.
    #[error("unexpected HTTP status {status} from {url}: {body}")]
    UnexpectedStatus {
        /// The HTTP status code.
        status: u16,
        /// The request URL.
        url: String,
        /// The response body (truncated).
        body: String,
    },

    /// Failed to build the HTTP client.
    #[error("failed to build HTTP client: {0}")]
    ClientBuildFailed(reqwest::Error),

    /// A transport-level or reqwest error.
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
}

// ---------------------------------------------------------------------------
// HttpBlockFetcher
// ---------------------------------------------------------------------------

/// HTTP client for fetching blocks from an Algorand peer's block service.
///
/// Constructs URLs of the form `/v1/{genesis_id}/block/{round_base36}`
/// and returns the raw msgpack-encoded block+cert response body.
#[derive(Debug, Clone)]
pub struct HttpBlockFetcher {
    client: reqwest::Client,
    base_url: String,
    genesis_id: String,
}

impl HttpBlockFetcher {
    /// Create a new fetcher with the given peer base URL and genesis ID.
    ///
    /// The `base_url` should be the scheme + host (e.g. `http://peer:4160`).
    /// A trailing slash is stripped if present.
    ///
    /// # Errors
    ///
    /// Returns [`HttpBlockFetchError::ClientBuildFailed`] if the HTTP client
    /// cannot be constructed (e.g. TLS backend unavailable).
    pub fn new(
        base_url: impl Into<String>,
        genesis_id: impl Into<String>,
    ) -> Result<Self, HttpBlockFetchError> {
        Self::with_timeout(base_url, genesis_id, DEFAULT_FETCH_TIMEOUT)
    }

    /// Create a new fetcher with an explicit request timeout — go's
    /// `CatchupHTTPBlockFetchTimeoutSec` (`config.Local`, issue #1291).
    /// Callers with a loaded `config.json` should pass
    /// `node_config.catchup_http_block_fetch_timeout_sec` here rather than
    /// relying on [`Self::new`]'s [`DEFAULT_FETCH_TIMEOUT`] fallback.
    ///
    /// # Errors
    ///
    /// Returns [`HttpBlockFetchError::ClientBuildFailed`] if the HTTP client
    /// cannot be constructed (e.g. TLS backend unavailable).
    pub fn with_timeout(
        base_url: impl Into<String>,
        genesis_id: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, HttpBlockFetchError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .map_err(HttpBlockFetchError::ClientBuildFailed)?;
        Ok(Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            genesis_id: genesis_id.into(),
        })
    }

    /// Create a new fetcher with a custom [`reqwest::Client`], which allows
    /// the caller to configure timeouts, TLS, etc.
    pub fn with_client(
        client: reqwest::Client,
        base_url: impl Into<String>,
        genesis_id: impl Into<String>,
    ) -> Self {
        Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            genesis_id: genesis_id.into(),
        }
    }

    /// Return the base URL this fetcher is configured to use.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Return the genesis ID this fetcher is configured for.
    pub fn genesis_id(&self) -> &str {
        &self.genesis_id
    }

    /// Construct the full URL for fetching a block at the given round.
    pub fn block_url(&self, round: u64) -> String {
        format!(
            "{}/v1/{}/block/{}",
            self.base_url,
            self.genesis_id,
            format_round_base36(round),
        )
    }

    /// Fetch the raw msgpack-encoded block+cert bytes for the given round.
    ///
    /// On success, returns the response body which is a msgpack-encoded
    /// `EncodedBlockCert` (containing both the block and its agreement
    /// certificate).
    ///
    /// # Errors
    ///
    /// - [`HttpBlockFetchError::BlockNotAvailable`] on HTTP 404
    /// - [`HttpBlockFetchError::ServiceUnavailable`] on HTTP 503
    /// - [`HttpBlockFetchError::InvalidContentType`] if the content type
    ///   does not match the expected Algorand block content type
    /// - [`HttpBlockFetchError::HttpError`] on transport errors
    pub async fn fetch_block(&self, round: u64) -> Result<Vec<u8>, HttpBlockFetchError> {
        let url = self.block_url(round);
        debug!(round, url = %url, "fetching block via HTTP");

        let mut response = self
            .client
            .get(&url)
            .header(ACCEPT, BLOCK_RESPONSE_CONTENT_TYPE)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .send()
            .await?;

        let status = response.status();

        match status.as_u16() {
            200 => {}

            404 => {
                let latest_round = parse_latest_round_header(&response);
                return Err(HttpBlockFetchError::BlockNotAvailable { latest_round });
            }

            503 => {
                let retry_after = response
                    .headers()
                    .get("Retry-After")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok());
                return Err(HttpBlockFetchError::ServiceUnavailable { retry_after });
            }

            _ => {
                let body = response
                    .text()
                    .await
                    .unwrap_or_default()
                    .chars()
                    .take(512)
                    .collect::<String>();
                return Err(HttpBlockFetchError::UnexpectedStatus {
                    status: status.as_u16(),
                    url,
                    body,
                });
            }
        }

        // Validate Content-Type
        validate_content_type(&response)?;

        // Early rejection when Content-Length is present and exceeds the limit.
        let content_length = response.content_length();
        if let Some(len) = content_length {
            if len > MAX_BLOCK_BYTES as u64 {
                return Err(HttpBlockFetchError::ResponseTooLarge);
            }
        }

        // Stream the body in chunks, enforcing the size limit incrementally.
        // This prevents unbounded memory allocation from chunked
        // transfer-encoding responses that lack a Content-Length header.
        let mut body = Vec::with_capacity(
            content_length
                .map(|l| l as usize)
                .unwrap_or(0)
                .min(MAX_BLOCK_BYTES),
        );
        let mut total = 0usize;

        while let Some(chunk) = response.chunk().await? {
            total = total.saturating_add(chunk.len());
            if total > MAX_BLOCK_BYTES {
                return Err(HttpBlockFetchError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }

        Ok(body)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse the `X-Latest-Round` header from a response.
fn parse_latest_round_header(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get(LATEST_ROUND_HEADER)
        .and_then(|v: &HeaderValue| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}

/// Validate that the response has the expected Algorand block content type.
fn validate_content_type(response: &reqwest::Response) -> Result<(), HttpBlockFetchError> {
    let content_type = response
        .headers()
        .get("Content-Type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type == BLOCK_RESPONSE_CONTENT_TYPE
        || content_type == BLOCK_RESPONSE_CONTENT_TYPE_OLD
    {
        Ok(())
    } else {
        Err(HttpBlockFetchError::InvalidContentType {
            got: content_type.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- URL construction --

    #[test]
    fn block_url_round_zero() {
        let fetcher = HttpBlockFetcher::new("http://peer:4160", "testnet-v1.0").unwrap();
        assert_eq!(
            fetcher.block_url(0),
            "http://peer:4160/v1/testnet-v1.0/block/0"
        );
    }

    #[test]
    fn block_url_round_1000() {
        let fetcher = HttpBlockFetcher::new("http://peer:4160", "mainnet-v1.0").unwrap();
        // 1000 in base-36 = "rs"
        assert_eq!(
            fetcher.block_url(1000),
            "http://peer:4160/v1/mainnet-v1.0/block/rs"
        );
    }

    #[test]
    fn block_url_strips_trailing_slash() {
        let fetcher = HttpBlockFetcher::new("http://peer:4160/", "testnet-v1.0").unwrap();
        assert_eq!(
            fetcher.block_url(1),
            "http://peer:4160/v1/testnet-v1.0/block/1"
        );
    }

    #[test]
    fn block_url_large_round() {
        let fetcher = HttpBlockFetcher::new("http://peer:4160", "mainnet-v1.0").unwrap();
        let url = fetcher.block_url(1_000_000);
        // 1_000_000 in base-36 = "lfls"
        assert_eq!(url, "http://peer:4160/v1/mainnet-v1.0/block/lfls");
    }

    // -- Accessors --

    #[test]
    fn accessors() {
        let fetcher = HttpBlockFetcher::new("http://peer:4160", "testnet-v1.0").unwrap();
        assert_eq!(fetcher.base_url(), "http://peer:4160");
        assert_eq!(fetcher.genesis_id(), "testnet-v1.0");
    }

    #[test]
    fn with_client_constructor() {
        let client = reqwest::Client::new();
        let fetcher = HttpBlockFetcher::with_client(client, "http://peer:4160", "mainnet-v1.0");
        assert_eq!(fetcher.base_url(), "http://peer:4160");
        assert_eq!(fetcher.genesis_id(), "mainnet-v1.0");
    }

    // -- Content-type validation --

    #[test]
    fn content_type_constants_match_go() {
        // From go-algorand/rpcs/blockService.go:
        // BlockResponseContentType = "application/x-algorand-block-v1"
        assert_eq!(
            BLOCK_RESPONSE_CONTENT_TYPE,
            "application/x-algorand-block-v1"
        );
    }

    #[test]
    fn latest_round_header_constant_matches_go() {
        // From go-algorand/rpcs/blockService.go:
        // BlockResponseLatestRoundHeader = "X-Latest-Round"
        assert_eq!(LATEST_ROUND_HEADER, "X-Latest-Round");
    }

    // -- End-to-end fetch against a real HTTP server (go's TestUGetBlockHTTP) --

    /// Direct port of go's `TestUGetBlockHTTP` (`catchup/universalFetcher_test.go`):
    /// fetching the next round from a real (test) block service succeeds and
    /// returns the exact body bytes, then fetching the round immediately after
    /// (which the server does not have) fails with
    /// [`HttpBlockFetchError::BlockNotAvailable`] carrying the peer's latest
    /// round — mirroring go's `noBlockForRoundError{round: next+1, latest:
    /// next}` assertion. Unlike the URL-construction/accessor unit tests
    /// above, this drives `fetch_block` through a real `reqwest` request
    /// against a live listener, matching go's use of an actual
    /// `rpcs.MakeBlockService` HTTP handler.
    #[tokio::test]
    async fn fetch_block_succeeds_then_reports_no_block_for_next_round() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const NEXT_ROUND: u64 = 7;
        const BODY: &[u8] = b"fake-msgpack-block-and-cert-bytes";

        let server = MockServer::start().await;

        // The round-7 path in base-36 is "7".
        Mock::given(method("GET"))
            .and(path(format!("/v1/test-genesisID/block/{}", NEXT_ROUND)))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", BLOCK_RESPONSE_CONTENT_TYPE)
                    .set_body_bytes(BODY),
            )
            .mount(&server)
            .await;

        // The server has no block for round 8: respond 404 with the latest
        // round header, exactly as go's blockService does when asked for a
        // round beyond its tip.
        Mock::given(method("GET"))
            .and(path(format!("/v1/test-genesisID/block/{}", NEXT_ROUND + 1)))
            .respond_with(
                ResponseTemplate::new(404)
                    .insert_header("X-Latest-Round", NEXT_ROUND.to_string().as_str()),
            )
            .mount(&server)
            .await;

        let fetcher = HttpBlockFetcher::new(server.uri(), "test-genesisID").unwrap();

        // First call: succeeds and returns exactly the served bytes.
        let body = fetcher.fetch_block(NEXT_ROUND).await.unwrap();
        assert_eq!(body, BODY);

        // Second call: the server has nothing for `NEXT_ROUND + 1`, so the
        // fetch must fail with `BlockNotAvailable` carrying the latest round.
        let err = fetcher.fetch_block(NEXT_ROUND + 1).await.unwrap_err();
        match err {
            HttpBlockFetchError::BlockNotAvailable { latest_round } => {
                assert_eq!(latest_round, Some(NEXT_ROUND));
            }
            other => panic!("expected BlockNotAvailable, got: {other:?}"),
        }
    }

    // -- Configurable timeout (issue #1291) --

    /// `HttpBlockFetcher::new` previously always built its `reqwest::Client`
    /// with a hardcoded `DEFAULT_FETCH_TIMEOUT` (30s), regardless of go's
    /// `CatchupHTTPBlockFetchTimeoutSec` config — there was no way for a
    /// caller to get a *shorter* timeout without hand-building a
    /// `reqwest::Client` via `with_client`. `with_timeout` closes that gap:
    /// a fetch against a server that responds slower than the configured
    /// timeout must fail promptly (well under the server's own delay)
    /// rather than hang until `DEFAULT_FETCH_TIMEOUT` elapses.
    #[tokio::test]
    async fn with_timeout_aborts_a_slow_response_before_the_default_timeout_would() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/test-genesisID/block/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", BLOCK_RESPONSE_CONTENT_TYPE)
                    .set_body_bytes(b"unused" as &[u8])
                    .set_delay(Duration::from_secs(5)),
            )
            .mount(&server)
            .await;

        let fetcher = HttpBlockFetcher::with_timeout(
            server.uri(),
            "test-genesisID",
            Duration::from_millis(200),
        )
        .unwrap();

        let started = std::time::Instant::now();
        let result = fetcher.fetch_block(1).await;
        let elapsed = started.elapsed();

        assert!(
            result.is_err(),
            "a request slower than the configured timeout must fail, not succeed"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "expected the 200ms configured timeout to abort well before the server's 5s delay, \
             took {elapsed:?}"
        );
    }

    // -- Error Display --

    #[test]
    fn error_display_block_not_available() {
        let err = HttpBlockFetchError::BlockNotAvailable {
            latest_round: Some(42),
        };
        let msg = format!("{err}");
        assert!(msg.contains("block not available"));
        assert!(msg.contains("42"));
    }

    #[test]
    fn error_display_block_not_available_no_latest() {
        let err = HttpBlockFetchError::BlockNotAvailable { latest_round: None };
        let msg = format!("{err}");
        assert!(msg.contains("block not available"));
        assert!(msg.contains("None"));
    }

    #[test]
    fn error_display_service_unavailable() {
        let err = HttpBlockFetchError::ServiceUnavailable {
            retry_after: Some(3),
        };
        let msg = format!("{err}");
        assert!(msg.contains("service unavailable"));
        assert!(msg.contains("3"));
    }

    #[test]
    fn error_display_invalid_content_type() {
        let err = HttpBlockFetchError::InvalidContentType {
            got: "text/plain".into(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("invalid content type"));
        assert!(msg.contains("text/plain"));
    }

    #[test]
    fn error_display_unexpected_status() {
        let err = HttpBlockFetchError::UnexpectedStatus {
            status: 500,
            url: "http://peer/v1/net/block/0".into(),
            body: "internal error".into(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("500"));
        assert!(msg.contains("internal error"));
    }

    #[test]
    fn error_display_response_too_large() {
        let err = HttpBlockFetchError::ResponseTooLarge;
        let msg = format!("{err}");
        assert!(msg.contains("too large"));
    }
}
