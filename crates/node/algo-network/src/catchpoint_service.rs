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

//! Catchpoint service — server-side HTTP endpoint that serves a previously
//! exported catchpoint tarball to a requesting peer, mirroring Go's
//! `rpcs.LedgerService` (`rpcs/ledgerService.go`).
//!
//! ## HTTP endpoint
//!
//! `GET /v{version}/{genesis_id}/ledger/{round}` where `round` is base-36
//! encoded (same path shape as go's `LedgerServiceLedgerPath`). Returns the
//! catchpoint tarball as `application/x-algorand-ledger-v2.1`.
//!
//! Go's `LedgerService` transparently decompresses the underlying gzip
//! stream unless the caller advertises `Accept-Encoding: gzip`, in which
//! case the raw (still-gzipped) bytes are sent through unchanged with
//! `Content-Encoding: gzip`. This module mirrors that behavior exactly since
//! algod-rust's own catchpoint files
//! ([`algo_ledger::catchpoint::get_catchpoint_stream`]) are gzip-compressed
//! tarballs on disk, same as go's.
//!
//! ## Transport-agnostic by design
//!
//! Like go's `LedgerService`, this endpoint is a plain `http::Handler`
//! (here: an [`axum::Router`]) registered against whichever
//! [`crate::gossip_node::GossipNode`] implementation is running — the
//! classic WS-gossip transport's `register_http_handler` call is all that's
//! needed to serve it (see `bin/algod-rust/src/commands/relay.rs`). A
//! `algo-p2p` libp2p transport that exposes the same
//! `register_http_handler`-shaped registration point would serve this
//! identically with no code change here; wiring `algo-p2p` itself to expose
//! that registration point is out of this module's scope (tracked as a
//! follow-up — see issue #955's PR).

use std::io::Read;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::Method;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use http::{HeaderMap, StatusCode};

use crate::block_service::parse_round_base36;

/// HTTP Content-Type for a raw catchpoint tarball response.
///
/// Matches Go's `LedgerResponseContentType`.
pub const LEDGER_RESPONSE_CONTENT_TYPE: &str = "application/x-algorand-ledger-v2.1";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by the catchpoint service.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CatchpointServiceError {
    /// No catchpoint file is available for the requested round.
    #[error("catchpoint file for round {round} is not available")]
    NotFound {
        /// The round that was requested.
        round: u64,
    },

    /// Internal error retrieving/reading the catchpoint file.
    #[error("catchpoint file could not be retrieved due to internal error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// LedgerForCatchpointService trait
// ---------------------------------------------------------------------------

/// Trait for accessing a previously-exported catchpoint file's bytes.
///
/// Defined in `algo-network` (not `algo-ledger`) so this crate doesn't need
/// to depend on `algo-ledger` — callers adapt their own ledger/catchpoint
/// storage to this trait, mirroring [`crate::block_service::LedgerForBlockService`].
/// Mirrors Go's `rpcs.LedgerForService`.
pub trait LedgerForCatchpointService: Send + Sync + 'static {
    /// Returns the gzip-compressed catchpoint tarball bytes recorded for
    /// `round`.
    ///
    /// Implementations should return
    /// [`CatchpointServiceError::NotFound`] when no catchpoint file is known
    /// for `round` (go's `ledgercore.ErrNoEntry`), and
    /// [`CatchpointServiceError::Internal`] for any other failure (e.g. an
    /// I/O error reading an otherwise-known file).
    fn catchpoint_file_bytes(&self, round: u64) -> Result<Vec<u8>, CatchpointServiceError>;
}

// ---------------------------------------------------------------------------
// CatchpointService
// ---------------------------------------------------------------------------

/// Catchpoint service providing the HTTP catchpoint-tarball-serving
/// endpoint.
///
/// Mirrors Go's `rpcs.LedgerService`.
pub struct CatchpointService {
    ledger: std::sync::Arc<dyn LedgerForCatchpointService>,
    genesis_id: String,
}

impl CatchpointService {
    /// Create a new catchpoint service.
    ///
    /// - `ledger` — implementation of [`LedgerForCatchpointService`]
    /// - `genesis_id` — genesis identifier for path validation
    pub fn new(ledger: std::sync::Arc<dyn LedgerForCatchpointService>, genesis_id: String) -> Self {
        Self { ledger, genesis_id }
    }

    /// Build an [`axum::Router`] for the HTTP catchpoint endpoint.
    ///
    /// Registers `GET /v1/{genesis_id}/ledger/{round}` where `round` is
    /// base-36 encoded: go's `LedgerServiceLedgerPath` (only version 1).
    pub fn http_router(&self) -> Router {
        let state = CatchpointServiceState {
            ledger: std::sync::Arc::clone(&self.ledger),
            genesis_id: self.genesis_id.clone(),
        };

        Router::new()
            .route("/v1/{genesis_id}/ledger/{round}", get(serve_catchpoint))
            .with_state(state)
    }

    /// go's `LedgerService.ServeHTTP` without a `round` path value: the round
    /// (`r`) and an optional version (`v`) come from the query form. Like in
    /// go, no route reaches it (`/v1/{genesisID}/ledger/{round}` needs a
    /// round); it is the handler's own contract, called directly.
    pub async fn serve_ledger_query(
        &self,
        genesis_id: &str,
        query: &str,
        method: Method,
        headers: HeaderMap,
    ) -> Response {
        let state = CatchpointServiceState {
            ledger: std::sync::Arc::clone(&self.ledger),
            genesis_id: self.genesis_id.clone(),
        };
        if genesis_id != state.genesis_id {
            return (
                StatusCode::BAD_REQUEST,
                format!("mismatching genesisID '{genesis_id}'"),
            )
                .into_response();
        }
        let form: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        let values = |key: &str| -> Vec<String> {
            form.iter()
                .filter(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .collect()
        };
        let rounds = values("r");
        if rounds.len() != 1 {
            return (
                StatusCode::BAD_REQUEST,
                "invalid round number specified in 'r' form argument",
            )
                .into_response();
        }
        let plain_400 = |body: String| {
            let mut resp = (StatusCode::BAD_REQUEST, body).into_response();
            resp.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            resp.headers_mut().insert(
                "x-content-type-options",
                http::HeaderValue::from_static("nosniff"),
            );
            resp
        };
        match values("v").as_slice() {
            [] => {}
            [v] if v == "1" => {}
            [v] => return plain_400(format!("unsupported version specified '{v}'")),
            vs => return plain_400(format!("invalid number of version specified {}", vs.len())),
        }
        serve_round(state, &rounds[0], method, headers).await
    }
}

#[derive(Clone)]
struct CatchpointServiceState {
    ledger: std::sync::Arc<dyn LedgerForCatchpointService>,
    genesis_id: String,
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

/// Axum handler for `GET/HEAD /v1/{genesis_id}/ledger/{round}`.
async fn serve_catchpoint(
    State(state): State<CatchpointServiceState>,
    Path((genesis_id, round_str)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if genesis_id != state.genesis_id {
        return (
            StatusCode::BAD_REQUEST,
            format!("mismatching genesisID '{genesis_id}'"),
        )
            .into_response();
    }
    serve_round(state, &round_str, method, headers).await
}

/// The rest of go's `ServeHTTP`, from the parsed round on.
async fn serve_round(
    state: CatchpointServiceState,
    round_str: &str,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let round = match parse_round_base36(round_str) {
        Some(r) => r,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "specified round number could not be parsed using base 36".to_string(),
            )
                .into_response()
        }
    };

    let gz_bytes = match state.ledger.catchpoint_file_bytes(round) {
        Ok(bytes) => bytes,
        Err(CatchpointServiceError::NotFound { round }) => {
            return (
                StatusCode::NOT_FOUND,
                format!("catchpoint file for round {round} is not available"),
            )
                .into_response();
        }
        Err(CatchpointServiceError::Internal(msg)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "catchpoint file for round {round} could not be retrieved due to internal \
                     error : {msg}"
                ),
            )
                .into_response();
        }
    };

    if method == Method::HEAD {
        return Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", LEDGER_RESPONSE_CONTENT_TYPE)
            .body(Body::empty())
            .unwrap()
            .into_response();
    }

    let accepts_gzip = headers
        .get(http::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("gzip"))
        .unwrap_or(false);

    if accepts_gzip {
        // Pass the already-gzip-compressed bytes through unchanged.
        return Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", LEDGER_RESPONSE_CONTENT_TYPE)
            .header("Content-Encoding", "gzip")
            .body(Body::from(gz_bytes))
            .unwrap()
            .into_response();
    }

    // Decompress before sending, matching go's default (non-gzip-accepting
    // caller) behavior.
    let mut decoder = flate2::read::GzDecoder::new(&gz_bytes[..]);
    let mut decompressed = Vec::new();
    if let Err(e) = decoder.read_to_end(&mut decompressed) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("catchpoint file for round {round} could not be decompressed due to internal error : {e}"),
        )
            .into_response();
    }

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", LEDGER_RESPONSE_CONTENT_TYPE)
        .body(Body::from(decompressed))
        .unwrap()
        .into_response()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_fetcher::format_round_base36;
    use axum::body::Body;
    use http::Request;
    use std::io::Write;
    use std::sync::Mutex;
    use tower::ServiceExt; // for `oneshot`

    /// A mock ledger that stores catchpoint files (already-gzip-compressed
    /// bytes) by round.
    struct MockCatchpointLedger {
        files: Mutex<std::collections::HashMap<u64, Vec<u8>>>,
    }

    impl MockCatchpointLedger {
        fn new() -> Self {
            Self {
                files: Mutex::new(std::collections::HashMap::new()),
            }
        }

        /// Adds a catchpoint file for `round` containing (once decompressed)
        /// exactly `plaintext`.
        fn add_catchpoint(&self, round: u64, plaintext: &[u8]) {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(plaintext).unwrap();
            let gz = encoder.finish().unwrap();
            self.files.lock().unwrap().insert(round, gz);
        }
    }

    impl LedgerForCatchpointService for MockCatchpointLedger {
        fn catchpoint_file_bytes(&self, round: u64) -> Result<Vec<u8>, CatchpointServiceError> {
            self.files
                .lock()
                .unwrap()
                .get(&round)
                .cloned()
                .ok_or(CatchpointServiceError::NotFound { round })
        }
    }

    fn make_test_service(ledger: std::sync::Arc<MockCatchpointLedger>) -> Router {
        let service = CatchpointService::new(ledger, "testnet-v1.0".to_string());
        service.http_router()
    }

    #[tokio::test]
    async fn http_returns_decompressed_catchpoint_for_valid_round() {
        let ledger = std::sync::Arc::new(MockCatchpointLedger::new());
        ledger.add_catchpoint(42, b"catchpoint-tar-bytes");
        let app = make_test_service(ledger);

        let uri = format!("/v1/testnet-v1.0/ledger/{}", format_round_base36(42));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            LEDGER_RESPONSE_CONTENT_TYPE,
        );
        assert!(resp.headers().get("content-encoding").is_none());

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"catchpoint-tar-bytes");
    }

    #[tokio::test]
    async fn http_returns_raw_gzip_when_accept_encoding_gzip() {
        let ledger = std::sync::Arc::new(MockCatchpointLedger::new());
        ledger.add_catchpoint(42, b"catchpoint-tar-bytes");
        let app = make_test_service(ledger);

        let uri = format!("/v1/testnet-v1.0/ledger/{}", format_round_base36(42));
        let req = Request::builder()
            .uri(&uri)
            .header("Accept-Encoding", "gzip")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("content-encoding").unwrap(), "gzip");

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        // The raw bytes are the gzip stream itself -- decompress to verify.
        let mut decoder = flate2::read::GzDecoder::new(&body[..]);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"catchpoint-tar-bytes");
    }

    #[tokio::test]
    async fn http_returns_404_for_missing_round() {
        let ledger = std::sync::Arc::new(MockCatchpointLedger::new());
        let app = make_test_service(ledger);

        let uri = format!("/v1/testnet-v1.0/ledger/{}", format_round_base36(1111));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("is not available"));
    }

    #[tokio::test]
    async fn http_returns_500_for_internal_error() {
        struct FailingLedger;
        impl LedgerForCatchpointService for FailingLedger {
            fn catchpoint_file_bytes(
                &self,
                _round: u64,
            ) -> Result<Vec<u8>, CatchpointServiceError> {
                Err(CatchpointServiceError::Internal("disk on fire".to_string()))
            }
        }
        let service = CatchpointService::new(
            std::sync::Arc::new(FailingLedger),
            "testnet-v1.0".to_string(),
        );
        let app = service.http_router();

        let uri = format!("/v1/testnet-v1.0/ledger/{}", format_round_base36(1));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn http_head_returns_200_with_no_body() {
        let ledger = std::sync::Arc::new(MockCatchpointLedger::new());
        ledger.add_catchpoint(1, b"some-catchpoint-bytes");
        let app = make_test_service(ledger);

        let uri = format!("/v1/testnet-v1.0/ledger/{}", format_round_base36(1));
        let req = Request::builder()
            .method("HEAD")
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            LEDGER_RESPONSE_CONTENT_TYPE,
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.is_empty());
    }

    /// go v5.1.1 serves the ledger path with `http.ServeMux` and registers
    /// only `/v1/...` (`LedgerServiceLedgerPath`): any other version is not
    /// routed (404), where gorilla/mux's `v{version}` answered 400 (#2555,
    /// `TestServicePathsShareServeMux`'s `/v2/...` row).
    #[tokio::test]
    async fn http_does_not_route_other_versions() {
        let ledger = std::sync::Arc::new(MockCatchpointLedger::new());
        let app = make_test_service(ledger);

        for uri in ["/v2/testnet-v1.0/ledger/0", "/v1/testnet-v1.0/ledger/"] {
            let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
        }
    }

    /// go's `TestLedgerServiceVersionErrors`: the `?r=&v=` form answers a bad
    /// or repeated `v` with a plain-text 400 carrying `nosniff`, the version
    /// echoed back only as the text of a `text/plain` body.
    #[tokio::test]
    async fn query_form_version_errors_are_plain_text() {
        let ledger = std::sync::Arc::new(MockCatchpointLedger::new());
        let service = CatchpointService::new(ledger, "testnet-v1.0".to_string());
        for (query, want) in [
            (
                "r=1&v=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
                "unsupported version specified '<script>alert(1)</script>'",
            ),
            ("r=1&v=1&v=2", "invalid number of version specified 2"),
        ] {
            let resp = service
                .serve_ledger_query("testnet-v1.0", query, Method::GET, HeaderMap::new())
                .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{query}");
            assert_eq!(
                resp.headers().get("content-type").unwrap(),
                "text/plain; charset=utf-8"
            );
            assert_eq!(
                resp.headers().get("x-content-type-options").unwrap(),
                "nosniff"
            );
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(String::from_utf8_lossy(&body), want);
        }
    }

    #[tokio::test]
    async fn http_returns_400_for_bad_genesis_id() {
        let ledger = std::sync::Arc::new(MockCatchpointLedger::new());
        let app = make_test_service(ledger);

        let req = Request::builder()
            .uri("/v1/wrong-genesis/ledger/0")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("mismatching genesisID"));
    }

    #[tokio::test]
    async fn http_returns_400_for_bad_round() {
        let ledger = std::sync::Arc::new(MockCatchpointLedger::new());
        let app = make_test_service(ledger);

        let req = Request::builder()
            .uri("/v1/testnet-v1.0/ledger/INVALID")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
