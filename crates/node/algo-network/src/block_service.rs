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

//! Block service — HTTP and WebSocket block serving with memory cap enforcement.
//!
//! Implements the server-side block service that responds to block requests
//! from peers, mirroring Go's `rpcs/blockService.go`.
//!
//! ## HTTP endpoint
//!
//! `GET /v{version}/{genesis_id}/block/{round}` where `round` is base-36
//! encoded.  Returns the block+cert as msgpack (`application/x-algorand-block-v1`).
//!
//! ## WebSocket handler
//!
//! Handles incoming `UniEnsBlockReq` tagged messages, parses the request topics
//! (roundKey + requestDataType), looks up the block via the ledger trait, and
//! responds with a `TopicMsgResp` containing blockData + certData.
//!
//! ## Memory cap
//!
//! Both HTTP and WS paths enforce a memory cap (default 500 MiB).  An
//! `AtomicU64` tracks total bytes currently in-flight; when the cap is
//! exceeded, the service returns 503 (HTTP) or an error topic (WS).

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use http::StatusCode;
use http_body::Body as HttpBody;
use url::Url;

use crate::block_fetcher::decode_round_from_uvarint;
use crate::topics::{
    Topic, Topics, BLOCK_AND_CERT_VALUE, BLOCK_DATA_KEY, CERT_DATA_KEY, ERROR_KEY,
    LATEST_ROUND_KEY, REQUEST_DATA_TYPE_KEY, ROUND_KEY,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// HTTP Content-Type for encoded block responses.
///
/// Matches Go's `BlockResponseContentType`.
pub const BLOCK_RESPONSE_CONTENT_TYPE: &str = "application/x-algorand-block-v1";

/// Cache-Control header when the block is available (immutable, 1 year).
const BLOCK_RESPONSE_HAS_BLOCK_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// Cache-Control header when the block is not available (revalidate after 1s).
const BLOCK_RESPONSE_MISSING_BLOCK_CACHE_CONTROL: &str = "public, max-age=1, must-revalidate";

/// Retry-After header value in seconds.
const BLOCK_RESPONSE_RETRY_AFTER: &str = "1";

/// Header returned when the requested block is not yet available.
/// Matches Go's `BlockResponseLatestRoundHeader`.
const BLOCK_RESPONSE_LATEST_ROUND_HEADER: &str = "X-Latest-Round";

/// Default block service memory cap: 500,000,000 bytes, matching go's
/// `BlockServiceMemCap` literal `"500000000"` exactly (issue #748 fixed a
/// prior divergence: this used to be `500 * 1024 * 1024` = 524,288,000, a
/// binary-MiB approximation rather than go's literal decimal byte count).
pub const DEFAULT_BLOCK_SERVICE_MEM_CAP: u64 = 500_000_000;

// WS error messages matching Go constants.
const NO_ROUND_NUMBER_ERR_MSG: &str = "can't find the round number";
const NO_DATA_TYPE_ERR_MSG: &str = "can't find the data-type";
const ROUND_NUMBER_PARSE_ERR_MSG: &str = "unable to parse round number";
const BLOCK_NOT_AVAILABLE_ERR_MSG: &str = "requested block is not available";
const DATATYPE_UNSUPPORTED_ERR_MSG: &str = "requested data type is unsupported";
const MEMORY_AT_CAPACITY_ERR_MSG: &str = "block service memory over capacity";

// ---------------------------------------------------------------------------
// Fallback (redirect-to-archival-peer) endpoints
// ---------------------------------------------------------------------------
//
// Mirrors go's `rpcs/blockService.go` "Fast Catchup Backend"
// (`BlockServiceCustomFallbackEndpoints`, `fallbackEndpoints`,
// `redirectRequest`/`getNextCustomFallbackEndpoint`): when this node can't
// satisfy a block request itself (round not on disk yet, or over the
// in-flight memory cap), it 307-redirects the requester to the next
// configured fallback endpoint in round-robin order rather than answering
// 404/503 directly — issue #955.
//
// Deliberate simplification vs. go: go's `addr.ParseHostOrURL` accepts a
// handful of Go-`net/url`-specific quirky inputs (bare "host:port",
// scheme-relative "//host", multiaddr strings for the libp2p transport) and
// re-validates each configured endpoint lazily *at redirect time*, silently
// falling back to "no redirect" for that one request if parsing fails. This
// port instead validates once at construction time and drops any entry
// that can't be turned into a usable HTTP(S) redirect target, which is
// behaviorally equivalent for well-formed configuration (the common case)
// while being simpler to reason about; a misconfigured entry is surfaced
// immediately via a `tracing::warn!` at startup rather than silently
// degrading a single request. Multiaddr-style entries (`/ip4/.../p2p/...`)
// are recognized but always dropped here: `algo-p2p` doesn't yet expose the
// registration point this classic-transport service would need to build a
// meaningful redirect target for one (tracked as a follow-up to issue
// #955).

/// Round-robin list of configured fallback (redirect target) endpoints.
struct FallbackEndpoints {
    endpoints: Vec<Url>,
    next: AtomicUsize,
}

impl FallbackEndpoints {
    fn empty() -> Self {
        Self {
            endpoints: Vec::new(),
            next: AtomicUsize::new(0),
        }
    }

    /// Parse go's `BlockServiceCustomFallbackEndpoints` config string (a
    /// comma-delimited list) into validated redirect targets, mirroring
    /// go's `makeFallbackEndpoints` (see the module-level note above for
    /// where this simplifies vs. go).
    fn parse(custom_fallback_endpoints: &str) -> Self {
        let mut endpoints = Vec::new();
        for raw in custom_fallback_endpoints.split(',') {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            if is_multiaddr_like(raw) {
                tracing::warn!(
                    endpoint = raw,
                    "block service: multiaddr-style fallback endpoints are not yet \
                     supported (no algo-p2p HTTP-redirect target); skipping"
                );
                continue;
            }
            match parse_host_or_url(raw) {
                Some(url) => endpoints.push(url),
                None => {
                    tracing::warn!(
                        endpoint = raw,
                        "block service: could not parse fallback endpoint; skipping"
                    );
                }
            }
        }
        Self {
            endpoints,
            next: AtomicUsize::new(0),
        }
    }

    /// Returns the next endpoint in round-robin order, or `None` if no
    /// (valid) fallback endpoints are configured.
    fn next_endpoint(&self) -> Option<&Url> {
        if self.endpoints.is_empty() {
            return None;
        }
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.endpoints.len();
        Some(&self.endpoints[idx])
    }

    /// Builds the 307-redirect `Location` for `round` at the next
    /// round-robin fallback endpoint, or `None` if none are configured.
    fn redirect_location(&self, genesis_id: &str, round: u64) -> Option<String> {
        let endpoint = self.next_endpoint()?;
        let mut url = endpoint.clone();
        url.set_path(&format!(
            "/v1/{genesis_id}/block/{}",
            crate::block_fetcher::format_round_base36(round)
        ));
        Some(url.to_string())
    }
}

/// A crude structural check for a libp2p multiaddr (`/ip4/.../tcp/.../p2p/...`),
/// matching go's `addr.IsMultiaddr`'s prefix test (a leading `/` that isn't
/// the start of a scheme-relative URL's `//`) without pulling in a
/// multiaddr-parsing dependency this crate doesn't otherwise need.
fn is_multiaddr_like(s: &str) -> bool {
    s.starts_with('/') && !s.starts_with("//")
}

/// Parse a fallback endpoint into a usable redirect-target [`Url`],
/// mirroring go's `addr.ParseHostOrURL`'s two fallbacks: a bare
/// `host:port` (which plain URL parsing chokes on because it reads `host:`
/// as a scheme), or a full URL/host that's missing its scheme entirely.
fn parse_host_or_url(addr: &str) -> Option<Url> {
    if is_host_colon_port(addr) {
        return Url::parse(&format!("http://{addr}")).ok();
    }
    if let Ok(url) = Url::parse(addr) {
        if url.host().is_some() {
            return Some(url);
        }
        return None;
    }
    let with_scheme = Url::parse(&format!("http://{addr}")).ok()?;
    if with_scheme.host().is_some() {
        Some(with_scheme)
    } else {
        None
    }
}

/// Matches go's `HostColonPortPattern` (`^[-a-zA-Z0-9.]+:\d+$`).
fn is_host_colon_port(s: &str) -> bool {
    let Some((host, port)) = s.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !port.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by the block service.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlockServiceError {
    /// The requested round is not available in the ledger.
    #[error("block not available for round {round}")]
    BlockNotAvailable {
        /// The round that was requested.
        round: u64,
        /// The latest round known to the ledger (if available).
        latest_round: Option<u64>,
    },

    /// Memory cap has been reached — too many concurrent requests.
    #[error("block service memory over capacity: {used} / {capacity}")]
    MemoryAtCapacity {
        /// Currently tracked bytes.
        used: u64,
        /// Configured cap.
        capacity: u64,
    },

    /// The request could not be parsed (bad round, missing fields, etc.).
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Internal ledger error.
    #[error("internal error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// LedgerForBlockService trait
// ---------------------------------------------------------------------------

/// Trait for accessing block data from the ledger.
///
/// Defined in `algo-network` (not `algo-ledger`) so that callers provide
/// their own implementation.  Mirrors Go's `rpcs.LedgerForBlockService`.
pub trait LedgerForBlockService: Send + Sync + 'static {
    /// Returns the encoded block+certificate bytes for the given round.
    ///
    /// Returns separate raw msgpack blobs for the block and the certificate.
    /// On success the two byte vectors can be combined into an
    /// `EncodedBlockCert` msgpack payload for HTTP, or sent as separate
    /// topics for WS.
    fn encoded_block_cert(&self, round: u64) -> Result<(Vec<u8>, Vec<u8>), BlockServiceError>;

    /// Returns the latest available round.
    fn latest_round(&self) -> u64;
}

// ---------------------------------------------------------------------------
// BlockService
// ---------------------------------------------------------------------------

/// Block service providing HTTP and WebSocket block serving with memory cap.
///
/// Mirrors Go's `rpcs.BlockService`.
pub struct BlockService {
    /// The ledger implementation for fetching blocks.
    ledger: Arc<dyn LedgerForBlockService>,
    /// Genesis ID of this network (e.g. "mainnet-v1.0").
    genesis_id: String,
    /// Total bytes currently tracked across concurrent HTTP requests.
    http_mem_used: Arc<AtomicU64>,
    /// Total bytes currently tracked across concurrent WS requests.
    ws_mem_used: Arc<AtomicU64>,
    /// Maximum bytes allowed in-flight before returning 503 / error.
    mem_cap: u64,
    /// Configured redirect-to-archival-peer fallback endpoints (go's
    /// `BlockServiceCustomFallbackEndpoints`/"Fast Catchup Backend",
    /// issue #955). Empty by default — matches go's `""` default, under
    /// which `redirectRequest` always returns `false` and the service
    /// falls back to plain 404/503 responses.
    fallback: Arc<FallbackEndpoints>,
}

impl BlockService {
    /// Create a new block service.
    ///
    /// - `ledger` — implementation of [`LedgerForBlockService`]
    /// - `genesis_id` — genesis identifier for path validation
    /// - `mem_cap` — maximum bytes tracked in-flight (0 = unlimited)
    pub fn new(ledger: Arc<dyn LedgerForBlockService>, genesis_id: String, mem_cap: u64) -> Self {
        Self {
            ledger,
            genesis_id,
            http_mem_used: Arc::new(AtomicU64::new(0)),
            ws_mem_used: Arc::new(AtomicU64::new(0)),
            mem_cap,
            fallback: Arc::new(FallbackEndpoints::empty()),
        }
    }

    /// Configure redirect-to-archival-peer fallback endpoints from go's
    /// `BlockServiceCustomFallbackEndpoints` config string (a comma-delimited
    /// list of `host:port`/URL endpoints). When the HTTP block endpoint
    /// can't satisfy a request itself (block not available, or over the
    /// memory cap), it 307-redirects to the next endpoint in round-robin
    /// order instead of responding 404/503 directly — mirrors go's
    /// `redirectRequest`/`getNextCustomFallbackEndpoint`.
    ///
    /// A builder method (rather than an extra `new` parameter) so the many
    /// existing call sites that don't need redirect behavior are unaffected.
    pub fn with_custom_fallback_endpoints(mut self, custom_fallback_endpoints: &str) -> Self {
        self.fallback = Arc::new(FallbackEndpoints::parse(custom_fallback_endpoints));
        self
    }

    /// Build an [`axum::Router`] for the HTTP block endpoint.
    ///
    /// Registers `GET /{version_seg}/{genesis_id}/block/{round}` where
    /// `version_seg` looks like `v1`, and `round` is base-36 encoded.
    pub fn http_router(&self) -> Router {
        let state = BlockServiceState {
            ledger: Arc::clone(&self.ledger),
            genesis_id: self.genesis_id.clone(),
            mem_used: Arc::clone(&self.http_mem_used),
            mem_cap: self.mem_cap,
            fallback: Arc::clone(&self.fallback),
        };

        // Axum requires each `:param` to span a full path segment, so we
        // capture the `v1` segment as `:version_seg` and parse out the
        // version in the handler.
        Router::new()
            .route("/:version_seg/:genesis_id/block/:round", get(serve_block))
            .with_state(state)
    }

    /// Handle an incoming WebSocket block request (`UniEnsBlockReq`).
    ///
    /// Parses the request topics, looks up the block, and returns a
    /// `Topics` response suitable for sending as a `TopicMsgResp`, along
    /// with an optional [`MemoryGuard`] that tracks the in-flight bytes.
    ///
    /// The caller **must** hold the returned `MemoryGuard` until the
    /// response has been fully sent.  Dropping the guard releases the
    /// tracked memory.
    ///
    /// Subject to the same memory cap as the HTTP path (tracked separately
    /// on `ws_mem_used`).
    pub fn handle_ws_block_request(&self, request_data: &[u8]) -> (Topics, Option<MemoryGuard>) {
        // Check memory cap before processing (mem_cap == 0 means unlimited)
        let mem_used = self.ws_mem_used.load(Ordering::Relaxed);
        if self.mem_cap > 0 && mem_used >= self.mem_cap {
            return (
                Topics::from_vec(vec![Topic::new(
                    ERROR_KEY,
                    MEMORY_AT_CAPACITY_ERR_MSG.as_bytes().to_vec(),
                )]),
                None,
            );
        }

        // Parse the request topics
        let topics = match Topics::unmarshal(request_data) {
            Ok(t) => t,
            Err(e) => {
                return (
                    Topics::from_vec(vec![Topic::new(ERROR_KEY, format!("{e}").into_bytes())]),
                    None,
                );
            }
        };

        // Extract round key
        let round_bytes = match topics.get_value(ROUND_KEY) {
            Some(b) => b,
            None => {
                return (
                    Topics::from_vec(vec![Topic::new(
                        ERROR_KEY,
                        NO_ROUND_NUMBER_ERR_MSG.as_bytes().to_vec(),
                    )]),
                    None,
                );
            }
        };

        // Extract request data type
        let request_type = match topics.get_value(REQUEST_DATA_TYPE_KEY) {
            Some(b) => b,
            None => {
                return (
                    Topics::from_vec(vec![Topic::new(
                        ERROR_KEY,
                        NO_DATA_TYPE_ERR_MSG.as_bytes().to_vec(),
                    )]),
                    None,
                );
            }
        };

        // Parse the round number from uvarint
        let round = match decode_round_from_uvarint(round_bytes) {
            Some(r) => r,
            None => {
                return (
                    Topics::from_vec(vec![Topic::new(
                        ERROR_KEY,
                        ROUND_NUMBER_PARSE_ERR_MSG.as_bytes().to_vec(),
                    )]),
                    None,
                );
            }
        };

        // Check request type
        let request_type_str = String::from_utf8_lossy(request_type);
        if request_type_str != BLOCK_AND_CERT_VALUE {
            return (
                Topics::from_vec(vec![Topic::new(
                    ERROR_KEY,
                    DATATYPE_UNSUPPORTED_ERR_MSG.as_bytes().to_vec(),
                )]),
                None,
            );
        }

        // Fetch the block
        match self.ledger.encoded_block_cert(round) {
            Ok((block_data, cert_data)) => {
                let n = (block_data.len() + cert_data.len()) as u64;
                // Track memory — the returned MemoryGuard releases it on drop.
                self.ws_mem_used.fetch_add(n, Ordering::Relaxed);
                let guard = MemoryGuard {
                    mem_used: Arc::clone(&self.ws_mem_used),
                    bytes: n,
                };
                (
                    Topics::from_vec(vec![
                        Topic::new(BLOCK_DATA_KEY, block_data),
                        Topic::new(CERT_DATA_KEY, cert_data),
                    ]),
                    Some(guard),
                )
            }
            Err(BlockServiceError::BlockNotAvailable { latest_round, .. }) => {
                let mut resp = vec![Topic::new(
                    ERROR_KEY,
                    BLOCK_NOT_AVAILABLE_ERR_MSG.as_bytes().to_vec(),
                )];
                if let Some(latest) = latest_round {
                    resp.push(Topic::new(LATEST_ROUND_KEY, latest.to_be_bytes().to_vec()));
                }
                (Topics::from_vec(resp), None)
            }
            Err(_) => (
                Topics::from_vec(vec![Topic::new(
                    ERROR_KEY,
                    BLOCK_NOT_AVAILABLE_ERR_MSG.as_bytes().to_vec(),
                )]),
                None,
            ),
        }
    }

    /// Returns the current HTTP memory usage.
    pub fn http_mem_used(&self) -> u64 {
        self.http_mem_used.load(Ordering::Relaxed)
    }

    /// Returns the current WS memory usage.
    pub fn ws_mem_used(&self) -> u64 {
        self.ws_mem_used.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Axum handler state
// ---------------------------------------------------------------------------

/// Shared state for the axum block-service handler.
#[derive(Clone)]
struct BlockServiceState {
    ledger: Arc<dyn LedgerForBlockService>,
    genesis_id: String,
    mem_used: Arc<AtomicU64>,
    mem_cap: u64,
    fallback: Arc<FallbackEndpoints>,
}

// ---------------------------------------------------------------------------
// MemoryGuard — RAII guard for memory tracking
// ---------------------------------------------------------------------------

/// RAII guard that releases tracked memory when dropped.
///
/// Used by both the HTTP body wrapper and WS response handling to ensure
/// memory is released after the response data is fully consumed or dropped.
pub struct MemoryGuard {
    mem_used: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for MemoryGuard {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.mem_used.fetch_sub(self.bytes, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// MemoryTrackingBody — wraps an axum Body with a MemoryGuard
// ---------------------------------------------------------------------------

/// A response body wrapper that holds a [`MemoryGuard`], releasing the
/// tracked memory only when the body is fully consumed or dropped.
///
/// This ensures the memory cap accurately tracks in-flight bytes until the
/// response body has been sent to the client.
struct MemoryTrackingBody {
    inner: Body,
    _guard: MemoryGuard,
}

impl HttpBody for MemoryTrackingBody {
    type Data = bytes::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        // SAFETY: we only project to `inner` which is Unpin (Body is Unpin).
        let this = unsafe { self.get_unchecked_mut() };
        Pin::new(&mut this.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

// ---------------------------------------------------------------------------
// Base-36 parsing
// ---------------------------------------------------------------------------

/// Parse a base-36 encoded round number, matching Go's
/// `strconv.ParseUint(s, 36, 64)`.
///
/// `pub(crate)` so [`crate::catchpoint_service`] (go's `LedgerService` uses
/// the same base-36 round encoding as `BlockService`) can reuse it rather
/// than duplicating the parser.
pub(crate) fn parse_round_base36(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut result: u64 = 0;
    for ch in s.chars() {
        let digit = match ch {
            '0'..='9' => (ch as u64) - ('0' as u64),
            'a'..='z' => (ch as u64) - ('a' as u64) + 10,
            _ => return None,
        };
        result = result.checked_mul(36)?.checked_add(digit)?;
    }
    Some(result)
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

/// Axum handler for `GET /{version_seg}/{genesis_id}/block/{round}`.
///
/// The `version_seg` path segment is expected to be `v1` (matching Go's
/// route pattern `/v{version:[0-9.]+}/...`).
async fn serve_block(
    State(state): State<BlockServiceState>,
    Path((version_seg, genesis_id, round_str)): Path<(String, String, String)>,
) -> Response {
    // Parse version: expect "v1" pattern
    let version = version_seg.strip_prefix('v').unwrap_or("");
    if version != "1" {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Validate genesis ID
    if genesis_id != state.genesis_id {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Parse round from base-36
    let round = match parse_round_base36(&round_str) {
        Some(r) => r,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    // Check memory cap before processing (>= matches Go's behaviour).
    // mem_cap == 0 means unlimited — skip the check entirely.
    let mem_used = state.mem_used.load(Ordering::Relaxed);
    if state.mem_cap > 0 && mem_used >= state.mem_cap {
        // Go's `errMemoryAtCapacity` case: redirect to the next configured
        // fallback endpoint before giving up and returning 503.
        if let Some(location) = state.fallback.redirect_location(&state.genesis_id, round) {
            return redirect_response(&location);
        }
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("Retry-After", BLOCK_RESPONSE_RETRY_AFTER)
            .body(Body::empty())
            .unwrap()
            .into_response();
    }

    // Check if round is ahead of latest — return 404 (not 503) to match
    // Go's block service behaviour.  Go's catchup treats 404 as "try another
    // peer immediately" whereas 503 triggers aggressive backoff.
    let latest = state.ledger.latest_round();
    if round > latest {
        // Go's `ledgercore.ErrNoEntry` case: redirect before falling back
        // to a plain 404.
        if let Some(location) = state.fallback.redirect_location(&state.genesis_id, round) {
            return redirect_response(&location);
        }
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Cache-Control", BLOCK_RESPONSE_MISSING_BLOCK_CACHE_CONTROL)
            .header(BLOCK_RESPONSE_LATEST_ROUND_HEADER, latest.to_string())
            .body(Body::empty())
            .unwrap()
            .into_response();
    }

    // Fetch the block
    match state.ledger.encoded_block_cert(round) {
        Ok((block_data, cert_data)) => {
            // Encode as a PreEncodedBlockCert-style msgpack:
            // We need to produce the combined msgpack encoding of
            // { "block": <raw block bytes>, "cert": <raw cert bytes> }
            // Using rmp_serde to encode a struct with Raw fields.
            let encoded = encode_pre_encoded_block_cert(&block_data, &cert_data);
            let data_len = encoded.len() as u64;

            // Track memory — released when the MemoryTrackingBody is dropped
            // (i.e. after the response body has been fully sent to the client).
            state.mem_used.fetch_add(data_len, Ordering::Relaxed);
            let guard = MemoryGuard {
                mem_used: Arc::clone(&state.mem_used),
                bytes: data_len,
            };

            let body = MemoryTrackingBody {
                inner: Body::from(encoded),
                _guard: guard,
            };

            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", BLOCK_RESPONSE_CONTENT_TYPE)
                .header("Content-Length", data_len.to_string())
                .header("Cache-Control", BLOCK_RESPONSE_HAS_BLOCK_CACHE_CONTROL)
                .body(body)
                .unwrap()
                .into_response()
        }
        Err(BlockServiceError::BlockNotAvailable { latest_round, .. }) => {
            if let Some(location) = state.fallback.redirect_location(&state.genesis_id, round) {
                return redirect_response(&location);
            }
            let mut builder = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Cache-Control", BLOCK_RESPONSE_MISSING_BLOCK_CACHE_CONTROL);
            if let Some(latest) = latest_round {
                builder = builder.header("X-Latest-Round", latest.to_string());
            }
            builder.body(Body::empty()).unwrap().into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Builds a `307 Temporary Redirect` response with the given `Location`,
/// matching go's `http.Redirect(response, request, redirectURL,
/// http.StatusTemporaryRedirect)`.
fn redirect_response(location: &str) -> Response {
    Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header("Location", location)
        .body(Body::empty())
        .unwrap()
        .into_response()
}

/// Encode raw block and cert bytes into the PreEncodedBlockCert msgpack format.
///
/// Produces: `{"block": <raw_block>, "cert": <raw_cert>}` encoded as msgpack
/// with named fields, where the values are embedded as raw msgpack.
fn encode_pre_encoded_block_cert(block: &[u8], cert: &[u8]) -> Vec<u8> {
    // We build the msgpack by hand to embed raw bytes as-is (like Go's codec.Raw).
    // Format: fixmap(2) + "block" + raw_block + "cert" + raw_cert
    let mut buf = Vec::with_capacity(2 + 5 + block.len() + 4 + cert.len() + 16);

    // fixmap with 2 entries
    buf.push(0x82);

    // Key "block" (fixstr, length 5)
    buf.push(0xa5);
    buf.extend_from_slice(b"block");
    // Value: raw block bytes (already msgpack-encoded)
    buf.extend_from_slice(block);

    // Key "cert" (fixstr, length 4)
    buf.push(0xa4);
    buf.extend_from_slice(b"cert");
    // Value: raw cert bytes (already msgpack-encoded)
    buf.extend_from_slice(cert);

    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_fetcher::{format_round_base36, make_block_request_topics};
    use axum::body::Body;
    use http::Request;
    use std::sync::Mutex;
    use tower::ServiceExt; // for `oneshot`

    // -----------------------------------------------------------------------
    // Mock ledger
    // -----------------------------------------------------------------------

    /// Block data: (raw block bytes, raw cert bytes).
    type BlockEntry = (Vec<u8>, Vec<u8>);

    /// A simple mock ledger for testing.
    struct MockLedger {
        /// Blocks indexed by round.
        blocks: Mutex<std::collections::HashMap<u64, BlockEntry>>,
        /// Latest round.
        latest: Mutex<u64>,
    }

    impl MockLedger {
        fn new() -> Self {
            Self {
                blocks: Mutex::new(std::collections::HashMap::new()),
                latest: Mutex::new(0),
            }
        }

        fn add_block(&self, round: u64, block: Vec<u8>, cert: Vec<u8>) {
            self.blocks.lock().unwrap().insert(round, (block, cert));
            let mut latest = self.latest.lock().unwrap();
            if round > *latest {
                *latest = round;
            }
        }
    }

    impl LedgerForBlockService for MockLedger {
        fn encoded_block_cert(&self, round: u64) -> Result<(Vec<u8>, Vec<u8>), BlockServiceError> {
            let blocks = self.blocks.lock().unwrap();
            match blocks.get(&round) {
                Some((b, c)) => Ok((b.clone(), c.clone())),
                None => {
                    let latest = *self.latest.lock().unwrap();
                    Err(BlockServiceError::BlockNotAvailable {
                        round,
                        latest_round: Some(latest),
                    })
                }
            }
        }

        fn latest_round(&self) -> u64 {
            *self.latest.lock().unwrap()
        }
    }

    // -----------------------------------------------------------------------
    // Base-36 parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_base36_zero() {
        assert_eq!(parse_round_base36("0"), Some(0));
    }

    #[test]
    fn parse_base36_single_digit() {
        assert_eq!(parse_round_base36("1"), Some(1));
        assert_eq!(parse_round_base36("9"), Some(9));
        assert_eq!(parse_round_base36("a"), Some(10));
        assert_eq!(parse_round_base36("z"), Some(35));
    }

    #[test]
    fn parse_base36_multi_digit() {
        assert_eq!(parse_round_base36("10"), Some(36));
        assert_eq!(parse_round_base36("rs"), Some(1000));
        assert_eq!(parse_round_base36("lfls"), Some(1_000_000));
    }

    #[test]
    fn parse_base36_round_trips_with_format() {
        let values = [0, 1, 35, 36, 100, 1000, 1_000_000, u64::MAX];
        for &v in &values {
            let s = format_round_base36(v);
            let parsed = parse_round_base36(&s).unwrap();
            assert_eq!(parsed, v, "round-trip failed for {v} (encoded: {s})");
        }
    }

    #[test]
    fn parse_base36_empty_returns_none() {
        assert_eq!(parse_round_base36(""), None);
    }

    #[test]
    fn parse_base36_invalid_char_returns_none() {
        assert_eq!(parse_round_base36("ABC"), None); // uppercase
        assert_eq!(parse_round_base36("!"), None);
        assert_eq!(parse_round_base36("1-2"), None);
    }

    #[test]
    fn parse_base36_overflow_returns_none() {
        // This string is larger than u64::MAX in base-36
        assert_eq!(parse_round_base36("3w5e11264sgsg0"), None);
    }

    // -----------------------------------------------------------------------
    // HTTP handler tests
    // -----------------------------------------------------------------------

    fn make_test_service(ledger: Arc<MockLedger>) -> Router {
        let service = BlockService::new(
            ledger,
            "testnet-v1.0".to_string(),
            DEFAULT_BLOCK_SERVICE_MEM_CAP,
        );
        service.http_router()
    }

    #[tokio::test]
    async fn http_returns_block_for_valid_round() {
        let ledger = Arc::new(MockLedger::new());
        ledger.add_block(
            42,
            b"\x81\xa3foo\xa3bar".to_vec(), // some msgpack-ish block data
            b"\x80".to_vec(),               // some msgpack-ish cert data
        );
        let app = make_test_service(ledger);

        let round_b36 = format_round_base36(42); // "16"
        let uri = format!("/v1/testnet-v1.0/block/{round_b36}");
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            BLOCK_RESPONSE_CONTENT_TYPE,
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        // Should contain a msgpack map with "block" and "cert" keys
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn http_returns_404_for_missing_round() {
        // Add round 10 so latest=10, then request round 5 which isn't in the map
        let ledger = Arc::new(MockLedger::new());
        ledger.add_block(10, b"\x80".to_vec(), b"\x80".to_vec());
        let app = make_test_service(ledger);

        let uri = format!("/v1/testnet-v1.0/block/{}", format_round_base36(5));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn http_returns_404_when_round_ahead_of_latest() {
        let ledger = Arc::new(MockLedger::new());
        ledger.add_block(5, b"\x80".to_vec(), b"\x80".to_vec());
        let app = make_test_service(ledger);

        // Request round 100, which is > latest (5)
        let uri = format!("/v1/testnet-v1.0/block/{}", format_round_base36(100));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        // Must return 404 (not 503) to match Go's behaviour.
        // Go's catchup treats 404 as "try another peer immediately"
        // but treats 503 as "server overloaded, back off aggressively."
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers()
                .get(BLOCK_RESPONSE_LATEST_ROUND_HEADER)
                .unwrap()
                .to_str()
                .unwrap(),
            "5",
        );
    }

    #[tokio::test]
    async fn http_returns_503_when_mem_cap_exceeded() {
        let ledger = Arc::new(MockLedger::new());
        ledger.add_block(1, b"\x80".to_vec(), b"\x80".to_vec());
        // Create service with a tiny mem cap
        let service = BlockService::new(ledger, "testnet-v1.0".to_string(), 10);
        // Pre-load memory usage above cap
        service.http_mem_used.store(100, Ordering::Relaxed);
        let app = service.http_router();

        let uri = format!("/v1/testnet-v1.0/block/{}", format_round_base36(1));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers().get("retry-after").unwrap().to_str().unwrap(),
            BLOCK_RESPONSE_RETRY_AFTER,
        );
    }

    #[tokio::test]
    async fn http_returns_400_for_bad_version() {
        let ledger = Arc::new(MockLedger::new());
        let app = make_test_service(ledger);

        let req = Request::builder()
            .uri("/v2/testnet-v1.0/block/0")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn http_returns_400_for_bad_genesis_id() {
        let ledger = Arc::new(MockLedger::new());
        let app = make_test_service(ledger);

        let req = Request::builder()
            .uri("/v1/wrong-genesis/block/0")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn http_returns_400_for_bad_round() {
        let ledger = Arc::new(MockLedger::new());
        let app = make_test_service(ledger);

        // Uppercase letters are invalid in base-36 as Go uses lowercase
        let req = Request::builder()
            .uri("/v1/testnet-v1.0/block/INVALID")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn http_404_includes_latest_round_header() {
        let ledger = Arc::new(MockLedger::new());
        ledger.add_block(10, b"\x80".to_vec(), b"\x80".to_vec());
        let app = make_test_service(ledger);

        // Request round 5 which is <= latest but not in the ledger
        let uri = format!("/v1/testnet-v1.0/block/{}", format_round_base36(5));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers()
                .get("x-latest-round")
                .unwrap()
                .to_str()
                .unwrap(),
            "10",
        );
    }

    // -----------------------------------------------------------------------
    // Memory tracking tests
    // -----------------------------------------------------------------------

    #[test]
    fn memory_tracking_acquire_release() {
        let mem = Arc::new(AtomicU64::new(0));

        // Simulate acquiring memory
        mem.fetch_add(1000, Ordering::Relaxed);
        assert_eq!(mem.load(Ordering::Relaxed), 1000);

        // Simulate releasing memory
        mem.fetch_sub(1000, Ordering::Relaxed);
        assert_eq!(mem.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn block_service_ws_memory_release() {
        let ledger = Arc::new(MockLedger::new());
        ledger.add_block(1, b"\x80".to_vec(), b"\x80".to_vec());
        let service = BlockService::new(ledger, "test".to_string(), DEFAULT_BLOCK_SERVICE_MEM_CAP);

        assert_eq!(service.ws_mem_used(), 0);

        // Simulate WS request that returns block data
        let topics = make_block_request_topics(1);
        let request_data = topics.marshal();
        let (resp, guard) = service.handle_ws_block_request(&request_data);

        // Should have allocated memory for block + cert data
        let mem_after = service.ws_mem_used();
        assert!(mem_after > 0, "ws_mem_used should be > 0 after block fetch");
        assert!(
            guard.is_some(),
            "guard should be Some for successful block fetch"
        );

        // Release it by dropping the guard
        drop(guard);
        assert_eq!(service.ws_mem_used(), 0);

        // Verify response has block and cert data
        assert!(resp.get_value(BLOCK_DATA_KEY).is_some());
        assert!(resp.get_value(CERT_DATA_KEY).is_some());
    }

    // -----------------------------------------------------------------------
    // WS block request tests
    // -----------------------------------------------------------------------

    #[test]
    fn ws_block_request_success() {
        let ledger = Arc::new(MockLedger::new());
        ledger.add_block(42, b"block-data-42".to_vec(), b"cert-data-42".to_vec());
        let service = BlockService::new(ledger, "test".to_string(), DEFAULT_BLOCK_SERVICE_MEM_CAP);

        let topics = make_block_request_topics(42);
        let request_data = topics.marshal();
        let (resp, _guard) = service.handle_ws_block_request(&request_data);

        assert_eq!(
            resp.get_value(BLOCK_DATA_KEY),
            Some(b"block-data-42".as_slice())
        );
        assert_eq!(
            resp.get_value(CERT_DATA_KEY),
            Some(b"cert-data-42".as_slice())
        );
        assert!(resp.get_value(ERROR_KEY).is_none());
    }

    #[test]
    fn ws_block_request_not_available() {
        let ledger = Arc::new(MockLedger::new());
        ledger.add_block(10, b"\x80".to_vec(), b"\x80".to_vec());
        let service = BlockService::new(ledger, "test".to_string(), DEFAULT_BLOCK_SERVICE_MEM_CAP);

        let topics = make_block_request_topics(99);
        let request_data = topics.marshal();
        let (resp, guard) = service.handle_ws_block_request(&request_data);

        assert!(guard.is_none(), "no guard for error responses");

        let error = resp.get_value(ERROR_KEY).unwrap();
        assert_eq!(error, BLOCK_NOT_AVAILABLE_ERR_MSG.as_bytes());

        // Should include latest round
        let latest = resp.get_value(LATEST_ROUND_KEY).unwrap();
        assert_eq!(latest.len(), 8);
        let latest_round = u64::from_be_bytes(latest.try_into().unwrap());
        assert_eq!(latest_round, 10);
    }

    #[test]
    fn ws_block_request_missing_round_key() {
        let ledger = Arc::new(MockLedger::new());
        let service = BlockService::new(ledger, "test".to_string(), DEFAULT_BLOCK_SERVICE_MEM_CAP);

        // Construct topics without roundKey
        let topics = Topics::from_vec(vec![Topic::new(
            REQUEST_DATA_TYPE_KEY,
            BLOCK_AND_CERT_VALUE.as_bytes(),
        )]);
        let request_data = topics.marshal();
        let (resp, _guard) = service.handle_ws_block_request(&request_data);

        let error = resp.get_value(ERROR_KEY).unwrap();
        assert_eq!(error, NO_ROUND_NUMBER_ERR_MSG.as_bytes());
    }

    #[test]
    fn ws_block_request_missing_data_type() {
        let ledger = Arc::new(MockLedger::new());
        let service = BlockService::new(ledger, "test".to_string(), DEFAULT_BLOCK_SERVICE_MEM_CAP);

        // Construct topics without requestDataType
        let topics = Topics::from_vec(vec![Topic::new(ROUND_KEY, vec![42u8])]);
        let request_data = topics.marshal();
        let (resp, _guard) = service.handle_ws_block_request(&request_data);

        let error = resp.get_value(ERROR_KEY).unwrap();
        assert_eq!(error, NO_DATA_TYPE_ERR_MSG.as_bytes());
    }

    #[test]
    fn ws_block_request_unsupported_data_type() {
        let ledger = Arc::new(MockLedger::new());
        let service = BlockService::new(ledger, "test".to_string(), DEFAULT_BLOCK_SERVICE_MEM_CAP);

        let topics = Topics::from_vec(vec![
            Topic::new(REQUEST_DATA_TYPE_KEY, b"blockOnly".to_vec()),
            Topic::new(ROUND_KEY, vec![42u8]),
        ]);
        let request_data = topics.marshal();
        let (resp, _guard) = service.handle_ws_block_request(&request_data);

        let error = resp.get_value(ERROR_KEY).unwrap();
        assert_eq!(error, DATATYPE_UNSUPPORTED_ERR_MSG.as_bytes());
    }

    #[test]
    fn ws_block_request_memory_cap_exceeded() {
        let ledger = Arc::new(MockLedger::new());
        ledger.add_block(1, b"\x80".to_vec(), b"\x80".to_vec());
        let service = BlockService::new(ledger, "test".to_string(), 10);
        // Pre-load ws memory above cap
        service.ws_mem_used.store(100, Ordering::Relaxed);

        let topics = make_block_request_topics(1);
        let request_data = topics.marshal();
        let (resp, guard) = service.handle_ws_block_request(&request_data);

        assert!(guard.is_none(), "no guard for error responses");
        let error = resp.get_value(ERROR_KEY).unwrap();
        assert_eq!(error, MEMORY_AT_CAPACITY_ERR_MSG.as_bytes());
    }

    #[test]
    fn mem_cap_zero_allows_unlimited_requests() {
        // mem_cap == 0 is documented as "unlimited" — verify it does not
        // reject requests even when mem_used is already large.
        let ledger = Arc::new(MockLedger::new());
        ledger.add_block(1, b"\x80".to_vec(), b"\x80".to_vec());

        // WS path
        let service = BlockService::new(ledger.clone(), "test".to_string(), 0);
        service.ws_mem_used.store(u64::MAX / 2, Ordering::Relaxed);

        let topics = make_block_request_topics(1);
        let request_data = topics.marshal();
        let (resp, guard) = service.handle_ws_block_request(&request_data);

        assert!(
            guard.is_some(),
            "mem_cap=0 should allow the request (guard should be Some)"
        );
        assert!(resp.get_value(BLOCK_DATA_KEY).is_some());
        assert!(resp.get_value(ERROR_KEY).is_none());
    }

    #[tokio::test]
    async fn http_mem_cap_zero_allows_unlimited_requests() {
        let ledger = Arc::new(MockLedger::new());
        ledger.add_block(1, b"\x80".to_vec(), b"\x80".to_vec());

        // Build service with mem_cap=0 (unlimited)
        let service = BlockService::new(ledger, "testnet-v1.0".to_string(), 0);
        // Pre-load a large memory value to confirm it is not checked
        service.http_mem_used.store(u64::MAX / 2, Ordering::Relaxed);
        let app = service.http_router();

        let uri = format!("/v1/testnet-v1.0/block/{}", format_round_base36(1));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "mem_cap=0 should allow the request"
        );
    }

    /// A [`LedgerForBlockService`] that blocks inside `encoded_block_cert`
    /// until released, notifying a channel the instant it is entered.
    /// Lets a test deterministically observe "the handler is now in
    /// flight" before acting, instead of racing a fixed sleep against the
    /// real (near-instantaneous) in-process handler.
    struct SlowLedger {
        inner: MockLedger,
        entered_tx: std::sync::mpsc::Sender<()>,
        release_rx: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl LedgerForBlockService for SlowLedger {
        fn encoded_block_cert(&self, round: u64) -> Result<(Vec<u8>, Vec<u8>), BlockServiceError> {
            let _ = self.entered_tx.send(());
            // Blocking recv is fine here: the test runtime is multi-threaded
            // (see `#[tokio::test(flavor = "multi_thread", ...)]` below), so
            // stalling this handler's worker thread doesn't stall the
            // listener's accept loop or the shutdown-signal task.
            let _ = self.release_rx.lock().unwrap().recv();
            self.inner.encoded_block_cert(round)
        }

        fn latest_round(&self) -> u64 {
            self.inner.latest_round()
        }
    }

    /// Port of `TestBlockServiceShutdown` (`rpcs/blockService_test.go`):
    /// go's test starts the block service, fires off a block-fetch request
    /// on a background goroutine, immediately calls `bs1.Stop()` and
    /// `ledger1.Close()` while that request is in flight, then asserts the
    /// request's goroutine still completes (`<-requestDone`) rather than
    /// hanging forever.
    ///
    /// algod-rust has no separate `BlockService::Stop()` — the router it
    /// builds is served by the ambient `axum::serve` HTTP server, whose
    /// lifecycle (including graceful shutdown) is owned by the caller (see
    /// `algo-rest-api::server`). The equivalent guarantee here is that
    /// triggering that server's graceful-shutdown future while a
    /// block-fetch request is genuinely in flight (blocked inside the
    /// ledger lookup, confirmed via `entered_rx`) still lets that request
    /// complete and lets the server task exit promptly, instead of the
    /// client hanging or the server task never returning.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_server_graceful_shutdown_completes_inflight_request() {
        let inner = MockLedger::new();
        inner.add_block(1, b"\x81\xa3foo\xa3bar".to_vec(), b"\x80".to_vec());
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let ledger = Arc::new(SlowLedger {
            inner,
            entered_tx,
            release_rx: std::sync::Mutex::new(release_rx),
        });
        let service = BlockService::new(
            ledger,
            "testnet-v1.0".to_string(),
            DEFAULT_BLOCK_SERVICE_MEM_CAP,
        );
        let app = service.http_router();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let uri = format!(
            "http://{addr}/v1/testnet-v1.0/block/{}",
            format_round_base36(1)
        );
        let client = reqwest::Client::new();
        // Fire off the request on a background task, mirroring go's
        // `go func() { ...; client.Do(request) }()`.
        let request = tokio::spawn(async move { client.get(uri).send().await });

        // Block until the handler has genuinely entered the ledger lookup
        // (i.e. the request is in flight, not merely dispatched), then
        // trigger graceful shutdown -- exactly as go's test calls
        // `bs1.Stop()` while the fetch goroutine is still running.
        tokio::task::spawn_blocking(move || entered_rx.recv())
            .await
            .expect("blocking wait task must not panic")
            .expect("handler must signal it has entered the lookup");
        let _ = shutdown_tx.send(());

        // Give the shutdown signal a moment to actually stop the accept
        // loop before releasing the in-flight handler, so the test proves
        // the *in-flight* request survives shutdown rather than merely
        // being a request that got lucky and finished first.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = release_tx.send(());

        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), request)
            .await
            .expect("request must not hang past graceful shutdown")
            .expect("request task must not panic")
            .expect("in-flight request should still succeed despite concurrent shutdown");
        assert_eq!(resp.status(), reqwest::StatusCode::OK);

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("server task must exit promptly after graceful shutdown")
            .expect("server task must not panic")
            .expect("server must shut down without error");
    }

    #[test]
    fn ws_block_request_bad_topics() {
        let ledger = Arc::new(MockLedger::new());
        let service = BlockService::new(ledger, "test".to_string(), DEFAULT_BLOCK_SERVICE_MEM_CAP);

        // Send garbage data
        let (resp, _guard) = service.handle_ws_block_request(&[0xFF, 0xFF, 0xFF]);

        let error = resp.get_value(ERROR_KEY);
        assert!(error.is_some(), "should return error for bad topics");
    }

    // -----------------------------------------------------------------------
    // Pre-encoded block cert encoding test
    // -----------------------------------------------------------------------

    #[test]
    fn encode_pre_encoded_block_cert_format() {
        let block = b"\x80"; // empty msgpack map
        let cert = b"\x80"; // empty msgpack map
        let encoded = encode_pre_encoded_block_cert(block, cert);

        // Should be a 2-element map
        assert_eq!(encoded[0], 0x82, "should be fixmap(2)");

        // Decode with rmpv to validate structure
        let value: rmpv::Value = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
        let map = value.as_map().expect("should be a map");
        assert_eq!(map.len(), 2);

        // Check keys
        let key0 = map[0].0.as_str().unwrap();
        let key1 = map[1].0.as_str().unwrap();
        assert_eq!(key0, "block");
        assert_eq!(key1, "cert");
    }

    // -----------------------------------------------------------------------
    // Redirect-to-archival-peer fallback (issue #955)
    //
    // Ports the intent of go's `TestRedirectFallbackEndpoints`,
    // `TestRedirectOnFullCapacity`, `TestRedirectExceptions`, and
    // `TestBlockServiceRedirect` (`rpcs/blockService_test.go`), adapted to
    // this crate's construction-time endpoint validation (see the
    // module-level note above `FallbackEndpoints` for why) rather than
    // go's exact `net/url`-quirk-dependent runtime parsing.
    // -----------------------------------------------------------------------

    #[test]
    fn fallback_endpoints_parses_comma_delimited_list() {
        let fb = FallbackEndpoints::parse("10.0.0.1:1234,http://example.com:5678/foo");
        assert_eq!(fb.endpoints.len(), 2);
    }

    #[test]
    fn fallback_endpoints_skips_unparseable_entries() {
        // "://badaddress" cannot be parsed as a URL (no valid scheme) by
        // go's `net/url` or this crate's `url` crate alike -- go's
        // `redirectRequest` discovers this lazily per-request and returns
        // `ok=false` for that one attempt; this port instead drops it once
        // at construction, so round-robin never lands on it at all.
        let fb = FallbackEndpoints::parse("://badaddress,10.0.0.1:1234");
        assert_eq!(fb.endpoints.len(), 1);
    }

    #[test]
    fn fallback_endpoints_skips_multiaddr_entries() {
        let fb = FallbackEndpoints::parse(
            "/ip4/127.0.0.1/tcp/2345/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN,10.0.0.1:1234",
        );
        assert_eq!(fb.endpoints.len(), 1);
    }

    #[test]
    fn fallback_endpoints_empty_string_has_no_endpoints() {
        let fb = FallbackEndpoints::parse("");
        assert!(fb.next_endpoint().is_none());
    }

    #[test]
    fn fallback_endpoints_round_robin_cycles_through_all_entries() {
        let fb = FallbackEndpoints::parse("host-a:1111,host-b:2222,host-c:3333");
        let picked: Vec<String> = (0..6)
            .map(|_| fb.next_endpoint().unwrap().host_str().unwrap().to_string())
            .collect();
        assert_eq!(
            picked,
            vec!["host-a", "host-b", "host-c", "host-a", "host-b", "host-c"]
        );
    }

    #[test]
    fn redirect_location_builds_expected_url_and_path() {
        let fb = FallbackEndpoints::parse("archival.example.com:8080");
        let location = fb.redirect_location("test-genesis-ID", 10).unwrap();
        assert_eq!(
            location,
            format!(
                "http://archival.example.com:8080/v1/test-genesis-ID/block/{}",
                format_round_base36(10)
            )
        );
    }

    #[test]
    fn redirect_location_none_when_no_fallback_configured() {
        let fb = FallbackEndpoints::empty();
        assert!(fb.redirect_location("test-genesis-ID", 10).is_none());
    }

    /// Port of `TestRedirectFallbackEndpoints`: a block request for a round
    /// this node doesn't have yet redirects (307, with a `Location` header)
    /// to the configured fallback rather than answering 404 directly.
    #[tokio::test]
    async fn http_redirects_to_fallback_when_round_not_available() {
        let ledger = Arc::new(MockLedger::new());
        ledger.add_block(1, b"\x80".to_vec(), b"\x80".to_vec());
        let service = BlockService::new(
            ledger,
            "testnet-v1.0".to_string(),
            DEFAULT_BLOCK_SERVICE_MEM_CAP,
        )
        .with_custom_fallback_endpoints("archival.example.com:8080");
        let app = service.http_router();

        // Round 5 is ahead of latest (1) -- the "not available" branch.
        let uri = format!("/v1/testnet-v1.0/block/{}", format_round_base36(5));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("http://archival.example.com:8080/v1/testnet-v1.0/block/"));
    }

    /// Port of `TestRedirectOnFullCapacity`: over the memory cap, the
    /// service redirects rather than returning 503, when a fallback is
    /// configured.
    #[tokio::test]
    async fn http_redirects_to_fallback_when_over_memory_cap() {
        let ledger = Arc::new(MockLedger::new());
        ledger.add_block(1, b"\x80".to_vec(), b"\x80".to_vec());
        let service = BlockService::new(ledger, "testnet-v1.0".to_string(), 10)
            .with_custom_fallback_endpoints("archival.example.com:8080");
        service.http_mem_used.store(100, Ordering::Relaxed);
        let app = service.http_router();

        let uri = format!("/v1/testnet-v1.0/block/{}", format_round_base36(1));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        assert!(resp.headers().get("location").is_some());
    }

    /// Port of `TestRedirectExceptions`'s "no valid fallback" half: with no
    /// fallback endpoints configured, an unavailable round still falls back
    /// to a plain 404 (unchanged pre-#955 behavior) rather than ever
    /// producing a redirect.
    #[tokio::test]
    async fn http_returns_404_when_round_ahead_of_latest_and_no_fallback_configured() {
        let ledger = Arc::new(MockLedger::new());
        ledger.add_block(5, b"\x80".to_vec(), b"\x80".to_vec());
        let app = make_test_service(ledger); // no fallback endpoints configured

        let uri = format!("/v1/testnet-v1.0/block/{}", format_round_base36(100));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Port of `TestBlockServiceRedirect`: a bare `host:port` fallback
    /// endpoint redirects to an `http://` URL built from it, at the go-shaped
    /// block-query path.
    #[test]
    fn test_block_service_redirect_host_colon_port() {
        let fb = FallbackEndpoints::parse("localhost:1234");
        let location = fb.redirect_location("test-genesis-ID", 10).unwrap();
        assert_eq!(
            location,
            format!(
                "http://localhost:1234/v1/test-genesis-ID/block/{}",
                format_round_base36(10)
            )
        );
    }
}
