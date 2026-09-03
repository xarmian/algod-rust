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

//! Transaction-sync service — HTTP server side of the [`TxSyncer`] pull
//! protocol (issues #774, #792).
//!
//! Byte-for-byte port of go-algorand's `TxService`
//! (`rpcs/txService.go`/`RegisterTxService`/`TxService.ServeHTTP`): a peer
//! POSTs a Bloom filter ([`crate::bloom::Filter`]) over the txids it
//! already has pending, form-encoded as `application/x-www-form-urlencoded`
//! at go's real path `/v1/{genesisID}/txsync`, and this service answers
//! with a flat, canonically-msgpack-encoded array of every
//! locally-pending transaction whose group contains at least one txid the
//! filter says is missing, content-typed
//! `application/x-algorand-ptx-v1`.
//!
//! ## History: superseding the #774 simplified wire format
//!
//! #774 (this module's original PR) deliberately shipped a distinct,
//! simplified wire format (`/{version}/{genesisID}/rust-txsync`, a plain
//! `Vec<Digest>` request and a grouped msgpack response) rather than
//! porting go's Bloom filter — a scoped, documented simplification, not an
//! oversight, tracked for closing under this repo's own issue-carries-its-
//! own-gap-forward discipline. That gap is issue #792, which this version
//! of the module closes: the endpoint now speaks go's actual wire format,
//! so a real go-algorand `v5.0.0-stable` relay's tx-sync endpoint can serve
//! (and be served by) an algod-rust node.
//!
//! The #774 path is retired outright rather than kept behind a flag: the
//! Bloom filter's ~1% false-positive overhead is negligible even for
//! algod-rust-to-algod-rust sync, and maintaining two parallel wire
//! protocols for the same endpoint is a bigger long-term cost than that
//! overhead — an explicit call per #792's own acceptance criteria, not a
//! silent decision.
//!
//! ## Peer-fairness servicing gate (issues #821, #860)
//!
//! See [`TxSyncPeerLimiter`]'s doc comment for the full design: an optional
//! [`ElasticRateLimiter`]`<IpAddr>` guarding how much of *this* node's own
//! servicing capacity each requesting peer's `POST .../txsync` calls may
//! consume, keyed by the peer's source IP (available via axum's
//! `ConnectInfo<SocketAddr>` extractor once the router is served through
//! [`crate::ws_network::WebsocketNetwork`]'s connect-info-aware listener,
//! exactly as [`crate::block_service`]'s sibling endpoint could adopt too).
//!
//! [`TxSyncer`]: crate::tx_syncer::TxSyncer

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use http::{HeaderMap, StatusCode};
use tracing::debug;

use algo_codec::{canonical_encode_signed_transaction, compute_txn_id};
use algo_pool::{CapacityGuard, ElasticRateLimiter, ElasticRateLimiterError};
use algo_types::SignedTransaction;

use crate::bloom::Filter;

/// Content-Type required on the request body: a `bf=<base64url(filter)>`
/// form field. Matches go's `requestContentType`
/// (`rpcs/httpTxSync.go`).
pub const TX_SYNC_REQUEST_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

/// Content-Type set on the response body: a flat, canonically-encoded
/// msgpack array of `SignedTransaction`. Matches go's `responseContentType`
/// (`rpcs/txService.go`) — go's client (`httpTxSync.go`) also currently
/// accepts this same string under a second, vestigial constant name
/// (`responseContentTypeOld`), i.e. there is only one value in practice.
pub const TX_SYNC_RESPONSE_CONTENT_TYPE: &str = "application/x-algorand-ptx-v1";

/// go's real path: `TxServiceHTTPPath = "/v1/{genesisID}/txsync"`
/// (`rpcs/txService.go`).
const TX_SYNC_HTTP_PATH: &str = "/v1/:genesis_id/txsync";

/// Hard cap on the request body size read by the HTTP layer before this
/// handler ever sees it. A legitimate Bloom filter (even sized for a
/// pool of hundreds of thousands of pending txns at go's 1%
/// false-positive rate) is at most a few hundred KB once base64-inflated
/// and form-encoded; this cap is generously above that, mirroring go's
/// `maxRequestBodyLength` in spirit (go derives its cap from the
/// configured pool size; this flat cap is deliberately simpler and still
/// comfortably tight against an actually-oversized body).
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Peer-fairness gate for [`TxSyncService`]'s own servicing capacity
/// (issues #821, #860).
///
/// ## Why this exists
///
/// go-algorand's `ElasticRateLimiter`/RED pair (`util/rateLimit.go`,
/// wired in `data/txHandler.go`) protects a **push-based** admission
/// point: peers unsolicitedly relay transactions to this node, and the
/// gate decides whether to admit each one onto the shared backlog queue
/// *before* it consumes local resources, so one noisy or malicious peer
/// cannot flood the backlog and starve everyone else's transactions from
/// ever being processed.
///
/// algod-rust's actual peer-to-peer transaction path
/// ([`crate::tx_syncer::TxSyncer`]) is **pull-based**: this node polls
/// each peer's synced-transaction set on a timer, so there is no
/// reachable "unsolicited incoming transaction" admission point the way
/// go's gate has (see `algo_pool::elastic_rate_limiter`'s module doc for
/// the full architectural trace). The mirror image of go's gate on a
/// pull architecture is fairness across *which peer's pull request this
/// node services first* when this node's own servicing capacity (pool
/// snapshot + msgpack encoding + response bandwidth) is under pressure —
/// exactly the design this issue's own body sketches. `TxSyncPeerLimiter`
/// applies [`ElasticRateLimiter`]'s per-client capacity-reservation model
/// to that servicing capacity, keyed by the requesting peer's source IP:
///
/// * Each peer gets a small guaranteed reservation
///   (`capacity_per_peer`) out of a shared pool (`max_capacity`) sized to
///   this node's total concurrent tx-sync servicing budget — so one peer
///   issuing many pull requests back-to-back cannot exhaust capacity that
///   another, already-active peer has already reserved for itself (see
///   this module's `peer_reservation_isolates_fairness` test).
/// * Once a peer's reservation is empty, further requests draw from the
///   shared pool, optionally gated by [`RedCongestionManager`] exactly as
///   go's does: requests are dropped with probability proportional to how
///   far a peer's arrival rate exceeds its fair per-peer share of this
///   node's service rate.
/// * Congestion control is toggled dynamically based on shared-pool
///   utilization, mirroring go's `TxHandler.incomingMsgErlCheck`
///   (`data/txHandler.go`): go enables it once the backlog queue crosses
///   a configured congestion threshold and disables it once the queue
///   has drained back below that threshold (hysteresis so it doesn't
///   flap at the boundary); this port uses free shared-pool capacity as
///   the equivalent congestion signal (below `CONGESTION_THRESHOLD_PCT`
///   free triggers it, matching go's own default 50% framing), since a
///   synchronous request-serving path has no separate backlog-queue
///   depth to sample.
///
/// ## Honest limitation (inherited from the algorithm, not a wiring bug)
///
/// Reservations are opened lazily, on a peer's first request. A flood
/// from a brand-new peer that arrives *before* other peers have made
/// their own first request can still claim the entire shared pool (there
/// is nothing yet reserved for peers the node has never heard from) —
/// this matches go's own `capacityQueue` semantics exactly (the shared
/// pool is genuinely first-come while unclaimed) and is not something
/// this wiring, or go's original algorithm, tries to prevent. What the
/// mechanism *does* guarantee is that a peer who has already reserved
/// capacity keeps access to that reservation regardless of how hard any
/// other peer floods the shared pool afterward.
///
/// [`RedCongestionManager`]: algo_pool::RedCongestionManager
pub struct TxSyncPeerLimiter {
    erl: Mutex<ElasticRateLimiter<IpAddr>>,
    max_capacity: usize,
}

/// Free-shared-capacity threshold (as a percentage of `max_capacity`)
/// below which congestion control is enabled, and at/above which it is
/// disabled again. Mirrors the framing of go's
/// `TxBacklogRateLimitingCongestionPct` default (50%) — see
/// [`TxSyncPeerLimiter`]'s doc comment.
const CONGESTION_THRESHOLD_PCT: usize = 50;

impl TxSyncPeerLimiter {
    /// Creates a peer-fairness limiter with `max_capacity` total
    /// concurrently-servicable tx-sync requests, of which `capacity_per_peer`
    /// units are set aside as a guaranteed reservation for each distinct
    /// requesting peer (by source IP) the first time it is seen.
    /// `service_rate_window` sizes the sliding window
    /// [`RedCongestionManager`](algo_pool::RedCongestionManager) uses to
    /// estimate arrival/service rates once congestion control is enabled.
    #[must_use]
    pub fn new(
        max_capacity: usize,
        capacity_per_peer: usize,
        service_rate_window: Duration,
    ) -> Self {
        let max_capacity = max_capacity.max(1);
        Self {
            erl: Mutex::new(ElasticRateLimiter::new(
                max_capacity,
                capacity_per_peer,
                service_rate_window,
            )),
            max_capacity,
        }
    }

    /// Attempts to admit one tx-sync request from `peer`. On success,
    /// returns a guard the caller must pass to [`Self::complete`] once the
    /// request has been serviced (the equivalent of go's
    /// `ErlCapacityGuard.Served` + `Release`).
    fn admit(&self, peer: IpAddr) -> Result<CapacityGuard<IpAddr>, ElasticRateLimiterError> {
        let mut erl = self.erl.lock().expect("TxSyncPeerLimiter mutex poisoned");
        let was_congested =
            Self::shared_pool_congested(erl.shared_capacity_len(), self.max_capacity);
        let (is_cm_enabled, res) = erl.consume_capacity(&peer);
        // Mirrors go's `TxHandler.incomingMsgErlCheck` hysteresis: a failed
        // vend is itself the strongest possible congestion signal (force
        // it on, regardless of `is_cm_enabled`); otherwise flip based on
        // the pre-request utilization reading, matching go reading
        // `congestedERL` before consuming.
        if res.is_err() || (!is_cm_enabled && was_congested) {
            erl.enable_congestion_control();
        } else if !was_congested {
            erl.disable_congestion_control();
        }
        res
    }

    /// Marks the request the guard was admitting as fully serviced,
    /// informing the congestion manager's service-rate estimate, then
    /// returns the guard's capacity unit to its origin queue. Mirrors go's
    /// `ErlCapacityGuard.Served()` followed by `Release()`.
    fn complete(&self, mut guard: CapacityGuard<IpAddr>) {
        let mut erl = self.erl.lock().expect("TxSyncPeerLimiter mutex poisoned");
        erl.served(Instant::now());
        let _ = erl.release(&mut guard);
    }

    fn shared_pool_congested(free: usize, max_capacity: usize) -> bool {
        free.saturating_mul(100) / max_capacity.max(1) < CONGESTION_THRESHOLD_PCT
    }
}

impl std::fmt::Debug for TxSyncPeerLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxSyncPeerLimiter")
            .field("max_capacity", &self.max_capacity)
            .finish()
    }
}

/// Read-only view of the pool's locally-pending transaction groups.
///
/// Narrow on purpose (mirrors [`crate::block_service::LedgerForBlockService`]'s
/// rationale) so this module can be unit-tested without a real
/// `algo_pool::TransactionPool`.
pub trait PendingTxGroupsSource: Send + Sync + 'static {
    /// Snapshot of every pending transaction group currently held by the
    /// pool.
    fn pending_tx_groups(&self) -> Vec<Vec<SignedTransaction>>;
}

/// Server side of the transaction-sync pull protocol.
///
/// Mirrors [`crate::block_service::BlockService`]'s shape: construct once,
/// register `http_router()` on the gossip node before starting the
/// listener.
pub struct TxSyncService {
    pool: Arc<dyn PendingTxGroupsSource>,
    genesis_id: String,
    /// Cap (in encoded bytes) on the total size of transactions returned in
    /// one response. Mirrors go's `TxSyncServeResponseSize` /
    /// `responseSizeLimit` — once accumulating groups would exceed this,
    /// the response stops early (matching go's `getFilteredTxns` break,
    /// including on the very first group — go does not special-case an
    /// otherwise-empty response).
    response_size_limit: usize,
    /// Optional peer-fairness servicing gate (issues #821, #860). `None`
    /// (the default from [`Self::new`]) means every well-formed request is
    /// serviced unconditionally, matching this endpoint's original
    /// behavior.
    peer_limiter: Option<Arc<TxSyncPeerLimiter>>,
}

#[derive(Clone)]
struct TxSyncServiceState {
    pool: Arc<dyn PendingTxGroupsSource>,
    genesis_id: String,
    response_size_limit: usize,
    peer_limiter: Option<Arc<TxSyncPeerLimiter>>,
}

impl TxSyncService {
    /// Create a new tx-sync service.
    ///
    /// `response_size_limit` of `0` is treated as `1` — a zero-sized
    /// response cap would silently drop every response, which is never
    /// the intent of a misconfigured `TxSyncServeResponseSize: 0`.
    ///
    /// No peer-fairness gate is installed by default — call
    /// [`Self::with_peer_limiter`] to opt in.
    #[must_use]
    pub fn new(
        pool: Arc<dyn PendingTxGroupsSource>,
        genesis_id: String,
        response_size_limit: usize,
    ) -> Self {
        Self {
            pool,
            genesis_id,
            response_size_limit: response_size_limit.max(1),
            peer_limiter: None,
        }
    }

    /// Installs a [`TxSyncPeerLimiter`] gating how much of this node's
    /// servicing capacity each requesting peer's `POST .../txsync` calls
    /// may consume (issues #821, #860). See [`TxSyncPeerLimiter`]'s doc
    /// comment for the fairness design.
    #[must_use]
    pub fn with_peer_limiter(mut self, limiter: Arc<TxSyncPeerLimiter>) -> Self {
        self.peer_limiter = Some(limiter);
        self
    }

    /// Build an [`axum::Router`] for the HTTP tx-sync endpoint.
    ///
    /// Registers `POST /v1/:genesis_id/txsync` — go's real path
    /// (`TxServiceHTTPPath`). When a [`TxSyncPeerLimiter`] is installed,
    /// requests are identified by the caller's source IP via axum's
    /// `ConnectInfo<SocketAddr>` extractor — the router must therefore be
    /// served through a listener that supplies connect info (as
    /// [`crate::ws_network::WebsocketNetwork`]'s relay server does for
    /// every handler registered via `register_http_handler`).
    pub fn http_router(&self) -> Router {
        let state = TxSyncServiceState {
            pool: Arc::clone(&self.pool),
            genesis_id: self.genesis_id.clone(),
            response_size_limit: self.response_size_limit,
            peer_limiter: self.peer_limiter.clone(),
        };

        Router::new()
            .route(TX_SYNC_HTTP_PATH, post(serve_tx_sync))
            .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
            .with_state(state)
    }
}

async fn serve_tx_sync(
    State(state): State<TxSyncServiceState>,
    Path(genesis_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if genesis_id != state.genesis_id {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // go requires *exactly one* Content-Type header, equal to
    // `requestContentType` (`rpcs/txService.go`'s `len(contentTypes) != 1`
    // check) — not merely "contains" or "starts with".
    let mut content_types = headers.get_all(CONTENT_TYPE).iter();
    let content_type = content_types.next();
    if content_types.next().is_some() || content_type.is_none() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if content_type.and_then(|v| v.to_str().ok()) != Some(TX_SYNC_REQUEST_CONTENT_TYPE) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let bloom_filter_text = url::form_urlencoded::parse(&body)
        .find(|(k, _)| k == "bf")
        .map(|(_, v)| v.into_owned());
    let Some(bloom_filter_text) = bloom_filter_text.filter(|v| !v.is_empty()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    let filter_bytes = match base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE,
        &bloom_filter_text,
    ) {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let filter = match Filter::unmarshal_binary(&filter_bytes) {
        Ok(f) => f,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    // Peer-fairness servicing gate (issues #821, #860) — applied only now,
    // after the request is known well-formed and immediately before the
    // real servicing work (reading the pool + encoding the response), so
    // a malformed request never consumes a peer's fairness budget. See
    // `TxSyncPeerLimiter`'s doc comment for the design.
    let guard = match &state.peer_limiter {
        Some(limiter) => match limiter.admit(remote_addr.ip()) {
            Ok(g) => Some(g),
            Err(e) => {
                debug!(
                    peer = %remote_addr.ip(),
                    error = %e,
                    "tx-sync request throttled: this node's own servicing capacity is under \
                     pressure and this peer's fair share is exhausted",
                );
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        },
        None => None,
    };

    let payload = build_response_body(
        state.pool.pending_tx_groups(),
        &filter,
        state.response_size_limit,
    );

    if let (Some(limiter), Some(guard)) = (&state.peer_limiter, guard) {
        limiter.complete(guard);
    }

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", TX_SYNC_RESPONSE_CONTENT_TYPE)
        .body(axum::body::Body::from(payload))
        .expect("well-formed response")
}

/// Build the flat, canonically-encoded msgpack array response body: every
/// transaction belonging to a group that has at least one txid missing
/// from `filter`, capped by `response_size_limit` encoded bytes. Mirrors
/// go's `TxService.getFilteredTxns` exactly, including its unconditional
/// break (go does not special-case keeping at least one group when the
/// very first candidate group already exceeds the cap).
fn build_response_body(
    groups: Vec<Vec<SignedTransaction>>,
    filter: &Filter,
    response_size_limit: usize,
) -> Vec<u8> {
    let mut missing_encoded: Vec<Vec<u8>> = Vec::new();
    let mut encoded_len: usize = 0;

    for group in groups {
        let has_missing = group
            .iter()
            .any(|tx| !filter.test(compute_txn_id(&tx.txn).as_bytes()));
        if !has_missing {
            continue;
        }

        let group_encoded: Vec<Vec<u8>> = group
            .iter()
            .map(canonical_encode_signed_transaction)
            .collect();
        let group_len: usize = group_encoded.iter().map(Vec::len).sum();

        if encoded_len.saturating_add(group_len) > response_size_limit {
            break;
        }
        encoded_len += group_len;
        missing_encoded.extend(group_encoded);
    }

    let mut body = Vec::with_capacity(8 + encoded_len);
    rmp::encode::write_array_len(&mut body, missing_encoded.len() as u32)
        .expect("txn count fits u32 (bounded by response_size_limit)");
    for seg in &missing_encoded {
        body.extend_from_slice(seg);
    }
    body
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt;

    struct FakePool(Vec<Vec<SignedTransaction>>);
    impl PendingTxGroupsSource for FakePool {
        fn pending_tx_groups(&self) -> Vec<Vec<SignedTransaction>> {
            self.0.clone()
        }
    }

    fn make_txn(fee: u64) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        // A real pending transaction always has a valid, non-empty type
        // and a non-zero sender; `canonical_encode_transaction` omits
        // both when zero-valued (go's omitempty), and `Transaction`'s
        // `Deserialize` requires them present (no `#[serde(default)]`,
        // matching that these are never legitimately absent), so an
        // unconditionally-zero-valued fixture would fail to round-trip
        // through the real canonical wire encoding this handler now uses.
        stx.txn.txn_type = algo_types::TxnType::Pay;
        stx.txn.sender = algo_types::Address([1u8; 32]);
        stx.txn.fee = fee;
        stx
    }

    /// Build a go-shaped request body: `bf=<base64url(filter bytes)>`.
    fn bf_form_body(filter: &Filter) -> Vec<u8> {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE,
            filter.marshal_binary(),
        );
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("bf", &encoded)
            .finish()
            .into_bytes()
    }

    /// A filter sized generously for a handful of elements, with none of
    /// `known` set -- "requester has nothing pending" (every server-side
    /// group is reported missing).
    fn empty_filter() -> Filter {
        let (size_bits, num_hashes) = Filter::optimal(4, 0.01);
        Filter::new(size_bits, num_hashes, 0)
    }

    /// A filter with exactly `known` txids set.
    fn filter_with(known: &[[u8; 32]]) -> Filter {
        let (size_bits, num_hashes) = Filter::optimal(known.len().max(1), 0.01);
        let mut f = Filter::new(size_bits, num_hashes, 0);
        for k in known {
            f.set(k);
        }
        f
    }

    /// Default remote address used by [`post`] for tests that don't care
    /// about peer identity.
    fn default_remote_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 0)
    }

    async fn post(router: Router, path: &str, content_type: &str, body: Vec<u8>) -> Response {
        post_from(router, path, content_type, body, default_remote_addr()).await
    }

    /// Like [`post`], but from an explicit peer address — the `oneshot`
    /// harness bypasses axum's connect-info-aware listener plumbing (see
    /// `TxSyncService::http_router`'s doc comment), so tests must insert
    /// `ConnectInfo` into the request extensions themselves, exactly as
    /// `into_make_service_with_connect_info` would at the real listener.
    async fn post_from(
        router: Router,
        path: &str,
        content_type: &str,
        body: Vec<u8>,
        remote_addr: SocketAddr,
    ) -> Response {
        let mut req = Request::builder()
            .method("POST")
            .uri(path)
            .header("Content-Type", content_type)
            .body(Body::from(body))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(remote_addr));
        router.oneshot(req).await.unwrap()
    }

    async fn decode_response_txns(resp: Response) -> Vec<SignedTransaction> {
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            TX_SYNC_RESPONSE_CONTENT_TYPE,
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        rmp_serde::from_slice(&bytes).expect("valid canonical msgpack array")
    }

    #[tokio::test]
    async fn returns_only_groups_with_a_missing_txid() {
        let have = make_txn(1);
        let missing = make_txn(2);
        let have_id = compute_txn_id(&have.txn);
        let missing_id = compute_txn_id(&missing.txn);

        let service = TxSyncService::new(
            Arc::new(FakePool(vec![vec![have.clone()], vec![missing.clone()]])),
            "test-genesis".to_string(),
            1_000_000,
        );
        let router = service.http_router();

        // Requester already has `have_id`; server should return only the
        // transaction with `missing_id`.
        let filter = filter_with(&[*have_id.as_bytes()]);
        let resp = post(
            router,
            "/v1/test-genesis/txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            bf_form_body(&filter),
        )
        .await;
        let txns = decode_response_txns(resp).await;
        assert_eq!(txns.len(), 1);
        assert_eq!(compute_txn_id(&txns[0].txn), missing_id);
    }

    #[tokio::test]
    async fn empty_pending_filter_returns_every_group() {
        let a = make_txn(1);
        let b = make_txn(2);
        let service = TxSyncService::new(
            Arc::new(FakePool(vec![vec![a], vec![b]])),
            "g".to_string(),
            1_000_000,
        );
        let router = service.http_router();
        let resp = post(
            router,
            "/v1/g/txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            bf_form_body(&empty_filter()),
        )
        .await;
        let txns = decode_response_txns(resp).await;
        assert_eq!(txns.len(), 2);
    }

    #[tokio::test]
    async fn all_known_returns_empty() {
        let a = make_txn(1);
        let id_a = compute_txn_id(&a.txn);
        let service = TxSyncService::new(
            Arc::new(FakePool(vec![vec![a]])),
            "g".to_string(),
            1_000_000,
        );
        let router = service.http_router();
        let filter = filter_with(&[*id_a.as_bytes()]);
        let resp = post(
            router,
            "/v1/g/txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            bf_form_body(&filter),
        )
        .await;
        let txns = decode_response_txns(resp).await;
        assert!(txns.is_empty());
    }

    #[tokio::test]
    async fn wrong_genesis_id_is_bad_request() {
        let service = TxSyncService::new(Arc::new(FakePool(vec![])), "g".to_string(), 1_000_000);
        let router = service.http_router();
        let resp = post(
            router,
            "/v1/other-genesis/txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            bf_form_body(&empty_filter()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn wrong_content_type_is_bad_request() {
        let service = TxSyncService::new(Arc::new(FakePool(vec![])), "g".to_string(), 1_000_000);
        let router = service.http_router();
        let resp = post(
            router,
            "/v1/g/txsync",
            "application/octet-stream",
            bf_form_body(&empty_filter()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn missing_bf_field_is_bad_request() {
        let service = TxSyncService::new(Arc::new(FakePool(vec![])), "g".to_string(), 1_000_000);
        let router = service.http_router();
        let resp = post(
            router,
            "/v1/g/txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            b"nope=1".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn malformed_bloom_filter_is_bad_request() {
        let service = TxSyncService::new(Arc::new(FakePool(vec![])), "g".to_string(), 1_000_000);
        let router = service.http_router();
        let garbage = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE,
            [0u8; 3], // shorter than the 8-byte header -- ShortData
        );
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("bf", &garbage)
            .finish()
            .into_bytes();
        let resp = post(router, "/v1/g/txsync", TX_SYNC_REQUEST_CONTENT_TYPE, body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn response_size_limit_stops_after_first_group_even_when_it_alone_exceeds_the_cap() {
        // Matches go's unconditional break: if even the FIRST candidate
        // group exceeds the cap, the response is empty -- go does not
        // special-case "keep at least one group".
        let a = make_txn(1);
        let a_len = canonical_encode_signed_transaction(&a).len();
        let service = TxSyncService::new(
            Arc::new(FakePool(vec![vec![a.clone()]])),
            "g".to_string(),
            a_len - 1, // one byte too small for even this one txn
        );
        let router = service.http_router();
        let resp = post(
            router,
            "/v1/g/txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            bf_form_body(&empty_filter()),
        )
        .await;
        let txns = decode_response_txns(resp).await;
        assert!(
            txns.is_empty(),
            "go's break is unconditional, even on the first group"
        );
    }

    #[tokio::test]
    async fn response_size_limit_includes_first_group_then_stops() {
        let a = make_txn(1);
        let b = make_txn(2);
        let a_len = canonical_encode_signed_transaction(&a).len();
        let service = TxSyncService::new(
            Arc::new(FakePool(vec![vec![a.clone()], vec![b.clone()]])),
            "g".to_string(),
            a_len, // exactly fits one group, not two
        );
        let router = service.http_router();
        let resp = post(
            router,
            "/v1/g/txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            bf_form_body(&empty_filter()),
        )
        .await;
        let txns = decode_response_txns(resp).await;
        assert_eq!(txns.len(), 1, "response should stop after the cap is hit");
    }

    // ── TxSyncPeerLimiter: fairness algorithm (issues #821, #860) ──────

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::from([a, b, c, d])
    }

    /// Core fairness property required by the issue: a peer that has
    /// already reserved capacity keeps access to *its own* reservation
    /// regardless of how hard another peer floods the shared pool
    /// afterward. This is the guarantee that stands in for RED's "no
    /// single peer can starve others" property on the pull-based side.
    #[test]
    fn peer_reservation_isolates_fairness_from_a_flooding_peer() {
        let quiet = ip(10, 0, 0, 1);
        let noisy = ip(10, 0, 0, 2);
        let limiter = TxSyncPeerLimiter::new(4, 1, Duration::from_secs(10));

        // `quiet` shows up first and reserves its 1 guaranteed unit but
        // does not (yet) consume it -- simulating a peer that has been
        // active before the flood starts.
        let quiet_guard = limiter
            .admit(quiet)
            .expect("quiet peer's first request opens a reservation");
        limiter.complete(quiet_guard);

        // `noisy` now floods: first request opens its own reservation (1
        // unit, drawn from the shared pool) and consumes it; every
        // subsequent request drains the shared pool directly. Never
        // completed, simulating many requests still in flight.
        let mut noisy_guards = Vec::new();
        for _ in 0..10 {
            if let Ok(g) = limiter.admit(noisy) {
                noisy_guards.push(g);
            }
        }
        // Shared pool (4) minus quiet's reservation (1) minus noisy's
        // reservation (1) leaves 2 shared units for noisy to drain -- so
        // noisy should have successfully admitted exactly 3 requests
        // (1 from its own reservation + 2 from the shared pool) before
        // running out of capacity entirely.
        assert_eq!(
            noisy_guards.len(),
            3,
            "noisy peer should exhaust its reservation plus all remaining shared capacity"
        );

        // Despite the flood having fully drained the shared pool, `quiet`
        // can still draw from its own untouched reservation.
        let quiet_guard2 = limiter.admit(quiet);
        assert!(
            quiet_guard2.is_ok(),
            "quiet peer's own reservation must survive another peer's flood, got {quiet_guard2:?}"
        );
        assert_eq!(limiter.erl.lock().unwrap().client_capacity_len(&quiet), 0);
    }

    /// A brand-new peer arriving while the shared pool is already fully
    /// claimed by other peers' reservations legitimately gets no capacity
    /// -- documented as an honest limitation inherited from the algorithm
    /// (a reservation can only be guaranteed for a peer the node has
    /// already heard from), not a wiring bug.
    #[test]
    fn brand_new_peer_can_be_denied_once_all_capacity_is_reserved() {
        let a = ip(10, 0, 1, 1);
        let b = ip(10, 0, 1, 2);
        let limiter = TxSyncPeerLimiter::new(2, 1, Duration::from_secs(10));

        let a_guard = limiter.admit(a).expect("first peer opens a reservation");
        limiter.complete(a_guard);
        let b_guard = limiter.admit(b).expect("second peer opens a reservation");
        limiter.complete(b_guard);

        // Both units of the 2-unit pool are now committed as reservations
        // (1 each); a third, never-seen peer cannot open one.
        let c = ip(10, 0, 1, 3);
        let res = limiter.admit(c);
        assert!(
            matches!(
                res,
                Err(ElasticRateLimiterError::InsufficientCapacity { .. })
            ),
            "expected InsufficientCapacity, got {res:?}"
        );
    }

    /// Pure threshold check backing the dynamic congestion-control
    /// hysteresis: fewer than `CONGESTION_THRESHOLD_PCT`% of `max_capacity`
    /// free counts as congested.
    #[test]
    fn shared_pool_congested_threshold() {
        assert!(!TxSyncPeerLimiter::shared_pool_congested(4, 4), "100% free");
        assert!(
            !TxSyncPeerLimiter::shared_pool_congested(2, 4),
            "50% free: not below threshold"
        );
        assert!(
            TxSyncPeerLimiter::shared_pool_congested(1, 4),
            "25% free: congested"
        );
        assert!(
            TxSyncPeerLimiter::shared_pool_congested(0, 4),
            "0% free: congested"
        );
    }

    /// A congestion manager that always recommends dropping -- mirrors
    /// `algo_pool::elastic_rate_limiter`'s own test-only
    /// `MockCongestionControl`, redeclared here since that one is private
    /// to its module.
    struct AlwaysDropCongestionManager;
    impl algo_pool::CongestionManager<IpAddr> for AlwaysDropCongestionManager {
        fn consumed(&mut self, _client: IpAddr, _t: std::time::Instant) {}
        fn served(&mut self, _t: std::time::Instant) {}
        fn should_drop(&mut self, _client: &IpAddr) -> bool {
            true
        }
    }

    /// End-to-end proof that `admit()` actually drives go's
    /// `TxHandler.incomingMsgErlCheck` hysteresis, not just computes the
    /// threshold: congestion control starts disabled, so a client is not
    /// gated by the (always-drop) mock while the pool has capacity; once a
    /// call observes the shared pool below the free-capacity threshold,
    /// congestion control is switched on as a side effect, and the very
    /// next request from any client is dropped by the mock without ever
    /// touching the (by-then-exhausted) shared pool.
    #[test]
    fn admit_auto_enables_congestion_control_once_shared_pool_crosses_threshold() {
        let peer = ip(10, 0, 2, 1);
        // capacity_per_peer = 0 so every consume draws straight from the
        // shared pool, keeping the utilization arithmetic simple.
        let limiter = TxSyncPeerLimiter::new(4, 0, Duration::from_secs(10));
        limiter
            .erl
            .lock()
            .unwrap()
            .set_congestion_manager(Some(Box::new(AlwaysDropCongestionManager)));

        // Drain 3/4 units. Each call's *pre*-call utilization is still at
        // or above the 50% threshold (100%, 75%, 50% free respectively),
        // so congestion control is never switched on for these, and the
        // mock (which isn't consulted while congestion control is off) is
        // never in the way.
        let _g1 = limiter.admit(peer).expect("1/4, pre-call 100% free");
        let _g2 = limiter.admit(peer).expect("2/4, pre-call 75% free");
        let _g3 = limiter.admit(peer).expect("3/4, pre-call 50% free");

        // 4th call: pre-call utilization is 25% free (congested). Congestion
        // control's *is_cm_enabled* snapshot is taken at the very top of
        // this same call (still `false`), so this call itself still draws
        // from the shared pool successfully; only *after* it succeeds does
        // the wrapper switch congestion control on for subsequent calls.
        let _g4 = limiter
            .admit(peer)
            .expect("4/4, still succeeds -- CM flips on only as a side effect of this call");

        // 5th call: congestion control is now enabled, so the mock's
        // always-drop verdict is consulted (and honored) *before* the
        // (already-empty) shared pool would have rejected it anyway.
        let g5 = limiter.admit(peer);
        assert!(
            matches!(g5, Err(ElasticRateLimiterError::CongestionDropped)),
            "expected CongestionDropped once congestion control auto-enabled, got {g5:?}"
        );
    }

    // ── TxSyncPeerLimiter: wired into the HTTP endpoint ─────────────────

    #[tokio::test]
    async fn http_endpoint_returns_503_once_peer_fairness_budget_is_exhausted() {
        let limiter = Arc::new(TxSyncPeerLimiter::new(1, 1, Duration::from_secs(10)));
        let addr = SocketAddr::new(ip(10, 1, 0, 1), 12345);

        // Externally exhaust this peer's own capacity via a request that
        // never completes -- simulating an in-flight request still being
        // serviced (e.g. this node's own servicing capacity is
        // saturated). With max_capacity == capacity_per_peer == 1, this
        // single reservation *is* the entire pool.
        let occupying_guard = limiter
            .admit(addr.ip())
            .expect("first request opens this peer's reservation");

        let service = TxSyncService::new(Arc::new(FakePool(vec![])), "g".to_string(), 1_000_000)
            .with_peer_limiter(limiter.clone());
        let router = service.http_router();
        let resp = post_from(
            router,
            "/v1/g/txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            bf_form_body(&empty_filter()),
            addr,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Once the occupying request completes and its capacity unit is
        // released back to this peer's own reservation, the peer's next
        // request succeeds.
        limiter.complete(occupying_guard);
        let service2 = TxSyncService::new(Arc::new(FakePool(vec![])), "g".to_string(), 1_000_000)
            .with_peer_limiter(limiter);
        let router2 = service2.http_router();
        let resp2 = post_from(
            router2,
            "/v1/g/txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            bf_form_body(&empty_filter()),
            addr,
        )
        .await;
        assert_eq!(resp2.status(), StatusCode::OK);
    }

    /// A malformed request (wrong content-type here) must never consume a
    /// peer's fairness budget -- the gate sits after validation, not
    /// before it.
    #[tokio::test]
    async fn http_endpoint_malformed_request_never_consumes_fairness_budget() {
        let limiter = Arc::new(TxSyncPeerLimiter::new(1, 1, Duration::from_secs(10)));
        let addr = SocketAddr::new(ip(10, 1, 1, 1), 1);
        let service = TxSyncService::new(Arc::new(FakePool(vec![])), "g".to_string(), 1_000_000)
            .with_peer_limiter(limiter.clone());
        let router = service.http_router();

        let resp = post_from(
            router,
            "/v1/g/txsync",
            "application/octet-stream", // wrong content-type -- 400, before the gate
            bf_form_body(&empty_filter()),
            addr,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // The peer's reservation is untouched -- a well-formed follow-up
        // request from the same peer still succeeds.
        let service2 = TxSyncService::new(Arc::new(FakePool(vec![])), "g".to_string(), 1_000_000)
            .with_peer_limiter(limiter);
        let router2 = service2.http_router();
        let resp2 = post_from(
            router2,
            "/v1/g/txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            bf_form_body(&empty_filter()),
            addr,
        )
        .await;
        assert_eq!(resp2.status(), StatusCode::OK);
    }

    /// Two distinct peers are serviced independently through the real HTTP
    /// path -- a busy peer occupying its own reservation does not block a
    /// second peer's request.
    #[tokio::test]
    async fn http_endpoint_isolates_distinct_peers() {
        let limiter = Arc::new(TxSyncPeerLimiter::new(4, 1, Duration::from_secs(10)));
        let peer_a_addr = SocketAddr::new(ip(10, 2, 0, 1), 1);
        let peer_b_addr = SocketAddr::new(ip(10, 2, 0, 2), 1);

        // peer A opens (and holds, unreleased) its own reservation.
        let _a_guard = limiter.admit(peer_a_addr.ip()).expect("peer A reserves");

        let service = TxSyncService::new(Arc::new(FakePool(vec![])), "g".to_string(), 1_000_000)
            .with_peer_limiter(limiter);
        let router = service.http_router();
        let resp = post_from(
            router,
            "/v1/g/txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            bf_form_body(&empty_filter()),
            peer_b_addr,
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "peer B must be serviced independently of peer A's outstanding reservation"
        );
    }
}
