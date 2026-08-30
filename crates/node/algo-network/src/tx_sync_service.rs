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
//! [`TxSyncer`]: crate::tx_syncer::TxSyncer

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use http::{HeaderMap, StatusCode};

use algo_codec::{canonical_encode_signed_transaction, compute_txn_id};
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
}

#[derive(Clone)]
struct TxSyncServiceState {
    pool: Arc<dyn PendingTxGroupsSource>,
    genesis_id: String,
    response_size_limit: usize,
}

impl TxSyncService {
    /// Create a new tx-sync service.
    ///
    /// `response_size_limit` of `0` is treated as `1` — a zero-sized
    /// response cap would silently drop every response, which is never
    /// the intent of a misconfigured `TxSyncServeResponseSize: 0`.
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
        }
    }

    /// Build an [`axum::Router`] for the HTTP tx-sync endpoint.
    ///
    /// Registers `POST /v1/:genesis_id/txsync` — go's real path
    /// (`TxServiceHTTPPath`).
    pub fn http_router(&self) -> Router {
        let state = TxSyncServiceState {
            pool: Arc::clone(&self.pool),
            genesis_id: self.genesis_id.clone(),
            response_size_limit: self.response_size_limit,
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

    let payload = build_response_body(
        state.pool.pending_tx_groups(),
        &filter,
        state.response_size_limit,
    );

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

    async fn post(router: Router, path: &str, content_type: &str, body: Vec<u8>) -> Response {
        router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("Content-Type", content_type)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
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
}
