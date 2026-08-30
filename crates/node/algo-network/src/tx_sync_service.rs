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
//! protocol (issue #774).
//!
//! Mirrors the *role* of `go-algorand/rpcs/txService.go`
//! (`RegisterTxService`/`TxService.ServeHTTP`): a peer POSTs the txids it
//! already has pending, and this service answers with every locally-pending
//! transaction group that contains at least one txid the peer is missing.
//!
//! ## Deliberate wire-format deviation from go-algorand
//!
//! Go's real `TxService` negotiates a Bloom filter (`util/bloom`, keyed with
//! SipHash-2-4) base64-encoded into an `application/x-www-form-urlencoded`
//! body, at path `/v1/{genesisID}/txsync`. This service instead exchanges a
//! plain `Vec<Digest>` of pending txids (no Bloom filter, no false
//! positives) at a distinct path (`/{version}/{genesisID}/rust-txsync`) so
//! it can never be confused for go's endpoint by a real go-algorand peer
//! (which would 400 on our body shape, and vice versa — a safe, inert
//! mismatch rather than a silent wire incompatibility).
//!
//! This is a scoped simplification, not an oversight: the
//! [`crate::tx_syncer`] skeleton's own module doc already flagged the
//! Bloom-filter wire protocol as a deferred concern ("the wire format is an
//! implementation detail of the peer client"). Byte-for-byte interop with
//! real go-algorand relays on this specific endpoint is tracked as a
//! separate follow-up (see issue referenced in the PR that landed this
//! file) rather than being silently designed away.
//!
//! [`TxSyncer`]: crate::tx_syncer::TxSyncer

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use http::StatusCode;

use algo_codec::compute_txn_id;
use algo_types::{Digest, SignedTransaction};

/// Content-Type for the request body (a msgpack-encoded `Vec<Digest>`).
pub const TX_SYNC_REQUEST_CONTENT_TYPE: &str = "application/x-algod-rust-txsync-req";

/// Content-Type for the response body (a msgpack-encoded
/// `Vec<Vec<SignedTransaction>>`).
pub const TX_SYNC_RESPONSE_CONTENT_TYPE: &str = "application/x-algod-rust-txsync-resp";

/// Hard cap on the number of pending txids accepted in one request body,
/// independent of the byte-length cap enforced by [`MAX_REQUEST_BODY_BYTES`].
/// Defends against a request that packs an implausibly large id list into a
/// body that's still under the byte cap (each `Digest` is ~34 encoded bytes,
/// so this is already generous headroom over the byte cap below).
const MAX_REQUEST_PENDING_IDS: usize = 300_000;

/// Hard cap on the request body size read by the HTTP layer before this
/// handler ever sees it. Chosen generously above what
/// [`MAX_REQUEST_PENDING_IDS`] digests encode to, so the id-count cap is
/// what actually bites in practice; this is the last line of defense
/// against an unbounded read.
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
    /// the response stops early (matching go's `getFilteredTxns` break).
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
    /// Registers `POST /:version_seg/:genesis_id/rust-txsync`.
    pub fn http_router(&self) -> Router {
        let state = TxSyncServiceState {
            pool: Arc::clone(&self.pool),
            genesis_id: self.genesis_id.clone(),
            response_size_limit: self.response_size_limit,
        };

        Router::new()
            .route("/:version_seg/:genesis_id/rust-txsync", post(serve_tx_sync))
            .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
            .with_state(state)
    }
}

async fn serve_tx_sync(
    State(state): State<TxSyncServiceState>,
    Path((_version_seg, genesis_id)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    if genesis_id != state.genesis_id {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let requester_pending: Vec<Digest> = match rmp_serde::from_slice(&body) {
        Ok(ids) => ids,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if requester_pending.len() > MAX_REQUEST_PENDING_IDS {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let requester_pending: std::collections::HashSet<Digest> =
        requester_pending.into_iter().collect();

    let groups = state.pool.pending_tx_groups();
    let mut missing_groups: Vec<Vec<SignedTransaction>> = Vec::new();
    let mut encoded_len: usize = 0;

    for group in groups {
        let has_missing = group
            .iter()
            .any(|tx| !requester_pending.contains(&compute_txn_id(&tx.txn)));
        if !has_missing {
            continue;
        }

        let group_len: usize = group
            .iter()
            .map(|tx| rmp_serde::to_vec_named(tx).map(|b| b.len()).unwrap_or(0))
            .sum();
        if encoded_len.saturating_add(group_len) > state.response_size_limit
            && !missing_groups.is_empty()
        {
            // Matches go's `getFilteredTxns`: stop once the accumulated
            // size would exceed the cap, but only after at least one
            // group has been included (an empty response is worse than
            // one slightly-over-cap group when the pool holds nothing
            // smaller).
            break;
        }
        encoded_len += group_len;
        missing_groups.push(group);
    }

    match rmp_serde::to_vec_named(&missing_groups) {
        Ok(payload) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", TX_SYNC_RESPONSE_CONTENT_TYPE)
            .body(axum::body::Body::from(payload))
            .expect("well-formed response"),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
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
        stx.txn.fee = fee;
        stx
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
        // group containing `missing_id`.
        let req_body = rmp_serde::to_vec(&vec![have_id]).unwrap();
        let resp = post(
            router,
            "/v1/test-genesis/rust-txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            req_body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let groups: Vec<Vec<SignedTransaction>> = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(compute_txn_id(&groups[0][0].txn), missing_id);
    }

    #[tokio::test]
    async fn empty_pending_returns_every_group() {
        let a = make_txn(1);
        let b = make_txn(2);
        let service = TxSyncService::new(
            Arc::new(FakePool(vec![vec![a], vec![b]])),
            "g".to_string(),
            1_000_000,
        );
        let router = service.http_router();
        let req_body = rmp_serde::to_vec(&Vec::<Digest>::new()).unwrap();
        let resp = post(
            router,
            "/v1/g/rust-txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            req_body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let groups: Vec<Vec<SignedTransaction>> = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(groups.len(), 2);
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
        let req_body = rmp_serde::to_vec(&vec![id_a]).unwrap();
        let resp = post(
            router,
            "/v1/g/rust-txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            req_body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let groups: Vec<Vec<SignedTransaction>> = rmp_serde::from_slice(&bytes).unwrap();
        assert!(groups.is_empty());
    }

    #[tokio::test]
    async fn wrong_genesis_id_is_bad_request() {
        let service = TxSyncService::new(Arc::new(FakePool(vec![])), "g".to_string(), 1_000_000);
        let router = service.http_router();
        let req_body = rmp_serde::to_vec(&Vec::<Digest>::new()).unwrap();
        let resp = post(
            router,
            "/v1/other-genesis/rust-txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            req_body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn malformed_body_is_bad_request() {
        let service = TxSyncService::new(Arc::new(FakePool(vec![])), "g".to_string(), 1_000_000);
        let router = service.http_router();
        let resp = post(
            router,
            "/v1/g/rust-txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            vec![0xC1, 0xC1, 0xC1],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn response_size_limit_stops_after_first_group() {
        // Two large-ish groups; response_size_limit is tuned to fit only
        // the first group's encoded size.
        let a = make_txn(1);
        let b = make_txn(2);
        let a_len = rmp_serde::to_vec_named(&a).unwrap().len();
        let service = TxSyncService::new(
            Arc::new(FakePool(vec![vec![a.clone()], vec![b.clone()]])),
            "g".to_string(),
            a_len, // exactly fits one group, not two
        );
        let router = service.http_router();
        let req_body = rmp_serde::to_vec(&Vec::<Digest>::new()).unwrap();
        let resp = post(
            router,
            "/v1/g/rust-txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            req_body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let groups: Vec<Vec<SignedTransaction>> = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(groups.len(), 1, "response should stop after the cap is hit");
    }

    #[tokio::test]
    async fn too_many_pending_ids_is_bad_request() {
        let service = TxSyncService::new(Arc::new(FakePool(vec![])), "g".to_string(), 1_000_000);
        let router = service.http_router();
        let too_many: Vec<Digest> = (0..MAX_REQUEST_PENDING_IDS + 1)
            .map(|i| Digest([(i % 256) as u8; 32]))
            .collect();
        let req_body = rmp_serde::to_vec(&too_many).unwrap();
        let resp = post(
            router,
            "/v1/g/rust-txsync",
            TX_SYNC_REQUEST_CONTENT_TYPE,
            req_body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
