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

//! Unit tests for the transaction-submission, pending-lookup, and
//! suggested-params endpoints on `AlgodClient` (TASK-198).
//!
//! These tests run against a `wiremock` mock server in-process; they do
//! NOT require a live algod or docker. End-to-end coverage against a real
//! `algod-go` localnet lands in TASK-184's harness.

use algo_error::AlgoError;
use algo_rest_client::{AlgodClient, ClientConfig, PendingTxnInfo, TxId};
use std::time::Duration;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Build a client with retries disabled so tests don't waste seconds on
/// transient-error paths.
fn client_for(server: &MockServer) -> AlgodClient {
    let cfg = ClientConfig {
        timeout: Duration::from_secs(5),
        long_poll_timeout: Duration::from_secs(5),
        max_retries: 0,
        initial_backoff: Duration::from_millis(1),
    };
    AlgodClient::with_config(server.uri(), "test-token", cfg)
}

// ---------- send_raw_transaction ---------------------------------------------

#[tokio::test]
async fn send_raw_transaction_happy_path_returns_txid() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v2/transactions"))
        .and(header("X-Algo-API-Token", "test-token"))
        .and(header("Content-Type", "application/x-binary"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"txId": "ABCDEFG123456"})),
        )
        .mount(&server)
        .await;

    let client = client_for(&server);
    let txid = client
        .send_raw_transaction(&[0xde, 0xad, 0xbe, 0xef])
        .await
        .expect("submission should succeed");

    assert_eq!(txid.as_str(), "ABCDEFG123456");
}

#[tokio::test]
async fn send_raw_transaction_400_returns_conformance_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v2/transactions"))
        .respond_with(ResponseTemplate::new(400).set_body_string("transaction validation failed"))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client
        .send_raw_transaction(&[0; 4])
        .await
        .expect_err("400 should be an error");

    match err {
        AlgoError::Conformance { message } => {
            assert!(
                message.contains("400") && message.contains("transaction validation failed"),
                "unexpected message: {message}"
            );
        }
        other => panic!("expected Conformance error, got {other:?}"),
    }
}

#[tokio::test]
async fn send_raw_transaction_malformed_json_returns_rest_client_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v2/transactions"))
        .respond_with(ResponseTemplate::new(200).set_body_string("this is not json"))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client
        .send_raw_transaction(&[0; 4])
        .await
        .expect_err("malformed body should be an error");

    matches!(err, AlgoError::RestClient { .. })
        .then_some(())
        .unwrap_or_else(|| panic!("expected RestClient error, got {err:?}"));
}

// ---------- get_pending_transaction ------------------------------------------

#[tokio::test]
async fn get_pending_transaction_pending_state() {
    let server = MockServer::start().await;
    let txid = "PENDINGTXID";

    Mock::given(method("GET"))
        .and(path(format!("/v2/transactions/pending/{txid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "pool-error": "",
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let info = client
        .get_pending_transaction(&TxId(txid.into()))
        .await
        .expect("pending lookup should succeed");

    assert_eq!(info.confirmed_round, None);
    assert_eq!(info.pool_error, "");
    assert!(!info.is_committed());
    assert!(!info.is_rejected());
}

#[tokio::test]
async fn get_pending_transaction_committed_state() {
    let server = MockServer::start().await;
    let txid = "COMMITTEDTXID";

    Mock::given(method("GET"))
        .and(path(format!("/v2/transactions/pending/{txid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "confirmed-round": 4242_u64,
            "pool-error": "",
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let info: PendingTxnInfo = client
        .get_pending_transaction(&TxId(txid.into()))
        .await
        .expect("committed lookup should succeed");

    assert_eq!(info.confirmed_round, Some(4242));
    assert!(info.is_committed());
    assert!(!info.is_rejected());
}

#[tokio::test]
async fn get_pending_transaction_rejected_state() {
    let server = MockServer::start().await;
    let txid = "REJECTEDTXID";

    Mock::given(method("GET"))
        .and(path(format!("/v2/transactions/pending/{txid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "pool-error": "TransactionPool.Remember: txn dead",
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let info = client
        .get_pending_transaction(&TxId(txid.into()))
        .await
        .expect("rejected lookup should still return a body");

    assert_eq!(info.confirmed_round, None);
    assert!(info.is_rejected());
    assert!(info.pool_error.contains("txn dead"));
}

#[tokio::test]
async fn get_pending_transaction_unknown_txid_returns_not_found() {
    let server = MockServer::start().await;
    let txid = "UNKNOWNTXID";

    Mock::given(method("GET"))
        .and(path(format!("/v2/transactions/pending/{txid}")))
        .respond_with(ResponseTemplate::new(404).set_body_string("transaction not found"))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client
        .get_pending_transaction(&TxId(txid.into()))
        .await
        .expect_err("404 should be an error");

    match err {
        AlgoError::NotFound(msg) => {
            assert!(
                msg.contains(txid),
                "NotFound message should mention the txid, got: {msg}"
            );
        }
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn get_pending_transaction_malformed_json_returns_rest_client_error() {
    let server = MockServer::start().await;
    let txid = "MALFORMEDTXID";

    Mock::given(method("GET"))
        .and(path(format!("/v2/transactions/pending/{txid}")))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>not json</html>"))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client
        .get_pending_transaction(&TxId(txid.into()))
        .await
        .expect_err("malformed body should be an error");

    matches!(err, AlgoError::RestClient { .. })
        .then_some(())
        .unwrap_or_else(|| panic!("expected RestClient error, got {err:?}"));
}

// ---------- suggested_transaction_params -------------------------------------

#[tokio::test]
async fn suggested_transaction_params_decodes_genesis_hash() {
    let server = MockServer::start().await;

    // Standard base64 of 32 known bytes — easy to validate after decode.
    let hash_bytes = [0xab_u8; 32];
    let hash_b64 = "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s="; // STANDARD base64 of 32 × 0xab

    Mock::given(method("GET"))
        .and(path("/v2/transactions/params"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "consensus-version": "https://github.com/algorandfoundation/specs/tree/abc",
            "fee": 0_u64,
            "genesis-hash": hash_b64,
            "genesis-id": "devnet-v1",
            "last-round": 12345_u64,
            "min-fee": 1000_u64,
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let params = client
        .suggested_transaction_params()
        .await
        .expect("params fetch should succeed");

    assert_eq!(
        params.consensus_version,
        "https://github.com/algorandfoundation/specs/tree/abc"
    );
    assert_eq!(params.fee, 0);
    assert_eq!(params.genesis_hash.0, hash_bytes);
    assert_eq!(params.genesis_id, "devnet-v1");
    assert_eq!(params.last_round, 12345);
    assert_eq!(params.min_fee, 1000);
}

#[tokio::test]
async fn suggested_transaction_params_rejects_wrong_length_hash() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v2/transactions/params"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "consensus-version": "v",
            "fee": 0_u64,
            // 4-byte hash — should fail length check in the serde adapter.
            "genesis-hash": "AAECAw==",
            "genesis-id": "devnet-v1",
            "last-round": 1_u64,
            "min-fee": 1000_u64,
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client
        .suggested_transaction_params()
        .await
        .expect_err("short genesis-hash should fail decode");

    matches!(err, AlgoError::RestClient { .. })
        .then_some(())
        .unwrap_or_else(|| panic!("expected RestClient error, got {err:?}"));
}
