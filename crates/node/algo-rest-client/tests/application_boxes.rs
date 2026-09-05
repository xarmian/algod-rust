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

//! Tests for the `/v2/applications/{id}/box` and `/v2/applications/{id}/boxes`
//! REST surface (issue #962), exercised against a `wiremock` mock server —
//! same pattern as `tests/participation.rs`.

use algo_error::AlgoError;
use algo_rest_client::{AlgodClient, ClientConfig};
use base64::Engine;
use std::time::Duration;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client_for(server: &MockServer) -> AlgodClient {
    let cfg = ClientConfig {
        timeout: Duration::from_secs(5),
        long_poll_timeout: Duration::from_secs(5),
        max_retries: 0,
        initial_backoff: Duration::from_millis(1),
    };
    AlgodClient::with_config(server.uri(), "test-token", cfg)
}

#[tokio::test]
async fn get_application_box_by_name_decodes_base64_fields() {
    let server = MockServer::start().await;
    let name_b64 = base64::engine::general_purpose::STANDARD.encode(b"mybox");
    let value_b64 = base64::engine::general_purpose::STANDARD.encode(b"boxvalue");
    Mock::given(method("GET"))
        .and(path("/v2/applications/5/box"))
        .and(query_param("name", "str:mybox"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": name_b64,
            "round": 100,
            "value": value_b64,
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let resp = client
        .get_application_box_by_name(5, "str:mybox")
        .await
        .unwrap();
    assert_eq!(resp.name, b"mybox".to_vec());
    assert_eq!(resp.round, 100);
    assert_eq!(resp.value, b"boxvalue".to_vec());
}

#[tokio::test]
async fn get_application_box_by_name_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/applications/5/box"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "message": "box not found"
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client
        .get_application_box_by_name(5, "str:missing")
        .await
        .unwrap_err();
    assert!(matches!(err, AlgoError::NotFound(_)));
}

/// Confirms `str:` box names with special characters are percent-encoded
/// correctly and the base64 `value`/`next`/`prefix` forms (which contain
/// `+`, `/`, `=`) survive the round trip through the query string.
#[tokio::test]
async fn get_application_boxes_page_encodes_b64_prefix_and_next() {
    let server = MockServer::start().await;
    // A base64 form containing every character that needs escaping.
    let tricky = "b64:AQ+ID/BA==";
    Mock::given(method("GET"))
        .and(path("/v2/applications/9/boxes"))
        .and(query_param("limit", "10"))
        .and(query_param("next", tricky))
        .and(query_param("prefix", tricky))
        .and(query_param("include", "values"))
        .and(query_param("round", "42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "boxes": [
                {
                    "name": base64::engine::general_purpose::STANDARD.encode(b"box1"),
                    "value": base64::engine::general_purpose::STANDARD.encode(b"val1"),
                }
            ],
            "round": 42,
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let resp = client
        .get_application_boxes_page(9, 10, tricky, tricky, true, 42)
        .await
        .unwrap();
    assert_eq!(resp.boxes.len(), 1);
    assert_eq!(resp.boxes[0].name, b"box1".to_vec());
    assert_eq!(resp.boxes[0].value, Some(b"val1".to_vec()));
    assert_eq!(resp.round, Some(42));
    assert_eq!(resp.next_token, None);
}

#[tokio::test]
async fn get_application_boxes_page_omits_optional_params_when_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/applications/9/boxes"))
        .and(query_param("limit", "1000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "boxes": [],
            "next-token": "str:cursor",
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let resp = client
        .get_application_boxes_page(9, 1000, "", "", false, 0)
        .await
        .unwrap();
    assert!(resp.boxes.is_empty());
    assert_eq!(resp.next_token.as_deref(), Some("str:cursor"));
    assert_eq!(resp.round, None);
}
