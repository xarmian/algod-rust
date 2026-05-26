//! Tests for the `/v2/participation*` REST surface (TASK-241 / B9).
//! All five methods exercised against a `wiremock` mock server.

use algo_error::AlgoError;
use algo_rest_client::{AlgodClient, ClientConfig};
use base64::Engine;
use std::time::Duration;
use wiremock::matchers::{header, method, path, query_param};
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

fn sample_partkey_json() -> serde_json::Value {
    serde_json::json!({
        "id": "PARTID1",
        "address": "ADDR1",
        "effective-first-valid": 1000,
        "effective-last-valid": 2000,
        "last-vote": 1500,
        "key": {
            "selection-participation-key": base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
            "vote-participation-key": base64::engine::general_purpose::STANDARD.encode([2u8; 32]),
            "vote-first-valid": 1000,
            "vote-last-valid": 2000,
            "vote-key-dilution": 100,
        }
    })
}

#[tokio::test]
async fn list_participation_keys_returns_all() {
    use base64::Engine;
    let _ = base64::engine::general_purpose::STANDARD.encode([0u8; 1]);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/participation"))
        .and(header("X-Algo-API-Token", "test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            sample_partkey_json(),
            {
                "id": "PARTID2",
                "address": "ADDR2",
                "key": {
                    "selection-participation-key": base64::engine::general_purpose::STANDARD.encode([3u8; 32]),
                    "vote-participation-key": base64::engine::general_purpose::STANDARD.encode([4u8; 32]),
                    "vote-first-valid": 100,
                    "vote-last-valid": 200,
                    "vote-key-dilution": 50,
                },
            }
        ])))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let keys = client.list_participation_keys().await.expect("list");
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].id, "PARTID1");
    assert_eq!(keys[0].address, "ADDR1");
    assert_eq!(keys[0].effective_first_valid, Some(1000));
    assert_eq!(keys[0].last_vote, Some(1500));
    assert_eq!(keys[1].id, "PARTID2");
    assert_eq!(keys[1].key.vote_first_valid, 100);
    assert_eq!(keys[1].effective_first_valid, None);
}

#[tokio::test]
async fn list_participation_keys_handles_null_response_as_empty() {
    // Go's GetParticipationKeys appends to a nil slice, which
    // serializes as JSON `null` when no keys are installed. Codex
    // round-1: the prior Vec<ParticipationKey> deserializer failed
    // on that wire shape.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/participation"))
        .respond_with(ResponseTemplate::new(200).set_body_string("null"))
        .mount(&server)
        .await;
    let client = client_for(&server);
    let keys = client.list_participation_keys().await.expect("list");
    assert!(keys.is_empty(), "JSON null must deserialize as empty vec");
}

#[tokio::test]
async fn get_participation_key_returns_one() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/participation/PARTID1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_partkey_json()))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let key = client.get_participation_key("PARTID1").await.expect("get");
    assert_eq!(key.id, "PARTID1");
    assert_eq!(key.address, "ADDR1");
    assert_eq!(key.key.selection_participation_key.len(), 32);
    assert_eq!(key.key.vote_participation_key.len(), 32);
}

#[tokio::test]
async fn get_participation_key_404_surfaces_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/participation/MISSING"))
        .respond_with(ResponseTemplate::new(404).set_body_string("no such key"))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client
        .get_participation_key("MISSING")
        .await
        .expect_err("404 must error");
    assert!(matches!(err, AlgoError::NotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn add_participation_key_posts_msgpack_body_and_returns_partid() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/participation"))
        .and(header("Content-Type", "application/msgpack"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"partId": "NEW_PART_ID"})),
        )
        .mount(&server)
        .await;

    let client = client_for(&server);
    let added = client
        .add_participation_key(&[0xab, 0xcd])
        .await
        .expect("add");
    assert_eq!(added.part_id, "NEW_PART_ID");
}

#[tokio::test]
async fn delete_participation_key_204_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/v2/participation/PARTID1"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let client = client_for(&server);
    client
        .delete_participation_key("PARTID1")
        .await
        .expect("delete");
}

#[tokio::test]
async fn delete_participation_key_404_surfaces_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/v2/participation/X"))
        .respond_with(ResponseTemplate::new(404).set_body_string("missing"))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client
        .delete_participation_key("X")
        .await
        .expect_err("404 must error");
    assert!(matches!(err, AlgoError::NotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn generate_participation_keys_emits_query_params() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/participation/generate/SOMEADDR"))
        .and(query_param("first", "1000"))
        .and(query_param("last", "2000"))
        .and(query_param("dilution", "55"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let body = client
        .generate_participation_keys("SOMEADDR", 1000, 2000, Some(55))
        .await
        .expect("generate");
    assert_eq!(body, "{}");
}

#[tokio::test]
async fn generate_participation_keys_omits_dilution_when_none() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/participation/generate/SOMEADDR"))
        .and(query_param("first", "1"))
        .and(query_param("last", "9"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let body = client
        .generate_participation_keys("SOMEADDR", 1, 9, None)
        .await
        .expect("generate");
    assert_eq!(body, "{}");
}
