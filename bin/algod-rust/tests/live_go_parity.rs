//! Live dual-node REST conformance suite (issue #129).
//!
//! Drives a *real* go-algorand v4.5.1-stable node and a real algod-rust node
//! — both booted from the identical genesis.json via
//! `docker/docker-compose.validate-api.yml` (see that file's header comment
//! for why a shared genesis makes state-dependent comparison meaningful,
//! not just structural) — with identical HTTP requests, and diffs the
//! responses. This encodes the manual verification performed while fixing
//! issues #129/#206/#213/#215/#191: JSON error envelope, auth-tier fallback
//! routing, CORS, gzip compression, the JSON trailing-newline convention,
//! and genesis-status handling for the fee sink/rewards pool.
//!
//! Every test is `#[ignore]` by default since it requires the dual-node
//! harness to already be running. Bring it up first:
//!
//! ```text
//! make validate-api-up
//! cargo test --package algod-rust --test live_go_parity -- --ignored --nocapture
//! make validate-api-down
//! ```
//!
//! or in one step:
//!
//! ```text
//! make validate-api
//! ```
//!
//! Base URLs default to the ports `docker-compose.validate-api.yml` publishes
//! (`http://127.0.0.1:4001` for go, `:4002` for algod-rust) and can be
//! overridden via the `ALGOD_GO_URL` / `ALGOD_RUST_URL` env vars.
//!
//! # Scope
//!
//! This is a representative, not exhaustive, slice of go-algorand's ~54 v2
//! endpoints — the ones covered while chasing down real conformance bugs.
//! Extending it to the full endpoint surface, adding msgpack-format
//! comparison for every endpoint, live long-poll timing verification, and
//! transaction-submission cross-verification remain open follow-up work for
//! issue #129.

use std::time::Duration;

/// The fixed dev token both `docker-compose.validate-api.yml` services use
/// (matching `docker/localnet-rust/data/algod.token`).
const DEV_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn go_url() -> String {
    std::env::var("ALGOD_GO_URL").unwrap_or_else(|_| "http://127.0.0.1:4001".to_string())
}

fn rust_url() -> String {
    std::env::var("ALGOD_RUST_URL").unwrap_or_else(|_| "http://127.0.0.1:4002".to_string())
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build reqwest client")
}

async fn get(client: &reqwest::Client, base: &str, path: &str) -> reqwest::Response {
    client
        .get(format!("{base}{path}"))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {base}{path} failed: {e}"))
}

/// A recursive, order-independent JSON diff, reporting every field-level
/// mismatch (not just the first). Shared shape with
/// `crates/node/algo-rest-api/tests/rest_conformance.rs`'s offline harness.
fn diff_json(
    path: &str,
    expected: &serde_json::Value,
    actual: &serde_json::Value,
    out: &mut Vec<String>,
) {
    use serde_json::Value as V;
    match (expected, actual) {
        (V::Object(e), V::Object(a)) => {
            let mut keys: Vec<&String> = e.keys().chain(a.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let child = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                match (e.get(k), a.get(k)) {
                    (Some(ev), Some(av)) => diff_json(&child, ev, av, out),
                    (Some(ev), None) => out.push(format!("{child}: go={ev} rust=<missing>")),
                    (None, Some(av)) => out.push(format!("{child}: go=<missing> rust={av}")),
                    (None, None) => unreachable!(),
                }
            }
        }
        (e, a) if e != a => out.push(format!("{path}: go={e} rust={a}")),
        _ => {}
    }
}

/// Fields that are legitimately node-specific (build metadata, telemetry)
/// and never expected to match between two different implementations.
fn strip_implementation_specific_fields(
    mut v: serde_json::Value,
    paths: &[&str],
) -> serde_json::Value {
    for p in paths {
        let mut cur = &mut v;
        let parts: Vec<&str> = p.split('.').collect();
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                if let Some(obj) = cur.as_object_mut() {
                    obj.remove(*part);
                }
            } else if let Some(next) = cur.get_mut(*part) {
                cur = next;
            } else {
                break;
            }
        }
    }
    v
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn status_at_genesis_is_byte_identical() {
    let c = client();
    let go = get(&c, &go_url(), "/v2/status").await;
    let rust = get(&c, &rust_url(), "/v2/status").await;
    assert_eq!(go.status(), 200);
    assert_eq!(rust.status(), 200);

    let go_bytes = go.bytes().await.unwrap();
    let rust_bytes = rust.bytes().await.unwrap();
    assert_eq!(
        go_bytes.as_ref(),
        rust_bytes.as_ref(),
        "GET /v2/status must be byte-identical at round 0 with a shared genesis\ngo:   {}\nrust: {}",
        String::from_utf8_lossy(&go_bytes),
        String::from_utf8_lossy(&rust_bytes),
    );
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn genesis_endpoint_matches_field_for_field() {
    let c = client();
    let go: serde_json::Value = get(&c, &go_url(), "/genesis").await.json().await.unwrap();
    let rust: serde_json::Value = get(&c, &rust_url(), "/genesis").await.json().await.unwrap();

    let mut mismatches = Vec::new();
    diff_json("", &go, &rust, &mut mismatches);
    assert!(
        mismatches.is_empty(),
        "/genesis field mismatches:\n{}",
        mismatches.join("\n")
    );
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn ledger_supply_excludes_fee_sink() {
    let c = client();
    let go: serde_json::Value = get(&c, &go_url(), "/v2/ledger/supply")
        .await
        .json()
        .await
        .unwrap();
    let rust: serde_json::Value = get(&c, &rust_url(), "/v2/ledger/supply")
        .await
        .json()
        .await
        .unwrap();

    let mut mismatches = Vec::new();
    diff_json("", &go, &rust, &mut mismatches);
    assert!(
        mismatches.is_empty(),
        "/v2/ledger/supply field mismatches (fee sink must be excluded from total-money on both):\n{}",
        mismatches.join("\n")
    );
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn fee_sink_account_status_matches() {
    // The funded dev account genesis's fee sink (docs/DEV_WORKFLOW.md).
    const FEE_SINK: &str = "AOVDCP4FEMVDRM6XDX6ERJDHLY6TDW42MRKCVLX2PAZZQZICS7M2EZWWAU";
    let c = client();
    let go: serde_json::Value = get(&c, &go_url(), &format!("/v2/accounts/{FEE_SINK}"))
        .await
        .json()
        .await
        .unwrap();
    let rust: serde_json::Value = get(&c, &rust_url(), &format!("/v2/accounts/{FEE_SINK}"))
        .await
        .json()
        .await
        .unwrap();

    assert_eq!(go["status"], "Not Participating");
    assert_eq!(
        rust["status"], "Not Participating",
        "fee sink must report Not Participating regardless of the genesis file's onl:0 (issue #129)"
    );
    assert_eq!(go["amount"], rust["amount"]);
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn versions_match_except_build_metadata() {
    let c = client();
    let go: serde_json::Value = get(&c, &go_url(), "/versions").await.json().await.unwrap();
    let rust: serde_json::Value = get(&c, &rust_url(), "/versions")
        .await
        .json()
        .await
        .unwrap();

    // `build` (version numbers, commit hash, branch, channel) is legitimately
    // implementation-specific and never expected to match go's.
    let go = strip_implementation_specific_fields(go, &["build"]);
    let rust = strip_implementation_specific_fields(rust, &["build"]);

    let mut mismatches = Vec::new();
    diff_json("", &go, &rust, &mut mismatches);
    assert!(
        mismatches.is_empty(),
        "/versions field mismatches (excluding build metadata):\n{}",
        mismatches.join("\n")
    );
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn unmatched_route_matches_go_error_envelope() {
    let c = client();
    let go = c
        .get(format!("{}/v2/this-route-does-not-exist", go_url()))
        .send()
        .await
        .unwrap();
    let rust = c
        .get(format!("{}/v2/this-route-does-not-exist", rust_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(go.status(), 404);
    assert_eq!(
        rust.status(),
        404,
        "unmatched route must 404 without any auth token, matching go (issue #129)"
    );
    let go_body: serde_json::Value = go.json().await.unwrap();
    let rust_body: serde_json::Value = rust.json().await.unwrap();
    assert_eq!(go_body, rust_body);
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn cors_preflight_matches_go() {
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = c
            .request(reqwest::Method::OPTIONS, format!("{base}/v2/status"))
            .header("Origin", "https://example.com")
            .header("Access-Control-Request-Method", "GET")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204, "{label}: preflight must return 204");
        assert_eq!(
            resp.headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("*"),
            "{label}: must allow any origin"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn gzip_compression_matches_go() {
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = c
            .get(format!("{base}/v2/status"))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .header("Accept-Encoding", "gzip")
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.headers()
                .get("content-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("gzip"),
            "{label}: must compress when the client accepts gzip"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn json_responses_end_with_trailing_newline() {
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = get(&c, &base, "/v2/status").await;
        let bytes = resp.bytes().await.unwrap();
        assert_eq!(
            bytes.last(),
            Some(&b'\n'),
            "{label}: JSON response must end with a trailing newline (encoding/json's Encoder convention)"
        );
    }
}
