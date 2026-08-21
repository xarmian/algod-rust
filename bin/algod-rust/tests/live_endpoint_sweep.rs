//! Live dual-node full-endpoint-sweep conformance suite (issue #447).
//!
//! Extends `live_go_parity.rs`'s dual-node harness (see that file's module
//! docs for setup) to every v2/common endpoint that isn't already covered
//! by `live_go_parity.rs` (core status/genesis/supply), `live_msgpack_parity.rs`
//! (format=msgpack), `live_auth_parity.rs` (auth tiers), `live_headers_parity.rs`
//! (headers), or `live_txn_cross_verification.rs`/`live_longpoll_parity.rs`
//! (transaction submission, long-poll). At genesis (round 0, no
//! transactions/apps/assets/boxes yet), every endpoint here is exercised
//! at its not-found/empty-state path — the happy path for state-dependent
//! endpoints (a real app, asset, or box) is covered transitively by the
//! txn-cross-verification suite's create+call/create+transfer tests, which
//! already assert on `/v2/accounts/{address}` sub-resources after creation.
//!
//! Bring up the harness first:
//!
//! ```text
//! make validate-api-up
//! cargo test --package algod-rust --test live_endpoint_sweep -- --ignored --nocapture
//! make validate-api-down
//! ```

use std::time::Duration;

/// The public API token (`docker/localnet-rust/data/algod.token`).
const DEV_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The validate-api-scoped distinct admin token (issue #458).
const ADMIN_TOKEN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// The funded dev account's fee sink, guaranteed to exist at genesis on
/// both nodes (see `docs/DEV_WORKFLOW.md`).
const FEE_SINK: &str = "AOVDCP4FEMVDRM6XDX6ERJDHLY6TDW42MRKCVLX2PAZZQZICS7M2EZWWAU";

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

async fn get(client: &reqwest::Client, base: &str, path: &str, token: &str) -> reqwest::Response {
    client
        .get(format!("{base}{path}"))
        .header("X-Algo-API-Token", token)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {base}{path} failed: {e}"))
}

/// A recursive, order-independent JSON diff, reporting every field-level
/// mismatch (not just the first). Same shape as `live_go_parity.rs`'s.
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

/// Compare a JSON-returning endpoint between the two live nodes: status
/// codes must match, and (for 200s) the decoded bodies must match
/// field-for-field.
async fn assert_json_parity(path: &str, token: &str) {
    let c = client();
    let go_resp = get(&c, &go_url(), path, token).await;
    let rust_resp = get(&c, &rust_url(), path, token).await;
    let go_status = go_resp.status().as_u16();
    let rust_status = rust_resp.status().as_u16();
    assert_eq!(
        go_status, rust_status,
        "GET {path} status mismatch: go={go_status} rust={rust_status}"
    );
    if go_status == 200 {
        let go_body: serde_json::Value = go_resp.json().await.unwrap();
        let rust_body: serde_json::Value = rust_resp.json().await.unwrap();
        let mut mismatches = Vec::new();
        diff_json("", &go_body, &rust_body, &mut mismatches);
        assert!(
            mismatches.is_empty(),
            "GET {path} field mismatches:\n{}",
            mismatches.join("\n")
        );
    }
}

/// Compare only the status code of an endpoint between the two live
/// nodes — used where the body is opaque (binary, HTML, huge) or where
/// full content parity is covered elsewhere.
async fn assert_status_parity(path: &str, token: &str) {
    let c = client();
    let go_status = get(&c, &go_url(), path, token).await.status();
    let rust_status = get(&c, &rust_url(), path, token).await.status();
    assert_eq!(
        go_status, rust_status,
        "GET {path} status mismatch: go={go_status} rust={rust_status}"
    );
}

// ---------------------------------------------------------------------------
// Accounts sub-resources
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn account_assets_list_and_experimental_disabled_on_both() {
    // `docker/localnet-rust/data/config.json` doesn't set
    // `EnableExperimentalAPI`, so both `/v2/experimental` and the
    // experimental-gated `/v2/accounts/{address}/assets` list must be
    // consistently disabled (or consistently enabled) on both nodes.
    assert_status_parity("/v2/experimental", DEV_TOKEN).await;
    assert_status_parity(&format!("/v2/accounts/{FEE_SINK}/assets"), DEV_TOKEN).await;
}

// ---------------------------------------------------------------------------
// Applications / assets
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn application_by_id_404_matches() {
    assert_json_parity("/v2/applications/1", DEV_TOKEN).await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn application_box_by_name_404_matches() {
    // go requires a `name=` query param (base64-encoded key); use a
    // trivial one-byte key, "b64:AA==".
    assert_json_parity("/v2/applications/1/box?name=b64:AA==", DEV_TOKEN).await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn application_boxes_404_matches() {
    assert_json_parity("/v2/applications/1/boxes", DEV_TOKEN).await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn asset_by_id_404_matches() {
    assert_json_parity("/v2/assets/1", DEV_TOKEN).await;
}

// ---------------------------------------------------------------------------
// Blocks sub-resources
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn block_hash_matches_field_for_field() {
    assert_json_parity("/v2/blocks/0/hash", DEV_TOKEN).await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn block_txids_empty_matches() {
    assert_json_parity("/v2/blocks/0/txids", DEV_TOKEN).await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn block_logs_empty_matches() {
    assert_json_parity("/v2/blocks/0/logs", DEV_TOKEN).await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn block_lightheader_proof_status_matches() {
    // Genesis has no state-proof-covered light header commitment yet on
    // either node; only status parity is asserted since the error body's
    // internal detail is implementation-specific.
    assert_status_parity("/v2/blocks/0/lightheader/proof", DEV_TOKEN).await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn block_transaction_proof_404_matches() {
    let unknown_txid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert_json_parity(
        &format!("/v2/blocks/0/transactions/{unknown_txid}/proof"),
        DEV_TOKEN,
    )
    .await;
}

// ---------------------------------------------------------------------------
// TEAL compile / disassemble / dryrun
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn teal_compile_matches() {
    let c = client();
    let source = "#pragma version 8\nint 1\n";
    let go = c
        .post(format!("{}/v2/teal/compile", go_url()))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .body(source)
        .send()
        .await
        .unwrap();
    let rust = c
        .post(format!("{}/v2/teal/compile", rust_url()))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .body(source)
        .send()
        .await
        .unwrap();
    assert_eq!(go.status(), 200, "go teal/compile status");
    assert_eq!(rust.status(), 200, "rust teal/compile status");
    let go_body: serde_json::Value = go.json().await.unwrap();
    let rust_body: serde_json::Value = rust.json().await.unwrap();
    let mut mismatches = Vec::new();
    diff_json("", &go_body, &rust_body, &mut mismatches);
    assert!(
        mismatches.is_empty(),
        "POST /v2/teal/compile field mismatches:\n{}",
        mismatches.join("\n")
    );
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn teal_disassemble_matches() {
    let c = client();
    // `#pragma version 8` + `int 1` + `return`, precompiled bytes.
    let program: &[u8] = &[0x08, 0x81, 0x01, 0x43];
    let go = c
        .post(format!("{}/v2/teal/disassemble", go_url()))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .body(program)
        .send()
        .await
        .unwrap();
    let rust = c
        .post(format!("{}/v2/teal/disassemble", rust_url()))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .body(program)
        .send()
        .await
        .unwrap();
    assert_eq!(go.status(), 200, "go teal/disassemble status");
    assert_eq!(rust.status(), 200, "rust teal/disassemble status");
    let go_body: serde_json::Value = go.json().await.unwrap();
    let rust_body: serde_json::Value = rust.json().await.unwrap();
    let mut mismatches = Vec::new();
    diff_json("", &go_body, &rust_body, &mut mismatches);
    assert!(
        mismatches.is_empty(),
        "POST /v2/teal/disassemble field mismatches:\n{}",
        mismatches.join("\n")
    );
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn teal_dryrun_malformed_body_status_matches() {
    let c = client();
    let go = c
        .post(format!("{}/v2/teal/dryrun", go_url()))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .header("Content-Type", "application/msgpack")
        .body(vec![0xff, 0x00])
        .send()
        .await
        .unwrap();
    let rust = c
        .post(format!("{}/v2/teal/dryrun", rust_url()))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .header("Content-Type", "application/msgpack")
        .body(vec![0xff, 0x00])
        .send()
        .await
        .unwrap();
    assert_eq!(
        go.status(),
        rust.status(),
        "POST /v2/teal/dryrun with a malformed body must 400 identically"
    );
}

// ---------------------------------------------------------------------------
// Transactions: simulate / async
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn transactions_simulate_malformed_body_status_matches() {
    let c = client();
    let go = c
        .post(format!("{}/v2/transactions/simulate", go_url()))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .header("Content-Type", "application/msgpack")
        .body(vec![0xff, 0x00])
        .send()
        .await
        .unwrap();
    let rust = c
        .post(format!("{}/v2/transactions/simulate", rust_url()))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .header("Content-Type", "application/msgpack")
        .body(vec![0xff, 0x00])
        .send()
        .await
        .unwrap();
    assert_eq!(
        go.status(),
        rust.status(),
        "POST /v2/transactions/simulate with a malformed body must 400 identically"
    );
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn transactions_async_malformed_body_status_matches() {
    let c = client();
    let go = c
        .post(format!("{}/v2/transactions/async", go_url()))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .header("Content-Type", "application/x-binary")
        .body(vec![0xff, 0x00])
        .send()
        .await
        .unwrap();
    let rust = c
        .post(format!("{}/v2/transactions/async", rust_url()))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .header("Content-Type", "application/x-binary")
        .body(vec![0xff, 0x00])
        .send()
        .await
        .unwrap();
    assert_eq!(
        go.status(),
        rust.status(),
        "POST /v2/transactions/async with a malformed body must reject identically"
    );
}

// ---------------------------------------------------------------------------
// Devmode / state proofs
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn devmode_blocks_offset_get_matches() {
    assert_json_parity("/v2/devmode/blocks/offset", DEV_TOKEN).await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn stateproofs_404_matches() {
    assert_json_parity("/v2/stateproofs/1", DEV_TOKEN).await;
}

// ---------------------------------------------------------------------------
// Admin-tier: participation, debug settings
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn participation_list_matches() {
    assert_json_parity("/v2/participation", ADMIN_TOKEN).await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn participation_by_unknown_id_matches() {
    // A syntactically plausible but nonexistent participation id. Despite
    // the function name, go's real response here is 500, not 404: `node/
    // node.go`'s `GetParticipationKey` always returns
    // `account.ErrParticipationIDNotFound` as an *error* for an unknown
    // ID, which `handlers.go`'s `GetParticipationKeyByID` maps through its
    // generic `err != nil -> internalError` branch (its dedicated 404
    // branch, for a zero-value record with *no* error, is dead code this
    // node impl never takes). Confirmed live -- see the matching fix in
    // `crates/node/algo-rest-api/src/handlers.rs::get_participation_key_by_id`.
    let bogus_id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert_json_parity(&format!("/v2/participation/{bogus_id}"), ADMIN_TOKEN).await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn debug_settings_config_matches() {
    assert_status_parity("/debug/settings/config", ADMIN_TOKEN).await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn debug_settings_pprof_status_matches() {
    // Opaque runtime pprof settings payload -- status parity only.
    assert_status_parity("/debug/settings/pprof", ADMIN_TOKEN).await;
}

// ---------------------------------------------------------------------------
// Misc public endpoints
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn ready_and_health_and_swagger_status_matches() {
    for path in ["/ready", "/health", "/swagger.json"] {
        assert_status_parity(path, DEV_TOKEN).await;
    }
}
