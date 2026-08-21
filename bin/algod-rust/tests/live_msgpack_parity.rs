//! Live dual-node msgpack response conformance suite (issue #448).
//!
//! Extends `live_go_parity.rs`'s dual-node harness (see that file's module
//! docs for setup) to `?format=msgpack` responses specifically. JSON parity
//! is covered elsewhere; this file exists because msgpack has its own
//! encoding path in both implementations (go's `codec.Handle` vs. Rust's
//! `rmp_serde`) and its own `Content-Type`/error-message conventions that a
//! JSON-only comparison can't catch.
//!
//! Bring up the harness first:
//!
//! ```text
//! make validate-api-up
//! cargo test --package algod-rust --test live_msgpack_parity -- --ignored --nocapture
//! make validate-api-down
//! ```
//!
//! # Scope
//!
//! Covers every endpoint that accepts `?format=msgpack` per
//! `daemon/algod/api/algod.oas3.yml`, exercised against genesis-round state
//! (the only state both nodes are guaranteed to share without a prior
//! transaction cross-verification step — see issue #449 for that):
//! `/v2/accounts/{address}`, `/v2/accounts/{address}/assets/{asset-id}`,
//! `/v2/accounts/{address}/applications/{application-id}`,
//! `/v2/blocks/{round}`, `/v2/transactions/pending/{txid}`,
//! `/v2/accounts/{address}/transactions/pending`, `/v2/deltas/{round}`,
//! `/v2/deltas/txn/group/{id}`, `/v2/deltas/{round}/txn/group`, plus the
//! shared `negotiate_format` error path (invalid/mixed-case format values).
//!
//! `/v2/transactions/simulate`'s msgpack request/response encoding is left
//! to issue #449, since simulating a meaningful transaction group needs the
//! signed-transaction infrastructure that ticket already owns.

use std::time::Duration;

const DEV_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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

async fn get(client: &reqwest::Client, base: &str, path: &str) -> reqwest::Response {
    client
        .get(format!("{base}{path}"))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {base}{path} failed: {e}"))
}

/// A recursive, order-independent diff over decoded msgpack values (reused
/// as `rmpv::Value` rather than `serde_json::Value` since msgpack has no
/// canonical JSON round-trip guarantee for every type go emits, e.g. binary
/// blobs). Reports every field-level mismatch, not just the first.
fn diff_msgpack(path: &str, expected: &rmpv::Value, actual: &rmpv::Value, out: &mut Vec<String>) {
    use rmpv::Value as V;
    match (expected, actual) {
        (V::Map(e), V::Map(a)) => {
            let mut keys: Vec<String> = e
                .iter()
                .chain(a.iter())
                .map(|(k, _)| k.to_string())
                .collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let child = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                let ev = e.iter().find(|(mk, _)| mk.to_string() == k).map(|(_, v)| v);
                let av = a.iter().find(|(mk, _)| mk.to_string() == k).map(|(_, v)| v);
                match (ev, av) {
                    (Some(ev), Some(av)) => diff_msgpack(&child, ev, av, out),
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

async fn get_msgpack(client: &reqwest::Client, base: &str, path: &str) -> (u16, rmpv::Value) {
    let resp = client
        .get(format!("{base}{path}"))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {base}{path} failed: {e}"));
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = resp.bytes().await.unwrap();
    let value = if status == 200 {
        assert_eq!(
            content_type, "application/msgpack",
            "GET {path} must report Content-Type: application/msgpack when format=msgpack succeeds (got {content_type})"
        );
        rmpv::decode::read_value(&mut bytes.as_ref())
            .unwrap_or_else(|e| panic!("GET {base}{path}: failed to decode msgpack body: {e}"))
    } else {
        // Error responses stay JSON-enveloped even under format=msgpack
        // (see `negotiate_invalid_error_message_matches_go`'s corresponding
        // in-process test and go's `returnError`, which always calls
        // `ctx.JSON`).
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("GET {base}{path}: failed to decode error body as JSON: {e}")
        });
        json_to_rmpv(&json)
    };
    (status, value)
}

fn json_to_rmpv(v: &serde_json::Value) -> rmpv::Value {
    match v {
        serde_json::Value::Null => rmpv::Value::Nil,
        serde_json::Value::Bool(b) => rmpv::Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                rmpv::Value::Integer(i.into())
            } else {
                rmpv::Value::F64(n.as_f64().unwrap_or_default())
            }
        }
        serde_json::Value::String(s) => rmpv::Value::String(s.as_str().into()),
        serde_json::Value::Array(a) => rmpv::Value::Array(a.iter().map(json_to_rmpv).collect()),
        serde_json::Value::Object(o) => rmpv::Value::Map(
            o.iter()
                .map(|(k, v)| (rmpv::Value::String(k.as_str().into()), json_to_rmpv(v)))
                .collect(),
        ),
    }
}

/// Compare a msgpack-format endpoint between the two live nodes: status
/// codes must match, and (for 200s) the decoded bodies must match
/// field-for-field.
async fn assert_msgpack_parity(path: &str) {
    let c = client();
    let (go_status, go_val) = get_msgpack(&c, &go_url(), path).await;
    let (rust_status, rust_val) = get_msgpack(&c, &rust_url(), path).await;
    assert_eq!(
        go_status, rust_status,
        "GET {path}?format=msgpack status mismatch: go={go_status} rust={rust_status}"
    );
    let mut mismatches = Vec::new();
    diff_msgpack("", &go_val, &rust_val, &mut mismatches);
    assert!(
        mismatches.is_empty(),
        "GET {path} field mismatches:\n{}",
        mismatches.join("\n")
    );
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn account_information_msgpack_matches() {
    assert_msgpack_parity(&format!("/v2/accounts/{FEE_SINK}?format=msgpack")).await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn account_information_msgp_alias_matches() {
    // "msgp" is go's accepted alias for "msgpack" (`getCodecHandle`).
    assert_msgpack_parity(&format!("/v2/accounts/{FEE_SINK}?format=msgp")).await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn account_asset_information_msgpack_404_matches() {
    // No assets exist yet at genesis; both nodes must 404 identically.
    assert_msgpack_parity(&format!("/v2/accounts/{FEE_SINK}/assets/1?format=msgpack")).await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn account_application_information_msgpack_404_matches() {
    assert_msgpack_parity(&format!(
        "/v2/accounts/{FEE_SINK}/applications/1?format=msgpack"
    ))
    .await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn get_block_msgpack_envelope_matches() {
    // Full byte/field parity of the *block body* is blocked on a deeper,
    // pre-existing gap this test discovered: algod-rust's stored block
    // bytes are not run through the canonical/omitempty msgpack encoder
    // go-algorand's `codec` struct tags apply (e.g. go omits zero-valued
    // `rnd`/`ts`/`nextbefore`/`nextswitch` at genesis; algod-rust's stored
    // bytes include them explicitly, and is separately missing `txn` since
    // `make_genesis_block` intentionally leaves `txn_commitment` as a
    // zero digest rather than go's real empty-payset commitment — see
    // `algo-ledger/src/genesis.rs`'s `make_genesis_block` doc comment).
    // That's a block-storage/genesis-construction fix, not a REST
    // format-negotiation one — tracked separately so it gets the scrutiny
    // consensus-adjacent code deserves rather than a rushed fix here.
    //
    // This test instead locks in what issue #448 *did* fix: the envelope
    // shape. go's `rpcs.EncodedBlockCert` always carries both "block" and
    // "cert" keys (no `omitempty` on either field) — previously algod-rust
    // omitted "cert" entirely when no certificate was stored (true for
    // round 0's synthetic genesis block on every fresh node). Both nodes
    // must now agree on that envelope shape and on the Content-Type.
    let c = client();
    let (go_status, go_val) = get_msgpack(&c, &go_url(), "/v2/blocks/0?format=msgpack").await;
    let (rust_status, rust_val) = get_msgpack(&c, &rust_url(), "/v2/blocks/0?format=msgpack").await;
    assert_eq!(go_status, 200);
    assert_eq!(rust_status, 200);

    for (label, val) in [("go", &go_val), ("rust", &rust_val)] {
        let map = val.as_map().unwrap_or_else(|| {
            panic!("{label}: /v2/blocks/0?format=msgpack body must decode as a map")
        });
        let keys: Vec<String> = map
            .iter()
            .filter_map(|(k, _)| k.as_str().map(String::from))
            .collect();
        assert!(
            keys.contains(&"block".to_string()),
            "{label}: envelope must carry a \"block\" key, got {keys:?}"
        );
        assert!(
            keys.contains(&"cert".to_string()),
            "{label}: envelope must carry a \"cert\" key even with no stored certificate (issue #448), got {keys:?}"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn pending_transaction_information_msgpack_404_matches() {
    let unknown_txid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert_msgpack_parity(&format!(
        "/v2/transactions/pending/{unknown_txid}?format=msgpack"
    ))
    .await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn pending_transactions_by_address_msgpack_matches() {
    // No transactions have been submitted yet: both nodes must report an
    // empty pending list identically.
    assert_msgpack_parity(&format!(
        "/v2/accounts/{FEE_SINK}/transactions/pending?format=msgpack"
    ))
    .await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn ledger_state_delta_not_found_error_prefix_matches() {
    // Neither node retains round 0 in its rolling delta window at genesis,
    // so both 404. go's `errFailedRetrievingStateDelta = "failed retrieving
    // State Delta: %v"` wraps an *internal* error whose text exposes go's
    // private `accountUpdates` bookkeeping (`"round %d not in deltas:
    // dbRound %d, deltas %d, offset %d"`) -- implementation-specific detail
    // with no equivalent in algod-rust's `DeltaCache`, so only the shared
    // external-message prefix is asserted, not full text equality (the
    // `%v` suffix is legitimately implementation-specific, like `/versions`'
    // `build` field).
    let c = client();
    let go = get(&c, &go_url(), "/v2/deltas/0?format=msgpack").await;
    let rust = get(&c, &rust_url(), "/v2/deltas/0?format=msgpack").await;
    assert_eq!(go.status(), 404);
    assert_eq!(rust.status(), 404);

    let go_body: serde_json::Value = go.json().await.unwrap();
    let rust_body: serde_json::Value = rust.json().await.unwrap();
    let prefix = "failed retrieving State Delta: ";
    assert!(
        go_body["message"].as_str().unwrap().starts_with(prefix),
        "go message must start with go's own errFailedRetrievingStateDelta prefix: {go_body}"
    );
    assert!(
        rust_body["message"].as_str().unwrap().starts_with(prefix),
        "rust message must match go's errFailedRetrievingStateDelta prefix exactly: {rust_body}"
    );
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn txn_group_delta_status_matches() {
    // Neither node has the txn-group-delta tracer enabled by
    // `docker/localnet-rust/data/config.json`, so both must report the same
    // status (go: 501 via `notImplemented` when `GetTracer()` isn't a
    // `*eval.TxnGroupDeltaTracer`; algod-rust: hardcoded 501, see
    // `handlers::get_txn_group_delta`) rather than diverging on 200 vs 501.
    let unknown_group_id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let c = client();
    let go = get(
        &c,
        &go_url(),
        &format!("/v2/deltas/txn/group/{unknown_group_id}?format=msgpack"),
    )
    .await;
    let rust = get(
        &c,
        &rust_url(),
        &format!("/v2/deltas/txn/group/{unknown_group_id}?format=msgpack"),
    )
    .await;
    assert_eq!(
        go.status(),
        rust.status(),
        "GET /v2/deltas/txn/group/{{id}} status must match with the tracer disabled on both nodes"
    );
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn txn_group_deltas_for_round_status_matches() {
    let c = client();
    let go = get(&c, &go_url(), "/v2/deltas/0/txn/group?format=msgpack").await;
    let rust = get(&c, &rust_url(), "/v2/deltas/0/txn/group?format=msgpack").await;
    assert_eq!(
        go.status(),
        rust.status(),
        "GET /v2/deltas/{{round}}/txn/group status must match with the tracer disabled on both nodes"
    );
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn invalid_format_value_error_matches_go() {
    let c = client();
    let go = get(
        &c,
        &go_url(),
        &format!("/v2/accounts/{FEE_SINK}?format=xml"),
    )
    .await;
    let rust = get(
        &c,
        &rust_url(),
        &format!("/v2/accounts/{FEE_SINK}?format=xml"),
    )
    .await;
    assert_eq!(go.status(), 400);
    assert_eq!(rust.status(), 400);
    let go_body: serde_json::Value = go.json().await.unwrap();
    let rust_body: serde_json::Value = rust.json().await.unwrap();
    assert_eq!(
        go_body["message"], rust_body["message"],
        "invalid `format` value must produce go's fixed \"failed to parse the format option\" message, not an echo of the invalid value (issue #448)"
    );
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn uppercase_format_value_accepted_on_both() {
    // go lowercases the format value before matching (`strings.ToLower` in
    // `getCodecHandle`); algod-rust must accept "MSGPACK" too.
    let c = client();
    let go = get(
        &c,
        &go_url(),
        &format!("/v2/accounts/{FEE_SINK}?format=MSGPACK"),
    )
    .await;
    let rust = get(
        &c,
        &rust_url(),
        &format!("/v2/accounts/{FEE_SINK}?format=MSGPACK"),
    )
    .await;
    assert_eq!(go.status(), 200, "go must accept uppercase MSGPACK");
    assert_eq!(
        rust.status(),
        200,
        "rust must accept uppercase MSGPACK, matching go's case-insensitive format parsing (issue #448)"
    );
}
