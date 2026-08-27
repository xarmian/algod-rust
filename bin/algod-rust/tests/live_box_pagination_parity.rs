//! Live dual-node byte-for-byte parity check for the paginated box-list
//! endpoint (issue #551, follow-up to #536/PR #550).
//!
//! #536/PR #550 ported go-algorand v4.7.0-beta's cursor-based
//! pagination/prefix filtering for `GET /v2/applications/{id}/boxes`
//! (upstream PR #6558) into algod-rust, but its acceptance criterion for a
//! live dual-node byte-for-byte comparison rested on a static/source-level
//! diff against go-algorand's OAS spec and handlers, not an actual
//! side-by-side HTTP comparison against a running go-algorand node. This
//! file closes that gap: it deploys a real application on *each* of a real
//! go-algorand v4.7.3-stable node and a real algod-rust node, creates the
//! same set of boxes via real `box_put` app calls on both, and diffs the
//! `GET /v2/applications/{id}/boxes` JSON responses field-for-field for:
//! the legacy (unpaginated) call shape, a multi-page cursor walk with
//! `include=values`, and a `prefix`-filtered query.
//!
//! Since the two nodes run independent dev-mode chains (see
//! `live_txn_cross_verification.rs`'s module docs), "byte-for-byte" here
//! means *same input => same response shape* on each side: box names,
//! base64-encoded values, and the `next-token` cursor encoding (which is a
//! deterministic function of the raw box name bytes, not of round number)
//! must match exactly. Only the response's `round` field is legitimately
//! node-specific (each node has advanced through a different number of
//! rounds by the time this suite runs) and is stripped before comparing,
//! following this repo's `strip_implementation_specific_fields` convention
//! (see `live_go_parity.rs`).
//!
//! Extends `live_go_parity.rs`'s dual-node harness (see that file's module
//! docs for setup) and reuses `live_txn_cross_verification.rs`'s signed
//! transaction submission helpers.
//!
//! # Serialization requirement
//!
//! Like `live_txn_cross_verification.rs`, every test here mutates the dev
//! account's on-chain state (creates an app, funds it, creates boxes) on
//! both live nodes. Run with `--test-threads=1`:
//!
//! ```text
//! make validate-api-up
//! cargo test --package algod-rust --test live_box_pagination_parity \
//!   -- --ignored --nocapture --test-threads=1
//! make validate-api-down
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use algo_codec::{canonical_encode_transaction, compute_txn_id};
use algo_types::{BoxRef, Round, SignedTransaction, TxnType};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ed25519_dalek::Signer;
use serde_bytes::ByteBuf;

const DEV_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// `docs/DEV_WORKFLOW.md`'s funded dev account (25-word mnemonic).
const DEV_MNEMONIC: &str = "under this above produce during card issue fire gloom reopen topple rough cat smooth salad put broken decade vocal loud pulp gauge hurdle absorb olympic";

/// Approval program: on creation (or any call with fewer than 2 app args)
/// just approves; on a call with exactly 2 app args, writes
/// `box_put(args[0], args[1])`, then approves. Assembled once and reused
/// (identical bytes) for both nodes' app creation, matching this file's
/// "same input -> same observable behavior" comparison approach.
const APPROVAL_SOURCE: &str = r#"#pragma version 8
txn NumAppArgs
int 2
==
bz done
txna ApplicationArgs 0
txna ApplicationArgs 1
box_put
done:
int 1
return
"#;

/// Trivial approve-all clear-state program (version 8, `pushint 1`).
const CLEAR_STATE_PROGRAM: &[u8] = &[0x08, 0x81, 0x01];

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

fn unique_note(tag: &str) -> Vec<u8> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("live_box_pagination_parity:{tag}:{nanos}").into_bytes()
}

fn dev_signing_key() -> ed25519_dalek::SigningKey {
    let seed = algo_consensus_crypto::passphrase::mnemonic_to_key(DEV_MNEMONIC)
        .expect("dev mnemonic must decode to a valid key");
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

fn dev_address() -> algo_types::Address {
    algo_types::Address(dev_signing_key().verifying_key().to_bytes())
}

fn sign(txn: &mut algo_types::Transaction, sk: &ed25519_dalek::SigningKey) -> SignedTransaction {
    let mut msg = Vec::with_capacity(2 + 256);
    msg.extend_from_slice(b"TX");
    msg.extend_from_slice(&canonical_encode_transaction(txn));
    let sig = sk.sign(&msg).to_bytes();
    SignedTransaction {
        txn: std::mem::take(txn),
        sig,
        ..Default::default()
    }
}

fn encode(stx: &SignedTransaction) -> Vec<u8> {
    rmp_serde::to_vec_named(stx).expect("encode signed txn")
}

fn base64_decode(s: &str) -> Vec<u8> {
    BASE64_STANDARD.decode(s).expect("valid base64")
}

async fn base_txn(client: &reqwest::Client, base: &str) -> algo_types::Transaction {
    let params: serde_json::Value = client
        .get(format!("{base}/v2/transactions/params"))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let genesis_hash_b64 = params["genesis-hash"].as_str().unwrap();
    let genesis_hash_bytes = base64_decode(genesis_hash_b64);
    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&genesis_hash_bytes);
    let last_round = params["last-round"].as_u64().unwrap();
    let min_fee = params["min-fee"].as_u64().unwrap();

    algo_types::Transaction {
        sender: dev_address(),
        fee: min_fee.max(1000),
        first_valid: Round(last_round.max(1)),
        last_valid: Round(last_round + 1000),
        genesis_id: params["genesis-id"].as_str().unwrap().to_string(),
        genesis_hash,
        ..Default::default()
    }
}

struct SubmitResult {
    status: u16,
    body: Vec<u8>,
}

impl SubmitResult {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// POST a signed transaction, transparently retrying while go-algorand's
/// dev-mode node reports its transient just-booted pool error. Same
/// rationale as `live_txn_cross_verification.rs::submit`.
async fn submit(client: &reqwest::Client, base: &str, bytes: &[u8]) -> SubmitResult {
    const TRANSIENT_NOT_READY: &str = "no pending block evaluator";
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let resp = client
            .post(format!("{base}/v2/transactions"))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .header("Content-Type", "application/x-binary")
            .body(bytes.to_vec())
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let body = resp.bytes().await.unwrap().to_vec();
        if status == 400 && std::time::Instant::now() < deadline {
            let text = String::from_utf8_lossy(&body);
            if text.contains(TRANSIENT_NOT_READY) {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        }
        return SubmitResult { status, body };
    }
}

async fn get_json(client: &reqwest::Client, base: &str, path: &str) -> (u16, serde_json::Value) {
    let resp = client
        .get(format!("{base}{path}"))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, body)
}

async fn wait_for_confirmation(
    client: &reqwest::Client,
    base: &str,
    txid: &str,
    deadline: std::time::Instant,
) -> serde_json::Value {
    loop {
        let (status, body) =
            get_json(client, base, &format!("/v2/transactions/pending/{txid}")).await;
        if status == 200 && body["confirmed-round"].as_u64().unwrap_or(0) > 0 {
            return body;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "txid {txid} on {base} did not confirm before deadline (last status {status}, body {body})"
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn submit_and_confirm(
    client: &reqwest::Client,
    base: &str,
    label: &str,
    txn: &mut algo_types::Transaction,
    sk: &ed25519_dalek::SigningKey,
    what: &str,
) -> serde_json::Value {
    let txid = compute_txn_id(txn).to_string();
    let stx = sign(txn, sk);
    let bytes = encode(&stx);
    let resp = submit(client, base, &bytes).await;
    assert_eq!(
        resp.status,
        200,
        "{label}: {what} rejected: {}",
        resp.text()
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    wait_for_confirmation(client, base, &txid, deadline).await
}

/// A recursive, order-independent JSON diff. Same shape as
/// `live_go_parity.rs`'s.
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
        (V::Array(e), V::Array(a)) => {
            if e.len() != a.len() {
                out.push(format!(
                    "{path}: array length go={} rust={}",
                    e.len(),
                    a.len()
                ));
                return;
            }
            for (i, (ev, av)) in e.iter().zip(a.iter()).enumerate() {
                diff_json(&format!("{path}[{i}]"), ev, av, out);
            }
        }
        (e, a) if e != a => out.push(format!("{path}: go={e} rust={a}")),
        _ => {}
    }
}

/// Strip the given top-level fields (implementation-specific, e.g. the
/// per-node current round) before comparing. Same convention as
/// `live_go_parity.rs::strip_implementation_specific_fields`.
fn strip_fields(mut v: serde_json::Value, fields: &[&str]) -> serde_json::Value {
    if let Some(obj) = v.as_object_mut() {
        for f in fields {
            obj.remove(*f);
        }
    }
    v
}

/// Sort a `BoxesResponse`-shaped JSON value's `boxes` array by (base64)
/// name, so page contents can be compared independent of any incidental
/// ordering difference -- go-algorand's box iteration order is already
/// verified lexicographic by `handlers.go`/PR #550's static parity check,
/// but this keeps the *comparison* itself order-tolerant so it pins actual
/// content, not incidental key order.
fn sort_boxes_by_name(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(boxes) = v.get_mut("boxes").and_then(|b| b.as_array_mut()) {
        boxes.sort_by(|a, b| {
            a["name"]
                .as_str()
                .unwrap_or("")
                .cmp(b["name"].as_str().unwrap_or(""))
        });
    }
    v
}

/// The box names/values created on both nodes for this suite, sharing a
/// common prefix for the ones meant to be exercised by the `prefix` filter,
/// plus one deliberately-excluded box outside that prefix.
fn box_fixtures() -> Vec<(&'static str, &'static str)> {
    vec![
        ("pgbox-000", "v0"),
        ("pgbox-001", "v1"),
        ("pgbox-002", "v2"),
        ("pgbox-003", "v3"),
        ("pgbox-004", "v4"),
        ("zzz-excluded", "vX"),
    ]
}

const PREFIX: &str = "pgbox-";

/// Deploys the box-writing app on `base`, funds its account, creates every
/// fixture box, and returns the app id.
async fn deploy_and_populate(client: &reqwest::Client, base: &str, label: &str) -> u64 {
    let sk = dev_signing_key();
    let approval = algo_avm::assembler::assemble_string(APPROVAL_SOURCE)
        .unwrap_or_else(|e| panic!("{label}: approval program failed to assemble: {e:?}"))
        .program;

    // 1. Create the app.
    let mut create = base_txn(client, base).await;
    create.txn_type = TxnType::Appl;
    create.approval_program = Some(ByteBuf::from(approval));
    create.clear_state_program = Some(ByteBuf::from(CLEAR_STATE_PROGRAM.to_vec()));
    create.note = unique_note(&format!("app-create-{label}")).into();
    let confirmed = submit_and_confirm(client, base, label, &mut create, &sk, "app creation").await;
    let app_id = confirmed["application-index"].as_u64().unwrap_or_else(|| {
        panic!("{label}: confirmed app creation must report application-index: {confirmed}")
    });

    // 2. Fund the app account so it can cover box MBR (flat + per-byte
    //    cost for every fixture box's name+value bytes).
    let app_addr = algo_types::Address(algo_ledger::avm_context::app_address(app_id));
    let mut fund = base_txn(client, base).await;
    fund.txn_type = TxnType::Pay;
    fund.receiver = app_addr;
    fund.amount = 5_000_000;
    fund.note = unique_note(&format!("app-fund-{label}")).into();
    submit_and_confirm(client, base, label, &mut fund, &sk, "app funding").await;

    // 3. Create every fixture box via a NoOp call with 2 app args
    //    (name, value) and a box reference to that same name.
    for (name, value) in box_fixtures() {
        let mut call = base_txn(client, base).await;
        call.txn_type = TxnType::Appl;
        call.application_id = app_id;
        call.app_arguments = Some(vec![
            Some(ByteBuf::from(name.as_bytes().to_vec())),
            Some(ByteBuf::from(value.as_bytes().to_vec())),
        ]);
        call.boxes = Some(vec![BoxRef {
            index: 0,
            name: Some(ByteBuf::from(name.as_bytes().to_vec())),
        }]);
        call.note = unique_note(&format!("box-create-{label}-{name}")).into();
        submit_and_confirm(
            client,
            base,
            label,
            &mut call,
            &sk,
            &format!("box creation for {name}"),
        )
        .await;
    }

    app_id
}

// ---------------------------------------------------------------------------

/// Fast, always-run (not `#[ignore]`d) regression test: pins that
/// `APPROVAL_SOURCE` actually assembles. This is deliberately *not*
/// gated behind the dual-node harness -- a TEAL syntax mistake here (e.g.
/// using `txn` instead of `txna` for an array field, which this test
/// caught live in CI before this test existed) should fail fast in
/// default `cargo test --workspace`, not only when someone happens to run
/// the ignored live suite.
#[test]
fn approval_program_assembles() {
    let ops = algo_avm::assembler::assemble_string(APPROVAL_SOURCE)
        .expect("APPROVAL_SOURCE must assemble cleanly");
    assert!(
        !ops.program.is_empty(),
        "assembled program must not be empty"
    );
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn legacy_box_list_matches_after_creation() {
    let c = client();
    let mut go_body = serde_json::Value::Null;
    let mut rust_body = serde_json::Value::Null;

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let app_id = deploy_and_populate(&c, &base, label).await;
        let (status, body) = get_json(&c, &base, &format!("/v2/applications/{app_id}/boxes")).await;
        assert_eq!(status, 200, "{label}: GET .../boxes (legacy) status");
        let body = sort_boxes_by_name(body);
        if label == "go" {
            go_body = body;
        } else {
            rust_body = body;
        }
    }

    let mut mismatches = Vec::new();
    diff_json("", &go_body, &rust_body, &mut mismatches);
    assert!(
        mismatches.is_empty(),
        "legacy GET /v2/applications/{{id}}/boxes field mismatches:\n{}",
        mismatches.join("\n")
    );

    let boxes = go_body["boxes"].as_array().unwrap();
    assert_eq!(
        boxes.len(),
        box_fixtures().len(),
        "legacy call must return every created box"
    );
    for b in boxes {
        assert!(
            b.get("value").is_none(),
            "legacy call must never include box values: {b}"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn paginated_box_list_with_values_matches() {
    let c = client();
    let mut go_body = serde_json::Value::Null;
    let mut rust_body = serde_json::Value::Null;

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let app_id = deploy_and_populate(&c, &base, label).await;
        let (status, body) = get_json(
            &c,
            &base,
            &format!("/v2/applications/{app_id}/boxes?limit=10&include=values"),
        )
        .await;
        assert_eq!(status, 200, "{label}: GET .../boxes (paginated) status");
        // `round` is legitimately node-specific (each node has advanced a
        // different number of rounds by the time this test runs) -- strip
        // it before comparing, same convention as `versions_match_except_
        // build_metadata` strips `build`.
        let body = sort_boxes_by_name(strip_fields(body, &["round"]));
        if label == "go" {
            go_body = body;
        } else {
            rust_body = body;
        }
    }

    let mut mismatches = Vec::new();
    diff_json("", &go_body, &rust_body, &mut mismatches);
    assert!(
        mismatches.is_empty(),
        "paginated GET /v2/applications/{{id}}/boxes?limit=10&include=values field mismatches:\n{}",
        mismatches.join("\n")
    );

    let boxes = go_body["boxes"].as_array().unwrap();
    assert_eq!(
        boxes.len(),
        box_fixtures().len(),
        "single page (limit=10 > 6 boxes) must return every box"
    );
    assert!(
        go_body.get("next-token").is_none(),
        "no next-token expected once every box fits on one page: {go_body}"
    );
    for (name, value) in box_fixtures() {
        let want_name = BASE64_STANDARD.encode(name.as_bytes());
        let want_value = BASE64_STANDARD.encode(value.as_bytes());
        let found = boxes
            .iter()
            .find(|b| b["name"].as_str() == Some(want_name.as_str()))
            .unwrap_or_else(|| panic!("box {name} missing from paginated response: {boxes:?}"));
        assert_eq!(
            found["value"].as_str(),
            Some(want_value.as_str()),
            "box {name}'s value must round-trip through include=values"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn paginated_box_list_prefix_filter_and_cursor_walk_matches() {
    let c = client();
    let prefix_token = format!("b64:{}", BASE64_STANDARD.encode(PREFIX.as_bytes()));

    // (page bodies with `round` stripped, sorted within each page) per node.
    let mut pages_by_label: std::collections::HashMap<&str, Vec<serde_json::Value>> =
        std::collections::HashMap::new();

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let app_id = deploy_and_populate(&c, &base, label).await;

        let mut pages = Vec::new();
        let mut next: Option<String> = None;
        let mut seen_names = std::collections::HashSet::new();
        loop {
            let mut path = format!(
                "/v2/applications/{app_id}/boxes?limit=2&include=values&prefix={}",
                urlencoding_encode(&prefix_token)
            );
            if let Some(n) = &next {
                path.push_str(&format!("&next={}", urlencoding_encode(n)));
            }
            let (status, body) = get_json(&c, &base, &path).await;
            assert_eq!(
                status, 200,
                "{label}: GET .../boxes (prefix page) status: {body}"
            );

            let boxes = body["boxes"].as_array().cloned().unwrap_or_default();
            assert!(
                boxes.len() <= 2,
                "{label}: page must respect limit=2, got {}: {body}",
                boxes.len()
            );
            for b in &boxes {
                let name = b["name"].as_str().unwrap().to_string();
                assert!(
                    seen_names.insert(name.clone()),
                    "{label}: box {name} returned on more than one page (cursor exclusivity broken): {body}"
                );
            }

            let body = sort_boxes_by_name(strip_fields(body, &["round"]));
            let next_token = body
                .get("next-token")
                .and_then(|t| t.as_str())
                .map(str::to_string);
            pages.push(body);

            match next_token {
                Some(t) => next = Some(t),
                None => break,
            }
        }

        // Only the 5 "pgbox-" boxes must ever appear; "zzz-excluded" must
        // never surface under the prefix filter.
        assert_eq!(
            seen_names.len(),
            5,
            "{label}: prefix filter must yield exactly the 5 pgbox- boxes across all pages, got {seen_names:?}"
        );
        assert!(
            !seen_names.contains("zzz-excluded"),
            "{label}: prefix filter leaked a non-matching box name"
        );

        pages_by_label.insert(label, pages);
    }

    let go_pages = &pages_by_label["go"];
    let rust_pages = &pages_by_label["rust"];
    assert_eq!(
        go_pages.len(),
        rust_pages.len(),
        "go and rust must paginate the same 5-box, limit=2 prefix query into the same number of pages\ngo pages: {go_pages:?}\nrust pages: {rust_pages:?}"
    );
    for (i, (g, r)) in go_pages.iter().zip(rust_pages.iter()).enumerate() {
        let mut mismatches = Vec::new();
        diff_json(&format!("page[{i}]"), g, r, &mut mismatches);
        assert!(
            mismatches.is_empty(),
            "prefix-filtered page {i} field mismatches (including next-token cursor encoding):\n{}",
            mismatches.join("\n")
        );
    }
}

/// Minimal query-string percent-encoding for the handful of characters
/// that appear in a `b64:`-prefixed cursor/prefix token (`+`, `/`, `=`) --
/// avoids pulling in a full `urlencoding` crate dependency for three
/// characters.
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
