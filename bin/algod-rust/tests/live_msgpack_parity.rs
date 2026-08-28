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
//! cargo test --package algod-rust --test live_msgpack_parity -- --ignored --nocapture --test-threads=1
//! make validate-api-down
//! ```
//!
//! # Serialization requirement
//!
//! `get_produced_block_msgpack_matches` (issue #453) submits and confirms a
//! real transaction on each node to exercise the normal block-sealing path,
//! which permanently advances both nodes' round and the shared genesis fee
//! sink's collected-fees balance. Every other test in this file assumes
//! genesis-only (round 0) state. Run with `--test-threads=1` so the
//! state-mutating test fully completes (and both nodes converge on the same
//! post-fee balance) before any other test in this file observes state —
//! same pattern as `live_txn_cross_verification.rs`.
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
    // Full field-for-field parity of round 0 (genesis), now that issue #453
    // fixed both the envelope shape (issue #448: go's `rpcs.EncodedBlockCert`
    // always carries "block" and "cert", no `omitempty` on either) and the
    // underlying gap: stored block bytes now go through
    // `algo_codec::canonical_encode_block` (omitempty/canonical, matching
    // go's `codec` struct tags) instead of plain `rmp_serde::to_vec_named`,
    // and `make_genesis_block` sets `txn_commitment` to go's real empty-payset
    // commitment (`Payset{}.CommitGenesis()`) instead of a zero placeholder.
    assert_msgpack_parity("/v2/blocks/0?format=msgpack").await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn get_produced_block_msgpack_matches() {
    // Round 0 (genesis) is a special-cased, never-applied block on both
    // implementations (see issue #453's investigation: go's own
    // `MakeGenesisBlock` always uses the flat `CommitGenesis` commitment,
    // bypassing the merkle-payset path modern protocols otherwise use).
    // Verify the canonical-encoding fix also holds for a normally-sealed
    // block (round > 0, non-empty payset, going through the standard
    // `apply_block`/`put_block` path in `algo-ledger/src/apply.rs`), not
    // just the genesis special case.
    //
    // Both nodes must confirm the *identical* signed transaction bytes (not
    // just "a" payment each) so the payset content — and therefore every
    // payset-derived commitment field — is directly comparable, following
    // `live_txn_cross_verification.rs`'s cross-node identical-input pattern.
    // Each node still runs its own independent dev-mode chain, so the
    // confirmed round number itself can differ between them; only the block
    // *contents* at each node's own confirmed round are compared.
    let c = client();
    let (go_round, rust_round) = submit_identical_payment_and_get_confirmed_rounds(&c).await;

    let (go_status, go_val) = get_msgpack(
        &c,
        &go_url(),
        &format!("/v2/blocks/{go_round}?format=msgpack"),
    )
    .await;
    let (rust_status, rust_val) = get_msgpack(
        &c,
        &rust_url(),
        &format!("/v2/blocks/{rust_round}?format=msgpack"),
    )
    .await;
    assert_eq!(go_status, 200);
    assert_eq!(rust_status, 200);

    let mut mismatches = Vec::new();
    diff_msgpack("", &go_val, &rust_val, &mut mismatches);
    // "block"."rnd" legitimately differs: each node's own dev-mode chain
    // reaches this transaction at its own round number (see doc comment
    // above). "block"."bi" (proposer bonus payout) and "block"."spt" (state
    // proof tracking) used to be allowlisted here as unimplemented feature
    // gaps; issue #462 implemented both (`algo_ledger::block_header`'s
    // `next_bonus` / `next_state_proof_tracking`, ports of go's
    // `bookkeeping.NextBonus` and `eval.endOfBlock`), so they are now asserted.
    // TODO(#681): go-algorand v5.0.0-stable is the first pin in this repo's
    // history where ConsensusCurrentVersion itself advances past genesis
    // (V41 -> V42), so the pinned Go dev-mode node now casts a real default
    // upgrade proposal/vote from round 1. algod-rust's block-production path
    // deliberately never proposes/votes for protocol upgrades (see
    // `algo_ledger::block_header`'s module doc comment) and so never
    // populates these fields; remove this exclusion when #681 lands.
    let allowed_prefixes = [
        "\"block\".\"rnd\"",
        "\"block\".\"nextbefore\"",
        "\"block\".\"nextproto\"",
        "\"block\".\"nextswitch\"",
        "\"block\".\"nextyes\"",
        "\"block\".\"upgradedelay\"",
        "\"block\".\"upgradeprop\"",
        "\"block\".\"upgradeyes\"",
    ];
    mismatches.retain(|m| {
        !allowed_prefixes
            .iter()
            .any(|p| m.starts_with(&format!("{p}:")))
    });
    assert!(
        mismatches.is_empty(),
        "GET /v2/blocks/{{round}} field mismatches (go round {go_round}, rust round {rust_round}):\n{}",
        mismatches.join("\n")
    );
}

/// Signs one payment transaction and submits the *identical* signed bytes
/// to both nodes (so payset content, and every payset-derived commitment
/// field, is directly comparable — see [`get_produced_block_msgpack_matches`]),
/// waits for confirmation on each, and returns `(go_round, rust_round)`.
async fn submit_identical_payment_and_get_confirmed_rounds(client: &reqwest::Client) -> (u64, u64) {
    use algo_codec::{canonical_encode_transaction, compute_txn_id};
    use algo_types::{Round, SignedTransaction, TxnType};
    use ed25519_dalek::Signer;

    const DEV_MNEMONIC: &str = "under this above produce during card issue fire gloom reopen topple rough cat smooth salad put broken decade vocal loud pulp gauge hurdle absorb olympic";
    let seed = algo_consensus_crypto::passphrase::mnemonic_to_key(DEV_MNEMONIC)
        .expect("dev mnemonic must decode to a valid key");
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let addr = algo_types::Address(sk.verifying_key().to_bytes());

    // Both nodes boot from the byte-identical shared genesis
    // (`docker/localnet-rust/data/genesis.json`), so genesis-hash/id are the
    // same on both; a fixed first/last-valid window (matching
    // `tx_propagation_two_binary.rs`'s pattern) keeps the txn bytes
    // identical without needing to query per-node suggested params.
    let mut genesis_hash = [0u8; 32];
    {
        let go_params: serde_json::Value = client
            .get(format!("{}/v2/transactions/params", go_url()))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        let bytes = STANDARD
            .decode(go_params["genesis-hash"].as_str().unwrap())
            .expect("valid base64");
        genesis_hash.copy_from_slice(&bytes);
    }

    let mut txn = algo_types::Transaction {
        sender: addr,
        fee: 1000,
        first_valid: Round(1),
        last_valid: Round(1000),
        genesis_id: "localnet-rust-v1".to_string(),
        genesis_hash,
        txn_type: TxnType::Pay,
        receiver: addr,
        amount: 0,
        note: format!(
            "live_msgpack_parity:issue-453:{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
        .into_bytes()
        .into(),
        ..Default::default()
    };
    let mut msg = Vec::with_capacity(2 + 256);
    msg.extend_from_slice(b"TX");
    msg.extend_from_slice(&canonical_encode_transaction(&txn));
    let sig = sk.sign(&msg).to_bytes();
    let stx = SignedTransaction {
        txn: std::mem::take(&mut txn),
        sig,
        ..Default::default()
    };
    let txid = compute_txn_id(&stx.txn).to_string();
    let body = rmp_serde::to_vec_named(&stx).expect("encode signed txn");

    let go_round = submit_and_wait_for_confirmation(client, &go_url(), &txid, &body).await;
    let rust_round = submit_and_wait_for_confirmation(client, &rust_url(), &txid, &body).await;
    (go_round, rust_round)
}

async fn submit_and_wait_for_confirmation(
    client: &reqwest::Client,
    base: &str,
    txid: &str,
    body: &[u8],
) -> u64 {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let resp = client
            .post(format!("{base}/v2/transactions"))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .header("Content-Type", "application/x-binary")
            .body(body.to_vec())
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        if status == 200 {
            break;
        }
        let text = resp.text().await.unwrap_or_default();
        if status == 400
            && text.contains("no pending block evaluator")
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        panic!("POST {base}/v2/transactions failed: {status} {text}");
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let resp = client
            .get(format!("{base}/v2/transactions/pending/{txid}"))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        if status == 200 {
            if let Some(r) = body["confirmed-round"].as_u64() {
                if r > 0 {
                    return r;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            panic!("txid {txid} on {base} did not confirm before deadline (last body {body})");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
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
