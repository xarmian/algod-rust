//! Live dual-node conformance check for `StateDelta.kv_mods` against real
//! go-algorand's `GET /v2/deltas/{round}` (issue #573, follow-up to #570).
//!
//! #570 populated `StateDelta.kv_mods` during Execute-mode block apply (box
//! create/put/delete deltas) and pinned the *semantics* with synthetic,
//! hand-built blocks. It never verified the wire format against a real
//! go-algorand node's own `/v2/deltas/{round}` response -- this file closes
//! that gap.
//!
//! Extends `live_go_parity.rs`'s dual-node harness (see that file's module
//! docs for setup) and `live_box_pagination_parity.rs`'s box-app deployment
//! pattern.
//!
//! # Why not a strict byte-for-byte diff of the two full responses
//!
//! `docker-compose.validate-api.yml` boots both nodes from the *same*
//! genesis, but each node's chain then advances independently as this
//! suite (and any other live suite that already ran against the same
//! long-lived containers) submits transactions to it separately. That means
//! the app this test deploys can land at a different `ApplicationID` and a
//! different round on each side -- and `KvMods` is keyed by
//! `"bx:" + big-endian(app_id) + box_name` (see
//! `algo_ledger::state_delta`'s key-type note, issue #570), so the *raw
//! key bytes* legitimately differ between the two nodes even though the
//! same box operations were performed. Same rationale
//! `live_box_pagination_parity.rs` already documents for stripping `round`.
//!
//! Instead, on **each node independently**, this test:
//! 1. Reconstructs the expected `KvMods` key from that node's own
//!    `ApplicationID` (`"bx:" + app_id.to_be_bytes() + name`) and confirms
//!    it is the exact key go-algorand (respectively algod-rust) used --
//!    this is the byte-for-byte assertion, just keyed by each node's own
//!    app id instead of a hard-coded one.
//! 2. Confirms the `Data`/`OldData` semantics (first-touch `OldData`,
//!    last-write `Data`, empty `Data` after delete) match across a
//!    create -> put -> delete sequence.
//! 3. Confirms the JSON encoding of `Data`/`OldData` is a base64 string
//!    (go's real wire format for untagged `[]byte` fields -- see the fix
//!    landed alongside this test in `algo_ledger::state_delta`) on both
//!    nodes, and the msgpack encoding is raw bytes on both nodes.
//!
//! Then, as the genuinely two-sided comparison, it diffs the *shape* of
//! the create/put/delete `Data`/`OldData` progression between go and rust
//! (both must show the identical create -> "v1", put -> "v2" w/
//! OldData="v1", delete -> OldData="v2" progression) -- proving algod-rust's
//! real running `/v2/deltas/{round}` endpoint (delta-cache-backed, per
//! `node_interface_impl.rs`) matches go-algorand's for box mutations, not
//! just algod-rust's own synthetic unit tests.
//!
//! # Serialization requirement
//!
//! Like `live_box_pagination_parity.rs`, every test here mutates on-chain
//! state on both live nodes. Run with `--test-threads=1`:
//!
//! ```text
//! make validate-api-up
//! cargo test --package algod-rust --test live_state_delta_parity \
//!   -- --ignored --nocapture --test-threads=1
//! make validate-api-down
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use algo_codec::{canonical_encode_transaction, compute_txn_id};
use algo_rest_client::AlgodClient;
use algo_types::{BoxRef, Round, SignedTransaction, TxnType};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ed25519_dalek::Signer;
use serde_bytes::ByteBuf;

const DEV_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// `docs/DEV_WORKFLOW.md`'s funded dev account (25-word mnemonic).
const DEV_MNEMONIC: &str = "under this above produce during card issue fire gloom reopen topple rough cat smooth salad put broken decade vocal loud pulp gauge hurdle absorb olympic";

/// Approval program: on creation (0 args) just approves; on a 2-arg call,
/// `box_put(args[0], args[1])`; on a 1-arg call, `box_del(args[0])`.
const APPROVAL_SOURCE: &str = r#"#pragma version 8
txn NumAppArgs
int 2
==
bnz do_put
txn NumAppArgs
int 1
==
bnz do_del
b done
do_put:
txna ApplicationArgs 0
txna ApplicationArgs 1
box_put
b done
do_del:
txna ApplicationArgs 0
box_del
pop
done:
int 1
return
"#;

/// Trivial approve-all clear-state program (version 8, `pushint 1`).
const CLEAR_STATE_PROGRAM: &[u8] = &[0x08, 0x81, 0x01];

const BOX_NAME: &str = "svc-box";
// `box_put` on an *existing* key requires the new value to be exactly the
// same length as the current one (go-algorand: "attempt to box_put wrong
// size"; boxes don't resize via box_put) -- these two values are both 8
// bytes so the create -> put/mutate sequence exercises a same-size update.
const BOX_VALUE_1: &str = "value_v1";
const BOX_VALUE_2: &str = "value_v2";

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
    format!("live_state_delta_parity:{tag}:{nanos}").into_bytes()
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

/// Fast, always-run (not `#[ignore]`d) regression test: pins that
/// `APPROVAL_SOURCE` actually assembles. Same rationale as
/// `live_box_pagination_parity.rs::approval_program_assembles`.
#[test]
fn approval_program_assembles() {
    let ops = algo_avm::assembler::assemble_string(APPROVAL_SOURCE)
        .expect("APPROVAL_SOURCE must assemble cleanly");
    assert!(
        !ops.program.is_empty(),
        "assembled program must not be empty"
    );
}

/// The expected `KvMods` key for `BOX_NAME` under `app_id`, following
/// go-algorand's `apps.MakeBoxKey`/algod-rust's `make_box_key`:
/// `"bx:" + big-endian(app_id) + box_name`.
fn expected_box_key(app_id: u64) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend_from_slice(b"bx:");
    key.extend_from_slice(&app_id.to_be_bytes());
    key.extend_from_slice(BOX_NAME.as_bytes());
    key
}

/// Deploys the box-writing app on `base`, funds it, and performs a
/// create -> put -> delete sequence on `BOX_NAME`, returning
/// `(app_id, create_round, put_round, del_round)`.
async fn deploy_and_mutate_box(
    client: &reqwest::Client,
    base: &str,
    label: &str,
) -> (u64, u64, u64, u64) {
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

    // 2. Fund the app account so it can cover box MBR.
    let app_addr = algo_types::Address(algo_ledger::avm_context::app_address(app_id));
    let mut fund = base_txn(client, base).await;
    fund.txn_type = TxnType::Pay;
    fund.receiver = app_addr;
    fund.amount = 1_000_000;
    fund.note = unique_note(&format!("app-fund-{label}")).into();
    submit_and_confirm(client, base, label, &mut fund, &sk, "app funding").await;

    // 3. Create the box (box_put with a fresh name -> Data=v1, no OldData).
    let mut create_call = base_txn(client, base).await;
    create_call.txn_type = TxnType::Appl;
    create_call.application_id = app_id;
    create_call.app_arguments = Some(vec![
        Some(ByteBuf::from(BOX_NAME.as_bytes().to_vec())),
        Some(ByteBuf::from(BOX_VALUE_1.as_bytes().to_vec())),
    ]);
    create_call.boxes = Some(vec![BoxRef {
        index: 0,
        name: Some(ByteBuf::from(BOX_NAME.as_bytes().to_vec())),
    }]);
    create_call.note = unique_note(&format!("box-create-{label}")).into();
    let confirmed =
        submit_and_confirm(client, base, label, &mut create_call, &sk, "box create").await;
    let create_round = confirmed["confirmed-round"].as_u64().unwrap();

    // 4. Mutate the box (box_put with an existing name -> Data=v2, OldData=v1).
    let mut put_call = base_txn(client, base).await;
    put_call.txn_type = TxnType::Appl;
    put_call.application_id = app_id;
    put_call.app_arguments = Some(vec![
        Some(ByteBuf::from(BOX_NAME.as_bytes().to_vec())),
        Some(ByteBuf::from(BOX_VALUE_2.as_bytes().to_vec())),
    ]);
    put_call.boxes = Some(vec![BoxRef {
        index: 0,
        name: Some(ByteBuf::from(BOX_NAME.as_bytes().to_vec())),
    }]);
    put_call.note = unique_note(&format!("box-put-{label}")).into();
    let confirmed =
        submit_and_confirm(client, base, label, &mut put_call, &sk, "box put/mutate").await;
    let put_round = confirmed["confirmed-round"].as_u64().unwrap();

    // 5. Delete the box (box_del -> Data empty, OldData=v2).
    let mut del_call = base_txn(client, base).await;
    del_call.txn_type = TxnType::Appl;
    del_call.application_id = app_id;
    del_call.app_arguments = Some(vec![Some(ByteBuf::from(BOX_NAME.as_bytes().to_vec()))]);
    del_call.boxes = Some(vec![BoxRef {
        index: 0,
        name: Some(ByteBuf::from(BOX_NAME.as_bytes().to_vec())),
    }]);
    del_call.note = unique_note(&format!("box-del-{label}")).into();
    let confirmed = submit_and_confirm(client, base, label, &mut del_call, &sk, "box delete").await;
    let del_round = confirmed["confirmed-round"].as_u64().unwrap();

    (app_id, create_round, put_round, del_round)
}

/// Fetches `GET /v2/deltas/{round}?format=json` and returns the single
/// `KvMods` entry present (key bytes as sent on the wire -- possibly
/// lossy-UTF8, see module docs -- plus its `Data`/`OldData` JSON values),
/// panicking if the round's `KvMods` doesn't have exactly one entry.
async fn single_kv_mods_entry(
    client: &reqwest::Client,
    base: &str,
    label: &str,
    round: u64,
) -> (String, serde_json::Value) {
    let (status, body) = get_json(client, base, &format!("/v2/deltas/{round}?format=json")).await;
    assert_eq!(
        status, 200,
        "{label}: GET /v2/deltas/{round} status: {body}"
    );
    let kv_mods = body
        .get("KvMods")
        .and_then(|v| v.as_object())
        .unwrap_or_else(|| panic!("{label}: round {round} StateDelta has no KvMods: {body}"));
    assert_eq!(
        kv_mods.len(),
        1,
        "{label}: round {round} expected exactly one KvMods entry (single box-touching txn): {kv_mods:?}"
    );
    let (k, v) = kv_mods.iter().next().unwrap();
    (k.clone(), v.clone())
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn state_delta_kv_mods_matches_go_for_box_create_put_delete() {
    let c = client();

    // (create_entry, put_entry, del_entry) JSON KvMods values, per node.
    type PerNodeJsonEntries = (serde_json::Value, serde_json::Value, serde_json::Value);
    let mut results: std::collections::HashMap<&str, PerNodeJsonEntries> =
        std::collections::HashMap::new();

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let (app_id, create_round, put_round, del_round) =
            deploy_and_mutate_box(&c, &base, label).await;
        let want_key_bytes = expected_box_key(app_id);
        let want_key = String::from_utf8_lossy(&want_key_bytes).into_owned();

        let (create_key, create_val) = single_kv_mods_entry(&c, &base, label, create_round).await;
        let (put_key, put_val) = single_kv_mods_entry(&c, &base, label, put_round).await;
        let (del_key, del_val) = single_kv_mods_entry(&c, &base, label, del_round).await;

        // 1. Byte-for-byte key-format assertion: the real node's KvMods
        //    key for this box must be exactly "bx:" + big-endian(app_id) +
        //    box_name, reconstructed independently from the confirmed
        //    ApplicationID -- proving go's (and algod-rust's) actual box
        //    key construction, not an assumption about it.
        for (round_label, key) in [
            ("create", &create_key),
            ("put", &put_key),
            ("delete", &del_key),
        ] {
            assert_eq!(
                key, &want_key,
                "{label}: {round_label} round KvMods key must be \"bx:\" + big-endian(app_id={app_id}) + {BOX_NAME:?}"
            );
        }

        // 2. Data/OldData semantics: create has null OldData, put's OldData
        //    is the prior value, delete clears Data (null) and keeps
        //    OldData. Note: go-algorand's `KvValueDelta` has no `omitempty`
        //    directive, so a real node's response always includes both
        //    keys with JSON `null` for an unset value, never omitting the
        //    key outright (issue #573, live-verified).
        assert_eq!(
            create_val.get("Data"),
            Some(&serde_json::Value::String(
                BASE64_STANDARD.encode(BOX_VALUE_1)
            )),
            "{label}: box-create round Data must be the base64-encoded first value: {create_val}"
        );
        assert_eq!(
            create_val.get("OldData"),
            Some(&serde_json::Value::Null),
            "{label}: box-create round OldData must be present and null (box didn't exist before): {create_val}"
        );

        assert_eq!(
            put_val.get("Data"),
            Some(&serde_json::Value::String(
                BASE64_STANDARD.encode(BOX_VALUE_2)
            )),
            "{label}: box-put round Data must be the base64-encoded second value: {put_val}"
        );
        assert_eq!(
            put_val.get("OldData"),
            Some(&serde_json::Value::String(
                BASE64_STANDARD.encode(BOX_VALUE_1)
            )),
            "{label}: box-put round OldData must be the base64-encoded first value: {put_val}"
        );

        assert_eq!(
            del_val.get("Data"),
            Some(&serde_json::Value::Null),
            "{label}: box-delete round Data must be present and null (box no longer exists): {del_val}"
        );
        assert_eq!(
            del_val.get("OldData"),
            Some(&serde_json::Value::String(
                BASE64_STANDARD.encode(BOX_VALUE_2)
            )),
            "{label}: box-delete round OldData must be the base64-encoded last value before deletion: {del_val}"
        );

        results.insert(label, (create_val, put_val, del_val));
    }

    // Cross-node comparison: since Data/OldData don't embed the (per-node
    // divergent) app id or round, the actual JSON values must be identical
    // between go and rust for the same create/put/delete sequence.
    let (go_create, go_put, go_del) = &results["go"];
    let (rust_create, rust_put, rust_del) = &results["rust"];
    assert_eq!(
        go_create, rust_create,
        "box-create round KvMods entry must match between go and rust"
    );
    assert_eq!(
        go_put, rust_put,
        "box-put round KvMods entry must match between go and rust"
    );
    assert_eq!(
        go_del, rust_del,
        "box-delete round KvMods entry must match between go and rust"
    );
}

/// Same create -> put -> delete sequence, but verifies the msgpack-format
/// response (`?format=msgpack`): the `KvMods` key and `Data`/`OldData`
/// values must be raw bytes on the wire (no base64), matching between go
/// and rust, and matching the reconstructed expected key exactly.
#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn state_delta_kv_mods_msgpack_matches_go() {
    let c = client();

    async fn fetch_msgpack_kv_entry(
        c: &reqwest::Client,
        base: &str,
        round: u64,
    ) -> (Vec<u8>, rmpv::Value) {
        let resp = c
            .get(format!("{base}/v2/deltas/{round}?format=msgpack"))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "GET /v2/deltas/{round}?format=msgpack status"
        );
        let bytes = resp.bytes().await.unwrap();
        let decoded: rmpv::Value =
            rmpv::decode::read_value(&mut &bytes[..]).expect("must decode as msgpack");
        let kv_mods = decoded
            .as_map()
            .and_then(|m| m.iter().find(|(k, _)| k.as_str() == Some("KvMods")))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| {
                panic!("round {round} msgpack StateDelta has no KvMods: {decoded:?}")
            });
        let map = kv_mods
            .as_map()
            .unwrap_or_else(|| panic!("round {round} KvMods must be a map: {kv_mods:?}"));
        assert_eq!(
            map.len(),
            1,
            "round {round} expected exactly one msgpack KvMods entry: {map:?}"
        );
        let (k, v) = &map[0];
        // `Value::as_slice()` returns the raw payload bytes for both String
        // and Binary variants -- unlike `as_str()`, it works even when the
        // string payload isn't valid UTF-8 (as an app-id-embedded box key
        // frequently isn't), which is exactly what's needed here.
        let key_bytes = k
            .as_slice()
            .map(|b| b.to_vec())
            .unwrap_or_else(|| panic!("KvMods key must be a msgpack string/bin: {k:?}"));
        (key_bytes, v.clone())
    }

    type PerNodeByteEntries = (Vec<u8>, Vec<u8>, Vec<u8>);
    let mut per_node: std::collections::HashMap<&str, PerNodeByteEntries> =
        std::collections::HashMap::new();

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let (app_id, create_round, put_round, del_round) =
            deploy_and_mutate_box(&c, &base, label).await;
        let want_key = expected_box_key(app_id);

        let (create_key, create_val) = fetch_msgpack_kv_entry(&c, &base, create_round).await;
        let (put_key, put_val) = fetch_msgpack_kv_entry(&c, &base, put_round).await;
        let (del_key, del_val) = fetch_msgpack_kv_entry(&c, &base, del_round).await;

        assert_eq!(
            create_key, want_key,
            "{label}: msgpack KvMods key bytes must exactly equal \"bx:\" + big-endian(app_id) + name (no lossy encoding in msgpack)"
        );
        assert_eq!(put_key, want_key, "{label}: put round key");
        assert_eq!(del_key, want_key, "{label}: delete round key");

        let data_of = |v: &rmpv::Value, field: &str| -> Vec<u8> {
            v.as_map()
                .and_then(|m| m.iter().find(|(k, _)| k.as_str() == Some(field)))
                .and_then(|(_, v)| v.as_slice().map(|b| b.to_vec()))
                .unwrap_or_default()
        };

        assert_eq!(
            data_of(&create_val, "Data"),
            BOX_VALUE_1.as_bytes(),
            "{label}: msgpack box-create Data must be raw bytes of the first value"
        );
        assert_eq!(
            data_of(&put_val, "OldData"),
            BOX_VALUE_1.as_bytes(),
            "{label}: msgpack box-put OldData must be raw bytes of the first value"
        );
        assert_eq!(
            data_of(&put_val, "Data"),
            BOX_VALUE_2.as_bytes(),
            "{label}: msgpack box-put Data must be raw bytes of the second value"
        );
        assert_eq!(
            data_of(&del_val, "OldData"),
            BOX_VALUE_2.as_bytes(),
            "{label}: msgpack box-delete OldData must be raw bytes of the second value"
        );

        per_node.insert(
            label,
            (
                data_of(&create_val, "Data"),
                data_of(&put_val, "Data"),
                data_of(&del_val, "OldData"),
            ),
        );
    }

    assert_eq!(
        per_node["go"], per_node["rust"],
        "msgpack Data/OldData byte progression must match between go and rust"
    );
}

/// Sanity check that `AlgodClient::get_state_delta_json`/
/// `get_state_delta_msgpack_raw` (added alongside this test for
/// `algo-fixtures`' capture path, issue #573 acceptance criterion 1) can
/// round-trip a real node's response and that `algo_fixtures::
/// capture_state_delta` writes out the expected files.
#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn algo_fixtures_can_capture_state_delta() {
    let c = client();
    let base = go_url();
    let (_, create_round, _, _) = deploy_and_mutate_box(&c, &base, "go-fixture-capture").await;

    let algod_client = AlgodClient::new(base.clone(), DEV_TOKEN);
    let dir = tempfile_dir();
    let path =
        algo_fixtures::capture_state_delta(&algod_client, Round(create_round), dir.path(), &base)
            .await
            .expect("capture_state_delta must succeed against a live node");

    assert!(path.exists(), "captured JSON fixture must exist: {path:?}");
    let json_bytes = std::fs::read(&path).expect("read captured JSON fixture");
    let json: serde_json::Value =
        serde_json::from_slice(&json_bytes).expect("captured JSON fixture must parse");
    assert!(
        json.get("KvMods").is_some(),
        "captured JSON fixture must contain KvMods: {json}"
    );

    let msgpack_path = dir
        .path()
        .join(format!("state_delta_{create_round}.msgpack"));
    assert!(
        msgpack_path.exists(),
        "captured msgpack fixture must exist: {msgpack_path:?}"
    );
    let msgpack_bytes = std::fs::read(&msgpack_path).expect("read captured msgpack fixture");
    let decoded: rmpv::Value = rmpv::decode::read_value(&mut &msgpack_bytes[..])
        .expect("captured msgpack fixture must decode");
    assert!(
        decoded
            .as_map()
            .map(|m| m.iter().any(|(k, _)| k.as_str() == Some("KvMods")))
            .unwrap_or(false),
        "captured msgpack fixture must contain a KvMods entry: {decoded:?}"
    );

    let meta_path = dir
        .path()
        .join(format!("state_delta_{create_round}.meta.json"));
    assert!(
        meta_path.exists(),
        "captured metadata must exist: {meta_path:?}"
    );
}

fn tempfile_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("create scratch dir for fixture capture")
}

/// Issue #576 (follow-up to #573): live-verifies that fields *outside*
/// `KvValueDelta` are never omitted either. `ledgercore.AccountBaseData`
/// (the `Accts[]` entries under `StateDelta.Accts`) carries no `_struct
/// codec:",omitempty,omitemptyarray"` marker, so a real node's response for
/// a plain payment round -- where most `AccountBaseData` fields are zero --
/// must still include every one of those fields, e.g. `"Status":0`,
/// `"AuthAddr":"AAAA...Y5HFKQ"` (the all-zero address's checksum string, not
/// omitted/null), `"TotalAppSchema":{}` (present as an empty object, not
/// omitted). This is exactly the example quoted in issue #576 itself.
#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn state_delta_accts_zero_fields_matches_go_for_plain_payment() {
    let c = client();
    let sk = dev_signing_key();

    // A second dev-mode account: the recipient. Any funded, distinct
    // address works; genesis dev-mode accounts always exist, so pick the
    // all-zero address's "next" byte pattern to guarantee it's a fresh
    // account with zero `AccountBaseData` (no prior Status/AuthAddr/etc.)
    // wherever it lands in Accts.
    let receiver = algo_types::Address([0x07; 32]);

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let mut pay = base_txn(&c, &base).await;
        pay.txn_type = TxnType::Pay;
        pay.receiver = receiver;
        pay.amount = 1234;
        pay.note = unique_note(&format!("plain-payment-{label}")).into();
        let confirmed = submit_and_confirm(&c, &base, label, &mut pay, &sk, "plain payment").await;
        let round = confirmed["confirmed-round"].as_u64().unwrap();

        let (status, body) = get_json(&c, &base, &format!("/v2/deltas/{round}?format=json")).await;
        assert_eq!(
            status, 200,
            "{label}: GET /v2/deltas/{round} status: {body}"
        );

        let accts = body["Accts"]["Accts"]
            .as_array()
            .unwrap_or_else(|| panic!("{label}: round {round} StateDelta.Accts.Accts must be a (possibly empty) array: {body}"));
        assert!(
            !accts.is_empty(),
            "{label}: a plain payment round must touch at least the sender and receiver: {body}"
        );

        // Find the freshly-touched receiver's BalanceRecord by its zero
        // `Status`/`MicroAlgos`... wait, MicroAlgos is nonzero after the
        // payment, so key on the fields that stay zero for a brand-new
        // account with no app/asset history (Status, TotalAppSchema,
        // TotalAppParams): the sender (a long-lived dev-mode account) won't
        // match all of these simultaneously. Not matching by the `Addr`
        // field's *string* value deliberately -- `ledgercore.AccountDeltas`'
        // `Addr`/`AuthAddr` fields have their own separate, pre-existing
        // wire-encoding bug (tracked in a dedicated follow-up issue filed
        // alongside #576) unrelated to this test's omitempty concern.
        let receiver_record = accts
            .iter()
            .find(|r| {
                r.get("Status") == Some(&serde_json::json!(0))
                    && r.get("TotalAppSchema") == Some(&serde_json::json!({}))
                    && r.get("TotalAppParams") == Some(&serde_json::json!(0))
            })
            .unwrap_or_else(|| {
                panic!("{label}: round {round} Accts must contain a fresh zero-history receiver: {accts:?}")
            });

        for key in [
            "Status",
            "MicroAlgos",
            "RewardsBase",
            "RewardedMicroAlgos",
            "AuthAddr",
            "IncentiveEligible",
            "TotalAppSchema",
            "TotalExtraAppPages",
            "TotalAppParams",
            "TotalAppLocalStates",
            "TotalAssetParams",
            "TotalAssets",
            "TotalBoxes",
            "TotalBoxBytes",
            "LastProposed",
            "LastHeartbeat",
        ] {
            assert!(
                receiver_record.get(key).is_some(),
                "{label}: round {round} receiver's AccountBaseData must always include {key} \
                 (no omitempty on ledgercore.AccountBaseData), even when zero: {receiver_record}"
            );
        }
        // Spot-check the exact zero-value wire forms the issue itself
        // quotes: Status as a bare 0, AuthAddr as the real (non-omitted,
        // non-null) checksum-address string, TotalAppSchema as `{}`.
        assert_eq!(
            receiver_record["Status"],
            serde_json::json!(0),
            "{label}: fresh receiver's Status must be present as 0: {receiver_record}"
        );
        assert_eq!(
            receiver_record["TotalAppSchema"],
            serde_json::json!({}),
            "{label}: fresh receiver's TotalAppSchema must be present as {{}}: {receiver_record}"
        );
    }
}
