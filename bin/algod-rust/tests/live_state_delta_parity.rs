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

//! # Issue #603 / #606 additions
//!
//! Issue #603 split out #586's own unmet acceptance criterion (a live
//! dual-node comparison for `AccountDeltas::app_resources`/
//! `asset_resources`/`StateDelta::creatables`/`totals`, populated by #586
//! but never verified against a real go-algorand node) and the
//! `block_state_delta_is_complete` cache gate that controls whether the
//! *sync* path (`bin/algod-rust/src/commands/sync.rs`) caches a delta for
//! `GET /v2/deltas/{round}` to later serve. The tests below
//! (`state_delta_asset_resources_matches_go_for_*`) cover the Acfg (asset
//! create/reconfigure/destroy) and Axfer (opt-in/close-out) lifecycle #603
//! widened that gate to admit, live-diffing `AssetResources`/`Creatables`
//! field-for-field against go -- live-verification found and fixed two
//! real gaps along the way (see `apply.rs`'s `asset_holding_force_emit`
//! doc comment): a destroy Acfg wasn't attributing the creator's holding
//! removal, and neither loop matched go's "was this resource `Put`
//! during the round" emission semantics (value-diffed instead, so a
//! value-identical reconfigure produced an empty record). `Appl` stays
//! excluded from that *sync-path* gate (issue #604 -- inner-transaction
//! resource attribution is still a real gap there), but this harness's
//! algod-rust node runs in `--dev` mode, whose self-produced-block path
//! bypasses the gate entirely (see
//! `state_delta_app_resources_matches_go_for_create_update`'s doc comment
//! for why), so that test still live-verifies full field-for-field parity
//! for an app create + update (no inner transactions), including issue
//! #606's `AppParamsRecord.v` live-verification.
//!
//! # Issue #609 addendum
//!
//! Issue #604 fixed `apply_block_with_delta_mode_and_apply_data`'s
//! inner-transaction resource-collection gap (a `RecordingStore` wrapper
//! that records every mutation's pre-image as it happens, at any call
//! depth, so resource keys don't need to be known before the block is
//! applied). Issue #609 then fixed the sync path's *other* consumer gated
//! on the same predicate -- `apply.rs`'s `Execute`-mode per-group delta
//! capture used by `TxnGroupDeltaTracer` -- with an equivalent group-scoped
//! `RecordingStore` wrap, and fixed `apply_block_caching_delta`'s
//! "complete" branch to select `ApplyMode::Execute` (not the hard-coded
//! `Replay` it used before) whenever the block contains an `appl` call.
//! With both fixed, `sqlite::block_state_delta_is_complete` now admits
//! `Appl` blocks.
//!
//! `crates/core/algo-ledger/src/sqlite.rs`'s
//! `apply_block_caching_delta_caches_full_delta_for_appl_with_inner_acfg`
//! and `group_delta_tracer_captures_inner_txn_only_touched_account_for_appl`
//! pin the target end-to-end behavior (a normally-synced Appl block with an
//! inner transaction gets a complete, correctly-attributed `StateDelta`,
//! for both the per-round cache and the per-group tracer) as fast, always-
//! run unit tests -- satisfying the "or a fast in-process test if that's
//! sufficient to pin the gate behavior" alternative issue #609 itself
//! offered, since this file's own dual-node harness cannot exercise the
//! *sync* path at all: the algod-rust node it boots always runs `--dev`
//! (see the paragraph above), whose self-produced-block path calls
//! `SqliteLedger::cache_state_delta` directly and never consults
//! `block_state_delta_is_complete`/`apply_block_caching_delta` in the first
//! place, regardless of what the gate admits.
//!
//! # Issue #612: the genuine sync-path live test
//!
//! #612 added exactly the third process the paragraph above called for:
//! `algod-rust node start --follow <peer-url>` (see
//! `bin/algod-rust/src/commands/node.rs::run_follow_loop`) fetches new
//! blocks one round at a time from a REST peer and applies each one via
//! `SqliteLedger::apply_block_caching_delta` -- the exact call
//! `commands/sync.rs` makes per received block -- while continuing to
//! serve its own REST API, so `GET /v2/deltas/{round}` can be queried
//! against a block that was genuinely synced, not dev-mode-produced.
//! `Makefile`'s `validate-api-up` now boots this node on `:4003`, following
//! `algod-go-shared` (`:4001`) directly.
//!
//! `state_delta_appl_inner_txn_matches_go_through_real_sync_path` below
//! submits an itxn-issuing app call to go ALONE (unlike every other test in
//! this file, which submits independently to both `--dev` nodes), waits
//! for the `:4003` follow node to sync that round over its own independent
//! REST poll of go, and then diffs `GET /v2/deltas/{round}` between go and
//! the syncing node for that *same* round of the *same* chain -- a full,
//! unstripped comparison (not the per-side key-stripped comparison the
//! rest of this file needs for two independently-advancing chains, per the
//! header note above), since both sides now describe literally the same
//! block. This is the live proof that #609/#613's sync-path fix
//! (`apply_block_caching_delta` routing `Appl` blocks through
//! `ApplyMode::Execute`) works end-to-end against a real peer, closing the
//! gap this file's module doc used to describe as open.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use algo_codec::{canonical_encode_transaction, compute_txn_id};
use algo_rest_client::AlgodClient;
use algo_types::{AssetParams, BoxRef, Round, SignedTransaction, TxnType};
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

/// Deterministic-per-`tag` fresh signing key, following the same
/// nanos-seeded pattern already used inline by
/// `state_delta_asset_resources_matches_go_for_optin_closeout` -- factored
/// out here since issues #608's new tests below need several independent
/// fresh accounts per node run (one per opt-in/close-out/clear-state actor).
fn fresh_account(tag: &str) -> ed25519_dalek::SigningKey {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut seed = [0u8; 32];
    let bytes = format!("{tag}-{nanos}").into_bytes();
    let n = bytes.len().min(32);
    seed[..n].copy_from_slice(&bytes[..n]);
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

/// Issue #576 (follow-up to #573): live-verifies that fields *outside*
/// `KvValueDelta` are never omitted either. `ledgercore.AccountBaseData`
/// (the `Accts[]` entries under `StateDelta.Accts`) carries no `_struct
/// codec:",omitempty,omitemptyarray"` marker, so a real node's response
/// must still include every one of those fields even when zero, e.g.
/// `"Status":0`, `"AuthAddr":"AAAA...Y5HFKQ"` (the all-zero address's
/// checksum string, not omitted/null), `"TotalAppSchema":{}` (present as an
/// empty object, not omitted). This is exactly the example quoted in issue
/// #576 itself.
///
/// **go-algorand gets the full assertion; algod-rust gets a weaker,
/// documented one.** While first writing this test, every round shape
/// tried (plain payment, bare app creation, and this test's box-create
/// round) showed algod-rust's own dev-mode block producer's delta-caching
/// path populating *only* `KvMods` in its cached `StateDelta` -- `Accts`
/// (and `Totals`/`Txids`/`Creatables`/`Hdr`) stay at their empty/default
/// values regardless of round content, even in the exact same response
/// where `KvMods` is correctly populated. That's a separate, pre-existing
/// ledger/dev-mode-block-production bug, unrelated to this issue's
/// serialization-format scope -- filed and root-caused as its own
/// follow-up, issue #581. Per issue #576's own acceptance criteria ("any
/// field where live verification is genuinely infeasible is documented
/// with root cause, not silently left as-is"): go's response is asserted
/// in full (proving the real go-algorand wire form this issue's fix
/// targets); algod-rust's response is only checked for the one shape
/// invariant #581's gap can't break -- the `Accts.Accts` key is present as
/// an array (never omitted, never `null`) -- not for populated account
/// content, which #581 blocks until fixed.
#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn state_delta_accts_zero_fields_matches_go_for_box_create_round() {
    let c = client();

    let account_base_data_keys = [
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
    ];

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let (_app_id, create_round, _put_round, _del_round) =
            deploy_and_mutate_box(&c, &base, label).await;

        let (status, body) =
            get_json(&c, &base, &format!("/v2/deltas/{create_round}?format=json")).await;
        assert_eq!(
            status, 200,
            "{label}: GET /v2/deltas/{create_round} status: {body}"
        );

        // Always true regardless of the #581 gap: the outer `AccountDeltas`
        // shape this #576 fix controls (never-omitted `Accts` key,
        // `AppResources`/`AssetResources` as `null` when untouched) must
        // hold on both nodes even when `Accts.Accts` itself ends up empty.
        assert!(
            body["Accts"]["Accts"].is_array(),
            "{label}: round {create_round} StateDelta.Accts.Accts must be a (possibly empty) array: {body}"
        );

        if label == "rust" {
            // See this test's doc comment / issue #581: algod-rust's own
            // dev-mode chain doesn't populate Accts content yet, so the
            // never-omit-when-populated assertions below would spuriously
            // fail here for a reason this issue's fix doesn't control.
            continue;
        }

        let accts = body["Accts"]["Accts"].as_array().unwrap();
        assert!(
            !accts.is_empty(),
            "{label}: the box-create round must touch at least the app account: {body}"
        );

        // Every `AccountBaseData` key must be present on *every* touched
        // account, regardless of that account's specific field values --
        // the dev account driving this suite accumulates state (app/asset
        // counts, balances) across every other live test sharing this
        // long-lived cluster, so pinning on a specific "fresh account" shape
        // is brittle; presence-of-every-key is what issue #576 is actually
        // about, and checking it across every entry is strictly stronger
        // than checking one hand-picked entry. Not asserting on the `Addr`/
        // `AuthAddr` fields' *string* value deliberately -- those have their
        // own separate, pre-existing wire-encoding bug (tracked in a
        // dedicated follow-up issue filed alongside #576) unrelated to this
        // test's omitempty concern.
        for record in accts {
            for key in account_base_data_keys {
                assert!(
                    record.get(key).is_some(),
                    "{label}: round {create_round}'s every Accts[] entry must always include {key} \
                     (no omitempty on ledgercore.AccountBaseData), even when zero: {record}"
                );
            }
        }

        // Spot-check the exact zero-value wire form the issue itself
        // quotes -- find some entry with a literal 0, proving it's a bare
        // number and not e.g. a stringified/omitted placeholder.
        assert!(
            accts
                .iter()
                .any(|r| r.get("TotalBoxes") == Some(&serde_json::json!(0))),
            "{label}: round {create_round} must have at least one Accts[] entry with TotalBoxes present as 0: {accts:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Issue #603: Acfg/Axfer AssetResources/Creatables live verification + the
// widened `block_state_delta_is_complete` cache gate.
// ---------------------------------------------------------------------------

const ASSET_TOTAL: u64 = 1_000_000;
const ASSET_UNIT_NAME: &str = "TSTU";
const ASSET_NAME: &str = "TestAsset603";
const ASSET_URL: &str = "https://example.com/asset603";

/// Deploys an asset on `base` (dev account holds every role), reconfigures
/// it (manager re-affirms itself, a pure `AssetParamsDelta` change that
/// must not touch the holding), then destroys it (empty `AssetParams`
/// signals destroy per `apply_acfg`/go's `AssetConfigTxnFields` -- the
/// creator still holds the full supply, so destroy is legal). Returns
/// `(asset_id, create_round, update_round, destroy_round)`.
async fn deploy_and_mutate_asset(
    client: &reqwest::Client,
    base: &str,
    label: &str,
) -> (u64, u64, u64, u64) {
    let sk = dev_signing_key();
    let addr = dev_address();

    // 1. Create.
    let mut create = base_txn(client, base).await;
    create.txn_type = TxnType::Acfg;
    create.asset_params = Some(AssetParams {
        total: ASSET_TOTAL,
        decimals: 2,
        default_frozen: false,
        unit_name: ASSET_UNIT_NAME.to_string(),
        asset_name: ASSET_NAME.to_string(),
        url: ASSET_URL.to_string(),
        manager: Some(addr),
        reserve: Some(addr),
        freeze: Some(addr),
        clawback: Some(addr),
        ..Default::default()
    });
    create.note = unique_note(&format!("asset-create-{label}")).into();
    let confirmed =
        submit_and_confirm(client, base, label, &mut create, &sk, "asset creation").await;
    let asset_id = confirmed["asset-index"].as_u64().unwrap_or_else(|| {
        panic!("{label}: confirmed asset creation must report asset-index: {confirmed}")
    });
    let create_round = confirmed["confirmed-round"].as_u64().unwrap();

    // 2. Reconfigure (manager re-affirms every role -- a real params change
    // that must not touch the holding).
    let mut reconfig = base_txn(client, base).await;
    reconfig.txn_type = TxnType::Acfg;
    reconfig.config_asset = asset_id;
    reconfig.asset_params = Some(AssetParams {
        manager: Some(addr),
        reserve: Some(addr),
        freeze: Some(addr),
        clawback: Some(addr),
        ..Default::default()
    });
    reconfig.note = unique_note(&format!("asset-reconfig-{label}")).into();
    let confirmed =
        submit_and_confirm(client, base, label, &mut reconfig, &sk, "asset reconfigure").await;
    let update_round = confirmed["confirmed-round"].as_u64().unwrap();

    // 3. Destroy.
    let mut destroy = base_txn(client, base).await;
    destroy.txn_type = TxnType::Acfg;
    destroy.config_asset = asset_id;
    destroy.note = unique_note(&format!("asset-destroy-{label}")).into();
    let confirmed =
        submit_and_confirm(client, base, label, &mut destroy, &sk, "asset destroy").await;
    let destroy_round = confirmed["confirmed-round"].as_u64().unwrap();

    (asset_id, create_round, update_round, destroy_round)
}

/// `GET /v2/deltas/{round}?format=json`, asserting the request succeeds
/// (used by rounds this widened gate is now expected to serve).
async fn fetch_delta_expect_200(
    c: &reqwest::Client,
    base: &str,
    label: &str,
    round: u64,
    context: &str,
) -> serde_json::Value {
    let (status, body) = get_json(c, base, &format!("/v2/deltas/{round}?format=json")).await;
    assert_eq!(
        status, 200,
        "{label}: round {round} GET /v2/deltas must succeed ({context}): {body}"
    );
    body
}

fn asset_resources(body: &serde_json::Value) -> Vec<serde_json::Value> {
    body["Accts"]["AssetResources"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// Live dual-node verification for issue #603's Acfg (asset create /
/// reconfigure / destroy) coverage: proves `block_state_delta_is_complete`'s
/// widened gate actually serves a cached delta (`200`, not `404`) for these
/// rounds, and that the delta's `AssetResources`/`Creatables` content
/// matches go-algorand field-for-field.
#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn state_delta_asset_resources_matches_go_for_create_update_destroy() {
    let c = client();
    let addr_str = dev_address().to_string();

    // (create, update, destroy) AssetResources[0] JSON entries per node,
    // with the per-node-divergent `Aidx` stripped so the remaining shape
    // can be compared directly between go and rust.
    type PerNodeEntries = (serde_json::Value, serde_json::Value, serde_json::Value);
    let mut results: std::collections::HashMap<&str, PerNodeEntries> =
        std::collections::HashMap::new();

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let (asset_id, create_round, update_round, destroy_round) =
            deploy_and_mutate_asset(&c, &base, label).await;

        let create_body =
            fetch_delta_expect_200(&c, &base, label, create_round, "issue #603").await;
        let update_body =
            fetch_delta_expect_200(&c, &base, label, update_round, "issue #603").await;
        let destroy_body =
            fetch_delta_expect_200(&c, &base, label, destroy_round, "issue #603").await;

        // -- create round --
        let recs = asset_resources(&create_body);
        assert_eq!(
            recs.len(),
            1,
            "{label}: create round expected exactly one AssetResourceRecord: {recs:?}"
        );
        let rec = &recs[0];
        assert_eq!(rec["Aidx"].as_u64(), Some(asset_id));
        assert_eq!(rec["Addr"].as_str(), Some(addr_str.as_str()));
        assert_eq!(rec["Params"]["Deleted"], serde_json::json!(false));
        let params = &rec["Params"]["Params"];
        assert_eq!(params["t"].as_u64(), Some(ASSET_TOTAL), "{label}: total");
        assert_eq!(params["dc"].as_u64(), Some(2), "{label}: decimals");
        assert_eq!(params["un"].as_str(), Some(ASSET_UNIT_NAME));
        assert_eq!(params["an"].as_str(), Some(ASSET_NAME));
        assert_eq!(params["au"].as_str(), Some(ASSET_URL));
        assert_eq!(params["m"].as_str(), Some(addr_str.as_str()));
        assert_eq!(rec["Holding"]["Deleted"], serde_json::json!(false));
        assert_eq!(
            rec["Holding"]["Holding"]["a"].as_u64(),
            Some(ASSET_TOTAL),
            "{label}: creator's initial holding must equal the total supply: {rec}"
        );
        let creatable = &create_body["Creatables"][asset_id.to_string()];
        assert_eq!(
            creatable["Created"],
            serde_json::json!(true),
            "{label}: create round Creatables entry: {creatable}"
        );
        assert_eq!(
            creatable["Ctype"],
            serde_json::json!(0),
            "{label}: 0 = asset"
        );

        // -- update (reconfigure) round --
        let recs = asset_resources(&update_body);
        assert_eq!(
            recs.len(),
            1,
            "{label}: update round expected exactly one AssetResourceRecord: {recs:?}"
        );
        let rec = &recs[0];
        assert_eq!(rec["Params"]["Deleted"], serde_json::json!(false));
        assert!(
            rec["Params"]["Params"].is_object(),
            "{label}: reconfigure must carry a Params delta: {rec}"
        );
        // Live-verification finding (issue #603): go-algorand's
        // `AccountDeltas` are "was this resource `Put` during the round"
        // -tracked, not before/after diffed -- a reconfigure that
        // re-affirms identical role addresses (this test's) still carries
        // the creator's *unchanged* holding on the wire, not a null/absent
        // one.
        assert_eq!(rec["Holding"]["Deleted"], serde_json::json!(false));
        assert_eq!(
            rec["Holding"]["Holding"]["a"].as_u64(),
            Some(ASSET_TOTAL),
            "{label}: a reconfigure round still carries the creator's (unchanged) \
             holding on go's wire response: {rec}"
        );

        // -- destroy round --
        let recs = asset_resources(&destroy_body);
        assert_eq!(
            recs.len(),
            1,
            "{label}: destroy round expected exactly one AssetResourceRecord: {recs:?}"
        );
        let rec = &recs[0];
        assert_eq!(rec["Params"]["Deleted"], serde_json::json!(true));
        assert!(rec["Params"]["Params"].is_null());
        assert_eq!(
            rec["Holding"]["Deleted"],
            serde_json::json!(true),
            "{label}: creator's holding must be removed on destroy: {rec}"
        );
        assert!(rec["Holding"]["Holding"].is_null());
        let creatable = &destroy_body["Creatables"][asset_id.to_string()];
        assert_eq!(
            creatable["Created"],
            serde_json::json!(false),
            "{label}: destroy round Creatables entry: {creatable}"
        );

        let strip_aidx = |mut v: serde_json::Value| {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("Aidx");
            }
            v
        };
        results.insert(
            label,
            (
                strip_aidx(recs_first(&create_body)),
                strip_aidx(recs_first(&update_body)),
                strip_aidx(recs_first(&destroy_body)),
            ),
        );
    }

    // Cross-node comparison: with `Aidx` stripped (per-node divergent asset
    // id), the remaining shape -- Addr (same dev account on both nodes),
    // Params, Holding -- must be identical between go and rust.
    let (go_create, go_update, go_destroy) = &results["go"];
    let (rust_create, rust_update, rust_destroy) = &results["rust"];
    assert_eq!(
        go_create, rust_create,
        "create round AssetResourceRecord must match between go and rust"
    );
    assert_eq!(
        go_update, rust_update,
        "update round AssetResourceRecord must match between go and rust"
    );
    assert_eq!(
        go_destroy, rust_destroy,
        "destroy round AssetResourceRecord must match between go and rust"
    );
}

fn recs_first(body: &serde_json::Value) -> serde_json::Value {
    asset_resources(body)
        .into_iter()
        .next()
        .unwrap_or(serde_json::Value::Null)
}

/// Live dual-node verification for issue #603's Axfer opt-in/close-out
/// coverage: a second account opts into the asset (zero-amount self
/// transfer), then closes out (reclaiming its holding to the creator via
/// `AssetCloseTo`). Both rounds are `Axfer`-only, so `#603`'s widened gate
/// must serve them.
#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn state_delta_asset_resources_matches_go_for_optin_closeout() {
    let c = client();
    let dev_addr = dev_address();

    type PerNodeEntries = (serde_json::Value, serde_json::Value);
    let mut results: std::collections::HashMap<&str, PerNodeEntries> =
        std::collections::HashMap::new();

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        // Fresh account for this run so opt-in always starts from a clean
        // (not-yet-opted-in) state, deterministic per (label, run) via the
        // note-based uniqueness already used for other txns in this suite.
        let opt_sk = ed25519_dalek::SigningKey::from_bytes(&{
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let mut seed = [0u8; 32];
            let bytes = format!("{label}-{nanos}").into_bytes();
            let n = bytes.len().min(32);
            seed[..n].copy_from_slice(&bytes[..n]);
            seed
        });
        let opt_addr = algo_types::Address(opt_sk.verifying_key().to_bytes());

        // Create the asset (dev account holds full supply + clawback so it
        // can fund/close out the opt-in account).
        let mut create = base_txn(&c, &base).await;
        create.txn_type = TxnType::Acfg;
        create.asset_params = Some(AssetParams {
            total: ASSET_TOTAL,
            unit_name: ASSET_UNIT_NAME.to_string(),
            asset_name: ASSET_NAME.to_string(),
            manager: Some(dev_addr),
            reserve: Some(dev_addr),
            freeze: Some(dev_addr),
            clawback: Some(dev_addr),
            ..Default::default()
        });
        create.note = unique_note(&format!("asset-optin-create-{label}")).into();
        let confirmed = submit_and_confirm(
            &c,
            &base,
            label,
            &mut create,
            &dev_signing_key(),
            "asset create",
        )
        .await;
        let asset_id = confirmed["asset-index"].as_u64().unwrap();

        // Fund the opt-in account with algos to cover its min balance.
        let mut fund = base_txn(&c, &base).await;
        fund.txn_type = TxnType::Pay;
        fund.receiver = opt_addr;
        fund.amount = 1_000_000;
        fund.note = unique_note(&format!("asset-optin-fund-{label}")).into();
        submit_and_confirm(
            &c,
            &base,
            label,
            &mut fund,
            &dev_signing_key(),
            "fund opt-in acct",
        )
        .await;

        // Opt in (zero-amount self transfer).
        let mut optin = base_txn(&c, &base).await;
        optin.sender = opt_addr;
        optin.txn_type = TxnType::Axfer;
        optin.xaid = asset_id;
        optin.asset_receiver = Some(opt_addr);
        optin.amount = 0;
        optin.note = unique_note(&format!("asset-optin-{label}")).into();
        let confirmed =
            submit_and_confirm(&c, &base, label, &mut optin, &opt_sk, "asset opt-in").await;
        let optin_round = confirmed["confirmed-round"].as_u64().unwrap();

        // Close out back to the dev/creator account.
        let mut closeout = base_txn(&c, &base).await;
        closeout.sender = opt_addr;
        closeout.txn_type = TxnType::Axfer;
        closeout.xaid = asset_id;
        closeout.asset_receiver = Some(dev_addr);
        closeout.asset_close_to = Some(dev_addr);
        closeout.amount = 0;
        closeout.note = unique_note(&format!("asset-closeout-{label}")).into();
        let confirmed =
            submit_and_confirm(&c, &base, label, &mut closeout, &opt_sk, "asset close-out").await;
        let closeout_round = confirmed["confirmed-round"].as_u64().unwrap();

        let (status, optin_body) =
            get_json(&c, &base, &format!("/v2/deltas/{optin_round}?format=json")).await;
        assert_eq!(
            status, 200,
            "{label}: opt-in round GET /v2/deltas: {optin_body}"
        );
        let (status, closeout_body) = get_json(
            &c,
            &base,
            &format!("/v2/deltas/{closeout_round}?format=json"),
        )
        .await;
        assert_eq!(
            status, 200,
            "{label}: close-out round GET /v2/deltas: {closeout_body}"
        );

        // Opt-in round: the opted-in account's holding must appear with
        // amount 0, not frozen, not deleted.
        let recs = asset_resources(&optin_body);
        let opt_rec = recs
            .iter()
            .find(|r| r["Aidx"].as_u64() == Some(asset_id))
            .unwrap_or_else(|| {
                panic!("{label}: opt-in round missing AssetResourceRecord for {asset_id}: {recs:?}")
            });
        assert_eq!(opt_rec["Holding"]["Deleted"], serde_json::json!(false));
        // `AssetHoldingRecord.a`'s wire tag has `skip_serializing_if =
        // "is_zero_u64"` (matching go's own short-codec `omitempty`), so a
        // fresh opt-in's zero balance is an *absent* key, not a literal 0.
        assert!(
            opt_rec["Holding"]["Holding"].get("a").is_none(),
            "{label}: fresh opt-in holding must omit `a` at amount 0: {opt_rec}"
        );

        // Close-out round: the account's holding is removed (go-algorand
        // deletes a zero-balance closed-out holding).
        let recs = asset_resources(&closeout_body);
        let close_rec = recs
            .iter()
            .find(|r| r["Aidx"].as_u64() == Some(asset_id))
            .unwrap_or_else(|| {
                panic!(
                    "{label}: close-out round missing AssetResourceRecord for {asset_id}: {recs:?}"
                )
            });
        assert_eq!(
            close_rec["Holding"]["Deleted"],
            serde_json::json!(true),
            "{label}: close-out must remove the closing account's holding: {close_rec}"
        );

        let strip = |mut v: serde_json::Value| {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("Aidx");
                obj.remove("Addr");
            }
            v
        };
        results.insert(label, (strip(opt_rec.clone()), strip(close_rec.clone())));
    }

    let (go_optin, go_closeout) = &results["go"];
    let (rust_optin, rust_closeout) = &results["rust"];
    assert_eq!(
        go_optin, rust_optin,
        "opt-in round AssetResourceRecord (Aidx/Addr stripped) must match between go and rust"
    );
    assert_eq!(
        go_closeout, rust_closeout,
        "close-out round AssetResourceRecord (Aidx/Addr stripped) must match between go and rust"
    );
}

/// Live dual-node verification of `AppResources`/`Creatables` for an app
/// create + update (no inner transactions), including issue #606's
/// `AppParamsRecord.v` field (`0`, omitted, on create; `1` on update).
///
/// **Why this doesn't exercise `block_state_delta_is_complete`'s `Appl`
/// exclusion (issue #604), and isn't expected to:** this harness's
/// algod-rust node runs in `--dev` mode (see `docker/docker-compose.
/// validate-api.yml` / `Makefile`'s `validate-api-up`), and
/// `bin/algod-rust/src/dev_producer.rs`'s self-produced-block path calls
/// `SqliteLedger::cache_state_delta` directly with the `StateDelta` it just
/// computed via a real `ApplyMode::Execute` run -- it never calls
/// `apply_block_caching_delta` (and therefore never consults
/// `block_state_delta_is_complete`) at all. That gate only protects the
/// *sync* path (`bin/algod-rust/src/commands/sync.rs`, replaying blocks
/// received from peers), which this live harness doesn't exercise; the
/// gate's `Appl`-excluding logic itself is unit-tested directly in
/// `algo_ledger::sqlite::tests::test_block_state_delta_is_complete_gate`.
/// Since #586 already made top-level Appl resource-key collection correct
/// (only *inner*-transaction resources are the #604 gap, and this test's
/// create/update have none), algod-rust's dev-mode response for these
/// rounds is expected to be fully correct and is compared field-for-field
/// against go's, just like the Acfg/Axfer tests above.
#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn state_delta_app_resources_matches_go_for_create_update() {
    let c = client();
    let sk = dev_signing_key();

    let approval_v1 = algo_avm::assembler::assemble_string("#pragma version 8\nint 1\nreturn\n")
        .expect("approval v1 must assemble")
        .program;
    let approval_v2 =
        algo_avm::assembler::assemble_string("#pragma version 8\nint 1\nint 1\n==\nreturn\n")
            .expect("approval v2 must assemble")
            .program;

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let mut create = base_txn(&c, &base).await;
        create.txn_type = TxnType::Appl;
        create.approval_program = Some(ByteBuf::from(approval_v1.clone()));
        create.clear_state_program = Some(ByteBuf::from(CLEAR_STATE_PROGRAM.to_vec()));
        create.note = unique_note(&format!("app-resource-create-{label}")).into();
        let confirmed =
            submit_and_confirm(&c, &base, label, &mut create, &sk, "app creation").await;
        let app_id = confirmed["application-index"].as_u64().unwrap();
        let create_round = confirmed["confirmed-round"].as_u64().unwrap();

        let mut update = base_txn(&c, &base).await;
        update.txn_type = TxnType::Appl;
        update.application_id = app_id;
        update.on_completion = 4; // UpdateApplication
        update.approval_program = Some(ByteBuf::from(approval_v2.clone()));
        update.clear_state_program = Some(ByteBuf::from(CLEAR_STATE_PROGRAM.to_vec()));
        update.note = unique_note(&format!("app-resource-update-{label}")).into();
        let confirmed = submit_and_confirm(&c, &base, label, &mut update, &sk, "app update").await;
        let update_round = confirmed["confirmed-round"].as_u64().unwrap();

        let create_body =
            fetch_delta_expect_200(&c, &base, label, create_round, "dev-mode always caches").await;
        let update_body =
            fetch_delta_expect_200(&c, &base, label, update_round, "dev-mode always caches").await;

        let create_recs = create_body["Accts"]["AppResources"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let rec = create_recs
            .iter()
            .find(|r| r["Aidx"].as_u64() == Some(app_id))
            .unwrap_or_else(|| {
                panic!(
                    "{label}: create round missing AppResourceRecord for {app_id}: {create_recs:?}"
                )
            });
        assert_eq!(rec["Params"]["Deleted"], serde_json::json!(false));
        // Issue #606: version omitted (0) on create -- `AppParamsRecord`'s
        // `v` field has `skip_serializing_if = "is_zero_u64"`.
        assert!(
            rec["Params"]["Params"].get("v").is_none(),
            "{label}: create round AppParamsRecord.v must be omitted at 0: {rec}"
        );

        let update_recs = update_body["Accts"]["AppResources"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let rec = update_recs
            .iter()
            .find(|r| r["Aidx"].as_u64() == Some(app_id))
            .unwrap_or_else(|| {
                panic!(
                    "{label}: update round missing AppResourceRecord for {app_id}: {update_recs:?}"
                )
            });
        assert_eq!(rec["Params"]["Deleted"], serde_json::json!(false));
        assert_eq!(
            rec["Params"]["Params"]["v"].as_u64(),
            Some(1),
            "{label}: update round AppParamsRecord.v must be 1 (issue #606): {rec}"
        );

        let creatable = &create_body["Creatables"][app_id.to_string()];
        assert_eq!(creatable["Created"], serde_json::json!(true));
        assert_eq!(creatable["Ctype"], serde_json::json!(1), "1 = app");
    }
}

// ---------------------------------------------------------------------------
// Issue #608: app opt-in/close-out/clear-state/destroy live verification,
// and Axfer/Afrz Put-tracking (widening #603's Acfg-only
// `asset_holding_force_emit` fix).
// ---------------------------------------------------------------------------

/// On-completion constants, matching `algo_ledger::apply`'s
/// `ON_COMPLETION_*` values / go-algorand's `transactions.OnCompletion`.
const OC_OPT_IN: u64 = 1;
const OC_CLOSE_OUT: u64 = 2;
const OC_CLEAR_STATE: u64 = 3;
const OC_DELETE: u64 = 5;

/// An `Appl`-call actor: signing key + its address, bundled together so
/// `submit_appl_call` stays under clippy's `too_many_arguments` threshold.
struct ApplActor<'a> {
    sk: &'a ed25519_dalek::SigningKey,
    addr: algo_types::Address,
}

/// Submits an `Appl` call from `actor` against `app_id` with the given
/// `on_completion`, waits for confirmation, and returns the confirmed round.
async fn submit_appl_call(
    c: &reqwest::Client,
    base: &str,
    label: &str,
    actor: &ApplActor<'_>,
    app_id: u64,
    on_completion: u64,
    note_tag: &str,
) -> u64 {
    let mut txn = base_txn(c, base).await;
    txn.sender = actor.addr;
    txn.txn_type = TxnType::Appl;
    txn.application_id = app_id;
    txn.on_completion = on_completion;
    txn.note = unique_note(&format!("{note_tag}-{label}")).into();
    let confirmed = submit_and_confirm(c, base, label, &mut txn, actor.sk, note_tag).await;
    confirmed["confirmed-round"].as_u64().unwrap()
}

fn app_resource_record<'a>(
    body: &'a serde_json::Value,
    app_id: u64,
    addr: &str,
) -> &'a serde_json::Value {
    body["Accts"]["AppResources"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["Aidx"].as_u64() == Some(app_id) && r["Addr"].as_str() == Some(addr))
        .unwrap_or_else(|| {
            panic!("missing AppResourceRecord for (app {app_id}, addr {addr}) in body: {body}")
        })
}

/// Live dual-node verification for issue #608: an app opt-in / close-out /
/// clear-state / destroy sequence, diffing `AppResources`/`Creatables`
/// field-for-field against go-algorand at each round. #603's own app
/// coverage (`state_delta_app_resources_matches_go_for_create_update`)
/// stopped at create+update; this test covers the four states that were
/// never live-verified.
///
/// Two independent accounts are used for close-out (`acct_b`) and
/// clear-state (`acct_c`) since a single account can't demonstrate both
/// terminal transitions.
#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn state_delta_app_resources_matches_go_for_optin_closeout_clearstate_destroy() {
    let c = client();
    let sk = dev_signing_key();

    let approval = algo_avm::assembler::assemble_string("#pragma version 8\nint 1\nreturn\n")
        .expect("approval must assemble")
        .program;

    // (optin_b, closeout_b, optin_c, clearstate_c, destroy) AppResourceRecord
    // JSON entries per node, with `Aidx`/`Addr` stripped (per-node divergent)
    // so the remaining shape can be compared directly between go and rust.
    type PerNodeEntries = (
        serde_json::Value,
        serde_json::Value,
        serde_json::Value,
        serde_json::Value,
        serde_json::Value,
    );
    let mut results: std::collections::HashMap<&str, PerNodeEntries> =
        std::collections::HashMap::new();

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        // 1. Create the app.
        let mut create = base_txn(&c, &base).await;
        create.txn_type = TxnType::Appl;
        create.approval_program = Some(ByteBuf::from(approval.clone()));
        create.clear_state_program = Some(ByteBuf::from(CLEAR_STATE_PROGRAM.to_vec()));
        create.note = unique_note(&format!("app608-create-{label}")).into();
        let confirmed =
            submit_and_confirm(&c, &base, label, &mut create, &sk, "app creation").await;
        let app_id = confirmed["application-index"].as_u64().unwrap();

        // 2. Fund and opt in `acct_b`, then close it out.
        let b_sk = fresh_account(&format!("app608-b-{label}"));
        let b_addr = algo_types::Address(b_sk.verifying_key().to_bytes());
        let mut fund_b = base_txn(&c, &base).await;
        fund_b.txn_type = TxnType::Pay;
        fund_b.receiver = b_addr;
        fund_b.amount = 1_000_000;
        fund_b.note = unique_note(&format!("app608-fund-b-{label}")).into();
        submit_and_confirm(&c, &base, label, &mut fund_b, &sk, "fund acct_b").await;

        let actor_b = ApplActor {
            sk: &b_sk,
            addr: b_addr,
        };
        let optin_b_round = submit_appl_call(
            &c,
            &base,
            label,
            &actor_b,
            app_id,
            OC_OPT_IN,
            "app608-optin-b",
        )
        .await;
        let closeout_b_round = submit_appl_call(
            &c,
            &base,
            label,
            &actor_b,
            app_id,
            OC_CLOSE_OUT,
            "app608-closeout-b",
        )
        .await;

        // 3. Fund and opt in `acct_c`, then clear-state it.
        let c_sk = fresh_account(&format!("app608-c-{label}"));
        let c_addr = algo_types::Address(c_sk.verifying_key().to_bytes());
        let mut fund_c = base_txn(&c, &base).await;
        fund_c.txn_type = TxnType::Pay;
        fund_c.receiver = c_addr;
        fund_c.amount = 1_000_000;
        fund_c.note = unique_note(&format!("app608-fund-c-{label}")).into();
        submit_and_confirm(&c, &base, label, &mut fund_c, &sk, "fund acct_c").await;

        let actor_c = ApplActor {
            sk: &c_sk,
            addr: c_addr,
        };
        let optin_c_round = submit_appl_call(
            &c,
            &base,
            label,
            &actor_c,
            app_id,
            OC_OPT_IN,
            "app608-optin-c",
        )
        .await;
        let clearstate_c_round = submit_appl_call(
            &c,
            &base,
            label,
            &actor_c,
            app_id,
            OC_CLEAR_STATE,
            "app608-clearstate-c",
        )
        .await;

        // 4. Destroy the app (creator).
        let actor_dev = ApplActor {
            sk: &sk,
            addr: dev_address(),
        };
        let destroy_round = submit_appl_call(
            &c,
            &base,
            label,
            &actor_dev,
            app_id,
            OC_DELETE,
            "app608-destroy",
        )
        .await;

        let optin_b_body =
            fetch_delta_expect_200(&c, &base, label, optin_b_round, "issue #608 opt-in").await;
        let closeout_b_body =
            fetch_delta_expect_200(&c, &base, label, closeout_b_round, "issue #608 close-out")
                .await;
        let optin_c_body =
            fetch_delta_expect_200(&c, &base, label, optin_c_round, "issue #608 opt-in").await;
        let clearstate_c_body = fetch_delta_expect_200(
            &c,
            &base,
            label,
            clearstate_c_round,
            "issue #608 clear-state",
        )
        .await;
        let destroy_body =
            fetch_delta_expect_200(&c, &base, label, destroy_round, "issue #608 destroy").await;

        let b_addr_str = b_addr.to_string();
        let c_addr_str = c_addr.to_string();

        // -- opt-in (b) --
        let rec = app_resource_record(&optin_b_body, app_id, &b_addr_str);
        assert_eq!(rec["State"]["Deleted"], serde_json::json!(false));
        assert!(
            rec["State"]["LocalState"].is_object(),
            "{label}: opt-in round must carry a LocalState record: {rec}"
        );

        // -- close-out (b): local state removed --
        let rec = app_resource_record(&closeout_b_body, app_id, &b_addr_str);
        assert_eq!(
            rec["State"]["Deleted"],
            serde_json::json!(true),
            "{label}: close-out must remove the account's local state: {rec}"
        );
        assert!(rec["State"]["LocalState"].is_null());

        // -- opt-in (c) --
        let rec = app_resource_record(&optin_c_body, app_id, &c_addr_str);
        assert_eq!(rec["State"]["Deleted"], serde_json::json!(false));
        assert!(rec["State"]["LocalState"].is_object());

        // -- clear-state (c): local state removed --
        let rec = app_resource_record(&clearstate_c_body, app_id, &c_addr_str);
        assert_eq!(
            rec["State"]["Deleted"],
            serde_json::json!(true),
            "{label}: clear-state must remove the account's local state: {rec}"
        );
        assert!(rec["State"]["LocalState"].is_null());

        // -- destroy: app params removed, Creatables reflects it --
        let dev_addr_str = dev_address().to_string();
        let rec = app_resource_record(&destroy_body, app_id, &dev_addr_str);
        assert_eq!(
            rec["Params"]["Deleted"],
            serde_json::json!(true),
            "{label}: destroy must remove the app's params: {rec}"
        );
        assert!(rec["Params"]["Params"].is_null());
        let creatable = &destroy_body["Creatables"][app_id.to_string()];
        assert_eq!(
            creatable["Created"],
            serde_json::json!(false),
            "{label}: destroy round Creatables entry: {creatable}"
        );

        let strip = |mut v: serde_json::Value| {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("Aidx");
                obj.remove("Addr");
            }
            v
        };
        results.insert(
            label,
            (
                strip(app_resource_record(&optin_b_body, app_id, &b_addr_str).clone()),
                strip(app_resource_record(&closeout_b_body, app_id, &b_addr_str).clone()),
                strip(app_resource_record(&optin_c_body, app_id, &c_addr_str).clone()),
                strip(app_resource_record(&clearstate_c_body, app_id, &c_addr_str).clone()),
                strip(app_resource_record(&destroy_body, app_id, &dev_addr_str).clone()),
            ),
        );
    }

    let (go_optin_b, go_closeout_b, go_optin_c, go_clearstate_c, go_destroy) = &results["go"];
    let (rust_optin_b, rust_closeout_b, rust_optin_c, rust_clearstate_c, rust_destroy) =
        &results["rust"];
    assert_eq!(
        go_optin_b, rust_optin_b,
        "opt-in (b) AppResourceRecord (Aidx/Addr stripped) must match between go and rust"
    );
    assert_eq!(
        go_closeout_b, rust_closeout_b,
        "close-out (b) AppResourceRecord (Aidx/Addr stripped) must match between go and rust"
    );
    assert_eq!(
        go_optin_c, rust_optin_c,
        "opt-in (c) AppResourceRecord (Aidx/Addr stripped) must match between go and rust"
    );
    assert_eq!(
        go_clearstate_c, rust_clearstate_c,
        "clear-state (c) AppResourceRecord (Aidx/Addr stripped) must match between go and rust"
    );
    assert_eq!(
        go_destroy, rust_destroy,
        "destroy AppResourceRecord (Aidx/Addr stripped) must match between go and rust"
    );
}

/// Live dual-node verification for issue #608's second concern: does
/// go-algorand's `AccountDeltas` "was this resource `Put`"-tracking (see
/// `apply.rs`'s `asset_holding_force_emit` doc comment, issue #603) also
/// apply to Axfer/Afrz-touched holdings, not just Acfg's?
///
/// Two value-identical scenarios, each producing no *net* change to the
/// holding's value while still calling go's `PutAssetHolding` (per
/// `ledger/apply/asset.go`'s `takeOut`/`putIn`/`AssetFreeze`, which call it
/// unconditionally, not gated on whether the value actually changed):
///
/// 1. **Value-identical Axfer**: the dev account (already opted in, holding
///    the full non-zero supply) self-transfers a non-zero amount to itself.
///    `takeOut` then `putIn` both run and both call `PutAssetHolding`, but
///    the net amount is unchanged (X subtracted, X added back).
/// 2. **Value-identical Afrz**: freeze the dev account's own holding to
///    `true`, then freeze it to `true` again (no-op from the caller's
///    perspective, but go's `AssetFreeze` calls `PutAssetHolding`
///    unconditionally every time).
///
/// If go's response still carries the holding record in both cases (the
/// expected finding, given `PutAssetHolding`'s unconditional call sites),
/// this proves `apply.rs`'s widened `asset_holding_force_emit` (populated
/// from `RecordingStore`'s `touches.asset_holdings` for *every* touched key,
/// not just Acfg-derived ones) is required and correct.
#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn state_delta_asset_holding_force_emit_matches_go_for_value_identical_axfer_and_afrz() {
    let c = client();
    let dev_addr = dev_address();
    let dev_addr_str = dev_addr.to_string();

    type PerNodeEntries = (serde_json::Value, serde_json::Value);
    let mut results: std::collections::HashMap<&str, PerNodeEntries> =
        std::collections::HashMap::new();

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let sk = dev_signing_key();

        // Create the asset (dev holds full supply, is its own freeze addr).
        let mut create = base_txn(&c, &base).await;
        create.txn_type = TxnType::Acfg;
        create.asset_params = Some(AssetParams {
            total: ASSET_TOTAL,
            unit_name: ASSET_UNIT_NAME.to_string(),
            asset_name: ASSET_NAME.to_string(),
            manager: Some(dev_addr),
            reserve: Some(dev_addr),
            freeze: Some(dev_addr),
            clawback: Some(dev_addr),
            ..Default::default()
        });
        create.note = unique_note(&format!("axferafrz608-create-{label}")).into();
        let confirmed =
            submit_and_confirm(&c, &base, label, &mut create, &sk, "asset create").await;
        let asset_id = confirmed["asset-index"].as_u64().unwrap();

        // 1. Value-identical Axfer: self-transfer a non-zero amount.
        let mut selfxfer = base_txn(&c, &base).await;
        selfxfer.txn_type = TxnType::Axfer;
        selfxfer.xaid = asset_id;
        selfxfer.asset_receiver = Some(dev_addr);
        selfxfer.asset_amount = 1_000;
        selfxfer.note = unique_note(&format!("axferafrz608-selfxfer-{label}")).into();
        let confirmed =
            submit_and_confirm(&c, &base, label, &mut selfxfer, &sk, "self-transfer").await;
        let selfxfer_round = confirmed["confirmed-round"].as_u64().unwrap();

        // 2a. First freeze: true -> true (already unfrozen -> now frozen;
        // establishes a known Frozen=true baseline).
        let mut freeze1 = base_txn(&c, &base).await;
        freeze1.txn_type = TxnType::Afrz;
        freeze1.freeze_asset = asset_id;
        freeze1.freeze_account = Some(dev_addr);
        freeze1.asset_frozen = true;
        freeze1.note = unique_note(&format!("axferafrz608-freeze1-{label}")).into();
        submit_and_confirm(&c, &base, label, &mut freeze1, &sk, "freeze (baseline)").await;

        // 2b. Second freeze: true -> true again -- value-identical from the
        // holding's perspective, but go's AssetFreeze still calls
        // PutAssetHolding unconditionally.
        let mut freeze2 = base_txn(&c, &base).await;
        freeze2.txn_type = TxnType::Afrz;
        freeze2.freeze_asset = asset_id;
        freeze2.freeze_account = Some(dev_addr);
        freeze2.asset_frozen = true;
        freeze2.note = unique_note(&format!("axferafrz608-freeze2-{label}")).into();
        let confirmed = submit_and_confirm(
            &c,
            &base,
            label,
            &mut freeze2,
            &sk,
            "freeze (value-identical)",
        )
        .await;
        let freeze2_round = confirmed["confirmed-round"].as_u64().unwrap();

        let selfxfer_body = fetch_delta_expect_200(
            &c,
            &base,
            label,
            selfxfer_round,
            "issue #608 value-identical axfer",
        )
        .await;
        let freeze2_body = fetch_delta_expect_200(
            &c,
            &base,
            label,
            freeze2_round,
            "issue #608 value-identical afrz",
        )
        .await;

        // Self-transfer round: go's response still carries the holding
        // record for the dev account, with its (unchanged) amount.
        let rec = asset_resources(&selfxfer_body)
            .into_iter()
            .find(|r| {
                r["Aidx"].as_u64() == Some(asset_id) && r["Addr"].as_str() == Some(&dev_addr_str)
            })
            .unwrap_or_else(|| {
                panic!(
                    "{label}: value-identical self-transfer round missing AssetResourceRecord for \
                     (asset {asset_id}, addr {dev_addr_str}): {selfxfer_body}"
                )
            });
        assert_eq!(rec["Holding"]["Deleted"], serde_json::json!(false));
        assert_eq!(
            rec["Holding"]["Holding"]["a"].as_u64(),
            Some(ASSET_TOTAL),
            "{label}: self-transfer round's holding amount must be unchanged \
             (net zero) but still present: {rec}"
        );

        // Second-freeze round: go's response still carries the holding
        // record even though Frozen stays `true` across both freeze calls.
        let frec = asset_resources(&freeze2_body)
            .into_iter()
            .find(|r| {
                r["Aidx"].as_u64() == Some(asset_id) && r["Addr"].as_str() == Some(&dev_addr_str)
            })
            .unwrap_or_else(|| {
                panic!(
                    "{label}: value-identical re-freeze round missing AssetResourceRecord for \
                     (asset {asset_id}, addr {dev_addr_str}): {freeze2_body}"
                )
            });
        assert_eq!(frec["Holding"]["Deleted"], serde_json::json!(false));
        assert_eq!(
            frec["Holding"]["Holding"]["f"],
            serde_json::json!(true),
            "{label}: re-freeze round's holding must still show Frozen=true \
             (unchanged from before) but still present: {frec}"
        );

        let strip = |mut v: serde_json::Value| {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("Aidx");
                obj.remove("Addr");
            }
            v
        };
        results.insert(label, (strip(rec), strip(frec)));
    }

    let (go_xfer, go_freeze) = &results["go"];
    let (rust_xfer, rust_freeze) = &results["rust"];
    assert_eq!(
        go_xfer, rust_xfer,
        "value-identical self-transfer AssetResourceRecord must match between go and rust"
    );
    assert_eq!(
        go_freeze, rust_freeze,
        "value-identical re-freeze AssetResourceRecord must match between go and rust"
    );
}

// ---------------------------------------------------------------------------
// Issue #612: genuine sync-path live verification (algod-rust `--follow`,
// syncing from go-algorand, vs the `--dev` nodes every other test above
// uses). See the module docs' "Issue #612" section for why this needed a
// third harness node.
// ---------------------------------------------------------------------------

fn sync_url() -> String {
    std::env::var("ALGOD_RUST_SYNC_URL").unwrap_or_else(|_| "http://127.0.0.1:4003".to_string())
}

/// Polls the `--follow` node's `/v2/status` until its `last-round` reaches
/// at least `round`, bounded by `deadline`. This is the live proof that
/// the node is actually syncing new blocks from its peer over its own
/// independent REST poll loop (`commands/node.rs::run_follow_loop`) --
/// before #609/#613's fix, the round could show up as synced yet still
/// 404 on `/v2/deltas/{round}` (the old gate excluded `Appl` blocks from
/// the delta cache); after #604, a stale `Replay`-mode apply of an `Appl`
/// block could diverge from go entirely. This helper only waits for the
/// round to be *seen*; the delta comparison below is what actually
/// exercises those fixed paths.
async fn wait_for_sync_round(c: &reqwest::Client, round: u64, deadline: std::time::Instant) {
    loop {
        let (status, body) = get_json(c, &sync_url(), "/v2/status").await;
        if status == 200 {
            if let Some(last) = body["last-round"].as_u64() {
                if last >= round {
                    return;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "algod-rust --follow node (issue #612) did not sync round {round} before \
                 deadline (last status {status}, body {body}) -- is `node start --follow` \
                 running on {}? (see Makefile's validate-api-up)",
                sync_url()
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Live sync-path verification for issue #612.
///
/// Unlike every other test in this file (each of which submits
/// independently to `go_url()` and `rust_url()` -- two `--dev` nodes each
/// building their own chain from the shared genesis, requiring the
/// per-side key-stripped comparison this file's module docs explain), this
/// test submits ONLY to `go_url()`. It then waits for a third algod-rust
/// process -- started with `node start --follow http://localhost:4001`
/// (see `Makefile`'s `validate-api-up`,
/// `commands/node.rs::run_follow_loop`) -- to genuinely sync that same
/// block over its own REST poll of go, through the real sync-path call
/// (`SqliteLedger::apply_block_caching_delta`, the exact function
/// `commands/sync.rs` calls per received block; `--dev` mode never calls
/// it at all). Both nodes then serve `GET /v2/deltas/{round}` for the
/// *same* round of the *same* chain, so this is a strict, unstripped
/// comparison, not the per-side one the rest of this file needs.
///
/// Deploys the same itxn-issuing app as `algo_ledger::apply`'s
/// `issue_604_inner_acfg_create_populates_asset_resources_and_creatables` /
/// `sqlite::apply_block_caching_delta_caches_full_delta_for_appl_with_inner_acfg`:
/// approve on create, `itxn_submit` an inner `acfg` (asset create) on any
/// later call -- so the round under comparison is exactly the shape
/// #609/#613 fixed sync-path attribution for.
#[tokio::test]
#[ignore = "requires `make validate-api-up` (needs the --follow node on :4003); see module docs"]
async fn state_delta_appl_inner_txn_matches_go_through_real_sync_path() {
    let c = client();
    let sk = dev_signing_key();
    let go = go_url();
    let dev_addr_str = dev_address().to_string();

    let approval_src = "#pragma version 6\n\
        txn ApplicationID\n\
        bz approve\n\
        itxn_begin\n\
        int acfg\n\
        itxn_field TypeEnum\n\
        int 1000000\n\
        itxn_field ConfigAssetTotal\n\
        int 0\n\
        itxn_field ConfigAssetDecimals\n\
        byte \"UNIT\"\n\
        itxn_field ConfigAssetUnitName\n\
        byte \"Asset\"\n\
        itxn_field ConfigAssetName\n\
        itxn_submit\n\
        approve:\n\
        int 1\n\
        return\n";
    let approval = algo_avm::assembler::assemble_string(approval_src)
        .expect("approval program must assemble")
        .program;

    // 1. Create the app on go ONLY -- the syncing node has no submit
    // capability of its own; it only ever consumes go's blocks.
    let mut create = base_txn(&c, &go).await;
    create.txn_type = TxnType::Appl;
    create.approval_program = Some(ByteBuf::from(approval));
    create.clear_state_program = Some(ByteBuf::from(CLEAR_STATE_PROGRAM.to_vec()));
    create.note = unique_note("issue612-appl-create").into();
    let confirmed = submit_and_confirm(&c, &go, "go", &mut create, &sk, "app creation").await;
    let app_id = confirmed["application-index"].as_u64().unwrap_or_else(|| {
        panic!("go: confirmed app creation must report application-index: {confirmed}")
    });

    // 2. Fund the app account so its inner acfg can cover the asset's MBR.
    let app_addr = algo_types::Address(algo_ledger::avm_context::app_address(app_id));
    let mut fund = base_txn(&c, &go).await;
    fund.txn_type = TxnType::Pay;
    fund.receiver = app_addr;
    fund.amount = 1_000_000;
    fund.note = unique_note("issue612-appl-fund").into();
    submit_and_confirm(&c, &go, "go", &mut fund, &sk, "app funding").await;

    // 3. Call the app -- its approval program itxn_submits an inner acfg.
    let mut call = base_txn(&c, &go).await;
    call.txn_type = TxnType::Appl;
    call.application_id = app_id;
    call.note = unique_note("issue612-appl-call").into();
    let confirmed =
        submit_and_confirm(&c, &go, "go", &mut call, &sk, "app call (inner acfg)").await;
    let call_round = confirmed["confirmed-round"].as_u64().unwrap();
    let inner_txns = confirmed["inner-txns"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        inner_txns.len(),
        1,
        "go: app call must report exactly one inner txn: {confirmed}"
    );
    let created_asset_id = inner_txns[0]["asset-index"]
        .as_u64()
        .unwrap_or_else(|| panic!("go: inner acfg must report asset-index: {confirmed}"));

    // 4. Wait for the syncing --follow node to genuinely apply this round
    //    over its own independent REST poll of go.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    wait_for_sync_round(&c, call_round, deadline).await;

    // 5. Compare GET /v2/deltas/{call_round} between go and the syncing
    //    rust node for the SAME round of the SAME chain -- a full-body
    //    comparison is meaningful here (unlike the rest of this file)
    //    because both nodes now describe literally the same block, same
    //    app id, same inner-created asset id.
    let go_body = fetch_delta_expect_200(&c, &go, "go", call_round, "issue #612 sync path").await;
    let sync_body = fetch_delta_expect_200(
        &c,
        &sync_url(),
        "rust-sync",
        call_round,
        "issue #612 sync path",
    )
    .await;

    // 5a. The app-call AppResourceRecord (attributed to the dev account,
    // the outer call's sender) must match field-for-field.
    let go_app_rec = app_resource_record(&go_body, app_id, &dev_addr_str);
    let sync_app_rec = app_resource_record(&sync_body, app_id, &dev_addr_str);
    assert_eq!(
        go_app_rec, sync_app_rec,
        "AppResourceRecord for the calling app must match between go and the syncing rust node"
    );

    // 5b. The inner acfg's AssetResourceRecord -- attributed to the APP
    // account (the inner txn's implicit sender), not the outer call's
    // sender; this is exactly the attribution issue #604/#609 fixed. Must
    // match field-for-field, including the app address as Addr.
    let app_addr_str = app_addr.to_string();
    let go_asset_rec = asset_resources(&go_body)
        .into_iter()
        .find(|r| r["Aidx"].as_u64() == Some(created_asset_id))
        .unwrap_or_else(|| {
            panic!("go: missing AssetResourceRecord for inner-created asset {created_asset_id}: {go_body}")
        });
    let sync_asset_rec = asset_resources(&sync_body)
        .into_iter()
        .find(|r| r["Aidx"].as_u64() == Some(created_asset_id))
        .unwrap_or_else(|| {
            panic!(
                "rust-sync: missing AssetResourceRecord for inner-created asset \
                 {created_asset_id} -- this is exactly the sync-path gap #609/#613 fixed: {sync_body}"
            )
        });
    assert_eq!(
        go_asset_rec["Addr"].as_str(),
        Some(app_addr_str.as_str()),
        "go: inner acfg's AssetResourceRecord must be attributed to the app account: {go_asset_rec}"
    );
    assert_eq!(
        go_asset_rec, sync_asset_rec,
        "inner-created asset's AssetResourceRecord must match between go and the syncing rust node"
    );

    // 5c. Both Creatables entries (the app itself and the inner-created
    // asset) must match too.
    let go_app_creatable = &go_body["Creatables"][app_id.to_string()];
    let sync_app_creatable = &sync_body["Creatables"][app_id.to_string()];
    assert_eq!(
        go_app_creatable, sync_app_creatable,
        "app Creatables entry must match between go and the syncing rust node"
    );
    let go_asset_creatable = &go_body["Creatables"][created_asset_id.to_string()];
    let sync_asset_creatable = &sync_body["Creatables"][created_asset_id.to_string()];
    assert_eq!(
        go_asset_creatable, sync_asset_creatable,
        "inner-created asset's Creatables entry must match between go and the syncing rust node"
    );
}
