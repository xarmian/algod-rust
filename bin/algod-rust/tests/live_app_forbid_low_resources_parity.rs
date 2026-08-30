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

//! Live dual-node verification of `AppForbidLowResources` (issue #760,
//! follow-up to #747/PR #759's deferred acceptance criterion #1).
//!
//! PR #759 added go-algorand v38's `AppForbidLowResources` low-id
//! restriction (`crates/core/algo-ledger/src/avm_context.rs`'s
//! `check_forbidden_low_resource`, gated by
//! `ConsensusParams::app_forbid_low_resources`) but verified it only with
//! targeted unit tests constructing an `EvalContext` directly -- never
//! end-to-end against a real running go-algorand node.
//!
//! This file closes that gap for the *post*-v38 side: this harness's shared
//! genesis pins a single fixed (current) consensus version -- V42, itself
//! long past v38 -- so it cannot exercise the *pre*-v38 branch (that side is
//! already covered by the hand-constructed V37 unit test
//! `low_resource_ids_allowed_before_app_forbid_low_resources` in
//! `avm_context.rs`, using this repo's own historical `ConsensusParams`
//! table -- no live node needed or able to reach a retired protocol
//! version). What a live node genuinely adds is: does algod-rust's
//! `AppForbidLowResources` REJECT decision (and its exact error text) match
//! a real go-algorand v5.0.0-stable node's, for a transaction that
//! *directly names* (as an AVM "available" reference, not merely a
//! non-existent id) an asset id <= 255 -- the boundary condition that
//! matters is the numeric value of the *resolved* id, not whether that
//! asset actually exists on chain (`data/transactions/logic/eval.go`'s
//! `resolveAsset`: the low-id check runs in a `defer` on every successfully
//! resolved id, before any existence check).
//!
//! Both nodes' fresh V42 genesis starts `TxnCounter` at 1000 (see
//! `avm_context.rs`'s own genesis docs), so no asset/app actually created on
//! either chain can ever have an id <= 255 -- this test instead lists a
//! deliberately-fabricated low id in `foreign_assets`, which go's
//! `availableAsset` (and algod-rust's `resolve_asset_unchecked`) treats as a
//! *direct reference* regardless of whether that asset was ever created.
//!
//! ```text
//! make validate-api-up
//! cargo test --package algod-rust --test live_app_forbid_low_resources_parity \
//!   -- --ignored --nocapture --test-threads=1
//! make validate-api-down
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use algo_codec::{canonical_encode_transaction, compute_txn_id};
use algo_types::{Round, SignedTransaction, TxnType};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ed25519_dalek::Signer;
use serde_bytes::ByteBuf;

const DEV_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// `docs/DEV_WORKFLOW.md`'s funded dev account (25-word mnemonic).
const DEV_MNEMONIC: &str = "under this above produce during card issue fire gloom reopen topple rough cat smooth salad put broken decade vocal loud pulp gauge hurdle absorb olympic";

/// Approval program: on creation (`NumAppArgs == 0`) just approves. On a
/// call with exactly 1 app arg (a big-endian-uint64-encoded asset id), reads
/// that id via `asset_params_get AssetTotal` -- exercising real
/// `resolveAsset` (Go) / `resolve_asset` (Rust) opcode-level resolution --
/// then approves regardless of the field-get result (existence is
/// irrelevant to this test; only whether the *resolution itself* was
/// rejected as a forbidden low id matters).
const APPROVAL_SOURCE: &str = r#"#pragma version 8
txn NumAppArgs
int 1
==
bz done
txna ApplicationArgs 0
btoi
asset_params_get AssetTotal
pop
pop
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
    format!("live_app_forbid_low_resources_parity:{tag}:{nanos}").into_bytes()
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

    let genesis_hash_bytes = base64_decode(params["genesis-hash"].as_str().unwrap());
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

/// POST a signed transaction, transparently retrying while a just-booted
/// dev-mode node reports its transient pool error. Same rationale as
/// `live_txn_cross_verification.rs::submit`.
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

async fn wait_for_confirmation(
    client: &reqwest::Client,
    base: &str,
    txid: &str,
    deadline: std::time::Instant,
) {
    loop {
        let resp = client
            .get(format!("{base}/v2/transactions/pending/{txid}"))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        if status == 200 && body["confirmed-round"].as_u64().unwrap_or(0) > 0 {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("txid {txid} on {base} did not confirm before deadline (last status {status}, body {body})");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Deploys `APPROVAL_SOURCE` on `base`, returning its app id.
async fn deploy_app(client: &reqwest::Client, base: &str, label: &str) -> u64 {
    let sk = dev_signing_key();
    let approval = algo_avm::assembler::assemble_string(APPROVAL_SOURCE)
        .unwrap_or_else(|e| panic!("{label}: approval program failed to assemble: {e:?}"))
        .program;

    let mut create = base_txn(client, base).await;
    create.txn_type = TxnType::Appl;
    create.approval_program = Some(ByteBuf::from(approval));
    create.clear_state_program = Some(ByteBuf::from(CLEAR_STATE_PROGRAM.to_vec()));
    create.note = unique_note(&format!("app-create-{label}")).into();
    let txid = compute_txn_id(&create).to_string();
    let stx = sign(&mut create, &sk);
    let resp = submit(client, base, &encode(&stx)).await;
    assert_eq!(
        resp.status,
        200,
        "{label}: app creation rejected: {}",
        resp.text()
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    wait_for_confirmation(client, base, &txid, deadline).await;

    let resp = client
        .get(format!("{base}/v2/transactions/pending/{txid}"))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    body["application-index"].as_u64().unwrap_or_else(|| {
        panic!("{label}: confirmed app creation must report application-index: {body}")
    })
}

/// Calls `app_id` on `base` with a single app arg (`asset_id` as a
/// big-endian uint64) and that same id listed in `foreign_assets` -- a
/// direct AVM reference, "available" regardless of whether the asset
/// actually exists. Returns the raw submit response (never waits for
/// confirmation, since the forbidden-id case never confirms).
async fn call_with_asset_reference(
    client: &reqwest::Client,
    base: &str,
    app_id: u64,
    asset_id: u64,
) -> SubmitResult {
    let sk = dev_signing_key();
    let mut call = base_txn(client, base).await;
    call.txn_type = TxnType::Appl;
    call.application_id = app_id;
    call.app_arguments = Some(vec![Some(ByteBuf::from(asset_id.to_be_bytes().to_vec()))]);
    call.foreign_assets = Some(vec![asset_id]);
    call.note = unique_note(&format!("call-{base}-{asset_id}")).into();
    let stx = sign(&mut call, &sk);
    submit(client, base, &encode(&stx)).await
}

// ---------------------------------------------------------------------------

/// Fast, always-run (not `#[ignore]`d) regression test: pins that
/// `APPROVAL_SOURCE` actually assembles, so a TEAL syntax mistake fails in
/// default `cargo test --workspace`, not only when the ignored live suite
/// happens to run.
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
async fn low_asset_id_reference_rejected_identically_on_both_nodes() {
    let c = client();

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let app_id = deploy_app(&c, &base, label).await;

        // A forbidden low id (<= 255, go-algorand's `lastForbiddenResource`)
        // must be rejected at submission (the AVM error surfaces as a logic
        // eval failure during simulate-at-submit / pool add, matching a
        // `LogicSigError`/approval-reject on both implementations).
        let low_resp = call_with_asset_reference(&c, &base, app_id, 5).await;
        assert_ne!(
            low_resp.status,
            200,
            "{label}: referencing forbidden low asset id 5 must be rejected, got 200: {}",
            low_resp.text()
        );
        let low_text = low_resp.text();
        assert!(
            low_text.contains("low Asset lookup 5"),
            "{label}: rejection must cite go-algorand's exact \
             `resolveAsset` error text \"low Asset lookup 5\" \
             (data/transactions/logic/eval.go), got: {low_text}"
        );

        // A high, non-forbidden id must NOT trip the same check -- it's
        // still not a real asset, so `asset_params_get` legitimately
        // reports non-existence (exists=0) rather than erroring, and the
        // call confirms normally. This is the control case proving the
        // low-id check is what rejected the id=5 call above, not something
        // incidental about the transaction shape.
        const HIGH_ID: u64 = 999_999_999;
        let high_resp = call_with_asset_reference(&c, &base, app_id, HIGH_ID).await;
        assert_eq!(
            high_resp.status,
            200,
            "{label}: referencing non-forbidden high asset id {HIGH_ID} must be accepted, got: {}",
            high_resp.text()
        );
    }
}
