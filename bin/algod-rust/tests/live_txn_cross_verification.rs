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

//! Live dual-node transaction submission cross-verification (issue #449).
//!
//! Extends `live_go_parity.rs`'s dual-node harness (see that file's module
//! docs for setup) with real signed-transaction submission. Since each node
//! runs its **own** independent dev-mode chain (no shared consensus between
//! them), "cross-verification" here means *same input ⇒ same observable
//! behavior on each node* — same computed txid, same acceptance/rejection
//! outcome, same resulting state on that node's own ledger — not literally
//! shared chain state.
//!
//! Uses the funded dev account baked into the shared genesis
//! (`docker/localnet-rust/data/genesis.json`; mnemonic in
//! `docs/DEV_WORKFLOW.md`) as the only account both nodes start with a
//! nonzero balance for.
//!
//! # Serialization requirement
//!
//! Every test here mutates the dev account's on-chain state (balance,
//! pending pool) on both live nodes. Running them concurrently would race:
//! one test's "before" balance snapshot could observe another test's
//! in-flight submission. Run with `--test-threads=1`:
//!
//! ```text
//! make validate-api-up
//! cargo test --package algod-rust --test live_txn_cross_verification \
//!   -- --ignored --nocapture --test-threads=1
//! make validate-api-down
//! ```
//!
//! `make validate-api` already serializes correctly since each live test
//! *binary* Cargo builds runs to completion before the next starts; only
//! tests *within* this file need explicit serialization.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use algo_codec::{canonical_encode_transaction, compute_txn_id};
use algo_types::{AssetParams, Round, SignedTransaction, TxnType};
use ed25519_dalek::Signer;

const DEV_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// `docs/DEV_WORKFLOW.md`'s funded dev account (25-word mnemonic).
const DEV_MNEMONIC: &str = "under this above produce during card issue fire gloom reopen topple rough cat smooth salad put broken decade vocal loud pulp gauge hurdle absorb olympic";

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

/// A monotonically-distinct note payload so repeated test runs against a
/// freshly-booted harness never collide on an identical previously-seen
/// txid within a single test process (each note byte string is unique per
/// call, combining the call site tag with a nanosecond timestamp).
fn unique_note(tag: &str) -> Vec<u8> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("live_txn_cross_verification:{tag}:{nanos}").into_bytes()
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

/// A base transaction template pre-filled with the dev account's suggested
/// params fetched live from `base`, so first-valid/last-valid, fee, and
/// genesis fields are always consistent with whatever round that node is
/// actually on -- a wide 1000-round validity window (matching
/// `tx_propagation_two_binary.rs`'s pattern) means later tests in this file
/// never race a prior test's block production off the window.
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

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    STANDARD.decode(s).expect("valid base64")
}

/// Result of [`submit`]: status code plus the raw response body (already
/// consumed from the underlying `reqwest::Response`, since the retry loop
/// below needs to inspect it either way).
struct SubmitResult {
    status: u16,
    body: Vec<u8>,
}

impl SubmitResult {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// POST a signed transaction. Transparently retries while go-algorand's
/// dev-mode node reports its transient just-booted "no pending block
/// evaluator" pool error (`TransactionPool.Remember: TransactionPool.ingest:
/// no pending block evaluator`) -- observed live immediately after
/// `algod-go-shared`'s healthcheck passes, before its pool's block
/// evaluator has finished initializing. This is a boot-timing artifact of
/// the harness, not a code path any of this file's tests are trying to
/// exercise, so retrying transparently (rather than working around it in
/// every call site, or asserting on it) keeps each test's actual assertion
/// about the *real* status/message it cares about.
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

/// Poll `/v2/transactions/pending/{txid}` until it reports a nonzero
/// `confirmed-round` (dev-mode confirms almost immediately -- one block per
/// submitted group) or the deadline passes.
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

async fn account_balance(client: &reqwest::Client, base: &str, addr: &str) -> u64 {
    let (status, body) = get_json(client, base, &format!("/v2/accounts/{addr}")).await;
    assert_eq!(status, 200, "GET /v2/accounts/{addr} on {base}: {body}");
    body["amount"].as_u64().unwrap()
}

// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn transaction_params_field_parity() {
    let c = client();
    let go: serde_json::Value = c
        .get(format!("{}/v2/transactions/params", go_url()))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rust: serde_json::Value = c
        .get(format!("{}/v2/transactions/params", rust_url()))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    for field in ["genesis-hash", "genesis-id", "min-fee"] {
        assert_eq!(
            go[field], rust[field],
            "/v2/transactions/params.{field} must match between go and rust"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn payment_accepted_and_confirmed_matches() {
    let c = client();
    let dev = dev_address().to_algorand_string();

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let mut txn = base_txn(&c, &base).await;
        txn.txn_type = TxnType::Pay;
        txn.receiver = dev_address();
        txn.amount = 1000;
        txn.note = unique_note(&format!("payment-{label}")).into();
        let sk = dev_signing_key();
        let expected_txid = compute_txn_id(&txn).to_string();
        let stx = sign(&mut txn, &sk);
        let bytes = encode(&stx);

        let before = account_balance(&c, &base, &dev).await;

        let resp = submit(&c, &base, &bytes).await;
        assert_eq!(
            resp.status,
            200,
            "{label}: POST /v2/transactions rejected a well-formed payment: {}",
            resp.text()
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let pending = wait_for_confirmation(&c, &base, &expected_txid, deadline).await;
        assert_eq!(
            pending["txn"]["txn"]["fee"].as_u64(),
            Some(txn_fee_used()),
            "{label}: confirmed pending-info fee must reflect the submitted transaction"
        );

        // Self-payment: balance changes only by the fee (paid to the fee
        // sink), not by the payment amount (sender == receiver).
        let after = account_balance(&c, &base, &dev).await;
        assert!(
            after < before,
            "{label}: self-payment must still deduct the fee (before={before} after={after})"
        );
    }
}

/// The fee `base_txn` assigns (kept in sync with `payment_accepted_and_confirmed_matches`).
fn txn_fee_used() -> u64 {
    1000
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn payment_txid_is_identical_across_nodes_for_identical_input() {
    // Build ONE signed transaction and submit the exact same bytes to both
    // nodes -- proves the two implementations compute the same txid for
    // the same input, not just that each is internally consistent.
    let c = client();
    let mut txn = base_txn(&c, &go_url()).await;
    // Since the two nodes run independent chains, each has already advanced
    // to a different current round by the time earlier tests in this file
    // have run (dev-mode confirms almost instantly, but not identically on
    // both sides). A validity window built from *one* node's current round
    // can already be in the *other* node's past-or-future by submission
    // time -- pin it to the always-valid [1, 1000] window instead (same
    // pattern `tx_propagation_two_binary.rs` uses) so this test only
    // exercises what it's actually meant to: that both implementations
    // compute the same txid for the same input, not round-window timing.
    txn.first_valid = Round(1);
    txn.last_valid = Round(1000);
    txn.txn_type = TxnType::Pay;
    txn.receiver = dev_address();
    txn.amount = 0;
    txn.note = unique_note("identical-txid").into();
    let sk = dev_signing_key();
    let expected_txid = compute_txn_id(&txn).to_string();
    let stx = sign(&mut txn, &sk);
    let bytes = encode(&stx);

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = submit(&c, &base, &bytes).await;
        assert_eq!(
            resp.status,
            200,
            "{label}: submission rejected: {}",
            resp.text()
        );
        let body: serde_json::Value = resp.json();
        assert_eq!(
            body["txId"].as_str(),
            Some(expected_txid.as_str()),
            "{label}: returned txId must match the txid computed from the shared input"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn rejected_fee_below_minimum_matches() {
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let mut txn = base_txn(&c, &base).await;
        txn.txn_type = TxnType::Pay;
        txn.receiver = dev_address();
        txn.amount = 0;
        txn.fee = 0; // below MinTxnFee
        txn.note = unique_note(&format!("low-fee-{label}")).into();
        let sk = dev_signing_key();
        let stx = sign(&mut txn, &sk);
        let bytes = encode(&stx);

        let resp = submit(&c, &base, &bytes).await;
        assert_eq!(
            resp.status, 400,
            "{label}: a below-minimum fee must be rejected with 400"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn rejected_invalid_signature_matches() {
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let mut txn = base_txn(&c, &base).await;
        txn.txn_type = TxnType::Pay;
        txn.receiver = dev_address();
        txn.amount = 0;
        txn.note = unique_note(&format!("bad-sig-{label}")).into();
        // Sign with an unrelated key so the signature does not verify
        // against `txn.sender` (the dev account).
        let wrong_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let stx = sign(&mut txn, &wrong_key);
        let bytes = encode(&stx);

        let resp = submit(&c, &base, &bytes).await;
        assert_eq!(
            resp.status, 400,
            "{label}: an invalid signature must be rejected with 400"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn rejected_wrong_genesis_hash_matches() {
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let mut txn = base_txn(&c, &base).await;
        txn.txn_type = TxnType::Pay;
        txn.receiver = dev_address();
        txn.amount = 0;
        txn.genesis_hash = [0xEE; 32]; // deliberately wrong
        txn.note = unique_note(&format!("bad-genesis-{label}")).into();
        let sk = dev_signing_key();
        let stx = sign(&mut txn, &sk);
        let bytes = encode(&stx);

        let resp = submit(&c, &base, &bytes).await;
        assert_eq!(
            resp.status, 400,
            "{label}: a mismatched genesis hash must be rejected with 400"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn rejected_malformed_msgpack_body_matches() {
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let garbage: &[u8] = b"\xff\xff\xff not valid msgpack at all";
        let resp = submit(&c, &base, garbage).await;
        assert_eq!(
            resp.status, 400,
            "{label}: a malformed msgpack body must be rejected with 400"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn rejected_duplicate_submission_matches() {
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let mut txn = base_txn(&c, &base).await;
        txn.txn_type = TxnType::Pay;
        txn.receiver = dev_address();
        txn.amount = 0;
        txn.note = unique_note(&format!("dup-{label}")).into();
        let sk = dev_signing_key();
        let expected_txid = compute_txn_id(&txn).to_string();
        let stx = sign(&mut txn, &sk);
        let bytes = encode(&stx);

        let first = submit(&c, &base, &bytes).await;
        assert_eq!(
            first.status, 200,
            "{label}: first submission must be accepted"
        );

        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        wait_for_confirmation(&c, &base, &expected_txid, deadline).await;

        // Resubmitting the exact same signed bytes after confirmation must
        // be rejected (already committed to the ledger).
        let second = submit(&c, &base, &bytes).await;
        assert_eq!(
            second.status, 400,
            "{label}: resubmitting an already-confirmed transaction must be rejected with 400"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn asset_create_and_transfer_accepted_and_confirmed_matches() {
    let c = client();
    let dev = dev_address().to_algorand_string();

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        // 1. Create a small fungible asset, entirely held by the dev
        //    account (default distribution: creator receives `total`).
        let mut create = base_txn(&c, &base).await;
        create.txn_type = TxnType::Acfg;
        create.note = unique_note(&format!("asset-create-{label}")).into();
        create.asset_params = Some(AssetParams {
            total: 1_000_000,
            decimals: 0,
            default_frozen: false,
            unit_name: "TST".to_string(),
            asset_name: "Test Asset".to_string(),
            manager: Some(dev_address()),
            reserve: Some(dev_address()),
            freeze: Some(dev_address()),
            clawback: Some(dev_address()),
            ..Default::default()
        });
        let sk = dev_signing_key();
        let create_txid = compute_txn_id(&create).to_string();
        let stx = sign(&mut create, &sk);
        let bytes = encode(&stx);

        let resp = submit(&c, &base, &bytes).await;
        assert_eq!(
            resp.status,
            200,
            "{label}: asset creation rejected: {}",
            resp.text()
        );

        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let confirmed = wait_for_confirmation(&c, &base, &create_txid, deadline).await;
        let asset_id = confirmed["asset-index"].as_u64().unwrap_or_else(|| {
            panic!("{label}: confirmed asset creation must report asset-index: {confirmed}")
        });

        // 2. Self-transfer a fraction of the newly created asset (the dev
        //    account is already implicitly opted in as the creator).
        let mut transfer = base_txn(&c, &base).await;
        transfer.txn_type = TxnType::Axfer;
        transfer.xaid = asset_id;
        transfer.asset_amount = 10;
        transfer.asset_receiver = Some(dev_address());
        transfer.note = unique_note(&format!("asset-transfer-{label}")).into();
        let transfer_txid = compute_txn_id(&transfer).to_string();
        let stx = sign(&mut transfer, &sk);
        let bytes = encode(&stx);

        let resp = submit(&c, &base, &bytes).await;
        assert_eq!(
            resp.status,
            200,
            "{label}: asset transfer rejected: {}",
            resp.text()
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        wait_for_confirmation(&c, &base, &transfer_txid, deadline).await;

        // 3. Both the created asset and the holding must be visible via
        //    the account endpoint.
        let (status, account) = get_json(&c, &base, &format!("/v2/accounts/{dev}")).await;
        assert_eq!(status, 200);
        assert!(
            account["total-created-assets"].as_u64().unwrap_or(0) >= 1,
            "{label}: account must report the created asset: {account}"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn app_create_and_call_accepted_and_confirmed_matches() {
    let c = client();
    let dev = dev_address().to_algorand_string();
    // Minimal approve-all program: version 6, pushint 1 -- the same
    // pattern used throughout `algo-rest-api`'s own integration tests.
    let approve_all: Vec<u8> = vec![0x06, 0x81, 0x01];

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let mut create = base_txn(&c, &base).await;
        create.txn_type = TxnType::Appl;
        create.approval_program = Some(approve_all.clone().into());
        create.clear_state_program = Some(approve_all.clone().into());
        create.note = unique_note(&format!("app-create-{label}")).into();
        let sk = dev_signing_key();
        let create_txid = compute_txn_id(&create).to_string();
        let stx = sign(&mut create, &sk);
        let bytes = encode(&stx);

        let resp = submit(&c, &base, &bytes).await;
        assert_eq!(
            resp.status,
            200,
            "{label}: app creation rejected: {}",
            resp.text()
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let confirmed = wait_for_confirmation(&c, &base, &create_txid, deadline).await;
        let app_id = confirmed["application-index"].as_u64().unwrap_or_else(|| {
            panic!("{label}: confirmed app creation must report application-index: {confirmed}")
        });

        // NoOp call into the freshly created app.
        let mut call = base_txn(&c, &base).await;
        call.txn_type = TxnType::Appl;
        call.application_id = app_id;
        call.note = unique_note(&format!("app-call-{label}")).into();
        let call_txid = compute_txn_id(&call).to_string();
        let stx = sign(&mut call, &sk);
        let bytes = encode(&stx);

        let resp = submit(&c, &base, &bytes).await;
        assert_eq!(
            resp.status,
            200,
            "{label}: app call rejected: {}",
            resp.text()
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        wait_for_confirmation(&c, &base, &call_txid, deadline).await;

        let (status, account) = get_json(&c, &base, &format!("/v2/accounts/{dev}")).await;
        assert_eq!(status, 200);
        assert!(
            account["total-created-apps"].as_u64().unwrap_or(0) >= 1,
            "{label}: account must report the created app: {account}"
        );
    }
}
