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

//! Phase 17 e2e-area sweep (issue #1457, batch 8): go-algorand's
//! `TestSendingFromEmptyAccountErrs` and `TestSendingLowFeeErrs`
//! (`test/e2e-go/restAPI/restClient_test.go`) submit real signed
//! transactions to a *live* node over its REST API and assert the broadcast
//! is rejected. `crates/node/algo-rest-api/tests/integration.rs`'s
//! `raw_transaction_insufficient_balance_returns_400` and
//! `raw_transaction_fee_below_minimum_returns_400` already pin the exact
//! `POST /v2/transactions` 400 response shape and message text for both
//! cases, but only through `MockNode` -- a stub `NodeInterface`, not a real
//! ledger/pool.
//!
//! This file closes that "live node" gap the same way
//! `consensus_override_wire_test.rs` (issue #764) did for the consensus.json
//! override: spawn the real `algod-rust` binary against a fresh data
//! directory, submit real signed transactions to its live `/v2/transactions`
//! endpoint, and observe the real accept/reject decision computed by the
//! actual ledger/pool apply path (`algo-ledger`'s
//! `"sender {} has insufficient balance {} for payment {}"` /
//! `algo-validate`'s `"transaction fee {} is below minimum {}"`), not a
//! locally-computed or mocked one.
//!
//! Single-node, no go-algorand peer needed -- this proves algod-rust's own
//! live rejection behavior, matching go's single-fixture-node originals.
//! Runs in the default `cargo test --workspace` suite (no `MIXED_CLUSTER`
//! gate needed), like `consensus_override_wire_test.rs`.

#![cfg(unix)]

use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use algo_types::consensus::{built_in_consensus_protocols, CONSENSUS_FUTURE};
use algo_types::{Address, Round, SignedTransaction, Transaction, TxnType};
use ed25519_dalek::{Signer, SigningKey};

const FUNDED_AMOUNT: u64 = 10_000_000;

fn sigterm(pid: u32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe {
        kill(pid as i32, 15);
    }
}

struct NodeGuard(Child);
impl Drop for NodeGuard {
    fn drop(&mut self) {
        sigterm(self.0.id());
        let _ = self.0.wait();
    }
}

fn write_genesis(dir: &Path, funded: &str) {
    let fees = Address([0xFE; 32]).to_algorand_string();
    let rwd = Address([0xFD; 32]).to_algorand_string();
    let genesis = format!(
        r#"{{"id":"v1","network":"localnet","proto":"future","fees":"{fees}","rwd":"{rwd}","timestamp":0,"alloc":[{{"addr":"{funded}","comment":"Wallet1","state":{{"algo":{FUNDED_AMOUNT},"onl":0}}}}]}}"#
    );
    std::fs::write(dir.join("genesis.json"), genesis).unwrap();
}

fn spawn_node(dir: &Path) -> NodeGuard {
    let bin = env!("CARGO_BIN_EXE_algod-rust");
    let child = Command::new(bin)
        .args(["node", "start", "-d"])
        .arg(dir)
        .args(["--listen", "127.0.0.1:0", "--dev"])
        .spawn()
        .expect("spawn algod-rust node start");
    NodeGuard(child)
}

/// Poll for the server-written `algod.net`; return (base_url, api_token).
fn wait_ready(dir: &Path) -> (String, String) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        if let Ok(net) = std::fs::read_to_string(dir.join("algod.net")) {
            let net = net.trim();
            if !net.is_empty() {
                let api = std::fs::read_to_string(dir.join("algod.token")).unwrap_or_default();
                if !api.trim().is_empty() {
                    return (format!("http://{net}"), api.trim().to_string());
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("node did not write algod.net/algod.token within 30s");
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build reqwest client")
}

async fn get_json(c: &reqwest::Client, base: &str, path: &str, token: &str) -> serde_json::Value {
    c.get(format!("{base}{path}"))
        .header("X-Algo-API-Token", token)
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json body")
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    STANDARD.decode(s).expect("valid base64")
}

async fn base_txn(c: &reqwest::Client, base: &str, token: &str, sender: Address) -> Transaction {
    let params = get_json(c, base, "/v2/transactions/params", token).await;
    let genesis_hash_bytes = base64_decode(params["genesis-hash"].as_str().unwrap());
    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&genesis_hash_bytes);
    let last_round = params["last-round"].as_u64().unwrap();

    Transaction {
        txn_type: TxnType::Pay,
        sender,
        first_valid: Round(last_round.max(1)),
        last_valid: Round(last_round + 1000),
        genesis_id: params["genesis-id"].as_str().unwrap().to_string(),
        genesis_hash,
        ..Default::default()
    }
}

fn sign(txn: &mut Transaction, sk: &SigningKey) -> SignedTransaction {
    let mut msg = Vec::with_capacity(2 + 256);
    msg.extend_from_slice(b"TX");
    msg.extend_from_slice(&algo_codec::canonical_encode_transaction(txn));
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

fn unique_note(tag: &str) -> serde_bytes::ByteBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    serde_bytes::ByteBuf::from(
        format!("live_node_rejects_invalid_submissions_test:{tag}:{nanos}").into_bytes(),
    )
}

struct SubmitResult {
    status: u16,
    body: String,
}

async fn submit(c: &reqwest::Client, base: &str, token: &str, bytes: &[u8]) -> SubmitResult {
    let resp = c
        .post(format!("{base}/v2/transactions"))
        .header("X-Algo-API-Token", token)
        .header("Content-Type", "application/x-binary")
        .body(bytes.to_vec())
        .send()
        .await
        .expect("submit request");
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    SubmitResult { status, body }
}

/// go: `TestSendingFromEmptyAccountErrs` -- a payment broadcast from an
/// account with zero balance must be rejected by the live node, over the
/// wire, with an insufficient-balance error.
#[tokio::test]
async fn live_node_rejects_payment_from_empty_account_over_the_wire() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();

    // Funded sender exists only so the node has a non-empty genesis; the
    // actual transaction under test is sent FROM a second, freshly
    // generated key that genesis never allocates anything to.
    let funded_sk = SigningKey::from_bytes(&[0x11; 32]);
    let funded_addr = Address(funded_sk.verifying_key().to_bytes());
    write_genesis(dir, &funded_addr.to_algorand_string());

    let _node = spawn_node(dir);
    let (base, token) = wait_ready(dir);
    let c = client();

    let empty_sk = SigningKey::from_bytes(&[0x22; 32]);
    let empty_addr = Address(empty_sk.verifying_key().to_bytes());

    let min_fee = built_in_consensus_protocols()
        .get(CONSENSUS_FUTURE)
        .expect("\"future\" must be a known built-in protocol version")
        .min_txn_fee;

    let mut txn = base_txn(&c, &base, &token, empty_addr).await;
    txn.receiver = funded_addr;
    txn.amount = 100_000;
    txn.fee = min_fee;
    txn.note = unique_note("from-empty");
    let stx = sign(&mut txn, &empty_sk);

    let rejected = submit(&c, &base, &token, &encode(&stx)).await;
    assert_ne!(
        rejected.status, 200,
        "a payment broadcast from a zero-balance account must be rejected by the live node, \
         but it returned 200: {}",
        rejected.body
    );
    assert!(
        rejected.body.contains("insufficient balance"),
        "expected an insufficient-balance rejection reason, got: {}",
        rejected.body
    );
}

/// go: `TestSendingLowFeeErrs` -- a payment broadcast with a fee below the
/// protocol minimum must be rejected by the live node, over the wire, both
/// for a too-low nonzero fee and for a zero fee.
#[tokio::test]
async fn live_node_rejects_low_fee_payment_over_the_wire() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();

    let sk = SigningKey::from_bytes(&[0x33; 32]);
    let sender = Address(sk.verifying_key().to_bytes());
    write_genesis(dir, &sender.to_algorand_string());

    let _node = spawn_node(dir);
    let (base, token) = wait_ready(dir);
    let c = client();

    let min_fee = built_in_consensus_protocols()
        .get(CONSENSUS_FUTURE)
        .expect("\"future\" must be a known built-in protocol version")
        .min_txn_fee;
    assert!(
        min_fee > 1,
        "this test needs a nonzero min fee floor to submit a meaningfully too-low fee"
    );

    // (1) A nonzero fee that is still below the minimum must be rejected.
    let mut low_fee_txn = base_txn(&c, &base, &token, sender).await;
    low_fee_txn.receiver = sender;
    low_fee_txn.amount = 0;
    low_fee_txn.fee = 1;
    low_fee_txn.note = unique_note("low-fee");
    let low_fee_stx = sign(&mut low_fee_txn, &sk);
    let rejected_low = submit(&c, &base, &token, &encode(&low_fee_stx)).await;
    assert_ne!(
        rejected_low.status, 200,
        "a payment paying fee 1 (below the protocol minimum {min_fee}) must be rejected by the \
         live node, but it returned 200: {}",
        rejected_low.body
    );
    assert!(
        rejected_low.body.contains("below minimum") || rejected_low.body.contains("fee"),
        "expected a fee-related rejection reason, got: {}",
        rejected_low.body
    );

    // (2) A zero fee must also be rejected.
    let mut zero_fee_txn = base_txn(&c, &base, &token, sender).await;
    zero_fee_txn.receiver = sender;
    zero_fee_txn.amount = 0;
    zero_fee_txn.fee = 0;
    zero_fee_txn.note = unique_note("zero-fee");
    let zero_fee_stx = sign(&mut zero_fee_txn, &sk);
    let rejected_zero = submit(&c, &base, &token, &encode(&zero_fee_stx)).await;
    assert_ne!(
        rejected_zero.status, 200,
        "a payment paying fee 0 must be rejected by the live node, but it returned 200: {}",
        rejected_zero.body
    );
    assert!(
        rejected_zero.body.contains("below minimum") || rejected_zero.body.contains("fee"),
        "expected a fee-related rejection reason, got: {}",
        rejected_zero.body
    );
}
