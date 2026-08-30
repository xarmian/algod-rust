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

//! Issue #764's centerpiece: a real, running `algod-rust node start` process,
//! booted with a genuine `<data_dir>/consensus.json` override, must actually
//! enforce that override *over the wire* -- via its live REST API -- not
//! merely in an in-process function call.
//!
//! #762 (PR #763) already proved the override registry threads through
//! `consensus_params_for_version` and is honored by a direct
//! `algo_validate::validate_block` call
//! (`crates/core/algo-validate/tests/consensus_override_e2e_test.rs`), but
//! deliberately deferred the live-node/live-wire half of the verification to
//! this issue. This file closes that gap: it spawns the real `algod-rust`
//! binary (the same `CARGO_BIN_EXE_algod-rust` mechanism
//! `node_serve_test.rs` uses) against a fresh data directory carrying a
//! `consensus.json` that raises the "future" protocol's `MinTxnFee` well
//! above its built-in default, then submits real signed transactions to the
//! node's live `/v2/transactions` endpoint and observes the real
//! accept/reject decision -- not a decision computed locally.
//!
//! The `consensus.json` payload itself is `docker/config/vfuture-consensus.json`
//! -- the same real, go-algorand-authored, full-struct-replace fixture issue
//! #750/#762 already used, and the same one `docker/scripts/vfuture-entrypoint.sh`
//! has separately proven boots a real go-algorand node successfully -- with
//! only its `MinTxnFee` value bumped, so this test exercises a realistic,
//! fully-populated override rather than a synthetic all-zero-fields one.
//!
//! Single-node, no go-algorand peer and no Docker: this verifies
//! algod-rust's *own* consensus.json override mechanism, not cross-
//! implementation parity, so the dual-node `validate-api` harness (which
//! exists for byte-for-byte parity checks) would be unnecessary machinery
//! here -- matching the issue's own suggestion that a solo-node harness is
//! the right fit. Runs in the default `cargo test --workspace` suite (no
//! external `make` target / Docker Compose needed), like `node_serve_test.rs`.

#![cfg(unix)]

use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use algo_types::consensus::{built_in_consensus_protocols, CONSENSUS_FUTURE};
use algo_types::{Address, Round, SignedTransaction, Transaction, TxnType};
use ed25519_dalek::{Signer, SigningKey};

const FUNDED_AMOUNT: u64 = 10_000_000;
/// `MinTxnFee` is bumped to five times whatever the built-in "future" table
/// defines (computed at runtime below, not hardcoded), so the override is
/// unambiguously observable regardless of upstream drift in the built-in
/// default.
const OVERRIDE_MULTIPLIER: u64 = 5;

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

/// Write `<dir>/consensus.json` by loading the real, go-algorand-authored
/// `docker/config/vfuture-consensus.json` fixture (a full, wholesale
/// replacement for the "future" protocol -- see
/// `algo_types::consensus::merge_consensus_protocols`'s doc comment for why
/// a partial override isn't meaningful here) and overwriting only its
/// `MinTxnFee` field with `overridden_min_fee`.
fn write_consensus_override(dir: &Path, overridden_min_fee: u64) {
    const FIXTURE: &str = include_str!("../../../docker/config/vfuture-consensus.json");
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE)
        .expect("docker/config/vfuture-consensus.json must be valid JSON");
    value["future"]["MinTxnFee"] = serde_json::Value::from(overridden_min_fee);
    let encoded = serde_json::to_vec_pretty(&value).expect("re-encode consensus.json");
    std::fs::write(dir.join("consensus.json"), encoded).expect("write consensus.json");
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
    serde_bytes::ByteBuf::from(format!("consensus_override_wire_test:{tag}:{nanos}").into_bytes())
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

async fn wait_for_confirmation(c: &reqwest::Client, base: &str, token: &str, txid: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let resp = c
            .get(format!("{base}/v2/transactions/pending/{txid}"))
            .header("X-Algo-API-Token", token)
            .send()
            .await
            .expect("pending request");
        if resp.status().as_u16() == 200 {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            if body["confirmed-round"].as_u64().unwrap_or(0) > 0 {
                return;
            }
        }
        if Instant::now() >= deadline {
            panic!("txid {txid} did not confirm before deadline on {base}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Issue #764's full acceptance bar in one boot: a real node, started with a
/// custom `consensus.json` that raises `MinTxnFee` above its built-in
/// default, (1) rejects -- over its live REST API -- a transaction paying
/// only the OLD (pre-override) minimum fee, and (2) accepts/confirms a
/// transaction paying the NEW (overridden) minimum fee, ruling out "the
/// override silently disabled all transactions" as a false-positive pass.
#[tokio::test]
async fn live_node_enforces_consensus_json_min_txn_fee_override_over_the_wire() {
    let pristine_min_fee = built_in_consensus_protocols()
        .get(CONSENSUS_FUTURE)
        .expect("\"future\" must be a known built-in protocol version")
        .min_txn_fee;
    let overridden_min_fee = pristine_min_fee.saturating_mul(OVERRIDE_MULTIPLIER);
    assert!(
        overridden_min_fee > pristine_min_fee,
        "the override must actually raise the fee floor for this test to be meaningful"
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let sk = SigningKey::from_bytes(&[0x42; 32]);
    let sender = Address(sk.verifying_key().to_bytes());
    write_genesis(dir, &sender.to_algorand_string());
    write_consensus_override(dir, overridden_min_fee);

    let _node = spawn_node(dir);
    let (base, token) = wait_ready(dir);
    let c = client();

    // Sanity: `/v2/transactions/params` itself must already reflect the
    // overridden fee (issue #762's introspection-level proof), before we
    // check the enforcement-level proof below.
    let params = get_json(&c, &base, "/v2/transactions/params", &token).await;
    assert_eq!(
        params["min-fee"].as_u64(),
        Some(overridden_min_fee),
        "the live node's own suggested-params endpoint must reflect the loaded consensus.json override"
    );

    // ── (1) A transaction paying only the OLD (pre-override) minimum fee
    // must be rejected by the live node -- not a local computation.
    let mut low_fee_txn = base_txn(&c, &base, &token, sender).await;
    low_fee_txn.receiver = sender;
    low_fee_txn.amount = 0;
    low_fee_txn.fee = pristine_min_fee;
    low_fee_txn.note = unique_note("below-override");
    let low_fee_stx = sign(&mut low_fee_txn, &sk);
    let rejected = submit(&c, &base, &token, &encode(&low_fee_stx)).await;
    assert_ne!(
        rejected.status, 200,
        "a transaction paying only the pre-override minimum fee ({pristine_min_fee}) must be \
         rejected once consensus.json raises MinTxnFee to {overridden_min_fee}, but the live \
         node returned 200: {}",
        rejected.body
    );
    assert!(
        rejected.body.contains("below minimum") || rejected.body.contains("fee"),
        "expected a fee-related rejection reason, got: {}",
        rejected.body
    );

    // ── (2) A transaction paying the NEW (overridden) minimum fee must be
    // accepted and confirmed -- ruling out "the override silently disabled
    // all transactions" as a false-positive pass on (1) alone.
    let mut ok_fee_txn = base_txn(&c, &base, &token, sender).await;
    ok_fee_txn.receiver = sender;
    ok_fee_txn.amount = 0;
    ok_fee_txn.fee = overridden_min_fee;
    ok_fee_txn.note = unique_note("at-override");
    let ok_fee_stx = sign(&mut ok_fee_txn, &sk);
    let ok_fee_txid = algo_codec::compute_txn_id(&ok_fee_stx.txn).to_string();
    let accepted = submit(&c, &base, &token, &encode(&ok_fee_stx)).await;
    assert_eq!(
        accepted.status, 200,
        "a transaction paying the overridden minimum fee ({overridden_min_fee}) must be accepted \
         by the live node, got status {}: {}",
        accepted.status, accepted.body
    );
    wait_for_confirmation(&c, &base, &token, &ok_fee_txid).await;
}
