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

//! Live dual-node verification of v13 varint branch encoding (issue #691,
//! a follow-up to #661/#690).
//!
//! #661/PR #690 implemented go-algorand PR #6600's variable-length
//! (zigzag+ULEB128) branch encoding for `bnz`/`bz`/`b`/`callsub` at
//! `varintBranchVersion = 13`, verified only against 10 hand-derived
//! oracle unit tests in `crates/core/algo-avm/tests/varint_branch.rs`
//! written directly against go-algorand's `branchTargetVarint`/
//! `checkBranchVarint`/`findBranchSizes`/`resolveLabels` (`../go-algorand`
//! @ v5.0.0-stable, `data/transactions/logic/eval.go` / `assembler.go`) as
//! the oracle. This file closes the two live-verification gaps #661 left
//! open:
//!
//!  1. `assembler_byte_diff_matches_v13_varint_branch_programs` — a
//!     byte-for-byte diff of algod-rust's assembler output against a
//!     *real* go-algorand v5.0.0-stable node's own `POST /v2/teal/compile`
//!     (which calls the same `logic.AssembleString` `goal clerk compile`
//!     uses) for representative v13 TEAL programs exercising `bnz`, `bz`,
//!     `b`, and `callsub` with both a small (1-byte) and a large (2+ byte)
//!     forward or back varint offset.
//!  2. `mixed_forward_and_back_branch_execution_trace_matches_live` — an
//!     app whose approval program mixes a forward (`bz`) and a back (`b`)
//!     varint branch in a countdown loop, deployed and called on both
//!     nodes, diffing the resulting on-chain global state
//!     (`GET /v2/applications/{id}`'s `params.global-state`) byte-for-byte
//!     -- proof that both AVM implementations executed the v13 branch
//!     encoding identically, not merely that both *accepted* the
//!     transaction.
//!
//! ## Test 2 is now wired into CI (issue #720)
//!
//! Test 2 originally failed against this harness's shared genesis
//! (`docker/localnet-rust/data/genesis.json`), which was pinned to
//! consensus V41 (`LogicSigVersion` 12) rather than go-algorand
//! v5.0.0-stable's `ConsensusCurrentVersion` V42 (`LogicSigVersion` 13) --
//! confirmed live in this repo's own CI
//! (<https://github.com/xarmian/algod-rust/actions/runs/33253102996>,
//! `... check failed on ApprovalProgram: program version 13 greater than
//! protocol supported version 12`). That was a pre-existing harness gap
//! (this shared genesis was apparently never bumped forward through
//! phases 9-14's version-upgrade sweeps), not a v13 varint-branch defect.
//! Issue #720 bumped the harness's genesis `proto` to V42 and audited
//! every other `validate-api`-dependent live test for V42-specific
//! assumptions (fee/size-limit parameters), so `Makefile`'s `validate-api`
//! target now runs this file's full ignored set, test 2 included.
//!
//! ## Why this harness, not `ops/mixed-cluster/`
//!
//! The issue's acceptance criteria named `ops/mixed-cluster/` (the 4-node
//! BFT agreement conformance harness, Epic 42) for the live execution
//! check. That harness has no established transaction/app-deployment
//! tooling to extend -- it is purpose-built to verify the *agreement*
//! protocol (proposals, votes, certificates, forks), which is orthogonal
//! to AVM opcode correctness, and none of its funded genesis wallets have
//! a signing path wired up for it. `validate-api`'s dual-node harness
//! (used by `live_go_parity.rs`, `live_txn_cross_verification.rs`, etc.),
//! by contrast, already boots a *real* go-algorand v5.0.0-stable node and
//! a real algod-rust node from a shared genesis with a funded dev account
//! and full signed-transaction submission machinery -- exactly what this
//! verification needs -- so this file extends that established pattern
//! rather than inventing new mixed-cluster plumbing out of proportion to
//! a medium-effort follow-up issue. See `live_txn_cross_verification.rs`'s
//! module docs for why "cross-verification" here means *same input =>
//! byte-identical output on each node's own independent dev-mode chain*,
//! not literally shared consensus state.
//!
//! Bring up the harness first:
//!
//! ```text
//! make validate-api-up
//! cargo test --package algod-rust --test live_varint_branch_parity -- --ignored --nocapture --test-threads=1
//! make validate-api-down
//! ```
//!
//! or in one step: `make validate-api`, which runs both tests (see
//! "Test 2 is now wired into CI" above).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use algo_avm::assembler::assemble_string;
use algo_codec::{canonical_encode_transaction, compute_txn_id};
use algo_types::{SignedTransaction, StateSchema, TxnType};
use ed25519_dalek::Signer;

const DEV_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// `docs/DEV_WORKFLOW.md`'s funded dev account (25-word mnemonic), the
/// same one `live_txn_cross_verification.rs` uses.
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

fn unique_note(tag: &str) -> Vec<u8> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("live_varint_branch_parity:{tag}:{nanos}").into_bytes()
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
        first_valid: algo_types::Round(last_round.max(1)),
        last_valid: algo_types::Round(last_round + 1000),
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

struct SubmitResult {
    status: u16,
    body: Vec<u8>,
}

impl SubmitResult {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// POST a signed transaction, transparently retrying go-algorand's
/// transient just-booted "no pending block evaluator" pool error -- see
/// `live_txn_cross_verification.rs`'s `submit` for the full rationale.
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

/// A recursive, order-independent JSON diff, reporting every field-level
/// mismatch. Same shape as `live_go_parity.rs`'s.
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

// ---------------------------------------------------------------------------
// 1. Assembler byte-for-byte diff against a real go-algorand v5.0.0-stable
//    node's own `/v2/teal/compile` (issue #691 acceptance criterion 1+2).
// ---------------------------------------------------------------------------

/// Representative v13 TEAL programs exercising every varint-branch opcode
/// (`bnz`/`bz`/`b`/`callsub`) with small (1-byte) and large (2+ byte)
/// forward and back offsets. Each must assemble byte-identically on a real
/// go-algorand node and on algod-rust.
fn v13_varint_branch_programs() -> Vec<(&'static str, String)> {
    let mut programs = vec![
        (
            "bnz_small_forward_offset",
            "#pragma version 13\n\
             int 1\n\
             bnz target\n\
             int 0\n\
             return\n\
             target:\n\
             int 1\n\
             return\n"
                .to_string(),
        ),
        (
            "mixed_forward_bz_and_back_b_small_offsets",
            "#pragma version 13\n\
             int 3\n\
             store 0\n\
             loop:\n\
             load 0\n\
             bz done\n\
             load 0\n\
             int 1\n\
             -\n\
             store 0\n\
             b loop\n\
             done:\n\
             int 1\n\
             return\n"
                .to_string(),
        ),
        (
            "callsub_varint_branch",
            "#pragma version 13\n\
             callsub add\n\
             int 1\n\
             return\n\
             \n\
             add:\n\
             proto 0 0\n\
             int 41\n\
             int 1\n\
             +\n\
             pop\n\
             retsub\n"
                .to_string(),
        ),
    ];

    // A forward `b` whose target is far enough away that the zigzag
    // varint offset needs 2+ bytes (mirrors
    // `crates/core/algo-avm/tests/varint_branch.rs`'s
    // `test_branch_offset_requiring_two_or_more_varint_bytes`).
    let mut large_offset = String::from("#pragma version 13\nb target\n");
    for i in 0..40u32 {
        large_offset.push_str(&format!("pushint {i}\npop\n"));
    }
    large_offset.push_str("target:\nint 1\nreturn\n");
    programs.push(("b_large_forward_offset_two_plus_byte_varint", large_offset));

    programs
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn assembler_byte_diff_matches_v13_varint_branch_programs() {
    let c = client();
    let mut failures = Vec::new();

    for (label, source) in v13_varint_branch_programs() {
        // Sanity: algod-rust's own assembler must accept this source
        // (this test's premise is a diff of two *successful* compiles).
        assemble_string(&source)
            .unwrap_or_else(|e| panic!("{label}: algod-rust assembler rejected: {e:?}"));

        let go = c
            .post(format!("{}/v2/teal/compile", go_url()))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .body(source.clone())
            .send()
            .await
            .unwrap_or_else(|e| panic!("{label}: POST go /v2/teal/compile failed: {e}"));
        let rust = c
            .post(format!("{}/v2/teal/compile", rust_url()))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .body(source.clone())
            .send()
            .await
            .unwrap_or_else(|e| panic!("{label}: POST rust /v2/teal/compile failed: {e}"));

        let go_status = go.status();
        let rust_status = rust.status();
        let go_body: serde_json::Value = go.json().await.unwrap_or(serde_json::Value::Null);
        let rust_body: serde_json::Value = rust.json().await.unwrap_or(serde_json::Value::Null);

        if go_status != 200 || rust_status != 200 {
            failures.push(format!(
                "{label}: status mismatch or non-200 (go={go_status} rust={rust_status}) go_body={go_body} rust_body={rust_body}"
            ));
            continue;
        }

        let mut mismatches = Vec::new();
        diff_json("", &go_body, &rust_body, &mut mismatches);
        if !mismatches.is_empty() {
            failures.push(format!(
                "{label}: /v2/teal/compile field mismatches:\n{}",
                mismatches.join("\n")
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "v13 varint-branch assembler byte-diff failures:\n{}",
        failures.join("\n\n")
    );
}

// ---------------------------------------------------------------------------
// 2. Live execution-trace parity: deploy + call an app whose approval
//    program mixes forward/back varint branches, diff resulting global
//    state (issue #691 acceptance criterion 3).
// ---------------------------------------------------------------------------

/// `#pragma version 13` approval program: a 5-iteration countdown loop
/// using both a forward branch (`bz done`, taken only on the final
/// iteration) and a back branch (`b loop`, taken on every iteration but
/// the last) -- the same sign-dependent-base-point mix
/// `crates/core/algo-avm/tests/varint_branch.rs`'s
/// `test_mixed_forward_and_back_varint_branches_execute_correctly` pins at
/// the interpreter-unit level, but here executed end-to-end through both
/// nodes' real transaction-processing pipelines. Stores the loop's final
/// value (always 0) as global state key "result" so the two independent
/// executions can be compared byte-for-byte afterward.
const APPROVAL_SOURCE: &str = "\
#pragma version 13
int 5
store 0
loop:
load 0
bz done
load 0
int 1
-
store 0
b loop
done:
byte \"result\"
load 0
itob
app_global_put
int 1
return
";

const CLEAR_SOURCE: &str = "#pragma version 13\nint 1\nreturn\n";

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; see module docs"]
async fn mixed_forward_and_back_branch_execution_trace_matches_live() {
    let c = client();
    let approval = assemble_string(APPROVAL_SOURCE)
        .expect("v13 mixed-branch approval program must assemble")
        .program;
    let clear = assemble_string(CLEAR_SOURCE)
        .expect("clear state program must assemble")
        .program;

    let mut global_states = Vec::new();

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let sk = dev_signing_key();

        // 1. Create the app (this alone already runs the loop once).
        let mut create = base_txn(&c, &base).await;
        create.txn_type = TxnType::Appl;
        create.approval_program = Some(approval.clone().into());
        create.clear_state_program = Some(clear.clone().into());
        create.global_state_schema = Some(StateSchema {
            num_uint: 0,
            num_byte_slice: 1,
        });
        create.note = unique_note(&format!("varint-branch-app-create-{label}")).into();
        let create_txid = compute_txn_id(&create).to_string();
        let stx = sign(&mut create, &sk);
        let bytes = encode(&stx);

        let resp = submit(&c, &base, &bytes).await;
        assert_eq!(
            resp.status,
            200,
            "{label}: v13 mixed-branch app creation rejected: {}",
            resp.text()
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let confirmed = wait_for_confirmation(&c, &base, &create_txid, deadline).await;
        let app_id = confirmed["application-index"].as_u64().unwrap_or_else(|| {
            panic!("{label}: confirmed app creation must report application-index: {confirmed}")
        });

        // 2. NoOp call: re-runs the same mixed forward/back branch loop.
        let mut call = base_txn(&c, &base).await;
        call.txn_type = TxnType::Appl;
        call.application_id = app_id;
        call.note = unique_note(&format!("varint-branch-app-call-{label}")).into();
        let call_txid = compute_txn_id(&call).to_string();
        let stx = sign(&mut call, &sk);
        let bytes = encode(&stx);

        let resp = submit(&c, &base, &bytes).await;
        assert_eq!(
            resp.status,
            200,
            "{label}: v13 mixed-branch app call rejected: {}",
            resp.text()
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        wait_for_confirmation(&c, &base, &call_txid, deadline).await;

        // 3. Read back the resulting global state.
        let (status, app_info) = get_json(&c, &base, &format!("/v2/applications/{app_id}")).await;
        assert_eq!(
            status, 200,
            "{label}: GET /v2/applications/{app_id} failed: {app_info}"
        );
        let global_state = app_info["params"]["global-state"].clone();
        assert!(
            global_state.is_array() && !global_state.as_array().unwrap().is_empty(),
            "{label}: app_global_put in the loop's `done:` branch must have produced global state: {app_info}"
        );
        global_states.push((label, global_state));
    }

    let (go_label, go_state) = &global_states[0];
    let (rust_label, rust_state) = &global_states[1];
    let mut mismatches = Vec::new();
    diff_json("", go_state, rust_state, &mut mismatches);
    assert!(
        mismatches.is_empty(),
        "v13 mixed forward/back varint-branch execution trace diverged between {go_label} and {rust_label}:\n{}",
        mismatches.join("\n")
    );
}
