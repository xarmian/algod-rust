//! Live dual-node verification of go-algorand v5.0.0's "big transaction"
//! size-pricing fee boundaries (issue #703, a follow-up to #657/#677).
//!
//! #657 implemented go-algorand v5.0.0's size-pricing primitives
//! (`FeeForUsage`, `Micros.MulInt`, `feeFactor`/`FeeContribution`/
//! `feeContribution`, `logicSigProgramFeeContribution`, `SummarizeFees`) in
//! `crates/core/algo-validate/src/fee.rs`, pinned against go's own
//! `TestFeeForUsage`/`TestFeeForUsagePrecise` unit-test oracle
//! (`../go-algorand`'s `data/basics/units_test.go`) but never against a real
//! go-algorand node's own well-formedness/fee acceptance decision for actual
//! transactions straddling the size boundaries -- that gap is what this file
//! closes.
//!
//! Each test below submits transactions at and around one of the four
//! size-pricing boundary families named in #703's acceptance criteria --
//! note bytes, `ApplicationArgs` total bytes, app approval+clear program
//! total bytes, and `LogicSig` program bytes -- to BOTH a real go-algorand
//! v5.0.0-stable node and algod-rust from the shared `validate-api` genesis
//! (consensus V42, bumped there by issue #720/#721), and asserts that:
//!
//!  1. go-algorand and algod-rust agree on accept/reject for every case, and
//!  2. both agree with algod-rust's own `algo_validate::required_fee_for_txn`
//!     / `summarize_fees` formula: paying exactly the computed required fee
//!     is accepted, paying one microAlgo less is rejected, and a size that
//!     exceeds the *hard* (`MaxAbsolute*`) cap is rejected regardless of fee.
//!
//! This directly pins the "exact required fee amount" half of #703's
//! acceptance criteria (not just the accept/reject decision) without needing
//! to parse go's `Micros`/`MicroAlgos` custom string formatting
//! (`"1.601mA"`-style) out of its error text: if algod-rust's required-fee
//! formula were off by even one microAlgo, either go would accept at
//! `required - 1` (formula too high) or reject at `required` (formula too
//! low), and the cross-node assertion below would catch it.
//!
//! ## Scope
//!
//! Threading `FeeForUsage`'s residue through nested inner-transaction groups
//! (`opItxnSubmit`/`EvalParams`) is out of scope here -- that is #677's
//! subject, already implemented and closed (PR #704), which made an explicit
//! judgment call to skip live/mixed-cluster verification for that narrow,
//! deterministic, formula-level fix (see #677's closing comment). This file
//! only covers #657's own outstanding "fixtures/oracle comparison against
//! go-algorand for fee amounts at note/arg/program-byte boundaries"
//! acceptance criterion.
//!
//! Bring up the harness first:
//!
//! ```text
//! make validate-api-up
//! cargo test --package algod-rust --test live_fee_size_pricing_parity -- --ignored --nocapture --test-threads=1
//! make validate-api-down
//! ```
//!
//! or in one step: `make validate-api`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use algo_avm::assembler::assemble_string;
use algo_codec::{canonical_encode_transaction, compute_group_id, compute_txn_id};
use algo_types::consensus::{consensus_params_for_version, ConsensusParams, CONSENSUS_V42};
use algo_types::{LogicSig, SignedTransaction, StateSchema, Transaction, TxnType};
use ed25519_dalek::Signer;
use serde_bytes::ByteBuf;

const DEV_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// `docs/DEV_WORKFLOW.md`'s funded dev account (25-word mnemonic), the same
/// one `live_txn_cross_verification.rs`/`live_varint_branch_parity.rs` use.
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

fn v42_params() -> ConsensusParams {
    consensus_params_for_version(CONSENSUS_V42).expect("V42 must be a known protocol version")
}

fn sign(txn: &mut Transaction, sk: &ed25519_dalek::SigningKey) -> SignedTransaction {
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

/// Delegated LogicSig signature: ed25519 over `"Program" || logic`, matching
/// `algo-validate::signature::logicsig_sanity_check`'s `has_sig` path.
fn sign_delegated_lsig(program: &[u8], sk: &ed25519_dalek::SigningKey) -> [u8; 64] {
    let mut msg = Vec::with_capacity(7 + program.len());
    msg.extend_from_slice(b"Program");
    msg.extend_from_slice(program);
    sk.sign(&msg).to_bytes()
}

fn encode(stx: &SignedTransaction) -> Vec<u8> {
    rmp_serde::to_vec_named(stx).expect("encode signed txn")
}

fn unique_note(tag: &str) -> Vec<u8> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("live_fee_size_pricing_parity:{tag}:{nanos}").into_bytes()
}

async fn base_txn(client: &reqwest::Client, base: &str) -> Transaction {
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

    Transaction {
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

    fn accepted(&self) -> bool {
        self.status == 200
    }
}

/// POST signed-transaction bytes, transparently retrying go-algorand's
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

// ---------------------------------------------------------------------------
// Byte-padding helpers
// ---------------------------------------------------------------------------

/// Assembles a valid AVM program of *exactly* `target_len` bytes: a chain of
/// `pushbytes <zero-filled literal>; pop` blocks (each literal kept well
/// under the hardcoded 4096-byte `pushbytes`-literal ceiling --
/// `MAX_STRING_SIZE`/`MaxAVMBytesSize` -- since these test programs must
/// reach up to `MaxAbsoluteLogicSigProgramSize`/oversized-app-program
/// lengths far past that single-literal limit), followed by `int 1;
/// return`. Dead code after `return` still needs to decode as valid opcodes
/// for `CheckProgram`/`logicsig_sanity_check` to accept it, so this is a
/// real padding scheme, not garbage bytes appended after a terminator.
///
/// Converges by trial: assembles a candidate, measures the real length, and
/// nudges the last block's payload size by the exact diff (rolling extra
/// full blocks in/out as that nudge crosses a block's size range). A
/// `pushbytes` payload's length-varuint changes from 1 to 2 bytes at the
/// 128-byte boundary, which this loop absorbs the same way.
fn program_of_len(target_len: usize, version: u8) -> Vec<u8> {
    const CHUNK: usize = 3800;
    const BLOCK_OVERHEAD: usize = 4; // pushbytes opcode(1) + 2-byte varuint len + pop(1)

    let build = |num_blocks: usize, last_pad: usize| -> String {
        let mut src = format!("#pragma version {version}\n");
        for _ in 0..num_blocks {
            src.push_str(&format!("pushbytes 0x{}\npop\n", "00".repeat(CHUNK)));
        }
        src.push_str(&format!("pushbytes 0x{}\npop\n", "00".repeat(last_pad)));
        src.push_str("int 1\nreturn\n");
        src
    };

    let mut num_blocks = target_len / (CHUNK + BLOCK_OVERHEAD);
    let mut last_pad: isize =
        target_len as isize - (num_blocks * (CHUNK + BLOCK_OVERHEAD)) as isize - 8;

    for _ in 0..200 {
        if last_pad < 0 {
            if num_blocks == 0 {
                last_pad = 0;
            } else {
                num_blocks -= 1;
                last_pad += (CHUNK + BLOCK_OVERHEAD) as isize;
                continue;
            }
        }
        if last_pad as usize > CHUNK {
            num_blocks += 1;
            last_pad -= (CHUNK + BLOCK_OVERHEAD) as isize;
            continue;
        }
        let src = build(num_blocks, last_pad as usize);
        let asm = assemble_string(&src).unwrap_or_else(|e| {
            panic!(
                "assemble failed for target={target_len} blocks={num_blocks} last_pad={last_pad}: {e:?}"
            )
        });
        let len = asm.program.len() as isize;
        if len == target_len as isize {
            return asm.program;
        }
        last_pad += target_len as isize - len;
    }
    panic!("program_of_len failed to converge for target_len={target_len}");
}

/// Splits `total` bytes across as few `ApplicationArgs` entries as possible,
/// respecting the hardcoded per-argument `MAX_STRING_SIZE`/`MaxAVMBytesSize`
/// ceiling (4096) that is independent of the consensus-versioned total-length
/// cap this test is targeting.
fn app_args_of_total_len(total: usize) -> Vec<Option<ByteBuf>> {
    const MAX_ARG: usize = 4096;
    let mut remaining = total;
    let mut args = Vec::new();
    while remaining > 0 {
        let n = remaining.min(MAX_ARG);
        args.push(Some(ByteBuf::from(vec![0u8; n])));
        remaining -= n;
    }
    if args.is_empty() {
        args.push(Some(ByteBuf::from(Vec::new())));
    }
    args
}

// ---------------------------------------------------------------------------
// Generic per-case runner
// ---------------------------------------------------------------------------

struct CaseOutcome {
    label: &'static str,
    go: SubmitResult,
    rust: SubmitResult,
}

/// Builds a transaction from a fresh `base_txn` on each node, applies
/// `mutate`, sets `fee`, signs with `sk`, and submits to both nodes.
async fn run_case(
    c: &reqwest::Client,
    sk: &ed25519_dalek::SigningKey,
    label: &'static str,
    mutate: impl Fn(&mut Transaction),
    fee: u64,
) -> CaseOutcome {
    let mut go_txn = base_txn(c, &go_url()).await;
    mutate(&mut go_txn);
    go_txn.fee = fee;
    go_txn.note = ByteBuf::from(unique_note(&format!("{label}-go")));
    let go_stx = sign(&mut go_txn, sk);
    let go_bytes = encode(&go_stx);
    let go = submit(c, &go_url(), &go_bytes).await;

    let mut rust_txn = base_txn(c, &rust_url()).await;
    mutate(&mut rust_txn);
    rust_txn.fee = fee;
    rust_txn.note = ByteBuf::from(unique_note(&format!("{label}-rust")));
    let rust_stx = sign(&mut rust_txn, sk);
    let rust_bytes = encode(&rust_stx);
    let rust = submit(c, &rust_url(), &rust_bytes).await;

    CaseOutcome { label, go, rust }
}

/// Asserts that go and algod-rust agree on accept/reject for this case, and
/// that both match algod-rust's own predicted decision (from
/// `algo_validate::required_fee_for_txn`/`summarize_fees`).
fn assert_case_parity(outcome: &CaseOutcome, expect_accept: bool) -> Result<(), String> {
    let go_ok = outcome.go.accepted();
    let rust_ok = outcome.rust.accepted();
    if go_ok != expect_accept || rust_ok != expect_accept {
        return Err(format!(
            "{}: expected accept={expect_accept}, got go accept={go_ok} (status {}, body {}) rust accept={rust_ok} (status {}, body {})",
            outcome.label,
            outcome.go.status,
            outcome.go.text(),
            outcome.rust.status,
            outcome.rust.text(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 1. Note bytes: MaxTxnNoteBytes (1024, soft) / MaxAbsoluteTxnNoteBytes
//    (4096, hard).
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn note_bytes_size_pricing_boundaries_match_live() {
    let c = client();
    let sk = dev_signing_key();
    let params = v42_params();
    let soft = params.max_txn_note_bytes;
    let hard = algo_validate::effective_max_note_bytes(&params);
    let mut failures = Vec::new();

    let note_txn = |len: usize| -> Transaction {
        Transaction {
            txn_type: TxnType::Pay,
            receiver: dev_address(),
            amount: 0,
            note: ByteBuf::from(vec![0u8; len]),
            ..Default::default()
        }
    };
    let required_fee = |len: usize| -> u64 {
        let txn = note_txn(len);
        algo_validate::required_fee_for_txn(&txn, &params).0
    };

    // At the soft cap: no surcharge, min fee suffices.
    let outcome = run_case(
        &c,
        &sk,
        "note_at_soft_cap_min_fee",
        |txn| {
            txn.txn_type = TxnType::Pay;
            txn.receiver = dev_address();
            txn.amount = 0;
            txn.note = ByteBuf::from(vec![0u8; soft]);
        },
        params.min_txn_fee,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, true) {
        failures.push(e);
    }

    // Just over the soft cap: min fee alone is insufficient.
    let over_soft = soft + 50;
    let over_soft_required = required_fee(over_soft);
    let outcome = run_case(
        &c,
        &sk,
        "note_over_soft_min_fee_reject",
        |txn| {
            txn.txn_type = TxnType::Pay;
            txn.receiver = dev_address();
            txn.amount = 0;
            txn.note = ByteBuf::from(vec![0u8; over_soft]);
        },
        params.min_txn_fee,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }

    // Same size, exactly the required fee: accepted.
    let outcome = run_case(
        &c,
        &sk,
        "note_over_soft_exact_fee_accept",
        |txn| {
            txn.txn_type = TxnType::Pay;
            txn.receiver = dev_address();
            txn.amount = 0;
            txn.note = ByteBuf::from(vec![0u8; over_soft]);
        },
        over_soft_required,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, true) {
        failures.push(e);
    }

    // Same size, one microAlgo short: rejected.
    let outcome = run_case(
        &c,
        &sk,
        "note_over_soft_fee_minus_one_reject",
        |txn| {
            txn.txn_type = TxnType::Pay;
            txn.receiver = dev_address();
            txn.amount = 0;
            txn.note = ByteBuf::from(vec![0u8; over_soft]);
        },
        over_soft_required - 1,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }

    // At the hard cap: exact required fee accepted, one less rejected.
    let hard_required = required_fee(hard);
    let outcome = run_case(
        &c,
        &sk,
        "note_at_hard_cap_exact_fee_accept",
        |txn| {
            txn.txn_type = TxnType::Pay;
            txn.receiver = dev_address();
            txn.amount = 0;
            txn.note = ByteBuf::from(vec![0u8; hard]);
        },
        hard_required,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, true) {
        failures.push(e);
    }
    let outcome = run_case(
        &c,
        &sk,
        "note_at_hard_cap_fee_minus_one_reject",
        |txn| {
            txn.txn_type = TxnType::Pay;
            txn.receiver = dev_address();
            txn.amount = 0;
            txn.note = ByteBuf::from(vec![0u8; hard]);
        },
        hard_required - 1,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }

    // Over the hard cap: rejected regardless of fee (well-formedness, not fee).
    let outcome = run_case(
        &c,
        &sk,
        "note_over_hard_cap_reject_unconditional",
        |txn| {
            txn.txn_type = TxnType::Pay;
            txn.receiver = dev_address();
            txn.amount = 0;
            txn.note = ByteBuf::from(vec![0u8; hard + 1]);
        },
        hard_required + 1_000_000,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }

    assert!(
        failures.is_empty(),
        "note-bytes size-pricing boundary mismatches:\n{}",
        failures.join("\n\n")
    );
}

// ---------------------------------------------------------------------------
// 2. ApplicationArgs total bytes: MaxAppTotalArgLen (2048, soft) /
//    MaxAbsoluteTotalArgLen (16384, hard).
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn app_args_size_pricing_boundaries_match_live() {
    let c = client();
    let sk = dev_signing_key();
    let params = v42_params();
    let soft = params.max_app_total_arg_len;
    let hard = algo_validate::effective_max_total_arg_len(&params);
    let mut failures = Vec::new();

    // A trivial always-approving app, created fresh per node, to call NoOp
    // against with varying ApplicationArgs sizes.
    let approval = assemble_string("#pragma version 8\nint 1\nreturn\n")
        .expect("trivial approval must assemble")
        .program;
    let clear = assemble_string("#pragma version 8\nint 1\nreturn\n")
        .expect("trivial clear must assemble")
        .program;

    let mut app_ids = Vec::new();
    for base in [go_url(), rust_url()] {
        let mut create = base_txn(&c, &base).await;
        create.txn_type = TxnType::Appl;
        create.approval_program = Some(approval.clone().into());
        create.clear_state_program = Some(clear.clone().into());
        create.global_state_schema = Some(StateSchema {
            num_uint: 0,
            num_byte_slice: 0,
        });
        create.note = ByteBuf::from(unique_note("app-args-boundary-create"));
        let create_txid = compute_txn_id(&create).to_string();
        let stx = sign(&mut create, &sk);
        let bytes = encode(&stx);
        let resp = submit(&c, &base, &bytes).await;
        assert_eq!(
            resp.status,
            200,
            "trivial app creation on {base} rejected: {}",
            resp.text()
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let confirmed = wait_for_confirmation(&c, &base, &create_txid, deadline).await;
        let app_id = confirmed["application-index"].as_u64().unwrap_or_else(|| {
            panic!("{base}: confirmed app creation must report application-index: {confirmed}")
        });
        app_ids.push(app_id);
    }
    let go_app_id = app_ids[0];
    let rust_app_id = app_ids[1];

    let required_fee = |total_args: usize| -> u64 {
        let txn = Transaction {
            txn_type: TxnType::Appl,
            app_arguments: Some(app_args_of_total_len(total_args)),
            ..Default::default()
        };
        algo_validate::required_fee_for_txn(&txn, &params).0
    };

    async fn run_args_case(
        c: &reqwest::Client,
        sk: &ed25519_dalek::SigningKey,
        go_app_id: u64,
        rust_app_id: u64,
        label: &'static str,
        total_args: usize,
        fee: u64,
    ) -> CaseOutcome {
        let mut go_txn = base_txn(c, &go_url()).await;
        go_txn.txn_type = TxnType::Appl;
        go_txn.application_id = go_app_id;
        go_txn.app_arguments = Some(app_args_of_total_len(total_args));
        go_txn.fee = fee;
        go_txn.note = ByteBuf::from(unique_note(&format!("{label}-go")));
        let go_stx = sign(&mut go_txn, sk);
        let go = submit(c, &go_url(), &encode(&go_stx)).await;

        let mut rust_txn = base_txn(c, &rust_url()).await;
        rust_txn.txn_type = TxnType::Appl;
        rust_txn.application_id = rust_app_id;
        rust_txn.app_arguments = Some(app_args_of_total_len(total_args));
        rust_txn.fee = fee;
        rust_txn.note = ByteBuf::from(unique_note(&format!("{label}-rust")));
        let rust_stx = sign(&mut rust_txn, sk);
        let rust = submit(c, &rust_url(), &encode(&rust_stx)).await;

        CaseOutcome { label, go, rust }
    }

    // At the soft cap: no surcharge.
    let outcome = run_args_case(
        &c,
        &sk,
        go_app_id,
        rust_app_id,
        "args_at_soft_cap_min_fee",
        soft,
        params.min_txn_fee,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, true) {
        failures.push(e);
    }

    // Just over the soft cap.
    let over_soft = soft + 50;
    let over_soft_required = required_fee(over_soft);
    let outcome = run_args_case(
        &c,
        &sk,
        go_app_id,
        rust_app_id,
        "args_over_soft_min_fee_reject",
        over_soft,
        params.min_txn_fee,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }
    let outcome = run_args_case(
        &c,
        &sk,
        go_app_id,
        rust_app_id,
        "args_over_soft_exact_fee_accept",
        over_soft,
        over_soft_required,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, true) {
        failures.push(e);
    }
    let outcome = run_args_case(
        &c,
        &sk,
        go_app_id,
        rust_app_id,
        "args_over_soft_fee_minus_one_reject",
        over_soft,
        over_soft_required - 1,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }

    // At the hard cap.
    let hard_required = required_fee(hard);
    let outcome = run_args_case(
        &c,
        &sk,
        go_app_id,
        rust_app_id,
        "args_at_hard_cap_exact_fee_accept",
        hard,
        hard_required,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, true) {
        failures.push(e);
    }
    let outcome = run_args_case(
        &c,
        &sk,
        go_app_id,
        rust_app_id,
        "args_at_hard_cap_fee_minus_one_reject",
        hard,
        hard_required - 1,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }

    // Over the hard cap: rejected regardless of fee.
    let outcome = run_args_case(
        &c,
        &sk,
        go_app_id,
        rust_app_id,
        "args_over_hard_cap_reject_unconditional",
        hard + 1,
        hard_required + 1_000_000,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }

    assert!(
        failures.is_empty(),
        "app-args size-pricing boundary mismatches:\n{}",
        failures.join("\n\n")
    );
}

// ---------------------------------------------------------------------------
// 3. App approval+clear program total bytes:
//    MaxAppTotalProgramLen*(1+MaxExtraAppProgramPages) (8192, soft) /
//    MaxAppTotalProgramLen*(1+MaxAbsoluteExtraProgramPages) (16384, hard).
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn app_program_size_pricing_boundaries_match_live() {
    let c = client();
    let sk = dev_signing_key();
    let params = v42_params();
    let page_len = params.max_app_total_program_len;
    let soft_epp = params.max_extra_app_program_pages;
    let hard_epp = params.max_absolute_extra_program_pages;
    let soft_limit = page_len * (1 + soft_epp as usize);
    let hard_limit = page_len * (1 + hard_epp as usize);
    let mut failures = Vec::new();

    let clear_program = program_of_len(16, 8);
    let clear_len = clear_program.len();

    // Extra pages needed for well-formedness to allow a program of
    // `total_len` bytes, capped at the absolute maximum.
    let epp_for = |total_len: usize| -> u32 {
        let pages_needed = total_len.div_ceil(page_len).max(1);
        ((pages_needed - 1) as u32).min(hard_epp)
    };

    let required_fee = |approval_len: usize, clear_len: usize| -> u64 {
        let txn = Transaction {
            txn_type: TxnType::Appl,
            approval_program: Some(vec![0u8; approval_len].into()),
            clear_state_program: Some(vec![0u8; clear_len].into()),
            ..Default::default()
        };
        algo_validate::required_fee_for_txn(&txn, &params).0
    };

    async fn run_program_case(
        c: &reqwest::Client,
        sk: &ed25519_dalek::SigningKey,
        label: &'static str,
        approval: Vec<u8>,
        clear: Vec<u8>,
        epp: u32,
        fee: u64,
    ) -> CaseOutcome {
        let mutate = |txn: &mut Transaction| {
            txn.txn_type = TxnType::Appl;
            txn.approval_program = Some(approval.clone().into());
            txn.clear_state_program = Some(clear.clone().into());
            txn.extra_program_pages = epp;
            txn.global_state_schema = Some(StateSchema {
                num_uint: 0,
                num_byte_slice: 0,
            });
        };
        run_case(c, sk, label, mutate, fee).await
    }

    // At the soft (fee-free) limit, with exactly enough extra pages.
    let epp = epp_for(soft_limit);
    let approval_len = soft_limit - clear_len;
    let approval = program_of_len(approval_len, 8);
    let outcome = run_program_case(
        &c,
        &sk,
        "program_at_soft_cap_min_fee",
        approval,
        clear_program.clone(),
        epp,
        params.min_txn_fee,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, true) {
        failures.push(e);
    }

    // Just over the soft (fee-free) limit -- needs one more extra page for
    // well-formedness, and a surcharge for the fee.
    let over_soft = soft_limit + 50;
    let over_soft_required = required_fee(over_soft - clear_len, clear_len);
    let epp = epp_for(over_soft);
    let approval_len = over_soft - clear_len;
    let approval = program_of_len(approval_len, 8);
    let outcome = run_program_case(
        &c,
        &sk,
        "program_over_soft_min_fee_reject",
        approval.clone(),
        clear_program.clone(),
        epp,
        params.min_txn_fee,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }
    let outcome = run_program_case(
        &c,
        &sk,
        "program_over_soft_exact_fee_accept",
        approval.clone(),
        clear_program.clone(),
        epp,
        over_soft_required,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, true) {
        failures.push(e);
    }
    let outcome = run_program_case(
        &c,
        &sk,
        "program_over_soft_fee_minus_one_reject",
        approval,
        clear_program.clone(),
        epp,
        over_soft_required - 1,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }

    // At the hard cap, using the maximum extra pages.
    let hard_required = required_fee(hard_limit - clear_len, clear_len);
    let approval = program_of_len(hard_limit - clear_len, 8);
    let outcome = run_program_case(
        &c,
        &sk,
        "program_at_hard_cap_exact_fee_accept",
        approval.clone(),
        clear_program.clone(),
        hard_epp,
        hard_required,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, true) {
        failures.push(e);
    }
    let outcome = run_program_case(
        &c,
        &sk,
        "program_at_hard_cap_fee_minus_one_reject",
        approval,
        clear_program.clone(),
        hard_epp,
        hard_required - 1,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }

    // Over the hard cap, even at max extra pages: rejected regardless of fee.
    let approval = program_of_len(hard_limit + 1 - clear_len, 8);
    let outcome = run_program_case(
        &c,
        &sk,
        "program_over_hard_cap_reject_unconditional",
        approval,
        clear_program.clone(),
        hard_epp,
        hard_required + 1_000_000,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }

    // ExtraProgramPages itself over MaxAbsoluteExtraProgramPages: rejected
    // unconditionally, independent of program size or fee.
    let outcome = run_program_case(
        &c,
        &sk,
        "program_epp_over_absolute_max_reject_unconditional",
        program_of_len(20, 8),
        clear_program,
        hard_epp + 1,
        hard_required + 1_000_000,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }

    assert!(
        failures.is_empty(),
        "app-program size-pricing boundary mismatches:\n{}",
        failures.join("\n\n")
    );
}

// ---------------------------------------------------------------------------
// 4. LogicSig program bytes: LogicSigMaxSize (1000, soft/pooled) /
//    MaxAbsoluteLogicSigProgramSize (16000, hard/unconditional).
// ---------------------------------------------------------------------------

/// Builds a self-payment (amount 0, sender == receiver == dev account)
/// authorized by a delegated LogicSig running `program`, and submits it to
/// `base`.
async fn submit_lsig_txn(
    c: &reqwest::Client,
    base: &str,
    sk: &ed25519_dalek::SigningKey,
    program: Vec<u8>,
    fee: u64,
    note_tag: &str,
) -> SubmitResult {
    let mut txn = base_txn(c, base).await;
    txn.txn_type = TxnType::Pay;
    txn.receiver = dev_address();
    txn.amount = 0;
    txn.fee = fee;
    txn.note = ByteBuf::from(unique_note(note_tag));

    let sig = sign_delegated_lsig(&program, sk);
    let stx = SignedTransaction {
        txn,
        lsig: Some(LogicSig {
            logic: ByteBuf::from(program),
            sig,
            ..Default::default()
        }),
        ..Default::default()
    };
    submit(c, base, &encode(&stx)).await
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn logicsig_size_pricing_boundaries_match_live() {
    let c = client();
    let sk = dev_signing_key();
    let params = v42_params();
    let soft = params.logic_sig_max_size as usize; // free pool for a group of 1
    let hard = params.max_absolute_logic_sig_program_size as usize;
    let mut failures = Vec::new();

    let required_fee_for_lsig = |program_len: usize| -> u64 {
        let group_txn = SignedTransaction {
            txn: Transaction {
                txn_type: TxnType::Pay,
                fee: 0,
                ..Default::default()
            },
            lsig: Some(LogicSig {
                logic: vec![0u8; program_len].into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let group = [&group_txn];
        let usage = algo_validate::txn_fee_factor(&group_txn.txn, &params)
            + algo_validate::logic_sig_program_fee_contribution(&group, &params);
        algo_validate::required_fee_for_usage(usage, &params).0
    };

    async fn run_lsig_case(
        c: &reqwest::Client,
        sk: &ed25519_dalek::SigningKey,
        version: u8,
        label: &'static str,
        program_len: usize,
        fee: u64,
    ) -> CaseOutcome {
        let program = program_of_len(program_len, version);
        let go = submit_lsig_txn(
            c,
            &go_url(),
            sk,
            program.clone(),
            fee,
            &format!("{label}-go"),
        )
        .await;
        let rust =
            submit_lsig_txn(c, &rust_url(), sk, program, fee, &format!("{label}-rust")).await;
        CaseOutcome { label, go, rust }
    }

    // At the free pool (group of 1): no surcharge.
    let outcome = run_lsig_case(&c, &sk, 6, "lsig_at_pool_min_fee", soft, params.min_txn_fee).await;
    if let Err(e) = assert_case_parity(&outcome, true) {
        failures.push(e);
    }

    // Just over the free pool.
    let over_soft = soft + 50;
    let over_soft_required = required_fee_for_lsig(over_soft);
    let outcome = run_lsig_case(
        &c,
        &sk,
        6,
        "lsig_over_pool_min_fee_reject",
        over_soft,
        params.min_txn_fee,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }
    let outcome = run_lsig_case(
        &c,
        &sk,
        6,
        "lsig_over_pool_exact_fee_accept",
        over_soft,
        over_soft_required,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, true) {
        failures.push(e);
    }
    let outcome = run_lsig_case(
        &c,
        &sk,
        6,
        "lsig_over_pool_fee_minus_one_reject",
        over_soft,
        over_soft_required - 1,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }

    // At the hard (absolute) cap.
    let hard_required = required_fee_for_lsig(hard);
    let outcome = run_lsig_case(
        &c,
        &sk,
        6,
        "lsig_at_absolute_cap_exact_fee_accept",
        hard,
        hard_required,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, true) {
        failures.push(e);
    }
    let outcome = run_lsig_case(
        &c,
        &sk,
        6,
        "lsig_at_absolute_cap_fee_minus_one_reject",
        hard,
        hard_required - 1,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }

    // Over the hard cap: rejected regardless of fee or pooling.
    let outcome = run_lsig_case(
        &c,
        &sk,
        6,
        "lsig_over_absolute_cap_reject_unconditional",
        hard + 1,
        hard_required + 1_000_000,
    )
    .await;
    if let Err(e) = assert_case_parity(&outcome, false) {
        failures.push(e);
    }

    assert!(
        failures.is_empty(),
        "LogicSig size-pricing boundary mismatches:\n{}",
        failures.join("\n\n")
    );
}

/// Group-pooled case (#703's "including group-pooled cases" criterion): a
/// group of 3 transactions where only one carries an oversized LogicSig
/// program. The free byte pool is `len(txgroup) * LogicSigMaxSize`, pooled
/// across the whole group, and the fee surcharge/requirement is a *group*
/// total that can be paid via any member's `fee` field -- not necessarily
/// the one carrying the oversized program.
#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn logicsig_group_pooled_size_pricing_boundary_matches_live() {
    let c = client();
    let sk = dev_signing_key();
    let params = v42_params();
    let group_size = 3usize;
    let pool = group_size * params.logic_sig_max_size as usize;
    let over_pool = pool + 50;
    let program = program_of_len(over_pool, 6);
    let mut failures = Vec::new();

    // Required total group fee: 3 ordinary pay txns' usage + the pooled
    // LogicSig program-byte surcharge (computed the same way
    // `summarize_fees`/`logic_sig_program_fee_contribution` do).
    let plain = SignedTransaction {
        txn: Transaction {
            txn_type: TxnType::Pay,
            ..Default::default()
        },
        ..Default::default()
    };
    let lsig_txn = SignedTransaction {
        txn: Transaction {
            txn_type: TxnType::Pay,
            ..Default::default()
        },
        lsig: Some(LogicSig {
            logic: program.clone().into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let group_for_usage = [&lsig_txn, &plain, &plain];
    let (usage, _paid) = algo_validate::summarize_fees(&group_for_usage, &params);
    let required_total = algo_validate::required_fee_for_usage(usage, &params).0;

    async fn submit_group(
        c: &reqwest::Client,
        base: &str,
        sk: &ed25519_dalek::SigningKey,
        program: &[u8],
        lsig_fee: u64,
        min_fee: u64,
        label: &str,
    ) -> SubmitResult {
        let mut lsig_txn = base_txn(c, base).await;
        lsig_txn.txn_type = TxnType::Pay;
        lsig_txn.receiver = dev_address();
        lsig_txn.amount = 0;
        lsig_txn.fee = lsig_fee;
        lsig_txn.note = ByteBuf::from(unique_note(&format!("{label}-lsig")));

        let mut plain_a = base_txn(c, base).await;
        plain_a.txn_type = TxnType::Pay;
        plain_a.receiver = dev_address();
        plain_a.amount = 0;
        plain_a.fee = min_fee;
        plain_a.note = ByteBuf::from(unique_note(&format!("{label}-a")));

        let mut plain_b = base_txn(c, base).await;
        plain_b.txn_type = TxnType::Pay;
        plain_b.receiver = dev_address();
        plain_b.amount = 0;
        plain_b.fee = min_fee;
        plain_b.note = ByteBuf::from(unique_note(&format!("{label}-b")));

        let group_id = compute_group_id(&[lsig_txn.clone(), plain_a.clone(), plain_b.clone()]);
        lsig_txn.group = group_id.0;
        plain_a.group = group_id.0;
        plain_b.group = group_id.0;

        let lsig_sig = sign_delegated_lsig(program, sk);
        let lsig_stx = SignedTransaction {
            txn: lsig_txn,
            lsig: Some(LogicSig {
                logic: ByteBuf::from(program.to_vec()),
                sig: lsig_sig,
                ..Default::default()
            }),
            ..Default::default()
        };
        let plain_a_stx = sign(&mut plain_a, sk);
        let plain_b_stx = sign(&mut plain_b, sk);

        let mut bytes = encode(&lsig_stx);
        bytes.extend(encode(&plain_a_stx));
        bytes.extend(encode(&plain_b_stx));
        submit(c, base, &bytes).await
    }

    // Reject: group pays required_total - 1 (short by one microAlgo on the
    // LogicSig-bearing member).
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = submit_group(
            &c,
            &base,
            &sk,
            &program,
            required_total - 1 - 2 * params.min_txn_fee,
            params.min_txn_fee,
            &format!("pooled-reject-{label}"),
        )
        .await;
        if resp.accepted() {
            failures.push(format!(
                "{base}: group paying required_total-1 should be rejected, got 200: {}",
                resp.text()
            ));
        }
    }

    // Accept: group pays exactly required_total (split across members).
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = submit_group(
            &c,
            &base,
            &sk,
            &program,
            required_total - 2 * params.min_txn_fee,
            params.min_txn_fee,
            &format!("pooled-accept-{label}"),
        )
        .await;
        if !resp.accepted() {
            failures.push(format!(
                "{base}: group paying exactly required_total should be accepted, got {}: {}",
                resp.status,
                resp.text()
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "LogicSig group-pooled size-pricing boundary mismatches:\n{}",
        failures.join("\n\n")
    );
}
