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

//! Live dual-node verification that a real block's state-proof-tracking
//! voters commitment (`"spt"[0]."v"`) and online total weight
//! (`"spt"[0]."t"`) are byte-for-byte reproducible by independently
//! recomputing them from the same node's own REST-observed account/header
//! state (issue #780's two remaining acceptance criteria).
//!
//! PR #782 wired `algo_ledger::voters_tracker` (the `votersTracker`
//! snapshot cache) and `algo_ledger::voters` (issue #758's selection +
//! commitment math) into block production (`block_header::next_state_proof_tracking`)
//! and validation (`apply::validate_state_proof_tracking`), so every
//! `--dev` node in this harness now embeds real (non-zero) `"v"`/`"t"`
//! values at `StateProofInterval` (256, unchanged from v34 through this
//! harness's v42) boundaries -- but nothing yet checked those values
//! against anything other than fabricated unit-test inputs
//! (`voters.rs`'s and `voters_tracker.rs`'s own `#[cfg(test)]` modules).
//!
//! This file closes both of issue #780's remaining acceptance criteria in
//! one live scenario, run identically against each independent node in the
//! dual-node harness:
//!
//! - **Byte-level parity against a real go-algorand-produced root**: the
//!   `go` iteration below drives go-algorand v5.0.0-stable's own `--dev`
//!   node to a real state-proof voters round, then independently
//!   recomputes the expected root/weight from go's own live-observed
//!   account and block-header state using algod-rust's *own* production
//!   commitment code (`algo_ledger::voters::{select_top_online_accounts,
//!   build_voters_tree}`) and asserts byte-for-byte equality against the
//!   `"v"`/`"t"` go itself embedded in its block header. This is a genuine
//!   oracle check against real go-algorand output, not a replay of a
//!   captured fixture.
//! - **Live mixed-cluster verification**: the `rust` iteration drives
//!   algod-rust's own live `--dev` node through the identical scenario on
//!   the same shared genesis, exercising its *real* block-production
//!   (`next_state_proof_tracking`) and block-validation
//!   (`apply::validate_state_proof_tracking`) code paths for a live round,
//!   then applies the same independent-recomputation oracle check to
//!   algod-rust's own output.
//!
//! # Why not compare go's root against rust's root directly?
//!
//! Each node runs its own independent dev-mode chain (see
//! `live_txn_cross_verification.rs`'s module docs on "cross-verification"),
//! and by the time this file runs (last in `make validate-api`'s ordered
//! sequence -- see the Makefile's `validate-api` target) the two chains'
//! current rounds have already diverged by whatever residue earlier test
//! files left (retries, timing). A direct root-for-root comparison would
//! require both chains to reach an *identical* round with *identical*
//! accumulated `RewardsLevel`, which this harness does not guarantee.
//! Recomputing each side's own expected value from its own observed state
//! sidesteps that entirely: it is a self-contained oracle check per node,
//! and running it against go-algorand specifically is what makes the go
//! iteration byte-level parity evidence against real go-algorand output.
//!
//! # Why round 256+ is reachable in CI
//!
//! `StateProofInterval` is 256 and `StateProofVotersLookback` is 16 for
//! every consensus version from v34 through this harness's v42 (see
//! `config/consensus.go`, unchanged since `v34.StateProofInterval = 256`).
//! `live_online_circulation_expiry.rs` already demonstrates advancing a
//! dev-mode chain ~330 rounds via sequential filler self-payments
//! completes in roughly a minute per node; reaching the next
//! `StateProofInterval` boundary after whatever round earlier test files
//! left the chain at is the same order of magnitude and well within this
//! workflow's 25-minute timeout.
//!
//! Because the *voting* participant's key must stay valid through the
//! round the state proof (not just the commitment) would apply to --
//! `vote_rnd = snapshot_round + StateProofVotersLookback + StateProofInterval`,
//! one full interval beyond the block whose header this test reads -- the
//! keyreg below registers a vote-key window far longer than the handful of
//! rounds this test actually advances through.
//!
//! ```text
//! make validate-api-up
//! cargo test --package algod-rust --test live_state_proof_voters_parity \
//!   -- --ignored --nocapture --test-threads=1
//! make validate-api-down
//! ```

use std::time::Duration;

use algo_codec::{canonical_encode_transaction, compute_txn_id};
use algo_ledger::voters::{build_voters_tree, select_top_online_accounts, OnlineAccountCandidate};
use algo_types::consensus::{consensus_params_for_version, CONSENSUS_V42};
use algo_types::{Address, Round, SignedTransaction, TxnType};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::Signer;

const DEV_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// `docs/DEV_WORKFLOW.md`'s funded dev account (25-word mnemonic).
const DEV_MNEMONIC: &str = "under this above produce during card issue fire gloom reopen topple rough cat smooth salad put broken decade vocal loud pulp gauge hurdle absorb olympic";

/// Headroom (in rounds) between the keyreg's confirmation and the snapshot
/// round this test targets, so the keyreg is unambiguously applied before
/// the snapshot is taken regardless of whichever round earlier test files
/// in the same `make validate-api` run left this chain at.
const SAFETY_MARGIN: u64 = 20;

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
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("live_state_proof_voters_parity:{tag}:{nanos}").into_bytes()
}

fn dev_signing_key() -> ed25519_dalek::SigningKey {
    let seed = algo_consensus_crypto::passphrase::mnemonic_to_key(DEV_MNEMONIC)
        .expect("dev mnemonic must decode to a valid key");
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

fn dev_address() -> Address {
    Address(dev_signing_key().verifying_key().to_bytes())
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

struct SubmitResult {
    status: u16,
    body: Vec<u8>,
}

impl SubmitResult {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// POST a signed transaction, transparently retrying dev-mode's transient
/// just-booted "no pending block evaluator" pool error (same rationale as
/// `live_online_circulation_expiry.rs::submit`).
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

async fn get_msgpack(client: &reqwest::Client, base: &str, path: &str) -> (u16, rmpv::Value) {
    let resp = client
        .get(format!("{base}{path}"))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let bytes = resp.bytes().await.unwrap();
    let value = rmpv::decode::read_value(&mut bytes.as_ref())
        .unwrap_or_else(|e| panic!("GET {base}{path}: failed to decode msgpack body: {e}"));
    (status, value)
}

async fn current_round(client: &reqwest::Client, base: &str) -> u64 {
    let (status, body) = get_json(client, base, "/v2/status").await;
    assert_eq!(status, 200, "{base}: GET /v2/status: {body}");
    body["last-round"].as_u64().unwrap()
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
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

struct TxnTemplate {
    genesis_hash: [u8; 32],
    genesis_id: String,
    min_fee: u64,
}

async fn txn_template(client: &reqwest::Client, base: &str) -> TxnTemplate {
    let params: serde_json::Value = client
        .get(format!("{base}/v2/transactions/params"))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let genesis_hash_bytes = BASE64
        .decode(params["genesis-hash"].as_str().unwrap())
        .expect("valid base64");
    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&genesis_hash_bytes);
    TxnTemplate {
        genesis_hash,
        genesis_id: params["genesis-id"].as_str().unwrap().to_string(),
        min_fee: params["min-fee"].as_u64().unwrap().max(1000),
    }
}

/// go's `MaxTxnLife` (`config/consensus.go`: `1000`, unchanged since v7):
/// the hard cap on `LastValid - FirstValid` for *any* transaction's own
/// validity window -- distinct from (and much smaller than) a keyreg's
/// `VoteFirst`/`VoteLast` participation-key window, which is bounded
/// separately by `MaxKeyregValidPeriod` (~16.7M rounds). Every
/// transaction built below must stay within this window regardless of how
/// far this test advances the chain, since -- unlike the original
/// `live_online_circulation_expiry.rs`, which runs early enough that a
/// fixed `[1, 1000]` window suffices for its whole run -- this file
/// deliberately runs last, so the chain's current round may already be
/// well past 1000 before this test's own advancement even starts.
const MAX_TXN_LIFE: u64 = 1000;

impl TxnTemplate {
    /// Build a transaction valid starting at `first_valid`, with a window
    /// capped by [`MAX_TXN_LIFE`].
    fn base_txn(&self, first_valid: u64) -> algo_types::Transaction {
        algo_types::Transaction {
            sender: dev_address(),
            fee: self.min_fee,
            first_valid: Round(first_valid),
            last_valid: Round(first_valid + MAX_TXN_LIFE),
            genesis_id: self.genesis_id.clone(),
            genesis_hash: self.genesis_hash,
            ..Default::default()
        }
    }
}

/// Submit a self-payment (amount 0) and wait for it to confirm; each
/// accepted dev-mode group is its own block, so this advances the round by
/// exactly one.
async fn advance_one_round(client: &reqwest::Client, base: &str, tmpl: &TxnTemplate, tag: &str) {
    let sk = dev_signing_key();
    let first_valid = current_round(client, base).await;
    let mut txn = tmpl.base_txn(first_valid);
    txn.txn_type = TxnType::Pay;
    txn.receiver = dev_address();
    txn.amount = 0;
    txn.note = unique_note(tag).into();
    let expected_txid = compute_txn_id(&txn).to_string();
    let stx = sign(&mut txn, &sk);
    let bytes = encode(&stx);

    let resp = submit(client, base, &bytes).await;
    assert_eq!(
        resp.status,
        200,
        "{base}: filler self-payment rejected: {}",
        resp.text()
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    wait_for_confirmation(client, base, &expected_txid, deadline).await;
}

async fn advance_to_round(client: &reqwest::Client, base: &str, tmpl: &TxnTemplate, target: u64) {
    let mut round = current_round(client, base).await;
    let mut i: u64 = 0;
    while round < target {
        advance_one_round(client, base, tmpl, &format!("advance-{i}")).await;
        i += 1;
        round = current_round(client, base).await;
    }
}

/// go `basics.Round.RoundUpToMultipleOf` (`data/basics/units.go:161`),
/// mirroring `algo_ledger::block_header::round_up_to_multiple_of` (private
/// to that crate) so this test can compute the same snapshot/consuming
/// round pair the production code itself uses.
fn round_up_to_multiple_of(round: u64, n: u64) -> u64 {
    round.saturating_add(n - 1) / n * n
}

/// Find `map[key]` in an `rmpv::Value::Map` keyed by strings.
fn map_get_str<'a>(v: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    match v {
        rmpv::Value::Map(m) => m
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v),
        _ => None,
    }
}

/// Find `map[key]` in an `rmpv::Value::Map` keyed by integers (used for the
/// `"spt"` map, whose keys are `protocol.StateProofType` values, not
/// strings).
fn map_get_u64key(v: &rmpv::Value, key: u64) -> Option<&rmpv::Value> {
    match v {
        rmpv::Value::Map(m) => m
            .iter()
            .find(|(k, _)| k.as_u64() == Some(key))
            .map(|(_, v)| v),
        _ => None,
    }
}

/// The real, live-produced `"spt"[0]."v"`/`"t"` fields read out of a
/// fetched block's msgpack envelope, defaulting to empty/zero when the
/// round did not carry a `StateProofBasic` entry (shouldn't happen at the
/// consuming round this test targets, but mirrors go's own zero-fill
/// rather than panicking if it ever did).
fn read_spt_v_and_t(block_envelope: &rmpv::Value) -> (Vec<u8>, u64) {
    let block = map_get_str(block_envelope, "block").expect("envelope must have a \"block\" key");
    let Some(spt) = map_get_str(block, "spt") else {
        return (Vec::new(), 0);
    };
    // protocol.StateProofBasic == 0.
    let Some(basic) = map_get_u64key(spt, 0) else {
        return (Vec::new(), 0);
    };
    let v = map_get_str(basic, "v")
        .and_then(|v| v.as_slice())
        .map(|b| b.to_vec())
        .unwrap_or_default();
    let t = map_get_str(basic, "t")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    (v, t)
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; slow (advances each node to the next StateProofInterval boundary); see module docs"]
async fn voters_commitment_matches_independent_recomputation_from_live_state() {
    let c = client();
    let params = consensus_params_for_version(CONSENSUS_V42)
        .expect("harness genesis pins consensus V42 (see docker/localnet-rust/data/genesis.json)");
    let interval = params.state_proof_interval;
    let lookback = params.state_proof_voters_lookback;
    assert_eq!(interval, 256, "sanity: V42 StateProofInterval");
    assert_eq!(lookback, 16, "sanity: V42 StateProofVotersLookback");

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let tmpl = txn_template(&c, &base).await;
        let dev = dev_address().to_algorand_string();
        let sk = dev_signing_key();

        // 1. Register (or re-register) a long-lived online participation
        //    key. The vote window must reach far past the block this test
        //    reads: the *voting* round go's `votersTracker` filters on is
        //    one full StateProofInterval beyond the consuming round itself
        //    (see module docs), so a window merely covering the target
        //    round is not enough.
        let round_at_keyreg = current_round(&c, &base).await;
        let vote_first = 1u64;
        let vote_last = round_at_keyreg + 5_000;
        let mut keyreg = tmpl.base_txn(round_at_keyreg);
        keyreg.txn_type = TxnType::Keyreg;
        keyreg.vote_pk = Some([0x11u8; 32]);
        keyreg.selection_pk = Some([0x22u8; 32]);
        keyreg.state_proof_pk = Some([0x33u8; 64]);
        keyreg.vote_first = vote_first;
        keyreg.vote_last = vote_last;
        keyreg.vote_key_dilution = 10_000;
        keyreg.note = unique_note(&format!("keyreg-{label}")).into();
        let keyreg_txid = compute_txn_id(&keyreg).to_string();
        let stx = sign(&mut keyreg, &sk);
        let bytes = encode(&stx);
        let resp = submit(&c, &base, &bytes).await;
        assert_eq!(
            resp.status,
            200,
            "{label}: online keyreg with vote_last={vote_last} rejected: {}",
            resp.text()
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        wait_for_confirmation(&c, &base, &keyreg_txid, deadline).await;
        let round_after_keyreg = current_round(&c, &base).await;

        // 2. Compute the snapshot round `r` ((r + lookback) % interval ==
        //    0) and the consuming round `c = r + lookback` (a StateProofInterval
        //    multiple) this scenario will exercise -- mirroring
        //    `algo_ledger::voters_tracker::{record_voters_snapshot,
        //    expected_voters_tracking}`'s own round arithmetic.
        let consuming_round =
            round_up_to_multiple_of(round_after_keyreg + SAFETY_MARGIN + lookback, interval);
        let snapshot_round = consuming_round - lookback;
        assert!(
            snapshot_round > round_after_keyreg,
            "{label}: snapshot round must be strictly after the keyreg confirmed"
        );

        // 3. Advance to the snapshot round, then immediately capture the
        //    dev wallet's *own* account state and that round's block header
        //    (for RewardsLevel) -- both only queryable "as of now" via the
        //    REST API, so this must happen before any further round
        //    advancement changes them.
        advance_to_round(&c, &base, &tmpl, snapshot_round).await;

        let (status, account) = get_json(&c, &base, &format!("/v2/accounts/{dev}")).await;
        assert_eq!(status, 200, "{label}: GET /v2/accounts/{dev}: {account}");
        assert_eq!(
            account["status"], "Online",
            "{label}: dev wallet must still be Online at the snapshot round"
        );
        let amount_without_pending_rewards = account["amount-without-pending-rewards"]
            .as_u64()
            .expect("amount-without-pending-rewards must be present");
        let rewards_base = account["reward-base"].as_u64().unwrap_or(0);
        let observed_vote_first = account["participation"]["vote-first-valid"]
            .as_u64()
            .expect("vote-first-valid must be present for an Online account");
        let observed_vote_last = account["participation"]["vote-last-valid"]
            .as_u64()
            .expect("vote-last-valid must be present for an Online account");
        let state_proof_key_b64 = account["participation"]["state-proof-key"].as_str();
        let mut state_proof_id = [0u8; 64];
        if let Some(b64) = state_proof_key_b64 {
            let decoded = BASE64.decode(b64).expect("valid base64 state-proof-key");
            assert_eq!(
                decoded.len(),
                64,
                "{label}: state-proof-key must be 64 bytes"
            );
            state_proof_id.copy_from_slice(&decoded);
        }

        let (block_status, snapshot_block) = get_msgpack(
            &c,
            &base,
            &format!("/v2/blocks/{snapshot_round}?format=msgpack"),
        )
        .await;
        assert_eq!(
            block_status, 200,
            "{label}: GET /v2/blocks/{snapshot_round}?format=msgpack"
        );
        let rewards_level_at_snapshot = map_get_str(&snapshot_block, "block")
            .and_then(|b| map_get_str(b, "earn"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // 4. Advance the rest of the way to the consuming round and read
        //    that block's real, live-produced "spt"[0] fields.
        advance_to_round(&c, &base, &tmpl, consuming_round).await;
        let (block_status, consuming_block) = get_msgpack(
            &c,
            &base,
            &format!("/v2/blocks/{consuming_round}?format=msgpack"),
        )
        .await;
        assert_eq!(
            block_status, 200,
            "{label}: GET /v2/blocks/{consuming_round}?format=msgpack"
        );
        let (actual_v, actual_t) = read_spt_v_and_t(&consuming_block);
        assert!(
            !actual_v.is_empty(),
            "{label}: round {consuming_round}'s \"spt\"[0].\"v\" must be non-empty -- \
             the sole online account's vote window must cover this round's voters snapshot; \
             full block: {consuming_block}"
        );
        assert!(
            actual_t > 0,
            "{label}: round {consuming_round}'s \"spt\"[0].\"t\" must be non-zero"
        );

        // 5. Independently recompute the expected root/weight from the
        //    live-observed state captured in step 3, using algod-rust's own
        //    production commitment code (issue #758's `algo_ledger::voters`)
        //    -- for the `go` iteration this is a genuine byte-level oracle
        //    check against real go-algorand-produced output; for the `rust`
        //    iteration this exercises algod-rust's own live block-production/
        //    validation path against the same independent oracle.
        let candidate = OnlineAccountCandidate {
            address: dev_address(),
            micro_algos: amount_without_pending_rewards,
            rewards_base,
            vote_first_valid: observed_vote_first,
            vote_last_valid: observed_vote_last,
            state_proof_id,
        };
        // go's `votersTracker.loadTree`: `stateProofRound := r + lookback + interval`.
        let vote_rnd = snapshot_round + lookback + interval;
        let selected = select_top_online_accounts(
            &[candidate],
            params.state_proof_top_voters,
            vote_rnd,
            params.reward_unit,
        );
        assert_eq!(
            selected.len(),
            1,
            "{label}: the dev wallet's vote window (first={observed_vote_first}, \
             last={observed_vote_last}) must cover vote_rnd={vote_rnd}"
        );
        let (expected_root, expected_weight) =
            build_voters_tree(&selected, rewards_level_at_snapshot, params.reward_unit)
                .unwrap_or_else(|e| panic!("{label}: build_voters_tree: {e}"));

        assert_eq!(
            expected_root, actual_v,
            "{label}: round {consuming_round}'s real voters commitment must equal the root \
             independently recomputed from this node's own observed account state as of round \
             {snapshot_round} (rewards_level={rewards_level_at_snapshot})"
        );
        assert_eq!(
            expected_weight, actual_t,
            "{label}: round {consuming_round}'s real online total weight must equal the weight \
             independently recomputed from this node's own observed account state as of round \
             {snapshot_round}"
        );
    }
}
