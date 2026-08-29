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

//! Live dual-node verification that `GET /v2/ledger/supply`'s `online-stake`
//! excludes stake behind an expired-but-still-online participation key
//! (issue #518).
//!
//! Extends `live_go_parity.rs`'s dual-node harness (see that file's module
//! docs for setup) with a crafted keyreg scenario. Both go-algorand
//! v4.6.0-stable and algod-rust boot from the identical dev-mode genesis
//! (`docker/localnet-rust/data/genesis.json`, consensus V42 since issue
//! #720), whose only
//! *online* account is the funded dev wallet
//! (`E4A7NFAARAKFG4ZK7KQ7VZBO5XEQIUKBK2U3KNLAFTX6R3HTJBFG75MQZE`) -- with no
//! participation key registered yet (`VoteLastValid == 0` in the genesis
//! alloc), so it does not count as "expired" under go's
//! `d.VoteLastValid != 0 && voteRnd > d.VoteLastValid` predicate
//! (`ledger/acctonline.go`) until this test registers one.
//!
//! Since each node runs its **own** independent dev-mode chain (see
//! `live_txn_cross_verification.rs`'s module docs on "cross-verification"),
//! the scenario is driven identically -- same keyreg parameters, same number
//! of round-advancing filler transactions -- against each node in turn, and
//! the *same resulting online-stake value* (0, since the dev wallet is the
//! only online account) is asserted on each side independently.
//!
//! # Why round 320+
//!
//! `online-stake` is computed at agreement's lookback round
//! (`BalanceRound(latest) = latest.SubSaturate(MaxBalLookback)`,
//! `MaxBalLookback = 320`, unchanged from v41 through v42 -- set once at
//! v7's definition and never overridden by a later version). Both go's
//! `onlineCirculation`
//! and algod-rust's `online_circulation_at_round` skip the expired-stake
//! subtraction entirely while that lookback round is still 0 (go's explicit
//! genesis-balance carve-out for the first `MaxBalLookback` rounds) -- so
//! this test must advance the dev-mode chain past round 320 for the
//! exclusion to be observable via the REST API on *either* implementation,
//! not just algod-rust's. This is inherent to the feature (same threshold
//! go-algorand itself requires), not a workaround.
//!
//! Advancing ~330 rounds via ~330 sequential filler transactions on each
//! node is why this lives in its own file rather than `live_txn_cross_verification.rs`:
//! it is slow enough (a minute or so per node) that it should not gate the
//! fast suites, and it needs `--test-threads=1` for the same reason that
//! file does (shared on-chain dev-account state).
//!
//! # `status` is now compared too (issue #526)
//!
//! Building this test live originally surfaced a real divergence unrelated
//! to #518's accessor fix: go-algorand's real block proposer *also*
//! independently sweeps expired online accounts to `Offline`
//! (`resetExpiredOnlineAccountsParticipationKeys`, `ledger/eval/eval.go`) --
//! confirmed live, go reports `status: "Offline"` well before round 320 in
//! this scenario -- while algod-rust's `--dev` block producer
//! (`bin/algod-rust/src/dev_producer.rs`, via
//! `SimpleBlockEvaluator::generate_block` in
//! `bin/algod-rust/src/commands/participate.rs`) did not populate
//! `expired_participation_accounts` when assembling its own blocks, so on
//! algod-rust's self-produced chain the account stayed `status: "Online"`
//! indefinitely. Issue #526 closed that gap (proposal-time computation via
//! `SqliteLedger::expired_participation_account_candidates`, mirroring the
//! expiry half of go's `generateKnockOfflineAccountsList`), so this test now
//! asserts `status`/`online-money` on both implementations, not just the
//! `online-stake` field #518 governs.
//!
//! ```text
//! make validate-api-up
//! cargo test --package algod-rust --test live_online_circulation_expiry \
//!   -- --ignored --nocapture --test-threads=1
//! make validate-api-down
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use algo_codec::{canonical_encode_transaction, compute_txn_id};
use algo_types::{Round, SignedTransaction, TxnType};
use ed25519_dalek::Signer;

const DEV_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// `docs/DEV_WORKFLOW.md`'s funded dev account (25-word mnemonic).
const DEV_MNEMONIC: &str = "under this above produce during card issue fire gloom reopen topple rough cat smooth salad put broken decade vocal loud pulp gauge hurdle absorb olympic";

/// `MaxBalLookback` (`config/consensus.go`,
/// `2 * SeedRefreshInterval(80) * SeedLookback(2)`), unchanged from v41
/// through v42 (this harness's consensus version since issue #720). The round the
/// expired-stake exclusion first becomes observable at is strictly beyond
/// this (see module docs).
const MAX_BAL_LOOKBACK: u64 = 320;

/// How many rounds past `MAX_BAL_LOOKBACK` (and past the keyreg's
/// `vote_last`) to advance before checking `online-stake`, as headroom
/// against off-by-one lookback arithmetic.
const SAFETY_MARGIN: u64 = 10;

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
    format!("live_online_circulation_expiry:{tag}:{nanos}").into_bytes()
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
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    STANDARD.decode(s).expect("valid base64")
}

/// A base transaction with a fixed, always-valid `[1, 1000]` window (mirrors
/// `live_txn_cross_verification.rs::payment_txid_is_identical_across_nodes_for_identical_input`'s
/// rationale) so the ~330 filler payments below need only one
/// `/v2/transactions/params` fetch for genesis-hash/genesis-id/min-fee, not
/// one per round advanced.
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
    let genesis_hash_bytes = base64_decode(params["genesis-hash"].as_str().unwrap());
    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&genesis_hash_bytes);
    TxnTemplate {
        genesis_hash,
        genesis_id: params["genesis-id"].as_str().unwrap().to_string(),
        min_fee: params["min-fee"].as_u64().unwrap().max(1000),
    }
}

impl TxnTemplate {
    fn base_txn(&self) -> algo_types::Transaction {
        algo_types::Transaction {
            sender: dev_address(),
            fee: self.min_fee,
            first_valid: Round(1),
            last_valid: Round(1000),
            genesis_id: self.genesis_id.clone(),
            genesis_hash: self.genesis_hash,
            ..Default::default()
        }
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

/// POST a signed transaction, transparently retrying go-algorand dev-mode's
/// transient just-booted "no pending block evaluator" pool error -- see
/// `live_txn_cross_verification.rs::submit`'s doc comment for why.
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

/// Submit a self-payment (amount 0) and wait for it to confirm. In dev
/// mode each accepted transaction group is immediately committed as its own
/// block, so this reliably advances the node's round by exactly one.
async fn advance_one_round(client: &reqwest::Client, base: &str, tmpl: &TxnTemplate, tag: &str) {
    let sk = dev_signing_key();
    let mut txn = tmpl.base_txn();
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

/// Submit filler self-payments (see [`advance_one_round`]) until the node's
/// current round is at least `target`.
async fn advance_to_round(client: &reqwest::Client, base: &str, tmpl: &TxnTemplate, target: u64) {
    let mut round = current_round(client, base).await;
    let mut i: u64 = 0;
    while round < target {
        advance_one_round(client, base, tmpl, &format!("advance-{i}")).await;
        i += 1;
        round = current_round(client, base).await;
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; run with --test-threads=1; slow (~1-2 min per node advancing ~330 rounds); see module docs"]
async fn online_stake_excludes_expired_participation_key_live() {
    let c = client();

    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let tmpl = txn_template(&c, &base).await;
        let dev = dev_address().to_algorand_string();
        let sk = dev_signing_key();

        // Baseline: the dev wallet is the genesis's only online account
        // (`onl: 1`, docker/localnet-rust/data/genesis.json) but has never
        // registered a participation key, so `online-money` (current
        // aggregate) must already be its full balance.
        let (status, supply_before) = get_json(&c, &base, "/v2/ledger/supply").await;
        assert_eq!(
            status, 200,
            "{label}: GET /v2/ledger/supply: {supply_before}"
        );
        let online_money_before = supply_before["online-money"].as_u64().unwrap();
        assert!(
            online_money_before > 0,
            "{label}: dev wallet must already be online with nonzero stake"
        );

        // 1. Register a participation key with a short vote-key validity
        //    window (`ledger/apply/application.go`'s keyreg path requires
        //    VoteLast > current round -- D14 coherency check, both go and
        //    algod-rust enforce this at submission time).
        let round_at_keyreg = current_round(&c, &base).await;
        let vote_first = round_at_keyreg + 1;
        let vote_last = round_at_keyreg + 5;
        let mut keyreg = tmpl.base_txn();
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

        // Sanity: the account is now Online with the registered
        // vote-last-valid, on both implementations.
        let (status, account) = get_json(&c, &base, &format!("/v2/accounts/{dev}")).await;
        assert_eq!(status, 200, "{label}: GET /v2/accounts/{dev}: {account}");
        assert_eq!(
            account["status"], "Online",
            "{label}: dev wallet must report Online after keyreg"
        );
        assert_eq!(
            account["participation"]["vote-last-valid"].as_u64(),
            Some(vote_last),
            "{label}: registered vote-last-valid must be reported back"
        );

        // 2. Advance the dev-mode chain until the LOOKBACK round itself
        //    (current_round - MaxBalLookback) is at or past the round the
        //    keyreg confirmed at -- not just past `vote_last` in absolute
        //    terms. go's (and algod-rust's) `onlineCirculation(rnd, voteRnd)`
        //    reads the online-account snapshot as it stood AT `rnd`; if
        //    `rnd` (the lookback round) predates the keyreg's confirmation,
        //    that historical snapshot still shows `VoteLastValid == 0`
        //    (unregistered) and the exclusion legitimately does not apply
        //    yet, no matter how far the *current* round has advanced past
        //    `vote_last`. This only matters when this test runs after other
        //    round-advancing suites in the same harness session (`make
        //    validate-api`'s ordered run, where `live_txn_cross_verification`
        //    and `live_longpoll_parity` already advanced the shared dev-mode
        //    chain before this test's keyreg) -- `round_at_keyreg` is then
        //    already nonzero, so `target_round` must scale with it, not just
        //    with the fixed `MaxBalLookback` threshold (a bug caught by
        //    exactly this ordering in CI while building this test).
        let target_round = round_at_keyreg + MAX_BAL_LOOKBACK + SAFETY_MARGIN;
        advance_to_round(&c, &base, &tmpl, target_round).await;

        // 3. The participation key is now expired (`VoteLastValid <
        //    current round`). `online-stake` (the lookback-round,
        //    expiry-excluding accessor #518 fixes) must now exclude the dev
        //    wallet's stake entirely -- it is the only online account in
        //    this genesis, so the expected result is exactly 0.
        let (status, supply_after) = get_json(&c, &base, "/v2/ledger/supply").await;
        assert_eq!(
            status, 200,
            "{label}: GET /v2/ledger/supply: {supply_after}"
        );
        let online_stake_after = supply_after["online-stake"].as_u64().unwrap();

        assert_eq!(
            online_stake_after, 0,
            "{label}: online-stake must exclude the sole online account's stake \
             once its participation key has expired (issue #518); \
             online-stake={online_stake_after} (full supply response: {supply_after})"
        );

        // 4. Both implementations' block proposers independently sweep an
        //    expired online account to Offline as part of ordinary block
        //    production -- go via `resetExpiredOnlineAccountsParticipationKeys`
        //    (`ledger/eval/eval.go`), algod-rust via
        //    `SimpleBlockEvaluator::generate_block` populating
        //    `expired_participation_accounts` (issue #526) which
        //    `algo_ledger::apply::reset_expired_online_accounts` then
        //    applies. `online-money` (the current, non-lookback aggregate)
        //    is swept to 0 by that same mechanism.
        let (status, account_after) = get_json(&c, &base, &format!("/v2/accounts/{dev}")).await;
        assert_eq!(
            status, 200,
            "{label}: GET /v2/accounts/{dev}: {account_after}"
        );
        assert_eq!(
            account_after["status"], "Offline",
            "{label}: dev wallet must be swept Offline once its participation \
             key has expired (go: eval.go's reset sweep; algod-rust: issue #526); \
             account={account_after}"
        );
        let online_money_after = supply_after["online-money"].as_u64().unwrap();
        assert_eq!(
            online_money_after, 0,
            "{label}: online-money must be 0 once the sole online account is \
             swept Offline; online-money={online_money_after} \
             (full supply response: {supply_after})"
        );
    }
}
