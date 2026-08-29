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

//! Headline end-to-end keyreg participation flow (TASK-185).
//!
//! Drives the full algokey-rust binary chain against a live `algod-go`
//! localnet:
//!
//!   generate account (library) → fund from faucet → `part generate` →
//!   `part keyreg` → `sign` → submit raw bytes → wait for confirmation →
//!   assert account flips to `Online` with the correct voting / selection /
//!   state-proof keys and validity window.
//!
//! Sibling tests cover the other Phase D edge cases listed in the task:
//!
//! - **Offline keyreg** — online account → `part keyreg --offline` → flips
//!   to `Offline`.
//! - **Reparent before keyreg** — partkey for account A → `part reparent`
//!   to B → keyreg using B → B goes online.
//! - **State-proof key presence** — the headline test inspects the
//!   pre-submission keyreg txn and asserts `state_proof_pk = Some([_; 64])`,
//!   matching Go's default `include_state_proof_keys = true`.
//!
//! Run with `--test-threads=1` so parallel test binaries don't race on
//! `Localnet::bring_up()`. The canonical invocation is:
//!
//! ```text
//! make localnet-up && \
//!   cargo test -p algokey-rust --features e2e --test e2e_keyreg \
//!     -- --test-threads=1
//! ```

#[path = "mod.rs"]
mod e2e;

use std::path::Path;

use algo_codec::canonical_encode_signed_transaction;
use algo_consensus_crypto::{key_to_mnemonic, mnemonic_to_key};
use algo_rest_client::SuggestedParams;
use algo_types::{Address, SignedTransaction};
use assert_cmd::Command as AssertCmd;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use tempfile::TempDir;

use e2e::Localnet;

/// Minimum funding for a participation account (10 algos in microAlgos) —
/// covers min-balance + keyreg fee with plenty of headroom.
const FUNDING_MICROALGOS: u64 = 10_000_000;

/// Validity window for both the partkey and the keyreg txn. Must be
/// `<= TXN_LIFE` (1000) per `algokey-rust part keyreg`'s security check.
const VALIDITY_ROUNDS: u64 = 1000;

/// Rounds to wait for confirmation. Devnet block intervals are sub-second
/// so this is generous.
const MAX_CONFIRMATION_ROUNDS: u64 = 10;

// ---------------------------------------------------------------------------
// Account generation + funding helpers
// ---------------------------------------------------------------------------

/// A freshly-generated participation account with the mnemonic populated so
/// `algokey-rust sign -m` can find the key. Address is derived from the seed.
struct FreshAccount {
    address: Address,
    mnemonic: String,
}

fn generate_account() -> FreshAccount {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let pk = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let mnemonic = key_to_mnemonic(&seed).expect("encode mnemonic");

    // Round-trip sanity check — guards against a regression in
    // algo_consensus_crypto::passphrase that would silently break signing.
    let decoded = mnemonic_to_key(&mnemonic).expect("decode mnemonic");
    assert_eq!(decoded, seed, "key_to_mnemonic round-trip must hold");

    FreshAccount {
        address: Address(pk),
        mnemonic,
    }
}

/// Fund `target` from the genesis faucet and wait for confirmation.
async fn fund_and_wait(net: &Localnet, target: Address, amount: u64) {
    let faucet = e2e::discover_faucet(net)
        .await
        .expect("discover faucet account");
    let txid = e2e::fund_address(net, &faucet, target, amount)
        .await
        .expect("submit funding payment");
    e2e::wait_for_confirmation(net, &txid, MAX_CONFIRMATION_ROUNDS)
        .await
        .expect("funding payment must confirm");
}

// ---------------------------------------------------------------------------
// algokey-rust binary invocations (assert_cmd, per TASK-185 acceptance crit.)
// ---------------------------------------------------------------------------

fn algokey() -> AssertCmd {
    AssertCmd::cargo_bin("algokey-rust").expect("locate algokey-rust binary")
}

/// `algokey-rust part generate --keyfile <path> --parent <addr>
///                              --first <r> --last <r+VALIDITY_ROUNDS>`
fn run_part_generate(keyfile: &Path, parent: Address, first: u64, last: u64) {
    algokey()
        .args(["part", "generate"])
        .arg("--keyfile")
        .arg(keyfile)
        .args(["--parent", &parent.to_algorand_string()])
        .args(["--first", &first.to_string()])
        .args(["--last", &last.to_string()])
        .assert()
        .success();
    assert!(
        keyfile.exists(),
        "part generate must produce {}",
        keyfile.display()
    );
}

/// `algokey-rust part reparent --keyfile <path> --parent <new-addr>`
fn run_part_reparent(keyfile: &Path, new_parent: Address) {
    algokey()
        .args(["part", "reparent"])
        .arg("--keyfile")
        .arg(keyfile)
        .args(["--parent", &new_parent.to_algorand_string()])
        .assert()
        .success();
}

/// `algokey-rust part keyreg --keyfile <partkey>
///        --firstvalid <r> --lastvalid <r+...> --network devnet
///        --fee 1000 -o <out>`
///
/// Sets `ALGOKEY_GENESIS_HASH` to the localnet's actual genesis-hash
/// (algod's `dockernet-v1` genesis is generated per `make localnet-up` and
/// does NOT match the canonical devnet hash); the env var takes precedence
/// over the `--network` flag (see Go `cmd/algokey/keyreg.go:118`).
fn run_part_keyreg_online(partkey: &Path, params: &SuggestedParams, out: &Path) {
    let genesis_b64 = STANDARD.encode(params.genesis_hash.0);
    let first = params.last_round;
    let last = first + VALIDITY_ROUNDS;

    algokey()
        .env("ALGOKEY_GENESIS_HASH", genesis_b64)
        .args(["part", "keyreg"])
        .arg("--keyfile")
        .arg(partkey)
        .args(["--firstvalid", &first.to_string()])
        .args(["--lastvalid", &last.to_string()])
        .args(["--network", "devnet"]) // any value; env override wins
        .args(["--fee", "1000"])
        .arg("-o")
        .arg(out)
        .assert()
        .success();
    assert!(
        out.exists(),
        "part keyreg must produce keyreg txn at {}",
        out.display()
    );
}

/// `algokey-rust part keyreg --offline --account <addr>
///        --firstvalid <r> --lastvalid <r+...> --network devnet
///        --fee 1000 -o <out>`
fn run_part_keyreg_offline(account: Address, params: &SuggestedParams, out: &Path) {
    let genesis_b64 = STANDARD.encode(params.genesis_hash.0);
    let first = params.last_round;
    let last = first + VALIDITY_ROUNDS;

    algokey()
        .env("ALGOKEY_GENESIS_HASH", genesis_b64)
        .args(["part", "keyreg"])
        .arg("--offline")
        .args(["--account", &account.to_algorand_string()])
        .args(["--firstvalid", &first.to_string()])
        .args(["--lastvalid", &last.to_string()])
        .args(["--network", "devnet"])
        .args(["--fee", "1000"])
        .arg("-o")
        .arg(out)
        .assert()
        .success();
    assert!(
        out.exists(),
        "offline keyreg must produce txn at {}",
        out.display()
    );
}

/// `algokey-rust sign -m "<mnemonic>" -t <txfile> -o <out>`
fn run_sign(mnemonic: &str, txfile: &Path, out: &Path) {
    algokey()
        .args(["sign", "-m", mnemonic, "-t"])
        .arg(txfile)
        .arg("-o")
        .arg(out)
        .assert()
        .success();
    assert!(
        out.exists(),
        "sign must produce signed txn at {}",
        out.display()
    );
}

// ---------------------------------------------------------------------------
// Decode helpers
// ---------------------------------------------------------------------------

/// Read the file produced by `part keyreg` / `sign` and decode the (single)
/// `SignedTransaction` it contains.
fn read_signed_txn(path: &Path) -> SignedTransaction {
    let bytes = std::fs::read(path).expect("read txn file");
    let mut de = rmp_serde::Deserializer::new(std::io::Cursor::new(&bytes));
    serde::Deserialize::deserialize(&mut de).expect("decode SignedTransaction")
}

/// Re-encode a `SignedTransaction` for submission. We could just submit the
/// raw file bytes, but going through the canonical encoder asserts that the
/// produced txn round-trips through our own codec — useful negative-control.
fn encode_for_submission(stx: &SignedTransaction) -> Vec<u8> {
    canonical_encode_signed_transaction(stx)
}

// ---------------------------------------------------------------------------
// Headline test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn headline_online_keyreg_round_trips() {
    let net = Localnet::bring_up().await.expect("bring up localnet");
    let account = generate_account();

    fund_and_wait(&net, account.address, FUNDING_MICROALGOS).await;

    let workdir = TempDir::new().expect("tempdir");
    let partkey = workdir.path().join("part.sqlite");
    let txnfile = workdir.path().join("keyreg.txn");
    let signedfile = workdir.path().join("keyreg.signed");

    // Step 1: generate participation key.
    let params = net
        .client()
        .suggested_transaction_params()
        .await
        .expect("suggested params");
    let part_first = params.last_round;
    let part_last = params.last_round + VALIDITY_ROUNDS;
    run_part_generate(&partkey, account.address, part_first, part_last);

    // Step 2: build the keyreg txn (unsigned). Refresh params here so that
    // last_round picks up any rounds advanced during partkey generation
    // (Falcon keygen is real work — ~seconds on a fresh devnet block).
    let params = net
        .client()
        .suggested_transaction_params()
        .await
        .expect("suggested params (post-partgen)");
    run_part_keyreg_online(&partkey, &params, &txnfile);

    // Step 3: inspect the unsigned keyreg txn against the partkey + acceptance
    // criteria BEFORE signing — this lets us pin down what the algokey-rust
    // CLI produced, independent of algod's post-commit view.
    let unsigned = read_signed_txn(&txnfile);
    let expected_first = params.last_round;
    let expected_last = expected_first + VALIDITY_ROUNDS;
    assert_eq!(unsigned.txn.txn_type.as_str(), "keyreg");
    assert_eq!(unsigned.txn.sender, account.address);
    assert_eq!(unsigned.txn.first_valid.0, expected_first);
    assert_eq!(unsigned.txn.last_valid.0, expected_last);
    assert!(
        unsigned.txn.vote_pk.is_some(),
        "online keyreg must populate votekey"
    );
    assert!(
        unsigned.txn.selection_pk.is_some(),
        "online keyreg must populate selkey"
    );
    assert!(
        unsigned.txn.state_proof_pk.is_some(),
        "online keyreg must populate sprfkey (matches Go's default include_state_proof_keys=true)"
    );
    assert_eq!(unsigned.txn.state_proof_pk.as_ref().unwrap().len(), 64);
    assert_eq!(
        unsigned.txn.vote_first, part_first,
        "votefst must mirror partkey's first_valid",
    );
    assert_eq!(
        unsigned.txn.vote_last, part_last,
        "votelst must mirror partkey's last_valid",
    );
    assert!(
        unsigned.txn.vote_key_dilution > 0,
        "votekd must be populated"
    );
    assert!(
        !unsigned.txn.non_participation,
        "nonpart must be false on online keyreg"
    );
    assert_eq!(
        unsigned.sig, [0u8; 64],
        "txn from `part keyreg` must be unsigned"
    );

    let vote_pk = unsigned.txn.vote_pk.unwrap();
    let selection_pk = unsigned.txn.selection_pk.unwrap();
    let state_proof_pk = unsigned.txn.state_proof_pk.unwrap();
    let key_dilution = unsigned.txn.vote_key_dilution;

    // Step 4: sign with the participation account's mnemonic.
    run_sign(&account.mnemonic, &txnfile, &signedfile);
    let signed = read_signed_txn(&signedfile);
    assert_ne!(signed.sig, [0u8; 64], "sign must populate the ed25519 sig");
    assert_eq!(
        signed.auth_addr, None,
        "non-rekey case must leave AuthAddr empty"
    );

    // Step 5: submit + confirm.
    let txid = e2e::submit_raw_txn(&net, &encode_for_submission(&signed))
        .await
        .expect("submit keyreg");
    let confirmed = e2e::wait_for_confirmation(&net, &txid, MAX_CONFIRMATION_ROUNDS)
        .await
        .expect("keyreg must confirm");
    assert!(
        confirmed.confirmed_round >= expected_first,
        "confirmed round {} must be ≥ keyreg firstvalid {}",
        confirmed.confirmed_round,
        expected_first
    );

    // Step 6: assert account participation state matches what we registered.
    let status = e2e::get_account_status(&net, account.address)
        .await
        .expect("get account status");
    assert!(
        status.is_online(),
        "account must be Online after keyreg, got {:?}",
        status.status
    );
    let part = status
        .participation
        .expect("Online account must have participation block");
    assert_eq!(part.vote_participation_key, vote_pk);
    assert_eq!(part.selection_participation_key, selection_pk);
    assert_eq!(
        part.state_proof_key.as_deref(),
        Some(&state_proof_pk[..]),
        "state-proof key must round-trip through algod"
    );
    assert_eq!(part.vote_first_valid, part_first);
    assert_eq!(part.vote_last_valid, part_last);
    assert_eq!(part.vote_key_dilution, key_dilution);
}

// ---------------------------------------------------------------------------
// Sibling test 1: offline keyreg flips an online account back offline
// ---------------------------------------------------------------------------

#[tokio::test]
async fn offline_keyreg_flips_account_offline() {
    let net = Localnet::bring_up().await.expect("bring up localnet");
    let account = generate_account();
    fund_and_wait(&net, account.address, FUNDING_MICROALGOS).await;

    let workdir = TempDir::new().expect("tempdir");
    let partkey = workdir.path().join("part.sqlite");
    let online_txn = workdir.path().join("online.txn");
    let online_signed = workdir.path().join("online.signed");
    let offline_txn = workdir.path().join("offline.txn");
    let offline_signed = workdir.path().join("offline.signed");

    // Bring online (same flow as the headline test, condensed).
    let params = net.client().suggested_transaction_params().await.unwrap();
    let part_first = params.last_round;
    let part_last = params.last_round + VALIDITY_ROUNDS;
    run_part_generate(&partkey, account.address, part_first, part_last);

    let params = net.client().suggested_transaction_params().await.unwrap();
    run_part_keyreg_online(&partkey, &params, &online_txn);
    run_sign(&account.mnemonic, &online_txn, &online_signed);
    let online_signed_stx = read_signed_txn(&online_signed);
    let online_txid = e2e::submit_raw_txn(&net, &encode_for_submission(&online_signed_stx))
        .await
        .unwrap();
    e2e::wait_for_confirmation(&net, &online_txid, MAX_CONFIRMATION_ROUNDS)
        .await
        .unwrap();

    let pre = e2e::get_account_status(&net, account.address)
        .await
        .unwrap();
    assert!(
        pre.is_online(),
        "precondition: account must be online before offline keyreg"
    );

    // Now flip offline.
    let params = net.client().suggested_transaction_params().await.unwrap();
    run_part_keyreg_offline(account.address, &params, &offline_txn);

    let unsigned = read_signed_txn(&offline_txn);
    assert_eq!(unsigned.txn.txn_type.as_str(), "keyreg");
    assert_eq!(unsigned.txn.sender, account.address);
    assert!(
        unsigned.txn.vote_pk.is_none(),
        "offline keyreg must NOT carry vote_pk"
    );
    assert!(unsigned.txn.selection_pk.is_none());
    assert!(unsigned.txn.state_proof_pk.is_none());

    run_sign(&account.mnemonic, &offline_txn, &offline_signed);
    let offline_signed_stx = read_signed_txn(&offline_signed);
    let offline_txid = e2e::submit_raw_txn(&net, &encode_for_submission(&offline_signed_stx))
        .await
        .unwrap();
    e2e::wait_for_confirmation(&net, &offline_txid, MAX_CONFIRMATION_ROUNDS)
        .await
        .unwrap();

    let post = e2e::get_account_status(&net, account.address)
        .await
        .unwrap();
    assert!(
        post.is_offline(),
        "account must be Offline after offline keyreg, got {:?}",
        post.status
    );
}

// ---------------------------------------------------------------------------
// Sibling test 2: reparent before keyreg
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reparent_before_keyreg_makes_new_parent_online() {
    let net = Localnet::bring_up().await.expect("bring up localnet");

    // Two fresh accounts: A is the original parent, B is the new parent.
    // Only B needs funding because B sends the keyreg txn.
    let a = generate_account();
    let b = generate_account();
    fund_and_wait(&net, b.address, FUNDING_MICROALGOS).await;

    let workdir = TempDir::new().expect("tempdir");
    let partkey = workdir.path().join("part.sqlite");
    let txnfile = workdir.path().join("keyreg.txn");
    let signedfile = workdir.path().join("keyreg.signed");

    let params = net.client().suggested_transaction_params().await.unwrap();
    let part_first = params.last_round;
    let part_last = params.last_round + VALIDITY_ROUNDS;

    // Generate partkey for A, then reparent to B.
    run_part_generate(&partkey, a.address, part_first, part_last);
    run_part_reparent(&partkey, b.address);

    // Now keyreg using the reparented partkey — sender will be B.
    let params = net.client().suggested_transaction_params().await.unwrap();
    run_part_keyreg_online(&partkey, &params, &txnfile);

    let unsigned = read_signed_txn(&txnfile);
    assert_eq!(
        unsigned.txn.sender, b.address,
        "after reparent, keyreg sender must be the new parent B"
    );
    assert_ne!(
        unsigned.txn.sender, a.address,
        "after reparent, keyreg sender must NOT be the original parent A"
    );

    // Sign with B's mnemonic (NOT A's) and submit.
    run_sign(&b.mnemonic, &txnfile, &signedfile);
    let signed = read_signed_txn(&signedfile);
    let txid = e2e::submit_raw_txn(&net, &encode_for_submission(&signed))
        .await
        .unwrap();
    e2e::wait_for_confirmation(&net, &txid, MAX_CONFIRMATION_ROUNDS)
        .await
        .unwrap();

    let status_b = e2e::get_account_status(&net, b.address).await.unwrap();
    assert!(
        status_b.is_online(),
        "B (the new parent) must be Online after reparent + keyreg, got {:?}",
        status_b.status
    );

    // A is unfunded and was never sent a keyreg; algod returns Offline for
    // any unknown account. Sanity check that the reparent didn't accidentally
    // online A.
    let status_a = e2e::get_account_status(&net, a.address).await.unwrap();
    assert!(
        !status_a.is_online(),
        "A (the original parent) must NOT be Online after reparent, got {:?}",
        status_a.status
    );
}
