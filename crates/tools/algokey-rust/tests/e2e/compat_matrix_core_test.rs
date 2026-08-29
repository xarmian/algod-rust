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

//! Bidirectional algokey compatibility matrix — core (TASK-199).
//!
//! Each row produces an artifact on one side (Go or Rust `algokey`) and
//! verifies that the other side accepts it. 8 round-trips total:
//!
//! | Artifact            | Go → Rust                                   | Rust → Go                                  |
//! |---------------------|---------------------------------------------|--------------------------------------------|
//! | keyfile             | Go gen → Rust export → address match        | Rust gen → Go export → address match       |
//! | mnemonic            | Go gen mnemonic → Rust import → addr match  | Rust gen mnemonic → Go import → addr match |
//! | signed-txn-single   | Go sign → Rust `verify_single_sig`          | Rust sign → submit to algod → confirmed    |
//! | signed-txn-rekeyed  | Go sign rekey → Rust verifies AuthAddr      | Rust sign rekey → real-rekeyed submit ok   |
//!
//! Skip-with-notice (returns success) if Go `algokey` isn't on PATH.
//!
//! Canonical invocation:
//! ```text
//! make localnet-up && \
//!   cargo test -p algokey-rust --features e2e --test compat_matrix_core \
//!     -- --test-threads=1
//! ```

#[path = "mod.rs"]
mod e2e;

use std::path::{Path, PathBuf};
use std::process::Command;

use algo_codec::canonical_encode_signed_transaction;
use algo_consensus_crypto::{key_to_mnemonic, mnemonic_to_key};
use algo_types::{Address, Round, SignedTransaction, Transaction, TxnType};
use algo_validate::signature::verify_single_sig;
use assert_cmd::Command as AssertCmd;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use tempfile::TempDir;

use e2e::compat_framework::{go_algokey_available, skip_message, Direction, MatrixReport};
use e2e::Localnet;

const MAX_CONFIRMATION_ROUNDS: u64 = 10;

// ---------------------------------------------------------------------------
// CLI wrappers
// ---------------------------------------------------------------------------

fn rust_algokey() -> AssertCmd {
    AssertCmd::cargo_bin("algokey-rust").expect("locate algokey-rust binary")
}

/// Run `algokey <args>` (Go binary). Returns combined stdout for parsing.
fn run_go_algokey(args: &[&str]) -> String {
    let out = Command::new("algokey")
        .args(args)
        .output()
        .expect("spawn Go algokey");
    assert!(
        out.status.success(),
        "Go algokey {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

// ---------------------------------------------------------------------------
// Keyfile + mnemonic + address helpers
// ---------------------------------------------------------------------------

/// Address derived from a 32-byte ed25519 seed.
fn address_for_seed(seed: &[u8; 32]) -> Address {
    Address(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

/// Parse the `Public key: <addr>` line from Go algokey's stdout.
fn parse_pubkey(stdout: &str) -> Address {
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("Public key:") {
            let s = rest.trim();
            return Address::from_algorand_string(s).expect("decode pubkey");
        }
    }
    panic!("no `Public key:` line in algokey output:\n{stdout}");
}

/// Parse the `Private key mnemonic: <25 words>` line from algokey stdout.
fn parse_mnemonic(stdout: &str) -> String {
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("Private key mnemonic:") {
            return rest.trim().to_string();
        }
    }
    panic!("no `Private key mnemonic:` line in algokey output:\n{stdout}");
}

// ---------------------------------------------------------------------------
// Build helpers for signed-txn rows
// ---------------------------------------------------------------------------

/// Build an unsigned `SignedTransaction` (sig = zero) and msgpack-encode it
/// to a file. Both sides accept this file as input to `sign`.
#[allow(clippy::too_many_arguments)] // Constructor signature mirrors the txn fields it sets.
fn write_unsigned_txn(
    path: &Path,
    sender: Address,
    receiver: Address,
    amount: u64,
    fee: u64,
    first_valid: u64,
    last_valid: u64,
    genesis_hash: [u8; 32],
    genesis_id: &str,
) {
    let txn = Transaction {
        txn_type: TxnType::Pay,
        sender,
        fee,
        first_valid: Round(first_valid),
        last_valid: Round(last_valid),
        genesis_hash,
        genesis_id: genesis_id.to_string(),
        receiver,
        amount,
        ..Transaction::default()
    };
    let unsigned = SignedTransaction {
        txn,
        ..SignedTransaction::default()
    };
    let bytes = canonical_encode_signed_transaction(&unsigned);
    std::fs::write(path, bytes).expect("write unsigned txn");
}

fn read_signed_txn(path: &Path) -> SignedTransaction {
    let bytes = std::fs::read(path).expect("read signed txn");
    let mut de = rmp_serde::Deserializer::new(std::io::Cursor::new(&bytes));
    serde::Deserialize::deserialize(&mut de).expect("decode SignedTransaction")
}

// ---------------------------------------------------------------------------
// Per-row implementations
// ---------------------------------------------------------------------------

fn row_keyfile(report: &mut MatrixReport, workdir: &Path) {
    let artifact = "keyfile";

    // Go → Rust: Go generates a keyfile, Rust exports it and asserts the
    // pubkey matches what Go reported.
    {
        let go_kf = workdir.join("go.key");
        let go_stdout = run_go_algokey(&["generate", "-f", go_kf.to_str().unwrap()]);
        let go_addr = parse_pubkey(&go_stdout);

        let rust_out = rust_algokey()
            .args(["export", "-f"])
            .arg(&go_kf)
            .output()
            .expect("rust export");
        if !rust_out.status.success() {
            report.fail(
                artifact,
                Direction::GoToRust,
                format!(
                    "rust export of Go keyfile failed: {}",
                    String::from_utf8_lossy(&rust_out.stderr)
                ),
            );
            return;
        }
        let rust_stdout = String::from_utf8_lossy(&rust_out.stdout);
        let rust_addr = parse_pubkey(&rust_stdout);
        if rust_addr == go_addr {
            report.pass(artifact, Direction::GoToRust);
        } else {
            report.fail(
                artifact,
                Direction::GoToRust,
                format!("address mismatch: go={go_addr} rust={rust_addr}"),
            );
        }
    }

    // Rust → Go: Rust generates a keyfile, Go exports it and asserts match.
    {
        let rust_kf = workdir.join("rust.key");
        let rust_out = rust_algokey()
            .args(["generate", "-f"])
            .arg(&rust_kf)
            .output()
            .expect("rust generate");
        assert!(rust_out.status.success(), "rust generate failed");
        let rust_addr = parse_pubkey(&String::from_utf8_lossy(&rust_out.stdout));

        let go_stdout = run_go_algokey(&["export", "-f", rust_kf.to_str().unwrap()]);
        let go_addr = parse_pubkey(&go_stdout);
        if rust_addr == go_addr {
            report.pass(artifact, Direction::RustToGo);
        } else {
            report.fail(
                artifact,
                Direction::RustToGo,
                format!("address mismatch: rust={rust_addr} go={go_addr}"),
            );
        }
    }
}

fn row_mnemonic(report: &mut MatrixReport, workdir: &Path) {
    let artifact = "mnemonic";

    // Go → Rust: Go mnemonic → Rust import → same address.
    {
        let go_kf = workdir.join("go_mn.key");
        let go_stdout = run_go_algokey(&["generate", "-f", go_kf.to_str().unwrap()]);
        let go_mnemonic = parse_mnemonic(&go_stdout);
        let go_addr = parse_pubkey(&go_stdout);

        let rust_kf = workdir.join("from_go_mn.key");
        let out = rust_algokey()
            .args(["import", "-m", &go_mnemonic, "-f"])
            .arg(&rust_kf)
            .output()
            .expect("rust import");
        if !out.status.success() {
            report.fail(
                artifact,
                Direction::GoToRust,
                format!(
                    "rust import failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                ),
            );
            return;
        }
        let seed_bytes = std::fs::read(&rust_kf).expect("read imported keyfile");
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes[..32]);
        let rust_addr = address_for_seed(&seed);
        if rust_addr == go_addr {
            report.pass(artifact, Direction::GoToRust);
        } else {
            report.fail(
                artifact,
                Direction::GoToRust,
                format!("address mismatch: go={go_addr} rust={rust_addr}"),
            );
        }
    }

    // Rust → Go: Rust mnemonic → Go import → same address.
    {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let rust_mnemonic = key_to_mnemonic(&seed).expect("encode mnemonic");
        let rust_addr = address_for_seed(&seed);

        let go_kf = workdir.join("from_rust_mn.key");
        let _ = run_go_algokey(&[
            "import",
            "-m",
            &rust_mnemonic,
            "-f",
            go_kf.to_str().unwrap(),
        ]);
        let stdout = run_go_algokey(&["export", "-f", go_kf.to_str().unwrap()]);
        let go_addr = parse_pubkey(&stdout);
        if go_addr == rust_addr {
            report.pass(artifact, Direction::RustToGo);
        } else {
            report.fail(
                artifact,
                Direction::RustToGo,
                format!("address mismatch: rust={rust_addr} go={go_addr}"),
            );
        }

        // Cross-check via mnemonic round-trip on the Rust side too.
        let reseed = mnemonic_to_key(&rust_mnemonic).expect("decode mnemonic");
        assert_eq!(reseed, seed);
    }
}

async fn row_signed_txn_single(report: &mut MatrixReport, workdir: &Path, net: &Localnet) {
    let artifact = "signed-txn-single";

    let params = net.client().suggested_transaction_params().await.unwrap();
    let faucet = e2e::discover_faucet(net).await.expect("faucet");

    // Go → Rust: build unsigned txn (sender=faucet, self-pay 0), Go signs,
    // Rust verifies.
    {
        let unsigned_path = workdir.join("g2r_single.unsigned");
        let signed_path = workdir.join("g2r_single.signed");
        write_unsigned_txn(
            &unsigned_path,
            faucet.address,
            faucet.address,
            0,
            params.min_fee.max(params.fee),
            params.last_round,
            params.last_round + 1000,
            params.genesis_hash.0,
            &params.genesis_id,
        );
        run_go_algokey(&[
            "sign",
            "-m",
            &faucet.mnemonic,
            "-t",
            unsigned_path.to_str().unwrap(),
            "-o",
            signed_path.to_str().unwrap(),
        ]);
        let signed = read_signed_txn(&signed_path);
        match verify_single_sig(&signed) {
            Ok(()) => report.pass(artifact, Direction::GoToRust),
            Err(e) => report.fail(
                artifact,
                Direction::GoToRust,
                format!("Rust rejected Go-signed txn: {e}"),
            ),
        }
    }

    // Rust → Go: Rust signs the same kind of unsigned txn, submit to Go algod,
    // observe confirmation = signature is valid by Go's standards.
    {
        let unsigned_path = workdir.join("r2g_single.unsigned");
        let signed_path = workdir.join("r2g_single.signed");
        let params = net.client().suggested_transaction_params().await.unwrap();
        write_unsigned_txn(
            &unsigned_path,
            faucet.address,
            faucet.address,
            0,
            params.min_fee.max(params.fee),
            params.last_round,
            params.last_round + 1000,
            params.genesis_hash.0,
            &params.genesis_id,
        );
        rust_algokey()
            .args(["sign", "-m", &faucet.mnemonic, "-t"])
            .arg(&unsigned_path)
            .arg("-o")
            .arg(&signed_path)
            .assert()
            .success();
        let signed = read_signed_txn(&signed_path);
        let encoded = canonical_encode_signed_transaction(&signed);
        match e2e::submit_raw_txn(net, &encoded).await {
            Ok(txid) => match e2e::wait_for_confirmation(net, &txid, MAX_CONFIRMATION_ROUNDS).await
            {
                Ok(_) => report.pass(artifact, Direction::RustToGo),
                Err(e) => report.fail(
                    artifact,
                    Direction::RustToGo,
                    format!("Go algod did not confirm Rust-signed txn: {e}"),
                ),
            },
            Err(e) => report.fail(
                artifact,
                Direction::RustToGo,
                format!("Go algod rejected Rust-signed txn on submit: {e}"),
            ),
        }
    }
}

async fn row_signed_txn_rekeyed(report: &mut MatrixReport, workdir: &Path, net: &Localnet) {
    let artifact = "signed-txn-rekeyed";

    let faucet = e2e::discover_faucet(net).await.expect("faucet");
    let params = net.client().suggested_transaction_params().await.unwrap();

    // Go → Rust: build txn with sender != signer; Go signs with signer's
    // mnemonic; expect AuthAddr=signer. Rust verifies the AuthAddr-aware
    // signature math. No on-chain submission needed (Rust verifies math).
    {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let signer_addr = address_for_seed(&seed);
        let sender = Address([0xAA; 32]); // arbitrary sender ≠ signer

        let signer_mnemonic = key_to_mnemonic(&seed).expect("encode mnemonic");

        let unsigned_path = workdir.join("g2r_rekey.unsigned");
        let signed_path = workdir.join("g2r_rekey.signed");
        write_unsigned_txn(
            &unsigned_path,
            sender,
            sender,
            0,
            params.min_fee,
            params.last_round,
            params.last_round + 1000,
            params.genesis_hash.0,
            &params.genesis_id,
        );
        run_go_algokey(&[
            "sign",
            "-m",
            &signer_mnemonic,
            "-t",
            unsigned_path.to_str().unwrap(),
            "-o",
            signed_path.to_str().unwrap(),
        ]);
        let signed = read_signed_txn(&signed_path);
        if signed.auth_addr != Some(signer_addr) {
            report.fail(
                artifact,
                Direction::GoToRust,
                format!(
                    "expected Go to set auth_addr={signer_addr}, got {:?}",
                    signed.auth_addr
                ),
            );
        } else {
            match verify_single_sig(&signed) {
                Ok(()) => report.pass(artifact, Direction::GoToRust),
                Err(e) => report.fail(
                    artifact,
                    Direction::GoToRust,
                    format!("Rust rejected Go-signed rekey'd txn: {e}"),
                ),
            }
        }
    }

    // Rust → Go: real on-chain rekey path. Steps:
    //   1. Generate fresh account A, fund from faucet
    //   2. Submit A→A 0-algo with rekey_to=faucet → A is now authorized via faucet
    //   3. Build txn sender=A, sign with faucet's mnemonic → AuthAddr=faucet
    //   4. Submit to algod, observe confirmation
    {
        let mut a_seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut a_seed);
        let a_addr = address_for_seed(&a_seed);
        let a_mnemonic = key_to_mnemonic(&a_seed).expect("encode mnemonic");

        // Step 1: fund A from faucet.
        let funding_txid = e2e::fund_address(net, &faucet, a_addr, 10_000_000)
            .await
            .expect("fund A");
        e2e::wait_for_confirmation(net, &funding_txid, MAX_CONFIRMATION_ROUNDS)
            .await
            .expect("funding must confirm");

        // Step 2: A submits a rekey-to-faucet payment to itself.
        let params = net.client().suggested_transaction_params().await.unwrap();
        let rekey_txn = Transaction {
            txn_type: TxnType::Pay,
            sender: a_addr,
            fee: params.min_fee,
            first_valid: Round(params.last_round),
            last_valid: Round(params.last_round + 1000),
            genesis_hash: params.genesis_hash.0,
            genesis_id: params.genesis_id.clone(),
            receiver: a_addr,
            amount: 0,
            rekey_to: Some(faucet.address),
            ..Transaction::default()
        };
        let rekey_signed = e2e::accounts::sign(rekey_txn, &SigningKey::from_bytes(&a_seed));
        let rekey_txid =
            e2e::submit_raw_txn(net, &canonical_encode_signed_transaction(&rekey_signed))
                .await
                .expect("submit rekey txn");
        e2e::wait_for_confirmation(net, &rekey_txid, MAX_CONFIRMATION_ROUNDS)
            .await
            .expect("rekey must confirm");

        // Step 3: build sender=A self-pay; sign with FAUCET's mnemonic via
        // algokey-rust. Sig should be valid for AuthAddr=faucet.
        let params = net.client().suggested_transaction_params().await.unwrap();
        let unsigned_path = workdir.join("r2g_rekey.unsigned");
        let signed_path = workdir.join("r2g_rekey.signed");
        write_unsigned_txn(
            &unsigned_path,
            a_addr,
            a_addr,
            0,
            params.min_fee,
            params.last_round,
            params.last_round + 1000,
            params.genesis_hash.0,
            &params.genesis_id,
        );
        rust_algokey()
            .args(["sign", "-m", &faucet.mnemonic, "-t"])
            .arg(&unsigned_path)
            .arg("-o")
            .arg(&signed_path)
            .assert()
            .success();
        let signed = read_signed_txn(&signed_path);
        assert_eq!(signed.auth_addr, Some(faucet.address));

        // Step 4: submit and wait.
        let encoded = canonical_encode_signed_transaction(&signed);
        match e2e::submit_raw_txn(net, &encoded).await {
            Ok(txid) => match e2e::wait_for_confirmation(net, &txid, MAX_CONFIRMATION_ROUNDS).await
            {
                Ok(_) => report.pass(artifact, Direction::RustToGo),
                Err(e) => report.fail(
                    artifact,
                    Direction::RustToGo,
                    format!("algod did not confirm rekeyed Rust-signed txn: {e}"),
                ),
            },
            Err(e) => report.fail(
                artifact,
                Direction::RustToGo,
                format!("algod rejected rekeyed Rust-signed txn: {e}"),
            ),
        }

        // Suppress unused: a_mnemonic could be used for future cross-checks.
        let _ = a_mnemonic;
    }
}

// ---------------------------------------------------------------------------
// Negative control: tamper with a Rust-signed txn and assert Rust verify fails.
// ---------------------------------------------------------------------------

fn row_negative_control(report: &mut MatrixReport, workdir: &Path) {
    let artifact = "negative-control";

    // Build, sign, then flip a byte in the signature → verify must fail.
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let signer = address_for_seed(&seed);
    let mnemonic = key_to_mnemonic(&seed).unwrap();

    let unsigned_path = workdir.join("neg.unsigned");
    let signed_path = workdir.join("neg.signed");
    write_unsigned_txn(
        &unsigned_path,
        signer,
        signer,
        0,
        1000,
        1,
        1000,
        [9u8; 32],
        "devnet-v1",
    );
    rust_algokey()
        .args(["sign", "-m", &mnemonic, "-t"])
        .arg(&unsigned_path)
        .arg("-o")
        .arg(&signed_path)
        .assert()
        .success();

    let mut signed = read_signed_txn(&signed_path);
    let original_sig = signed.sig;
    assert!(verify_single_sig(&signed).is_ok(), "baseline must verify");

    signed.sig[0] ^= 0xFF;
    match verify_single_sig(&signed) {
        Err(_) => report.pass(artifact, Direction::GoToRust),
        Ok(()) => report.fail(
            artifact,
            Direction::GoToRust,
            format!(
                "verify_single_sig should reject tampered sig (orig[0]={:#x}, tampered[0]={:#x})",
                original_sig[0], signed.sig[0]
            ),
        ),
    }
}

// ---------------------------------------------------------------------------
// Test entry point
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn algokey_compat_matrix_core() {
    if !go_algokey_available() {
        skip_message();
        return;
    }

    let net = Localnet::bring_up().await.expect("bring up localnet");
    let workdir = TempDir::new().expect("tempdir");
    let root: PathBuf = workdir.path().to_path_buf();

    let mut report = MatrixReport::new("Artifact compatibility matrix (core):");

    row_keyfile(&mut report, &root);
    row_mnemonic(&mut report, &root);
    row_signed_txn_single(&mut report, &root, &net).await;
    row_signed_txn_rekeyed(&mut report, &root, &net).await;
    row_negative_control(&mut report, &root);

    report.print_summary();
    let xml_path = e2e::compat_framework::junit_report_path("core");
    report
        .write_junit(&xml_path, "algokey-compat-matrix-core")
        .expect("write JUnit XML");
    println!("JUnit report written to {}", xml_path.display());
    report.assert_all_pass();
}
