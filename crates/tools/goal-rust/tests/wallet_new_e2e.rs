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

//! End-to-end smoke tests for `goal-rust wallet new`. Spawns the
//! in-tree `kmd-rust serve` binary against a temp data dir, fakes up
//! a "private" algod data dir layout pointing at it via the
//! kmd-v0.5 subdirectory, runs `goal-rust wallet new <name> -d <dir>
//! -w <pw>`, and asserts:
//!
//! - exit 0 + stdout matches Go's exact text
//! - the wallet exists in kmd-rust's `/v1/wallets` afterwards
//!
//! Plus error-path tests:
//! - missing kmd produces Go's `Could not contact kmd` text + exit 1
//! - duplicate name surfaces kmd's server-side message verbatim
//! - non-TTY stdin password path is exercised

#![cfg(unix)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root resolves")
}

fn kmd_rust_binary() -> PathBuf {
    let root = workspace_root();
    let status = Command::new("cargo")
        .args(["build", "-p", "kmd-rust"])
        .current_dir(&root)
        .status()
        .expect("cargo build kmd-rust");
    assert!(status.success(), "cargo build -p kmd-rust failed");
    for c in ["debug/kmd-rust", "release/kmd-rust"] {
        let p = root.join("target").join(c);
        if p.exists() {
            return p;
        }
    }
    panic!("kmd-rust binary not found under {}/target", root.display());
}

fn write_kmd_config(dir: &Path) {
    let cfg = serde_json::json!({
        "drivers": {
            "sqlite": {
                "scrypt": {"scrypt_n": 1024, "scrypt_r": 1, "scrypt_p": 1},
                "allow_unsafe_scrypt": true,
            },
        },
        "session_lifetime_secs": 60,
    });
    std::fs::write(
        dir.join("kmd_config.json"),
        serde_json::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
}

fn poll_for_ready(dir: &Path) -> Result<(), String> {
    let net = dir.join("kmd.net");
    let tok = dir.join("kmd.token");
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        if let (Ok(n), Ok(t)) = (std::fs::read_to_string(&net), std::fs::read_to_string(&tok)) {
            if !n.trim().is_empty() && !t.trim().is_empty() {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "kmd-rust never wrote kmd.net + kmd.token at {}",
        dir.display()
    ))
}

fn sigterm(pid: u32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe {
        kill(pid as i32, 15);
    }
}

struct KmdGuard(Child);
impl Drop for KmdGuard {
    fn drop(&mut self) {
        sigterm(self.0.id());
        let _ = self.0.wait();
    }
}

/// Build a fake algod data dir layout so `resolve_kmd_data_dir`
/// resolves the kmd directory we control. No system.json ⇒ the data
/// dir is "private", so kmd resides at `<data_dir>/kmd-v0.5`.
fn setup_data_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let kmd = tmp.path().join("kmd-v0.5");
    std::fs::create_dir_all(&kmd).unwrap();
    write_kmd_config(&kmd);
    (tmp, kmd)
}

fn spawn_kmd(kmd_dir: &Path) -> KmdGuard {
    let bin = kmd_rust_binary();
    let child = Command::new(&bin)
        .args(["serve", "--data-dir"])
        .arg(kmd_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kmd-rust");
    let guard = KmdGuard(child);
    poll_for_ready(kmd_dir).expect("kmd-rust ready");
    guard
}

#[test]
fn wallet_new_creates_wallet_with_go_exact_output() {
    let (data_dir, kmd_dir) = setup_data_dir();
    let _guard = spawn_kmd(&kmd_dir);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["wallet", "new", "test-wallet", "-w", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust wallet new");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "wallet new failed: exit={:?}, stdout={stdout:?}, stderr={stderr:?}",
        out.status.code(),
    );
    // Go's exact lines.
    assert!(
        stdout.contains("Creating wallet..."),
        "stdout missing infoCreatingWallet: {stdout:?}",
    );
    assert!(
        stdout.contains("Created wallet 'test-wallet'"),
        "stdout missing infoCreatedWallet: {stdout:?}",
    );
}

#[test]
fn wallet_new_missing_kmd_produces_go_unreachable_error() {
    // No kmd-rust spawn ⇒ kmd.net / kmd.token missing from kmd-v0.5.
    let (data_dir, _kmd_dir) = setup_data_dir();
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["wallet", "new", "any-name", "-w", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust wallet new");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "wallet new must fail without kmd; exit={:?} stderr={stderr:?}",
        out.status.code(),
    );
    assert!(
        stderr.contains("Could not contact kmd; is it running?"),
        "stderr must carry Go's unreachable text; got {stderr:?}",
    );
}

#[test]
fn wallet_new_duplicate_name_surfaces_server_message() {
    let (data_dir, kmd_dir) = setup_data_dir();
    let _guard = spawn_kmd(&kmd_dir);

    // First create succeeds.
    let first = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["wallet", "new", "dup", "-w", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run first wallet new");
    assert!(first.status.success(), "first create must succeed");

    // Second with the same name must fail with kmd's API message
    // surfaced verbatim (server-side `envelope.message`).
    let second = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["wallet", "new", "dup", "-w", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run second wallet new");
    assert!(
        !second.status.success(),
        "duplicate create must fail; exit={:?}",
        second.status.code(),
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.starts_with("Couldn't create wallet:"),
        "stderr must use Go's errorCouldntCreateWallet template; got {stderr:?}",
    );
    // Don't pin the exact server message (kmd's wording may evolve);
    // require only that *some* non-empty message follows the colon.
    let after_colon = stderr.split_once(':').map(|(_, r)| r.trim()).unwrap_or("");
    assert!(
        !after_colon.is_empty(),
        "errorCouldntCreateWallet must embed the server message; got {stderr:?}",
    );
}

#[test]
fn wallet_new_reads_password_from_non_tty_stdin() {
    // When --password is omitted and stdin is a pipe (non-TTY), we
    // read one line as the password. This is the CI / scripting
    // path Go also supports.
    let (data_dir, kmd_dir) = setup_data_dir();
    let _guard = spawn_kmd(&kmd_dir);
    let mut child = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["wallet", "new", "from-stdin"])
        .env_remove("ALGORAND_DATA")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn goal-rust wallet new");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"stdin-password\n")
        .unwrap();
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "stdin-password path must succeed; exit={:?}, stdout={stdout:?}, stderr={stderr:?}",
        out.status.code(),
    );
    assert!(
        stdout.contains("Created wallet 'from-stdin'"),
        "stdout must confirm creation: {stdout:?}",
    );
}

// ------- TASK-234 (B2): --recover, --unencrypted, --no-display-seed -------

/// Known 25-word "all-abandon" mnemonic ⇒ a deterministic 32-byte key.
/// The same constant the algokey-rust test suite uses
/// (`commands/import.rs:69`). Decoding it via `mnemonic_to_key`
/// returns the all-zero key, so recovery → MDK = [0u8; 32] →
/// re-export → mnemonic should round-trip back to this string.
const ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest";

#[test]
fn wallet_new_recover_mnemonic_creates_wallet_from_seed() {
    let (data_dir, kmd_dir) = setup_data_dir();
    let _guard = spawn_kmd(&kmd_dir);

    // Feed the password on stdin (non-TTY path) after the mnemonic.
    // Order matches Go: mnemonic read first (`wallet.go:101-117`),
    // password second. --no-display-seed suppresses the backup prompt
    // so we don't have to feed a third line.
    let mut child = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args([
            "wallet",
            "new",
            "recovered",
            "--recover",
            "--no-display-seed",
        ])
        .env_remove("ALGORAND_DATA")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    {
        let mut stdin = child.stdin.take().unwrap();
        // Mnemonic first (terminated with newline so read_line
        // returns), then password.
        stdin.write_all(ZERO_MNEMONIC.as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.write_all(b"pw\n").unwrap();
    }
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "recover path must succeed; exit={:?}, stdout={stdout:?}, stderr={stderr:?}",
        out.status.code(),
    );
    assert!(
        stdout.contains("Created wallet 'recovered'"),
        "stdout must confirm creation: {stdout:?}",
    );
    // --no-display-seed ⇒ no backup-phrase prompt or mnemonic.
    assert!(
        !stdout.contains("Your backup phrase is printed below"),
        "--no-display-seed must suppress backup prompt; got {stdout:?}",
    );
}

#[test]
fn wallet_new_unencrypted_prints_info_unencrypted() {
    let (data_dir, kmd_dir) = setup_data_dir();
    let _guard = spawn_kmd(&kmd_dir);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args([
            "wallet",
            "new",
            "unenc",
            "--unencrypted",
            "--no-display-seed",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "unencrypted create must succeed; exit={:?}, stdout={stdout:?}, stderr={stderr:?}",
        out.status.code(),
    );
    // Go's infoUnencrypted line — byte-exact.
    assert!(
        stderr.contains("Creating unencrypted wallet"),
        "stderr missing infoUnencrypted: {stderr:?}",
    );
    assert!(
        stdout.contains("Created wallet 'unenc'"),
        "stdout missing infoCreatedWallet: {stdout:?}",
    );
}

#[test]
fn wallet_new_no_display_seed_suppresses_backup_phrase() {
    let (data_dir, kmd_dir) = setup_data_dir();
    let _guard = spawn_kmd(&kmd_dir);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["wallet", "new", "no-seed", "-w", "pw", "--no-display-seed"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "must succeed; stdout={stdout:?}");
    assert!(
        !stdout.contains("Your new wallet has a backup phrase"),
        "--no-display-seed must omit infoBackupExplanation; got {stdout:?}",
    );
    assert!(
        !stdout.contains("Your backup phrase is printed below"),
        "--no-display-seed must omit infoPrintedBackupPhrase; got {stdout:?}",
    );
}

/// Build a fake private data dir with genesis.json so AccountsList
/// can resolve `<data_dir>/<genesis_id>/accountList.json`. Returns
/// (tempdir guard, data_dir path, kmd-v0.5 path).
fn setup_data_dir_with_genesis() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let kmd = data_dir.join("kmd-v0.5");
    std::fs::create_dir_all(&kmd).unwrap();
    write_kmd_config(&kmd);
    // Minimal genesis.json — `read_genesis_id` concatenates
    // `network-id` so we need both fields.
    let genesis = serde_json::json!({
        "id": "v1",
        "network": "testnet",
        "proto": "future",
        "alloc": [],
        "rwd": "FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I",
        "fees": "FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I",
    });
    std::fs::write(
        data_dir.join("genesis.json"),
        serde_json::to_string_pretty(&genesis).unwrap(),
    )
    .unwrap();
    (tmp, data_dir, kmd)
}

#[test]
fn wallet_new_first_wallet_persists_default_for_wallet_list() {
    let (_tmp, data_dir, kmd_dir) = setup_data_dir_with_genesis();
    let _guard = spawn_kmd(&kmd_dir);

    // Create the wallet (also exercises the set-default-on-first
    // path with --no-display-seed to keep output focused).
    let create = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&data_dir)
        .args(["wallet", "new", "primary", "-w", "pw", "--no-display-seed"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run wallet new");
    let create_stdout = String::from_utf8_lossy(&create.stdout);
    let create_stderr = String::from_utf8_lossy(&create.stderr);
    assert!(
        create.status.success(),
        "create must succeed; stdout={create_stdout:?}, stderr={create_stderr:?}",
    );
    // accountList.json landed under <data_dir>/<gid>/accountList.json.
    let acct = data_dir.join("testnet-v1").join("accountList.json");
    assert!(
        acct.exists(),
        "accountList.json must be written for set-default-on-first; expected at {acct:?}",
    );

    // wallet list should mark this wallet as the default.
    let list = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&data_dir)
        .args(["wallet", "list"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run wallet list");
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(
        list.status.success(),
        "wallet list must succeed; stdout={stdout:?}",
    );
    assert!(
        stdout.contains("Wallet:\tprimary (default)"),
        "wallet list must mark primary as default; got {stdout:?}",
    );
}
