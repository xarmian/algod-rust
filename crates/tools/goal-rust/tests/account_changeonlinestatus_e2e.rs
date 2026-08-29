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

//! `goal-rust account changeonlinestatus / marknonparticipating` and
//! `renewpartkey --register` E2E (TASK-244 / B12).
//!
//! Drives the full build → sign → submit → confirm pipeline: a real spawned
//! `kmd-rust` signs the keyreg transaction (so the wallet/handle/signing path
//! is exercised end to end), while a purpose-built mock algod serves suggested
//! params, `/v2/participation`, transaction submission, and pending-txn
//! confirmation. Asserts Go-parity output lines and that a real keyreg was
//! broadcast.

#![cfg(unix)]

use base64::Engine as _;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

// ---------------------------------------------------------------------------
// kmd-rust harness (mirrors account_multisig_e2e.rs)
// ---------------------------------------------------------------------------

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
    assert!(status.success());
    for c in ["debug/kmd-rust", "release/kmd-rust"] {
        let p = root.join("target").join(c);
        if p.exists() {
            return p;
        }
    }
    panic!("kmd-rust binary not found");
}

fn write_kmd_config(dir: &Path) {
    let cfg = serde_json::json!({
        "drivers": {
            "sqlite": {"scrypt": {"scrypt_n": 1024, "scrypt_r": 1, "scrypt_p": 1}, "allow_unsafe_scrypt": true},
        },
        "session_lifetime_secs": 60,
    });
    std::fs::write(
        dir.join("kmd_config.json"),
        serde_json::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
}

fn poll_kmd_ready(dir: &Path) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        if let (Ok(n), Ok(t)) = (
            std::fs::read_to_string(dir.join("kmd.net")),
            std::fs::read_to_string(dir.join("kmd.token")),
        ) {
            if !n.trim().is_empty() && !t.trim().is_empty() {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("kmd-rust never ready".into())
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

fn spawn_kmd(kmd_dir: &Path) -> KmdGuard {
    let bin = kmd_rust_binary();
    let child = Command::new(&bin)
        .args(["serve", "--data-dir"])
        .arg(kmd_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kmd-rust");
    let g = KmdGuard(child);
    poll_kmd_ready(kmd_dir).expect("kmd ready");
    g
}

fn setup_data_dir() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dd = tmp.path().to_path_buf();
    let kmd = dd.join("kmd-v0.5");
    std::fs::create_dir_all(&kmd).unwrap();
    write_kmd_config(&kmd);
    std::fs::write(
        dd.join("genesis.json"),
        r#"{"id":"v1","network":"testnet","proto":"future","alloc":[],"rwd":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I","fees":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I"}"#,
    )
    .unwrap();
    (tmp, dd, kmd)
}

fn goal(dd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(dd)
        .args(args)
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("goal-rust")
}

/// Create wallet "w" (password "pw") and a fresh account; return its address.
fn create_wallet_and_account(dd: &Path) -> String {
    let out = goal(dd, &["wallet", "new", "w", "-w", "pw", "--no-display-seed"]);
    assert!(
        out.status.success(),
        "wallet new failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = goal(dd, &["account", "new", "-w", "w", "--password", "pw"]);
    assert!(
        out.status.success(),
        "account new failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // "Created new account with address <ADDR>"
    stdout
        .split_whitespace()
        .next_back()
        .expect("address in account-new output")
        .to_string()
}

// ---------------------------------------------------------------------------
// Mock algod (path-prefix routing; captures submitted txns)
// ---------------------------------------------------------------------------

struct AlgodState {
    address: String,
    last_round: u64,
    /// Raw bodies POSTed to /v2/transactions (the broadcast signed txns).
    submitted: Vec<Vec<u8>>,
    /// Set once `/v2/participation/generate/*` has been called. Before that the
    /// node reports only the pre-existing key; after, it also reports the freshly
    /// generated one (so `renewpartkey --register`'s preflight passes, then the
    /// register step finds the new key).
    generated: bool,
}

fn spawn_mock_algod(
    address: String,
    last_round: u64,
) -> (Arc<Mutex<AlgodState>>, Arc<AtomicBool>, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let state = Arc::new(Mutex::new(AlgodState {
        address,
        last_round,
        submitted: Vec::new(),
        generated: false,
    }));
    let state_clone = state.clone();

    std::thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut sock, _)) => {
                    sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
                    let mut buf = vec![0u8; 8192];
                    let n = sock.read(&mut buf).unwrap_or(0);
                    let raw = &buf[..n];
                    let text = String::from_utf8_lossy(raw);
                    let first_line = text.lines().next().unwrap_or("");
                    let mut parts = first_line.split_whitespace();
                    let method = parts.next().unwrap_or("");
                    let path = parts.next().unwrap_or("");
                    let path_no_qs = path.split('?').next().unwrap_or(path);

                    // Capture POST body (after the blank line) for assertions.
                    if method == "POST" && path_no_qs == "/v2/transactions" {
                        if let Some(idx) = text.find("\r\n\r\n") {
                            let body = &raw[idx + 4..];
                            state_clone.lock().unwrap().submitted.push(body.to_vec());
                        }
                    }
                    // A renew issues server-side key generation before registering.
                    if method == "POST" && path_no_qs.starts_with("/v2/participation/generate/") {
                        state_clone.lock().unwrap().generated = true;
                    }

                    let body = route(method, path_no_qs, &state_clone);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len(),
                    );
                    let _ = sock.write_all(resp.as_bytes());
                    let _ = sock.write_all(&body);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    (state, stop, port)
}

fn part_entry(address: &str, id: &str, vote_last: u64) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "address": address,
        "key": {
            "selection-participation-key": base64::engine::general_purpose::STANDARD.encode([0x22u8; 32]),
            "vote-participation-key": base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]),
            "state-proof-key": base64::engine::general_purpose::STANDARD.encode([0x33u8; 64]),
            "vote-first-valid": 1,
            "vote-last-valid": vote_last,
            "vote-key-dilution": 100,
        },
    })
}

fn route(method: &str, path: &str, state: &Arc<Mutex<AlgodState>>) -> Vec<u8> {
    let st = state.lock().unwrap();
    let json = if path == "/v2/transactions/params" {
        serde_json::json!({
            "consensus-version": "future",
            "fee": 0,
            "genesis-hash": base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
            "genesis-id": "v1",
            "last-round": st.last_round,
            "min-fee": 1000,
        })
    } else if path == "/v2/status" {
        serde_json::json!({ "last-round": st.last_round })
    } else if path == "/v2/participation" {
        // The pre-existing key (always present). For the changeonlinestatus
        // tests this is the key registered; for renew its short validity keeps
        // the preflight (reject if a key already covers roundLastValid) happy.
        let existing = part_entry(
            &st.address,
            "PARTOLDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            4000,
        );
        if st.generated {
            // After a renew's generation, also report the new longer-lived key,
            // which choose_participation picks (farthest expiry).
            let fresh = part_entry(
                &st.address,
                "PARTNEWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                5000,
            );
            serde_json::json!([existing, fresh])
        } else {
            serde_json::json!([existing])
        }
    } else if path == "/v2/transactions" && method == "POST" {
        serde_json::json!({ "txId": "TXIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" })
    } else if path.starts_with("/v2/transactions/pending/") {
        // Immediately report committed so wait_for_confirmation returns.
        serde_json::json!({ "confirmed-round": st.last_round + 1, "pool-error": "" })
    } else {
        // Generic OK (e.g. POST /v2/participation/generate/*).
        serde_json::json!({})
    };
    json.to_string().into_bytes()
}

fn wire_algod(dd: &Path, port: u16) {
    std::fs::write(dd.join("algod.net"), format!("127.0.0.1:{port}\n")).unwrap();
    std::fs::write(dd.join("algod.token"), "x".repeat(64)).unwrap();
}

/// Decode a captured submitted body as a `SignedTransaction` and confirm it
/// carries a keyreg with the expected sender + nonparticipation flag.
fn assert_submitted_keyreg(body: &[u8], expected_sender: &str, expect_nonpart: bool) {
    let stx = algo_types::SignedTransaction::decode_from_bytes(body)
        .expect("submitted body decodes as SignedTransaction");
    assert_eq!(stx.txn.txn_type, algo_types::TxnType::Keyreg);
    assert_eq!(stx.txn.sender.to_algorand_string(), expected_sender);
    assert_eq!(stx.txn.non_participation, expect_nonpart);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn changeonlinestatus_online_then_offline_round_trip() {
    let (_tmp, dd, kmd_dir) = setup_data_dir();
    let _kmd = spawn_kmd(&kmd_dir);
    let addr = create_wallet_and_account(&dd);
    let (state, stop, port) = spawn_mock_algod(addr.clone(), 100);
    wire_algod(&dd, port);

    // --- online ---
    let out = goal(
        &dd,
        &[
            "account",
            "changeonlinestatus",
            "-a",
            &addr,
            "--online",
            "-w",
            "w",
            "--password",
            "pw",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "changeonlinestatus --online failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("Transaction id for status change transaction:"),
        "missing status-change txid line; got {stdout:?}"
    );
    assert!(
        stdout.contains("committed in round"),
        "missing confirmation line; got {stdout:?}"
    );

    // --- offline ---
    let out = goal(
        &dd,
        &[
            "account",
            "changeonlinestatus",
            "-a",
            &addr,
            "--offline",
            "-w",
            "w",
            "--password",
            "pw",
        ],
    );
    assert!(
        out.status.success(),
        "changeonlinestatus --offline failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    stop.store(true, Ordering::Relaxed);

    let submitted = &state.lock().unwrap().submitted;
    assert_eq!(
        submitted.len(),
        2,
        "expected one online + one offline keyreg"
    );
    // Both are keyregs from the account; neither is nonparticipating.
    assert_submitted_keyreg(&submitted[0], &addr, false);
    assert_submitted_keyreg(&submitted[1], &addr, false);
}

#[test]
fn changeonlinestatus_no_wait_skips_confirmation() {
    let (_tmp, dd, kmd_dir) = setup_data_dir();
    let _kmd = spawn_kmd(&kmd_dir);
    let addr = create_wallet_and_account(&dd);
    let (_state, stop, port) = spawn_mock_algod(addr.clone(), 100);
    wire_algod(&dd, port);

    let out = goal(
        &dd,
        &[
            "account",
            "changeonlinestatus",
            "-a",
            &addr,
            "--offline",
            "-w",
            "w",
            "--password",
            "pw",
            "--no-wait",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("status will not change until transaction is finalized"),
        "missing no-wait note; got {stdout:?}"
    );
    assert!(
        !stdout.contains("committed in round"),
        "must not wait for confirmation; got {stdout:?}"
    );
    stop.store(true, Ordering::Relaxed);
}

#[test]
fn marknonparticipating_warns_and_submits() {
    let (_tmp, dd, kmd_dir) = setup_data_dir();
    let _kmd = spawn_kmd(&kmd_dir);
    let addr = create_wallet_and_account(&dd);
    let (state, stop, port) = spawn_mock_algod(addr.clone(), 100);
    wire_algod(&dd, port);

    let out = goal(
        &dd,
        &[
            "account",
            "marknonparticipating",
            "-a",
            &addr,
            "-w",
            "w",
            "--password",
            "pw",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "marknonparticipating failed: {stderr}"
    );
    assert!(
        stdout.contains("Transaction id for mark-nonparticipating transaction:"),
        "missing mark-nonparticipating txid line; got {stdout:?}"
    );
    assert!(
        stderr.contains("permanent and irreversible"),
        "missing irreversibility warning; got {stderr:?}"
    );
    stop.store(true, Ordering::Relaxed);

    let submitted = &state.lock().unwrap().submitted;
    assert_eq!(submitted.len(), 1);
    assert_submitted_keyreg(&submitted[0], &addr, true);
}

#[test]
fn renewpartkey_register_submits_online_keyreg() {
    let (_tmp, dd, kmd_dir) = setup_data_dir();
    let _kmd = spawn_kmd(&kmd_dir);
    let addr = create_wallet_and_account(&dd);
    let (state, stop, port) = spawn_mock_algod(addr.clone(), 100);
    wire_algod(&dd, port);

    // renewpartkey has no -w/--password flags (mirrors Go); the --register step
    // prompts for the default wallet's password, so pipe it via stdin.
    let mut child = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "renewpartkey",
            "-a",
            &addr,
            "--roundLastValid",
            "5000",
            "--register",
        ])
        .env_remove("ALGORAND_DATA")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn renewpartkey");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"pw\n")
        .expect("write password to stdin");
    let out = child.wait_with_output().expect("renewpartkey output");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "renewpartkey --register failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("Transaction id for status change transaction:"),
        "register must broadcast a keyreg; got {stdout:?}"
    );
    stop.store(true, Ordering::Relaxed);

    let submitted = &state.lock().unwrap().submitted;
    assert_eq!(submitted.len(), 1, "register broadcasts one online keyreg");
    assert_submitted_keyreg(&submitted[0], &addr, false);
}
