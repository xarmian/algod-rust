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

//! `goal-rust account renewpartkey / renewallpartkeys` E2E
//! (TASK-243 / B11).

#![cfg(unix)]

use base64::Engine as _;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

fn mk_data_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dd = tmp.path().to_path_buf();
    std::fs::write(
        dd.join("genesis.json"),
        r#"{"id":"v1","network":"testnet","proto":"future","alloc":[],"rwd":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I","fees":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I"}"#,
    ).unwrap();
    (tmp, dd)
}

#[derive(Default)]
struct MockState {
    table: HashMap<(String, String), serde_json::Value>,
    requests: Vec<(String, String)>,
}

fn spawn_mock_algod(
    initial: MockState,
) -> (
    Arc<Mutex<MockState>>,
    Arc<AtomicBool>,
    std::thread::JoinHandle<()>,
    u16,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let state = Arc::new(Mutex::new(initial));
    let state_clone = state.clone();
    let jh = std::thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut sock, _)) => {
                    sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first_line = req.lines().next().unwrap_or("");
                    let mut parts = first_line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_string();
                    let path = parts.next().unwrap_or("").to_string();
                    let lookup = {
                        let mut s = state_clone.lock().unwrap();
                        s.requests.push((method.clone(), path.clone()));
                        let p_no_qs = path.split('?').next().unwrap_or(&path).to_string();
                        s.table
                            .get(&(method.clone(), p_no_qs.clone()))
                            .cloned()
                            .or_else(|| s.table.get(&(method.clone(), path.clone())).cloned())
                    };
                    let (code, body) = match lookup {
                        Some(v) => (200u16, v.to_string().into_bytes()),
                        None => {
                            if method == "POST" || method == "DELETE" {
                                (200, b"{}".to_vec())
                            } else {
                                (404, Vec::new())
                            }
                        }
                    };
                    let resp = format!(
                        "HTTP/1.1 {code} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
    (state, stop, jh, port)
}

fn wire_algod(dd: &std::path::Path, port: u16) {
    std::fs::write(dd.join("algod.net"), format!("127.0.0.1:{port}\n")).unwrap();
    std::fs::write(dd.join("algod.token"), "x".repeat(64)).unwrap();
}

fn status_response(last_round: u64) -> serde_json::Value {
    serde_json::json!({
        "last-round": last_round,
        "time-since-last-round": 0,
        "catchup-time": 0,
        "last-version": "future",
        "next-version": "future",
        "next-version-round": 0,
        "next-version-supported": true,
        "stopped-at-unsupported-round": false,
    })
}

fn partkey_entry(address: &str, id: &str, vote_last: u64) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "address": address,
        "key": {
            "selection-participation-key": base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
            "vote-participation-key": base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
            "vote-first-valid": 1,
            "vote-last-valid": vote_last,
            "vote-key-dilution": 100,
        },
    })
}

/// `renewpartkey --register` is now implemented (B12); the batch
/// `renewallpartkeys --register` remains deferred and must still exit with a
/// clear message rather than silently renewing without registering.
#[test]
fn renewallpartkeys_register_flag_exits_with_deferral() {
    let (_t, dd) = mk_data_dir();
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "renewallpartkeys",
            "--roundLastValid",
            "5000",
            "--register",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("renewallpartkeys");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "--register must error");
    assert!(
        stderr.contains("not yet supported"),
        "stderr must carry deferral message; got {stderr:?}",
    );
}

#[test]
fn renewpartkey_invokes_generate_with_current_round_as_first() {
    let (_t, dd) = mk_data_dir();
    let addr = algo_types::Address([0x55; 32]).to_algorand_string();
    let mut initial = MockState::default();
    initial.table.insert(
        ("GET".to_string(), "/v2/status".to_string()),
        status_response(1000),
    );
    // Empty partkey list — preflight succeeds without finding a duplicate.
    initial.table.insert(
        ("GET".to_string(), "/v2/participation".to_string()),
        serde_json::json!([]),
    );
    let (state, stop, jh, port) = spawn_mock_algod(initial);
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "renewpartkey",
            "-a",
            &addr,
            "--roundLastValid",
            "5000",
            "--keyDilution",
            "77",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("renewpartkey");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "renewpartkey: stdout={stdout:?}, stderr={stderr:?}"
    );
    let s = state.lock().unwrap();
    let gen_req = s
        .requests
        .iter()
        .find(|(m, p)| m == "POST" && p.starts_with(&format!("/v2/participation/generate/{addr}")));
    let (_, path) = gen_req.expect("must POST generate");
    assert!(
        path.contains("first=1000"),
        "first=current round; got {path}"
    );
    assert!(path.contains("last=5000"));
    assert!(path.contains("dilution=77"));
}

#[test]
fn renewpartkey_round_last_must_exceed_current_plus_maxtxnlife() {
    // Codex round-1: Go requires roundLastValid > currentRound + MaxTxnLife.
    let (_t, dd) = mk_data_dir();
    let addr = algo_types::Address([0x66; 32]).to_algorand_string();
    let mut initial = MockState::default();
    initial.table.insert(
        ("GET".to_string(), "/v2/status".to_string()),
        status_response(5000),
    );
    initial.table.insert(
        ("GET".to_string(), "/v2/participation".to_string()),
        serde_json::json!([]),
    );
    let (_state, stop, jh, port) = spawn_mock_algod(initial);
    wire_algod(&dd, port);

    // Within 1000-round window of current → must fail
    // (current + MaxTxnLife = 6000).
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "renewpartkey",
            "-a",
            &addr,
            "--roundLastValid",
            "5500",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("renewpartkey");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "roundLastValid within MaxTxnLife must fail",
    );
    assert!(
        stderr.contains("MaxTxnLife"),
        "stderr must explain MaxTxnLife rule; got {stderr:?}",
    );
}

#[test]
fn renewpartkey_skips_when_existing_key_already_covers_round() {
    // Codex round-1: preflight existing partkey vs roundLastValid.
    let (_t, dd) = mk_data_dir();
    let addr = algo_types::Address([0x99; 32]).to_algorand_string();
    let mut initial = MockState::default();
    initial.table.insert(
        ("GET".to_string(), "/v2/status".to_string()),
        status_response(1000),
    );
    initial.table.insert(
        ("GET".to_string(), "/v2/participation".to_string()),
        serde_json::json!([partkey_entry(&addr, "IDX", 9000)]),
    );
    let (_state, stop, jh, port) = spawn_mock_algod(initial);
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "renewpartkey",
            "-a",
            &addr,
            "--roundLastValid",
            "5000",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("renewpartkey");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "preflight must reject duplicate-covered renewal",
    );
    assert!(
        stderr.contains("already valid through round"),
        "stderr must explain duplicate-cover rejection; got {stderr:?}",
    );
}

#[test]
fn renewpartkey_aborts_when_preflight_list_fails() {
    // Codex round-2: silent fall-through on list failure would
    // re-introduce the duplicate-install path.
    let (_t, dd) = mk_data_dir();
    let addr = algo_types::Address([0xAA; 32]).to_algorand_string();
    let mut initial = MockState::default();
    initial.table.insert(
        ("GET".to_string(), "/v2/status".to_string()),
        status_response(1000),
    );
    // Deliberately return non-JSON garbage so the deserialization
    // fails. The mock's default 200 OK with `{}` payload for unknown
    // GETs would otherwise pass; so insert garbage explicitly. We
    // can't easily return a non-2xx here without extending the mock,
    // so use a malformed JSON shape (a number) that will fail to
    // deserialize as Option<Vec<ParticipationKey>>.
    initial.table.insert(
        ("GET".to_string(), "/v2/participation".to_string()),
        serde_json::json!(42),
    );
    let (_state, stop, jh, port) = spawn_mock_algod(initial);
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "renewpartkey",
            "-a",
            &addr,
            "--roundLastValid",
            "5000",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("renewpartkey");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    assert!(
        !out.status.success(),
        "list_participation_keys failure must be fatal",
    );
}

#[test]
fn renewallpartkeys_iterates_unique_addresses_and_skips_already_valid() {
    let (_t, dd) = mk_data_dir();
    let addr_a = algo_types::Address([0x77; 32]).to_algorand_string();
    let addr_b = algo_types::Address([0x88; 32]).to_algorand_string();
    let mut initial = MockState::default();
    // status returns current round 1000.
    initial.table.insert(
        ("GET".to_string(), "/v2/status".to_string()),
        status_response(1000),
    );
    // Pre-existing partkeys: addr_a has vote_last=2000 (will be renewed),
    // addr_b has vote_last=9000 (already covers requested 5000 → skip).
    initial.table.insert(
        ("GET".to_string(), "/v2/participation".to_string()),
        serde_json::json!([
            partkey_entry(&addr_a, "IDA", 2000),
            partkey_entry(&addr_b, "IDB", 9000),
        ]),
    );
    let (state, stop, jh, port) = spawn_mock_algod(initial);
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "renewallpartkeys", "--roundLastValid", "5000"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("renewallpartkeys");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "renewallpartkeys: stdout={stdout:?}, stderr={stderr:?}"
    );
    assert!(
        stdout.contains(&format!("Skipping {addr_b}:")),
        "stdout must skip addr_b (vote_last >= requested); got {stdout:?}",
    );
    // Only addr_a should have been generated.
    let s = state.lock().unwrap();
    let gen_a = s.requests.iter().any(|(m, p)| {
        m == "POST" && p.starts_with(&format!("/v2/participation/generate/{addr_a}"))
    });
    let gen_b = s.requests.iter().any(|(m, p)| {
        m == "POST" && p.starts_with(&format!("/v2/participation/generate/{addr_b}"))
    });
    assert!(gen_a, "must generate for addr_a");
    assert!(!gen_b, "must NOT generate for addr_b (already covered)");
}
