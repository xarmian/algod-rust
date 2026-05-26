//! `goal-rust account addpartkey/installpartkey/listpartkeys/
//! partkeyinfo/deletepartkey` E2E (TASK-242 / B10). Uses a stub
//! algod that records POSTs and serves canned participation lists.

#![cfg(unix)]

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
    /// Path → canned JSON response (200 OK). Missing path → 404.
    table: HashMap<String, serde_json::Value>,
    /// Records each method+path the mock saw, for assertion.
    requests: Vec<(String, String)>,
    /// POST bodies received, keyed by path. Last write wins.
    post_bodies: HashMap<String, Vec<u8>>,
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
                    let mut buf = [0u8; 8192];
                    let n = sock.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first_line = req.lines().next().unwrap_or("");
                    let mut parts = first_line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_string();
                    let path = parts.next().unwrap_or("").to_string();
                    // Body extraction: split on \r\n\r\n.
                    let body_bytes: Vec<u8> = if let Some(pos) = req.find("\r\n\r\n") {
                        buf[pos + 4..n].to_vec()
                    } else {
                        Vec::new()
                    };
                    let lookup = {
                        let mut s = state_clone.lock().unwrap();
                        s.requests.push((method.clone(), path.clone()));
                        if method == "POST" || method == "PUT" {
                            s.post_bodies.insert(path.clone(), body_bytes);
                        }
                        // Strip query string for lookup (Go's
                        // generate_participation_keys uses ?first=…&last=…).
                        let path_no_qs = path.split('?').next().unwrap_or(&path).to_string();
                        s.table
                            .get(&path_no_qs)
                            .cloned()
                            .or_else(|| s.table.get(&path).cloned())
                    };
                    let (code, msg, body) = match lookup {
                        Some(v) => (200u16, "OK", v.to_string().into_bytes()),
                        None => {
                            // For unknown DELETE/POST, return 200 ""
                            // so callers can assert successful path
                            // by recording the request.
                            if method == "DELETE" || method == "POST" {
                                (200, "OK", b"{}".to_vec())
                            } else {
                                (404, "Not Found", Vec::new())
                            }
                        }
                    };
                    let resp = format!(
                        "HTTP/1.1 {code} {msg}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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

fn sample_partkey_list() -> serde_json::Value {
    use base64::Engine;
    serde_json::json!([{
        "id": "PARTID1XXXXLONGENOUGH",
        "address": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "effective-first-valid": 1000,
        "effective-last-valid": 2000,
        "last-vote": 1500,
        "key": {
            "selection-participation-key": base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]),
            "vote-participation-key": base64::engine::general_purpose::STANDARD.encode([0x22u8; 32]),
            "vote-first-valid": 1000,
            "vote-last-valid": 2000,
            "vote-key-dilution": 100,
        },
    }])
}

#[test]
fn addpartkey_invokes_generate_endpoint_with_query_params() {
    let (_t, dd) = mk_data_dir();
    let addr = algo_types::Address([0x11; 32]).to_algorand_string();
    let (state, stop, jh, port) = spawn_mock_algod(MockState::default());
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "addpartkey",
            "-a",
            &addr,
            "--roundFirstValid",
            "1000",
            "--roundLastValid",
            "2000",
            "--keyDilution",
            "55",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("addpartkey");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "addpartkey: stdout={stdout:?}, stderr={stderr:?}"
    );

    let s = state.lock().unwrap();
    let got = s
        .requests
        .iter()
        .find(|(m, p)| m == "POST" && p.starts_with(&format!("/v2/participation/generate/{addr}")));
    let (_, path) = got.expect("addpartkey must POST generate");
    assert!(
        path.contains("first=1000"),
        "must carry first=…; got {path}"
    );
    assert!(path.contains("last=2000"));
    assert!(path.contains("dilution=55"));
}

#[test]
fn addpartkey_bad_address_errors_before_any_request() {
    let (_t, dd) = mk_data_dir();
    let (state, stop, jh, port) = spawn_mock_algod(MockState::default());
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "addpartkey",
            "-a",
            "BADADDR",
            "--roundFirstValid",
            "1000",
            "--roundLastValid",
            "2000",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("addpartkey");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "bad address must fail");
    assert!(stderr.contains("Could not parse address"), "got {stderr:?}");
    assert!(
        state.lock().unwrap().requests.is_empty(),
        "no requests should have been issued",
    );
}

#[test]
fn installpartkey_requires_delete_input_flag() {
    let (tmp, dd) = mk_data_dir();
    let pk = tmp.path().join("dummy.partkey");
    std::fs::write(&pk, b"any-bytes").unwrap();

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "installpartkey", "--partkey"])
        .arg(&pk)
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("installpartkey");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "missing --delete-input must fail");
    assert!(
        stderr.contains("No --delete-input flag specified"),
        "stderr must carry Go's refusal text; got {stderr:?}",
    );
    // Input file must NOT be deleted on refusal.
    assert!(pk.exists(), "input partkey must not be deleted on refusal");
}

#[test]
fn installpartkey_uploads_bytes_and_deletes_input() {
    let (tmp, dd) = mk_data_dir();
    let pk = tmp.path().join("good.partkey");
    let pk_bytes = b"synthetic-partkey-bytes-for-test";
    std::fs::write(&pk, pk_bytes).unwrap();

    let mut initial = MockState::default();
    initial.table.insert(
        "/v2/participation".to_string(),
        serde_json::json!({"partId": "NEWPARTID"}),
    );
    let (state, stop, jh, port) = spawn_mock_algod(initial);
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "installpartkey", "--delete-input", "--partkey"])
        .arg(&pk)
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("installpartkey");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "installpartkey failed: stdout={stdout:?}, stderr={stderr:?}"
    );
    assert!(
        stdout.contains("Participation key installed successfully, Participation ID: NEWPARTID"),
        "stdout must match Go's template; got {stdout:?}",
    );
    // Body bytes survived the wire round-trip.
    let s = state.lock().unwrap();
    let body = s
        .post_bodies
        .get("/v2/participation")
        .expect("body recorded");
    assert_eq!(body.as_slice(), pk_bytes);
    // Input file deleted on success.
    assert!(!pk.exists(), "input must be deleted after install");
}

#[test]
fn listpartkeys_renders_columns_and_short_address_id() {
    let (_t, dd) = mk_data_dir();
    let mut initial = MockState::default();
    initial
        .table
        .insert("/v2/participation".to_string(), sample_partkey_list());
    let (_state, stop, jh, port) = spawn_mock_algod(initial);
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "listpartkeys"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("listpartkeys");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "listpartkeys: {stdout:?}");
    for col in [
        "Registered",
        "Account",
        "ParticipationID",
        "Last Used",
        "First round",
        "Last round",
    ] {
        assert!(
            stdout.contains(col),
            "header missing {col:?}; got {stdout:?}"
        );
    }
    // Address abbreviated as "ABCD...VWYZ" pattern (first 4 + last 4).
    assert!(
        stdout.contains("ABCD..."),
        "must abbreviate address; got {stdout:?}"
    );
    assert!(
        stdout.contains("PARTID1X..."),
        "must abbreviate part id (first 8 chars); got {stdout:?}"
    );
    assert!(
        stdout.contains("1500"),
        "last-vote must surface; got {stdout:?}"
    );
    assert!(stdout.contains("1000"));
    assert!(stdout.contains("2000"));
}

#[test]
fn partkeyinfo_renders_full_block_per_key() {
    let (_t, dd) = mk_data_dir();
    let mut initial = MockState::default();
    initial
        .table
        .insert("/v2/participation".to_string(), sample_partkey_list());
    let (_state, stop, jh, port) = spawn_mock_algod(initial);
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "partkeyinfo"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("partkeyinfo");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    for line in [
        "Dumping participation key info from",
        "Participation ID:          PARTID1XXXXLONGENOUGH",
        "Parent address:            ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Last vote round:           1500",
        "Last block proposal round: N/A",
        "Effective first round:     1000",
        "Effective last round:      2000",
        "First round:               1000",
        "Last round:                2000",
        "Key dilution:              100",
        "Selection key:",
        "Voting key:",
    ] {
        assert!(
            stdout.contains(line),
            "partkeyinfo missing {line:?}; got {stdout:?}"
        );
    }
}

#[test]
fn partkeyinfo_iterates_every_data_dir() {
    // Codex round-1 finding: Go's partkeyInfoCmd uses OnDataDirs;
    // single-dir ensure_single_data_dir was wrong.
    let (_t1, dd1) = mk_data_dir();
    let (_t2, dd2) = mk_data_dir();

    let mut initial = MockState::default();
    initial
        .table
        .insert("/v2/participation".to_string(), sample_partkey_list());
    let (_state, stop, jh, port) = spawn_mock_algod(initial);
    wire_algod(&dd1, port);
    wire_algod(&dd2, port);

    let out = Command::new(GOAL_RUST_BIN)
        .args(["-d"])
        .arg(&dd1)
        .args(["-d"])
        .arg(&dd2)
        .args(["account", "partkeyinfo"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("partkeyinfo");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "multi-dir partkeyinfo: {stdout:?}");
    let dd1_marker = format!("Dumping participation key info from {}", dd1.display());
    let dd2_marker = format!("Dumping participation key info from {}", dd2.display());
    assert!(
        stdout.contains(&dd1_marker),
        "stdout must include dd1 header; got {stdout:?}",
    );
    assert!(
        stdout.contains(&dd2_marker),
        "stdout must include dd2 header; got {stdout:?}",
    );
}

#[test]
fn addpartkey_accepts_one_round_range() {
    // Codex round-1 finding: last==first must be allowed.
    let (_t, dd) = mk_data_dir();
    let addr = algo_types::Address([0x22; 32]).to_algorand_string();
    let (_state, stop, jh, port) = spawn_mock_algod(MockState::default());
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "addpartkey",
            "-a",
            &addr,
            "--roundFirstValid",
            "1000",
            "--roundLastValid",
            "1000",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("addpartkey");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "last==first must be accepted; stderr={stderr:?}",
    );
}

#[test]
fn deletepartkey_issues_delete_request() {
    let (_t, dd) = mk_data_dir();
    let (state, stop, jh, port) = spawn_mock_algod(MockState::default());
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "deletepartkey", "--partkeyid", "PARTID1"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("deletepartkey");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "deletepartkey: {stderr:?}");
    let s = state.lock().unwrap();
    assert!(
        s.requests
            .iter()
            .any(|(m, p)| m == "DELETE" && p == "/v2/participation/PARTID1"),
        "must issue DELETE /v2/participation/PARTID1; got {:?}",
        s.requests,
    );
}
