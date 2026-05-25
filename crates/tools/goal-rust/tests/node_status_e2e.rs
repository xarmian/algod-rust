//! End-to-end smoke test: spawn a minimal mock algod that serves
//! `/v2/status` and `/versions` from canned JSON, then run
//! `goal-rust node status -d <tmp>` and assert the stdout matches the
//! Go-format golden text.
//!
//! Using a hand-rolled `std::net::TcpListener` mock instead of spawning
//! `algod-rust` itself — that crate has a heavyweight startup path
//! (genesis load, ledger init) that's overkill for a single-roundtrip
//! parity test. The mock is wire-compatible because it serves the same
//! `/v2/status` + `/versions` JSON shapes our client expects, and the
//! `make_status_string` formatter is the unit under test.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

/// Captured tokens (`X-Algo-API-Token` header values) observed across
/// every accepted request, in arrival order.
type TokenLog = Arc<Mutex<Vec<String>>>;

fn spawn_mock_algod(
    status_json: &'static str,
    versions_json: &'static str,
) -> (u16, TokenLog, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1");
    let port = listener.local_addr().unwrap().port();
    let tokens: TokenLog = Arc::new(Mutex::new(Vec::new()));
    let log = tokens.clone();
    let handle = thread::spawn(move || {
        // Accept-once-per-route, then exit. The client makes two
        // requests (status, versions); we accept both before
        // returning so the OS doesn't drop the connection mid-test.
        for _ in 0..16 {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut first = String::new();
            if reader.read_line(&mut first).is_err() {
                continue;
            }
            // Drain remaining headers, capturing the API token header.
            let mut token = String::new();
            loop {
                let mut buf = String::new();
                if reader.read_line(&mut buf).is_err() || buf == "\r\n" || buf.is_empty() {
                    break;
                }
                if let Some(rest) = buf
                    .strip_prefix("X-Algo-API-Token: ")
                    .or_else(|| buf.strip_prefix("x-algo-api-token: "))
                {
                    token = rest.trim_end_matches(['\r', '\n']).to_string();
                }
            }
            log.lock().unwrap().push(token);
            let body = if first.contains("/v2/status") {
                status_json
            } else if first.contains("/versions") {
                versions_json
            } else {
                "{}"
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    (port, tokens, handle)
}

fn write_algod_files(data_dir: &Path, port: u16, token: &str) {
    std::fs::write(data_dir.join("algod.net"), format!("127.0.0.1:{port}\n")).unwrap();
    std::fs::write(data_dir.join("algod.token"), format!("{token}\n")).unwrap();
}

#[test]
fn node_status_short_w_flag_accepted() {
    // Regression guard (Codex review of TASK-223 round 1): Go's
    // `goal node status -w 1` is valid (`--watch`'s short alias).
    // Verify clap accepts `-w 0` (single shot) without erroring on
    // an unknown flag. We don't actually invoke the loop with
    // non-zero millis; just confirm the parser path.
    let tmp = tempfile::tempdir().expect("tempdir");
    // No algod files written: status will fail to read algod.net,
    // exit 1 — but only AFTER clap accepts `-w 0`. Failure-mode
    // matters: an "unexpected argument '-w'" message would mean we
    // never got past parsing.
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(tmp.path())
        .args(["node", "status", "-w", "0"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust node status -w 0");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("unexpected argument"),
        "-w should be accepted; got stderr: {stderr:?}",
    );
}

#[test]
fn node_status_prefers_admin_token_when_both_present() {
    // Regression guard (Codex review of TASK-223 round 1): Go's
    // ensureAlgodClient reads algod.admin.token first, falls back to
    // algod.token. With only algod.admin.token present, the call
    // must still go through (we're not asserting which token reaches
    // the server; just that the run doesn't fail before connecting).
    let data_dir = tempfile::tempdir().expect("tempdir");
    let status_json = r#"{
        "last-round": 1,
        "time-since-last-round": 0,
        "catchup-time": 0,
        "last-version": "v",
        "next-version": "v",
        "next-version-round": 2,
        "next-version-supported": true,
        "stopped-at-unsupported-round": false
    }"#;
    let versions_json = r#"{
        "versions": ["v2"],
        "genesis_id": "g",
        "genesis_hash_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }"#;
    let (port, tokens, _server) = spawn_mock_algod(status_json, versions_json);
    // Write BOTH tokens with distinct values so the test actually
    // exercises the preference (Codex round 2): the admin one must
    // be the value transmitted on the wire.
    std::fs::write(
        data_dir.path().join("algod.net"),
        format!("127.0.0.1:{port}\n"),
    )
    .unwrap();
    std::fs::write(data_dir.path().join("algod.token"), "regular-tok\n").unwrap();
    std::fs::write(data_dir.path().join("algod.admin.token"), "admin-tok\n").unwrap();

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["node", "status"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust node status");
    assert!(
        out.status.success(),
        "expected success; exit={:?}, stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
    let seen = tokens.lock().unwrap().clone();
    assert!(
        !seen.is_empty(),
        "mock algod should have observed at least one request",
    );
    for t in &seen {
        assert_eq!(
            t, "admin-tok",
            "admin token must be preferred over algod.token; got {seen:?}",
        );
    }
}

#[test]
fn node_status_prints_go_format_text_for_synced_node() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let status_json = r#"{
        "last-round": 42,
        "time-since-last-round": 3500000000,
        "catchup-time": 0,
        "last-version": "future",
        "next-version": "future",
        "next-version-round": 100,
        "next-version-supported": true,
        "stopped-at-unsupported-round": false
    }"#;
    let versions_json = r#"{
        "versions": ["v2"],
        "genesis_id": "testnet-v1",
        "genesis_hash_b64": "SGVsbG8gV29ybGQAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }"#;
    let (port, _tokens, _server) = spawn_mock_algod(status_json, versions_json);
    write_algod_files(data_dir.path(), port, "deadbeef");

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["node", "status"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust node status");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "node status failed: exit={:?}, stdout={stdout:?}, stderr={stderr:?}",
        out.status.code(),
    );
    let expected = "Last committed block: 42\n\
        Time since last block: 3.5s\n\
        Sync Time: 0.0s\n\
        Last consensus protocol: future\n\
        Next consensus protocol: future\n\
        Round for next consensus protocol: 100\n\
        Next consensus protocol supported: true\n\
        Genesis ID: testnet-v1\n\
        Genesis hash: SGVsbG8gV29ybGQAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
    assert_eq!(
        stdout, expected,
        "stdout did not match golden text (stderr={stderr:?})",
    );
}
