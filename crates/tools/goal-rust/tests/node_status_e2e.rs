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

//! End-to-end smoke tests for `goal-rust node {status,lastround,
//! generatetoken}`. Spawns a minimal mock algod that serves
//! `/v2/status`, `/versions`, and `/health` from canned JSON / status
//! codes, then runs `goal-rust` with `-d <tmp>` and asserts stdout.
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
            let (status_line, body) = if first.contains("/v2/status") {
                ("HTTP/1.1 200 OK", status_json)
            } else if first.contains("/versions") {
                ("HTTP/1.1 200 OK", versions_json)
            } else if first.contains("/health") {
                // `algod_is_running` probes /health; the mock claims
                // health by default so generatetoken's "running" guard
                // can be exercised in one of the integration tests.
                ("HTTP/1.1 200 OK", "")
            } else {
                ("HTTP/1.1 200 OK", "{}")
            };
            let resp = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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

#[test]
fn node_lastround_prints_round_decimal_with_trailing_newline() {
    // Mirrors Go's `reportInfof("%d\n", round)` at node.go:527.
    let data_dir = tempfile::tempdir().expect("tempdir");
    let status_json = r#"{"last-round": 4096, "last-version": "v", "next-version": "v", "next-version-supported": true}"#;
    // `/versions` shouldn't be hit by lastround, but keep the mock
    // responsive in case retry logic touches it.
    let versions_json = r#"{"versions": ["v2"], "genesis_id": "", "genesis_hash_b64": ""}"#;
    let (port, _tokens, _server) = spawn_mock_algod(status_json, versions_json);
    write_algod_files(data_dir.path(), port, "deadbeef");

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["node", "lastround"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust node lastround");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "node lastround failed: exit={:?}, stdout={stdout:?}, stderr={stderr:?}",
        out.status.code(),
    );
    assert_eq!(stdout, "4096\n", "lastround must print `<round>\\n`");
}

#[test]
fn node_generatetoken_refuses_when_algod_running() {
    // Mirrors `node.go:393-396`: HealthCheck success ⇒
    // `reportErrorln(errorNodeRunning)`. Our mock returns 200 on
    // `/health`, so generatetoken must refuse and exit 1 without
    // writing the file.
    let data_dir = tempfile::tempdir().expect("tempdir");
    let (port, _tokens, _server) = spawn_mock_algod(
        r#"{}"#, // status unused
        r#"{}"#, // versions unused
    );
    write_algod_files(data_dir.path(), port, "tok");
    let token_path = data_dir.path().join("algod.token");
    let original = std::fs::read_to_string(&token_path).unwrap();

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["node", "generatetoken"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust node generatetoken");
    assert!(
        !out.status.success(),
        "generatetoken must exit non-zero when /health responds",
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Node must be stopped before writing APIToken"),
        "stderr must carry Go's errorNodeRunning text; got {stderr:?}",
    );
    let after = std::fs::read_to_string(&token_path).unwrap();
    assert_eq!(after, original, "token file must not be rewritten");
}

#[test]
fn node_generatetoken_refuses_when_algod_unreachable_ambiguously() {
    // Regression guard (Codex review of TASK-224 round 1): the
    // safety guard must refuse rotation on ambiguous errors (DNS
    // failure, timeout, TLS, …) rather than only when the server
    // returns 2xx. Point algod.net at an invalid `.invalid` TLD
    // which RFC 6761 guarantees is never resolvable — that's a
    // DNS error, NOT a connect-refused, so algod_is_running's
    // conservative path must engage and refuse rotation.
    let data_dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        data_dir.path().join("algod.net"),
        "definitely-not-resolvable.invalid:1\n",
    )
    .unwrap();
    let original_token = "preserve-me\n";
    std::fs::write(data_dir.path().join("algod.token"), original_token).unwrap();

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["node", "generatetoken"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust node generatetoken");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "generatetoken must refuse rotation on ambiguous probe failure; exit={:?} stderr={stderr:?}",
        out.status.code(),
    );
    assert!(
        stderr.contains("Node must be stopped before writing APIToken"),
        "must surface errorNodeRunning text; got {stderr:?}",
    );
    let after = std::fs::read_to_string(data_dir.path().join("algod.token")).unwrap();
    assert_eq!(
        after, original_token,
        "token file must NOT be rotated when probe is ambiguous",
    );
}

#[test]
fn node_start_stop_restart_print_advisory_on_stderr_and_exit_zero() {
    // Phase A's advisory stubs (TASK-225): start / stop / restart
    // delegate to the host supervisor and print guidance. They MUST
    // exit 0 (running them isn't a usage error) and the text MUST go
    // to stderr (so scripts that grep stdout don't trip).
    let tmp = tempfile::tempdir().expect("tempdir");
    for sub in ["start", "stop", "restart"] {
        let out = Command::new(GOAL_RUST_BIN)
            .arg("-d")
            .arg(tmp.path())
            .args(["node", sub])
            .env_remove("ALGORAND_DATA")
            .output()
            .unwrap_or_else(|e| panic!("run goal-rust node {sub}: {e}"));
        assert!(
            out.status.success(),
            "node {sub} must exit 0 (advisory); got exit={:?}, stderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr),
        );
        assert!(
            out.stdout.is_empty(),
            "node {sub} must not write to stdout; got {:?}",
            String::from_utf8_lossy(&out.stdout),
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("goal-rust does"),
            "node {sub} stderr must carry the advisory text; got {stderr:?}",
        );
        // Sanity: the resolved data dir is embedded for
        // copy-paste convenience.
        assert!(
            stderr.contains(&tmp.path().display().to_string()),
            "node {sub} stderr must embed the data dir; got {stderr:?}",
        );
    }
}

#[test]
fn node_generatetoken_refuses_when_algod_net_is_empty() {
    // Regression guard (Codex review of TASK-224 round 3): an
    // empty `algod.net` is ambiguous (partial write, truncation,
    // half-initialized data dir). The conservative guard must
    // refuse rotation in that case.
    let data_dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(data_dir.path().join("algod.net"), "").unwrap();
    std::fs::write(data_dir.path().join("algod.token"), "preserve\n").unwrap();
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["node", "generatetoken"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust node generatetoken");
    assert!(
        !out.status.success(),
        "empty algod.net is ambiguous — generatetoken must refuse",
    );
    assert_eq!(
        std::fs::read_to_string(data_dir.path().join("algod.token")).unwrap(),
        "preserve\n",
        "token file must NOT be rewritten",
    );
}

#[test]
fn node_generatetoken_writes_64_hex_token_when_algod_down() {
    // No mock algod ⇒ /health connect-refuses ⇒ `algod_is_running`
    // returns false ⇒ rotation proceeds. Token must be 64 lowercase
    // hex chars and the file must end up at `<data_dir>/algod.token`.
    let data_dir = tempfile::tempdir().expect("tempdir");
    // Point at an unbound port so the health probe fails fast.
    std::fs::write(data_dir.path().join("algod.net"), "127.0.0.1:1\n").unwrap();

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["node", "generatetoken"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust node generatetoken");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "generatetoken must succeed when algod is down; exit={:?}, stderr={stderr:?}",
        out.status.code(),
    );
    let token_path = data_dir.path().join("algod.token");
    let on_disk = std::fs::read_to_string(&token_path).expect("token file written");
    assert_eq!(
        on_disk.len(),
        64,
        "token on disk must be 64 chars; got {:?}",
        on_disk,
    );
    assert!(
        on_disk
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "token must be lowercase hex; got {on_disk:?}",
    );
    let info_prefix = "Successfully wrote new API token: ";
    assert!(
        stdout.starts_with(info_prefix),
        "stdout must begin with Go's infoNodeWroteToken; got {stdout:?}",
    );
    let printed = stdout
        .trim_start_matches(info_prefix)
        .trim_end_matches('\n');
    assert_eq!(printed, on_disk, "printed token must match on-disk token");
}
