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

//! `goal-rust node catchup | wait | pendingtxns` against a mock algod
//! (issue #1992): the exact REST calls they make and go's output / exit codes.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");
const LABEL: &str = "6500000#2YMHX6VN6SNZXF5HD6JDBTVCA4F2AE4PHMEHLFL6Q2X7N3NQX4MA";

type Seen = Arc<Mutex<Vec<String>>>;

/// A mock algod: `route(request_line, n)` answers the n-th request (0-based).
/// Returns the port and the request lines it saw.
fn mock<F>(route: F) -> (u16, Seen)
where
    F: Fn(&str, usize) -> (u16, String) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    thread::spawn(move || {
        let mut n = 0usize;
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut first = String::new();
            if reader.read_line(&mut first).is_err() {
                continue;
            }
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
                    break;
                }
            }
            let line = first.trim_end().to_string();
            log.lock().unwrap().push(line.clone());
            let (code, body) = route(&line, n);
            n += 1;
            let reason = if code == 200 { "OK" } else { "Error" };
            let resp = format!(
                "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    (port, seen)
}

fn data_dir(port: u16) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    write_net(dir.path(), port);
    dir
}

fn write_net(dir: &Path, port: u16) {
    std::fs::write(dir.join("algod.net"), format!("127.0.0.1:{port}\n")).unwrap();
    std::fs::write(dir.join("algod.token"), "tok\n").unwrap();
}

fn goal(dir: &Path, args: &[&str]) -> Output {
    Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(dir)
        .arg("node")
        .args(args)
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust")
}

fn status(round: u64, catchpoint: &str) -> String {
    format!(r#"{{"last-round": {round}, "catchpoint": "{catchpoint}"}}"#)
}

#[test]
fn catchup_posts_the_label_with_min_and_stays_quiet_when_the_node_echoes_it() {
    let (port, seen) = mock(|_, _| (200, format!(r#"{{"catchup-message": "{LABEL}"}}"#)));
    let dir = data_dir(port);
    let out = goal(dir.path(), &["catchup", LABEL, "--min", "50"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.stdout.is_empty(), "echoed label prints nothing");
    let lines = seen.lock().unwrap().clone();
    assert_eq!(
        lines,
        vec![format!(
            "POST /v2/catchup/{}?min=50 HTTP/1.1",
            LABEL.replace('#', "%23")
        )]
    );
}

#[test]
fn catchup_reports_a_different_node_response() {
    let (port, _) = mock(|_, _| (200, r#"{"catchup-message": "something else"}"#.to_string()));
    let dir = data_dir(port);
    let out = goal(dir.path(), &["catchup", LABEL]);
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "node response: something else"
    );
}

#[test]
fn catchup_abort_deletes_the_running_catchpoint_and_is_a_no_op_otherwise() {
    // catching up: DELETE the catchpoint reported by /v2/status
    let (port, seen) = mock(|line, _| {
        if line.starts_with("GET /v2/status") {
            (200, status(10, "1#ABC"))
        } else {
            (200, "{}".to_string())
        }
    });
    let dir = data_dir(port);
    let out = goal(dir.path(), &["catchup", "--abort"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let lines = seen.lock().unwrap().clone();
    assert!(
        lines.iter().any(|l| l == "DELETE /v2/catchup/1%23ABC HTTP/1.1"),
        "{lines:?}"
    );

    // not catching up: no DELETE, no error
    let (port, seen) = mock(|_, _| (200, status(10, "")));
    let dir = data_dir(port);
    let out = goal(dir.path(), &["catchup", "-x"]);
    assert!(out.status.success());
    assert!(!seen.lock().unwrap().iter().any(|l| l.starts_with("DELETE")));
}

#[test]
fn catchup_rejects_bad_and_multiple_labels_like_go() {
    let dir = tempfile::tempdir().unwrap();
    let out = goal(dir.path(), &["catchup", "not-a-label"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr)
        .contains("The provided catchpoint is not a valid one"));
    let out = goal(dir.path(), &["catchup", LABEL, LABEL]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr)
        .contains("The catchup command expect a single catchpoint"));
}

#[test]
fn catchup_reports_an_unreachable_node_like_go() {
    let dir = tempfile::tempdir().unwrap();
    let out = goal(dir.path(), &["catchup", LABEL]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Cannot contact Algorand node: "));
}

#[test]
fn pendingtxns_asks_for_json_with_the_cap_and_prints_go_s_header() {
    let (port, seen) = mock(|_, _| {
        (200, r#"{"top-transactions": [], "total-transactions": 0}"#.to_string())
    });
    let dir = data_dir(port);
    let out = goal(dir.path(), &["pendingtxns", "-m", "3"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "Pending Transactions (Truncated max=3, Total in pool=0): \nNone\n"
    );
    assert_eq!(
        seen.lock().unwrap().clone(),
        vec!["GET /v2/transactions/pending?max=3&format=json HTTP/1.1".to_string()]
    );
}

#[test]
fn pendingtxns_does_not_report_none_for_an_unexpected_response() {
    let (port, _) = mock(|_, _| (200, r#"{"something": "else"}"#.to_string()));
    let dir = data_dir(port);
    let out = goal(dir.path(), &["pendingtxns"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Cannot contact Algorand node: "));
    assert!(out.stdout.is_empty(), "must not print None");
}

#[test]
fn catchup_abort_surfaces_the_node_message_on_failure() {
    let (port, _) = mock(|line, _| {
        if line.starts_with("GET /v2/status") {
            (200, status(10, "1#ABC"))
        } else {
            (400, r#"{"message":"no catchup in progress"}"#.to_string())
        }
    });
    let dir = data_dir(port);
    let out = goal(dir.path(), &["catchup", "--abort"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no catchup in progress"));
}

#[test]
fn wait_succeeds_as_soon_as_the_round_advances() {
    let (port, _) = mock(|_, n| (200, status(100 + n as u64, "")));
    let dir = data_dir(port);
    let out = goal(dir.path(), &["wait", "-w", "10"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn wait_times_out_when_the_node_makes_no_progress() {
    let (port, _) = mock(|_, _| (200, status(100, "")));
    let dir = data_dir(port);
    let out = goal(dir.path(), &["wait", "-w", "1"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr)
        .contains("Timed out waiting for node to make progress"));
}
