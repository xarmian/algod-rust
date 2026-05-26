//! `goal-rust account info / balance / rewards / assetdetails` E2E
//! (TASK-237 / B5). Uses a stub HTTP server that answers
//! `GET /v2/accounts/{addr}` and `GET /v2/assets/{aid}` so we can
//! pin output without spawning algod.

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
    )
    .unwrap();
    (tmp, dd)
}

/// Mock algod serving `/v2/accounts/{addr}` and `/v2/assets/{aid}`
/// from a per-path canned-JSON map. Missing keys → 404.
fn spawn_mock_algod(
    table: HashMap<String, serde_json::Value>,
) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let table = Arc::new(Mutex::new(table));
    let handle = std::thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut sock, _)) => {
                    sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
                    let mut buf = [0u8; 2048];
                    let n = sock.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first_line = req.lines().next().unwrap_or("");
                    let path = first_line.split_whitespace().nth(1).unwrap_or("");
                    let lookup = { table.lock().unwrap().get(path).cloned() };
                    let body = match lookup {
                        Some(v) => v.to_string().into_bytes(),
                        None => Vec::new(),
                    };
                    let (code, msg) = if body.is_empty() {
                        (404, "Not Found")
                    } else {
                        (200, "OK")
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
    (stop, handle, port)
}

fn wire_algod(dd: &std::path::Path, port: u16) {
    std::fs::write(dd.join("algod.net"), format!("127.0.0.1:{port}\n")).unwrap();
    std::fs::write(dd.join("algod.token"), "x".repeat(64)).unwrap();
}

#[test]
fn account_balance_prints_amount_microalgos() {
    let (_t, dd) = mk_data_dir();
    let addr = algo_types::Address([0x11; 32]).to_algorand_string();
    let mut table = HashMap::new();
    table.insert(
        format!("/v2/accounts/{addr}"),
        serde_json::json!({
            "address": addr, "amount": 999999, "amount-without-pending-rewards": 999000,
            "pending-rewards": 999, "rewards": 42, "status": "Offline", "round": 7,
        }),
    );
    let (stop, jh, port) = spawn_mock_algod(table);
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "balance", "-a", &addr])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("balance");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "balance failed: {stdout:?}");
    assert_eq!(stdout.trim(), "999999 microAlgos");
}

#[test]
fn account_rewards_prints_rewards_microalgos() {
    let (_t, dd) = mk_data_dir();
    let addr = algo_types::Address([0x22; 32]).to_algorand_string();
    let mut table = HashMap::new();
    table.insert(
        format!("/v2/accounts/{addr}"),
        serde_json::json!({
            "address": addr, "amount": 10, "amount-without-pending-rewards": 5,
            "pending-rewards": 5, "rewards": 12345, "status": "Offline", "round": 1,
        }),
    );
    let (stop, jh, port) = spawn_mock_algod(table);
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "rewards", "-a", &addr])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("rewards");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert_eq!(stdout.trim(), "12345 microAlgos");
}

#[test]
fn account_assetdetails_prints_per_asset_block() {
    let (_t, dd) = mk_data_dir();
    let addr = algo_types::Address([0x33; 32]).to_algorand_string();
    let mut table = HashMap::new();
    table.insert(
        format!("/v2/accounts/{addr}"),
        serde_json::json!({
            "address": addr, "amount": 0, "amount-without-pending-rewards": 0,
            "pending-rewards": 0, "rewards": 0, "status": "Offline", "round": 5,
            "assets": [
                {"asset-id": 100, "amount": 250, "is-frozen": false},
            ],
        }),
    );
    table.insert(
        "/v2/assets/100".to_string(),
        serde_json::json!({
            "index": 100,
            "params": {
                "creator": "CR", "name": "ACME", "unit-name": "AC",
                "total": 1000, "decimals": 2, "url": "https://acme",
            },
        }),
    );
    let (stop, jh, port) = spawn_mock_algod(table);
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "assetdetails", "-a", &addr])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("assetdetails");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "assetdetails: {stdout:?}");
    for line in [
        &format!("Account: {addr}"),
        "Round: 5",
        "Assets:",
        "  Asset ID: 100",
        "    Amount: 2.50",
        "    IsFrozen: false",
        "  Asset Params:",
        "    Creator: CR",
        "    Name: ACME",
        "    Units: AC",
        "    Total: 1000",
        "    Decimals: 2",
        "    URL: https://acme",
    ] {
        assert!(
            stdout.contains(line),
            "assetdetails output missing line {line:?}; got {stdout:?}",
        );
    }
}

#[test]
fn account_info_prints_all_five_sections() {
    let (_t, dd) = mk_data_dir();
    let addr = algo_types::Address([0x44; 32]).to_algorand_string();
    let mut table = HashMap::new();
    table.insert(
        format!("/v2/accounts/{addr}"),
        serde_json::json!({
            "address": addr,
            "amount": 1_000_000, "amount-without-pending-rewards": 1_000_000,
            "pending-rewards": 0, "rewards": 0, "status": "Online", "round": 1,
            "min-balance": 200000,
            "assets": [{"asset-id": 50, "amount": 250, "is-frozen": true}],
            "created-assets": [{
                "index": 50,
                "params": {
                    "name": "ACME", "unit-name": "AC",
                    "total": 1000, "decimals": 2,
                },
            }],
            "created-apps": [{
                "id": 7,
                "params": {
                    "global-state-schema": {"num-uint": 4, "num-byte-slice": 2},
                    "global-state": [
                        {"key": "k1", "value": {"type": 2, "uint": 1}},
                    ],
                    "version": 8,
                },
            }],
            "apps-local-state": [{
                "id": 11,
                "schema": {"num-uint": 1, "num-byte-slice": 1},
                "key-value": [
                    {"key": "x", "value": {"type": 2, "uint": 9}},
                ],
            }],
        }),
    );
    table.insert(
        "/v2/assets/50".to_string(),
        serde_json::json!({
            "index": 50,
            "params": {"name": "ACME", "unit-name": "AC", "decimals": 2, "total": 1000, "creator": "C"},
        }),
    );
    let (stop, jh, port) = spawn_mock_algod(table);
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "info", "-a", &addr])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("info");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "info failed: stdout={stdout:?}, stderr={stderr:?}"
    );
    for expected in [
        "Created Assets:",
        "\tID 50, ACME, supply 10.00 AC",
        "Held Assets:",
        "\tID 50, ACME, balance 2.50 AC (frozen)",
        "Created Apps:",
        "\tID 7, global state used 1/4 uints, 0/2 byte slices, version 8",
        "Opted In Apps:",
        "\tID 11, local state used 1/1 uints, 0/1 byte slices",
        "Minimum Balance:\t200000 microAlgos",
    ] {
        assert!(
            stdout.contains(expected),
            "info missing {expected:?}; got {stdout:?}",
        );
    }
}

#[test]
fn account_info_empty_account_prints_none_placeholders() {
    let (_t, dd) = mk_data_dir();
    let addr = algo_types::Address([0x55; 32]).to_algorand_string();
    let mut table = HashMap::new();
    table.insert(
        format!("/v2/accounts/{addr}"),
        serde_json::json!({
            "address": addr, "amount": 0, "amount-without-pending-rewards": 0,
            "pending-rewards": 0, "rewards": 0, "status": "Offline", "round": 1,
            "min-balance": 100000,
        }),
    );
    let (stop, jh, port) = spawn_mock_algod(table);
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "info", "-a", &addr])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("info");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    for header in [
        "Created Assets:\n\t<none>",
        "Held Assets:\n\t<none>",
        "Created Apps:\n\t<none>",
        "Opted In Apps:\n\t<none>",
    ] {
        assert!(
            stdout.contains(header),
            "info missing placeholder header {header:?}; got {stdout:?}",
        );
    }
    assert!(stdout.contains("Minimum Balance:\t100000 microAlgos"));
}

#[test]
fn account_info_held_asset_404_renders_deleted_unknown() {
    let (_t, dd) = mk_data_dir();
    let addr = algo_types::Address([0x66; 32]).to_algorand_string();
    let mut table = HashMap::new();
    table.insert(
        format!("/v2/accounts/{addr}"),
        serde_json::json!({
            "address": addr, "amount": 0, "amount-without-pending-rewards": 0,
            "pending-rewards": 0, "rewards": 0, "status": "Offline", "round": 1,
            "min-balance": 0,
            "assets": [{"asset-id": 999, "amount": 1, "is-frozen": false}],
        }),
    );
    // No /v2/assets/999 entry ⇒ mock returns 404.
    let (stop, jh, port) = spawn_mock_algod(table);
    wire_algod(&dd, port);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "info", "-a", &addr])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("info");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "404 must not set non-zero exit");
    assert!(
        stdout.contains("\tID 999, <deleted/unknown asset>"),
        "info must render 404 asset as deleted/unknown; got {stdout:?}",
    );
}

#[test]
fn account_balance_bad_address_errors() {
    let (_t, dd) = mk_data_dir();
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "balance", "-a", "BADADDRESS"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("balance");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "bad address must fail");
    assert!(
        stderr.contains("Could not parse address"),
        "stderr must explain bad address; got {stderr:?}",
    );
}
