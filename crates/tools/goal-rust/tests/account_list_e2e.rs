//! `goal-rust account list` E2E (TASK-236 / B4).
//!
//! Reuses the kmd-rust spawn harness + a stub HTTP server that answers
//! `GET /v2/accounts/{addr}` with canned balances/statuses so we can
//! assert the formatted table without spawning algod.

#![cfg(unix)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
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

fn poll_ready(dir: &Path) -> Result<(), String> {
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
    poll_ready(kmd_dir).expect("ready");
    g
}

fn create_default_wallet(data_dir: &Path) {
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir)
        .args(["wallet", "new", "w", "-w", "pw", "--no-display-seed"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("wallet new");
    assert!(
        out.status.success(),
        "wallet new: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn create_account(data_dir: &Path, name: &str) -> String {
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir)
        .args(["account", "new", name, "--password", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("account new");
    assert!(
        out.status.success(),
        "account new {name}: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .strip_prefix("Created new account with address ")
        .and_then(|s| s.lines().next())
        .expect("address in stdout")
        .trim()
        .to_string()
}

/// Mock algod that serves a per-address (status, amount) table via
/// `GET /v2/accounts/{addr}`. Addresses not in the table get a
/// 404 → goal-rust falls back to `[n/a]`.
fn spawn_mock_algod(
    table: HashMap<String, (String, u64)>,
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
                    // Parse the path from "GET /v2/accounts/<addr> HTTP/1.1"
                    let first_line = req.lines().next().unwrap_or("");
                    let path = first_line.split_whitespace().nth(1).unwrap_or("");
                    let addr = path.strip_prefix("/v2/accounts/").unwrap_or("");
                    let lookup = { table.lock().unwrap().get(addr).cloned() };
                    let body = match lookup {
                        Some((status, amount)) => serde_json::json!({
                            "address": addr,
                            "status": status,
                            "amount": amount,
                            "amount-without-pending-rewards": amount,
                            "pending-rewards": 0,
                            "rewards": 0,
                            "round": 1,
                        })
                        .to_string()
                        .into_bytes(),
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

#[test]
fn account_list_renders_status_address_name_balance_and_default_marker() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);

    let alice = create_account(&dd, "alice");
    let bob = create_account(&dd, "bob");

    // Mock algod returns alice=online/12345, bob=offline/100.
    let mut table = HashMap::new();
    table.insert(alice.clone(), ("Online".to_string(), 12345u64));
    table.insert(bob.clone(), ("Offline".to_string(), 100u64));
    let (stop, jh, port) = spawn_mock_algod(table);
    std::fs::write(dd.join("algod.net"), format!("127.0.0.1:{port}\n")).unwrap();
    std::fs::write(dd.join("algod.token"), "x".repeat(64)).unwrap();

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "list", "--password", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("account list");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "list failed; stdout={stdout:?}, stderr={stderr:?}",
    );

    // Both addresses appear with their friendly names.
    assert!(stdout.contains(&alice), "alice address missing: {stdout:?}");
    assert!(stdout.contains(&bob), "bob address missing: {stdout:?}");
    assert!(stdout.contains("alice"), "alice name missing: {stdout:?}");
    assert!(stdout.contains("bob"), "bob name missing: {stdout:?}");
    // Status flags.
    assert!(
        stdout.contains("[online]"),
        "online flag missing: {stdout:?}"
    );
    assert!(
        stdout.contains("[offline]"),
        "offline flag missing: {stdout:?}"
    );
    // Balances.
    assert!(stdout.contains("12345 microAlgos"));
    assert!(stdout.contains("100 microAlgos"));
    // alice is the first account created → marked default by add_account.
    // Column order matches Go: [status]\t<name>\t<address>\t<amount>...\t*Default
    let alice_line = stdout
        .lines()
        .find(|l| l.contains(&alice))
        .expect("alice row present");
    assert!(
        alice_line.starts_with("[online]\talice\t"),
        "alice row must use Go's column order [status]\\t<name>\\t<address>...; got {alice_line:?}",
    );
    assert!(
        alice_line.ends_with("\t*Default"),
        "alice row must end with *Default suffix; got {alice_line:?}",
    );
    let bob_line = stdout
        .lines()
        .find(|l| l.contains(&bob))
        .expect("bob row present");
    assert!(
        bob_line.starts_with("[offline]\tbob\t"),
        "bob row must use Go's column order; got {bob_line:?}",
    );
    assert!(
        !bob_line.contains("*Default"),
        "bob row must NOT carry *Default; got {bob_line:?}",
    );
}

#[test]
fn account_list_empty_kmd_prints_info_no_accounts() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    // No wallets — kmd starts empty.

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "list"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("list");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "list must succeed on empty kmd");
    assert!(
        stdout.contains("Did not find any account. Please import or create a new one."),
        "stdout must carry infoNoAccounts; got {stdout:?}",
    );
}

#[test]
fn account_list_empty_wallet_prints_info_no_accounts() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);
    // Wallet exists but holds no keys.

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "list", "--password", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("list");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "list must succeed; stderr={stderr:?}");
    assert!(
        stdout.contains("Did not find any account"),
        "stdout must carry infoNoAccounts; got {stdout:?}",
    );
}

#[test]
fn account_list_unreachable_kmd_surfaces_go_text() {
    let (_t, dd, _kmd_dir) = setup_data_dir();
    // No kmd spawn — kmd.net / kmd.token absent.
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "list"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("list");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "list must fail without kmd");
    assert!(
        stderr.contains("Could not contact kmd; is it running?"),
        "stderr must carry Go's unreachable text; got {stderr:?}",
    );
}

#[test]
fn account_list_renders_notparticipating_as_excluded() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);
    let acct = create_account(&dd, "alice");

    let mut table = HashMap::new();
    // "Not Participating" (with a space) is the real wire value algod
    // returns (`Status.String()`, `data/basics/userBalance.go`; verified
    // live against go-algorand v4.6.0-stable, issue #129).
    table.insert(acct.clone(), ("Not Participating".to_string(), 50u64));
    let (stop, jh, port) = spawn_mock_algod(table);
    std::fs::write(dd.join("algod.net"), format!("127.0.0.1:{port}\n")).unwrap();
    std::fs::write(dd.join("algod.token"), "x".repeat(64)).unwrap();

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "list", "--password", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("list");
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "list must succeed");
    // Go maps NotParticipating → "excluded" (accountsList.go:226).
    assert!(
        stdout.contains("[excluded]"),
        "stdout must render NotParticipating as [excluded]; got {stdout:?}",
    );
}

#[test]
fn account_list_w_unknown_wallet_errors() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "list", "-w", "nosuchwallet"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("list");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "list with unknown -w must fail; stderr={stderr:?}",
    );
    assert!(
        stderr.contains("Could not find a wallet named 'nosuchwallet'"),
        "stderr must explain missing wallet; got {stderr:?}",
    );
}

#[test]
fn account_list_falls_back_to_na_when_algod_missing() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);
    let _alice = create_account(&dd, "alice");
    // Deliberately no algod.net / algod.token.

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "list", "--password", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("list");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "list must succeed without algod");
    assert!(
        stdout.contains("[n/a]"),
        "stdout must show [n/a] status when algod unreachable; got {stdout:?}",
    );
    assert!(stdout.contains("[n/a] microAlgos"));
}
