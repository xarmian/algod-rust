//! End-to-end coverage for `goal-rust account new / delete / rename`
//! (TASK-235 / B3). Reuses the same kmd-rust spawn harness pattern as
//! `wallet_new_e2e.rs`. `account dump` exercises a stub HTTP server so
//! it doesn't need a full algod spawn.

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
    assert!(status.success(), "kmd-rust build failed");
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

/// Build a private data dir with genesis.json so AccountsList resolves
/// `<data_dir>/<gid>/accountList.json`, and kmd-v0.5 wired up.
fn setup_data_dir() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dd = tmp.path().to_path_buf();
    let kmd = dd.join("kmd-v0.5");
    std::fs::create_dir_all(&kmd).unwrap();
    write_kmd_config(&kmd);
    let genesis = serde_json::json!({
        "id": "v1",
        "network": "testnet",
        "proto": "future",
        "alloc": [],
        "rwd": "FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I",
        "fees": "FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I",
    });
    std::fs::write(
        dd.join("genesis.json"),
        serde_json::to_string_pretty(&genesis).unwrap(),
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
    let guard = KmdGuard(child);
    poll_ready(kmd_dir).expect("kmd-rust ready");
    guard
}

/// Run `goal-rust wallet new w -w pw --no-display-seed -d <dd>`,
/// returning the resulting accountList.json default wallet id.
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
        "wallet new failed: {:?}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn account_new_creates_address_and_prints_go_text() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "new", "alice", "--password", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("account new");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "account new failed; stdout={stdout:?}, stderr={stderr:?}",
    );
    assert!(
        stdout.starts_with("Created new account with address "),
        "stdout must use infoCreatedNewAccount template; got {stdout:?}",
    );
    // accountList.json now contains the friendly name.
    let acct_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dd.join("testnet-v1").join("accountList.json")).unwrap(),
    )
    .unwrap();
    let accounts = acct_json.get("Accounts").unwrap().as_object().unwrap();
    assert!(
        accounts.values().any(|v| v == "alice"),
        "accountList must record alice; got {acct_json}",
    );
}

#[test]
fn account_rename_swaps_friendly_name() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);

    // Create an account named "alice".
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "new", "alice", "--password", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("account new");
    assert!(out.status.success());

    // Rename to bob.
    let r = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "rename", "alice", "bob"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("rename");
    let stdout = String::from_utf8_lossy(&r.stdout);
    assert!(r.status.success(), "rename failed: {stdout:?}");
    assert!(
        stdout.contains("Renamed account 'alice' to 'bob'"),
        "stdout must use infoRenamedAccount; got {stdout:?}",
    );

    // File now reflects bob.
    let acct_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dd.join("testnet-v1").join("accountList.json")).unwrap(),
    )
    .unwrap();
    let accounts = acct_json.get("Accounts").unwrap().as_object().unwrap();
    assert!(accounts.values().any(|v| v == "bob"));
    assert!(!accounts.values().any(|v| v == "alice"));
}

#[test]
fn account_rename_to_existing_name_errors() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);

    // Create alice + bob.
    for n in ["alice", "bob"] {
        let out = Command::new(GOAL_RUST_BIN)
            .arg("-d")
            .arg(&dd)
            .args(["account", "new", n, "--password", "pw"])
            .env_remove("ALGORAND_DATA")
            .output()
            .expect("account new");
        assert!(out.status.success());
    }

    // Renaming alice → bob must fail with errorNameAlreadyTaken.
    let r = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "rename", "alice", "bob"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("rename");
    let stderr = String::from_utf8_lossy(&r.stderr);
    assert!(!r.status.success(), "rename to taken name must fail");
    assert!(
        stderr.contains("The account name 'bob' is already taken"),
        "stderr must carry errorNameAlreadyTaken; got {stderr:?}",
    );
}

#[test]
fn account_rename_missing_old_name_errors() {
    let (_t, dd, _kmd_dir) = setup_data_dir();
    // No kmd / no wallet → rename is local-only and still needs the
    // accountList. Just make sure missing name produces errorNameDoesntExist.
    let r = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "rename", "nope", "newname"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("rename");
    let stderr = String::from_utf8_lossy(&r.stderr);
    assert!(!r.status.success());
    assert!(
        stderr.contains("An account named 'nope' does not exist"),
        "stderr must carry errorNameDoesntExist; got {stderr:?}",
    );
}

#[test]
fn account_delete_removes_key_and_local_entry() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);

    // Create an account; capture its address from stdout.
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "new", "victim", "--password", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("account new");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let addr = stdout
        .strip_prefix("Created new account with address ")
        .and_then(|s| s.lines().next())
        .expect("address in stdout")
        .trim();

    // Delete it.
    let d = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "delete", "-a", addr, "--password", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("delete");
    let derr = String::from_utf8_lossy(&d.stderr);
    assert!(d.status.success(), "delete failed: {derr:?}");

    // accountList.json no longer carries the entry.
    let acct_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dd.join("testnet-v1").join("accountList.json")).unwrap(),
    )
    .unwrap();
    let accounts = acct_json.get("Accounts").unwrap().as_object().unwrap();
    assert!(
        !accounts.contains_key(addr),
        "accountList must drop {addr}; got {acct_json}",
    );
}

/// Minimal HTTP server that answers `GET /v2/accounts/{addr}` with a
/// canned AccountInfo JSON. Used by the `account dump` test so we
/// don't have to spawn algod-rust.
fn spawn_mock_algod(
    canned: serde_json::Value,
) -> (
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::thread::JoinHandle<()>,
    u16,
) {
    use std::io::{Read, Write as _};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let handle = std::thread::spawn(move || {
        let body = serde_json::to_vec(&canned).unwrap();
        while !stop_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut sock, _)) => {
                    sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
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
fn account_dump_pretty_prints_rest_response() {
    use std::sync::atomic::Ordering;
    let tmp = tempfile::tempdir().expect("tempdir");
    let dd = tmp.path().to_path_buf();
    // Minimal genesis.json so data_dir helpers work.
    std::fs::write(
        dd.join("genesis.json"),
        r#"{"id":"v1","network":"testnet","proto":"future","alloc":[],"rwd":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I","fees":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I"}"#,
    )
    .unwrap();
    // Compute a known-valid Algorand address at runtime so the test
    // doesn't depend on a hand-typed checksum.
    let addr = algo_types::Address([0xab; 32]).to_algorand_string();
    let addr = addr.as_str();
    let canned = serde_json::json!({
        "address": addr,
        "amount": 12345,
        "amount-without-pending-rewards": 12000,
        "pending-rewards": 345,
        "rewards": 1000,
        "status": "Online",
        "min-balance": 100000,
        "round": 42,
    });
    let (stop, jh, port) = spawn_mock_algod(canned);
    std::fs::write(dd.join("algod.net"), format!("127.0.0.1:{port}\n")).unwrap();
    std::fs::write(dd.join("algod.token"), "x".repeat(64)).unwrap();

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "dump", "-a", addr])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("dump");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    stop.store(true, Ordering::Relaxed);
    let _ = jh.join();
    assert!(
        out.status.success(),
        "dump failed; stdout={stdout:?}, stderr={stderr:?}",
    );
    // Output is pretty JSON — must contain the address line and the
    // 2-space indent.
    assert!(stdout.contains(addr), "address must appear: {stdout:?}");
    assert!(
        stdout.contains("\n  "),
        "must be pretty-printed: {stdout:?}"
    );
    assert!(stdout.contains("\"amount\": 12345"));
}

/// Sanity guard: feeding `wallet new` an explicit stdin password line
/// works for `account new` too.
#[test]
fn account_new_reads_password_from_non_tty_stdin() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);

    let mut child = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "new", "from-stdin"])
        .env_remove("ALGORAND_DATA")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child.stdin.as_mut().unwrap().write_all(b"pw\n").unwrap();
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stdin-password path must succeed; stdout={stdout:?}",
    );
    assert!(stdout.starts_with("Created new account with address "));
}
