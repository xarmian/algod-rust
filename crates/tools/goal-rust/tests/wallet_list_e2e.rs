//! End-to-end tests for `goal-rust wallet list`. Reuses the same
//! kmd-rust spawn harness as `wallet_new_e2e.rs`, then creates one
//! or more wallets via the algo-kmd-client crate directly and asserts
//! the formatted output matches Go's `printWallets`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use algo_kmd_client::KmdClient;

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

fn poll_for_ready(dir: &Path) -> Result<(String, String), String> {
    let net_p = dir.join("kmd.net");
    let tok_p = dir.join("kmd.token");
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        if let (Ok(n), Ok(t)) = (
            std::fs::read_to_string(&net_p),
            std::fs::read_to_string(&tok_p),
        ) {
            let n = n.trim().to_string();
            let t = t.trim().to_string();
            if !n.is_empty() && !t.is_empty() {
                return Ok((n, t));
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("kmd-rust never ready".to_string())
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

fn setup_data_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let kmd = tmp.path().join("kmd-v0.5");
    std::fs::create_dir_all(&kmd).unwrap();
    write_kmd_config(&kmd);
    (tmp, kmd)
}

fn spawn_kmd(kmd_dir: &Path) -> (KmdGuard, String, String) {
    let bin = kmd_rust_binary();
    let child = Command::new(&bin)
        .args(["serve", "--data-dir"])
        .arg(kmd_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kmd-rust");
    let guard = KmdGuard(child);
    let (net, tok) = poll_for_ready(kmd_dir).expect("kmd-rust ready");
    (guard, net, tok)
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

#[test]
fn wallet_list_empty_prints_go_info_no_wallets() {
    let (data_dir, kmd_dir) = setup_data_dir();
    let _guard = spawn_kmd(&kmd_dir);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["wallet", "list"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust wallet list");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "list failed: exit={:?} stderr={stderr:?}",
        out.status.code(),
    );
    // Byte-exact vs Go's messages.go:178 (infoNoWallets) plus the
    // trailing newline reportInfoln adds.
    assert_eq!(
        stdout,
        "No wallets found. You can create a wallet with `goal wallet new`\n",
    );
}

#[test]
fn wallet_list_two_wallets_emits_go_format_banners() {
    let (data_dir, kmd_dir) = setup_data_dir();
    let (_guard, net, tok) = spawn_kmd(&kmd_dir);

    // Pre-populate two wallets directly via the kmd client so the
    // list test doesn't depend on `goal-rust wallet new`'s wiring.
    let client = KmdClient::new(&net, &tok).expect("client");
    rt().block_on(async {
        client
            .create_wallet("alpha", "sqlite", "pw", [0u8; 32])
            .await
            .expect("create alpha");
        client
            .create_wallet("bravo", "sqlite", "pw", [0u8; 32])
            .await
            .expect("create bravo");
    });

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["wallet", "list"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust wallet list");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "list failed: exit={:?} stderr={stderr:?}",
        out.status.code(),
    );
    // Structural assertions (don't pin order — kmd's ListWallets
    // doesn't guarantee one).
    let bar = "#".repeat(50);
    let lines: Vec<&str> = stdout.lines().collect();
    let bar_count = lines.iter().filter(|l| **l == bar).count();
    assert_eq!(
        bar_count, 3,
        "expected 3 separator lines (between+around two wallet blocks); got {bar_count}\n{stdout}",
    );
    assert!(
        lines.contains(&"Wallet:\talpha"),
        "missing `Wallet:\talpha`: {stdout:?}",
    );
    assert!(
        lines.contains(&"Wallet:\tbravo"),
        "missing `Wallet:\tbravo`: {stdout:?}",
    );
    // Every Wallet: line must be followed by an ID: line.
    for (i, line) in lines.iter().enumerate() {
        if line.starts_with("Wallet:\t") {
            assert!(
                lines.get(i + 1).is_some_and(|n| n.starts_with("ID:\t")),
                "Wallet: line at {i} not followed by ID: line\n{stdout}",
            );
        }
    }
}

#[test]
fn wallet_list_surfaces_unreachable_kmd_text() {
    let (data_dir, _kmd_dir) = setup_data_dir();
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["wallet", "list"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust wallet list");
    assert!(
        !out.status.success(),
        "list must fail without kmd; exit={:?}",
        out.status.code(),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Could not contact kmd; is it running?"),
        "stderr must carry Go's unreachable text; got {stderr:?}",
    );
}
