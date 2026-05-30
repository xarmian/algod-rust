//! Cross-impl interop (MIXED_CLUSTER): proves `goal-rust`'s `account` group is
//! wire-compatible with Go's `algod` + Go's `kmd`, not just our in-tree ports.
//!
//! Spawns Go's `algod` (devnet genesis) and Go's `kmd`, then drives a
//! representative subset of the Phase-B account commands against them. Mirrors
//! `algod_interop_test.rs` (PLAN-152 / TASK-230, A11) for the account group.
//!
//! Gated on `MIXED_CLUSTER=1`; Unix-only. Default `cargo test` skips cleanly.
//!
//! ```bash
//! MIXED_CLUSTER=1 cargo test -p goal-rust --test algod_account_interop_test
//! ```
//!
//! ## Subset & deliberate omissions
//!
//! Covered end-to-end against Go's stack: `wallet new` + `account new` (Go
//! kmd), `account list` (Go kmd open-handle), `account info` + `account
//! balance` (Go algod read paths).
//!
//! **`changeonlinestatus` / `marknonparticipating` are NOT in this subset.** A
//! keyreg status change must be signed by, and pay a fee from, a *funded*
//! account whose spending key we hold. The devnet genesis ships the funded
//! `WalletN` accounts' addresses (used for the read-path checks) but not their
//! spending keys, and a fresh `account new` account has a zero balance — so
//! there's no signable funded account against a bare `algod -d <genesis>` node
//! (funding one needs the heavier `goal network create` template flow, beyond
//! "spawn algod against genesis"). The keyreg submit/confirm path is covered
//! against the in-tree algod-rust + kmd-rust in
//! `account_changeonlinestatus_e2e.rs` (B12).
//!
//! **`addpartkey` / `listpartkeys` / `deletepartkey` are NOT in this subset.**
//! Go's algod gates `/v2/participation*` on the *admin* token
//! (`algod.admin.token`); goal-rust's client sends only the regular
//! `algod.token`, so those endpoints return 401 against real Go algod. That
//! admin-token gap is a goal-rust follow-up; partkey management is covered
//! against the in-tree algod-rust in `account_partkey_e2e.rs`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

fn mixed_cluster_enabled() -> bool {
    matches!(std::env::var("MIXED_CLUSTER").as_deref(), Ok(v) if !v.is_empty() && v != "0")
}

/// Workspace root — `<this crate>/../../..`.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root resolves")
}

/// Build a Go command (`./cmd/algod` or `./cmd/kmd`) from `../go-algorand`,
/// caching the binary under `target/algod-interop/`. Panics with a runnable
/// reproduction on failure.
fn ensure_go_cmd(pkg: &str, bin_name: &str) -> PathBuf {
    let target_dir = workspace_root().join("target/algod-interop");
    std::fs::create_dir_all(&target_dir).expect("mkdir algod-interop");
    let bin = target_dir.join(bin_name);
    let goalg = workspace_root().join("../go-algorand");
    assert!(
        goalg.join(pkg).exists(),
        "../go-algorand/{pkg} not found at {}; this test requires a v4.5.1-stable checkout",
        goalg.display(),
    );
    let status = Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg(format!("./{pkg}"))
        .current_dir(&goalg)
        .status()
        .expect("invoke go build");
    assert!(
        status.success(),
        "go build -o {} ./{pkg} failed; rerun manually:\n  cd {} && go build -o {} ./{pkg}",
        bin.display(),
        goalg.display(),
        bin.display(),
    );
    bin
}

/// Stage a fresh algod data dir with the devnet genesis + local-only config.
fn stage_data_dir() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("tempdir");
    let genesis_src = workspace_root().join("../go-algorand/installer/genesis/devnet/genesis.json");
    std::fs::copy(&genesis_src, tmp.path().join("genesis.json"))
        .unwrap_or_else(|e| panic!("copy devnet genesis from {}: {e}", genesis_src.display()));
    let cfg = serde_json::json!({
        "EndpointAddress": "127.0.0.1:0",
        "DNSBootstrapID": "",
        "ForceFetchTransactions": false,
        "EnableDeveloperAPI": true,
    });
    std::fs::write(
        tmp.path().join("config.json"),
        serde_json::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
    tmp
}

/// A funded address from the devnet genesis alloc (a `WalletN` entry — not the
/// RewardsPool/FeeSink), for the read-path (`info`/`balance`) checks. These are
/// online and genesis-funded; we never need their (absent) spending keys.
fn genesis_funded_address(data_dir: &Path) -> String {
    let raw = std::fs::read_to_string(data_dir.join("genesis.json")).expect("read genesis.json");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse genesis.json");
    for entry in v["alloc"].as_array().expect("alloc array") {
        let comment = entry["comment"].as_str().unwrap_or("");
        if comment.starts_with("Wallet") {
            return entry["addr"].as_str().expect("addr string").to_string();
        }
    }
    panic!("no WalletN funded address in devnet genesis alloc");
}

fn write_kmd_config(dir: &Path) {
    // Insecure scrypt so the test isn't dominated by KDF cost (matches the
    // other kmd integration tests). `sqlite` matches Go's json tag.
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

fn drain_child_output(child: &mut Child) -> String {
    use std::io::Read;
    let mut buf = String::new();
    if let Some(mut s) = child.stdout.take() {
        let mut tmp = Vec::new();
        let _ = s.read_to_end(&mut tmp);
        if !tmp.is_empty() {
            buf.push_str("[stdout]\n");
            buf.push_str(&String::from_utf8_lossy(&tmp));
            buf.push('\n');
        }
    }
    if let Some(mut s) = child.stderr.take() {
        let mut tmp = Vec::new();
        let _ = s.read_to_end(&mut tmp);
        if !tmp.is_empty() {
            buf.push_str("[stderr]\n");
            buf.push_str(&String::from_utf8_lossy(&tmp));
            buf.push('\n');
        }
    }
    if buf.is_empty() {
        "(no output captured)".to_string()
    } else {
        buf
    }
}

/// Poll for a daemon's `<name>.net` + `<name>.token` readiness markers, also
/// watching the child so an early exit surfaces its captured streams (the A11
/// lesson — a readiness-timeout-only path hides real startup failures).
fn poll_for_ready(child: &mut Child, dir: &Path, stem: &str) -> Result<(), String> {
    let net = dir.join(format!("{stem}.net"));
    let tok = dir.join(format!("{stem}.token"));
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!(
                "{stem} exited before readiness (status {status:?}):\n{}",
                drain_child_output(child),
            ));
        }
        if let (Ok(n), Ok(t)) = (std::fs::read_to_string(&net), std::fs::read_to_string(&tok)) {
            if !n.trim().is_empty() && !t.trim().is_empty() {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(format!(
        "{stem} did not write {stem}.net/{stem}.token within 60s at {}:\n{}",
        dir.display(),
        drain_child_output(child),
    ))
}

fn sigterm(pid: u32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe {
        kill(pid as i32, 15);
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        sigterm(self.0.id());
        let _ = self.0.wait();
    }
}

fn spawn_daemon(bin: &Path, data_dir: &Path, stem: &str) -> ChildGuard {
    let mut child = Command::new(bin)
        .arg("-d")
        .arg(data_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {stem}: {e}"));
    if let Err(e) = poll_for_ready(&mut child, data_dir, stem) {
        let _ = child.kill();
        let _ = child.wait();
        panic!("{stem} ready: {e}");
    }
    ChildGuard(child)
}

/// Run `goal-rust -d <dd> <args...>` with `ALGORAND_DATA` scrubbed.
fn goal(dd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(dd)
        .args(args)
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust")
}

fn assert_ok(out: &std::process::Output, what: &str) -> String {
    assert!(
        out.status.success(),
        "{what} failed: exit={:?}\n  stdout={}\n  stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn goal_rust_account_group_against_go_algod_and_kmd() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: algod_account_interop_test requires MIXED_CLUSTER=1.\n\
             Run with: MIXED_CLUSTER=1 cargo test -p goal-rust --test algod_account_interop_test",
        );
        return;
    }

    let go_algod = ensure_go_cmd("cmd/algod", "algod");
    let go_kmd = ensure_go_cmd("cmd/kmd", "kmd");

    let data_dir = stage_data_dir();
    let dd = data_dir.path();
    let _algod = spawn_daemon(&go_algod, dd, "algod");

    // kmd lives under <datadir>/kmd-v0.5 (goal-rust's default resolution).
    let kmd_dir = dd.join("kmd-v0.5");
    std::fs::create_dir_all(&kmd_dir).unwrap();
    write_kmd_config(&kmd_dir);
    let _kmd = spawn_daemon(&go_kmd, &kmd_dir, "kmd");

    // 1. wallet new (against Go kmd).
    assert_ok(
        &goal(
            dd,
            &[
                "wallet",
                "new",
                "test-wallet",
                "-w",
                "pw",
                "--no-display-seed",
            ],
        ),
        "wallet new",
    );

    // 2. account new → capture the address.
    let new_out = assert_ok(
        &goal(
            dd,
            &["account", "new", "-w", "test-wallet", "--password", "pw"],
        ),
        "account new",
    );
    let addr = new_out
        .split_whitespace()
        .next_back()
        .expect("address in account-new output")
        .to_string();

    // 3. account list → the new address is rendered. `account list` opens each
    // wallet via kmd, so it needs the password.
    let list_out = assert_ok(
        &goal(dd, &["account", "list", "--password", "pw"]),
        "account list",
    );
    assert!(
        list_out.contains(&addr),
        "account list missing the new address {addr}; got:\n{list_out}"
    );

    // 4-5. account info + balance against a genesis-funded address (read-only;
    // no spending key needed).
    let funded = genesis_funded_address(dd);
    let info_out = assert_ok(
        &goal(dd, &["account", "info", "-a", &funded]),
        "account info",
    );
    // `account info` renders the account's assets/apps/min-balance sections (it
    // doesn't echo the queried address). Assert a stable structural line so
    // wire-shape drift on `/v2/accounts/{addr}` would trip the test.
    assert!(
        info_out.contains("Minimum Balance:"),
        "account info missing the Minimum Balance line; got:\n{info_out}"
    );
    let bal_out = assert_ok(
        &goal(dd, &["account", "balance", "-a", &funded]),
        "account balance",
    );
    let bal_trimmed = bal_out.trim_end_matches('\n');
    assert!(
        bal_trimmed
            .split_whitespace()
            .next()
            .is_some_and(|t| t.chars().all(|c| c.is_ascii_digit())),
        "account balance must start with a microalgo count; got {bal_out:?}"
    );

    // NOTE: `addpartkey` / `listpartkeys` / `deletepartkey` are NOT driven here.
    // Go's algod gates the `/v2/participation*` endpoints on the *admin* token
    // (`algod.admin.token`), but goal-rust's client currently sends only the
    // regular `algod.token`, so these return 401 against a real Go algod (the
    // B10 e2e exercised them against a mock that didn't enforce the token). That
    // admin-token gap is tracked as a goal-rust follow-up; partkey management is
    // covered against the in-tree algod-rust in `account_partkey_e2e.rs`.
}
