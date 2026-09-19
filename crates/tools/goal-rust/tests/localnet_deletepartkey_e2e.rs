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

//! `TestDeletePartKey` (go-algorand
//! `test/e2e-go/features/participation/deletePartKeys_test.go:30`): a
//! single dev-mode node (`DevModeOneWallet.json`) with an existing
//! participation key; `goal-rust account deletepartkey` removes it and
//! `account listpartkeys`'s count (read via the raw `/v2/participation`
//! REST array, which carries full, untruncated IDs) drops by one -- part
//! of #1457, batch 10, `docs/phase17/parity_e2e.md`.
//!
//! Gated on `MIXED_CLUSTER=1`; Unix-only, mirroring
//! `localnet_node_e2e.rs`/`localnet_app_lifecycle_e2e.rs`.
//!
//! ```bash
//! MIXED_CLUSTER=1 cargo test -p goal-rust --test localnet_deletepartkey_e2e
//! ```

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

const DEV_ADDR: &str = "E4A7NFAARAKFG4ZK7KQ7VZBO5XEQIUKBK2U3KNLAFTX6R3HTJBFG75MQZE";
const DEV_MNEMONIC: &str = "under this above produce during card issue fire gloom reopen topple rough cat smooth salad put broken decade vocal loud pulp gauge hurdle absorb olympic";

fn mixed_cluster_enabled() -> bool {
    matches!(std::env::var("MIXED_CLUSTER").as_deref(), Ok(v) if !v.is_empty() && v != "0")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root resolves")
}

fn ensure_rust_bin(pkg: &str) -> PathBuf {
    let root = workspace_root();
    let status = Command::new("cargo")
        .args(["build", "-p", pkg])
        .current_dir(&root)
        .status()
        .unwrap_or_else(|e| panic!("cargo build -p {pkg}: {e}"));
    assert!(status.success(), "cargo build -p {pkg} failed");
    for c in ["debug", "release"] {
        let p = root.join("target").join(c).join(pkg);
        if p.exists() {
            return p;
        }
    }
    panic!("{pkg} binary not found after build");
}

fn stage_data_dir() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("tempdir");
    let genesis_src = workspace_root().join("docker/localnet-rust/data/genesis.json");
    std::fs::copy(&genesis_src, tmp.path().join("genesis.json"))
        .unwrap_or_else(|e| panic!("copy dev genesis from {}: {e}", genesis_src.display()));
    tmp
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

fn sigterm(pid: u32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe {
        kill(pid as i32, 15);
    }
}

struct DaemonGuard {
    child: Child,
    name: &'static str,
    log_path: PathBuf,
}

impl DaemonGuard {
    fn log_tail(&self) -> String {
        std::fs::read_to_string(&self.log_path)
            .unwrap_or_else(|e| format!("(could not read {} log: {e})", self.name))
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        sigterm(self.child.id());
        let _ = self.child.wait();
    }
}

fn spawn_daemon(
    bin: &Path,
    args: &[&str],
    cwd_dir: &Path,
    ready_dir: &Path,
    name: &'static str,
    stem: &str,
) -> DaemonGuard {
    let log_path = cwd_dir.join(format!("{name}.log"));
    let log = std::fs::File::create(&log_path)
        .unwrap_or_else(|e| panic!("create {} log at {}: {e}", name, log_path.display()));
    let log_err = log.try_clone().expect("clone log handle");
    let child = Command::new(bin)
        .args(args)
        .env_remove("ALGORAND_DATA")
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
    let mut guard = DaemonGuard {
        child,
        name,
        log_path,
    };

    let net = ready_dir.join(format!("{stem}.net"));
    let tok = ready_dir.join(format!("{stem}.token"));
    let start = Instant::now();
    loop {
        if let Ok(Some(status)) = guard.child.try_wait() {
            panic!(
                "{name} exited before readiness (status {status:?}); log:\n{}",
                guard.log_tail()
            );
        }
        if let (Ok(n), Ok(t)) = (std::fs::read_to_string(&net), std::fs::read_to_string(&tok)) {
            if !n.trim().is_empty() && !t.trim().is_empty() {
                return guard;
            }
        }
        if start.elapsed() > Duration::from_secs(60) {
            panic!(
                "{name} did not write {stem}.net/{stem}.token within 60s at {}; log:\n{}",
                ready_dir.display(),
                guard.log_tail()
            );
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn goal_rust(dd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(dd)
        .args(args)
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust")
}

fn assert_cli_ok(out: &std::process::Output, what: &str, node: &DaemonGuard) -> String {
    assert!(
        out.status.success(),
        "{what} failed: exit={:?}\n  stdout={}\n  stderr={}\n  --- node log ---\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
        node.log_tail(),
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// GET a `/v2/participation*` (or other admin-tier) endpoint using the
/// admin token (`algod.admin.token`) -- the public `algod.token` gets a 401
/// on these routes (`crates/node/algo-rest-api/src/router.rs:287-324`).
fn get_json_admin(dd: &Path, path: &str) -> serde_json::Value {
    get_json_with_token(dd, path, "algod.admin.token")
}

fn get_json_with_token(dd: &Path, path: &str, token_file: &str) -> serde_json::Value {
    let algod_net = std::fs::read_to_string(dd.join("algod.net"))
        .expect("algod.net written by spawn_daemon readiness poll")
        .trim()
        .to_string();
    let algod_token = std::fs::read_to_string(dd.join(token_file))
        .unwrap_or_else(|e| panic!("{token_file} not found in {}: {e}", dd.display()))
        .trim()
        .to_string();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let url = format!("http://{algod_net}{path}");
        let resp = reqwest::Client::new()
            .get(&url)
            .header("X-Algo-API-Token", &algod_token)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {url}: {e}"));
        assert!(
            resp.status().is_success(),
            "GET {url} returned {}",
            resp.status()
        );
        resp.json().await.expect("response is valid JSON")
    })
}

/// go's `TestDeletePartKey`: add a participation key, delete it via
/// `account deletepartkey`, and confirm the participation-key count drops
/// by exactly one.
#[test]
fn localnet_dev_node_deletepartkey_removes_key() {
    if !mixed_cluster_enabled() {
        eprintln!(
            "SKIPPED: localnet_deletepartkey_e2e requires MIXED_CLUSTER=1.\n\
             Run with: MIXED_CLUSTER=1 cargo test -p goal-rust --test localnet_deletepartkey_e2e",
        );
        return;
    }

    let algod_rust = ensure_rust_bin("algod-rust");
    let kmd_rust = ensure_rust_bin("kmd-rust");

    let data_dir = stage_data_dir();
    let dd = data_dir.path();

    let node = spawn_daemon(
        &algod_rust,
        &[
            "node",
            "start",
            "-d",
            dd.to_str().unwrap(),
            "-l",
            "127.0.0.1:0",
            "--dev",
        ],
        dd,
        dd,
        "node",
        "algod",
    );

    let kmd_dir = dd.join("kmd-v0.5");
    std::fs::create_dir_all(&kmd_dir).unwrap();
    write_kmd_config(&kmd_dir);
    let _kmd = spawn_daemon(
        &kmd_rust,
        &["serve", "--data-dir", kmd_dir.to_str().unwrap()],
        dd,
        &kmd_dir,
        "kmd",
        "kmd",
    );

    assert_cli_ok(
        &goal_rust(dd, &["wallet", "new", "w", "-w", "pw", "--no-display-seed"]),
        "wallet new",
        &node,
    );
    assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "account",
                "import",
                "-w",
                "w",
                "--password",
                "pw",
                "--mnemonic",
                DEV_MNEMONIC,
            ],
        ),
        "account import",
        &node,
    );

    // Register a participation key (mirrors `localnet_node_e2e.rs`'s
    // addpartkey usage) -- go's fixture starts with an existing key already
    // registered for the wallet's root account; we create one explicitly.
    assert_cli_ok(
        &goal_rust(
            dd,
            &[
                "account",
                "addpartkey",
                "-a",
                DEV_ADDR,
                "--roundFirstValid",
                "1",
                "--roundLastValid",
                "2000",
            ],
        ),
        "account addpartkey",
        &node,
    );

    // Poll /v2/participation until the new key is registered. An empty list
    // encodes as JSON `null` (nil-slice omitempty, matching go), not `[]`.
    let start = Instant::now();
    let parts_before = loop {
        let parts = get_json_admin(dd, "/v2/participation");
        let is_nonempty_array = parts.as_array().is_some_and(|a| !a.is_empty());
        if is_nonempty_array {
            break parts;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "no participation key registered within 30s of addpartkey; node log:\n{}",
            node.log_tail()
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    let before_arr = parts_before.as_array().unwrap();
    let count_before = before_arr.len();
    assert!(
        count_before > 0,
        "expected at least one participation key before delete; got:\n{parts_before}"
    );
    let target_id = before_arr[0]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("participation entry missing string 'id': {parts_before}"))
        .to_string();

    let delete_out = assert_cli_ok(
        &goal_rust(dd, &["account", "deletepartkey", "--partkeyid", &target_id]),
        "account deletepartkey",
        &node,
    );
    assert!(
        delete_out.is_empty() || !delete_out.to_lowercase().contains("error"),
        "deletepartkey should not report an error; got:\n{delete_out}"
    );

    let parts_after = get_json_admin(dd, "/v2/participation");
    // An empty list may encode as JSON `null` (nil-slice omitempty, matching
    // go's `[]model.ParticipationKey` wire behavior) rather than `[]`.
    let empty = Vec::new();
    let after_arr = if parts_after.is_null() {
        &empty
    } else {
        parts_after.as_array().unwrap_or_else(|| {
            panic!("GET /v2/participation did not return an array: {parts_after}")
        })
    };
    assert_eq!(
        after_arr.len(),
        count_before - 1,
        "participation-key count should drop by exactly 1 after delete; before={count_before}, after:\n{parts_after}"
    );
    assert!(
        !after_arr
            .iter()
            .any(|p| p["id"].as_str() == Some(target_id.as_str())),
        "deleted participation id {target_id} should no longer be listed; got:\n{parts_after}"
    );
}
