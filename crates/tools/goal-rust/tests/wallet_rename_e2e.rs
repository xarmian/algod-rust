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

//! End-to-end tests for `goal-rust wallet rename`. Spawns kmd-rust,
//! seeds wallets via the kmd client directly, then drives the
//! goal-rust binary and asserts Go-exact output for happy and error
//! paths.

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
    let net = dir.join("kmd.net");
    let tok = dir.join("kmd.token");
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        if let (Ok(n), Ok(t)) = (std::fs::read_to_string(&net), std::fs::read_to_string(&tok)) {
            let n = n.trim().to_string();
            let t = t.trim().to_string();
            if !n.is_empty() && !t.is_empty() {
                return Ok((n, t));
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("kmd never ready".to_string())
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
    let g = KmdGuard(child);
    let (net, tok) = poll_for_ready(kmd_dir).expect("ready");
    (g, net, tok)
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn wallet_rename_happy_path_prints_go_text_and_renames() {
    let (data_dir, kmd_dir) = setup_data_dir();
    let (_g, net, tok) = spawn_kmd(&kmd_dir);
    let client = KmdClient::new(&net, &tok).expect("client");
    rt().block_on(async {
        client
            .create_wallet("foo", "sqlite", "pw", [0u8; 32])
            .await
            .expect("seed foo");
    });

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["wallet", "rename", "foo", "bar", "-w", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust wallet rename");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "rename failed: exit={:?} stdout={stdout:?} stderr={stderr:?}",
        out.status.code(),
    );
    assert_eq!(stdout, "Renamed wallet 'foo' to 'bar'\n");

    // Verify the wallet is now named 'bar' in kmd.
    let listed = rt().block_on(async { client.list_wallets().await.unwrap().wallets });
    assert!(
        listed.iter().any(|w| w.name == "bar"),
        "wallet not renamed in kmd: {listed:?}",
    );
    assert!(
        !listed.iter().any(|w| w.name == "foo"),
        "old name still present: {listed:?}",
    );
}

#[test]
fn wallet_rename_missing_source_emits_go_couldnt_find() {
    let (data_dir, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["wallet", "rename", "nope", "bar", "-w", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust wallet rename");
    assert!(
        !out.status.success(),
        "rename must fail when source name absent",
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Couldn't find wallet: nope"),
        "stderr must use Go's errorCouldntFindWallet text; got {stderr:?}",
    );
}

#[test]
fn wallet_rename_wrong_password_surfaces_server_message() {
    let (data_dir, kmd_dir) = setup_data_dir();
    let (_g, net, tok) = spawn_kmd(&kmd_dir);
    rt().block_on(async {
        KmdClient::new(&net, &tok)
            .unwrap()
            .create_wallet("foo", "sqlite", "correct-pw", [0u8; 32])
            .await
            .expect("seed");
    });

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["wallet", "rename", "foo", "bar", "-w", "wrong-pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust wallet rename");
    assert!(
        !out.status.success(),
        "rename must fail with wrong password",
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.starts_with("Couldn't rename wallet:"),
        "stderr must use Go's errorCouldntRenameWallet template; got {stderr:?}",
    );
    let body = stderr.split_once(':').map(|(_, r)| r.trim()).unwrap_or("");
    assert!(!body.is_empty(), "server message missing: {stderr:?}");
}

#[test]
fn wallet_rename_same_name_rejects_locally() {
    // Mirrors wallet.go:232-234: Go reports
    // "new name is identical to current name" without contacting kmd.
    // We do the same check before listing — exercise it with an
    // entirely-unstarted kmd to confirm no network call is made.
    let (data_dir, _kmd_dir) = setup_data_dir();
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(data_dir.path())
        .args(["wallet", "rename", "same", "same", "-w", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal-rust wallet rename");
    assert!(!out.status.success(), "same-name rename must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Couldn't rename wallet: new name is identical to current name"),
        "stderr must surface Go's same-name reason; got {stderr:?}",
    );
}
