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

//! `goal-rust account multisig new/delete/info` E2E (TASK-240 / B8).
//! Creates three component accounts via `account new`, builds a
//! 2-of-3 multisig from their addresses, validates the round-trip.

#![cfg(unix)]

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
    ).unwrap();
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

fn create_default_wallet(dd: &Path) {
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(dd)
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

fn create_account(dd: &Path, name: &str) -> String {
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(dd)
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

#[test]
fn multisig_new_delete_info_round_trip() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);

    let a = create_account(&dd, "alice");
    let b = create_account(&dd, "bob");
    let c = create_account(&dd, "carol");

    // Create 2-of-3 multisig.
    let new = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "multisig",
            "new",
            "-T",
            "2",
            &a,
            &b,
            &c,
            "--password",
            "pw",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("multisig new");
    let stdout = String::from_utf8_lossy(&new.stdout);
    let stderr = String::from_utf8_lossy(&new.stderr);
    assert!(
        new.status.success(),
        "multisig new failed: stdout={stdout:?}, stderr={stderr:?}"
    );
    let msig_addr = stdout
        .strip_prefix("Created new account with address ")
        .and_then(|s| s.lines().next())
        .expect("multisig addr in stdout")
        .trim()
        .to_string();

    // multisig info renders Version/Threshold/Public keys block.
    let info = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "multisig",
            "info",
            "-a",
            &msig_addr,
            "--password",
            "pw",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("multisig info");
    let info_stdout = String::from_utf8_lossy(&info.stdout);
    let info_stderr = String::from_utf8_lossy(&info.stderr);
    assert!(
        info.status.success(),
        "multisig info failed: {info_stdout:?}, {info_stderr:?}"
    );
    assert!(
        info_stdout.contains("Version: 1\n"),
        "info must show version 1; got {info_stdout:?}"
    );
    assert!(
        info_stdout.contains("Threshold: 2\n"),
        "info must show threshold 2; got {info_stdout:?}"
    );
    assert!(info_stdout.contains("Public keys:"));
    assert!(
        info_stdout.contains(&a),
        "info must list alice's pubkey: {info_stdout:?}"
    );
    assert!(info_stdout.contains(&b));
    assert!(info_stdout.contains(&c));

    // multisig delete removes the entry.
    let del = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "multisig",
            "delete",
            "-a",
            &msig_addr,
            "--password",
            "pw",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("multisig delete");
    let del_stderr = String::from_utf8_lossy(&del.stderr);
    assert!(
        del.status.success(),
        "multisig delete failed: {del_stderr:?}"
    );

    // Subsequent info must fail (address no longer present).
    let info2 = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "multisig",
            "info",
            "-a",
            &msig_addr,
            "--password",
            "pw",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("multisig info after delete");
    assert!(!info2.status.success(), "info after delete must fail");
}

#[test]
fn multisig_new_threshold_zero_is_rejected_before_kmd() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);
    let a = create_account(&dd, "alice");

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "multisig",
            "new",
            "-T",
            "0",
            &a,
            "--password",
            "pw",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("multisig new");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "threshold=0 must fail");
    assert!(
        stderr.contains("Threshold must be greater than zero"),
        "stderr must explain zero-threshold; got {stderr:?}",
    );
}

#[test]
fn multisig_new_threshold_exceeds_addresses_is_rejected() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);
    let a = create_account(&dd, "alice");
    let b = create_account(&dd, "bob");

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "multisig",
            "new",
            "-T",
            "5",
            &a,
            &b,
            "--password",
            "pw",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("multisig new");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("Threshold (5) cannot exceed"),
        "stderr must explain threshold > N; got {stderr:?}",
    );
}

#[test]
fn multisig_new_bad_component_address_is_rejected_before_kmd() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);
    let a = create_account(&dd, "alice");

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "multisig",
            "new",
            "-T",
            "1",
            &a,
            "BADADDRESS",
            "--password",
            "pw",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("multisig new");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "bad component address must fail");
    assert!(
        stderr.contains("Could not parse address 'BADADDRESS'"),
        "stderr must explain bad address; got {stderr:?}",
    );
}
