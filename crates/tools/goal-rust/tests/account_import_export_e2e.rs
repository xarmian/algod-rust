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

//! `goal-rust account import / export` E2E (TASK-238 / B6).
//! Round-trips a deterministic mnemonic through kmd-rust to verify
//! the algo_consensus_crypto::{mnemonic_to_key, key_to_mnemonic} path
//! is shared end-to-end (the task's prime acceptance criterion).

#![cfg(unix)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

// The algokey-rust crate's standard "all-abandon" zero-seed mnemonic.
const ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest";

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

#[test]
fn account_import_export_round_trip_mnemonic() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);

    // Import via --mnemonic (skips the stdin prompt).
    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "import",
            "imported",
            "--mnemonic",
            ZERO_MNEMONIC,
            "--password",
            "pw",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("import");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "import failed; stdout={stdout:?}, stderr={stderr:?}"
    );
    let address = stdout
        .lines()
        .find_map(|l| l.strip_prefix("Imported "))
        .expect("Imported <addr> line")
        .trim()
        .to_string();
    assert_eq!(address.len(), 58, "Algorand base32 is 58 chars: {address}");

    // Now export and assert the mnemonic round-trips.
    let exp = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "export", "-a", &address, "--password", "pw"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("export");
    let exp_stdout = String::from_utf8_lossy(&exp.stdout);
    let exp_stderr = String::from_utf8_lossy(&exp.stderr);
    assert!(
        exp.status.success(),
        "export failed; stdout={exp_stdout:?}, stderr={exp_stderr:?}"
    );
    // Format: `Exported key for account <addr>: "<mnemonic>"`.
    let prefix = format!("Exported key for account {address}: \"");
    let after = exp_stdout
        .lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .expect("Exported... line");
    let exported_mnem = after.trim_end_matches('"');
    assert_eq!(
        exported_mnem, ZERO_MNEMONIC,
        "mnemonic must round-trip: imported {ZERO_MNEMONIC:?}, got {exported_mnem:?}",
    );
}

#[test]
fn account_import_bad_mnemonic_errors_with_go_template() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);

    let out = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "import",
            "bad",
            "--mnemonic",
            "this is definitely not a real mnemonic",
            "--password",
            "pw",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("import");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "bad mnemonic must fail");
    // messages.go:187 `errorBadMnemonic = "Problem with mnemonic: %s"`
    assert!(
        stderr.contains("Problem with mnemonic:"),
        "stderr must use errorBadMnemonic template; got {stderr:?}",
    );
}

#[test]
fn account_import_stdin_prompt_path_works() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);

    // Feed mnemonic on first stdin line.
    let mut child = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "import", "fromstdin", "--password", "pw"])
        .env_remove("ALGORAND_DATA")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(ZERO_MNEMONIC.as_bytes())
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stdin-mnemonic must succeed; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("Imported "),
        "stdout must contain Imported line; got {stdout:?}",
    );
}

#[test]
fn account_export_wrong_password_surfaces_kmd_error() {
    let (_t, dd, kmd_dir) = setup_data_dir();
    let _g = spawn_kmd(&kmd_dir);
    create_default_wallet(&dd);

    // Import an account first so there's something to export.
    let import = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args([
            "account",
            "import",
            "victim",
            "--mnemonic",
            ZERO_MNEMONIC,
            "--password",
            "pw",
        ])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("import");
    let stdout = String::from_utf8_lossy(&import.stdout);
    let address = stdout
        .lines()
        .find_map(|l| l.strip_prefix("Imported "))
        .expect("Imported <addr>")
        .trim();

    // Export with wrong password should fail via kmd.
    let exp = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(&dd)
        .args(["account", "export", "-a", address, "--password", "wrong"])
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("export");
    let stderr = String::from_utf8_lossy(&exp.stderr);
    assert!(!exp.status.success(), "wrong-password export must fail");
    assert!(
        stderr.contains("Request failed:"),
        "stderr must use errorRequestFail template; got {stderr:?}",
    );
}
