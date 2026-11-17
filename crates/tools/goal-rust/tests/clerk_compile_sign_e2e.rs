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

//! `goal clerk compile -s` (issue #2388): the program is signed through kmd
//! (`SignProgramWithWallet`) and the output is the msgpack signed LogicSig, not
//! the program. Runs the `goal-rust` binary against a real `kmd-rust` (no node
//! is needed, like go's `compileCmd`).
//!
//! The expected LogicSig is go v5.0.5-stable's: the program `#pragma version 8;
//! int 1; return` signed with the all-zero seed (the "abandon ... invest"
//! mnemonic) under the `"Program"` domain,
//! `protocol.Encode(&transactions.LogicSig{Logic: prog, Sig: sig})`.

#![cfg(unix)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

/// The all-zero seed's mnemonic.
const ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest";

const SOURCE: &str = "#pragma version 8\nint 1\nreturn\n";

/// go's `protocol.Encode` of the signed LogicSig of `SOURCE`'s program.
const GO_LSIG_B64: &str = "gqFsxAQIgQFDo3NpZ8RAZKYC2baKVvMn9rJLPkysusWXTfh9lAc7RogmSOcGUHuVRRIw4AhJ7O3rAqKWeDvtmNi8PQWXfkXa5bnVW7grBA==";

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

/// A data dir with a kmd-rust and a wallet `w` (password `pw`).
fn setup() -> (tempfile::TempDir, KmdGuard) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dd = tmp.path().to_path_buf();
    let kmd_dir = dd.join("kmd-v0.5");
    std::fs::create_dir_all(&kmd_dir).unwrap();
    write_kmd_config(&kmd_dir);
    std::fs::write(
        dd.join("genesis.json"),
        r#"{"id":"v1","network":"testnet","proto":"future","alloc":[],"rwd":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I","fees":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I"}"#,
    )
    .unwrap();
    let child = Command::new(kmd_rust_binary())
        .args(["serve", "--data-dir"])
        .arg(&kmd_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kmd-rust");
    let guard = KmdGuard(child);
    poll_ready(&kmd_dir).expect("ready");
    let out = goal(
        &dd,
        &["wallet", "new", "w", "-w", "pw", "--no-display-seed"],
        "",
    );
    assert!(out.status.success(), "wallet new: {}", text(&out.stderr));
    (tmp, guard)
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// `goal-rust -d <dd> <args>`, `stdin` as the password prompt's input.
fn goal(dd: &Path, args: &[&str], stdin: &str) -> std::process::Output {
    let mut child = Command::new(GOAL_RUST_BIN)
        .arg("-d")
        .arg(dd)
        .args(args)
        .current_dir(dd)
        .env_remove("ALGORAND_DATA")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn goal-rust");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().expect("goal-rust output")
}

fn import_zero_key(dd: &Path) -> String {
    let out = goal(
        dd,
        &[
            "account",
            "import",
            "imported",
            "--mnemonic",
            ZERO_MNEMONIC,
            "--password",
            "pw",
            "-w",
            "w",
        ],
        "",
    );
    assert!(out.status.success(), "import: {}", text(&out.stderr));
    text(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("Imported "))
        .expect("Imported <addr>")
        .trim()
        .to_string()
}

#[test]
fn compile_sign_writes_the_signed_logicsig_like_go() {
    let (tmp, _kmd) = setup();
    let dd = tmp.path();
    let addr = import_zero_key(dd);
    std::fs::write(dd.join("p.teal"), SOURCE).unwrap();
    let want = base64::engine::general_purpose::STANDARD
        .decode(GO_LSIG_B64)
        .unwrap();

    // `-a <address>`: no address line (go prints it only for unsigned output).
    let out = goal(
        dd,
        &["clerk", "compile", "-s", "-a", &addr, "-w", "w", "p.teal"],
        "pw\n",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "");
    assert_eq!(std::fs::read(dd.join("p.teal.tok")).unwrap(), want);

    // The record round-trips through `-D`: the program and go's inspection.
    let out = goal(dd, &["clerk", "compile", "-D", "p.teal.tok"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "#pragma version 8\npushint 1\nreturn\nLogicSig: {\n  \"sig\": \"ZKYC2baKVvMn9rJLPkysusWXTfh9lAc7RogmSOcGUHuVRRIw4AhJ7O3rAqKWeDvtmNi8PQWXfkXa5bnVW7grBA==\"\n}\n"
    );

    // By account name, to `-o`, and to stdout.
    let out = goal(
        dd,
        &[
            "clerk", "compile", "-s", "-a", "imported", "-w", "w", "-o", "o.lsig", "p.teal",
        ],
        "pw\n",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(std::fs::read(dd.join("o.lsig")).unwrap(), want);
    let out = goal(
        dd,
        &[
            "clerk", "compile", "-s", "-a", &addr, "-w", "w", "-o", "-", "p.teal",
        ],
        "pw\n",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(out.stdout, want);

    // `-n` writes nothing.
    std::fs::remove_file(dd.join("o.lsig")).unwrap();
    let out = goal(
        dd,
        &[
            "clerk", "compile", "-s", "-n", "-a", &addr, "-w", "w", "-o", "o.lsig", "p.teal",
        ],
        "pw\n",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(!dd.join("o.lsig").exists());
}

#[test]
fn compile_sign_uses_and_announces_the_default_account() {
    let (tmp, _kmd) = setup();
    let dd = tmp.path();
    let addr = import_zero_key(dd);
    std::fs::write(dd.join("p.teal"), SOURCE).unwrap();
    std::fs::write(dd.join("q.teal"), SOURCE).unwrap();

    // The first imported account is the default one; go announces it once.
    let out = goal(
        dd,
        &["clerk", "compile", "-s", "-w", "w", "p.teal", "q.teal"],
        "pw\npw\n",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!("will use default account: {addr}\n")
    );
    let want = base64::engine::general_purpose::STANDARD
        .decode(GO_LSIG_B64)
        .unwrap();
    assert_eq!(std::fs::read(dd.join("p.teal.tok")).unwrap(), want);
    assert_eq!(std::fs::read(dd.join("q.teal.tok")).unwrap(), want);
}

#[test]
fn compile_sign_failures_match_go() {
    let (tmp, _kmd) = setup();
    let dd = tmp.path();
    std::fs::write(dd.join("p.teal"), SOURCE).unwrap();

    // No account in the wallet's list and none given.
    let out = goal(dd, &["clerk", "compile", "-s", "-w", "w", "p.teal"], "pw\n");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr),
        "no default account set. set one with 'goal account -f' or specify an account with '-a'.\n"
    );
    assert!(!dd.join("p.teal.tok").exists());

    // A key the wallet does not hold: kmd refuses; go's `errorSigningTX`.
    let out = goal(
        dd,
        &[
            "clerk",
            "compile",
            "-s",
            "-a",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
            "-w",
            "w",
            "p.teal",
        ],
        "pw\n",
    );
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(
        err.starts_with("Couldn't sign tx with kmd: ")
            && err.ends_with(" (for multisig accounts, write tx to file and sign manually)\n"),
        "{err}"
    );
    assert!(!dd.join("p.teal.tok").exists());

    // An assembly error is reported before any wallet access.
    std::fs::write(dd.join("bad.teal"), "#pragma version 8\nbogus\n").unwrap();
    let out = goal(dd, &["clerk", "compile", "-s", "-w", "w", "bad.teal"], "");
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("unknown opcode: bogus"));
}
