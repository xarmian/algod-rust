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

//! The password prompts of go's `goal` outside `clerk` (issue #2407):
//! `wallet new` (`infoChoosePasswordPrompt` and `infoPasswordConfirmation`,
//! each read by `ensurePassword`), `wallet rename` (`infoPasswordPrompt` +
//! `ensurePassword` for an encrypted wallet only) and the account commands that
//! go through `getWalletHandleMaybePassword` (`account import`, `export`,
//! `delete`, `new`), plus the line reads of `wallet new` (`--recover`'s
//! mnemonic and the backup-phrase question) and cobra's `unknown flag` for the
//! password/extra flags go's `goal` does not define.
//!
//! go reads a password with `terminal.ReadPassword(stdin)` only: a pipe or
//! `/dev/null` fails with `Couldn't read password: inappropriate ioctl for
//! device`; a terminal is the one way to type it. `fixtures/wallet_password.jsonl`
//! holds what go v5.0.5-stable's `goal` printed (stdout, stderr, exit code) for
//! one fixed sequence of calls against a kmd-rust, every path (pipe,
//! `/dev/null`, a real pty) of each command. goal-rust must produce the same
//! rows (a default test, no go needed); a `MIXED_CLUSTER=1` run re-checks the
//! file against a real go `goal` (`GOAL_GO` names a prebuilt one), and
//! `REGEN_WALLET_PASSWORD_FIXTURE=1` rewrites it from go:
//!
//! ```bash
//! MIXED_CLUSTER=1 REGEN_WALLET_PASSWORD_FIXTURE=1 cargo test -p goal-rust \
//!   --test wallet_password_e2e wallet_password_fixture_matches_go_goal
//! ```
//!
//! CI runs the check in `.github/workflows/teal-corpus-drivers.yml`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::pty::{run, Ran, Stdin};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

const FIXTURE: &str = "tests/fixtures/wallet_password.jsonl";

/// The all-zero seed's mnemonic.
const ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest";

/// The all-zero seed's address.
const ZERO_ADDR: &str = "HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI";

const CONFIRM: &str = "Please confirm the password: ";
const BACKUP: &str = "Would you like to see it now? (Y/n): ";
const RECOVERY: &str = "hit return when you are done: ";

fn mixed_cluster_enabled() -> bool {
    matches!(std::env::var("MIXED_CLUSTER").as_deref(), Ok(v) if !v.is_empty() && v != "0")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root resolves")
}

/// `GOAL_GO` names a prebuilt Go `goal`; otherwise build `../go-algorand/cmd/goal`.
fn try_ensure_go_goal() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("GOAL_GO") {
        return Some(PathBuf::from(p));
    }
    let target_dir = workspace_root().join("target/algod-interop");
    std::fs::create_dir_all(&target_dir).expect("mkdir algod-interop");
    let bin = target_dir.join("goal");
    let goalg = workspace_root().join("../go-algorand");
    if !goalg.join("cmd/goal").exists() {
        eprintln!("Go-parity SKIPPED: ../go-algorand/cmd/goal not found");
        return None;
    }
    match Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg("./cmd/goal")
        .current_dir(&goalg)
        .status()
    {
        Ok(s) if s.success() => Some(bin),
        _ => {
            eprintln!("Go-parity SKIPPED: `go build ./cmd/goal` failed");
            None
        }
    }
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
        let p = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("target"))
            .join(c);
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
        "session_lifetime_secs": 600,
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

struct KmdGuard(Child);
impl Drop for KmdGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A data dir with a kmd-rust and no wallet.
fn setup() -> (tempfile::TempDir, KmdGuard) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dd = tmp.path().canonicalize().unwrap();
    let kmd_dir = dd.join("kmd-v0.5");
    std::fs::create_dir_all(&kmd_dir).unwrap();
    // The genesis directory go's accounts list (accountList.json) is kept in.
    std::fs::create_dir_all(dd.join("testnet-v1")).unwrap();
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
    (tmp, guard)
}

/// `s` with every run of exactly `len` characters of `class` replaced by `tag`.
fn mask_runs(s: &str, len: usize, class: impl Fn(char) -> bool, tag: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if class(chars[i]) {
            let start = i;
            while i < chars.len() && class(chars[i]) {
                i += 1;
            }
            if i - start == len {
                out.push_str(tag);
            } else {
                out.extend(&chars[start..i]);
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// One row: the run's exit code, stdout and stderr; the data dir, the wallet
/// IDs and the addresses of new accounts (which differ per run) masked.
fn row(name: &str, dd: &Path, ran: &Ran) -> serde_json::Value {
    let mask = |b: &[u8]| {
        let s = String::from_utf8_lossy(b).replace(dd.to_str().unwrap(), "<DD>");
        let s = mask_runs(
            &s,
            32,
            |c| c.is_ascii_digit() || ('a'..='f').contains(&c),
            "<WALLET_ID>",
        );
        let s = s.replace(ZERO_ADDR, "<ZERO_ADDR>");
        mask_runs(
            &s,
            58,
            |c| c.is_ascii_uppercase() || ('2'..='7').contains(&c),
            "<ADDR>",
        )
    };
    let mut row = serde_json::Map::new();
    row.insert("name".into(), name.into());
    row.insert("code".into(), ran.code.into());
    row.insert("stdout".into(), mask(&ran.stdout).into());
    row.insert("stderr".into(), mask(&ran.stderr).into());
    serde_json::Value::Object(row)
}

fn choose(wallet: &str) -> String {
    format!("Please choose a password for wallet '{wallet}': ")
}

fn enter(wallet: &str) -> String {
    format!("Please enter the password for wallet '{wallet}': ")
}

/// The fixed sequence of calls through `bin`.
fn sequence(bin: &Path) -> Vec<serde_json::Value> {
    let (tmp, _kmd) = setup();
    let dd = tmp.path().canonicalize().unwrap();
    let rows = std::cell::RefCell::new(Vec::new());
    let step_ran = |name: &str, ran: &Ran| rows.borrow_mut().push(row(name, &dd, ran));
    let step = |name: &str, args: &[&str], stdin: Stdin<'_>| {
        step_ran(name, &run(bin, &dd, args, stdin));
    };
    let (c_w1, c_r1, e_w1, e_r1) = (choose("w1"), choose("r1"), enter("w1"), enter("r1"));

    // `wallet new`: both passwords from the terminal only.
    let new_w1 = ["wallet", "new", "w1"];
    step(
        "wallet new stdin is a pipe",
        &new_w1,
        Stdin::Pipe("pw\npw\nn\n"),
    );
    step("wallet new stdin is /dev/null", &new_w1, Stdin::Null);
    step(
        "wallet new confirmation differs",
        &new_w1,
        Stdin::PtyAnswers(&[(&c_w1, "pw"), (CONFIRM, "other")]),
    );
    step(
        "wallet new pty, backup phrase declined",
        &new_w1,
        Stdin::PtyAnswers(&[(&c_w1, "pw"), (CONFIRM, "pw"), (BACKUP, "n")]),
    );
    step(
        "wallet new unencrypted, backup answer on a pipe",
        &["wallet", "new", "u1", "--unencrypted"],
        Stdin::Pipe("n\n"),
    );
    step(
        "wallet new unencrypted, backup answer on /dev/null",
        &["wallet", "new", "u2", "--unencrypted"],
        Stdin::Null,
    );
    step(
        "wallet new unencrypted --no-display-seed /dev/null",
        &["wallet", "new", "u3", "--unencrypted", "--no-display-seed"],
        Stdin::Null,
    );
    let new_r1 = ["wallet", "new", "r1", "--recover"];
    step(
        "wallet new --recover mnemonic on /dev/null",
        &new_r1,
        Stdin::Null,
    );
    step(
        "wallet new --recover mnemonic without a newline",
        &new_r1,
        Stdin::Pipe(ZERO_MNEMONIC),
    );
    let piped = format!("{ZERO_MNEMONIC}\npw\npw\n");
    step(
        "wallet new --recover stdin is a pipe",
        &new_r1,
        Stdin::Pipe(&piped),
    );
    step(
        "wallet new --recover pty",
        &new_r1,
        Stdin::PtyAnswers(&[(RECOVERY, ZERO_MNEMONIC), (&c_r1, "pw"), (CONFIRM, "pw")]),
    );

    // `wallet rename`: the password of an encrypted wallet from the terminal.
    let rename_w1 = ["wallet", "rename", "w1", "w1b"];
    step(
        "wallet rename stdin is a pipe",
        &rename_w1,
        Stdin::Pipe("pw\n"),
    );
    step("wallet rename stdin is /dev/null", &rename_w1, Stdin::Null);
    step(
        "wallet rename wrong password",
        &rename_w1,
        Stdin::Pty {
            prompt: &e_w1,
            line: "bad",
        },
    );
    step(
        "wallet rename pty",
        &rename_w1,
        Stdin::Pty {
            prompt: &e_w1,
            line: "pw",
        },
    );
    step(
        "wallet rename unencrypted /dev/null",
        &["wallet", "rename", "u1", "u1b"],
        Stdin::Null,
    );

    // The account commands: getWalletHandleMaybePassword, cold cache first.
    let _ = std::fs::remove_dir_all(dd.join("goal.cache"));
    let import = ["account", "import", "imp", "-m", ZERO_MNEMONIC, "-w", "r1"];
    step(
        "account import cold stdin is a pipe",
        &import,
        Stdin::Pipe("pw\n"),
    );
    step(
        "account import cold stdin is /dev/null",
        &import,
        Stdin::Null,
    );
    step(
        "account import cold wrong password",
        &import,
        Stdin::Pty {
            prompt: &e_r1,
            line: "bad",
        },
    );
    step(
        "account import cold pty",
        &import,
        Stdin::Pty {
            prompt: &e_r1,
            line: "pw",
        },
    );
    let export = ["account", "export", "-a", ZERO_ADDR, "-w", "r1"];
    step(
        "account export cached stdin is a pipe",
        &export,
        Stdin::Pipe("pw\n"),
    );
    step(
        "account export cached stdin is /dev/null",
        &export,
        Stdin::Null,
    );
    step(
        "account export cached wrong password",
        &export,
        Stdin::Pty {
            prompt: &e_r1,
            line: "bad",
        },
    );
    step(
        "account export cached pty",
        &export,
        Stdin::Pty {
            prompt: &e_r1,
            line: "pw",
        },
    );
    step(
        "account new cached encrypted wallet /dev/null",
        &["account", "new", "-w", "r1"],
        Stdin::Null,
    );
    step(
        "account new unencrypted wallet /dev/null",
        &["account", "new", "-w", "u1b"],
        Stdin::Null,
    );
    let delete = ["account", "delete", "-a", ZERO_ADDR, "-w", "r1"];
    step(
        "account delete cached stdin is /dev/null",
        &delete,
        Stdin::Null,
    );
    step(
        "account delete cached pty",
        &delete,
        Stdin::Pty {
            prompt: &e_r1,
            line: "pw",
        },
    );
    // kmd lists the wallets in the order of their (random) IDs: the blocks
    // sorted by name.
    let mut listed = run(bin, &dd, &["wallet", "list"], Stdin::Null);
    let sep = format!("{}\n", "#".repeat(50));
    let text = String::from_utf8_lossy(&listed.stdout).into_owned();
    let mut blocks: Vec<&str> = text.split(&sep).filter(|b| !b.is_empty()).collect();
    blocks.sort_unstable();
    listed.stdout = blocks
        .iter()
        .map(|b| format!("{sep}{b}"))
        .chain([sep.clone()])
        .collect::<String>()
        .into_bytes();
    step_ran("wallet list, blocks sorted", &listed);

    // Flags goal does not define.
    for args in [
        &["wallet", "new", "x", "-w", "pw"][..],
        &["wallet", "new", "x", "--password", "pw"],
        &["wallet", "new", "x", "--driver", "sqlite"],
        &["wallet", "rename", "a", "b", "-w", "pw"],
        &["wallet", "rename", "a", "b", "--password", "pw"],
        &["account", "new", "--password", "pw"],
        &["account", "list", "--password", "pw"],
        &["account", "export", "-a", ZERO_ADDR, "--password", "pw"],
        &["account", "import", "-m", "m", "--password", "pw"],
        &[
            "account",
            "changeonlinestatus",
            "-a",
            ZERO_ADDR,
            "--offline",
        ],
        &[
            "account",
            "renewpartkey",
            "-a",
            ZERO_ADDR,
            "--roundLastValid",
            "5",
            "--register",
        ],
        &[
            "account",
            "renewallpartkeys",
            "--roundLastValid",
            "5",
            "--register",
        ],
    ] {
        step(&args.join(" "), args, Stdin::Null);
    }
    rows.into_inner()
}

fn read_fixture() -> Vec<serde_json::Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .map(|l| serde_json::from_str(l).expect("fixture row is JSON"))
        .collect()
}

#[test]
fn wallet_password_fixture_matches_goal_rust() {
    let want = read_fixture();
    let got = sequence(Path::new(GOAL_RUST_BIN));
    assert_eq!(got.len(), want.len(), "{FIXTURE} is out of date");
    let mismatches: Vec<String> = want
        .iter()
        .zip(&got)
        .filter(|(w, g)| w != g)
        .map(|(w, g)| format!("{}:\n  go:   {w}\n  rust: {g}", w["name"]))
        .collect();
    assert!(
        mismatches.is_empty(),
        "{} of {} rows differ from go:\n{}",
        mismatches.len(),
        want.len(),
        mismatches.join("\n")
    );
}

#[test]
fn wallet_password_fixture_matches_go_goal() {
    if !mixed_cluster_enabled() {
        eprintln!("Go-parity SKIPPED: set MIXED_CLUSTER=1");
        return;
    }
    let Some(go_goal) = try_ensure_go_goal() else {
        return;
    };
    let text: String = sequence(&go_goal)
        .iter()
        .map(|r| format!("{r}\n"))
        .collect();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    if std::env::var("REGEN_WALLET_PASSWORD_FIXTURE").is_ok_and(|v| !v.is_empty() && v != "0") {
        std::fs::write(&path, text).expect("write the fixture");
        return;
    }
    let committed = std::fs::read_to_string(&path).expect("fixture file");
    assert!(
        committed == text,
        "{FIXTURE} differs from go's output: regenerate it with REGEN_WALLET_PASSWORD_FIXTURE=1"
    );
}
