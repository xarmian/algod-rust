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

//! go's `goal account -f/--default <name>` and `goal wallet -f/--default
//! <name>` set the default account / wallet kept in the data dir's
//! `accountList.json` (`cmd/goal/account.go` `accountCmd`,
//! `cmd/goal/wallet.go` `walletCmd`), and `goal account import` takes `-m`
//! for `--mnemonic` (issue #2448). Extra arguments to `account` / `wallet`
//! and a `-f` placed before a subcommand fail with cobra's error and usage
//! text (issue #2453).
//!
//! `fixtures/default_flags.jsonl` holds what go v5.0.5-stable's `goal`
//! printed (exit code, stdout, stderr) and the `accountList.json` it left, for
//! one fixed sequence of calls against a kmd-rust (the wallet password typed
//! into a pty). goal-rust must produce the same rows (a default test, no go
//! needed); a `MIXED_CLUSTER=1` run re-checks the file against a real go
//! `goal` (`GOAL_GO` names a prebuilt one), and `REGEN_DEFAULT_FLAGS_FIXTURE=1`
//! rewrites it from go:
//!
//! ```bash
//! MIXED_CLUSTER=1 REGEN_DEFAULT_FLAGS_FIXTURE=1 cargo test -p goal-rust \
//!   --test default_flags_e2e default_flags_fixture_matches_go_goal
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

const FIXTURE: &str = "tests/fixtures/default_flags.jsonl";

/// The all-zero seed's mnemonic.
const ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest";

const GENESIS: &str = r#"{"id":"v1","network":"testnet","proto":"future","alloc":[],"rwd":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I","fees":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I"}"#;

const PROMPT: &str = "Please enter the password for wallet 'w': ";

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

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// What differs from run to run, replaced by a fixed label in every row.
struct Masks(Vec<(String, &'static str)>);

impl Masks {
    fn apply(&self, s: &str) -> String {
        let mut s = s.to_string();
        for (from, to) in &self.0 {
            if !from.is_empty() {
                s = s.replace(from.as_str(), to);
            }
        }
        s
    }
}

/// `(name, id)` of every wallet, from goal-rust's `wallet list`.
fn wallets(dd: &Path) -> Vec<(String, String)> {
    let out = run(
        Path::new(GOAL_RUST_BIN),
        dd,
        &["wallet", "list"],
        Stdin::Null,
    );
    let mut res = Vec::new();
    let mut name = None;
    for l in text(&out.stdout).lines() {
        if let Some(n) = l.strip_prefix("Wallet:\t") {
            name = Some(n.trim_end_matches(" (default)").to_string());
        } else if let Some(id) = l.strip_prefix("ID:\t") {
            res.push((name.take().unwrap_or_default(), id.to_string()));
        }
    }
    res
}

/// A data dir with a genesis, a kmd-rust and two wallets, `w` (the default,
/// the first one) and `w2`, both with password `pw`; `w` holds the all-0x01
/// seed's account named `first` (the default account). Set up with goal-rust whichever binary
/// the rows are run with.
fn setup() -> (tempfile::TempDir, KmdGuard, Masks) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dd = tmp.path().canonicalize().unwrap();
    let kmd_dir = dd.join("kmd-v0.5");
    std::fs::create_dir_all(&kmd_dir).unwrap();
    write_kmd_config(&kmd_dir);
    std::fs::write(dd.join("genesis.json"), GENESIS).unwrap();
    let child = Command::new(kmd_rust_binary())
        .args(["serve", "--data-dir"])
        .arg(&kmd_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kmd-rust");
    let guard = KmdGuard(child);
    poll_ready(&kmd_dir).expect("ready");
    let goal = Path::new(GOAL_RUST_BIN);
    for w in ["w", "w2"] {
        let out = run(
            goal,
            &dd,
            &["wallet", "new", w, "-w", "pw", "--no-display-seed"],
            Stdin::Null,
        );
        assert_eq!(out.code, Some(0), "wallet new {w}: {}", text(&out.stderr));
    }
    // A fixed key, so the account order in the file is the same every run.
    let first = algo_consensus_crypto::key_to_mnemonic(&[1u8; 32]).expect("mnemonic");
    let out = run(
        goal,
        &dd,
        &[
            "account",
            "import",
            "first",
            "--mnemonic",
            &first,
            "-w",
            "w",
            "--password",
            "pw",
        ],
        Stdin::Null,
    );
    assert_eq!(out.code, Some(0), "account import: {}", text(&out.stderr));
    let mut masks = vec![(dd.to_str().unwrap().to_string(), "<DD>")];
    for (name, id) in wallets(&dd) {
        masks.push((
            id,
            match name.as_str() {
                "w" => "<W_ID>",
                _ => "<W2_ID>",
            },
        ));
    }
    // The setup goal-rust calls leave a wallet handle cache behind; every
    // sequence starts cold.
    let _ = std::fs::remove_dir_all(dd.join("goal.cache"));
    (tmp, guard, Masks(masks))
}

/// One row: the run's exit code, stdout and stderr, masked.
fn row(name: &str, masks: &Masks, ran: &Ran) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "code": ran.code,
        "stdout": masks.apply(&text(&ran.stdout)),
        "stderr": masks.apply(&text(&ran.stderr)),
    })
}

/// The `accountList.json` bytes, masked.
fn list_row(name: &str, dd: &Path, masks: &Masks) -> serde_json::Value {
    let path = dd.join("testnet-v1").join("accountList.json");
    let file = std::fs::read_to_string(&path).unwrap_or_else(|e| format!("<{e}>"));
    serde_json::json!({"name": name, "accountList": masks.apply(&file)})
}

/// The fixed sequence of calls through `bin`.
fn sequence(bin: &Path) -> Vec<serde_json::Value> {
    let (tmp, kmd, masks) = setup();
    let dd = tmp.path().canonicalize().unwrap();
    let go = |args: &[&str], stdin: Stdin<'_>| run(bin, &dd, args, stdin);
    let mut rows = vec![list_row("accountList after the setup", &dd, &masks)];

    rows.push(row(
        "account import -m",
        &masks,
        &go(
            &[
                "account",
                "import",
                "imported",
                "-m",
                ZERO_MNEMONIC,
                "-w",
                "w",
            ],
            Stdin::Pty {
                prompt: PROMPT,
                line: "pw",
            },
        ),
    ));
    rows.push(list_row("accountList after the import", &dd, &masks));
    rows.push(row(
        "account -f unknown name",
        &masks,
        &go(&["account", "-f", "nosuch"], Stdin::Null),
    ));
    rows.push(row(
        "account -f imported",
        &masks,
        &go(&["account", "-f", "imported"], Stdin::Null),
    ));
    rows.push(list_row("accountList after account -f", &dd, &masks));
    rows.push(row(
        "account --default first",
        &masks,
        &go(&["account", "--default", "first"], Stdin::Null),
    ));
    rows.push(list_row("accountList after account --default", &dd, &masks));
    rows.push(row(
        "wallet -f unknown name",
        &masks,
        &go(&["wallet", "-f", "nosuch"], Stdin::Null),
    ));
    rows.push(row(
        "wallet -f w2",
        &masks,
        &go(&["wallet", "-f", "w2"], Stdin::Null),
    ));
    rows.push(list_row("accountList after wallet -f", &dd, &masks));
    rows.push(row(
        "wallet --default w",
        &masks,
        &go(&["wallet", "--default", "w"], Stdin::Null),
    ));
    rows.push(list_row("accountList after wallet --default", &dd, &masks));
    // #2453: `account` and `wallet` take no positional arguments
    // (`validateNoPosArgsFn` = `cobra.NoArgs`), and their `-f/--default` is a
    // local flag, so before a subcommand it is that subcommand's flag: an
    // unknown one, or the subcommand's own `-f`. cobra prints the error and
    // the command's usage.
    for args in [
        &["account", "-f", "imported", "extra"][..],
        &["account", "-f", "imported", "extra", "more"],
        &["account", "extra"],
        &["account", "-w", "w", "lsit"],
        &["wallet", "-f", "w2", "extra"],
        &["wallet", "extra"],
        &["account", "-f", "imported", "list"],
        &["account", "--default", "imported", "list"],
        &["account", "-fimported", "list", "--info"],
        &["account", "-w", "w", "-f", "imported", "balance"],
        &["account", "--default=imported", "multisig", "info"],
        &["account", "-f", "imported", "multisig"],
        &["account", "--default", "1000", "changeonlinestatus"],
        &["wallet", "-f", "w2", "list"],
        &["wallet", "--default=w2", "new", "w3"],
        &["wallet", "-f", "w2", "rename", "w", "w4"],
    ] {
        rows.push(row(&args.join(" "), &masks, &go(args, Stdin::Null)));
    }
    // A subcommand with its own `-f` takes it: `account -f first new` is
    // `account new -f first` (a bool `-f`, and `first` is a name in use).
    rows.push(row(
        "account -f first new",
        &masks,
        &go(&["account", "-f", "first", "new"], Stdin::Null),
    ));
    rows.push(list_row("accountList after the cobra errors", &dd, &masks));
    // kmd gone: the default account needs no kmd. (go's `wallet -f` would
    // then try to start a kmd, which is not compared here.)
    drop(kmd);
    rows.push(row(
        "account -f imported without kmd",
        &masks,
        &go(&["account", "-f", "imported"], Stdin::Null),
    ));
    rows.push(list_row("accountList at the end", &dd, &masks));
    rows
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
fn default_flags_fixture_matches_goal_rust() {
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
fn default_flags_fixture_matches_go_goal() {
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
    if std::env::var("REGEN_DEFAULT_FLAGS_FIXTURE").is_ok_and(|v| !v.is_empty() && v != "0") {
        std::fs::write(&path, text).expect("write the fixture");
        return;
    }
    let committed = std::fs::read_to_string(&path).expect("fixture file");
    assert!(
        committed == text,
        "{FIXTURE} differs from go's output: regenerate it with REGEN_DEFAULT_FLAGS_FIXTURE=1"
    );
}
