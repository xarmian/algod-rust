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

//! The wallet handle token cache and the password input of go's `goal`
//! (`getWalletHandleMaybePassword`, `libgoal` `GetWalletHandleTokenCached`),
//! issue #2391, seen through `goal clerk compile -s`.
//!
//! go keeps a wallet's handle token in `<datadir>/goal.cache/walletHandles.json`
//! and reuses it without a password check, the password goal prompts for is only
//! handed to the signing call (a wrong one then fails there, with a different
//! text than a wrong one at the initialisation); the password is read from a
//! terminal only (no line from a pipe). `fixtures/clerk_wallet_token.jsonl`
//! holds what go v5.0.5-stable's `goal` printed (stdout, stderr, exit code, the
//! cache file) for one fixed sequence of calls against a kmd-rust, the
//! password typed into a real pty. goal-rust must produce the same rows (a
//! default test, no go needed); a `MIXED_CLUSTER=1` run re-checks the file
//! against a real go `goal` (`GOAL_GO` names a prebuilt one), and
//! `REGEN_WALLET_TOKEN_FIXTURE=1` rewrites it from go:
//!
//! ```bash
//! MIXED_CLUSTER=1 REGEN_WALLET_TOKEN_FIXTURE=1 cargo test -p goal-rust \
//!   --test clerk_wallet_token_e2e wallet_token_fixture_matches_go_goal
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

const FIXTURE: &str = "tests/fixtures/clerk_wallet_token.jsonl";

/// The all-zero seed's mnemonic.
const ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest";

/// An address that is in no wallet.
const UNKNOWN_ADDR: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ";

const SOURCE: &str = "#pragma version 8\nint 1\nreturn\n";

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

/// A data dir with a kmd-rust, a wallet `w` (password `pw`) holding the
/// all-zero key; set up with goal-rust whichever binary the rows are run with.
fn setup() -> (tempfile::TempDir, KmdGuard, String) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dd = tmp.path().canonicalize().unwrap();
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
    let goal = Path::new(GOAL_RUST_BIN);
    let out = run(
        goal,
        &dd,
        &["wallet", "new", "w", "-w", "pw", "--no-display-seed"],
        Stdin::Null,
    );
    assert_eq!(out.code, Some(0), "wallet new: {}", text(&out.stderr));
    let out = run(
        goal,
        &dd,
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
        Stdin::Null,
    );
    assert_eq!(out.code, Some(0), "import: {}", text(&out.stderr));
    let addr = text(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("Imported "))
        .expect("Imported <addr>")
        .trim()
        .to_string();
    std::fs::write(dd.join("p.teal"), SOURCE).unwrap();
    // The setup goal-rust calls leave a cache behind; every sequence starts cold.
    let _ = std::fs::remove_dir_all(dd.join("goal.cache"));
    (tmp, guard, addr)
}

fn wallet_id(dd: &Path) -> String {
    let out = run(
        Path::new(GOAL_RUST_BIN),
        dd,
        &["wallet", "list"],
        Stdin::Null,
    );
    text(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("ID:	"))
        .unwrap_or_default()
        .to_string()
}

/// One row: the run's exit code, stdout, stderr, and whether the output file
/// was written; the data dir and wallet id (which differ per run) masked.
fn row(name: &str, dd: &Path, wid: &str, ran: &Ran) -> serde_json::Value {
    let mask = |b: &[u8]| {
        let mut s = text(b).replace(dd.to_str().unwrap(), "<DD>");
        if !wid.is_empty() {
            s = s.replace(wid, "<WALLET_ID>");
        }
        s
    };
    let mut row = serde_json::Map::new();
    row.insert("name".into(), name.into());
    row.insert("code".into(), ran.code.into());
    row.insert("stdout".into(), mask(&ran.stdout).into());
    row.insert("stderr".into(), mask(&ran.stderr).into());
    let lsig = dd.join("o.lsig");
    row.insert("outfile".into(), lsig.exists().into());
    let _ = std::fs::remove_file(lsig);
    serde_json::Value::Object(row)
}

/// The cache file as a row: the permissions and the JSON with the token masked.
fn cache_row(name: &str, dd: &Path, wid: &str) -> serde_json::Value {
    use std::os::unix::fs::PermissionsExt;
    let path = dd.join("goal.cache").join("walletHandles.json");
    let mut row = serde_json::Map::new();
    row.insert("name".into(), name.into());
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let v: serde_json::Value = serde_json::from_str(&s).expect("cache is JSON");
            let handles = v["Handles"].as_object().expect("Handles");
            let masked: Vec<String> = handles
                .iter()
                .map(|(k, t)| {
                    let k = if k == wid { "<WALLET_ID>" } else { k };
                    format!(
                        "{k}:{}",
                        if t.as_str().is_some_and(|t| !t.is_empty()) {
                            "<TOKEN>"
                        } else {
                            ""
                        }
                    )
                })
                .collect();
            row.insert("cache".into(), masked.into());
            row.insert(
                "pretty".into(),
                (s == serde_json::to_string_pretty(&v).unwrap()).into(),
            );
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            row.insert("mode".into(), format!("{mode:o}").into());
        }
        Err(_) => {
            row.insert("cache".into(), "absent".into());
        }
    }
    serde_json::Value::Object(row)
}

/// The fixed sequence of `clerk compile -s` calls through `bin`.
fn sequence(bin: &Path) -> Vec<serde_json::Value> {
    let (tmp, _kmd, addr) = setup();
    let dd = tmp.path().canonicalize().unwrap();
    let wid = wallet_id(&dd);
    assert!(!wid.is_empty(), "wallet id");
    let mut rows = Vec::new();
    let sign = |who: &str, stdin: Stdin<'_>| {
        run(
            bin,
            &dd,
            &[
                "clerk", "compile", "-s", "-a", who, "-w", "w", "-o", "o.lsig", "p.teal",
            ],
            stdin,
        )
    };
    let typed = |line: &'static str| Stdin::Pty {
        prompt: PROMPT,
        line,
    };

    // Cold cache: the wallet is initialised with the password at once.
    rows.push(row(
        "cold stdin is a pipe",
        &dd,
        &wid,
        &sign(&addr, Stdin::Pipe("pw\n")),
    ));
    rows.push(row(
        "cold stdin is /dev/null",
        &dd,
        &wid,
        &sign(&addr, Stdin::Null),
    ));
    rows.push(cache_row("cache after the failed reads", &dd, &wid));
    rows.push(row(
        "cold wrong password",
        &dd,
        &wid,
        &sign(&addr, typed("bad")),
    ));
    rows.push(cache_row("cache after the wrong password", &dd, &wid));
    rows.push(row(
        "cold unknown account",
        &dd,
        &wid,
        &sign(UNKNOWN_ADDR, typed("pw")),
    ));
    rows.push(cache_row("cache after the first token", &dd, &wid));

    // A cached token: no password check at the initialisation, the typed
    // password reaches only the signing call.
    rows.push(row("cached success", &dd, &wid, &sign(&addr, typed("pw"))));
    rows.push(row(
        "cached wrong password",
        &dd,
        &wid,
        &sign(&addr, typed("bad")),
    ));
    rows.push(row(
        "cached unknown account",
        &dd,
        &wid,
        &sign(UNKNOWN_ADDR, typed("pw")),
    ));
    rows.push(row(
        "cached stdin is a pipe",
        &dd,
        &wid,
        &sign(&addr, Stdin::Pipe("pw\n")),
    ));
    rows.push(row(
        "cached stdin is /dev/null",
        &dd,
        &wid,
        &sign(&addr, Stdin::Null),
    ));

    // A token kmd no longer knows (a stale cache) is replaced.
    std::fs::write(
        dd.join("goal.cache/walletHandles.json"),
        format!("{{\"Handles\":{{\"{wid}\":\"stale\"}}}}"),
    )
    .unwrap();
    rows.push(row(
        "stale token wrong password",
        &dd,
        &wid,
        &sign(&addr, typed("bad")),
    ));
    rows.push(row(
        "stale token success",
        &dd,
        &wid,
        &sign(&addr, typed("pw")),
    ));
    rows.push(cache_row("cache after the stale token", &dd, &wid));

    // Cache removed: cold again.
    std::fs::remove_dir_all(dd.join("goal.cache")).unwrap();
    rows.push(row("cold success", &dd, &wid, &sign(&addr, typed("pw"))));
    rows.push(cache_row("cache after the cold success", &dd, &wid));
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
fn wallet_token_fixture_matches_goal_rust() {
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
fn wallet_token_fixture_matches_go_goal() {
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
    if std::env::var("REGEN_WALLET_TOKEN_FIXTURE").is_ok_and(|v| !v.is_empty() && v != "0") {
        std::fs::write(&path, text).expect("write the fixture");
        return;
    }
    let committed = std::fs::read_to_string(&path).expect("fixture file");
    assert!(
        committed == text,
        "{FIXTURE} differs from go's output: regenerate it with REGEN_WALLET_TOKEN_FIXTURE=1"
    );
}
