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

//! go's `goal` stops when the data dir's genesis ID cannot be read: every
//! `makeAccountsList` → `loadList` → `accountListFileName`
//! (`cmd/goal/accountsList.go`) exits 1 with
//! `errorGenesisIDFail` (`cmd/goal/messages.go`),
//! `Error determining kmd folder (open <dd>/genesis.json: no such file or
//! directory). Ensure the node is running in <dd>.` (issue #2436).
//!
//! Issue #2449 adds what go does around it:
//! - `accountListFileName` first builds a client (`ensureGoalClient`), whose
//!   `ensureCacheDir` creates `<dd>/goal.cache` (mode 0700) even when the
//!   genesis ID then fails, so every row records the files the command left
//!   in the data dir;
//! - the `asset` commands call `ensureFullClient` before `makeAccountsList`,
//!   so without a node they fail starting kmd (`Cannot contact Algorand node:
//!   fork/exec <BIN>/kmd: ...`, `<BIN>` being the directory of the goal
//!   binary, here a copy of it in a temporary directory without kmd), leaving
//!   `kmd-v0.5/` and its two log files behind;
//! - a malformed `genesis.json` fails with go-codec's decode error (`EOF`,
//!   `json decode error [pos N]: ...`), while the odd inputs go accepts get
//!   past the genesis ID.
//!
//! `fixtures/genesis_id_fail.jsonl` holds what go v5.0.5-stable's `goal`
//! printed (exit code, stdout, stderr, the data dir and the binary dir
//! masked) and the files it created, for the commands below, each run against
//! a data dir without a node and, unless the row gives one, without
//! `genesis.json`. goal-rust must produce the same rows (a default test, no go
//! needed); a `MIXED_CLUSTER=1` run re-checks the file against a real go
//! `goal` (`GOAL_GO` names a prebuilt one), and `REGEN_GENESIS_ID_FIXTURE=1`
//! rewrites it from go:
//!
//! ```bash
//! MIXED_CLUSTER=1 REGEN_GENESIS_ID_FIXTURE=1 cargo test -p goal-rust \
//!   --test genesis_id_fail_e2e genesis_id_fail_fixture_matches_go_goal
//! ```
//!
//! CI runs the check in `.github/workflows/teal-corpus-drivers.yml`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;
use common::pty::{run_env, Stdin};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

const FIXTURE: &str = "tests/fixtures/genesis_id_fail.jsonl";

/// An address that is in no wallet.
const ADDR: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ";

/// The all-zero seed's mnemonic.
const ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest";

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

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// The commands, each one a fresh data dir holding only `p.teal` and a
/// LogicSig file go's decoder rejects (`l.lsig`), so a goal that does not stop
/// at the genesis ID goes on to a different error.
fn cases() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("clerk send", vec!["clerk", "send", "-t", ADDR, "-a", "1"]),
        (
            "clerk send -L",
            vec!["clerk", "send", "-L", "l.lsig", "-t", ADDR, "-a", "1"],
        ),
        (
            "clerk send -f -o",
            vec![
                "clerk", "send", "-f", ADDR, "-t", ADDR, "-a", "1", "-o", "o.txn",
            ],
        ),
        // No `-s`: go never builds the accounts list, so the genesis ID is
        // not needed.
        ("clerk compile", vec!["clerk", "compile", "p.teal"]),
        (
            "clerk compile -s",
            vec!["clerk", "compile", "-s", "-a", ADDR, "p.teal"],
        ),
        // go's `accountCmd` builds the list before it looks at `-f` (#2448).
        ("account", vec!["account"]),
        ("account -f", vec!["account", "-f", "a"]),
        ("account list", vec!["account", "list"]),
        ("account new", vec!["account", "new"]),
        ("account rename", vec!["account", "rename", "a", "b"]),
        ("account delete", vec!["account", "delete", "-a", ADDR]),
        (
            "account import",
            vec!["account", "import", "--mnemonic", ZERO_MNEMONIC],
        ),
        (
            "account multisig new",
            vec!["account", "multisig", "new", ADDR, "-T", "1"],
        ),
        (
            "account multisig delete",
            vec!["account", "multisig", "delete", "-a", ADDR],
        ),
        (
            "account import -m",
            vec!["account", "import", "-m", ZERO_MNEMONIC],
        ),
        ("wallet new", vec!["wallet", "new", "w"]),
        // go's `walletCmd` builds the list before it asks kmd (#2448).
        ("wallet -f", vec!["wallet", "-f", "w"]),
        // go's `asset` commands call `ensureFullClient` (which starts kmd)
        // before `makeAccountsList` (#2449).
        (
            "asset create",
            vec!["asset", "create", "--creator", ADDR, "--total", "1"],
        ),
        (
            "asset destroy",
            vec!["asset", "destroy", "--creator", ADDR, "--assetid", "1"],
        ),
        (
            "asset config",
            vec!["asset", "config", "--manager", ADDR, "--assetid", "1"],
        ),
        (
            "asset send",
            vec![
                "asset",
                "send",
                "--to",
                ADDR,
                "--amount",
                "1",
                "--assetid",
                "1",
            ],
        ),
        (
            "asset freeze",
            vec![
                "asset",
                "freeze",
                "--freezer",
                ADDR,
                "--account",
                ADDR,
                "--freeze",
                "--assetid",
                "1",
            ],
        ),
        ("asset optin", vec!["asset", "optin", "--assetid", "1"]),
        ("asset info", vec!["asset", "info", "--assetid", "1"]),
    ]
}

/// `genesis.json` contents go's decoder rejects, or accepts although they are
/// odd, each one tried with `account -f nosuch` (which needs the genesis ID
/// and then nothing but the accounts list).
const GENESIS_CASES: &[(&str, &str)] = &[
    ("empty", ""),
    ("whitespace", " \n\t "),
    ("not json", "not json"),
    ("truncated map", "{"),
    ("truncated field", r#"{"id":"v1","network":"testnet""#),
    ("truncated string", r#"{"id":"v1"#),
    ("missing colon", r#"{"id" "v1"}"#),
    ("missing comma", r#"{"id":"v1" "network":"t"}"#),
    ("trailing comma", r#"{"id":"v1",}"#),
    ("unknown field", r#"{"id":"v1","x":1}"#),
    ("bad literal", r#"{"id":tru}"#),
    ("bad escape", r#"{"id":"\q"}"#),
    ("short unicode escape", r#"{"id":"\u12"}"#),
    ("unicode escape", r#"{"id":"\u0041\ud800x","network":"t"}"#),
    ("unicode escape too short", r#"{"id":"\u1"}"#),
    ("unicode escape at the end", r#"{"id":"\u12""#),
    ("surrogate pair", r#"{"id":"\ud83d\ude00","network":"t"}"#),
    (
        "surrogate pair bad hex",
        r#"{"id":"\ud83d\uzz00","network":"t"}"#,
    ),
    ("surrogate at the end", r#"{"id":"\ud800\u00""#),
    ("top-level string", r#""str""#),
    ("top-level number", "123"),
    ("top-level true", "true"),
    ("top-level array", r#"["v1","t"]"#),
    ("array past the fields", "[1,2,3,4,5,6,7,8,9,10]"),
    ("number as string", r#"{"id":5,"network":true}"#),
    ("null fields", r#"{"id":null,"network":"t"}"#),
    ("trailing bytes", r#"{"id":"v1","network":"t"}xyz"#),
    ("timestamp string", r#"{"timestamp":"abc"}"#),
    ("timestamp fraction", r#"{"timestamp":1.5}"#),
    (
        "timestamp overflow",
        r#"{"timestamp":99999999999999999999}"#,
    ),
    ("devmode number", r#"{"devmode":1}"#),
    ("alloc string", r#"{"alloc":"x"}"#),
    ("alloc number", r#"{"alloc":1}"#),
    ("alloc unknown field", r#"{"alloc":[{"x":1}]}"#),
    ("alloc state scalar", r#"{"alloc":[{"state":1}]}"#),
    (
        "alloc ok",
        r#"{"id":"v1","network":"t","alloc":[{"addr":"A","state":{"algo":1}}]}"#,
    ),
    ("null", "null"),
];

/// Every file and directory under `dd` but the inputs, as
/// `<path> <mode> <d|f>`, sorted.
fn files(dd: &Path) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt;
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).expect("read_dir").flatten() {
            let p = e.path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            if ["p.teal", "l.lsig", "genesis.json"].contains(&rel.as_str()) {
                continue;
            }
            let meta = std::fs::symlink_metadata(&p).expect("metadata");
            let kind = if meta.is_dir() { "d" } else { "f" };
            out.push(format!(
                "{rel} {:o} {kind}",
                meta.permissions().mode() & 0o777
            ));
            if meta.is_dir() {
                walk(root, &p, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dd, dd, &mut out);
    out.sort();
    out
}

/// One row per case: exit code, stdout, stderr and the files created; the
/// data dir and the binary dir masked. The binary runs from a copy in a fresh
/// directory (go starts `<its dir>/kmd`), with a `PATH` that holds no kmd.
fn sequence(bin: &Path) -> Vec<serde_json::Value> {
    let bin_tmp = tempfile::tempdir().expect("tempdir");
    let bin_dir = bin_tmp.path().canonicalize().unwrap();
    let bin_copy = bin_dir.join("goal");
    std::fs::copy(bin, &bin_copy).expect("copy the goal binary");
    let all = cases()
        .into_iter()
        .map(|(name, args)| (name.to_string(), None, args))
        .chain(GENESIS_CASES.iter().map(|(name, genesis)| {
            (
                format!("genesis.json {name}"),
                Some(*genesis),
                vec!["account", "-f", "nosuch"],
            )
        }));
    all.map(|(name, genesis, args)| {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dd = tmp.path().canonicalize().unwrap();
        std::fs::write(dd.join("p.teal"), "#pragma version 8\nint 1\n").unwrap();
        std::fs::write(dd.join("l.lsig"), b"\x81\xa3zzz\x01").unwrap();
        if let Some(g) = genesis {
            std::fs::write(dd.join("genesis.json"), g).unwrap();
        }
        let ran = run_env(
            &bin_copy,
            &dd,
            &args,
            Stdin::Null,
            &[("PATH", "/usr/bin:/bin")],
        );
        let mask = |b: &[u8]| {
            text(b)
                .replace(dd.to_str().unwrap(), "<DD>")
                .replace(bin_dir.to_str().unwrap(), "<BIN>")
        };
        serde_json::json!({
            "name": name,
            "code": ran.code,
            "stdout": mask(&ran.stdout),
            "stderr": mask(&ran.stderr),
            "files": files(&dd),
        })
    })
    .collect()
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
fn genesis_id_fail_fixture_matches_goal_rust() {
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
fn genesis_id_fail_fixture_matches_go_goal() {
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
    if std::env::var("REGEN_GENESIS_ID_FIXTURE").is_ok_and(|v| !v.is_empty() && v != "0") {
        std::fs::write(&path, text).expect("write the fixture");
        return;
    }
    let committed = std::fs::read_to_string(&path).expect("fixture file");
    assert!(
        committed == text,
        "{FIXTURE} differs from go's output: regenerate it with REGEN_GENESIS_ID_FIXTURE=1"
    );
}
