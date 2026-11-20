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

//! go's `goal` builds a `libgoal.Client` of the type each command needs
//! (`cmd/goal/commands.go` `ensureKmdClient` / `ensureAlgodClient` /
//! `ensureFullClient` / `getGoalClient`, `libgoal/libgoal.go` `Client.init`),
//! issue #2454:
//! - a `KmdClient` / `FullClient` starts kmd when it is not running
//!   (`nodecontrol/kmdControl.go` `StartKMD`: `<BIN>/kmd -d <kmddir> -t 180`,
//!   `<BIN>` the directory of the goal binary), and fails with `Cannot
//!   contact Algorand node: fork/exec <BIN>/kmd: no such file or directory`
//!   when there is none;
//! - an `AlgodClient` / `FullClient` reads the algod token before
//!   `algod.net` (`Cannot contact Algorand node: open <DD>/algod.token: ...`);
//! - every client then loads `<DD>/consensus.json`
//!   (`config.PreloadConfigurableConsensusProtocols`, go's `encoding/json`);
//! - a wallet handle built without a client first
//!   (`getWalletHandleMaybePassword`) fails with `kmd client init error: ...`.
//!
//! `fixtures/goal_client.jsonl` holds what go v5.0.5-stable's `goal` printed
//! (exit code, stdout, stderr, the data dir and the binary dir masked) and
//! the files it left in the data dir, for each command below (all of go's
//! call sites), run against a data dir holding a genesis but no node:
//! - with no kmd next to the binary (a copy of it in a temporary directory,
//!   `PATH=/usr/bin:/bin`);
//! - with a kmd next to it, which the command starts (go's `kmd` for go's
//!   goal, `kmd-rust` for goal-rust; the files kmd writes, `kmd.lock` 0600,
//!   `kmd.net` / `kmd.pid` / `kmd.log` 0640, are compared too, issue #2460),
//!   then stopped;
//! - with a `consensus.json` go's decoder rejects, or accepts.
//!
//! goal-rust must produce the same rows (a default test, no go needed); a
//! `MIXED_CLUSTER=1` run re-checks the file against a real go `goal` and
//! `kmd` (`GOAL_GO` / `KMD_GO` name prebuilt ones), and
//! `REGEN_GOAL_CLIENT_FIXTURE=1` rewrites it from go:
//!
//! ```bash
//! MIXED_CLUSTER=1 REGEN_GOAL_CLIENT_FIXTURE=1 cargo test -p goal-rust \
//!   --test goal_client_e2e goal_client_fixture_matches_go_goal
//! ```
//!
//! CI runs the check in `.github/workflows/teal-corpus-drivers.yml`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

mod common;
use common::pty::{run_env, Stdin};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

const FIXTURE: &str = "tests/fixtures/goal_client.jsonl";

const GENESIS: &str = r#"{"id":"v1","network":"testnet","proto":"future","alloc":[],"rwd":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I","fees":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I"}"#;

/// An address that is in no wallet.
const ADDR: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ";

/// The all-zero seed's mnemonic.
const ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest";

/// The files the data dir holds before the command runs.
const INPUTS: [&str; 5] = ["genesis.json", "consensus.json", "p.teal", "x.txn", "d.txn"];

fn mixed_cluster_enabled() -> bool {
    matches!(std::env::var("MIXED_CLUSTER").as_deref(), Ok(v) if !v.is_empty() && v != "0")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root resolves")
}

/// `<env>` names a prebuilt Go binary; otherwise build
/// `../go-algorand/cmd/<name>`.
fn try_ensure_go_binary(env: &str, name: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var(env) {
        return Some(PathBuf::from(p));
    }
    let target_dir = workspace_root().join("target/algod-interop");
    std::fs::create_dir_all(&target_dir).expect("mkdir algod-interop");
    let bin = target_dir.join(name);
    let goalg = workspace_root().join("../go-algorand");
    if !goalg.join("cmd").join(name).exists() {
        eprintln!("Go-parity SKIPPED: ../go-algorand/cmd/{name} not found");
        return None;
    }
    match Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg(format!("./cmd/{name}"))
        .current_dir(&goalg)
        .status()
    {
        Ok(s) if s.success() => Some(bin),
        _ => {
            eprintln!("Go-parity SKIPPED: `go build ./cmd/{name}` failed");
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

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Every command, each run without kmd. Arguments that get past the flag
/// checks, so the command reaches its client.
fn cases() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        // wallet.go
        ("wallet list", vec!["wallet", "list"]),
        ("wallet new", vec!["wallet", "new", "w"]),
        ("wallet -f", vec!["wallet", "-f", "w"]),
        ("wallet rename", vec!["wallet", "rename", "a", "b"]),
        // account.go
        ("account list", vec!["account", "list"]),
        ("account new", vec!["account", "new"]),
        ("account delete", vec!["account", "delete", "-a", ADDR]),
        ("account rename", vec!["account", "rename", "a", "b"]),
        (
            "account import",
            vec!["account", "import", "--mnemonic", ZERO_MNEMONIC],
        ),
        ("account export", vec!["account", "export", "-a", ADDR]),
        ("account info", vec!["account", "info", "-a", ADDR]),
        ("account balance", vec!["account", "balance", "-a", ADDR]),
        ("account rewards", vec!["account", "rewards", "-a", ADDR]),
        ("account dump", vec!["account", "dump", "-a", ADDR]),
        ("account listpartkeys", vec!["account", "listpartkeys"]),
        ("account partkeyinfo", vec!["account", "partkeyinfo"]),
        (
            "account addpartkey",
            vec![
                "account",
                "addpartkey",
                "-a",
                ADDR,
                "--roundFirstValid",
                "1",
                "--roundLastValid",
                "2",
            ],
        ),
        (
            "account changeonlinestatus",
            vec!["account", "changeonlinestatus", "-a", ADDR],
        ),
        (
            "account marknonparticipating",
            vec!["account", "marknonparticipating", "-a", ADDR],
        ),
        (
            "account renewpartkey",
            vec!["account", "renewpartkey", "-a", ADDR, "--roundLastValid", "9"],
        ),
        (
            "account renewallpartkeys",
            vec!["account", "renewallpartkeys", "--roundLastValid", "9"],
        ),
        (
            "account installpartkey",
            vec![
                "account",
                "installpartkey",
                "--partkey",
                "p.teal",
                "--delete-input",
            ],
        ),
        (
            "account deletepartkey",
            vec!["account", "deletepartkey", "--partkeyid", "x"],
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
            "account multisig info",
            vec!["account", "multisig", "info", "-a", ADDR],
        ),
        // clerk.go, multisig.go
        (
            "clerk send",
            vec!["clerk", "send", "-f", ADDR, "-t", ADDR, "-a", "1"],
        ),
        (
            "clerk send -o",
            vec![
                "clerk", "send", "-f", ADDR, "-t", ADDR, "-a", "1", "-o", "o.txn",
            ],
        ),
        ("clerk rawsend", vec!["clerk", "rawsend", "-f", "x.txn"]),
        (
            "clerk sign",
            vec!["clerk", "sign", "-i", "x.txn", "-o", "o.txn"],
        ),
        (
            "clerk multisig sign",
            vec!["clerk", "multisig", "sign", "-t", "x.txn", "-a", ADDR],
        ),
        (
            "clerk multisig signprogram",
            vec![
                "clerk",
                "multisig",
                "signprogram",
                "-p",
                "p.teal",
                "-a",
                ADDR,
                "-A",
                ADDR,
            ],
        ),
        (
            "clerk compile -s",
            vec!["clerk", "compile", "-s", "-a", ADDR, "p.teal"],
        ),
        ("clerk simulate", vec!["clerk", "simulate", "-t", "x.txn"]),
        // A LogicSig: `getProto` without `--proto` is `ensureAlgodClient`.
        (
            "clerk sign -p",
            vec![
                "clerk", "sign", "-i", "d.txn", "-o", "o.txn", "-p", "p.teal",
            ],
        ),
        (
            "clerk sign -p --proto",
            vec![
                "clerk", "sign", "-i", "d.txn", "-o", "o.txn", "-p", "p.teal", "--proto", "future",
            ],
        ),
        // application.go
        ("app info", vec!["app", "info", "--app-id", "1"]),
        (
            "app create",
            vec![
                "app",
                "create",
                "--creator",
                ADDR,
                "--approval-prog",
                "p.teal",
                "--clear-prog",
                "p.teal",
            ],
        ),
        (
            "app call",
            vec!["app", "call", "--app-id", "1", "--from", ADDR],
        ),
        (
            "app read",
            vec!["app", "read", "--app-id", "1", "--global"],
        ),
        ("app box list", vec!["app", "box", "list", "--app-id", "1"]),
        // node.go, ledger.go, commands.go
        ("node status", vec!["node", "status"]),
        ("node lastround", vec!["node", "lastround"]),
        ("node pendingtxns", vec!["node", "pendingtxns"]),
        ("node wait", vec!["node", "wait"]),
        ("node catchup", vec!["node", "catchup", "--abort"]),
        ("ledger supply", vec!["ledger", "supply"]),
        ("ledger block", vec!["ledger", "block", "1"]),
        ("version", vec!["version"]),
    ]
}

/// The commands also run with a kmd next to the binary, which they start.
const KMD_CASES: &[&str] = &[
    "wallet list",
    "wallet -f",
    "wallet rename",
    "account list",
    "account new",
    "clerk send",
    "clerk send -o",
    "app info",
    "account info",
    "node status",
    "ledger supply",
    "ledger block",
    "version",
];

/// `consensus.json` contents go's `encoding/json` decoder rejects, or
/// accepts, each one tried with `account list` (a `DynamicClient` first).
const CONSENSUS_CASES: &[(&str, &str)] = &[
    ("empty", ""),
    ("whitespace", " \n\t "),
    ("not json", "not json"),
    ("bom", "\u{feff}{}"),
    ("truncated map", "{"),
    ("truncated key", r#"{"v"#),
    ("truncated after key", r#"{"v""#),
    ("truncated after colon", r#"{"v":"#),
    ("truncated value", r#"{"v":{"MinTxnFee":1"#),
    ("truncated number", "-"),
    ("number", "12"),
    ("top-level string", r#""str""#),
    ("top-level true", "true"),
    ("top-level null", "null"),
    ("top-level array", "[1,2]"),
    ("empty object", "{}"),
    ("missing colon", r#"{"v" {}}"#),
    ("missing comma", r#"{"v":{} "w":{}}"#),
    ("trailing comma", r#"{"v":{},}"#),
    ("bare key", "{v:1}"),
    ("bad literal", r#"{"v":tru}"#),
    ("bad null", r#"{"v":nul}"#),
    ("bad false", r#"{"v":fals}"#),
    ("bad escape", r#"{"\q":1}"#),
    ("bad unicode escape", r#"{"\u12x4":1}"#),
    ("control in string", "{\"a\tb\":1}"),
    ("bad number", r#"{"v":-}"#),
    ("bad fraction", r#"{"v":1.}"#),
    ("bad exponent", r#"{"v":1e}"#),
    ("leading zero", r#"{"v":01}"#),
    ("non-ascii", "{\"v\":\u{e9}}"),
    ("high byte", "{\"v\":\u{80}}"),
    ("nbsp", "{\"v\":\u{a0}}"),
    ("del", "{\"v\":\u{7f}}"),
    ("quote", r#"{"v":'}"#),
    ("trailing bytes", r#"{"v":{}}xyz"#),
    ("two values", "{} {"),
    ("value string", r#"{"v":"x"}"#),
    ("value number", r#"{"v":1}"#),
    ("value array", r#"{"v":[1]}"#),
    ("value true", r#"{"v":true}"#),
    ("value null", r#"{"v":null}"#),
    ("field string", r#"{"v":{"MinTxnFee":"a"}}"#),
    ("field negative", r#"{"v":{"MinTxnFee":-1}}"#),
    ("field fraction", r#"{"v":{"MinTxnFee":1.5}}"#),
    ("field exponent", r#"{"v":{"MinTxnFee":1e3}}"#),
    (
        "field overflow",
        r#"{"v":{"MinTxnFee":18446744073709551616}}"#,
    ),
    ("field bool", r#"{"v":{"MinTxnFee":true}}"#),
    ("field object", r#"{"v":{"MinTxnFee":{}}}"#),
    ("field array", r#"{"v":{"MinTxnFee":[]}}"#),
    ("field null", r#"{"v":{"MinTxnFee":null}}"#),
    ("field folded", r#"{"v":{"mintxnfee":"a"}}"#),
    ("field unknown", r#"{"v":{"Nope":"a"}}"#),
    ("bool field number", r#"{"v":{"PaymentTxnEnabled":1}}"#),
    ("bool field string", r#"{"v":{"PaymentTxnEnabled":"true"}}"#),
    ("int field", r#"{"v":{"MaxAppProgramLen":"x"}}"#),
    ("int field negative", r#"{"v":{"MaxAppProgramLen":-5}}"#),
    ("uint32 overflow", r#"{"v":{"MaxAssetDecimals":5000000000}}"#),
    ("uint32 max", r#"{"v":{"MaxAssetDecimals":4294967295,"MaxTimestampIncrement":-9}}"#),
    ("duration", r#"{"v":{"AgreementFilterTimeout":"1s"}}"#),
    ("payset commit", r#"{"v":{"PaysetCommit":"x"}}"#),
    ("micros", r#"{"v":{"PerByteTxnSurcharge":"x"}}"#),
    ("upgrades string", r#"{"v":{"ApprovedUpgrades":"x"}}"#),
    ("upgrades value", r#"{"v":{"ApprovedUpgrades":{"w":"x"}}}"#),
    ("payouts string", r#"{"v":{"Payouts":"x"}}"#),
    ("payouts field", r#"{"v":{"Payouts":{"Percent":"x"}}}"#),
    ("bonus field", r#"{"v":{"Bonus":{"BaseRound":true}}}"#),
    ("first error wins", r#"{"v":{"MinTxnFee":"a","MaxTxnLife":"b"}}"#),
    ("type error then syntax", r#"{"v":{"MinTxnFee":"a"},"w":}"#),
    ("ok", r#"{"v":{"MinTxnFee":5,"ApprovedUpgrades":{"w":0}}}"#),
];

/// The sorted list of every file and directory under `dd` but the inputs, as
/// `<path> <mode> <d|f>`.
fn files(dd: &Path) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt;
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).expect("read_dir").flatten() {
            let p = e.path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            if INPUTS.contains(&rel.as_str()) {
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

/// Stop the kmd a command started (its pid in `kmd-v0.5/kmd.pid`).
fn stop_kmd(dd: &Path) {
    let Ok(pid) = std::fs::read_to_string(dd.join("kmd-v0.5/kmd.pid")) else {
        return;
    };
    let pid = pid.trim();
    let _ = Command::new("kill").args(["-TERM", pid]).status();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let alive = Command::new("kill")
            .args(["-0", pid])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !alive {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = Command::new("kill").args(["-KILL", pid]).status();
}

/// One row: exit code, stdout, stderr and the files created; the data dir and
/// the binary dir masked.
fn row(bin_dir: &Path, name: String, args: &[&str], consensus: Option<&str>) -> serde_json::Value {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dd = tmp.path().canonicalize().unwrap();
    std::fs::write(dd.join("genesis.json"), GENESIS).unwrap();
    std::fs::write(dd.join("p.teal"), "#pragma version 8\nint 1\n").unwrap();
    std::fs::write(dd.join("x.txn"), b"\x81\xa3zzz\x01").unwrap();
    // A transaction go decodes: `{"txn": {"snd": <0x01 * 32>, "type": "pay"}}`.
    let mut txn = b"\x81\xa3txn\x82\xa3snd\xc4\x20".to_vec();
    txn.extend_from_slice(&[1u8; 32]);
    txn.extend_from_slice(b"\xa4type\xa3pay");
    std::fs::write(dd.join("d.txn"), txn).unwrap();
    if let Some(c) = consensus {
        std::fs::write(dd.join("consensus.json"), c).unwrap();
    }
    let ran = run_env(
        &bin_dir.join("goal"),
        &dd,
        args,
        Stdin::Null,
        &[("PATH", "/usr/bin:/bin")],
    );
    let files = files(&dd);
    stop_kmd(&dd);
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
        "files": files,
    })
}

/// Every row, the binary run from a copy in a fresh directory with a `PATH`
/// that holds no kmd; `kmd` is `(the kmd binary, its name next to goal)`.
fn sequence(goal: &Path, kmd: (&Path, &str)) -> Vec<serde_json::Value> {
    let bin_tmp = tempfile::tempdir().expect("tempdir");
    let bin_dir = bin_tmp.path().canonicalize().unwrap();
    std::fs::copy(goal, bin_dir.join("goal")).expect("copy the goal binary");
    let all = cases();
    let mut rows = Vec::new();
    for (name, args) in &all {
        rows.push(row(&bin_dir, name.to_string(), args, None));
    }
    for (name, consensus) in CONSENSUS_CASES {
        rows.push(row(
            &bin_dir,
            format!("consensus.json {name}"),
            &["account", "list"],
            Some(consensus),
        ));
    }
    // An `AlgodClient` fails on the algod token before it loads the file.
    rows.push(row(
        &bin_dir,
        "consensus.json not json: node status".to_string(),
        &["node", "status"],
        Some("not json"),
    ));
    std::fs::copy(kmd.0, bin_dir.join(kmd.1)).expect("copy the kmd binary");
    for name in KMD_CASES {
        let (_, args) = all
            .iter()
            .find(|(n, _)| n == name)
            .expect("a kmd case is a case");
        rows.push(row(&bin_dir, format!("with kmd: {name}"), args, None));
    }
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
fn goal_client_fixture_matches_goal_rust() {
    let want = read_fixture();
    let kmd = kmd_rust_binary();
    let got = sequence(Path::new(GOAL_RUST_BIN), (&kmd, "kmd-rust"));
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
fn goal_client_fixture_matches_go_goal() {
    if !mixed_cluster_enabled() {
        eprintln!("Go-parity SKIPPED: set MIXED_CLUSTER=1");
        return;
    }
    let Some(go_goal) = try_ensure_go_binary("GOAL_GO", "goal") else {
        return;
    };
    let Some(go_kmd) = try_ensure_go_binary("KMD_GO", "kmd") else {
        return;
    };
    let text: String = sequence(&go_goal, (&go_kmd, "kmd"))
        .iter()
        .map(|r| format!("{r}\n"))
        .collect();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    if std::env::var("REGEN_GOAL_CLIENT_FIXTURE").is_ok_and(|v| !v.is_empty() && v != "0") {
        std::fs::write(&path, text).expect("write the fixture");
        return;
    }
    let committed = std::fs::read_to_string(&path).expect("fixture file");
    let stale: Vec<String> = committed
        .lines()
        .zip(text.lines())
        .filter(|(c, g)| c != g)
        .map(|(c, g)| format!("  fixture: {c}\n  go:      {g}"))
        .collect();
    assert!(
        committed == text,
        "{FIXTURE} differs from go's output ({} vs {} rows): regenerate it with \
         REGEN_GOAL_CLIENT_FIXTURE=1\n{}",
        committed.lines().count(),
        text.lines().count(),
        stale.join("\n")
    );
}
