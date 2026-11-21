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

//! go `goal`'s cobra command-line handling (issue #2472): `--help` / `-h`,
//! unknown flags, missing and bad flag values, `Args` errors and required
//! flags, for every command of the trees goal-rust's `cobra_compat` parses.
//!
//! The rows come from go's own command tree, `src/cobra_tree.json`: for
//! each command its help (both spellings), an unknown long and short flag,
//! each of its flags without a value and with a value its type rejects, too
//! many or too few positional arguments for its `Args` rule, and none of
//! its required flags, plus a few hand-picked lines. None of them gets as
//! far as running the command. `fixtures/cobra_cli.jsonl` holds what go
//! v5.0.5-stable's `goal` printed for each (exit code, stdout, stderr; a
//! usage or help text exactly as the tree holds it is named, not repeated);
//! goal-rust must print the same (a default test, no go needed). A
//! `MIXED_CLUSTER=1` run re-checks the file against a real go `goal`
//! (`GOAL_GO` names a prebuilt one), and `REGEN_COBRA_CLI_FIXTURE=1`
//! rewrites it from go:
//!
//! ```bash
//! MIXED_CLUSTER=1 REGEN_COBRA_CLI_FIXTURE=1 cargo test -p goal-rust \
//!   --test cobra_cli_e2e cobra_cli_fixture_matches_go_goal
//! ```
//!
//! `cobra_tree_matches_go` (also `MIXED_CLUSTER=1`) checks the tree itself
//! against `tools/goal-cobra-oracle` run in `../go-algorand` (`GO_ALGORAND`
//! names another checkout); `REGEN_COBRA_TREE=1` rewrites it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

const FIXTURE: &str = "tests/fixtures/cobra_cli.jsonl";

const TREE: &str = include_str!("../src/cobra_tree.json");

fn mixed_cluster_enabled() -> bool {
    matches!(std::env::var("MIXED_CLUSTER").as_deref(), Ok(v) if !v.is_empty() && v != "0")
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| !v.is_empty() && v != "0")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root resolves")
}

fn go_algorand() -> PathBuf {
    std::env::var_os("GO_ALGORAND")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("../go-algorand"))
}

/// `GOAL_GO` names a prebuilt Go `goal`; otherwise build `../go-algorand/cmd/goal`.
fn try_ensure_go_goal() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("GOAL_GO") {
        return Some(PathBuf::from(p));
    }
    let target_dir = workspace_root().join("target/algod-interop");
    std::fs::create_dir_all(&target_dir).expect("mkdir algod-interop");
    let bin = target_dir.join("goal");
    let goalg = go_algorand();
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

fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or_default().to_string()
}

/// Every command line of the rows, from go's tree.
fn command_lines() -> Vec<Vec<String>> {
    let tree: Value = serde_json::from_str(TREE).expect("cobra_tree.json");
    let cmds = tree["commands"].as_array().expect("commands");
    let by_path: BTreeMap<String, &Value> = cmds.iter().map(|c| (s(c, "path"), c)).collect();
    let mut lines: Vec<Vec<String>> = Vec::new();
    for c in cmds {
        let path = s(c, "path");
        let words: Vec<String> = path
            .split(' ')
            .filter(|w| !w.is_empty())
            .map(str::to_string)
            .collect();
        let line = |extra: &[&str]| -> Vec<String> {
            let mut v = words.clone();
            v.extend(extra.iter().map(|e| e.to_string()));
            v
        };
        lines.push(line(&["--help"]));
        lines.push(line(&["-h"]));
        lines.push(line(&["--nosuchflag"]));
        lines.push(line(&["-%"]));
        // The command's own flags; an inherited one where it is declared
        // (the root's at the top of each tree).
        let mut flags: Vec<&Value> = c["local"].as_array().unwrap().iter().collect();
        flags.extend(c["persistent"].as_array().unwrap());
        if !path.is_empty() && !path.contains(' ') {
            flags.extend(by_path[""]["persistent"].as_array().unwrap());
        }
        for f in flags {
            let long = format!("--{}", s(f, "name"));
            let short = s(f, "shorthand");
            if s(f, "no_opt_def_val").is_empty() {
                lines.push(line(&[&long]));
                if !short.is_empty() {
                    lines.push(line(&[&format!("-{short}")]));
                }
            }
            let bad: &[&str] = match s(f, "type").as_str() {
                "bool" => &["maybe", ""],
                "uint64" => &["x", "-1", "18446744073709551616", "1__0"],
                "uint32" => &["x", "4294967296"],
                "uint8" => &["x", "256"],
                "int" => &["x", "9223372036854775808", "-9223372036854775809"],
                "stringSlice" => &["a\"b", "\"a", "x,\"a\"b", "\n"],
                _ => &[],
            };
            for (i, b) in bad.iter().enumerate() {
                lines.push(line(&[&format!("{long}={b}")]));
                // (A bool shorthand takes no value: `-s maybe` would run.)
                if i == 0 && !short.is_empty() && s(f, "type") != "bool" {
                    lines.push(line(&[&format!("-{short}"), b]));
                }
            }
        }
        // The `Args` rule: every count from 0 to 3 it rejects.
        if let Some(probe) = c["args_probe"].as_array() {
            for (n, p) in probe.iter().enumerate().take(4) {
                if !p.is_null() {
                    let args: Vec<String> = (1..=n).map(|i| format!("a{i}")).collect();
                    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                    lines.push(line(&refs));
                }
            }
        }
        // No required flag set (when it has any).
        let required = c["local"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["required"].as_bool() == Some(true));
        if required {
            lines.push(line(&[]));
        }
    }
    for l in [
        // A tree's group flags before and after its subcommand, combined
        // shorthands, the help flag's place, `--` and `=` forms.
        &["clerk", "-w", "w", "send", "--nosuch"][..],
        &["clerk", "-w"],
        &["-d", "x", "clerk", "-z", "send"],
        &["clerk", "-h", "send"],
        &["clerk", "send", "-h", "-z"],
        &["clerk", "send", "-a", "1", "-h", "extra"],
        &["clerk", "send", "-a", "1", "-t", "T", "extra"],
        &["clerk", "send", "-sN", "-a", "x"],
        &["clerk", "send", "-sz"],
        &["clerk", "send", "-a=x"],
        &["clerk", "send", "-ax"],
        &["clerk", "send", "--amount=1", "--to=T", "--", "extra"],
        &["clerk", "send", "---a"],
        &["clerk", "send", "--=a"],
        &["clerk", "multisig", "-z", "sign"],
        &["clerk", "multisig", "sign", "-a", "A"],
        &["clerk", "split", "-i", "x", "extra", "more"],
        &["clerk", "tealsign", "--set-lsig-arg-idx", "x"],
        &[
            "clerk",
            "simulate",
            "--extra-opcode-budget",
            "0x8000000000000000",
        ],
        &["clerk", "compile", "-o"],
        &["clerk", "compile", "-D", "-sz"],
        &["clerk", "sign", "--argb64", "a,\"b\nc"],
        &["clerk", "send", "--argb64", "\"a\nb"],
        &["app", "-w", "w", "call", "--nosuch"],
        &["app", "--app-arg", "x", "box", "info", "-z"],
        &["app", "box", "--app-id", "x", "list"],
        &["app", "box", "list", "--app-id=0x_1", "extra"],
        &["app", "read", "--local", "--nosuch"],
        &["app", "read", "--local=x"],
        &["app", "call", "--foreign-app", "a\"b"],
        &["app", "method", "--arg", "x", "--nosuch"],
        &["app", "create", "--extra-pages", "-1"],
        &["asset", "-w"],
        &["asset", "send", "-a", "x"],
        &["asset", "create", "--decimals", "4294967296"],
        &["node", "wait", "-w", "x"],
        &["node", "catchup", "1#AAAA", "2#AAAA"],
        &["node", "catchup", "x", "y"],
        &["node", "catchup", "1#AAAA", "-z"],
        &["node", "status", "-w", "1", "extra"],
        &["ledger", "block"],
        &["ledger", "block", "1", "2"],
        &["ledger", "-z", "supply"],
        // The root, cobra's help command and goal's `helptest`.
        &[],
        &["extra"],
        &["lsit", "-d", "x"],
        &["-d", "x", "extra", "-k", "y"],
        &["-h", "clerk"],
        &["--help=x"],
        &["-v=maybe"],
        &["-vz"],
        &["--", "clerk"],
        &["help"],
        &["help", "clerk", "send"],
        &["help", "clerk", "nosuch"],
        &["help", "nosuch", "more"],
        &["help", "help"],
        &["-d", "x", "help", "app", "box", "list"],
        &["help", "-z"],
        &["help", "--", "-x"],
        &["helptest"],
        &["helptest", "x"],
        &["kmd", "-t", "x", "start"],
        &["network", "-r"],
        &["network", "create", "-r", "x", "--nosuch"],
        &["completion", "zsh", "extra"],
        &["version", "-v", "extra"],
        &["license", "-d"],
        // strconv.Quote of runes go does not print.
        &["x\u{200b}"],
        &["\u{2028}\u{2029}"],
        &["\u{feff}y"],
        &["\u{a0}\u{ad}\u{85}\u{3000}"],
        &["\u{e000}\u{e0001}\u{10ffff}"],
        &["é日本😀\u{301}"],
        &["account", "info", "-a", "A", "\u{7}\u{1b}\u{7f}"],
        &["clerk", "send", "--fee", "\u{200b}1"],
        &["clerk", "send", "--argb64", "\u{2028}\"x"],
    ] {
        lines.push(l.iter().map(|a| a.to_string()).collect());
    }
    lines
}

struct Ran {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Runs `bin` with `args` in an empty directory, no data dir in the
/// environment, and kills it after 20 s (a row must never run a command).
fn run(bin: &Path, dir: &Path, args: &[String]) -> Ran {
    let mut child = Command::new(bin)
        .args(args)
        .current_dir(dir)
        .env_remove("ALGORAND_DATA")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn goal");
    let start = Instant::now();
    loop {
        if child.try_wait().expect("wait").is_some() {
            break;
        }
        if start.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let out = child.wait_with_output().expect("output");
    Ran {
        code: out.status.code(),
        stdout: out.stdout,
        stderr: out.stderr,
    }
}

/// go's usage and help texts of every command (`src/cobra_tree.json`,
/// itself checked against go by `cobra_tree_matches_go`), longest first.
fn texts() -> Vec<(String, String, String)> {
    let tree: Value = serde_json::from_str(TREE).expect("cobra_tree.json");
    let mut out: Vec<(String, String, String)> = tree["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .map(|c| (s(c, "path"), s(c, "usage"), s(c, "help")))
        .collect();
    out.sort_by_key(|(_, usage, _)| std::cmp::Reverse(usage.len()));
    out
}

/// A row's output with each of go's texts (exactly as the tree holds it)
/// written as `<usage of PATH>` / `<help of PATH>`, which keeps the fixture
/// small: any other text, a usage that differs from go's included, stays
/// as it is.
fn named(out: &str, texts: &[(String, String, String)]) -> String {
    if let Some((path, _, _)) = texts.iter().find(|(_, _, help)| help == out) {
        return format!("<help of {path:?}>");
    }
    let mut out = out.to_string();
    for (path, usage, _) in texts {
        if out.contains(usage.as_str()) {
            out = out.replace(usage.as_str(), &format!("<usage of {path:?}>"));
        }
    }
    out
}

fn rows(bin: &Path) -> Vec<Value> {
    let tmp = tempfile::tempdir().expect("tempdir");
    let texts = texts();
    command_lines()
        .iter()
        .map(|args| {
            let ran = run(bin, tmp.path(), args);
            serde_json::json!({
                "args": args,
                "code": ran.code,
                "stdout": named(&String::from_utf8_lossy(&ran.stdout), &texts),
                "stderr": named(&String::from_utf8_lossy(&ran.stderr), &texts),
            })
        })
        .collect()
}

fn read_fixture() -> Vec<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .map(|l| serde_json::from_str(l).expect("fixture row is JSON"))
        .collect()
}

#[test]
fn cobra_cli_fixture_matches_goal_rust() {
    let want = read_fixture();
    let got = rows(Path::new(GOAL_RUST_BIN));
    assert_eq!(got.len(), want.len(), "{FIXTURE} is out of date");
    let mismatches: Vec<String> = want
        .iter()
        .zip(&got)
        .filter(|(w, g)| w != g)
        .map(|(w, g)| format!("{}:\n  go:   {w}\n  rust: {g}", w["args"]))
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
fn cobra_cli_fixture_matches_go_goal() {
    if !mixed_cluster_enabled() {
        eprintln!("Go-parity SKIPPED: set MIXED_CLUSTER=1");
        return;
    }
    let Some(go_goal) = try_ensure_go_goal() else {
        return;
    };
    let text: String = rows(&go_goal).iter().map(|r| format!("{r}\n")).collect();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    if env_flag("REGEN_COBRA_CLI_FIXTURE") {
        std::fs::write(&path, text).expect("write the fixture");
        return;
    }
    let committed = std::fs::read_to_string(&path).expect("fixture file");
    assert!(
        committed == text,
        "{FIXTURE} differs from go's output: regenerate it with REGEN_COBRA_CLI_FIXTURE=1"
    );
}

/// `src/cobra_tree.json` is what `tools/goal-cobra-oracle` dumps from go's
/// `cmd/goal` (built through `go test -overlay`, so the checkout is not
/// changed).
#[test]
fn cobra_tree_matches_go() {
    if !mixed_cluster_enabled() {
        eprintln!("Go-parity SKIPPED: set MIXED_CLUSTER=1");
        return;
    }
    let goalg = go_algorand();
    if !goalg.join("cmd/goal").exists() {
        eprintln!("Go-parity SKIPPED: {} has no cmd/goal", goalg.display());
        return;
    }
    let goalg = goalg.canonicalize().expect("go-algorand");
    let tmp = tempfile::tempdir().expect("tempdir");
    let oracle = workspace_root().join("tools/goal-cobra-oracle/dump_test.go");
    let overlay = tmp.path().join("overlay.json");
    std::fs::write(
        &overlay,
        serde_json::json!({"Replace": {
            goalg.join("cmd/goal/zz_cobra_dump_test.go").to_str().unwrap(): oracle.to_str().unwrap()
        }})
        .to_string(),
    )
    .expect("overlay");
    let out = tmp.path().join("cobra_tree.json");
    let status = Command::new("go")
        .args(["test", "-overlay"])
        .arg(&overlay)
        .args(["-run", "TestGoalCobraDump", "-count=1", "./cmd/goal"])
        .env("GOAL_COBRA_DUMP_OUT", &out)
        .current_dir(&goalg)
        .status()
        .expect("go test");
    assert!(status.success(), "the goal cobra-tree oracle failed");
    let dumped = std::fs::read_to_string(&out).expect("the oracle's tree");
    let committed = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cobra_tree.json");
    if env_flag("REGEN_COBRA_TREE") {
        std::fs::write(&committed, dumped).expect("write the tree");
        return;
    }
    assert!(
        dumped == TREE,
        "src/cobra_tree.json differs from go's tree: regenerate it with REGEN_COBRA_TREE=1"
    );
}
