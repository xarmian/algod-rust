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

//! go's `goal node create` and `goal node clone` (issue #2512): both only touch
//! the local disk (`cmd/goal/node.go` `createCmd`, `nodecontrol`'s `Clone`).
//!
//! `fixtures/node_create_clone.jsonl` holds what go v5.0.5-stable's `goal`
//! printed (exit code, stdout, stderr) and the files it left (path, mode,
//! SHA-256) for one fixed sequence of calls in a scratch directory: `node
//! create` for every network and every flag, its failures, and `node clone`
//! with and without the ledger from a hand-made data directory. goal-rust must
//! produce the same rows (a default test, no go needed); a `MIXED_CLUSTER=1`
//! run re-checks the file against a real go `goal` (`GOAL_GO` names a prebuilt
//! one), and `REGEN_NODE_CREATE_CLONE_FIXTURE=1` rewrites it from go:
//!
//! ```bash
//! MIXED_CLUSTER=1 REGEN_NODE_CREATE_CLONE_FIXTURE=1 cargo test -p goal-rust \
//!   --test node_create_clone_e2e node_create_clone_fixture_matches_go_goal
//! ```

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

const FIXTURE: &str = "tests/fixtures/node_create_clone.jsonl";

/// What `genesis.ID()` of the hand-made source data dir names its ledger
/// folder after: `<network>-<id>`.
const SRC_GENESIS: &str = r#"{"id":"v1.0","network":"srcnet","proto":"future","alloc":[],"rwd":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I","fees":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I"}"#;

const LEDGER_FILES: [&str; 6] = [
    "ledger.block.sqlite",
    "ledger.block.sqlite-shm",
    "ledger.block.sqlite-wal",
    "ledger.tracker.sqlite",
    "ledger.tracker.sqlite-shm",
    "ledger.tracker.sqlite-wal",
];

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

/// `<path> <mode> <d|f> [<sha256 prefix>]` of everything under `root/rel`
/// (the thing itself first), sorted.
fn listing(root: &Path, rel: &str) -> Vec<String> {
    fn walk(root: &Path, p: &Path, out: &mut Vec<String>) {
        let Ok(meta) = std::fs::symlink_metadata(p) else {
            return;
        };
        let name = p.strip_prefix(root).unwrap().display().to_string();
        let mode = meta.permissions().mode() & 0o777;
        if meta.is_dir() {
            out.push(format!("{name} {mode:o} d"));
            let mut kids: Vec<_> = std::fs::read_dir(p)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            kids.sort();
            for k in kids {
                walk(root, &k, out);
            }
        } else {
            let sum = Sha256::digest(std::fs::read(p).unwrap());
            let hex: String = sum.iter().take(8).map(|b| format!("{b:02x}")).collect();
            out.push(format!("{name} {mode:o} f {hex}"));
        }
    }
    let mut out = Vec::new();
    walk(root, &root.join(rel), &mut out);
    out
}

/// The scratch directory of a run: a hand-made source data dir `src`.
fn setup() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o750)).unwrap();
    std::fs::write(src.join("genesis.json"), SRC_GENESIS).unwrap();
    std::fs::write(src.join("config.json"), "{\n  \"Version\": 1\n}\n").unwrap();
    std::fs::write(src.join("phonebook.json"), "{\"Include\":[]}").unwrap();
    std::fs::write(src.join("algod.token"), "secret").unwrap();
    let ledger = src.join("srcnet-v1.0");
    std::fs::create_dir(&ledger).unwrap();
    std::fs::set_permissions(&ledger, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (i, f) in LEDGER_FILES.iter().enumerate() {
        std::fs::write(ledger.join(f), format!("ledger file {i}")).unwrap();
    }
    // a data dir whose ledger is incomplete, one without a ledger folder and
    // one without a genesis.json
    let partial = tmp.path().join("partial");
    std::fs::create_dir_all(partial.join("srcnet-v1.0")).unwrap();
    std::fs::write(partial.join("genesis.json"), SRC_GENESIS).unwrap();
    std::fs::write(partial.join("srcnet-v1.0/ledger.block.sqlite"), "x").unwrap();
    let noledger = tmp.path().join("noledger");
    std::fs::create_dir(&noledger).unwrap();
    std::fs::write(noledger.join("genesis.json"), SRC_GENESIS).unwrap();
    let nogenesis = tmp.path().join("nogenesis");
    std::fs::create_dir(&nogenesis).unwrap();
    std::fs::write(nogenesis.join("config.json"), "{}").unwrap();
    let badgenesis = tmp.path().join("badgenesis");
    std::fs::create_dir(&badgenesis).unwrap();
    std::fs::write(badgenesis.join("genesis.json"), "not json").unwrap();
    // a destination that is a plain file and a target with something in it
    std::fs::write(tmp.path().join("afile"), "x").unwrap();
    std::fs::create_dir(tmp.path().join("old")).unwrap();
    std::fs::write(tmp.path().join("old/stale"), "stale").unwrap();
    tmp
}

fn sequence(bin: &Path) -> Vec<serde_json::Value> {
    let tmp = setup();
    let root = tmp.path();
    let mut rows = Vec::new();
    // go makes the data dir absolute: the scratch directory is `<TMP>`.
    let mask = |b: &[u8]| String::from_utf8_lossy(b).replace(&root.display().to_string(), "<TMP>");
    let mut step = |name: &str, args: &[&str], watch: &[&str]| {
        let mut cmd = Command::new(bin);
        cmd.args(args)
            .current_dir(root)
            .env_remove("ALGORAND_DATA")
            .env_remove("ALGORAND_DATA2");
        // SAFETY: `umask` is async-signal-safe; the same mask for both goals.
        unsafe {
            cmd.pre_exec(|| {
                libc::umask(0o022);
                Ok(())
            });
        }
        let out = cmd.output().expect("run goal");
        let files: Vec<String> = watch
            .iter()
            .filter(|w| !w.is_empty())
            .flat_map(|w| listing(root, w))
            .collect();
        rows.push(serde_json::json!({
            "name": name,
            "code": out.status.code(),
            "stdout": mask(&out.stdout),
            "stderr": mask(&out.stderr),
            "files": files,
        }));
    };

    // node create: every network, then every flag
    for net in ["mainnet", "testnet", "betanet", "devnet"] {
        let dest = format!("c-{net}");
        step(
            &format!("node create {net}"),
            &["node", "create", "--network", net, "--destination", &dest],
            &[&dest],
        );
    }
    let create: Vec<(&str, Vec<&str>, &str)> = vec![
        (
            "--archival",
            vec!["--network", "testnet", "--destination", "c1", "--archival"],
            "c1",
        ),
        (
            "-a",
            vec!["--network", "testnet", "--destination", "c2", "-a"],
            "c2",
        ),
        (
            "--archival=false",
            vec!["--network", "testnet", "--destination", "c3", "--archival=false"],
            "c3",
        ),
        (
            "--relay",
            vec!["--network", "testnet", "--destination", "c4", "--relay", "127.0.0.1:4161"],
            "c4",
        ),
        (
            "--relay ipv6",
            vec!["--network", "testnet", "--destination", "c5", "--relay", "[::1]:4161"],
            "c5",
        ),
        (
            "--relay no port",
            vec!["--network", "testnet", "--destination", "c6", "--relay", "127.0.0.1"],
            "c6",
        ),
        (
            "--relay hostname",
            vec!["--network", "testnet", "--destination", "c7", "--relay", "localhost:4161"],
            "c7",
        ),
        (
            "--relay empty port",
            vec!["--network", "testnet", "--destination", "c8", "--relay", "127.0.0.1:"],
            "c8",
        ),
        (
            "--relay empty host",
            vec!["--network", "testnet", "--destination", "c9", "--relay", ":4161"],
            "c9",
        ),
        (
            "--relay empty",
            vec!["--network", "testnet", "--destination", "c10", "--relay", ""],
            "c10",
        ),
        (
            "--api",
            vec!["--network", "testnet", "--destination", "c11", "--api", "127.0.0.1:8080"],
            "c11",
        ),
        (
            "--api bad",
            vec!["--network", "testnet", "--destination", "c12", "--api", "8080"],
            "c12",
        ),
        (
            "--api and --relay bad",
            vec![
                "--network", "testnet", "--destination", "c13", "--relay", "x", "--api", "y",
            ],
            "c13",
        ),
        (
            "--hosted",
            vec!["--network", "testnet", "--destination", "c14", "--hosted"],
            "c14",
        ),
        (
            "-H",
            vec!["--network", "testnet", "--destination", "c15", "-H"],
            "c15",
        ),
        (
            "--full-config",
            vec!["--network", "testnet", "--destination", "c16", "--full-config"],
            "c16",
        ),
        (
            "everything",
            vec![
                "--network",
                "mainnet",
                "--destination",
                "c17",
                "--archival",
                "--relay",
                "0.0.0.0:4160",
                "--api",
                "127.0.0.1:8081",
                "--hosted",
                "--full-config",
            ],
            "c17",
        ),
        (
            "relay implies archival",
            vec![
                "--network",
                "devnet",
                "--destination",
                "c18",
                "--relay",
                "127.0.0.1:4160",
                "--archival=false",
            ],
            "c18",
        ),
        (
            "nested destination",
            vec!["--network", "testnet", "--destination", "deep/er/dest"],
            "deep",
        ),
        (
            "existing directory",
            vec!["--network", "testnet", "--destination", "src"],
            "src",
        ),
        (
            "existing file",
            vec!["--network", "testnet", "--destination", "afile"],
            "afile",
        ),
        (
            "unknown network",
            vec!["--network", "nonet", "--destination", "c19"],
            "c19",
        ),
        (
            "empty network",
            vec!["--network", "", "--destination", "c20"],
            "c20",
        ),
        (
            "network is case sensitive",
            vec!["--network", "TestNet", "--destination", "c21"],
            "c21",
        ),
        (
            "unknown network and bad relay",
            vec!["--network", "nonet", "--destination", "c22", "--relay", "x"],
            "c22",
        ),
        (
            "bad relay and existing destination",
            vec!["--network", "testnet", "--destination", "src", "--relay", "x"],
            "src",
        ),
        (
            "destination under a file",
            vec!["--network", "testnet", "--destination", "afile/sub"],
            "afile",
        ),
        ("no flags", vec![], ""),
        ("no destination", vec!["--network", "testnet"], ""),
        ("no network", vec!["--destination", "c23"], "c23"),
        (
            "extra argument",
            vec!["--network", "testnet", "--destination", "c24", "extra"],
            "c24",
        ),
    ];
    for (name, args, watch) in &create {
        let mut full = vec!["node", "create"];
        full.extend(args);
        step(&format!("node create {name}"), &full, &[watch]);
    }

    // node clone
    let clone: Vec<(&str, Vec<&str>, &str)> = vec![
        ("with the ledger", vec!["-d", "src", "node", "clone", "-t", "k1"], "k1"),
        (
            "--targetdir",
            vec!["-d", "src", "node", "clone", "--targetdir", "k2"],
            "k2",
        ),
        (
            "--noledger",
            vec!["-d", "src", "node", "clone", "-t", "k3", "--noledger"],
            "k3",
        ),
        ("-n", vec!["-d", "src", "node", "clone", "-t", "k4", "-n"], "k4"),
        (
            "existing target is replaced",
            vec!["-d", "src", "node", "clone", "-t", "old"],
            "old",
        ),
        (
            "target is a file",
            vec!["-d", "src", "node", "clone", "-t", "afile"],
            "afile",
        ),
        (
            "nested target",
            vec!["-d", "src", "node", "clone", "-t", "no/such/dir"],
            "no",
        ),
        ("no target", vec!["-d", "src", "node", "clone"], ""),
        ("empty target", vec!["-d", "src", "node", "clone", "-t", ""], ""),
        (
            "target is the source",
            vec!["-d", "src", "node", "clone", "-t", "src", "-n"],
            "src",
        ),
        (
            "missing data dir",
            vec!["-d", "nope", "node", "clone", "-t", "k5"],
            "k5",
        ),
        (
            "no data dir",
            vec!["node", "clone", "-t", "k6"],
            "k6",
        ),
        (
            "incomplete ledger",
            vec!["-d", "partial", "node", "clone", "-t", "k7"],
            "k7",
        ),
        (
            "incomplete ledger --noledger",
            vec!["-d", "partial", "node", "clone", "-t", "k8", "-n"],
            "k8",
        ),
        (
            "no ledger folder",
            vec!["-d", "noledger", "node", "clone", "-t", "k9"],
            "k9",
        ),
        (
            "no genesis.json",
            vec!["-d", "nogenesis", "node", "clone", "-t", "k10"],
            "k10",
        ),
        (
            "no genesis.json --noledger",
            vec!["-d", "nogenesis", "node", "clone", "-t", "k11", "-n"],
            "k11",
        ),
        (
            "bad genesis.json",
            vec!["-d", "badgenesis", "node", "clone", "-t", "k12"],
            "k12",
        ),
        (
            "extra argument",
            vec!["-d", "src", "node", "clone", "-t", "k13", "extra"],
            "k13",
        ),
    ];
    for (name, args, watch) in &clone {
        step(&format!("node clone {name}"), args, &[watch]);
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
fn node_create_clone_fixture_matches_goal_rust() {
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
fn node_create_clone_fixture_matches_go_goal() {
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
    if std::env::var("REGEN_NODE_CREATE_CLONE_FIXTURE").is_ok_and(|v| !v.is_empty() && v != "0") {
        std::fs::write(&path, text).expect("write the fixture");
        return;
    }
    let committed = std::fs::read_to_string(&path).expect("fixture file");
    assert!(
        committed == text,
        "{FIXTURE} differs from go's output: regenerate it with REGEN_NODE_CREATE_CLONE_FIXTURE=1"
    );
}
