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

//! `goal clerk sign -L <lsig file>` decodes the LogicSig with go's strict
//! `protocol.Decode` (`lsigFromArgs`, `cmd/goal/clerk.go`), issue #2393.
//!
//! `fixtures/clerk_sign_lsig.jsonl` holds, for each record of the shared
//! `lsig_cases.rs` (at most `FIXTURE_MAX_INPUT` bytes), what go
//! v5.0.5-stable's `goal clerk sign -L` printed and wrote for a payment whose
//! sender is the program's contract account (a decode failure prints msgp's
//! error text with its context path, issue #2404; `clerk send -L` decodes
//! through the same `lsigFromArgs` and is checked against those rows too).
//! goal-rust must do the same (a
//! default test, no go needed); a `MIXED_CLUSTER=1` run re-checks the file
//! against a real go `goal` (`GOAL_GO` names a prebuilt one), and
//! `REGEN_SIGN_LSIG_FIXTURE=1` rewrites it from go:
//!
//! ```bash
//! MIXED_CLUSTER=1 REGEN_SIGN_LSIG_FIXTURE=1 cargo test -p goal-rust \
//!   --test clerk_sign_lsig_e2e sign_lsig_fixture_matches_go_goal
//! ```
//!
//! CI runs the check in `.github/workflows/teal-corpus-drivers.yml`.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256, Sha512_256};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

#[path = "../../../core/algo-codec/tests/common/lsig_cases.rs"]
mod lsig_cases;
use lsig_cases::{lsig_decode_cases, lsig_mutant_cases};

const FIXTURE: &str = "tests/fixtures/clerk_sign_lsig.jsonl";
const FIXTURE_MAX_INPUT: usize = 2048;
const FIXTURE_INLINE_OUTPUT: usize = 1024;

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

fn cases() -> Vec<(String, Vec<u8>)> {
    lsig_decode_cases()
        .into_iter()
        .chain(lsig_mutant_cases())
        .filter(|(_, b)| b.len() <= FIXTURE_MAX_INPUT)
        .collect()
}

/// msgpack of one unsigned payment `{"txn": {...}}` from `sender`.
fn payment_from(sender: [u8; 32]) -> Vec<u8> {
    use rmp::encode::{write_bin, write_map_len, write_str, write_uint};
    let mut b = Vec::new();
    write_map_len(&mut b, 1).unwrap();
    write_str(&mut b, "txn").unwrap();
    write_map_len(&mut b, 8).unwrap();
    write_str(&mut b, "amt").unwrap();
    write_uint(&mut b, 1).unwrap();
    write_str(&mut b, "fee").unwrap();
    write_uint(&mut b, 1000).unwrap();
    write_str(&mut b, "fv").unwrap();
    write_uint(&mut b, 1).unwrap();
    write_str(&mut b, "gh").unwrap();
    write_bin(&mut b, &[3u8; 32]).unwrap();
    write_str(&mut b, "lv").unwrap();
    write_uint(&mut b, 100).unwrap();
    write_str(&mut b, "rcv").unwrap();
    write_bin(&mut b, &[2u8; 32]).unwrap();
    write_str(&mut b, "snd").unwrap();
    write_bin(&mut b, &sender).unwrap();
    write_str(&mut b, "type").unwrap();
    write_str(&mut b, "pay").unwrap();
    b
}

/// The contract account of the cases' program `[8, 0x81, 1]`.
fn program_account() -> [u8; 32] {
    let mut h = Sha512_256::new();
    h.update(b"Program");
    h.update([8u8, 0x81, 1]);
    h.finalize().into()
}

type RunResult = (Option<i32>, Vec<u8>, Vec<u8>, Option<Vec<u8>>);

fn run_sign(bin: &Path, lsig: &[u8]) -> RunResult {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("l.lsig"), lsig).unwrap();
    std::fs::write(tmp.path().join("t.txn"), payment_from(program_account())).unwrap();
    let out = Command::new(bin)
        .args([
            "clerk", "sign", "-L", "l.lsig", "-i", "t.txn", "-o", "o.stxn",
        ])
        .current_dir(tmp.path())
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal");
    (
        out.status.code(),
        out.stdout,
        out.stderr,
        std::fs::read(tmp.path().join("o.stxn")).ok(),
    )
}

fn row(name: &str, input: &[u8], run: &RunResult) -> serde_json::Value {
    let mut row = serde_json::Map::new();
    row.insert("name".into(), name.into());
    row.insert("input".into(), hex::encode(input).into());
    row.insert("code".into(), run.0.into());
    for (key, bytes) in [("stdout", &run.1), ("stderr", &run.2)] {
        if bytes.is_empty() {
            continue;
        }
        match std::str::from_utf8(bytes) {
            Ok(t) if bytes.len() <= FIXTURE_INLINE_OUTPUT => {
                row.insert(key.into(), t.into());
            }
            _ if bytes.len() > FIXTURE_INLINE_OUTPUT => {
                row.insert(
                    format!("{key}_sha256"),
                    hex::encode(Sha256::digest(bytes)).into(),
                );
                row.insert(format!("{key}_len"), bytes.len().into());
            }
            _ => {
                row.insert(format!("{key}_hex"), hex::encode(bytes).into());
            }
        }
    }
    if let Some(f) = &run.3 {
        row.insert("outfile_hex".into(), hex::encode(f).into());
    }
    serde_json::Value::Object(row)
}

/// What issue #2393 is about is the decode: whether `lsigFromArgs` accepts the
/// file. Past the decode, go's `LogicSigSanityCheck` runs (its message texts, its
/// order of checks, the consensus params it uses, the PQ scheme gate) and
/// goal-rust's `algo_validate` check words and orders some of it differently
/// (follow-up #2405), so:
///
/// * a record go decodes and then rejects in the sanity check is compared as
///   "decoded" only;
/// * everything else must match exactly: go's success (the signed file
///   included) and go's decode failure, whose stderr carries msgp's error text
///   with its context path (`... at Subsigs/0 at Msig`) and goal's
///   "One or more non-printable characters" preamble (issue #2404).
fn same_outcome(want: &serde_json::Value, got: &serde_json::Value) -> bool {
    let werr = want["stderr"].as_str().unwrap_or("");
    let gerr = got["stderr"].as_str().unwrap_or("");
    if werr.contains("t.txn: txn[0] error") {
        return !gerr.contains("decode failed");
    }
    got == want
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
fn sign_lsig_fixture_matches_goal_rust() {
    let cases = cases();
    let fixture = read_fixture();
    assert_eq!(
        fixture.len(),
        cases.len(),
        "{FIXTURE} is out of date: regenerate it (see the module comment)"
    );
    let mut mismatches = Vec::new();
    for ((name, input), want) in cases.iter().zip(&fixture) {
        assert_eq!(want["name"], *name, "{FIXTURE} is out of date");
        assert_eq!(want["input"], hex::encode(input), "{name}: out of date");
        let got = row(name, input, &run_sign(Path::new(GOAL_RUST_BIN), input));
        if !same_outcome(want, &got) {
            mismatches.push(format!("{name}:\n  go:   {want}\n  rust: {got}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} records differ from go:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches.join("\n")
    );
}

/// The zero address, a valid `--to`.
const ZERO_ADDR: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ";

/// `goal clerk send -L l.lsig` with a data dir holding only a genesis: go's
/// `sendCmd` resolves the data dir and the accounts list (which locates the kmd
/// directory from the genesis), then decodes the file with the same
/// `lsigFromArgs` as `clerk sign` (clerk.go:375), before any node is contacted.
fn run_send(bin: &Path, lsig: &[u8]) -> RunResult {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("l.lsig"), lsig).unwrap();
    std::fs::create_dir(tmp.path().join("data")).unwrap();
    std::fs::write(
        tmp.path().join("data/genesis.json"),
        r#"{"id":"v1","network":"testnet","proto":"future","alloc":[],"rwd":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I","fees":"FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I"}"#,
    )
    .unwrap();
    let out = Command::new(bin)
        .args([
            "clerk", "send", "-L", "l.lsig", "-t", ZERO_ADDR, "-a", "1", "-d", "data",
        ])
        .current_dir(tmp.path())
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal");
    (out.status.code(), out.stdout, out.stderr, None)
}

/// Every fixture record go's `lsigFromArgs` fails to decode, run through
/// `clerk send -L` with `bin`: its exit code and stderr must be the fixture's.
fn send_decode_failure_mismatches(bin: &Path) -> (usize, Vec<String>) {
    let fixture = read_fixture();
    let mut checked = 0;
    let mut mismatches = Vec::new();
    for ((name, input), want) in cases().iter().zip(&fixture) {
        assert_eq!(want["name"], *name, "{FIXTURE} is out of date");
        if !want["stderr"]
            .as_str()
            .unwrap_or("")
            .contains("l.lsig: decode failed, ")
        {
            continue;
        }
        checked += 1;
        let got = row(name, input, &run_send(bin, input));
        let differs = ["code", "stdout", "stderr", "stderr_hex"]
            .iter()
            .any(|k| got[k] != want[k]);
        if differs {
            mismatches.push(format!("{name}:\n  go sign: {want}\n  send:    {got}"));
        }
    }
    (checked, mismatches)
}

#[test]
fn send_lsig_decode_failures_match_go() {
    let (checked, mismatches) = send_decode_failure_mismatches(Path::new(GOAL_RUST_BIN));
    assert!(checked > 100, "only {checked} decode-failure records");
    assert!(
        mismatches.is_empty(),
        "{} of {checked} records differ from go:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn send_lsig_decode_failures_match_go_goal() {
    if !mixed_cluster_enabled() {
        eprintln!("Go-parity SKIPPED: set MIXED_CLUSTER=1");
        return;
    }
    let Some(go_goal) = try_ensure_go_goal() else {
        return;
    };
    let (checked, mismatches) = send_decode_failure_mismatches(&go_goal);
    assert!(
        mismatches.is_empty(),
        "go's `clerk send -L` differs from its `clerk sign -L` on {} of {checked} records:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn sign_lsig_fixture_matches_go_goal() {
    if !mixed_cluster_enabled() {
        eprintln!("Go-parity SKIPPED: set MIXED_CLUSTER=1");
        return;
    }
    let Some(go_goal) = try_ensure_go_goal() else {
        return;
    };
    let text: String = cases()
        .iter()
        .map(|(name, input)| format!("{}\n", row(name, input, &run_sign(&go_goal, input))))
        .collect();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    if std::env::var("REGEN_SIGN_LSIG_FIXTURE").is_ok_and(|v| !v.is_empty() && v != "0") {
        std::fs::write(&path, text).expect("write the fixture");
        return;
    }
    let committed = std::fs::read_to_string(&path).expect("fixture file");
    assert!(
        committed == text,
        "{FIXTURE} differs from go's output: regenerate it with REGEN_SIGN_LSIG_FIXTURE=1"
    );
}
