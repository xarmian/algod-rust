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
//! `fixtures/clerk_sign_delegated_msig.jsonl` (issue #2461) holds go's
//! verdict for a correctly signed delegated multisig LogicSig, in its `msig`
//! and its `lmsig` form, under `-P` v40, v42 (the localnet's protocol) and
//! v43; the same two variables check and regenerate it.
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

/// Every record must match go exactly: go's success (the signed file
/// included), go's decode failure, whose stderr carries msgp's error text with
/// its context path (`... at Subsigs/0 at Msig`) and goal's "One or more
/// non-printable characters" preamble (issue #2404), and go's
/// `LogicSigSanityCheck` rejection (`t.txn: txn[0] error ...`: its texts, its
/// order of checks, its consensus params, the PQ scheme gate; issue #2405).
fn same_outcome(want: &serde_json::Value, got: &serde_json::Value) -> bool {
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

// ---------------------------------------------------------------------------
// Delegated multisig LogicSigs (issue #2461)
// ---------------------------------------------------------------------------

/// go's verdict for `clerk sign -L` of a correctly signed 2-of-3 delegated
/// multisig LogicSig, in its legacy `msig` form and its `lmsig` form, under
/// `-P` v40 (`LogicSigMsig`), v42 (the localnet-rust dev genesis's protocol,
/// `LogicSigLMsig` only) and v43 (current). Rows: `<form> <proto label>`.
const DELEGATED_FIXTURE: &str = "tests/fixtures/clerk_sign_delegated_msig.jsonl";

const DELEGATED_PROTOS: [(&str, &str); 3] = [
    (
        "v40",
        "https://github.com/algorandfoundation/specs/tree/236dcc18c9c507d794813ab768e467ea42d1b4d9",
    ),
    (
        "v42",
        "https://github.com/algorandfoundation/specs/tree/268b63433a907455d439995bf916f6b296018f4f",
    ),
    (
        "v43",
        "https://github.com/algorandfoundation/specs/tree/73c43b4a9699390884c51e2a9598d49e28373d10",
    ),
];

/// The delegated program, `#pragma version 8; pushint 1`.
const DELEGATED_PROGRAM: [u8; 3] = [8, 0x81, 1];

fn delegated_keys() -> Vec<ed25519_dalek::SigningKey> {
    (1u8..=3)
        .map(|i| ed25519_dalek::SigningKey::from_bytes(&[i; 32]))
        .collect()
}

/// go's `crypto.MultisigAddrGen(1, 2, pks)`.
fn delegated_msig_addr(keys: &[ed25519_dalek::SigningKey]) -> [u8; 32] {
    let mut h = Sha512_256::new();
    h.update(b"MultisigAddr");
    h.update([1u8, 2u8]);
    for k in keys {
        h.update(k.verifying_key().to_bytes());
    }
    h.finalize().into()
}

/// msgpack of `{"l": program, <field>: {subsig, thr: 2, v: 1}}` signed by the
/// first two keys: `msig` over `"Program" || program`, `lmsig` over
/// `"MsigProgram" || msig address || program` (go's `MultisigProgram`).
fn delegated_lsig(field: &str) -> Vec<u8> {
    use ed25519_dalek::Signer;
    use rmp::encode::{write_array_len, write_bin, write_map_len, write_str, write_uint};
    let keys = delegated_keys();
    let addr = delegated_msig_addr(&keys);
    let mut msg = Vec::new();
    if field == "lmsig" {
        msg.extend_from_slice(b"MsigProgram");
        msg.extend_from_slice(&addr);
    } else {
        msg.extend_from_slice(b"Program");
    }
    msg.extend_from_slice(&DELEGATED_PROGRAM);

    let mut b = Vec::new();
    write_map_len(&mut b, 2).unwrap();
    write_str(&mut b, "l").unwrap();
    write_bin(&mut b, &DELEGATED_PROGRAM).unwrap();
    write_str(&mut b, field).unwrap();
    write_map_len(&mut b, 3).unwrap();
    write_str(&mut b, "subsig").unwrap();
    write_array_len(&mut b, 3).unwrap();
    for (i, k) in keys.iter().enumerate() {
        write_map_len(&mut b, if i < 2 { 2 } else { 1 }).unwrap();
        write_str(&mut b, "pk").unwrap();
        write_bin(&mut b, &k.verifying_key().to_bytes()).unwrap();
        if i < 2 {
            write_str(&mut b, "s").unwrap();
            write_bin(&mut b, &k.sign(&msg).to_bytes()).unwrap();
        }
    }
    write_str(&mut b, "thr").unwrap();
    write_uint(&mut b, 2).unwrap();
    write_str(&mut b, "v").unwrap();
    write_uint(&mut b, 1).unwrap();
    b
}

/// `goal clerk sign -L l.lsig -i t.txn -o o.stxn -P <proto>` for a payment
/// from the multisig account the LogicSig is delegated by.
fn run_sign_delegated(bin: &Path, lsig: &[u8], proto: &str) -> RunResult {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("l.lsig"), lsig).unwrap();
    let sender = delegated_msig_addr(&delegated_keys());
    std::fs::write(tmp.path().join("t.txn"), payment_from(sender)).unwrap();
    let out = Command::new(bin)
        .args([
            "clerk", "sign", "-L", "l.lsig", "-i", "t.txn", "-o", "o.stxn", "-P", proto,
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

fn delegated_rows(bin: &Path) -> Vec<serde_json::Value> {
    let mut rows = Vec::new();
    for field in ["msig", "lmsig"] {
        let lsig = delegated_lsig(field);
        for (label, proto) in DELEGATED_PROTOS {
            let name = format!("{field} {label}");
            rows.push(row(&name, &lsig, &run_sign_delegated(bin, &lsig, proto)));
        }
    }
    rows
}

fn read_delegated_fixture() -> Vec<serde_json::Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DELEGATED_FIXTURE);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .map(|l| serde_json::from_str(l).expect("fixture row is JSON"))
        .collect()
}

/// goal-rust gives go's verdict on every delegated multisig row: the legacy
/// `msig` form is signed under v40 and rejected with go's
/// `LogicSig Msig field not supported in this consensus version` under v42
/// (the localnet's protocol) and v43, the `lmsig` form the other way round,
/// and each accepted file is go's byte for byte.
#[test]
fn sign_delegated_msig_lsig_matches_go() {
    let want = read_delegated_fixture();
    let got = delegated_rows(Path::new(GOAL_RUST_BIN));
    assert_eq!(
        want.len(),
        got.len(),
        "{DELEGATED_FIXTURE} is out of date: regenerate it (see the module comment)"
    );
    let mismatches: Vec<String> = want
        .iter()
        .zip(&got)
        .filter(|(w, g)| w != g)
        .map(|(w, g)| format!("{}:\n  go:   {w}\n  rust: {g}", w["name"]))
        .collect();
    assert!(
        mismatches.is_empty(),
        "{} of {} delegated multisig records differ from go:\n{}",
        mismatches.len(),
        want.len(),
        mismatches.join("\n")
    );
    // The verdicts the localnet e2e relies on (issue #2461): on v42 go
    // accepts only the `lmsig` form.
    let code = |name: &str| {
        want.iter()
            .find(|r| r["name"] == name)
            .unwrap_or_else(|| panic!("no {name} row"))["code"]
            .as_i64()
    };
    assert_eq!(code("msig v40"), Some(0));
    assert_eq!(code("lmsig v40"), Some(1));
    assert_eq!(code("msig v42"), Some(1));
    assert_eq!(code("lmsig v42"), Some(0));
    assert_eq!(code("msig v43"), Some(1));
    assert_eq!(code("lmsig v43"), Some(0));
}

/// `MIXED_CLUSTER=1`: the delegated fixture is go `goal`'s output
/// (`REGEN_SIGN_LSIG_FIXTURE=1` rewrites it).
#[test]
fn sign_delegated_msig_lsig_fixture_matches_go_goal() {
    if !mixed_cluster_enabled() {
        eprintln!("Go-parity SKIPPED: set MIXED_CLUSTER=1");
        return;
    }
    let Some(go_goal) = try_ensure_go_goal() else {
        return;
    };
    let text: String = delegated_rows(&go_goal)
        .iter()
        .map(|r| format!("{r}\n"))
        .collect();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DELEGATED_FIXTURE);
    if std::env::var("REGEN_SIGN_LSIG_FIXTURE").is_ok_and(|v| !v.is_empty() && v != "0") {
        std::fs::write(&path, text).expect("write the fixture");
        return;
    }
    let committed = std::fs::read_to_string(&path).expect("fixture file");
    assert!(
        committed == text,
        "{DELEGATED_FIXTURE} differs from go's output: regenerate it with REGEN_SIGN_LSIG_FIXTURE=1"
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
