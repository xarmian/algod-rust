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

//! End-to-end tests of the `teal-corpus` binary against the small committed
//! fixture corpus (`tests/fixtures/small`): a valid program, an invalid
//! program and inputs that make each side error, pinned to the expected JSONL.
//! The `expected/go.*.jsonl` files are the output of the Go driver
//! (`tools/teal-corpus`, built against the pinned go-algorand), so a pass here
//! means the Rust driver reproduces go-algorand's rows on the fixture.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const VALID_PUSHINT: &str = "231654048e28b40e1a7d043b5ebd2f998843458fba11c2bc5891bb97bfc27c0b";
const TRUNCATED: &str = "f65d31940ec0553eeda1a41574387df924e010d8acfad07b2253a9a06b5e7370";
const SRC_VALID: &str = "c33e255c1323f8168bcee5936ac3f79729e11dd92628df5747d470a1b94ad53c";
const SRC_INVALID: &str = "bad152c46a63b97f51bdf42c6b038ffcee6ece1f1aa52c0c5a8b25f19ce40b42";
const SRC_WARNING: &str = "dadd1391b887de52fc570557bcd6b89b17fd6a306afc852b98a807a68383c67a";

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/small")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("teal-corpus-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_teal-corpus"))
}

fn run_driver(op: &str, out: &Path, jobs: &str) -> Output {
    bin()
        .arg(op)
        .arg("--corpus")
        .arg(fixture())
        .arg("--out")
        .arg(out)
        .args(["--jobs", jobs])
        .output()
        .expect("spawn teal-corpus")
}

fn rows(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).expect("jsonl line"))
        .filter(|v| v.get("header").is_none())
        .collect()
}

fn row<'a>(rows: &'a [Value], sha: &str) -> &'a Value {
    rows.iter()
        .find(|r| r["sha256"] == sha)
        .unwrap_or_else(|| panic!("no row for {sha}"))
}

#[test]
fn disassemble_fixture_rows_are_pinned() {
    let out = scratch("dis").join("dis.jsonl");
    let res = run_driver("disassemble", &out, "2");
    assert_eq!(
        res.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&res.stderr)
    );
    let r = rows(&out);
    assert_eq!(r.len(), 4, "one row per fixture program");
    let sorted: Vec<&str> = r.iter().map(|v| v["sha256"].as_str().unwrap()).collect();
    assert!(
        sorted.windows(2).all(|w| w[0] < w[1]),
        "rows sorted by sha256"
    );

    let ok = row(&r, VALID_PUSHINT);
    assert_eq!(ok["ok"], true);
    assert_eq!(ok["text"], "#pragma version 8\npushint 1\n");
    assert!(ok.get("error").is_none());

    let bad = row(&r, TRUNCATED);
    assert_eq!(bad["ok"], false);
    assert!(bad["error"].as_str().is_some_and(|e| !e.is_empty()));
    assert!(bad.get("text").is_none());
}

#[test]
fn assemble_fixture_rows_are_pinned() {
    let out = scratch("asm").join("asm.jsonl");
    let res = run_driver("assemble", &out, "2");
    assert_eq!(
        res.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&res.stderr)
    );
    let r = rows(&out);
    assert_eq!(r.len(), 4);

    let ok = row(&r, SRC_VALID);
    assert_eq!(ok["ok"], true);
    assert_eq!(ok["bytecode_b64"], "CIEBQw==");
    assert!(ok["hash"].as_str().is_some_and(|h| h.len() == 58));
    assert_eq!(ok["sourcemap"]["version"], 3);
    assert_eq!(ok["sourcemap"]["sources"][0], "<body>");
    assert!(ok.get("warnings").is_none(), "empty warnings are omitted");

    let bad = row(&r, SRC_INVALID);
    assert_eq!(bad["ok"], false);
    let errs = bad["errors"].as_array().expect("errors[]");
    assert!(errs.len() >= 2, "the full ordered error list: {errs:?}");
    assert_eq!(errs[0]["line"], 3);
    assert!(errs[0]["message"].as_str().unwrap().contains("frobnicate"));
    assert!(bad.get("bytecode_b64").is_none());

    let warn = row(&r, SRC_WARNING);
    assert_eq!(warn["ok"], true);
    assert_eq!(warn["warnings"][0]["line"], 2);
    assert!(warn["warnings"][0]["message"]
        .as_str()
        .unwrap()
        .contains("autosalt"));
}

const INVALID_VERSION: &str = "8d0d8ce9b5f33f6105918d9d0adc9ec40886e14e59379bba65d935b45389a34d";

fn diff_against_go(op: &str) -> (Option<i32>, Vec<Value>) {
    let d = scratch(&format!("vsgo-{op}"));
    let out = d.join("rust.jsonl");
    let res = run_driver(op, &out, "4");
    assert_eq!(res.status.code(), Some(0));
    let go = fixture().join(format!("expected/go.{op}.jsonl"));
    assert_eq!(rows(&go).len(), rows(&out).len());
    let m = d.join("mismatches.jsonl");
    let r = bin()
        .arg("diff")
        .arg(&go)
        .arg(&out)
        .arg("--out")
        .arg(&m)
        .output()
        .unwrap();
    (r.status.code(), rows(&m))
}

/// Known assembler difference the drivers surface on the invalid fixture
/// source: go quotes the unknown opcode (`unknown opcode: frobnicate`, the
/// Rust assembler `unknown opcode: "frobnicate"`) and reports column 4 for the
/// `byte` argument error where Rust reports 0. Fixing it is #2368/#2369's job;
/// when it lands this test must tighten to an empty mismatch list. The valid
/// and warning sources must already agree on bytecode, hash, source map and
/// warnings.
#[test]
fn rust_assemble_rows_equal_the_go_driver_rows_except_the_known_invalid_source() {
    let (code, ms) = diff_against_go("assemble");
    let shas: Vec<&str> = ms.iter().map(|m| m["sha256"].as_str().unwrap()).collect();
    assert_eq!(code, Some(1));
    assert_eq!(shas, [SRC_INVALID], "{ms:?}");
    assert_eq!(ms[0]["field"], "errors");
}

/// Known disassembly differences the drivers surface on the two invalid
/// fixture programs (error text; go also accepts an unsupported version as a
/// `// unsupported version` comment). Fixing them is #2367's job; when it
/// lands this test must tighten to an empty mismatch list. Valid programs
/// must already agree.
#[test]
fn rust_disassemble_rows_equal_the_go_driver_rows_except_the_known_invalid_programs() {
    let (code, ms) = diff_against_go("disassemble");
    let shas: Vec<&str> = ms.iter().map(|m| m["sha256"].as_str().unwrap()).collect();
    assert_eq!(code, Some(1));
    assert_eq!(shas, [INVALID_VERSION, TRUNCATED], "{ms:?}");
    assert!(ms.iter().all(|m| m["field"] == "error"));
}

#[test]
fn header_names_implementation_and_operation() {
    let out = scratch("hdr").join("dis.jsonl");
    run_driver("disassemble", &out, "1");
    let first: Value = serde_json::from_str(
        std::fs::read_to_string(&out)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(first["header"]["impl"], "algod-rust");
    assert_eq!(first["header"]["operation"], "disassemble");
    assert_eq!(first["header"]["count"], 4);
    assert_eq!(first["header"]["schema"], 1);
}

#[test]
fn output_is_byte_deterministic_across_runs_and_thread_counts() {
    for op in ["disassemble", "assemble"] {
        let d = scratch(&format!("det-{op}"));
        let mut outs = Vec::new();
        for (i, jobs) in ["1", "1", "3", "16"].iter().enumerate() {
            let p = d.join(format!("{i}.jsonl"));
            assert_eq!(run_driver(op, &p, jobs).status.code(), Some(0));
            outs.push(std::fs::read(&p).unwrap());
        }
        assert!(!outs[0].is_empty());
        for o in &outs[1..] {
            assert_eq!(&outs[0], o, "{op}: output differs across runs/jobs");
        }
    }
}

#[test]
fn diff_of_a_file_against_itself_is_empty_and_exits_zero() {
    let d = scratch("selfdiff");
    let a = d.join("a.jsonl");
    run_driver("assemble", &a, "2");
    let m = d.join("mismatches.jsonl");
    let res = bin()
        .arg("diff")
        .arg(&a)
        .arg(&a)
        .arg("--out")
        .arg(&m)
        .output()
        .unwrap();
    assert_eq!(res.status.code(), Some(0));
    assert_eq!(std::fs::read(&m).unwrap().len(), 0);
}

#[test]
fn diff_reports_a_seeded_difference_and_exits_nonzero() {
    let d = scratch("seeded");
    let a = d.join("a.jsonl");
    run_driver("disassemble", &a, "2");
    let text = std::fs::read_to_string(&a).unwrap();
    let b = d.join("b.jsonl");
    std::fs::write(&b, text.replacen("pushint 1", "pushint 2", 1)).unwrap();
    let m = d.join("mismatches.jsonl");
    let res = bin()
        .arg("diff")
        .arg(&a)
        .arg(&b)
        .arg("--out")
        .arg(&m)
        .output()
        .unwrap();
    assert_eq!(res.status.code(), Some(1));
    let ms = rows(&m);
    assert_eq!(ms.len(), 1, "{ms:?}");
    assert_eq!(ms[0]["sha256"], VALID_PUSHINT);
    assert_eq!(ms[0]["operation"], "disassemble");
    assert_eq!(ms[0]["field"], "text");
    assert_eq!(ms[0]["first_diff"]["kind"], "line");
    assert_eq!(ms[0]["first_diff"]["at"], 2);
    assert_eq!(ms[0]["left"], "#pragma version 8\npushint 1\n");
    assert_eq!(ms[0]["right"], "#pragma version 8\npushint 2\n");
}

#[test]
fn diff_reports_a_row_missing_on_one_side() {
    let d = scratch("missing");
    let a = d.join("a.jsonl");
    run_driver("disassemble", &a, "2");
    let kept: Vec<String> = std::fs::read_to_string(&a)
        .unwrap()
        .lines()
        .filter(|l| !l.contains(TRUNCATED))
        .map(str::to_string)
        .collect();
    let b = d.join("b.jsonl");
    std::fs::write(&b, kept.join("\n") + "\n").unwrap();
    let m = d.join("m.jsonl");
    let res = bin()
        .arg("diff")
        .arg(&a)
        .arg(&b)
        .arg("--out")
        .arg(&m)
        .output()
        .unwrap();
    assert_eq!(res.status.code(), Some(1));
    let ms = rows(&m);
    assert_eq!(ms[0]["sha256"], TRUNCATED);
    assert_eq!(ms[0]["field"], "row");
    assert_eq!(ms[0]["right"], Value::Null);
}

#[test]
fn missing_corpus_directory_is_a_usage_error() {
    let res = bin()
        .arg("disassemble")
        .args(["--corpus", "/nonexistent/teal-corpus"])
        .output()
        .unwrap();
    assert_eq!(res.status.code(), Some(2));
}
