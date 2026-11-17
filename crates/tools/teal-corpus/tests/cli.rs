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

/// Assembly parity on the fixture corpus: the valid sources, the warning source
/// and the invalid source (go quotes nothing in `unknown opcode: frobnicate` and
/// blames column 4 of `byte` for its missing argument) all match go row for
/// row. The regression cases live in `algo-avm/tests/assemble_go_parity.rs`
/// (#2368) and the full-registry run in `scripts/teal-corpus/run_drivers.sh`.
#[test]
fn rust_assemble_rows_equal_the_go_driver_rows() {
    let (code, ms) = diff_against_go("assemble");
    assert_eq!(code, Some(0), "{ms:?}");
    assert!(ms.is_empty(), "{ms:?}");
}

/// Disassembly parity on the fixture corpus: the valid programs, the
/// unsupported-version program (go prints a `// unsupported version` comment)
/// and the truncated program (same error text) all match go row for row. The
/// full-registry run and the byte-program regression cases live in #2367's
/// `algo-avm/tests/disassemble_go_parity.rs`.
#[test]
fn rust_disassemble_rows_equal_the_go_driver_rows() {
    let (code, ms) = diff_against_go("disassemble");
    assert_eq!(code, Some(0), "{ms:?}");
    assert!(ms.is_empty(), "{ms:?}");
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

/// The summary #2367 asks for: programs compared, identical, both-error-
/// identical, mismatched, panics/timeouts. The fixture has 3 successful rows
/// and 1 truncated program that errors the same way on both sides.
#[test]
fn diff_summary_counts_identical_both_error_mismatched_and_robustness() {
    let d = scratch("summary");
    let a = d.join("a.jsonl");
    run_driver("disassemble", &a, "2");
    let m = d.join("m.jsonl");
    let res = bin()
        .arg("diff")
        .arg(&a)
        .arg(&a)
        .arg("--out")
        .arg(&m)
        .output()
        .unwrap();
    assert_eq!(res.status.code(), Some(0));
    let err = String::from_utf8_lossy(&res.stderr);
    assert!(
        err.contains(
            "4 rows compared, 3 identical, 1 both-error-identical, 0 mismatches, 0 panics/timeouts"
        ),
        "{err}"
    );
}

/// A panic or timeout row is a failure even when both sides recorded the
/// same one: the comparison must not pass over it as "identical".
#[test]
fn diff_fails_on_a_recorded_panic_even_when_both_sides_agree() {
    let d = scratch("panicrow");
    let a = d.join("a.jsonl");
    run_driver("disassemble", &a, "2");
    let text = std::fs::read_to_string(&a).unwrap();
    let b = d.join("b.jsonl");
    let seeded = text.replacen(
        &format!("{{\"ok\":true,\"sha256\":\"{VALID_PUSHINT}\",\"text\":\"#pragma version 8\\npushint 1\\n\"}}"),
        &format!("{{\"ok\":false,\"panic\":\"boom\",\"sha256\":\"{VALID_PUSHINT}\"}}"),
        1,
    );
    assert_ne!(seeded, text, "the seeded panic row replaced nothing");
    std::fs::write(&b, &seeded).unwrap();
    let m = d.join("m.jsonl");
    let res = bin()
        .arg("diff")
        .arg(&b)
        .arg(&b)
        .arg("--out")
        .arg(&m)
        .output()
        .unwrap();
    assert_eq!(res.status.code(), Some(1));
    assert_eq!(std::fs::read(&m).unwrap().len(), 0, "no mismatch rows");
    let err = String::from_utf8_lossy(&res.stderr);
    assert!(err.contains("2 panics/timeouts"), "{err}");
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

/// Sources that are not UTF-8 (issue #2388): go assembles any byte string, so
/// both drivers do. The expected rows are the Go driver's own output for these
/// four inputs (a literal that keeps its bytes, a comment that is ignored, two
/// errors whose messages carry one U+FFFD per invalid byte, and a valid
/// multi-byte literal).
#[test]
fn assemble_non_utf8_sources_equal_the_go_driver_rows() {
    let dir = scratch("non-utf8");
    let sources = dir.join("corpus/sources");
    std::fs::create_dir_all(&sources).unwrap();
    let inputs: [&[u8]; 4] = [
        b"#pragma version 8\nbyte \"\xff\xfe\"\nint 1\n",
        b"#pragma version 8\nint 1 // \xff\xfe comment\n",
        b"#pragma version 8\nfoo\xff\nint 1\nbar\xe2\x82\n",
        b"#pragma version 8\nbyte \"\xc3\xa9\"\nint 1\nint 1\n+\nreturn\n",
    ];
    for (i, src) in inputs.iter().enumerate() {
        std::fs::write(sources.join(format!("{i}.teal")), src).unwrap();
    }
    let out = dir.join("rows.jsonl");
    let res = bin()
        .args(["assemble", "--corpus"])
        .arg(dir.join("corpus"))
        .arg("--out")
        .arg(&out)
        .args(["--jobs", "1"])
        .output()
        .expect("spawn teal-corpus");
    assert_eq!(
        res.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&res.stderr)
    );
    let want: [&str; 4] = [
        r#"{"bytecode_b64":"CIAC//6BAQ==","hash":"MFCZLYTBNJYZALFOIWR6GTHRV7FRWIZPI3NSVBI4YHIUEF5FDYXVBDL354","ok":true,"sha256":"34f95dc3137dd7491772889091dcc286e4a419fee3917b3d16c9ceb0168cf4fa","sourcemap":{"version":3,"sources":["<body>"],"names":[],"mappings":";AACA;;;;AACA"}}"#,
        r#"{"bytecode_b64":"CIEB","hash":"PQOFFIOE4JA726ULBV4EQ23PNP3VGUP7KUB2UPK4CA6LWQ2RBMOX7PQRJM","ok":true,"sha256":"34f9aec451118531e5a5b10433903bfc35b4af06fbed9e1acb4531fb561b2fb0","sourcemap":{"version":3,"sources":["<body>"],"names":[],"mappings":";AACA"}}"#,
        r#"{"errors":[{"col":0,"line":2,"message":"unknown opcode: foo�"},{"col":0,"line":4,"message":"unknown opcode: bar��"}],"ok":false,"sha256":"18baab47d7c160fc457f0319e61d7f01aac057c7a65d7cbe80514b37e2ae3638"}"#,
        r#"{"bytecode_b64":"CCABAYACw6kiIghD","hash":"ZWINNQMHEMUVPEDKRQ3EPMKGP2WYYARSW7PVO7RT3DSMMEZE77ZS7CMOYQ","ok":true,"sha256":"cc35385260f178723cf8dc94c1cce06cd8410c00524f1f9cabba7e9dabd7487c","sourcemap":{"version":3,"sources":["<body>"],"names":[],"mappings":";;;;AACA;;;;AACA;AACA;AACA;AACA"}}"#,
    ];
    let got = rows(&out);
    assert_eq!(got.len(), want.len());
    for w in want {
        let w: Value = serde_json::from_str(w).unwrap();
        assert_eq!(*row(&got, w["sha256"].as_str().unwrap()), w);
    }
}

/// Issue #2371: `--timings` writes a per-program wall-clock table next to the
/// rows without changing the rows (the benchmark tier reads it).
#[test]
fn timings_file_has_one_entry_per_input_and_leaves_rows_unchanged() {
    let dir = scratch("timings");
    let (plain, timed, timings) = (
        dir.join("plain.jsonl"),
        dir.join("timed.jsonl"),
        dir.join("timings.json"),
    );
    assert_eq!(run_driver("disassemble", &plain, "1").status.code(), Some(0));
    let res = bin()
        .arg("disassemble")
        .arg("--corpus")
        .arg(fixture())
        .arg("--out")
        .arg(&timed)
        .args(["--jobs", "1", "--timings"])
        .arg(&timings)
        .output()
        .expect("spawn teal-corpus");
    assert_eq!(res.status.code(), Some(0));
    assert_eq!(
        std::fs::read(&plain).unwrap(),
        std::fs::read(&timed).unwrap(),
        "--timings must not change the output rows"
    );
    let t: Value = serde_json::from_slice(&std::fs::read(&timings).unwrap()).unwrap();
    assert_eq!(t["schema"], "teal-corpus-timings/v1");
    assert_eq!(t["impl"], "algod-rust");
    assert_eq!(t["operation"], "disassemble");
    assert_eq!(t["jobs"], 1);
    assert_eq!(t["inputs"], 4);
    assert!(t["input_bytes"].as_u64().unwrap() > 0);
    assert!(t["wall_ns"].as_u64().unwrap() > 0);
    let per = t["per_program_ns"].as_object().unwrap();
    assert_eq!(per.len(), 4);
    for r in rows(&plain) {
        assert!(per.contains_key(r["sha256"].as_str().unwrap()));
    }
}
