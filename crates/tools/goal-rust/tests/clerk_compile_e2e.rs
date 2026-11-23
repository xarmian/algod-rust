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

//! `goal clerk compile` / `-D` / `-m` (issue #2370, Phase 25 epic #2364).
//!
//! Go's `compileCmd` assembles and disassembles **locally**; goal-rust used to
//! POST the source to a node. These tests run the `goal-rust` binary without
//! any node or data dir, and, when `MIXED_CLUSTER=1` and `../go-algorand/cmd/goal`
//! builds (`make libsodium` first), run the same inputs through Go's `goal` and
//! require identical exit code, stdout, stderr and output files. With
//! `TEAL_CORPUS_DIR` pointing at a corpus from `scripts/teal-corpus/extract.py`
//! the Go comparison also covers a seeded sample of real programs and sources
//! (`TEAL_CORPUS_GOAL_SAMPLE`, default 24 of each).
//!
//! ```bash
//! cargo test -p goal-rust --test clerk_compile_e2e
//! MIXED_CLUSTER=1 TEAL_CORPUS_DIR=teal-corpus-work/corpus \
//!   cargo test -p goal-rust --test clerk_compile_e2e -- --nocapture
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

// The records of the strict `LogicSig` decode (#2390), shared with algo-codec's tests.
#[path = "../../../core/algo-codec/tests/common/lsig_cases.rs"]
mod lsig_cases;
use lsig_cases::{lsig_decode_cases, lsig_mutant_cases, lsig_mutant_cases_with};

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
        Ok(s) => {
            eprintln!("Go-parity SKIPPED: `go build ./cmd/goal` exited {s:?}");
            None
        }
        Err(e) => {
            eprintln!("Go-parity SKIPPED: failed to invoke `go build`: {e}");
            None
        }
    }
}

fn run(bin: &Path, cwd: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .args(args)
        .current_dir(cwd)
        .env_remove("ALGORAND_DATA")
        .output()
        .expect("run goal")
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

const GOOD: &str = "#pragma version 8\nint 1\nreturn\n";

#[test]
fn compile_writes_tok_prints_address_and_needs_no_node() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("a.teal"), GOOD).unwrap();

    let out = run(
        Path::new(GOAL_RUST_BIN),
        tmp.path(),
        &["clerk", "compile", "a.teal"],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.starts_with("a.teal: "), "{stdout}");
    // `<address> (salted: <address>)`: go v5.1 appends the `ls` address to the line.
    assert_eq!(
        stdout.trim_end().len(),
        "a.teal: ".len() + 58 + " (salted: ".len() + 58 + ")".len(),
        "{stdout}"
    );
    assert!(stdout.contains(" (salted: ") && stdout.trim_end().ends_with(')'), "{stdout}");
    assert_eq!(
        std::fs::read(tmp.path().join("a.teal.tok")).unwrap(),
        vec![8, 0x81, 1, 0x43]
    );
}

#[test]
fn compile_to_stdout_map_and_disassemble() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("a.teal"), GOOD).unwrap();
    let goal = Path::new(GOAL_RUST_BIN);

    // -o - writes the program to stdout and prints no address.
    let out = run(goal, tmp.path(), &["clerk", "compile", "-o", "-", "a.teal"]);
    assert!(out.status.success());
    assert_eq!(out.stdout, vec![8, 0x81, 1, 0x43]);

    // -m writes <out>.map; json.Marshal escapes `<`/`>` (stdin source is "<stdin>").
    let out = run(
        goal,
        tmp.path(),
        &["clerk", "compile", "-m", "-o", "b.tok", "a.teal"],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let map = std::fs::read_to_string(tmp.path().join("b.tok.map")).unwrap();
    assert!(
        map.starts_with("{\"version\":3,\"sources\":[\"a.teal\"]"),
        "{map}"
    );

    // -m with stdout output is an error after the program was written.
    let out = run(
        goal,
        tmp.path(),
        &["clerk", "compile", "-m", "-o", "-", "a.teal"],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("-: cannot print map to stdout"));

    // -D prints the disassembly of a compiled program.
    let out = run(goal, tmp.path(), &["clerk", "compile", "a.teal"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let out = run(goal, tmp.path(), &["clerk", "compile", "-D", "a.teal.tok"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "#pragma version 8\npushint 1\nreturn\n");
}

#[test]
fn compile_reports_errors_like_go() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("bad.teal"), "#pragma version 8\nbogus\n").unwrap();
    std::fs::write(
        tmp.path().join("bad2.teal"),
        "#pragma version 8\nbogus\nbogus\n",
    )
    .unwrap();
    let goal = Path::new(GOAL_RUST_BIN);

    let out = run(goal, tmp.path(), &["clerk", "compile", "bad.teal"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr),
        "bad.teal: 1 error: 2: unknown opcode: bogus\nbad.teal: 1 error: 2: unknown opcode: bogus\n"
    );
    assert!(!tmp.path().join("bad.teal.tok").exists());

    let out = run(goal, tmp.path(), &["clerk", "compile", "bad2.teal"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr),
        "bad2.teal: 2: unknown opcode: bogus\nbad2.teal: 3: unknown opcode: bogus\nbad2.teal: 2 errors\n"
    );
}

/// Same inputs through Go's `goal` and goal-rust, in separate directories with
/// identical relative names: exit code, stdout, stderr and every file written
/// must be identical.
/// Exit code, stdout, stderr and the files a case writes.
type RunResult = (
    Option<i32>,
    Vec<u8>,
    Vec<u8>,
    Vec<(String, Option<Vec<u8>>)>,
);

/// `(label, bytes)` pairs.
type Named = Vec<(String, Vec<u8>)>;

struct Case {
    name: String,
    files: Vec<(String, Vec<u8>)>,
    args: Vec<String>,
    outputs: Vec<String>,
}

fn run_case(bin: &Path, case: &Case) -> RunResult {
    let tmp = tempfile::tempdir().unwrap();
    for (n, b) in &case.files {
        std::fs::write(tmp.path().join(n), b).unwrap();
    }
    let args: Vec<&str> = case.args.iter().map(String::as_str).collect();
    let out = run(bin, tmp.path(), &args);
    let files = case
        .outputs
        .iter()
        .map(|n| (n.clone(), std::fs::read(tmp.path().join(n)).ok()))
        .collect();
    (out.status.code(), out.stdout, out.stderr, files)
}

fn compile_case(name: &str, src: &[u8], extra: &[&str]) -> Case {
    let mut args = vec!["clerk".to_string(), "compile".to_string()];
    args.extend(extra.iter().map(|s| s.to_string()));
    args.push("p.teal".to_string());
    Case {
        name: name.to_string(),
        files: vec![("p.teal".into(), src.to_vec())],
        args,
        outputs: vec![
            "p.teal.tok".into(),
            "p.teal.tok.map".into(),
            "o.bin".into(),
            "o.bin.map".into(),
        ],
    }
}

fn disassemble_case(name: &str, program: &[u8]) -> Case {
    Case {
        name: name.to_string(),
        files: vec![("p.tok".into(), program.to_vec())],
        args: ["clerk", "compile", "-D", "p.tok"]
            .map(String::from)
            .to_vec(),
        outputs: vec![],
    }
}

fn corpus_sample(dir: &Path, want: usize) -> (Named, Named) {
    let manifest = std::fs::read_to_string(dir.join("manifest.jsonl")).expect("manifest.jsonl");
    let mut shas: Vec<(String, Option<String>)> = manifest
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            (
                v["sha256"].as_str().unwrap().to_string(),
                v["source_sha256"].as_str().map(str::to_string),
            )
        })
        .collect();
    shas.sort();
    let step = (shas.len() / want.max(1)).max(1);
    let mut programs = Vec::new();
    let mut sources = Vec::new();
    for (sha, source) in shas.iter().step_by(step).take(want) {
        if let Ok(b) = std::fs::read(dir.join("programs").join(format!("{sha}.bin"))) {
            programs.push((format!("program {sha}"), b));
        }
        if let Some(s) = source {
            if let Ok(b) = std::fs::read(dir.join("sources").join(format!("{s}.teal"))) {
                sources.push((format!("source {s}"), b));
            }
        }
    }
    (programs, sources)
}

#[test]
fn compile_matches_go_goal() {
    if !mixed_cluster_enabled() {
        eprintln!("Go-parity SKIPPED: set MIXED_CLUSTER=1");
        return;
    }
    let Some(go_goal) = try_ensure_go_goal() else {
        return;
    };

    let mut cases = vec![
        compile_case("good", GOOD.as_bytes(), &[]),
        compile_case("good -n", GOOD.as_bytes(), &["-n"]),
        compile_case("good -m -o", GOOD.as_bytes(), &["-m", "-o", "o.bin"]),
        compile_case("good -o -", GOOD.as_bytes(), &["-o", "-"]),
        compile_case("good -m -o -", GOOD.as_bytes(), &["-m", "-o", "-"]),
        compile_case("one error", b"#pragma version 8\nbogus\n", &[]),
        compile_case("two errors", b"#pragma version 8\nbogus\nbogus\n", &[]),
        compile_case("empty", b"", &[]),
        compile_case(
            "warning",
            b"#pragma version 8\nint 1\nint 1\n+\nreturn\n// trailing\n",
            &[],
        ),
        disassemble_case("D good", &[8, 0x81, 1, 0x43]),
        disassemble_case("D bad version", &[0xff, 0xff, 0xff]),
        disassemble_case("D empty", &[]),
    ];
    // Sources that are not UTF-8 (#2388): go assembles any byte string.
    for (name, src) in NON_UTF8_SOURCES {
        cases.push(compile_case(name, src, &[]));
        cases.push(compile_case(&format!("{name} -m"), src, &["-m"]));
    }
    // `-D` of signed LogicSig records (#2388) and of byte strings that are not.
    for (name, bytes) in lsig_files() {
        cases.push(disassemble_case(&format!("D lsig {name}"), &bytes));
    }
    // Hand-made and damaged LogicSig records (#2390).
    // `LSIG_MUTANTS_PER_BASE=4000` widens the seeded mutant search.
    let mutants = match std::env::var("LSIG_MUTANTS_PER_BASE")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(n) => lsig_mutant_cases_with(n),
        None => lsig_mutant_cases(),
    };
    for (name, bytes) in lsig_decode_cases().into_iter().chain(mutants) {
        cases.push(disassemble_case(&format!("D lsig {name}"), &bytes));
    }
    if let Ok(dir) = std::env::var("TEAL_CORPUS_DIR") {
        let want = std::env::var("TEAL_CORPUS_GOAL_SAMPLE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(24);
        let (programs, sources) = corpus_sample(Path::new(&dir), want);
        for (name, src) in &sources {
            cases.push(compile_case(name, src, &["-m"]));
        }
        for (name, program) in &programs {
            cases.push(disassemble_case(name, program));
        }
    }

    let mut mismatches = Vec::new();
    for case in &cases {
        let go = run_case(&go_goal, case);
        let rs = run_case(Path::new(GOAL_RUST_BIN), case);
        if go != rs {
            mismatches.push(format!(
                "{}:\n  go:   {:?} stdout={:?} stderr={:?} files={:?}\n  rust: {:?} stdout={:?} stderr={:?} files={:?}",
                case.name,
                go.0,
                String::from_utf8_lossy(&go.1),
                String::from_utf8_lossy(&go.2),
                go.3,
                rs.0,
                String::from_utf8_lossy(&rs.1),
                String::from_utf8_lossy(&rs.2),
                rs.3,
            ));
        }
    }
    println!(
        "goal compile parity: {} cases, {} mismatches",
        cases.len(),
        mismatches.len()
    );
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

// ---- sources that are not UTF-8 (issue #2388) ------------------------------

/// Sources whose bytes are not (all) UTF-8: go assembles them, keeping a string
/// literal's bytes and ignoring a comment's, and reports the bytes of a bad
/// token as they are.
const NON_UTF8_SOURCES: &[(&str, &[u8])] = &[
    ("literal", b"#pragma version 8\nbyte \"\xff\xfe\"\nint 1\n"),
    ("comment", b"#pragma version 8\nint 1 // \xff\xfe\n"),
    ("label", b"#pragma version 8\nint 1\n\xfe:\nint 1\n"),
    ("unknown opcode", b"#pragma version 8\nfoo\xff\nint 1\n"),
    (
        "truncated sequence",
        b"#pragma version 8\nint 1\n\xe2\x82 \n",
    ),
    ("two errors", b"#pragma version 8\nfoo\xff\nbar\xfe\n"),
    ("int immediate", b"#pragma version 8\nint \xff\n"),
    ("hex literal", b"#pragma version 8\nbyte 0x\xffab\n"),
    ("macro name", b"#pragma version 8\n#define \xff 1\nint 1\n"),
    (
        "private use",
        b"#pragma version 8\nfoo\xf4\x8f\xbc\x80\nint 1\n",
    ),
    ("whole file", b"\xff\xfe"),
    (
        "control character",
        b"#pragma version 8\nfoo\x01bar\nint 1\n",
    ),
    (
        "control character in a warning",
        b"#pragma version 8\nbyte \"\x01\"\nint 1\nint 1\n+\nreturn\n",
    ),
    (
        "warning with literal",
        b"#pragma version 8\nbyte \"\xff\"\nint 1\nint 1\n+\nreturn\n",
    ),
];

#[test]
fn compile_assembles_non_utf8_source_like_go() {
    let tmp = tempfile::tempdir().unwrap();
    let goal = Path::new(GOAL_RUST_BIN);
    std::fs::write(tmp.path().join("p.teal"), NON_UTF8_SOURCES[0].1).unwrap();

    // The probe of #2388; the address is go's (`/v2/teal/compile` answers the
    // same `hash` and `result` CIAC//6BAQ==).
    let out = run(goal, tmp.path(), &["clerk", "compile", "p.teal"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    // go v5.1 appends the program's `ls` address (`compile_matches_go_goal` pins it).
    assert!(
        stdout.starts_with(
            "p.teal: MFCZLYTBNJYZALFOIWR6GTHRV7FRWIZPI3NSVBI4YHIUEF5FDYXVBDL354 (salted: "
        ) && stdout.ends_with(")
"),
        "{stdout}"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("p.teal.tok")).unwrap(),
        vec![8, 0x80, 2, 0xff, 0xfe, 0x81, 1]
    );

    // A bad token is reported with its bytes by `ReportMultipleErrors` and, like
    // every goal error line (`unicodePrintable`), as U+FFFD by `reportErrorf`.
    std::fs::write(
        tmp.path().join("bad.teal"),
        b"#pragma version 8\nfoo\xff\nint 1\n",
    )
    .unwrap();
    let out = run(goal, tmp.path(), &["clerk", "compile", "bad.teal"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        out.stderr,
        b"bad.teal: 1 error: 2: unknown opcode: foo\xff\nbad.teal: 1 error: 2: unknown opcode: foo\xef\xbf\xbd\n".to_vec()
    );
}

// ---- `-D` of a signed LogicSig (issue #2388) --------------------------------

const PROGRAM: [u8; 3] = [8, 0x81, 1];

fn sig64() -> [u8; 64] {
    std::array::from_fn(|i| i as u8)
}

fn pk32(mul: usize) -> [u8; 32] {
    std::array::from_fn(|i| (i * mul % 256) as u8)
}

fn lsig_base() -> algo_types::LogicSig {
    algo_types::LogicSig {
        logic: serde_bytes::ByteBuf::from(PROGRAM.to_vec()),
        ..algo_types::LogicSig::default()
    }
}

fn msig(threshold: u8, subs: &[([u8; 32], [u8; 64])]) -> algo_types::MultisigSig {
    algo_types::MultisigSig {
        version: 1,
        threshold,
        subsigs: subs
            .iter()
            .map(|(pk, s)| algo_types::MultisigSubsig {
                public_key: *pk,
                signature: *s,
            })
            .collect(),
    }
}

/// LogicSig records (and byte strings that are not one) as `goal clerk compile
/// -D` reads them.
fn lsig_files() -> Vec<(String, Vec<u8>)> {
    let enc = |l: &algo_types::LogicSig| algo_codec::canonical_encode_logicsig(l);
    let args = |a: &[&[u8]]| {
        Some(
            a.iter()
                .map(|x| Some(serde_bytes::ByteBuf::from(x.to_vec())))
                .collect::<Vec<_>>(),
        )
    };
    let mut v = vec![
        ("unsigned".to_string(), enc(&lsig_base())),
        (
            "sig".into(),
            enc(&algo_types::LogicSig {
                sig: sig64(),
                ..lsig_base()
            }),
        ),
        (
            "blank sig".into(),
            enc(&algo_types::LogicSig {
                sig: [0; 64],
                ..lsig_base()
            }),
        ),
        (
            "args".into(),
            enc(&algo_types::LogicSig {
                args: args(&[b"\x01\x02", b"", b"hello"]),
                ..lsig_base()
            }),
        ),
        (
            "sig and args".into(),
            enc(&algo_types::LogicSig {
                sig: sig64(),
                args: args(&[b"\xff"]),
                ..lsig_base()
            }),
        ),
        (
            "msig".into(),
            enc(&algo_types::LogicSig {
                msig: Some(msig(2, &[(pk32(3), sig64()), (pk32(7), [0; 64])])),
                ..lsig_base()
            }),
        ),
        (
            "lmsig".into(),
            enc(&algo_types::LogicSig {
                lmsig: Some(msig(1, &[(pk32(3), sig64())])),
                ..lsig_base()
            }),
        ),
        (
            "everything".into(),
            enc(&algo_types::LogicSig {
                sig: sig64(),
                msig: Some(msig(2, &[(pk32(3), sig64())])),
                lmsig: Some(msig(1, &[(pk32(7), sig64())])),
                args: args(&[b"a"]),
                ..lsig_base()
            }),
        ),
        (
            "pqsig".into(),
            enc(&algo_types::LogicSig {
                pqsig: Some(algo_types::SaltedKeySig {
                    scheme: *b"fn",
                    salt: algo_types::AddressSalt(3),
                    public_key: serde_bytes::ByteBuf::from((0..20).collect::<Vec<u8>>()),
                    signature: serde_bytes::ByteBuf::from((0..30).collect::<Vec<u8>>()),
                }),
                ..lsig_base()
            }),
        ),
        (
            "signed, no program".into(),
            enc(&algo_types::LogicSig {
                logic: serde_bytes::ByteBuf::new(),
                sig: sig64(),
                ..lsig_base()
            }),
        ),
        (
            "signed, program of an unknown version".into(),
            enc(&algo_types::LogicSig {
                logic: serde_bytes::ByteBuf::from(vec![99, 1, 2]),
                sig: sig64(),
                ..lsig_base()
            }),
        ),
    ];
    // Not LogicSig records: go falls back to disassembling the bytes.
    v.push(("trailing bytes".into(), {
        let mut b = enc(&lsig_base());
        b.push(0);
        b
    }));
    v.push(("empty map".into(), vec![0x80]));
    v.push(("junk".into(), vec![1, 2, 3]));
    v
}

#[test]
fn disassemble_prints_the_inspection_of_a_signed_logicsig() {
    let tmp = tempfile::tempdir().unwrap();
    let goal = Path::new(GOAL_RUST_BIN);
    let sig_b64 =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";
    let files: std::collections::HashMap<_, _> = lsig_files().into_iter().collect();
    let disassemble = |name: &str| -> String {
        let f = tmp.path().join("x.lsig");
        std::fs::write(&f, &files[name]).unwrap();
        let out = run(goal, tmp.path(), &["clerk", "compile", "-D", "x.lsig"]);
        assert!(out.status.success(), "{name}: {}", text(&out.stderr));
        text(&out.stdout)
    };
    let head = "#pragma version 8\npushint 1\n";

    // An unsigned record and a blank signature print only the program.
    assert_eq!(disassemble("unsigned"), head);
    assert_eq!(disassemble("blank sig"), head);

    // Expected texts are go v5.0.5-stable's `goal clerk compile -D`.
    assert_eq!(
        disassemble("sig"),
        format!("{head}LogicSig: {{\n  \"sig\": \"{sig_b64}\"\n}}\n")
    );
    assert_eq!(
        disassemble("sig and args"),
        format!(
            "{head}LogicSig: {{\n  \"arg\": [\n    \"/w==\"\n  ],\n  \"sig\": \"{sig_b64}\"\n}}\n"
        )
    );
    assert_eq!(
        disassemble("args"),
        format!("{head}LogicSig: {{\n  \"arg\": [\n    \"AQI=\",\n    \"\",\n    \"aGVsbG8=\"\n  ]\n}}\n")
    );
    assert_eq!(
        disassemble("msig"),
        format!(
            "{head}LogicSig: {{\n  \"msig\": {{\n    \"subsig\": [\n      {{\n        \"pk\": \"AABQMCIMB4JBKGA3DYQSIJZKFUYDGNRZHQ7UERKIJNHFCVCXLJOYLCOB6Q\",\n        \"s\": \"{sig_b64}\"\n      }},\n      {{\n        \"pk\": \"AADQ4FI4EMVDCOB7IZGVIW3CNFYHO7UFRSJZVINIV63L3RGL2LM534AZPY\"\n      }}\n    ],\n    \"thr\": 2,\n    \"v\": 1\n  }}\n}}\n"
        )
    );
    assert_eq!(
        disassemble("pqsig"),
        format!(
            "{head}LogicSig: {{\n  \"pqsig\": {{\n    \"pk\": \"AAECAwQFBgcICQoLDA0ODxAREhM=\",\n    \"sch\": \"Zm4=\",\n    \"sig\": \"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd\",\n    \"slt\": 3\n  }}\n}}\n"
        )
    );
    // The members come out in go's canonical order: arg, lmsig, msig, pqsig, sig.
    let all = disassemble("everything");
    let at = |k: &str| {
        all.find(&format!("\n  \"{k}\""))
            .unwrap_or_else(|| panic!("{k} in {all}"))
    };
    assert!(at("arg") < at("lmsig") && at("lmsig") < at("msig") && at("msig") < at("sig"));
    // A signed record without a program, and one with an unknown version.
    assert_eq!(
        disassemble("signed, no program"),
        format!("// invalid version\nLogicSig: {{\n  \"sig\": \"{sig_b64}\"\n}}\n")
    );
    assert_eq!(
        disassemble("signed, program of an unknown version"),
        format!("// unsupported version 99\nLogicSig: {{\n  \"sig\": \"{sig_b64}\"\n}}\n")
    );
    // Bytes that are not a LogicSig record are disassembled as a program.
    assert_eq!(
        disassemble("junk"),
        "#pragma version 1\nkeccak256\nsha512_256\n"
    );
    assert_eq!(disassemble("empty map"), "// invalid version\n");
}

// ---- the strict `LogicSig` decode, committed (issue #2390) -------------------
//
// `fixtures/clerk_lsig_decode.jsonl` holds, for each record of
// `lsig_cases.rs` whose input is at most `FIXTURE_MAX_INPUT` bytes, what go
// v5.0.5-stable's `goal clerk compile -D` printed. goal-rust must print the
// same (a default test, no go needed), and a `MIXED_CLUSTER=1` run re-checks the
// file against a real go `goal`; `REGEN_LSIG_FIXTURE=1` rewrites it from go:
//
// ```bash
// MIXED_CLUSTER=1 REGEN_LSIG_FIXTURE=1 cargo test -p goal-rust \
//   --test clerk_compile_e2e lsig_decode_fixture_matches_go_goal
// ```
//
// CI runs the check in `.github/workflows/teal-corpus-drivers.yml`.

const LSIG_FIXTURE: &str = "tests/fixtures/clerk_lsig_decode.jsonl";
/// Larger records are compared with go live only (`compile_matches_go_goal`).
const FIXTURE_MAX_INPUT: usize = 2048;
/// Longer output is stored as its SHA-256 and length.
const FIXTURE_INLINE_OUTPUT: usize = 1024;

fn lsig_fixture_cases() -> Vec<(String, Vec<u8>)> {
    lsig_decode_cases()
        .into_iter()
        .chain(lsig_mutant_cases())
        .filter(|(_, b)| b.len() <= FIXTURE_MAX_INPUT)
        .collect()
}

/// The part of go's output that is kept, as one fixture row.
fn fixture_row(name: &str, input: &[u8], run: &RunResult) -> serde_json::Value {
    use sha2::{Digest, Sha256};
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
    serde_json::Value::Object(row)
}

fn read_fixture() -> Vec<serde_json::Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(LSIG_FIXTURE);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .map(|l| serde_json::from_str(l).expect("fixture row is JSON"))
        .collect()
}

fn disassemble_run(bin: &Path, name: &str, input: &[u8]) -> RunResult {
    run_case(bin, &disassemble_case(name, input))
}

#[test]
fn lsig_decode_fixture_matches_goal_rust() {
    let cases = lsig_fixture_cases();
    let fixture = read_fixture();
    assert_eq!(
        fixture.len(),
        cases.len(),
        "{LSIG_FIXTURE} is out of date: regenerate it (see the comment above LSIG_FIXTURE)"
    );
    let mut mismatches = Vec::new();
    for ((name, input), want) in cases.iter().zip(&fixture) {
        assert_eq!(want["name"], *name, "{LSIG_FIXTURE} is out of date");
        assert_eq!(
            want["input"],
            hex::encode(input),
            "{name}: {LSIG_FIXTURE} is out of date"
        );
        let got = fixture_row(
            name,
            input,
            &disassemble_run(Path::new(GOAL_RUST_BIN), name, input),
        );
        if got != *want {
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

#[test]
fn lsig_decode_fixture_matches_go_goal() {
    if !mixed_cluster_enabled() {
        eprintln!("Go-parity SKIPPED: set MIXED_CLUSTER=1");
        return;
    }
    let Some(go_goal) = try_ensure_go_goal() else {
        return;
    };
    let cases = lsig_fixture_cases();
    let rows: Vec<serde_json::Value> = cases
        .iter()
        .map(|(name, input)| fixture_row(name, input, &disassemble_run(&go_goal, name, input)))
        .collect();
    let text: String = rows.iter().map(|r| format!("{r}\n")).collect();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(LSIG_FIXTURE);
    if std::env::var("REGEN_LSIG_FIXTURE").is_ok_and(|v| !v.is_empty() && v != "0") {
        std::fs::write(&path, text).expect("write the fixture");
        return;
    }
    let committed = std::fs::read_to_string(&path).expect("fixture file");
    assert!(
        committed == text,
        "{LSIG_FIXTURE} differs from go's output: regenerate it with REGEN_LSIG_FIXTURE=1"
    );
}
