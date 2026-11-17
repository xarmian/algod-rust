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
    assert_eq!(stdout.trim_end().len(), "a.teal: ".len() + 58, "{stdout}");
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
type RunResult = (Option<i32>, String, String, Vec<(String, Option<Vec<u8>>)>);

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
    (
        out.status.code(),
        text(&out.stdout),
        text(&out.stderr),
        files,
    )
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
            mismatches.push(format!("{}:\n  go:   {go:?}\n  rust: {rs:?}", case.name));
        }
    }
    println!(
        "goal compile parity: {} cases, {} mismatches",
        cases.len(),
        mismatches.len()
    );
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}
