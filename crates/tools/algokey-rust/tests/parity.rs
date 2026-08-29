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

//! Byte-equal parity vs go-algorand `algokey` (v4.6.0-stable).
//!
//! For each captured fixture under `tests/fixtures/algokey/`, run the
//! Rust binary and assert stdout matches the Go-captured bytes
//! verbatim. A divergence here is a strict-conformance regression — the
//! Phase A correctness surface (`generate`/`import`/`export`) MUST be
//! byte-identical to Go.

use std::path::{Path, PathBuf};
use std::process::Command;

fn algokey_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_algokey-rust"))
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/algokey")
}

/// Iterate over `import` fixture cases, returning `(case_name, mnemonic, expected_stdout)`.
fn import_cases() -> Vec<(String, String, String)> {
    let dir = fixtures_dir().join("import");
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {} ({e})", dir.display()))
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "stdout"))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    entries
        .into_iter()
        .map(|e| {
            let path = e.path();
            let name = path.file_stem().unwrap().to_string_lossy().into_owned();
            let stdout = std::fs::read_to_string(&path).expect("read stdout");
            // The mnemonic is whatever follows "Private key mnemonic: "
            // on the first line — extract it so we feed the Rust binary
            // the same input Go saw.
            let first = stdout.lines().next().expect("non-empty stdout");
            let mnemonic = first
                .strip_prefix("Private key mnemonic: ")
                .expect("first line shape")
                .to_string();
            (name, mnemonic, stdout)
        })
        .collect()
}

/// Iterate over `export` fixture cases — `(case_name, keyfile_path, expected_stdout)`.
fn export_cases() -> Vec<(String, PathBuf, String)> {
    let dir = fixtures_dir().join("export");
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {} ({e})", dir.display()))
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "keyfile"))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    entries
        .into_iter()
        .map(|e| {
            let keyfile = e.path();
            let stem = keyfile.file_stem().unwrap().to_string_lossy().into_owned();
            let stdout_path = dir.join(format!("{stem}.stdout"));
            let stdout = std::fs::read_to_string(&stdout_path).expect("read stdout");
            (stem, keyfile, stdout)
        })
        .collect()
}

fn run_bytes(cmd: &mut Command) -> Vec<u8> {
    let out = cmd.output().expect("spawn algokey-rust");
    assert!(
        out.status.success(),
        "non-zero exit {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

#[test]
fn import_stdout_matches_go_byte_for_byte() {
    let cases = import_cases();
    assert!(!cases.is_empty(), "no import fixtures found");
    for (name, mnemonic, expected) in cases {
        let got = run_bytes(algokey_bin().args(["import", "-m"]).arg(&mnemonic));
        let got_text = String::from_utf8(got).expect("utf8 stdout");
        assert_eq!(
            got_text, expected,
            "import divergence for `{name}` (mnemonic={mnemonic})"
        );
    }
}

#[test]
fn export_stdout_matches_go_byte_for_byte() {
    let cases = export_cases();
    assert!(!cases.is_empty(), "no export fixtures found");
    for (name, keyfile, expected) in cases {
        // Ensure the committed keyfile is exactly 32 bytes.
        let kbytes = std::fs::read(&keyfile).expect("read keyfile");
        assert_eq!(kbytes.len(), 32, "keyfile {name} must be 32 bytes");
        let got = run_bytes(algokey_bin().args(["export", "-f"]).arg(&keyfile));
        let got_text = String::from_utf8(got).expect("utf8 stdout");
        assert_eq!(got_text, expected, "export divergence for `{name}`");
    }
}

#[test]
fn import_then_export_keyfile_roundtrip_for_every_fixture() {
    // For each (seed, mnemonic) pair, calling `algokey-rust import -m
    // <mnemonic> -f <kf>` then `algokey-rust export -f <kf>` should
    // produce stdout byte-equal to the captured Go export fixture.
    let exports = export_cases();
    let imports = import_cases();
    assert_eq!(exports.len(), imports.len(), "fixture-count mismatch");

    for ((name, mnemonic, _), (_, _, expected_export)) in imports.iter().zip(exports.iter()) {
        let dir = tempfile::tempdir().expect("tempdir");
        let kf = dir.path().join("k");
        run_bytes(
            algokey_bin()
                .args(["import", "-m"])
                .arg(mnemonic)
                .arg("-f")
                .arg(&kf),
        );
        let got = run_bytes(algokey_bin().args(["export", "-f"]).arg(&kf));
        let got_text = String::from_utf8(got).expect("utf8");
        assert_eq!(
            &got_text, expected_export,
            "import+export round-trip divergence on `{name}`"
        );
    }
}

// ---------------------------------------------------------------------------
// Cross-impl: only runs when the Go `algokey` binary is on PATH. Otherwise
// the tests skip with a println! notice so CI/local runs without the Go
// toolchain stay green.
// ---------------------------------------------------------------------------

fn locate_go_algokey() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ALGOKEY") {
        let path = PathBuf::from(&p);
        if path.is_file() {
            return Some(path);
        }
    }
    // Walk PATH for a binary named `algokey`.
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let cand = dir.join("algokey");
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

fn run_go_algokey(go: &Path, args: &[&str]) -> std::process::Output {
    Command::new(go)
        .args(args)
        .output()
        .expect("run Go algokey")
}

#[test]
fn rust_import_keyfile_is_readable_by_go_export() {
    let Some(go) = locate_go_algokey() else {
        println!(
            "skipping rust_import_keyfile_is_readable_by_go_export: \
             Go `algokey` not on PATH (set ALGOKEY=/path/to/algokey to enable)"
        );
        return;
    };
    for (name, mnemonic, expected_rust_stdout) in import_cases() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("k");
        // Rust writes the keyfile.
        run_bytes(
            algokey_bin()
                .args(["import", "-m"])
                .arg(&mnemonic)
                .arg("-f")
                .arg(&kf),
        );
        // Go reads it via export.
        let go_out = run_go_algokey(&go, &["export", "-f", kf.to_str().unwrap()]);
        assert!(
            go_out.status.success(),
            "go algokey export failed for `{name}`: {}",
            String::from_utf8_lossy(&go_out.stderr)
        );
        // Go's export stdout should match the same mnemonic we imported.
        let go_text = String::from_utf8(go_out.stdout).expect("utf8");
        assert_eq!(
            go_text, expected_rust_stdout,
            "Go cannot read Rust-written keyfile for `{name}`"
        );
    }
}

#[test]
fn go_import_keyfile_is_readable_by_rust_export() {
    let Some(go) = locate_go_algokey() else {
        println!(
            "skipping go_import_keyfile_is_readable_by_rust_export: \
             Go `algokey` not on PATH (set ALGOKEY=/path/to/algokey to enable)"
        );
        return;
    };
    for (name, mnemonic, expected_stdout) in import_cases() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("k");
        // Go writes the keyfile.
        let go_out = run_go_algokey(
            &go,
            &["import", "-m", &mnemonic, "-f", kf.to_str().unwrap()],
        );
        assert!(go_out.status.success(), "go algokey import failed: {name}");
        // Rust reads it via export.
        let got = run_bytes(algokey_bin().args(["export", "-f"]).arg(&kf));
        let got_text = String::from_utf8(got).expect("utf8");
        assert_eq!(
            got_text, expected_stdout,
            "Rust cannot read Go-written keyfile for `{name}`"
        );
    }
}
