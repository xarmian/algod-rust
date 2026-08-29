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

//! Integration test for `algokey-rust part generate`.
//!
//! Exercises the full keygen → persist → info round-trip without
//! relying on a Go-captured fixture (those land under [[TASK-182]]).

use std::path::PathBuf;
use std::process::Command;

fn algokey_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_algokey-rust"))
}

fn tmp_db_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "algokey-rust-part-gen-{}-{}.sqlite",
        name,
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn generate_then_info_round_trips_for_a_small_window() {
    // Small window keeps Falcon keygen runtime negligible (~1 MSS key).
    let path = tmp_db_path("small");

    let gen = algokey_bin()
        .args(["part", "generate", "--keyfile"])
        .arg(&path)
        .args(["--first", "1", "--last", "512", "--dilution", "100"])
        .output()
        .expect("spawn generate");
    assert!(
        gen.status.success(),
        "generate failed: status={:?}\nstdout: {}\nstderr: {}",
        gen.status,
        String::from_utf8_lossy(&gen.stdout),
        String::from_utf8_lossy(&gen.stderr)
    );

    let stdout = String::from_utf8_lossy(&gen.stdout);
    assert!(
        stdout.contains("Please stand by while generating keys."),
        "missing status line: {stdout}"
    );
    assert!(
        stdout.contains("Participation key generation successful"),
        "missing success line: {stdout}"
    );
    assert!(
        stdout.contains("Parent address:    "),
        "missing printed parent line: {stdout}"
    );
    assert!(
        stdout.contains("Generated with algokey v"),
        "missing version footer: {stdout}"
    );

    assert!(
        path.exists(),
        "keyfile must exist after successful generate"
    );

    // Round-trip via `part info` — the freshly-generated DB must be
    // readable and produce the same key dilution / first/last rounds we
    // requested.
    let info = algokey_bin()
        .args(["part", "info", "--keyfile"])
        .arg(&path)
        .output()
        .expect("spawn info");
    assert!(
        info.status.success(),
        "info failed: stderr {}",
        String::from_utf8_lossy(&info.stderr)
    );
    let info_out = String::from_utf8_lossy(&info.stdout);
    assert!(info_out.contains("First round:       1"), "{info_out}");
    assert!(info_out.contains("Last round:        512"), "{info_out}");
    assert!(info_out.contains("Key dilution:      100"), "{info_out}");
    assert!(info_out.contains("State proof key:   "), "{info_out}");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn generate_rejects_inverted_range_with_go_wording() {
    let path = tmp_db_path("inverted");
    let out = algokey_bin()
        .args(["part", "generate", "--keyfile"])
        .arg(&path)
        .args(["--first", "100", "--last", "50"])
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "must exit non-zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Last round 50 < first round 100"),
        "actual stderr: {stderr}"
    );
    // The validation fires before the DB is opened, so no cleanup needed.
    assert!(!path.exists(), "keyfile must not be created on early error");
}

#[test]
fn generate_rejects_bad_parent_with_go_wording() {
    let path = tmp_db_path("badparent");
    let out = algokey_bin()
        .args(["part", "generate", "--keyfile"])
        .arg(&path)
        .args([
            "--first",
            "1",
            "--last",
            "512",
            "--dilution",
            "100",
            "--parent",
            "this-is-not-a-valid-address",
        ])
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "must exit non-zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Cannot parse parent address this-is-not-a-valid-address"),
        "actual stderr: {stderr}"
    );
}

#[test]
fn generate_defaults_dilution_when_zero_or_omitted() {
    let path = tmp_db_path("default-dilution");

    // Omit --dilution — clap default 0 → orchestrator applies
    // default_key_dilution.
    let gen = algokey_bin()
        .args(["part", "generate", "--keyfile"])
        .arg(&path)
        .args(["--first", "1", "--last", "101"])
        .output()
        .expect("spawn");
    assert!(
        gen.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&gen.stderr)
    );

    let info = algokey_bin()
        .args(["part", "info", "--keyfile"])
        .arg(&path)
        .output()
        .expect("info");
    let info_out = String::from_utf8_lossy(&info.stdout);
    // default_key_dilution(1, 101) = 1 + floor(sqrt(100)) = 11.
    assert!(info_out.contains("Key dilution:      11"), "{info_out}");

    let _ = std::fs::remove_file(&path);
}
