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

//! Byte-equal parity: `algokey-rust part info` stdout vs Go's
//! captured `algokey part info` stdout for every fixture under
//! `tests/fixtures/partkey/`.
//!
//! A divergence here is a strict-conformance regression — Phase C's
//! correctness surface MUST be byte-identical to Go (per [[CONVE-7]]).

use std::path::{Path, PathBuf};
use std::process::Command;

fn algokey_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_algokey-rust"))
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/partkey")
}

fn assert_part_info_parity(fixture_name: &str) {
    let dir = fixtures_dir();
    let db_path: PathBuf = dir.join(format!("{fixture_name}.db"));
    let expected_path: PathBuf = dir
        .join("part_info_outputs")
        .join(format!("{fixture_name}.stdout"));

    assert!(
        db_path.exists(),
        "fixture DB missing: {} — run scripts/capture-algokey-fixtures.sh",
        db_path.display()
    );
    assert!(
        expected_path.exists(),
        "captured stdout missing: {} — run scripts/capture-algokey-fixtures.sh",
        expected_path.display()
    );

    let expected = std::fs::read(&expected_path).expect("read expected");

    // `part info` opens the DB read-write (matches Go's
    // MakeErasableAccessor). To keep the on-disk fixture pristine
    // between test runs, copy it into a tempfile first.
    let tmp = copy_to_tmp(&db_path);
    let out = algokey_bin()
        .args(["part", "info", "--keyfile"])
        .arg(&tmp)
        .output()
        .expect("spawn binary");
    assert!(
        out.status.success(),
        "part info exited {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    if out.stdout != expected {
        let actual = String::from_utf8_lossy(&out.stdout);
        let expected_utf8 = String::from_utf8_lossy(&expected);
        panic!(
            "part info stdout for {fixture_name} diverged from Go capture\n\
             --- expected ---\n{expected_utf8}\n--- actual ---\n{actual}\n\
             (test fixture: {} / capture: {})",
            db_path.display(),
            expected_path.display()
        );
    }

    let _ = std::fs::remove_file(&tmp);
}

fn copy_to_tmp(src: &Path) -> PathBuf {
    let mut dest = std::env::temp_dir();
    dest.push(format!(
        "algokey-rust-fixture-{}-{}.sqlite",
        src.file_stem().unwrap().to_string_lossy(),
        std::process::id()
    ));
    let _ = std::fs::remove_file(&dest);
    std::fs::copy(src, &dest).expect("copy fixture to tmp");
    dest
}

#[test]
fn part_info_matches_go_for_small_with_sp() {
    assert_part_info_parity("small_with_sp");
}
