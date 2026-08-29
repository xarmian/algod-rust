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

//! Shared parity-fixture harness used across the per-leaf
//! `tests/*.rs` files.
//!
//! Acts as a thin wrapper around the committed fixtures under
//! `tests/fixtures/parity/` so the per-leaf tests don't reinvent
//! file-reading / diff-printing on their own.
//!
//! All fixtures are byte-exact snapshots of Go's `goal` output —
//! see `tests/fixtures/parity/README.md` for the refresh workflow.

#![allow(dead_code)] // utilities are picked up per-test-binary

use std::path::PathBuf;

/// Absolute path of `tests/fixtures/parity/<name>.txt`.
pub fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("parity")
        .join(format!("{name}.txt"))
}

/// Read the committed fixture; panics with a helpful message if it's
/// missing so a typo doesn't silently turn into a passing test.
pub fn load_fixture(name: &str) -> String {
    let p = fixture_path(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "missing parity fixture {} ({e}); see {}",
            p.display(),
            "crates/tools/goal-rust/tests/fixtures/parity/README.md",
        )
    })
}

/// Diff-clean assertion. The harness deliberately has no "rewrite
/// the fixture from Rust output" escape hatch: doing that would let
/// a Rust regression bake itself in as the new expected without ever
/// being compared against Go (Codex review TASK-229 round 1). The
/// only sanctioned refresh path runs the Go binary via
/// `tools/capture-goal-fixtures.sh`; see
/// `tests/fixtures/parity/README.md`.
pub fn assert_matches_fixture(name: &str, actual: &str) {
    let expected = load_fixture(name);
    assert_eq!(
        actual,
        expected,
        "parity fixture mismatch: {}\n\
         To refresh after an INTENTIONAL Go-side wording change, run\n\
         `MIXED_CLUSTER=1 ./crates/tools/goal-rust/tools/capture-goal-fixtures.sh`\n\
         and inspect the diff before committing.",
        fixture_path(name).display(),
    );
}
