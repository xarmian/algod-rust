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

//! Issue #2193: `validate_transaction_wellformed_in_mode`'s mode decides what
//! an unknown transaction type does, so every PRODUCTION call site must pass
//! the intended one: block validation and simulation the block mode (they
//! reject an unknown type earlier, in `check_txn_group`), the REST and gossip
//! admission paths (`participate.rs`) the admission mode.

use std::path::{Path, PathBuf};

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.is_dir() {
            if !matches!(name, "tests" | "target" | "benches" | "examples") {
                rust_sources(&p, out);
            }
        } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") {
            out.push(p);
        }
    }
}

/// `(file relative to the repo root, mode)` of every non-test call.
fn call_sites() -> Vec<(String, &'static str)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut files = Vec::new();
    rust_sources(&root.join("crates"), &mut files);
    rust_sources(&root.join("bin"), &mut files);
    let mut sites = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        // The definitions, their doc examples and the differential tests.
        if rel.ends_with("algo-validate/src/rules.rs") || rel.contains("/rules/") {
            continue;
        }
        let text = std::fs::read_to_string(&f).expect("source");
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim_start();
            if t.starts_with("#[cfg(test)]")
                && lines
                    .get(i + 1)
                    .is_some_and(|l| l.trim_start().starts_with("mod "))
            {
                break; // the test module: everything after is test code
            }
            if t.starts_with("//") || !t.contains("validate_transaction_wellformed") {
                continue;
            }
            if !t.contains('(') {
                continue; // an import or re-export
            }
            let call: String = lines[i..(i + 8).min(lines.len())].join(" ");
            let mode = if t.contains("validate_transaction_wellformed_in_mode(") {
                if call.contains("WellFormedMode::Admission") {
                    "admission"
                } else if call.contains("WellFormedMode::Block") {
                    "block"
                } else {
                    "unknown"
                }
            } else {
                "block"
            };
            sites.push((rel.clone(), mode));
        }
    }
    sites.sort();
    sites
}

#[test]
fn wellformed_callers_pass_the_intended_mode() {
    let got = call_sites();
    let want: Vec<(String, &str)> = vec![
        (
            "bin/algod-rust/src/commands/participate.rs".into(),
            "admission",
        ),
        (
            "bin/algod-rust/src/commands/participate.rs".into(),
            "admission",
        ),
        (
            "crates/core/algo-ledger/src/simulation/mod.rs".into(),
            "block",
        ),
        ("crates/core/algo-validate/src/block.rs".into(), "block"),
    ];
    assert_eq!(
        got, want,
        "a production caller of the WellFormed check changed: decide its mode (issue #2193)"
    );
}
