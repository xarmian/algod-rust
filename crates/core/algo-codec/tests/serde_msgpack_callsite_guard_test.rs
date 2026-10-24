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

//! Issue #2042 guard: a direct `rmp_serde::to_vec*` of a transaction/block
//! bearing type leaks the non-UTF-8 placeholder ext (tag 0x5a) instead of
//! go's `str`. Production code must call
//! `algo_codec::to_vec_named_str_preserving`; this scan fails when a new
//! direct call appears in a production source file that is not allow-listed
//! below with a justification (types that cannot contain `AssetParams`, or
//! local crash state decoded back inside `with_ext_accepted`).

use std::path::{Path, PathBuf};

/// (path suffix, why a direct rmp_serde encode is fine there)
const ALLOWED: &[(&str, &str)] = &[
    ("algo-codec/src/lib.rs", "the wrapper itself"),
    (
        "algo-agreement/src/persistence.rs",
        "local crash state; decoded inside with_ext_accepted",
    ),
    (
        "algo-agreement/src/trace.rs",
        "local cadaver trace, never wire",
    ),
    (
        "algo-ledger/src/catchpoint/importer.rs",
        "state-proof verification context: no AssetParams",
    ),
    ("algo-kmd/src/api_v1.rs", "MultisigSig only"),
    (
        "algo-kmd/src/crypto.rs",
        "typedPlaintext / db blob wire structs",
    ),
    ("algo-p2p/src/wsproto.rs", "string headers"),
];

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if p.is_dir() {
            if name == "target" || name == "tests" || name == "benches" || name == ".git" {
                continue;
            }
            walk(&p, out);
        } else if name.ends_with(".rs")
            && !name.ends_with("_test.rs")
            && !name.ends_with("_tests.rs")
        {
            out.push(p);
        }
    }
}

#[test]
fn no_unreviewed_direct_serde_msgpack_encode_in_production_code() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut files = Vec::new();
    for sub in ["crates", "bin", "tools"] {
        walk(&root.join(sub), &mut files);
    }
    assert!(
        files.len() > 100,
        "scan found too few files: {}",
        files.len()
    );
    let mut offenders = Vec::new();
    for f in files {
        let norm = f.to_string_lossy().replace('\\', "/");
        if ALLOWED.iter().any(|(s, _)| norm.ends_with(s)) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&f) else {
            continue;
        };
        for (i, line) in src.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("#[cfg(test)]") {
                break; // test modules follow production code
            }
            if t.starts_with("//") {
                continue;
            }
            if line.contains("rmp_serde::to_vec") || line.contains("rmp_serde::encode::to_vec") {
                offenders.push(format!("{norm}:{}: {}", i + 1, t));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "direct rmp_serde encode in production code; use algo_codec::to_vec_named_str_preserving \
         or add a justified entry to ALLOWED:\n{}",
        offenders.join("\n")
    );
}
