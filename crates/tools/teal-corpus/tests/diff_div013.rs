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

//! The one documented Go-panic / Rust-error pairing of the diff command
//! (DIV-013, #2381): go's assembler panics on a constant scratch index >= 256
//! (`typeStores`/`typeLoads`), algod-rust reports an assembly error. Exactly
//! that pairing is classified as a known divergence; every other panic, and
//! any Rust-side panic, still fails the diff.

use std::path::PathBuf;

use teal_corpus::diff_files;

fn tmp(name: &str, lines: &[&str]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("teal-corpus-div013-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    let mut text = String::from("{\"header\":{\"operation\":\"assemble\"}}\n");
    for l in lines {
        text.push_str(l);
        text.push('\n');
    }
    std::fs::write(&p, text).unwrap();
    p
}

const GO_PANIC: &str = r#"{"ok":false,"panic":"runtime error: index out of range [300] with length 256","sha256":"a"}"#;
const RUST_ERR: &str = r#"{"errors":[{"col":0,"line":4,"message":"stores: constant scratch index 300 is out of range (must be < 256)"}],"ok":false,"sha256":"a"}"#;

#[test]
fn the_documented_scratch_index_pairing_is_a_known_divergence() {
    let go = tmp("go1.jsonl", &[GO_PANIC]);
    let rust = tmp("rust1.jsonl", &[RUST_ERR]);
    let rep = diff_files(&go, &rust).unwrap();
    assert!(rep.mismatches.is_empty(), "{:?}", rep.mismatches);
    assert_eq!(rep.robustness_failures, 0);
    assert_eq!(rep.known_divergences, 1);
}

#[test]
fn any_other_go_panic_still_fails_the_diff() {
    let other = r#"{"ok":false,"panic":"runtime error: index out of range [3] with length 2","sha256":"a"}"#;
    let go = tmp("go2.jsonl", &[other]);
    let rust = tmp("rust2.jsonl", &[RUST_ERR]);
    let rep = diff_files(&go, &rust).unwrap();
    assert_eq!(rep.known_divergences, 0);
    assert_eq!(rep.mismatches.len(), 1);
    assert_eq!(rep.robustness_failures, 1);
}

#[test]
fn the_go_panic_against_a_rust_success_or_a_different_error_is_a_mismatch() {
    let ok = r#"{"bytecode_b64":"AA==","hash":"h","ok":true,"sha256":"a"}"#;
    let other = r#"{"errors":[{"col":0,"line":1,"message":"nope"}],"ok":false,"sha256":"a"}"#;
    for rust_row in [ok, other] {
        let go = tmp("go3.jsonl", &[GO_PANIC]);
        let rust = tmp("rust3.jsonl", &[rust_row]);
        let rep = diff_files(&go, &rust).unwrap();
        assert_eq!(rep.known_divergences, 0, "{rust_row}");
        assert_eq!(rep.mismatches.len(), 1, "{rust_row}");
    }
}

#[test]
fn a_rust_panic_is_never_excused() {
    let rust_panic =
        r#"{"ok":false,"panic":"index out of range [300] with length 256","sha256":"a"}"#;
    let go = tmp("go4.jsonl", &[GO_PANIC]);
    let rust = tmp("rust4.jsonl", &[rust_panic]);
    let rep = diff_files(&go, &rust).unwrap();
    assert_eq!(rep.known_divergences, 0);
    assert!(rep.robustness_failures >= 1);
}
