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

//! go's assembler panics on a constant scratch index >= 256 (`typeStores` /
//! `typeLoads`, issue #2381). The Rust driver emits the same `panic` row for
//! that input without panicking, so the diff sees identical rows: parity by
//! construction. Any other panic still fails the diff.

use std::path::PathBuf;
use std::sync::Arc;

use teal_corpus::{diff_files, has_robustness_failure, process, Input, Operation};

fn tmp(name: &str, lines: &[&str]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("teal-corpus-panic-{}", std::process::id()));
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

const PANIC_300: &str = "runtime error: index out of range [300] with length 256";

#[test]
fn the_rust_driver_emits_go_s_panic_row_for_a_constant_scratch_index_of_300() {
    let src = "#pragma version 14\nint 300\nbyte 0x\nstores";
    let input = Input {
        sha256: "a".to_string(),
        bytes: Arc::new(src.as_bytes().to_vec()),
    };
    let row = process(Operation::Assemble, &input);
    assert!(!row.ok);
    assert_eq!(row.panic.as_deref(), Some(PANIC_300));
    assert_eq!(
        serde_json::to_string(&row).unwrap(),
        format!(r#"{{"ok":false,"panic":"{PANIC_300}","sha256":"a"}}"#)
    );
    // Typed, not a real panic: the batch is not a robustness failure.
    assert!(!has_robustness_failure(&[row]));
}

#[test]
fn identical_panic_rows_are_parity_not_a_failure() {
    let row = format!(r#"{{"ok":false,"panic":"{PANIC_300}","sha256":"a"}}"#);
    let rep = diff_files(&tmp("go1.jsonl", &[&row]), &tmp("rust1.jsonl", &[&row])).unwrap();
    assert!(rep.mismatches.is_empty(), "{:?}", rep.mismatches);
    assert_eq!(rep.robustness_failures, 0);
    assert_eq!(rep.both_panic_identical, 1);
}

#[test]
fn an_identical_panic_of_any_other_kind_is_still_a_failure() {
    let row = r#"{"ok":false,"panic":"boom","sha256":"a"}"#;
    let rep = diff_files(&tmp("go5.jsonl", &[row]), &tmp("rust5.jsonl", &[row])).unwrap();
    assert_eq!(rep.robustness_failures, 2);
    assert_eq!(rep.both_panic_identical, 0);
}

#[test]
fn a_go_panic_against_any_rust_row_is_still_a_mismatch_and_a_failure() {
    let go = format!(r#"{{"ok":false,"panic":"{PANIC_300}","sha256":"a"}}"#);
    let rust_rows = [
        r#"{"bytecode_b64":"AA==","hash":"h","ok":true,"sha256":"a"}"#,
        r#"{"errors":[{"col":0,"line":1,"message":"nope"}],"ok":false,"sha256":"a"}"#,
        r#"{"ok":false,"panic":"runtime error: index out of range [3] with length 256","sha256":"a"}"#,
    ];
    for r in rust_rows {
        let rep = diff_files(&tmp("go2.jsonl", &[&go]), &tmp("rust2.jsonl", &[r])).unwrap();
        assert_eq!(rep.mismatches.len(), 1, "{r}");
        assert!(rep.robustness_failures >= 1, "{r}");
        assert_eq!(rep.both_panic_identical, 0, "{r}");
    }
}
