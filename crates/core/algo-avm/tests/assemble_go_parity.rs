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

//! Assembly parity with go-algorand's `logic.AssembleString` (issue #2368, epic
//! #2364): every minimal TEAL source in `tests/fixtures/asm_go_parity.jsonl` is
//! assembled and compared with the bytecode, or the ordered error list (line,
//! column, message), and the warnings the pinned go-algorand produced for it. The
//! fixture is generated from the Go driver by
//! `scripts/teal-corpus/asm_fixtures.py` (never from this implementation); each
//! case is the smallest source of one mismatch class the registry reassembly
//! corpus run (and the type-tracking port) surfaced.

use algo_avm::assembler::assemble_bytes;
use base64::Engine as _;
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/asm_go_parity.jsonl");

fn diags(v: &Value) -> Vec<(u64, u64, String)> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|d| {
                    (
                        d["line"].as_u64().expect("line"),
                        d["col"].as_u64().expect("col"),
                        d["message"].as_str().expect("message").to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A message as go's `encoding/json` shows it (what the fixture stores): every
/// byte that is not part of a valid UTF-8 sequence is one U+FFFD.
fn go_json_message(bytes: &[u8]) -> String {
    algo_avm::raw_text::go_lossy(bytes)
}

#[test]
fn assemble_matches_go_on_every_regression_case() {
    let mut failures = Vec::new();
    let mut n = 0;
    for line in FIXTURE.lines().filter(|l| !l.is_empty()) {
        n += 1;
        let case: Value = serde_json::from_str(line).expect("fixture row is JSON");
        let name = case["name"].as_str().expect("name");
        // A source that is not UTF-8 is stored as `source_b64` (issue #2388).
        let source: Vec<u8> = match case["source"].as_str() {
            Some(s) => s.as_bytes().to_vec(),
            None => base64::engine::general_purpose::STANDARD
                .decode(case["source_b64"].as_str().expect("source or source_b64"))
                .expect("source_b64 is base64"),
        };
        let (got_ok, got_bytes, got_errors, got_warnings) = match assemble_bytes(&source) {
            Ok(ops) => (
                true,
                base64::engine::general_purpose::STANDARD.encode(&ops.program),
                vec![],
                ops.warnings
                    .iter()
                    .map(|w| {
                        (
                            w.line as u64,
                            w.col as u64,
                            go_json_message(&w.message_bytes()),
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
            Err(errs) => (
                false,
                String::new(),
                errs.iter()
                    .map(|e| {
                        (
                            e.line as u64,
                            e.col as u64,
                            go_json_message(&e.message_bytes()),
                        )
                    })
                    .collect::<Vec<_>>(),
                vec![],
            ),
        };
        let want_ok = case["ok"].as_bool().expect("ok");
        let want_bytes = case["bytecode_b64"].as_str().unwrap_or("").to_string();
        let want_errors = diags(&case["errors"]);
        let want_warnings = diags(&case["warnings"]);
        let same = want_ok == got_ok
            && want_bytes == got_bytes
            && want_errors == got_errors
            && want_warnings == got_warnings;
        if !same {
            failures.push(format!(
                "{name} ({}):\n  go:   ok={want_ok} bytecode={want_bytes} errors={want_errors:?} warnings={want_warnings:?}\n  rust: ok={got_ok} bytecode={got_bytes} errors={got_errors:?} warnings={got_warnings:?}",
                case["class"].as_str().unwrap_or("?"),
            ));
        }
    }
    assert!(n > 100, "fixture unexpectedly small: {n} cases");
    assert!(
        failures.is_empty(),
        "{} of {n} cases differ from go-algorand:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
