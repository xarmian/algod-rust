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

//! Disassembly parity with go-algorand's `logic.Disassemble` (issue #2367, epic
//! #2364): every minimal byte program in `tests/fixtures/disasm_go_parity.jsonl`
//! is disassembled and compared with the text or error string the pinned
//! go-algorand produced for it. The fixture is generated from the Go driver by
//! `scripts/teal-corpus/disasm_fixtures.py` (never from this implementation);
//! each case is the smallest program of one mismatch class the registry corpus
//! run surfaced.

use algo_avm::disassembler::disassemble;
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/disasm_go_parity.jsonl");

#[test]
fn disassemble_matches_go_on_every_regression_case() {
    let mut failures = Vec::new();
    let mut n = 0;
    for line in FIXTURE.lines().filter(|l| !l.is_empty()) {
        n += 1;
        let case: Value = serde_json::from_str(line).expect("fixture row is JSON");
        let name = case["name"].as_str().expect("name");
        let program = hex::decode(case["program_hex"].as_str().expect("program_hex"))
            .expect("program_hex is hex");
        let got = disassemble(&program);
        let want: Result<String, String> = if case["ok"].as_bool().expect("ok") {
            Ok(case["text"].as_str().expect("text").to_string())
        } else {
            Err(case["error"].as_str().expect("error").to_string())
        };
        if got != want {
            failures.push(format!(
                "{name} ({}): program {}\n  go:   {want:?}\n  rust: {got:?}",
                case["class"].as_str().unwrap_or("?"),
                case["program_hex"].as_str().unwrap_or("?"),
            ));
        }
    }
    assert!(n > 50, "fixture unexpectedly small: {n} cases");
    assert!(
        failures.is_empty(),
        "{} of {n} cases differ from go-algorand:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
