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

//! Execution-level tests for the `match` opcode (v8, 0x8e) -- issue #823.
//!
//! Ported from go-algorand's `TestMatch`/`TestShortMatch`
//! (`data/transactions/logic/eval_test.go`). Stack effect per go's opcode
//! table: `"[A1, A2, ..., AN], B" -> ""` -- the match *target* `B` is
//! pushed LAST (top of stack), with the `N` case values `A1..AN` pushed
//! before it, in the same left-to-right order as the opcode's label list.
//!
//! Note: go's source uses `;` as a statement separator (e.g. `zero: int 1;
//! return`); this assembler treats `;` as a comment delimiter instead
//! (issue #847, filed while porting these tests), so each statement here
//! is written on its own line rather than ported verbatim.

use algo_avm::assembler::assemble_string;
use algo_avm::{parse, AvmMachine, ExecMode, NullContext};

/// Assemble and run a v8 LogicSig program, returning `Ok(pass)`.
fn run(source: &str) -> Result<bool, algo_error::AlgoError> {
    let full = format!("#pragma version 8\n{source}");
    let ops = assemble_string(&full).expect("assembly should succeed");
    let program = parse(&ops.program).unwrap();
    let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 20_000);
    machine.run(&mut NullContext)
}

#[test]
fn match_takes_zeroth_label_with_int_cases() {
    // target(99) equals case0(99) -> jump to `zero`, which returns 1 (pass).
    let result = run(r#"
int 99
int 100
int 99
match zero one
err
zero:
int 1
return
one:
int 0
"#);
    assert!(result.unwrap(), "should take the 0th label");
}

#[test]
fn match_takes_zeroth_label_with_bytes_cases() {
    let result = run(r#"
byte "0"
byte "1"
byte "0"
match zero one
err
zero:
int 1
return
one:
int 0
"#);
    assert!(result.unwrap(), "should take the 0th label");
}

#[test]
fn match_takes_first_label_with_int_cases() {
    // target(100) equals case1(100) -> jump to `one`, which pushes 0 (reject).
    let result = run(r#"
int 99
int 100
int 100
match zero one
err
zero:
int 1
return
one:
int 0
"#);
    assert!(!result.unwrap(), "should take the 1st label");
}

#[test]
fn match_takes_first_label_with_bytes_cases() {
    let result = run(r#"
byte "0"
byte "1"
byte "1"
match zero one
err
zero:
int 1
return
one:
int 0
"#);
    assert!(!result.unwrap(), "should take the 1st label");
}

#[test]
fn match_falls_through_when_no_case_matches() {
    // target(101) matches neither case0(99) nor case1(100) -> fall through
    // into `err`.
    let result = run(r#"
int 99
int 100
int 101
match zero one
err
zero:
int 1
return
one:
int 0
return
"#);
    assert!(result.is_err(), "no match should fall through to err");
}

#[test]
fn match_truncated_program_is_rejected() {
    // Ported from go-algorand's `TestShortMatch`
    // (`data/transactions/logic/eval_test.go`): a well-formed program
    // ending right at `match`'s own label targets must be rejected once
    // any of the label-list bytes (offsets, or the label count itself)
    // are chopped off the end -- a `match` opcode must not silently parse
    // as if its label list were shorter than what it declares.
    let source = "\nint 1\nint 40\nint 45\nint 40\nmatch label1 label2\nlabel1:\nlabel2:\n";
    let full = format!("#pragma version 8\n{source}");
    let ops = assemble_string(&full).expect("assembly should succeed");
    let full_program = ops.program.clone();

    // The full, untruncated program parses successfully.
    assert!(parse(&full_program).is_ok(), "full program should parse");

    for cut in 1..=5 {
        assert!(
            full_program.len() > cut,
            "test program too short to truncate by {cut} bytes"
        );
        let truncated = &full_program[..full_program.len() - cut];
        assert!(
            parse(truncated).is_err(),
            "truncating the match label list by {cut} byte(s) should be rejected"
        );
    }
}

#[test]
fn match_with_single_case() {
    let result = run(r#"
int 42
int 42
match only
int 0
return
only:
int 1
return
"#);
    assert!(result.unwrap(), "single case should match");
}
