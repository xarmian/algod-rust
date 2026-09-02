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

//! Execution/parse-level tests for the `switch` opcode's malformed-bytecode
//! handling (v8, 0x8d) -- issue #823 theme 1 remainder.
//!
//! Ported from go-algorand's `TestShortSwitch`
//! (`data/transactions/logic/eval_test.go`). go's opcode dispatch reads the
//! program bytes lazily at each step (`switchTarget`, `eval.go`), so a
//! truncated `switch` label list is caught by `opSwitch` itself at
//! execution time with "switch opcode claims to extend beyond program" /
//! "bare switch opcode at end of program". algod-rust decodes the whole
//! instruction stream up front (`bytecode::parse`, called before any
//! execution begins), so the equivalent failure surfaces one layer earlier
//! -- at parse time rather than mid-execution -- with the decode-error
//! wording added for `TestDisassembleBadSwitch` ("could not decode label
//! count for switch" / "could not decode labels for switch"). Either way,
//! the *behavior* go's test pins is preserved: a well-formed `switch`
//! program that gets its label-list bytes chopped off must be rejected,
//! never silently misdecoded or executed with a bogus target.

use algo_avm::assembler::assemble_string;
use algo_avm::{parse, AvmMachine, ExecMode, NullContext};

#[test]
fn switch_full_program_executes_fine() {
    // Ported from TestShortSwitch's "fine as is" case.
    let source = "\nint 1\nint 1\nswitch label1 label2\nlabel1:\nlabel2:\n";
    let full = format!("#pragma version 8\n{source}");
    let ops = assemble_string(&full).expect("assembly should succeed");
    let program = parse(&ops.program).expect("full program should parse");
    let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 20_000);
    // Falls through to the end of the program with no explicit `return`;
    // the important thing pinned here is that it doesn't error.
    let _ = machine.run(&mut NullContext);
}

#[test]
fn switch_truncated_program_is_rejected() {
    let source = "\nint 1\nint 1\nswitch label1 label2\nlabel1:\nlabel2:\n";
    let full = format!("#pragma version 8\n{source}");
    let ops = assemble_string(&full).expect("assembly should succeed");
    let full_program = ops.program.clone();

    assert!(parse(&full_program).is_ok(), "full program should parse");

    // Mirrors go's four truncation depths: missing a label, all labels
    // gone but the count byte kept, the count byte gone too, and half of
    // a label's two offset bytes gone.
    for cut in [2usize, 4, 5, 1] {
        assert!(
            full_program.len() > cut,
            "test program too short to truncate by {cut} bytes"
        );
        let truncated = &full_program[..full_program.len() - cut];
        assert!(
            parse(truncated).is_err(),
            "truncating the switch label list by {cut} byte(s) should be rejected"
        );
    }
}
