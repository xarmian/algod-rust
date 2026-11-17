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

//! Assembling TEAL source that is not UTF-8 (issue #2388, epic #2364).
//!
//! go's `logic.AssembleString(string(body))` takes any byte string: a string
//! literal keeps its raw bytes, a comment is ignored, and an invalid byte in an
//! error message is rendered by the caller (`\ufffd` in the JSON of
//! `/v2/teal/compile`, `\xNN` through `%#v`). Every expectation below was
//! produced by go-algorand v5.0.5-stable (`POST /v2/teal/compile` on a real
//! node; the `result` is the base64 of the program, the messages are the
//! decoded JSON `message`).

use algo_avm::assembler::{assemble_bytes, assemble_bytes_checked, assemble_string};
use base64::Engine as _;

/// go's `json.Marshal` view of a byte string: every invalid byte is one
/// U+FFFD (what the compile handler's JSON shows).
fn go_json_view(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        for _ in chunk.invalid() {
            out.push('\u{fffd}');
        }
    }
    out
}

/// A program that assembles: the source and the base64 of the go program.
const OK_CASES: &[(&str, &[u8], &str)] = &[
    (
        "invalid bytes in a string literal are kept (the #2388 probe)",
        b"#pragma version 8\nbyte \"\xff\xfe\"\nint 1\n",
        "CIAC//6BAQ==",
    ),
    (
        "invalid bytes in a comment are ignored",
        b"#pragma version 8\nint 1 // \xff\xfe comment\n",
        "CIEB",
    ),
    (
        "an invalid byte in a label",
        b"#pragma version 8\nint 1 // ok\n\xfe:\nint 1\n",
        "CCABASIi",
    ),
    (
        "valid private-use characters in a literal keep their bytes",
        b"#pragma version 8\nbyte \"\xf4\x8f\xbc\x80\xf4\x8f\xbf\xbf\"\nint 1\n",
        "CIAI9I+8gPSPv7+BAQ==",
    ),
    (
        "a truncated sequence after valid text in a literal",
        b"#pragma version 8\nbyte \"\xc3\xa9\xe2\"\nint 1\n",
        "CIADw6nigQE=",
    ),
    (
        "method of an invalid signature",
        b"#pragma version 8\nmethod \"\xff\"\n",
        "CIAEpor/GQ==",
    ),
];

#[test]
fn programs_assemble_to_go_bytes() {
    for (name, source, want_b64) in OK_CASES {
        let ops =
            assemble_bytes(source).unwrap_or_else(|e| panic!("{name}: assembly failed: {e:?}"));
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(&ops.program),
            *want_b64,
            "{name}"
        );
    }
}

/// A source that fails: the source, then go's `(line, col, message)` list.
type ErrCase = (
    &'static str,
    &'static [u8],
    &'static [(usize, usize, &'static str)],
);

const ERR_CASES: &[ErrCase] = &[
    (
        "invalid byte after an opcode name",
        b"#pragma version 8\nfoo\xff\nint 1\n",
        &[(2, 0, "unknown opcode: foo\u{fffd}")],
    ),
    (
        "invalid byte as the mnemonic",
        b"#pragma version 8\n\xff foo\nint 1\n",
        &[(2, 0, "unknown opcode: \u{fffd}")],
    ),
    (
        "macro name with an invalid byte",
        b"#pragma version 8\n#define \xff 1\nint 1\n",
        &[(2, 8, "\u{fffd} character not allowed in macro name")],
    ),
    (
        "int immediate",
        b"#pragma version 8\nint \xff\n",
        &[(2, 4, "unable to parse \"\\xff\" as integer")],
    ),
    (
        "int immediate with a trailing invalid byte",
        b"#pragma version 8\nint 1\x80\n",
        &[(2, 4, "unable to parse \"1\\x80\" as integer")],
    ),
    (
        "hex literal: the byte, not its UTF-8 form",
        b"#pragma version 8\nbyte 0x\xffab\n",
        &[(2, 5, "byte encoding/hex: invalid byte: U+00FF '\u{ff}'")],
    ),
    (
        "hex literal with a valid private-use character",
        b"#pragma version 8\nbyte 0x\xf4\x8f\xbc\x80\n",
        &[(2, 5, "byte encoding/hex: invalid byte: U+00F4 '\u{f4}'")],
    ),
    (
        "bad hex escape in a string literal",
        b"#pragma version 8\nbyte \"\\x\xff\xfe\"\n",
        &[(
            2,
            5,
            "byte strconv.ParseUint: parsing \"\\xff\\xfe\": invalid syntax",
        )],
    ),
    (
        "base64(...) offsets are byte offsets",
        b"#pragma version 8\nbyte b64(\xff)\n",
        &[(2, 5, "byte illegal base64 data at input byte 4")],
    ),
    (
        "base64 argument",
        b"#pragma version 8\nbyte b64 \xff\xfe\n",
        &[(2, 9, "byte illegal base64 data at input byte 0")],
    ),
    (
        "valid private-use character after an opcode name",
        b"#pragma version 8\nfoo\xf4\x8f\xbc\x80\nint 1\n",
        &[(2, 0, "unknown opcode: foo\u{10FF00}")],
    ),
    (
        "pragma version argument",
        b"#pragma version \xff\n",
        &[(1, 16, "bad #pragma version: \"\\xff\"")],
    ),
    (
        "pragma directive",
        b"#pragma \xff 1\n",
        &[(1, 0, "unsupported pragma directive: \"\\xff\"")],
    ),
    (
        "field name",
        b"#pragma version 8\ntxn \xff\n",
        &[(2, 4, "txn unknown field: \"\\xff\"")],
    ),
    (
        "the whole program is invalid",
        b"\xff\xfe",
        &[(1, 0, "unknown opcode: \u{fffd}\u{fffd}")],
    ),
    (
        "an invalid byte followed by an ASCII byte",
        b"#pragma version 8\n\xc3\x28 foo\n",
        &[(2, 0, "unknown opcode: \u{fffd}(")],
    ),
    (
        "every byte of a truncated sequence is one replacement",
        b"#pragma version 8\nint 1\n\xe2\x82 \n",
        &[(3, 0, "unknown opcode: \u{fffd}\u{fffd}")],
    ),
    (
        "addr",
        b"#pragma version 8\naddr \xff\n",
        &[(2, 5, "failed to decode address \u{fffd} from base 32")],
    ),
    (
        "second statement of a line",
        b"#pragma version 8\nint 1; \xff; int 2\n",
        &[(2, 7, "unknown opcode: \u{fffd}")],
    ),
];

#[test]
fn errors_match_go() {
    for (name, source, want) in ERR_CASES {
        let errors = match assemble_bytes(source) {
            Ok(_) => panic!("{name}: assembled, go rejects it"),
            Err(e) => e,
        };
        let got: Vec<(usize, usize, String)> = errors
            .iter()
            .map(|e| (e.line, e.col, go_json_view(&e.message_bytes())))
            .collect();
        let want: Vec<(usize, usize, String)> = want
            .iter()
            .map(|(l, c, m)| (*l, *c, (*m).to_string()))
            .collect();
        assert_eq!(got, want, "{name}");
    }
}

/// `report_multiple_errors_bytes` is the text the compile handler and goal
/// print: raw bytes, one error per line.
#[test]
fn report_keeps_raw_bytes() {
    let source = b"#pragma version 8\nfoo\xff\nint 1\n";
    let (failure, warnings) = algo_avm::assembler::assemble_bytes_reported(source)
        .err()
        .expect("fails");
    let algo_avm::assembler::AssembleFailure::Errors(errors) = failure else {
        panic!("not an error list");
    };
    assert_eq!(
        algo_avm::assembler::report_multiple_errors_bytes("", &errors, &warnings),
        b"1 error: 2: unknown opcode: foo\xff\n".to_vec()
    );
}

/// The `&str` entry points are unchanged, including for a valid private-use
/// character (which the byte-preserving representation reserves).
#[test]
fn str_entry_points_agree_with_bytes() {
    let src = "#pragma version 8\nbyte \"\u{10FF00}\u{e9}\"\nint 1\n";
    let a = assemble_string(src).expect("str assembles");
    let b = assemble_bytes(src.as_bytes()).expect("bytes assemble");
    assert_eq!(a.program, b.program);
    assert_eq!(
        a.program,
        vec![0x08, 0x80, 0x06, 0xf4, 0x8f, 0xbc, 0x80, 0xc3, 0xa9, 0x81, 0x01]
    );

    let Err(errs) = assemble_string("#pragma version 8\nfoo\u{10FF00}\n") else {
        panic!("assembled");
    };
    assert_eq!(
        errs[0].message_bytes(),
        "unknown opcode: foo\u{10FF00}".as_bytes()
    );
}

/// Never a panic, whatever the bytes are.
#[test]
fn arbitrary_bytes_never_panic() {
    let prefixes: [&[u8]; 4] = [b"", b"#pragma version 8\n", b"byte \"", b"#define "];
    for p in prefixes {
        for b in 0u8..=255 {
            let mut src = p.to_vec();
            src.push(b);
            src.extend_from_slice(b" 1\n");
            let _ = assemble_bytes_checked(&src);
            let mut src2 = p.to_vec();
            src2.extend_from_slice(&[b, b, b]);
            let _ = assemble_bytes_checked(&src2);
        }
    }
    // Overlongs, a surrogate, an out-of-range lead and truncated four-byte
    // sequences (one of them the prefix of a private-use character).
    for src in [
        &b"\xed\xa0\x80"[..],
        b"\xc0\xaf",
        b"\xf4\x90\x80\x80",
        b"\xf4\x8f\xbc",
        b"int \xf4\x8f\xbc\x80\xf4\x8f\xbc",
    ] {
        let _ = assemble_bytes_checked(src);
    }
}
