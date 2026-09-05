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

//! Terminal-safe output formatting helpers, porting
//! `../go-algorand/cmd/goal/formatting.go`'s `unicodePrintable` and
//! `encodeBytesAsAppCallBytes`.
//!
//! go's `goal asset info`/`goal app info` (and similar leaves that echo
//! back arbitrary bytes supplied by a transaction's sender, e.g. an ASA
//! unit-name/asset-name) run any such string through `unicodePrintable`
//! before printing it, so a malicious name embedding ANSI escape codes or
//! control characters can't corrupt the operator's terminal. goal-rust's
//! `asset` leaf is not yet ported (see `crate::groups::asset`), so there is
//! no live call site for `unicode_printable` itself yet — it is provided
//! now so that port can reuse it, and so `TestUnicodePrintable` parity is
//! pinned ahead of that work. [`encode_bytes_as_app_call_bytes`] (issue
//! #962) *is* wired into a live call site: `goal-rust app box info`/
//! `app box list` (`crate::cmd::app`).

/// Mirrors go's `unicodePrintable` (`cmd/goal/formatting.go:32-44`).
///
/// Returns `(is_printable, printable_string)`: `printable_string` is the
/// input with every non-printable `char` dropped (matching Go's
/// `unicode.IsPrint`), and `is_printable` is `false` iff at least one
/// `char` was dropped.
pub fn unicode_printable(s: &str) -> (bool, String) {
    let mut is_printable = true;
    let mut printable_string = String::with_capacity(s.len());
    for c in s.chars() {
        if !is_print(c) {
            is_printable = false;
        } else {
            printable_string.push(c);
        }
    }
    (is_printable, printable_string)
}

/// Mirrors Go's `unicode.IsPrint`: a rune is printable if it is in one of
/// the Letter, Mark, Number, Punctuation, Symbol, or (ASCII) Space
/// categories. Rust's `char::is_control` covers exactly the complement for
/// our purposes here (C0/C1 control codes, which is what every one of Go's
/// `TestUnicodePrintable` cases exercises), plus the U+FEFF byte-order-mark
/// which Go's table also excludes (`unicode.PrintRanges` — BOM is not a
/// Cf-category exclusion Go carves out, it's simply not in `L/M/N/P/S/Zs`).
fn is_print(c: char) -> bool {
    !c.is_control() && c != '\u{feff}'
}

/// Mirrors go's `encodeBytesAsAppCallBytes` (`cmd/goal/formatting.go:203-209`):
/// the reverse of [`crate::cmd::app::parse_app_call_bytes`]'s `str:`/`b64:`
/// forms, used to pretty-print an app-call argument or box name/value back
/// to the operator. Printable input (per [`unicode_printable`]) is rendered
/// as `str:<value>`; anything else as `b64:<standard-base64>`.
///
/// Go's `string(value)` reinterprets the raw bytes as UTF-8, decoding
/// invalid sequences rune-by-rune as `utf8.RuneError` (which is itself
/// printable), so a byte string with a handful of invalid UTF-8 bytes can
/// still round-trip as `str:`. We simplify slightly: bytes that aren't
/// valid UTF-8 at all always take the `b64:` branch, since real box
/// values/app-args are either legitimate UTF-8 text or opaque binary data,
/// not adversarially crafted to hit that boundary.
pub fn encode_bytes_as_app_call_bytes(value: &[u8]) -> String {
    use base64::Engine as _;
    if let Ok(s) = std::str::from_utf8(value) {
        let (is_printable, _) = unicode_printable(s);
        if is_printable {
            return format!("str:{s}");
        }
    }
    format!(
        "b64:{}",
        base64::engine::general_purpose::STANDARD.encode(value)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// Direct port of go's `TestUnicodePrintable`
    /// (`cmd/goal/formatting_test.go:28-48`).
    #[test]
    fn unicode_printable_matches_go_test_cases() {
        let cases: &[(&str, bool, &str)] = &[
            ("abc", true, "abc"),
            ("", true, ""),
            ("\u{05d0}\u{05d1}\u{05d2}", true, "\u{05d0}\u{05d1}\u{05d2}"),
            ("\u{001b}[31mABC\u{001b}[0m", false, "[31mABC[0m"),
            ("ab\nc", false, "abc"),
        ];
        for (input, expected_printable, expected_string) in cases {
            let (is_printable, printable_string) = unicode_printable(input);
            assert_eq!(is_printable, *expected_printable, "input: {input:?}");
            assert_eq!(printable_string, *expected_string, "input: {input:?}");
        }
    }

    // ---- encode_bytes_as_app_call_bytes --------------------------------
    // Direct port of go's `TestBytesToAppCallBytes`
    // (`cmd/goal/formatting_test.go:115-134`).

    #[test]
    fn encode_bytes_matches_go_test_cases() {
        assert_eq!(encode_bytes_as_app_call_bytes(b"unicode"), "str:unicode");
        assert_eq!(
            encode_bytes_as_app_call_bytes(&[1, 2, 3, 4]),
            "b64:AQIDBA=="
        );
    }

    #[test]
    fn encode_bytes_empty_is_printable_str() {
        assert_eq!(encode_bytes_as_app_call_bytes(b""), "str:");
    }

    #[test]
    fn encode_bytes_non_utf8_falls_back_to_b64() {
        let value = [0xffu8, 0xfe, 0x00, 0x01];
        assert_eq!(
            encode_bytes_as_app_call_bytes(&value),
            format!(
                "b64:{}",
                base64::engine::general_purpose::STANDARD.encode(value)
            )
        );
    }

    /// Parity property from issue #962's acceptance criteria:
    /// `encode_bytes_as_app_call_bytes` round-trips through
    /// `parse_app_call_bytes` — i.e. decoding a value in any of the
    /// `--app-arg`/`--box` encodings, re-encoding it for display, and
    /// decoding that display form again yields the same bytes.
    #[test]
    fn encode_then_parse_round_trips_every_input_encoding() {
        use crate::cmd::app::parse_app_call_bytes;

        let addr = algo_types::Address([0x42; 32]).to_algorand_string();
        let cases = vec![
            "str:hello world".to_string(),
            "int:123456789".to_string(),
            format!("addr:{addr}"),
            format!("b32:{}", data_encoding::BASE32.encode(b"box-name")),
            "b64:aGVsbG8=".to_string(),
            "abi:uint64:99".to_string(),
        ];
        for input in cases {
            let original_bytes = parse_app_call_bytes(&input).unwrap();
            let redisplayed = encode_bytes_as_app_call_bytes(&original_bytes);
            let round_tripped_bytes = parse_app_call_bytes(&redisplayed).unwrap();
            assert_eq!(
                round_tripped_bytes, original_bytes,
                "input {input:?} -> displayed as {redisplayed:?}"
            );
        }
    }
}
