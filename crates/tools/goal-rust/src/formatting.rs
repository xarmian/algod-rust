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
    // go ranges over the runes of the bytes it kept: each invalid byte of a
    // text in the lossless `raw_text` form is a `RuneError`, which is printable
    let lossy;
    let s = if algo_types::raw_text::has_raw(s) {
        lossy = algo_types::raw_text::go_lossy(&algo_types::raw_text::decode(s));
        lossy.as_str()
    } else {
        s
    };
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

/// go's `errorNonPrintableCharacters` (`cmd/goal/messages.go`).
pub const ERROR_NON_PRINTABLE_CHARACTERS: &str =
    "One or more non-printable characters were omitted from the following error message:";

/// The text go's `reportErrorln` / `reportErrorf` (`cmd/goal/commands.go`)
/// prints for `msg`, without the final newline: each line through
/// [`unicode_printable`], a line that lost anything preceded by
/// [`ERROR_NON_PRINTABLE_CHARACTERS`].
pub fn report_error_text(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    for (i, line) in msg.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        // a raw byte of the lossless form is go's RuneError, printable
        let line = algo_types::raw_text::go_lossy(&algo_types::raw_text::decode(line));
        let (printable, printable_line) = unicode_printable(&line);
        if !printable {
            out.push_str(ERROR_NON_PRINTABLE_CHARACTERS);
            out.push('\n');
        }
        out.push_str(&printable_line);
    }
    out
}

/// go's `infoNonPrintableCharacters` (`cmd/goal/messages.go`).
pub const INFO_NON_PRINTABLE_CHARACTERS: &str =
    "One or more non-printable characters were omitted from the subsequent line:";

/// What go's `reportInfoln` / `reportInfof` prints for `msg` (to stdout):
/// each line through [`unicode_printable`] and a newline, a line that lost
/// anything preceded by [`INFO_NON_PRINTABLE_CHARACTERS`].
pub fn report_info_text(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len() + 1);
    for line in msg.split('\n') {
        let (printable, printable_line) = unicode_printable(line);
        if !printable {
            out.push_str(INFO_NON_PRINTABLE_CHARACTERS);
            out.push('\n');
        }
        out.push_str(&printable_line);
        out.push('\n');
    }
    out
}

/// Mirrors Go's `unicode.IsPrint` (letters, marks, numbers, punctuation,
/// symbols and the ASCII space; not controls, format characters, private use,
/// unassigned code points or non-ASCII spaces): the assembler's port, which
/// also decides what `%#v` quotes.
fn is_print(c: char) -> bool {
    algo_avm::assembler::go_is_print(c)
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

/// go's `assetDecimalsFmt` (`cmd/goal/asset.go`): `amount` with `decimals`
/// digits after the point (go's `pow` wraps like any `uint64`).
pub fn asset_decimals_fmt(amount: u64, decimals: u64) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let mut pow = 1u64;
    for _ in 0..decimals.min(64) {
        pow = pow.wrapping_mul(10);
    }
    if pow == 0 {
        // go: an integer divide by zero; no asset has 64 decimals
        return amount.to_string();
    }
    format!(
        "{}.{:0width$}",
        amount / pow,
        amount % pow,
        width = usize::try_from(decimals).unwrap_or(usize::MAX)
    )
}

/// go's `unicodePrintable(s)`'s printable string.
pub fn printable(s: &str) -> String {
    unicode_printable(s).1
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn asset_decimals_fmt_matches_go() {
        assert_eq!(asset_decimals_fmt(12345, 0), "12345");
        assert_eq!(asset_decimals_fmt(12345, 3), "12.345");
        assert_eq!(asset_decimals_fmt(1, 3), "0.001");
        assert_eq!(asset_decimals_fmt(u64::MAX, 19), "1.8446744073709551615");
        // go's pow wraps: 10^20 mod 2^64
        assert_eq!(asset_decimals_fmt(u64::MAX, 20), "2.02914184810805067775");
    }

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

/// go's `fmt.Printf` of a string that kept the bytes of an algod answer
/// (go-codec's `string`): written byte for byte, a text in the lossless form
/// of [`algo_types::raw_text`] giving its original bytes back.
pub fn print_raw(text: &str) {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(&algo_types::raw_text::decode(text));
}

/// [`print_raw`] of a formatted text.
#[macro_export]
macro_rules! print_raw {
    ($($arg:tt)*) => {
        $crate::formatting::print_raw(&format!($($arg)*))
    };
}

/// [`print_raw!`] and a newline (go's `fmt.Println` / `Printf("...
")`).
#[macro_export]
macro_rules! println_raw {
    ($($arg:tt)*) => {
        $crate::formatting::print_raw(&format!("{}
", format!($($arg)*)))
    };
}
