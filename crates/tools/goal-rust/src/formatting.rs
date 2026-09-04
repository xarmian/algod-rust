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
//! `../go-algorand/cmd/goal/formatting.go`'s `unicodePrintable`.
//!
//! go's `goal asset info`/`goal app info` (and similar leaves that echo
//! back arbitrary bytes supplied by a transaction's sender, e.g. an ASA
//! unit-name/asset-name) run any such string through `unicodePrintable`
//! before printing it, so a malicious name embedding ANSI escape codes or
//! control characters can't corrupt the operator's terminal. goal-rust's
//! `asset`/`app` leaves are not yet ported (see
//! `crate::groups::asset`/`crate::groups::app`), so there is no live call
//! site to wire this into yet — it is provided now so that port can reuse
//! it, and so `TestUnicodePrintable` parity is pinned ahead of that work.

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
