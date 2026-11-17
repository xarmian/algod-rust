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

//! A lossless `String` view of an arbitrary byte string (issue #2388).
//!
//! go's `logic.AssembleString(string(body))` takes any byte string: a Go
//! `string` is not required to be UTF-8, so a string literal keeps raw bytes
//! and an invalid byte in a comment is ignored. The assembler front end here
//! works on `&str`, so source text goes through this representation first:
//!
//! * every byte that is not part of a valid UTF-8 sequence becomes the
//!   private-use character `U+10FF00 + byte` (a *raw* character);
//! * a *valid* character in the same range (`U+10FF00..=U+10FFFF`, four bytes
//!   each) is also represented as its four bytes' raw characters, so the
//!   mapping is a bijection: [`decode`] returns exactly the original bytes.
//!
//! Text that contains no byte `0xF4` and is valid UTF-8 (every real source) is
//! borrowed unchanged. Strings holding raw characters are only ever produced
//! by [`encode`]/[`encode_str`] and turned back into bytes by [`decode`];
//! diagnostics built from them (`AssemblyError::message`) stay in this form
//! and are read through `message_bytes()`.

use std::borrow::Cow;

/// First code point of the raw range: raw byte `b` is `U+10FF00 + b`.
const RAW_BASE: u32 = 0x10FF00;

fn is_raw(c: char) -> bool {
    (RAW_BASE..RAW_BASE + 0x100).contains(&(c as u32))
}

fn raw_char(b: u8) -> char {
    char::from_u32(RAW_BASE + u32::from(b)).expect("U+10FF00..=U+10FFFF are valid scalar values")
}

/// Whether `s` contains a raw character.
pub fn has_raw(s: &str) -> bool {
    // U+10FF00..=U+10FFFF are F4 8F BC 80 .. F4 8F BF BF.
    s.as_bytes().contains(&0xF4) && s.chars().any(is_raw)
}

/// The lossless `String` form of `bytes`.
pub fn encode(bytes: &[u8]) -> Cow<'_, str> {
    match std::str::from_utf8(bytes) {
        Ok(s) => encode_str(s),
        Err(_) => {
            let mut out = String::with_capacity(bytes.len());
            for chunk in bytes.utf8_chunks() {
                push_valid(&mut out, chunk.valid());
                for &b in chunk.invalid() {
                    out.push(raw_char(b));
                }
            }
            Cow::Owned(out)
        }
    }
}

/// The lossless form of valid UTF-8 text: unchanged unless it holds a
/// character of the raw range.
pub fn encode_str(s: &str) -> Cow<'_, str> {
    if !has_raw(s) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    push_valid(&mut out, s);
    Cow::Owned(out)
}

fn push_valid(out: &mut String, valid: &str) {
    for c in valid.chars() {
        if is_raw(c) {
            let mut buf = [0u8; 4];
            for &b in c.encode_utf8(&mut buf).as_bytes() {
                out.push(raw_char(b));
            }
        } else {
            out.push(c);
        }
    }
}

/// The original bytes of a lossless string: raw characters are their byte,
/// everything else its UTF-8 encoding.
pub fn decode(s: &str) -> Cow<'_, [u8]> {
    if !has_raw(s) {
        return Cow::Borrowed(s.as_bytes());
    }
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        if is_raw(c) {
            out.push((c as u32 - RAW_BASE) as u8);
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    Cow::Owned(out)
}

/// The byte length of the original text (go's `len(string)`).
pub fn raw_len(s: &str) -> usize {
    if !has_raw(s) {
        return s.len();
    }
    s.chars()
        .map(|c| if is_raw(c) { 1 } else { c.len_utf8() })
        .sum()
}

/// go's `string(r)` / `json.Marshal` view of a byte string: every byte that is
/// not part of a valid UTF-8 sequence is one U+FFFD (go decodes an invalid byte
/// as `RuneError` of width 1, unlike `String::from_utf8_lossy`, which folds a
/// truncated sequence into one replacement).
pub fn go_lossy(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        for _ in chunk.invalid() {
            out.push('\u{fffd}');
        }
    }
    out
}

/// go's rune iteration (`for _, r := range s`) over a lossless string: valid
/// characters as they are, each invalid byte as U+FFFD.
pub fn go_runes(s: &str) -> Vec<char> {
    go_lossy(&decode(s)).chars().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_text_is_borrowed() {
        assert!(matches!(encode(b"int 1 // \xc3\xa9"), Cow::Borrowed(_)));
        assert!(matches!(encode_str("a\u{10FEFF}b"), Cow::Borrowed(_)));
    }

    #[test]
    fn every_byte_string_round_trips() {
        for src in [
            &b"\xff\xfe"[..],
            b"a\xc3\xa9\xe2",
            b"\xf4\x8f\xbc\x80",
            b"\xf4\x8f\xbc\x80\xf4\x8f\xbf\xbf\xff",
            b"\xf4\x8f\xbc",
            b"\xf4\x90\x80\x80",
            b"\xed\xa0\x80",
        ] {
            let enc = encode(src);
            assert_eq!(decode(&enc).as_ref(), src, "{src:?}");
            assert_eq!(raw_len(&enc), src.len(), "{src:?}");
        }
        for b in 0..=255u8 {
            let one = [b];
            let enc = encode(&one);
            assert_eq!(decode(&enc).as_ref(), &one[..]);
        }
    }

    #[test]
    fn go_runes_decode_each_invalid_byte_alone() {
        assert_eq!(
            go_runes(&encode(b"\xe2\x82 ")),
            vec!['\u{fffd}', '\u{fffd}', ' ']
        );
        assert_eq!(go_runes(&encode(b"\xf4\x8f\xbc\x80")), vec!['\u{10FF00}']);
    }
}
