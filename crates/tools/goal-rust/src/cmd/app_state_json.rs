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

//! `goal app read`'s JSON serialization path: an exact byte-for-byte port of
//! go's `protocol.EncodeJSON` applied to a `map[string]basics.TealValue`
//! (`cmd/goal/application.go`'s `readStateAppCmd`, `application.go:1032`/
//! `1062`), plus the `--guess-format` heuristic
//! (`cmd/goal/formatting.go`'s `heuristicFormat`/`heuristicFormatStr`).
//!
//! This is a *different* wire shape from this repo's existing array-shaped
//! `TealKeyValueStore` REST model (`crates/node/algo-rest-client`): go's
//! `protocol.EncodeJSON` here is `github.com/algorand/go-codec`'s
//! `JsonHandle` with `Canonical: true` (sorted map keys *and* sorted struct
//! fields — verified against the real `go-codec` v1.1.10 dependency, not
//! guessed), `Indent: 2`, and `HTMLCharsAsIs: true` (leaves `<`, `>`, `&`
//! unescaped). `basics.TealValue`'s `codec:"tt"/"tb"/"ui"` tags
//! (`data/basics/teal.go`) and its struct-level `,omitempty` mean at most two
//! of the three fields are ever present: `{"tb":...,"tt":1}` for a bytes
//! value (alphabetically tb before tt), or `{"tt":2,"ui":...}` for a uint
//! value (tt before ui) — `ui`/`tb` are omitted entirely when they hold the
//! Go zero value (`0`/`""`), *including* a real stored `0` or empty string.
//!
//! String/key escaping was verified against a small throwaway Go program
//! linking the real `github.com/algorand/go-codec` module (not guessed):
//! quote/backslash/C0 controls (except `\b\t\n\f\r`) escape as usual;
//! `U+007F` (DEL) is written literally (`cmd/goal/formatting.go`'s own
//! `htmlSafeSet` table marks it safe, and go-codec's JSON writer agrees);
//! `U+2028`/`U+2029` (JS line/paragraph separators) are *always* escaped,
//! independent of `HTMLCharsAsIs`; invalid UTF-8 byte sequences are replaced
//! by `U+FFFD`, which is itself then escaped as `\ufffd` rather than written
//! as literal UTF-8 bytes; every other valid Unicode scalar (including
//! multi-byte, non-ASCII runes) is written as literal UTF-8.

use algo_types::{Address, TealValue};

/// A local/global state key-value entry: the raw (possibly non-UTF-8, Go
/// `string`-typed) key bytes and its [`TealValue`].
pub(crate) type TealEntry = (Vec<u8>, TealValue);

/// Whether `bytes` is "JSON printable" per go's `jsonPrintable`
/// (`cmd/goal/formatting.go:46-162`): true iff every byte is ASCII (`<
/// 0x80`) and not a C0 control character, `"`, `\`, `<`, `>`, or `&`. Used
/// only by [`heuristic_format_entries`] (`--guess-format`); the plain
/// (non-heuristic) JSON encoder in [`encode_teal_state_json`] handles the
/// full byte range unconditionally.
fn json_printable(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| {
        // Matches go's `htmlSafeSet` table (`cmd/goal/formatting.go:54-151`):
        // every byte < 0x80 is safe except the C0 control range (0-31) and
        // `"`/`&`/`<`/`>`/`\` -- notably 0x7f (DEL) *is* on the safe list.
        (0x20..0x80).contains(&b) && b != b'"' && b != b'\\' && b != b'<' && b != b'>' && b != b'&'
    })
}

/// Mirrors go's `heuristicFormatStr` (`cmd/goal/formatting.go:164-179`): if
/// `raw` is already JSON-printable, return it unchanged; otherwise, if it's
/// exactly 32 bytes, reinterpret it as an [`Address`] and return its
/// checksummed string form; otherwise return it unchanged. Note this is the
/// *only* transformation `--guess-format` ever performs — a raw value/key
/// that is neither JSON-printable nor 32 bytes passes through untouched,
/// same as without the flag.
fn heuristic_format_bytes(raw: &[u8]) -> Vec<u8> {
    if json_printable(raw) {
        return raw.to_vec();
    }
    if raw.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(raw);
        return Address(arr).to_algorand_string().into_bytes();
    }
    raw.to_vec()
}

/// Mirrors go's `heuristicFormat` (`cmd/goal/formatting.go:193-199`):
/// rewrite every key and every `Bytes`-typed value's bytes through
/// [`heuristic_format_bytes`]; `Uint`-typed values pass through unchanged
/// (`heuristicFormatVal`'s `if val.Type == basics.TealUintType { return val
/// }` branch). Applied *before* [`encode_teal_state_json`], so the sort
/// order the encoder computes is over the (possibly address-rewritten) new
/// keys, matching Go's `kv = heuristicFormat(kv)` reassignment before
/// `protocol.EncodeJSON(kv)`.
pub(crate) fn heuristic_format_entries(entries: Vec<TealEntry>) -> Vec<TealEntry> {
    entries
        .into_iter()
        .map(|(k, v)| {
            let new_key = heuristic_format_bytes(&k);
            let new_val = match v {
                TealValue::Bytes(b) => TealValue::Bytes(heuristic_format_bytes(&b)),
                TealValue::Uint(u) => TealValue::Uint(u),
            };
            (new_key, new_val)
        })
        .collect()
}

/// JSON-encode a single string value (a map key or a `TealValue::Bytes`
/// payload), including the surrounding quotes, exactly as go-codec's
/// `JsonHandle` (`Canonical`, `Indent: 2`, `HTMLCharsAsIs: true`) does. See
/// the module docs for the verified escaping rules.
fn write_json_string(out: &mut Vec<u8>, raw: &[u8]) {
    out.push(b'"');
    for c in String::from_utf8_lossy(raw).chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{9}' => out.extend_from_slice(b"\\t"),
            '\u{a}' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\u{d}' => out.extend_from_slice(b"\\r"),
            // JS line/paragraph separators: always escaped, independent of
            // HTMLCharsAsIs (which only governs `<`/`>`/`&`).
            '\u{2028}' => out.extend_from_slice(b"\\u2028"),
            '\u{2029}' => out.extend_from_slice(b"\\u2029"),
            // The Unicode replacement character -- whether it's a literal
            // U+FFFD in valid input or substituted for an invalid UTF-8
            // byte by `from_utf8_lossy` above -- is written as the escape
            // sequence, not literal UTF-8 bytes (verified against the real
            // go-codec encoder: a lone invalid byte encodes as `\ufffd`,
            // not the 3-byte EF BF BD sequence).
            '\u{fffd}' => out.extend_from_slice(b"\\ufffd"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Write a single [`TealValue`] as its indented JSON object, at nesting
/// `indent` (the number of leading spaces already used for its containing
/// key line). Field order/presence mirrors go's alphabetically-sorted,
/// per-field `,omitempty` struct encoding: a `Bytes` value emits `tb` then
/// `tt` (never `ui`); a `Uint` value emits `tt` then `ui` (never `tb`) --
/// and either field is omitted outright when it holds the Go zero value.
fn write_teal_value_json(out: &mut Vec<u8>, val: &TealValue, indent: usize) {
    let inner = " ".repeat(indent + 2);
    let close = " ".repeat(indent);
    out.extend_from_slice(b"{\n");
    match val {
        TealValue::Bytes(b) => {
            if !b.is_empty() {
                out.extend_from_slice(inner.as_bytes());
                write_json_string(out, b"tb");
                out.extend_from_slice(b": ");
                write_json_string(out, b);
                out.extend_from_slice(b",\n");
            }
            out.extend_from_slice(inner.as_bytes());
            out.extend_from_slice(b"\"tt\": 1\n");
        }
        TealValue::Uint(u) => {
            out.extend_from_slice(inner.as_bytes());
            out.extend_from_slice(b"\"tt\": 2");
            if *u != 0 {
                out.extend_from_slice(b",\n");
                out.extend_from_slice(inner.as_bytes());
                out.extend_from_slice(format!("\"ui\": {u}").as_bytes());
            }
            out.push(b'\n');
        }
    }
    out.extend_from_slice(close.as_bytes());
    out.push(b'}');
}

/// Mirrors go's `protocol.EncodeJSON(kv)` where `kv` is a
/// `map[string]basics.TealValue` (`readStateAppCmd`, `application.go:1032`/
/// `1062`): `None` (the field was entirely absent on the wire -- Go's zero
/// value for a nil map) encodes as the literal `null`; `Some(entries)`
/// (even empty) encodes as a `{}`-or-populated JSON object, with entries
/// sorted by raw key bytes (matching Go's byte-wise string comparison) and
/// indented two spaces per level. No trailing newline, matching Go's
/// `os.Stdout.Write(enc)` (no `Println`).
pub(crate) fn encode_teal_state_json(entries: Option<Vec<TealEntry>>) -> Vec<u8> {
    let Some(mut entries) = entries else {
        return b"null".to_vec();
    };
    if entries.is_empty() {
        return b"{}".to_vec();
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = Vec::new();
    out.extend_from_slice(b"{\n");
    let last = entries.len() - 1;
    for (i, (k, v)) in entries.iter().enumerate() {
        out.extend_from_slice(b"  ");
        write_json_string(&mut out, k);
        out.extend_from_slice(b": ");
        write_teal_value_json(&mut out, v, 2);
        if i != last {
            out.push(b',');
        }
        out.push(b'\n');
    }
    out.push(b'}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries_json(entries: Vec<TealEntry>) -> String {
        String::from_utf8(encode_teal_state_json(Some(entries))).unwrap()
    }

    #[test]
    fn nil_state_encodes_as_null() {
        assert_eq!(encode_teal_state_json(None), b"null");
    }

    #[test]
    fn empty_state_encodes_as_empty_object() {
        assert_eq!(entries_json(vec![]), "{}");
    }

    #[test]
    fn bytes_and_uint_entries_match_go_codec_fixture() {
        // Verified against a real `github.com/algorand/go-codec` v1.1.10
        // JsonHandle{Canonical:true,Indent:2,HTMLCharsAsIs:true} encode of
        // map[string]TealValue{"foo": {Type:1,Bytes:"bar"}, "num":
        // {Type:2,Uint:42}}.
        let json = entries_json(vec![
            (b"foo".to_vec(), TealValue::Bytes(b"bar".to_vec())),
            (b"num".to_vec(), TealValue::Uint(42)),
        ]);
        assert_eq!(
            json,
            "{\n  \"foo\": {\n    \"tb\": \"bar\",\n    \"tt\": 1\n  },\n  \"num\": {\n    \"tt\": 2,\n    \"ui\": 42\n  }\n}"
        );
    }

    #[test]
    fn zero_valued_fields_are_omitted() {
        // Verified fixture: map[string]TealValue{"zero": {Type:2,Uint:0},
        // "empty": {Type:1,Bytes:""}} -> {"empty":{"tt":1},"zero":{"tt":2}}.
        let json = entries_json(vec![
            (b"zero".to_vec(), TealValue::Uint(0)),
            (b"empty".to_vec(), TealValue::Bytes(vec![])),
        ]);
        assert_eq!(
            json,
            "{\n  \"empty\": {\n    \"tt\": 1\n  },\n  \"zero\": {\n    \"tt\": 2\n  }\n}"
        );
    }

    #[test]
    fn keys_sort_by_raw_bytes_not_escaped_form() {
        // Verified fixture: keys "\x00xyz" < "\x01abc" < "abc" (raw
        // byte-wise order), not by their escaped JSON text.
        let json = entries_json(vec![
            (b"\x01abc".to_vec(), TealValue::Uint(1)),
            (b"\x00xyz".to_vec(), TealValue::Uint(2)),
            (b"abc".to_vec(), TealValue::Uint(3)),
        ]);
        assert_eq!(
            json,
            "{\n  \"\\u0000xyz\": {\n    \"tt\": 2,\n    \"ui\": 2\n  },\n  \"\\u0001abc\": {\n    \"tt\": 2,\n    \"ui\": 1\n  },\n  \"abc\": {\n    \"tt\": 2,\n    \"ui\": 3\n  }\n}"
        );
    }

    #[test]
    fn control_chars_and_del_and_html_chars_escape_correctly() {
        // Verified fixture: 0x00-0x1f escape as \u00XX (with \b\t\n\f\r
        // shorthands), 0x7f (DEL) is literal, and `<`/`>`/`&` stay literal
        // (HTMLCharsAsIs).
        let json = entries_json(vec![(
            b"k".to_vec(),
            TealValue::Bytes(b"\x00\x01\x08\x09\x0a\x0c\x0d\x7f<>&".to_vec()),
        )]);
        assert_eq!(
            json,
            "{\n  \"k\": {\n    \"tb\": \"\\u0000\\u0001\\b\\t\\n\\f\\r\u{7f}<>&\",\n    \"tt\": 1\n  }\n}"
        );
    }

    #[test]
    fn invalid_utf8_becomes_escaped_replacement_char() {
        // Verified fixture: Bytes:"\xff\xfe" -> "tb":"\ufffd\ufffd" (two
        // separate escapes, one per invalid byte -- not merged, and not
        // written as literal UTF-8 EF BF BD bytes).
        let json = entries_json(vec![(
            b"invalid".to_vec(),
            TealValue::Bytes(vec![0xff, 0xfe]),
        )]);
        assert_eq!(
            json,
            "{\n  \"invalid\": {\n    \"tb\": \"\\ufffd\\ufffd\",\n    \"tt\": 1\n  }\n}"
        );
    }

    #[test]
    fn valid_multibyte_utf8_is_written_literally() {
        let json = entries_json(vec![(
            b"emoji".to_vec(),
            TealValue::Bytes("hi \u{1F600} caf\u{e9}".as_bytes().to_vec()),
        )]);
        assert_eq!(
            json,
            "{\n  \"emoji\": {\n    \"tb\": \"hi \u{1F600} caf\u{e9}\",\n    \"tt\": 1\n  }\n}"
        );
    }

    #[test]
    fn js_separators_always_escaped() {
        let json = entries_json(vec![(
            b"sep".to_vec(),
            TealValue::Bytes("a\u{2028}\u{2029}b".as_bytes().to_vec()),
        )]);
        assert_eq!(
            json,
            "{\n  \"sep\": {\n    \"tb\": \"a\\u2028\\u2029b\",\n    \"tt\": 1\n  }\n}"
        );
    }

    // --- --guess-format heuristic ---

    #[test]
    fn guess_format_leaves_printable_values_unchanged() {
        let entries = heuristic_format_entries(vec![(
            b"key".to_vec(),
            TealValue::Bytes(b"hello world".to_vec()),
        )]);
        assert_eq!(
            entries,
            vec![(b"key".to_vec(), TealValue::Bytes(b"hello world".to_vec()))]
        );
    }

    #[test]
    fn guess_format_leaves_uint_values_unchanged() {
        let entries = heuristic_format_entries(vec![(b"key".to_vec(), TealValue::Uint(7))]);
        assert_eq!(entries, vec![(b"key".to_vec(), TealValue::Uint(7))]);
    }

    #[test]
    fn guess_format_converts_32_byte_unprintable_value_to_address() {
        let raw = [0xffu8; 32];
        let entries =
            heuristic_format_entries(vec![(b"key".to_vec(), TealValue::Bytes(raw.to_vec()))]);
        let expected = Address(raw).to_algorand_string();
        assert_eq!(
            entries,
            vec![(b"key".to_vec(), TealValue::Bytes(expected.into_bytes()))]
        );
    }

    #[test]
    fn guess_format_leaves_32_byte_printable_value_unchanged() {
        // All-ASCII-printable 32-byte value stays untouched even though
        // it's exactly 32 bytes -- the address conversion only fires when
        // the bytes are NOT already jsonPrintable.
        let raw = b"abcdefghijklmnopqrstuvwxyz012345".to_vec();
        assert_eq!(raw.len(), 32);
        let entries =
            heuristic_format_entries(vec![(b"key".to_vec(), TealValue::Bytes(raw.clone()))]);
        assert_eq!(entries, vec![(b"key".to_vec(), TealValue::Bytes(raw))]);
    }

    #[test]
    fn guess_format_leaves_non_32_byte_unprintable_value_unchanged() {
        let raw = vec![0xffu8; 10];
        let entries =
            heuristic_format_entries(vec![(b"key".to_vec(), TealValue::Bytes(raw.clone()))]);
        assert_eq!(entries, vec![(b"key".to_vec(), TealValue::Bytes(raw))]);
    }

    #[test]
    fn guess_format_converts_unprintable_32_byte_key() {
        let raw = [0x00u8; 32];
        let entries = heuristic_format_entries(vec![(raw.to_vec(), TealValue::Uint(1))]);
        let expected = Address(raw).to_algorand_string();
        assert_eq!(entries, vec![(expected.into_bytes(), TealValue::Uint(1))]);
    }

    #[test]
    fn guess_format_reorders_sort_after_key_rewrite() {
        // Sorting happens on the post-heuristic keys, matching Go's
        // `kv = heuristicFormat(kv)` reassignment before `EncodeJSON`.
        let raw_key = [0xffu8; 32]; // becomes an "A..." address (checksummed base32)
        let entries = vec![
            (raw_key.to_vec(), TealValue::Uint(1)),
            (b"zzz".to_vec(), TealValue::Uint(2)),
        ];
        let formatted = heuristic_format_entries(entries);
        let json = String::from_utf8(encode_teal_state_json(Some(formatted))).unwrap();
        let addr = Address(raw_key).to_algorand_string();
        // The address-form key must appear before "zzz" iff it sorts first
        // by raw bytes -- verify by checking both keys are present and the
        // ordering is self-consistent with a byte sort.
        let addr_pos = json.find(&addr).expect("address key present");
        let zzz_pos = json.find("zzz").expect("zzz key present");
        if addr.as_bytes() < b"zzz".as_ref() {
            assert!(addr_pos < zzz_pos);
        } else {
            assert!(zzz_pos < addr_pos);
        }
    }
}
