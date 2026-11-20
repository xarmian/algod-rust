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

//! Port of go-algorand's `protocol/transcode` msgpack-to-JSON direction
//! (`Transcode(true, base32Encoding, strictJSON, in, out)`), the conversion
//! `goal ledger block` and `msgpacktool -d` print (issue #2460).
//!
//! go decodes each msgpack value of the input into an `interface{}` with
//! go-codec's msgpack handle (`RawToString`, `PositiveIntUnsigned`,
//! `WriteExt`), rewrites it (`toJSON`: a binary value under a string key
//! becomes `<key>:b64` / `<key>:b32` with the value encoded, `--strict`
//! turns every other key into its `%v` string), and encodes it with
//! go-codec's JSON handle (`Canonical`, `Indent: 2`), a newline after each
//! value. What that means, byte for byte:
//! - integers: a positive one is a `uint64`, a negative one an `int64`;
//!   floats (`float32` widened) as go-codec prints them
//!   (`jsonFloatStrconvFmtPrec`: `strconv` `'e'` or `'f'`, integral values
//!   with `.0`, `NaN`, `+Inf`);
//! - strings: go-codec's `quoteStr` (HTML characters, controls, invalid
//!   UTF-8 as `�`, U+2028/U+2029 escaped), binary values as standard
//!   base64 strings, a binary map key as the string it holds;
//! - an extension value is `null`, except the msgpack timestamp (type -1),
//!   an RFC 3339 time in UTC;
//! - map keys sorted by their encoded bytes (go-codec's canonical order for
//!   `map[interface{}]interface{}`), a non-string key printed bare;
//! - an input that ends inside a value ends the output there without an
//!   error (go-codec reports `io.EOF`); `0xc1`, a timestamp of the wrong
//!   length and an unhashable map key are errors, with go-codec's text.

use std::fmt::Write as _;

/// A decoded msgpack value: go-codec's `DecodeNaked` result types.
#[derive(Clone, Debug)]
enum Value {
    Nil,
    Bool(bool),
    Uint(u64),
    Int(i64),
    Float(f64),
    /// A msgpack string (`RawToString`), possibly not UTF-8.
    Str(Vec<u8>),
    Bin(Vec<u8>),
    /// A msgpack timestamp: `time.Unix(secs, nanos).UTC()`.
    Time(i128),
    /// Any other extension value (`codec.RawExt`).
    Ext,
    Arr(Vec<Value>),
    Map(Vec<(Value, Value)>),
}

impl Value {
    /// go's `==` on two hashable `interface{}` map keys.
    fn key_eq(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Nil, Value::Nil) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Uint(a), Value::Uint(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => a == b,
            (Value::Str(a), Value::Str(b)) => a == b,
            (Value::Time(a), Value::Time(b)) => a == b,
            _ => false,
        }
    }
}

/// Why decoding stopped.
enum Stop {
    /// The input ended inside a value: go-codec's `io.EOF`.
    Eof,
    /// A decode error, go-codec's text.
    Err(String),
}

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
    /// How many arrays and maps enclose the value being decoded.
    depth: usize,
}

/// go-codec's `decDefMaxDepth`: the 1024th nested array or map is an error.
const MAX_DEPTH: usize = 1024;

const NANOS_PER_SEC: i128 = 1_000_000_000;

impl Decoder<'_> {
    fn err<T>(&self, msg: impl std::fmt::Display) -> Result<T, Stop> {
        Err(Stop::Err(format!(
            "msgpack decode error [pos {}]: {msg}",
            self.pos
        )))
    }

    fn bytes(&mut self, n: usize) -> Result<&[u8], Stop> {
        if self.buf.len() - self.pos < n {
            return Err(Stop::Eof);
        }
        let b = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(b)
    }

    fn byte(&mut self) -> Result<u8, Stop> {
        Ok(self.bytes(1)?[0])
    }

    fn be(&mut self, n: usize) -> Result<u64, Stop> {
        Ok(self
            .bytes(n)?
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
    }

    fn signed(&mut self, n: usize) -> Result<Value, Stop> {
        let raw = self.be(n)?;
        let shift = 64 - 8 * n as u32;
        let v = ((raw << shift) as i64) >> shift;
        Ok(if v >= 0 {
            Value::Uint(v as u64)
        } else {
            Value::Int(v)
        })
    }

    fn len_then(&mut self, n: usize) -> Result<usize, Stop> {
        // A length past the input is an `io.EOF` once go-codec reads it.
        Ok(usize::try_from(self.be(n)?).unwrap_or(usize::MAX))
    }

    fn ext(&mut self, len: usize) -> Result<Value, Stop> {
        let tag = self.byte()? as i8;
        if tag != -1 {
            self.bytes(len)?;
            return Ok(Value::Ext);
        }
        if !matches!(len, 4 | 8 | 12) {
            return self.err(format_args!(
                "invalid length of bytes for decoding time - expecting 4 or 8 or 12, got {len}"
            ));
        }
        let b = self.bytes(len)?;
        let be = |s: &[u8]| s.iter().fold(0u64, |acc, x| (acc << 8) | u64::from(*x));
        let (secs, nanos) = match len {
            4 => (i128::from(be(b)), 0),
            8 => {
                let v = be(b);
                (i128::from(v & 0x3_ffff_ffff), i128::from(v >> 34))
            }
            _ => (i128::from(be(&b[4..]) as i64), i128::from(be(&b[..4]))),
        };
        Ok(Value::Time(secs * NANOS_PER_SEC + nanos))
    }

    /// go-codec's `depthIncr`.
    fn enter(&mut self) -> Result<(), Stop> {
        self.depth += 1;
        if self.depth >= MAX_DEPTH {
            return self.err("maximum decoding depth exceeded");
        }
        Ok(())
    }

    fn array(&mut self, n: usize) -> Result<Value, Stop> {
        self.enter()?;
        let mut v = Vec::new();
        for _ in 0..n {
            v.push(self.value()?);
        }
        self.depth -= 1;
        Ok(Value::Arr(v))
    }

    fn map(&mut self, n: usize) -> Result<Value, Stop> {
        self.enter()?;
        let mut entries: Vec<(Value, Value)> = Vec::new();
        for _ in 0..n {
            let key = match self.value()? {
                // a `[]byte` key becomes the string it holds
                Value::Bin(b) => Value::Str(b),
                k => k,
            };
            let val = self.value()?;
            let unhashable = match key {
                Value::Arr(_) => Some("[]interface {}"),
                Value::Map(_) => Some("map[interface {}]interface {}"),
                Value::Ext => Some("codec.RawExt"),
                _ => None,
            };
            if let Some(t) = unhashable {
                return self.err(format_args!("hash of unhashable type: {t}"));
            }
            match entries.iter_mut().find(|(k, _)| k.key_eq(&key)) {
                Some(e) => e.1 = val,
                None => entries.push((key, val)),
            }
        }
        self.depth -= 1;
        Ok(Value::Map(entries))
    }

    fn value(&mut self) -> Result<Value, Stop> {
        let bd = self.byte()?;
        match bd {
            0x00..=0x7f => Ok(Value::Uint(u64::from(bd))),
            0xe0..=0xff => Ok(Value::Int(i64::from(bd as i8))),
            0x80..=0x8f => self.map(usize::from(bd & 0x0f)),
            0x90..=0x9f => self.array(usize::from(bd & 0x0f)),
            0xa0..=0xbf => Ok(Value::Str(self.bytes(usize::from(bd & 0x1f))?.to_vec())),
            0xc0 => Ok(Value::Nil),
            0xc2 => Ok(Value::Bool(false)),
            0xc3 => Ok(Value::Bool(true)),
            0xc4..=0xc6 => {
                let n = self.len_then(1 << (bd - 0xc4))?;
                Ok(Value::Bin(self.bytes(n)?.to_vec()))
            }
            0xc7..=0xc9 => {
                let n = self.len_then(1 << (bd - 0xc7))?;
                self.ext(n)
            }
            0xca => Ok(Value::Float(f64::from(f32::from_bits(self.be(4)? as u32)))),
            0xcb => Ok(Value::Float(f64::from_bits(self.be(8)?))),
            0xcc..=0xcf => Ok(Value::Uint(self.be(1 << (bd - 0xcc))?)),
            0xd0..=0xd3 => self.signed(1 << (bd - 0xd0)),
            0xd4..=0xd8 => self.ext(1 << (bd - 0xd4)),
            0xd9..=0xdb => {
                let n = self.len_then(1 << (bd - 0xd9))?;
                Ok(Value::Str(self.bytes(n)?.to_vec()))
            }
            0xdc | 0xdd => {
                let n = self.len_then(if bd == 0xdc { 2 } else { 4 })?;
                self.array(n)
            }
            0xde | 0xdf => {
                let n = self.len_then(if bd == 0xde { 2 } else { 4 })?;
                self.map(n)
            }
            0xc1 => self.err(format_args!(
                "cannot infer value: unrecognized descriptor byte: Ox{bd:x}/{bd}/unknown"
            )),
        }
    }
}

/// A value after go's `toJSON`: what go-codec's JSON encoder sees.
#[derive(Debug)]
pub(crate) enum Json {
    Nil,
    Bool(bool),
    Uint(u64),
    Int(i64),
    Float(f64),
    Str(Vec<u8>),
    /// A `[]byte` go-codec prints as a base64 string.
    Bytes(Vec<u8>),
    Time(i128),
    Arr(Vec<Json>),
    Map(Vec<(Json, Json)>),
    /// A struct, or a map go-codec has already put in canonical order: the
    /// entries in the order given (issue #2467).
    Ordered(Vec<(Json, Json)>),
}

impl Json {
    fn key_eq(&self, other: &Json) -> bool {
        match (self, other) {
            (Json::Nil, Json::Nil) => true,
            (Json::Bool(a), Json::Bool(b)) => a == b,
            (Json::Uint(a), Json::Uint(b)) => a == b,
            (Json::Int(a), Json::Int(b)) => a == b,
            (Json::Float(a), Json::Float(b)) => a == b,
            (Json::Str(a), Json::Str(b)) => a == b,
            (Json::Time(a), Json::Time(b)) => a == b,
            _ => false,
        }
    }
}

/// go's `isSliceOfBytes`: a non-empty array of binary values only.
fn is_slice_of_bytes(v: &Value) -> bool {
    matches!(v, Value::Arr(a) if !a.is_empty() && a.iter().all(|e| matches!(e, Value::Bin(_))))
}

/// go's `toJSON`.
fn to_json(v: Value, base32: bool, strict: bool) -> Json {
    match v {
        Value::Map(entries) => {
            let suffix: &[u8] = if base32 { b":b32" } else { b":b64" };
            let mut r: Vec<(Json, Json)> = Vec::new();
            for (k, e) in entries {
                let (kenc, eenc) = match (k, e) {
                    (Value::Str(ks), Value::Bin(eb)) => {
                        let enc = if base32 {
                            data_encoding::BASE32.encode(&eb)
                        } else {
                            data_encoding::BASE64.encode(&eb)
                        };
                        (
                            Json::Str([ks, suffix.to_vec()].concat()),
                            Json::Str(enc.into_bytes()),
                        )
                    }
                    (Value::Str(ks), e) if is_slice_of_bytes(&e) => (
                        Json::Str([ks, suffix.to_vec()].concat()),
                        to_json(e, base32, strict),
                    ),
                    (k, e) => {
                        let k = if strict {
                            Value::Str(go_v(&k).into_bytes())
                        } else {
                            k
                        };
                        (to_json(k, base32, strict), to_json(e, base32, strict))
                    }
                };
                match r.iter_mut().find(|(rk, _)| rk.key_eq(&kenc)) {
                    Some(slot) => slot.1 = eenc,
                    None => r.push((kenc, eenc)),
                }
            }
            Json::Map(r)
        }
        Value::Arr(a) => Json::Arr(a.into_iter().map(|e| to_json(e, base32, strict)).collect()),
        Value::Nil | Value::Ext => Json::Nil,
        Value::Bool(b) => Json::Bool(b),
        Value::Uint(u) => Json::Uint(u),
        Value::Int(i) => Json::Int(i),
        Value::Float(f) => Json::Float(f),
        Value::Str(s) => Json::Str(s),
        Value::Bin(b) => Json::Bytes(b),
        Value::Time(t) => Json::Time(t),
    }
}

/// go's `fmt.Sprintf("%v", k)` of a map key.
fn go_v(k: &Value) -> String {
    match k {
        Value::Nil => "<nil>".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Uint(u) => u.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => format_float(*f, FloatFmt::G),
        Value::Str(s) => String::from_utf8_lossy(s).into_owned(),
        Value::Time(t) => time_string(*t),
        // not a hashable key: rejected while decoding
        Value::Bin(_) | Value::Ext | Value::Arr(_) | Value::Map(_) => String::new(),
    }
}

// ---- floats -------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum FloatFmt {
    /// `strconv` `'e'`, shortest.
    E,
    /// `strconv` `'f'`, shortest.
    F,
    /// `strconv` `'f'` with one decimal.
    F1,
    /// `strconv` `'g'`, shortest (`%v`).
    G,
}

/// `strconv.AppendFloat(f, fmt, prec, 64)` for the formats go-codec and
/// `%v` use.
fn format_float(f: f64, fmt: FloatFmt) -> String {
    if f.is_nan() {
        return "NaN".to_string();
    }
    if f.is_infinite() {
        return if f > 0.0 { "+Inf" } else { "-Inf" }.to_string();
    }
    if fmt == FloatFmt::F1 {
        return format!("{f:.1}");
    }
    // The shortest digits that round-trip and the decimal exponent:
    // `d.ddd` x 10^exp.
    let sci = format!("{:e}", f.abs());
    let (mant, exp) = sci.split_once('e').expect("{:e} has an exponent");
    let exp: i32 = exp.parse().expect("{:e} exponent");
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let neg = if f.is_sign_negative() { "-" } else { "" };
    // `'g'` shortest: `%e` when the exponent is < -4 or >= 6.
    let fmt = match fmt {
        FloatFmt::G if !(-4..6).contains(&exp) => FloatFmt::E,
        FloatFmt::G => FloatFmt::F,
        other => other,
    };
    match fmt {
        FloatFmt::E => {
            let mut s = format!("{neg}{}", &digits[..1]);
            if digits.len() > 1 {
                s.push('.');
                s.push_str(&digits[1..]);
            }
            let sign = if exp < 0 { '-' } else { '+' };
            let _ = write!(s, "e{sign}{:02}", exp.abs());
            s
        }
        _ => format!("{neg}{}", f.abs()),
    }
}

/// go-codec's `EncodeFloat64` (`jsonFloatStrconvFmtPrec`).
fn json_float(f: f64) -> String {
    let abs = f.abs();
    if abs != 0.0 && (abs < 1e-6 || abs >= 1e21) {
        return format_float(f, FloatFmt::E);
    }
    if abs.is_finite() && (abs == 0.0 || abs == 1.0 || (abs > 1.0 && abs.fract() == 0.0)) {
        return format_float(f, FloatFmt::F1);
    }
    format_float(f, FloatFmt::F)
}

// ---- times ----------------------------------------------------------------------

/// `(year, month, day, hour, minute, second, nanosecond)` of a UTC instant in
/// nanoseconds since the Unix epoch.
fn civil(t: i128) -> (i128, u32, u32, u32, u32, u32, u32) {
    let secs = t.div_euclid(NANOS_PER_SEC);
    let nanos = t.rem_euclid(NANOS_PER_SEC) as u32;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400) as u32;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i128::from(month <= 2);
    (year, month, day, sod / 3600, sod / 60 % 60, sod % 60, nanos)
}

/// go's year in a layout: at least four digits, a leading `-` when negative.
fn go_year(year: i128) -> String {
    if year < 0 {
        format!("-{:04}", -year)
    } else {
        format!("{year:04}")
    }
}

/// `.999999999`: the nanoseconds without trailing zeros, nothing for none.
fn go_fraction(nanos: u32) -> String {
    if nanos == 0 {
        return String::new();
    }
    format!(".{nanos:09}").trim_end_matches('0').to_string()
}

/// go-codec's `EncodeTime`: `time.RFC3339Nano` in UTC.
fn rfc3339_nano(t: i128) -> String {
    let (y, mo, d, h, mi, s, n) = civil(t);
    format!(
        "{}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}{}Z",
        go_year(y),
        go_fraction(n)
    )
}

/// go's `time.Time.String()` of a UTC time.
fn time_string(t: i128) -> String {
    let (y, mo, d, h, mi, s, n) = civil(t);
    format!(
        "{}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}{} +0000 UTC",
        go_year(y),
        go_fraction(n)
    )
}

/// `time.Time{}` (January 1, year 1, 00:00:00 UTC), which go-codec prints
/// as `null`.
const ZERO_TIME: i128 = -62_135_596_800 * NANOS_PER_SEC;

// ---- the JSON encoder -------------------------------------------------------------

/// go-codec's `quoteStr`; `<`, `>` and `&` are escaped unless
/// `HTMLCharsAsIs` (`html_as_is`).
fn quote(out: &mut Vec<u8>, s: &[u8], html_as_is: bool) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if b < 0x80 {
            match b {
                b'\\' | b'"' => out.extend_from_slice(&[b'\\', b]),
                b'\n' => out.extend_from_slice(b"\\n"),
                b'\r' => out.extend_from_slice(b"\\r"),
                0x08 => out.extend_from_slice(b"\\b"),
                0x0c => out.extend_from_slice(b"\\f"),
                b'\t' => out.extend_from_slice(b"\\t"),
                b'<' | b'>' | b'&' if html_as_is => out.push(b),
                b'<' | b'>' | b'&' | 0x00..=0x1f => {
                    out.extend_from_slice(b"\\u00");
                    out.push(HEX[usize::from(b >> 4)]);
                    out.push(HEX[usize::from(b & 0xf)]);
                }
                _ => out.push(b),
            }
            i += 1;
            continue;
        }
        let (c, size) = decode_rune(&s[i..]);
        match c {
            None => out.extend_from_slice(b"\\ufffd"),
            Some('\u{2028}') => out.extend_from_slice(b"\\u2028"),
            Some('\u{2029}') => out.extend_from_slice(b"\\u2029"),
            Some(_) => out.extend_from_slice(&s[i..i + size]),
        }
        i += size;
    }
    out.push(b'"');
}

/// go's `utf8.DecodeRuneInString` for a non-ASCII start byte: the rune and
/// its length, or `None` and 1 for an invalid encoding.
fn decode_rune(s: &[u8]) -> (Option<char>, usize) {
    let want = match s[0] {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return (None, 1),
    };
    match s.get(..want).and_then(|b| std::str::from_utf8(b).ok()) {
        Some(t) => (t.chars().next(), want),
        None => (None, 1),
    }
}

fn indent(out: &mut Vec<u8>, level: usize) {
    out.push(b'\n');
    out.resize(out.len() + 2 * level, b' ');
}

/// go-codec's JSON encoding of `v` (`Canonical`, `Indent: 2`, and
/// `HTMLCharsAsIs` when `html`) at nesting `level`.
fn encode(out: &mut Vec<u8>, v: &Json, level: usize, html: bool) {
    match v {
        Json::Nil => out.extend_from_slice(b"null"),
        Json::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Json::Uint(u) => out.extend_from_slice(u.to_string().as_bytes()),
        Json::Int(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Json::Float(f) => out.extend_from_slice(json_float(*f).as_bytes()),
        Json::Str(s) => quote(out, s, html),
        Json::Bytes(b) => {
            out.push(b'"');
            out.extend_from_slice(data_encoding::BASE64.encode(b).as_bytes());
            out.push(b'"');
        }
        Json::Time(t) if *t == ZERO_TIME => out.extend_from_slice(b"null"),
        Json::Time(t) => quote(out, rfc3339_nano(*t).as_bytes(), html),
        Json::Arr(a) => {
            out.push(b'[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                indent(out, level + 1);
                encode(out, e, level + 1, html);
            }
            if !a.is_empty() {
                indent(out, level);
            }
            out.push(b']');
        }
        Json::Map(m) => {
            // canonical: the keys sorted by their encoding
            let mut keyed: Vec<(Vec<u8>, &Json)> = m
                .iter()
                .map(|(k, e)| {
                    let mut kb = Vec::new();
                    encode(&mut kb, k, 0, html);
                    (kb, e)
                })
                .collect();
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            encode_entries(out, &keyed, level, html);
        }
        Json::Ordered(m) => {
            let keyed: Vec<(Vec<u8>, &Json)> = m
                .iter()
                .map(|(k, e)| {
                    let mut kb = Vec::new();
                    encode(&mut kb, k, 0, html);
                    (kb, e)
                })
                .collect();
            encode_entries(out, &keyed, level, html);
        }
    }
}

/// The `{...}` of a map or struct whose keys are already encoded, in order.
fn encode_entries(out: &mut Vec<u8>, keyed: &[(Vec<u8>, &Json)], level: usize, html: bool) {
    out.push(b'{');
    for (i, (k, e)) in keyed.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        indent(out, level + 1);
        out.extend_from_slice(k);
        out.extend_from_slice(b": ");
        encode(out, e, level + 1, html);
    }
    if !keyed.is_empty() {
        indent(out, level);
    }
    out.push(b'}');
}

/// go's `protocol.EncodeJSON` / `EncodeJSONStrict` of a value already in
/// go-codec's shape: `protocol.JSONHandle` (`Canonical`, `Indent: 2`,
/// `HTMLCharsAsIs`), no trailing newline.
pub(crate) fn encode_protocol_json(v: &Json) -> Vec<u8> {
    let mut out = Vec::new();
    encode(&mut out, v, 0, true);
    out
}

/// go's `transcode.Transcode(true, base32Encoding, strictJSON, in, out)`:
/// the JSON of each msgpack value of `input`, each followed by a newline,
/// or go-codec's decode error.
pub fn msgpack_to_json(input: &[u8], base32: bool, strict: bool) -> Result<Vec<u8>, String> {
    // Up to `MAX_DEPTH` nested values recurse through the decoder, `to_json`
    // and the encoder: a stack of its own, the same size on every platform.
    std::thread::scope(|s| {
        std::thread::Builder::new()
            .stack_size(TRANSCODE_STACK_BYTES)
            .spawn_scoped(s, || transcode(input, base32, strict))
            .map_err(|e| format!("transcode thread: {e}"))?
            .join()
            .unwrap_or_else(|p| std::panic::resume_unwind(p))
    })
}

/// The stack of [`msgpack_to_json`]'s thread: room for `MAX_DEPTH` levels of
/// recursion in a debug build.
const TRANSCODE_STACK_BYTES: usize = 64 << 20;

fn transcode(input: &[u8], base32: bool, strict: bool) -> Result<Vec<u8>, String> {
    let mut dec = Decoder {
        buf: input,
        pos: 0,
        depth: 0,
    };
    let mut out = Vec::new();
    while dec.pos < input.len() {
        let v = match dec.value() {
            Ok(v) => v,
            Err(Stop::Eof) => break,
            Err(Stop::Err(e)) => return Err(e),
        };
        encode(&mut out, &to_json(v, base32, strict), 0, false);
        out.push(b'\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(input: &[u8], base32: bool, strict: bool) -> String {
        String::from_utf8(msgpack_to_json(input, base32, strict).unwrap()).unwrap()
    }

    #[test]
    fn floats_print_like_go_codec() {
        let cases = [
            (0.1, "0.1"),
            (1.5, "1.5"),
            (5.0, "5.0"),
            (1.0, "1.0"),
            (-0.0, "-0.0"),
            (0.0, "0.0"),
            (3e20, "300000000000000000000.0"),
            (1e21, "1e+21"),
            (-1e300, "-1e+300"),
            (1.5e-7, "1.5e-07"),
            (1e-7, "1e-07"),
            (f64::NAN, "NaN"),
            (f64::INFINITY, "+Inf"),
            (f64::NEG_INFINITY, "-Inf"),
            (f64::from(0.1f32), "0.10000000149011612"),
        ];
        for (f, want) in cases {
            assert_eq!(json_float(f), want, "{f:e}");
        }
    }

    #[test]
    fn strict_float_keys_print_like_go_percent_v() {
        let cases = [
            (100.0, "100"),
            (1e20, "1e+20"),
            (1e21, "1e+21"),
            (4.123722982716814e20, "4.123722982716814e+20"),
            (1.5035955289062012e-7, "1.5035955289062012e-07"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (-0.0, "-0"),
            (1.5, "1.5"),
            (1234567.0, "1.234567e+06"),
            (123456.0, "123456"),
            (f64::NAN, "NaN"),
            (f64::INFINITY, "+Inf"),
        ];
        for (f, want) in cases {
            assert_eq!(go_v(&Value::Float(f)), want, "{f:e}");
        }
    }

    #[test]
    fn times_print_like_go() {
        assert_eq!(rfc3339_nano(NANOS_PER_SEC), "1970-01-01T00:00:01Z");
        assert_eq!(rfc3339_nano(-NANOS_PER_SEC), "1969-12-31T23:59:59Z");
        assert_eq!(
            rfc3339_nano(2 * NANOS_PER_SEC + 30_864_197),
            "1970-01-01T00:00:02.030864197Z"
        );
        assert_eq!(
            rfc3339_nano(0x10_0000_0000 * NANOS_PER_SEC),
            "4147-08-20T07:32:16Z"
        );
        assert_eq!(
            rfc3339_nano(-0x10_0000_0000 * NANOS_PER_SEC),
            "-0208-05-13T16:27:44Z"
        );
        assert_eq!(time_string(NANOS_PER_SEC), "1970-01-01 00:00:01 +0000 UTC");
    }

    #[test]
    fn go_codec_edge_cases() {
        // a timestamp key, strict and not
        let ts_key = b"\x81\xd6\xff\x00\x00\x00\x01\x01";
        assert_eq!(
            t(ts_key, false, false),
            "{\n  \"1970-01-01T00:00:01Z\": 1\n}\n"
        );
        assert_eq!(
            t(ts_key, false, true),
            "{\n  \"1970-01-01 00:00:01 +0000 UTC\": 1\n}\n"
        );
        // timestamp64 and timestamp96 normalise their nanoseconds
        assert_eq!(
            t(b"\xd7\xff\xff\xff\xff\xfc\x00\x00\x00\x02", false, false),
            "\"1970-01-01T00:00:03.073741823Z\"\n"
        );
        assert_eq!(
            t(
                b"\xc7\x0c\xff\x3b\x9a\xca\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                false,
                false
            ),
            "\"1970-01-01T00:00:02Z\"\n"
        );
        // bool, nil, float and int keys
        assert_eq!(
            t(b"\x82\xc3\x01\xc2\x02", false, false),
            "{\n  false: 2,\n  true: 1\n}\n"
        );
        assert_eq!(t(b"\x81\xc0\x01", false, false), "{\n  null: 1\n}\n");
        assert_eq!(
            t(b"\x81\xc0\x01", false, true),
            "{\n  \"\\u003cnil\\u003e\": 1\n}\n"
        );
        assert_eq!(
            t(
                b"\x82\x01\x01\xcb\x3f\xf0\x00\x00\x00\x00\x00\x00\x02",
                false,
                false
            ),
            "{\n  1: 1,\n  1.0: 2\n}\n"
        );
        // a binary key equals the string key it holds: the later value wins
        assert_eq!(
            t(b"\x82\xa1a\x01\xc4\x01a\x02", false, false),
            "{\n  \"a\": 2\n}\n"
        );
        // an extension value, an empty input, a truncated one
        assert_eq!(t(b"\xc7\x02\x05\x01\x02", false, false), "null\n");
        assert_eq!(t(b"", false, false), "");
        assert_eq!(t(b"\xa5ab", false, false), "");
        assert_eq!(t(b"\x01\x92\x01", false, false), "1\n");
    }

    #[test]
    fn go_codec_errors() {
        let e = |b: &[u8]| msgpack_to_json(b, false, false).unwrap_err();
        let c1 = "cannot infer value: unrecognized descriptor byte: Oxc1/193/unknown";
        assert_eq!(
            e(b"\x81\xa1a\xc1"),
            format!("msgpack decode error [pos 4]: {c1}")
        );
        assert_eq!(
            e(b"\x01\xc1"),
            format!("msgpack decode error [pos 2]: {c1}")
        );
        assert_eq!(
            e(b"\x81\x91\x01\x01"),
            "msgpack decode error [pos 4]: hash of unhashable type: []interface {}"
        );
        assert_eq!(
            e(b"\x81\x80\x01"),
            "msgpack decode error [pos 3]: hash of unhashable type: map[interface {}]interface {}"
        );
        assert_eq!(
            e(b"\x81\xd4\x05\x00\x01"),
            "msgpack decode error [pos 5]: hash of unhashable type: codec.RawExt"
        );
        assert_eq!(
            e(b"\xd4\xff\x00"),
            "msgpack decode error [pos 2]: invalid length of bytes for decoding time - \
             expecting 4 or 8 or 12, got 1"
        );
        // go-codec's depth limit: 1023 nested arrays decode, 1024 do not
        let nested = |n: usize, open: &[u8]| [open.repeat(n), vec![0x01]].concat();
        assert!(msgpack_to_json(&nested(1023, b"\x91"), false, false).is_ok());
        assert_eq!(
            e(&nested(1024, b"\x91")),
            "msgpack decode error [pos 1024]: maximum decoding depth exceeded"
        );
        assert_eq!(
            e(&nested(1024, b"\x81\xa1a")),
            "msgpack decode error [pos 3070]: maximum decoding depth exceeded"
        );
    }
}
