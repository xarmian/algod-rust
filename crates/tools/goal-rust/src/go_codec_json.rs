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

//! What go's `goal` does with the JSON body of an algod answer (issue
//! #2466): `restClient.submitForm` decodes it with
//! `protocol.NewJSONDecoder(resp.Body).Decode(&response)` -- go-codec
//! (`github.com/algorand/go-codec/codec` v1.1.10) with `protocol.JSONHandle`
//! (`ErrorIfNoField`, `ErrorIfNoArrayExpand`), reading the body one byte at
//! a time through its unbuffered `ioDecReader` -- into the reflected Go type
//! of the answer (`model.Account`, `common.Version`, ...).
//!
//! go-codec accepts more than JSON (a quoted number, a string from a
//! number or a bool, an integer from `1e3`, a struct from an array, the
//! first value of a stream with garbage after it) and its errors are
//! `json decode error [pos N]: <what>`, `N` the bytes read when it failed,
//! or a bare `EOF`. [`decode`] ports the decoder for the Go types goal
//! reads ([`Ty`]) and returns the value as go's `encoding/json` would print
//! the decoded struct: every non-pointer field (its zero value when
//! absent), a nil pointer left out, a nil slice `null`, `[]byte` base64.

use base64::Engine as _;
use serde_json::{Map, Value};

/// A Go type of a decoded answer.
#[derive(Debug)]
pub enum Ty {
    /// `string`.
    Str,
    /// `uint64` and the named `uint64`s (`basics.Round`, `AppIndex`, ...).
    U64,
    /// `int` / `int64`.
    I64,
    /// `bool`.
    Bool,
    /// `[]byte`.
    Bytes,
    /// `[]string` (go-codec's fast path).
    Strings,
    /// `*T`.
    Ptr(&'static Ty),
    /// `[]T`, with go's name of the slice type (`[]model.Asset`).
    Slice(&'static Ty, &'static str),
    /// A struct.
    Struct(&'static [Field]),
}

/// A struct field: its JSON name and type, in go's declaration order.
#[derive(Debug)]
pub struct Field(pub &'static str, pub Ty);

/// Why go-codec's decode failed: its error text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// `io.EOF`, which go-codec passes up unwrapped: `EOF`.
    Eof,
    /// `json decode error [pos <pos>]: <msg>`.
    At(usize, String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eof => f.write_str("EOF"),
            Self::At(pos, msg) => write!(f, "json decode error [pos {pos}]: {msg}"),
        }
    }
}

/// go's `Decoder.Decode(&response)` with `response` an `any` holding a
/// pointer to `ty`: the decoded value, or go-codec's error.
pub fn decode(body: &[u8], ty: &'static Ty) -> Result<Value, Error> {
    let mut d = Dec::new(body);
    let mut v = zero(ty);
    // mustDecode: a top-level `null` leaves the struct zero
    if d.try_decode_as_nil()? {
        return Ok(v);
    }
    // kInterface: the interface holds a non-nil pointer, decode into it
    d.try_decode_as_nil()?;
    d.decode_value(ty, &mut v)?;
    Ok(v)
}

/// The zero value of `ty`, as go's `encoding/json` prints it.
fn zero(ty: &'static Ty) -> Value {
    match ty {
        Ty::Str => Value::String(String::new()),
        Ty::U64 | Ty::I64 => Value::from(0u64),
        Ty::Bool => Value::Bool(false),
        Ty::Bytes | Ty::Strings | Ty::Slice(..) => Value::Null,
        Ty::Ptr(_) => Value::Null, // left out of a struct
        Ty::Struct(fields) => {
            let mut m = Map::new();
            for Field(name, t) in fields.iter() {
                if !matches!(t, Ty::Ptr(_)) {
                    m.insert((*name).to_string(), zero(t));
                }
            }
            Value::Object(m)
        }
    }
}

/// go-codec's `valueType` numbers (`helper.go`).
const VALUE_TYPE_UNSET: u8 = 0;
const VALUE_TYPE_NIL: u8 = 1;
const VALUE_TYPE_STRING: u8 = 6;
const VALUE_TYPE_MAP: u8 = 9;
const VALUE_TYPE_ARRAY: u8 = 10;

#[derive(Clone, Copy, PartialEq, Eq)]
enum LastByte {
    Undefined,
    CanRead,
    CanUnread,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Container {
    None,
    MapStart,
    MapKey,
    MapValue,
    MapEnd,
    ArrayStart,
    ArrayElem,
    ArrayEnd,
}

/// `jsonScratchArrayLen`: the size of `jsonDecDriver.b2`, where a quoted
/// string is first read.
const SCRATCH: usize = 64;

#[derive(PartialEq, Eq)]
struct LoopState {
    n: usize,
    off: usize,
    tok: u8,
    last: u8,
    ls: LastByte,
    c: Container,
}

struct Dec<'a> {
    src: &'a [u8],
    off: usize,
    /// `ioDecReaderCommon.n`: the position errors report.
    n: usize,
    last: u8,
    ls: LastByte,
    tok: u8,
    c: Container,
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

fn is_num(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'e' | b'E' | b'.' | b'+' | b'-')
}

/// go's `%c` of a byte: the rune of that value.
fn ch(b: u8) -> char {
    char::from(b)
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

impl<'a> Dec<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            off: 0,
            n: 0,
            last: 0,
            ls: LastByte::Undefined,
            tok: 0,
            c: Container::None,
        }
    }

    fn err<T>(&self, msg: impl Into<String>) -> Result<T, Error> {
        Err(Error::At(self.n, msg.into()))
    }

    // ---- ioDecReader ------------------------------------------------------

    /// `ioDecReader.ReadByte` (through its own `Read`, as an
    /// `http.MaxBytesReader` is no `io.ByteScanner`).
    fn read_byte(&mut self) -> Option<u8> {
        if self.ls == LastByte::CanRead {
            self.ls = LastByte::CanUnread;
            return Some(self.last);
        }
        let b = *self.src.get(self.off)?;
        self.off += 1;
        self.last = b;
        self.ls = LastByte::CanUnread;
        Some(b)
    }

    fn readn1eof(&mut self) -> Option<u8> {
        let b = self.read_byte()?;
        self.n += 1;
        Some(b)
    }

    fn readn1(&mut self) -> Result<u8, Error> {
        self.readn1eof().ok_or(Error::Eof)
    }

    fn unreadn1(&mut self) -> Result<(), Error> {
        match self.ls {
            LastByte::CanUnread => {
                self.ls = LastByte::CanRead;
                self.n -= 1;
                Ok(())
            }
            LastByte::CanRead => self.err("cannot unread - last byte has not been read"),
            LastByte::Undefined => self.err("cannot unread - nothing has been read"),
        }
    }

    /// `readx(k)`: `decReadFull` of `k` bytes, `EOF` when the body ends
    /// first.
    fn readx(&mut self, k: usize) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(k);
        if self.ls == LastByte::CanRead {
            self.ls = LastByte::CanUnread;
            out.push(self.last);
        }
        let avail = (k - out.len()).min(self.src.len() - self.off);
        if avail > 0 {
            out.extend_from_slice(&self.src[self.off..self.off + avail]);
            self.off += avail;
            self.last = out[out.len() - 1];
            self.ls = LastByte::CanUnread;
        }
        if out.len() < k {
            return Err(Error::Eof);
        }
        self.n += k;
        Ok(out)
    }

    fn skip_ws(&mut self) -> u8 {
        loop {
            match self.readn1eof() {
                None => return 0,
                Some(b) if is_ws(b) => continue,
                Some(b) => return b,
            }
        }
    }

    fn read_to_num(&mut self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        loop {
            match self.readn1eof() {
                None => return Ok(out),
                Some(b) if is_num(b) => out.push(b),
                Some(_) => {
                    self.unreadn1()?;
                    return Ok(out);
                }
            }
        }
    }

    /// `readUntil(d.b2[:0], '"')`: the bytes up to and including the quote,
    /// and the capacity of the slice holding them (`b2`'s, or what go's
    /// `append` grew it to).
    fn read_until_quote(&mut self) -> Result<(Vec<u8>, usize), Error> {
        let mut out = Vec::new();
        let mut cap = SCRATCH;
        loop {
            let b = self.readn1eof().ok_or(Error::Eof)?;
            if out.len() == cap {
                cap = go_grow_bytes(cap, cap + 1);
            }
            out.push(b);
            if b == b'"' {
                return Ok((out, cap));
            }
        }
    }

    // ---- jsonDecDriver ----------------------------------------------------

    fn ensure_tok(&mut self) {
        if self.tok == 0 {
            self.tok = self.skip_ws();
        }
    }

    fn read_map_start(&mut self) -> Result<(), Error> {
        self.ensure_tok();
        if self.tok != b'{' {
            return self.err(format!(
                "read map - expect char '{{' but got char '{}'",
                ch(self.tok)
            ));
        }
        self.tok = 0;
        self.c = Container::MapStart;
        Ok(())
    }

    fn read_array_start(&mut self) -> Result<(), Error> {
        self.ensure_tok();
        if self.tok != b'[' {
            return self.err(format!(
                "read array - expect char '[' but got char '{}'",
                ch(self.tok)
            ));
        }
        self.tok = 0;
        self.c = Container::ArrayStart;
        Ok(())
    }

    fn check_break(&mut self) -> bool {
        self.ensure_tok();
        self.tok == b'}' || self.tok == b']'
    }

    /// `!CheckBreak()` of a container loop. A loop that starts again in
    /// exactly the state it last started in would go round forever: go-codec
    /// does, on an array cut after a comma (`[1,`: each element reads the
    /// comma back through `unreadn1`), growing the slice until the process
    /// runs out of memory. That is reported as the `EOF` it never gets to.
    fn more(&mut self, seen: &mut Option<LoopState>) -> Result<bool, Error> {
        let now = LoopState {
            n: self.n,
            off: self.off,
            tok: self.tok,
            last: self.last,
            ls: self.ls,
            c: self.c,
        };
        if seen.as_ref() == Some(&now) {
            return Err(Error::Eof);
        }
        *seen = Some(now);
        Ok(!self.check_break())
    }

    fn read_array_elem(&mut self) -> Result<(), Error> {
        self.ensure_tok();
        if self.c != Container::ArrayStart {
            if self.tok != b',' {
                return self.err(format!(
                    "read array element - expect char ',' but got char '{}'",
                    ch(self.tok)
                ));
            }
            self.tok = 0;
        }
        self.c = Container::ArrayElem;
        Ok(())
    }

    fn read_array_end(&mut self) -> Result<(), Error> {
        self.ensure_tok();
        if self.tok != b']' {
            return self.err(format!(
                "read array end - expect char ']' but got char '{}'",
                ch(self.tok)
            ));
        }
        self.tok = 0;
        self.c = Container::ArrayEnd;
        Ok(())
    }

    fn read_map_elem_key(&mut self) -> Result<(), Error> {
        self.ensure_tok();
        if self.c != Container::MapStart {
            if self.tok != b',' {
                return self.err(format!(
                    "read map key - expect char ',' but got char '{}'",
                    ch(self.tok)
                ));
            }
            self.tok = 0;
        }
        self.c = Container::MapKey;
        Ok(())
    }

    fn read_map_elem_value(&mut self) -> Result<(), Error> {
        self.ensure_tok();
        if self.tok != b':' {
            return self.err(format!(
                "read map value - expect char ':' but got char '{}'",
                ch(self.tok)
            ));
        }
        self.tok = 0;
        self.c = Container::MapValue;
        Ok(())
    }

    fn read_map_end(&mut self) -> Result<(), Error> {
        self.ensure_tok();
        if self.tok != b'}' {
            return self.err(format!(
                "read map end - expect char '}}' but got char '{}'",
                ch(self.tok)
            ));
        }
        self.tok = 0;
        self.c = Container::MapEnd;
        Ok(())
    }

    /// `readLit4True` / `readLit4False` / `readLit4Null`: the rest of the
    /// literal whose first byte is the token.
    fn read_lit(&mut self, rest: &str) -> Result<(), Error> {
        let bs = self.readx(rest.len())?;
        self.tok = 0;
        if bs != rest.as_bytes() {
            return self.err(format!("expecting {rest}: got {}", lossy(&bs)));
        }
        Ok(())
    }

    fn try_decode_as_nil(&mut self) -> Result<bool, Error> {
        self.ensure_tok();
        if self.tok == b'n' {
            self.read_lit("ull")?;
            return Ok(true);
        }
        Ok(false)
    }

    fn decode_bool(&mut self) -> Result<bool, Error> {
        self.ensure_tok();
        let fquot = self.c == Container::MapKey && self.tok == b'"';
        if fquot {
            self.tok = self.readn1()?;
        }
        let v = match self.tok {
            b'f' => {
                self.read_lit("alse")?;
                false
            }
            b't' => {
                self.read_lit("rue")?;
                true
            }
            t => return self.err(format!("decode bool: got first char {}", ch(t))),
        };
        if fquot {
            self.readn1()?;
        }
        Ok(v)
    }

    fn container_type(&mut self) -> u8 {
        self.ensure_tok();
        match self.tok {
            b'{' => VALUE_TYPE_MAP,
            b'[' => VALUE_TYPE_ARRAY,
            b'n' => VALUE_TYPE_NIL,
            b'"' => VALUE_TYPE_STRING,
            _ => VALUE_TYPE_UNSET,
        }
    }

    fn dec_num_bytes(&mut self) -> Result<Vec<u8>, Error> {
        self.ensure_tok();
        let bs = if self.tok == b'"' {
            let (mut bs, _) = self.read_until_quote()?;
            bs.pop();
            bs
        } else {
            self.unreadn1()?;
            self.read_to_num()?
        };
        self.tok = 0;
        Ok(bs)
    }

    fn decode_u64(&mut self) -> Result<u64, Error> {
        let bs = self.dec_num_bytes()?;
        if bs.is_empty() {
            return Ok(0);
        }
        let p = parse_integer(&bs);
        if p.overflow {
            return self.err(format!(
                "overflow parsing unsigned integer: {}",
                lossy(&bs)
            ));
        }
        if p.neg {
            return self.err(format!(
                "minus found parsing unsigned integer: {}",
                lossy(&bs)
            ));
        }
        if p.bad_syntax {
            return self.u64_via_float(&bs);
        }
        Ok(p.n)
    }

    fn decode_i64(&mut self) -> Result<i64, Error> {
        const CUTOFF: u64 = 1 << 63;
        let bs = self.dec_num_bytes()?;
        if bs.is_empty() {
            return Ok(0);
        }
        let p = parse_integer(&bs);
        let mut n = p.n;
        if p.overflow {
            return self.err(format!("overflow parsing integer: {}", lossy(&bs)));
        }
        if p.bad_syntax {
            n = if p.neg {
                self.u64_via_float(&bs[1..])?
            } else {
                self.u64_via_float(&bs)?
            };
        }
        if p.neg {
            if n > CUTOFF {
                return self.err(format!("overflow parsing integer: {}", lossy(&bs)));
            }
            Ok((n as i64).wrapping_neg())
        } else {
            if n >= CUTOFF {
                return self.err(format!("overflow parsing integer: {}", lossy(&bs)));
            }
            Ok(n as i64)
        }
    }

    /// `decUint64ViaFloat`.
    fn u64_via_float(&self, s: &[u8]) -> Result<u64, Error> {
        if s.is_empty() {
            return Ok(0);
        }
        let Some(f) = go_parse_float(s) else {
            return self.err(format!("invalid syntax for integer: {}", lossy(s)));
        };
        let (fi, ff) = (f.trunc(), f - f.trunc());
        let ff = if f.is_infinite() { 0.0 } else { ff };
        if ff > 0.0 {
            return self.err(format!(
                "fractional part found parsing integer: {}",
                lossy(s)
            ));
        }
        if fi > u64::MAX as f64 {
            return self.err(format!("overflow parsing integer: {}", lossy(s)));
        }
        Ok(go_f64_to_u64(fi))
    }

    /// `appendStringAsBytes`: a string, or a non-string scalar as its text.
    /// Returns the bytes and whether it was `null`.
    fn append_string_as_bytes(&mut self) -> Result<(Vec<u8>, bool), Error> {
        self.ensure_tok();
        if self.tok != b'"' {
            return match self.tok {
                b'n' => {
                    self.read_lit("ull")?;
                    Ok((Vec::new(), true))
                }
                b'f' => {
                    self.read_lit("alse")?;
                    Ok((b"false".to_vec(), false))
                }
                b't' => {
                    self.read_lit("rue")?;
                    Ok((b"true".to_vec(), false))
                }
                _ => Ok((self.dec_num_bytes()?, false)),
            };
        }
        self.tok = 0;
        let (mut cs, mut cap) = self.read_until_quote()?;
        let mut v = Vec::new();
        let (mut i, mut cursor) = (0usize, 0usize);
        loop {
            if i == cs.len() {
                v.extend_from_slice(&cs[cursor..]);
                (cs, cap) = self.read_until_quote()?;
                (i, cursor) = (0, 0);
            }
            let Some(&c) = cs.get(i) else {
                return self.err(format!(
                    "runtime error: index out of range [{i}] with length {}",
                    cs.len()
                ));
            };
            if c == b'"' {
                v.extend_from_slice(&cs[cursor..i]);
                break;
            }
            if c != b'\\' {
                i += 1;
                continue;
            }
            v.extend_from_slice(&cs[cursor..i]);
            i += 1;
            let c = cs[i];
            match c {
                b'"' | b'\\' | b'/' | b'\'' => v.push(c),
                b'b' => v.push(0x08),
                b'f' => v.push(0x0c),
                b'n' => v.push(b'\n'),
                b'r' => v.push(b'\r'),
                b't' => v.push(b'\t'),
                b'u' => {
                    if cs.len() < i + 4 {
                        return self.err("need at least 4 more bytes for unicode sequence");
                    }
                    if i + 5 > cap {
                        return self.err(format!(
                            "runtime error: slice bounds out of range [:{}] with capacity {cap}",
                            i + 5
                        ));
                    }
                    let r = self.unicode_escape(&cs, cap, &mut i)?;
                    let mut buf = [0u8; 4];
                    v.extend_from_slice(r.encode_utf8(&mut buf).as_bytes());
                }
                _ => {
                    return self.err(format!("unsupported escaped value: {}", ch(c)));
                }
            }
            i += 1;
            cursor = i;
        }
        Ok((v, false))
    }

    /// The rune of the `\uXXXX` escape whose `u` is at `cs[*i]`, leaving `*i`
    /// where go's loop leaves it. Only the bytes up to the first non-hex one
    /// are read, and the slice always ends with a quote, so no byte past
    /// `cs.len()` is ever looked at.
    fn unicode_escape(&self, cs: &[u8], cap: usize, i: &mut usize) -> Result<char, Error> {
        const REPLACEMENT: char = '\u{fffd}';
        let hex = |c: u8| match c {
            b'0'..=b'9' => Some(u32::from(c - b'0')),
            b'a'..=b'f' => Some(u32::from(c - b'a' + 10)),
            b'A'..=b'F' => Some(u32::from(c - b'A' + 10)),
            _ => None,
        };
        let mut rr = 0u32;
        for k in 0..4 {
            match cs.get(*i + 1 + k).copied().and_then(hex) {
                Some(d) => rr = rr * 16 + d,
                None => {
                    *i += 4;
                    return Ok(REPLACEMENT);
                }
            }
        }
        *i += 4;
        if !(0xd800..0xe000).contains(&rr) {
            return Ok(char::from_u32(rr).unwrap_or(REPLACEMENT));
        }
        // A surrogate: go consumes a following `\uXXXX` but (its low half
        // never being assigned) always yields U+FFFD.
        if cs.len() >= *i + 6 {
            // `cs[i+1:][:6:6]`
            let room = cap - (*i + 1);
            if room < 6 {
                return self.err(format!(
                    "runtime error: slice bounds out of range [::6] with capacity {room}"
                ));
            }
            if cs[*i + 1] == b'\\' && cs[*i + 2] == b'u' {
                *i += 2;
                for j in 2..6 {
                    if hex(cs[*i - 1 + j]).is_none() {
                        *i += 4;
                        return Ok(REPLACEMENT);
                    }
                }
                *i += 4;
            }
        }
        Ok(REPLACEMENT)
    }

    fn decode_string(&mut self) -> Result<String, Error> {
        Ok(lossy(&self.append_string_as_bytes()?.0))
    }

    /// `DecodeBytes`: a base64 string (`null` is a nil slice).
    fn decode_bytes(&mut self) -> Result<Value, Error> {
        let (bs, null) = self.append_string_as_bytes()?;
        if bs.is_empty() {
            return Ok(if null {
                Value::Null
            } else {
                Value::String(String::new())
            });
        }
        match go_base64_decode(&bs) {
            Ok(out) => Ok(Value::String(
                base64::engine::general_purpose::STANDARD.encode(out),
            )),
            Err(at) => self.err(format!(
                "error decoding base64 binary '{}': illegal base64 data at input byte {at}",
                lossy(&bs)
            )),
        }
    }

    // ---- Decoder ----------------------------------------------------------

    /// `decodeValue` of a value that is not `null` into `v`.
    fn decode_value(&mut self, ty: &'static Ty, v: &mut Value) -> Result<(), Error> {
        match ty {
            Ty::Str => *v = Value::String(self.decode_string()?),
            Ty::U64 => *v = Value::from(self.decode_u64()?),
            Ty::I64 => *v = Value::from(self.decode_i64()?),
            Ty::Bool => *v = Value::Bool(self.decode_bool()?),
            Ty::Ptr(t) => {
                if v.is_null() {
                    *v = zero(t);
                }
                self.decode_value(t, v)?;
            }
            Ty::Struct(fields) => self.decode_struct(fields, v)?,
            Ty::Bytes => self.decode_byte_slice(v)?,
            Ty::Strings => self.decode_strings(v)?,
            Ty::Slice(elem, name) => self.decode_slice(elem, name, v)?,
        }
        Ok(())
    }

    /// `kStruct`.
    fn decode_struct(&mut self, fields: &'static [Field], v: &mut Value) -> Result<(), Error> {
        let ctyp = self.container_type();
        if ctyp == VALUE_TYPE_MAP {
            self.read_map_start()?;
            let mut seen = None;
        while self.more(&mut seen)? {
                self.read_map_elem_key()?;
                let (key, _) = self.append_string_as_bytes()?;
                self.read_map_elem_value()?;
                // `indexForEncName` reads the first byte of the key (`tiSep2`)
                if key.is_empty() {
                    return self.err("runtime error: index out of range [0] with length 0");
                }
                match fields.iter().find(|f| f.0.as_bytes() == key.as_slice()) {
                    Some(Field(name, t)) => self.decode_field(name, t, v)?,
                    None => {
                        return self.err(format!(
                            "no matching struct field found when decoding stream map with key {}",
                            lossy(&key)
                        ))
                    }
                }
            }
            self.read_map_end()
        } else if ctyp == VALUE_TYPE_ARRAY {
            self.read_array_start()?;
            let mut broke = false;
            for Field(name, t) in fields.iter() {
                if self.check_break() {
                    broke = true;
                    break;
                }
                self.read_array_elem()?;
                self.decode_field(name, t, v)?;
            }
            if !broke && !self.check_break() {
                self.read_array_elem()?;
                return self.err(format!(
                    "no matching struct field found when decoding stream array at index {}",
                    fields.len()
                ));
            }
            self.read_array_end()
        } else {
            self.err("only encoded map or array can be decoded into a struct")
        }
    }

    /// A struct field: `null` sets its zero value, else it is decoded into.
    fn decode_field(&mut self, name: &str, t: &'static Ty, v: &mut Value) -> Result<(), Error> {
        let obj = v.as_object_mut().expect("a struct value is an object");
        if self.try_decode_as_nil()? {
            match t {
                Ty::Ptr(_) => {
                    obj.remove(name);
                }
                _ => {
                    obj.insert(name.to_string(), zero(t));
                }
            }
            return Ok(());
        }
        let slot = obj.entry(name.to_string()).or_insert(Value::Null);
        self.decode_value(t, slot)
    }

    /// `decSliceHelperStart`: whether the stream holds an array (else a map,
    /// whose keys and values are the elements).
    fn slice_start(&mut self) -> Result<bool, Error> {
        match self.container_type() {
            VALUE_TYPE_ARRAY => {
                self.read_array_start()?;
                Ok(true)
            }
            VALUE_TYPE_MAP => {
                self.read_map_start()?;
                Ok(false)
            }
            ctyp => self.err(format!(
                "only encoded map or array can be decoded into a slice ({ctyp})"
            )),
        }
    }

    fn slice_elem(&mut self, array: bool, j: usize) -> Result<(), Error> {
        if array {
            self.read_array_elem()
        } else if j.is_multiple_of(2) {
            self.read_map_elem_key()
        } else {
            self.read_map_elem_value()
        }
    }

    fn slice_end(&mut self, array: bool) -> Result<(), Error> {
        if array {
            self.read_array_end()
        } else {
            self.read_map_end()
        }
    }

    /// `kSlice` of a `[]T`: decoded into the elements already there.
    fn decode_slice(
        &mut self,
        elem: &'static Ty,
        name: &str,
        v: &mut Value,
    ) -> Result<(), Error> {
        let ctyp = self.container_type();
        if ctyp == VALUE_TYPE_STRING {
            return self.err(format!(
                "bytes/string in stream must decode into slice/array of bytes, not {name}"
            ));
        }
        let array = self.slice_start()?;
        let mut items = match std::mem::take(v) {
            Value::Array(a) => a,
            _ => Vec::new(),
        };
        let mut j = 0;
        let mut seen = None;
        while self.more(&mut seen)? {
            self.slice_elem(array, j)?;
            if j >= items.len() {
                items.push(zero(elem));
            }
            if self.try_decode_as_nil()? {
                items[j] = zero(elem);
            } else {
                self.decode_value(elem, &mut items[j])?;
            }
            j += 1;
        }
        items.truncate(j);
        *v = Value::Array(items);
        self.slice_end(array)
    }

    /// The fast path of `[]string`.
    fn decode_strings(&mut self, v: &mut Value) -> Result<(), Error> {
        let array = self.slice_start()?;
        let mut items = Vec::new();
        let mut j = 0;
        let mut seen = None;
        while self.more(&mut seen)? {
            self.slice_elem(array, j)?;
            let s = if self.try_decode_as_nil()? {
                String::new()
            } else {
                self.decode_string()?
            };
            items.push(Value::String(s));
            j += 1;
        }
        *v = Value::Array(items);
        self.slice_end(array)
    }

    /// `kSlice` of a `[]byte`: a base64 string, or the bytes one by one.
    fn decode_byte_slice(&mut self, v: &mut Value) -> Result<(), Error> {
        if self.container_type() == VALUE_TYPE_STRING {
            *v = self.decode_bytes()?;
            return Ok(());
        }
        let array = self.slice_start()?;
        let mut old = match v {
            Value::String(s) => base64::engine::general_purpose::STANDARD
                .decode(s.as_bytes())
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        let mut j = 0;
        let mut seen = None;
        while self.more(&mut seen)? {
            self.slice_elem(array, j)?;
            if j >= old.len() {
                old.push(0);
            }
            if self.try_decode_as_nil()? {
                old[j] = 0;
            } else {
                let b = self.decode_u64()?;
                if b > 0xff {
                    return self.err(format!("uint64 overflow: {b}"));
                }
                old[j] = b as u8;
            }
            j += 1;
        }
        old.truncate(j);
        *v = Value::String(base64::engine::general_purpose::STANDARD.encode(old));
        self.slice_end(array)
    }
}

struct ParsedInt {
    n: u64,
    neg: bool,
    bad_syntax: bool,
    overflow: bool,
}

/// go-codec's `jsonParseInteger`.
fn parse_integer(s: &[u8]) -> ParsedInt {
    let mut p = ParsedInt {
        n: 0,
        neg: false,
        bad_syntax: false,
        overflow: false,
    };
    let s = match s.first() {
        None => return p,
        Some(b'+') => &s[1..],
        Some(b'-') => {
            p.neg = true;
            &s[1..]
        }
        Some(_) => s,
    };
    const CUTOFF: u64 = u64::MAX / 10 + 1;
    for &c in s {
        if !c.is_ascii_digit() {
            p.bad_syntax = true;
            return p;
        }
        if p.n >= CUTOFF {
            p.overflow = true;
            return p;
        }
        p.n *= 10;
        match p.n.checked_add(u64::from(c - b'0')) {
            Some(n1) => p.n = n1,
            None => {
                p.overflow = true;
                return p;
            }
        }
    }
    p
}

/// go's `uint64(f)` on amd64 for a non-negative or NaN `f`.
fn go_f64_to_u64(f: f64) -> u64 {
    const TWO63: f64 = 9_223_372_036_854_775_808.0;
    if f < TWO63 {
        f as i64 as u64
    } else {
        // `int64(f - 2^63) | 1<<63`; NaN converts to 1<<63
        let y = f - TWO63;
        let i = if y.is_nan() || y >= TWO63 {
            i64::MIN
        } else {
            y as i64
        };
        (i as u64) | (1 << 63)
    }
}

/// Go's `strconv.underscoreOK`.
fn underscore_ok(s: &[u8]) -> bool {
    let mut saw = b'^';
    let mut i = 0;
    let s = match s.first() {
        Some(b'-' | b'+') => &s[1..],
        _ => s,
    };
    let mut hex = false;
    if s.len() >= 2 && s[0] == b'0' && matches!(s[1].to_ascii_lowercase(), b'b' | b'o' | b'x') {
        i = 2;
        saw = b'0';
        hex = s[1].eq_ignore_ascii_case(&b'x');
    }
    while i < s.len() {
        let c = s[i];
        if c.is_ascii_digit() || (hex && matches!(c.to_ascii_lowercase(), b'a'..=b'f')) {
            saw = b'0';
        } else if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
        } else {
            if saw == b'_' {
                return false;
            }
            saw = b'!';
        }
        i += 1;
    }
    saw != b'_'
}

/// Go's `strconv.special`: `±inf`, `±infinity`, `nan`, case-insensitive,
/// the whole string.
fn go_special(s: &[u8]) -> Option<f64> {
    let lower: Vec<u8> = s.iter().map(u8::to_ascii_lowercase).collect();
    let (sign, rest) = match lower.first() {
        Some(b'+') => (1.0, &lower[1..]),
        Some(b'-') => (-1.0, &lower[1..]),
        _ => {
            if lower == b"nan" {
                return Some(f64::NAN);
            }
            (1.0, &lower[..])
        }
    };
    (rest == b"inf" || rest == b"infinity").then_some(sign * f64::INFINITY)
}

/// Go's `strconv.readFloat` over all of `s`: `(hex, mantissa digits, binary
/// or decimal exponent)` as a cleaned string for the decimal case.
enum ReadFloat {
    Dec(String),
    Hex { neg: bool, mant: u64, trunc: bool, exp: i64 },
}

fn read_float(s: &[u8]) -> Option<ReadFloat> {
    let mut i = 0;
    let mut neg = false;
    let mut underscores = false;
    match s.first()? {
        b'+' => i += 1,
        b'-' => {
            i += 1;
            neg = true;
        }
        _ => {}
    }
    let hex = i + 2 < s.len() && s[i] == b'0' && s[i + 1].eq_ignore_ascii_case(&b'x');
    if hex {
        i += 2;
    }
    let (mut sawdot, mut sawdigits) = (false, false);
    let (mut nd, mut nd_mant, mut dp) = (0i64, 0i64, 0i64);
    let mut mant = 0u64;
    let mut trunc = false;
    let max_mant = if hex { 16 } else { 19 };
    while i < s.len() {
        let c = s[i];
        if c == b'_' {
            underscores = true;
        } else if c == b'.' {
            if sawdot {
                break;
            }
            sawdot = true;
            dp = nd;
        } else if c.is_ascii_digit() || (hex && matches!(c.to_ascii_lowercase(), b'a'..=b'f')) {
            sawdigits = true;
            let d = if c.is_ascii_digit() {
                u64::from(c - b'0')
            } else {
                u64::from(c.to_ascii_lowercase() - b'a' + 10)
            };
            if c == b'0' && nd == 0 {
                // leading zeros are ignored
                dp -= 1;
            } else {
                nd += 1;
                if nd_mant < max_mant {
                    mant = mant * if hex { 16 } else { 10 } + d;
                    nd_mant += 1;
                } else if !c.is_ascii_digit() || c != b'0' {
                    trunc = true;
                }
            }
        } else {
            break;
        }
        i += 1;
    }
    if !sawdigits {
        return None;
    }
    if !sawdot {
        dp = nd;
    }
    if hex {
        dp *= 4;
        nd_mant *= 4;
    }
    let exp_char = if hex { b'p' } else { b'e' };
    if i < s.len() && s[i].to_ascii_lowercase() == exp_char {
        i += 1;
        if i >= s.len() {
            return None;
        }
        let mut esign = 1i64;
        match s[i] {
            b'+' => i += 1,
            b'-' => {
                i += 1;
                esign = -1;
            }
            _ => {}
        }
        if i >= s.len() || !s[i].is_ascii_digit() {
            return None;
        }
        let mut e = 0i64;
        while i < s.len() && (s[i].is_ascii_digit() || s[i] == b'_') {
            if s[i] == b'_' {
                underscores = true;
            } else if e < 10000 {
                e = e * 10 + i64::from(s[i] - b'0');
            }
            i += 1;
        }
        dp += e * esign;
    } else if hex {
        return None;
    }
    if i != s.len() || (underscores && !underscore_ok(s)) {
        return None;
    }
    if hex {
        let exp = if mant != 0 { dp - nd_mant } else { 0 };
        return Some(ReadFloat::Hex {
            neg,
            mant,
            trunc,
            exp,
        });
    }
    let clean: String = s
        .iter()
        .filter(|&&c| c != b'_')
        .map(|&c| char::from(c))
        .collect();
    Some(ReadFloat::Dec(clean))
}

/// Go's `strconv.ParseFloat(s, 64)`, `None` on an error (bad syntax or out
/// of range).
fn go_parse_float(s: &[u8]) -> Option<f64> {
    if let Some(f) = go_special(s) {
        return Some(f);
    }
    let f = match read_float(s)? {
        ReadFloat::Dec(clean) => clean.parse::<f64>().ok()?,
        ReadFloat::Hex {
            neg,
            mant,
            trunc,
            exp,
        } => {
            let m = (mant | u64::from(trunc)) as f64;
            let f = m * 2f64.powi(exp.clamp(-2000, 2000) as i32);
            if neg {
                -f
            } else {
                f
            }
        }
    };
    (!f.is_infinite()).then_some(f)
}

/// The capacity go's `append` gives a `[]byte` of capacity `old` that must
/// hold `need` bytes (`runtime.growslice` with the malloc size classes).
fn go_grow_bytes(old: usize, need: usize) -> usize {
    let mut newcap = old;
    let doublecap = newcap + newcap;
    if need > doublecap {
        newcap = need;
    } else if old < 256 {
        newcap = doublecap;
    } else {
        while newcap < need {
            newcap += (newcap + 3 * 256) >> 2;
        }
    }
    round_up_size(newcap)
}

/// `runtime.roundupsize` for a no-pointer allocation.
fn round_up_size(size: usize) -> usize {
    const CLASSES: [usize; 67] = [
        8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256, 288, 320,
        352, 384, 416, 448, 480, 512, 576, 640, 704, 768, 896, 1024, 1152, 1280, 1408, 1536, 1792,
        2048, 2304, 2688, 3072, 3200, 3456, 4096, 4864, 5376, 6144, 6528, 6784, 6912, 8192, 9472,
        9728, 10240, 10880, 12288, 13568, 14336, 16384, 18432, 19072, 20480, 21760, 24576, 27264,
        28672, 32768,
    ];
    match CLASSES.iter().find(|&&c| c >= size) {
        Some(&c) => c,
        None => size.div_ceil(8192) * 8192,
    }
}

/// Go's `base64.StdEncoding.Decode`: the bytes, or the offset of its
/// `illegal base64 data at input byte N` (`\r` and `\n` are skipped).
fn go_base64_decode(src: &[u8]) -> Result<Vec<u8>, usize> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut si = 0;
    while si < src.len() {
        let mut dbuf = [0u8; 4];
        let mut dlen = 4;
        let mut j = 0;
        let mut trailing = None;
        while j < 4 {
            if si == src.len() {
                if j == 0 {
                    return Ok(out);
                }
                return Err(si - j);
            }
            let c = src[si];
            si += 1;
            if let Some(v) = val(c) {
                dbuf[j] = v;
                j += 1;
                continue;
            }
            if c == b'\n' || c == b'\r' {
                continue;
            }
            if c != b'=' {
                return Err(si - 1);
            }
            match j {
                0 | 1 => return Err(si - 1),
                2 => {
                    while si < src.len() && (src[si] == b'\n' || src[si] == b'\r') {
                        si += 1;
                    }
                    if si == src.len() {
                        return Err(src.len());
                    }
                    if src[si] != b'=' {
                        return Err(si - 1);
                    }
                    si += 1;
                }
                _ => {}
            }
            while si < src.len() && (src[si] == b'\n' || src[si] == b'\r') {
                si += 1;
            }
            if si < src.len() {
                trailing = Some(si);
            }
            dlen = j;
            break;
        }
        let v = u32::from(dbuf[0]) << 18
            | u32::from(dbuf[1]) << 12
            | u32::from(dbuf[2]) << 6
            | u32::from(dbuf[3]);
        let bytes = [(v >> 16) as u8, (v >> 8) as u8, v as u8];
        out.extend_from_slice(&bytes[..dlen - 1]);
        if let Some(at) = trailing {
            return Err(at);
        }
    }
    Ok(out)
}

// ---- the Go types goal reads ----------------------------------------------

const ROUND: Ty = Ty::U64;

/// `model.ApplicationStateSchema`.
pub const APPLICATION_STATE_SCHEMA: Ty = Ty::Struct(&[
    Field("num-byte-slice", Ty::U64),
    Field("num-uint", Ty::U64),
]);

/// `model.TealValue`.
const TEAL_VALUE: Ty = Ty::Struct(&[
    Field("bytes", Ty::Str),
    Field("type", Ty::U64),
    Field("uint", Ty::U64),
]);

/// `model.TealKeyValueStore` (`[]model.TealKeyValue`).
const TEAL_KEY_VALUE_STORE: Ty = Ty::Slice(
    &Ty::Struct(&[Field("key", Ty::Str), Field("value", TEAL_VALUE)]),
    "[]model.TealKeyValue",
);

/// `model.ApplicationLocalState`.
const APPLICATION_LOCAL_STATE: Ty = Ty::Struct(&[
    Field("id", Ty::U64),
    Field("key-value", Ty::Ptr(&TEAL_KEY_VALUE_STORE)),
    Field("schema", APPLICATION_STATE_SCHEMA),
]);

/// `model.AssetHolding`.
const ASSET_HOLDING: Ty = Ty::Struct(&[
    Field("amount", Ty::U64),
    Field("asset-id", Ty::U64),
    Field("is-frozen", Ty::Bool),
]);

/// `model.ApplicationParams`.
const APPLICATION_PARAMS: Ty = Ty::Struct(&[
    Field("approval-program", Ty::Bytes),
    Field("clear-state-program", Ty::Bytes),
    Field("creator", Ty::Str),
    Field("extra-program-pages", Ty::Ptr(&Ty::U64)),
    Field("family-box-access", Ty::Ptr(&Ty::Bool)),
    Field("foreign-box-reads", Ty::Ptr(&Ty::Bool)),
    Field("global-state", Ty::Ptr(&TEAL_KEY_VALUE_STORE)),
    Field("global-state-schema", Ty::Ptr(&APPLICATION_STATE_SCHEMA)),
    Field("local-state-schema", Ty::Ptr(&APPLICATION_STATE_SCHEMA)),
    Field("size-sponsor", Ty::Ptr(&Ty::Str)),
    Field("version", Ty::Ptr(&Ty::U64)),
]);

/// `model.AssetParams`.
const ASSET_PARAMS: Ty = Ty::Struct(&[
    Field("clawback", Ty::Ptr(&Ty::Str)),
    Field("creator", Ty::Str),
    Field("decimals", Ty::U64),
    Field("default-frozen", Ty::Ptr(&Ty::Bool)),
    Field("freeze", Ty::Ptr(&Ty::Str)),
    Field("manager", Ty::Ptr(&Ty::Str)),
    Field("metadata-hash", Ty::Ptr(&Ty::Bytes)),
    Field("name", Ty::Ptr(&Ty::Str)),
    Field("name-b64", Ty::Ptr(&Ty::Bytes)),
    Field("reserve", Ty::Ptr(&Ty::Str)),
    Field("total", Ty::U64),
    Field("unit-name", Ty::Ptr(&Ty::Str)),
    Field("unit-name-b64", Ty::Ptr(&Ty::Bytes)),
    Field("url", Ty::Ptr(&Ty::Str)),
    Field("url-b64", Ty::Ptr(&Ty::Bytes)),
]);

/// `model.AccountParticipation`.
const ACCOUNT_PARTICIPATION: Ty = Ty::Struct(&[
    Field("selection-participation-key", Ty::Bytes),
    Field("state-proof-key", Ty::Ptr(&Ty::Bytes)),
    Field("vote-first-valid", ROUND),
    Field("vote-key-dilution", Ty::U64),
    Field("vote-last-valid", ROUND),
    Field("vote-participation-key", Ty::Bytes),
]);

/// `model.Account` (`GET /v2/accounts/{address}`).
pub const ACCOUNT: Ty = Ty::Struct(&[
    Field("address", Ty::Str),
    Field("amount", Ty::U64),
    Field("amount-without-pending-rewards", Ty::U64),
    Field(
        "apps-local-state",
        Ty::Ptr(&Ty::Slice(
            &APPLICATION_LOCAL_STATE,
            "[]model.ApplicationLocalState",
        )),
    ),
    Field("apps-total-extra-pages", Ty::Ptr(&Ty::U64)),
    Field("apps-total-schema", Ty::Ptr(&APPLICATION_STATE_SCHEMA)),
    Field(
        "assets",
        Ty::Ptr(&Ty::Slice(&ASSET_HOLDING, "[]model.AssetHolding")),
    ),
    Field("auth-addr", Ty::Ptr(&Ty::Str)),
    Field(
        "created-apps",
        Ty::Ptr(&Ty::Slice(
            &Ty::Struct(&[
                Field("id", Ty::U64),
                Field("params", Ty::Ptr(&APPLICATION_PARAMS)),
            ]),
            "[]model.Application",
        )),
    ),
    Field(
        "created-assets",
        Ty::Ptr(&Ty::Slice(
            &Ty::Struct(&[
                Field("index", Ty::U64),
                Field("params", Ty::Ptr(&ASSET_PARAMS)),
            ]),
            "[]model.Asset",
        )),
    ),
    Field("incentive-eligible", Ty::Ptr(&Ty::Bool)),
    Field("last-heartbeat", Ty::Ptr(&ROUND)),
    Field("last-proposed", Ty::Ptr(&ROUND)),
    Field("min-balance", Ty::U64),
    Field("participation", Ty::Ptr(&ACCOUNT_PARTICIPATION)),
    Field("pending-rewards", Ty::U64),
    Field("reward-base", Ty::Ptr(&Ty::U64)),
    Field("rewards", Ty::U64),
    Field("round", ROUND),
    Field("sig-type", Ty::Ptr(&Ty::Str)),
    Field("status", Ty::Str),
    Field("total-apps-opted-in", Ty::U64),
    Field("total-assets-opted-in", Ty::U64),
    Field("total-box-bytes", Ty::Ptr(&Ty::U64)),
    Field("total-boxes", Ty::Ptr(&Ty::U64)),
    Field("total-created-apps", Ty::U64),
    Field("total-created-assets", Ty::U64),
]);

/// `common.Version` (`GET /versions`).
pub const VERSION: Ty = Ty::Struct(&[
    Field("versions", Ty::Strings),
    Field("genesis_id", Ty::Str),
    Field("genesis_hash_b64", Ty::Bytes),
    Field(
        "build",
        Ty::Struct(&[
            Field("major", Ty::I64),
            Field("minor", Ty::I64),
            Field("build_number", Ty::I64),
            Field("commit_hash", Ty::Str),
            Field("branch", Ty::Str),
            Field("channel", Ty::Str),
        ]),
    ),
]);

/// `model.NodeStatusResponse` (`GET /v2/status`).
pub const NODE_STATUS: Ty = Ty::Struct(&[
    Field("catchpoint", Ty::Ptr(&Ty::Str)),
    Field("catchpoint-acquired-blocks", Ty::Ptr(&Ty::U64)),
    Field("catchpoint-processed-accounts", Ty::Ptr(&Ty::U64)),
    Field("catchpoint-processed-kvs", Ty::Ptr(&Ty::U64)),
    Field("catchpoint-total-accounts", Ty::Ptr(&Ty::U64)),
    Field("catchpoint-total-blocks", Ty::Ptr(&Ty::U64)),
    Field("catchpoint-total-kvs", Ty::Ptr(&Ty::U64)),
    Field("catchpoint-verified-accounts", Ty::Ptr(&Ty::U64)),
    Field("catchpoint-verified-kvs", Ty::Ptr(&Ty::U64)),
    Field("catchup-time", Ty::I64),
    Field("last-catchpoint", Ty::Ptr(&Ty::Str)),
    Field("last-round", ROUND),
    Field("last-version", Ty::Str),
    Field("next-version", Ty::Str),
    Field("next-version-round", ROUND),
    Field("next-version-supported", Ty::Bool),
    Field("stopped-at-unsupported-round", Ty::Bool),
    Field("time-since-last-round", Ty::I64),
    Field("upgrade-delay", Ty::Ptr(&ROUND)),
    Field("upgrade-next-protocol-vote-before", Ty::Ptr(&ROUND)),
    Field("upgrade-no-votes", Ty::Ptr(&ROUND)),
    Field("upgrade-node-vote", Ty::Ptr(&Ty::Bool)),
    Field("upgrade-vote-rounds", Ty::Ptr(&ROUND)),
    Field("upgrade-votes", Ty::Ptr(&ROUND)),
    Field("upgrade-votes-required", Ty::Ptr(&ROUND)),
    Field("upgrade-yes-votes", Ty::Ptr(&ROUND)),
]);

/// `model.SupplyResponse` (`GET /v2/ledger/supply`).
pub const SUPPLY: Ty = Ty::Struct(&[
    Field("current_round", ROUND),
    Field("online-money", Ty::U64),
    Field("online-stake", Ty::U64),
    Field("total-money", Ty::U64),
]);

#[cfg(test)]
mod tests {
    use super::*;

    fn err(body: &str, ty: &'static Ty) -> String {
        decode(body.as_bytes(), ty).unwrap_err().to_string()
    }

    #[test]
    fn errors_read_like_go_codec() {
        assert_eq!(
            err(r#"{"amount":5,"foo":1}"#, &ACCOUNT),
            "json decode error [pos 18]: no matching struct field found when decoding stream map with key foo"
        );
        assert_eq!(err(r#"{"address":"abc"#, &ACCOUNT), "EOF");
        assert_eq!(
            err(r#"{"amount":"#, &ACCOUNT),
            "json decode error [pos 10]: read map key - expect char ',' but got char ':'"
        );
        assert_eq!(
            err(r#"{"address":"\u12"}"#, &ACCOUNT),
            "json decode error [pos 17]: runtime error: index out of range [6] with length 5"
        );
        assert_eq!(
            err("", &ACCOUNT),
            "json decode error [pos 0]: only encoded map or array can be decoded into a struct"
        );
        assert_eq!(
            err(r#"{"":1}"#, &ACCOUNT),
            "json decode error [pos 4]: runtime error: index out of range [0] with length 0"
        );
        // go-codec never returns from these (the slice grows until the
        // process runs out of memory)
        assert_eq!(err(r#"{"versions":[1,"#, &VERSION), "EOF");
        assert_eq!(
            err(r#"{"created-apps":[{"id":1,"params":{"approval-program":[1,"#, &ACCOUNT),
            "EOF"
        );
    }

    #[test]
    fn go_codec_accepts_what_json_does_not() {
        let v = decode(br#"{"amount":"42","address":true}xyz"#, &ACCOUNT).unwrap();
        assert_eq!(v["amount"], 42);
        assert_eq!(v["address"], "true");
        let v = decode(b"[1,2]", &ACCOUNT).unwrap();
        assert_eq!((v["address"].as_str(), v["amount"].as_u64()), (Some("1"), Some(2)));
        assert_eq!(decode(b"null", &ACCOUNT).unwrap()["amount"], 0);
        assert_eq!(decode(br#"{"amount":1e3}"#, &ACCOUNT).unwrap()["amount"], 1000);
    }

    #[test]
    fn go_base64_errors() {
        assert_eq!(go_base64_decode(b"!!"), Err(0));
        assert_eq!(go_base64_decode(b"QQ=="), Ok(b"A".to_vec()));
        assert_eq!(go_base64_decode(b"QQ="), Err(3));
        assert_eq!(go_base64_decode(b"QQ==x"), Err(4));
        assert_eq!(go_base64_decode(b"Q\nQ=\r="), Ok(b"A".to_vec()));
        assert_eq!(go_base64_decode(b"QUJD"), Ok(b"ABC".to_vec()));
        assert_eq!(go_base64_decode(b"QUJ"), Err(0));
    }

    #[test]
    fn go_parse_float_matches_strconv() {
        for (s, want) in [
            ("1_0", Some(10.0)),
            ("0x1p3", Some(8.0)),
            ("0x_1p3", Some(8.0)),
            ("1e400", None),
            ("1e-400", Some(0.0)),
            ("+Inf", Some(f64::INFINITY)),
            ("+nan", None),
            (".5", Some(0.5)),
            ("5.", Some(5.0)),
            ("1e+", None),
            ("1__0", None),
            ("0x1.8p1", Some(3.0)),
            ("0x1", None),
            ("1e1_0", Some(1e10)),
            ("infin", None),
        ] {
            assert_eq!(go_parse_float(s.as_bytes()), want, "{s}");
        }
        assert!(go_parse_float(b"NaN").unwrap().is_nan());
    }
}
