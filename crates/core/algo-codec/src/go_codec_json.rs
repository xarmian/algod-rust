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

//! go-codec's JSON decoder (`github.com/algorand/go-codec/codec` v1.1.10)
//! with go-algorand's `protocol.JSONHandle` / `JSONStrictHandle`
//! (`ErrorIfNoField`, `ErrorIfNoArrayExpand`; the two differ only when
//! encoding) decoding into a reflected Go type ([`Ty`]), from either of its
//! two readers:
//!
//! * [`decode`] / [`decode_reading`]: what go's `goal` does with the JSON body
//!   of an algod answer (issue #2466): `restClient.submitForm` decodes it with
//!   `protocol.NewJSONDecoder(resp.Body).Decode(&response)`, reading the body
//!   one byte at a time through its unbuffered `ioDecReader`, into an `any`
//!   holding a pointer to the answer (`model.Account`, `common.Version`, ...).
//! * [`decode_slice`]: `codec.NewDecoderBytes(body, h).Decode(&v)` with `v`
//!   a struct, through its `bytesDecReader`, as algod's REST handlers decode
//!   a request body (`POST /v2/transactions/simulate`, issue #2477). This
//!   reader reports `EOF` where the other reads a zero byte, and slices its
//!   strings out of the body itself.
//!
//! go-codec accepts more than JSON (a quoted number, a string from a
//! number or a bool, an integer from `1e3`, a struct from an array, the
//! first value of a stream with garbage after it) and its errors are
//! `json decode error [pos N]: <what>`, `N` the bytes read when it failed,
//! or a bare `EOF`. The decoded value is returned as go's `encoding/json`
//! would print the decoded struct: every non-pointer field (its zero value
//! when absent), a nil pointer left out, a nil slice `null`, `[]byte` base64;
//! the types only a request body has print as noted on their [`Ty`] variant.

use base64::Engine as _;
use serde_json::{Map, Value};

/// A Go type of a decoded answer.
#[derive(Debug)]
pub enum Ty {
    /// `string`.
    Str,
    /// `uint64` and the named `uint64`s (`basics.Round`, `AppIndex`, ...).
    U64,
    /// `uint32`.
    U32,
    /// `uint16`.
    U16,
    /// `uint8`.
    U8,
    /// `int` / `int64`.
    I64,
    /// `bool`.
    Bool,
    /// `[]byte`.
    Bytes,
    /// `[N]byte` (`crypto.Digest`, `crypto.Signature`, ...), printed as the
    /// base64 of its `N` bytes.
    ByteArray(usize),
    /// `basics.Address`, a `TextUnmarshaler` (`UnmarshalChecksumAddress`),
    /// printed as its checksummed text.
    Address,
    /// `[]string` (go-codec's fast path).
    Strings,
    /// `[]T` of another predeclared `T` (go-codec's fast path: `[]uint64`).
    FastSlice(&'static Ty),
    /// `map[K]V` (`kMap`), printed as an object keyed by the key's text.
    Map(&'static Ty, &'static Ty),
    /// `*T`.
    Ptr(&'static Ty),
    /// `[]T`, with go's name of the slice type (`[]model.Asset`).
    Slice(&'static Ty, &'static str),
    /// A struct.
    Struct(&'static [Field]),
    /// `interface{}` (go-codec's `DecodeNaked`): any value; a JSON object
    /// as a `map[string]interface{}`, an array as `[]interface{}`, a number
    /// as a `float64` (or the integer it holds), printed as decoded. Only the
    /// JSON decoder reads it.
    Any,
}

/// A struct field: its JSON name and type, in go's declaration order.
#[derive(Debug)]
pub struct Field(pub &'static str, pub Ty);

/// Why go-codec's decode failed: its error text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// `io.EOF`, which go-codec passes up unwrapped: `EOF`.
    Eof,
    /// `json decode error [pos <pos>]: <msg>`; `msg` is bytes, as go's
    /// `%s` of a source token that is not UTF-8 is.
    At(usize, Vec<u8>),
    /// Only from [`decode_guarded`]: a container loop went round more than the
    /// guard allows (go's never ends, issue #2537). `elements` is the size
    /// the container being filled had grown to.
    Endless { iterations: u64, elements: usize },
}

impl Error {
    /// The error text as go's `err.Error()` bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Eof => b"EOF".to_vec(),
            Self::At(pos, msg) => {
                cat(&[format!("json decode error [pos {pos}]: ").as_bytes(), msg])
            }
            Self::Endless {
                iterations,
                elements,
            } => format!(
                "go-codec does not finish decoding this (guard: {iterations} rounds of one loop, {elements} elements)"
            )
            .into_bytes(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.to_bytes()))
    }
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// go's `Decoder.Decode(&response)` with `response` an `any` holding a
/// pointer to `ty`: the decoded value, or go-codec's error.
pub fn decode(body: &[u8], ty: &'static Ty) -> Result<Value, Error> {
    decode_reading(body, ty).0
}

/// [`decode`] with a guard: a container loop that goes round more than
/// `max_loop_iterations` times fails with [`Error::Endless`]. go's decoder
/// loops for ever on an array cut after a comma (issue #2537) and so does
/// [`decode`]; this entry point lets a test observe that without hanging.
pub fn decode_guarded(
    body: &[u8],
    ty: &'static Ty,
    max_loop_iterations: u64,
) -> Result<Value, Error> {
    let mut d = Dec::new(body, Mode::Io);
    d.guard = Some(max_loop_iterations);
    decode_with(&mut d, ty)
}

/// [`decode`], and whether it read past the end of `body`: on a body that
/// broke off there, go-codec's read gets the body's error instead
/// (`ioDecReader.readn1` panics with it), which is what `Decode` returns.
pub fn decode_reading(body: &[u8], ty: &'static Ty) -> (Result<Value, Error>, bool) {
    let mut d = Dec::new(body, Mode::Io);
    let res = decode_with(&mut d, ty);
    (res, d.hit_end)
}

/// go's `codec.NewDecoderBytes(body, h).Decode(&v)` with `v` a value of
/// `ty` (a struct): the decoded value, or go-codec's error. A top-level
/// `null` leaves `v` zero; bytes after the first value are not read.
pub fn decode_slice(body: &[u8], ty: &'static Ty) -> Result<Value, Error> {
    let mut d = Dec::new(body, Mode::Bytes);
    let mut v = zero(ty);
    if d.try_decode_as_nil()? {
        return Ok(v);
    }
    d.decode_value(ty, &mut v)?;
    Ok(v)
}

fn decode_with(d: &mut Dec<'_>, ty: &'static Ty) -> Result<Value, Error> {
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
        Ty::U64 | Ty::U32 | Ty::U16 | Ty::U8 | Ty::I64 => Value::from(0u64),
        Ty::Bool => Value::Bool(false),
        Ty::Bytes | Ty::Strings | Ty::FastSlice(_) | Ty::Slice(..) | Ty::Map(..) => Value::Null,
        Ty::ByteArray(n) => {
            Value::String(base64::engine::general_purpose::STANDARD.encode(vec![0u8; *n]))
        }
        Ty::Address => Value::String(algo_types::Address([0u8; 32]).to_string()),
        Ty::Ptr(_) | Ty::Any => Value::Null, // a pointer is left out of a struct
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

/// Which go-codec reader feeds the decoder.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `ioDecReader` over an `io.Reader`.
    Io,
    /// `bytesDecReader` over a `[]byte`.
    Bytes,
}

struct Dec<'a> {
    mode: Mode,
    src: &'a [u8],
    off: usize,
    /// `ioDecReaderCommon.n`: the position errors report.
    n: usize,
    last: u8,
    ls: LastByte,
    tok: u8,
    c: Container,
    /// A read went past the end of the body.
    hit_end: bool,
    /// Rounds of one container loop after which the decode gives up with
    /// [`Error::Endless`]; `None` (every production entry point) never does,
    /// as go's does not.
    guard: Option<u64>,
    /// Keep a decoded string's bytes as they are (the lossless
    /// [`algo_types::raw_text`] form), as go's `string` does and `fmt` prints
    /// unfiltered: only the REST client's decode ([`Mode::Io`]); the
    /// request decoding of the node keeps its lossy strings.
    raw_strings: bool,
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
    fn new(src: &'a [u8], mode: Mode) -> Self {
        Self {
            mode,
            src,
            off: 0,
            n: 0,
            last: 0,
            ls: LastByte::Undefined,
            tok: 0,
            c: Container::None,
            hit_end: false,
            raw_strings: mode == Mode::Io,
            guard: None,
        }
    }

    fn err<T>(&self, msg: impl Into<Vec<u8>>) -> Result<T, Error> {
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
        let Some(&b) = self.src.get(self.off) else {
            self.hit_end = true;
            return None;
        };
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
        if self.mode == Mode::Bytes {
            let &b = self.src.get(self.off).ok_or(Error::Eof)?;
            self.off += 1;
            self.n = self.off;
            return Ok(b);
        }
        self.readn1eof().ok_or(Error::Eof)
    }

    fn unreadn1(&mut self) -> Result<(), Error> {
        if self.mode == Mode::Bytes {
            if self.off == 0 || self.src.is_empty() {
                return self.err("cannot unread last byte read");
            }
            self.off -= 1;
            self.n = self.off;
            return Ok(());
        }
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
        if self.mode == Mode::Bytes {
            if self.off + k > self.src.len() {
                self.off = self.src.len();
                self.n = self.off;
                return Err(Error::Eof);
            }
            let out = self.src[self.off..self.off + k].to_vec();
            self.off += k;
            self.n = self.off;
            return Ok(out);
        }
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
            self.hit_end = true;
            return Err(Error::Eof);
        }
        self.n += k;
        Ok(out)
    }

    /// `skip(&jsonCharWhitespaceSet)`: the first byte that is not
    /// whitespace; `0` at the end of an `io.Reader`, `EOF` at the end of a
    /// `[]byte`.
    fn skip_ws(&mut self) -> Result<u8, Error> {
        if self.mode == Mode::Bytes {
            while let Some(&b) = self.src.get(self.off) {
                self.off += 1;
                if !is_ws(b) {
                    self.n = self.off;
                    return Ok(b);
                }
            }
            return Err(Error::Eof);
        }
        loop {
            match self.readn1eof() {
                None => return Ok(0),
                Some(b) if is_ws(b) => continue,
                Some(b) => return Ok(b),
            }
        }
    }

    fn read_to_num(&mut self) -> Result<Vec<u8>, Error> {
        if self.mode == Mode::Bytes {
            if self.off == self.src.len() {
                return Err(Error::Eof);
            }
            let start = self.off;
            while self.src.get(self.off).is_some_and(|&b| is_num(b)) {
                self.off += 1;
            }
            self.n = self.off;
            return Ok(self.src[start..self.off].to_vec());
        }
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
        if self.mode == Mode::Bytes {
            // a subslice of the body: its capacity runs to the body's end
            let start = self.off;
            let q = self.src[start..]
                .iter()
                .position(|&b| b == b'"')
                .ok_or(Error::Eof)?;
            self.off = start + q + 1;
            self.n = self.off;
            return Ok((self.src[start..self.off].to_vec(), self.src.len() - start));
        }
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

    fn ensure_tok(&mut self) -> Result<(), Error> {
        if self.tok == 0 {
            self.tok = self.skip_ws()?;
        }
        Ok(())
    }

    fn read_map_start(&mut self) -> Result<(), Error> {
        self.ensure_tok()?;
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
        self.ensure_tok()?;
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

    fn check_break(&mut self) -> Result<bool, Error> {
        self.ensure_tok()?;
        Ok(self.tok == b'}' || self.tok == b']')
    }

    /// `!CheckBreak()` of a container loop, one round.
    ///
    /// A loop that starts again in exactly the state it last started in goes
    /// round forever: go-codec does, on an array cut after a comma (`[1,`:
    /// each element reads the comma back through `unreadn1`), growing the
    /// slice until the process runs out of memory (issue #2537). So does this
    /// decoder; only a decoder given a guard ([`decode_guarded`]) stops, with
    /// [`Error::Endless`], after that many rounds of one loop. `elements` is
    /// the size of the container being filled.
    fn more(&mut self, rounds: &mut u64, elements: usize) -> Result<bool, Error> {
        *rounds += 1;
        if let Some(max) = self.guard {
            if *rounds > max {
                return Err(Error::Endless {
                    iterations: *rounds,
                    elements,
                });
            }
        }
        Ok(!self.check_break()?)
    }

    fn read_array_elem(&mut self) -> Result<(), Error> {
        self.ensure_tok()?;
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
        self.ensure_tok()?;
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
        self.ensure_tok()?;
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
        self.ensure_tok()?;
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
        self.ensure_tok()?;
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
            return self.err(cat(&[b"expecting ", rest.as_bytes(), b": got ", &bs]));
        }
        Ok(())
    }

    fn try_decode_as_nil(&mut self) -> Result<bool, Error> {
        self.ensure_tok()?;
        if self.tok == b'n' {
            self.read_lit("ull")?;
            return Ok(true);
        }
        Ok(false)
    }

    fn decode_bool(&mut self) -> Result<bool, Error> {
        self.ensure_tok()?;
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

    fn container_type(&mut self) -> Result<u8, Error> {
        self.ensure_tok()?;
        Ok(match self.tok {
            b'{' => VALUE_TYPE_MAP,
            b'[' => VALUE_TYPE_ARRAY,
            b'n' => VALUE_TYPE_NIL,
            b'"' => VALUE_TYPE_STRING,
            _ => VALUE_TYPE_UNSET,
        })
    }

    fn dec_num_bytes(&mut self) -> Result<Vec<u8>, Error> {
        self.ensure_tok()?;
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
            return self.err(cat(&[b"overflow parsing unsigned integer: ", &bs]));
        }
        if p.neg {
            return self.err(cat(&[b"minus found parsing unsigned integer: ", &bs]));
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
            return self.err(cat(&[b"overflow parsing integer: ", &bs]));
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
                return self.err(cat(&[b"overflow parsing integer: ", &bs]));
            }
            Ok((n as i64).wrapping_neg())
        } else {
            if n >= CUTOFF {
                return self.err(cat(&[b"overflow parsing integer: ", &bs]));
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
            return self.err(cat(&[b"invalid syntax for integer: ", s]));
        };
        let (fi, ff) = (f.trunc(), f - f.trunc());
        let ff = if f.is_infinite() { 0.0 } else { ff };
        if ff > 0.0 {
            return self.err(cat(&[b"fractional part found parsing integer: ", s]));
        }
        if fi > u64::MAX as f64 {
            return self.err(cat(&[b"overflow parsing integer: ", s]));
        }
        Ok(go_f64_to_u64(fi))
    }

    /// `appendStringAsBytes`: a string, or a non-string scalar as its text.
    /// Returns the bytes and whether it was `null`.
    fn append_string_as_bytes(&mut self) -> Result<(Vec<u8>, bool), Error> {
        self.ensure_tok()?;
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
        let bytes = self.append_string_as_bytes()?.0;
        Ok(if self.raw_strings {
            algo_types::raw_text::encode(&bytes).into_owned()
        } else {
            lossy(&bytes)
        })
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
            Err(at) => self.err(cat(&[
                b"error decoding base64 binary '",
                &bs,
                format!("': illegal base64 data at input byte {at}").as_bytes(),
            ])),
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
            Ty::U32 => *v = Value::from(self.decode_uint_bits(32)?),
            Ty::U16 => *v = Value::from(self.decode_uint_bits(16)?),
            Ty::U8 => *v = Value::from(self.decode_uint_bits(8)?),
            Ty::ByteArray(n) => self.decode_byte_array(*n, v)?,
            Ty::Address => *v = Value::String(self.decode_address()?),
            Ty::FastSlice(elem) => self.decode_fast_slice(elem, v)?,
            Ty::Map(key, val) => self.decode_map(key, val, v)?,
            Ty::Any => *v = self.decode_naked()?,
        }
        Ok(())
    }

    /// go-codec's `DecodeNaked` of a JSON value into an `interface{}`.
    fn decode_naked(&mut self) -> Result<Value, Error> {
        self.ensure_tok()?;
        match self.tok {
            b'n' => {
                self.read_lit("ull")?;
                Ok(Value::Null)
            }
            b'f' | b't' => Ok(Value::Bool(self.decode_bool()?)),
            b'"' => Ok(Value::String(self.decode_string()?)),
            b'{' => {
                self.read_map_start()?;
                let mut m = Map::new();
                let mut rounds = 0u64;
                while self.more(&mut rounds, m.len())? {
                    // a `map[interface{}]interface{}`: the key is naked too
                    self.read_map_elem_key()?;
                    let k = match self.decode_naked()? {
                        Value::String(k) => k,
                        other => other.to_string(),
                    };
                    self.read_map_elem_value()?;
                    let val = self.decode_naked()?;
                    m.insert(k, val);
                }
                self.read_map_end()?;
                Ok(Value::Object(m))
            }
            b'[' => {
                self.read_array_start()?;
                let mut items = Vec::new();
                let mut rounds = 0u64;
                while self.more(&mut rounds, items.len())? {
                    self.read_array_elem()?;
                    items.push(self.decode_naked()?);
                }
                self.read_array_end()?;
                Ok(Value::Array(items))
            }
            _ => {
                // `decNumBytes`, then `nakedNum`: an integer as a `uint64` /
                // `int64`, anything else through `strconv.ParseFloat`.
                let bs = self.dec_num_bytes()?;
                if bs.is_empty() {
                    return self.err("decode number from empty string");
                }
                let p = parse_integer(&bs);
                if !p.bad_syntax && !p.overflow && !(p.neg && p.n > 1 << 63) {
                    return Ok(if p.neg {
                        Value::from((p.n as i64).wrapping_neg())
                    } else {
                        Value::from(p.n)
                    });
                }
                match go_parse_float(&bs) {
                    Some(f) => Ok(go_marshaled_float(f)),
                    None => {
                        let why = if read_float(&bs).is_some() {
                            "value out of range"
                        } else {
                            "invalid syntax"
                        };
                        self.err(cat(&[
                            b"decode number from ",
                            &bs,
                            b": strconv.ParseFloat: parsing \"",
                            &bs,
                            b"\": ",
                            why.as_bytes(),
                        ]))
                    }
                }
            }
        }
    }

    /// `kUint8` / `kUint16` / `kUint32`: `chkOvf.UintV(DecodeUint64(), bits)`.
    fn decode_uint_bits(&mut self, bits: u32) -> Result<u64, Error> {
        let v = self.decode_u64()?;
        if v >> bits != 0 {
            return self.err(format!("uint64 overflow: {v}"));
        }
        Ok(v)
    }

    /// `textUnmarshal` of a `basics.Address`: `UnmarshalText` of
    /// `DecodeStringAsBytes()`.
    fn decode_address(&mut self) -> Result<String, Error> {
        let (text, _) = self.append_string_as_bytes()?;
        match go_unmarshal_checksum_address(&text) {
            Ok(addr) => Ok(algo_types::Address(addr).to_string()),
            Err(msg) => self.err(msg),
        }
    }

    /// `kSlice` of a `[N]byte` (`seqTypeArray`): a base64 string copied
    /// over its first bytes, or the bytes one by one, never more than `N`.
    fn decode_byte_array(&mut self, n: usize, v: &mut Value) -> Result<(), Error> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut arr = match v {
            Value::String(s) => b64.decode(s.as_bytes()).unwrap_or_default(),
            _ => Vec::new(),
        };
        arr.resize(n, 0);
        if self.container_type()? == VALUE_TYPE_STRING {
            // `DecodeBytes` then `copy(rvbs, bs2)`
            if let Value::String(s) = self.decode_bytes()? {
                let bs = b64.decode(s.as_bytes()).unwrap_or_default();
                let k = bs.len().min(n);
                arr[..k].copy_from_slice(&bs[..k]);
            }
            *v = Value::String(b64.encode(arr));
            return Ok(());
        }
        let array = self.slice_start()?;
        let mut j = 0;
        let mut rounds = 0u64;
        while self.more(&mut rounds, j)? {
            self.slice_elem(array, j)?;
            let nil = self.try_decode_as_nil()?;
            if j >= n {
                return self.err(format!(
                    "cannot expand array len during decode from {n} to {}",
                    j + 1
                ));
            }
            arr[j] = if nil {
                0
            } else {
                self.decode_uint_bits(8)? as u8
            };
            j += 1;
        }
        *v = Value::String(b64.encode(arr));
        self.slice_end(array)
    }

    /// The fast path of a `[]T` of a predeclared `T` (`DecSliceUint64V`).
    fn decode_fast_slice(&mut self, elem: &'static Ty, v: &mut Value) -> Result<(), Error> {
        let array = self.slice_start()?;
        let mut items = Vec::new();
        let mut j = 0;
        let mut rounds = 0u64;
        while self.more(&mut rounds, items.len())? {
            self.slice_elem(array, j)?;
            let mut item = zero(elem);
            if !self.try_decode_as_nil()? {
                self.decode_value(elem, &mut item)?;
            }
            items.push(item);
            j += 1;
        }
        *v = Value::Array(items);
        self.slice_end(array)
    }

    /// `kMap`: a key decoded as its type (no `null` check), a `null` value
    /// as the zero value, any other decoded into the entry already there.
    fn decode_map(
        &mut self,
        key: &'static Ty,
        val: &'static Ty,
        v: &mut Value,
    ) -> Result<(), Error> {
        self.read_map_start()?;
        let mut m = match std::mem::take(v) {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        let mut rounds = 0u64;
        while self.more(&mut rounds, m.len())? {
            self.read_map_elem_key()?;
            let mut k = zero(key);
            self.decode_value(key, &mut k)?;
            let k = match k {
                Value::String(s) => s,
                other => other.to_string(),
            };
            self.read_map_elem_value()?;
            if self.try_decode_as_nil()? {
                m.insert(k, zero(val));
                continue;
            }
            let slot = m.entry(k).or_insert_with(|| zero(val));
            self.decode_value(val, slot)?;
        }
        *v = Value::Object(m);
        self.read_map_end()
    }

    /// `kStruct`.
    fn decode_struct(&mut self, fields: &'static [Field], v: &mut Value) -> Result<(), Error> {
        let ctyp = self.container_type()?;
        if ctyp == VALUE_TYPE_MAP {
            self.read_map_start()?;
            let mut rounds = 0u64;
            while self.more(&mut rounds, 0)? {
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
                        return self.err(cat(&[
                            b"no matching struct field found when decoding stream map with key ",
                            &key,
                        ]))
                    }
                }
            }
            self.read_map_end()
        } else if ctyp == VALUE_TYPE_ARRAY {
            self.read_array_start()?;
            let mut broke = false;
            for Field(name, t) in fields.iter() {
                if self.check_break()? {
                    broke = true;
                    break;
                }
                self.read_array_elem()?;
                self.decode_field(name, t, v)?;
            }
            if !broke && !self.check_break()? {
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
        match self.container_type()? {
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
    fn decode_slice(&mut self, elem: &'static Ty, name: &str, v: &mut Value) -> Result<(), Error> {
        let ctyp = self.container_type()?;
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
        let mut rounds = 0u64;
        while self.more(&mut rounds, items.len())? {
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
        let mut rounds = 0u64;
        while self.more(&mut rounds, items.len())? {
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
        if self.container_type()? == VALUE_TYPE_STRING {
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
        let mut rounds = 0u64;
        while self.more(&mut rounds, old.len())? {
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
    Hex {
        neg: bool,
        mant: u64,
        trunc: bool,
        exp: i64,
    },
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

/// A `float64` as go's `encoding/json` prints it, read back as JSON: an
/// integral value below 1e21 is printed without a fraction or exponent.
fn go_marshaled_float(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 1e21 {
        if (0.0..18_446_744_073_709_551_616.0).contains(&f) {
            return Value::from(f as u64);
        }
        if f < 0.0 && f >= i64::MIN as f64 {
            return Value::from(f as i64);
        }
    }
    serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)
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

/// go's `base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString`
/// (`\r` and `\n` are dropped first): the bytes, or `None` on its
/// `CorruptInputError`. A final group of 1, 3 or 6 characters yields no
/// byte, and `0xff` (the "no padding" rune as a byte) still reads as padding.
fn go_base32_nopad_decode(src: &[u8]) -> Option<Vec<u8>> {
    const PAD: u8 = 0xff;
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    };
    let src: Vec<u8> = src
        .iter()
        .copied()
        .filter(|&b| b != b'\r' && b != b'\n')
        .collect();
    let mut out = Vec::new();
    let mut si = 0;
    let mut end = false;
    while si < src.len() && !end {
        let mut dbuf = [0u8; 8];
        let mut dlen = 8;
        let mut j = 0;
        while j < 8 {
            if si == src.len() {
                (dlen, end) = (j, true);
                break;
            }
            let c = src[si];
            si += 1;
            let rest = src.len() - si;
            if c == PAD && j >= 2 && rest < 8 {
                if rest + j < 7 {
                    return None;
                }
                if (0..7 - j).any(|k| rest > k && src[si + k] != PAD) {
                    return None;
                }
                (dlen, end) = (j, true);
                if matches!(dlen, 1 | 3 | 6) {
                    return None;
                }
                break;
            }
            dbuf[j] = val(c)?;
            j += 1;
        }
        let quantum = [
            dbuf[0] << 3 | dbuf[1] >> 2,
            dbuf[1] << 6 | dbuf[2] << 1 | dbuf[3] >> 4,
            dbuf[3] << 4 | dbuf[4] >> 1,
            dbuf[4] << 7 | dbuf[5] << 2 | dbuf[6] >> 3,
            dbuf[6] << 5 | dbuf[7],
        ];
        let k = match dlen {
            8 => 5,
            7 => 4,
            5 => 3,
            4 => 2,
            2 => 1,
            _ => 0,
        };
        out.extend_from_slice(&quantum[..k]);
    }
    Some(out)
}

/// go's `basics.UnmarshalChecksumAddress(string(text))`: the address, or its
/// error text.
fn go_unmarshal_checksum_address(text: &[u8]) -> Result<[u8; 32], Vec<u8>> {
    use sha2::Digest as _;
    let Some(decoded) = go_base32_nopad_decode(text) else {
        return Err(cat(&[b"failed to decode address ", text, b" from base 32"]));
    };
    if decoded.len() < 32 {
        return Err(cat(&[b"decoded bad addr: ", text]));
    }
    let mut short = [0u8; 32];
    short.copy_from_slice(&decoded[..32]);
    let hash = sha2::Sha512_256::digest(short);
    if decoded[decoded.len() - 4..] != hash[hash.len() - 4..] {
        return Err(cat(&[
            b"address ",
            text,
            b" is malformed, checksum verification failed",
        ]));
    }
    if algo_types::Address(short).to_string().as_bytes() != text {
        return Err(cat(&[b"address ", text, b" is non-canonical"]));
    }
    Ok(short)
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

#[cfg(test)]
mod tests {
    use super::*;

    const PAIR: Ty = Ty::Struct(&[Field("a", Ty::U8), Field("b", Ty::ByteArray(2))]);
    const REQ: Ty = Ty::Struct(&[
        Field("n", Ty::U64),
        Field("s", Ty::Slice(&PAIR, "[]main.Pair")),
        Field("m", Ty::Map(&Ty::U64, &PAIR)),
        Field("d", Ty::Address),
        Field("f", Ty::FastSlice(&Ty::U64)),
    ]);

    fn slice_err(body: &[u8]) -> String {
        decode_slice(body, &REQ).unwrap_err().to_string()
    }

    /// `bytesDecReader` texts, as go-algorand v5.0.5-stable's go-codec gives
    /// them decoding these bodies with `JSONStrictHandle` into the same Go
    /// struct (package `main`; issue #2477: the REST oracle
    /// `simulate_request_texts.jsonl` covers the real request type).
    #[test]
    fn byte_reader_errors_read_like_go_codec() {
        // where the io reader reads a zero byte, the byte reader ends
        assert_eq!(slice_err(b""), "EOF");
        assert_eq!(slice_err(b"{\"n\":1"), "EOF");
        assert_eq!(slice_err(b"\x00"), "EOF");
        assert_eq!(
            slice_err(b"{\"s\":[{\"a\":256}]}"),
            "json decode error [pos 14]: uint64 overflow: 256"
        );
        assert_eq!(
            slice_err(b"{\"s\":[{\"b\":[1,2,3]}]}"),
            "json decode error [pos 17]: cannot expand array len during decode from 2 to 3"
        );
        assert_eq!(
            slice_err(b"{\"s\":\"x\"}"),
            "json decode error [pos 6]: bytes/string in stream must decode into slice/array of bytes, not []main.Pair"
        );
        assert_eq!(
            slice_err(b"{\"f\":\"x\"}"),
            "json decode error [pos 6]: only encoded map or array can be decoded into a slice (6)"
        );
        assert_eq!(
            slice_err(b"{\"m\":5}"),
            "json decode error [pos 6]: read map - expect char '{' but got char '5'"
        );
        assert_eq!(
            slice_err(b"{\"m\":{\"x\":{}}}"),
            "json decode error [pos 9]: invalid syntax for integer: x"
        );
        assert_eq!(
            slice_err(b"{\"d\":\"x\"}"),
            "json decode error [pos 8]: failed to decode address x from base 32"
        );
        assert_eq!(
            slice_err(b"{\"d\":\"\"}"),
            "json decode error [pos 7]: decoded bad addr: "
        );
    }

    #[test]
    fn byte_reader_decodes_what_go_codec_accepts() {
        let v = decode_slice(
            br#"{"n":"7","m":{"3":{"a":1}},"s":[[2,"AQI="]],"f":[1,null]}tail"#,
            &REQ,
        )
        .unwrap();
        assert_eq!(v["n"], 7);
        assert_eq!(v["m"]["3"]["a"], 1);
        assert_eq!(v["s"][0]["a"], 2);
        assert_eq!(v["s"][0]["b"], "AQI=");
        assert_eq!(v["f"], serde_json::json!([1, 0]));
        assert_eq!(decode_slice(b"null", &REQ).unwrap()["n"], 0);
        // a base64 string longer than the array fills it
        let v = decode_slice(br#"{"s":[{"b":"AQIDBA=="}]}"#, &REQ).unwrap();
        assert_eq!(v["s"][0]["b"], "AQI=");
    }

    #[test]
    fn go_checksum_address_texts() {
        let zero = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ";
        assert_eq!(
            go_unmarshal_checksum_address(zero.as_bytes()),
            Ok([0u8; 32])
        );
        let text = |s: &str| {
            String::from_utf8(go_unmarshal_checksum_address(s.as_bytes()).unwrap_err()).unwrap()
        };
        assert_eq!(
            text(&zero.to_lowercase()),
            format!(
                "failed to decode address {} from base 32",
                zero.to_lowercase()
            )
        );
        let bad = format!("B{}", &zero[1..]);
        assert_eq!(
            text(&bad),
            format!("address {bad} is malformed, checksum verification failed")
        );
        // the last character's two low bits are not decoded
        let alias = format!("{}R", &zero[..57]);
        assert_eq!(text(&alias), format!("address {alias} is non-canonical"));
        // newlines are dropped before decoding, so only the canonical check fails
        let nl = format!("{}\n{}", &zero[..56], &zero[56..]);
        assert_eq!(text(&nl), format!("address {nl} is non-canonical"));
        assert_eq!(go_base32_nopad_decode(b"AE"), Some(vec![1]));
        // a final group of three characters decodes to nothing
        assert_eq!(go_base32_nopad_decode(b"AEA"), Some(vec![]));
        assert_eq!(go_base32_nopad_decode(b"AEAQ"), Some(vec![1, 1]));
        assert_eq!(go_base32_nopad_decode(b"A1"), None);
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
