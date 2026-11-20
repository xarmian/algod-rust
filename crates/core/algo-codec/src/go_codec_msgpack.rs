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

//! go-codec's msgpack decoder (`github.com/algorand/go-codec/codec` v1.1.10)
//! with go-algorand's `protocol.CodecHandle` (`ErrorIfNoField`,
//! `ErrorIfNoArrayExpand`, no `MaxInitLen`) decoding into a reflected Go
//! type ([`Ty`]) from an `io.Reader`, one value after another: what go's
//! `decodeTxGroup` does with the body of `POST /v2/transactions` and
//! `/v2/transactions/async` (`protocol.NewDecoder(body)` and `Decode(&st)`
//! until `io.EOF`, issue #2492).
//!
//! The decoded value is a [`GoVal`], the Go value go-codec leaves behind:
//! decoding into the value already there (a repeated struct key merges, a
//! repeated slice keeps the elements of its capacity, a repeated key of a
//! `map[K]struct` decodes into an unaddressable copy), with go-codec's
//! leniencies (a struct from an array, a slice from a map, `[N]byte` from a
//! shorter or longer `bin`, a struct key from a `bin` or an array of bytes).
//!
//! Its errors are `msgpack decode error [pos N]: <what>`, `N` the bytes read
//! when it failed, or `EOF` when the body ended, wherever that was: go-codec
//! passes `io.EOF` up unwrapped, so `decodeTxGroup` takes a body that breaks
//! off inside a transaction for the end of the group.
//!
//! [`Ty::Address`] decodes as the `[32]byte` it is: `basics.Address` is a
//! `TextUnmarshaler`, which go-codec only uses for text formats.

use crate::go_codec_json::{Field, Ty};

/// Why go-codec's decode failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// `io.EOF`: the body ended (go passes it up unwrapped).
    Eof,
    /// `msgpack decode error [pos <pos>]: <msg>`; `msg` is bytes, as go's
    /// `%s` of a struct key that is not UTF-8 is.
    At(usize, Vec<u8>),
}

impl Error {
    /// The error text as go's `err.Error()` bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Eof => b"EOF".to_vec(),
            Self::At(pos, msg) => [
                format!("msgpack decode error [pos {pos}]: ").as_bytes(),
                msg,
            ]
            .concat(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.to_bytes()))
    }
}

/// A Go slice: its elements up to its capacity (`backing.len()` is the
/// capacity) and its length, or nil.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GoSlice<T> {
    pub nil: bool,
    pub len: usize,
    pub backing: Vec<T>,
}

impl<T> GoSlice<T> {
    fn nil() -> Self {
        Self {
            nil: true,
            len: 0,
            backing: Vec::new(),
        }
    }

    /// The elements within the length.
    pub fn elems(&self) -> &[T] {
        &self.backing[..self.len]
    }
}

/// A decoded Go value of a [`Ty`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoVal {
    /// Any unsigned integer type.
    Uint(u64),
    /// `int` / `int64`.
    Int(i64),
    Bool(bool),
    /// `string`: bytes, as go keeps them (not checked for UTF-8).
    Str(Vec<u8>),
    /// `[]byte` (and the named `[]byte`s).
    Bytes(GoSlice<u8>),
    /// `[N]byte`.
    Array(Vec<u8>),
    /// `[]T` (`[]uint64` and `[]string` too).
    Slice(GoSlice<GoVal>),
    /// `map[uint64]T`, in insertion order; nil is `None`.
    Map(Option<Vec<(u64, GoVal)>>),
    /// `*T`.
    Ptr(Option<Box<GoVal>>),
    /// A struct's fields, in the order of its [`Ty::Struct`].
    Struct(Vec<GoVal>),
}

impl GoVal {
    /// The zero value of `ty`.
    pub fn zero(ty: &'static Ty) -> Self {
        match ty {
            Ty::Str => Self::Str(Vec::new()),
            Ty::U64 | Ty::U32 | Ty::U16 | Ty::U8 => Self::Uint(0),
            Ty::I64 => Self::Int(0),
            Ty::Bool => Self::Bool(false),
            Ty::Bytes => Self::Bytes(GoSlice::nil()),
            Ty::ByteArray(n) => Self::Array(vec![0; *n]),
            Ty::Address => Self::Array(vec![0; 32]),
            Ty::Strings | Ty::FastSlice(_) | Ty::Slice(..) => Self::Slice(GoSlice::nil()),
            Ty::Map(..) => Self::Map(None),
            // `Ty::Any` is a JSON-only type: a nil `interface{}`.
            Ty::Ptr(_) | Ty::Any => Self::Ptr(None),
            Ty::Struct(fields) => Self::Struct(fields.iter().map(|f| Self::zero(&f.1)).collect()),
        }
    }

    /// Whether this is its type's zero value (what go's msgp `omitempty`
    /// leaves out: an empty slice or map counts, a non-nil pointer does not).
    pub fn is_zero(&self) -> bool {
        match self {
            Self::Uint(v) => *v == 0,
            Self::Int(v) => *v == 0,
            Self::Bool(b) => !b,
            Self::Str(s) => s.is_empty(),
            Self::Bytes(s) => s.len == 0,
            Self::Array(a) => a.iter().all(|&b| b == 0),
            Self::Slice(s) => s.len == 0,
            Self::Map(m) => m.as_ref().is_none_or(Vec::is_empty),
            Self::Ptr(p) => p.is_none(),
            Self::Struct(fields) => fields.iter().all(Self::is_zero),
        }
    }
}

/// Encode `v` (of type `ty`) as a msgpack map form: each struct a map of its
/// non-zero fields, keys sorted, integers in their shortest form; a pointer
/// is written when it is not nil. What a plain msgpack reader needs to
/// rebuild the value go-codec decoded.
pub fn encode(v: &GoVal, ty: &'static Ty, out: &mut Vec<u8>) {
    match (ty, v) {
        (Ty::Ptr(t), GoVal::Ptr(Some(inner))) => encode(inner, t, out),
        (_, GoVal::Ptr(None)) => out.push(0xc0),
        (Ty::Struct(fields), GoVal::Struct(vals)) => {
            let mut set: Vec<(&str, &'static Ty, &GoVal)> = fields
                .iter()
                .zip(vals)
                .filter(|(f, x)| matches!(f.1, Ty::Ptr(_)) || !x.is_zero())
                .filter(|(_, x)| !matches!(x, GoVal::Ptr(None)))
                .map(|(Field(name, t), x)| (*name, t, x))
                .collect();
            set.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            write_map_len(out, set.len());
            for (name, t, x) in set {
                write_str(out, name.as_bytes());
                encode(x, t, out);
            }
        }
        (_, GoVal::Uint(u)) => write_uint(out, *u),
        (_, GoVal::Int(i)) => {
            if *i >= 0 {
                write_uint(out, *i as u64);
            } else {
                out.push(0xd3);
                out.extend_from_slice(&i.to_be_bytes());
            }
        }
        (_, GoVal::Bool(b)) => out.push(if *b { 0xc3 } else { 0xc2 }),
        (_, GoVal::Str(s)) => write_str(out, s),
        // a nil `[]byte` (a slice element: a field is left out when empty)
        (_, GoVal::Bytes(b)) if b.nil => out.push(0xc0),
        (_, GoVal::Bytes(b)) => write_bin(out, b.elems()),
        (_, GoVal::Array(a)) => write_bin(out, a),
        (Ty::Slice(elem, _) | Ty::FastSlice(elem), GoVal::Slice(s)) => {
            write_array_len(out, s.len);
            for x in s.elems() {
                encode(x, elem, out);
            }
        }
        (Ty::Strings, GoVal::Slice(s)) => {
            write_array_len(out, s.len);
            for x in s.elems() {
                encode(x, &Ty::Str, out);
            }
        }
        (Ty::Map(_, vt), GoVal::Map(m)) => {
            let mut entries: Vec<&(u64, GoVal)> = m.iter().flatten().collect();
            entries.sort_by_key(|(k, _)| *k);
            write_map_len(out, entries.len());
            for (k, x) in entries {
                write_uint(out, *k);
                encode(x, vt, out);
            }
        }
        // a value never decoded into a type of another shape
        _ => out.push(0xc0),
    }
}

fn write_uint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=0x7f => out.push(v as u8),
        0x80..=0xff => out.extend_from_slice(&[0xcc, v as u8]),
        0x100..=0xffff => {
            out.push(0xcd);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xce);
            out.extend_from_slice(&(v as u32).to_be_bytes());
        }
        _ => {
            out.push(0xcf);
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
}

fn write_len(
    out: &mut Vec<u8>,
    n: usize,
    fix: Option<(u8, usize)>,
    m8: Option<u8>,
    m16: u8,
    m32: u8,
) {
    match (fix, m8) {
        (Some((base, cut)), _) if n < cut => out.push(base | n as u8),
        (_, Some(m)) if n < 256 => out.extend_from_slice(&[m, n as u8]),
        _ if n < 65536 => {
            out.push(m16);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        _ => {
            out.push(m32);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
}

fn write_map_len(out: &mut Vec<u8>, n: usize) {
    write_len(out, n, Some((0x80, 16)), None, 0xde, 0xdf);
}

fn write_array_len(out: &mut Vec<u8>, n: usize) {
    write_len(out, n, Some((0x90, 16)), None, 0xdc, 0xdd);
}

fn write_str(out: &mut Vec<u8>, s: &[u8]) {
    write_len(out, s.len(), Some((0xa0, 32)), Some(0xd9), 0xda, 0xdb);
    out.extend_from_slice(s);
}

fn write_bin(out: &mut Vec<u8>, b: &[u8]) {
    write_len(out, b.len(), None, Some(0xc4), 0xc5, 0xc6);
    out.extend_from_slice(b);
}

// ---- go-codec's msgpack constants ----------------------------------------

/// `valueType` numbers (`helper.go`).
const VT_UNSET: u8 = 0;
const VT_NIL: u8 = 1;
const VT_BYTES: u8 = 8;
const VT_MAP: u8 = 9;
const VT_ARRAY: u8 = 10;

const MP_NIL: u8 = 0xc0;

/// `msgpackContainerType`: (`bFixMin`, `b8`, `b16`, `b32`).
#[derive(Clone, Copy)]
struct ContainerType(u8, u8, u8, u8);
const CT_STR: ContainerType = ContainerType(0xa0, 0xd9, 0xda, 0xdb);
const CT_BIN: ContainerType = ContainerType(0, 0xc4, 0xc5, 0xc6);
const CT_LIST: ContainerType = ContainerType(0x90, 0, 0xdc, 0xdd);
const CT_MAP: ContainerType = ContainerType(0x80, 0, 0xde, 0xdf);

const MSG_BAD_DESC: &str = "unrecognized descriptor byte";
/// `decDefMaxDepth`.
const MAX_DEPTH: usize = 1024;

/// `mpdesc`.
fn mpdesc(bd: u8) -> &'static str {
    match bd {
        0xc0 => "nil",
        0xc2 => "false",
        0xc3 => "true",
        0xca | 0xcb => "float",
        0xcc..=0xcf => "uint",
        0xd0..=0xd3 | 0x00..=0x7f | 0xe0..=0xff => "int",
        0xa0..=0xbf | 0xd9..=0xdb => "string|bytes",
        0xc4..=0xc6 => "bytes",
        0x90..=0x9f | 0xdc | 0xdd => "array",
        0x80..=0x8f | 0xde | 0xdf => "map",
        0xd4..=0xd8 | 0xc7..=0xc9 => "ext",
        _ => "unknown",
    }
}

/// Whether go's `isImmutableKind` holds for a type (its values are copied,
/// not decoded into).
fn immutable(ty: &Ty) -> bool {
    matches!(
        ty,
        Ty::Str | Ty::U64 | Ty::U32 | Ty::U16 | Ty::U8 | Ty::I64 | Ty::Bool
    )
}

/// `reflect.Type.Size()` and alignment of a type, for go-codec's slice
/// growth (`decInferLen`, `growCap`).
fn size_align(ty: &Ty) -> (usize, usize) {
    match ty {
        Ty::Bool | Ty::U8 => (1, 1),
        Ty::U16 => (2, 2),
        Ty::U32 => (4, 4),
        Ty::U64 | Ty::I64 | Ty::Map(..) | Ty::Ptr(_) => (8, 8),
        Ty::Any => (16, 8),
        Ty::Str => (16, 8),
        Ty::Bytes | Ty::Strings | Ty::FastSlice(_) | Ty::Slice(..) => (24, 8),
        Ty::ByteArray(n) => (*n, 1),
        Ty::Address => (32, 1),
        Ty::Struct(fields) => {
            let (mut size, mut align) = (0usize, 1usize);
            for Field(_, t) in fields.iter() {
                let (s, a) = size_align(t);
                size = size.div_ceil(a) * a + s;
                align = align.max(a);
            }
            (size.div_ceil(align) * align, align)
        }
    }
}

/// `decInferLen(clen, 0, unit)`.
fn infer_len(clen: usize, unit: usize) -> usize {
    if clen == 0 {
        return 0;
    }
    if unit == 0 {
        return clen;
    }
    let maxlen = if unit < 256 / 4 {
        256 * 1024 / unit
    } else {
        4 * 1024
    };
    clen.min(maxlen)
}

/// `growCap(oldCap, unit, num)`.
fn grow_cap(old_cap: usize, unit: usize, num: usize) -> usize {
    let (t1, t2, t3) = if unit <= 1 {
        (4 * 1024, 8 * 1024, 16 * 1024)
    } else if unit < 16 {
        let t3 = 16 / unit * 1024;
        (t3 / 4, t3 * 2 / 4, t3)
    } else {
        (1024, 1024, 1024)
    };
    let x = if old_cap <= t1 {
        8
    } else if old_cap > t3 {
        5
    } else if old_cap <= t2 {
        7
    } else {
        6
    };
    let mut new_cap = x * old_cap / 4 + num;
    let m = if new_cap > 64 { 64 } else { 16 };
    if !new_cap.is_multiple_of(m) {
        new_cap = m * (new_cap / m + 1);
    }
    new_cap
}

fn tisep(name: &[u8]) -> u8 {
    0xfeu8
        .wrapping_sub(name[0] & 63)
        .wrapping_sub((name.len() & 63) as u8)
}

/// go-codec's decoder state over one body.
pub struct Decoder<'a> {
    src: &'a [u8],
    /// Bytes read: `ioDecReaderCommon.n`, the position errors report.
    off: usize,
    bd: u8,
    bd_read: bool,
    depth: usize,
}

type Res<T> = Result<T, Error>;

impl<'a> Decoder<'a> {
    pub fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            off: 0,
            bd: 0,
            bd_read: false,
            depth: 0,
        }
    }

    /// The bytes read so far.
    pub fn position(&self) -> usize {
        self.off
    }

    /// `Decoder.Decode(&v)` with `v` a zero `ty`: the value go is left with.
    pub fn decode(&mut self, ty: &'static Ty) -> Res<GoVal> {
        let mut v = GoVal::zero(ty);
        // mustDecode: a top-level nil leaves the value zero
        if self.try_decode_as_nil()? {
            return Ok(v);
        }
        self.decode_value(ty, &mut v, true)?;
        Ok(v)
    }

    fn err<T>(&self, msg: impl Into<Vec<u8>>) -> Res<T> {
        Err(Error::At(self.off, msg.into()))
    }

    // ---- reader ----------------------------------------------------------

    fn readn1(&mut self) -> Res<u8> {
        let b = *self.src.get(self.off).ok_or(Error::Eof)?;
        self.off += 1;
        Ok(b)
    }

    fn readx(&mut self, n: usize) -> Res<&'a [u8]> {
        if self.src.len() - self.off < n {
            return Err(Error::Eof);
        }
        let b = &self.src[self.off..self.off + n];
        self.off += n;
        Ok(b)
    }

    fn be(&mut self, n: usize) -> Res<u64> {
        Ok(self
            .readx(n)?
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    // ---- msgpackDecDriver ------------------------------------------------

    fn read_next_bd(&mut self) -> Res<()> {
        self.bd = self.readn1()?;
        self.bd_read = true;
        Ok(())
    }

    fn ensure_bd(&mut self) -> Res<()> {
        if !self.bd_read {
            self.read_next_bd()?;
        }
        Ok(())
    }

    fn try_decode_as_nil(&mut self) -> Res<bool> {
        self.ensure_bd()?;
        if self.bd == MP_NIL {
            self.bd_read = false;
            return Ok(true);
        }
        Ok(false)
    }

    fn container_type(&mut self) -> Res<u8> {
        self.ensure_bd()?;
        Ok(match self.bd {
            MP_NIL => VT_NIL,
            0xc4..=0xc6 | 0xd9..=0xdb | 0xa0..=0xbf => VT_BYTES,
            0xdc | 0xdd | 0x90..=0x9f => VT_ARRAY,
            0xde | 0xdf | 0x80..=0x8f => VT_MAP,
            _ => VT_UNSET,
        })
    }

    /// `readContainerLen`; -1 for nil.
    fn read_container_len(&mut self, ct: ContainerType) -> Res<i64> {
        let bd = self.bd;
        let clen = if bd == MP_NIL {
            -1
        } else if bd == ct.1 {
            i64::from(self.readn1()?)
        } else if bd == ct.2 {
            self.be(2)? as i64
        } else if bd == ct.3 {
            self.be(4)? as i64
        } else if ct.0 & bd == ct.0 {
            i64::from(ct.0 ^ bd)
        } else {
            return self.err(format!(
                "cannot read container length: {MSG_BAD_DESC}: hex: {bd:x}, decimal: {bd}"
            ));
        };
        self.bd_read = false;
        Ok(clen)
    }

    fn read_map_start(&mut self) -> Res<i64> {
        self.ensure_bd()?;
        self.read_container_len(CT_MAP)
    }

    fn read_array_start(&mut self) -> Res<i64> {
        self.ensure_bd()?;
        self.read_container_len(CT_LIST)
    }

    fn bad(&self, what: &str) -> Error {
        Error::At(
            self.off,
            format!(
                "cannot decode {what}: {MSG_BAD_DESC}: {:x}/{}",
                self.bd,
                mpdesc(self.bd)
            )
            .into_bytes(),
        )
    }

    fn decode_u64(&mut self) -> Res<u64> {
        self.ensure_bd()?;
        let neg = |d: &Self, i: i64| -> Res<u64> {
            if i >= 0 {
                Ok(i as u64)
            } else {
                d.err(format!(
                    "assigning negative signed value: {i}, to unsigned type"
                ))
            }
        };
        let v = match self.bd {
            0xcc => self.be(1)?,
            0xcd => self.be(2)?,
            0xce => self.be(4)?,
            0xcf => self.be(8)?,
            0xd0 => {
                let i = i64::from(self.be(1)? as u8 as i8);
                neg(self, i)?
            }
            0xd1 => {
                let i = i64::from(self.be(2)? as u16 as i16);
                neg(self, i)?
            }
            0xd2 => {
                let i = i64::from(self.be(4)? as u32 as i32);
                neg(self, i)?
            }
            0xd3 => {
                let i = self.be(8)? as i64;
                neg(self, i)?
            }
            b @ 0x00..=0x7f => u64::from(b),
            b @ 0xe0..=0xff => {
                return self.err(format!(
                    "assigning negative signed value: {b}, to unsigned type"
                ))
            }
            _ => return Err(self.bad("unsigned integer")),
        };
        self.bd_read = false;
        Ok(v)
    }

    fn decode_i64(&mut self) -> Res<i64> {
        self.ensure_bd()?;
        let v = match self.bd {
            0xcc => self.be(1)? as i64,
            0xcd => self.be(2)? as i64,
            0xce => self.be(4)? as i64,
            0xcf => self.be(8)? as i64,
            0xd0 => i64::from(self.be(1)? as u8 as i8),
            0xd1 => i64::from(self.be(2)? as u16 as i16),
            0xd2 => i64::from(self.be(4)? as u32 as i32),
            0xd3 => self.be(8)? as i64,
            b @ (0x00..=0x7f | 0xe0..=0xff) => i64::from(b as i8),
            _ => return Err(self.bad("signed integer")),
        };
        self.bd_read = false;
        Ok(v)
    }

    /// `chkOvf.UintV(DecodeUint64(), bits)`.
    fn decode_uint_bits(&mut self, bits: u32) -> Res<u64> {
        let v = self.decode_u64()?;
        if bits < 64 && v >> bits != 0 {
            return self.err(format!("uint64 overflow: {v}"));
        }
        Ok(v)
    }

    fn decode_bool(&mut self) -> Res<bool> {
        self.ensure_bd()?;
        let b = match self.bd {
            0xc2 | 0x00 => false,
            0xc3 | 0x01 => true,
            _ => return Err(self.bad("bool")),
        };
        self.bd_read = false;
        Ok(b)
    }

    /// `DecodeBytes`: the bytes of a `bin`/`str`, or of an array of bytes.
    fn decode_bytes(&mut self) -> Res<Vec<u8>> {
        self.ensure_bd()?;
        let bd = self.bd;
        let clen = match self.container_type()? {
            VT_BYTES => {
                let ct = if matches!(bd, 0xc4..=0xc6) {
                    CT_BIN
                } else {
                    CT_STR
                };
                self.read_container_len(ct)?
            }
            VT_ARRAY => return self.dec_slice_u8_fast(),
            vt => {
                return self.err(format!(
                    "invalid container type: expecting bin|str|array, got: 0x{vt:x}"
                ))
            }
        };
        self.bd_read = false;
        Ok(self.readx(clen.max(0) as usize)?.to_vec())
    }

    /// `decSliceHelperStart`: the element count of an array, or twice the
    /// entry count of a map.
    fn slice_helper_start(&mut self) -> Res<usize> {
        match self.container_type()? {
            VT_ARRAY => Ok(self.read_array_start()?.max(0) as usize),
            VT_MAP => Ok(self.read_map_start()?.max(0) as usize * 2),
            ct => self.err(format!(
                "only encoded map or array can be decoded into a slice ({ct})"
            )),
        }
    }

    fn depth_incr(&mut self) -> Res<()> {
        self.depth += 1;
        if self.depth >= MAX_DEPTH {
            return self.err("maximum decoding depth exceeded");
        }
        Ok(())
    }

    /// `fastpathTV.DecSliceUint8V` with `canChange`: the elements.
    fn dec_slice_u8_fast(&mut self) -> Res<Vec<u8>> {
        let n = self.slice_helper_start()?;
        let mut v = Vec::new();
        if n == 0 {
            return Ok(v);
        }
        self.depth_incr()?;
        for _ in 0..n {
            let b = if self.try_decode_as_nil()? {
                0
            } else {
                self.decode_uint_bits(8)? as u8
            };
            v.push(b);
        }
        self.depth -= 1;
        Ok(v)
    }

    // ---- Decoder: by type ------------------------------------------------

    /// `decodeValue` into `v` (the caller has read past a nil). `settable`
    /// is false inside an unaddressable value (a `map[K]struct` entry decoded
    /// again), where go-codec writes scalars through `unsafe` but cannot set
    /// a slice, array or pointer.
    fn decode_value(&mut self, ty: &'static Ty, v: &mut GoVal, settable: bool) -> Res<()> {
        match (ty, v) {
            (Ty::Ptr(t), GoVal::Ptr(p)) => {
                if p.is_none() {
                    if !settable {
                        return self.err("reflect: reflect.Value.Set using unaddressable value");
                    }
                    *p = Some(Box::new(GoVal::zero(t)));
                }
                let inner = p.as_mut().expect("allocated above");
                self.decode_value(t, inner, true)
            }
            (Ty::Struct(fields), GoVal::Struct(vals)) => self.k_struct(fields, vals, settable),
            (Ty::U64, v) => {
                *v = GoVal::Uint(self.decode_u64()?);
                Ok(())
            }
            (Ty::U32 | Ty::U16 | Ty::U8, v) => {
                let bits = match ty {
                    Ty::U32 => 32,
                    Ty::U16 => 16,
                    _ => 8,
                };
                *v = GoVal::Uint(self.decode_uint_bits(bits)?);
                Ok(())
            }
            (Ty::I64, v) => {
                *v = GoVal::Int(self.decode_i64()?);
                Ok(())
            }
            (Ty::Bool, v) => {
                *v = GoVal::Bool(self.decode_bool()?);
                Ok(())
            }
            (Ty::Str, v) => {
                *v = GoVal::Str(self.decode_bytes()?);
                Ok(())
            }
            (Ty::Bytes, GoVal::Bytes(b)) => self.k_bytes(b, settable),
            (Ty::ByteArray(_) | Ty::Address, GoVal::Array(a)) => {
                if !settable {
                    return self.err("reflect.Value.Slice: slice of unaddressable array");
                }
                self.k_byte_array(a)
            }
            (Ty::FastSlice(elem), GoVal::Slice(s)) => self.k_fast_slice(elem, s),
            (Ty::Strings, GoVal::Slice(s)) => self.k_fast_slice(&Ty::Str, s),
            (Ty::Slice(elem, name), GoVal::Slice(s)) => self.k_slice(elem, name, s, settable),
            (Ty::Map(kt, vt), GoVal::Map(m)) => self.k_map(kt, vt, m, settable),
            _ => unreachable!("a GoVal always has its Ty's shape"),
        }
    }

    /// `structFieldInfo.setToZeroValue` (a nil in the stream).
    fn set_zero(&self, ty: &'static Ty, v: &mut GoVal, settable: bool) -> Res<()> {
        if !settable {
            return self.err("reflect: reflect.Value.Set using unaddressable value");
        }
        *v = GoVal::zero(ty);
        Ok(())
    }

    fn k_struct(
        &mut self,
        fields: &'static [Field],
        vals: &mut [GoVal],
        settable: bool,
    ) -> Res<()> {
        match self.container_type()? {
            VT_MAP => {
                let n = self.read_map_start()?;
                if n == 0 {
                    return Ok(());
                }
                self.depth_incr()?;
                for _ in 0..n.max(0) {
                    let key = self.decode_bytes()?;
                    match self.index_for_enc_name(fields, &key)? {
                        Some(k) => {
                            let t = &fields[k].1;
                            if self.try_decode_as_nil()? {
                                self.set_zero(t, &mut vals[k], settable)?;
                            } else {
                                self.decode_value(t, &mut vals[k], settable)?;
                            }
                        }
                        None => {
                            // an empty key fails in indexForEncName first
                            let mut msg =
                                b"no matching struct field found when decoding stream map with key "
                                    .to_vec();
                            msg.extend_from_slice(&key);
                            return self.err(msg);
                        }
                    }
                }
                self.depth -= 1;
                Ok(())
            }
            VT_ARRAY => {
                let n = self.read_array_start()?.max(0) as usize;
                if n == 0 {
                    return Ok(());
                }
                self.depth_incr()?;
                for (j, Field(_, t)) in fields.iter().enumerate() {
                    if j == n {
                        break;
                    }
                    if self.try_decode_as_nil()? {
                        self.set_zero(t, &mut vals[j], settable)?;
                    } else {
                        self.decode_value(t, &mut vals[j], settable)?;
                    }
                }
                if n > fields.len() {
                    return self.err(format!(
                        "no matching struct field found when decoding stream array at index {}",
                        fields.len()
                    ));
                }
                self.depth -= 1;
                Ok(())
            }
            _ => self.err("only encoded map or array can be decoded into a struct"),
        }
    }

    /// `typeInfo.indexForEncName` over go-codec's `sfiNamesSort`: each field,
    /// in name order, as `sep name 0xff hi lo`; the first match of
    /// `sep(key) key 0xff` anywhere in it (it can span two entries) names
    /// the field. Go's runtime errors where it indexes out of range.
    fn index_for_enc_name(&self, fields: &'static [Field], key: &[u8]) -> Res<Option<usize>> {
        if key.is_empty() {
            return self.err("runtime error: index out of range [0] with length 0");
        }
        let mut sorted: Vec<&str> = fields.iter().map(|f| f.0).collect();
        sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let mut ss = Vec::new();
        for (i, name) in sorted.iter().enumerate() {
            ss.push(tisep(name.as_bytes()));
            ss.extend_from_slice(name.as_bytes());
            ss.extend_from_slice(&[0xff, (i >> 8) as u8, i as u8]);
        }
        let mut sn = Vec::with_capacity(key.len() + 2);
        sn.push(tisep(key));
        sn.extend_from_slice(key);
        sn.push(0xff);
        let Some(j) = ss.windows(sn.len()).position(|w| w == sn.as_slice()) else {
            return Ok(None);
        };
        let (lo_at, hi_at) = (j + sn.len() + 1, j + sn.len());
        for at in [lo_at, hi_at] {
            if at >= ss.len() {
                return self.err(format!(
                    "runtime error: index out of range [{at}] with length {}",
                    ss.len()
                ));
            }
        }
        let k = i16::from_be_bytes([ss[hi_at], ss[lo_at]]);
        if k < 0 {
            return Ok(None);
        }
        let k = k as usize;
        if k >= sorted.len() {
            return self.err(format!(
                "runtime error: index out of range [{k}] with length {}",
                sorted.len()
            ));
        }
        Ok(fields.iter().position(|f| f.0 == sorted[k]))
    }

    /// `kSlice` for a `[]byte`.
    fn k_bytes(&mut self, b: &mut GoSlice<u8>, settable: bool) -> Res<()> {
        let ct = self.container_type()?;
        if ct == VT_BYTES {
            let bs2 = self.decode_bytes()?;
            if settable {
                // decByteSlice reuses the slice when it is long enough
                let cap = if b.backing.len() >= bs2.len() && !bs2.is_empty() {
                    b.backing.len()
                } else {
                    bs2.len()
                };
                let mut backing = bs2;
                let len = backing.len();
                if cap > len {
                    backing.extend_from_slice(&b.backing[len..cap]);
                }
                *b = GoSlice {
                    nil: false,
                    len,
                    backing,
                };
            } else if b.len > 0 && !bs2.is_empty() {
                let k = b.len.min(bs2.len());
                b.backing[..k].copy_from_slice(&bs2[..k]);
            }
            return Ok(());
        }
        let n = self.slice_helper_start()?;
        // `[]uint8` elements: immutable, each set in turn
        self.slice_elems(n, b, 0, 1, settable, |d, _| {
            Ok(if d.try_decode_as_nil()? {
                Some(0)
            } else {
                Some(d.decode_uint_bits(8)? as u8)
            })
        })
    }

    /// `kSlice` for a `[N]byte` (a slice of the whole array, which go-codec
    /// can neither grow nor shrink).
    fn k_byte_array(&mut self, a: &mut [u8]) -> Res<()> {
        if self.container_type()? == VT_BYTES {
            let bs2 = self.decode_bytes()?;
            let k = a.len().min(bs2.len());
            a[..k].copy_from_slice(&bs2[..k]);
            return Ok(());
        }
        let n = self.slice_helper_start()?;
        if n == 0 {
            return Ok(());
        }
        self.depth_incr()?;
        for j in 0..n {
            let as_nil = self.try_decode_as_nil()?;
            if j >= a.len() {
                return self.err(format!(
                    "cannot expand array len during decode from {} to {}",
                    a.len(),
                    j + 1
                ));
            }
            a[j] = if as_nil {
                0
            } else {
                self.decode_uint_bits(8)? as u8
            };
        }
        self.depth -= 1;
        Ok(())
    }

    /// The fast paths (`DecSliceUint64V`, `DecSliceStringV`): a fresh slice
    /// of the elements.
    fn k_fast_slice(&mut self, elem: &'static Ty, s: &mut GoSlice<GoVal>) -> Res<()> {
        let n = self.slice_helper_start()?;
        let mut out = Vec::new();
        if n > 0 {
            self.depth_incr()?;
            for _ in 0..n {
                let x = if self.try_decode_as_nil()? {
                    GoVal::zero(elem)
                } else {
                    let mut x = GoVal::zero(elem);
                    self.decode_value(elem, &mut x, true)?;
                    x
                };
                out.push(x);
            }
            self.depth -= 1;
        }
        *s = GoSlice {
            nil: false,
            len: out.len(),
            backing: out,
        };
        Ok(())
    }

    /// `kSlice` for a `[]T`.
    fn k_slice(
        &mut self,
        elem: &'static Ty,
        name: &str,
        s: &mut GoSlice<GoVal>,
        settable: bool,
    ) -> Res<()> {
        let ct = self.container_type()?;
        if ct == VT_BYTES {
            return self.err(format!(
                "bytes/string in stream must decode into slice/array of bytes, not {name}"
            ));
        }
        let n = self.slice_helper_start()?;
        let unit = size_align(elem).0;
        self.slice_elems(
            n,
            s,
            GoVal::zero(elem),
            unit,
            settable,
            |d, x: &mut GoVal| {
                if d.try_decode_as_nil()? {
                    *x = GoVal::zero(elem);
                } else {
                    // a slice element is addressable even in an unaddressable slice
                    d.decode_value(elem, x, true)?;
                }
                Ok(None)
            },
        )
    }

    /// The element loop of `kSlice` (its length and capacity handling),
    /// generic over the element. `elem_fn` decodes element `j` (into the
    /// slot it is given) or returns the value to store.
    fn slice_elems<T: Clone>(
        &mut self,
        n: usize,
        s: &mut GoSlice<T>,
        zero: T,
        unit: usize,
        settable: bool,
        mut elem_fn: impl FnMut(&mut Self, &mut T) -> Res<Option<T>>,
    ) -> Res<()> {
        if n == 0 {
            if settable {
                s.nil = false;
                s.len = 0;
            }
            return Ok(());
        }
        self.depth_incr()?;
        let mut rvlen = s.len;
        let mut rvcap = s.backing.len();
        if n > rvcap {
            let old_len = s.len;
            rvlen = infer_len(n, unit);
            if rvlen <= rvcap {
                if settable {
                    s.len = rvlen;
                }
            } else if settable {
                // reflect.MakeSlice, then reflect.Copy of the old elements
                // (an immutable element is overwritten below either way)
                let mut backing = vec![zero.clone(); rvlen];
                backing[..old_len].clone_from_slice(&s.backing[..old_len]);
                s.backing = backing;
                s.nil = false;
                s.len = rvlen;
                rvcap = rvlen;
            } else {
                return self.err("cannot decode into non-settable slice");
            }
        } else if n != rvlen {
            rvlen = n;
            if settable {
                s.len = n;
            }
        }
        for j in 0..n {
            if j >= rvlen {
                // expandSliceRV by one
                if !settable {
                    return self.err("expand slice: cannot change");
                }
                if rvlen < rvcap {
                    s.len = rvlen + 1;
                } else {
                    let new_cap = grow_cap(rvcap, unit, 1);
                    let mut backing = vec![zero.clone(); new_cap];
                    backing[..rvlen].clone_from_slice(&s.backing[..rvlen]);
                    s.backing = backing;
                    s.len = rvlen + 1;
                    rvcap = new_cap;
                }
                rvlen += 1;
            }
            if j >= s.len {
                // rv.Index past the length of an unaddressable slice
                return self.err("reflect: slice index out of range");
            }
            if let Some(x) = elem_fn(self, &mut s.backing[j])? {
                s.backing[j] = x;
            }
        }
        if n < rvlen && settable {
            s.len = n;
        }
        self.depth -= 1;
        Ok(())
    }

    /// `kMap` for a `map[uint64]T`.
    fn k_map(
        &mut self,
        kt: &'static Ty,
        vt: &'static Ty,
        m: &mut Option<Vec<(u64, GoVal)>>,
        settable: bool,
    ) -> Res<()> {
        let n = self.read_map_start()?;
        if m.is_none() {
            if !settable {
                return self.err("reflect: reflect.Value.Set using unaddressable value");
            }
            *m = Some(Vec::new());
        }
        if n == 0 {
            return Ok(());
        }
        self.depth_incr()?;
        let entries = m.as_mut().expect("made above");
        for _ in 0..n.max(0) {
            let mut key = GoVal::zero(kt);
            self.decode_value(kt, &mut key, true)?;
            let GoVal::Uint(k) = key else {
                unreachable!("map keys are uint64")
            };
            let at = entries.iter().position(|(x, _)| *x == k);
            let val = if self.try_decode_as_nil()? {
                GoVal::zero(vt)
            } else {
                match at {
                    // mapGet: a mutable value is decoded into a copy of the
                    // entry, which reflect cannot address
                    Some(i) if !immutable(vt) => {
                        let mut copy = entries[i].1.clone();
                        self.decode_value(vt, &mut copy, false)?;
                        copy
                    }
                    _ => {
                        let mut fresh = GoVal::zero(vt);
                        self.decode_value(vt, &mut fresh, true)?;
                        fresh
                    }
                }
            };
            match at {
                Some(i) => entries[i].1 = val,
                None => entries.push((k, val)),
            }
        }
        self.depth -= 1;
        Ok(())
    }
}
