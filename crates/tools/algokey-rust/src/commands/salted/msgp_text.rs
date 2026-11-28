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

//! The msgp readers of `github.com/algorand/msgp` v1.1.66 (`msgp/read_bytes.go`)
//! with their error texts (`msgp/errors.go`), for the generated decoders of
//! `cmd/algokey/msgp_gen.go` (`saltedPublicMaterial`, `saltedSigningMaterial`):
//! a malformed key file is reported as go reports it (`protocol.Decode`).
//!
//! Copied from `crates/tools/goal-rust/src/balance_record.rs` (`goal account
//! dump`, #2467), which reads go's `basics` types the same way; only the
//! readers this decoder uses matter here.

#![allow(dead_code)]

use std::fmt;

// ---- msgp's errors (msgp/errors.go) -----------------------------------------

/// A msgp `Type` (`msgp/read.go` `Type.String`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Ty {
    Invalid,
    Str,
    Bin,
    Map,
    Array,
    Float64,
    Float32,
    Bool,
    Uint,
    Int,
    Ext,
    Nil,
}

impl Ty {
    fn name(self) -> &'static str {
        match self {
            Ty::Str => "str",
            Ty::Bin => "bin",
            Ty::Map => "map",
            Ty::Array => "array",
            Ty::Float64 => "float64",
            Ty::Float32 => "float32",
            Ty::Bool => "bool",
            Ty::Uint => "uint",
            Ty::Int => "int",
            Ty::Ext => "ext",
            Ty::Nil => "nil",
            Ty::Invalid => "<invalid>",
        }
    }
}

/// `sizes[lead].typ` (`msgp/elsize.go`).
fn type_of(lead: u8) -> Ty {
    match lead {
        0x00..=0x7f | 0xe0..=0xff | 0xd0..=0xd3 => Ty::Int,
        0x80..=0x8f | 0xde | 0xdf => Ty::Map,
        0x90..=0x9f | 0xdc | 0xdd => Ty::Array,
        0xa0..=0xbf | 0xd9..=0xdb => Ty::Str,
        0xc0 => Ty::Nil,
        0xc1 => Ty::Invalid,
        0xc2 | 0xc3 => Ty::Bool,
        0xc4..=0xc6 => Ty::Bin,
        0xc7..=0xc9 | 0xd4..=0xd8 => Ty::Ext,
        0xca => Ty::Float32,
        0xcb => Ty::Float64,
        0xcc..=0xcf => Ty::Uint,
    }
}

/// The msgp errors that keep a context of their own (`contextError`).
#[derive(Clone, Debug)]
pub(super) enum CtxKind {
    Type { method: Ty, encoded: Ty },
    UintOverflow { value: u64, bits: u32 },
    UintBelowZero { value: i64 },
}

/// A msgp decode error.
#[derive(Clone, Debug)]
pub(super) enum MErr {
    /// `ErrShortBytes`: never wrapped.
    Short,
    /// A `contextError` and its context.
    Ctx(CtxKind, String),
    /// An error without a context of its own: `ErrNoField`,
    /// `ErrTooManyArrayFields`, `errOverflow`, `InvalidPrefixError`.
    Plain(String),
    /// `errWrapped`: a cause and a context.
    Wrapped(Box<MErr>, String),
}

impl fmt::Display for MErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn at(f: &mut fmt::Formatter<'_>, ctx: &str) -> fmt::Result {
            if ctx.is_empty() {
                Ok(())
            } else {
                write!(f, " at {ctx}")
            }
        }
        match self {
            MErr::Short => f.write_str("msgp: too few bytes left to read object"),
            MErr::Ctx(kind, ctx) => {
                match kind {
                    CtxKind::Type { method, encoded } => write!(
                        f,
                        "msgp: attempted to decode type \"{}\" with method for \"{}\"",
                        encoded.name(),
                        method.name()
                    )?,
                    CtxKind::UintOverflow { value, bits } => {
                        write!(f, "msgp: {value} overflows uint{bits}")?
                    }
                    CtxKind::UintBelowZero { value } => {
                        write!(f, "msgp: attempted to cast int {value} to unsigned")?
                    }
                }
                at(f, ctx)
            }
            MErr::Plain(s) => f.write_str(s),
            MErr::Wrapped(cause, ctx) => {
                write!(f, "{cause}")?;
                at(f, ctx)
            }
        }
    }
}

/// msgp's `WrapError(err, ctx...)`.
pub(super) fn wrap(e: MErr, ctx: &[String]) -> MErr {
    let add = ctx.join("/");
    match e {
        MErr::Short => MErr::Short,
        // `UintBelowZero.withContext` replaces the context
        MErr::Ctx(k @ CtxKind::UintBelowZero { .. }, _) => MErr::Ctx(k, add),
        // `addCtx`
        MErr::Ctx(k, old) if old.is_empty() => MErr::Ctx(k, add),
        MErr::Ctx(k, old) => MErr::Ctx(k, format!("{add}/{old}")),
        other => MErr::Wrapped(Box::new(other), add),
    }
}

fn type_err(method: Ty, encoded: Ty) -> MErr {
    MErr::Ctx(CtxKind::Type { method, encoded }, String::new())
}

/// msgp's `badPrefix`.
fn bad_prefix(want: Ty, lead: u8) -> MErr {
    match type_of(lead) {
        Ty::Invalid => MErr::Plain(format!("msgp: unrecognized type prefix 0x{lead:x}")),
        t => type_err(want, t),
    }
}

fn encoded_type(e: &MErr) -> Option<Ty> {
    match e {
        MErr::Ctx(CtxKind::Type { encoded, .. }, _) => Some(*encoded),
        _ => None,
    }
}

/// `ctx` followed by `more`.
fn with(ctx: &[String], more: &[&str]) -> Vec<String> {
    ctx.iter()
        .cloned()
        .chain(more.iter().map(|s| (*s).to_string()))
        .collect()
}

// ---- msgp's readers (msgp/read_bytes.go) ------------------------------------

pub(super) type R<T> = Result<T, MErr>;

/// The bytes still to decode.
pub(super) struct Rd<'a>(pub(super) &'a [u8]);

fn be(b: &[u8], n: usize) -> u64 {
    b[..n].iter().fold(0u64, |a, x| (a << 8) | u64::from(*x))
}

/// `readArrayHeaderBytes(b, flattenMap)`: `(size, header length)`.
fn array_header_of(b: &[u8], flatten: bool) -> R<(usize, usize)> {
    let Some(&lead) = b.first() else {
        return Err(MErr::Short);
    };
    let need = |n: usize| {
        if b.len() < n {
            Err(MErr::Short)
        } else {
            Ok(())
        }
    };
    Ok(match lead {
        0x90..=0x9f => (usize::from(lead & 0x0f), 1),
        0x80..=0x8f if flatten => (2 * usize::from(lead & 0x0f), 1),
        0xc0 => (0, 1),
        0xdc => {
            need(3)?;
            (be(&b[1..], 2) as usize, 3)
        }
        0xdd => {
            need(5)?;
            (be(&b[1..], 4) as usize, 5)
        }
        0xde if flatten => {
            need(3)?;
            (2 * be(&b[1..], 2) as usize, 3)
        }
        0xdf if flatten => {
            need(5)?;
            (2 * be(&b[1..], 4) as usize, 5)
        }
        _ => return Err(bad_prefix(Ty::Array, lead)),
    })
}

/// A str and/or bin header: `Some((size, header length))`, `Some((0, 1))`
/// for nil, `None` for another type.
fn str_or_bin(b: &[u8], strs: bool, bins: bool) -> R<Option<(usize, usize)>> {
    let lead = b[0];
    let need = |n: usize| {
        if b.len() < n {
            Err(MErr::Short)
        } else {
            Ok(())
        }
    };
    Ok(Some(match lead {
        0xa0..=0xbf if strs => (usize::from(lead & 0x1f), 1),
        0xd9 if strs => {
            need(2)?;
            (usize::from(b[1]), 2)
        }
        0xda if strs => {
            need(3)?;
            (be(&b[1..], 2) as usize, 3)
        }
        0xdb if strs => {
            need(5)?;
            (be(&b[1..], 4) as usize, 5)
        }
        0xc0 => (0, 1),
        0xc4 if bins => {
            need(2)?;
            (usize::from(b[1]), 2)
        }
        0xc5 if bins => {
            need(3)?;
            (be(&b[1..], 2) as usize, 3)
        }
        0xc6 if bins => {
            need(5)?;
            (be(&b[1..], 4) as usize, 5)
        }
        _ => return Ok(None),
    }))
}

impl Rd<'_> {
    /// `ReadMapHeaderBytes`: `(size, isnil)`.
    pub(super) fn map_header(&mut self) -> R<(usize, bool)> {
        let b = self.0;
        let Some(&lead) = b.first() else {
            return Err(MErr::Short);
        };
        let need = |n: usize| {
            if b.len() < n {
                Err(MErr::Short)
            } else {
                Ok(())
            }
        };
        let (sz, used, nil) = match lead {
            0x80..=0x8f => (usize::from(lead & 0x0f), 1, false),
            0xc0 => (0, 1, true),
            0xde => {
                need(3)?;
                (be(&b[1..], 2) as usize, 3, false)
            }
            0xdf => {
                need(5)?;
                (be(&b[1..], 4) as usize, 5, false)
            }
            _ => return Err(bad_prefix(Ty::Map, lead)),
        };
        self.0 = &b[used..];
        Ok((sz, nil))
    }

    /// `ReadArrayHeaderBytes`.
    pub(super) fn array_header(&mut self) -> R<usize> {
        let (sz, used) = array_header_of(self.0, true)?;
        self.0 = &self.0[used..];
        Ok(sz)
    }

    /// `ReadUint64Bytes`.
    pub(super) fn u64(&mut self) -> R<u64> {
        let b = self.0;
        let Some(&lead) = b.first() else {
            return Err(MErr::Short);
        };
        let below = |v: i64| MErr::Ctx(CtxKind::UintBelowZero { value: v }, String::new());
        let need = |n: usize| {
            if b.len() < n {
                Err(MErr::Short)
            } else {
                Ok(())
            }
        };
        let (v, used) = match lead {
            0x00..=0x7f => (u64::from(lead), 1),
            0xc0 => (0, 1),
            0xcc..=0xcf => {
                let n = 1usize << (lead - 0xcc);
                need(1 + n)?;
                (be(&b[1..], n), 1 + n)
            }
            0xd0..=0xd3 => {
                let n = 1usize << (lead - 0xd0);
                need(1 + n)?;
                let shift = 64 - 8 * n as u32;
                let v = ((be(&b[1..], n) << shift) as i64) >> shift;
                if v < 0 {
                    return Err(below(v));
                }
                (v as u64, 1 + n)
            }
            0xe0..=0xff => return Err(below(i64::from(lead as i8))),
            _ => return Err(bad_prefix(Ty::Uint, lead)),
        };
        self.0 = &b[used..];
        Ok(v)
    }

    /// `ReadUint32Bytes` / `ReadUint8Bytes`: `ReadUint64Bytes`, then the
    /// overflow check (made after an error too, on the zero value).
    pub(super) fn uint(&mut self, bits: u32) -> R<u64> {
        let r = self.u64();
        let v = *r.as_ref().unwrap_or(&0);
        if v >> bits != 0 {
            return Err(MErr::Ctx(
                CtxKind::UintOverflow { value: v, bits },
                String::new(),
            ));
        }
        r
    }

    /// `ReadBoolBytes`.
    pub(super) fn bool(&mut self) -> R<bool> {
        let Some(&lead) = self.0.first() else {
            return Err(MErr::Short);
        };
        let v = match lead {
            0xc3 => true,
            0xc2 | 0xc0 => false,
            _ => return Err(bad_prefix(Ty::Bool, lead)),
        };
        self.0 = &self.0[1..];
        Ok(v)
    }

    /// `readBytesBytesSlow`: an array of bytes.
    pub(super) fn bytes_slow(&mut self, flatten: bool) -> R<Vec<u8>> {
        let (count, used) = array_header_of(self.0, flatten)?;
        let mut o = Rd(&self.0[used..]);
        if o.0.len() < count {
            return Err(MErr::Short);
        }
        let mut v = Vec::with_capacity(count);
        for _ in 0..count {
            v.push(o.uint(8)? as u8);
        }
        self.0 = o.0;
        Ok(v)
    }

    /// `readBytesBytes(b, scratch, zc, flattenMap)`.
    pub(super) fn bytes_flat(&mut self, flatten: bool) -> R<Vec<u8>> {
        let Some(&lead) = self.0.first() else {
            return Err(MErr::Short);
        };
        match str_or_bin(self.0, true, true)? {
            Some((n, used)) => {
                let rest = &self.0[used..];
                if rest.len() < n {
                    return Err(MErr::Short);
                }
                self.0 = &rest[n..];
                Ok(rest[..n].to_vec())
            }
            None => {
                let mut probe = Rd(self.0);
                match probe.bytes_slow(flatten) {
                    Ok(v) => {
                        self.0 = probe.0;
                        Ok(v)
                    }
                    Err(_) => Err(bad_prefix(Ty::Bin, lead)),
                }
            }
        }
    }

    /// `ReadBytesBytes`.
    pub(super) fn bytes(&mut self) -> R<Vec<u8>> {
        self.bytes_flat(true)
    }

    /// `ReadStringZC` / `ReadStringBytes`: the string's bytes.
    pub(super) fn string(&mut self) -> R<Vec<u8>> {
        let Some(&lead) = self.0.first() else {
            return Err(MErr::Short);
        };
        match str_or_bin(self.0, true, false)? {
            Some((n, used)) => {
                let rest = &self.0[used..];
                if rest.len() < n {
                    return Err(MErr::Short);
                }
                self.0 = &rest[n..];
                Ok(rest[..n].to_vec())
            }
            // go-codec compat: a bin (or an array of bytes) as a string
            None => {
                let mut probe = Rd(self.0);
                match probe.bytes_flat(false) {
                    Ok(v) => {
                        self.0 = probe.0;
                        Ok(v)
                    }
                    Err(_) => Err(type_err(Ty::Str, type_of(lead))),
                }
            }
        }
    }

    /// `ReadMapKeyZC`.
    pub(super) fn map_key(&mut self) -> R<Vec<u8>> {
        match self.string() {
            Err(e) if encoded_type(&e) == Some(Ty::Bin) => self.bytes_flat(true),
            r => r,
        }
    }

    /// `ReadBytesBytesHeader`: the size, nothing consumed.
    pub(super) fn bytes_header(&self) -> R<usize> {
        if self.0.is_empty() {
            return Err(MErr::Short);
        }
        match str_or_bin(self.0, true, true)? {
            Some((n, _)) => Ok(n),
            None => array_header_of(self.0, true).map(|(n, _)| n),
        }
    }

    /// `ReadExactBytes(b, into)`: up to `into.len()` bytes copied over it,
    /// nil clears it.
    pub(super) fn exact(&mut self, into: &mut [u8]) -> R<()> {
        let Some(&lead) = self.0.first() else {
            return Err(MErr::Short);
        };
        match str_or_bin(self.0, true, true)? {
            Some((_, 1)) if lead == 0xc0 => {
                into.fill(0);
                self.0 = &self.0[1..];
                Ok(())
            }
            Some((n, used)) => {
                let rest = &self.0[used..];
                if rest.len() < n {
                    return Err(MErr::Short);
                }
                let k = n.min(into.len());
                into[..k].copy_from_slice(&rest[..k]);
                self.0 = &rest[n..];
                Ok(())
            }
            None => {
                // `readExactBytesSlow`, any error reported as the prefix's
                let mut probe = Rd(self.0);
                let mut slow = || -> R<()> {
                    let count = probe.array_header()?;
                    if count > into.len() {
                        return Err(MErr::Short);
                    }
                    for b in into.iter_mut().take(count) {
                        *b = probe.uint(8)? as u8;
                    }
                    Ok(())
                };
                match slow() {
                    Ok(()) => {
                        self.0 = probe.0;
                        Ok(())
                    }
                    Err(_) => Err(bad_prefix(Ty::Bin, lead)),
                }
            }
        }
    }
}
