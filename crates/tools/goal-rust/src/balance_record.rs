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

//! `goal account dump` (`cmd/goal/account.go` `dumpCmd`), issue #2467: the
//! account's `basics.AccountData` as algod answers it in msgpack
//! (`GET /v2/accounts/<addr>?format=msgpack`), decoded as go decodes it
//! (`protocol.Decode`: the msgp-generated `UnmarshalMsg` of
//! `data/basics/msgp_gen.go`, with `github.com/algorand/msgp` v1.1.64's
//! readers and error texts), then the `basics.BalanceRecord` written as go
//! writes it: `protocol.EncodeJSONStrict` (go-codec, `Canonical`, `Indent:
//! 2`, `HTMLCharsAsIs`, `MapKeyAsString`, every field `omitempty`, an
//! `Address` through its `MarshalText`) or, for `-o`, `protocol.Encode`
//! (the msgp-generated `MarshalMsg`).
//!
//! The decoder mirrors the generated code's shape: a struct is a map of its
//! codec names or, if the value is not a map, an array of its fields in
//! source order (`struct-from-array`); a nested struct is decoded either by
//! its own `UnmarshalMsgWithState` (its error then wrapped by the caller) or
//! inline (the caller's context prefixed), which shows in how errors read.

use std::collections::BTreeMap;
use std::fmt;

use crate::transcode::{encode_protocol_json, Json};

// ---- msgp's errors (msgp/errors.go) -----------------------------------------

/// A msgp `Type` (`msgp/read.go` `Type.String`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ty {
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
enum CtxKind {
    Type { method: Ty, encoded: Ty },
    UintOverflow { value: u64, bits: u32 },
    UintBelowZero { value: i64 },
}

/// A msgp decode error.
#[derive(Clone, Debug)]
enum MErr {
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
fn wrap(e: MErr, ctx: &[String]) -> MErr {
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

type R<T> = Result<T, MErr>;

/// The bytes still to decode.
struct Rd<'a>(&'a [u8]);

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
    fn map_header(&mut self) -> R<(usize, bool)> {
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
    fn array_header(&mut self) -> R<usize> {
        let (sz, used) = array_header_of(self.0, true)?;
        self.0 = &self.0[used..];
        Ok(sz)
    }

    /// `ReadUint64Bytes`.
    fn u64(&mut self) -> R<u64> {
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
    fn uint(&mut self, bits: u32) -> R<u64> {
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
    fn bool(&mut self) -> R<bool> {
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
    fn bytes_slow(&mut self, flatten: bool) -> R<Vec<u8>> {
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
    fn bytes_flat(&mut self, flatten: bool) -> R<Vec<u8>> {
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
    fn bytes(&mut self) -> R<Vec<u8>> {
        self.bytes_flat(true)
    }

    /// `ReadStringZC` / `ReadStringBytes`: the string's bytes.
    fn string(&mut self) -> R<Vec<u8>> {
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
    fn map_key(&mut self) -> R<Vec<u8>> {
        match self.string() {
            Err(e) if encoded_type(&e) == Some(Ty::Bin) => self.bytes_flat(true),
            r => r,
        }
    }

    /// `ReadBytesBytesHeader`: the size, nothing consumed.
    fn bytes_header(&self) -> R<usize> {
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
    fn exact(&mut self, into: &mut [u8]) -> R<()> {
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

// ---- the types (data/basics) ------------------------------------------------

/// `StateSchema`.
#[derive(Clone, Default)]
struct StateSchema {
    num_uint: u64,
    num_byte_slice: u64,
}

/// `TealValue`.
#[derive(Clone, Default)]
struct TealValue {
    typ: u64,
    bytes: Vec<u8>,
    uint: u64,
}

type TealKeyValue = BTreeMap<Vec<u8>, TealValue>;

/// `AssetHolding`.
#[derive(Clone, Default)]
struct AssetHolding {
    amount: u64,
    frozen: bool,
}

/// `AssetParams`.
#[derive(Clone, Default)]
struct AssetParams {
    total: u64,
    decimals: u64,
    default_frozen: bool,
    unit_name: Vec<u8>,
    asset_name: Vec<u8>,
    url: Vec<u8>,
    metadata_hash: [u8; 32],
    manager: [u8; 32],
    reserve: [u8; 32],
    freeze: [u8; 32],
    clawback: [u8; 32],
}

/// `AppLocalState`.
#[derive(Clone, Default)]
struct AppLocalState {
    schema: StateSchema,
    key_value: TealKeyValue,
}

/// `AppParams` (with its embedded `StateSchemas`).
#[derive(Clone, Default)]
struct AppParams {
    approval_program: Vec<u8>,
    clear_state_program: Vec<u8>,
    global_state: TealKeyValue,
    local_state_schema: StateSchema,
    global_state_schema: StateSchema,
    extra_program_pages: u64,
    version: u64,
    size_sponsor: [u8; 32],
    foreign_box_reads: bool,
    family_box_access: bool,
}

/// `AccountData`.
#[derive(Clone)]
struct AccountData {
    status: u64,
    micro_algos: u64,
    rewards_base: u64,
    rewarded_micro_algos: u64,
    vote_id: [u8; 32],
    selection_id: [u8; 32],
    state_proof_id: [u8; 64],
    vote_first_valid: u64,
    vote_last_valid: u64,
    vote_key_dilution: u64,
    last_proposed: u64,
    last_heartbeat: u64,
    asset_params: BTreeMap<u64, AssetParams>,
    assets: BTreeMap<u64, AssetHolding>,
    auth_addr: [u8; 32],
    incentive_eligible: bool,
    app_local_states: BTreeMap<u64, AppLocalState>,
    app_params: BTreeMap<u64, AppParams>,
    total_app_schema: StateSchema,
    total_extra_app_pages: u64,
    total_boxes: u64,
    total_box_bytes: u64,
}

impl Default for AccountData {
    fn default() -> Self {
        Self {
            status: 0,
            micro_algos: 0,
            rewards_base: 0,
            rewarded_micro_algos: 0,
            vote_id: [0; 32],
            selection_id: [0; 32],
            state_proof_id: [0; 64],
            vote_first_valid: 0,
            vote_last_valid: 0,
            vote_key_dilution: 0,
            last_proposed: 0,
            last_heartbeat: 0,
            asset_params: BTreeMap::new(),
            assets: BTreeMap::new(),
            auth_addr: [0; 32],
            incentive_eligible: false,
            app_local_states: BTreeMap::new(),
            app_params: BTreeMap::new(),
            total_app_schema: StateSchema::default(),
            total_extra_app_pages: 0,
            total_boxes: 0,
            total_box_bytes: 0,
        }
    }
}

// ---- the decoder (data/basics/msgp_gen.go) ------------------------------------

/// The decoder of one field: the reader, the struct, the field's full
/// context (the struct's context, `struct-from-array` in the array form,
/// the field's Go name).
type FieldFn<T> = fn(&mut Rd<'_>, &mut T, &[String]) -> R<()>;

/// A struct field: `(codec name, Go name, decoder)`, in source order.
type Field<T> = (&'static str, &'static str, FieldFn<T>);

/// A msgp-generated struct decoder: the map form or, when the value is no
/// map, the array form. `ctx` is empty for a struct's own
/// `UnmarshalMsgWithState`, the caller's context for one decoded inline.
fn de_struct<T: Default>(r: &mut Rd<'_>, z: &mut T, ctx: &[String], fields: &[Field<T>]) -> R<()> {
    match r.map_header() {
        Err(e) if encoded_type(&e).is_some() => {
            let mut n = r.array_header().map_err(|e| wrap(e, ctx))?;
            for (_, go, de) in fields {
                if n == 0 {
                    break;
                }
                n -= 1;
                de(r, z, &with(ctx, &["struct-from-array", go]))?;
            }
            if n > 0 {
                let e = MErr::Plain(format!(
                    "Too many array fields when decoding into struct: {n} left"
                ));
                return Err(wrap(e, &with(ctx, &["struct-from-array"])));
            }
            Ok(())
        }
        Err(e) => Err(wrap(e, ctx)),
        Ok((n, nil)) => {
            if nil {
                *z = T::default();
            }
            for _ in 0..n {
                let key = r.map_key().map_err(|e| wrap(e, ctx))?;
                match fields.iter().find(|(codec, _, _)| codec.as_bytes() == key) {
                    Some((_, go, de)) => de(r, z, &with(ctx, &[go]))?,
                    None => {
                        let e = MErr::Plain(format!(
                            "Unknown field: {}",
                            String::from_utf8_lossy(&key)
                        ));
                        return Err(wrap(e, ctx));
                    }
                }
            }
            Ok(())
        }
    }
}

/// A leaf read wrapped with the field's context.
fn leaf<T>(r: R<T>, ctx: &[String]) -> R<T> {
    r.map_err(|e| wrap(e, ctx))
}

/// A `[N]byte` type's own `UnmarshalMsgWithState` (`crypto.Digest`,
/// `OneTimeSignatureVerifier`, `VRFVerifier`, `merklesignature.Commitment`,
/// `basics.Address`): `ReadExactBytes`, `WrapError(err)`.
fn method_exact(r: &mut Rd<'_>, into: &mut [u8], ctx: &[String]) -> R<()> {
    r.exact(into)
        .map_err(|e| wrap(e, &[]))
        .map_err(|e| wrap(e, ctx))
}

/// A `bounds` length check that go leaves unwrapped (`errOverflow`).
fn check_len(n: usize, bound: usize) -> R<()> {
    if n > bound {
        return Err(MErr::Plain(format!("msgp: length overflow: {n} > {bound}")));
    }
    Ok(())
}

/// A `[]byte` field: `ReadBytesBytesHeader`, the bound, `ReadBytesBytes`.
fn bounded_bytes(r: &mut Rd<'_>, ctx: &[String], bound: usize) -> R<Vec<u8>> {
    let n = leaf(r.bytes_header(), ctx)?;
    check_len(n, bound)?;
    leaf(r.bytes(), ctx)
}

/// A `string` field with an `allocbound`.
fn bounded_string(r: &mut Rd<'_>, ctx: &[String], bound: usize) -> R<Vec<u8>> {
    let n = leaf(r.bytes_header(), ctx)?;
    check_len(n, bound)?;
    leaf(r.string(), ctx)
}

/// A map field: the header (nil clears the map), a count bound wrapped
/// with the field's context, then each key and value.
fn de_map<K: Ord, V: Default>(
    r: &mut Rd<'_>,
    map: &mut BTreeMap<K, V>,
    ctx: &[String],
    bound: usize,
    key: fn(&mut Rd<'_>) -> R<K>,
    show: fn(&K) -> String,
    value: fn(&mut Rd<'_>, &mut V, &[String]) -> R<()>,
) -> R<()> {
    let (n, nil) = leaf(r.map_header(), ctx)?;
    if n > bound {
        let e = MErr::Plain(format!("msgp: length overflow: {n} > {bound}"));
        return Err(wrap(e, ctx));
    }
    if nil {
        map.clear();
    }
    for _ in 0..n {
        let k = leaf(key(r), ctx)?;
        let mut v = V::default();
        let mut vctx = ctx.to_vec();
        vctx.push(show(&k));
        value(r, &mut v, &vctx)?;
        map.insert(k, v);
    }
    Ok(())
}

/// `AssetIndex` / `AppIndex`'s `UnmarshalMsgWithState`.
fn index_key(r: &mut Rd<'_>) -> R<u64> {
    r.u64().map_err(|e| wrap(e, &[]))
}

/// A `TealKeyValue` key: `ReadStringBytes`.
fn string_key(r: &mut Rd<'_>) -> R<Vec<u8>> {
    r.string()
}

fn show_index(k: &u64) -> String {
    k.to_string()
}

// a `fn(&K)` for `K = Vec<u8>`
#[allow(clippy::ptr_arg)]
fn show_string(k: &Vec<u8>) -> String {
    String::from_utf8_lossy(k).into_owned()
}

/// go's `bounds` (`config/bounds`, set from the built-in protocols by
/// `checkSetAllocBounds`) the account decoder checks.
struct Bounds {
    asset_unit_name: usize,
    asset_name: usize,
    asset_url: usize,
    app_program: usize,
}

fn bounds() -> Bounds {
    let all = algo_types::consensus::built_in_consensus_protocols();
    let max = |f: fn(&algo_types::consensus::ConsensusParams) -> usize| {
        all.values().map(f).max().unwrap_or(0)
    };
    let program = max(|p| p.max_app_program_len);
    let pages = max(|p| p.max_absolute_extra_program_pages as usize);
    Bounds {
        asset_unit_name: max(|p| p.max_asset_unit_name_bytes),
        asset_name: max(|p| p.max_asset_name_bytes),
        asset_url: max(|p| p.max_asset_url_bytes),
        // `MaxAvailableAppProgramLen = MaxAppProgramLen * (1 + MaxExtraAppProgramLen)`
        app_program: program * (1 + pages),
    }
}

/// `bounds.EncodedMaxAssetsPerAccount`.
const ENCODED_MAX_ASSETS_PER_ACCOUNT: usize = 1024;
/// `bounds.EncodedMaxAppLocalStates`.
const ENCODED_MAX_APP_LOCAL_STATES: usize = 64;
/// `bounds.EncodedMaxAppParams`.
const ENCODED_MAX_APP_PARAMS: usize = 64;
/// `bounds.EncodedMaxKeyValueEntries`.
const ENCODED_MAX_KEY_VALUE_ENTRIES: usize = 1024;

thread_local! {
    static BOUNDS: Bounds = bounds();
}

const STATE_SCHEMA: &[Field<StateSchema>] = &[
    ("nui", "NumUint", |r, z, c| {
        z.num_uint = leaf(r.u64(), c)?;
        Ok(())
    }),
    ("nbs", "NumByteSlice", |r, z, c| {
        z.num_byte_slice = leaf(r.u64(), c)?;
        Ok(())
    }),
];

/// A `StateSchema` decoded inline.
fn inline_schema(r: &mut Rd<'_>, z: &mut StateSchema, ctx: &[String]) -> R<()> {
    de_struct(r, z, ctx, STATE_SCHEMA)
}

const TEAL_VALUE: &[Field<TealValue>] = &[
    ("tt", "Type", |r, z, c| {
        z.typ = leaf(r.u64(), c)?;
        Ok(())
    }),
    ("tb", "Bytes", |r, z, c| {
        z.bytes = leaf(r.string(), c)?;
        Ok(())
    }),
    ("ui", "Uint", |r, z, c| {
        z.uint = leaf(r.u64(), c)?;
        Ok(())
    }),
];

/// `TealValue`'s own `UnmarshalMsgWithState`, wrapped by the caller.
fn method_teal_value(r: &mut Rd<'_>, z: &mut TealValue, ctx: &[String]) -> R<()> {
    de_struct(r, z, &[], TEAL_VALUE).map_err(|e| wrap(e, ctx))
}

/// A `TealKeyValue` decoded inline (the map loop in the caller).
fn inline_key_value(r: &mut Rd<'_>, z: &mut TealKeyValue, ctx: &[String]) -> R<()> {
    de_map(
        r,
        z,
        ctx,
        ENCODED_MAX_KEY_VALUE_ENTRIES,
        string_key,
        show_string,
        method_teal_value,
    )
}

const ASSET_HOLDING: &[Field<AssetHolding>] = &[
    ("a", "Amount", |r, z, c| {
        z.amount = leaf(r.u64(), c)?;
        Ok(())
    }),
    ("f", "Frozen", |r, z, c| {
        z.frozen = leaf(r.bool(), c)?;
        Ok(())
    }),
];

fn inline_asset_holding(r: &mut Rd<'_>, z: &mut AssetHolding, ctx: &[String]) -> R<()> {
    de_struct(r, z, ctx, ASSET_HOLDING)
}

const ASSET_PARAMS: &[Field<AssetParams>] = &[
    ("t", "Total", |r, z, c| {
        z.total = leaf(r.u64(), c)?;
        Ok(())
    }),
    ("dc", "Decimals", |r, z, c| {
        z.decimals = leaf(r.uint(32), c)?;
        Ok(())
    }),
    ("df", "DefaultFrozen", |r, z, c| {
        z.default_frozen = leaf(r.bool(), c)?;
        Ok(())
    }),
    ("un", "UnitName", |r, z, c| {
        z.unit_name = bounded_string(r, c, BOUNDS.with(|b| b.asset_unit_name))?;
        Ok(())
    }),
    ("an", "AssetName", |r, z, c| {
        z.asset_name = bounded_string(r, c, BOUNDS.with(|b| b.asset_name))?;
        Ok(())
    }),
    ("au", "URL", |r, z, c| {
        z.url = bounded_string(r, c, BOUNDS.with(|b| b.asset_url))?;
        Ok(())
    }),
    ("am", "MetadataHash", |r, z, c| {
        leaf(r.exact(&mut z.metadata_hash), c)
    }),
    ("m", "Manager", |r, z, c| method_exact(r, &mut z.manager, c)),
    ("r", "Reserve", |r, z, c| method_exact(r, &mut z.reserve, c)),
    ("f", "Freeze", |r, z, c| method_exact(r, &mut z.freeze, c)),
    ("c", "Clawback", |r, z, c| {
        method_exact(r, &mut z.clawback, c)
    }),
];

fn method_asset_params(r: &mut Rd<'_>, z: &mut AssetParams, ctx: &[String]) -> R<()> {
    de_struct(r, z, &[], ASSET_PARAMS).map_err(|e| wrap(e, ctx))
}

const APP_LOCAL_STATE: &[Field<AppLocalState>] = &[
    ("hsch", "Schema", |r, z, c| {
        inline_schema(r, &mut z.schema, c)
    }),
    ("tkv", "KeyValue", |r, z, c| {
        inline_key_value(r, &mut z.key_value, c)
    }),
];

fn method_app_local_state(r: &mut Rd<'_>, z: &mut AppLocalState, ctx: &[String]) -> R<()> {
    de_struct(r, z, &[], APP_LOCAL_STATE).map_err(|e| wrap(e, ctx))
}

const APP_PARAMS: &[Field<AppParams>] = &[
    ("approv", "ApprovalProgram", |r, z, c| {
        z.approval_program = bounded_bytes(r, c, BOUNDS.with(|b| b.app_program))?;
        Ok(())
    }),
    ("clearp", "ClearStateProgram", |r, z, c| {
        z.clear_state_program = bounded_bytes(r, c, BOUNDS.with(|b| b.app_program))?;
        Ok(())
    }),
    ("gs", "GlobalState", |r, z, c| {
        inline_key_value(r, &mut z.global_state, c)
    }),
    ("lsch", "LocalStateSchema", |r, z, c| {
        inline_schema(r, &mut z.local_state_schema, c)
    }),
    ("gsch", "GlobalStateSchema", |r, z, c| {
        inline_schema(r, &mut z.global_state_schema, c)
    }),
    ("epp", "ExtraProgramPages", |r, z, c| {
        z.extra_program_pages = leaf(r.uint(32), c)?;
        Ok(())
    }),
    ("v", "Version", |r, z, c| {
        z.version = leaf(r.u64(), c)?;
        Ok(())
    }),
    ("ss", "SizeSponsor", |r, z, c| {
        method_exact(r, &mut z.size_sponsor, c)
    }),
    ("fbr", "ForeignBoxReads", |r, z, c| {
        z.foreign_box_reads = leaf(r.bool(), c)?;
        Ok(())
    }),
    ("fba", "FamilyBoxAccess", |r, z, c| {
        z.family_box_access = leaf(r.bool(), c)?;
        Ok(())
    }),
];

fn method_app_params(r: &mut Rd<'_>, z: &mut AppParams, ctx: &[String]) -> R<()> {
    de_struct(r, z, &[], APP_PARAMS).map_err(|e| wrap(e, ctx))
}

/// A `uint64`-kind field (`Round`, `MicroAlgos`' `UnmarshalMsgWithState`
/// returns `ReadUint64Bytes`' error as is).
fn u64_field(r: &mut Rd<'_>, ctx: &[String]) -> R<u64> {
    leaf(r.u64(), ctx)
}

const ACCOUNT_DATA: &[Field<AccountData>] = &[
    ("onl", "Status", |r, z, c| {
        z.status = leaf(r.uint(8), c)?;
        Ok(())
    }),
    ("algo", "MicroAlgos", |r, z, c| {
        z.micro_algos = u64_field(r, c)?;
        Ok(())
    }),
    ("ebase", "RewardsBase", |r, z, c| {
        z.rewards_base = u64_field(r, c)?;
        Ok(())
    }),
    ("ern", "RewardedMicroAlgos", |r, z, c| {
        z.rewarded_micro_algos = u64_field(r, c)?;
        Ok(())
    }),
    ("vote", "VoteID", |r, z, c| {
        method_exact(r, &mut z.vote_id, c)
    }),
    ("sel", "SelectionID", |r, z, c| {
        method_exact(r, &mut z.selection_id, c)
    }),
    ("stprf", "StateProofID", |r, z, c| {
        method_exact(r, &mut z.state_proof_id, c)
    }),
    ("voteFst", "VoteFirstValid", |r, z, c| {
        z.vote_first_valid = u64_field(r, c)?;
        Ok(())
    }),
    ("voteLst", "VoteLastValid", |r, z, c| {
        z.vote_last_valid = u64_field(r, c)?;
        Ok(())
    }),
    ("voteKD", "VoteKeyDilution", |r, z, c| {
        z.vote_key_dilution = u64_field(r, c)?;
        Ok(())
    }),
    ("lpr", "LastProposed", |r, z, c| {
        z.last_proposed = u64_field(r, c)?;
        Ok(())
    }),
    ("lhb", "LastHeartbeat", |r, z, c| {
        z.last_heartbeat = u64_field(r, c)?;
        Ok(())
    }),
    ("apar", "AssetParams", |r, z, c| {
        de_map(
            r,
            &mut z.asset_params,
            c,
            ENCODED_MAX_ASSETS_PER_ACCOUNT,
            index_key,
            show_index,
            method_asset_params,
        )
    }),
    ("asset", "Assets", |r, z, c| {
        de_map(
            r,
            &mut z.assets,
            c,
            ENCODED_MAX_ASSETS_PER_ACCOUNT,
            index_key,
            show_index,
            inline_asset_holding,
        )
    }),
    ("spend", "AuthAddr", |r, z, c| {
        method_exact(r, &mut z.auth_addr, c)
    }),
    ("ie", "IncentiveEligible", |r, z, c| {
        z.incentive_eligible = leaf(r.bool(), c)?;
        Ok(())
    }),
    ("appl", "AppLocalStates", |r, z, c| {
        de_map(
            r,
            &mut z.app_local_states,
            c,
            ENCODED_MAX_APP_LOCAL_STATES,
            index_key,
            show_index,
            method_app_local_state,
        )
    }),
    ("appp", "AppParams", |r, z, c| {
        de_map(
            r,
            &mut z.app_params,
            c,
            ENCODED_MAX_APP_PARAMS,
            index_key,
            show_index,
            method_app_params,
        )
    }),
    ("tsch", "TotalAppSchema", |r, z, c| {
        inline_schema(r, &mut z.total_app_schema, c)
    }),
    ("teap", "TotalExtraAppPages", |r, z, c| {
        z.total_extra_app_pages = leaf(r.uint(32), c)?;
        Ok(())
    }),
    ("tbx", "TotalBoxes", |r, z, c| {
        z.total_boxes = leaf(r.u64(), c)?;
        Ok(())
    }),
    ("tbxb", "TotalBoxBytes", |r, z, c| {
        z.total_box_bytes = leaf(r.u64(), c)?;
        Ok(())
    }),
];

/// go: `protocol.Decode(resp, &basics.AccountData{})` (bytes after the
/// value are allowed), or msgp's error text.
fn decode_account_data(msgpack: &[u8]) -> Result<AccountData, String> {
    let mut z = AccountData::default();
    de_struct(&mut Rd(msgpack), &mut z, &[], ACCOUNT_DATA).map_err(|e| e.to_string())?;
    Ok(z)
}

// ---- the encoders ---------------------------------------------------------------

/// A field of an `omitempty` struct: its codec name and value, `None` when
/// empty (go-codec's `RecursiveEmptyCheck` / msgp's `MsgIsZero`).
type Out = (&'static str, Option<V>);

/// A value both encoders write.
enum V {
    Uint(u64),
    Bool(bool),
    /// A Go `string`.
    Str(Vec<u8>),
    /// A `[]byte` or `[N]byte`.
    Bytes(Vec<u8>),
    /// A `basics.Address` (`MarshalText` in JSON).
    Addr([u8; 32]),
    /// A struct: its non-empty fields, sorted by codec name.
    Struct(Vec<(&'static str, V)>),
    /// A map with integer keys, in key order.
    IntMap(Vec<(u64, V)>),
    /// A map with string keys, in key order.
    StrMap(Vec<(Vec<u8>, V)>),
}

fn uint(v: u64) -> Option<V> {
    (v != 0).then_some(V::Uint(v))
}

fn boolean(v: bool) -> Option<V> {
    v.then_some(V::Bool(true))
}

fn string(v: &[u8]) -> Option<V> {
    (!v.is_empty()).then(|| V::Str(v.to_vec()))
}

fn bytes(v: &[u8]) -> Option<V> {
    (!v.is_empty()).then(|| V::Bytes(v.to_vec()))
}

fn array(v: &[u8]) -> Option<V> {
    v.iter().any(|b| *b != 0).then(|| V::Bytes(v.to_vec()))
}

fn addr(v: &[u8; 32]) -> Option<V> {
    v.iter().any(|b| *b != 0).then_some(V::Addr(*v))
}

/// A struct with its empty fields left out, `None` when all are.
fn object(mut fields: Vec<Out>) -> Option<V> {
    fields.sort_by(|a, b| a.0.cmp(b.0));
    let kept: Vec<(&'static str, V)> = fields
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect();
    (!kept.is_empty()).then_some(V::Struct(kept))
}

/// A struct that is a map's value: written even when empty.
fn entry(v: Option<V>) -> V {
    v.unwrap_or(V::Struct(Vec::new()))
}

fn schema(s: &StateSchema) -> Option<V> {
    object(vec![
        ("nui", uint(s.num_uint)),
        ("nbs", uint(s.num_byte_slice)),
    ])
}

fn key_value(kv: &TealKeyValue) -> Option<V> {
    let m: Vec<(Vec<u8>, V)> = kv
        .iter()
        .map(|(k, t)| {
            let v = object(vec![
                ("tt", uint(t.typ)),
                ("tb", string(&t.bytes)),
                ("ui", uint(t.uint)),
            ]);
            (k.clone(), entry(v))
        })
        .collect();
    (!m.is_empty()).then_some(V::StrMap(m))
}

fn int_map<T>(m: &BTreeMap<u64, T>, f: impl Fn(&T) -> Option<V>) -> Option<V> {
    let m: Vec<(u64, V)> = m.iter().map(|(k, v)| (*k, entry(f(v)))).collect();
    (!m.is_empty()).then_some(V::IntMap(m))
}

/// The `basics.BalanceRecord` of `addr` and `ad`.
fn balance_record(addr_bytes: &[u8; 32], ad: &AccountData) -> V {
    let asset_params = |p: &AssetParams| {
        object(vec![
            ("t", uint(p.total)),
            ("dc", uint(p.decimals)),
            ("df", boolean(p.default_frozen)),
            ("un", string(&p.unit_name)),
            ("an", string(&p.asset_name)),
            ("au", string(&p.url)),
            ("am", array(&p.metadata_hash)),
            ("m", addr(&p.manager)),
            ("r", addr(&p.reserve)),
            ("f", addr(&p.freeze)),
            ("c", addr(&p.clawback)),
        ])
    };
    let holding = |h: &AssetHolding| object(vec![("a", uint(h.amount)), ("f", boolean(h.frozen))]);
    let local = |l: &AppLocalState| {
        object(vec![
            ("hsch", schema(&l.schema)),
            ("tkv", key_value(&l.key_value)),
        ])
    };
    let app = |p: &AppParams| {
        object(vec![
            ("approv", bytes(&p.approval_program)),
            ("clearp", bytes(&p.clear_state_program)),
            ("gs", key_value(&p.global_state)),
            ("lsch", schema(&p.local_state_schema)),
            ("gsch", schema(&p.global_state_schema)),
            ("epp", uint(p.extra_program_pages)),
            ("v", uint(p.version)),
            ("ss", addr(&p.size_sponsor)),
            ("fbr", boolean(p.foreign_box_reads)),
            ("fba", boolean(p.family_box_access)),
        ])
    };
    entry(object(vec![
        ("addr", addr(addr_bytes)),
        ("onl", uint(ad.status)),
        ("algo", uint(ad.micro_algos)),
        ("ebase", uint(ad.rewards_base)),
        ("ern", uint(ad.rewarded_micro_algos)),
        ("vote", array(&ad.vote_id)),
        ("sel", array(&ad.selection_id)),
        ("stprf", array(&ad.state_proof_id)),
        ("voteFst", uint(ad.vote_first_valid)),
        ("voteLst", uint(ad.vote_last_valid)),
        ("voteKD", uint(ad.vote_key_dilution)),
        ("lpr", uint(ad.last_proposed)),
        ("lhb", uint(ad.last_heartbeat)),
        ("apar", int_map(&ad.asset_params, asset_params)),
        ("asset", int_map(&ad.assets, holding)),
        ("spend", addr(&ad.auth_addr)),
        ("ie", boolean(ad.incentive_eligible)),
        ("appl", int_map(&ad.app_local_states, local)),
        ("appp", int_map(&ad.app_params, app)),
        ("tsch", schema(&ad.total_app_schema)),
        ("teap", uint(ad.total_extra_app_pages)),
        ("tbx", uint(ad.total_boxes)),
        ("tbxb", uint(ad.total_box_bytes)),
    ]))
}

/// go-codec's JSON shape of a value (`JSONStrictHandle`: integer map keys
/// as strings).
fn to_json(v: &V) -> Json {
    let s = |b: &[u8]| Json::Str(b.to_vec());
    match v {
        V::Uint(u) => Json::Uint(*u),
        V::Bool(b) => Json::Bool(*b),
        V::Str(b) => s(b),
        V::Bytes(b) => Json::Bytes(b.clone()),
        V::Addr(a) => s(algo_types::Address(*a).to_string().as_bytes()),
        V::Struct(f) => Json::Ordered(
            f.iter()
                .map(|(k, v)| (s(k.as_bytes()), to_json(v)))
                .collect(),
        ),
        V::IntMap(m) => Json::Ordered(
            m.iter()
                .map(|(k, v)| (s(k.to_string().as_bytes()), to_json(v)))
                .collect(),
        ),
        V::StrMap(m) => Json::Ordered(m.iter().map(|(k, v)| (s(k), to_json(v))).collect()),
    }
}

/// msgp's `Append*` encoding of a value.
fn to_msgpack(out: &mut Vec<u8>, v: &V) {
    fn uint(out: &mut Vec<u8>, u: u64) {
        match u {
            0..=0x7f => out.push(u as u8),
            0x80..=0xff => out.extend_from_slice(&[0xcc, u as u8]),
            0x100..=0xffff => {
                out.push(0xcd);
                out.extend_from_slice(&(u as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                out.push(0xce);
                out.extend_from_slice(&(u as u32).to_be_bytes());
            }
            _ => {
                out.push(0xcf);
                out.extend_from_slice(&u.to_be_bytes());
            }
        }
    }
    fn len(out: &mut Vec<u8>, n: usize, fix: (u8, usize), w8: Option<u8>, w16: u8, w32: u8) {
        if n < fix.1 {
            out.push(fix.0 | n as u8);
        } else if let Some(b) = w8.filter(|_| n <= 0xff) {
            out.extend_from_slice(&[b, n as u8]);
        } else if n <= 0xffff {
            out.push(w16);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            out.push(w32);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
    let str_head = |out: &mut Vec<u8>, n: usize| len(out, n, (0xa0, 32), Some(0xd9), 0xda, 0xdb);
    let bin_head = |out: &mut Vec<u8>, n: usize| len(out, n, (0xc4, 0), Some(0xc4), 0xc5, 0xc6);
    let map_head = |out: &mut Vec<u8>, n: usize| len(out, n, (0x80, 16), None, 0xde, 0xdf);
    match v {
        V::Uint(u) => uint(out, *u),
        V::Bool(b) => out.push(if *b { 0xc3 } else { 0xc2 }),
        V::Str(b) => {
            str_head(out, b.len());
            out.extend_from_slice(b);
        }
        V::Bytes(b) => {
            bin_head(out, b.len());
            out.extend_from_slice(b);
        }
        V::Addr(a) => {
            bin_head(out, a.len());
            out.extend_from_slice(a);
        }
        V::Struct(f) => {
            map_head(out, f.len());
            for (k, v) in f {
                str_head(out, k.len());
                out.extend_from_slice(k.as_bytes());
                to_msgpack(out, v);
            }
        }
        V::IntMap(m) => {
            map_head(out, m.len());
            for (k, v) in m {
                uint(out, *k);
                to_msgpack(out, v);
            }
        }
        V::StrMap(m) => {
            map_head(out, m.len());
            for (k, v) in m {
                str_head(out, k.len());
                out.extend_from_slice(k);
                to_msgpack(out, v);
            }
        }
    }
}

/// What `goal account dump` writes: the JSON (`EncodeJSONStrict`) or, for
/// `-o`, the msgpack (`Encode`) of the `BalanceRecord` of `addr` and the
/// algod answer `msgpack`, or go's decode error.
pub fn dump(addr: &[u8; 32], msgpack: &[u8], as_msgpack: bool) -> Result<Vec<u8>, String> {
    let ad = decode_account_data(msgpack)?;
    let br = balance_record(addr, &ad);
    if as_msgpack {
        let mut out = Vec::new();
        to_msgpack(&mut out, &br);
        return Ok(out);
    }
    Ok(encode_protocol_json(&to_json(&br)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(b: &[u8]) -> String {
        decode_account_data(b).err().unwrap_or_default()
    }

    #[test]
    fn decode_errors_read_like_msgp() {
        assert_eq!(err(b""), "msgp: too few bytes left to read object");
        assert_eq!(
            err(br#"{"a":1}"#),
            "msgp: attempted to decode type \"int\" with method for \"array\""
        );
        assert_eq!(
            err(&[0x81, 0xa3, b'f', b'o', b'o', 0x01]),
            "Unknown field: foo"
        );
        assert_eq!(
            err(&[0x91, 0xa1, b'x']),
            "msgp: attempted to decode type \"str\" with method for \"uint\" at struct-from-array/Status"
        );
        assert_eq!(err(&[0xc1]), "msgp: unrecognized type prefix 0xc1");
    }

    #[test]
    fn an_empty_record_is_its_address() {
        let a = [7u8; 32];
        let json = dump(&a, &[0x80], false).unwrap();
        assert_eq!(
            String::from_utf8(json).unwrap(),
            format!("{{\n  \"addr\": \"{}\"\n}}", algo_types::Address(a))
        );
        let mp = dump(&a, &[0x80], true).unwrap();
        assert_eq!(&mp[..7], &[0x81, 0xa4, b'a', b'd', b'd', b'r', 0xc4]);
    }
}
