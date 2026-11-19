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

//! A line-by-line port of what go-algorand's `protocol.Decode(bytes, &lsig)`
//! does for a `transactions.LogicSig` (issue #2390): the msgp-generated
//! `LogicSig.UnmarshalMsgWithState` (`data/transactions/msgp_gen.go`) with its
//! members `crypto.MultisigSig` / `MultisigSubsig` (`crypto/msgp_gen.go`) and
//! `transactions.PQSig`, on top of algorand/msgp's read primitives
//! (`msgp/read_bytes.go`).
//!
//! It exists for tools that must accept and reject exactly what go does
//! (`goal clerk compile -D` falls back to disassembling the raw bytes when this
//! decode fails). It is NOT used by the consensus path: that one has
//! hand-written readers (`algo_types::*::decode_from_reader`) with the registered
//! differences of `docs/DIVERGENCES.md` DIV-004. Both are compared on every
//! record of `tests/logicsig_go_decode_test.rs`.
//!
//! What the generated decoder really does, and this port keeps:
//!
//! * a struct is read from a map, from `nil` (the zero struct) or, when the lead
//!   byte is neither, from an array whose members follow the Go field order
//!   (`LogicSig`: `l`, `sig`, `msig`, `lmsig`, `pqsig`, `arg`); more array members
//!   than fields is an error;
//! * map keys are `str`, `bin`, `nil` (the empty key) or an array of uint8, and
//!   an unknown key is an error (`msgp.ErrNoField`);
//! * a repeated key decodes into the value already there: a nested struct is
//!   merged, a fixed-size byte array keeps the tail the shorter value did not
//!   cover, a re-sized `subsig` list keeps the elements its backing array held;
//! * a byte string is `bin`, `str`, `nil` or an array of uint8 (a map counts as
//!   an interleaved key/value array); a fixed-size array takes the first `N`
//!   bytes of any encoded length;
//! * an integer field is any msgpack int that is non-negative (`nil` is 0) and
//!   fits, a size above its `allocbound` is an error, and `MultisigSig` rejects
//!   the zero value of `v`, `thr` and `subsig` (`codec:",required"`);
//! * bytes after the value are ignored.
//!
//! A failure is go's error value, whose text ([`GoMsgpError::text`]) is what
//! `err.Error()` prints (issue #2404): msgp's error kinds
//! (`algorand/msgp/msgp/errors.go`) and the context path the generated code adds
//! with `msgp.WrapError` (`... at Subsigs/0 at Msig`,
//! `... at struct-from-array/Msig`).

use algo_types::go_msgp::{
    bounds, EVAL_MAX_ARGS, MAX_LOGIC_SIG_ARG_SIZE, MAX_MULTISIG, MAX_PQ_PUBLIC_KEY_SIZE,
    MAX_PQ_SIGNATURE_SIZE,
};
use algo_types::{LogicSig, MultisigSig, MultisigSubsig, PQAddressSalt, PQSig};
use serde_bytes::ByteBuf;

/// A `transactions.LogicSig` as go's generated decoder leaves it.
#[derive(Debug, Clone, PartialEq)]
pub struct GoLogicSig {
    /// `Logic` (`l`).
    pub logic: Vec<u8>,
    /// `Logic == nil` in go: no `l` (or a `nil` one) was decoded. go's
    /// `goal clerk sign`/`send` treat that as "no LogicSig"; an empty but
    /// non-nil `l` is a LogicSig with an empty program.
    pub logic_nil: bool,
    /// `Sig` (`sig`).
    pub sig: [u8; 64],
    /// `Msig` (`msig`); a zero value when the record has none.
    pub msig: MultisigSig,
    /// `LMsig` (`lmsig`).
    pub lmsig: MultisigSig,
    /// `PQsig` (`pqsig`); a zero value when the record has none.
    pub pqsig: PQSig,
    /// `Args` (`arg`); `None` is a `nil` element (go's JSON prints it as `null`).
    pub args: Vec<Option<Vec<u8>>>,
}

/// The error go's `protocol.Decode` returns for a record [`decode_logicsig_go`]
/// / [`decode_multisig_go`] reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoMsgpError(E);

impl GoMsgpError {
    /// go's `err.Error()`. A byte string, not UTF-8 text: an unknown map key is
    /// printed as the key's raw bytes (`msgp.ErrNoField(string(field))`).
    pub fn text(&self) -> Vec<u8> {
        self.0.text()
    }
}

impl std::fmt::Display for GoMsgpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.text()))
    }
}

impl std::error::Error for GoMsgpError {}

/// Decode `bytes` as go's `protocol.Decode(bytes, &lsig)` does.
pub fn decode_logicsig_go(bytes: &[u8]) -> Result<GoLogicSig, GoMsgpError> {
    let mut b = bytes;
    let mut z = LsigState::default();
    z.decode(&mut b).map_err(GoMsgpError)?;
    Ok(z.finish())
}

/// Decode `bytes` as go's `protocol.Decode(bytes, &msig)` does for a
/// `crypto.MultisigSig` (what `libgoal` runs on kmd's `multisig/sign` and
/// `multisig/signprogram` responses): the same generated decoder
/// [`decode_logicsig_go`] runs for `msig` / `lmsig`.
pub fn decode_multisig_go(bytes: &[u8]) -> Result<MultisigSig, GoMsgpError> {
    let mut b = bytes;
    let mut z = MsigState::default();
    z.decode(&mut b).map_err(GoMsgpError)?;
    Ok(z.finish())
}

impl GoLogicSig {
    /// The value goal's signing and sending code works with: members go holds
    /// blank (`Blank()`: no sig, no msig, no pqsig, no args) are absent, so
    /// re-encoding omits them like go's `omitempty`. A `nil` argument stays
    /// nil (go's `msgp.AppendBytes` encodes a nil `[]byte` as `nil`, an empty
    /// one as `bin` 0; issue #2430).
    pub fn into_logicsig(self) -> LogicSig {
        let msig = |m: MultisigSig| Some(m).filter(|m| !m.blank());
        let args = (!self.args.is_empty()).then(|| {
            self.args
                .into_iter()
                .map(|a| a.map(ByteBuf::from))
                .collect()
        });
        LogicSig {
            logic: ByteBuf::from(self.logic),
            sig: self.sig,
            msig: msig(self.msig),
            args,
            lmsig: msig(self.lmsig),
            pqsig: Some(self.pqsig).filter(|p| !p.blank()),
        }
    }
}

/// msgp's `Type` (`msgp/read.go`), as `sizes[lead].typ` (`msgp/elsize.go`)
/// reports it for a lead byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ty {
    Invalid,
    Str,
    Bin,
    Map,
    Array,
    Float64,
    Float32,
    Bool,
    Int,
    Uint,
    Nil,
    Ext,
}

impl Ty {
    fn of(lead: u8) -> Self {
        match lead {
            0x00..=0x7f | 0xd0..=0xd3 | 0xe0..=0xff => Ty::Int,
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

    /// `Type.String()`.
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

/// The error values of `msgp/errors.go` the decoders here can return, plus the
/// generated code's `errors.New("missing required field: ...")`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum E {
    /// `ErrShortBytes`: never given a context.
    Short,
    /// `TypeError`: a context error, `withContext` prepends.
    Type {
        method: Ty,
        encoded: Ty,
        ctx: String,
    },
    /// `UintOverflow`: a context error, `withContext` prepends.
    UintOverflow { value: u64, bits: u8, ctx: String },
    /// `UintBelowZero`: a context error whose `withContext` *replaces* the context.
    UintBelowZero { value: i64, ctx: String },
    /// `InvalidPrefixError`.
    InvalidPrefix(u8),
    /// `ErrOverflow` (`errOverflow`).
    Overflow { l: u64, bound: u64 },
    /// `ErrNoField`: the raw key bytes.
    NoField(Vec<u8>),
    /// `ErrTooManyArrayFields`.
    TooManyArrayFields(usize),
    /// `errors.New("missing required field: <key>")`.
    Required(&'static str),
    /// `errWrapped`: any other error after `WrapError`; wrapping it again wraps
    /// the whole text (`... at Subsigs/0 at Msig`).
    Wrapped { cause: Vec<u8>, ctx: String },
}

/// msgp's `addCtx`.
fn add_ctx(ctx: &str, add: &str) -> String {
    if ctx.is_empty() {
        add.to_string()
    } else {
        format!("{add}/{ctx}")
    }
}

/// `" at <ctx>"` unless the context is empty.
fn at(mut s: String, ctx: &str) -> String {
    if !ctx.is_empty() {
        s.push_str(" at ");
        s.push_str(ctx);
    }
    s
}

impl E {
    /// `msgp.WrapError(err, ctx...)`, with the `ctx` members already joined by `/`.
    fn wrap(self, ctx: &str) -> E {
        match self {
            E::Short => E::Short,
            E::Type {
                method,
                encoded,
                ctx: old,
            } => E::Type {
                method,
                encoded,
                ctx: add_ctx(&old, ctx),
            },
            E::UintOverflow {
                value,
                bits,
                ctx: old,
            } => E::UintOverflow {
                value,
                bits,
                ctx: add_ctx(&old, ctx),
            },
            E::UintBelowZero { value, .. } => E::UintBelowZero {
                value,
                ctx: ctx.to_string(),
            },
            other => E::Wrapped {
                cause: other.text(),
                ctx: ctx.to_string(),
            },
        }
    }

    /// `err.Error()`.
    fn text(&self) -> Vec<u8> {
        match self {
            E::Short => b"msgp: too few bytes left to read object".to_vec(),
            E::Type {
                method,
                encoded,
                ctx,
            } => at(
                format!(
                    "msgp: attempted to decode type \"{}\" with method for \"{}\"",
                    encoded.name(),
                    method.name()
                ),
                ctx,
            )
            .into_bytes(),
            E::UintOverflow { value, bits, ctx } => {
                at(format!("msgp: {value} overflows uint{bits}"), ctx).into_bytes()
            }
            E::UintBelowZero { value, ctx } => at(
                format!("msgp: attempted to cast int {value} to unsigned"),
                ctx,
            )
            .into_bytes(),
            E::InvalidPrefix(lead) => {
                format!("msgp: unrecognized type prefix 0x{lead:x}").into_bytes()
            }
            E::Overflow { l, bound } => {
                format!("msgp: length overflow: {l} > {bound}").into_bytes()
            }
            E::NoField(key) => {
                let mut v = b"Unknown field: ".to_vec();
                v.extend_from_slice(key);
                v
            }
            E::TooManyArrayFields(n) => {
                format!("Too many array fields when decoding into struct: {n} left").into_bytes()
            }
            E::Required(text) => text.as_bytes().to_vec(),
            E::Wrapped { cause, ctx } => {
                let mut v = cause.clone();
                if !ctx.is_empty() {
                    v.extend_from_slice(b" at ");
                    v.extend_from_slice(ctx.as_bytes());
                }
                v
            }
        }
    }
}

type R<T> = std::result::Result<T, E>;

/// `msgp.WrapError` applied to a result.
fn w<T>(r: R<T>, ctx: &str) -> R<T> {
    r.map_err(|e| e.wrap(ctx))
}

/// `badPrefix`: an unknown lead byte is an `InvalidPrefixError`, any other a
/// `TypeError`.
fn bad_prefix(want: Ty, lead: u8) -> E {
    match Ty::of(lead) {
        Ty::Invalid => E::InvalidPrefix(lead),
        encoded => E::Type {
            method: want,
            encoded,
            ctx: String::new(),
        },
    }
}

fn overflow(l: usize, bound: usize) -> E {
    E::Overflow {
        l: l as u64,
        bound: bound as u64,
    }
}

fn head(b: &[u8], n: usize) -> R<&[u8]> {
    b.get(..n).ok_or(E::Short)
}

fn be(b: &[u8], n: usize) -> R<usize> {
    let h = head(b, 1 + n)?;
    Ok(h[1..]
        .iter()
        .fold(0usize, |a, &x| (a << 8) | usize::from(x)))
}

fn lead(b: &[u8]) -> R<u8> {
    b.first().copied().ok_or(E::Short)
}

fn below_zero(v: i64) -> R<u64> {
    u64::try_from(v).map_err(|_| E::UintBelowZero {
        value: v,
        ctx: String::new(),
    })
}

/// `msgp.ReadUint64Bytes`: fixint, `nil` (0), uint8..uint64 and the
/// non-negative int8..int64.
fn read_u64(b: &mut &[u8]) -> R<u64> {
    let lead = lead(b)?;
    let (v, used) = match lead {
        0x00..=0x7f => (u64::from(lead), 1),
        0xc0 => (0, 1),
        0xcc => (u64::from(head(b, 2)?[1]), 2),
        0xcd => (be(b, 2)? as u64, 3),
        0xce => (be(b, 4)? as u64, 5),
        0xcf => (u64::from_be_bytes(head(b, 9)?[1..9].try_into().unwrap()), 9),
        0xd0 => (below_zero(i64::from(head(b, 2)?[1] as i8))?, 2),
        0xd1 => (
            below_zero(i64::from(i16::from_be_bytes(
                head(b, 3)?[1..3].try_into().unwrap(),
            )))?,
            3,
        ),
        0xd2 => (
            below_zero(i64::from(i32::from_be_bytes(
                head(b, 5)?[1..5].try_into().unwrap(),
            )))?,
            5,
        ),
        0xd3 => (
            below_zero(i64::from_be_bytes(head(b, 9)?[1..9].try_into().unwrap()))?,
            9,
        ),
        0xe0..=0xff => {
            return Err(E::UintBelowZero {
                value: i64::from(lead as i8),
                ctx: String::new(),
            })
        }
        _ => return Err(bad_prefix(Ty::Uint, lead)),
    };
    *b = &b[used..];
    Ok(v)
}

/// `msgp.ReadUint8Bytes`.
fn read_u8(b: &mut &[u8]) -> R<u8> {
    let v = read_u64(b)?;
    u8::try_from(v).map_err(|_| E::UintOverflow {
        value: v,
        bits: 8,
        ctx: String::new(),
    })
}

/// `msgp.ReadMapHeaderBytes`. `Ok(None)` is go's `TypeError`, after which the
/// generated code tries the array header on the same bytes; any other failure
/// is final.
fn read_map_header(b: &mut &[u8]) -> R<Option<(usize, bool)>> {
    let lead = lead(b)?;
    let (n, nil, used) = match lead {
        0x80..=0x8f => (usize::from(lead & 0x0f), false, 1),
        0xc0 => (0, true, 1),
        0xde => (be(b, 2)?, false, 3),
        0xdf => (be(b, 4)?, false, 5),
        _ => {
            return match bad_prefix(Ty::Map, lead) {
                E::Type { .. } => Ok(None),
                e => Err(e),
            }
        }
    };
    *b = &b[used..];
    Ok(Some((n, nil)))
}

/// `msgp.ReadArrayHeaderBytes` (`flattenMap` true) / `readArrayHeaderBytes`:
/// returns the size and whether it was `nil`.
fn read_array_header(b: &mut &[u8], flatten_map: bool) -> R<(usize, bool)> {
    let lead = lead(b)?;
    let (n, nil, used) = match lead {
        0x90..=0x9f => (usize::from(lead & 0x0f), false, 1),
        0x80..=0x8f if flatten_map => (2 * usize::from(lead & 0x0f), false, 1),
        0xc0 => (0, true, 1),
        0xdc => (be(b, 2)?, false, 3),
        0xdd => (be(b, 4)?, false, 5),
        0xde if flatten_map => (2 * be(b, 2)?, false, 3),
        0xdf if flatten_map => (2 * be(b, 4)?, false, 5),
        _ => return Err(bad_prefix(Ty::Array, lead)),
    };
    *b = &b[used..];
    Ok((n, nil))
}

/// `msgp.ReadBytesBytesHeader`: the size a byte string claims, without
/// consuming it (the generated code bounds it before reading).
fn bytes_header_size(b: &[u8]) -> R<usize> {
    let lead = lead(b)?;
    match lead {
        0xa0..=0xbf => Ok(usize::from(lead & 0x1f)),
        0xc0 => Ok(0),
        0xd9 | 0xc4 => be(b, 1),
        0xda | 0xc5 => be(b, 2),
        0xdb | 0xc6 => be(b, 4),
        _ => {
            let mut c = b;
            read_array_header(&mut c, true).map(|(n, _)| n)
        }
    }
}

/// `readBytesBytesSlow`: an array of uint8 (or, `flatten_map`, a map as an
/// interleaved array).
fn read_bytes_slow(b: &mut &[u8], flatten_map: bool) -> R<Vec<u8>> {
    let (n, _) = read_array_header(b, flatten_map)?;
    if b.len() < n {
        return Err(E::Short);
    }
    (0..n).map(|_| read_u8(b)).collect()
}

/// `readBytesBytes`: the bytes and whether the value was `nil`.
fn read_bytes_flat(b: &mut &[u8], flatten_map: bool) -> R<(Vec<u8>, bool)> {
    let lead = lead(b)?;
    let (skip, len) = match lead {
        0xa0..=0xbf => (1, usize::from(lead & 0x1f)),
        0xc0 => {
            *b = &b[1..];
            return Ok((Vec::new(), true));
        }
        0xd9 | 0xc4 => (2, be(b, 1)?),
        0xda | 0xc5 => (3, be(b, 2)?),
        0xdb | 0xc6 => (5, be(b, 4)?),
        _ => {
            return read_bytes_slow(b, flatten_map)
                .map(|v| (v, false))
                .map_err(|_| bad_prefix(Ty::Bin, lead))
        }
    };
    let body = &b[skip..];
    if body.len() < len {
        return Err(E::Short);
    }
    let v = body[..len].to_vec();
    *b = &body[len..];
    Ok((v, false))
}

/// `msgp.ReadBytesBytes` / `ReadBytesZC`.
fn read_bytes(b: &mut &[u8]) -> R<(Vec<u8>, bool)> {
    read_bytes_flat(b, true)
}

/// A byte string whose claimed size is first checked against `bound`, as the
/// generated code does: the header and the read are wrapped with `ctx`, the
/// overflow is not.
fn read_bounded_bytes(b: &mut &[u8], bound: usize, ctx: &str) -> R<(Vec<u8>, bool)> {
    let n = w(bytes_header_size(b), ctx)?;
    if n > bound {
        return Err(overflow(n, bound));
    }
    w(read_bytes(b), ctx)
}

/// `msgp.ReadExactBytes`: fills `into` from the first `into.len()` bytes of any
/// encoded length, leaving the rest of `into` as it was; `nil` zeroes it.
fn read_exact(b: &mut &[u8], into: &mut [u8]) -> R<()> {
    let lead = lead(b)?;
    let (skip, read) = match lead {
        0xa0..=0xbf => (1, usize::from(lead & 0x1f)),
        0xc0 => {
            into.fill(0);
            *b = &b[1..];
            return Ok(());
        }
        0xd9 | 0xc4 => (2, be(b, 1)?),
        0xda | 0xc5 => (3, be(b, 2)?),
        0xdb | 0xc6 => (5, be(b, 4)?),
        _ => {
            // readExactBytesSlow: an array of uint8, a map as an interleaved
            // array; any failure is reported as `badPrefix(BinType, lead)`.
            let slow = |b: &mut &[u8], into: &mut [u8]| -> R<()> {
                let (n, _) = read_array_header(b, true)?;
                if n > into.len() {
                    // `ArrayError`, replaced below.
                    return Err(E::Short);
                }
                for slot in into.iter_mut().take(n) {
                    *slot = read_u8(b)?;
                }
                Ok(())
            };
            return slow(b, into).map_err(|_| bad_prefix(Ty::Bin, lead));
        }
    };
    let body = &b[skip..];
    if body.len() < read {
        return Err(E::Short);
    }
    let n = read.min(into.len());
    into[..n].copy_from_slice(&body[..n]);
    *b = &body[read..];
    Ok(())
}

/// `msgp.ReadStringZC`.
fn read_string(b: &mut &[u8]) -> R<Vec<u8>> {
    let lead = lead(b)?;
    let (skip, len) = match lead {
        0xa0..=0xbf => (1, usize::from(lead & 0x1f)),
        0xc0 => (1, 0),
        0xd9 => (2, be(b, 1)?),
        0xda => (3, be(b, 2)?),
        0xdb => (5, be(b, 4)?),
        _ => {
            // go-codec compat: a bin (or an array of uint8) as a string.
            return read_bytes_flat(b, false).map(|r| r.0).map_err(|_| E::Type {
                method: Ty::Str,
                encoded: Ty::of(lead),
                ctx: String::new(),
            });
        }
    };
    let body = &b[skip..];
    if body.len() < len {
        return Err(E::Short);
    }
    let v = body[..len].to_vec();
    *b = &body[len..];
    Ok(v)
}

/// `msgp.ReadMapKeyZC`: `str`, `nil` (empty), `bin`, or an array of uint8.
fn read_map_key(b: &mut &[u8]) -> R<Vec<u8>> {
    match read_string(b) {
        Err(E::Type {
            encoded: Ty::Bin, ..
        }) => read_bytes(b).map(|r| r.0),
        r => r,
    }
}

/// The fields of one generated decoder: a map (or `nil`) is a key loop, an array
/// is positional.
enum Form {
    /// Number of keys, and whether the header was `nil` (the struct is zeroed).
    Map(usize, bool),
    Array(usize),
}

/// Open a struct and report how it is laid out; a failure is wrapped with an
/// empty context, as the generated code does.
fn open_struct(b: &mut &[u8]) -> R<Form> {
    let form = match read_map_header(b) {
        Ok(Some((n, nil))) => Ok(Form::Map(n, nil)),
        Ok(None) => read_array_header(b, true).map(|(n, _)| Form::Array(n)),
        Err(e) => Err(e),
    };
    w(form, "")
}

/// An unknown map key: `msgp.WrapError(msgp.ErrNoField(string(field)))`.
fn no_field<T>(key: Vec<u8>) -> R<T> {
    Err(E::NoField(key).wrap(""))
}

/// The context of an array-form field: `"struct-from-array", <field>`.
fn sfa(field: &str) -> String {
    format!("struct-from-array/{field}")
}

/// The array-form `ErrTooManyArrayFields` check.
fn too_many(n: usize) -> R<()> {
    if n > 0 {
        return Err(E::TooManyArrayFields(n).wrap("struct-from-array"));
    }
    Ok(())
}

#[derive(Clone)]
struct SubsigState {
    key: [u8; 32],
    sig: [u8; 64],
}

impl Default for SubsigState {
    fn default() -> Self {
        Self {
            key: [0; 32],
            sig: [0; 64],
        }
    }
}

impl SubsigState {
    fn decode(&mut self, b: &mut &[u8]) -> R<()> {
        match open_struct(b)? {
            Form::Map(n, nil) => {
                if nil {
                    *self = Self::default();
                }
                for _ in 0..n {
                    match w(read_map_key(b), "")?.as_slice() {
                        b"pk" => w(read_exact(b, &mut self.key), "Key")?,
                        b"s" => w(read_exact(b, &mut self.sig), "Sig")?,
                        other => return no_field(other.to_vec()),
                    }
                }
            }
            Form::Array(mut n) => {
                if n > 0 {
                    n -= 1;
                    w(read_exact(b, &mut self.key), &sfa("Key"))?;
                }
                if n > 0 {
                    n -= 1;
                    w(read_exact(b, &mut self.sig), &sfa("Sig"))?;
                }
                too_many(n)?;
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct MsigState {
    version: u8,
    threshold: u8,
    /// `Subsigs`' backing array (`None` is a nil slice) and its length.
    backing: Option<Vec<SubsigState>>,
    len: usize,
}

impl MsigState {
    /// The `Subsigs` member; `ctx` is its context (`Subsigs` or
    /// `struct-from-array/Subsigs`).
    fn decode_subsigs(&mut self, b: &mut &[u8], ctx: &str) -> R<()> {
        let (n, nil) = w(read_array_header(b, true), ctx)?;
        if n > MAX_MULTISIG {
            return Err(overflow(n, MAX_MULTISIG).wrap(ctx));
        }
        if nil {
            self.backing = None;
        } else if !self.backing.as_ref().is_some_and(|v| v.len() >= n) {
            self.backing = Some(vec![SubsigState::default(); n]);
        }
        self.len = n;
        if let Some(v) = self.backing.as_mut() {
            for (i, s) in v.iter_mut().take(n).enumerate() {
                w(s.decode(b), &format!("{ctx}/{i}"))?;
            }
        }
        Ok(())
    }

    fn decode(&mut self, b: &mut &[u8]) -> R<()> {
        match open_struct(b)? {
            Form::Map(n, nil) => {
                if nil {
                    *self = Self::default();
                }
                for _ in 0..n {
                    match w(read_map_key(b), "")?.as_slice() {
                        b"v" => self.version = w(read_u8(b), "Version")?,
                        b"thr" => self.threshold = w(read_u8(b), "Threshold")?,
                        b"subsig" => self.decode_subsigs(b, "Subsigs")?,
                        other => return no_field(other.to_vec()),
                    }
                }
            }
            Form::Array(mut n) => {
                if n > 0 {
                    n -= 1;
                    self.version = w(read_u8(b), &sfa("Version"))?;
                }
                if n > 0 {
                    n -= 1;
                    self.threshold = w(read_u8(b), &sfa("Threshold"))?;
                }
                if n > 0 {
                    n -= 1;
                    self.decode_subsigs(b, &sfa("Subsigs"))?;
                }
                too_many(n)?;
            }
        }
        // `codec:",required"`: the zero value fails, whether or not the key was there.
        let missing = if self.version == 0 {
            Some("missing required field: v")
        } else if self.threshold == 0 {
            Some("missing required field: thr")
        } else if self.len == 0 {
            Some("missing required field: subsig")
        } else {
            None
        };
        match missing {
            Some(text) => Err(E::Required(text).wrap("")),
            None => Ok(()),
        }
    }

    fn finish(self) -> MultisigSig {
        let subsigs = self
            .backing
            .map(|v| {
                v.into_iter()
                    .take(self.len)
                    .map(|s| MultisigSubsig {
                        public_key: s.key,
                        signature: s.sig,
                    })
                    .collect()
            })
            .unwrap_or_default();
        MultisigSig {
            version: self.version,
            threshold: self.threshold,
            subsigs,
        }
    }
}

#[derive(Default)]
struct PqState {
    scheme: [u8; 2],
    salt: u8,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

impl PqState {
    /// `PQScheme.UnmarshalMsg` / `PQAddressSalt.UnmarshalMsg` wrap their own
    /// failure with an empty context before the field context is added.
    fn decode(&mut self, b: &mut &[u8]) -> R<()> {
        let scheme =
            |b: &mut &[u8], into: &mut [u8; 2], ctx: &str| w(w(read_exact(b, into), ""), ctx);
        let salt = |b: &mut &[u8], ctx: &str| w(w(read_u8(b), ""), ctx);
        match open_struct(b)? {
            Form::Map(n, nil) => {
                if nil {
                    *self = Self::default();
                }
                for _ in 0..n {
                    match w(read_map_key(b), "")?.as_slice() {
                        b"sch" => scheme(b, &mut self.scheme, "Scheme")?,
                        b"slt" => self.salt = salt(b, "Salt")?,
                        b"pk" => {
                            self.public_key =
                                read_bounded_bytes(b, MAX_PQ_PUBLIC_KEY_SIZE, "PublicKey")?.0
                        }
                        b"sig" => {
                            self.signature =
                                read_bounded_bytes(b, MAX_PQ_SIGNATURE_SIZE, "Signature")?.0
                        }
                        other => return no_field(other.to_vec()),
                    }
                }
            }
            Form::Array(mut n) => {
                if n > 0 {
                    n -= 1;
                    scheme(b, &mut self.scheme, &sfa("Scheme"))?;
                }
                if n > 0 {
                    n -= 1;
                    self.salt = salt(b, &sfa("Salt"))?;
                }
                if n > 0 {
                    n -= 1;
                    self.public_key =
                        read_bounded_bytes(b, MAX_PQ_PUBLIC_KEY_SIZE, &sfa("PublicKey"))?.0;
                }
                if n > 0 {
                    n -= 1;
                    self.signature =
                        read_bounded_bytes(b, MAX_PQ_SIGNATURE_SIZE, &sfa("Signature"))?.0;
                }
                too_many(n)?;
            }
        }
        Ok(())
    }

    fn finish(self) -> PQSig {
        PQSig {
            scheme: self.scheme,
            salt: PQAddressSalt(self.salt),
            public_key: ByteBuf::from(self.public_key),
            signature: ByteBuf::from(self.signature),
        }
    }
}

struct LsigState {
    logic: Vec<u8>,
    logic_nil: bool,
    sig: [u8; 64],
    msig: MsigState,
    lmsig: MsigState,
    pqsig: PqState,
    args: Vec<Option<Vec<u8>>>,
}

impl Default for LsigState {
    fn default() -> Self {
        Self {
            logic: Vec::new(),
            logic_nil: true,
            sig: [0; 64],
            msig: MsigState::default(),
            lmsig: MsigState::default(),
            pqsig: PqState::default(),
            args: Vec::new(),
        }
    }
}

impl LsigState {
    fn decode_logic(&mut self, b: &mut &[u8], ctx: &str) -> R<()> {
        let (v, nil) = read_bounded_bytes(b, bounds::MAX_LOGIC_SIG_MAX_SIZE.get(), ctx)?;
        self.logic = v;
        self.logic_nil = nil;
        Ok(())
    }

    /// `crypto.Signature.UnmarshalMsg`: `msgp.WrapError(err)`, then the field
    /// context.
    fn decode_sig(&mut self, b: &mut &[u8], ctx: &str) -> R<()> {
        w(w(read_exact(b, &mut self.sig), ""), ctx)
    }

    fn decode_args(&mut self, b: &mut &[u8], ctx: &str) -> R<()> {
        let (n, _nil) = w(read_array_header(b, true), ctx)?;
        if n > EVAL_MAX_ARGS {
            return Err(overflow(n, EVAL_MAX_ARGS).wrap(ctx));
        }
        let mut args = Vec::with_capacity(n);
        for i in 0..n {
            let (v, nil) = read_bounded_bytes(b, MAX_LOGIC_SIG_ARG_SIZE, &format!("{ctx}/{i}"))?;
            args.push((!nil).then_some(v));
        }
        self.args = args;
        Ok(())
    }

    fn decode(&mut self, b: &mut &[u8]) -> R<()> {
        match open_struct(b)? {
            Form::Map(n, nil) => {
                if nil {
                    *self = Self::default();
                }
                for _ in 0..n {
                    match w(read_map_key(b), "")?.as_slice() {
                        b"l" => self.decode_logic(b, "Logic")?,
                        b"sig" => self.decode_sig(b, "Sig")?,
                        b"msig" => w(self.msig.decode(b), "Msig")?,
                        b"lmsig" => w(self.lmsig.decode(b), "LMsig")?,
                        b"pqsig" => w(self.pqsig.decode(b), "PQsig")?,
                        b"arg" => self.decode_args(b, "Args")?,
                        other => return no_field(other.to_vec()),
                    }
                }
            }
            Form::Array(mut n) => {
                if n > 0 {
                    n -= 1;
                    self.decode_logic(b, &sfa("Logic"))?;
                }
                if n > 0 {
                    n -= 1;
                    self.decode_sig(b, &sfa("Sig"))?;
                }
                if n > 0 {
                    n -= 1;
                    w(self.msig.decode(b), &sfa("Msig"))?;
                }
                if n > 0 {
                    n -= 1;
                    w(self.lmsig.decode(b), &sfa("LMsig"))?;
                }
                if n > 0 {
                    n -= 1;
                    w(self.pqsig.decode(b), &sfa("PQsig"))?;
                }
                if n > 0 {
                    n -= 1;
                    self.decode_args(b, &sfa("Args"))?;
                }
                too_many(n)?;
            }
        }
        Ok(())
    }

    fn finish(self) -> GoLogicSig {
        GoLogicSig {
            logic: self.logic,
            logic_nil: self.logic_nil,
            sig: self.sig,
            msig: self.msig.finish(),
            lmsig: self.lmsig.finish(),
            pqsig: self.pqsig.finish(),
            args: self.args,
        }
    }
}
