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

use algo_error::{AlgoError, Result};
use algo_types::go_msgp::{
    EVAL_MAX_ARGS, MAX_LOGIC_SIG_ARG_SIZE, MAX_LOGIC_SIG_MAX_SIZE, MAX_MULTISIG,
    MAX_PQ_PUBLIC_KEY_SIZE, MAX_PQ_SIGNATURE_SIZE,
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

/// Decode `bytes` as go's `protocol.Decode(bytes, &lsig)` does.
pub fn decode_logicsig_go(bytes: &[u8]) -> Result<GoLogicSig> {
    let mut b = bytes;
    let mut z = LsigState::default();
    z.decode(&mut b).map_err(|e| AlgoError::Codec {
        source: e.into(),
        context: "failed to decode LogicSig like go's protocol.Decode".into(),
    })?;
    Ok(z.finish())
}

/// Decode `bytes` as go's `protocol.Decode(bytes, &msig)` does for a
/// `crypto.MultisigSig` (what `libgoal` runs on kmd's `multisig/sign` and
/// `multisig/signprogram` responses): the same generated decoder
/// [`decode_logicsig_go`] runs for `msig` / `lmsig`.
pub fn decode_multisig_go(bytes: &[u8]) -> Result<MultisigSig> {
    let mut b = bytes;
    let mut z = MsigState::default();
    z.decode(&mut b).map_err(|e| AlgoError::Codec {
        source: e.into(),
        context: "failed to decode MultisigSig like go's protocol.Decode".into(),
    })?;
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

type R<T> = std::result::Result<T, &'static str>;

const SHORT: &str = "msgp: too few bytes left to read object";
const BAD_TYPE: &str = "msgp: attempted to decode a value of the wrong type";

fn head(b: &[u8], n: usize) -> R<&[u8]> {
    b.get(..n).ok_or(SHORT)
}

fn be(b: &[u8], n: usize) -> R<usize> {
    let h = head(b, 1 + n)?;
    Ok(h[1..]
        .iter()
        .fold(0usize, |a, &x| (a << 8) | usize::from(x)))
}

/// `msgp.ReadUint64Bytes`: fixint, `nil` (0), uint8..uint64 and the
/// non-negative int8..int64.
fn read_u64(b: &mut &[u8]) -> R<u64> {
    let lead = *b.first().ok_or(SHORT)?;
    let (v, used) = match lead {
        0x00..=0x7f => (u64::from(lead), 1),
        0xc0 => (0, 1),
        0xcc => (u64::from(head(b, 2)?[1]), 2),
        0xcd => (be(b, 2)? as u64, 3),
        0xce => (be(b, 4)? as u64, 5),
        0xcf => (u64::from_be_bytes(head(b, 9)?[1..9].try_into().unwrap()), 9),
        0xd0 => {
            let v = head(b, 2)?[1] as i8;
            (
                u64::try_from(v).map_err(|_| "msgp: attempted to decode int < 0 as uint")?,
                2,
            )
        }
        0xd1 => {
            let v = i16::from_be_bytes(head(b, 3)?[1..3].try_into().unwrap());
            (
                u64::try_from(v).map_err(|_| "msgp: attempted to decode int < 0 as uint")?,
                3,
            )
        }
        0xd2 => {
            let v = i32::from_be_bytes(head(b, 5)?[1..5].try_into().unwrap());
            (
                u64::try_from(v).map_err(|_| "msgp: attempted to decode int < 0 as uint")?,
                5,
            )
        }
        0xd3 => {
            let v = i64::from_be_bytes(head(b, 9)?[1..9].try_into().unwrap());
            (
                u64::try_from(v).map_err(|_| "msgp: attempted to decode int < 0 as uint")?,
                9,
            )
        }
        _ => return Err(BAD_TYPE),
    };
    *b = &b[used..];
    Ok(v)
}

fn read_u8(b: &mut &[u8]) -> R<u8> {
    u8::try_from(read_u64(b)?).map_err(|_| "msgp: value too large for uint8")
}

/// `msgp.ReadMapHeaderBytes`. `Ok(None)` is go's `TypeError`, after which the
/// generated code tries the array header on the same bytes; any other failure
/// is final.
fn read_map_header(b: &mut &[u8]) -> R<Option<(usize, bool)>> {
    let lead = *b.first().ok_or(SHORT)?;
    let (n, nil, used) = match lead {
        0x80..=0x8f => (usize::from(lead & 0x0f), false, 1),
        0xc0 => (0, true, 1),
        0xde => (be(b, 2)?, false, 3),
        0xdf => (be(b, 4)?, false, 5),
        0xc1 => return Err("msgp: unrecognized type prefix"),
        _ => return Ok(None),
    };
    *b = &b[used..];
    Ok(Some((n, nil)))
}

/// `msgp.ReadArrayHeaderBytes` (`flattenMap` true) / `readArrayHeaderBytes`:
/// returns the size and whether it was `nil`.
fn read_array_header(b: &mut &[u8], flatten_map: bool) -> R<(usize, bool)> {
    let lead = *b.first().ok_or(SHORT)?;
    let (n, nil, used) = match lead {
        0x90..=0x9f => (usize::from(lead & 0x0f), false, 1),
        0x80..=0x8f if flatten_map => (2 * usize::from(lead & 0x0f), false, 1),
        0xc0 => (0, true, 1),
        0xdc => (be(b, 2)?, false, 3),
        0xdd => (be(b, 4)?, false, 5),
        0xde if flatten_map => (2 * be(b, 2)?, false, 3),
        0xdf if flatten_map => (2 * be(b, 4)?, false, 5),
        _ => return Err(BAD_TYPE),
    };
    *b = &b[used..];
    Ok((n, nil))
}

/// `msgp.ReadBytesBytesHeader`: the size a byte string claims, without
/// consuming it (the generated code bounds it before reading).
fn bytes_header_size(b: &[u8]) -> R<usize> {
    let lead = *b.first().ok_or(SHORT)?;
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
        return Err(SHORT);
    }
    (0..n).map(|_| read_u8(b)).collect()
}

/// `msgp.ReadBytesBytes`: the bytes and whether the value was `nil`.
fn read_bytes(b: &mut &[u8]) -> R<(Vec<u8>, bool)> {
    let lead = *b.first().ok_or(SHORT)?;
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
            return read_bytes_slow(b, true)
                .map(|v| (v, false))
                .map_err(|_| BAD_TYPE)
        }
    };
    let body = &b[skip..];
    if body.len() < len {
        return Err(SHORT);
    }
    let v = body[..len].to_vec();
    *b = &body[len..];
    Ok((v, false))
}

/// A byte string whose claimed size is first checked against `bound`.
fn read_bounded_bytes(b: &mut &[u8], bound: usize) -> R<(Vec<u8>, bool)> {
    if bytes_header_size(b)? > bound {
        return Err("msgp: length overflow");
    }
    read_bytes(b)
}

/// `msgp.ReadExactBytes`: fills `into` from the first `into.len()` bytes of any
/// encoded length, leaving the rest of `into` as it was; `nil` zeroes it.
fn read_exact(b: &mut &[u8], into: &mut [u8]) -> R<()> {
    let lead = *b.first().ok_or(SHORT)?;
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
            // readExactBytesSlow: an array of uint8, a map as an interleaved array.
            let (n, _) = read_array_header(b, true).map_err(|_| BAD_TYPE)?;
            if n > into.len() {
                return Err(BAD_TYPE);
            }
            for slot in into.iter_mut().take(n) {
                *slot = read_u8(b).map_err(|_| BAD_TYPE)?;
            }
            return Ok(());
        }
    };
    let body = &b[skip..];
    if body.len() < read {
        return Err(SHORT);
    }
    let n = read.min(into.len());
    into[..n].copy_from_slice(&body[..n]);
    *b = &body[read..];
    Ok(())
}

/// `msgp.ReadMapKeyZC`: `str`, `nil` (empty), `bin`, or an array of uint8.
fn read_map_key(b: &mut &[u8]) -> R<Vec<u8>> {
    let lead = *b.first().ok_or(SHORT)?;
    match lead {
        0x90..=0x9f | 0xdc | 0xdd => read_bytes_slow(b, false),
        0xa0..=0xbf | 0xc0 | 0xd9 | 0xda | 0xdb | 0xc4 | 0xc5 | 0xc6 => read_bytes(b).map(|r| r.0),
        _ => Err(BAD_TYPE),
    }
}

/// The fields of one generated decoder: a map (or `nil`) is a key loop, an array
/// is positional.
enum Form {
    /// Number of keys, and whether the header was `nil` (the struct is zeroed).
    Map(usize, bool),
    Array(usize),
}

/// Open a struct and report how it is laid out.
fn open_struct(b: &mut &[u8]) -> R<Form> {
    match read_map_header(b)? {
        Some((n, nil)) => Ok(Form::Map(n, nil)),
        None => read_array_header(b, true).map(|(n, _)| Form::Array(n)),
    }
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
                    match read_map_key(b)?.as_slice() {
                        b"pk" => read_exact(b, &mut self.key)?,
                        b"s" => read_exact(b, &mut self.sig)?,
                        _ => return Err("msgp: no matching struct field found"),
                    }
                }
            }
            Form::Array(mut n) => {
                if n > 0 {
                    n -= 1;
                    read_exact(b, &mut self.key)?;
                }
                if n > 0 {
                    n -= 1;
                    read_exact(b, &mut self.sig)?;
                }
                if n > 0 {
                    return Err("msgp: too many array fields");
                }
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
    fn decode_subsigs(&mut self, b: &mut &[u8]) -> R<()> {
        let (n, nil) = read_array_header(b, true)?;
        if n > MAX_MULTISIG {
            return Err("msgp: length overflow");
        }
        if nil {
            self.backing = None;
        } else if !self.backing.as_ref().is_some_and(|v| v.len() >= n) {
            self.backing = Some(vec![SubsigState::default(); n]);
        }
        self.len = n;
        if let Some(v) = self.backing.as_mut() {
            for s in v.iter_mut().take(n) {
                s.decode(b)?;
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
                    match read_map_key(b)?.as_slice() {
                        b"v" => self.version = read_u8(b)?,
                        b"thr" => self.threshold = read_u8(b)?,
                        b"subsig" => self.decode_subsigs(b)?,
                        _ => return Err("msgp: no matching struct field found"),
                    }
                }
            }
            Form::Array(mut n) => {
                if n > 0 {
                    n -= 1;
                    self.version = read_u8(b)?;
                }
                if n > 0 {
                    n -= 1;
                    self.threshold = read_u8(b)?;
                }
                if n > 0 {
                    n -= 1;
                    self.decode_subsigs(b)?;
                }
                if n > 0 {
                    return Err("msgp: too many array fields");
                }
            }
        }
        // `codec:",required"`: the zero value fails, whether or not the key was there.
        if self.version == 0 {
            return Err("missing required field: v");
        }
        if self.threshold == 0 {
            return Err("missing required field: thr");
        }
        if self.len == 0 {
            return Err("missing required field: subsig");
        }
        Ok(())
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
    fn decode(&mut self, b: &mut &[u8]) -> R<()> {
        match open_struct(b)? {
            Form::Map(n, nil) => {
                if nil {
                    *self = Self::default();
                }
                for _ in 0..n {
                    match read_map_key(b)?.as_slice() {
                        b"sch" => read_exact(b, &mut self.scheme)?,
                        b"slt" => self.salt = read_u8(b)?,
                        b"pk" => self.public_key = read_bounded_bytes(b, MAX_PQ_PUBLIC_KEY_SIZE)?.0,
                        b"sig" => self.signature = read_bounded_bytes(b, MAX_PQ_SIGNATURE_SIZE)?.0,
                        _ => return Err("msgp: no matching struct field found"),
                    }
                }
            }
            Form::Array(mut n) => {
                if n > 0 {
                    n -= 1;
                    read_exact(b, &mut self.scheme)?;
                }
                if n > 0 {
                    n -= 1;
                    self.salt = read_u8(b)?;
                }
                if n > 0 {
                    n -= 1;
                    self.public_key = read_bounded_bytes(b, MAX_PQ_PUBLIC_KEY_SIZE)?.0;
                }
                if n > 0 {
                    n -= 1;
                    self.signature = read_bounded_bytes(b, MAX_PQ_SIGNATURE_SIZE)?.0;
                }
                if n > 0 {
                    return Err("msgp: too many array fields");
                }
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
    fn decode_logic(&mut self, b: &mut &[u8]) -> R<()> {
        let (v, nil) = read_bounded_bytes(b, MAX_LOGIC_SIG_MAX_SIZE)?;
        self.logic = v;
        self.logic_nil = nil;
        Ok(())
    }

    fn decode_args(&mut self, b: &mut &[u8]) -> R<()> {
        let (n, _nil) = read_array_header(b, true)?;
        if n > EVAL_MAX_ARGS {
            return Err("msgp: length overflow");
        }
        let mut args = Vec::with_capacity(n);
        for _ in 0..n {
            let (v, nil) = read_bounded_bytes(b, MAX_LOGIC_SIG_ARG_SIZE)?;
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
                    match read_map_key(b)?.as_slice() {
                        b"l" => self.decode_logic(b)?,
                        b"sig" => read_exact(b, &mut self.sig)?,
                        b"msig" => self.msig.decode(b)?,
                        b"lmsig" => self.lmsig.decode(b)?,
                        b"pqsig" => self.pqsig.decode(b)?,
                        b"arg" => self.decode_args(b)?,
                        _ => return Err("msgp: no matching struct field found"),
                    }
                }
            }
            Form::Array(mut n) => {
                if n > 0 {
                    n -= 1;
                    self.decode_logic(b)?;
                }
                if n > 0 {
                    n -= 1;
                    read_exact(b, &mut self.sig)?;
                }
                if n > 0 {
                    n -= 1;
                    self.msig.decode(b)?;
                }
                if n > 0 {
                    n -= 1;
                    self.lmsig.decode(b)?;
                }
                if n > 0 {
                    n -= 1;
                    self.pqsig.decode(b)?;
                }
                if n > 0 {
                    n -= 1;
                    self.decode_args(b)?;
                }
                if n > 0 {
                    return Err("msgp: too many array fields");
                }
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
