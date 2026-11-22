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

//! The values algod-rust keeps as opaque `rmpv::Value`s, decoded the way go
//! decodes them (issue #2424).
//!
//! A transaction's `dt` (`transactions.EvalDelta`) and a header's `spt`
//! (`map[protocol.StateProofType]bookkeeping.StateProofTrackingData`) are
//! carried as `rmpv::Value`s and written back verbatim into the payset
//! commitment and the block hash. go decodes them with its generated msgp
//! decoders (unknown key: `msgp.ErrNoField`; a repeated key decodes INTO the
//! populated field; allocation bounds) and re-encodes what it decoded, so a
//! non-canonical encoding (a repeated key, unsorted keys, a zero field, a
//! short `[N]byte`, a non-minimal integer) never survives into a hash.
//!
//! The readers below decode into a typed mirror of go's struct with go's
//! semantics and keep go's canonical re-encode of it as the `rmpv::Value`
//! (inner transactions are re-encoded with [`crate::canonical`]). A value
//! decoded into again (a repeated `dt` / `spt` key) is first read back from
//! that canonical form, which is exactly go's value unless a repeated key
//! shrank one of its slices: go keeps the hidden elements in the slice's
//! capacity, so such a value is also kept typed, for the rest of the
//! [`DecodeSession`](crate::rmp_decode::DecodeSession).

use std::cell::RefCell;
use std::collections::BTreeMap;

use algo_error::{AlgoError, Result};

use crate::rmp_decode::{
    self, bounds, read_bytes_go_compat, read_fixed_bytes_into_go_compat, read_slice_into, read_u64,
    unknown_key,
};
use crate::{Address, SignedTransaction};

/// `protocol.NumStateProofTypes`.
const NUM_STATE_PROOF_TYPES: usize = 1;
/// `crypto.MaxHashDigestSize` (`SumhashDigestSize`).
const MAX_HASH_DIGEST_SIZE: usize = 64;

fn codec_err(msg: impl Into<String>) -> AlgoError {
    AlgoError::Codec {
        source: msg.into().into(),
        context: "go_eval_delta".into(),
    }
}

fn overflow(what: &str, n: usize, bound: usize) -> AlgoError {
    codec_err(format!(
        "{what}: {n} entries exceed the allocation bound {bound}"
    ))
}

/// A `nil`-aware map header (`msgp.ReadMapHeaderBytes`): `(entries, is_nil)`.
fn read_map_header(rd: &mut &[u8]) -> Result<(usize, bool)> {
    if rmp_decode::try_read_nil(rd) {
        return Ok((0, true));
    }
    rmp_decode::read_map_len(rd).map(|n| (n as usize, false))
}

/// A go `string` (`msgp.ReadStringBytes`): arbitrary bytes, `nil` is "".
fn read_go_string(rd: &mut &[u8]) -> Result<Vec<u8>> {
    rmp_decode::read_str_bytes(rd)
}

/// A go `string` / `[]byte` with an `allocbound`, checked before reading.
fn read_bounded_string(rd: &mut &[u8], bound: usize) -> Result<Vec<u8>> {
    rmp_decode::check_go_bytes_bound(rd, bound)?;
    read_go_string(rd)
}

// ── msgpack writers (go's `msgp.Append*`) ─────────────────────────────────

fn write_map_len(out: &mut Vec<u8>, n: usize) {
    rmp::encode::write_map_len(out, n as u32).expect("Vec write is infallible");
}

fn write_array_len(out: &mut Vec<u8>, n: usize) {
    rmp::encode::write_array_len(out, n as u32).expect("Vec write is infallible");
}

fn write_str(out: &mut Vec<u8>, b: &[u8]) {
    crate::canonical::write_str_marker_and_bytes(out, b);
}

fn write_bin(out: &mut Vec<u8>, b: &[u8]) {
    rmp::encode::write_bin(out, b).expect("Vec write is infallible");
}

fn write_key(out: &mut Vec<u8>, k: &str) {
    write_str(out, k.as_bytes());
}

// ── basics.ValueDelta / basics.StateDelta ──────────────────────────────────

/// `basics.ValueDelta`.
#[derive(Debug, Default, Clone, PartialEq)]
struct ValueDelta {
    action: u64,
    bytes: Vec<u8>,
    uint: u64,
}

impl ValueDelta {
    fn decode_into(rd: &mut &[u8], v: &mut Self) -> Result<()> {
        let mut keys = rmp_decode::struct_keys(rd, v, "basics.ValueDelta")?;
        while let Some(key) = keys.next(rd)? {
            match key {
                b"at" => v.action = read_u64(rd)?,
                b"bs" => v.bytes = read_bounded_string(rd, bounds::MAX_APP_BYTES_VALUE_LEN.get())?,
                b"ui" => v.uint = read_u64(rd)?,
                other => unknown_key(rd, other)?,
            }
        }
        Ok(())
    }

    fn encode(&self, out: &mut Vec<u8>) {
        let n = (self.action != 0) as usize
            + !self.bytes.is_empty() as usize
            + (self.uint != 0) as usize;
        write_map_len(out, n);
        if self.action != 0 {
            write_key(out, "at");
            crate::canonical::write_uint(out, self.action);
        }
        if !self.bytes.is_empty() {
            write_key(out, "bs");
            write_str(out, &self.bytes);
        }
        if self.uint != 0 {
            write_key(out, "ui");
            crate::canonical::write_uint(out, self.uint);
        }
    }
}

/// `basics.StateDelta` (`map[string]ValueDelta`); `None` is a nil map.
type StateDelta = Option<BTreeMap<Vec<u8>, ValueDelta>>;

/// `StateDelta.UnmarshalMsg` into the populated map: `nil` makes it nil,
/// entries are added, each value fresh.
fn state_delta_decode_into(rd: &mut &[u8], sd: &mut StateDelta) -> Result<()> {
    let (n, nil) = read_map_header(rd)?;
    if n > bounds::MAX_STATE_DELTA_KEYS.get() {
        return Err(overflow(
            "StateDelta",
            n,
            bounds::MAX_STATE_DELTA_KEYS.get(),
        ));
    }
    if nil {
        *sd = None;
        return Ok(());
    }
    let map = sd.get_or_insert_with(BTreeMap::new);
    for _ in 0..n {
        let key = read_go_string(rd)?;
        let mut v = ValueDelta::default();
        ValueDelta::decode_into(rd, &mut v)?;
        map.insert(key, v);
    }
    Ok(())
}

/// `StateDelta.MarshalMsg`: nil is `nil`, keys sorted.
fn state_delta_encode(sd: &StateDelta, out: &mut Vec<u8>) {
    match sd {
        None => out.push(0xc0),
        Some(m) => {
            write_map_len(out, m.len());
            for (k, v) in m {
                write_str(out, k);
                v.encode(out);
            }
        }
    }
}

fn state_delta_is_empty(sd: &StateDelta) -> bool {
    sd.as_ref().is_none_or(BTreeMap::is_empty)
}

// ── transactions.EvalDelta ─────────────────────────────────────────────────

/// `transactions.EvalDelta`, with go's nil-vs-empty distinctions.
#[derive(Debug, Default)]
struct EvalDelta {
    global: StateDelta,
    local: Option<BTreeMap<u64, StateDelta>>,
    shared_accts: Vec<Address>,
    logs: Vec<Vec<u8>>,
    inner: Vec<SignedTransaction>,
}

impl EvalDelta {
    fn decode_into(rd: &mut &[u8], d: &mut Self) -> Result<()> {
        let mut keys = rmp_decode::struct_keys(rd, d, "transactions.EvalDelta")?;
        while let Some(key) = keys.next(rd)? {
            match key {
                b"gd" => state_delta_decode_into(rd, &mut d.global)?,
                b"ld" => {
                    let (n, nil) = read_map_header(rd)?;
                    if n > bounds::MAX_EVAL_DELTA_ACCOUNTS.get() {
                        return Err(overflow(
                            "LocalDeltas",
                            n,
                            bounds::MAX_EVAL_DELTA_ACCOUNTS.get(),
                        ));
                    }
                    if nil {
                        d.local = None;
                    } else {
                        let map = d.local.get_or_insert_with(BTreeMap::new);
                        for _ in 0..n {
                            let k = read_u64(rd)?;
                            let mut sd = None;
                            state_delta_decode_into(rd, &mut sd)?;
                            map.insert(k, sd);
                        }
                    }
                }
                b"sa" => {
                    read_slice_into(
                        rd,
                        &mut d.shared_accts,
                        bounds::MAX_EVAL_DELTA_ACCOUNTS.get(),
                        Address::default,
                        |rd, a| read_fixed_bytes_into_go_compat(rd, &mut a.0),
                    )?;
                }
                b"lg" => {
                    read_slice_into(
                        rd,
                        &mut d.logs,
                        bounds::MAX_LOG_CALLS.get(),
                        Vec::new,
                        |rd, l| {
                            *l = read_go_string(rd)?;
                            Ok(())
                        },
                    )?;
                }
                b"itx" => {
                    read_slice_into(
                        rd,
                        &mut d.inner,
                        bounds::MAX_INNER_TRANSACTIONS_PER_DELTA.get(),
                        SignedTransaction::default,
                        |rd, t| SignedTransaction::decode_into(rd, t, false),
                    )?;
                }
                other => unknown_key(rd, other)?,
            }
        }
        Ok(())
    }

    /// `EvalDelta.MarshalMsg`.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let local_empty = self.local.as_ref().is_none_or(BTreeMap::is_empty);
        let n = !state_delta_is_empty(&self.global) as usize
            + !self.inner.is_empty() as usize
            + !local_empty as usize
            + !self.logs.is_empty() as usize
            + !self.shared_accts.is_empty() as usize;
        write_map_len(&mut out, n);
        if !state_delta_is_empty(&self.global) {
            write_key(&mut out, "gd");
            state_delta_encode(&self.global, &mut out);
        }
        if !self.inner.is_empty() {
            write_key(&mut out, "itx");
            write_array_len(&mut out, self.inner.len());
            for t in &self.inner {
                out.extend(crate::canonical::canonical_encode_signed_txn_with_ad(t));
            }
        }
        if let Some(local) = self.local.as_ref().filter(|m| !m.is_empty()) {
            write_key(&mut out, "ld");
            write_map_len(&mut out, local.len());
            for (k, sd) in local {
                crate::canonical::write_uint(&mut out, *k);
                state_delta_encode(sd, &mut out);
            }
        }
        if !self.logs.is_empty() {
            write_key(&mut out, "lg");
            write_array_len(&mut out, self.logs.len());
            for l in &self.logs {
                write_str(&mut out, l);
            }
        }
        if !self.shared_accts.is_empty() {
            write_key(&mut out, "sa");
            write_array_len(&mut out, self.shared_accts.len());
            for a in &self.shared_accts {
                write_bin(&mut out, &a.0);
            }
        }
        out
    }
}

thread_local! {
    /// Set while `canonical::eval_delta_len` decodes the inner transactions
    /// of a delta to compare their re-encode: a `dt` met there is decoded
    /// without its own canonical scan (issue #2539). A scan that fails is
    /// followed by the full decode of the same bytes, so a scan at every
    /// level made each level decode its subtree twice: a `dt` nested N levels
    /// took 2^N, not N, steps (go's msgp decodes it in one pass).
    static SCANNING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };

    /// Eval deltas whose slices hold hidden capacity (see the module docs),
    /// keyed by the buffer of the `rmpv` map that represents them; emptied
    /// with the slice records when the decode session ends.
    static KEPT: RefCell<Vec<(usize, rmpv::Value, EvalDelta)>> = const { RefCell::new(Vec::new()) };
}

pub(crate) fn clear_kept() {
    KEPT.with(|k| {
        if let Ok(mut k) = k.try_borrow_mut() {
            if !k.is_empty() {
                let dropped = std::mem::take(&mut *k);
                drop(k);
                drop(dropped);
            }
        }
    });
}

fn map_buffer(v: &rmpv::Value) -> Option<usize> {
    match v {
        rmpv::Value::Map(m) if m.capacity() > 0 => Some(m.as_ptr() as usize),
        _ => None,
    }
}

/// The go value an earlier `dt` decoded to, to decode a repeated `dt` into.
fn existing_eval_delta(slot: &mut Option<rmpv::Value>) -> Result<EvalDelta> {
    let Some(v) = slot.take() else {
        return Ok(EvalDelta::default());
    };
    if let Some(addr) = map_buffer(&v) {
        let kept = KEPT.with(|k| {
            let mut k = k.borrow_mut();
            let i = k.iter().position(|(a, val, _)| *a == addr && *val == v)?;
            Some(k.swap_remove(i).2)
        });
        if let Some(d) = kept {
            return Ok(d);
        }
    }
    let mut raw = Vec::new();
    crate::canonical::write_value_str_preserving(&mut raw, &v)
        .map_err(|e| codec_err(format!("re-encode eval delta: {e}")))?;
    let mut d = EvalDelta::default();
    EvalDelta::decode_into(&mut &raw[..], &mut d)?;
    Ok(d)
}

/// `ApplyData.EvalDelta` (`dt`) decoded into `slot` as go decodes it, kept
/// as go's canonical re-encode (`None` when that is the zero value).
pub(crate) fn read_eval_delta_into(rd: &mut &[u8], slot: &mut Option<rmpv::Value>) -> Result<()> {
    // The common case: the first `dt`, already in go's canonical form (every
    // honest block). Its bytes are then exactly go's re-encode of what go
    // decodes, so they are kept as they are, as before #2424.
    if slot.is_none() && !SCANNING.with(std::cell::Cell::get) {
        if let Some(len) = canonical::eval_delta_len(rd) {
            let (raw, rest) = rd.split_at(len);
            *rd = rest;
            if raw != [0x80] {
                let value = rmpv::decode::read_value(&mut &raw[..])
                    .map_err(|e| codec_err(format!("eval delta: {e}")))?;
                *slot = Some(value);
            }
            return Ok(());
        }
    }
    let mut d = existing_eval_delta(slot)?;
    let hidden_before = rmp_decode::spare_records();
    EvalDelta::decode_into(rd, &mut d)?;
    let enc = d.encode();
    let hidden = rmp_decode::spare_records() != hidden_before || d_has_hidden(&d);
    if enc == [0x80] && !hidden {
        return Ok(());
    }
    let mut value = rmpv::decode::read_value(&mut &enc[..])
        .map_err(|e| codec_err(format!("eval delta re-encode: {e}")))?;
    if hidden {
        // a map buffer of its own, to key the typed value by
        if let rmpv::Value::Map(m) = &mut value {
            m.reserve(1);
        }
        if let Some(addr) = map_buffer(&value) {
            let keep = (addr, value.clone(), d);
            KEPT.with(|k| k.borrow_mut().push(keep));
        }
    }
    *slot = Some(value);
    Ok(())
}

/// Whether one of `d`'s slices has hidden capacity recorded.
fn d_has_hidden(d: &EvalDelta) -> bool {
    rmp_decode::has_spare(&d.shared_accts)
        || rmp_decode::has_spare(&d.logs)
        || rmp_decode::has_spare(&d.inner)
}

// ── bookkeeping.BlockHeader.StateProofTracking ─────────────────────────────

/// `bookkeeping.StateProofTrackingData`.
#[derive(Debug, Default)]
struct StateProofTrackingData {
    voters_commitment: Vec<u8>,
    online_total_weight: u64,
    next_round: u64,
}

impl StateProofTrackingData {
    fn decode_into(rd: &mut &[u8], s: &mut Self) -> Result<()> {
        let mut keys = rmp_decode::struct_keys(rd, s, "bookkeeping.StateProofTrackingData")?;
        while let Some(key) = keys.next(rd)? {
            match key {
                b"v" => {
                    rmp_decode::check_go_bytes_bound(rd, MAX_HASH_DIGEST_SIZE)?;
                    s.voters_commitment = read_bytes_go_compat(rd)?;
                }
                b"t" => s.online_total_weight = read_u64(rd)?,
                b"n" => s.next_round = read_u64(rd)?,
                other => unknown_key(rd, other)?,
            }
        }
        Ok(())
    }

    fn encode(&self, out: &mut Vec<u8>) {
        let n = (self.next_round != 0) as usize
            + (self.online_total_weight != 0) as usize
            + !self.voters_commitment.is_empty() as usize;
        write_map_len(out, n);
        if self.next_round != 0 {
            write_key(out, "n");
            crate::canonical::write_uint(out, self.next_round);
        }
        if self.online_total_weight != 0 {
            write_key(out, "t");
            crate::canonical::write_uint(out, self.online_total_weight);
        }
        if !self.voters_commitment.is_empty() {
            write_key(out, "v");
            write_bin(out, &self.voters_commitment);
        }
    }
}

/// `BlockHeader.StateProofTracking` (`spt`) decoded into `slot` as go
/// decodes it (a map: `nil` makes it nil, entries are added, each value
/// fresh; at most `NumStateProofTypes` entries per occurrence), kept as go's
/// canonical re-encode (`None` when empty: go omits it).
pub(crate) fn read_state_proof_tracking_into(
    rd: &mut &[u8],
    slot: &mut Option<rmpv::Value>,
) -> Result<()> {
    let (n, nil) = read_map_header(rd)?;
    if n > NUM_STATE_PROOF_TYPES {
        return Err(overflow("StateProofTracking", n, NUM_STATE_PROOF_TYPES));
    }
    if nil {
        *slot = None;
        return Ok(());
    }
    let mut map: BTreeMap<u64, StateProofTrackingData> = BTreeMap::new();
    if let Some(v) = slot.take() {
        let mut raw = Vec::new();
        crate::canonical::write_value_str_preserving(&mut raw, &v)
            .map_err(|e| codec_err(format!("re-encode state proof tracking: {e}")))?;
        let mut rd = &raw[..];
        let (m, _) = read_map_header(&mut rd)?;
        for _ in 0..m {
            let k = read_u64(&mut rd)?;
            let mut d = StateProofTrackingData::default();
            StateProofTrackingData::decode_into(&mut rd, &mut d)?;
            map.insert(k, d);
        }
    }
    for _ in 0..n {
        let k = read_u64(rd)?;
        let mut d = StateProofTrackingData::default();
        StateProofTrackingData::decode_into(rd, &mut d)?;
        map.insert(k, d);
    }
    if map.is_empty() {
        return Ok(());
    }
    let mut enc = Vec::new();
    write_map_len(&mut enc, map.len());
    for (k, d) in &map {
        crate::canonical::write_uint(&mut enc, *k);
        d.encode(&mut enc);
    }
    let value = rmpv::decode::read_value(&mut &enc[..])
        .map_err(|e| codec_err(format!("state proof tracking re-encode: {e}")))?;
    *slot = Some(value);
    Ok(())
}

/// Whether an encoded eval delta is already exactly what go's `MarshalMsg`
/// writes (so go's decode-then-re-encode returns the same bytes), checked
/// without building it. Anything else, including any input go would reject,
/// returns `None` and takes the decoding path, which also gives go's verdict.
mod canonical {
    use crate::rmp_decode::bounds;
    use crate::SignedTransaction;

    fn be(b: &[u8], i: usize, n: usize) -> Option<usize> {
        let s = b.get(i..i.checked_add(n)?)?;
        Some(s.iter().fold(0usize, |a, &x| (a << 8) | x as usize))
    }

    /// A container header in go's minimal form: `(count, next index)`.
    fn header(b: &[u8], i: usize, fix: u8, h16: u8, h32: u8) -> Option<(usize, usize)> {
        let c = *b.get(i)?;
        if c & 0xf0 == fix {
            return Some(((c & 0x0f) as usize, i + 1));
        }
        let (n, j) = if c == h16 {
            (be(b, i + 1, 2)?, i + 3)
        } else if c == h32 {
            (be(b, i + 1, 4)?, i + 5)
        } else {
            return None;
        };
        let minimal = if c == h16 { n >= 16 } else { n > 0xffff };
        minimal.then_some((n, j))
    }

    fn map(b: &[u8], i: usize) -> Option<(usize, usize)> {
        header(b, i, 0x80, 0xde, 0xdf)
    }

    fn array(b: &[u8], i: usize) -> Option<(usize, usize)> {
        header(b, i, 0x90, 0xdc, 0xdd)
    }

    /// A `str` in go's minimal form (`msgp.AppendString`): `(range, next)`.
    fn string(b: &[u8], i: usize) -> Option<(std::ops::Range<usize>, usize)> {
        let c = *b.get(i)?;
        let (n, j) = match c {
            0xa0..=0xbf => ((c & 0x1f) as usize, i + 1),
            0xd9 => (be(b, i + 1, 1)?, i + 2),
            0xda => (be(b, i + 1, 2)?, i + 3),
            0xdb => (be(b, i + 1, 4)?, i + 5),
            _ => return None,
        };
        let minimal = match c {
            0xd9 => n >= 32,
            0xda => n > 0xff,
            0xdb => n > 0xffff,
            _ => true,
        };
        let end = j.checked_add(n)?;
        (minimal && end <= b.len()).then_some((j..end, end))
    }

    /// A non-zero unsigned integer in go's minimal form (`msgp.AppendUint64`).
    fn uint(b: &[u8], i: usize) -> Option<(u64, usize)> {
        let c = *b.get(i)?;
        let (v, j) = match c {
            0x00..=0x7f => (c as u64, i + 1),
            0xcc => (be(b, i + 1, 1)? as u64, i + 2),
            0xcd => (be(b, i + 1, 2)? as u64, i + 3),
            0xce => (be(b, i + 1, 4)? as u64, i + 5),
            0xcf => (
                u64::from_be_bytes(b.get(i + 1..i + 9)?.try_into().ok()?),
                i + 9,
            ),
            _ => return None,
        };
        let minimal = match c {
            0xcc => v > 0x7f,
            0xcd => v > 0xff,
            0xce => v > 0xffff,
            0xcf => v > 0xffff_ffff,
            _ => true,
        };
        (minimal && v != 0).then_some((v, j))
    }

    /// A struct's keys: each one of `keys`, strictly in that order.
    fn key(b: &[u8], i: usize, keys: &[&str], after: &mut usize) -> Option<(usize, usize)> {
        let (r, j) = string(b, i)?;
        let k = keys[*after..]
            .iter()
            .position(|k| k.as_bytes() == &b[r.clone()])?
            + *after;
        *after = k + 1;
        Some((k, j))
    }

    /// `basics.ValueDelta`.
    fn value_delta(b: &[u8], i: usize) -> Option<usize> {
        let (n, mut i) = map(b, i)?;
        let mut after = 0;
        for _ in 0..n {
            let (k, j) = key(b, i, &["at", "bs", "ui"], &mut after)?;
            i = if k == 1 {
                let (r, j) = string(b, j)?;
                (!r.is_empty() && r.len() <= bounds::MAX_APP_BYTES_VALUE_LEN.get()).then_some(j)?
            } else {
                uint(b, j)?.1
            };
        }
        Some(i)
    }

    /// `basics.StateDelta`: keys strictly ascending (go sorts them); empty
    /// only where go writes an empty map (`ld` values; `gd` is omitted then).
    fn state_delta(b: &[u8], i: usize, non_empty: bool) -> Option<usize> {
        let (n, mut i) = map(b, i)?;
        if (non_empty && n == 0) || n > bounds::MAX_STATE_DELTA_KEYS.get() {
            return None;
        }
        let mut prev: Option<std::ops::Range<usize>> = None;
        for _ in 0..n {
            let (r, j) = string(b, i)?;
            if prev.is_some_and(|p| b[p] >= b[r.clone()]) {
                return None;
            }
            prev = Some(r);
            i = value_delta(b, j)?;
        }
        Some(i)
    }

    /// The length of the canonical `transactions.EvalDelta` at the start of
    /// `b`, if it is one.
    pub(super) fn eval_delta_len(b: &[u8]) -> Option<usize> {
        let (n, mut i) = map(b, 0)?;
        let mut after = 0;
        for _ in 0..n {
            let (k, j) = key(b, i, &["gd", "itx", "ld", "lg", "sa"], &mut after)?;
            i = match k {
                0 => state_delta(b, j, true)?,
                1 => {
                    let (m, mut j) = array(b, j)?;
                    if m == 0 || m > bounds::MAX_INNER_TRANSACTIONS_PER_DELTA.get() {
                        return None;
                    }
                    for _ in 0..m {
                        let mut rd = &b[j..];
                        let mut t = SignedTransaction::default();
                        let outer = super::SCANNING.with(|f| f.replace(true));
                        let decoded = SignedTransaction::decode_into(&mut rd, &mut t, false);
                        super::SCANNING.with(|f| f.set(outer));
                        decoded.ok()?;
                        let end = b.len() - rd.len();
                        if crate::canonical::canonical_encode_signed_txn_with_ad(&t) != b[j..end] {
                            return None;
                        }
                        j = end;
                    }
                    j
                }
                2 => {
                    let (m, mut j) = map(b, j)?;
                    if m == 0 || m > bounds::MAX_EVAL_DELTA_ACCOUNTS.get() {
                        return None;
                    }
                    let mut prev = None;
                    for _ in 0..m {
                        // go's `AppendUint64`: 0 is a valid key here
                        let (v, k) = match *b.get(j)? {
                            0x00 => (0, j + 1),
                            _ => uint(b, j)?,
                        };
                        if prev.is_some_and(|p| p >= v) {
                            return None;
                        }
                        prev = Some(v);
                        j = if *b.get(k)? == 0xc0 {
                            k + 1
                        } else {
                            state_delta(b, k, false)?
                        };
                    }
                    j
                }
                3 => {
                    let (m, mut j) = array(b, j)?;
                    if m == 0 || m > bounds::MAX_LOG_CALLS.get() {
                        return None;
                    }
                    for _ in 0..m {
                        j = string(b, j)?.1;
                    }
                    j
                }
                _ => {
                    let (m, mut j) = array(b, j)?;
                    if m == 0 || m > bounds::MAX_EVAL_DELTA_ACCOUNTS.get() {
                        return None;
                    }
                    for _ in 0..m {
                        // `Address.MarshalMsg`: bin8 of 32 bytes
                        if b.get(j..j + 2)? != [0xc4, 32] || b.len() < j + 34 {
                            return None;
                        }
                        j += 34;
                    }
                    j
                }
            };
        }
        Some(i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dt(bytes: &[u8]) -> Option<Vec<u8>> {
        let _s = rmp_decode::decode_session();
        let mut slot = None;
        let mut rd = bytes;
        read_eval_delta_into(&mut rd, &mut slot).unwrap();
        assert!(rd.is_empty());
        slot.map(|v| {
            let mut out = Vec::new();
            crate::canonical::write_value_str_preserving(&mut out, &v).unwrap();
            out
        })
    }

    /// `{"lg": ["a"], "gd": {"k": {"ui": 1}}}`: the keys out of go's order.
    const UNSORTED: &[u8] = b"\x82\xa2lg\x91\xa1a\xa2gd\x81\xa1k\x81\xa2ui\x01";
    /// What go re-encodes it to: `gd` first.
    const SORTED: &[u8] = b"\x82\xa2gd\x81\xa1k\x81\xa2ui\x01\xa2lg\x91\xa1a";

    #[test]
    fn a_canonical_eval_delta_is_kept_as_it_is() {
        assert_eq!(canonical::eval_delta_len(SORTED), Some(SORTED.len()));
        assert_eq!(dt(SORTED).unwrap(), SORTED);
    }

    #[test]
    fn a_non_canonical_eval_delta_becomes_gos_re_encode() {
        assert_eq!(canonical::eval_delta_len(UNSORTED), None);
        assert_eq!(dt(UNSORTED).unwrap(), SORTED);
        // a zero field go omits, and a non-minimal integer
        let zero_and_wide = b"\x82\xa2gd\x81\xa1k\x82\xa2at\x00\xa2ui\xcc\x01\xa2lg\x91\xa1a";
        assert_eq!(dt(zero_and_wide).unwrap(), SORTED);
        // the zero value: no `dt` at all
        assert_eq!(dt(b"\x81\xa2lg\x90"), None);
    }

    /// A repeated `gd` adds entries to the map (each value fresh), a repeated
    /// `lg` is re-sliced, and a nil `ld` value stays nil (go writes `nil`).
    #[test]
    fn a_repeated_key_decodes_into_the_populated_field() {
        let rep = b"\x84\xa2gd\x81\xa1k\x81\xa2ui\x01\xa2lg\x92\xa1a\xa1b\xa2gd\x81\xa1j\x81\xa2at\x02\xa2lg\x91\xa1c";
        let want = b"\x82\xa2gd\x82\xa1j\x81\xa2at\x02\xa1k\x81\xa2ui\x01\xa2lg\x91\xa1c";
        assert_eq!(dt(rep).unwrap(), want);
        let ld_nil = b"\x81\xa2ld\x81\x05\xc0";
        assert_eq!(canonical::eval_delta_len(ld_nil), Some(ld_nil.len()));
        assert_eq!(dt(ld_nil).unwrap(), ld_nil);
    }

    /// go's allocation bound on a `ValueDelta`'s bytes (`MaxAppBytesValueLen`).
    #[test]
    fn the_value_bytes_bound_is_gos() {
        let mut long = b"\x81\xa2gd\x81\xa1k\x81\xa2bs\xd9\x81".to_vec();
        long.extend([b'x'; 129]);
        let _s = rmp_decode::decode_session();
        let mut slot = None;
        assert!(read_eval_delta_into(&mut &long[..], &mut slot).is_err());
    }

    /// `spt`: a repeated key adds entries, at most one per occurrence.
    #[test]
    fn state_proof_tracking_merges_like_go() {
        let _s = rmp_decode::decode_session();
        let mut slot = None;
        read_state_proof_tracking_into(&mut &b"\x81\x00\x81\xa1n\x05"[..], &mut slot).unwrap();
        read_state_proof_tracking_into(&mut &b"\x81\x01\x81\xa1t\x07"[..], &mut slot).unwrap();
        let mut out = Vec::new();
        crate::canonical::write_value_str_preserving(&mut out, &slot.unwrap()).unwrap();
        assert_eq!(out, b"\x82\x00\x81\xa1n\x05\x01\x81\xa1t\x07");
        let mut slot = None;
        assert!(
            read_state_proof_tracking_into(&mut &b"\x82\x00\x80\x01\x80"[..], &mut slot).is_err()
        );
    }
}
