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

//! Low-level msgpack decode helpers using `rmp` directly.
//! Avoids serde overhead for hot-path block/transaction decoding.

use algo_error::{AlgoError, Result};
use serde_bytes::ByteBuf;

use crate::Address;

/// Create a codec error with the given message.
fn codec_err(msg: impl Into<String>) -> AlgoError {
    AlgoError::Codec {
        source: msg.into().into(),
        context: "rmp_decode".into(),
    }
}

// ── Map / key reading ──────────────────────────────────────────

/// Read a msgpack map header, returning the number of key-value pairs.
#[inline]
pub fn read_map_len(rd: &mut &[u8]) -> Result<u32> {
    // nil: go's ReadMapHeaderBytes decodes nil as an empty map / zeroed struct
    // (issue #2065).
    // DIVERGENCE DIV-004: only the map form is read; go's struct-from-array
    // branch (ReadArrayHeaderBytes fallback) is intentionally not supported.
    if let [0xc0, rest @ ..] = *rd {
        *rd = rest;
        return Ok(0);
    }
    rmp::decode::read_map_len(rd).map_err(|e| codec_err(format!("read_map_len: {e}")))
}

/// Read a msgpack string key as raw bytes without allocation.
///
/// Reads the string header to get the length, then returns a borrowed
/// slice of the raw key bytes. No UTF-8 validation is performed.
///
/// Uses direct byte dispatch to avoid rmp::decode::read_str_len overhead.
/// Most Algorand keys are short (fixstr: len 0-31), so the common path is
/// a single byte read.
#[inline]
pub fn read_key_bytes<'a>(rd: &mut &'a [u8]) -> Result<&'a [u8]> {
    if rd.is_empty() {
        return Err(codec_err("read_key_bytes: unexpected EOF"));
    }
    let b = rd[0];
    let len: usize;
    // fixstr: 0xa0..=0xbf encodes length 0..31 in the marker itself
    if (0xa0..=0xbf).contains(&b) {
        len = (b & 0x1f) as usize;
        *rd = &rd[1..];
    } else if b == 0xd9 {
        // str8
        if rd.len() < 2 {
            return Err(codec_err("read_key_bytes: str8 unexpected EOF"));
        }
        len = rd[1] as usize;
        *rd = &rd[2..];
    } else if b == 0xda {
        // str16
        if rd.len() < 3 {
            return Err(codec_err("read_key_bytes: str16 unexpected EOF"));
        }
        len = u16::from_be_bytes([rd[1], rd[2]]) as usize;
        *rd = &rd[3..];
    } else {
        return Err(codec_err(format!(
            "read_key_bytes: expected string marker, got 0x{b:02x}"
        )));
    }
    if rd.len() < len {
        return Err(codec_err(format!(
            "read_key_bytes: need {len} bytes, have {}",
            rd.len()
        )));
    }
    let (key, rest) = rd.split_at(len);
    *rd = rest;
    Ok(key)
}

// ── go's msgp allocation bounds for LogicSig (issue #2390) ─────

/// `bounds.MaxLogicSigMaxSize` (`config/bounds`): the maximum, over every
/// consensus version, of `LogicSigMaxSize * MaxTxGroupSize` (1000 * 16) and
/// `MaxAbsoluteLogicSigProgramSize` (16000 since v40). The generated
/// `LogicSig` decoder rejects a larger `l` (`allocbound`).
pub const MAX_LOGIC_SIG_MAX_SIZE: usize = 16_000;
/// `transactions.EvalMaxArgs`: most elements of `LogicSig.Args`.
pub const EVAL_MAX_ARGS: usize = 255;
/// `transactions.MaxLogicSigArgSize` (`config.MaxAVMBytesSize`): longest element
/// of `LogicSig.Args`.
pub const MAX_LOGIC_SIG_ARG_SIZE: usize = 4096;
/// `crypto.maxMultisig`: most `subsig` entries of a `MultisigSig`.
pub const MAX_MULTISIG: usize = 255;
/// `crypto.MaxPQPublicKeySize` (`FalconPublicKeySize`).
pub const MAX_PQ_PUBLIC_KEY_SIZE: usize = 1793;
/// `crypto.MaxPQSignatureSize` (`FalconMaxSignatureSize`, the CT signature).
pub const MAX_PQ_SIGNATURE_SIZE: usize = 1538;

// ── go's other msgp allocation bounds of consensus messages (issue #2427) ──
//
// Every field below carries an `allocbound` in go v5.0.5-stable: its generated
// decoder reads the length header (`msgp.ReadBytesBytesHeader`,
// `ReadArrayHeaderBytes`, `ReadMapHeaderBytes`) and fails with
// `msgp.ErrOverflow` when it is larger, before reading the value. The
// `bounds.*` values are what `config.checkSetAllocBounds` computes, the
// maximum over every consensus version (vFuture included).

/// `bounds.MaxGenesisIDLen`: `gen` of a transaction and a block header.
pub const MAX_GENESIS_ID_LEN: usize = 128;
/// `bounds.MaxConsensusVersionLen`: a `protocol.ConsensusVersion` (`proto`,
/// `nextproto`, `upgradeprop`).
pub const MAX_CONSENSUS_VERSION_LEN: usize = 128;
/// `protocol.txTypeMaxLen`: a `protocol.TxType` (`type`).
pub const TX_TYPE_MAX_LEN: usize = 7;
/// `bounds.MaxTxnNoteBytes` (`MaxAbsoluteTxnNoteBytes`): `note`.
pub const MAX_TXN_NOTE_BYTES: usize = 4096;
/// `transactions.encodedMaxApplicationArgs`: elements of `apaa`.
pub const ENCODED_MAX_APPLICATION_ARGS: usize = 32;
/// `transactions.encodedMaxAccounts`: elements of `apat`.
pub const ENCODED_MAX_ACCOUNTS: usize = 32;
/// `transactions.encodedMaxForeignAssets`: elements of `apas`.
pub const ENCODED_MAX_FOREIGN_ASSETS: usize = 32;
/// `transactions.encodedMaxForeignApps`: elements of `apfa`.
pub const ENCODED_MAX_FOREIGN_APPS: usize = 32;
/// `transactions.encodedMaxBoxes`: elements of `apbx`.
pub const ENCODED_MAX_BOXES: usize = 32;
/// `bounds.MaxAppAccess`: elements of `al`.
pub const MAX_APP_ACCESS: usize = 16;
/// `bounds.MaxAvailableAppProgramLen` (`MaxAppProgramLen * (1 +
/// MaxExtraAppProgramLen)`, 2048 * 8): `apap`, `apsu`.
pub const MAX_AVAILABLE_APP_PROGRAM_LEN: usize = 16384;
/// `bounds.MaxBytesKeyValueLen`: a box name (`BoxRef.n`).
pub const MAX_BYTES_KEY_VALUE_LEN: usize = 128;
/// `bounds.MaxAssetUnitNameBytes`: `AssetParams.un`.
pub const MAX_ASSET_UNIT_NAME_BYTES: usize = 8;
/// `bounds.MaxAssetNameBytes`: `AssetParams.an`.
pub const MAX_ASSET_NAME_BYTES: usize = 32;
/// `bounds.MaxAssetURLBytes`: `AssetParams.au`.
pub const MAX_ASSET_URL_BYTES: usize = 96;
/// `crypto.MaxHashDigestSize` (`SumhashDigestSize`): a `crypto.GenericDigest`.
pub const MAX_HASH_DIGEST_SIZE: usize = 64;
/// `crypto.Sha256Size`: `stateproofmsg.Message.BlockHeadersCommitment`.
pub const SHA256_SIZE: usize = 32;
/// `crypto.SumhashDigestSize`: `stateproofmsg.Message.VotersCommitment`.
pub const SUMHASH_DIGEST_SIZE: usize = 64;
/// `crypto.FalconMaxSignatureSize` (`cfalcon.CTSignatureSize`): a
/// `crypto.FalconSignature`.
pub const FALCON_MAX_SIGNATURE_SIZE: usize = 1538;
/// `stateproof.MaxReveals`: entries of `Reveals`, elements of
/// `PositionsToReveal`.
pub const MAX_REVEALS: usize = 640;
/// `merklearray.MaxNumLeavesOnEncodedTree / 2`: elements of a proof's `pth`.
pub const MAX_PROOF_PATH_LEN: usize = (1 << 16) / 2;
/// `//msgp:allocbound Payset 100000`: transactions of a block.
pub const MAX_PAYSET_LEN: usize = 100_000;
/// `bounds.MaxVoteThreshold` (the largest committee threshold, 7750):
/// elements of a bundle's `vote` and `eqv`.
pub const MAX_VOTE_THRESHOLD: usize = 7750;

// ── Skip value ─────────────────────────────────────────────────

/// Matches go-algorand v4.7.2-stable's `msgp.DefaultUnmarshalState.AllowableDepth`
/// (`protocol/codec.go`), an anti-DoS bound on decode nesting depth.
pub(crate) const MAX_MSGPACK_DECODE_DEPTH: usize = 255;

/// Reject `bytes` if its (first) msgpack value nests containers deeper
/// than [`MAX_MSGPACK_DECODE_DEPTH`] levels, without otherwise decoding
/// or validating it.
///
/// Exposed for decoders that don't go through this module's own
/// `decode_from_reader` family — namely `algo-codec`'s `rmp_serde`/`rmpv`
/// entry points, whose decoders have no depth cap of their own. Run this
/// as a pre-scan before handing the bytes to them.
pub fn check_msgpack_depth(bytes: &[u8]) -> Result<()> {
    msgpack_value_len(bytes).map(|_| ())
}

/// Like [`check_msgpack_depth`], but on success returns the byte length of
/// the (first) msgpack value, so a caller walking a concatenated stream can
/// slice off exactly one element and advance in a single scan (issue #2043).
/// Errors (depth > 255, truncated, malformed) are identical to
/// [`check_msgpack_depth`]'s.
pub fn msgpack_value_len(bytes: &[u8]) -> Result<usize> {
    let mut rd = bytes;
    skip_value(&mut rd)?;
    Ok(bytes.len() - rd.len())
}

// ── Strict unknown-field mode (issue #1962) ────────────────────────────
//
// go-algorand's `POST /v2/transactions` decodes with `protocol.NewDecoder`
// (`ErrorIfNoField = true`): a key the target struct does not have is a 400
// whose text carries the stream offset just after that key. The hand-written
// readers below skip unknown keys (blocks and catchup depend on that), so the
// REST handlers switch the strict mode on for the duration of one synchronous
// group decode with [`strict_unknown_fields`]. The mode is thread-local and
// scoped by the returned guard; it must not be held across an `.await`.

use std::cell::Cell;

thread_local! {
    /// Scan mode: required-field checks are skipped (see
    /// [`strict_unknown_fields_scan`]).
    static SCAN_ONLY: Cell<bool> = const { Cell::new(false) };
    /// go-codec reflection mode (see [`go_codec_reflect`]).
    static REFLECT: Cell<bool> = const { Cell::new(false) };
    /// (address of the first byte, length) of the body being decoded in strict mode.
    static STRICT_BASE: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
}

/// go's rejection of a key its struct lacks: `pos` is the offset, from the
/// start of the whole request body, just after the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownFieldError {
    pub pos: usize,
    pub key: String,
}

impl std::fmt::Display for UnknownFieldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "msgpack decode error [pos {}]: no matching struct field found when decoding stream map with key {}",
            self.pos, self.key
        )
    }
}

impl std::error::Error for UnknownFieldError {}

/// Guard returned by [`strict_unknown_fields`]; restores the previous mode on drop.
#[must_use = "strict mode ends when the guard is dropped"]
pub struct StrictUnknownFieldsGuard {
    prev: Option<(usize, usize)>,
    prev_scan: bool,
    prev_reflect: bool,
    /// `!Send`: the mode is per-thread, so a guard held across an `.await`
    /// (which may resume on another worker) must not compile.
    _not_send: std::marker::PhantomData<*const ()>,
}

impl Drop for StrictUnknownFieldsGuard {
    fn drop(&mut self) {
        STRICT_BASE.with(|c| c.set(self.prev));
        SCAN_ONLY.with(|c| c.set(self.prev_scan));
        REFLECT.with(|c| c.set(self.prev_reflect));
    }
}

/// Reject unknown keys (as go's REST decoder does) while the guard is alive.
/// `body` is the whole request body; the readers must be driven with slices
/// of it so that positions count from its start.
pub fn strict_unknown_fields(body: &[u8]) -> StrictUnknownFieldsGuard {
    let prev = STRICT_BASE.with(|c| c.replace(Some((body.as_ptr() as usize, body.len()))));
    // a plain strict guard always enforces required fields, even when it is
    // created while a scan guard is alive
    let prev_scan = SCAN_ONLY.with(|c| c.replace(false));
    let prev_reflect = REFLECT.with(|c| c.replace(false));
    StrictUnknownFieldsGuard {
        prev,
        prev_scan,
        prev_reflect,
        _not_send: std::marker::PhantomData,
    }
}

/// [`strict_unknown_fields`] that also skips the readers' required-field
/// checks, so a decode runs on to the first unknown key even when an earlier
/// object is missing a field such as `snd`. go's JSON decoder
/// (`protocol.JSONStrictHandle`, reflection based) enforces no required
/// fields, so it reaches the unknown key where the msgpack-style readers would
/// stop first. For locating unknown keys only: the decoded value is not valid.
pub fn strict_unknown_fields_scan(body: &[u8]) -> StrictUnknownFieldsGuard {
    let guard = strict_unknown_fields(body);
    SCAN_ONLY.with(|c| c.set(true));
    guard
}

/// Decode the way go's `protocol.DecodeReflect` does (go-codec reflection,
/// `protocol.CodecHandle`: `ErrorIfNoField`, the tx-sync response in
/// `rpcs/httpTxSync.go`), not the generated msgp decoders, while the guard is
/// alive (issue #2424, every rule below read from go v5.0.5-stable with the
/// strict-decode oracle):
///
/// - unknown keys fail, as with [`strict_unknown_fields`];
/// - `codec:",required"` and the msgp `allocbound`s are msgp-only: go-codec
///   checks neither;
/// - a repeated key of a `map[K]struct` decodes INTO the existing entry, an
///   unaddressable map value: see `Reveal::decode_into_map_entry`;
/// - a repeated slice longer than its capacity keeps its elements (go-codec
///   copies them into the grown slice, msgp makes a fresh one, issue #2427):
///   see [`read_slice_into`].
///
/// Everything else (a repeated struct field merges, a slice within its
/// capacity, `[N]byte`) the two decoders do alike.
pub fn go_codec_reflect(body: &[u8]) -> StrictUnknownFieldsGuard {
    let guard = strict_unknown_fields(body);
    SCAN_ONLY.with(|c| c.set(true));
    REFLECT.with(|c| c.set(true));
    guard
}

/// Whether a [`go_codec_reflect`] guard is alive.
#[inline]
pub fn reflect_mode() -> bool {
    REFLECT.with(Cell::get)
}

/// Whether the readers enforce `codec:",required"` fields (false in scan mode).
#[inline]
pub fn required_fields_checked() -> bool {
    !SCAN_ONLY.with(Cell::get)
}

/// Whether the readers enforce go's msgp `allocbound`s (false in
/// [`go_codec_reflect`] mode: go-codec has none).
#[inline]
pub fn alloc_bounds_checked() -> bool {
    !REFLECT.with(Cell::get)
}

fn unknown_field_error(rd: &[u8], key: &[u8], (base, len): (usize, usize)) -> AlgoError {
    let at = rd.as_ptr() as usize;
    // The reader must be driven by slices of the body the guard was given;
    // anything else would print a meaningless offset.
    debug_assert!(
        at >= base && at <= base + len,
        "strict-mode reader is not inside the guarded body"
    );
    let e = UnknownFieldError {
        pos: at.saturating_sub(base),
        key: String::from_utf8_lossy(key).into_owned(),
    };
    AlgoError::Codec {
        context: e.to_string(),
        source: Box::new(e),
    }
}

/// The fallback arm of every reader's key match: a key the struct lacks.
///
/// go's generated msgp decoders (and the reflection codec, `ErrorIfNoField =
/// true`) fail with `msgp.ErrNoField` on such a key wherever the message
/// comes from (gossip, catchup, REST, a block DB read), so this is an error
/// whether or not a [`strict_unknown_fields`] guard is alive (issue #2394);
/// the guard only adds the request-body offset go's REST text carries. `rd`
/// must point just after the already-read `key`.
#[inline]
pub fn unknown_key(rd: &mut &[u8], key: &[u8]) -> Result<()> {
    Err(match STRICT_BASE.with(Cell::get) {
        Some(base) => unknown_field_error(rd, key, base),
        None => no_matching_field_error(key),
    })
}

/// [`unknown_key`] for a message with no request body to count offsets from.
#[cold]
pub fn no_matching_field_error(key: &[u8]) -> AlgoError {
    let text = format!(
        "msgpack decode error: no matching struct field found when decoding stream map with key {}",
        String::from_utf8_lossy(key)
    );
    AlgoError::Codec {
        source: text.clone().into(),
        context: text,
    }
}

/// For keys a reader understands only because blocks carry them (go's
/// `SignedTxn` has no such field): an error in strict mode, otherwise `Ok`.
#[inline]
pub fn reject_when_strict(rd: &[u8], key: &[u8]) -> Result<()> {
    match STRICT_BASE.with(Cell::get) {
        Some(base) => Err(unknown_field_error(rd, key, base)),
        None => Ok(()),
    }
}

/// Skip any msgpack value (handles all types, including arbitrarily
/// nested containers).
///
/// Iterative, not recursive: `remaining` holds, for each currently open
/// container, how many more values inside it still need skipping, so
/// nesting depth is `remaining.len()`. This is deliberate — a naive
/// recursive skip lets a maliciously deep/nested payload (this function
/// is reached for every *unrecognized* field a decoder skips, so an
/// attacker controls its shape freely) overflow the Rust call stack,
/// which aborts the process rather than returning an error. Bounding
/// `remaining.len()` at [`MAX_MSGPACK_DECODE_DEPTH`] mirrors go-algorand's
/// own bound and rejects the same maliciously deep payloads with a
/// catchable error instead.
#[inline]
pub fn skip_value(rd: &mut &[u8]) -> Result<()> {
    // Values still to read per nesting level. The outermost level (the one
    // value being skipped) lives in `outer`, so skipping a scalar, the common
    // case, does not allocate (issue #2317); `remaining` holds the levels
    // opened by containers.
    let mut outer: u64 = 1;
    let mut remaining: Vec<u64> = Vec::new();
    loop {
        let count = match remaining.last_mut() {
            Some(count) => count,
            None => &mut outer,
        };
        if *count == 0 {
            if remaining.pop().is_none() {
                break;
            }
            continue;
        }
        *count -= 1;
        if remaining.len() + 1 > MAX_MSGPACK_DECODE_DEPTH {
            return Err(codec_err(format!(
                "skip_value: nesting depth exceeds {MAX_MSGPACK_DECODE_DEPTH}"
            )));
        }
        if rd.is_empty() {
            return Err(codec_err("skip_value: unexpected EOF"));
        }
        let b = rd[0];
        *rd = &rd[1..];
        match b {
            // positive fixint (0x00..=0x7f) — no data bytes
            0x00..=0x7f => {}
            // fixmap (0x80..=0x8f) — len 0..15 key-value pairs
            0x80..=0x8f => remaining.push(((b & 0x0f) as u64) * 2),
            // fixarray (0x90..=0x9f) — len 0..15 elements
            0x90..=0x9f => remaining.push((b & 0x0f) as u64),
            // fixstr (0xa0..=0xbf) — len 0..31
            0xa0..=0xbf => skip_bytes(rd, (b & 0x1f) as usize)?,
            // nil, false, true
            0xc0 | 0xc2 | 0xc3 => {}
            // reserved
            0xc1 => return Err(codec_err("skip_value: reserved marker 0xc1")),
            // bin8
            0xc4 => {
                let len = read_data_u8(rd)? as usize;
                skip_bytes(rd, len)?;
            }
            // bin16
            0xc5 => {
                let len = read_data_u16(rd)? as usize;
                skip_bytes(rd, len)?;
            }
            // bin32
            0xc6 => {
                let len = read_data_u32_raw(rd)? as usize;
                skip_bytes(rd, len)?;
            }
            // ext8
            0xc7 => {
                let len = read_data_u8(rd)? as usize;
                skip_bytes(rd, 1 + len)?;
            }
            // ext16
            0xc8 => {
                let len = read_data_u16(rd)? as usize;
                skip_bytes(rd, 1 + len)?;
            }
            // ext32
            0xc9 => {
                let len = read_data_u32_raw(rd)? as usize;
                skip_bytes(rd, 1 + len)?;
            }
            // f32
            0xca => skip_bytes(rd, 4)?,
            // f64
            0xcb => skip_bytes(rd, 8)?,
            // u8
            0xcc => skip_bytes(rd, 1)?,
            // u16
            0xcd => skip_bytes(rd, 2)?,
            // u32
            0xce => skip_bytes(rd, 4)?,
            // u64
            0xcf => skip_bytes(rd, 8)?,
            // i8
            0xd0 => skip_bytes(rd, 1)?,
            // i16
            0xd1 => skip_bytes(rd, 2)?,
            // i32
            0xd2 => skip_bytes(rd, 4)?,
            // i64
            0xd3 => skip_bytes(rd, 8)?,
            // fixext1
            0xd4 => skip_bytes(rd, 2)?,
            // fixext2
            0xd5 => skip_bytes(rd, 3)?,
            // fixext4
            0xd6 => skip_bytes(rd, 5)?,
            // fixext8
            0xd7 => skip_bytes(rd, 9)?,
            // fixext16
            0xd8 => skip_bytes(rd, 17)?,
            // str8
            0xd9 => {
                let len = read_data_u8(rd)? as usize;
                skip_bytes(rd, len)?;
            }
            // str16
            0xda => {
                let len = read_data_u16(rd)? as usize;
                skip_bytes(rd, len)?;
            }
            // str32
            0xdb => {
                let len = read_data_u32_raw(rd)? as usize;
                skip_bytes(rd, len)?;
            }
            // array16
            0xdc => {
                let len = read_data_u16(rd)? as u64;
                remaining.push(len);
            }
            // array32
            0xdd => {
                let len = read_data_u32_raw(rd)? as u64;
                remaining.push(len);
            }
            // map16
            0xde => {
                let len = read_data_u16(rd)? as u64;
                remaining.push(len * 2);
            }
            // map32
            0xdf => {
                // u64 accounting: a map32 length near u32::MAX doubled
                // overflows u32 (and usize on 32-bit targets).
                let len = read_data_u32_raw(rd)? as u64;
                remaining.push(len * 2);
            }
            // negative fixint (0xe0..=0xff) — no data bytes
            0xe0..=0xff => {}
        }
    }
    Ok(())
}

/// Skip exactly `n` bytes from the reader.
#[inline]
fn skip_bytes(rd: &mut &[u8], n: usize) -> Result<()> {
    if rd.len() < n {
        return Err(codec_err(format!(
            "skip_bytes: need {n}, have {}",
            rd.len()
        )));
    }
    *rd = &rd[n..];
    Ok(())
}

// ── Raw data reading (no marker) ───────────────────────────────

/// Read a raw u8 (data only, no marker).
#[inline]
fn read_data_u8(rd: &mut &[u8]) -> Result<u8> {
    if rd.is_empty() {
        return Err(codec_err("read_data_u8: unexpected EOF"));
    }
    let v = rd[0];
    *rd = &rd[1..];
    Ok(v)
}

/// Read a raw big-endian u16 (data only, no marker).
#[inline]
fn read_data_u16(rd: &mut &[u8]) -> Result<u16> {
    if rd.len() < 2 {
        return Err(codec_err("read_data_u16: unexpected EOF"));
    }
    let v = u16::from_be_bytes([rd[0], rd[1]]);
    *rd = &rd[2..];
    Ok(v)
}

/// Read a raw big-endian u32 (data only, no marker).
#[inline]
fn read_data_u32_raw(rd: &mut &[u8]) -> Result<u32> {
    if rd.len() < 4 {
        return Err(codec_err("read_data_u32: unexpected EOF"));
    }
    let v = u32::from_be_bytes([rd[0], rd[1], rd[2], rd[3]]);
    *rd = &rd[4..];
    Ok(v)
}

/// Read a raw big-endian u64 (data only, no marker).
#[inline]
fn read_data_u64_raw(rd: &mut &[u8]) -> Result<u64> {
    if rd.len() < 8 {
        return Err(codec_err("read_data_u64: unexpected EOF"));
    }
    let v = u64::from_be_bytes(rd[..8].try_into().unwrap());
    *rd = &rd[8..];
    Ok(v)
}

/// Read a raw big-endian i16 (data only, no marker).
#[inline]
fn read_data_i16(rd: &mut &[u8]) -> Result<i16> {
    if rd.len() < 2 {
        return Err(codec_err("read_data_i16: unexpected EOF"));
    }
    let v = i16::from_be_bytes([rd[0], rd[1]]);
    *rd = &rd[2..];
    Ok(v)
}

/// Read a raw big-endian i32 (data only, no marker).
#[inline]
fn read_data_i32(rd: &mut &[u8]) -> Result<i32> {
    if rd.len() < 4 {
        return Err(codec_err("read_data_i32: unexpected EOF"));
    }
    let v = i32::from_be_bytes([rd[0], rd[1], rd[2], rd[3]]);
    *rd = &rd[4..];
    Ok(v)
}

/// Read a raw big-endian i64 (data only, no marker).
#[inline]
fn read_data_i64_raw(rd: &mut &[u8]) -> Result<i64> {
    if rd.len() < 8 {
        return Err(codec_err("read_data_i64: unexpected EOF"));
    }
    let v = i64::from_be_bytes(rd[..8].try_into().unwrap());
    *rd = &rd[8..];
    Ok(v)
}

// ── Integer readers (polymorphic) ──────────────────────────────

/// Read any msgpack integer format and return as u64.
///
/// Handles all integer encodings: fixint, u8, u16, u32, u64, i8, i16, i32, i64.
/// Returns an error if the value is negative or not an integer type.
///
/// Uses direct byte dispatch instead of rmp::decode::read_marker to avoid
/// Marker enum construction overhead. The hot path (fixint 0-127) is a single
/// branch.
#[inline]
pub fn read_u64(rd: &mut &[u8]) -> Result<u64> {
    if rd.is_empty() {
        return Err(codec_err("read_u64: unexpected EOF"));
    }
    let b = rd[0];
    *rd = &rd[1..];
    match b {
        // positive fixint: 0x00..=0x7f
        0x00..=0x7f => Ok(b as u64),
        // u8
        0xcc => Ok(read_data_u8(rd)? as u64),
        // u16
        0xcd => Ok(read_data_u16(rd)? as u64),
        // u32
        0xce => Ok(read_data_u32_raw(rd)? as u64),
        // u64
        0xcf => read_data_u64_raw(rd),
        // negative fixint: 0xe0..=0xff
        0xe0..=0xff => Err(codec_err(format!("read_u64: negative value {}", b as i8))),
        // i8
        0xd0 => {
            let v = read_data_u8(rd)? as i8;
            if v >= 0 {
                Ok(v as u64)
            } else {
                Err(codec_err(format!("read_u64: negative i8 value {v}")))
            }
        }
        // i16
        0xd1 => {
            let v = read_data_i16(rd)?;
            if v >= 0 {
                Ok(v as u64)
            } else {
                Err(codec_err(format!("read_u64: negative i16 value {v}")))
            }
        }
        // i32
        0xd2 => {
            let v = read_data_i32(rd)?;
            if v >= 0 {
                Ok(v as u64)
            } else {
                Err(codec_err(format!("read_u64: negative i32 value {v}")))
            }
        }
        // i64
        0xd3 => {
            let v = read_data_i64_raw(rd)?;
            if v >= 0 {
                Ok(v as u64)
            } else {
                Err(codec_err(format!("read_u64: negative i64 value {v}")))
            }
        }
        // nil: go's ReadUint64Bytes maps nil to 0 (issue #2065)
        0xc0 => Ok(0),
        other => Err(codec_err(format!(
            "read_u64: not an integer: 0x{other:02x}"
        ))),
    }
}

/// Read any msgpack integer format and return as i64.
#[inline]
pub fn read_i64(rd: &mut &[u8]) -> Result<i64> {
    if rd.is_empty() {
        return Err(codec_err("read_i64: unexpected EOF"));
    }
    let b = rd[0];
    *rd = &rd[1..];
    match b {
        // positive fixint: 0x00..=0x7f
        0x00..=0x7f => Ok(b as i64),
        // negative fixint: 0xe0..=0xff
        0xe0..=0xff => Ok(b as i8 as i64),
        // u8
        0xcc => Ok(read_data_u8(rd)? as i64),
        // u16
        0xcd => Ok(read_data_u16(rd)? as i64),
        // u32
        0xce => Ok(read_data_u32_raw(rd)? as i64),
        // u64
        0xcf => {
            let v = read_data_u64_raw(rd)?;
            i64::try_from(v)
                .map_err(|_| codec_err(format!("read_i64: u64 value {v} overflows i64")))
        }
        // i8
        0xd0 => Ok(read_data_u8(rd)? as i8 as i64),
        // i16
        0xd1 => Ok(read_data_i16(rd)? as i64),
        // i32
        0xd2 => Ok(read_data_i32(rd)? as i64),
        // i64
        0xd3 => read_data_i64_raw(rd),
        // nil: go's ReadInt64Bytes maps nil to 0 (issue #2065)
        0xc0 => Ok(0),
        other => Err(codec_err(format!(
            "read_i64: not an integer: 0x{other:02x}"
        ))),
    }
}

/// Read any msgpack integer format and return as u32.
#[inline]
pub fn read_u32(rd: &mut &[u8]) -> Result<u32> {
    let v = read_u64(rd)?;
    u32::try_from(v).map_err(|_| codec_err(format!("read_u32: value {v} overflows u32")))
}

/// Read any msgpack integer format and return as u16.
#[inline]
pub fn read_u16(rd: &mut &[u8]) -> Result<u16> {
    let v = read_u64(rd)?;
    u16::try_from(v).map_err(|_| codec_err(format!("read_u16: value {v} overflows u16")))
}

/// Read any msgpack integer format and return as u8.
#[inline]
pub fn read_u8_val(rd: &mut &[u8]) -> Result<u8> {
    let v = read_u64(rd)?;
    u8::try_from(v).map_err(|_| codec_err(format!("read_u8_val: value {v} overflows u8")))
}

/// Read a msgpack boolean value.
#[inline]
pub fn read_bool(rd: &mut &[u8]) -> Result<bool> {
    if rd.is_empty() {
        return Err(codec_err("read_bool: unexpected EOF"));
    }
    let b = rd[0];
    *rd = &rd[1..];
    match b {
        // 0xc0 nil: go's ReadBoolBytes maps nil to false (issue #2065)
        0xc2 | 0xc0 => Ok(false),
        0xc3 => Ok(true),
        _ => Err(codec_err(format!(
            "read_bool: expected bool marker, got 0x{b:02x}"
        ))),
    }
}

// ── String / bytes readers ─────────────────────────────────────

/// Read a msgpack string as an owned String, losslessly.
///
/// go's `string` fields (`gen`, `proto`, `nextproto`, `upgradeprop`, a
/// transaction's `type`, ...) are arbitrary byte sequences: `msgp.ReadStringZC`
/// only bounds the length and never validates UTF-8 (issue #2397). Valid UTF-8
/// is returned as is; a value with invalid bytes is returned in the bijective
/// [`crate::raw_text`] form (an invalid byte becomes a private-use character)
/// so that re-encoding with `raw_text::decode` reproduces go's exact bytes.
/// This matters for consensus: a proposer may put any byte string of at most
/// `MaxVersionStringLen` bytes in `upgradeprop`, go accepts the block, and the
/// string then lives on in every following header as `nextproto`.
#[inline]
pub fn read_string(rd: &mut &[u8]) -> Result<String> {
    read_go_string_bytes(rd).map(|b| crate::raw_text::encode(&b).into_owned())
}

/// The bytes of a go `string` field as `msgp.ReadStringZC` (used by every
/// generated `string` field) reads them: `str`, `nil` ("", issue #2046) and,
/// go-codec compat (its fallback `readBytesBytes(b, nil, true, false)`), a
/// `bin` or an explicit uint8 array, but not a map (issue #2421).
#[inline]
fn read_go_string_bytes<'a>(rd: &mut &'a [u8]) -> Result<std::borrow::Cow<'a, [u8]>> {
    match rd.first() {
        // the common shape, borrowed
        Some(0xa0..=0xbf | 0xd9 | 0xda | 0xdb) => {
            let len = rmp::decode::read_str_len(rd)
                .map_err(|e| codec_err(format!("read_string str_len: {e}")))?
                as usize;
            if rd.len() < len {
                return Err(codec_err(format!(
                    "read_string: need {len} bytes, have {}",
                    rd.len()
                )));
            }
            let (s, rest) = rd.split_at(len);
            *rd = rest;
            Ok(std::borrow::Cow::Borrowed(s))
        }
        Some(0x80..=0x8f | 0xde | 0xdf) => Err(codec_err("read_string: a map is not a string")),
        _ => read_go_byte_container(rd).map(|g| g.data),
    }
}

/// Read a msgpack `str`-format value as raw bytes, without requiring UTF-8
/// validity.
///
/// go's `string`-typed fields (e.g. `basics.AssetParams.UnitName`/
/// `AssetName`/`URL`, `data/basics/userBalance.go`) are arbitrary byte
/// sequences on the wire -- only length-bounded, never UTF-8-validated
/// (issue #1608). msgpack's "str" format marker itself carries no UTF-8
/// requirement either; it is purely a type tag chosen by the writer. Use
/// this instead of [`read_string`] for any field go declares `string` but
/// that must round-trip byte-for-byte (consensus-critical fields such as
/// `AssetParams` unit_name/asset_name/url).
#[inline]
pub fn read_str_bytes(rd: &mut &[u8]) -> Result<Vec<u8>> {
    // `msgp.ReadStringZC`: nil -> "" (issue #2046), bin / uint8 array too
    read_go_string_bytes(rd).map(std::borrow::Cow::into_owned)
}

// ── go-msgp-compatible byte readers (issue #2046) ──────────────
//
// go-algorand's generated decoders read every `[N]byte` field with
// `msgp.ReadExactBytes` and every `[]byte` field with `msgp.ReadBytesBytes`
// (algorand/msgp v1.1.64, `msgp/read_bytes.go`). Both are deliberately
// go-codec compatible and accept, besides `bin`: `str` markers (fixstr/
// str8/16/32), `nil` (empty slice / zeroed array) and an explicit array of
// uint8. `ReadExactBytes` additionally copies `min(encoded, N)` bytes, so a
// wrong-length value is NOT an error (short input leaves the tail zero, long
// input is truncated). The former strict `bin`-only/exact-length readers
// were removed once every call site (`block.rs`, `header.rs`,
// `transaction.rs`, `pq.rs`) was verified against go's generated decoder
// (per-site evidence in `docs/BYTES_DECODE_PARITY.md`).

/// Payload of one go-msgp byte container plus whether it was written as an
/// explicit array (go's `*Slow` paths).
struct GoBytes<'a> {
    data: std::borrow::Cow<'a, [u8]>,
    from_array: bool,
}

/// Big-endian length field of `n` bytes at `rd[1..]`, if present.
fn be_len(rd: &[u8], n: usize) -> Option<usize> {
    let b = rd.get(1..1 + n)?;
    Some(b.iter().fold(0usize, |acc, &x| (acc << 8) | x as usize))
}

/// Read one go-msgp byte container (`bin`, `str`, `nil`, array of uint8) and
/// return its payload bytes. Mirrors `readBytesBytes` / `ReadExactBytes`.
fn read_go_byte_container<'a>(rd: &mut &'a [u8]) -> Result<GoBytes<'a>> {
    use std::borrow::Cow;
    let truncated = || codec_err("read_go_byte_container: truncated input");
    let marker = *rd.first().ok_or_else(truncated)?;
    // (header bytes, payload length) for the raw bin/str forms.
    let (hdr, len) = match marker {
        0xc0 => {
            *rd = &rd[1..];
            return Ok(GoBytes {
                data: Cow::Borrowed(&[]),
                from_array: false,
            });
        }
        0xa0..=0xbf => (1, (marker & 0x1f) as usize),
        0xd9 | 0xc4 => (2, be_len(rd, 1).ok_or_else(truncated)?),
        0xda | 0xc5 => (3, be_len(rd, 2).ok_or_else(truncated)?),
        0xdb | 0xc6 => (5, be_len(rd, 4).ok_or_else(truncated)?),
        // go-codec compat: explicit array of uint8, or a map read as an
        // interleaved key/value array (`readArrayHeaderBytes(flattenMap)`).
        0x90..=0x9f | 0xdc | 0xdd | 0x80..=0x8f | 0xde | 0xdf => {
            let (n, is_map) = match marker {
                0x90..=0x9f | 0xdc | 0xdd => (
                    rmp::decode::read_array_len(rd)
                        .map_err(|e| codec_err(format!("read_go_byte_container array: {e}")))?
                        as usize,
                    false,
                ),
                _ => (
                    rmp::decode::read_map_len(rd)
                        .map_err(|e| codec_err(format!("read_go_byte_container map: {e}")))?
                        as usize,
                    true,
                ),
            };
            let n = if is_map { n.saturating_mul(2) } else { n };
            // Each element is at least one byte; bound before allocating.
            if rd.len() < n {
                return Err(truncated());
            }
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                // Fast path (issue #2063): positive fixint and uint8 are the
                // forms every encoder emits for a byte element; take them
                // without the generic integer decoder. Identical result.
                match rd.first() {
                    Some(&b) if b < 0x80 => {
                        v.push(b);
                        *rd = &rd[1..];
                        continue;
                    }
                    Some(&0xcc) if rd.len() >= 2 => {
                        v.push(rd[1]);
                        *rd = &rd[2..];
                        continue;
                    }
                    _ => {}
                }
                // go ReadUint8Bytes = ReadUint64Bytes (fixint, uint8-64,
                // non-negative int8-64, nil -> 0) + a > 255 overflow check.
                let e = if rd.first() == Some(&0xc0) {
                    *rd = &rd[1..];
                    0
                } else {
                    read_u64(rd)?
                };
                v.push(u8::try_from(e).map_err(|_| {
                    codec_err(format!("read_go_byte_container: element {e} exceeds u8"))
                })?);
            }
            return Ok(GoBytes {
                data: Cow::Owned(v),
                from_array: true,
            });
        }
        other => {
            return Err(codec_err(format!(
                "read_go_byte_container: unexpected marker 0x{other:02x}"
            )));
        }
    };
    let body = &rd[hdr..];
    if body.len() < len {
        return Err(codec_err(format!(
            "read_go_byte_container: need {len} bytes, have {}",
            body.len()
        )));
    }
    *rd = &body[len..];
    Ok(GoBytes {
        data: Cow::Borrowed(&body[..len]),
        from_array: false,
    })
}

/// go `msgp.ReadBytesBytes`: a `[]byte` field. Accepts `bin`, `str`, `nil`
/// (empty), an array of uint8 and a map read as an interleaved array.
#[inline]
pub fn read_bytes_go_compat(rd: &mut &[u8]) -> Result<Vec<u8>> {
    read_go_byte_container(rd).map(|g| g.data.into_owned())
}

/// [`read_bytes_go_compat`] as a `serde_bytes::ByteBuf`.
#[inline]
pub fn read_bytes_as_bytebuf_go_compat(rd: &mut &[u8]) -> Result<ByteBuf> {
    read_bytes_go_compat(rd).map(ByteBuf::from)
}

/// go `msgp.ReadExactBytes`: a `[N]byte` field. Accepts `bin`, `str`, `nil`
/// (zeroed) and an array of uint8; copies `min(encoded, N)` bytes (go does
/// not enforce the length for bin/str), leaving any tail zero. The explicit
/// array form is the exception: go's `readExactBytesSlow` rejects more than
/// N elements (`ArrayError`).
#[inline]
pub fn read_fixed_bytes_go_compat<const N: usize>(rd: &mut &[u8]) -> Result<[u8; N]> {
    let mut arr = [0u8; N];
    read_fixed_bytes_into_go_compat(rd, &mut arr)?;
    Ok(arr)
}

/// go `msgp.ReadExactBytes(b, into)` into an already decoded `[N]byte`
/// (issue #2421: a repeated key decodes into the populated field): `nil`
/// zeroes it, any other value overwrites only its first `min(encoded, N)`
/// bytes and leaves the rest as they were (a shorter repeated value keeps the
/// earlier tail). An explicit array of more than N elements is an error.
#[inline]
pub fn read_fixed_bytes_into_go_compat(rd: &mut &[u8], into: &mut [u8]) -> Result<()> {
    if rd.first() == Some(&0xc0) {
        *rd = &rd[1..];
        into.fill(0);
        return Ok(());
    }
    let g = read_go_byte_container(rd)?;
    if g.from_array && g.data.len() > into.len() {
        return Err(codec_err(format!(
            "read_fixed_bytes_go_compat: array of {} elements for [{}]byte",
            g.data.len(),
            into.len()
        )));
    }
    let n = g.data.len().min(into.len());
    into[..n].copy_from_slice(&g.data[..n]);
    Ok(())
}

/// A `basics.Address` field (go: `Address.UnmarshalMsg` -> `ReadExactBytes`).
#[inline]
pub fn read_address_go_compat(rd: &mut &[u8]) -> Result<Address> {
    read_fixed_bytes_go_compat::<32>(rd).map(Address)
}

// ── Nil helpers ────────────────────────────────────────────────

/// Peek at the next byte to check if it is nil (0xc0) without consuming.
#[inline]
pub fn is_nil(rd: &[u8]) -> bool {
    !rd.is_empty() && rd[0] == 0xc0
}

/// Consume a nil marker. Returns error if next byte is not nil.
#[inline]
#[allow(dead_code)]
pub fn read_nil(rd: &mut &[u8]) -> Result<()> {
    rmp::decode::read_nil(rd).map_err(|e| codec_err(format!("read_nil: {e}")))
}

/// If the next byte is nil (0xc0), consume it and return true. Otherwise return false.
#[inline]
pub fn try_read_nil(rd: &mut &[u8]) -> bool {
    if is_nil(rd) {
        *rd = &rd[1..];
        true
    } else {
        false
    }
}

// ── Optional / collection readers ──────────────────────────────

/// If the next value is nil, return None. Otherwise call `decode_fn` and wrap in Some.
#[inline]
pub fn read_optional<T>(
    rd: &mut &[u8],
    decode_fn: impl FnOnce(&mut &[u8]) -> Result<T>,
) -> Result<Option<T>> {
    if try_read_nil(rd) {
        Ok(None)
    } else {
        decode_fn(rd).map(Some)
    }
}

/// Fail like go's generated decoders when a byte string claims more than
/// `bound` bytes: they read `msgp.ReadBytesBytesHeader` and compare it to the
/// field's `allocbound` before reading the value (`msgp.ErrOverflow`). Peeks; the
/// value is not consumed. The size is the encoded length of a `bin`/`str`, the
/// element count of an array (a map counts twice its pairs) and 0 for `nil`.
#[inline]
pub fn check_go_bytes_bound(rd: &[u8], bound: usize) -> Result<()> {
    // the shapes every encoder writes, within the bound: no further work
    let size = match *rd {
        [b @ 0xa0..=0xbf, ..] => (b & 0x1f) as usize,
        [0xc0, ..] => 0,
        [0xc4 | 0xd9, n, ..] => n as usize,
        [0xc5 | 0xda, a, b, ..] => u16::from_be_bytes([a, b]) as usize,
        _ => usize::MAX,
    };
    if size <= bound {
        return Ok(());
    }
    check_go_bytes_bound_slow(rd, bound)
}

#[cold]
#[inline(never)]
fn check_go_bytes_bound_slow(rd: &[u8], bound: usize) -> Result<()> {
    if !alloc_bounds_checked() {
        return Ok(());
    }
    let short = || codec_err("check_go_bytes_bound: truncated input");
    let be = |n: usize| -> Result<usize> {
        let b = rd.get(1..1 + n).ok_or_else(short)?;
        Ok(b.iter().fold(0usize, |a, &x| (a << 8) | x as usize))
    };
    let lead = *rd.first().ok_or_else(short)?;
    let size = match lead {
        0xa0..=0xbf => (lead & 0x1f) as usize,
        0x90..=0x9f => (lead & 0x0f) as usize,
        0x80..=0x8f => 2 * (lead & 0x0f) as usize,
        0xc0 => 0,
        0xc4 | 0xd9 => be(1)?,
        0xc5 | 0xda | 0xdc => be(2)?,
        0xc6 | 0xdb | 0xdd => be(4)?,
        0xde => 2 * be(2)?,
        0xdf => 2 * be(4)?,
        other => {
            return Err(codec_err(format!(
                "check_go_bytes_bound: unexpected marker 0x{other:02x}"
            )))
        }
    };
    if size > bound {
        return Err(codec_err(format!(
            "check_go_bytes_bound: length {size} exceeds the allocation bound {bound}"
        )));
    }
    Ok(())
}

/// A go `string` field with an `allocbound` (issue #2427): the bound is
/// checked on the length header ([`check_go_bytes_bound`]), then the value is
/// read with [`read_string`].
#[inline]
pub fn read_bounded_string(rd: &mut &[u8], bound: usize) -> Result<String> {
    check_go_bytes_bound(rd, bound)?;
    read_string(rd)
}

/// [`read_bounded_string`] keeping the raw bytes ([`read_str_bytes`]).
#[inline]
pub fn read_bounded_str_bytes(rd: &mut &[u8], bound: usize) -> Result<Vec<u8>> {
    check_go_bytes_bound(rd, bound)?;
    read_str_bytes(rd)
}

/// A go `[]byte` field with an `allocbound` (issue #2427), checked on the
/// length header before the value is read.
#[inline]
pub fn read_bounded_bytebuf(rd: &mut &[u8], bound: usize) -> Result<ByteBuf> {
    check_go_bytes_bound(rd, bound)?;
    read_bytes_as_bytebuf_go_compat(rd)
}

/// go's check of a map field's `allocbound` on the entry count of its header
/// (`msgp.ErrOverflow`); none in [`go_codec_reflect`] mode.
#[inline]
pub fn check_go_map_bound(n: usize, bound: usize) -> Result<()> {
    if n > bound && alloc_bounds_checked() {
        return Err(codec_err(format!(
            "read_map: {n} entries exceed the allocation bound {bound}"
        )));
    }
    Ok(())
}

/// Read an rmpv::Value from the reader (for opaque passthrough fields like eval_delta).
#[inline]
pub fn read_rmpv_value(rd: &mut &[u8]) -> Result<rmpv::Value> {
    rmpv::decode::read_value(rd).map_err(|e| codec_err(format!("read_rmpv_value: {e}")))
}

/// Read an optional rmpv::Value. If nil, return None.
#[inline]
pub fn read_optional_rmpv(rd: &mut &[u8]) -> Result<Option<rmpv::Value>> {
    if try_read_nil(rd) {
        Ok(None)
    } else {
        read_rmpv_value(rd).map(Some)
    }
}

/// [`read_optional_rmpv`] for a value go decodes with a generated msgp
/// decoder: first check, against `sch`, that it holds no key go's struct lacks
/// (issue #2394), since the value itself is carried opaque.
pub(crate) fn read_checked_optional_rmpv(
    rd: &mut &[u8],
    sch: &crate::msgp_schema::Sch,
) -> Result<Option<rmpv::Value>> {
    if !is_nil(rd) {
        let mut probe = *rd;
        crate::msgp_schema::validate(&mut probe, sch)?;
    }
    read_optional_rmpv(rd)
}

// ── Decoding INTO an already decoded value (issues #2421, #2424) ─────
//
// go's generated `UnmarshalMsg` decodes every field in place, so a map key
// that occurs again is decoded again INTO the field it already filled:
//
// - a struct value is merged: the fields the repeat does not mention keep
//   their first value; a `nil` in place of its map resets the whole struct to
//   its zero value (`(*z) = T{}`), and the struct's `required` checks run on
//   the result either way;
// - a slice is re-sliced to the new length when its capacity allows
//   (`cap(z.X) >= n`: each element decoded INTO the element already there) and
//   is a fresh `make([]T, n)` otherwise; `nil` makes it nil;
// - a `[N]byte` keeps the bytes past a shorter value (`msgp.ReadExactBytes`),
//   `nil` zeroes it;
// - a map is reused and gains (or overwrites) entries, each value fresh;
// - scalars, strings and `[]byte` are overwritten.
//
// The readers below are the building blocks of every struct reader's
// `decode_into`.

use std::any::{Any, TypeId};
use std::cell::RefCell;

/// The `nil`-aware map header of a struct value decoded into `s`: `nil`
/// resets `s` to its zero value (go `(*z) = T{}`) and reads as no entries.
#[inline]
pub fn read_struct_map_len<T: Default>(rd: &mut &[u8], s: &mut T) -> Result<u32> {
    // DIVERGENCE DIV-004: only the map form is read; go's struct-from-array
    // branch (ReadArrayHeaderBytes fallback) is intentionally not supported.
    if let [0xc0, rest @ ..] = *rd {
        *rd = rest;
        *s = T::default();
        return Ok(0);
    }
    rmp::decode::read_map_len(rd).map_err(|e| codec_err(format!("read_map_len: {e}")))
}

/// A go value-typed struct field kept as an `Option` (`None` is its zero
/// value): decoded into the populated value. A `nil` still runs `into` on a
/// zero value, so the struct's `required` checks see it as go's do, and
/// leaves the field `None`.
#[inline]
pub fn read_struct_into_opt<T: Default>(
    rd: &mut &[u8],
    slot: &mut Option<T>,
    into: impl FnOnce(&mut &[u8], &mut T) -> Result<()>,
) -> Result<()> {
    if is_nil(rd) {
        let mut zero = T::default();
        into(rd, &mut zero)?;
        *slot = None;
        return Ok(());
    }
    into(rd, slot.get_or_insert_with(T::default))
}

/// A go pointer field (`*T`): `nil` makes it nil, anything else is decoded
/// into the pointed-to value, allocated when the pointer is nil.
#[inline]
pub fn read_pointer_into<T: Default>(
    rd: &mut &[u8],
    slot: &mut Option<T>,
    into: impl FnOnce(&mut &[u8], &mut T) -> Result<()>,
) -> Result<()> {
    if try_read_nil(rd) {
        *slot = None;
        return Ok(());
    }
    into(rd, slot.get_or_insert_with(T::default))
}

/// A go `[N]byte` field kept as an `Option` (`None` is all zeros), read with
/// `msgp.ReadExactBytes` into the populated value.
#[inline]
pub fn read_fixed_into_opt<const N: usize>(
    rd: &mut &[u8],
    slot: &mut Option<[u8; N]>,
) -> Result<()> {
    if try_read_nil(rd) {
        *slot = None;
        return Ok(());
    }
    read_fixed_bytes_into_go_compat(rd, slot.get_or_insert([0u8; N]))
}

/// [`read_fixed_into_opt`] for a `basics.Address`.
#[inline]
pub fn read_address_into_opt(rd: &mut &[u8], slot: &mut Option<Address>) -> Result<()> {
    if try_read_nil(rd) {
        *slot = None;
        return Ok(());
    }
    read_fixed_bytes_into_go_compat(rd, &mut slot.get_or_insert(Address([0u8; 32])).0)
}

/// go `msgp.ReadArrayHeaderBytes` (algorand/msgp v1.1.64): an array header,
/// `nil` (no elements, `isnil`) and, go-codec compat, a fixmap read as the
/// interleaved key/value array of twice its entries. A map16/map32 is a type
/// error.
#[inline]
pub fn read_go_array_header(rd: &mut &[u8]) -> Result<(usize, bool)> {
    match *rd {
        [m @ 0x90..=0x9f, ref rest @ ..] => {
            *rd = rest;
            Ok(((m & 0x0f) as usize, false))
        }
        [m @ 0x80..=0x8f, ref rest @ ..] => {
            *rd = rest;
            Ok((2 * (m & 0x0f) as usize, false))
        }
        [0xc0, ref rest @ ..] => {
            *rd = rest;
            Ok((0, true))
        }
        _ => rmp::decode::read_array_len(rd)
            .map(|n| (n as usize, false))
            .map_err(|e| codec_err(format!("read_array_len: {e}"))),
    }
}

thread_local! {
    /// The hidden elements of re-sliced slices (see [`read_slice_into`]),
    /// keyed by the slice's buffer address and element type. Only a repeated
    /// key that shrinks a slice adds an entry; [`DecodeSession`] empties it.
    static SLICE_SPARE: RefCell<Vec<SpareEntry>> = const { RefCell::new(Vec::new()) };
    /// `SLICE_SPARE.len()`, readable without a borrow (the common case is 0).
    static SPARE_LEN: Cell<usize> = const { Cell::new(0) };
    static SESSION_DEPTH: Cell<u32> = const { Cell::new(0) };
    static SPARE_PUTS: Cell<u64> = const { Cell::new(0) };
}

/// (buffer address, buffer capacity, element type, the hidden `Vec<T>`).
type SpareEntry = (usize, usize, TypeId, Box<dyn Any>);

/// Scope of one top-level decode: the hidden slice capacity
/// [`read_slice_into`] tracks lives until the outermost session ends. Every
/// public decoder entry point holds one; nested ones are free.
#[must_use = "the session ends when the guard is dropped"]
pub struct DecodeSession {
    /// `!Send`: the state is per-thread.
    _not_send: std::marker::PhantomData<*const ()>,
}

/// Start a [`DecodeSession`] (or join the one already running on this thread).
#[inline]
pub fn decode_session() -> DecodeSession {
    SESSION_DEPTH.with(|d| d.set(d.get() + 1));
    DecodeSession {
        _not_send: std::marker::PhantomData,
    }
}

impl Drop for DecodeSession {
    #[inline]
    fn drop(&mut self) {
        let depth = SESSION_DEPTH.with(|d| {
            let n = d.get().saturating_sub(1);
            d.set(n);
            n
        });
        if depth == 0 {
            clear_slice_spare();
        }
    }
}

#[inline]
fn clear_slice_spare() {
    crate::go_eval_delta::clear_kept();
    if SPARE_LEN.with(Cell::get) == 0 {
        return;
    }
    let dropped = SLICE_SPARE.with(|s| s.try_borrow_mut().map(|mut s| std::mem::take(&mut *s)));
    SPARE_LEN.with(|c| c.set(0));
    // the hidden elements are dropped outside the borrow
    drop(dropped);
}

/// Remove and return the hidden elements recorded for the buffer of `v`.
#[inline]
fn take_spare<T: 'static>(v: &Vec<T>) -> Vec<T> {
    if v.capacity() == 0 || SPARE_LEN.with(Cell::get) == 0 {
        return Vec::new();
    }
    take_spare_slow(v.as_ptr() as usize, v.capacity())
}

#[cold]
fn take_spare_slow<T: 'static>(addr: usize, cap: usize) -> Vec<T> {
    let found = SLICE_SPARE.with(|s| {
        let mut s = s.borrow_mut();
        let ty = TypeId::of::<T>();
        let i = s
            .iter()
            .position(|(a, c, t, _)| *a == addr && *c == cap && *t == ty)?;
        let e = s.swap_remove(i);
        SPARE_LEN.with(|c| c.set(s.len()));
        Some(e.3)
    });
    found
        .and_then(|b| b.downcast::<Vec<T>>().ok())
        .map(|b| *b)
        .unwrap_or_default()
}

/// How many hidden-capacity records this thread has made (a counter; it
/// changes whenever a repeated key shrinks a slice).
#[inline]
pub(crate) fn spare_records() -> u64 {
    SPARE_PUTS.with(Cell::get)
}

/// Whether hidden elements are recorded for the buffer of `v`.
pub(crate) fn has_spare<T: 'static>(v: &Vec<T>) -> bool {
    if v.capacity() == 0 || SPARE_LEN.with(Cell::get) == 0 {
        return false;
    }
    let (addr, cap, ty) = (v.as_ptr() as usize, v.capacity(), TypeId::of::<T>());
    SLICE_SPARE.with(|s| {
        s.borrow()
            .iter()
            .any(|(a, c, t, _)| *a == addr && *c == cap && *t == ty)
    })
}

#[cold]
fn put_spare<T: 'static>(v: &Vec<T>, spare: Vec<T>) {
    SPARE_PUTS.with(|c| c.set(c.get().wrapping_add(1)));
    SLICE_SPARE.with(|s| {
        let mut s = s.borrow_mut();
        s.push((
            v.as_ptr() as usize,
            v.capacity(),
            TypeId::of::<T>(),
            Box::new(spare),
        ));
        SPARE_LEN.with(|c| c.set(s.len()));
    });
}

/// A go slice field decoded into its already decoded value, exactly as go's
/// generated code does: `nil` empties it (go: nil); for `n` elements the
/// existing slice is re-sliced when its capacity allows (`cap(z.X) >= n`:
/// `z.X[:n]`, each element decoded INTO the element already there, so it keeps
/// what the new element does not mention, and a shorter re-slice hides the
/// elements past `n` until a longer one brings them back), and is otherwise a
/// fresh slice of `n` zero elements. More than `bound` elements is go's
/// `msgp.ErrOverflow`. Returns whether the value was `nil`.
pub fn read_slice_into<T: 'static>(
    rd: &mut &[u8],
    v: &mut Vec<T>,
    bound: usize,
    zero: impl Fn() -> T,
    mut item: impl FnMut(&mut &[u8], &mut T) -> Result<()>,
) -> Result<bool> {
    let (n, nil) = read_go_array_header(rd)?;
    if n > bound && alloc_bounds_checked() {
        return Err(codec_err(format!(
            "read_slice: {n} elements exceed the allocation bound {bound}"
        )));
    }
    let mut spare = take_spare(v);
    if nil {
        *v = Vec::new();
        return Ok(true);
    }
    if v.len() + spare.len() >= n {
        if n <= v.len() {
            let mut hidden: Vec<T> = v.drain(n..).collect();
            hidden.append(&mut spare);
            spare = hidden;
        } else {
            let rest = spare.split_off(n - v.len());
            v.append(&mut spare);
            spare = rest;
        }
    } else {
        // every element is at least one byte: bound the allocation by the input
        if rd.len() < n {
            return Err(codec_err(format!(
                "read_slice: {n} elements, {} bytes left",
                rd.len()
            )));
        }
        // (an empty slice grows alike in both decoders: the common case)
        if !v.is_empty() && reflect_mode() {
            grow_keeping_elements(v, n, &zero);
        } else {
            let mut fresh = Vec::with_capacity(n);
            fresh.extend((0..n).map(|_| zero()));
            // a stale record for a freed buffer at the same address
            drop(take_spare(&fresh));
            *v = fresh;
        }
        spare = Vec::new();
    }
    if !spare.is_empty() {
        put_spare(v, spare);
    }
    for e in v.iter_mut() {
        item(rd, e)?;
    }
    Ok(false)
}

/// go-codec (`kSlice`) grows a repeated slice past its capacity by copying its
/// elements (up to its length, not its capacity: the hidden ones are dropped)
/// into the new one, then decodes each element INTO what is there (issue
/// #2427, read with the strict-decode oracle); msgp makes a fresh slice.
#[cold]
#[inline(never)]
fn grow_keeping_elements<T: 'static>(v: &mut Vec<T>, n: usize, zero: &impl Fn() -> T) {
    v.reserve_exact(n - v.len());
    v.resize_with(n, zero);
    // a stale record for a freed buffer at the same address
    drop(take_spare(v));
}

/// [`read_slice_into`] for a slice kept as an `Option` (`None` is go's nil).
#[inline]
pub fn read_slice_into_opt<T: 'static>(
    rd: &mut &[u8],
    slot: &mut Option<Vec<T>>,
    bound: usize,
    zero: impl Fn() -> T,
    item: impl FnMut(&mut &[u8], &mut T) -> Result<()>,
) -> Result<()> {
    let v = slot.get_or_insert_with(Vec::new);
    if read_slice_into(rd, v, bound, zero, item)? {
        *slot = None;
    }
    Ok(())
}

/// A go fixed array `[N]T` (`msgp.ReadArrayHeaderBytes`, then at most N
/// elements, each decoded into the element already there; more than N is an
/// `msgp.ArrayError`, fewer leaves the rest as they were).
#[inline]
pub fn read_fixed_array_into<T>(
    rd: &mut &[u8],
    a: &mut [T],
    mut item: impl FnMut(&mut &[u8], &mut T) -> Result<()>,
) -> Result<()> {
    let (n, _) = read_go_array_header(rd)?;
    if n > a.len() {
        return Err(codec_err(format!(
            "read_fixed_array: {n} elements for a [{}] array",
            a.len()
        )));
    }
    for e in &mut a[..n] {
        item(rd, e)?;
    }
    Ok(())
}

/// A go `map[uint64]T` decoded into its populated value: `nil` makes it nil,
/// anything else adds (or overwrites) entries, each value decoded fresh. More
/// than `bound` entries is go's `msgp.ErrOverflow`.
#[inline]
pub fn read_u64_map_into<T>(
    rd: &mut &[u8],
    slot: &mut Option<std::collections::BTreeMap<u64, T>>,
    bound: usize,
    decode_fn: impl Fn(&mut &[u8]) -> Result<T>,
) -> Result<()> {
    if try_read_nil(rd) {
        *slot = None;
        return Ok(());
    }
    let len = read_map_len(rd)?;
    check_go_map_bound(len as usize, bound)?;
    let map = slot.get_or_insert_with(std::collections::BTreeMap::new);
    for _ in 0..len {
        let key = read_u64(rd)?;
        let value = decode_fn(rd)?;
        map.insert(key, value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skip_nil() {
        let data = [0xc0]; // nil
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_fixint() {
        let data = [0x05]; // fixint 5
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_negfixint() {
        let data = [0xff]; // fixneg -1
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_string() {
        // fixstr "hi" = 0xa2 0x68 0x69
        let data = [0xa2, 0x68, 0x69];
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_map() {
        // fixmap(1) { fixstr("a"): fixint(1) } = 0x81 0xa1 0x61 0x01
        let data = [0x81, 0xa1, 0x61, 0x01];
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_array() {
        // fixarray(2) [fixint 1, fixint 2] = 0x92 0x01 0x02
        let data = [0x92, 0x01, 0x02];
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_read_u64_fixint() {
        let data = [42u8];
        let mut rd = &data[..];
        assert_eq!(read_u64(&mut rd).unwrap(), 42);
    }

    #[test]
    fn test_read_u64_from_u16() {
        // u16 marker=0xcd, value=0x01 0x00 = 256
        let data = [0xcd, 0x01, 0x00];
        let mut rd = &data[..];
        assert_eq!(read_u64(&mut rd).unwrap(), 256);
    }

    #[test]
    fn test_read_i64_negative() {
        // negative fixint -5 = 0xfb
        let data = [0xfb];
        let mut rd = &data[..];
        assert_eq!(read_i64(&mut rd).unwrap(), -5);
    }

    #[test]
    fn test_read_string() {
        // fixstr "pay" = 0xa3 p a y
        let data = [0xa3, b'p', b'a', b'y'];
        let mut rd = &data[..];
        assert_eq!(read_string(&mut rd).unwrap(), "pay");
    }

    /// Issue #2397: a go `string` may hold any bytes; reading keeps them
    /// losslessly (valid UTF-8 unchanged).
    #[test]
    fn read_string_keeps_non_utf8_bytes_losslessly() {
        let data = [0xa3, 0xff, b'a', 0xc3];
        let mut rd = &data[..];
        let s = read_string(&mut rd).unwrap();
        assert!(rd.is_empty());
        assert_eq!(crate::raw_text::decode(&s).as_ref(), &data[1..]);
        let mut rd = &[0xa2, 0xc3, 0xa9][..];
        assert_eq!(read_string(&mut rd).unwrap(), "\u{e9}");
    }

    #[test]
    fn test_read_key_bytes() {
        // fixstr "fee" = 0xa3 f e e
        let data = [0xa3, b'f', b'e', b'e'];
        let mut rd = &data[..];
        assert_eq!(read_key_bytes(&mut rd).unwrap(), b"fee");
    }

    // go-msgp differential vectors (issue #2046). Expected values follow
    // algorand/msgp v1.1.64 `ReadExactBytes` / `ReadBytesBytes` /
    // `ReadStringZC` (`msgp/read_bytes.go`), read from source.
    fn all_encodings_of_123() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("bin8", vec![0xc4, 3, 1, 2, 3]),
            ("bin16", vec![0xc5, 0, 3, 1, 2, 3]),
            ("bin32", vec![0xc6, 0, 0, 0, 3, 1, 2, 3]),
            ("fixstr", vec![0xa3, 1, 2, 3]),
            ("str8", vec![0xd9, 3, 1, 2, 3]),
            ("str16", vec![0xda, 0, 3, 1, 2, 3]),
            ("str32", vec![0xdb, 0, 0, 0, 3, 1, 2, 3]),
            ("fixarray", vec![0x93, 1, 2, 3]),
            ("array16", vec![0xdc, 0, 3, 1, 2, 3]),
        ]
    }

    #[test]
    fn go_compat_bytes_accepts_every_go_encoding() {
        for (name, enc) in all_encodings_of_123() {
            let mut rd = &enc[..];
            assert_eq!(
                read_bytes_go_compat(&mut rd).unwrap(),
                vec![1, 2, 3],
                "{name}"
            );
            assert!(rd.is_empty(), "{name} fully consumed");
            let mut rd = &enc[..];
            assert_eq!(
                read_fixed_bytes_go_compat::<4>(&mut rd).unwrap(),
                [1, 2, 3, 0],
                "{name}"
            );
            assert!(rd.is_empty(), "{name} fully consumed");
        }
    }

    #[test]
    fn go_compat_nil_and_length_semantics() {
        // ReadBytesBytes: nil -> empty; ReadExactBytes: nil -> zeroed array.
        let mut rd: &[u8] = &[0xc0, 0xff];
        assert!(read_bytes_go_compat(&mut rd).unwrap().is_empty());
        assert_eq!(rd, &[0xff]);
        let mut rd: &[u8] = &[0xc0];
        assert_eq!(read_fixed_bytes_go_compat::<4>(&mut rd).unwrap(), [0; 4]);
        // ReadExactBytes copies min(encoded, N): long input truncated.
        let mut rd: &[u8] = &[0xc4, 5, 1, 2, 3, 4, 5];
        assert_eq!(
            read_fixed_bytes_go_compat::<4>(&mut rd).unwrap(),
            [1, 2, 3, 4]
        );
        assert!(rd.is_empty());
        // Address from a str-encoded 32 bytes.
        let mut enc = vec![0xd9, 32];
        enc.extend_from_slice(&[9u8; 32]);
        let mut rd = &enc[..];
        assert_eq!(read_address_go_compat(&mut rd).unwrap().0, [9u8; 32]);
    }

    #[test]
    fn go_compat_array_element_encodings_match_go_readuint8() {
        // go ReadUint8Bytes = ReadUint64Bytes + >255 check: accepts fixint,
        // uint8/16/32/64 (value <= 255), non-negative int8..int64, nil -> 0.
        let ok: &[(&[u8], &[u8])] = &[
            (
                &[0x93, 0x7f, 0xcc, 0xff, 0xcd, 0x00, 0x2a],
                &[0x7f, 0xff, 0x2a],
            ),
            (&[0x92, 0xd0, 0x05, 0xd1, 0x00, 0x06], &[5, 6]), // int8/int16 >= 0
            (
                &[0x92, 0xce, 0, 0, 0, 7, 0xcf, 0, 0, 0, 0, 0, 0, 0, 8],
                &[7, 8],
            ),
            (&[0x92, 0xc0, 0x01], &[0, 1]), // nil element -> 0
            (&[0xdc, 0x00, 0x02, 0x01, 0x02], &[1, 2]), // array16
            (&[0xdd, 0, 0, 0, 2, 0x01, 0x02], &[1, 2]), // array32
            (&[0x82, 0x01, 0x02, 0x03, 0x04], &[1, 2, 3, 4]), // fixmap flattened
            (&[0xde, 0, 1, 0x09, 0x0a], &[9, 10]), // map16 flattened
        ];
        for (enc, want) in ok {
            let mut rd = *enc;
            assert_eq!(read_bytes_go_compat(&mut rd).unwrap(), *want, "{enc:02x?}");
            assert!(rd.is_empty());
        }
        let bad: &[&[u8]] = &[
            &[0x91, 0xff],             // negative fixint
            &[0x91, 0xd0, 0xff],       // int8 -1
            &[0x91, 0xd1, 0xff, 0xfe], // int16 -2
            &[0x91, 0xcd, 0x01, 0x00], // uint16 256 > u8
        ];
        for enc in bad {
            let mut rd = *enc;
            assert!(read_bytes_go_compat(&mut rd).is_err(), "{enc:02x?}");
        }
        // Fixed arrays: the explicit-array form rejects more than N elements
        // (go readExactBytesSlow ArrayError); fewer leaves the tail zero.
        let mut rd: &[u8] = &[0x93, 1, 2, 3];
        assert!(read_fixed_bytes_go_compat::<2>(&mut rd).is_err());
        let mut rd: &[u8] = &[0x92, 1, 2];
        assert_eq!(
            read_fixed_bytes_go_compat::<4>(&mut rd).unwrap(),
            [1, 2, 0, 0]
        );
    }

    #[test]
    fn go_compat_bytes_rejects_what_go_rejects() {
        // A bare integer is not a byte container (go: badPrefix(BinType)).
        for bad in [
            &[0x05u8][..],
            &[0xc3],                   // true
            &[0x81, 0xa1, 0x61, 0x01], // map whose key is not a uint8
            &[0xc4, 3, 1, 2],          // short bin
            &[0xa3, 1, 2],             // short str
            &[0x92, 1, 0xcd, 1, 0],    // array element > u8
            &[],                       // empty input
        ] {
            let mut rd = bad;
            assert!(read_bytes_go_compat(&mut rd).is_err(), "{bad:02x?}");
            let mut rd = bad;
            assert!(
                read_fixed_bytes_go_compat::<4>(&mut rd).is_err(),
                "{bad:02x?}"
            );
        }
        // A huge array header must not allocate before the bound check.
        let mut rd: &[u8] = &[0xdd, 0xff, 0xff, 0xff, 0xff, 1];
        assert!(read_bytes_go_compat(&mut rd).is_err());
    }

    #[test]
    fn go_compat_array_fast_path_matches_generic_decoder() {
        // Large uint8 array (fixint + uint8 elements): same bytes as bin form.
        let want: Vec<u8> = (0..70_000u32).map(|i| (i % 256) as u8).collect();
        let mut enc = vec![0xdd];
        enc.extend_from_slice(&(want.len() as u32).to_be_bytes());
        for &b in &want {
            if b < 0x80 {
                enc.push(b);
            } else {
                enc.extend_from_slice(&[0xcc, b]);
            }
        }
        let mut rd = &enc[..];
        assert_eq!(read_bytes_go_compat(&mut rd).unwrap(), want);
        assert!(rd.is_empty());
        // Truncated uint8 element still errors (fast path must not read past).
        let mut rd: &[u8] = &[0x92, 0x01, 0xcc];
        assert!(read_bytes_go_compat(&mut rd).is_err());
    }

    #[test]
    fn string_readers_map_nil_to_empty_like_go() {
        // go ReadStringZC: nil -> "".
        let mut rd: &[u8] = &[0xc0, 0xa1, b'x'];
        assert_eq!(read_string(&mut rd).unwrap(), "");
        assert_eq!(read_string(&mut rd).unwrap(), "x");
        let mut rd: &[u8] = &[0xc0];
        assert!(read_str_bytes(&mut rd).unwrap().is_empty());
        // ... and a bin is one too: ReadStringZC has no mbin case, but its
        // default branch falls back to go-codec's `readBytesBytes` (issue
        // #2421; go's oracle accepts a `bin` catchpoint label).
        assert_eq!(read_string(&mut &[0xc4u8, 1, 65][..]).unwrap(), "A");
        assert_eq!(read_str_bytes(&mut &[0xc4u8, 1, 65][..]).unwrap(), b"A");
    }

    #[test]
    fn test_try_read_nil() {
        let data = [0xc0, 0x05]; // nil, then fixint 5
        let mut rd = &data[..];
        assert!(try_read_nil(&mut rd));
        assert_eq!(rd.len(), 1);
        assert!(!try_read_nil(&mut rd));
        assert_eq!(rd.len(), 1); // didn't consume non-nil
    }

    #[test]
    fn test_read_optional_some() {
        let data = [42u8]; // fixint 42
        let mut rd = &data[..];
        let result = read_optional(&mut rd, read_u64).unwrap();
        assert_eq!(result, Some(42));
    }

    #[test]
    fn test_read_optional_none() {
        let data = [0xc0]; // nil
        let mut rd = &data[..];
        let result = read_optional(&mut rd, read_u64).unwrap();
        assert_eq!(result, None);
    }

    fn u64_into(rd: &mut &[u8], e: &mut u64) -> Result<()> {
        *e = read_u64(rd)?;
        Ok(())
    }

    #[test]
    fn test_read_vec_u64() {
        // fixarray(3) [1, 2, 3]
        let data = [0x93, 0x01, 0x02, 0x03];
        let mut rd = &data[..];
        let mut v = Vec::new();
        read_slice_into(&mut rd, &mut v, usize::MAX, || 0, u64_into).unwrap();
        assert_eq!(v, vec![1, 2, 3]);
    }

    #[test]
    fn test_read_bool_true() {
        let data = [0xc3]; // true
        let mut rd = &data[..];
        assert!(read_bool(&mut rd).unwrap());
    }

    #[test]
    fn test_read_bool_false() {
        let data = [0xc2]; // false
        let mut rd = &data[..];
        assert!(!read_bool(&mut rd).unwrap());
    }

    #[test]
    fn test_skip_nested_map() {
        // fixmap(1) { fixstr("k"): fixmap(1) { fixstr("n"): fixint(1) } }
        // 0x81 0xa1 0x6b 0x81 0xa1 0x6e 0x01
        let data = [0x81, 0xa1, 0x6b, 0x81, 0xa1, 0x6e, 0x01];
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_bool() {
        let data = [0xc3]; // true
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_u8() {
        let data = [0xcc, 0xff]; // u8 255
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_u64() {
        // u64 marker + 8 bytes
        let data = [0xcf, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    /// Issue #642: a u64/i64 marker followed by fewer than 8 data bytes (a
    /// truncated wire message, exactly the kind of malformed input an
    /// attacker controls) must return `Err`, not panic via out-of-bounds
    /// slice indexing in `read_data_u64_raw`/`read_data_i64_raw`. Audited
    /// during the panic-hardening pass and confirmed already correctly
    /// guarded (`if rd.len() < 8 { return Err(...) }` precedes the slice
    /// index in both); this test pins that guard against regression.
    #[test]
    fn read_u64_truncated_after_marker_does_not_panic() {
        for len in 0..8 {
            let mut data = vec![0xcfu8];
            data.extend(std::iter::repeat_n(0u8, len));
            let mut rd = &data[..];
            let result = read_u64(&mut rd);
            assert!(
                result.is_err(),
                "u64 marker + {len} data bytes must be rejected, not accepted or panic"
            );
        }
    }

    #[test]
    fn read_i64_truncated_after_marker_does_not_panic() {
        for len in 0..8 {
            let mut data = vec![0xd3u8];
            data.extend(std::iter::repeat_n(0u8, len));
            let mut rd = &data[..];
            let result = read_i64(&mut rd);
            assert!(
                result.is_err(),
                "i64 marker + {len} data bytes must be rejected, not accepted or panic"
            );
        }
    }

    /// Issue #2065: go's `ReadUint64Bytes` / `ReadInt64Bytes` /
    /// `ReadBoolBytes` / `ReadMapHeaderBytes` map nil to the zero value.
    #[test]
    fn nil_reads_as_zero_like_go_msgp() {
        let data = [0xc0u8, 0x05];
        let mut rd = &data[..];
        assert_eq!(read_u64(&mut rd).unwrap(), 0);
        assert_eq!(rd, &[0x05]);
        let mut rd = &data[..];
        assert_eq!(read_i64(&mut rd).unwrap(), 0);
        assert_eq!(rd, &[0x05]);
        let mut rd = &data[..];
        assert_eq!(read_u32(&mut rd).unwrap(), 0);
        let mut rd = &data[..];
        assert_eq!(read_u16(&mut rd).unwrap(), 0);
        let mut rd = &data[..];
        assert_eq!(read_u8_val(&mut rd).unwrap(), 0);
        let mut rd = &data[..];
        assert!(!read_bool(&mut rd).unwrap());
        assert_eq!(rd, &[0x05]);
        let mut rd = &data[..];
        assert_eq!(read_map_len(&mut rd).unwrap(), 0);
        assert_eq!(rd, &[0x05]);
    }

    #[test]
    fn test_skip_bin8() {
        // bin8 with 4 bytes
        let data = [0xc4, 0x04, 0x01, 0x02, 0x03, 0x04];
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_f32() {
        let data = [0xca, 0x40, 0x48, 0xf5, 0xc3]; // f32 3.14
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_f64() {
        let data = [0xcb, 0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18]; // f64 pi
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_read_u32_ok() {
        let data = [0xce, 0x00, 0x01, 0x00, 0x00]; // u32 65536
        let mut rd = &data[..];
        assert_eq!(read_u32(&mut rd).unwrap(), 65536);
    }

    #[test]
    fn test_read_u16_ok() {
        let data = [0xcd, 0x01, 0x00]; // u16 256
        let mut rd = &data[..];
        assert_eq!(read_u16(&mut rd).unwrap(), 256);
    }

    #[test]
    fn test_read_u8_val_ok() {
        let data = [0xcc, 0xff]; // u8 255
        let mut rd = &data[..];
        assert_eq!(read_u8_val(&mut rd).unwrap(), 255);
    }

    #[test]
    fn test_read_map_len_fixmap() {
        let data = [0x83]; // fixmap(3)
        let mut rd = &data[..];
        assert_eq!(read_map_len(&mut rd).unwrap(), 3);
    }

    #[test]
    fn test_read_optional_vec_nil() {
        let data = [0xc0]; // nil
        let mut rd = &data[..];
        let mut result: Option<Vec<u64>> = Some(vec![7]);
        read_slice_into_opt(&mut rd, &mut result, usize::MAX, || 0, u64_into).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_read_optional_vec_some() {
        // fixarray(2) [1, 2]
        let data = [0x92, 0x01, 0x02];
        let mut rd = &data[..];
        let mut result: Option<Vec<u64>> = None;
        read_slice_into_opt(&mut rd, &mut result, usize::MAX, || 0, u64_into).unwrap();
        assert_eq!(result, Some(vec![1, 2]));
    }

    // ── issue #2424: a slice decoded into again keeps go's capacity ──

    /// A `[32]byte` element: `ReadExactBytes` into the element already there.
    fn addr_into(rd: &mut &[u8], e: &mut [u8; 4]) -> Result<()> {
        read_fixed_bytes_into_go_compat(rd, e)
    }

    /// go: `[[1 2 3 4] [5 6 7 8] [9 9 9 9]]`, then `[[0xaa]]` (re-sliced to one
    /// element, `ReadExactBytes` keeps its tail), then a nil-free three-element
    /// value whose last two are one byte: within the capacity, the hidden
    /// elements come back and keep their tails.
    #[test]
    fn repeated_slice_reuses_go_capacity() {
        let _s = decode_session();
        let mut v: Vec<[u8; 4]> = Vec::new();
        let first = [
            0x93, 0xc4, 4, 1, 2, 3, 4, 0xc4, 4, 5, 6, 7, 8, 0xc4, 4, 9, 9, 9, 9,
        ];
        read_slice_into(&mut &first[..], &mut v, 8, || [0; 4], addr_into).unwrap();
        let shrink = [0x91, 0xc4, 1, 0xaa];
        read_slice_into(&mut &shrink[..], &mut v, 8, || [0; 4], addr_into).unwrap();
        assert_eq!(v, vec![[0xaa, 2, 3, 4]]);
        let grow = [0x93, 0xc4, 1, 0xbb, 0xc4, 1, 0xcc, 0xc4, 1, 0xdd];
        read_slice_into(&mut &grow[..], &mut v, 8, || [0; 4], addr_into).unwrap();
        assert_eq!(v, vec![[0xbb, 2, 3, 4], [0xcc, 6, 7, 8], [0xdd, 9, 9, 9]]);
        // past the capacity: a fresh slice of zero elements
        let fresh = [0x94, 0xc4, 1, 1, 0xc4, 1, 2, 0xc4, 1, 3, 0xc4, 1, 4];
        read_slice_into(&mut &fresh[..], &mut v, 8, || [0; 4], addr_into).unwrap();
        assert_eq!(
            v,
            vec![[1, 0, 0, 0], [2, 0, 0, 0], [3, 0, 0, 0], [4, 0, 0, 0]]
        );
        // nil drops the capacity: the next value is fresh
        read_slice_into(&mut &[0xc0][..], &mut v, 8, || [0; 4], addr_into).unwrap();
        assert!(v.is_empty());
        read_slice_into(
            &mut &[0x91, 0xc4, 1, 7][..],
            &mut v,
            8,
            || [0; 4],
            addr_into,
        )
        .unwrap();
        assert_eq!(v, vec![[7, 0, 0, 0]]);
    }

    /// go `msgp.ReadArrayHeaderBytes`: a fixmap is read as the interleaved
    /// key/value array; a map16 is a type error; a count over the
    /// `allocbound` is `ErrOverflow`.
    #[test]
    fn slice_header_reads_like_go() {
        let _s = decode_session();
        let mut v: Vec<u64> = Vec::new();
        read_slice_into(&mut &[0x81, 0x01, 0x02][..], &mut v, 8, || 0, u64_into).unwrap();
        assert_eq!(v, vec![1, 2]);
        assert!(read_slice_into(&mut &[0xde, 0, 1, 1, 2][..], &mut v, 8, || 0, u64_into).is_err());
        assert!(read_slice_into(&mut &[0x93, 1, 2, 3][..], &mut v, 2, || 0, u64_into).is_err());
    }

    // ── go-algorand v4.7.2-stable msgpack decode nesting depth cap ─────
    //
    // Builds `wrappers` nested fixarray(1) markers (0x91) around a single
    // scalar leaf (fixint 0). The leaf value sits at nesting depth
    // `wrappers + 1`, so `wrappers = MAX_MSGPACK_DECODE_DEPTH - 1` is the
    // deepest payload that still stays within the 255-level bound, and
    // `wrappers = MAX_MSGPACK_DECODE_DEPTH` is the shallowest one that
    // exceeds it.
    fn nested_fixarray_payload(wrappers: usize) -> Vec<u8> {
        let mut buf = vec![0x91u8; wrappers];
        buf.push(0x00); // fixint 0 leaf
        buf
    }

    #[test]
    fn skip_value_accepts_payload_at_max_depth() {
        let data = nested_fixarray_payload(MAX_MSGPACK_DECODE_DEPTH - 1);
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn skip_value_huge_container_headers_error_without_overflow() {
        // map32 / array32 claiming 0xFFFF_FFFF entries with no body: must
        // be a clean EOF error (previously `len * 2` overflowed u32).
        for hdr in [0xdfu8, 0xdd] {
            let mut data = vec![hdr];
            data.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
            let mut rd = &data[..];
            assert!(skip_value(&mut rd).is_err());
            assert!(msgpack_value_len(&data).is_err());
        }
        // Same with a little body so the loop runs a few iterations.
        let mut data = vec![0xdfu8];
        data.extend_from_slice(&0x8000_0000u32.to_be_bytes());
        data.extend_from_slice(&[0x01, 0x02, 0x03]);
        let mut rd = &data[..];
        assert!(skip_value(&mut rd).is_err());
    }

    #[test]
    fn skip_value_rejects_payload_exceeding_max_depth() {
        let data = nested_fixarray_payload(MAX_MSGPACK_DECODE_DEPTH);
        let mut rd = &data[..];
        let err = skip_value(&mut rd).unwrap_err();
        let msg = std::error::Error::source(&err)
            .map(|s| s.to_string())
            .unwrap_or_default();
        assert!(msg.to_lowercase().contains("depth"), "got: {msg}");
    }

    #[test]
    fn skip_value_does_not_stack_overflow_on_very_deep_payload() {
        // Two orders of magnitude past the bound — would overflow a naive
        // recursive skip; the iterative implementation must still return a
        // clean error rather than crash the test process.
        let data = nested_fixarray_payload(50_000);
        let mut rd = &data[..];
        assert!(skip_value(&mut rd).is_err());
    }

    #[test]
    fn check_msgpack_depth_matches_skip_value_at_the_boundary() {
        assert!(
            check_msgpack_depth(&nested_fixarray_payload(MAX_MSGPACK_DECODE_DEPTH - 1)).is_ok()
        );
        assert!(check_msgpack_depth(&nested_fixarray_payload(MAX_MSGPACK_DECODE_DEPTH)).is_err());
    }

    #[test]
    fn msgpack_value_len_returns_first_value_length_and_same_errors() {
        // Two concatenated values: [0x91 0x00] then fixint 7.
        let data = [0x91u8, 0x00, 0x07];
        assert_eq!(msgpack_value_len(&data).unwrap(), 2);
        assert_eq!(msgpack_value_len(&data[2..]).unwrap(), 1);
        // Truncated array (claims one element, none present).
        assert!(msgpack_value_len(&[0x91]).is_err());
        assert!(msgpack_value_len(&[]).is_err());
        // Depth boundary matches check_msgpack_depth.
        let ok = nested_fixarray_payload(MAX_MSGPACK_DECODE_DEPTH - 1);
        assert_eq!(msgpack_value_len(&ok).unwrap(), ok.len());
        assert!(msgpack_value_len(&nested_fixarray_payload(MAX_MSGPACK_DECODE_DEPTH)).is_err());
    }

    #[test]
    fn unknown_field_with_deeply_nested_value_is_rejected_not_skipped() {
        // Integration check: an unrecognized Transaction field whose value is
        // a maliciously deep structure is rejected, not skipped.
        use crate::Transaction;

        let mut buf = Vec::new();
        rmp::encode::write_map_len(&mut buf, 3).unwrap();
        rmp::encode::write_str(&mut buf, "type").unwrap();
        rmp::encode::write_str(&mut buf, "pay").unwrap();
        rmp::encode::write_str(&mut buf, "snd").unwrap();
        rmp::encode::write_bin(&mut buf, &[7u8; 32]).unwrap();
        rmp::encode::write_str(&mut buf, "zzz_unknown_field").unwrap();
        buf.extend(nested_fixarray_payload(MAX_MSGPACK_DECODE_DEPTH));

        let mut rd = &buf[..];
        let err = Transaction::decode_from_reader(&mut rd).unwrap_err();
        // the unknown key is refused (go's msgp.ErrNoField) before its value is
        // skipped, so the 255 cap is not reached here; it still holds for the
        // pre-scan (`check_msgpack_depth_matches_skip_value_at_the_boundary`)
        assert!(
            format!("{err:?}").contains("no matching struct field"),
            "got: {err:?}"
        );
    }

    /// go `msgp.ReadStringZC`: `str`, `nil`, and (go-codec compat) `bin` or a
    /// uint8 array, but not a map (issue #2421).
    #[test]
    fn read_string_accepts_go_string_forms() {
        for (enc, want) in [
            (&b"\xa2hi"[..], "hi"),
            (&b"\xc0"[..], ""),
            (&b"\xc4\x02hi"[..], "hi"),
            (&b"\x92\x68\x69"[..], "hi"),
        ] {
            let mut rd = enc;
            assert_eq!(read_string(&mut rd).unwrap(), want, "{enc:02x?}");
            assert!(rd.is_empty());
            let mut rd = enc;
            assert_eq!(read_str_bytes(&mut rd).unwrap(), want.as_bytes());
        }
        let mut rd = &b"\x81\x01\x02"[..];
        assert!(read_string(&mut rd).is_err());
        // a non-UTF-8 bin is kept losslessly
        let mut rd = &b"\xc4\x01\xff"[..];
        let s = read_string(&mut rd).unwrap();
        assert_eq!(&*crate::raw_text::decode(&s), b"\xff");
    }

    /// go `msgp.ReadExactBytes(b, into)`: a shorter value overwrites only its
    /// prefix, nil zeroes, a longer explicit array is an error (issue #2421).
    #[test]
    fn read_fixed_bytes_into_keeps_the_tail() {
        let mut a = [7u8; 4];
        read_fixed_bytes_into_go_compat(&mut &b"\xc4\x01\x01"[..], &mut a).unwrap();
        assert_eq!(a, [1, 7, 7, 7]);
        read_fixed_bytes_into_go_compat(&mut &b"\x92\x02\x03"[..], &mut a).unwrap();
        assert_eq!(a, [2, 3, 7, 7]);
        read_fixed_bytes_into_go_compat(&mut &b"\xc4\x06\x01\x02\x03\x04\x05\x06"[..], &mut a)
            .unwrap();
        assert_eq!(a, [1, 2, 3, 4]);
        read_fixed_bytes_into_go_compat(&mut &b"\xc0"[..], &mut a).unwrap();
        assert_eq!(a, [0; 4]);
        assert!(
            read_fixed_bytes_into_go_compat(&mut &b"\x95\x01\x01\x01\x01\x01"[..], &mut a).is_err()
        );
    }
}
