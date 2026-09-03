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

//! `vpack`: stateless + stateful vote msgpack compression codec.
//!
//! Ports go-algorand's `network/vpack` package (`network/vpack/vpack.go`,
//! `network/vpack/msgp.go`, `network/vpack/parse.go` for the stateless
//! layer; `network/vpack/dynamic_vpack.go`, `network/vpack/lru_table.go`,
//! `network/vpack/proposal_window.go` for the stateful layer, pinned at
//! `v5.0.0-stable`).
//!
//! `vpack` is a specialized, schema-aware compressor for the msgpack
//! encoding of `agreement.UnauthenticatedVote` (this crate's
//! [`algo_agreement::UnauthenticatedVote`] /
//! [`algo_agreement::codec::encode_vote`]/[`algo_agreement::codec::decode_vote`]).
//! It strips all msgpack map/string-key formatting and replaces the six
//! optional fields' presence with a 1-byte bitmask, exploiting the fixed,
//! well-known field structure of a vote to compress far better than
//! generic msgpack ever could.
//!
//! # Two compression layers
//!
//! 1. **Stateless** ([`compress_vote`]/[`decompress_vote`]): always
//!    applied, no memory overhead. Strips msgpack formatting/field names.
//! 2. **Stateful** ([`StatefulEncoder`]/[`StatefulDecoder`]): optional,
//!    per-connection layer that further compresses by replacing frequently
//!    repeated field values (sender address, the two `(pubkey, signature)`
//!    pairs, and the proposal bundle) with short references into LRU
//!    tables / a small sliding window, and delta-encodes `r.rnd` against
//!    the previous vote's round. It operates on the *output* of the
//!    stateless layer, i.e. `StatefulEncoder::compress` takes
//!    [`compress_vote`]'s output and [`StatefulDecoder::decompress`]
//!    produces input suitable for [`decompress_vote`]. See
//!    go-algorand's `network/vpack/README.md` §2.2 and §3 for the exact
//!    per-field reference/delta rules mirrored here.
//!
//! # Scope: standalone codec only, not wired into any network path
//!
//! This module is **intentionally not wired into any live network code
//! path** (no changes to `peer_features.rs`'s handshake negotiation,
//! `ws_peer.rs`, or any connection-handling code). Wiring a new wire-format
//! codec into live peer negotiation — including the stateful layer's
//! abort/renegotiation handshake (go-algorand's
//! `network/msgCompressor.go` `wsPeerMsgCodec`) — is a
//! network-protocol-compatibility change that needs live multi-node
//! interop testing beyond what this standalone codec's test suite can
//! provide. `avvpack`/`avvpack<N>` peer feature bits are already
//! advertised in `peer_features.rs`, but nothing in the live
//! handshake/connection paths calls into this module.
//!
//! # Wire format
//!
//! See go-algorand's `network/vpack/README.md` for the full specification.
//! Byte-for-byte layout:
//!
//! ```text
//! +---------+-----------------+----------------+---------------------------+
//! | Header  | VrfProof ("pf") | rawVote ("r")  | OneTimeSignature ("sig")  |
//! | 2 bytes | 80 bytes        | variable length| 256 bytes                |
//! +---------+-----------------+----------------+---------------------------+
//! ```
//!
//! Header byte 0 is a presence bitmask for six optional `rawVote` fields
//! (`r.per`, `r.prop.dig`, `r.prop.encdig`, `r.prop.oper`, `r.prop.oprop`,
//! `r.step`) and is always present, whether or not the stateful layer is
//! used. Header byte 1 is `0x00` when only the stateless layer is used;
//! when the stateful layer is also applied it becomes a bitmask of
//! reference/delta flags (see [`StatefulEncoder::compress`]).

use std::fmt;

// ── msgpack constants (mirrors go-algorand network/vpack/msgp.go) ──────────

const MSGP_FIXMAP_MASK: u8 = 0x80;
const MSGP_FIXMAP_MAX: u8 = 0x8f;
const MSGP_FIXSTR_MASK: u8 = 0xa0;
const MSGP_FIXSTR_MAX: u8 = 0xbf;
const MSGP_BIN8: u8 = 0xc4;
const MSGP_UINT8: u8 = 0xcc;
const MSGP_UINT16: u8 = 0xcd;
const MSGP_UINT32: u8 = 0xce;
const MSGP_UINT64: u8 = 0xcf;

/// msgpack fixstr-prefixed field-name literals, exactly as go-algorand's
/// msgp codegen emits them (marker byte + ASCII bytes).
const FIXSTR_CRED: &[u8] = b"\xa4cred";
const FIXSTR_DIG: &[u8] = b"\xa3dig";
const FIXSTR_ENCDIG: &[u8] = b"\xa6encdig";
const FIXSTR_OPER: &[u8] = b"\xa4oper";
const FIXSTR_OPROP: &[u8] = b"\xa5oprop";
const FIXSTR_P: &[u8] = b"\xa1p";
const FIXSTR_P1S: &[u8] = b"\xa3p1s";
const FIXSTR_P2: &[u8] = b"\xa2p2";
const FIXSTR_P2S: &[u8] = b"\xa3p2s";
const FIXSTR_PER: &[u8] = b"\xa3per";
const FIXSTR_PF: &[u8] = b"\xa2pf";
const FIXSTR_PROP: &[u8] = b"\xa4prop";
const FIXSTR_PS: &[u8] = b"\xa2ps";
const FIXSTR_R: &[u8] = b"\xa1r";
const FIXSTR_RND: &[u8] = b"\xa3rnd";
const FIXSTR_S: &[u8] = b"\xa1s";
const FIXSTR_SIG: &[u8] = b"\xa3sig";
const FIXSTR_SND: &[u8] = b"\xa3snd";
const FIXSTR_STEP: &[u8] = b"\xa4step";

fn is_msgp_fixint(b: u8) -> bool {
    b >> 7 == 0
}

/// Given the first byte of a msgpack-encoded varuint, return the number of
/// bytes remaining (not including the marker byte itself).
fn msgp_varuint_remaining(first: u8) -> Result<usize, VpackError> {
    match first {
        MSGP_UINT8 => Ok(1),
        MSGP_UINT16 => Ok(2),
        MSGP_UINT32 => Ok(4),
        MSGP_UINT64 => Ok(8),
        _ if is_msgp_fixint(first) => Ok(0),
        _ => Err(VpackError::Parse(format!(
            "expected fixint or varuint tag, got 0x{first:02x}"
        ))),
    }
}

// ── header bitmask (mirrors go-algorand network/vpack/vpack.go) ────────────

const BIT_PER: u8 = 1 << 0;
const BIT_DIG: u8 = 1 << 1;
const BIT_ENC_DIG: u8 = 1 << 2;
const BIT_OPER: u8 = 1 << 3;
const BIT_OPROP: u8 = 1 << 4;
const BIT_STEP: u8 = 1 << 5;

const PROP_FIELDS_MASK: u8 = BIT_DIG | BIT_ENC_DIG | BIT_OPER | BIT_OPROP;
const TOTAL_REQUIRED_FIELDS: u8 = 8;

/// 1 byte for the stateless bitmask, 1 byte reserved for the (unimplemented)
/// stateful layer — always `0x00` here.
const HEADER_SIZE: usize = 2;

const MAX_MSGP_VARUINT_SIZE: usize = 9;
const MSGP_BIN8_LEN32_SIZE: usize = 2 + 32;
const MSGP_BIN8_LEN64_SIZE: usize = 2 + 64;
const MSGP_BIN8_LEN80_SIZE: usize = 2 + 80;
const MSGP_FIXMAP_MARKER_SIZE: usize = 1;

/// Maximum size of a msgpack-encoded vote, including msgpack control
/// characters and all required and optional data fields.
pub const MAX_MSGPACK_VOTE_SIZE: usize = MSGP_FIXMAP_MARKER_SIZE
    + FIXSTR_CRED.len()
    + MSGP_FIXMAP_MARKER_SIZE
    + FIXSTR_PF.len()
    + MSGP_BIN8_LEN80_SIZE
    + FIXSTR_R.len()
    + MSGP_FIXMAP_MARKER_SIZE
    + FIXSTR_PER.len()
    + MAX_MSGP_VARUINT_SIZE
    + FIXSTR_PROP.len()
    + MSGP_FIXMAP_MARKER_SIZE
    + FIXSTR_DIG.len()
    + MSGP_BIN8_LEN32_SIZE
    + FIXSTR_ENCDIG.len()
    + MSGP_BIN8_LEN32_SIZE
    + FIXSTR_OPER.len()
    + MAX_MSGP_VARUINT_SIZE
    + FIXSTR_OPROP.len()
    + MSGP_BIN8_LEN32_SIZE
    + FIXSTR_RND.len()
    + MAX_MSGP_VARUINT_SIZE
    + FIXSTR_SND.len()
    + MSGP_BIN8_LEN32_SIZE
    + FIXSTR_STEP.len()
    + MAX_MSGP_VARUINT_SIZE
    + FIXSTR_SIG.len()
    + MSGP_FIXMAP_MARKER_SIZE
    + FIXSTR_P.len()
    + MSGP_BIN8_LEN32_SIZE
    + FIXSTR_P1S.len()
    + MSGP_BIN8_LEN64_SIZE
    + FIXSTR_P2.len()
    + MSGP_BIN8_LEN32_SIZE
    + FIXSTR_P2S.len()
    + MSGP_BIN8_LEN64_SIZE
    + FIXSTR_PS.len()
    + MSGP_BIN8_LEN64_SIZE
    + FIXSTR_S.len()
    + MSGP_BIN8_LEN64_SIZE;

/// Maximum size of a stateless-compressed vote, including all required and
/// optional fields.
pub const MAX_COMPRESSED_VOTE_SIZE: usize = HEADER_SIZE
    + 80 // cred.pf
    + MAX_MSGP_VARUINT_SIZE * 4 // r.rnd, r.per, r.step, r.prop.oper
    + 32 * 6 // r.prop.dig, r.prop.encdig, r.prop.oprop, r.snd, sig.p, sig.p2
    + 64 * 3; // sig.p1s, sig.p2s, sig.s (sig.ps is omitted)

/// Errors that can occur during vpack compression or decompression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpackError {
    /// The source msgpack vote could not be parsed (malformed or an
    /// unexpected field/shape was encountered).
    Parse(String),
    /// A required vote field was missing from the source.
    MissingRequiredFields,
    /// The destination buffer would overflow [`MAX_COMPRESSED_VOTE_SIZE`].
    BufferTooSmall,
    /// The compressed source is malformed or truncated.
    Decompress(String),
    /// Decompression failed on data that looks like it might actually be
    /// uncompressed msgpack sent by a peer that claimed vpack support.
    LikelyUncompressed(String),
    /// [`StatefulEncoder::new`]/[`StatefulDecoder::new`] was given a table
    /// size that is not a power of two, or is smaller than 16.
    InvalidTableSize(String),
}

impl fmt::Display for VpackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(msg) => write!(f, "vpack: failed to parse vote: {msg}"),
            Self::MissingRequiredFields => write!(f, "vpack: missing required fields"),
            Self::BufferTooSmall => write!(f, "vpack: destination buffer too small"),
            Self::Decompress(msg) => write!(f, "vpack: failed to decompress vote: {msg}"),
            Self::LikelyUncompressed(msg) => {
                write!(f, "vpack: data appears to be uncompressed msgpack: {msg}")
            }
            Self::InvalidTableSize(msg) => write!(f, "vpack: invalid table size: {msg}"),
        }
    }
}

impl std::error::Error for VpackError {}

// ── zero-allocation msgpack vote parser (mirrors msgpVoteParser) ───────────

struct MsgpVoteParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> MsgpVoteParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn ensure_bytes(&self, n: usize) -> Result<(), VpackError> {
        if self.pos + n > self.data.len() {
            return Err(VpackError::Parse(format!(
                "unexpected EOF: need {n} bytes, have {}",
                self.data.len().saturating_sub(self.pos)
            )));
        }
        Ok(())
    }

    fn read_byte(&mut self) -> Result<u8, VpackError> {
        self.ensure_bytes(1)?;
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_fixmap(&mut self) -> Result<u8, VpackError> {
        let b = self.read_byte()?;
        if !(MSGP_FIXMAP_MASK..=MSGP_FIXMAP_MAX).contains(&b) {
            return Err(VpackError::Parse(format!("expected fixmap, got 0x{b:02x}")));
        }
        Ok(b & 0x0f)
    }

    fn read_string(&mut self) -> Result<&'a [u8], VpackError> {
        let b = self.read_byte()?;
        if !(MSGP_FIXSTR_MASK..=MSGP_FIXSTR_MAX).contains(&b) {
            return Err(VpackError::Parse(format!(
                "readString: expected fixstr, got 0x{b:02x}"
            )));
        }
        let length = (b & 0x1f) as usize;
        self.ensure_bytes(length)?;
        let s = &self.data[self.pos..self.pos + length];
        self.pos += length;
        Ok(s)
    }

    fn expect_string(&mut self, expected: &str) -> Result<(), VpackError> {
        let s = self.read_string()?;
        if s != expected.as_bytes() {
            return Err(VpackError::Parse(format!(
                "expected string {expected}, got {}",
                String::from_utf8_lossy(s)
            )));
        }
        Ok(())
    }

    fn read_bin_n<const N: usize>(&mut self) -> Result<[u8; N], VpackError> {
        self.ensure_bytes(N + 2)?;
        if self.data[self.pos] != MSGP_BIN8 || self.data[self.pos + 1] as usize != N {
            return Err(VpackError::Parse(format!(
                "expected bin8 length {N}, got {}",
                self.data[self.pos + 1]
            )));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.data[self.pos + 2..self.pos + 2 + N]);
        self.pos += N + 2;
        Ok(out)
    }

    /// Reads a variable-length msgpack unsigned integer, returning the raw
    /// marker+value bytes (zero-copy, matches Go's `readUintBytes`).
    fn read_uint_bytes(&mut self) -> Result<&'a [u8], VpackError> {
        let start_pos = self.pos;
        let b = self.read_byte()?;
        let data_size = msgp_varuint_remaining(b)?;
        if data_size == 0 {
            return Ok(&self.data[start_pos..start_pos + 1]);
        }
        self.ensure_bytes(data_size)?;
        self.pos += data_size;
        Ok(&self.data[start_pos..start_pos + data_size + 1])
    }
}

// ── field mask tracking used while parsing/encoding (mirrors updateMask) ───

#[derive(Default)]
struct EncodeState {
    out: Vec<u8>,
    mask: u8,
    required_fields: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VoteValueType {
    CredPf,
    RPer,
    RPropDig,
    RPropEncdig,
    RPropOper,
    RPropOprop,
    RRnd,
    RSnd,
    RStep,
    SigP1s,
    SigP2,
    SigP2s,
    SigP,
    SigS,
}

impl EncodeState {
    fn update_mask(&mut self, field: VoteValueType) {
        match field {
            VoteValueType::RPer => self.mask |= BIT_PER,
            VoteValueType::RPropDig => self.mask |= BIT_DIG,
            VoteValueType::RPropEncdig => self.mask |= BIT_ENC_DIG,
            VoteValueType::RPropOper => self.mask |= BIT_OPER,
            VoteValueType::RPropOprop => self.mask |= BIT_OPROP,
            VoteValueType::RStep => self.mask |= BIT_STEP,
            _ => self.required_fields += 1,
        }
    }

    fn write_varuint(&mut self, field: VoteValueType, bytes: &[u8]) {
        self.update_mask(field);
        self.out.extend_from_slice(bytes);
    }

    fn write_bin(&mut self, field: VoteValueType, bytes: &[u8]) {
        self.update_mask(field);
        self.out.extend_from_slice(bytes);
    }
}

/// Parses a msgpack-encoded `agreement.UnauthenticatedVote` (as produced by
/// [`algo_agreement::codec::encode_vote`]) and writes the stateless vpack
/// encoding (without the 2-byte header, which the caller fills in) into
/// `state`. Mirrors go-algorand's `network/vpack/parse.go`'s
/// `parseMsgpVote`.
fn parse_msgp_vote(msgp_data: &[u8], state: &mut EncodeState) -> Result<(), VpackError> {
    let mut p = MsgpVoteParser::new(msgp_data);

    // unauthenticatedVote: fixmap(3) { cred, r, sig }
    let cnt = p.read_fixmap()?;
    if cnt != 3 {
        return Err(VpackError::Parse(format!(
            "expected fixed map size 3 for unauthenticatedVote, got {cnt}"
        )));
    }
    p.expect_string("cred")?;

    // UnauthenticatedCredential: fixmap(1) { pf }
    let cnt = p.read_fixmap()?;
    if cnt != 1 {
        return Err(VpackError::Parse(format!(
            "expected fixed map size 1 for UnauthenticatedCredential, got {cnt}"
        )));
    }
    p.expect_string("pf")?;
    let pf: [u8; 80] = p
        .read_bin_n()
        .map_err(|e| VpackError::Parse(format!("reading pf: {e}")))?;
    state.write_bin(VoteValueType::CredPf, &pf);

    p.expect_string("r")?;

    // rawVote: fixmap { per?, prop?, rnd, snd, step? }
    let cnt = p.read_fixmap()?;
    if !(1..=5).contains(&cnt) {
        return Err(VpackError::Parse(format!(
            "expected fixmap size for rawVote 1 <= cnt <= 5, got {cnt}"
        )));
    }
    for _ in 0..cnt {
        let vote_key = p.read_string()?;
        match vote_key {
            b"per" => {
                let val = p
                    .read_uint_bytes()
                    .map_err(|e| VpackError::Parse(format!("reading per: {e}")))?;
                state.write_varuint(VoteValueType::RPer, val);
            }
            b"prop" => {
                let prop_cnt = p.read_fixmap()?;
                if !(1..=4).contains(&prop_cnt) {
                    return Err(VpackError::Parse(format!(
                        "expected fixmap size for proposalValue 1 <= cnt <= 4, got {prop_cnt}"
                    )));
                }
                for _ in 0..prop_cnt {
                    let prop_key = p.read_string()?;
                    match prop_key {
                        b"dig" => {
                            let val: [u8; 32] = p
                                .read_bin_n()
                                .map_err(|e| VpackError::Parse(format!("reading dig: {e}")))?;
                            state.write_bin(VoteValueType::RPropDig, &val);
                        }
                        b"encdig" => {
                            let val: [u8; 32] = p
                                .read_bin_n()
                                .map_err(|e| VpackError::Parse(format!("reading encdig: {e}")))?;
                            state.write_bin(VoteValueType::RPropEncdig, &val);
                        }
                        b"oper" => {
                            let val = p
                                .read_uint_bytes()
                                .map_err(|e| VpackError::Parse(format!("reading oper: {e}")))?;
                            state.write_varuint(VoteValueType::RPropOper, val);
                        }
                        b"oprop" => {
                            let val: [u8; 32] = p
                                .read_bin_n()
                                .map_err(|e| VpackError::Parse(format!("reading oprop: {e}")))?;
                            state.write_bin(VoteValueType::RPropOprop, &val);
                        }
                        other => {
                            return Err(VpackError::Parse(format!(
                                "unexpected field in proposalValue: {:?}",
                                String::from_utf8_lossy(other)
                            )))
                        }
                    }
                }
            }
            b"rnd" => {
                let val = p
                    .read_uint_bytes()
                    .map_err(|e| VpackError::Parse(format!("reading rnd: {e}")))?;
                state.write_varuint(VoteValueType::RRnd, val);
            }
            b"snd" => {
                let val: [u8; 32] = p
                    .read_bin_n()
                    .map_err(|e| VpackError::Parse(format!("reading snd: {e}")))?;
                state.write_bin(VoteValueType::RSnd, &val);
            }
            b"step" => {
                let val = p
                    .read_uint_bytes()
                    .map_err(|e| VpackError::Parse(format!("reading step: {e}")))?;
                state.write_varuint(VoteValueType::RStep, val);
            }
            other => {
                return Err(VpackError::Parse(format!(
                    "unexpected field in rawVote: {:?}",
                    String::from_utf8_lossy(other)
                )))
            }
        }
    }

    p.expect_string("sig")?;

    // OneTimeSignature: fixmap(6) { p, p1s, p2, p2s, ps, s }
    let cnt = p.read_fixmap()?;
    if cnt != 6 {
        return Err(VpackError::Parse(format!(
            "expected fixed map size 6 for OneTimeSignature, got {cnt}"
        )));
    }
    p.expect_string("p")?;
    let val: [u8; 32] = p
        .read_bin_n()
        .map_err(|e| VpackError::Parse(format!("reading p: {e}")))?;
    state.write_bin(VoteValueType::SigP, &val);

    p.expect_string("p1s")?;
    let val: [u8; 64] = p
        .read_bin_n()
        .map_err(|e| VpackError::Parse(format!("reading p1s: {e}")))?;
    state.write_bin(VoteValueType::SigP1s, &val);

    p.expect_string("p2")?;
    let val: [u8; 32] = p
        .read_bin_n()
        .map_err(|e| VpackError::Parse(format!("reading p2: {e}")))?;
    state.write_bin(VoteValueType::SigP2, &val);

    p.expect_string("p2s")?;
    let val: [u8; 64] = p
        .read_bin_n()
        .map_err(|e| VpackError::Parse(format!("reading p2s: {e}")))?;
    state.write_bin(VoteValueType::SigP2s, &val);

    p.expect_string("ps")?;
    let val: [u8; 64] = p
        .read_bin_n()
        .map_err(|e| VpackError::Parse(format!("reading ps: {e}")))?;
    if val != [0u8; 64] {
        return Err(VpackError::Parse("expected empty array for ps".into()));
    }

    p.expect_string("s")?;
    let val: [u8; 64] = p
        .read_bin_n()
        .map_err(|e| VpackError::Parse(format!("reading s: {e}")))?;
    state.write_bin(VoteValueType::SigS, &val);

    if p.pos < p.data.len() {
        return Err(VpackError::Parse(format!(
            "unexpected trailing data: {} bytes remain unprocessed",
            p.data.len() - p.pos
        )));
    }

    Ok(())
}

/// Compresses a msgpack-encoded `agreement.UnauthenticatedVote` using the
/// stateless vpack scheme. `src` must be the canonical msgpack encoding
/// produced by [`algo_agreement::codec::encode_vote`] (equivalently, Go's
/// `protocol.EncodeMsgp(&unauthenticatedVote{...})`).
///
/// Mirrors go-algorand's `vpack.StatelessEncoder.CompressVote`.
pub fn compress_vote(src: &[u8]) -> Result<Vec<u8>, VpackError> {
    let mut state = EncodeState::default();
    parse_msgp_vote(src, &mut state)?;

    if state.required_fields != TOTAL_REQUIRED_FIELDS {
        return Err(VpackError::MissingRequiredFields);
    }

    let mut out = Vec::with_capacity(HEADER_SIZE + state.out.len());
    out.push(state.mask);
    out.push(0); // stateful-layer byte, always zero (unimplemented)
    out.extend_from_slice(&state.out);

    if out.len() > MAX_COMPRESSED_VOTE_SIZE {
        return Err(VpackError::BufferTooSmall);
    }

    Ok(out)
}

// ── decompression ────────────────────────────────────────────────────────

fn raw_vote_map_size(mask: u8) -> u8 {
    let mut cnt = 2 + (mask & (BIT_PER | BIT_STEP)).count_ones() as u8;
    if mask & PROP_FIELDS_MASK != 0 {
        cnt += 1;
    }
    cnt
}

fn proposal_value_map_size(mask: u8) -> u8 {
    (mask & (BIT_DIG | BIT_ENC_DIG | BIT_OPER | BIT_OPROP)).count_ones() as u8
}

/// Checks whether `src` looks like an uncompressed msgpack vote that was
/// mistakenly handed to the vpack decoder (a peer claiming vpack support
/// but sending a message with a vpack-negotiated tag as plain msgpack).
///
/// Uncompressed msgpack votes start with `0x83` (fixmap marker, 3
/// elements: cred, r, sig), followed by `0xa4` (fixstr length 4), then
/// `"cred"`.
fn is_likely_uncompressed_msgpack(src: &[u8]) -> bool {
    src.len() > 5 && src[0] == 0x83 && src[1] == 0xa4 && &src[2..6] == b"cred"
}

struct StatelessReader<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> StatelessReader<'a> {
    fn bin_n<const N: usize>(&mut self, field_str: &[u8]) -> Result<[u8; N], VpackError> {
        if self.pos + N > self.src.len() {
            return Err(VpackError::Decompress(format!(
                "not enough data to read value for field {}",
                strip_fixstr_marker(field_str)
            )));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.src[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn varuint(&mut self, field_name: &[u8]) -> Result<Vec<u8>, VpackError> {
        if self.pos + 1 > self.src.len() {
            return Err(VpackError::Decompress(format!(
                "not enough data to read varuint marker for field {}",
                strip_fixstr_marker(field_name)
            )));
        }
        let marker = self.src[self.pos];
        let more_bytes = msgp_varuint_remaining(marker).map_err(|_| {
            VpackError::Decompress(format!(
                "invalid varuint marker {marker} for field {}",
                strip_fixstr_marker(field_name)
            ))
        })?;
        if self.pos + 1 + more_bytes > self.src.len() {
            return Err(VpackError::Decompress(format!(
                "not enough data for varuint (need {more_bytes} bytes) for field {}",
                strip_fixstr_marker(field_name)
            )));
        }
        let mut out = Vec::with_capacity(1 + more_bytes);
        out.push(marker);
        out.extend_from_slice(&self.src[self.pos + 1..self.pos + 1 + more_bytes]);
        self.pos += more_bytes + 1;
        Ok(out)
    }
}

fn strip_fixstr_marker(field_str: &[u8]) -> String {
    if field_str.len() > 1 && (field_str[0] & 0xe0) == 0xa0 {
        String::from_utf8_lossy(&field_str[1..]).into_owned()
    } else {
        String::from_utf8_lossy(field_str).into_owned()
    }
}

/// Decompresses a stateless-vpack-compressed vote back into the canonical
/// msgpack encoding of `agreement.UnauthenticatedVote` (byte-identical to
/// what [`algo_agreement::codec::encode_vote`] would have produced, and to
/// what [`algo_agreement::codec::decode_vote`] can parse).
///
/// Mirrors go-algorand's `vpack.StatelessDecoder.DecompressVote`.
pub fn decompress_vote(src: &[u8]) -> Result<Vec<u8>, VpackError> {
    match decompress_vote_inner(src) {
        Err(e) if is_likely_uncompressed_msgpack(src) => {
            Err(VpackError::LikelyUncompressed(e.to_string()))
        }
        other => other,
    }
}

fn decompress_vote_inner(src: &[u8]) -> Result<Vec<u8>, VpackError> {
    if src.len() < 2 {
        return Err(VpackError::Decompress("header missing".into()));
    }
    let mask = src[0];
    let mut r = StatelessReader { src, pos: 2 };
    let mut dst = Vec::with_capacity(MAX_MSGPACK_VOTE_SIZE);

    // top-level UnauthenticatedVote: fixmap(3) { cred, rawVote, sig }
    dst.push(MSGP_FIXMAP_MASK | 3);

    // cred: fixmap(1) { pf: bin8(80) }
    dst.extend_from_slice(FIXSTR_CRED);
    dst.push(MSGP_FIXMAP_MASK | 1);
    dst.extend_from_slice(FIXSTR_PF);
    dst.push(MSGP_BIN8);
    dst.push(80);
    let pf = r.bin_n::<80>(FIXSTR_PF)?;
    dst.extend_from_slice(&pf);

    // rawVote: fixmap { per, prop, rnd, snd, step }
    dst.extend_from_slice(FIXSTR_R);
    dst.push(MSGP_FIXMAP_MASK | raw_vote_map_size(mask));

    if mask & BIT_PER != 0 {
        dst.extend_from_slice(FIXSTR_PER);
        let v = r.varuint(FIXSTR_PER)?;
        dst.extend_from_slice(&v);
    }

    if mask & PROP_FIELDS_MASK != 0 {
        dst.extend_from_slice(FIXSTR_PROP);
        dst.push(MSGP_FIXMAP_MASK | proposal_value_map_size(mask));
        if mask & BIT_DIG != 0 {
            dst.extend_from_slice(FIXSTR_DIG);
            dst.push(MSGP_BIN8);
            dst.push(32);
            dst.extend_from_slice(&r.bin_n::<32>(FIXSTR_DIG)?);
        }
        if mask & BIT_ENC_DIG != 0 {
            dst.extend_from_slice(FIXSTR_ENCDIG);
            dst.push(MSGP_BIN8);
            dst.push(32);
            dst.extend_from_slice(&r.bin_n::<32>(FIXSTR_ENCDIG)?);
        }
        if mask & BIT_OPER != 0 {
            dst.extend_from_slice(FIXSTR_OPER);
            let v = r.varuint(FIXSTR_OPER)?;
            dst.extend_from_slice(&v);
        }
        if mask & BIT_OPROP != 0 {
            dst.extend_from_slice(FIXSTR_OPROP);
            dst.push(MSGP_BIN8);
            dst.push(32);
            dst.extend_from_slice(&r.bin_n::<32>(FIXSTR_OPROP)?);
        }
    }

    dst.extend_from_slice(FIXSTR_RND);
    let v = r.varuint(FIXSTR_RND)?;
    dst.extend_from_slice(&v);

    dst.extend_from_slice(FIXSTR_SND);
    dst.push(MSGP_BIN8);
    dst.push(32);
    dst.extend_from_slice(&r.bin_n::<32>(FIXSTR_SND)?);

    if mask & BIT_STEP != 0 {
        dst.extend_from_slice(FIXSTR_STEP);
        let v = r.varuint(FIXSTR_STEP)?;
        dst.extend_from_slice(&v);
    }

    // sig: fixmap(6) { p, p1s, p2, p2s, ps, s }
    dst.extend_from_slice(FIXSTR_SIG);
    dst.push(MSGP_FIXMAP_MASK | 6);

    dst.extend_from_slice(FIXSTR_P);
    dst.push(MSGP_BIN8);
    dst.push(32);
    dst.extend_from_slice(&r.bin_n::<32>(FIXSTR_P)?);

    dst.extend_from_slice(FIXSTR_P1S);
    dst.push(MSGP_BIN8);
    dst.push(64);
    dst.extend_from_slice(&r.bin_n::<64>(FIXSTR_P1S)?);

    dst.extend_from_slice(FIXSTR_P2);
    dst.push(MSGP_BIN8);
    dst.push(32);
    dst.extend_from_slice(&r.bin_n::<32>(FIXSTR_P2)?);

    dst.extend_from_slice(FIXSTR_P2S);
    dst.push(MSGP_BIN8);
    dst.push(64);
    dst.extend_from_slice(&r.bin_n::<64>(FIXSTR_P2S)?);

    // sig.ps is always zero and never transmitted
    dst.extend_from_slice(FIXSTR_PS);
    dst.push(MSGP_BIN8);
    dst.push(64);
    dst.extend(std::iter::repeat(0u8).take(64));

    dst.extend_from_slice(FIXSTR_S);
    dst.push(MSGP_BIN8);
    dst.push(64);
    dst.extend_from_slice(&r.bin_n::<64>(FIXSTR_S)?);

    if r.pos < r.src.len() {
        return Err(VpackError::Decompress(format!(
            "unexpected trailing data: {} bytes remain",
            r.src.len() - r.pos
        )));
    }

    Ok(dst)
}

// ── convenience wrappers over algo_agreement's UnauthenticatedVote ─────────

/// Encodes `vote` to canonical msgpack (via
/// [`algo_agreement::codec::encode_vote`]) and compresses it with
/// [`compress_vote`].
pub fn compress_unauthenticated_vote(
    vote: &algo_agreement::UnauthenticatedVote,
) -> Result<Vec<u8>, VpackError> {
    let msgp = algo_agreement::codec::encode_vote(vote);
    compress_vote(&msgp)
}

/// Decompresses `src` with [`decompress_vote`] and decodes the resulting
/// msgpack into an [`algo_agreement::UnauthenticatedVote`] (via
/// [`algo_agreement::codec::decode_vote`]).
pub fn decompress_to_unauthenticated_vote(
    src: &[u8],
) -> Result<algo_agreement::UnauthenticatedVote, VpackError> {
    let msgp = decompress_vote(src)?;
    algo_agreement::codec::decode_vote(&msgp)
        .map_err(|e| VpackError::Decompress(format!("decode_vote: {e}")))
}

// ── stateful (dynamic-table) compression ────────────────────────────────
//
// Mirrors go-algorand's `network/vpack/lru_table.go`,
// `network/vpack/proposal_window.go`, and `network/vpack/dynamic_vpack.go`.
// Operates on the *output* of the stateless layer above: `Compress` takes
// [`compress_vote`]'s output and produces a further-compressed buffer;
// `Decompress` reverses that back into stateless-layer output suitable for
// [`decompress_vote`].

const PF_SIZE: usize = 80; // committee.VrfProof
const DIGEST_SIZE: usize = 32; // crypto.Digest (and basics.Address)
const SIG_SIZE: usize = 64; // crypto.Signature
const PK_SIZE: usize = 32; // crypto.PublicKey

// hdr1 (byte 1 of the header) bit layout: see the module doc / README.md §2.2.
const HDR1_RND_MASK: u8 = 0b0000_0011;
const HDR1_RND_DELTA_PLUS1: u8 = 0b01;
const HDR1_RND_DELTA_MINUS1: u8 = 0b10;
const HDR1_RND_DELTA_SAME: u8 = 0b11;
const HDR1_RND_LITERAL: u8 = 0b00;

const HDR1_PROP_SHIFT: u8 = 2;
const HDR1_PROP_MASK: u8 = 0b0001_1100;

const HDR1_SND_REF: u8 = 1 << 5;
const HDR1_PK_REF: u8 = 1 << 6;
const HDR1_PK2_REF: u8 = 1 << 7;

// ── LRU table (mirrors lru_table.go) ────────────────────────────────────

/// Reference ID for a key in an [`LruTable`]: `(bucket << 1) | slot`.
type LruTableReferenceId = u16;

/// A fixed-size, 2-way set-associative hash table. Mirrors go-algorand's
/// `lruTable[K]`: `numBuckets = n/2` buckets, each holding 2 slots, with a
/// 1-bit-per-bucket MRU flag driving LRU eviction on collision.
#[derive(Debug)]
struct LruTable<K> {
    num_buckets: u32,
    buckets: Vec<[K; 2]>,
    mru: Vec<u8>, // 1 bit per bucket
}

impl<K: Copy + Default + PartialEq> LruTable<K> {
    /// `n` is the total entry count (power of two, at least 16); the table
    /// has `n/2` buckets of 2 slots each.
    fn new(n: u32) -> Result<Self, VpackError> {
        if n < 16 || (n & (n - 1)) != 0 {
            return Err(VpackError::InvalidTableSize(
                "lruTable size must be a power of 2 and at least 16".into(),
            ));
        }
        let num_buckets = n / 2;
        Ok(Self {
            num_buckets,
            buckets: vec![[K::default(); 2]; num_buckets as usize],
            mru: vec![0u8; (num_buckets / 8) as usize],
        })
    }

    fn mru_bitmask(&self, b: u32) -> (usize, u8) {
        ((b >> 3) as usize, 1 << (b & 7))
    }

    /// Returns the index (0 or 1) of the LRU slot in bucket `b`.
    fn lru_slot(&self, b: u32) -> u8 {
        let (byte_idx, mask) = self.mru_bitmask(b);
        if (self.mru[byte_idx] & mask) == 0 {
            1
        } else {
            0
        }
    }

    fn set_mru_slot(&mut self, b: u32, slot: u8) {
        let (byte_idx, mask) = self.mru_bitmask(b);
        if slot == 0 {
            self.mru[byte_idx] &= !mask;
        } else {
            self.mru[byte_idx] |= mask;
        }
    }

    fn hash_to_bucket_index(&self, h: u64) -> u32 {
        (h & u64::from(self.num_buckets - 1)) as u32
    }

    /// Looks up `k` (using precomputed hash `h`); marks it MRU if found.
    fn lookup(&mut self, k: K, h: u64) -> Option<LruTableReferenceId> {
        let b = self.hash_to_bucket_index(h);
        let slots = self.buckets[b as usize];
        if slots[0] == k {
            self.set_mru_slot(b, 0);
            return Some((b << 1) as LruTableReferenceId);
        }
        if slots[1] == k {
            self.set_mru_slot(b, 1);
            return Some(((b << 1) | 1) as LruTableReferenceId);
        }
        None
    }

    /// Inserts `k` (evicting the LRU slot in its bucket) and returns its
    /// new reference ID. The inserted key becomes MRU.
    fn insert(&mut self, k: K, h: u64) -> LruTableReferenceId {
        let b = self.hash_to_bucket_index(h);
        let evict = self.lru_slot(b);
        self.buckets[b as usize][evict as usize] = k;
        self.set_mru_slot(b, evict);
        ((b as LruTableReferenceId) << 1) | LruTableReferenceId::from(evict)
    }

    /// Returns the key for `id`, marking it MRU. `None` if `id` is
    /// out-of-range (bucket index `>= num_buckets`).
    fn fetch(&mut self, id: LruTableReferenceId) -> Option<K> {
        let b = u32::from(id) >> 1;
        let slot = (id & 1) as u8;
        if b >= self.num_buckets {
            return None;
        }
        self.set_mru_slot(b, slot);
        Some(self.buckets[b as usize][slot as usize])
    }
}

// ── proposal sliding window (mirrors proposal_window.go) ───────────────

/// All values inside a vote's `r.prop` map, plus a mask of which optional
/// fields were present. Mirrors go-algorand's `proposalEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ProposalEntry {
    dig: [u8; DIGEST_SIZE],
    encdig: [u8; DIGEST_SIZE],
    oprop: [u8; DIGEST_SIZE],
    oper_enc: [u8; MAX_MSGP_VARUINT_SIZE],
    oper_len: u8,
    mask: u8,
}

/// Fixed at 7 because hdr1 holds only 3 bits for the reference code
/// (0 = literal, 1-7 = index).
const PROPOSAL_WINDOW_SIZE: usize = 7;

/// A 7-entry HPACK-style (RFC 7541) sliding window of recent proposal
/// bundles. Mirrors go-algorand's `propWindow`.
#[derive(Default)]
struct PropWindow {
    entries: [ProposalEntry; PROPOSAL_WINDOW_SIZE],
    head: usize,
    size: usize,
}

impl PropWindow {
    /// Returns the 1-based HPACK index of `pv` (0 if not found); walks
    /// oldest-to-newest, worst case 7 comparisons.
    fn lookup(&self, pv: &ProposalEntry) -> usize {
        for i in 0..self.size {
            let slot = (self.head + i) % PROPOSAL_WINDOW_SIZE;
            if self.entries[slot] == *pv {
                return self.size - i;
            }
        }
        0
    }

    /// Returns the entry at HPACK index `idx` (1..=size), `None` if out of
    /// range.
    fn by_ref(&self, idx: usize) -> Option<ProposalEntry> {
        if idx < 1 || idx > self.size {
            return None;
        }
        let physical = (self.head + self.size - idx) % PROPOSAL_WINDOW_SIZE;
        Some(self.entries[physical])
    }

    /// Inserts `pv` as the newest entry (HPACK index 1), evicting the
    /// oldest entry once the window is full.
    fn insert_new(&mut self, pv: ProposalEntry) {
        if self.size == PROPOSAL_WINDOW_SIZE {
            self.entries[self.head] = pv;
            self.head = (self.head + 1) % PROPOSAL_WINDOW_SIZE;
        } else {
            let pos = (self.head + self.size) % PROPOSAL_WINDOW_SIZE;
            self.entries[pos] = pv;
            self.size += 1;
        }
    }
}

// ── dynamic-table state shared by StatefulEncoder/StatefulDecoder ──────

/// 32-byte address, keyed in the `snd` LRU table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct AddressValue([u8; DIGEST_SIZE]);

impl AddressValue {
    /// Addresses are fairly uniformly distributed, so a simple XOR of
    /// four 8-byte little-endian chunks is a good hash.
    fn hash(&self) -> u64 {
        u64::from_le_bytes(self.0[0..8].try_into().unwrap())
            ^ u64::from_le_bytes(self.0[8..16].try_into().unwrap())
            ^ u64::from_le_bytes(self.0[16..24].try_into().unwrap())
            ^ u64::from_le_bytes(self.0[24..32].try_into().unwrap())
    }
}

/// A 32-byte public key + 64-byte signature, keyed in the `pk`/`pk2` LRU
/// tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PkSigPair {
    pk: [u8; PK_SIZE],
    sig: [u8; SIG_SIZE],
}

impl Default for PkSigPair {
    // `[u8; 64]` has no `Default` impl (only arrays up to length 32 do), so
    // this can't be derived.
    fn default() -> Self {
        Self {
            pk: [0; PK_SIZE],
            sig: [0; SIG_SIZE],
        }
    }
}

impl PkSigPair {
    /// `pk` and `sig` should already be uniformly distributed, so XOR the
    /// first 8 bytes of each. Malicious values causing hash collisions
    /// only affect the sending peer's own per-peer compression state.
    fn hash(&self) -> u64 {
        u64::from_le_bytes(self.pk[0..8].try_into().unwrap())
            ^ u64::from_le_bytes(self.sig[0..8].try_into().unwrap())
    }
}

/// State shared by [`StatefulEncoder`] and [`StatefulDecoder`]: the three
/// LRU tables (`snd`, `pk`, `pk2`), the proposal sliding window, and the
/// last-seen round number (for `r.rnd` delta encoding). Mirrors
/// go-algorand's `dynamicTableState`.
struct DynamicTableState {
    snd_table: LruTable<AddressValue>,
    pk_table: LruTable<PkSigPair>,
    pk2_table: LruTable<PkSigPair>,
    proposal_window: PropWindow,
    last_rnd: u64,
}

impl DynamicTableState {
    fn new(table_size: u32) -> Result<Self, VpackError> {
        Ok(Self {
            snd_table: LruTable::new(table_size)?,
            pk_table: LruTable::new(table_size)?,
            pk2_table: LruTable::new(table_size)?,
            proposal_window: PropWindow::default(),
            last_rnd: 0,
        })
    }
}

// ── stateful-layer reader (mirrors statefulReader) ──────────────────────

struct StatefulReader<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> StatefulReader<'a> {
    fn read_fixed(&mut self, n: usize, field: &str) -> Result<&'a [u8], VpackError> {
        if self.pos + n > self.src.len() {
            return Err(VpackError::Decompress(format!("truncated {field}")));
        }
        let data = &self.src[self.pos..self.pos + n];
        self.pos += n;
        Ok(data)
    }

    fn read_varuint_bytes(&mut self, field: &str) -> Result<&'a [u8], VpackError> {
        if self.pos + 1 > self.src.len() {
            return Err(VpackError::Decompress(format!("truncated {field} marker")));
        }
        let more = msgp_varuint_remaining(self.src[self.pos])
            .map_err(|_| VpackError::Decompress(format!("invalid {field} marker")))?;
        let total = 1 + more;
        if self.pos + total > self.src.len() {
            return Err(VpackError::Decompress(format!("truncated {field}")));
        }
        let data = &self.src[self.pos..self.pos + total];
        self.pos += total;
        Ok(data)
    }

    fn read_varuint(&mut self, field: &str) -> Result<(&'a [u8], u64), VpackError> {
        let data = self.read_varuint_bytes(field)?;
        let value = match data.len() {
            1 => u64::from(data[0]),
            2 => u64::from(data[1]),
            3 => u64::from(u16::from_be_bytes(data[1..3].try_into().unwrap())),
            5 => u64::from(u32::from_be_bytes(data[1..5].try_into().unwrap())),
            9 => u64::from_be_bytes(data[1..9].try_into().unwrap()),
            n => {
                return Err(VpackError::Decompress(format!(
                    "readVaruint: {field} unexpected length {n}"
                )))
            }
        };
        Ok((data, value))
    }

    fn read_dynamic_ref(&mut self, field: &str) -> Result<LruTableReferenceId, VpackError> {
        if self.pos + 2 > self.src.len() {
            return Err(VpackError::Decompress(format!("truncated {field}")));
        }
        let id = u16::from_be_bytes(self.src[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        Ok(id)
    }
}

fn append_dynamic_ref(out: &mut Vec<u8>, id: LruTableReferenceId) {
    out.extend_from_slice(&id.to_be_bytes());
}

/// Appends the canonical msgpack encoding of `v` to `out` (mirrors the
/// subset of `github.com/algorand/msgp/msgp`'s `AppendUint64` used by
/// go-algorand's `StatefulDecoder.Decompress` to re-synthesize a delta
/// -decoded round number).
fn append_msgp_uint64(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=0x7f => out.push(v as u8),
        0x80..=0xff => {
            out.push(MSGP_UINT8);
            out.push(v as u8);
        }
        0x100..=0xffff => {
            out.push(MSGP_UINT16);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
        0x10000..=0xffff_ffff => {
            out.push(MSGP_UINT32);
            out.extend_from_slice(&(v as u32).to_be_bytes());
        }
        _ => {
            out.push(MSGP_UINT64);
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
}

/// Compresses votes (previously compressed by the stateless layer) by
/// replacing frequently repeated field values with references to
/// previously-seen values. Mirrors go-algorand's `vpack.StatefulEncoder`.
///
/// Not thread-safe; not wired into any live network path (see the module
/// docs).
pub struct StatefulEncoder {
    state: DynamicTableState,
}

impl StatefulEncoder {
    /// `table_size` is the total entry count for each of the three LRU
    /// tables (must be a power of two, at least 16).
    pub fn new(table_size: u32) -> Result<Self, VpackError> {
        Ok(Self {
            state: DynamicTableState::new(table_size)?,
        })
    }

    /// Compresses `src` (the output of [`compress_vote`]) using dynamic
    /// references to previously seen values. Mirrors go-algorand's
    /// `StatefulEncoder.Compress`.
    pub fn compress(&mut self, src: &[u8]) -> Result<Vec<u8>, VpackError> {
        let mut r = StatefulReader { src, pos: 0 };

        if src.len() < 2 {
            return Err(VpackError::Decompress("src too short".into()));
        }
        let hdr0 = src[0];
        let mut hdr1: u8 = 0;
        r.pos = 2;

        let mut out = Vec::with_capacity(src.len());
        out.push(hdr0);
        out.push(0); // filled in with hdr1 below

        let pf = r.read_fixed(PF_SIZE, "pf")?;
        out.extend_from_slice(pf);

        if (hdr0 & BIT_PER) != 0 {
            let per = r.read_varuint_bytes("r.per")?;
            out.extend_from_slice(per);
        }

        let mut prop = ProposalEntry::default();
        if (hdr0 & BIT_DIG) != 0 {
            let dig = r.read_fixed(DIGEST_SIZE, "dig")?;
            prop.dig.copy_from_slice(dig);
        }
        if (hdr0 & BIT_ENC_DIG) != 0 {
            let encdig = r.read_fixed(DIGEST_SIZE, "encdig")?;
            prop.encdig.copy_from_slice(encdig);
        }
        if (hdr0 & BIT_OPER) != 0 {
            let oper = r.read_varuint_bytes("oper")?;
            prop.oper_enc[..oper.len()].copy_from_slice(oper);
            prop.oper_len = oper.len() as u8;
        }
        if (hdr0 & BIT_OPROP) != 0 {
            let oprop = r.read_fixed(DIGEST_SIZE, "oprop")?;
            prop.oprop.copy_from_slice(oprop);
        }
        prop.mask = hdr0 & PROP_FIELDS_MASK;

        let idx = self.state.proposal_window.lookup(&prop);
        if idx != 0 {
            hdr1 |= (idx as u8) << HDR1_PROP_SHIFT;
        } else {
            self.state.proposal_window.insert_new(prop);
            if (hdr0 & BIT_DIG) != 0 {
                out.extend_from_slice(&prop.dig);
            }
            if (hdr0 & BIT_ENC_DIG) != 0 {
                out.extend_from_slice(&prop.encdig);
            }
            if (hdr0 & BIT_OPER) != 0 {
                out.extend_from_slice(&prop.oper_enc[..prop.oper_len as usize]);
            }
            if (hdr0 & BIT_OPROP) != 0 {
                out.extend_from_slice(&prop.oprop);
            }
        }

        let (rnd_data, rnd) = r.read_varuint("rnd")?;
        let last_rnd = self.state.last_rnd;
        if rnd == last_rnd {
            hdr1 |= HDR1_RND_DELTA_SAME;
        } else if last_rnd < u64::MAX && rnd == last_rnd + 1 {
            hdr1 |= HDR1_RND_DELTA_PLUS1;
        } else if last_rnd > 0 && rnd == last_rnd - 1 {
            hdr1 |= HDR1_RND_DELTA_MINUS1;
        } else {
            out.extend_from_slice(rnd_data);
        }
        self.state.last_rnd = rnd;

        let snd_data = r.read_fixed(DIGEST_SIZE, "sender")?;
        let mut snd = AddressValue::default();
        snd.0.copy_from_slice(snd_data);
        let snd_h = snd.hash();
        if let Some(id) = self.state.snd_table.lookup(snd, snd_h) {
            hdr1 |= HDR1_SND_REF;
            append_dynamic_ref(&mut out, id);
        } else {
            out.extend_from_slice(&snd.0);
            self.state.snd_table.insert(snd, snd_h);
        }

        if (hdr0 & BIT_STEP) != 0 {
            let step = r.read_varuint_bytes("step")?;
            out.extend_from_slice(step);
        }

        let pk_bundle = r.read_fixed(PK_SIZE + SIG_SIZE, "pk bundle")?;
        let mut pk = PkSigPair::default();
        pk.pk.copy_from_slice(&pk_bundle[..PK_SIZE]);
        pk.sig.copy_from_slice(&pk_bundle[PK_SIZE..]);
        let pk_h = pk.hash();
        if let Some(id) = self.state.pk_table.lookup(pk, pk_h) {
            hdr1 |= HDR1_PK_REF;
            append_dynamic_ref(&mut out, id);
        } else {
            out.extend_from_slice(&pk.pk);
            out.extend_from_slice(&pk.sig);
            self.state.pk_table.insert(pk, pk_h);
        }

        let pk2_bundle = r.read_fixed(PK_SIZE + SIG_SIZE, "pk2 bundle")?;
        let mut pk2 = PkSigPair::default();
        pk2.pk.copy_from_slice(&pk2_bundle[..PK_SIZE]);
        pk2.sig.copy_from_slice(&pk2_bundle[PK_SIZE..]);
        let pk2_h = pk2.hash();
        if let Some(id) = self.state.pk2_table.lookup(pk2, pk2_h) {
            hdr1 |= HDR1_PK2_REF;
            append_dynamic_ref(&mut out, id);
        } else {
            out.extend_from_slice(&pk2.pk);
            out.extend_from_slice(&pk2.sig);
            self.state.pk2_table.insert(pk2, pk2_h);
        }

        let sigs = r.read_fixed(SIG_SIZE, "sig.s")?;
        out.extend_from_slice(sigs);

        if r.pos != src.len() {
            return Err(VpackError::Decompress(format!(
                "length mismatch: expected {}, got {}",
                src.len(),
                r.pos
            )));
        }

        out[1] = hdr1;
        Ok(out)
    }
}

/// Decompresses votes compressed by [`StatefulEncoder`], reversing it back
/// into valid stateless-vpack-format bytes (pass the result to
/// [`decompress_vote`]). Mirrors go-algorand's `vpack.StatefulDecoder`.
///
/// Not thread-safe; not wired into any live network path (see the module
/// docs).
pub struct StatefulDecoder {
    state: DynamicTableState,
}

impl StatefulDecoder {
    /// `table_size` is the total entry count for each of the three LRU
    /// tables (must be a power of two, at least 16).
    pub fn new(table_size: u32) -> Result<Self, VpackError> {
        Ok(Self {
            state: DynamicTableState::new(table_size)?,
        })
    }

    /// Reverses [`StatefulEncoder::compress`], producing stateless-vpack
    /// bytes suitable for [`decompress_vote`].
    pub fn decompress(&mut self, src: &[u8]) -> Result<Vec<u8>, VpackError> {
        let mut r = StatefulReader { src, pos: 0 };

        if src.len() < 2 {
            return Err(VpackError::Decompress(
                "input shorter than header".into(),
            ));
        }
        let hdr0 = src[0];
        let hdr1 = src[1];
        r.pos = 2;

        let mut out = Vec::with_capacity(src.len());
        out.push(hdr0);
        out.push(0);

        let pf = r.read_fixed(PF_SIZE, "pf")?;
        out.extend_from_slice(pf);

        if (hdr0 & BIT_PER) != 0 {
            let per = r.read_varuint_bytes("per")?;
            out.extend_from_slice(per);
        }

        let prop_ref = (hdr1 & HDR1_PROP_MASK) >> HDR1_PROP_SHIFT;
        let prop = if prop_ref == 0 {
            let mut prop = ProposalEntry::default();
            if (hdr0 & BIT_DIG) != 0 {
                let dig = r.read_fixed(DIGEST_SIZE, "digest")?;
                prop.dig.copy_from_slice(dig);
            }
            if (hdr0 & BIT_ENC_DIG) != 0 {
                let encdig = r.read_fixed(DIGEST_SIZE, "encdig")?;
                prop.encdig.copy_from_slice(encdig);
            }
            if (hdr0 & BIT_OPER) != 0 {
                let oper = r.read_varuint_bytes("oper")?;
                prop.oper_enc[..oper.len()].copy_from_slice(oper);
                prop.oper_len = oper.len() as u8;
            }
            if (hdr0 & BIT_OPROP) != 0 {
                let oprop = r.read_fixed(DIGEST_SIZE, "oprop")?;
                prop.oprop.copy_from_slice(oprop);
            }
            prop.mask = hdr0 & PROP_FIELDS_MASK;
            self.state.proposal_window.insert_new(prop);
            prop
        } else {
            self.state
                .proposal_window
                .by_ref(prop_ref as usize)
                .ok_or_else(|| VpackError::Decompress(format!("bad proposal ref: {prop_ref}")))?
        };

        if (prop.mask & BIT_DIG) != 0 {
            out.extend_from_slice(&prop.dig);
        }
        if (prop.mask & BIT_ENC_DIG) != 0 {
            out.extend_from_slice(&prop.encdig);
        }
        if (prop.mask & BIT_OPER) != 0 {
            out.extend_from_slice(&prop.oper_enc[..prop.oper_len as usize]);
        }
        if (prop.mask & BIT_OPROP) != 0 {
            out.extend_from_slice(&prop.oprop);
        }

        let rnd = match hdr1 & HDR1_RND_MASK {
            HDR1_RND_DELTA_SAME => {
                let rnd = self.state.last_rnd;
                append_msgp_uint64(&mut out, rnd);
                rnd
            }
            HDR1_RND_DELTA_PLUS1 => {
                if self.state.last_rnd == u64::MAX {
                    return Err(VpackError::Decompress(format!(
                        "round overflow: lastRnd {}",
                        self.state.last_rnd
                    )));
                }
                let rnd = self.state.last_rnd + 1;
                append_msgp_uint64(&mut out, rnd);
                rnd
            }
            HDR1_RND_DELTA_MINUS1 => {
                if self.state.last_rnd == 0 {
                    return Err(VpackError::Decompress(format!(
                        "round underflow: lastRnd {}",
                        self.state.last_rnd
                    )));
                }
                let rnd = self.state.last_rnd - 1;
                append_msgp_uint64(&mut out, rnd);
                rnd
            }
            _ => {
                // HDR1_RND_LITERAL (0b00); `debug_assert!` keeps the
                // constant demonstrably load-bearing for this arm.
                debug_assert_eq!(hdr1 & HDR1_RND_MASK, HDR1_RND_LITERAL);
                let (rnd_data, rnd_val) = r.read_varuint("rnd")?;
                out.extend_from_slice(rnd_data);
                rnd_val
            }
        };
        self.state.last_rnd = rnd;

        if (hdr1 & HDR1_SND_REF) != 0 {
            let id = r.read_dynamic_ref("snd ref")?;
            let addr = self
                .state
                .snd_table
                .fetch(id)
                .ok_or_else(|| VpackError::Decompress(format!("bad sender ref: {id}")))?;
            out.extend_from_slice(&addr.0);
        } else {
            let snd_data = r.read_fixed(DIGEST_SIZE, "sender")?;
            let mut addr = AddressValue::default();
            addr.0.copy_from_slice(snd_data);
            out.extend_from_slice(&addr.0);
            self.state.snd_table.insert(addr, addr.hash());
        }

        if (hdr0 & BIT_STEP) != 0 {
            let step = r.read_varuint_bytes("step")?;
            out.extend_from_slice(step);
        }

        if (hdr1 & HDR1_PK_REF) != 0 {
            let id = r.read_dynamic_ref("pk ref")?;
            let pkb = self
                .state
                .pk_table
                .fetch(id)
                .ok_or_else(|| VpackError::Decompress(format!("bad pk ref: {id}")))?;
            out.extend_from_slice(&pkb.pk);
            out.extend_from_slice(&pkb.sig);
        } else {
            let pk_bundle = r.read_fixed(PK_SIZE + SIG_SIZE, "pk bundle")?;
            let mut pkb = PkSigPair::default();
            pkb.pk.copy_from_slice(&pk_bundle[..PK_SIZE]);
            pkb.sig.copy_from_slice(&pk_bundle[PK_SIZE..]);
            out.extend_from_slice(&pkb.pk);
            out.extend_from_slice(&pkb.sig);
            self.state.pk_table.insert(pkb, pkb.hash());
        }

        if (hdr1 & HDR1_PK2_REF) != 0 {
            let id = r.read_dynamic_ref("pk2 ref")?;
            let pk2b = self
                .state
                .pk2_table
                .fetch(id)
                .ok_or_else(|| VpackError::Decompress(format!("bad pk2 ref: {id}")))?;
            out.extend_from_slice(&pk2b.pk);
            out.extend_from_slice(&pk2b.sig);
        } else {
            let pk2_bundle = r.read_fixed(PK_SIZE + SIG_SIZE, "pk2 bundle")?;
            let mut pk2b = PkSigPair::default();
            pk2b.pk.copy_from_slice(&pk2_bundle[..PK_SIZE]);
            pk2b.sig.copy_from_slice(&pk2_bundle[PK_SIZE..]);
            out.extend_from_slice(&pk2b.pk);
            out.extend_from_slice(&pk2b.sig);
            self.state.pk2_table.insert(pk2b, pk2b.hash());
        }

        let sigs = r.read_fixed(SIG_SIZE, "sig.s")?;
        out.extend_from_slice(sigs);

        if r.pos != src.len() {
            return Err(VpackError::Decompress(format!(
                "length mismatch: expected {}, got {}",
                src.len(),
                r.pos
            )));
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── hand-built msgpack vote helpers (mirrors the fixture generator
    // used to capture real go-algorand vpack output; see module docs) ──────

    fn seq(n: usize, start: u8) -> Vec<u8> {
        (0..n).map(|i| start.wrapping_add(i as u8)).collect()
    }

    fn append_fixmap(buf: &mut Vec<u8>, n: usize) {
        buf.push(0x80 | n as u8);
    }
    fn append_fixstr(buf: &mut Vec<u8>, s: &str) {
        buf.push(0xa0 | s.len() as u8);
        buf.extend_from_slice(s.as_bytes());
    }
    fn append_bin8(buf: &mut Vec<u8>, data: &[u8]) {
        buf.push(0xc4);
        buf.push(data.len() as u8);
        buf.extend_from_slice(data);
    }
    fn append_uint(buf: &mut Vec<u8>, u: u64) {
        match u {
            0..=0x7f => buf.push(u as u8),
            0x80..=0xff => {
                buf.push(0xcc);
                buf.push(u as u8);
            }
            0x100..=0xffff => {
                buf.push(0xcd);
                buf.extend_from_slice(&(u as u16).to_be_bytes());
            }
            0x10000..=0xffff_ffff => {
                buf.push(0xce);
                buf.extend_from_slice(&(u as u32).to_be_bytes());
            }
            _ => {
                buf.push(0xcf);
                buf.extend_from_slice(&u.to_be_bytes());
            }
        }
    }

    #[derive(Default, Clone)]
    struct VoteSpec {
        pf: Vec<u8>,
        per: Option<u64>,
        dig: Option<Vec<u8>>,
        encdig: Option<Vec<u8>>,
        oper: Option<u64>,
        oprop: Option<Vec<u8>>,
        rnd: u64,
        snd: Vec<u8>,
        step: Option<u64>,
        p: Vec<u8>,
        p1s: Vec<u8>,
        p2: Vec<u8>,
        p2s: Vec<u8>,
        s: Vec<u8>,
    }

    /// Hand-encodes the exact msgpack bytes go-algorand's msgp codegen
    /// produces for `agreement.UnauthenticatedVote` (fixmap, omitempty,
    /// lexicographically-sorted keys). This is the same construction used
    /// offline against the real `network/vpack` source (copied verbatim
    /// from `../go-algorand/network/vpack/{vpack,msgp,parse}.go`, pinned at
    /// `v5.0.0-stable`) to capture the `EXPECTED_*` byte vectors below —
    /// see [`interop_fixtures`].
    fn build_msgp_vote(v: &VoteSpec) -> Vec<u8> {
        let mut buf = Vec::new();

        let prop_present =
            v.dig.is_some() || v.encdig.is_some() || v.oper.is_some() || v.oprop.is_some();
        let mut r_field_count = 2; // rnd, snd
        if v.per.is_some() {
            r_field_count += 1;
        }
        if prop_present {
            r_field_count += 1;
        }
        if v.step.is_some() {
            r_field_count += 1;
        }

        append_fixmap(&mut buf, 3);
        append_fixstr(&mut buf, "cred");
        append_fixmap(&mut buf, 1);
        append_fixstr(&mut buf, "pf");
        append_bin8(&mut buf, &v.pf);

        append_fixstr(&mut buf, "r");
        append_fixmap(&mut buf, r_field_count);
        if let Some(per) = v.per {
            append_fixstr(&mut buf, "per");
            append_uint(&mut buf, per);
        }
        if prop_present {
            let mut prop_count = 0;
            if v.dig.is_some() {
                prop_count += 1;
            }
            if v.encdig.is_some() {
                prop_count += 1;
            }
            if v.oper.is_some() {
                prop_count += 1;
            }
            if v.oprop.is_some() {
                prop_count += 1;
            }
            append_fixstr(&mut buf, "prop");
            append_fixmap(&mut buf, prop_count);
            if let Some(dig) = &v.dig {
                append_fixstr(&mut buf, "dig");
                append_bin8(&mut buf, dig);
            }
            if let Some(encdig) = &v.encdig {
                append_fixstr(&mut buf, "encdig");
                append_bin8(&mut buf, encdig);
            }
            if let Some(oper) = v.oper {
                append_fixstr(&mut buf, "oper");
                append_uint(&mut buf, oper);
            }
            if let Some(oprop) = &v.oprop {
                append_fixstr(&mut buf, "oprop");
                append_bin8(&mut buf, oprop);
            }
        }
        append_fixstr(&mut buf, "rnd");
        append_uint(&mut buf, v.rnd);
        append_fixstr(&mut buf, "snd");
        append_bin8(&mut buf, &v.snd);
        if let Some(step) = v.step {
            append_fixstr(&mut buf, "step");
            append_uint(&mut buf, step);
        }

        append_fixstr(&mut buf, "sig");
        append_fixmap(&mut buf, 6);
        append_fixstr(&mut buf, "p");
        append_bin8(&mut buf, &v.p);
        append_fixstr(&mut buf, "p1s");
        append_bin8(&mut buf, &v.p1s);
        append_fixstr(&mut buf, "p2");
        append_bin8(&mut buf, &v.p2);
        append_fixstr(&mut buf, "p2s");
        append_bin8(&mut buf, &v.p2s);
        append_fixstr(&mut buf, "ps");
        append_bin8(&mut buf, &[0u8; 64]);
        append_fixstr(&mut buf, "s");
        append_bin8(&mut buf, &v.s);

        buf
    }

    fn base_spec() -> VoteSpec {
        VoteSpec {
            pf: seq(80, 0x01),
            rnd: 12345,
            snd: seq(32, 0x10),
            p: seq(32, 0x20),
            p1s: seq(64, 0x30),
            p2: seq(32, 0x40),
            p2s: seq(64, 0x50),
            s: seq(64, 0x60),
            ..Default::default()
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ── round-trip tests over hand-built votes ──────────────────────────

    #[test]
    fn roundtrip_minimal_vote() {
        let v = base_spec();
        let msgp = build_msgp_vote(&v);
        let compressed = compress_vote(&msgp).unwrap();
        assert_eq!(compressed[0], 0); // no optional bits set
        assert_eq!(compressed[1], 0); // stateful byte always zero
        let decompressed = decompress_vote(&compressed).unwrap();
        assert_eq!(decompressed, msgp);
    }

    #[test]
    fn roundtrip_with_per() {
        let mut v = base_spec();
        v.per = Some(3);
        let msgp = build_msgp_vote(&v);
        let compressed = compress_vote(&msgp).unwrap();
        assert_eq!(compressed[0], BIT_PER);
        assert_eq!(decompress_vote(&compressed).unwrap(), msgp);
    }

    #[test]
    fn roundtrip_with_step() {
        let mut v = base_spec();
        v.step = Some(5);
        let msgp = build_msgp_vote(&v);
        let compressed = compress_vote(&msgp).unwrap();
        assert_eq!(compressed[0], BIT_STEP);
        assert_eq!(decompress_vote(&compressed).unwrap(), msgp);
    }

    #[test]
    fn roundtrip_full_proposal() {
        let mut v = base_spec();
        v.dig = Some(seq(32, 0x70));
        v.encdig = Some(seq(32, 0x80));
        v.oper = Some(7);
        v.oprop = Some(seq(32, 0x90));
        let msgp = build_msgp_vote(&v);
        let compressed = compress_vote(&msgp).unwrap();
        assert_eq!(compressed[0], BIT_DIG | BIT_ENC_DIG | BIT_OPER | BIT_OPROP);
        assert_eq!(decompress_vote(&compressed).unwrap(), msgp);
    }

    #[test]
    fn roundtrip_everything() {
        let mut v = base_spec();
        v.per = Some(2);
        v.step = Some(9);
        v.dig = Some(seq(32, 0xA0));
        v.encdig = Some(seq(32, 0xB0));
        v.oper = Some(300); // exercises uint16 varuint width
        v.oprop = Some(seq(32, 0xC0));
        let msgp = build_msgp_vote(&v);
        let compressed = compress_vote(&msgp).unwrap();
        assert_eq!(
            compressed[0],
            BIT_PER | BIT_STEP | BIT_DIG | BIT_ENC_DIG | BIT_OPER | BIT_OPROP
        );
        assert_eq!(decompress_vote(&compressed).unwrap(), msgp);
    }

    #[test]
    fn roundtrip_large_varuints() {
        let mut v = base_spec();
        v.rnd = 70_000; // uint32 varuint
        v.step = Some(130); // uint8 varuint
        v.dig = Some(seq(32, 0xD0));
        v.oper = Some(5_000_000_000); // uint64 varuint
        let msgp = build_msgp_vote(&v);
        let compressed = compress_vote(&msgp).unwrap();
        assert_eq!(decompress_vote(&compressed).unwrap(), msgp);
    }

    #[test]
    fn roundtrip_dig_only() {
        let mut v = base_spec();
        v.dig = Some(seq(32, 0xE0));
        let msgp = build_msgp_vote(&v);
        let compressed = compress_vote(&msgp).unwrap();
        assert_eq!(compressed[0], BIT_DIG);
        assert_eq!(decompress_vote(&compressed).unwrap(), msgp);
    }

    #[test]
    fn roundtrip_via_unauthenticated_vote_type() {
        use algo_agreement::{
            Period, ProposalValue, RawVote, Step, UnauthenticatedCredential, UnauthenticatedVote,
        };
        use algo_consensus_crypto::OneTimeSignature;
        use algo_types::{Address, Digest, Round};

        let vote = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x11; 32]),
                round: Round(999),
                period: Period(0),
                step: Step(1),
                proposal: ProposalValue {
                    original_period: Period(0),
                    original_proposer: Address([0u8; 32]),
                    block_digest: Digest([0x22; 32]),
                    encoding_digest: Digest([0u8; 32]),
                },
            },
            cred: UnauthenticatedCredential::new([0x33; 80]),
            sig: OneTimeSignature {
                sig: [0x44; 64],
                pk: [0x55; 32],
                pk_sig_old: [0u8; 64],
                pk2: [0x66; 32],
                pk1_sig: [0x77; 64],
                pk2_sig: [0x88; 64],
            },
        };

        let compressed = compress_unauthenticated_vote(&vote).unwrap();
        let decoded = decompress_to_unauthenticated_vote(&compressed).unwrap();

        // Neither UnauthenticatedVote nor OneTimeSignature derive PartialEq
        // (upstream types), so compare field-by-field.
        assert_eq!(decoded.raw_vote.sender.0, vote.raw_vote.sender.0);
        assert_eq!(decoded.raw_vote.round.0, vote.raw_vote.round.0);
        assert_eq!(decoded.raw_vote.period.0, vote.raw_vote.period.0);
        assert_eq!(decoded.raw_vote.step.0, vote.raw_vote.step.0);
        assert_eq!(decoded.raw_vote.proposal, vote.raw_vote.proposal);
        assert_eq!(decoded.cred.proof, vote.cred.proof);
        assert_eq!(decoded.sig.sig, vote.sig.sig);
        assert_eq!(decoded.sig.pk, vote.sig.pk);
        assert_eq!(decoded.sig.pk_sig_old, vote.sig.pk_sig_old);
        assert_eq!(decoded.sig.pk2, vote.sig.pk2);
        assert_eq!(decoded.sig.pk1_sig, vote.sig.pk1_sig);
        assert_eq!(decoded.sig.pk2_sig, vote.sig.pk2_sig);
    }

    // ── error-path tests ─────────────────────────────────────────────────

    #[test]
    fn compress_rejects_wrong_top_level_field_count() {
        let mut buf = Vec::new();
        append_fixmap(&mut buf, 2); // wrong: should be 3
        append_fixstr(&mut buf, "cred");
        append_fixmap(&mut buf, 0);
        append_fixstr(&mut buf, "r");
        append_fixmap(&mut buf, 0);
        let err = compress_vote(&buf).unwrap_err();
        assert!(matches!(err, VpackError::Parse(_)));
    }

    #[test]
    fn compress_rejects_nonzero_ps() {
        let mut v = base_spec();
        // build manually with nonzero "ps"
        let mut buf = Vec::new();
        append_fixmap(&mut buf, 3);
        append_fixstr(&mut buf, "cred");
        append_fixmap(&mut buf, 1);
        append_fixstr(&mut buf, "pf");
        append_bin8(&mut buf, &v.pf);
        append_fixstr(&mut buf, "r");
        append_fixmap(&mut buf, 2);
        append_fixstr(&mut buf, "rnd");
        append_uint(&mut buf, v.rnd);
        append_fixstr(&mut buf, "snd");
        append_bin8(&mut buf, &v.snd);
        append_fixstr(&mut buf, "sig");
        append_fixmap(&mut buf, 6);
        append_fixstr(&mut buf, "p");
        append_bin8(&mut buf, &v.p);
        append_fixstr(&mut buf, "p1s");
        append_bin8(&mut buf, &v.p1s);
        append_fixstr(&mut buf, "p2");
        append_bin8(&mut buf, &v.p2);
        append_fixstr(&mut buf, "p2s");
        append_bin8(&mut buf, &v.p2s);
        append_fixstr(&mut buf, "ps");
        append_bin8(&mut buf, &[1u8; 64]); // nonzero!
        append_fixstr(&mut buf, "s");
        append_bin8(&mut buf, &v.s);

        v.p = vec![]; // silence unused-mut warning path
        let err = compress_vote(&buf).unwrap_err();
        assert!(matches!(err, VpackError::Parse(_)));
    }

    #[test]
    fn decompress_rejects_truncated_header() {
        let err = decompress_vote(&[0x00]).unwrap_err();
        assert!(matches!(err, VpackError::Decompress(_)));
    }

    #[test]
    fn decompress_rejects_trailing_bytes() {
        let v = base_spec();
        let msgp = build_msgp_vote(&v);
        let mut compressed = compress_vote(&msgp).unwrap();
        compressed.push(0xff);
        let err = decompress_vote(&compressed).unwrap_err();
        assert!(matches!(err, VpackError::Decompress(_)));
    }

    #[test]
    fn decompress_flags_likely_uncompressed_input() {
        // A plausible-looking (but not actually valid) uncompressed msgpack
        // vote header handed to the vpack decoder should be flagged.
        let v = base_spec();
        let msgp = build_msgp_vote(&v);
        let err = decompress_vote(&msgp).unwrap_err();
        assert!(matches!(err, VpackError::LikelyUncompressed(_)));
    }

    #[test]
    fn compressed_size_bounds_hold() {
        let mut v = base_spec();
        v.per = Some(u64::MAX);
        v.step = Some(u64::MAX);
        v.dig = Some(seq(32, 0));
        v.encdig = Some(seq(32, 1));
        v.oper = Some(u64::MAX);
        v.oprop = Some(seq(32, 2));
        let msgp = build_msgp_vote(&v);
        assert!(msgp.len() <= MAX_MSGPACK_VOTE_SIZE);
        let compressed = compress_vote(&msgp).unwrap();
        assert!(compressed.len() <= MAX_COMPRESSED_VOTE_SIZE);
    }

    // ── pinned interop fixtures ──────────────────────────────────────────
    //
    // These byte vectors were captured by running go-algorand's actual,
    // *unmodified* `network/vpack` source (`vpack.go`, `msgp.go`,
    // `parse.go` copied verbatim from `../go-algorand/network/vpack/` at
    // the repo's `v5.0.0-stable` pin) against hand-built msgpack vote
    // bytes identical to `build_msgp_vote` above, offline via a small Go
    // driver (not checked into either repo). Both the `msgp` (uncompressed
    // input) and `vpack` (go-algorand's real compressed output) columns
    // are pinned so this test proves genuine byte-level wire compatibility
    // with real go-algorand `vpack` output, not just Rust self-consistency.
    mod interop_fixtures {
        use super::*;

        fn check(msgp_hex: &str, vpack_hex: &str) {
            let msgp = from_hex(msgp_hex);
            let expected_vpack = from_hex(vpack_hex);

            let compressed = compress_vote(&msgp).expect("compress");
            assert_eq!(
                hex(&compressed),
                hex(&expected_vpack),
                "compressed output must byte-match real go-algorand vpack output"
            );

            let decompressed = decompress_vote(&expected_vpack).expect("decompress");
            assert_eq!(
                hex(&decompressed),
                msgp_hex,
                "decompressing go-algorand's own output must reproduce the original msgp"
            );
        }

        #[test]
        fn minimal() {
            check(
                "83a46372656481a27066c4500102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50a17282a3726e64cd3039a3736e64c420101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2fa373696786a170c420202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fa3703173c440303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6fa27032c420404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fa3703273c440505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8fa27073c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a173c440606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "00000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50cd3039101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            );
        }

        #[test]
        fn with_per() {
            check(
                "83a46372656481a27066c4500102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50a17283a370657203a3726e64cd3039a3736e64c420101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2fa373696786a170c420202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fa3703173c440303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6fa27032c420404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fa3703273c440505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8fa27073c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a173c440606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5003cd3039101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            );
        }

        #[test]
        fn with_step() {
            check(
                "83a46372656481a27066c4500102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50a17283a3726e64cd3039a3736e64c420101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2fa47374657005a373696786a170c420202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fa3703173c440303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6fa27032c420404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fa3703273c440505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8fa27073c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a173c440606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50cd3039101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f05202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            );
        }

        #[test]
        fn with_full_prop() {
            check(
                "83a46372656481a27066c4500102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50a17283a470726f7084a3646967c420707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8fa6656e63646967c420808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa46f70657207a56f70726f70c420909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafa3726e64cd3039a3736e64c420101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2fa373696786a170c420202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fa3703173c440303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6fa27032c420404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fa3703273c440505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8fa27073c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a173c440606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "1e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f07909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafcd3039101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            );
        }

        #[test]
        fn with_everything() {
            check(
                "83a46372656481a27066c4500102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50a17285a370657202a470726f7084a3646967c420a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfa6656e63646967c420b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfa46f706572cd012ca56f70726f70c420c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfa3726e64cd3039a3736e64c420101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2fa47374657009a373696786a170c420202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fa3703173c440303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6fa27032c420404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fa3703273c440505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8fa27073c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a173c440606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "3f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5002a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfcd012cc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfcd3039101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f09202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            );
        }

        #[test]
        fn large_varuints() {
            check(
                "83a46372656481a27066c4500102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50a17284a470726f7082a3646967c420d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeefa46f706572cf000000012a05f200a3726e64ce00011170a3736e64c420101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2fa473746570cc82a373696786a170c420202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fa3703173c440303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6fa27032c420404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fa3703273c440505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8fa27073c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a173c440606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "2a000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeefcf000000012a05f200ce00011170101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2fcc82202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            );
        }

        #[test]
        fn dig_only() {
            check(
                "83a46372656481a27066c4500102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50a17283a470726f7081a3646967c420e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeffa3726e64cd3039a3736e64c420101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2fa373696786a170c420202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fa3703173c440303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6fa27032c420404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fa3703273c440505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8fa27073c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a173c440606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "02000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeffcd3039101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            );
        }
    }

    // ── stateful (dynamic-table) layer tests ────────────────────────────

    mod stateful {
        use super::*;

        // ── LRU table (mirrors network/vpack/lru_table_test.go) ─────────

        #[test]
        fn lru_table_size_validation() {
            let err = LruTable::<i32>::new(100).unwrap_err();
            assert!(matches!(err, VpackError::InvalidTableSize(_)));
            let err = LruTable::<i32>::new(8).unwrap_err();
            assert!(matches!(err, VpackError::InvalidTableSize(_)));

            for size in [16u32, 32, 64, 128, 256, 512, 1024, 2048] {
                assert!(LruTable::<i32>::new(size).is_ok());
                assert!(StatefulEncoder::new(size).is_ok());
                assert!(StatefulDecoder::new(size).is_ok());
            }
        }

        #[test]
        fn lru_table_invalid_id_fetch() {
            let mut table = LruTable::<PkSigPair>::new(1024).unwrap();
            let invalid_id: LruTableReferenceId = 1024; // >= num_buckets (512)
            assert_eq!(table.fetch(invalid_id), None);
        }

        #[test]
        fn lru_table_insert_lookup_fetch() {
            let mut tab = LruTable::<i32>::new(1024).unwrap();
            let bucket_hash: u64 = 42;
            let base_id: LruTableReferenceId = (bucket_hash as LruTableReferenceId) << 1;

            // first insert on empty table: slot 1 gets used (MRU bit starts 0)
            let id1 = tab.insert(100, bucket_hash);
            assert_eq!(id1, base_id | 1);
            assert_eq!(tab.lru_slot(bucket_hash as u32), 0);

            assert_eq!(tab.lookup(100, bucket_hash), Some(id1));
            assert_eq!(tab.lru_slot(bucket_hash as u32), 0);

            let id2 = tab.insert(200, bucket_hash);
            assert_eq!(id2, base_id);
            assert_eq!(tab.lru_slot(bucket_hash as u32), 1);

            assert!(tab.lookup(100, bucket_hash).is_some());
            assert_eq!(tab.lru_slot(bucket_hash as u32), 0);

            assert!(tab.lookup(200, bucket_hash).is_some());
            assert_eq!(tab.lru_slot(bucket_hash as u32), 1);

            let id3 = tab.insert(300, bucket_hash);
            assert_eq!(id3, base_id | 1);
            assert_eq!(tab.lru_slot(bucket_hash as u32), 0);

            assert_eq!(tab.fetch(id3), Some(300));
            assert_eq!(tab.lru_slot(bucket_hash as u32), 0);

            let id4 = tab.insert(400, bucket_hash);
            assert_eq!(id4, base_id);
            assert_eq!(tab.lru_slot(bucket_hash as u32), 1);

            assert_eq!(tab.fetch(id3), Some(300));
            assert_eq!(tab.lru_slot(bucket_hash as u32), 0);
            assert_eq!(tab.fetch(id4), Some(400));
            assert_eq!(tab.lru_slot(bucket_hash as u32), 1);
        }

        #[test]
        fn lru_eviction_order() {
            let mut tab = LruTable::<i32>::new(1024).unwrap();
            let h: u64 = 42;

            let id1 = tab.insert(100, h);
            assert_eq!(tab.fetch(id1), Some(100));
            let id2 = tab.insert(200, h);
            assert_eq!(tab.fetch(id2), Some(200));

            assert_eq!(tab.lookup(100, h), Some(id1));
            assert_eq!(tab.lookup(200, h), Some(id2));
            // make 100 MRU
            assert_eq!(tab.lookup(100, h), Some(id1));

            // 200 is now LRU; inserting evicts it
            let id3 = tab.insert(300, h);
            assert_eq!(tab.fetch(id3), Some(300));
            assert_eq!(tab.lookup(100, h), Some(id1));
            assert_eq!(tab.lookup(200, h), None);
            assert_eq!(tab.lookup(300, h), Some(id3));

            // make 300 MRU, then insert evicts 100 (now LRU)
            assert_eq!(tab.lookup(300, h), Some(id3));
            let id4 = tab.insert(400, h);
            assert_eq!(tab.fetch(id4), Some(400));
            assert_eq!(tab.lookup(100, h), None);
            assert_eq!(tab.lookup(300, h), Some(id3));
            assert_eq!(tab.lookup(400, h), Some(id4));
        }

        #[test]
        fn lru_ref_id_consistency() {
            let mut tab = LruTable::<i32>::new(1024).unwrap();
            let h: u64 = 42;

            let id1 = tab.insert(100, h);
            assert_eq!(tab.lookup(100, h), Some(id1));
            assert_eq!(tab.fetch(id1), Some(100));

            let id2 = tab.insert(200, h);
            assert_ne!(id1, id2);
            assert_eq!(tab.fetch(id1), Some(100));
            assert_eq!(tab.fetch(id2), Some(200));
        }

        // ── proposal sliding window (mirrors proposal_window_test.go) ───

        fn make_test_prop_bundle(seed: u8) -> ProposalEntry {
            let mut p = ProposalEntry {
                dig: [seed; DIGEST_SIZE],
                mask: BIT_DIG | BIT_OPER,
                oper_len: 1,
                ..Default::default()
            };
            p.oper_enc[0] = seed;
            p
        }

        #[test]
        fn prop_window_hpack() {
            let mut w = PropWindow::default();

            for i in 0..PROPOSAL_WINDOW_SIZE {
                let pb = make_test_prop_bundle(i as u8);
                w.insert_new(pb);
                assert_eq!(w.size, i + 1);
                assert_eq!(w.lookup(&pb), 1, "newly inserted entry must be HPACK index 1");
            }

            for idx in 1..=PROPOSAL_WINDOW_SIZE {
                let prop = w.by_ref(idx).unwrap();
                let expected_seed = (PROPOSAL_WINDOW_SIZE - idx) as u8;
                assert_eq!(prop, make_test_prop_bundle(expected_seed));
            }

            let evicted = make_test_prop_bundle(0);
            let new_entry = make_test_prop_bundle(7);
            w.insert_new(new_entry);
            assert_eq!(w.size, PROPOSAL_WINDOW_SIZE);
            assert_eq!(w.lookup(&evicted), 0, "evicted entry must not be found");
            assert_eq!(w.lookup(&new_entry), 1);

            assert_eq!(w.by_ref(1).unwrap(), new_entry);
            assert_eq!(w.by_ref(PROPOSAL_WINDOW_SIZE).unwrap(), make_test_prop_bundle(1));
        }

        // ── header-bit sync + reference-id size (mirrors
        // TestStatefulEncoderHeaderBits / TestStatefulEncodeRef) ─────────

        #[test]
        fn header_bits_stay_in_sync() {
            let got = (HDR1_PROP_MASK >> HDR1_PROP_SHIFT) as usize;
            assert_eq!(got, PROPOSAL_WINDOW_SIZE);
            assert_eq!(HDR1_RND_LITERAL, 0);
        }

        #[test]
        fn ref_id_fits_in_u16() {
            assert_eq!(std::mem::size_of::<LruTableReferenceId>(), 2);
            // max supported table size is 2048 -> 1024 buckets, last bucket
            // 1023, last slot 1 -> maxID = (1023<<1)|1 = 2047
            let max_table_size: u32 = 2048;
            let max_bucket_index = (max_table_size / 2) - 1;
            let max_id: LruTableReferenceId = ((max_bucket_index << 1) | 1) as LruTableReferenceId;
            assert!(u32::from(max_id) <= u32::from(u16::MAX));
        }

        // ── round-trip sequence + reuse (mirrors
        // TestStatefulEncoderDecoderSequence / TestStatefulEncoderReuse) ─

        fn stateful_vote_spec(i: usize) -> VoteSpec {
            let mut v = base_spec();
            v.snd = seq(32, 0x10u8.wrapping_add(i as u8));
            v.p = seq(32, 0x20u8.wrapping_add(i as u8));
            v.p1s = seq(64, 0x30u8.wrapping_add(i as u8));
            v.p2 = seq(32, 0x40u8.wrapping_add(i as u8));
            v.p2s = seq(64, 0x50u8.wrapping_add(i as u8));
            v.s = seq(64, 0x60u8.wrapping_add(i as u8));
            v.rnd = 1000 + i as u64;
            if i % 3 == 0 {
                v.dig = Some(seq(32, 0x70));
            } else if i % 3 == 1 {
                v.dig = Some(seq(32, 0x71));
            } else {
                v.dig = None;
                v.encdig = Some(seq(32, 0x72));
            }
            if i % 2 == 0 {
                v.step = Some(i as u64);
            }
            v
        }

        #[test]
        fn stateful_encoder_decoder_sequence_round_trip() {
            let mut enc = StatefulEncoder::new(1024).unwrap();
            let mut dec = StatefulDecoder::new(1024).unwrap();

            for i in 0..30 {
                let v = stateful_vote_spec(i);
                let msgp = build_msgp_vote(&v);
                let stateless = compress_vote(&msgp).unwrap();

                let stateful = enc.compress(&stateless).unwrap();
                // compressed output must never exceed the stateless input
                assert!(stateful.len() <= stateless.len());

                let stateless_out = dec.decompress(&stateful).unwrap();
                assert_eq!(stateless_out, stateless, "vote {i} stateful round-trip");

                let msgp_out = decompress_vote(&stateless_out).unwrap();
                assert_eq!(msgp_out, msgp, "vote {i} full round-trip");
            }
        }

        #[test]
        fn stateful_rnd_delta() {
            let rounds = [10u64, 10, 11, 10, 11, 11, 20];
            let expected = [
                HDR1_RND_LITERAL,
                HDR1_RND_DELTA_SAME,
                HDR1_RND_DELTA_PLUS1,
                HDR1_RND_DELTA_MINUS1,
                HDR1_RND_DELTA_PLUS1,
                HDR1_RND_DELTA_SAME,
                HDR1_RND_LITERAL,
            ];

            let mut enc = StatefulEncoder::new(1024).unwrap();
            let mut dec = StatefulDecoder::new(1024).unwrap();

            for (i, &rnd) in rounds.iter().enumerate() {
                let mut v = base_spec();
                v.rnd = rnd;
                let msgp = build_msgp_vote(&v);
                let stateless = compress_vote(&msgp).unwrap();

                let stateful = enc.compress(&stateless).unwrap();
                assert!(stateful.len() >= 2);
                assert_eq!(stateful[1] & HDR1_RND_MASK, expected[i], "vote {i}");

                let decompressed = dec.decompress(&stateful).unwrap();
                assert_eq!(decompressed, stateless);
            }
        }

        // ── error paths (mirrors TestStatefulDecoderErrors /
        // TestStatefulEncoderErrors) ──────────────────────────────────

        fn zeros(n: usize) -> Vec<u8> {
            vec![0u8; n]
        }

        #[test]
        fn stateful_decoder_error_paths() {
            let mut full_vote = Vec::new();
            full_vote.push(BIT_PER | BIT_DIG | BIT_STEP | BIT_ENC_DIG | BIT_OPER | BIT_OPROP);
            full_vote.push(0x00);
            full_vote.extend(zeros(PF_SIZE));
            full_vote.push(MSGP_UINT32);
            full_vote.extend([0x01, 0x02, 0x03, 0x04]); // per
            full_vote.extend(zeros(DIGEST_SIZE)); // dig
            full_vote.extend(zeros(DIGEST_SIZE)); // encdig
            full_vote.push(MSGP_UINT32);
            full_vote.extend([0x01, 0x02, 0x03, 0x04]); // oper
            full_vote.extend(zeros(DIGEST_SIZE)); // oprop
            full_vote.push(MSGP_UINT32);
            full_vote.extend([0x01, 0x02, 0x03, 0x04]); // rnd
            full_vote.extend(zeros(DIGEST_SIZE)); // sender
            full_vote.push(MSGP_UINT32);
            full_vote.extend([0x01, 0x02, 0x03, 0x04]); // step
            full_vote.extend(zeros(PK_SIZE + SIG_SIZE)); // pk bundle
            full_vote.extend(zeros(PK_SIZE + SIG_SIZE)); // pk2 bundle
            full_vote.extend(zeros(SIG_SIZE)); // sig.s

            let mut ref_vote = Vec::new();
            ref_vote.push(0x00);
            ref_vote.push(HDR1_SND_REF | HDR1_PK_REF | HDR1_PK2_REF | HDR1_RND_LITERAL);
            ref_vote.extend(zeros(PF_SIZE));
            ref_vote.push(0x07); // rnd literal (fixint)
            ref_vote.extend([0x01, 0x02]); // snd ref id
            ref_vote.extend([0x03, 0x04]); // pk ref id
            ref_vote.extend([0x05, 0x06]); // pk2 ref id
            ref_vote.extend(zeros(SIG_SIZE)); // sig.s

            let cases: Vec<(&str, Vec<u8>)> = vec![
                ("input shorter than header", full_vote[..1].to_vec()),
                ("truncated pf", full_vote[..2].to_vec()),
                ("truncated per marker", full_vote[..82].to_vec()),
                ("truncated per", full_vote[..83].to_vec()),
                ("truncated digest", full_vote[..87].to_vec()),
                ("truncated encdig", full_vote[..119].to_vec()),
                ("truncated oper marker", full_vote[..151].to_vec()),
                ("truncated oper", full_vote[..152].to_vec()),
                ("truncated oprop", full_vote[..160].to_vec()),
                ("truncated rnd marker", full_vote[..188].to_vec()),
                ("truncated rnd", full_vote[..189].to_vec()),
                ("truncated sender", full_vote[..193].to_vec()),
                ("truncated step marker", full_vote[..225].to_vec()),
                ("truncated step", full_vote[..226].to_vec()),
                ("truncated pk bundle", full_vote[..234].to_vec()),
                ("truncated pk2 bundle", full_vote[..334].to_vec()),
                ("truncated sig.s", full_vote[..422].to_vec()),
                ("truncated snd ref", ref_vote[..84].to_vec()),
                ("truncated pk ref", ref_vote[..86].to_vec()),
                ("truncated pk2 ref", ref_vote[..88].to_vec()),
                ("bad sender ref", {
                    let mut b = ref_vote[..83].to_vec();
                    b.extend([0xFF, 0xFF]);
                    b
                }),
                ("bad pk ref", {
                    let mut b = ref_vote[..85].to_vec();
                    b.extend([0xFF, 0xFF]);
                    b
                }),
                ("bad pk2 ref", {
                    let mut b = ref_vote[..87].to_vec();
                    b.extend([0xFF, 0xFF]);
                    b
                }),
                ("bad proposal ref", {
                    let mut b = vec![0x00u8, 3 << HDR1_PROP_SHIFT];
                    b.extend(zeros(PF_SIZE));
                    b.push(0x01);
                    b
                }),
                ("length mismatch: expected", {
                    let mut b = full_vote.clone();
                    b.extend([0xFF, 0xFF]);
                    b
                }),
            ];

            for (want, buf) in cases {
                let mut dec = StatefulDecoder::new(1024).unwrap();
                let err = dec.decompress(&buf).unwrap_err();
                let msg = err.to_string();
                assert!(
                    msg.contains(want),
                    "case {want:?}: got error {msg:?}"
                );
            }
        }

        #[test]
        fn stateful_encoder_error_paths() {
            let mut enc = StatefulEncoder::new(1024).unwrap();

            let err = enc.compress(&[0x00]).unwrap_err();
            assert!(err.to_string().contains("src too short"));

            let v = base_spec();
            let msgp = build_msgp_vote(&v);
            let stateless = compress_vote(&msgp).unwrap();

            let mut bad_buf = stateless.clone();
            bad_buf.push(0xFF);
            let err = enc.compress(&bad_buf).unwrap_err();
            assert!(err.to_string().contains("length mismatch"));

            let compressed = enc.compress(&stateless).unwrap();
            assert!(!compressed.is_empty());

            let cases: Vec<(&str, Vec<u8>)> = vec![
                ("truncated pf", {
                    vec![0x00, 0x00]
                }),
                ("truncated r.per marker", {
                    let mut b = vec![BIT_PER, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b
                }),
                ("truncated r.per", {
                    let mut b = vec![BIT_PER, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b.push(MSGP_UINT32);
                    b
                }),
                ("truncated dig", {
                    let mut b = vec![BIT_DIG, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b
                }),
                ("truncated encdig", {
                    let mut b = vec![BIT_ENC_DIG, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b
                }),
                ("truncated oper marker", {
                    let mut b = vec![BIT_OPER, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b
                }),
                ("truncated oper", {
                    let mut b = vec![BIT_OPER, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b.push(MSGP_UINT32);
                    b
                }),
                ("truncated oprop", {
                    let mut b = vec![BIT_OPROP, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b
                }),
                ("truncated rnd marker", {
                    let mut b = vec![0x00, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b
                }),
                ("truncated rnd", {
                    let mut b = vec![0x00, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b.push(MSGP_UINT32);
                    b
                }),
                ("truncated sender", {
                    let mut b = vec![0x00, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b.push(0x07);
                    b
                }),
                ("truncated step marker", {
                    let mut b = vec![BIT_STEP, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b.push(0x07);
                    b.extend(zeros(DIGEST_SIZE));
                    b
                }),
                ("truncated step", {
                    let mut b = vec![BIT_STEP, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b.push(0x07);
                    b.extend(zeros(DIGEST_SIZE));
                    b.push(MSGP_UINT32);
                    b
                }),
                ("truncated pk bundle", {
                    let mut b = vec![0x00, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b.push(0x07);
                    b.extend(zeros(DIGEST_SIZE));
                    b
                }),
                ("truncated pk2 bundle", {
                    let mut b = vec![0x00, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b.push(0x07);
                    b.extend(zeros(DIGEST_SIZE));
                    b.extend(zeros(PK_SIZE + SIG_SIZE));
                    b
                }),
                ("truncated sig.s", {
                    let mut b = vec![0x00, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b.push(0x07);
                    b.extend(zeros(DIGEST_SIZE));
                    b.extend(zeros(PK_SIZE + SIG_SIZE));
                    b.extend(zeros(PK_SIZE + SIG_SIZE));
                    b
                }),
                ("invalid r.per marker", {
                    let mut b = vec![BIT_PER, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b.push(0xFF);
                    b
                }),
                ("invalid oper marker", {
                    let mut b = vec![BIT_OPER, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b.push(0xFF);
                    b
                }),
                ("invalid rnd marker", {
                    let mut b = vec![0x00, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b.push(0xFF);
                    b
                }),
                ("invalid step marker", {
                    let mut b = vec![BIT_STEP, 0x00];
                    b.extend(zeros(PF_SIZE));
                    b.push(0x07);
                    b.extend(zeros(DIGEST_SIZE));
                    b.push(0xFF);
                    b
                }),
            ];

            for (want, buf) in cases {
                let mut enc = StatefulEncoder::new(1024).unwrap();
                let err = enc.compress(&buf).unwrap_err();
                let msg = err.to_string();
                assert!(msg.contains(want), "case {want:?}: got error {msg:?}");
            }
        }

        // ── pinned interop fixtures (stateful layer) ─────────────────────
        //
        // Captured the same way as the stateless `interop_fixtures` above:
        // by running go-algorand's actual, unmodified `network/vpack`
        // source (`vpack.go`, `msgp.go`, `parse.go`, `lru_table.go`,
        // `proposal_window.go`, `dynamic_vpack.go`, copied verbatim from
        // `../go-algorand/network/vpack/` at the repo's `v5.0.0-stable`
        // pin) against a small Go driver (not checked into either repo)
        // that feeds a sequence of votes through `StatelessEncoder` then
        // `StatefulEncoder`, printing hex. These byte vectors prove
        // genuine wire-level interop with real go-algorand `vpack`
        // stateful output, not just Rust self-consistency.
        mod interop_fixtures {
            use super::*;

            /// Feeds `votes` through a fresh `StatefulEncoder`/`StatefulDecoder`
            /// pair (persistent across the sequence, matching how a real
            /// connection would use them), and checks vote `pin_at[i]`'s
            /// stateful-compressed bytes against `expected_hex[i]`.
            fn check_sequence(
                table_size: u32,
                votes: &[VoteSpec],
                pins: &[(usize, &str)],
            ) {
                let mut enc = StatefulEncoder::new(table_size).unwrap();
                let mut dec = StatefulDecoder::new(table_size).unwrap();

                for (i, v) in votes.iter().enumerate() {
                    let msgp = build_msgp_vote(v);
                    let stateless = compress_vote(&msgp).unwrap();
                    let stateful = enc.compress(&stateless).unwrap();

                    // every vote must round-trip, whether pinned or not
                    let stateless_out = dec.decompress(&stateful).unwrap();
                    assert_eq!(stateless_out, stateless, "vote {i} stateful round-trip");
                    let msgp_out = decompress_vote(&stateless_out).unwrap();
                    assert_eq!(msgp_out, msgp, "vote {i} full round-trip");

                    if let Some(&(_, expected_hex)) = pins.iter().find(|&&(idx, _)| idx == i) {
                        assert_eq!(
                            hex(&stateful),
                            expected_hex,
                            "vote {i} must byte-match real go-algorand StatefulEncoder output"
                        );
                    }
                }
            }

            /// Mirrors the Go driver's `votesA` sequence: same proposal/round
            /// reused across votes, exercising literal->reference transitions
            /// for `snd`/`pk`/`pk2`/`prop` and all four `r.rnd` delta cases.
            #[test]
            fn mixed_literal_and_reference() {
                let pf = seq(80, 0x01);
                let dig_a = seq(32, 0x70);
                let dig_b = seq(32, 0x71);
                let snd_s1 = seq(32, 0x10);
                let snd_s2 = seq(32, 0x11);
                let pk_p1 = seq(32, 0x20);
                let p1s_sig1 = seq(64, 0x30);
                let pk2_p1 = seq(32, 0x40);
                let p2s_sig1 = seq(64, 0x50);

                let votes = vec![
                    VoteSpec {
                        pf: pf.clone(),
                        dig: Some(dig_a.clone()),
                        rnd: 100,
                        snd: snd_s1.clone(),
                        p: pk_p1.clone(),
                        p1s: p1s_sig1.clone(),
                        p2: pk2_p1.clone(),
                        p2s: p2s_sig1.clone(),
                        s: seq(64, 0x60),
                        step: Some(1),
                        ..Default::default()
                    },
                    VoteSpec {
                        pf: pf.clone(),
                        dig: Some(dig_a.clone()),
                        rnd: 101,
                        snd: snd_s1.clone(),
                        p: pk_p1.clone(),
                        p1s: p1s_sig1.clone(),
                        p2: pk2_p1.clone(),
                        p2s: p2s_sig1.clone(),
                        s: seq(64, 0x61),
                        step: Some(2),
                        ..Default::default()
                    },
                    VoteSpec {
                        pf: pf.clone(),
                        dig: Some(dig_b.clone()),
                        rnd: 101,
                        snd: snd_s1.clone(),
                        p: pk_p1.clone(),
                        p1s: p1s_sig1.clone(),
                        p2: pk2_p1.clone(),
                        p2s: p2s_sig1.clone(),
                        s: seq(64, 0x62),
                        step: Some(3),
                        ..Default::default()
                    },
                    VoteSpec {
                        pf: pf.clone(),
                        dig: Some(dig_a.clone()),
                        rnd: 100,
                        snd: snd_s2.clone(),
                        p: pk_p1.clone(),
                        p1s: p1s_sig1.clone(),
                        p2: pk2_p1.clone(),
                        p2s: p2s_sig1.clone(),
                        s: seq(64, 0x63),
                        step: Some(4),
                        ..Default::default()
                    },
                    VoteSpec {
                        pf: pf.clone(),
                        dig: Some(dig_b.clone()),
                        rnd: 100,
                        snd: snd_s1.clone(),
                        p: pk_p1.clone(),
                        p1s: p1s_sig1.clone(),
                        p2: pk2_p1.clone(),
                        p2s: p2s_sig1.clone(),
                        s: seq(64, 0x64),
                        step: Some(5),
                        ..Default::default()
                    },
                    VoteSpec {
                        pf: pf.clone(),
                        rnd: 500,
                        snd: seq(32, 0x12),
                        p: seq(32, 0x21),
                        p1s: seq(64, 0x31),
                        p2: seq(32, 0x41),
                        p2s: seq(64, 0x51),
                        s: seq(64, 0x65),
                        ..Default::default()
                    },
                ];

                let pins: [(usize, &str); 6] = [
                    (0, "22000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f64101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f01202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
                    (1, "22e50102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50000102002100216162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0"),
                    (2, "22e30102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f507172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f900001030021002162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1"),
                    (3, "22ca0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f501112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f300400210021636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2"),
                    (4, "22e70102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50000105002100216465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3"),
                    (5, "00000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50cd01f412131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30312122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f403132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f704142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f605152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9065666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4"),
                ];

                check_sequence(1024, &votes, &pins);
            }

            /// Mirrors the Go driver's `votesB` sequence: table size 16
            /// forces LRU eviction of the `snd` table after 20 distinct
            /// senders are inserted, so the 22nd vote's reference to the
            /// very first sender must fall back to a literal re-insert
            /// (`sndRef` bit clear in hdr1, unlike `pk`/`pk2`/`prop` which
            /// stay unevicted references throughout).
            #[test]
            fn small_table_eviction() {
                let pf = seq(80, 0x01);
                let dig_a = seq(32, 0x70);
                let pk_p1 = seq(32, 0x20);
                let p1s_sig1 = seq(64, 0x30);
                let pk2_p1 = seq(32, 0x40);
                let p2s_sig1 = seq(64, 0x50);
                let first_snd = seq(32, 0xA0);

                let mut votes = vec![VoteSpec {
                    pf: pf.clone(),
                    dig: Some(dig_a.clone()),
                    rnd: 1,
                    snd: first_snd.clone(),
                    p: pk_p1.clone(),
                    p1s: p1s_sig1.clone(),
                    p2: pk2_p1.clone(),
                    p2s: p2s_sig1.clone(),
                    s: seq(64, 0x70),
                    ..Default::default()
                }];
                for i in 0u8..20 {
                    votes.push(VoteSpec {
                        pf: pf.clone(),
                        dig: Some(dig_a.clone()),
                        rnd: 1 + u64::from(i) + 1,
                        snd: seq(32, 0xB0u8.wrapping_add(i)),
                        p: pk_p1.clone(),
                        p1s: p1s_sig1.clone(),
                        p2: pk2_p1.clone(),
                        p2s: p2s_sig1.clone(),
                        s: seq(64, 0x71u8.wrapping_add(i)),
                        ..Default::default()
                    });
                }
                votes.push(VoteSpec {
                    pf: pf.clone(),
                    dig: Some(dig_a.clone()),
                    rnd: 100,
                    snd: first_snd.clone(),
                    p: pk_p1.clone(),
                    p1s: p1s_sig1.clone(),
                    p2: pk2_p1.clone(),
                    p2s: p2s_sig1.clone(),
                    s: seq(64, 0x99),
                    ..Default::default()
                });
                assert_eq!(votes.len(), 22);

                let pins: [(usize, &str); 2] = [
                    (0, "02010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
                    (21, "02c40102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5064a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf00010001999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8"),
                ];

                check_sequence(16, &votes, &pins);
            }
        }
    }
}
