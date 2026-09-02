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

//! `vpack`: stateless vote msgpack compression codec.
//!
//! Ports go-algorand's `network/vpack` package (`network/vpack/vpack.go`,
//! `network/vpack/msgp.go`, `network/vpack/parse.go`, pinned at
//! `v5.0.0-stable`), covering **stateless mode only**.
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
//! # Scope: stateless only, not wired into any network path
//!
//! go-algorand's `vpack` package also has a **stateful** mode
//! (`StatefulEncoder`/`StatefulDecoder` in `network/vpack/dynamic_vpack.go`)
//! that further compresses votes using per-connection LRU reference tables
//! and an 8-slot HPACK-style proposal window. That mode is **not**
//! implemented here — it is materially more complex (shared mutable
//! encoder/decoder state, LRU eviction, round-delta encoding) and is left
//! as a documented follow-up (see the issue tracking this module).
//!
//! This module is also **intentionally not wired into any live network
//! code path** (no changes to `peer_features.rs`'s handshake negotiation,
//! `ws_peer.rs`, or any connection-handling code). Wiring a new wire-format
//! codec into live peer negotiation is a network-protocol-compatibility
//! change that needs live multi-node interop testing beyond what this
//! standalone codec's test suite can provide. `avvpack`/`avvpack<N>` peer
//! feature bits are already advertised in `peer_features.rs`, but nothing
//! in the live handshake/connection paths calls into this module.
//!
//! # Wire format
//!
//! See go-algorand's `network/vpack/README.md` for the full specification.
//! Byte-for-byte layout (stateless bytes only; byte 1 of the header is
//! reserved for the stateful layer and is always `0` here):
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
//! `r.step`); header byte 1 is always `0x00` in stateless-only output.

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
}
