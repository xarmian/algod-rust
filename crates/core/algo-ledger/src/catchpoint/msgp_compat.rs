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

//! Go `msgp`-compatible decoders for catchpoint raw blobs.
//!
//! Go's `protocol.Encode` uses the `msgp` library's `MarshalMsg` method which
//! emits **map-encoded msgpack** (string keys, omitempty). Since msgp 1.1.66
//! (go-algorand v5.1.1, go #6774) the generated `UnmarshalMsg` reads a struct
//! from a map only: an array is a `TypeError` (issue #2609).
//!
//! The raw blobs stored inside catchpoint `BalanceRecordV6.account_data`,
//! `BalanceRecordV6.resources[idx]`, `OnlineAccountRecordV6.data`, and
//! `OnlineRoundParamsRecordV6.data` are all map-encoded msgpack produced by
//! `protocol.Encode`.
//!
//! This module provides decoders that handle the map format only, like go.

use super::types::{
    AccountTotals, AlgoCount, BalanceRecordV6, CatchpointBaseAccountData,
    CatchpointBaseOnlineAccountData, CatchpointError, CatchpointFileHeader,
    CatchpointOnlineRoundParamsData, CatchpointResourcesData, CatchpointSnapshotChunkV6,
    CatchpointStateProofVerificationWrapper, KVRecordV6, OnlineAccountRecordV6,
    OnlineRoundParamsRecordV6,
};

// ---------------------------------------------------------------------------
// Low-level msgpack helpers
// ---------------------------------------------------------------------------

/// Peek at the next msgpack type marker byte without consuming it.
fn peek_byte(rd: &[u8]) -> Result<u8, CatchpointError> {
    rd.first()
        .copied()
        .ok_or_else(|| CatchpointError::DecodeError("unexpected end of input".into()))
}

/// Read a msgpack integer value as u64.
///
/// Handles positive fixint, uint8, uint16, uint32, uint64, and also
/// int8/int16/int32/int64 when the value is non-negative.
fn read_u64(rd: &mut &[u8]) -> Result<u64, CatchpointError> {
    let marker = peek_byte(rd)?;
    match marker {
        // positive fixint (0x00..=0x7f)
        0x00..=0x7f => {
            let v = rd[0] as u64;
            *rd = &rd[1..];
            Ok(v)
        }
        // uint8
        0xcc => {
            if rd.len() < 2 {
                return Err(CatchpointError::DecodeError("truncated uint8".into()));
            }
            let v = rd[1] as u64;
            *rd = &rd[2..];
            Ok(v)
        }
        // uint16
        0xcd => {
            if rd.len() < 3 {
                return Err(CatchpointError::DecodeError("truncated uint16".into()));
            }
            let v = u16::from_be_bytes([rd[1], rd[2]]) as u64;
            *rd = &rd[3..];
            Ok(v)
        }
        // uint32
        0xce => {
            if rd.len() < 5 {
                return Err(CatchpointError::DecodeError("truncated uint32".into()));
            }
            let v = u32::from_be_bytes([rd[1], rd[2], rd[3], rd[4]]) as u64;
            *rd = &rd[5..];
            Ok(v)
        }
        // uint64
        0xcf => {
            if rd.len() < 9 {
                return Err(CatchpointError::DecodeError("truncated uint64".into()));
            }
            let v = u64::from_be_bytes([rd[1], rd[2], rd[3], rd[4], rd[5], rd[6], rd[7], rd[8]]);
            *rd = &rd[9..];
            Ok(v)
        }
        // int8 (negative fixint values will fail here, but non-negative int8 is ok)
        0xd0 => {
            if rd.len() < 2 {
                return Err(CatchpointError::DecodeError("truncated int8".into()));
            }
            let v = rd[1] as i8;
            *rd = &rd[2..];
            if v < 0 {
                return Err(CatchpointError::DecodeError(
                    "negative int in uint context".into(),
                ));
            }
            Ok(v as u64)
        }
        // int16
        0xd1 => {
            if rd.len() < 3 {
                return Err(CatchpointError::DecodeError("truncated int16".into()));
            }
            let v = i16::from_be_bytes([rd[1], rd[2]]);
            *rd = &rd[3..];
            if v < 0 {
                return Err(CatchpointError::DecodeError(
                    "negative int in uint context".into(),
                ));
            }
            Ok(v as u64)
        }
        // int32
        0xd2 => {
            if rd.len() < 5 {
                return Err(CatchpointError::DecodeError("truncated int32".into()));
            }
            let v = i32::from_be_bytes([rd[1], rd[2], rd[3], rd[4]]);
            *rd = &rd[5..];
            if v < 0 {
                return Err(CatchpointError::DecodeError(
                    "negative int in uint context".into(),
                ));
            }
            Ok(v as u64)
        }
        // int64
        0xd3 => {
            if rd.len() < 9 {
                return Err(CatchpointError::DecodeError("truncated int64".into()));
            }
            let v = i64::from_be_bytes([rd[1], rd[2], rd[3], rd[4], rd[5], rd[6], rd[7], rd[8]]);
            *rd = &rd[9..];
            if v < 0 {
                return Err(CatchpointError::DecodeError(
                    "negative int in uint context".into(),
                ));
            }
            Ok(v as u64)
        }
        // nil -> treat as 0
        0xc0 => {
            *rd = &rd[1..];
            Ok(0)
        }
        _ => Err(CatchpointError::DecodeError(format!(
            "expected integer, got marker 0x{marker:02x}"
        ))),
    }
}

/// A go `uint32` field: `msgp.ReadUint32Bytes` fails on a larger value
/// (`msgp.UintOverflow`) rather than truncating it (issue #2396).
fn read_u32(rd: &mut &[u8]) -> Result<u32, CatchpointError> {
    let v = read_u64(rd)?;
    u32::try_from(v).map_err(|_| CatchpointError::DecodeError(format!("uint {v} overflows uint32")))
}

/// A go `uint8` / `byte` field (`basics.Status`, `ResourceFlags`):
/// `msgp.ReadUint8Bytes` / `ReadByteBytes` fail on a larger value.
fn read_u8(rd: &mut &[u8]) -> Result<u8, CatchpointError> {
    let v = read_u64(rd)?;
    u8::try_from(v).map_err(|_| CatchpointError::DecodeError(format!("uint {v} overflows uint8")))
}

/// Read a msgpack bool value.
fn read_bool(rd: &mut &[u8]) -> Result<bool, CatchpointError> {
    let marker = peek_byte(rd)?;
    match marker {
        0xc2 => {
            *rd = &rd[1..];
            Ok(false)
        }
        0xc3 => {
            *rd = &rd[1..];
            Ok(true)
        }
        0xc0 => {
            // nil -> false
            *rd = &rd[1..];
            Ok(false)
        }
        _ => Err(CatchpointError::DecodeError(format!(
            "expected bool, got marker 0x{marker:02x}"
        ))),
    }
}

/// Read a `[N]byte` field like go's generated decoders (`msgp.ReadExactBytes`,
/// issue #2063): `bin`/`str`/`nil` (zeroed)/uint8-array, and `min(len, N)`
/// bytes are copied -- go does not enforce the length (the strict check is
/// commented out in `read_bytes.go`), so a wrong-length value is not an error.
#[cfg(test)]
fn read_bytes_fixed<const N: usize>(rd: &mut &[u8]) -> Result<[u8; N], CatchpointError> {
    algo_types::go_msgp::read_fixed_bytes_go_compat::<N>(rd)
        .map_err(|e| CatchpointError::DecodeError(e.to_string()))
}

/// Read a `[N]byte` field into its already decoded value, as go's generated
/// decoders do (`msgp.ReadExactBytes(b, z.X[:])`, issue #2421): a repeated
/// key with a shorter value keeps the earlier tail, `nil` zeroes it.
fn read_fixed_into(rd: &mut &[u8], into: &mut [u8]) -> Result<(), CatchpointError> {
    algo_types::go_msgp::read_fixed_bytes_into_go_compat(rd, into)
        .map_err(|e| CatchpointError::DecodeError(e.to_string()))
}

/// Read a `[]byte` field like go's `msgp.ReadBytesBytes` (issue #2063):
/// `bin`, `str`, `nil` (empty), uint8-array.
fn read_bytes_vec(rd: &mut &[u8]) -> Result<Vec<u8>, CatchpointError> {
    algo_types::go_msgp::read_bytes_go_compat(rd)
        .map_err(|e| CatchpointError::DecodeError(e.to_string()))
}

/// A go `string` field's bytes (`msgp.ReadStringBytes`: `str`, `bin`, `nil`
/// or a uint8 array, never UTF-8 checked).
fn read_go_str_bytes(rd: &mut &[u8]) -> Result<Vec<u8>, CatchpointError> {
    algo_types::go_msgp::read_str_bytes(rd).map_err(|e| CatchpointError::DecodeError(e.to_string()))
}

/// Read a msgpack string value.
fn read_string(rd: &mut &[u8]) -> Result<String, CatchpointError> {
    let bytes = read_bytes_vec(rd)?;
    String::from_utf8(bytes)
        .map_err(|e| CatchpointError::DecodeError(format!("invalid UTF-8 string: {e}")))
}

/// Read a msgpack map key as a string.
fn read_map_key(rd: &mut &[u8]) -> Result<String, CatchpointError> {
    read_string(rd)
}

/// Read the raw bytes of a single msgpack value without interpreting it.
/// Returns a Vec<u8> containing the complete msgpack encoding of that value.
fn read_raw_value(rd: &mut &[u8]) -> Result<Vec<u8>, CatchpointError> {
    let start = *rd;
    skip_value(rd)?;
    let consumed = start.len() - rd.len();
    Ok(start[..consumed].to_vec())
}

/// Skip a single msgpack value, advancing the reader past it.
/// go's `msgp.ErrNoField`: a key the struct lacks fails the decode.
#[cold]
fn unknown_field(key: &str) -> CatchpointError {
    CatchpointError::DecodeError(format!(
        "no matching struct field found when decoding stream map with key {key}"
    ))
}

fn skip_value(rd: &mut &[u8]) -> Result<(), CatchpointError> {
    let marker = peek_byte(rd)?;
    match marker {
        // nil, false, true
        0xc0 | 0xc2 | 0xc3 => {
            *rd = &rd[1..];
        }
        // positive fixint
        0x00..=0x7f => {
            *rd = &rd[1..];
        }
        // negative fixint
        0xe0..=0xff => {
            *rd = &rd[1..];
        }
        // uint8, int8
        0xcc | 0xd0 => {
            if rd.len() < 2 {
                return Err(CatchpointError::DecodeError("truncated".into()));
            }
            *rd = &rd[2..];
        }
        // uint16, int16
        0xcd | 0xd1 => {
            if rd.len() < 3 {
                return Err(CatchpointError::DecodeError("truncated".into()));
            }
            *rd = &rd[3..];
        }
        // uint32, int32, float32
        0xce | 0xd2 | 0xca => {
            if rd.len() < 5 {
                return Err(CatchpointError::DecodeError("truncated".into()));
            }
            *rd = &rd[5..];
        }
        // uint64, int64, float64
        0xcf | 0xd3 | 0xcb => {
            if rd.len() < 9 {
                return Err(CatchpointError::DecodeError("truncated".into()));
            }
            *rd = &rd[9..];
        }
        // fixstr
        m @ 0xa0..=0xbf => {
            let len = (m & 0x1f) as usize;
            if rd.len() < 1 + len {
                return Err(CatchpointError::DecodeError("truncated fixstr".into()));
            }
            *rd = &rd[1 + len..];
        }
        // str8
        0xd9 => {
            if rd.len() < 2 {
                return Err(CatchpointError::DecodeError("truncated".into()));
            }
            let len = rd[1] as usize;
            if rd.len() < 2 + len {
                return Err(CatchpointError::DecodeError("truncated str8".into()));
            }
            *rd = &rd[2 + len..];
        }
        // str16
        0xda => {
            if rd.len() < 3 {
                return Err(CatchpointError::DecodeError("truncated".into()));
            }
            let len = u16::from_be_bytes([rd[1], rd[2]]) as usize;
            if rd.len() < 3 + len {
                return Err(CatchpointError::DecodeError("truncated str16".into()));
            }
            *rd = &rd[3 + len..];
        }
        // str32
        0xdb => {
            if rd.len() < 5 {
                return Err(CatchpointError::DecodeError("truncated".into()));
            }
            let len = u32::from_be_bytes([rd[1], rd[2], rd[3], rd[4]]) as usize;
            if rd.len() < 5 + len {
                return Err(CatchpointError::DecodeError("truncated str32".into()));
            }
            *rd = &rd[5 + len..];
        }
        // bin8
        0xc4 => {
            if rd.len() < 2 {
                return Err(CatchpointError::DecodeError("truncated".into()));
            }
            let len = rd[1] as usize;
            if rd.len() < 2 + len {
                return Err(CatchpointError::DecodeError("truncated bin8".into()));
            }
            *rd = &rd[2 + len..];
        }
        // bin16
        0xc5 => {
            if rd.len() < 3 {
                return Err(CatchpointError::DecodeError("truncated".into()));
            }
            let len = u16::from_be_bytes([rd[1], rd[2]]) as usize;
            if rd.len() < 3 + len {
                return Err(CatchpointError::DecodeError("truncated bin16".into()));
            }
            *rd = &rd[3 + len..];
        }
        // bin32
        0xc6 => {
            if rd.len() < 5 {
                return Err(CatchpointError::DecodeError("truncated".into()));
            }
            let len = u32::from_be_bytes([rd[1], rd[2], rd[3], rd[4]]) as usize;
            if rd.len() < 5 + len {
                return Err(CatchpointError::DecodeError("truncated bin32".into()));
            }
            *rd = &rd[5 + len..];
        }
        // fixarray
        m @ 0x90..=0x9f => {
            let count = (m & 0x0f) as usize;
            *rd = &rd[1..];
            for _ in 0..count {
                skip_value(rd)?;
            }
        }
        // array16
        0xdc => {
            if rd.len() < 3 {
                return Err(CatchpointError::DecodeError("truncated".into()));
            }
            let count = u16::from_be_bytes([rd[1], rd[2]]) as usize;
            *rd = &rd[3..];
            for _ in 0..count {
                skip_value(rd)?;
            }
        }
        // array32
        0xdd => {
            if rd.len() < 5 {
                return Err(CatchpointError::DecodeError("truncated".into()));
            }
            let count = u32::from_be_bytes([rd[1], rd[2], rd[3], rd[4]]) as usize;
            *rd = &rd[5..];
            for _ in 0..count {
                skip_value(rd)?;
            }
        }
        // fixmap
        m @ 0x80..=0x8f => {
            let count = (m & 0x0f) as usize;
            *rd = &rd[1..];
            for _ in 0..count {
                skip_value(rd)?; // key
                skip_value(rd)?; // value
            }
        }
        // map16
        0xde => {
            if rd.len() < 3 {
                return Err(CatchpointError::DecodeError("truncated".into()));
            }
            let count = u16::from_be_bytes([rd[1], rd[2]]) as usize;
            *rd = &rd[3..];
            for _ in 0..count {
                skip_value(rd)?;
                skip_value(rd)?;
            }
        }
        // map32
        0xdf => {
            if rd.len() < 5 {
                return Err(CatchpointError::DecodeError("truncated".into()));
            }
            let count = u32::from_be_bytes([rd[1], rd[2], rd[3], rd[4]]) as usize;
            *rd = &rd[5..];
            for _ in 0..count {
                skip_value(rd)?;
                skip_value(rd)?;
            }
        }
        // fixext1, fixext2, fixext4, fixext8, fixext16
        0xd4 => {
            if rd.len() < 3 {
                return Err(CatchpointError::DecodeError("truncated fixext1".into()));
            }
            *rd = &rd[3..];
        }
        0xd5 => {
            if rd.len() < 4 {
                return Err(CatchpointError::DecodeError("truncated fixext2".into()));
            }
            *rd = &rd[4..];
        }
        0xd6 => {
            if rd.len() < 6 {
                return Err(CatchpointError::DecodeError("truncated fixext4".into()));
            }
            *rd = &rd[6..];
        }
        0xd7 => {
            if rd.len() < 10 {
                return Err(CatchpointError::DecodeError("truncated fixext8".into()));
            }
            *rd = &rd[10..];
        }
        0xd8 => {
            if rd.len() < 18 {
                return Err(CatchpointError::DecodeError("truncated fixext16".into()));
            }
            *rd = &rd[18..];
        }
        // ext8
        0xc7 => {
            if rd.len() < 3 {
                return Err(CatchpointError::DecodeError("truncated ext8".into()));
            }
            let len = rd[1] as usize;
            if rd.len() < 3 + len {
                return Err(CatchpointError::DecodeError("truncated ext8 data".into()));
            }
            *rd = &rd[3 + len..];
        }
        // ext16
        0xc8 => {
            if rd.len() < 4 {
                return Err(CatchpointError::DecodeError("truncated ext16".into()));
            }
            let len = u16::from_be_bytes([rd[1], rd[2]]) as usize;
            if rd.len() < 4 + len {
                return Err(CatchpointError::DecodeError("truncated ext16 data".into()));
            }
            *rd = &rd[4 + len..];
        }
        // ext32
        0xc9 => {
            if rd.len() < 6 {
                return Err(CatchpointError::DecodeError("truncated ext32".into()));
            }
            let len = u32::from_be_bytes([rd[1], rd[2], rd[3], rd[4]]) as usize;
            if rd.len() < 6 + len {
                return Err(CatchpointError::DecodeError("truncated ext32 data".into()));
            }
            *rd = &rd[6 + len..];
        }
        // never used (0xc1)
        _ => {
            return Err(CatchpointError::DecodeError(format!(
                "unknown msgpack marker 0x{marker:02x}"
            )));
        }
    }
    Ok(())
}

/// go `msgp.ReadMapHeaderBytes` (a generated struct decoder's first read): a
/// map header, `nil` as an empty map, and anything else a `TypeError`, an
/// array included (go v5.1.1 generated decoders have no struct-from-array
/// branch since msgp 1.1.66, go #6774; issue #2609).
fn read_map_header(rd: &mut &[u8]) -> Result<u32, CatchpointError> {
    let marker = peek_byte(rd)?;
    match marker {
        // fixmap
        m @ 0x80..=0x8f => {
            *rd = &rd[1..];
            Ok((m & 0x0f) as u32)
        }
        // map16
        0xde => {
            if rd.len() < 3 {
                return Err(CatchpointError::DecodeError("truncated map16".into()));
            }
            let n = u16::from_be_bytes([rd[1], rd[2]]) as u32;
            *rd = &rd[3..];
            Ok(n)
        }
        // map32
        0xdf => {
            if rd.len() < 5 {
                return Err(CatchpointError::DecodeError("truncated map32".into()));
            }
            let n = u32::from_be_bytes([rd[1], rd[2], rd[3], rd[4]]);
            *rd = &rd[5..];
            Ok(n)
        }
        // nil -> empty
        0xc0 => {
            *rd = &rd[1..];
            Ok(0)
        }
        // fixarray, array16, array32: msgp.TypeError
        0x90..=0x9f | 0xdc | 0xdd => Err(CatchpointError::DecodeError(
            "msgp: attempted to decode type \"array\" with method for \"map\"".into(),
        )),
        _ => Err(CatchpointError::DecodeError(format!(
            "expected map header, got marker 0x{marker:02x}"
        ))),
    }
}

/// Read an array header, returning the element count.
fn read_array_header(rd: &mut &[u8]) -> Result<u32, CatchpointError> {
    let marker = peek_byte(rd)?;
    match marker {
        // fixarray
        m @ 0x90..=0x9f => {
            *rd = &rd[1..];
            Ok((m & 0x0f) as u32)
        }
        // array16
        0xdc => {
            if rd.len() < 3 {
                return Err(CatchpointError::DecodeError("truncated array16".into()));
            }
            let n = u16::from_be_bytes([rd[1], rd[2]]) as u32;
            *rd = &rd[3..];
            Ok(n)
        }
        // array32
        0xdd => {
            if rd.len() < 5 {
                return Err(CatchpointError::DecodeError("truncated array32".into()));
            }
            let n = u32::from_be_bytes([rd[1], rd[2], rd[3], rd[4]]);
            *rd = &rd[5..];
            Ok(n)
        }
        _ => Err(CatchpointError::DecodeError(format!(
            "expected array header, got marker 0x{marker:02x}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// BaseAccountData decoder
// ---------------------------------------------------------------------------

/// Decode a raw msgpack blob into `CatchpointBaseAccountData`.
///
/// Map-encoded only, like go v5.1.1's generated decoder (an array is a
/// `TypeError`, issue #2609).
///
/// Map keys (from Go `trackerdb.BaseAccountData` codec tags):
///   a=Status, b=MicroAlgos, c=RewardsBase, d=RewardedMicroAlgos,
///   e=AuthAddr, f=TotalAppSchemaNumUint, g=TotalAppSchemaNumByteSlice,
///   h=TotalExtraAppPages, i=TotalAssetParams, j=TotalAssets,
///   k=TotalAppParams, l=TotalAppLocalStates, m=TotalBoxes, n=TotalBoxBytes,
///   o=IncentiveEligible, p=LastProposed, q=LastHeartbeat,
///   A=VoteID, B=SelectionID, C=VoteFirstValid, D=VoteLastValid,
///   E=VoteKeyDilution, F=StateProofID, z=UpdateRound
pub fn decode_base_account_data(raw: &[u8]) -> Result<CatchpointBaseAccountData, CatchpointError> {
    if raw.is_empty() {
        return Ok(CatchpointBaseAccountData::default());
    }

    let mut rd: &[u8] = raw;
    let mut result = CatchpointBaseAccountData::default();

    let n = read_map_header(&mut rd)?;
    // Map-encoded format
    for _ in 0..n {
        let key = read_map_key(&mut rd)?;
        match key.as_str() {
            "a" => result.status = read_u8(&mut rd)?,
            "b" => result.micro_algos = read_u64(&mut rd)?,
            "c" => result.rewards_base = read_u64(&mut rd)?,
            "d" => result.rewarded_micro_algos = read_u64(&mut rd)?,
            "e" => read_fixed_into(&mut rd, &mut result.auth_addr)?,
            "f" => result.total_app_schema_num_uint = read_u64(&mut rd)?,
            "g" => result.total_app_schema_num_byte_slice = read_u64(&mut rd)?,
            "h" => result.total_extra_app_pages = read_u32(&mut rd)?,
            "i" => result.total_asset_params = read_u64(&mut rd)?,
            "j" => result.total_assets = read_u64(&mut rd)?,
            "k" => result.total_app_params = read_u64(&mut rd)?,
            "l" => result.total_app_local_states = read_u64(&mut rd)?,
            "m" => result.total_boxes = read_u64(&mut rd)?,
            "n" => result.total_box_bytes = read_u64(&mut rd)?,
            "o" => result.incentive_eligible = read_bool(&mut rd)?,
            "p" => result.last_proposed = read_u64(&mut rd)?,
            "q" => result.last_heartbeat = read_u64(&mut rd)?,
            "A" => read_fixed_into(&mut rd, &mut result.vote_id)?,
            "B" => read_fixed_into(&mut rd, &mut result.selection_id)?,
            "C" => result.vote_first_valid = read_u64(&mut rd)?,
            "D" => result.vote_last_valid = read_u64(&mut rd)?,
            "E" => result.vote_key_dilution = read_u64(&mut rd)?,
            "F" => read_fixed_into(&mut rd, &mut result.state_proof_id)?,
            "z" => result.update_round = read_u64(&mut rd)?,
            // go's msgp decoder: msgp.ErrNoField (issue #2394)
            other => return Err(unknown_field(other)),
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// ResourcesData decoder
// ---------------------------------------------------------------------------

/// Decode a raw msgpack blob into `CatchpointResourcesData`.
///
/// Map keys (from Go `trackerdb.ResourcesData` codec tags):
///   a=Total, b=Decimals, c=DefaultFrozen, d=UnitName, e=AssetName,
///   f=URL, g=MetadataHash, h=Manager, i=Reserve, j=Freeze, k=Clawback,
///   l=Amount, m=Frozen,
///   n=SchemaNumUint, o=SchemaNumByteSlice, p=KeyValue,
///   q=ApprovalProgram, r=ClearStateProgram, s=GlobalState,
///   t=LocalStateSchemaNumUint, u=LocalStateSchemaNumByteSlice,
///   v=GlobalStateSchemaNumUint, w=GlobalStateSchemaNumByteSlice,
///   x=ExtraProgramPages, y=ResourceFlags, z=UpdateRound,
///   A=Version, B=SizeSponsor, C=ForeignBoxReads, D=FamilyBoxAccess
pub fn decode_resources_data(raw: &[u8]) -> Result<CatchpointResourcesData, CatchpointError> {
    if raw.is_empty() {
        return Ok(CatchpointResourcesData::default());
    }

    let mut rd: &[u8] = raw;
    let mut result = CatchpointResourcesData::default();

    let n = read_map_header(&mut rd)?;
    for _ in 0..n {
        let key = read_map_key(&mut rd)?;
        match key.as_str() {
            "a" => result.total = read_u64(&mut rd)?,
            "b" => result.decimals = read_u32(&mut rd)?,
            "c" => result.default_frozen = read_bool(&mut rd)?,
            // Issue #1608: raw bytes, not `read_string` -- go's
            // `string`-typed UnitName/AssetName/URL are not
            // UTF-8-validated on the wire, and real mainnet catchpoints
            // contain non-UTF-8 bytes in these fields.
            "d" => result.unit_name = read_go_str_bytes(&mut rd)?,
            "e" => result.asset_name = read_go_str_bytes(&mut rd)?,
            "f" => result.url = read_go_str_bytes(&mut rd)?,
            "g" => read_fixed_into(&mut rd, &mut result.metadata_hash)?,
            "h" => read_fixed_into(&mut rd, &mut result.manager)?,
            "i" => read_fixed_into(&mut rd, &mut result.reserve)?,
            "j" => read_fixed_into(&mut rd, &mut result.freeze)?,
            "k" => read_fixed_into(&mut rd, &mut result.clawback)?,
            "l" => result.amount = read_u64(&mut rd)?,
            "m" => result.frozen = read_bool(&mut rd)?,
            "n" => result.schema_num_uint = read_u64(&mut rd)?,
            "o" => result.schema_num_byte_slice = read_u64(&mut rd)?,
            "p" => merge_teal_key_value(&mut rd, &mut result.key_value)?,
            "q" => result.approval_program = read_bytes_vec(&mut rd)?,
            "r" => result.clear_state_program = read_bytes_vec(&mut rd)?,
            "s" => merge_teal_key_value(&mut rd, &mut result.global_state)?,
            "t" => result.local_state_schema_num_uint = read_u64(&mut rd)?,
            "u" => result.local_state_schema_num_byte_slice = read_u64(&mut rd)?,
            "v" => result.global_state_schema_num_uint = read_u64(&mut rd)?,
            "w" => result.global_state_schema_num_byte_slice = read_u64(&mut rd)?,
            "x" => result.extra_program_pages = read_u32(&mut rd)?,
            "y" => result.resource_flags = read_u8(&mut rd)?,
            "z" => result.update_round = read_u64(&mut rd)?,
            "A" => result.version = read_u64(&mut rd)?,
            "B" => read_fixed_into(&mut rd, &mut result.size_sponsor)?,
            "C" => result.foreign_box_reads = read_bool(&mut rd)?,
            "D" => result.family_box_access = read_bool(&mut rd)?,
            // go's msgp decoder: msgp.ErrNoField (issue #2394)
            other => return Err(unknown_field(other)),
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// BaseOnlineAccountData decoder
// ---------------------------------------------------------------------------

/// Decode a raw msgpack blob into `CatchpointBaseOnlineAccountData`.
///
/// Map keys (from Go `trackerdb.BaseOnlineAccountData` codec tags):
///   A=VoteID, B=SelectionID, C=VoteFirstValid, D=VoteLastValid,
///   E=VoteKeyDilution, F=StateProofID,
///   V=LastProposed, W=LastHeartbeat, X=IncentiveEligible,
///   Y=MicroAlgos, Z=RewardsBase
pub fn decode_base_online_account_data(
    raw: &[u8],
) -> Result<CatchpointBaseOnlineAccountData, CatchpointError> {
    if raw.is_empty() {
        return Ok(CatchpointBaseOnlineAccountData::default());
    }

    let mut rd: &[u8] = raw;
    let mut result = CatchpointBaseOnlineAccountData::default();

    let n = read_map_header(&mut rd)?;
    for _ in 0..n {
        let key = read_map_key(&mut rd)?;
        match key.as_str() {
            "A" => read_fixed_into(&mut rd, &mut result.vote_id)?,
            "B" => read_fixed_into(&mut rd, &mut result.selection_id)?,
            "C" => result.vote_first_valid = read_u64(&mut rd)?,
            "D" => result.vote_last_valid = read_u64(&mut rd)?,
            "E" => result.vote_key_dilution = read_u64(&mut rd)?,
            "F" => read_fixed_into(&mut rd, &mut result.state_proof_id)?,
            "V" => result.last_proposed = read_u64(&mut rd)?,
            "W" => result.last_heartbeat = read_u64(&mut rd)?,
            "X" => result.incentive_eligible = read_bool(&mut rd)?,
            "Y" => result.micro_algos = read_u64(&mut rd)?,
            "Z" => result.rewards_base = read_u64(&mut rd)?,
            // go's msgp decoder: msgp.ErrNoField (issue #2394)
            other => return Err(unknown_field(other)),
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// OnlineRoundParamsData decoder
// ---------------------------------------------------------------------------

/// Decode a raw msgpack blob into `CatchpointOnlineRoundParamsData`.
///
/// Map keys (from Go `ledgercore.OnlineRoundParamsData` codec tags):
///   "online"=OnlineSupply, "rwdlvl"=RewardsLevel, "proto"=CurrentProtocol
pub fn decode_online_round_params_data(
    raw: &[u8],
) -> Result<CatchpointOnlineRoundParamsData, CatchpointError> {
    if raw.is_empty() {
        return Ok(CatchpointOnlineRoundParamsData::default());
    }

    let mut rd: &[u8] = raw;
    let mut result = CatchpointOnlineRoundParamsData::default();

    let n = read_map_header(&mut rd)?;
    for _ in 0..n {
        let key = read_map_key(&mut rd)?;
        match key.as_str() {
            "online" => result.online_supply = read_u64(&mut rd)?,
            "rwdlvl" => result.rewards_level = read_u64(&mut rd)?,
            "proto" => result.current_protocol = read_string(&mut rd)?,
            // go's msgp decoder: msgp.ErrNoField (issue #2394)
            other => return Err(unknown_field(other)),
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Catchpoint file sections (issue #2396)
// ---------------------------------------------------------------------------
//
// go's catchpoint restore decodes every section of a catchpoint file with its
// generated msgp decoders (`ledger/catchupaccessor.go`, `protocol.Decode`):
// a key the struct lacks is `msgp.ErrNoField`, a slice / map longer than its
// `allocbound` is `msgp.ErrOverflow`, `nil` is an empty value, a `string` is
// arbitrary bytes and a struct is read from a map only. The
// readers below follow exactly that, for `content.msgpack`
// (`CatchpointFileHeader`), `balances.N.msgpack` (`CatchpointSnapshotChunkV6`)
// and `stateProofVerificationContext.msgpack`
// (`catchpointStateProofVerificationContext`).

/// `BalancesPerCatchpointFileChunk` (`ledger/catchpointfilewriter.go`): the
/// `allocbound` of each record slice of a chunk.
const BALANCES_PER_CATCHPOINT_FILE_CHUNK: usize = 512;
/// `resourcesPerCatchpointFileChunkBackwardCompatible`
/// (`ledger/encoded/recordsV6.go`): the `allocbound` of `BalanceRecordV6.Resources`.
const RESOURCES_PER_CATCHPOINT_FILE_CHUNK_BACKWARD_COMPATIBLE: usize = 300_000;
/// `encoded.KVRecordV6MaxKeyLength`.
const KV_RECORD_V6_MAX_KEY_LENGTH: usize = 128;
/// `encoded.KVRecordV6MaxValueLength`.
const KV_RECORD_V6_MAX_VALUE_LENGTH: usize = 32768;
/// `SPContextPerCatchpointFile` (`ledger/catchpointfilewriter.go`).
const SP_CONTEXT_PER_CATCHPOINT_FILE: usize = 70_000;
/// `crypto.MaxHashDigestSize`: the `allocbound` of a `crypto.GenericDigest`.
const MAX_HASH_DIGEST_SIZE: usize = 64;
/// `bounds.MaxConsensusVersionLen`: the `allocbound` of a `protocol.ConsensusVersion`.
const MAX_CONSENSUS_VERSION_LEN: usize = 128;

fn overflow(what: &str, n: usize, bound: usize) -> CatchpointError {
    CatchpointError::DecodeError(format!("{what}: msgp: {n} overflows the bound of {bound}"))
}

/// One go msgp struct: a map, a key dispatched to `field` (which returns
/// `false` for a key the struct lacks). go v5.1.1's generated decoders read a
/// struct from a map only (msgp 1.1.66, go #6774): an array, empty or not, is
/// `ReadMapHeaderBytes`'s `TypeError` (issue #2609).
fn decode_struct(
    rd: &mut &[u8],
    mut field: impl FnMut(&str, &mut &[u8]) -> Result<bool, CatchpointError>,
) -> Result<(), CatchpointError> {
    for _ in 0..read_map_header(rd)? {
        let key = read_map_key(rd)?;
        if !field(&key, rd)? {
            return Err(unknown_field(&key));
        }
    }
    Ok(())
}

/// [`decode_struct`] into an already decoded value, as go's generated
/// `UnmarshalMsg` does (issue #2421): a repeated key decodes into the field
/// again (a nested struct keeps the fields the repeat does not mention), and a
/// `nil` map header resets the whole value to `zero` (go: `(*z) = T{}`).
fn decode_struct_into<T>(
    rd: &mut &[u8],
    v: &mut T,
    zero: impl FnOnce() -> T,
    mut field: impl FnMut(&mut T, &str, &mut &[u8]) -> Result<bool, CatchpointError>,
) -> Result<(), CatchpointError> {
    if peek_byte(rd)? == 0xc0 {
        *rd = &rd[1..];
        *v = zero();
        return Ok(());
    }
    decode_struct(rd, |k, rd| field(v, k, rd))
}

/// A slice field with an `allocbound`, decoded into its already decoded value
/// exactly as go's generated code does (issue #2421): `nil` makes it nil, a
/// map is read as its interleaved key/value array (go-codec compat in
/// `msgp.ReadArrayHeaderBytes`), and for `n` elements go re-slices the
/// existing slice when its capacity allows (`cap(z.X) >= n`: `z.X[:n]`, each
/// element decoded INTO the element already there, so it keeps what the new
/// element does not mention) and else makes a fresh one of `n` zero elements.
/// `spare` holds the elements past `v.len()` that are still within go's
/// capacity (a shorter repeat hides them, a longer one brings them back).
fn read_bounded_vec_into<T>(
    rd: &mut &[u8],
    what: &str,
    bound: usize,
    v: &mut Vec<T>,
    spare: &mut Vec<T>,
    zero: impl Fn() -> T,
    mut item: impl FnMut(&mut &[u8], &mut T) -> Result<(), CatchpointError>,
) -> Result<(), CatchpointError> {
    let n = match peek_byte(rd)? {
        0xc0 => {
            *rd = &rd[1..];
            v.clear();
            spare.clear();
            return Ok(());
        }
        0x80..=0x8f | 0xde | 0xdf => 2 * read_map_header(rd)? as usize,
        _ => read_array_header(rd)? as usize,
    };
    if n > bound {
        return Err(overflow(what, n, bound));
    }
    if v.len() + spare.len() >= n {
        if n <= v.len() {
            let mut hidden = v.split_off(n);
            hidden.append(spare);
            *spare = hidden;
        } else {
            let rest = spare.split_off(n - v.len());
            v.append(spare);
            *spare = rest;
        }
    } else {
        v.clear();
        spare.clear();
        v.extend((0..n).map(|_| zero()));
    }
    for e in v.iter_mut() {
        item(rd, e)?;
    }
    Ok(())
}

/// A `[]byte` with an `allocbound` (go reads the header and fails before the
/// value when it is longer).
fn read_bounded_bytes(
    rd: &mut &[u8],
    what: &str,
    bound: usize,
) -> Result<Vec<u8>, CatchpointError> {
    algo_types::go_msgp::check_go_bytes_bound(rd, bound)
        .map_err(|e| CatchpointError::DecodeError(format!("{what}: {e}")))?;
    read_bytes_vec(rd)
}

/// A go `string` (`msgp.ReadStringBytes`: arbitrary bytes, `nil` is "").
fn read_go_string(rd: &mut &[u8]) -> Result<String, CatchpointError> {
    algo_types::go_msgp::read_string(rd).map_err(|e| CatchpointError::DecodeError(e.to_string()))
}

/// A bounded go string type (`protocol.ConsensusVersion`).
fn read_bounded_go_string(
    rd: &mut &[u8],
    what: &str,
    bound: usize,
) -> Result<String, CatchpointError> {
    algo_types::go_msgp::check_go_bytes_bound(rd, bound)
        .map_err(|e| CatchpointError::DecodeError(format!("{what}: {e}")))?;
    read_go_string(rd)
}

/// A `msgp.Raw` field: the encoded bytes of the next value, verbatim (`nil` is
/// empty, as go's `Raw.UnmarshalMsg`). A `bin` value is taken as the
/// already-unwrapped blob, the shape `rmp_serde` writes for these `ByteBuf`
/// fields (this crate's own test chunks).
fn read_msgp_raw(rd: &mut &[u8]) -> Result<serde_bytes::ByteBuf, CatchpointError> {
    match peek_byte(rd)? {
        0xc0 => {
            *rd = &rd[1..];
            Ok(serde_bytes::ByteBuf::new())
        }
        0xc4..=0xc6 => read_bytes_vec(rd).map(serde_bytes::ByteBuf::from),
        _ => read_raw_value(rd).map(serde_bytes::ByteBuf::from),
    }
}

/// A go `basics.Address` (`[32]byte`) held in a `ByteBuf`, decoded into its
/// current value (see [`read_fixed_into`]).
fn read_address_into(
    rd: &mut &[u8],
    addr: &mut serde_bytes::ByteBuf,
) -> Result<(), CatchpointError> {
    let mut a = [0u8; 32];
    let n = addr.len().min(32);
    a[..n].copy_from_slice(&addr[..n]);
    read_fixed_into(rd, &mut a)?;
    *addr = serde_bytes::ByteBuf::from(a.to_vec());
    Ok(())
}

fn zero_address() -> serde_bytes::ByteBuf {
    serde_bytes::ByteBuf::from(vec![0u8; 32])
}

fn decode_algo_count(rd: &mut &[u8], v: &mut AlgoCount) -> Result<(), CatchpointError> {
    decode_struct_into(rd, v, AlgoCount::default, |v, k, rd| {
        match k {
            "mon" => v.money = read_u64(rd)?,
            "rwd" => v.reward_units = read_u64(rd)?,
            _ => return Ok(false),
        }
        Ok(true)
    })
}

fn decode_account_totals(rd: &mut &[u8], v: &mut AccountTotals) -> Result<(), CatchpointError> {
    decode_struct_into(rd, v, AccountTotals::default, |v, k, rd| {
        match k {
            "online" => decode_algo_count(rd, &mut v.online)?,
            "offline" => decode_algo_count(rd, &mut v.offline)?,
            "notpart" => decode_algo_count(rd, &mut v.not_participating)?,
            "rwdlvl" => v.rewards_level = read_u64(rd)?,
            _ => return Ok(false),
        }
        Ok(true)
    })
}

/// Decode `content.msgpack`: go `CatchpointFileHeader` (`ledger/catchpointfileheader.go`).
pub fn decode_catchpoint_file_header(raw: &[u8]) -> Result<CatchpointFileHeader, CatchpointError> {
    let mut rd = raw;
    let mut v = CatchpointFileHeader::default();
    decode_struct(&mut rd, |k, rd| {
        match k {
            "version" => v.version = read_u64(rd)?,
            "balancesRound" => v.balances_round = read_u64(rd)?,
            "blocksRound" => v.blocks_round = read_u64(rd)?,
            "accountTotals" => decode_account_totals(rd, &mut v.totals)?,
            "accountsCount" => v.total_accounts = read_u64(rd)?,
            "chunksCount" => v.total_chunks = read_u64(rd)?,
            "kvsCount" => v.total_kvs = read_u64(rd)?,
            "onlineAccountsCount" => v.total_online_accounts = read_u64(rd)?,
            "onlineRoundParamsCount" => v.total_online_round_params = read_u64(rd)?,
            "catchpoint" => v.catchpoint = read_go_string(rd)?,
            "blockHeaderDigest" => read_address_into(rd, &mut v.block_header_digest)?,
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(v)
}

fn zero_balance_record() -> BalanceRecordV6 {
    BalanceRecordV6 {
        address: zero_address(),
        ..Default::default()
    }
}

fn decode_balance_record(rd: &mut &[u8], v: &mut BalanceRecordV6) -> Result<(), CatchpointError> {
    decode_struct_into(rd, v, zero_balance_record, |v, k, rd| {
        match k {
            "a" => read_address_into(rd, &mut v.address)?,
            "b" => v.account_data = read_msgp_raw(rd)?,
            "c" => {
                // go: a nil map clears it, any other map is decoded into
                // the existing one (entries added, a repeated index
                // replaced)
                let nil = peek_byte(rd)? == 0xc0;
                let n = read_map_header(rd)? as usize;
                if n > RESOURCES_PER_CATCHPOINT_FILE_CHUNK_BACKWARD_COMPATIBLE {
                    return Err(overflow(
                        "BalanceRecordV6.c",
                        n,
                        RESOURCES_PER_CATCHPOINT_FILE_CHUNK_BACKWARD_COMPATIBLE,
                    ));
                }
                if nil {
                    v.resources.clear();
                }
                v.resources.reserve(n.min(1024));
                for _ in 0..n {
                    let aidx = read_u64(rd)?;
                    let res = read_msgp_raw(rd)?;
                    v.resources.insert(aidx, res);
                }
            }
            "e" => v.expecting_more_entries = read_bool(rd)?,
            _ => return Ok(false),
        }
        Ok(true)
    })
}

fn decode_kv_record(rd: &mut &[u8], v: &mut KVRecordV6) -> Result<(), CatchpointError> {
    decode_struct_into(rd, v, KVRecordV6::default, |v, k, rd| {
        match k {
            "k" => {
                v.key = read_bounded_bytes(rd, "KVRecordV6.k", KV_RECORD_V6_MAX_KEY_LENGTH)?.into()
            }
            "v" => {
                v.value =
                    read_bounded_bytes(rd, "KVRecordV6.v", KV_RECORD_V6_MAX_VALUE_LENGTH)?.into()
            }
            _ => return Ok(false),
        }
        Ok(true)
    })
}

fn zero_online_account_record() -> OnlineAccountRecordV6 {
    OnlineAccountRecordV6 {
        address: zero_address(),
        ..Default::default()
    }
}

fn decode_online_account_record(
    rd: &mut &[u8],
    v: &mut OnlineAccountRecordV6,
) -> Result<(), CatchpointError> {
    decode_struct_into(rd, v, zero_online_account_record, |v, k, rd| {
        match k {
            "addr" => read_address_into(rd, &mut v.address)?,
            "upd" => v.updated_round = read_u64(rd)?,
            "nob" => v.normalized_online_balance = read_u64(rd)?,
            "vlv" => v.vote_last_valid = read_u64(rd)?,
            "data" => v.data = read_msgp_raw(rd)?,
            _ => return Ok(false),
        }
        Ok(true)
    })
}

fn decode_online_round_params_record(
    rd: &mut &[u8],
    v: &mut OnlineRoundParamsRecordV6,
) -> Result<(), CatchpointError> {
    decode_struct_into(rd, v, OnlineRoundParamsRecordV6::default, |v, k, rd| {
        match k {
            "rnd" => v.round = read_u64(rd)?,
            "data" => v.data = read_msgp_raw(rd)?,
            _ => return Ok(false),
        }
        Ok(true)
    })
}

/// Decode one (decompressed) `balances.N.msgpack`: go `CatchpointSnapshotChunkV6`.
/// The `msgp.Raw` account / resource / online blobs are kept verbatim (the
/// bytes go hashes); the importer decodes them.
pub fn decode_catchpoint_snapshot_chunk(
    raw: &[u8],
) -> Result<CatchpointSnapshotChunkV6, CatchpointError> {
    let mut rd = raw;
    let mut v = CatchpointSnapshotChunkV6::default();
    // go's hidden slice capacity per field (see `read_bounded_vec_into`)
    let (mut bl, mut kv, mut oa, mut orp) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let bound = BALANCES_PER_CATCHPOINT_FILE_CHUNK;
    decode_struct(&mut rd, |k, rd| {
        match k {
            "bl" => read_bounded_vec_into(
                rd,
                "bl",
                bound,
                &mut v.balances,
                &mut bl,
                zero_balance_record,
                decode_balance_record,
            )?,
            "kv" => read_bounded_vec_into(
                rd,
                "kv",
                bound,
                &mut v.kvs,
                &mut kv,
                KVRecordV6::default,
                decode_kv_record,
            )?,
            "oa" => read_bounded_vec_into(
                rd,
                "oa",
                bound,
                &mut v.online_accounts,
                &mut oa,
                zero_online_account_record,
                decode_online_account_record,
            )?,
            "orp" => read_bounded_vec_into(
                rd,
                "orp",
                bound,
                &mut v.online_round_params,
                &mut orp,
                OnlineRoundParamsRecordV6::default,
                decode_online_round_params_record,
            )?,
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(v)
}

fn decode_sp_verification_context(
    rd: &mut &[u8],
    v: &mut algo_codec::StateProofVerificationContext,
) -> Result<(), CatchpointError> {
    decode_struct_into(
        rd,
        v,
        algo_codec::StateProofVerificationContext::default,
        |v, k, rd| {
            match k {
                "spround" => v.last_attested_round = read_u64(rd)?,
                "vc" => v.voters_commitment = read_bounded_bytes(rd, "vc", MAX_HASH_DIGEST_SIZE)?,
                "pw" => v.online_total_weight = read_u64(rd)?,
                "v" => v.version = read_bounded_go_string(rd, "v", MAX_CONSENSUS_VERSION_LEN)?,
                _ => return Ok(false),
            }
            Ok(true)
        },
    )
}

/// Decode `stateProofVerificationContext.msgpack`: go
/// `catchpointStateProofVerificationContext` (`ledger/catchpointfilewriter.go`).
pub fn decode_catchpoint_sp_verification(
    raw: &[u8],
) -> Result<CatchpointStateProofVerificationWrapper, CatchpointError> {
    let mut rd = raw;
    let mut v = CatchpointStateProofVerificationWrapper::default();
    let mut spare = Vec::new();
    decode_struct(&mut rd, |k, rd| {
        match k {
            "spd" => read_bounded_vec_into(
                rd,
                "spd",
                SP_CONTEXT_PER_CATCHPOINT_FILE,
                &mut v.data,
                &mut spare,
                algo_codec::StateProofVerificationContext::default,
                decode_sp_verification_context,
            )?,
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(v)
}

/// The entries of a `basics.TealKeyValue` (`map[string]TealValue`, an app's
/// global or local state inside a resource blob), checked the way go's
/// generated decoder reads them: a map of go-string keys to `TealValue`
/// structs (`tt`, `tb`, `ui`), where any other `TealValue` key is
/// `msgp.ErrNoField`. Each entry is (key bytes, encoded key, encoded value).
#[allow(clippy::type_complexity)]
fn read_teal_entries<'a>(
    rd: &mut &'a [u8],
) -> Result<Vec<(Vec<u8>, &'a [u8], &'a [u8])>, CatchpointError> {
    let n = read_map_header(rd)?;
    let mut out = Vec::with_capacity((n as usize).min(1024));
    for _ in 0..n {
        let ks = *rd;
        let key = read_go_str_bytes(rd)?;
        let vs = *rd;
        decode_struct(rd, |k, rd| {
            match k {
                "tt" | "ui" => {
                    read_u64(rd)?;
                }
                "tb" => {
                    read_go_str_bytes(rd)?;
                }
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        out.push((key, &ks[..ks.len() - vs.len()], &vs[..vs.len() - rd.len()]));
    }
    Ok(out)
}

/// Decode a `basics.TealKeyValue` into the already decoded one, as go's
/// generated decoder does (issue #2421): `nil` clears it, otherwise the
/// existing map receives the entries (each value a fresh `TealValue`, a
/// repeated map key keeping its last value). Kept as raw msgpack: empty for a
/// nil or empty map (go's `len(KeyValue) == 0`), the value verbatim when
/// nothing was decoded before, else a map of the merged entries.
fn merge_teal_key_value(rd: &mut &[u8], kv: &mut Vec<u8>) -> Result<(), CatchpointError> {
    if peek_byte(rd)? == 0xc0 {
        *rd = &rd[1..];
        kv.clear();
        return Ok(());
    }
    let start = *rd;
    let entries = read_teal_entries(rd)?;
    if entries.is_empty() {
        return Ok(());
    }
    if kv.is_empty() {
        *kv = start[..start.len() - rd.len()].to_vec();
        return Ok(());
    }
    let mut old: &[u8] = kv;
    let mut merged: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    let prior = read_teal_entries(&mut old)?;
    for (k, ke, ve) in prior.into_iter().chain(entries) {
        match merged.iter_mut().find(|e| e.0 == k) {
            Some(e) => e.2 = ve.to_vec(),
            None => merged.push((k, ke.to_vec(), ve.to_vec())),
        }
    }
    let mut out = Vec::new();
    rmp::encode::write_map_len(&mut out, merged.len() as u32)
        .map_err(|e| CatchpointError::DecodeError(e.to_string()))?;
    for (_, ke, ve) in merged {
        out.extend_from_slice(&ke);
        out.extend_from_slice(&ve);
    }
    *kv = out;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build a msgpack map manually using rmpv for known values.
    fn encode_map(pairs: &[(&str, rmpv::Value)]) -> Vec<u8> {
        let map_pairs: Vec<(rmpv::Value, rmpv::Value)> = pairs
            .iter()
            .map(|(k, v)| (rmpv::Value::String((*k).into()), v.clone()))
            .collect();
        let val = rmpv::Value::Map(map_pairs);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &val).expect("encode");
        buf
    }

    // -----------------------------------------------------------------------
    // BaseAccountData tests
    // -----------------------------------------------------------------------

    #[test]
    fn decode_base_account_data_empty_map() {
        // Empty map -> all defaults
        let raw = encode_map(&[]);
        let result = decode_base_account_data(&raw).unwrap();
        assert_eq!(result, CatchpointBaseAccountData::default());
    }

    #[test]
    fn decode_base_account_data_empty_input() {
        let result = decode_base_account_data(&[]).unwrap();
        assert_eq!(result, CatchpointBaseAccountData::default());
    }

    #[test]
    fn decode_base_account_data_map_with_values() {
        let auth_addr = [0xABu8; 32];
        let vote_id = [0x11u8; 32];
        let selection_id = [0x22u8; 32];
        let state_proof_id = [0x33u8; 64];

        let raw = encode_map(&[
            ("a", rmpv::Value::from(1u64)),                 // status = Online
            ("b", rmpv::Value::from(5_000_000u64)),         // micro_algos
            ("c", rmpv::Value::from(100u64)),               // rewards_base
            ("d", rmpv::Value::from(500u64)),               // rewarded_micro_algos
            ("e", rmpv::Value::Binary(auth_addr.to_vec())), // auth_addr
            ("f", rmpv::Value::from(10u64)),                // total_app_schema_num_uint
            ("g", rmpv::Value::from(5u64)),                 // total_app_schema_num_byte_slice
            ("h", rmpv::Value::from(3u64)),                 // total_extra_app_pages
            ("i", rmpv::Value::from(7u64)),                 // total_asset_params
            ("j", rmpv::Value::from(12u64)),                // total_assets
            ("k", rmpv::Value::from(4u64)),                 // total_app_params
            ("l", rmpv::Value::from(8u64)),                 // total_app_local_states
            ("m", rmpv::Value::from(2u64)),                 // total_boxes
            ("n", rmpv::Value::from(1024u64)),              // total_box_bytes
            ("o", rmpv::Value::Boolean(true)),              // incentive_eligible
            ("p", rmpv::Value::from(999u64)),               // last_proposed
            ("q", rmpv::Value::from(998u64)),               // last_heartbeat
            ("A", rmpv::Value::Binary(vote_id.to_vec())),
            ("B", rmpv::Value::Binary(selection_id.to_vec())),
            ("C", rmpv::Value::from(100u64)),  // vote_first_valid
            ("D", rmpv::Value::from(200u64)),  // vote_last_valid
            ("E", rmpv::Value::from(1000u64)), // vote_key_dilution
            ("F", rmpv::Value::Binary(state_proof_id.to_vec())),
            ("z", rmpv::Value::from(42u64)), // update_round
        ]);

        let result = decode_base_account_data(&raw).unwrap();
        assert_eq!(result.status, 1);
        assert_eq!(result.micro_algos, 5_000_000);
        assert_eq!(result.rewards_base, 100);
        assert_eq!(result.rewarded_micro_algos, 500);
        assert_eq!(result.auth_addr, auth_addr);
        assert_eq!(result.total_app_schema_num_uint, 10);
        assert_eq!(result.total_app_schema_num_byte_slice, 5);
        assert_eq!(result.total_extra_app_pages, 3);
        assert_eq!(result.total_asset_params, 7);
        assert_eq!(result.total_assets, 12);
        assert_eq!(result.total_app_params, 4);
        assert_eq!(result.total_app_local_states, 8);
        assert_eq!(result.total_boxes, 2);
        assert_eq!(result.total_box_bytes, 1024);
        assert!(result.incentive_eligible);
        assert_eq!(result.last_proposed, 999);
        assert_eq!(result.last_heartbeat, 998);
        assert_eq!(result.vote_id, vote_id);
        assert_eq!(result.selection_id, selection_id);
        assert_eq!(result.vote_first_valid, 100);
        assert_eq!(result.vote_last_valid, 200);
        assert_eq!(result.vote_key_dilution, 1000);
        assert_eq!(result.state_proof_id, state_proof_id);
        assert_eq!(result.update_round, 42);
    }

    #[test]
    fn decode_base_account_data_partial_map() {
        // Only a few fields set (omitempty)
        let raw = encode_map(&[
            ("b", rmpv::Value::from(1_000_000u64)),
            ("z", rmpv::Value::from(10u64)),
        ]);
        let result = decode_base_account_data(&raw).unwrap();
        assert_eq!(result.status, 0);
        assert_eq!(result.micro_algos, 1_000_000);
        assert_eq!(result.update_round, 10);
        assert_eq!(result.total_boxes, 0);
    }

    #[test]
    fn decode_base_account_data_unknown_keys_rejected() {
        // go's generated decoder: msgp.ErrNoField (issue #2394)
        let raw = encode_map(&[
            ("b", rmpv::Value::from(42u64)),
            ("zzz_future", rmpv::Value::from(999u64)),
        ]);
        let err = decode_base_account_data(&raw).unwrap_err();
        assert!(err.to_string().contains("zzz_future"), "{err}");
    }

    #[test]
    fn decode_base_account_data_truncated_error() {
        // Just a map header with 1 entry but no data
        let raw = vec![0x81]; // fixmap with 1 entry, but no key/value
        let result = decode_base_account_data(&raw);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // ResourcesData tests
    // -----------------------------------------------------------------------

    #[test]
    fn decode_resources_data_empty_map() {
        let raw = encode_map(&[]);
        let result = decode_resources_data(&raw).unwrap();
        assert_eq!(result, CatchpointResourcesData::default());
    }

    #[test]
    fn decode_resources_data_empty_input() {
        let result = decode_resources_data(&[]).unwrap();
        assert_eq!(result, CatchpointResourcesData::default());
    }

    #[test]
    fn decode_resources_data_asset_params() {
        let manager = [0x11u8; 32];
        let raw = encode_map(&[
            ("a", rmpv::Value::from(1_000_000u64)),                // total
            ("b", rmpv::Value::from(6u64)),                        // decimals
            ("c", rmpv::Value::Boolean(true)),                     // default_frozen
            ("d", rmpv::Value::String("ALGO".into())),             // unit_name
            ("e", rmpv::Value::String("Algorand".into())),         // asset_name
            ("f", rmpv::Value::String("https://algo.org".into())), // url
            ("h", rmpv::Value::Binary(manager.to_vec())),          // manager
            ("y", rmpv::Value::from(2u64)),                        // resource_flags (ownership)
        ]);
        let result = decode_resources_data(&raw).unwrap();
        assert_eq!(result.total, 1_000_000);
        assert_eq!(result.decimals, 6);
        assert!(result.default_frozen);
        assert_eq!(result.unit_name, b"ALGO");
        assert_eq!(result.asset_name, b"Algorand");
        assert_eq!(result.url, b"https://algo.org");
        assert_eq!(result.manager, manager);
        assert_eq!(result.resource_flags, 2);
    }

    /// Issue #1608: go-algorand's `AssetParams.UnitName`/`AssetName`/`URL`
    /// are Go `string`s, which are arbitrary byte sequences -- NOT
    /// guaranteed to be valid UTF-8 (only length-bounded). A real mainnet
    /// catchpoint (round 65370000, see the nightly soak in issue #1598) was
    /// observed to contain exactly this: a msgpack "str"-marker value whose
    /// payload is not valid UTF-8. `decode_resources_data` must decode it
    /// successfully and preserve the exact original bytes, not hard-error
    /// the way `String::from_utf8` would.
    #[test]
    fn decode_resources_data_non_utf8_asset_fields_preserved_byte_exact() {
        // 0xFF is never a valid UTF-8 lead byte -- these are deliberately
        // invalid UTF-8 sequences, still valid as msgpack "str" payloads
        // (msgpack's str format marker carries no UTF-8 requirement).
        let non_utf8_unit: &[u8] = &[0xFF, 0xFE, b'x'];
        let non_utf8_name: &[u8] = &[b'A', 0xFF, b'B', 0x80];
        let non_utf8_url: &[u8] = &[0xC0, 0xC1, b'?'];

        // Hand-encode msgpack "str" values directly (rmpv's `Value::String`
        // cannot represent invalid UTF-8 in this crate's rmpv version), the
        // same way `algo_codec::canonical`'s `add_str_bytes` does, so this
        // fixture is a faithful stand-in for go-algorand's own
        // never-UTF-8-validated msgp-generated encoder output.
        fn str_bytes(b: &[u8]) -> Vec<u8> {
            let mut buf = Vec::new();
            rmp::encode::write_str_len(&mut buf, b.len() as u32).unwrap();
            buf.extend_from_slice(b);
            buf
        }

        let mut raw = Vec::new();
        rmp::encode::write_map_len(&mut raw, 3).unwrap();
        rmp::encode::write_str(&mut raw, "d").unwrap();
        raw.extend_from_slice(&str_bytes(non_utf8_unit));
        rmp::encode::write_str(&mut raw, "e").unwrap();
        raw.extend_from_slice(&str_bytes(non_utf8_name));
        rmp::encode::write_str(&mut raw, "f").unwrap();
        raw.extend_from_slice(&str_bytes(non_utf8_url));

        let result = decode_resources_data(&raw).expect(
            "decode_resources_data must accept non-UTF-8 unit_name/asset_name/url bytes, \
             matching go-algorand's unvalidated Go `string` fields",
        );
        assert_eq!(result.unit_name, non_utf8_unit);
        assert_eq!(result.asset_name, non_utf8_name);
        assert_eq!(result.url, non_utf8_url);
    }

    #[test]
    fn decode_resources_data_asset_holding() {
        let raw = encode_map(&[
            ("l", rmpv::Value::from(500u64)),  // amount
            ("m", rmpv::Value::Boolean(true)), // frozen
        ]);
        let result = decode_resources_data(&raw).unwrap();
        assert_eq!(result.amount, 500);
        assert!(result.frozen);
    }

    #[test]
    fn decode_resources_data_app_params() {
        let approval = vec![0x06, 0x80, 0x01, 0x00]; // TEAL bytecode
        let clear = vec![0x06, 0x81];

        let raw = encode_map(&[
            ("q", rmpv::Value::Binary(approval.clone())), // approval_program
            ("r", rmpv::Value::Binary(clear.clone())),    // clear_state_program
            ("t", rmpv::Value::from(4u64)),               // local_state_schema_num_uint
            ("u", rmpv::Value::from(2u64)),               // local_state_schema_num_byte_slice
            ("v", rmpv::Value::from(8u64)),               // global_state_schema_num_uint
            ("w", rmpv::Value::from(4u64)),               // global_state_schema_num_byte_slice
            ("x", rmpv::Value::from(1u64)),               // extra_program_pages
            ("A", rmpv::Value::from(3u64)),               // version
            ("y", rmpv::Value::from(2u64)),               // resource_flags (ownership)
        ]);
        let result = decode_resources_data(&raw).unwrap();
        assert_eq!(result.approval_program, approval);
        assert_eq!(result.clear_state_program, clear);
        assert_eq!(result.local_state_schema_num_uint, 4);
        assert_eq!(result.local_state_schema_num_byte_slice, 2);
        assert_eq!(result.global_state_schema_num_uint, 8);
        assert_eq!(result.global_state_schema_num_byte_slice, 4);
        assert_eq!(result.extra_program_pages, 1);
        assert_eq!(result.version, 3);
        assert_eq!(result.resource_flags, 2);
    }

    #[test]
    fn decode_resources_data_with_key_value() {
        // Key-value is stored as raw msgpack; an empty map is empty, like
        // go's `len(KeyValue) == 0` (issue #2421).
        let raw = encode_map(&[
            ("n", rmpv::Value::from(1u64)),  // schema_num_uint
            ("p", rmpv::Value::Map(vec![])), // key_value (empty map)
        ]);
        let result = decode_resources_data(&raw).unwrap();
        assert_eq!(result.schema_num_uint, 1);
        assert!(result.key_value.is_empty());

        let kv = rmpv::Value::Map(vec![(
            "k".into(),
            rmpv::Value::Map(vec![("ui".into(), 3u64.into())]),
        )]);
        let mut kv_raw = Vec::new();
        rmpv::encode::write_value(&mut kv_raw, &kv).unwrap();
        let raw = encode_map(&[("p", kv)]);
        assert_eq!(decode_resources_data(&raw).unwrap().key_value, kv_raw);
    }

    #[test]
    fn decode_resources_data_unknown_keys_rejected() {
        // go's generated decoder: msgp.ErrNoField (issue #2394)
        let raw = encode_map(&[
            ("a", rmpv::Value::from(100u64)),
            ("ZZZ", rmpv::Value::from(999u64)),
        ]);
        let err = decode_resources_data(&raw).unwrap_err();
        assert!(err.to_string().contains("ZZZ"), "{err}");
    }

    // -----------------------------------------------------------------------
    // BaseOnlineAccountData tests
    // -----------------------------------------------------------------------

    #[test]
    fn decode_base_online_account_data_empty_map() {
        let raw = encode_map(&[]);
        let result = decode_base_online_account_data(&raw).unwrap();
        assert_eq!(result, CatchpointBaseOnlineAccountData::default());
    }

    #[test]
    fn decode_base_online_account_data_empty_input() {
        let result = decode_base_online_account_data(&[]).unwrap();
        assert_eq!(result, CatchpointBaseOnlineAccountData::default());
    }

    #[test]
    fn decode_base_online_account_data_map_with_values() {
        let vote_id = [0xAAu8; 32];
        let selection_id = [0xBBu8; 32];
        let state_proof_id = [0xCCu8; 64];

        let raw = encode_map(&[
            ("A", rmpv::Value::Binary(vote_id.to_vec())),
            ("B", rmpv::Value::Binary(selection_id.to_vec())),
            ("C", rmpv::Value::from(100u64)),
            ("D", rmpv::Value::from(200u64)),
            ("E", rmpv::Value::from(1000u64)),
            ("F", rmpv::Value::Binary(state_proof_id.to_vec())),
            ("V", rmpv::Value::from(50u64)),
            ("W", rmpv::Value::from(49u64)),
            ("X", rmpv::Value::Boolean(true)),
            ("Y", rmpv::Value::from(2_000_000u64)),
            ("Z", rmpv::Value::from(300u64)),
        ]);
        let result = decode_base_online_account_data(&raw).unwrap();

        assert_eq!(result.vote_id, vote_id);
        assert_eq!(result.selection_id, selection_id);
        assert_eq!(result.vote_first_valid, 100);
        assert_eq!(result.vote_last_valid, 200);
        assert_eq!(result.vote_key_dilution, 1000);
        assert_eq!(result.state_proof_id, state_proof_id);
        assert_eq!(result.last_proposed, 50);
        assert_eq!(result.last_heartbeat, 49);
        assert!(result.incentive_eligible);
        assert_eq!(result.micro_algos, 2_000_000);
        assert_eq!(result.rewards_base, 300);
    }

    #[test]
    fn decode_base_online_account_data_partial() {
        // Only voting keys, no online-specific fields
        let raw = encode_map(&[
            ("A", rmpv::Value::Binary(vec![0xFFu8; 32])),
            ("C", rmpv::Value::from(1u64)),
        ]);
        let result = decode_base_online_account_data(&raw).unwrap();
        assert_eq!(result.vote_id, [0xFFu8; 32]);
        assert_eq!(result.vote_first_valid, 1);
        assert_eq!(result.micro_algos, 0);
    }

    // -----------------------------------------------------------------------
    // OnlineRoundParamsData tests
    // -----------------------------------------------------------------------

    #[test]
    fn decode_online_round_params_data_empty_map() {
        let raw = encode_map(&[]);
        let result = decode_online_round_params_data(&raw).unwrap();
        assert_eq!(result, CatchpointOnlineRoundParamsData::default());
    }

    /// TestMarshalUnmarshalOnlineRoundParamsData
    /// (`ledger/ledgercore/msgp_gen_test.go`): go's generated
    /// `MarshalMsg`/`UnmarshalMsg` round-trip a zero-value
    /// `OnlineRoundParamsData` cleanly, with zero bytes left over. Go's
    /// `_struct struct{} codec:",omitempty,omitemptyarray"` tag means every
    /// field (`OnlineSupply`/`RewardsLevel`/`CurrentProtocol`, all
    /// zero-valued) is omitted, so `MarshalMsg` of the zero value produces
    /// exactly the canonical fixed-map-of-zero-entries byte (`0x80`) --
    /// there is no other value it could encode to. algod-rust has no
    /// `CatchpointOnlineRoundParamsData` encoder (only the hand-written
    /// positional `decode_online_round_params_data` decoder, since this
    /// blob is only ever read from go-produced catchpoints, never written),
    /// so this pins the Rust-reachable half of the same round-trip
    /// property directly against that literal byte -- decoding go's own
    /// canonical zero-value encoding must yield the default struct, with
    /// nothing left over (the same assertion `TestMarshalUnmarshalOnlineRoundParamsData`
    /// makes about `UnmarshalMsg`'s leftover-byte count).
    #[test]
    fn online_round_params_data_zero_value_matches_gos_canonical_empty_map_byte() {
        const GO_ZERO_VALUE_CANONICAL_BYTES: &[u8] = &[0x80]; // fixmap(0): every field omitempty-dropped
        assert_eq!(
            encode_map(&[]),
            GO_ZERO_VALUE_CANONICAL_BYTES,
            "the empty-map helper used by the sibling test must itself match go's canonical \
             zero-value byte, not merely an arbitrary empty map"
        );
        let result = decode_online_round_params_data(GO_ZERO_VALUE_CANONICAL_BYTES).unwrap();
        assert_eq!(result, CatchpointOnlineRoundParamsData::default());
    }

    #[test]
    fn decode_online_round_params_data_empty_input() {
        let result = decode_online_round_params_data(&[]).unwrap();
        assert_eq!(result, CatchpointOnlineRoundParamsData::default());
    }

    #[test]
    fn decode_online_round_params_data_map_with_values() {
        let raw = encode_map(&[
            ("online", rmpv::Value::from(10_000_000_000u64)),
            ("proto", rmpv::Value::String("https://github.com/algorandfoundation/specs/tree/44fa607d6051730f5264526bf59afb8b1caeab17".into())),
            ("rwdlvl", rmpv::Value::from(12345u64)),
        ]);
        let result = decode_online_round_params_data(&raw).unwrap();

        assert_eq!(result.online_supply, 10_000_000_000);
        assert_eq!(result.rewards_level, 12345);
        assert_eq!(
            result.current_protocol,
            "https://github.com/algorandfoundation/specs/tree/44fa607d6051730f5264526bf59afb8b1caeab17"
        );
    }

    #[test]
    fn decode_online_round_params_data_partial() {
        // Only online_supply set
        let raw = encode_map(&[("online", rmpv::Value::from(42u64))]);
        let result = decode_online_round_params_data(&raw).unwrap();
        assert_eq!(result.online_supply, 42);
        assert_eq!(result.rewards_level, 0);
        assert!(result.current_protocol.is_empty());
    }

    // -----------------------------------------------------------------------
    // Helper function tests
    // -----------------------------------------------------------------------

    #[test]
    fn skip_value_various_types() {
        // Test skip over different msgpack types
        let test_cases: Vec<(&str, Vec<u8>)> = vec![
            ("nil", vec![0xc0]),
            ("false", vec![0xc2]),
            ("true", vec![0xc3]),
            ("fixint_0", vec![0x00]),
            ("fixint_127", vec![0x7f]),
            ("uint8", vec![0xcc, 0xff]),
            ("uint16", vec![0xcd, 0x01, 0x00]),
            ("uint32", vec![0xce, 0x00, 0x01, 0x00, 0x00]),
            ("uint64", vec![0xcf, 0, 0, 0, 0, 0, 0, 0, 1]),
            ("fixstr_empty", vec![0xa0]),
            ("fixstr_a", vec![0xa1, b'a']),
            ("bin8_empty", vec![0xc4, 0x00]),
            ("fixmap_empty", vec![0x80]),
            ("fixarray_empty", vec![0x90]),
            ("neg_fixint", vec![0xe0]),
        ];

        for (name, data) in test_cases {
            let mut rd: &[u8] = &data;
            skip_value(&mut rd).unwrap_or_else(|e| panic!("skip_value failed for {name}: {e}"));
            assert!(
                rd.is_empty(),
                "skip_value did not consume all bytes for {name}"
            );
        }
    }

    /// go v5.1.1 (msgp 1.1.66, go #6774) generates struct decoders that read a
    /// map only: an array, however it is shaped, is a `TypeError` (issue #2609).
    #[test]
    fn array_form_is_a_type_error_like_go_v5_1_1() {
        let arrays: [&[u8]; 7] = [
            &[0x90],
            &[0x91, 0xc0],
            &[0x92, 0x01, 0x02],
            &[0x91, 0x80],
            &[0xdc, 0x00, 0x00],
            &[0xdd, 0x00, 0x00, 0x00, 0x00],
            &[0x93, 0x01],
        ];
        for raw in arrays {
            let results = [
                ("base account", decode_base_account_data(raw).map(|_| ())),
                ("resources", decode_resources_data(raw).map(|_| ())),
                (
                    "online account",
                    decode_base_online_account_data(raw).map(|_| ()),
                ),
                (
                    "online round params",
                    decode_online_round_params_data(raw).map(|_| ()),
                ),
            ];
            for (what, r) in results {
                let e = r.expect_err(what).to_string();
                assert!(e.contains("array"), "{what} {raw:02x?}: {e}");
            }
        }
    }

    #[test]
    fn read_u64_various_encodings() {
        // positive fixint
        let mut rd: &[u8] = &[42];
        assert_eq!(read_u64(&mut rd).unwrap(), 42);

        // uint8
        let mut rd: &[u8] = &[0xcc, 200];
        assert_eq!(read_u64(&mut rd).unwrap(), 200);

        // uint16
        let mut rd: &[u8] = &[0xcd, 0x01, 0x00];
        assert_eq!(read_u64(&mut rd).unwrap(), 256);

        // uint32
        let mut rd: &[u8] = &[0xce, 0x00, 0x01, 0x00, 0x00];
        assert_eq!(read_u64(&mut rd).unwrap(), 65536);

        // uint64
        let mut rd: &[u8] = &[0xcf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(read_u64(&mut rd).unwrap(), 0x1_0000_0000);

        // nil -> 0
        let mut rd: &[u8] = &[0xc0];
        assert_eq!(read_u64(&mut rd).unwrap(), 0);
    }

    #[test]
    fn read_bool_values() {
        let mut rd: &[u8] = &[0xc2];
        assert!(!read_bool(&mut rd).unwrap());

        let mut rd: &[u8] = &[0xc3];
        assert!(read_bool(&mut rd).unwrap());

        let mut rd: &[u8] = &[0xc0];
        assert!(!read_bool(&mut rd).unwrap());
    }

    #[test]
    fn read_string_values() {
        // fixstr "abc"
        let mut rd: &[u8] = &[0xa3, b'a', b'b', b'c'];
        assert_eq!(read_string(&mut rd).unwrap(), "abc");

        // empty string
        let mut rd: &[u8] = &[0xa0];
        assert_eq!(read_string(&mut rd).unwrap(), "");

        // nil -> empty
        let mut rd: &[u8] = &[0xc0];
        assert_eq!(read_string(&mut rd).unwrap(), "");
    }

    #[test]
    fn read_bytes_fixed_32() {
        let mut data = vec![0xc4, 32]; // bin8 with 32 bytes
        data.extend_from_slice(&[0xAA; 32]);
        let mut rd: &[u8] = &data;
        let result = read_bytes_fixed::<32>(&mut rd).unwrap();
        assert_eq!(result, [0xAA; 32]);

        // nil -> zeroed
        let mut rd: &[u8] = &[0xc0];
        let result = read_bytes_fixed::<32>(&mut rd).unwrap();
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn read_bytes_fixed_wrong_size() {
        // go ReadExactBytes copies min(len, N) and does not enforce the
        // length (issue #2063): short input zero-pads, long input truncates.
        let mut data = vec![0xc4, 16]; // bin8 with 16 bytes
        data.extend_from_slice(&[0xBB; 16]);
        let mut rd: &[u8] = &data;
        let result = read_bytes_fixed::<32>(&mut rd).unwrap();
        assert_eq!(&result[..16], &[0xBB; 16]);
        assert_eq!(&result[16..], &[0u8; 16]);
        // str form and uint8-array form (go accepts both)
        let mut rd: &[u8] = &[0xa2, 1, 2];
        assert_eq!(&read_bytes_fixed::<4>(&mut rd).unwrap(), &[1, 2, 0, 0]);
        let mut rd: &[u8] = &[0x92, 1, 2];
        assert_eq!(&read_bytes_fixed::<4>(&mut rd).unwrap(), &[1, 2, 0, 0]);
        // a non-container is still an error
        let mut rd: &[u8] = &[0x05];
        assert!(read_bytes_fixed::<4>(&mut rd).is_err());
    }

    #[test]
    fn read_raw_value_preserves_encoding() {
        // Encode a small map and read it back as raw bytes
        let map = encode_map(&[
            ("x", rmpv::Value::from(1u64)),
            ("y", rmpv::Value::from(2u64)),
        ]);
        let mut rd: &[u8] = &map;
        let raw = read_raw_value(&mut rd).unwrap();
        assert_eq!(raw, map);
        assert!(rd.is_empty());
    }

    // -----------------------------------------------------------------------
    // Error case tests
    // -----------------------------------------------------------------------

    #[test]
    fn decode_error_wrong_type() {
        // A string where we expect a map/array header
        let raw = vec![0xa3, b'a', b'b', b'c']; // fixstr "abc"
        let result = decode_base_account_data(&raw);
        assert!(result.is_err());
    }

    #[test]
    fn decode_error_truncated_data() {
        // Map header says 3 entries but only 1 key-value pair
        let raw = encode_map(&[("b", rmpv::Value::from(42u64))]);
        // Corrupt by changing map header to claim more entries
        let mut corrupted = raw.clone();
        corrupted[0] = 0x83; // fixmap with 3 entries
        let result = decode_base_account_data(&corrupted);
        assert!(result.is_err());
    }

    #[test]
    fn decode_nil_value_in_map() {
        // nil value for a uint64 field should default to 0
        let raw = encode_map(&[("b", rmpv::Value::Nil)]);
        let result = decode_base_account_data(&raw).unwrap();
        assert_eq!(result.micro_algos, 0);
    }

    // -----------------------------------------------------------------------
    // Round-trip test with sqlite encode/decode for comparison
    // -----------------------------------------------------------------------

    #[test]
    fn decode_base_account_data_matches_types() {
        // Verify that our decoded CatchpointBaseAccountData can be converted
        // to AccountData via the From impl.
        let raw = encode_map(&[
            ("a", rmpv::Value::from(1u64)),
            ("b", rmpv::Value::from(1_000_000u64)),
            ("i", rmpv::Value::from(3u64)),
            ("j", rmpv::Value::from(5u64)),
        ]);
        let catchpoint_data = decode_base_account_data(&raw).unwrap();
        let account_data = algo_types::AccountData::from(&catchpoint_data);

        assert_eq!(account_data.status, algo_types::AccountStatus::Online);
        assert_eq!(account_data.micro_algos, 1_000_000);
        assert_eq!(account_data.total_created_assets, 3);
        assert_eq!(account_data.total_assets_opted_in, 5);
    }

    // -----------------------------------------------------------------------
    // Repeated keys decode into the populated field, like go (issue #2421)
    // -----------------------------------------------------------------------

    fn hex_bytes(h: &str) -> Vec<u8> {
        hex::decode(h).unwrap()
    }

    /// The slice capacity go keeps: `bl` three times, 3 then 1 then 2
    /// elements. The second re-slices to 1 element (merging into the first),
    /// the third re-slices back to 2 within the old capacity, so the hidden
    /// second element comes back with its first-occurrence fields. go
    /// v5.0.5-stable decodes this to `{bl:[{a:01..}, {a:02.., e:true}]}`.
    #[test]
    fn repeated_slice_reuses_go_capacity() {
        let a1 = "01".repeat(32);
        let a2 = "02".repeat(32);
        let a3 = "03".repeat(32);
        let raw = hex_bytes(&format!(
            "83a2626c9382a161c420{a1}a165c382a161c420{a2}a165c381a161c420{a3}a2626c9181a165c2a2626c928080"
        ));
        let c = decode_catchpoint_snapshot_chunk(&raw).unwrap();
        assert_eq!(c.balances.len(), 2);
        assert_eq!(c.balances[0].address.as_ref(), [1u8; 32]);
        assert!(!c.balances[0].expecting_more_entries);
        assert_eq!(c.balances[1].address.as_ref(), [2u8; 32]);
        assert!(c.balances[1].expecting_more_entries);
    }

    /// A longer repeat is a fresh slice (go: `make`), and a nil element
    /// resets the element it is decoded into.
    #[test]
    fn repeated_slice_longer_is_fresh_and_nil_element_resets() {
        let a1 = "01".repeat(32);
        let raw = hex_bytes(&format!("82a2626c9182a161c420{a1}a165c3a2626c928080"));
        let c = decode_catchpoint_snapshot_chunk(&raw).unwrap();
        assert_eq!(c.balances.len(), 2);
        assert_eq!(c.balances[0].address.as_ref(), [0u8; 32]);
        assert!(!c.balances[0].expecting_more_entries);

        let raw = hex_bytes(&format!("82a2626c9182a161c420{a1}a165c3a2626c91c0"));
        let c = decode_catchpoint_snapshot_chunk(&raw).unwrap();
        assert_eq!(c.balances.len(), 1);
        assert_eq!(c.balances[0].address.as_ref(), [0u8; 32]);
        assert!(!c.balances[0].expecting_more_entries);
    }

    /// A repeated `[32]byte` with a shorter value keeps the earlier tail; a
    /// nil one zeroes it.
    #[test]
    fn repeated_fixed_bytes_keep_the_tail() {
        let raw = encode_map(&[
            ("e", rmpv::Value::Binary(vec![0xAB; 32])),
            ("e", rmpv::Value::Binary(vec![0x01])),
        ]);
        let d = decode_base_account_data(&raw).unwrap();
        let mut want = [0xABu8; 32];
        want[0] = 1;
        assert_eq!(d.auth_addr, want);

        let raw = encode_map(&[
            ("e", rmpv::Value::Binary(vec![0xAB; 32])),
            ("e", rmpv::Value::Nil),
        ]);
        assert_eq!(decode_base_account_data(&raw).unwrap().auth_addr, [0u8; 32]);
    }

    /// A repeated resources map adds to the existing one; nil clears it.
    #[test]
    fn repeated_resources_map_merges() {
        // {bl:[{c:{1:{a:1}}, c:<extra>}]}
        let rec = |extra: &str| hex_bytes(&format!("81a2626c9182a163810181a16101a163{extra}"));
        // {bl:[{c:{1:{a:1}}, c:{2:{a:2}}}]}
        let mut raw = rec("8102" /* {2: */);
        raw.extend(hex_bytes("81a16102"));
        let c = decode_catchpoint_snapshot_chunk(&raw).unwrap();
        let mut keys: Vec<_> = c.balances[0].resources.keys().copied().collect();
        keys.sort_unstable();
        assert_eq!(keys, [1, 2]);

        let raw = rec("c0");
        let c = decode_catchpoint_snapshot_chunk(&raw).unwrap();
        assert!(c.balances[0].resources.is_empty());
    }

    /// A repeated `TealKeyValue` merges the entries (a repeated state key
    /// keeps its last value); an empty or nil one is empty, as go's
    /// `len(KeyValue) == 0`.
    #[test]
    fn repeated_teal_key_value_merges() {
        let tv = |ui: u64| rmpv::Value::Map(vec![("ui".into(), ui.into())]);
        let kv = |e: Vec<(&str, u64)>| {
            rmpv::Value::Map(e.into_iter().map(|(k, u)| (k.into(), tv(u))).collect())
        };
        let raw = encode_map(&[
            ("p", kv(vec![("x", 1), ("y", 2)])),
            ("p", kv(vec![("y", 3), ("z", 4)])),
        ]);
        let d = decode_resources_data(&raw).unwrap();
        let got = rmpv::decode::read_value(&mut &d.key_value[..]).unwrap();
        assert_eq!(got, kv(vec![("x", 1), ("y", 3), ("z", 4)]));

        let raw = encode_map(&[("p", kv(vec![("x", 1)])), ("p", rmpv::Value::Nil)]);
        assert!(decode_resources_data(&raw).unwrap().key_value.is_empty());
        let raw = encode_map(&[("p", kv(vec![]))]);
        assert!(decode_resources_data(&raw).unwrap().key_value.is_empty());
    }

    /// A go `string` field also reads a `bin` (`msgp.ReadStringBytes`'s
    /// go-codec fallback), which a repeated `catchpoint` key may carry.
    #[test]
    fn string_field_reads_bin() {
        let raw = encode_map(&[("catchpoint", rmpv::Value::Binary(b"7#AB".to_vec()))]);
        assert_eq!(
            decode_catchpoint_file_header(&raw).unwrap().catchpoint,
            "7#AB"
        );
    }
}
