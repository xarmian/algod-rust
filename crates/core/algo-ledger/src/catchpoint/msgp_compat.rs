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
//! emits **map-encoded msgpack** (string keys, omitempty). The `UnmarshalMsg`
//! supports both map and positional-array formats as a fallback.
//!
//! The raw blobs stored inside catchpoint `BalanceRecordV6.account_data`,
//! `BalanceRecordV6.resources[idx]`, `OnlineAccountRecordV6.data`, and
//! `OnlineRoundParamsRecordV6.data` are all map-encoded msgpack produced by
//! `protocol.Encode`.
//!
//! This module provides decoders that handle the map format (primary) and the
//! positional-array format (fallback, for forward compatibility).

use super::types::{
    CatchpointBaseAccountData, CatchpointBaseOnlineAccountData, CatchpointError,
    CatchpointOnlineRoundParamsData, CatchpointResourcesData,
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

/// Read a msgpack binary value and copy into a fixed-size array.
/// If the value is nil, returns a zeroed array.
fn read_bytes_fixed<const N: usize>(rd: &mut &[u8]) -> Result<[u8; N], CatchpointError> {
    let marker = peek_byte(rd)?;
    if marker == 0xc0 {
        // nil
        *rd = &rd[1..];
        return Ok([0u8; N]);
    }
    let data = read_bytes_vec(rd)?;
    if data.len() != N {
        return Err(CatchpointError::DecodeError(format!(
            "expected {} bytes, got {}",
            N,
            data.len()
        )));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&data);
    Ok(arr)
}

/// Read a msgpack binary or string value as a byte vector.
fn read_bytes_vec(rd: &mut &[u8]) -> Result<Vec<u8>, CatchpointError> {
    let marker = peek_byte(rd)?;
    match marker {
        // nil
        0xc0 => {
            *rd = &rd[1..];
            Ok(Vec::new())
        }
        // bin8
        0xc4 => {
            if rd.len() < 2 {
                return Err(CatchpointError::DecodeError("truncated bin8".into()));
            }
            let len = rd[1] as usize;
            if rd.len() < 2 + len {
                return Err(CatchpointError::DecodeError("truncated bin8 data".into()));
            }
            let data = rd[2..2 + len].to_vec();
            *rd = &rd[2 + len..];
            Ok(data)
        }
        // bin16
        0xc5 => {
            if rd.len() < 3 {
                return Err(CatchpointError::DecodeError("truncated bin16".into()));
            }
            let len = u16::from_be_bytes([rd[1], rd[2]]) as usize;
            if rd.len() < 3 + len {
                return Err(CatchpointError::DecodeError("truncated bin16 data".into()));
            }
            let data = rd[3..3 + len].to_vec();
            *rd = &rd[3 + len..];
            Ok(data)
        }
        // bin32
        0xc6 => {
            if rd.len() < 5 {
                return Err(CatchpointError::DecodeError("truncated bin32".into()));
            }
            let len = u32::from_be_bytes([rd[1], rd[2], rd[3], rd[4]]) as usize;
            if rd.len() < 5 + len {
                return Err(CatchpointError::DecodeError("truncated bin32 data".into()));
            }
            let data = rd[5..5 + len].to_vec();
            *rd = &rd[5 + len..];
            Ok(data)
        }
        // fixstr (0xa0..=0xbf) -- Go's msgp sometimes encodes short byte sequences as str
        m @ 0xa0..=0xbf => {
            let len = (m & 0x1f) as usize;
            if rd.len() < 1 + len {
                return Err(CatchpointError::DecodeError("truncated fixstr".into()));
            }
            let data = rd[1..1 + len].to_vec();
            *rd = &rd[1 + len..];
            Ok(data)
        }
        // str8
        0xd9 => {
            if rd.len() < 2 {
                return Err(CatchpointError::DecodeError("truncated str8".into()));
            }
            let len = rd[1] as usize;
            if rd.len() < 2 + len {
                return Err(CatchpointError::DecodeError("truncated str8 data".into()));
            }
            let data = rd[2..2 + len].to_vec();
            *rd = &rd[2 + len..];
            Ok(data)
        }
        // str16
        0xda => {
            if rd.len() < 3 {
                return Err(CatchpointError::DecodeError("truncated str16".into()));
            }
            let len = u16::from_be_bytes([rd[1], rd[2]]) as usize;
            if rd.len() < 3 + len {
                return Err(CatchpointError::DecodeError("truncated str16 data".into()));
            }
            let data = rd[3..3 + len].to_vec();
            *rd = &rd[3 + len..];
            Ok(data)
        }
        // str32
        0xdb => {
            if rd.len() < 5 {
                return Err(CatchpointError::DecodeError("truncated str32".into()));
            }
            let len = u32::from_be_bytes([rd[1], rd[2], rd[3], rd[4]]) as usize;
            if rd.len() < 5 + len {
                return Err(CatchpointError::DecodeError("truncated str32 data".into()));
            }
            let data = rd[5..5 + len].to_vec();
            *rd = &rd[5 + len..];
            Ok(data)
        }
        _ => Err(CatchpointError::DecodeError(format!(
            "expected bin/str, got marker 0x{marker:02x}"
        ))),
    }
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

/// Try to read a map header. Returns Ok(Some(n)) for map, Ok(None) if it's an
/// array (caller should use read_array_header), or Err on other types.
fn try_read_map_header(rd: &mut &[u8]) -> Result<Option<u32>, CatchpointError> {
    let marker = peek_byte(rd)?;
    match marker {
        // fixmap
        m @ 0x80..=0x8f => {
            *rd = &rd[1..];
            Ok(Some((m & 0x0f) as u32))
        }
        // map16
        0xde => {
            if rd.len() < 3 {
                return Err(CatchpointError::DecodeError("truncated map16".into()));
            }
            let n = u16::from_be_bytes([rd[1], rd[2]]) as u32;
            *rd = &rd[3..];
            Ok(Some(n))
        }
        // map32
        0xdf => {
            if rd.len() < 5 {
                return Err(CatchpointError::DecodeError("truncated map32".into()));
            }
            let n = u32::from_be_bytes([rd[1], rd[2], rd[3], rd[4]]);
            *rd = &rd[5..];
            Ok(Some(n))
        }
        // fixarray, array16, array32 -- not a map
        0x90..=0x9f | 0xdc | 0xdd => Ok(None),
        // nil -> empty
        0xc0 => {
            *rd = &rd[1..];
            Ok(Some(0))
        }
        _ => Err(CatchpointError::DecodeError(format!(
            "expected map or array header, got marker 0x{marker:02x}"
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
/// Handles both map-encoded (primary, used by `protocol.Encode`) and
/// array-encoded (fallback) formats.
///
/// Map keys (from Go `trackerdb.BaseAccountData` codec tags):
///   a=Status, b=MicroAlgos, c=RewardsBase, d=RewardedMicroAlgos,
///   e=AuthAddr, f=TotalAppSchemaNumUint, g=TotalAppSchemaNumByteSlice,
///   h=TotalExtraAppPages, i=TotalAssetParams, j=TotalAssets,
///   k=TotalAppParams, l=TotalAppLocalStates, m=TotalBoxes, n=TotalBoxBytes,
///   o=IncentiveEligible, p=LastProposed, q=LastHeartbeat,
///   A=VoteID, B=SelectionID, C=VoteFirstValid, D=VoteLastValid,
///   E=VoteKeyDilution, F=StateProofID, z=UpdateRound
///
/// Array order (from Go struct declaration order):
///   Status, MicroAlgos, RewardsBase, RewardedMicroAlgos, AuthAddr,
///   TotalAppSchemaNumUint, TotalAppSchemaNumByteSlice, TotalExtraAppPages,
///   TotalAssetParams, TotalAssets, TotalAppParams, TotalAppLocalStates,
///   TotalBoxes, TotalBoxBytes, IncentiveEligible, LastProposed, LastHeartbeat,
///   VoteID, SelectionID, VoteFirstValid, VoteLastValid, VoteKeyDilution,
///   StateProofID, UpdateRound
pub fn decode_base_account_data(raw: &[u8]) -> Result<CatchpointBaseAccountData, CatchpointError> {
    if raw.is_empty() {
        return Ok(CatchpointBaseAccountData::default());
    }

    let mut rd: &[u8] = raw;
    let mut result = CatchpointBaseAccountData::default();

    match try_read_map_header(&mut rd)? {
        Some(n) => {
            // Map-encoded format
            for _ in 0..n {
                let key = read_map_key(&mut rd)?;
                match key.as_str() {
                    "a" => result.status = read_u64(&mut rd)? as u8,
                    "b" => result.micro_algos = read_u64(&mut rd)?,
                    "c" => result.rewards_base = read_u64(&mut rd)?,
                    "d" => result.rewarded_micro_algos = read_u64(&mut rd)?,
                    "e" => result.auth_addr = read_bytes_fixed::<32>(&mut rd)?,
                    "f" => result.total_app_schema_num_uint = read_u64(&mut rd)?,
                    "g" => result.total_app_schema_num_byte_slice = read_u64(&mut rd)?,
                    "h" => result.total_extra_app_pages = read_u64(&mut rd)? as u32,
                    "i" => result.total_asset_params = read_u64(&mut rd)?,
                    "j" => result.total_assets = read_u64(&mut rd)?,
                    "k" => result.total_app_params = read_u64(&mut rd)?,
                    "l" => result.total_app_local_states = read_u64(&mut rd)?,
                    "m" => result.total_boxes = read_u64(&mut rd)?,
                    "n" => result.total_box_bytes = read_u64(&mut rd)?,
                    "o" => result.incentive_eligible = read_bool(&mut rd)?,
                    "p" => result.last_proposed = read_u64(&mut rd)?,
                    "q" => result.last_heartbeat = read_u64(&mut rd)?,
                    "A" => result.vote_id = read_bytes_fixed::<32>(&mut rd)?,
                    "B" => result.selection_id = read_bytes_fixed::<32>(&mut rd)?,
                    "C" => result.vote_first_valid = read_u64(&mut rd)?,
                    "D" => result.vote_last_valid = read_u64(&mut rd)?,
                    "E" => result.vote_key_dilution = read_u64(&mut rd)?,
                    "F" => result.state_proof_id = read_bytes_fixed::<64>(&mut rd)?,
                    "z" => result.update_round = read_u64(&mut rd)?,
                    _ => skip_value(&mut rd)?,
                }
            }
        }
        None => {
            // Array-encoded format (fallback).
            // Field order matches Go struct declaration order.
            let len = read_array_header(&mut rd)?;
            let mut idx = 0u32;

            macro_rules! next_field {
                ($field:expr, u64) => {
                    if idx < len {
                        idx += 1;
                        $field = read_u64(&mut rd)?;
                    }
                };
                ($field:expr, u32) => {
                    if idx < len {
                        idx += 1;
                        $field = read_u64(&mut rd)? as u32;
                    }
                };
                ($field:expr, u8) => {
                    if idx < len {
                        idx += 1;
                        $field = read_u64(&mut rd)? as u8;
                    }
                };
                ($field:expr, bool) => {
                    if idx < len {
                        idx += 1;
                        $field = read_bool(&mut rd)?;
                    }
                };
                ($field:expr, bytes32) => {
                    if idx < len {
                        idx += 1;
                        $field = read_bytes_fixed::<32>(&mut rd)?;
                    }
                };
                ($field:expr, bytes64) => {
                    if idx < len {
                        idx += 1;
                        $field = read_bytes_fixed::<64>(&mut rd)?;
                    }
                };
            }

            // Go struct declaration order:
            next_field!(result.status, u8);
            next_field!(result.micro_algos, u64);
            next_field!(result.rewards_base, u64);
            next_field!(result.rewarded_micro_algos, u64);
            next_field!(result.auth_addr, bytes32);
            next_field!(result.total_app_schema_num_uint, u64);
            next_field!(result.total_app_schema_num_byte_slice, u64);
            next_field!(result.total_extra_app_pages, u32);
            next_field!(result.total_asset_params, u64);
            next_field!(result.total_assets, u64);
            next_field!(result.total_app_params, u64);
            next_field!(result.total_app_local_states, u64);
            next_field!(result.total_boxes, u64);
            next_field!(result.total_box_bytes, u64);
            next_field!(result.incentive_eligible, bool);
            next_field!(result.last_proposed, u64);
            next_field!(result.last_heartbeat, u64);
            // Embedded BaseVotingData fields:
            next_field!(result.vote_id, bytes32);
            next_field!(result.selection_id, bytes32);
            next_field!(result.vote_first_valid, u64);
            next_field!(result.vote_last_valid, u64);
            next_field!(result.vote_key_dilution, u64);
            next_field!(result.state_proof_id, bytes64);
            // UpdateRound:
            next_field!(result.update_round, u64);
            _ = idx;
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
///
/// Array order (from Go struct declaration):
///   Total, Decimals, DefaultFrozen, UnitName, AssetName, URL, MetadataHash,
///   Manager, Reserve, Freeze, Clawback, Amount, Frozen,
///   SchemaNumUint, SchemaNumByteSlice, KeyValue,
///   ApprovalProgram, ClearStateProgram, GlobalState,
///   LocalStateSchemaNumUint, LocalStateSchemaNumByteSlice,
///   GlobalStateSchemaNumUint, GlobalStateSchemaNumByteSlice,
///   ExtraProgramPages, ResourceFlags, UpdateRound, Version, SizeSponsor,
///   ForeignBoxReads, FamilyBoxAccess
pub fn decode_resources_data(raw: &[u8]) -> Result<CatchpointResourcesData, CatchpointError> {
    if raw.is_empty() {
        return Ok(CatchpointResourcesData::default());
    }

    let mut rd: &[u8] = raw;
    let mut result = CatchpointResourcesData::default();

    match try_read_map_header(&mut rd)? {
        Some(n) => {
            for _ in 0..n {
                let key = read_map_key(&mut rd)?;
                match key.as_str() {
                    "a" => result.total = read_u64(&mut rd)?,
                    "b" => result.decimals = read_u64(&mut rd)? as u32,
                    "c" => result.default_frozen = read_bool(&mut rd)?,
                    "d" => result.unit_name = read_string(&mut rd)?,
                    "e" => result.asset_name = read_string(&mut rd)?,
                    "f" => result.url = read_string(&mut rd)?,
                    "g" => result.metadata_hash = read_bytes_fixed::<32>(&mut rd)?,
                    "h" => result.manager = read_bytes_fixed::<32>(&mut rd)?,
                    "i" => result.reserve = read_bytes_fixed::<32>(&mut rd)?,
                    "j" => result.freeze = read_bytes_fixed::<32>(&mut rd)?,
                    "k" => result.clawback = read_bytes_fixed::<32>(&mut rd)?,
                    "l" => result.amount = read_u64(&mut rd)?,
                    "m" => result.frozen = read_bool(&mut rd)?,
                    "n" => result.schema_num_uint = read_u64(&mut rd)?,
                    "o" => result.schema_num_byte_slice = read_u64(&mut rd)?,
                    "p" => result.key_value = read_raw_value(&mut rd)?,
                    "q" => result.approval_program = read_bytes_vec(&mut rd)?,
                    "r" => result.clear_state_program = read_bytes_vec(&mut rd)?,
                    "s" => result.global_state = read_raw_value(&mut rd)?,
                    "t" => result.local_state_schema_num_uint = read_u64(&mut rd)?,
                    "u" => result.local_state_schema_num_byte_slice = read_u64(&mut rd)?,
                    "v" => result.global_state_schema_num_uint = read_u64(&mut rd)?,
                    "w" => result.global_state_schema_num_byte_slice = read_u64(&mut rd)?,
                    "x" => result.extra_program_pages = read_u64(&mut rd)? as u32,
                    "y" => result.resource_flags = read_u64(&mut rd)? as u8,
                    "z" => result.update_round = read_u64(&mut rd)?,
                    "A" => result.version = read_u64(&mut rd)?,
                    "B" => result.size_sponsor = read_bytes_fixed::<32>(&mut rd)?,
                    "C" => result.foreign_box_reads = read_bool(&mut rd)?,
                    "D" => result.family_box_access = read_bool(&mut rd)?,
                    _ => skip_value(&mut rd)?,
                }
            }
        }
        None => {
            let len = read_array_header(&mut rd)?;
            let mut idx = 0u32;

            macro_rules! next_field {
                ($field:expr, u64) => {
                    if idx < len {
                        idx += 1;
                        $field = read_u64(&mut rd)?;
                    }
                };
                ($field:expr, u32) => {
                    if idx < len {
                        idx += 1;
                        $field = read_u64(&mut rd)? as u32;
                    }
                };
                ($field:expr, u8) => {
                    if idx < len {
                        idx += 1;
                        $field = read_u64(&mut rd)? as u8;
                    }
                };
                ($field:expr, bool) => {
                    if idx < len {
                        idx += 1;
                        $field = read_bool(&mut rd)?;
                    }
                };
                ($field:expr, string) => {
                    if idx < len {
                        idx += 1;
                        $field = read_string(&mut rd)?;
                    }
                };
                ($field:expr, bytes32) => {
                    if idx < len {
                        idx += 1;
                        $field = read_bytes_fixed::<32>(&mut rd)?;
                    }
                };
                ($field:expr, bytes_vec) => {
                    if idx < len {
                        idx += 1;
                        $field = read_bytes_vec(&mut rd)?;
                    }
                };
                ($field:expr, raw_value) => {
                    if idx < len {
                        idx += 1;
                        $field = read_raw_value(&mut rd)?;
                    }
                };
            }

            // Go struct declaration order:
            next_field!(result.total, u64);
            next_field!(result.decimals, u32);
            next_field!(result.default_frozen, bool);
            next_field!(result.unit_name, string);
            next_field!(result.asset_name, string);
            next_field!(result.url, string);
            next_field!(result.metadata_hash, bytes32);
            next_field!(result.manager, bytes32);
            next_field!(result.reserve, bytes32);
            next_field!(result.freeze, bytes32);
            next_field!(result.clawback, bytes32);
            next_field!(result.amount, u64);
            next_field!(result.frozen, bool);
            next_field!(result.schema_num_uint, u64);
            next_field!(result.schema_num_byte_slice, u64);
            next_field!(result.key_value, raw_value);
            next_field!(result.approval_program, bytes_vec);
            next_field!(result.clear_state_program, bytes_vec);
            next_field!(result.global_state, raw_value);
            next_field!(result.local_state_schema_num_uint, u64);
            next_field!(result.local_state_schema_num_byte_slice, u64);
            next_field!(result.global_state_schema_num_uint, u64);
            next_field!(result.global_state_schema_num_byte_slice, u64);
            next_field!(result.extra_program_pages, u32);
            next_field!(result.resource_flags, u8);
            next_field!(result.update_round, u64);
            next_field!(result.version, u64);
            next_field!(result.size_sponsor, bytes32);
            next_field!(result.foreign_box_reads, bool);
            next_field!(result.family_box_access, bool);
            _ = idx;
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
///
/// Array order (from Go struct declaration, embedded BaseVotingData first):
///   VoteID, SelectionID, VoteFirstValid, VoteLastValid, VoteKeyDilution,
///   StateProofID, LastProposed, LastHeartbeat, IncentiveEligible,
///   MicroAlgos, RewardsBase
pub fn decode_base_online_account_data(
    raw: &[u8],
) -> Result<CatchpointBaseOnlineAccountData, CatchpointError> {
    if raw.is_empty() {
        return Ok(CatchpointBaseOnlineAccountData::default());
    }

    let mut rd: &[u8] = raw;
    let mut result = CatchpointBaseOnlineAccountData::default();

    match try_read_map_header(&mut rd)? {
        Some(n) => {
            for _ in 0..n {
                let key = read_map_key(&mut rd)?;
                match key.as_str() {
                    "A" => result.vote_id = read_bytes_fixed::<32>(&mut rd)?,
                    "B" => result.selection_id = read_bytes_fixed::<32>(&mut rd)?,
                    "C" => result.vote_first_valid = read_u64(&mut rd)?,
                    "D" => result.vote_last_valid = read_u64(&mut rd)?,
                    "E" => result.vote_key_dilution = read_u64(&mut rd)?,
                    "F" => result.state_proof_id = read_bytes_fixed::<64>(&mut rd)?,
                    "V" => result.last_proposed = read_u64(&mut rd)?,
                    "W" => result.last_heartbeat = read_u64(&mut rd)?,
                    "X" => result.incentive_eligible = read_bool(&mut rd)?,
                    "Y" => result.micro_algos = read_u64(&mut rd)?,
                    "Z" => result.rewards_base = read_u64(&mut rd)?,
                    _ => skip_value(&mut rd)?,
                }
            }
        }
        None => {
            let len = read_array_header(&mut rd)?;
            let mut idx = 0u32;

            macro_rules! next_field {
                ($field:expr, u64) => {
                    if idx < len {
                        idx += 1;
                        $field = read_u64(&mut rd)?;
                    }
                };
                ($field:expr, bool) => {
                    if idx < len {
                        idx += 1;
                        $field = read_bool(&mut rd)?;
                    }
                };
                ($field:expr, bytes32) => {
                    if idx < len {
                        idx += 1;
                        $field = read_bytes_fixed::<32>(&mut rd)?;
                    }
                };
                ($field:expr, bytes64) => {
                    if idx < len {
                        idx += 1;
                        $field = read_bytes_fixed::<64>(&mut rd)?;
                    }
                };
            }

            // Embedded BaseVotingData first, then own fields:
            next_field!(result.vote_id, bytes32);
            next_field!(result.selection_id, bytes32);
            next_field!(result.vote_first_valid, u64);
            next_field!(result.vote_last_valid, u64);
            next_field!(result.vote_key_dilution, u64);
            next_field!(result.state_proof_id, bytes64);
            next_field!(result.last_proposed, u64);
            next_field!(result.last_heartbeat, u64);
            next_field!(result.incentive_eligible, bool);
            next_field!(result.micro_algos, u64);
            next_field!(result.rewards_base, u64);
            _ = idx;
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
///
/// Array order (from Go struct declaration):
///   OnlineSupply, RewardsLevel, CurrentProtocol
pub fn decode_online_round_params_data(
    raw: &[u8],
) -> Result<CatchpointOnlineRoundParamsData, CatchpointError> {
    if raw.is_empty() {
        return Ok(CatchpointOnlineRoundParamsData::default());
    }

    let mut rd: &[u8] = raw;
    let mut result = CatchpointOnlineRoundParamsData::default();

    match try_read_map_header(&mut rd)? {
        Some(n) => {
            for _ in 0..n {
                let key = read_map_key(&mut rd)?;
                match key.as_str() {
                    "online" => result.online_supply = read_u64(&mut rd)?,
                    "rwdlvl" => result.rewards_level = read_u64(&mut rd)?,
                    "proto" => result.current_protocol = read_string(&mut rd)?,
                    _ => skip_value(&mut rd)?,
                }
            }
        }
        None => {
            let len = read_array_header(&mut rd)?;
            let mut idx = 0u32;

            if idx < len {
                idx += 1;
                result.online_supply = read_u64(&mut rd)?;
            }
            if idx < len {
                idx += 1;
                result.rewards_level = read_u64(&mut rd)?;
            }
            if idx < len {
                let _ = idx;
                result.current_protocol = read_string(&mut rd)?;
            }
        }
    }

    Ok(result)
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

    // Helper: build a msgpack array manually.
    fn encode_array(values: &[rmpv::Value]) -> Vec<u8> {
        let val = rmpv::Value::Array(values.to_vec());
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
    fn decode_base_account_data_unknown_keys_ignored() {
        let raw = encode_map(&[
            ("b", rmpv::Value::from(42u64)),
            ("zzz_future", rmpv::Value::from(999u64)),
        ]);
        let result = decode_base_account_data(&raw).unwrap();
        assert_eq!(result.micro_algos, 42);
    }

    #[test]
    fn decode_base_account_data_array_format() {
        // Positional array with all 24 fields
        let values: Vec<rmpv::Value> = vec![
            rmpv::Value::from(2u64),               // status
            rmpv::Value::from(3_000_000u64),       // micro_algos
            rmpv::Value::from(50u64),              // rewards_base
            rmpv::Value::from(25u64),              // rewarded_micro_algos
            rmpv::Value::Binary(vec![0xBBu8; 32]), // auth_addr
            rmpv::Value::from(1u64),               // total_app_schema_num_uint
            rmpv::Value::from(2u64),               // total_app_schema_num_byte_slice
            rmpv::Value::from(1u64),               // total_extra_app_pages
            rmpv::Value::from(3u64),               // total_asset_params
            rmpv::Value::from(5u64),               // total_assets
            rmpv::Value::from(2u64),               // total_app_params
            rmpv::Value::from(4u64),               // total_app_local_states
            rmpv::Value::from(1u64),               // total_boxes
            rmpv::Value::from(256u64),             // total_box_bytes
            rmpv::Value::Boolean(true),            // incentive_eligible
            rmpv::Value::from(800u64),             // last_proposed
            rmpv::Value::from(799u64),             // last_heartbeat
            rmpv::Value::Binary(vec![0x44u8; 32]), // vote_id
            rmpv::Value::Binary(vec![0x55u8; 32]), // selection_id
            rmpv::Value::from(10u64),              // vote_first_valid
            rmpv::Value::from(20u64),              // vote_last_valid
            rmpv::Value::from(100u64),             // vote_key_dilution
            rmpv::Value::Binary(vec![0x66u8; 64]), // state_proof_id
            rmpv::Value::from(77u64),              // update_round
        ];
        let raw = encode_array(&values);
        let result = decode_base_account_data(&raw).unwrap();

        assert_eq!(result.status, 2);
        assert_eq!(result.micro_algos, 3_000_000);
        assert_eq!(result.rewards_base, 50);
        assert_eq!(result.rewarded_micro_algos, 25);
        assert_eq!(result.auth_addr, [0xBBu8; 32]);
        assert_eq!(result.total_app_schema_num_uint, 1);
        assert_eq!(result.total_app_schema_num_byte_slice, 2);
        assert_eq!(result.total_extra_app_pages, 1);
        assert_eq!(result.total_asset_params, 3);
        assert_eq!(result.total_assets, 5);
        assert_eq!(result.total_app_params, 2);
        assert_eq!(result.total_app_local_states, 4);
        assert_eq!(result.total_boxes, 1);
        assert_eq!(result.total_box_bytes, 256);
        assert!(result.incentive_eligible);
        assert_eq!(result.last_proposed, 800);
        assert_eq!(result.last_heartbeat, 799);
        assert_eq!(result.vote_id, [0x44u8; 32]);
        assert_eq!(result.selection_id, [0x55u8; 32]);
        assert_eq!(result.vote_first_valid, 10);
        assert_eq!(result.vote_last_valid, 20);
        assert_eq!(result.vote_key_dilution, 100);
        assert_eq!(result.state_proof_id, [0x66u8; 64]);
        assert_eq!(result.update_round, 77);
    }

    #[test]
    fn decode_base_account_data_short_array() {
        // Array with only 3 fields -- remaining should be defaults
        let values: Vec<rmpv::Value> = vec![
            rmpv::Value::from(1u64),   // status
            rmpv::Value::from(999u64), // micro_algos
            rmpv::Value::from(10u64),  // rewards_base
        ];
        let raw = encode_array(&values);
        let result = decode_base_account_data(&raw).unwrap();

        assert_eq!(result.status, 1);
        assert_eq!(result.micro_algos, 999);
        assert_eq!(result.rewards_base, 10);
        assert_eq!(result.rewarded_micro_algos, 0);
        assert_eq!(result.auth_addr, [0u8; 32]);
        assert_eq!(result.update_round, 0);
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
        assert_eq!(result.unit_name, "ALGO");
        assert_eq!(result.asset_name, "Algorand");
        assert_eq!(result.url, "https://algo.org");
        assert_eq!(result.manager, manager);
        assert_eq!(result.resource_flags, 2);
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
        // Key-value is stored as raw msgpack. Use an empty map as test data.
        let kv_raw = encode_map(&[]);
        let raw = encode_map(&[
            ("n", rmpv::Value::from(1u64)),  // schema_num_uint
            ("p", rmpv::Value::Map(vec![])), // key_value (empty map)
        ]);
        let result = decode_resources_data(&raw).unwrap();
        assert_eq!(result.schema_num_uint, 1);
        // The key_value should be the raw msgpack encoding of the empty map
        assert_eq!(result.key_value, kv_raw);
    }

    #[test]
    fn decode_resources_data_array_format() {
        let values: Vec<rmpv::Value> = vec![
            rmpv::Value::from(1_000_000u64),                // total
            rmpv::Value::from(6u64),                        // decimals
            rmpv::Value::Boolean(false),                    // default_frozen
            rmpv::Value::String("TST".into()),              // unit_name
            rmpv::Value::String("Test".into()),             // asset_name
            rmpv::Value::String("https://test.com".into()), // url
            rmpv::Value::Binary(vec![0u8; 32]),             // metadata_hash
            rmpv::Value::Binary(vec![0u8; 32]),             // manager
            rmpv::Value::Binary(vec![0u8; 32]),             // reserve
            rmpv::Value::Binary(vec![0u8; 32]),             // freeze
            rmpv::Value::Binary(vec![0u8; 32]),             // clawback
            rmpv::Value::from(500u64),                      // amount
            rmpv::Value::Boolean(true),                     // frozen
            rmpv::Value::from(0u64),                        // schema_num_uint
            rmpv::Value::from(0u64),                        // schema_num_byte_slice
            rmpv::Value::Nil,                               // key_value (nil)
            rmpv::Value::Nil,                               // approval_program (nil)
            rmpv::Value::Nil,                               // clear_state_program (nil)
            rmpv::Value::Nil,                               // global_state (nil)
            rmpv::Value::from(0u64),                        // local_state_schema_num_uint
            rmpv::Value::from(0u64),                        // local_state_schema_num_byte_slice
            rmpv::Value::from(0u64),                        // global_state_schema_num_uint
            rmpv::Value::from(0u64),                        // global_state_schema_num_byte_slice
            rmpv::Value::from(0u64),                        // extra_program_pages
            rmpv::Value::from(0u64),                        // resource_flags
            rmpv::Value::from(42u64),                       // update_round
            rmpv::Value::from(0u64),                        // version
            rmpv::Value::Binary(vec![0u8; 32]),             // size_sponsor
        ];
        let raw = encode_array(&values);
        let result = decode_resources_data(&raw).unwrap();

        assert_eq!(result.total, 1_000_000);
        assert_eq!(result.decimals, 6);
        assert!(!result.default_frozen);
        assert_eq!(result.unit_name, "TST");
        assert_eq!(result.asset_name, "Test");
        assert_eq!(result.url, "https://test.com");
        assert_eq!(result.amount, 500);
        assert!(result.frozen);
        assert_eq!(result.update_round, 42);
    }

    #[test]
    fn decode_resources_data_unknown_keys_ignored() {
        let raw = encode_map(&[
            ("a", rmpv::Value::from(100u64)),
            ("ZZZ", rmpv::Value::from(999u64)),
        ]);
        let result = decode_resources_data(&raw).unwrap();
        assert_eq!(result.total, 100);
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
    fn decode_base_online_account_data_array_format() {
        let values: Vec<rmpv::Value> = vec![
            rmpv::Value::Binary(vec![0x11u8; 32]), // vote_id
            rmpv::Value::Binary(vec![0x22u8; 32]), // selection_id
            rmpv::Value::from(10u64),              // vote_first_valid
            rmpv::Value::from(20u64),              // vote_last_valid
            rmpv::Value::from(100u64),             // vote_key_dilution
            rmpv::Value::Binary(vec![0x33u8; 64]), // state_proof_id
            rmpv::Value::from(5u64),               // last_proposed
            rmpv::Value::from(4u64),               // last_heartbeat
            rmpv::Value::Boolean(false),           // incentive_eligible
            rmpv::Value::from(1_000u64),           // micro_algos
            rmpv::Value::from(50u64),              // rewards_base
        ];
        let raw = encode_array(&values);
        let result = decode_base_online_account_data(&raw).unwrap();

        assert_eq!(result.vote_id, [0x11u8; 32]);
        assert_eq!(result.selection_id, [0x22u8; 32]);
        assert_eq!(result.vote_first_valid, 10);
        assert_eq!(result.vote_last_valid, 20);
        assert_eq!(result.vote_key_dilution, 100);
        assert_eq!(result.state_proof_id, [0x33u8; 64]);
        assert_eq!(result.last_proposed, 5);
        assert_eq!(result.last_heartbeat, 4);
        assert!(!result.incentive_eligible);
        assert_eq!(result.micro_algos, 1_000);
        assert_eq!(result.rewards_base, 50);
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
    fn decode_online_round_params_data_array_format() {
        let values: Vec<rmpv::Value> = vec![
            rmpv::Value::from(5_000_000u64),   // online_supply
            rmpv::Value::from(999u64),         // rewards_level
            rmpv::Value::String("v41".into()), // current_protocol
        ];
        let raw = encode_array(&values);
        let result = decode_online_round_params_data(&raw).unwrap();

        assert_eq!(result.online_supply, 5_000_000);
        assert_eq!(result.rewards_level, 999);
        assert_eq!(result.current_protocol, "v41");
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
        let mut data = vec![0xc4, 16]; // bin8 with 16 bytes
        data.extend_from_slice(&[0xBB; 16]);
        let mut rd: &[u8] = &data;
        let result = read_bytes_fixed::<32>(&mut rd);
        assert!(result.is_err());
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
}
