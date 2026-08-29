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

//! Block fetch primitives for WebSocket unicast catchup.
//!
//! This module implements the client-side protocol for requesting blocks
//! from peers over the Algorand WebSocket block service. It constructs
//! request [`Topics`] and parses response [`Topics`] according to the
//! protocol defined in `go-algorand/rpcs/blockService.go` and
//! `go-algorand/catchup/universalFetcher.go`.
//!
//! ## Protocol summary
//!
//! **Request** (tag `UE` / `UniEnsBlockReq`):
//! - `requestDataType` → `"blockAndCert"` (ASCII)
//! - `roundKey` → uvarint-encoded round number
//!
//! **Response** (tag `TS` / `TopicMsgResp`):
//! - On success: `blockData` → raw msgpack block bytes,
//!   `certData` → raw msgpack cert bytes
//! - On error: `Error` → UTF-8 error message,
//!   optionally `latest` → big-endian u64 of the latest available round

use crate::topics::{
    Topic, Topics, BLOCK_AND_CERT_VALUE, BLOCK_DATA_KEY, CERT_DATA_KEY, ERROR_KEY,
    LATEST_ROUND_KEY, REQUEST_DATA_TYPE_KEY, ROUND_KEY,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned when parsing a block-service response.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlockFetchError {
    /// The peer returned an error topic, with an optional latest-round hint.
    #[error("block service error: {message}")]
    ServiceError {
        /// The error message from the peer.
        message: String,
        /// The peer's latest available round (if provided).
        latest_round: Option<u64>,
    },

    /// The response is missing the required `blockData` topic.
    #[error("response missing blockData topic")]
    MissingBlockData,

    /// The response is missing the required `certData` topic.
    #[error("response missing certData topic")]
    MissingCertData,

    /// The `latest` round value could not be decoded (not 8 bytes big-endian).
    #[error("invalid latest round encoding: expected 8 bytes, got {0}")]
    InvalidLatestRound(usize),
}

// ---------------------------------------------------------------------------
// Base-36 round encoding (for HTTP block paths)
// ---------------------------------------------------------------------------

/// Encode a round number in base-36, matching Go's
/// `strconv.FormatUint(round, 36)`.
///
/// This is used when constructing HTTP block-fetch URLs (e.g.
/// `/v1/{genesisID}/block/{round_base36}`). WebSocket topic requests use
/// uvarint encoding instead — see [`make_block_request_topics`].
pub fn format_round_base36(round: u64) -> String {
    if round == 0 {
        return "0".to_string();
    }

    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut buf = Vec::with_capacity(14); // u64::MAX in base-36 is 13 chars
    let mut n = round;
    while n > 0 {
        buf.push(DIGITS[(n % 36) as usize]);
        n /= 36;
    }
    buf.reverse();
    // All bytes are ASCII digits/lowercase letters, so this cannot fail.
    String::from_utf8(buf).expect("base36 digits are valid UTF-8")
}

// ---------------------------------------------------------------------------
// Uvarint encoding helper (LEB128, same as Go binary.PutUvarint)
// ---------------------------------------------------------------------------

/// Encode a `u64` as unsigned LEB128 (uvarint).
fn encode_uvarint(mut value: u64) -> Vec<u8> {
    // Maximum 10 bytes for u64
    let mut buf = Vec::with_capacity(10);
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
    buf
}

/// Decode an unsigned LEB128 (uvarint) from `buf`.
/// Returns `(value, bytes_consumed)` or `None` on malformed input.
fn decode_uvarint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 63 && byte > 1 {
            return None; // overflow
        }
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None
}

// ---------------------------------------------------------------------------
// Request construction
// ---------------------------------------------------------------------------

/// Construct a [`Topics`] request for fetching block+cert at the given round.
///
/// Matches Go's `makeBlockRequestTopics()` from `universalFetcher.go`:
/// - `requestDataType` → `"blockAndCert"`
/// - `roundKey` → round encoded as uvarint bytes
///
/// The caller should send this as the payload of a `UniEnsBlockReq` (`UE`)
/// tagged message.
pub fn make_block_request_topics(round: u64) -> Topics {
    let round_bytes = encode_uvarint(round);
    Topics::from_vec(vec![
        Topic::new(REQUEST_DATA_TYPE_KEY, BLOCK_AND_CERT_VALUE.as_bytes()),
        Topic::new(ROUND_KEY, round_bytes),
    ])
}

// ---------------------------------------------------------------------------
// Response data
// ---------------------------------------------------------------------------

/// Parsed block-service response data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockResponseData {
    /// Raw msgpack-encoded block bytes.
    pub block_data: Vec<u8>,
    /// Raw msgpack-encoded certificate bytes.
    pub cert_data: Vec<u8>,
    /// The peer's latest available round (only present in some error paths,
    /// but also extractable from success responses if the server includes it).
    pub latest_round: Option<u64>,
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

/// Parse a block-service response from [`Topics`].
///
/// Follows the same logic as Go's `wsFetcherClient.requestBlock()`:
/// 1. If `Error` key is present → return [`BlockFetchError::ServiceError`]
///    (with optional `latest` round).
/// 2. Extract `blockData` → error if missing.
/// 3. Extract `certData` → error if missing.
/// 4. Optionally extract `latest` round.
pub fn parse_block_response(topics: &Topics) -> Result<BlockResponseData, BlockFetchError> {
    // Check for error response first
    if let Some(err_bytes) = topics.get_value(ERROR_KEY) {
        let message = String::from_utf8_lossy(err_bytes).into_owned();
        let latest_round = parse_latest_round(topics)?;
        return Err(BlockFetchError::ServiceError {
            message,
            latest_round,
        });
    }

    // Extract block data
    let block_data = topics
        .get_value(BLOCK_DATA_KEY)
        .ok_or(BlockFetchError::MissingBlockData)?
        .to_vec();

    // Extract cert data
    let cert_data = topics
        .get_value(CERT_DATA_KEY)
        .ok_or(BlockFetchError::MissingCertData)?
        .to_vec();

    // Optionally extract latest round (non-error path; rarely present but harmless)
    let latest_round = parse_latest_round(topics).ok().flatten();

    Ok(BlockResponseData {
        block_data,
        cert_data,
        latest_round,
    })
}

/// Parse the `latest` round from response topics if present.
///
/// Go encodes it as `binary.BigEndian.AppendUint64([]byte{}, uint64(latest))`
/// — an 8-byte big-endian value.
fn parse_latest_round(topics: &Topics) -> Result<Option<u64>, BlockFetchError> {
    match topics.get_value(LATEST_ROUND_KEY) {
        None => Ok(None),
        Some(bytes) => {
            if bytes.len() != 8 {
                return Err(BlockFetchError::InvalidLatestRound(bytes.len()));
            }
            let arr: [u8; 8] = bytes.try_into().expect("checked length");
            Ok(Some(u64::from_be_bytes(arr)))
        }
    }
}

/// Decode a uvarint-encoded round number from bytes (e.g. from a received
/// `roundKey` topic value). Returns `None` if decoding fails.
pub fn decode_round_from_uvarint(bytes: &[u8]) -> Option<u64> {
    decode_uvarint(bytes).map(|(val, _)| val)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Base-36 encoding --

    #[test]
    fn base36_zero() {
        assert_eq!(format_round_base36(0), "0");
    }

    #[test]
    fn base36_single_digit() {
        assert_eq!(format_round_base36(1), "1");
        assert_eq!(format_round_base36(9), "9");
        assert_eq!(format_round_base36(10), "a");
        assert_eq!(format_round_base36(35), "z");
    }

    #[test]
    fn base36_boundary() {
        // 36 = "10" in base 36
        assert_eq!(format_round_base36(36), "10");
        // 37 = "11" in base 36
        assert_eq!(format_round_base36(37), "11");
    }

    #[test]
    fn base36_1000() {
        // Go: strconv.FormatUint(1000, 36) == "rs"
        // 1000 = 27*36 + 28 -> "rs"
        assert_eq!(format_round_base36(1000), "rs");
    }

    #[test]
    fn base36_large_round() {
        // Go: strconv.FormatUint(1_000_000, 36) == "lfls"
        assert_eq!(format_round_base36(1_000_000), "lfls");
    }

    #[test]
    fn base36_max_u64() {
        // Go: strconv.FormatUint(18446744073709551615, 36) == "3w5e11264sgsf"
        assert_eq!(format_round_base36(u64::MAX), "3w5e11264sgsf");
    }

    // -- Uvarint encoding --

    #[test]
    fn uvarint_round_trip() {
        let values = [0, 1, 127, 128, 255, 256, 16383, 16384, 1_000_000, u64::MAX];
        for &v in &values {
            let encoded = encode_uvarint(v);
            let (decoded, consumed) = decode_uvarint(&encoded).unwrap();
            assert_eq!(decoded, v, "round-trip failed for {v}");
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn uvarint_zero_is_single_byte() {
        let encoded = encode_uvarint(0);
        assert_eq!(encoded, vec![0x00]);
    }

    #[test]
    fn uvarint_128_is_two_bytes() {
        let encoded = encode_uvarint(128);
        assert_eq!(encoded, vec![0x80, 0x01]);
    }

    // -- Topics construction --

    #[test]
    fn make_request_topics_has_correct_keys() {
        let topics = make_block_request_topics(42);
        assert_eq!(topics.0.len(), 2);

        // Check requestDataType
        let rdt = topics.get_value(REQUEST_DATA_TYPE_KEY).unwrap();
        assert_eq!(rdt, b"blockAndCert");

        // Check roundKey (42 uvarint = single byte 0x2A)
        let rk = topics.get_value(ROUND_KEY).unwrap();
        assert_eq!(rk, &[42u8]);
    }

    #[test]
    fn make_request_topics_round_zero() {
        let topics = make_block_request_topics(0);
        let rk = topics.get_value(ROUND_KEY).unwrap();
        assert_eq!(rk, &[0u8]);
    }

    #[test]
    fn make_request_topics_large_round() {
        let round = 1_000_000u64;
        let topics = make_block_request_topics(round);
        let rk = topics.get_value(ROUND_KEY).unwrap();
        let decoded = decode_round_from_uvarint(rk).unwrap();
        assert_eq!(decoded, round);
    }

    #[test]
    fn request_topics_marshal_unmarshal_round_trip() {
        let topics = make_block_request_topics(100);
        let bytes = topics.marshal();
        let decoded = Topics::unmarshal(&bytes).unwrap();
        assert_eq!(decoded, topics);
    }

    // -- Response parsing: success --

    #[test]
    fn parse_success_response() {
        let block = b"block-bytes-here";
        let cert = b"cert-bytes-here";
        let topics = Topics::from_vec(vec![
            Topic::new(BLOCK_DATA_KEY, block.to_vec()),
            Topic::new(CERT_DATA_KEY, cert.to_vec()),
        ]);
        let result = parse_block_response(&topics).unwrap();
        assert_eq!(result.block_data, block.to_vec());
        assert_eq!(result.cert_data, cert.to_vec());
        assert_eq!(result.latest_round, None);
    }

    #[test]
    fn parse_success_response_with_latest_round() {
        let block = b"blk";
        let cert = b"crt";
        let latest: u64 = 12345;
        let topics = Topics::from_vec(vec![
            Topic::new(BLOCK_DATA_KEY, block.to_vec()),
            Topic::new(CERT_DATA_KEY, cert.to_vec()),
            Topic::new(LATEST_ROUND_KEY, latest.to_be_bytes().to_vec()),
        ]);
        let result = parse_block_response(&topics).unwrap();
        assert_eq!(result.block_data, block.to_vec());
        assert_eq!(result.cert_data, cert.to_vec());
        assert_eq!(result.latest_round, Some(12345));
    }

    // -- Response parsing: errors --

    #[test]
    fn parse_error_response_without_latest() {
        let topics = Topics::from_vec(vec![Topic::new(
            ERROR_KEY,
            b"requested block is not available".to_vec(),
        )]);
        let err = parse_block_response(&topics).unwrap_err();
        match err {
            BlockFetchError::ServiceError {
                message,
                latest_round,
            } => {
                assert_eq!(message, "requested block is not available");
                assert_eq!(latest_round, None);
            }
            other => panic!("expected ServiceError, got {other:?}"),
        }
    }

    #[test]
    fn parse_error_response_with_latest() {
        let latest: u64 = 999;
        let topics = Topics::from_vec(vec![
            Topic::new(ERROR_KEY, b"requested block is not available".to_vec()),
            Topic::new(LATEST_ROUND_KEY, latest.to_be_bytes().to_vec()),
        ]);
        let err = parse_block_response(&topics).unwrap_err();
        match err {
            BlockFetchError::ServiceError {
                message,
                latest_round,
            } => {
                assert_eq!(message, "requested block is not available");
                assert_eq!(latest_round, Some(999));
            }
            other => panic!("expected ServiceError, got {other:?}"),
        }
    }

    #[test]
    fn parse_error_response_with_invalid_latest_round() {
        // latest round must be exactly 8 bytes
        let topics = Topics::from_vec(vec![
            Topic::new(ERROR_KEY, b"some error".to_vec()),
            Topic::new(LATEST_ROUND_KEY, vec![0x01, 0x02, 0x03]), // only 3 bytes
        ]);
        let err = parse_block_response(&topics).unwrap_err();
        assert!(matches!(err, BlockFetchError::InvalidLatestRound(3)));
    }

    #[test]
    fn parse_missing_block_data() {
        let topics = Topics::from_vec(vec![Topic::new(CERT_DATA_KEY, b"cert-only".to_vec())]);
        let err = parse_block_response(&topics).unwrap_err();
        assert!(matches!(err, BlockFetchError::MissingBlockData));
    }

    #[test]
    fn parse_missing_cert_data() {
        let topics = Topics::from_vec(vec![Topic::new(BLOCK_DATA_KEY, b"block-only".to_vec())]);
        let err = parse_block_response(&topics).unwrap_err();
        assert!(matches!(err, BlockFetchError::MissingCertData));
    }

    #[test]
    fn parse_empty_topics() {
        let topics = Topics::new();
        let err = parse_block_response(&topics).unwrap_err();
        assert!(matches!(err, BlockFetchError::MissingBlockData));
    }

    // -- decode_round_from_uvarint --

    #[test]
    fn decode_round_uvarint_valid() {
        let cases: Vec<u64> = vec![0, 1, 42, 127, 128, 1_000_000, u64::MAX];
        for &round in &cases {
            let bytes = encode_uvarint(round);
            assert_eq!(decode_round_from_uvarint(&bytes), Some(round));
        }
    }

    #[test]
    fn decode_round_uvarint_empty() {
        assert_eq!(decode_round_from_uvarint(&[]), None);
    }

    // -- Cross-validation: topic key constants match Go --

    #[test]
    fn topic_keys_match_go_constants() {
        // From go-algorand/rpcs/blockService.go
        assert_eq!(ROUND_KEY, "roundKey");
        assert_eq!(REQUEST_DATA_TYPE_KEY, "requestDataType");
        assert_eq!(BLOCK_DATA_KEY, "blockData");
        assert_eq!(CERT_DATA_KEY, "certData");
        assert_eq!(BLOCK_AND_CERT_VALUE, "blockAndCert");
        assert_eq!(LATEST_ROUND_KEY, "latest");
        assert_eq!(ERROR_KEY, "Error");
    }
}
