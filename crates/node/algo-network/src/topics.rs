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

//! Topics encoding for Algorand network protocol.
//!
//! Topics use a custom binary format (NOT msgpack):
//! `uvarint(num_topics)` followed by for each topic:
//! `uvarint(key_len) + key_bytes + uvarint(data_len) + data_bytes`
//!
//! Reference: go-algorand/network/topics.go

use std::fmt;

use crate::tag::MAX_MESSAGE_LENGTH;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of topics allowed in a single Topics collection.
const MAX_TOPICS: u64 = 32;

/// Maximum key length in bytes.
const MAX_KEY_LENGTH: u64 = 64;

// Well-known topic keys (from go-algorand rpcs/blockService.go and network/topics.go)

/// Block round-number topic key in requests.
pub const ROUND_KEY: &str = "roundKey";

/// Data-type topic key in requests (e.g. block, cert, block+cert).
pub const REQUEST_DATA_TYPE_KEY: &str = "requestDataType";

/// Block data topic key in responses.
pub const BLOCK_DATA_KEY: &str = "blockData";

/// Cert data topic key in responses.
pub const CERT_DATA_KEY: &str = "certData";

/// Block-and-cert request data value (value of REQUEST_DATA_TYPE_KEY).
pub const BLOCK_AND_CERT_VALUE: &str = "blockAndCert";

/// "latest" round sentinel.
pub const LATEST_ROUND_KEY: &str = "latest";

/// Request hash topic key.
pub const REQUEST_HASH_KEY: &str = "RequestHash";

/// Error topic key.
pub const ERROR_KEY: &str = "Error";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors arising from Topics encoding / decoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TopicsError {
    #[error("could not read the number of topics")]
    MissingTopicCount,

    #[error("number of topics {0} exceeds maximum of {MAX_TOPICS}")]
    TooManyTopics(u64),

    #[error("could not read the key length")]
    MissingKeyLength,

    #[error("invalid key: length {0} (must be 1..={MAX_KEY_LENGTH} and fit in buffer)")]
    InvalidKey(u64),

    #[error("could not read the data length")]
    MissingDataLength,

    #[error("data length {0} exceeds maximum message length")]
    DataTooLarge(u64),

    #[error("topic key is not valid UTF-8")]
    InvalidKeyEncoding,

    #[error("data larger than remaining buffer")]
    BufferUnderflow,
}

// ---------------------------------------------------------------------------
// uvarint helpers (unsigned LEB128, same encoding as Go binary.PutUvarint)
// ---------------------------------------------------------------------------

/// Encode a `u64` as an unsigned variable-length integer (LEB128) and append
/// to `buf`. Returns the number of bytes written.
fn put_uvarint(buf: &mut Vec<u8>, mut value: u64) -> usize {
    let start = buf.len();
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
    buf.len() - start
}

/// Decode an unsigned variable-length integer from `buf`.
/// Returns `(value, bytes_consumed)` or `None` if the buffer is malformed
/// (truncated or overflows u64).
fn read_uvarint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 63 && byte > 1 {
            // Would overflow u64
            return None;
        }
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    // Ran out of bytes before finding a terminating byte
    None
}

// ---------------------------------------------------------------------------
// Topic / Topics types
// ---------------------------------------------------------------------------

/// A single key-value topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topic {
    pub key: String,
    pub data: Vec<u8>,
}

impl Topic {
    /// Create a new topic.
    pub fn new(key: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        Self {
            key: key.into(),
            data: data.into(),
        }
    }
}

/// An ordered collection of [`Topic`] values.
///
/// Encoded with a custom binary format -- see module docs.
#[derive(Clone, PartialEq, Eq)]
pub struct Topics(pub Vec<Topic>);

impl fmt::Debug for Topics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Topics").field(&self.0).finish()
    }
}

impl Topics {
    /// Create an empty `Topics`.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Create `Topics` from a vector of topics.
    pub fn from_vec(topics: Vec<Topic>) -> Self {
        Self(topics)
    }

    /// Serialize Topics to the custom binary format.
    ///
    /// Format: `uvarint(num_topics)` then for each topic:
    /// `uvarint(key_len) key_bytes uvarint(data_len) data_bytes`
    pub fn marshal(&self) -> Vec<u8> {
        // Pre-calculate approximate buffer size
        let mut capacity = 5; // max uvarint for topic count
        for t in &self.0 {
            capacity += 5 + t.key.len() + 5 + t.data.len();
        }
        let mut buf = Vec::with_capacity(capacity);

        put_uvarint(&mut buf, self.0.len() as u64);
        for t in &self.0 {
            put_uvarint(&mut buf, t.key.len() as u64);
            buf.extend_from_slice(t.key.as_bytes());
            put_uvarint(&mut buf, t.data.len() as u64);
            buf.extend_from_slice(&t.data);
        }
        buf
    }

    /// Deserialize Topics from the custom binary format.
    pub fn unmarshal(buffer: &[u8]) -> Result<Topics, TopicsError> {
        let (num_topics, mut idx) = read_uvarint(buffer).ok_or(TopicsError::MissingTopicCount)?;

        if num_topics > MAX_TOPICS {
            return Err(TopicsError::TooManyTopics(num_topics));
        }

        let mut topics = Vec::with_capacity(num_topics as usize);

        for _ in 0..num_topics {
            // Read key length
            let (key_len, nr) =
                read_uvarint(&buffer[idx..]).ok_or(TopicsError::MissingKeyLength)?;
            idx += nr;

            // Validate key length
            if key_len == 0 || key_len > MAX_KEY_LENGTH || idx + key_len as usize > buffer.len() {
                return Err(TopicsError::InvalidKey(key_len));
            }
            let key = String::from_utf8(buffer[idx..idx + key_len as usize].to_vec())
                .map_err(|_| TopicsError::InvalidKeyEncoding)?;
            idx += key_len as usize;

            // Read data length
            let (data_len, nr) =
                read_uvarint(&buffer[idx..]).ok_or(TopicsError::MissingDataLength)?;
            idx += nr;

            if data_len > MAX_MESSAGE_LENGTH as u64 {
                return Err(TopicsError::DataTooLarge(data_len));
            }

            if idx + data_len as usize > buffer.len() {
                return Err(TopicsError::BufferUnderflow);
            }

            let data = buffer[idx..idx + data_len as usize].to_vec();
            idx += data_len as usize;

            topics.push(Topic { key, data });
        }

        Ok(Topics(topics))
    }

    /// Look up the value for a given key. Returns the first match.
    pub fn get_value(&self, key: &str) -> Option<&[u8]> {
        self.0
            .iter()
            .find(|t| t.key == key)
            .map(|t| t.data.as_slice())
    }
}

impl Default for Topics {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- uvarint helpers --

    #[test]
    fn uvarint_round_trip_small() {
        for v in 0..=300u64 {
            let mut buf = Vec::new();
            put_uvarint(&mut buf, v);
            let (decoded, len) = read_uvarint(&buf).unwrap();
            assert_eq!(decoded, v, "value {v}");
            assert_eq!(len, buf.len());
        }
    }

    #[test]
    fn uvarint_round_trip_large() {
        let values = [127, 128, 255, 256, 16383, 16384, u64::MAX / 2, u64::MAX];
        for &v in &values {
            let mut buf = Vec::new();
            put_uvarint(&mut buf, v);
            let (decoded, _) = read_uvarint(&buf).unwrap();
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn uvarint_empty_buffer() {
        assert!(read_uvarint(&[]).is_none());
    }

    #[test]
    fn uvarint_single_byte_values() {
        // 0 encodes as [0x00]
        let mut buf = Vec::new();
        put_uvarint(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);

        // 1 encodes as [0x01]
        buf.clear();
        put_uvarint(&mut buf, 1);
        assert_eq!(buf, vec![0x01]);

        // 127 encodes as [0x7F]
        buf.clear();
        put_uvarint(&mut buf, 127);
        assert_eq!(buf, vec![0x7F]);

        // 128 encodes as [0x80, 0x01]
        buf.clear();
        put_uvarint(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x01]);
    }

    // -- Topics marshal/unmarshal --

    #[test]
    fn empty_topics_round_trip() {
        let topics = Topics::new();
        let bytes = topics.marshal();
        let decoded = Topics::unmarshal(&bytes).unwrap();
        assert_eq!(decoded.0.len(), 0);
    }

    #[test]
    fn single_topic_round_trip() {
        let topics = Topics::from_vec(vec![Topic::new("hello", b"world".to_vec())]);
        let bytes = topics.marshal();
        let decoded = Topics::unmarshal(&bytes).unwrap();
        assert_eq!(decoded, topics);
    }

    #[test]
    fn multiple_topics_round_trip() {
        let topics = Topics::from_vec(vec![
            Topic::new(ROUND_KEY, b"42".to_vec()),
            Topic::new(REQUEST_DATA_TYPE_KEY, b"blockAndCert".to_vec()),
        ]);
        let bytes = topics.marshal();
        let decoded = Topics::unmarshal(&bytes).unwrap();
        assert_eq!(decoded, topics);
    }

    #[test]
    fn empty_data_topic_round_trip() {
        let topics = Topics::from_vec(vec![Topic::new("key", Vec::new())]);
        let bytes = topics.marshal();
        let decoded = Topics::unmarshal(&bytes).unwrap();
        assert_eq!(decoded.0[0].data, Vec::<u8>::new());
    }

    #[test]
    fn max_topics_round_trip() {
        let topics = Topics::from_vec(
            (0..MAX_TOPICS as usize)
                .map(|i| Topic::new(format!("k{i:02}"), vec![i as u8]))
                .collect(),
        );
        let bytes = topics.marshal();
        let decoded = Topics::unmarshal(&bytes).unwrap();
        assert_eq!(decoded.0.len(), MAX_TOPICS as usize);
    }

    #[test]
    fn too_many_topics_error() {
        let topics = Topics::from_vec(
            (0..33)
                .map(|i| Topic::new(format!("k{i:02}"), vec![i as u8]))
                .collect(),
        );
        let bytes = topics.marshal();
        let err = Topics::unmarshal(&bytes).unwrap_err();
        assert!(matches!(err, TopicsError::TooManyTopics(33)));
    }

    #[test]
    fn oversized_key_error() {
        // Manually construct a buffer with a key length of 65
        let mut buf = Vec::new();
        put_uvarint(&mut buf, 1); // 1 topic
        put_uvarint(&mut buf, 65); // key length 65 (> 64)
        buf.extend_from_slice(&[b'a'; 65]); // key bytes
        put_uvarint(&mut buf, 0); // data length 0

        let err = Topics::unmarshal(&buf).unwrap_err();
        assert!(matches!(err, TopicsError::InvalidKey(65)));
    }

    #[test]
    fn empty_key_error() {
        // Manually construct a buffer with a key length of 0
        let mut buf = Vec::new();
        put_uvarint(&mut buf, 1); // 1 topic
        put_uvarint(&mut buf, 0); // key length 0

        let err = Topics::unmarshal(&buf).unwrap_err();
        assert!(matches!(err, TopicsError::InvalidKey(0)));
    }

    #[test]
    fn data_too_large_error() {
        // Construct a buffer claiming data length > MAX_MESSAGE_LENGTH
        let mut buf = Vec::new();
        put_uvarint(&mut buf, 1); // 1 topic
        put_uvarint(&mut buf, 1); // key length 1
        buf.push(b'k'); // key
        put_uvarint(&mut buf, MAX_MESSAGE_LENGTH as u64 + 1); // data length too big

        let err = Topics::unmarshal(&buf).unwrap_err();
        assert!(matches!(err, TopicsError::DataTooLarge(_)));
    }

    #[test]
    fn buffer_underflow_data_error() {
        // Construct a buffer where claimed data length exceeds remaining bytes
        let mut buf = Vec::new();
        put_uvarint(&mut buf, 1); // 1 topic
        put_uvarint(&mut buf, 1); // key length 1
        buf.push(b'k'); // key
        put_uvarint(&mut buf, 100); // data length 100
        buf.extend_from_slice(&[0u8; 10]); // only 10 bytes of data

        let err = Topics::unmarshal(&buf).unwrap_err();
        assert!(matches!(err, TopicsError::BufferUnderflow));
    }

    #[test]
    fn truncated_buffer_errors() {
        // Completely empty
        assert!(Topics::unmarshal(&[]).is_err());

        // Topic count says 1, but no topic data
        let mut buf = Vec::new();
        put_uvarint(&mut buf, 1);
        assert!(Topics::unmarshal(&buf).is_err());
    }

    #[test]
    fn get_value_found() {
        let topics = Topics::from_vec(vec![
            Topic::new("a", b"1".to_vec()),
            Topic::new("b", b"2".to_vec()),
        ]);
        assert_eq!(topics.get_value("b"), Some(b"2".as_slice()));
    }

    #[test]
    fn get_value_not_found() {
        let topics = Topics::from_vec(vec![Topic::new("a", b"1".to_vec())]);
        assert_eq!(topics.get_value("missing"), None);
    }

    #[test]
    fn get_value_returns_first_match() {
        let topics = Topics::from_vec(vec![
            Topic::new("dup", b"first".to_vec()),
            Topic::new("dup", b"second".to_vec()),
        ]);
        assert_eq!(topics.get_value("dup"), Some(b"first".as_slice()));
    }

    #[test]
    fn max_key_length_accepted() {
        let long_key = "a".repeat(MAX_KEY_LENGTH as usize);
        let topics = Topics::from_vec(vec![Topic::new(&long_key, b"val".to_vec())]);
        let bytes = topics.marshal();
        let decoded = Topics::unmarshal(&bytes).unwrap();
        assert_eq!(decoded.0[0].key, long_key);
    }

    #[test]
    fn well_known_keys_are_valid_strings() {
        // Smoke test that the constants are reasonable
        assert_eq!(ROUND_KEY, "roundKey");
        assert_eq!(REQUEST_DATA_TYPE_KEY, "requestDataType");
        assert_eq!(BLOCK_DATA_KEY, "blockData");
        assert_eq!(CERT_DATA_KEY, "certData");
        assert_eq!(BLOCK_AND_CERT_VALUE, "blockAndCert");
        assert_eq!(LATEST_ROUND_KEY, "latest");
        assert_eq!(REQUEST_HASH_KEY, "RequestHash");
        assert_eq!(ERROR_KEY, "Error");
    }

    #[test]
    fn binary_format_matches_go_encoding() {
        // Verify our encoding matches Go's binary.PutUvarint format.
        // Go encodes Topics([Topic{key:"a", data:[1]}]) as:
        //   01   -- 1 topic (uvarint)
        //   01   -- key length 1 (uvarint)
        //   61   -- 'a'
        //   01   -- data length 1 (uvarint)
        //   01   -- data byte
        let topics = Topics::from_vec(vec![Topic::new("a", vec![1])]);
        let bytes = topics.marshal();
        assert_eq!(bytes, vec![0x01, 0x01, b'a', 0x01, 0x01]);
    }
}
