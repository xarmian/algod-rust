//! Serde adapter that (de)serializes byte arrays and slices as base64
//! strings, matching go-codec's `JsonHandle` behavior for `[N]byte` and
//! `[]byte` fields in `protocol.EncodeJSON` output.
//!
//! Usage:
//!
//! ```ignore
//! #[derive(Serialize, Deserialize)]
//! struct Foo {
//!     #[serde(with = "algo_kmd_api_types::base64_bytes::array_32")]
//!     pub key: [u8; 32],
//!     #[serde(with = "algo_kmd_api_types::base64_bytes::vec")]
//!     pub blob: Vec<u8>,
//! }
//! ```
//!
//! Use the standard alphabet with padding (Go's default
//! `base64.StdEncoding` and go-codec's `JsonHandle` default).

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn decode<E: serde::de::Error>(s: &str) -> Result<Vec<u8>, E> {
    STANDARD.decode(s).map_err(serde::de::Error::custom)
}

/// (De)serialize a `[u8; 32]` as a base64 string.
pub mod array_32 {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        encode(value).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = decode::<D::Error>(&s)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

/// (De)serialize a `[u8; 64]` as a base64 string.
pub mod array_64 {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        encode(value).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = decode::<D::Error>(&s)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

/// (De)serialize a `Vec<u8>` as a base64 string.
pub mod vec {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        encode(value).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        decode::<D::Error>(&s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct Sample {
        #[serde(with = "array_32")]
        k32: [u8; 32],
        #[serde(with = "array_64")]
        k64: [u8; 64],
        #[serde(with = "vec")]
        blob: Vec<u8>,
    }

    #[test]
    fn round_trip_through_serde_json() {
        let s = Sample {
            k32: std::array::from_fn(|i| i as u8 + 1),
            k64: std::array::from_fn(|i| i as u8),
            blob: vec![1, 2, 3, 4],
        };
        let json = serde_json::to_string(&s).unwrap();
        // All three fields must encode as base64 strings (not arrays of numbers).
        assert!(
            json.contains("\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\""),
            "k32 must be base64: {json}"
        );
        let back: Sample = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn rejects_wrong_length_for_fixed_arrays() {
        let bad = r#"{"k32":"YQ==","k64":"YQ==","blob":""}"#;
        assert!(serde_json::from_str::<Sample>(bad).is_err());
    }
}
