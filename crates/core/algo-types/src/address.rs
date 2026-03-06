use algo_error::AlgoError;
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512_256};
use std::fmt;
use std::str::FromStr;

/// A 32-byte Algorand address (Ed25519 public key for single-sig accounts).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(transparent)]
pub struct Address(#[serde(with = "serde_bytes")] pub [u8; 32]);

impl Address {
    pub const ZERO: Self = Address([0u8; 32]);

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Decode a 58-character checksummed base32 Algorand address.
    ///
    /// Algorithm: base32 decode (RFC 4648, no padding) → 36 bytes →
    /// first 32 = public key, last 4 = checksum where
    /// checksum = SHA512/256(pubkey)[28..32].
    pub fn from_algorand_string(s: &str) -> Result<Address, AlgoError> {
        let decoded = BASE32_NOPAD
            .decode(s.as_bytes())
            .map_err(|e| AlgoError::Config(format!("invalid address base32: {e}")))?;

        if decoded.len() != 36 {
            return Err(AlgoError::Config(format!(
                "invalid address length: expected 36 decoded bytes, got {}",
                decoded.len()
            )));
        }

        let pubkey: [u8; 32] = decoded[..32].try_into().unwrap();
        let provided_checksum = &decoded[32..36];

        let hash = Sha512_256::digest(pubkey);
        let expected_checksum = &hash[28..32];

        if provided_checksum != expected_checksum {
            return Err(AlgoError::Config("invalid address checksum".to_string()));
        }

        Ok(Address(pubkey))
    }

    /// Encode as a checksummed Algorand base32 address string.
    ///
    /// Computes checksum = SHA512/256(pubkey)[28..32], concatenates
    /// pubkey + checksum, then base32 encodes (uppercase, no padding).
    pub fn to_algorand_string(&self) -> String {
        let hash = Sha512_256::digest(self.0);
        let checksum = &hash[28..32];

        let mut payload = [0u8; 36];
        payload[..32].copy_from_slice(&self.0);
        payload[32..].copy_from_slice(checksum);

        BASE32_NOPAD.encode(&payload)
    }
}

impl Default for Address {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", hex::encode(&self.0[..8]))
    }
}

/// Display as the canonical Algorand checksummed base32 address string.
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_algorand_string())
    }
}

impl FromStr for Address {
    type Err = AlgoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::from_algorand_string(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEE_SINK: &str = "Y76M3MSY6DKBRHBL7C3NNDXGS5IIMQVQVUAB6MP4XEMMGVF2QWNPL226CA";
    const REWARDS_POOL: &str = "737777777777777777777777777777777777777777777777777UFEJ2CI";
    const ZERO_ADDR: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ";

    #[test]
    fn test_parse_fee_sink_address() {
        let addr = Address::from_algorand_string(FEE_SINK).unwrap();
        assert!(!addr.is_zero());
    }

    #[test]
    fn test_parse_rewards_pool_address() {
        let addr = Address::from_algorand_string(REWARDS_POOL).unwrap();
        assert!(!addr.is_zero());
    }

    #[test]
    fn test_parse_zero_address() {
        let addr = Address::from_algorand_string(ZERO_ADDR).unwrap();
        assert!(addr.is_zero());
    }

    #[test]
    fn test_round_trip_fee_sink() {
        let addr = Address::from_algorand_string(FEE_SINK).unwrap();
        let encoded = addr.to_algorand_string();
        assert_eq!(encoded, FEE_SINK);
        let reparsed = Address::from_algorand_string(&encoded).unwrap();
        assert_eq!(addr, reparsed);
    }

    #[test]
    fn test_round_trip_rewards_pool() {
        let addr = Address::from_algorand_string(REWARDS_POOL).unwrap();
        let encoded = addr.to_algorand_string();
        assert_eq!(encoded, REWARDS_POOL);
        let reparsed = Address::from_algorand_string(&encoded).unwrap();
        assert_eq!(addr, reparsed);
    }

    #[test]
    fn test_round_trip_zero_address() {
        let addr = Address::from_algorand_string(ZERO_ADDR).unwrap();
        let encoded = addr.to_algorand_string();
        assert_eq!(encoded, ZERO_ADDR);
        let reparsed = Address::from_algorand_string(&encoded).unwrap();
        assert_eq!(addr, reparsed);
    }

    #[test]
    fn test_from_str_trait() {
        let addr: Address = FEE_SINK.parse().unwrap();
        assert_eq!(addr.to_algorand_string(), FEE_SINK);
    }

    #[test]
    fn test_display_trait() {
        let addr = Address::from_algorand_string(FEE_SINK).unwrap();
        assert_eq!(format!("{}", addr), FEE_SINK);
    }

    #[test]
    fn test_invalid_checksum() {
        // Take a valid address and corrupt the last character (checksum)
        let mut bad = FEE_SINK.to_string();
        let last = bad.pop().unwrap();
        // Replace last char with something different
        let replacement = if last == 'A' { 'B' } else { 'A' };
        bad.push(replacement);
        let result = Address::from_algorand_string(&bad);
        assert!(result.is_err(), "should reject address with bad checksum");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("checksum") || err_msg.contains("base32"),
            "error should mention checksum or base32, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_wrong_length_too_short() {
        let result = Address::from_algorand_string("AAAA");
        assert!(result.is_err(), "should reject short address");
    }

    #[test]
    fn test_wrong_length_too_long() {
        // 59 A's -- one character too many for a valid address
        let long = "A".repeat(59);
        let result = Address::from_algorand_string(&long);
        assert!(result.is_err(), "should reject overly long address");
    }

    #[test]
    fn test_empty_string() {
        let result = Address::from_algorand_string("");
        assert!(result.is_err(), "should reject empty string");
    }

    #[test]
    fn test_invalid_base32_characters() {
        // Lowercase is invalid in standard base32
        let result = Address::from_algorand_string(
            "y76m3msy6dkbrhbl7c3nndxgs5iimqvqvuab6mp4xemmgvf2qwnpl226ca",
        );
        assert!(result.is_err(), "should reject lowercase base32");
    }

    #[test]
    fn test_different_addresses_not_equal() {
        let addr1 = Address::from_algorand_string(FEE_SINK).unwrap();
        let addr2 = Address::from_algorand_string(REWARDS_POOL).unwrap();
        assert_ne!(addr1, addr2);
    }
}

mod serde_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = Deserialize::deserialize(deserializer)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
        })
    }
}
