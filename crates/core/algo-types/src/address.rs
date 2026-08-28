use algo_error::AlgoError;
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha512_256};
use std::fmt;
use std::str::FromStr;

/// A 32-byte Algorand address (Ed25519 public key for single-sig accounts).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct Address(pub [u8; 32]);

impl Address {
    pub const ZERO: Self = Address([0u8; 32]);

    /// The canonical state-proof sender address.
    ///
    /// Computed as `SHA512/256("SpecialAddr" || "StateProofSender")`, matching
    /// go-algorand's `transactions.StateProofSender` which is initialised via
    /// `crypto.HashObj(specialAddr("StateProofSender"))`.
    pub const STATE_PROOF_SENDER: Self = Address([
        0xbb, 0x3c, 0x52, 0x62, 0xa9, 0xd5, 0xc7, 0x4d, 0x20, 0x27, 0xe3, 0xa7, 0xea, 0xe4, 0xd6,
        0xff, 0x70, 0xcf, 0x6c, 0x4c, 0xe4, 0xc5, 0xe0, 0x57, 0xc1, 0x1e, 0xd3, 0x9b, 0x95, 0x34,
        0x42, 0x05,
    ]);

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Reports whether this address is eligible to be a native post-quantum
    /// account address: it must NOT decode as a valid Edwards25519 curve
    /// point (otherwise the same 32 bytes could double as a spendable
    /// ed25519 on-curve address, defeating PQ-address/ed25519-address
    /// unambiguity). Mirrors go-algorand's `basics.Address.IsPQCompliant()`
    /// (`data/basics/address.go`), which is `!crypto.IsEdwards25519Point(addr[:])`.
    /// `IsEdwards25519Point` decodes the same way `filippo.io/edwards25519`'s
    /// `Point.SetBytes` does (accepting some non-canonical point encodings,
    /// not checking prime-order-subgroup membership); `curve25519-dalek`'s
    /// `CompressedEdwardsY::decompress` follows the same reference algorithm
    /// and matches that acceptance behavior (see also
    /// `algo-avm::assembler::program_hash_is_edwards25519_point`, which uses
    /// the identical check for LogicSig contract-account addresses).
    pub fn is_pq_compliant(&self) -> bool {
        curve25519_dalek::edwards::CompressedEdwardsY(self.0)
            .decompress()
            .is_none()
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

// ---------------------------------------------------------------------------
// Wire encoding (issue #578)
// ---------------------------------------------------------------------------
//
// go-algorand's `basics.Address` implements `encoding.TextMarshaler`
// (`data/basics/address.go`'s `MarshalText`/`String`), so go-codec's JSON
// handle always renders it as the checksummed base32 string, while the
// msgpack handle (which has no special-case for `TextMarshaler`) still
// writes the raw 32 bytes. A plain `#[serde(with = "serde_bytes")]` (the
// prior impl here) reproduced the msgpack side correctly but not JSON:
// `serde_json`'s `Serializer::serialize_bytes` has no native "bytes" type
// and falls back to a JSON array of 32 numbers instead of the checksum
// string -- the same class of bug issue #573 fixed for
// `KvValueDelta.Data`/`.OldData` and issue #576 fixed for
// `basics.VotingData`'s `VoteID`/`SelectionID`/`StateProofID`.
impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_algorand_string())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

// Deliberately does NOT branch on `deserializer.is_human_readable()` (see
// `state_delta.rs`'s `deserialize_bytes_array` for the full writeup, and
// `AccountBaseData::auth_addr` -- flattened via `LedgercoreAccountData` --
// for a live call site that hits exactly this trap). Serde's derive
// implements `#[serde(flatten)]` deserialization by first buffering the
// remaining input into a generic `serde::__private::de::Content` value,
// whose `Deserializer::is_human_readable()` hard-codes `true` regardless of
// the real wire format. Branching on it would silently try to base32-decode
// raw msgpack bytes whenever an `Address` sits under a flattened struct.
// Using `deserialize_any` instead asks "what shape is this value" (a
// `Content::Str`/`Content::Bytes` case preserves the real original kind even
// though its `is_human_readable()` lies), which sidesteps the bug entirely
// and works identically whether or not `Address` is flattened.
impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AddressVisitor;

        impl<'de> serde::de::Visitor<'de> for AddressVisitor {
            type Value = Address;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a base32 Algorand address string or 32 raw bytes")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Address, E> {
                Address::from_algorand_string(v).map_err(E::custom)
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Address, E> {
                v.try_into()
                    .map(Address)
                    .map_err(|_| E::custom(format!("expected 32 bytes, got {}", v.len())))
            }

            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Address, E> {
                self.visit_bytes(&v)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Address, A::Error> {
                let mut arr = [0u8; 32];
                for (i, byte) in arr.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(Address(arr))
            }
        }

        deserializer.deserialize_any(AddressVisitor)
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

    // -----------------------------------------------------------------
    // JSON must serialize as the base32 checksum string (issue #578),
    // matching go-algorand's basics.Address (encoding.TextMarshaler),
    // not a raw byte array. Msgpack must stay raw bytes (unaffected).
    // -----------------------------------------------------------------

    #[test]
    fn test_json_serializes_as_base32_checksum_string() {
        let addr = Address::from_algorand_string(FEE_SINK).unwrap();
        let json = serde_json::to_value(addr).expect("serialize");
        assert_eq!(json, serde_json::Value::String(FEE_SINK.to_string()));
    }

    #[test]
    fn test_json_round_trips_through_base32_string() {
        let addr = Address::from_algorand_string(REWARDS_POOL).unwrap();
        let json = serde_json::to_value(addr).expect("serialize");
        let round_tripped: Address = serde_json::from_value(json).expect("deserialize");
        assert_eq!(addr, round_tripped);
    }

    #[test]
    fn test_zero_address_json_round_trip() {
        let addr = Address::ZERO;
        let json = serde_json::to_value(addr).expect("serialize");
        assert_eq!(json, serde_json::Value::String(ZERO_ADDR.to_string()));
        let round_tripped: Address = serde_json::from_value(json).expect("deserialize");
        assert_eq!(addr, round_tripped);
    }

    #[test]
    fn test_msgpack_round_trips_as_raw_bytes_not_string() {
        let addr = Address::from_algorand_string(FEE_SINK).unwrap();
        let bytes = rmp_serde::to_vec_named(&addr).expect("msgpack encode");
        // Raw 32-byte msgpack bin, not a base32 string -- must stay far
        // smaller than the 58-char string encoding would be.
        assert!(
            bytes.len() < 40,
            "expected compact raw-bytes msgpack encoding, got {} bytes",
            bytes.len()
        );
        let round_tripped: Address = rmp_serde::from_slice(&bytes).expect("msgpack decode");
        assert_eq!(addr, round_tripped);
    }

    #[test]
    fn test_address_behind_flatten_round_trips_through_msgpack() {
        // Regression guard for the `#[serde(flatten)]` + `is_human_readable()`
        // trap documented in issue #578 / algo-ledger's state_delta.rs: an
        // `Address` sitting under a flattened struct must still decode
        // correctly from msgpack, since serde's flatten machinery buffers
        // into a `Content` value whose `is_human_readable()` always lies and
        // says `true`.
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        struct Inner {
            addr: Address,
        }
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        struct Outer {
            #[serde(flatten)]
            inner: Inner,
        }

        let outer = Outer {
            inner: Inner {
                addr: Address::from_algorand_string(FEE_SINK).unwrap(),
            },
        };
        let bytes = rmp_serde::to_vec_named(&outer).expect("msgpack encode");
        let round_tripped: Outer = rmp_serde::from_slice(&bytes).expect("msgpack decode");
        assert_eq!(outer, round_tripped);
    }
}
