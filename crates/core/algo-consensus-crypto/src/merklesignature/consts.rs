//! Constants for the Merkle Signature Scheme.
//!
//! Mirrors `../go-algorand/crypto/merklesignature/const.go`.

use crate::sumhash::SUMHASH512_DIGEST_SIZE;

/// Default key lifetime in rounds.
///
/// Mirrors `merklesignature.KeyLifetimeDefault` (`const.go`).
pub const KEY_LIFETIME_DEFAULT: u64 = 256;

/// Current salt version of merkleSignature.
///
/// Mirrors `merklesignature.SchemeSaltVersion` (`const.go`).
pub const SCHEME_SALT_VERSION: u8 = 0;

/// Cryptographic primitives identifier for the MSS leaves.
///
/// `0` means: subset-sum hash function + Falcon signature scheme.
/// Mirrors `merklesignature.CryptoPrimitivesID` (`const.go`).
pub const CRYPTO_PRIMITIVES_ID: u16 = 0;

/// Size, in bytes, of an MSS commitment (== sumhash512 digest size).
///
/// Mirrors `merklesignature.MerkleSignatureSchemeRootSize`.
pub const COMMITMENT_SIZE: usize = SUMHASH512_DIGEST_SIZE;

/// Domain-separation prefix for MSS leaves: `protocol.KeysInMSS = "KP"`.
///
/// See `../go-algorand/protocol/hash.go:47`.
pub const KEYS_IN_MSS_PREFIX: &[u8] = b"KP";
