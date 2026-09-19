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

use algo_error::AlgoError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A 32-byte cryptographic digest (SHA512/256 output).
///
/// Displayed as base32 (RFC 4648, no padding) to match Go's transaction ID format.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", data_encoding::BASE32_NOPAD.encode(&self.0))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", hex::encode(self.0))
    }
}

impl From<[u8; 32]> for Digest {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Parses the base32 (RFC 4648, no padding) string produced by [`Display`]
/// back into a `Digest`, mirroring go-algorand's `crypto.DigestFromString`
/// (`crypto/util.go`) — the decode half of the round trip go's
/// `TestEncodeDecode` (`crypto/util_test.go`) pins.
///
/// [`Display`]: fmt::Display
impl FromStr for Digest {
    type Err = AlgoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = data_encoding::BASE32_NOPAD
            .decode(s.as_bytes())
            .map_err(|e| AlgoError::Config(format!("invalid digest base32: {e}")))?;
        if decoded.len() != 32 {
            return Err(AlgoError::Config(format!(
                "attempted to decode a string which was not a Digest: {s:?}"
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&decoded);
        Ok(Digest(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors go's `TestDigest_IsZero` (`crypto/util_test.go:40`): the
    /// all-zero digest reports `IsZero() == true`, and any digest with at
    /// least one non-zero byte (first, middle, or last) reports `false`.
    #[test]
    fn is_zero_true_for_all_zero_bytes() {
        assert!(Digest([0u8; 32]).is_zero());
    }

    #[test]
    fn is_zero_false_when_any_byte_nonzero() {
        let mut first = [0u8; 32];
        first[0] = 1;
        assert!(!Digest(first).is_zero());

        let mut middle = [0u8; 32];
        middle[16] = 1;
        assert!(!Digest(middle).is_zero());

        let mut last = [0u8; 32];
        last[31] = 1;
        assert!(!Digest(last).is_zero());

        assert!(!Digest([0xffu8; 32]).is_zero());
    }

    /// Mirrors go's `TestEncodeDecode` (`crypto/util_test.go:29`): hash some
    /// bytes, `String()`/`Display` it to base32, `DigestFromString`/
    /// `FromStr` it back, and confirm the round trip is lossless.
    #[test]
    fn from_str_round_trips_through_display() {
        let mut sha = sha2::Sha512_256::default();
        sha2::Digest::update(&mut sha, b"this is a test");
        let hashed_bytes: [u8; 32] = sha2::Digest::finalize(sha).into();
        let hashed = Digest(hashed_bytes);

        let hashed_str = hashed.to_string();
        let recovered: Digest = hashed_str.parse().expect("valid base32 digest");

        assert_eq!(recovered, hashed);
    }

    #[test]
    fn from_str_rejects_wrong_length() {
        // Valid base32 but decodes to fewer than 32 bytes.
        let err = "AAAA".parse::<Digest>();
        assert!(err.is_err());
    }

    #[test]
    fn from_str_rejects_invalid_base32() {
        let err = "not-valid-base32!!!".parse::<Digest>();
        assert!(err.is_err());
    }
}
