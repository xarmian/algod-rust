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

use serde::{Deserialize, Serialize};
use std::fmt;

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
}
