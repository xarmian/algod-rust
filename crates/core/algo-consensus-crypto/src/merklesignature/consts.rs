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
