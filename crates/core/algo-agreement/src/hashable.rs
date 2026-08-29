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

// Hashable trait and hash_obj function, matching go-algorand/crypto/util.go.
//
// This is the core domain-separated hashing pattern used by all agreement types:
//   hash_obj(h) = SHA512/256(hash_id || to_be_hashed)

use algo_types::Digest;
use sha2::{Digest as _, Sha512_256};

/// A type that can be hashed with domain separation.
///
/// Mirrors Go's `crypto.Hashable` interface.
pub trait Hashable {
    /// Domain separation prefix (e.g. `b"AS"` for agreement selector).
    fn hash_id() -> &'static [u8];

    /// Canonical encoding of the object (typically msgpack).
    fn to_be_hashed(&self) -> Vec<u8>;
}

/// Compute the domain-separated SHA512/256 digest of a `Hashable` object.
///
/// Mirrors Go's `crypto.HashObj`: `SHA512_256(hash_id || to_be_hashed)`.
pub fn hash_obj<H: Hashable>(h: &H) -> Digest {
    let raw = hash_rep(h);
    let result = Sha512_256::digest(&raw);
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Digest(out)
}

/// Returns the domain-separated raw bytes of a `Hashable` object
/// WITHOUT hashing: `hash_id || to_be_hashed`.
///
/// Mirrors Go's `crypto.HashRep`. This is the message that should be
/// passed to VRF verify (Go passes `hashRep(obj)` to VRF, not the digest).
pub fn hash_rep<H: Hashable>(h: &H) -> Vec<u8> {
    let id = H::hash_id();
    let data = h.to_be_hashed();
    let mut out = Vec::with_capacity(id.len() + data.len());
    out.extend_from_slice(id);
    out.extend(data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial Hashable for testing, matching Go's `protocol.TestHashable = "TE"`.
    struct TestHashable(Vec<u8>);

    impl Hashable for TestHashable {
        fn hash_id() -> &'static [u8] {
            b"TE"
        }
        fn to_be_hashed(&self) -> Vec<u8> {
            self.0.clone()
        }
    }

    #[test]
    fn hash_obj_produces_correct_sha512_256() {
        let h = TestHashable(b"hello".to_vec());
        let digest = hash_obj(&h);

        // Manually compute SHA512/256("TE" || "hello")
        let mut hasher = Sha512_256::new();
        hasher.update(b"TE");
        hasher.update(b"hello");
        let expected = hasher.finalize();

        assert_eq!(digest.0, expected.as_slice());
    }

    #[test]
    fn hash_obj_empty_data() {
        let h = TestHashable(vec![]);
        let digest = hash_obj(&h);

        let mut hasher = Sha512_256::new();
        hasher.update(b"TE");
        let expected = hasher.finalize();

        assert_eq!(digest.0, expected.as_slice());
    }

    #[test]
    fn different_hash_ids_produce_different_digests() {
        struct OtherHashable(Vec<u8>);
        impl Hashable for OtherHashable {
            fn hash_id() -> &'static [u8] {
                b"XX"
            }
            fn to_be_hashed(&self) -> Vec<u8> {
                self.0.clone()
            }
        }

        let data = b"same data".to_vec();
        let d1 = hash_obj(&TestHashable(data.clone()));
        let d2 = hash_obj(&OtherHashable(data));
        assert_ne!(d1, d2);
    }
}
