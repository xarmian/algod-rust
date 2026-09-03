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

//! A minimal block header used to build the `BlockHeadersCommitment` a
//! state-proof message attests to. Ports go-algorand's
//! `data/bookkeeping/lightBlockHeader.go`'s `LightBlockHeader` type (issue
//! #814's live-daemon-wiring scope: the `GenerateStateProofMessage` port
//! needs a Merkle-tree-hashable representation of each block header in the
//! interval, over SHA-256 only, per that file's own doc comment: "this
//! struct is designed to be used on environments where only SHA256 function
//! exists").
//!
//! This type (and its [`Hashable`] impl) live in `algo-consensus-crypto`
//! rather than `algo-types`/`algo-ledger` because `Hashable` is defined
//! here and Rust's orphan rule requires the impl to live alongside one of
//! the two. The caller (`algo_ledger::stateproof_message`) is responsible
//! for populating the fields correctly from a real `BlockHeader` — this
//! module only knows how to hash/encode whatever it's given.

use crate::merklearray::{self, Hashable};

/// `protocol.BlockHeader256 = "B256"` — the domain-separation prefix for
/// hashing a [`LightBlockHeader`] (`protocol/hash.go:42`).
const BLOCK_HEADER_256: &[u8] = b"B256";

/// Mirrors go's `bookkeeping.LightBlockHeader`
/// (`data/bookkeeping/lightBlockHeader.go:30`). Exactly one of `seed`/
/// `block_hash` is populated per go's `ToLightBlockHeader`: `block_hash`
/// under `StateProofBlockHashInLightHeader` (v39+, i.e. always at this
/// repo's parity pin), `seed` otherwise.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LightBlockHeader {
    pub seed: [u8; 32],
    pub block_hash: [u8; 32],
    pub round: u64,
    pub genesis_hash: [u8; 32],
    /// go: `Sha256TxnCommitment crypto.GenericDigest` — the block's
    /// `Sha256Commitment` ("txn256") field.
    pub sha256_txn_commitment: [u8; 32],
}

impl Hashable for LightBlockHeader {
    fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
        (BLOCK_HEADER_256, self.canonical_encode())
    }
}

impl LightBlockHeader {
    /// Canonical msgpack encoding, matching go's codec tags exactly:
    /// `"0"` (seed), `"1"` (block_hash), `"gh"` (genesis_hash), `"r"`
    /// (round), `"tc"` (sha256_txn_commitment) — `omitempty`, sorted
    /// lexicographically by key ("0" < "1" < "gh" < "r" < "tc").
    fn canonical_encode(&self) -> Vec<u8> {
        let seed_zero = self.seed == [0u8; 32];
        let hash_zero = self.block_hash == [0u8; 32];
        let commit_zero = self.sha256_txn_commitment == [0u8; 32];
        let gh_zero = self.genesis_hash == [0u8; 32];

        let mut field_count: u8 = 0;
        if !seed_zero {
            field_count += 1;
        }
        if !hash_zero {
            field_count += 1;
        }
        if !gh_zero {
            field_count += 1;
        }
        if self.round != 0 {
            field_count += 1;
        }
        if !commit_zero {
            field_count += 1;
        }

        let mut buf = Vec::with_capacity(140);
        // fixmap can encode up to 15 entries; we have at most 5.
        buf.push(0x80 | field_count);

        if !seed_zero {
            write_fixstr(&mut buf, "0");
            rmp::encode::write_bin(&mut buf, &self.seed).unwrap();
        }
        if !hash_zero {
            write_fixstr(&mut buf, "1");
            rmp::encode::write_bin(&mut buf, &self.block_hash).unwrap();
        }
        if !gh_zero {
            write_fixstr(&mut buf, "gh");
            rmp::encode::write_bin(&mut buf, &self.genesis_hash).unwrap();
        }
        if self.round != 0 {
            write_fixstr(&mut buf, "r");
            rmp::encode::write_uint(&mut buf, self.round).unwrap();
        }
        if !commit_zero {
            write_fixstr(&mut buf, "tc");
            rmp::encode::write_bin(&mut buf, &self.sha256_txn_commitment).unwrap();
        }

        buf
    }
}

fn write_fixstr(buf: &mut Vec<u8>, s: &str) {
    debug_assert!(s.len() <= 31, "fixstr supports up to 31 bytes");
    buf.push(0xa0 | s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
}

/// An indexable array of [`LightBlockHeader`]s, ready for vector-commitment
/// tree construction. Matches go's private `lightBlockHeaders` array type
/// (`stateproofMessageGenerator.go:40`).
#[derive(Debug, Clone, Default)]
pub struct LightBlockHeaderArray(pub Vec<LightBlockHeader>);

impl merklearray::Array for LightBlockHeaderArray {
    fn length(&self) -> u64 {
        self.0.len() as u64
    }

    fn marshal(&self, pos: u64) -> Result<Box<dyn Hashable>, merklearray::MerkleError> {
        self.0
            .get(pos as usize)
            .cloned()
            .map(|h| Box::new(h) as Box<dyn Hashable>)
            .ok_or(merklearray::MerkleError::PosOutOfBound {
                pos,
                bound: self.0.len() as u64,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merklearray::{build_vector_commitment_tree, HashFactory, HashType};

    #[test]
    fn to_be_hashed_uses_b256_prefix() {
        let h = LightBlockHeader {
            round: 5,
            ..Default::default()
        };
        let (prefix, _) = h.to_be_hashed();
        assert_eq!(prefix, b"B256");
    }

    #[test]
    fn canonical_encode_omits_zero_fields() {
        let h = LightBlockHeader::default();
        // Every field zero -> empty map (0x80).
        assert_eq!(h.canonical_encode(), vec![0x80]);
    }

    #[test]
    fn canonical_encode_is_deterministic() {
        let a = LightBlockHeader {
            round: 256,
            genesis_hash: [7u8; 32],
            sha256_txn_commitment: [9u8; 32],
            ..Default::default()
        };
        let b = a.clone();
        assert_eq!(a.canonical_encode(), b.canonical_encode());
    }

    #[test]
    fn distinct_headers_encode_differently() {
        let a = LightBlockHeader {
            round: 1,
            genesis_hash: [1u8; 32],
            ..Default::default()
        };
        let b = LightBlockHeader {
            round: 2,
            genesis_hash: [1u8; 32],
            ..Default::default()
        };
        assert_ne!(a.canonical_encode(), b.canonical_encode());
    }

    #[test]
    fn builds_a_vector_commitment_tree_over_light_headers() {
        let headers: Vec<LightBlockHeader> = (1..=8u64)
            .map(|r| LightBlockHeader {
                round: r,
                genesis_hash: [0xAAu8; 32],
                sha256_txn_commitment: [r as u8; 32],
                ..Default::default()
            })
            .collect();
        let array = LightBlockHeaderArray(headers);
        let factory = HashFactory::new(HashType::Sha256);
        let tree = build_vector_commitment_tree(&array, factory).expect("build tree");
        assert!(!tree.root().is_empty());
    }
}
