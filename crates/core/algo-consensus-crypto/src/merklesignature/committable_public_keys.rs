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

//! Leaf-hashing adapter for the MSS vector commitment tree.
//!
//! Mirrors `../go-algorand/crypto/merklesignature/committablePublicKeys.go`.
//! For each ephemeral Falcon keypair the leaf preimage is:
//!
//! ```text
//! HashID("KP") || LE_u16(CryptoPrimitivesID=0) || LE_u64(round) || FalconPublicKey
//! ```
//!
//! The `(prefix, body)` pair is consumed by [`merklearray::build_vector_commitment_tree`]
//! which prepends the prefix and hashes via [`HashFactory`] (sumhash512 for MSS).

use super::posdivs::index_to_round;
use super::{consts, FalconSigner};
use crate::merklearray::{Array, Hashable, MerkleError};

/// A single ephemeral Falcon public key bound to its covering round.
///
/// Mirrors Go's `CommittablePublicKey`.
pub struct CommittablePublicKey<'a> {
    /// Raw Falcon-1024 public key bytes (length [`algo_falcon::FALCON_DET1024_PUBKEY_SIZE`]).
    pub falcon_pk: &'a [u8],
    /// Round this key signs for.
    pub round: u64,
}

impl<'a> Hashable for CommittablePublicKey<'a> {
    fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
        // scheme(2) || round(8) || pk(N) — matches Go's append order.
        let mut body = Vec::with_capacity(2 + 8 + self.falcon_pk.len());
        body.extend_from_slice(&consts::CRYPTO_PRIMITIVES_ID.to_le_bytes());
        body.extend_from_slice(&self.round.to_le_bytes());
        body.extend_from_slice(self.falcon_pk);
        (consts::KEYS_IN_MSS_PREFIX, body)
    }
}

/// Array of Falcon ephemeral keys, projected onto the merkle vector commitment.
///
/// Mirrors Go's unexported `committablePublicKeyArray`.
pub(crate) struct CommittablePublicKeyArray<'a> {
    pub keys: &'a [FalconSigner],
    pub first_valid: u64,
    pub key_lifetime: u64,
}

impl<'a> Array for CommittablePublicKeyArray<'a> {
    fn length(&self) -> u64 {
        self.keys.len() as u64
    }

    fn marshal(&self, pos: u64) -> Result<Box<dyn Hashable>, MerkleError> {
        if pos as usize >= self.keys.len() {
            return Err(MerkleError::PosOutOfBound {
                pos,
                bound: self.keys.len() as u64,
            });
        }
        // We must own the pubkey bytes because the trait object outlives the
        // borrowed slice through merklearray. Cheap clone (1793 bytes).
        let pk = self.keys[pos as usize].public_key().to_vec();
        let round = index_to_round(self.first_valid, self.key_lifetime, pos);
        Ok(Box::new(OwnedCommittablePublicKey {
            falcon_pk: pk,
            round,
        }))
    }
}

/// Owned variant used to satisfy the `Box<dyn Hashable>` lifetime requirement
/// from `merklearray::Array::marshal`. Encodes identically to
/// [`CommittablePublicKey`].
struct OwnedCommittablePublicKey {
    falcon_pk: Vec<u8>,
    round: u64,
}

impl Hashable for OwnedCommittablePublicKey {
    fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
        let mut body = Vec::with_capacity(2 + 8 + self.falcon_pk.len());
        body.extend_from_slice(&consts::CRYPTO_PRIMITIVES_ID.to_le_bytes());
        body.extend_from_slice(&self.round.to_le_bytes());
        body.extend_from_slice(&self.falcon_pk);
        (consts::KEYS_IN_MSS_PREFIX, body)
    }
}
