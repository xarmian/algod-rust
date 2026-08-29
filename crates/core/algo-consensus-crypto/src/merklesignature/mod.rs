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

//! Merkle Signature Scheme (MSS) — Falcon-1024 ephemeral keys committed
//! under a sumhash-rooted vector commitment.
//!
//! This module ports the writer-side primitives from
//! `../go-algorand/crypto/merklesignature/`:
//!
//! - [`Secrets::new`] — pre-generates one Falcon ephemeral signer per
//!   covered round (parallel keygen via [`keys_builder`]) and builds the
//!   commitment tree (`merklearray::build_vector_commitment_tree`).
//! - [`SignerContext`] — the immutable verifier-side metadata that ships
//!   alongside the ephemeral keys.
//! - [`Verifier`] — the long-term `(commitment, key_lifetime)` pair.
//!
//! Read paths (signature verification, msgpack decode) live alongside the
//! existing reader infrastructure in Phase B; this module focuses on the
//! writer-side path needed by [`TASK-177`]
//! (`FillDBWithParticipationKeys`).
//!
//! [`TASK-177`]: ../../../../../../crates/core/algo-consensus-crypto/src/merklesignature/mod.rs

pub mod committable_public_keys;
pub mod consts;
pub mod keys_builder;
pub mod posdivs;

use crate::merklearray::{build_vector_commitment_tree, HashFactory, HashType, Tree};
use committable_public_keys::CommittablePublicKeyArray;
pub use consts::{
    COMMITMENT_SIZE, CRYPTO_PRIMITIVES_ID, KEYS_IN_MSS_PREFIX, KEY_LIFETIME_DEFAULT,
    SCHEME_SALT_VERSION,
};
pub use keys_builder::keys_builder;

/// Errors specific to MSS key generation.
///
/// Mirrors `merklesignature.Err*` (`merkleSignatureScheme.go:88-95`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MssError {
    /// `first_valid > last_valid`.
    StartBiggerThanEndRound,
    /// `key_lifetime == 0`.
    KeyLifetimeIsZero,
    /// Underlying Falcon C library returned an error during keygen.
    FalconKeygen(String),
    /// Underlying merkle-tree builder returned an error.
    MerkleTree(String),
}

impl std::fmt::Display for MssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StartBiggerThanEndRound => write!(
                f,
                "cannot create Merkle Signature Scheme because end round is smaller then start round"
            ),
            Self::KeyLifetimeIsZero => write!(f, "received zero KeyLifetime"),
            Self::FalconKeygen(msg) => write!(f, "falcon keygen failed: {msg}"),
            Self::MerkleTree(msg) => write!(f, "merkle tree build failed: {msg}"),
        }
    }
}

impl std::error::Error for MssError {}

/// A Falcon-1024 ephemeral signer.
///
/// Mirrors `crypto.FalconSigner` — owns both the public and private key bytes
/// so a single value can both sign and report its verifier. The on-wire
/// representation is the raw `(pk_bytes, sk_bytes)` pair produced by
/// [`algo_falcon::falcon_keygen`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FalconSigner {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

impl FalconSigner {
    /// Raw Falcon-1024 public key bytes (1793 bytes).
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Raw Falcon-1024 private key bytes (2305 bytes).
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }
}

/// `(round, key)` pair returned by [`Secrets::get_all_keys`].
///
/// Mirrors `merklesignature.KeyRoundPair`.
#[derive(Clone, Debug)]
pub struct KeyRoundPair {
    pub round: u64,
    pub key: FalconSigner,
}

/// Verifier-side metadata that ships alongside the ephemeral keys.
///
/// Mirrors `merklesignature.SignerContext`.
#[derive(Clone, Debug)]
pub struct SignerContext {
    pub first_valid: u64,
    pub key_lifetime: u64,
    pub tree: Tree,
}

impl SignerContext {
    /// Derive the long-term verifier (commitment + key_lifetime).
    ///
    /// Mirrors `(*SignerContext).GetVerifier`.
    pub fn get_verifier(&self) -> Verifier {
        let mut commitment = [0u8; COMMITMENT_SIZE];
        let root = self.tree.root();
        // Empty tree returns a zero-length digest; pad/truncate to digest size.
        let n = root.len().min(COMMITMENT_SIZE);
        commitment[..n].copy_from_slice(&root[..n]);
        Verifier {
            commitment,
            key_lifetime: self.key_lifetime,
        }
    }
}

/// Long-term verifier for an MSS commitment.
///
/// Mirrors `merklesignature.Verifier`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verifier {
    pub commitment: [u8; COMMITMENT_SIZE],
    pub key_lifetime: u64,
}

/// Private MSS secrets — owns the ephemeral Falcon keys until the caller
/// persists them to disk (TASK-176) and drops the in-memory copy.
///
/// Mirrors `merklesignature.Secrets`.
#[derive(Debug)]
pub struct Secrets {
    pub ephemeral_keys: Vec<FalconSigner>,
    pub signer_context: SignerContext,
}

impl Secrets {
    /// Generate a fresh MSS key tree covering `[first_valid, last_valid]`
    /// at the given `key_lifetime`.
    ///
    /// Mirrors `merklesignature.New` (`merkleSignatureScheme.go:108-140`):
    ///
    /// 1. Validate inputs.
    /// 2. Compute the number of keys:
    ///    `last_valid/key_lifetime - (first_valid - 1)/key_lifetime`
    ///    (special-case: `first_valid == 0` adds 1 for round zero).
    /// 3. Parallel Falcon keygen via [`keys_builder`].
    /// 4. Build the vector commitment tree using sumhash512.
    pub fn new(first_valid: u64, last_valid: u64, key_lifetime: u64) -> Result<Self, MssError> {
        if first_valid > last_valid {
            return Err(MssError::StartBiggerThanEndRound);
        }
        if key_lifetime == 0 {
            return Err(MssError::KeyLifetimeIsZero);
        }

        let number_of_keys = if first_valid == 0 {
            last_valid / key_lifetime + 1
        } else {
            last_valid / key_lifetime - (first_valid - 1) / key_lifetime
        };

        let keys = keys_builder(number_of_keys)?;
        let array = CommittablePublicKeyArray {
            keys: &keys,
            first_valid,
            key_lifetime,
        };
        let factory = HashFactory::new(HashType::Sumhash);
        let tree = build_vector_commitment_tree(&array, factory)
            .map_err(|e| MssError::MerkleTree(format!("{e}")))?;

        Ok(Self {
            ephemeral_keys: keys,
            signer_context: SignerContext {
                first_valid,
                key_lifetime,
                tree,
            },
        })
    }

    /// Derive the long-term verifier.
    pub fn get_verifier(&self) -> Verifier {
        self.signer_context.get_verifier()
    }

    /// Return every `(round, ephemeral_key)` pair this signer owns.
    ///
    /// Mirrors `(*Secrets).GetAllKeys`. Pairs are returned in index order.
    pub fn get_all_keys(&self) -> Vec<KeyRoundPair> {
        self.ephemeral_keys
            .iter()
            .enumerate()
            .map(|(i, key)| KeyRoundPair {
                round: posdivs::index_to_round(
                    self.signer_context.first_valid,
                    self.signer_context.key_lifetime,
                    i as u64,
                ),
                key: key.clone(),
            })
            .collect()
    }

    /// Return the ephemeral key covering `round`, if one exists.
    ///
    /// Mirrors `(*Secrets).GetSigner` semantics: a request for any round
    /// floors to the key's first round in its key-lifetime window
    /// (`firstRoundInKeyLifetime`) and indexes into `ephemeral_keys`. So
    /// `get_key(300)` for `Secrets::new(256, 512, 256)` returns the key
    /// at the round-256 slot.
    ///
    /// Returns `None` only when the round falls outside the participation
    /// window (i.e. before the first owned key's round, or past the end
    /// of `ephemeral_keys`).
    pub fn get_key(&self, round: u64) -> Option<&FalconSigner> {
        let first_valid = self.signer_context.first_valid;
        let key_lifetime = self.signer_context.key_lifetime;
        if key_lifetime == 0 {
            return None;
        }
        let valid_round = posdivs::first_round_in_key_lifetime(round, key_lifetime);
        let rofi = posdivs::round_of_first_index(first_valid, key_lifetime);
        if valid_round < rofi {
            return None;
        }
        let idx = posdivs::round_to_index(first_valid, valid_round, key_lifetime) as usize;
        self.ephemeral_keys.get(idx)
    }
}
