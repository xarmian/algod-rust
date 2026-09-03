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

//! Consensus-layer cryptographic primitives for algod-rust.
//!
//! This crate provides:
//! - **VRF** (Verifiable Random Function) prove/verify operations needed for
//!   Algorand consensus participation, following ECVRF-ED25519-SHA512-Elligator2
//!   (draft-irtf-cfrg-vrf-03).
//! - **One-time signatures (OTS)** — a two-level ed25519 ephemeral key tree
//!   with forward-secure deletion, matching go-algorand's `crypto/onetimesig.go`.
//! - **Sortition** — VRF-based committee selection.

mod f128;
pub mod kdf;
pub mod light_block_header;
pub mod merklearray;
pub mod merklesig;
pub mod merklesignature;
pub mod multisig;
pub mod onetimesig;
pub mod passphrase;
pub mod sortition;
pub mod stateproof;
pub mod sumhash;
pub mod vrf;

pub use kdf::{scrypt_key, ScryptError};

pub use multisig::{
    multisig_addr_gen, multisig_assemble, multisig_preimage_from_pks, multisig_sign,
};
pub use passphrase::{key_to_mnemonic, mnemonic_to_key, PassphraseError};

pub use onetimesig::{
    one_time_id_for_round, verify_one_time_signature, OneTimeSignature, OneTimeSignatureIdentifier,
    OneTimeSignatureSecrets, OneTimeSignatureSubkeyBatchID, OneTimeSignatureSubkeyOffsetID,
};
pub use vrf::{VrfKeypair, VrfOutput, VrfPrivkey, VrfProof, VrfPubkey};
