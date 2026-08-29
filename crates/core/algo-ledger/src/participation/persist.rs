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

//! Partkey sqlite writer — `Persist` + `PersistNewParent`.
//!
//! Mirrors `../go-algorand/data/account/participation.go:281-305` and
//! `:211-217` (v4.6.0-stable). Owns the single-row `ParticipationAccount`
//! INSERT (under a fresh-install schema) and the `parent` UPDATE used by
//! `algokey part reparent` (TASK-181).
//!
//! StateProofKeys table writes are owned by TASK-176 — this module only
//! writes the `stateProof` BLOB column on `ParticipationAccount` (the
//! `merklesig::Secrets` metadata blob; ephemeral Falcon keys live in the
//! sibling table).

use algo_consensus_crypto::VrfPubkey;
use algo_types::Address;
use rusqlite::params;
use thiserror::Error;

use crate::erasable_db::ErasableDb;
use crate::participation::install::{part_install_database, InstallError};
use crate::participation::stateproof_persist::{persist_secrets, StateProofPersistError};
use crate::participation::Participation;

/// Errors from [`persist_participation`] / [`persist_new_parent`].
#[derive(Debug, Error)]
pub enum PersistError {
    /// Underlying sqlite write failure.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Schema install failed (table create conflict, etc.).
    #[error("install: {0}")]
    Install(#[from] InstallError),
    /// StateProofKeys persistence (per-row INSERT) failed.
    #[error("state proof keys: {0}")]
    StateProofPersist(#[from] StateProofPersistError),
}

/// Persist a [`Participation`] into an empty partkey DB.
///
/// Mirrors Go's `(PersistedParticipation).PersistWithSecrets` chain
/// (`participation.go:281-305` + `persistentMerkleSignatureScheme.go::Persist`):
///
/// 1. First tx: install the partkey schema + INSERT the single
///    `ParticipationAccount` row with msgpack-encoded VRF, Voting and
///    StateProof-metadata blobs (mirrors `Persist`).
/// 2. Second tx (if `part.state_proof_secrets` is `Some`): install the
///    StateProofKeys table and INSERT one row per ephemeral Falcon key
///    (mirrors `(*Secrets).Persist`).
///
/// Go runs the two writes in separate `Atomic` blocks — we follow the
/// same boundary so a state-proof-persist failure leaves the
/// `ParticipationAccount` row written (matches Go behaviour). A
/// participation with `state_proof_secrets == None` skips the second
/// transaction and produces a DB without the StateProofKeys table —
/// matches Go's behaviour for participations generated without state
/// proof support.
pub fn persist_participation(
    db: &mut ErasableDb,
    part: &Participation,
) -> Result<(), PersistError> {
    let raw_vrf = encode_vrf_blob(&part.vrf.pk, part.vrf.sk.seed());
    let raw_voting = part.voting.to_msgpack();
    let raw_state_proof = part
        .state_proof_secrets
        .as_ref()
        .map(|s| s.to_msgpack())
        .unwrap_or_default();

    let tx = db.conn_mut().transaction()?;
    part_install_database(&tx)?;
    tx.execute(
        "INSERT INTO ParticipationAccount \
         (parent, vrf, voting, firstValid, lastValid, keyDilution, stateProof) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            &part.parent.0[..],
            &raw_vrf,
            &raw_voting,
            part.first_valid.0 as i64,
            part.last_valid.0 as i64,
            part.key_dilution as i64,
            &raw_state_proof,
        ],
    )?;
    tx.commit()?;

    // Second transaction (mirrors Go's PersistWithSecrets chain): when
    // the participation owns state-proof secrets, also persist the
    // ephemeral Falcon keys into the StateProofKeys table.
    if let Some(ref secrets) = part.state_proof_secrets {
        // Persist only when the secrets actually carry ephemeral keys
        // (zero-key windows produce no rows). A non-empty key vector with
        // a zero key_lifetime is the only configuration that errors —
        // surface that as a PersistError.
        persist_secrets(db, secrets)?;
    }
    Ok(())
}

/// Reparent the persisted participation row.
///
/// Mirrors `(PersistedParticipation).PersistNewParent` in
/// `participation.go:211-217`: a bare `UPDATE ParticipationAccount SET
/// parent = ?`, no WHERE clause (the table is single-row by design).
pub fn persist_new_parent(db: &mut ErasableDb, new_parent: Address) -> Result<(), PersistError> {
    let tx = db.conn_mut().transaction()?;
    tx.execute(
        "UPDATE ParticipationAccount SET parent = ?1",
        params![&new_parent.0[..]],
    )?;
    tx.commit()?;
    Ok(())
}

/// Encode a `VrfKeypair` into Go's `crypto.VRFSecrets` msgpack format:
/// a 2-entry fixmap `{PK: bin32(public), SK: bin64(seed || public)}`.
///
/// Sort order: `"PK"` before `"SK"` (Go's `codec` emits map entries in
/// alphabetical key order); both keys are 2 bytes so `fixstr` is fine.
/// The 64-byte SK encoding mirrors libsodium's secret key layout
/// (`seed || derived_public_key`), matching what the reader expects in
/// [`super::restore::decode_vrf_blob`].
fn encode_vrf_blob(pk: &VrfPubkey, seed: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 1 + 2 + 2 + 32 + 1 + 2 + 2 + 64);
    // fixmap(2)
    buf.push(0x82);
    // "PK" → bin32
    buf.extend_from_slice(&[0xa2, b'P', b'K', 0xc4, 0x20]);
    buf.extend_from_slice(&pk.0);
    // "SK" → bin64 (seed || public)
    buf.extend_from_slice(&[0xa2, b'S', b'K', 0xc4, 0x40]);
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&pk.0);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_consensus_crypto::VrfPrivkey;

    #[test]
    fn encode_vrf_blob_layout_matches_reader_expectation() {
        let seed = [0xab_u8; 32];
        let pk = VrfPrivkey::from_seed(seed).pubkey();
        let blob = encode_vrf_blob(&pk, &seed);

        // 1 fixmap header + 2 ("PK" key) + 2 (bin8 hdr) + 32 + 2 ("SK") + 2 + 64
        assert_eq!(blob.len(), 1 + 5 + 32 + 5 + 64);
        assert_eq!(blob[0], 0x82, "fixmap(2)");
        assert_eq!(&blob[1..3], &[0xa2, b'P']);
        assert_eq!(blob[3], b'K');
        assert_eq!(blob[4], 0xc4, "bin8");
        assert_eq!(blob[5], 0x20, "len 32");
        assert_eq!(&blob[6..38], &pk.0);
        // SK
        assert_eq!(&blob[38..41], &[0xa2, b'S', b'K']);
        assert_eq!(blob[41], 0xc4);
        assert_eq!(blob[42], 0x40, "len 64");
        assert_eq!(&blob[43..75], &seed);
        assert_eq!(&blob[75..107], &pk.0);
    }
}
