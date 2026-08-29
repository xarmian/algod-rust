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

//! Participation key persistence (SQLite-backed store).
//!
//! Matches go-algorand's `data/account/participationRegistry.go` schema
//! with `Keysets` and `Rolling` tables joined by an auto-increment primary key.
//!
//! # Security
//!
//! **The SQLite database file contains raw private key material** (VRF seeds,
//! ed25519 signing keys for voting). It should be protected with filesystem
//! permissions (e.g., mode 0600) and ideally stored on an encrypted volume.
//! This matches go-algorand's storage model.
//!
//! # Blob serialization
//!
//! - **VRF**: stored as the raw 32-byte seed. Reconstructed via
//!   `VrfKeypair::from_seed`.
//! - **Voting secrets**: serialized via `OneTimeSignatureSecrets::to_msgpack()`
//!   and deserialized via `OneTimeSignatureSecrets::from_msgpack()`. This allows
//!   full round-trip persistence including forward-secure key deletion state.
//! - **State proof**: stored as raw bytes (opaque blob).

use std::path::Path;

use algo_consensus_crypto::merklesig::{self, index_to_round, FalconSigner};
use algo_consensus_crypto::{OneTimeSignatureSecrets, VrfKeypair};
use algo_types::{Address, Round};
use rusqlite::{params, Connection, OptionalExtension};

use super::{Participation, ParticipationAction, ParticipationID, ParticipationRecord};

// ---------------------------------------------------------------------------
// Schema DDL
// ---------------------------------------------------------------------------

const CREATE_KEYSETS: &str = "
CREATE TABLE IF NOT EXISTS Keysets (
    pk              INTEGER PRIMARY KEY NOT NULL,
    participationID BLOB NOT NULL UNIQUE,
    account         BLOB NOT NULL,
    firstValidRound INTEGER NOT NULL,
    lastValidRound  INTEGER NOT NULL,
    keyDilution     INTEGER NOT NULL,
    vrf             BLOB,
    stateProof      BLOB
)";

const CREATE_ROLLING: &str = "
CREATE TABLE IF NOT EXISTS Rolling (
    pk                        INTEGER PRIMARY KEY NOT NULL,
    lastVoteRound             INTEGER,
    lastBlockProposalRound    INTEGER,
    lastStateProofRound       INTEGER,
    effectiveFirstRound       INTEGER,
    effectiveLastRound        INTEGER,
    voting                    BLOB
)";

const CREATE_STATE_PROOF_KEYS: &str = "
CREATE TABLE IF NOT EXISTS StateProofKeys (
    pk    INTEGER NOT NULL,
    round INTEGER NOT NULL,
    key   BLOB    NOT NULL,
    PRIMARY KEY (pk, round)
)";

// ---------------------------------------------------------------------------
// SQL statements
// ---------------------------------------------------------------------------

const INSERT_KEYSET: &str = "
INSERT INTO Keysets (participationID, account, firstValidRound, lastValidRound, keyDilution, vrf, stateProof)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";

const INSERT_ROLLING: &str = "INSERT INTO Rolling (pk, voting) VALUES (?1, ?2)";

const SELECT_RECORDS: &str = "
SELECT
    k.participationID, k.account, k.firstValidRound, k.lastValidRound, k.keyDilution,
    k.vrf, k.stateProof,
    r.lastVoteRound, r.lastBlockProposalRound, r.lastStateProofRound,
    r.effectiveFirstRound, r.effectiveLastRound, r.voting
FROM Keysets k
INNER JOIN Rolling r ON k.pk = r.pk";

const SELECT_PK: &str = "SELECT pk FROM Keysets WHERE participationID = ?1 LIMIT 1";

const DELETE_KEYSET: &str = "DELETE FROM Keysets WHERE pk = ?1";
const DELETE_ROLLING: &str = "DELETE FROM Rolling WHERE pk = ?1";
const DELETE_STATE_PROOF_KEYS: &str = "DELETE FROM StateProofKeys WHERE pk = ?1";

const INSERT_STATE_PROOF_KEY: &str =
    "INSERT INTO StateProofKeys (pk, round, key) VALUES (?1, ?2, ?3)";
const SELECT_STATE_PROOF_KEYS: &str =
    "SELECT round, key FROM StateProofKeys WHERE pk = ?1 ORDER BY round ASC";
const DELETE_STATE_PROOF_KEYS_BEFORE: &str =
    "DELETE FROM StateProofKeys WHERE pk = ?1 AND round < ?2";

// ---------------------------------------------------------------------------
// ParticipationStore
// ---------------------------------------------------------------------------

/// SQLite-backed participation key registry.
///
/// Mirrors go-algorand's `participationDB` with synchronous operations
/// (no background write thread).
pub struct ParticipationStore {
    conn: Connection,
}

impl ParticipationStore {
    /// Create a new store wrapping an existing connection.
    ///
    /// Creates the `Keysets` and `Rolling` tables if they do not exist.
    pub fn new(conn: Connection) -> Result<Self, rusqlite::Error> {
        // The registry holds raw private key material (VRF seeds, ed25519
        // voting keys, Falcon state-proof keys). Enable `secure_delete` so that
        // when a key is removed (`delete` / `delete_expired` /
        // `delete_state_proof_keys_before`) SQLite zeroes the freed pages
        // instead of leaving the secrets recoverable in the file's free list.
        // Mirrors go-algorand's erasable participation accessor
        // (`secure_delete=ON`, `../go-algorand/util/db/dbutil.go` /
        // `node.go:868`).
        conn.execute_batch("PRAGMA secure_delete = ON;")?;
        conn.execute_batch(CREATE_KEYSETS)?;
        conn.execute_batch(CREATE_ROLLING)?;
        conn.execute_batch(CREATE_STATE_PROOF_KEYS)?;
        Ok(Self { conn })
    }

    /// Open (or create) a store backed by the given file path.
    ///
    /// The database holds raw private key material (VRF seeds, ed25519 voting
    /// keys, Falcon state-proof keys), so on unix the file is restricted to
    /// `0600` (owner read/write only) — matching go-algorand, which opens the
    /// participation registry via an erasable accessor with restricted
    /// permissions (`../go-algorand/node/node.go:868`). The chmod is best-effort
    /// idempotent: it runs on every open, tightening a file created under a
    /// looser umask on a prior run.
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            // Only attempt the chmod for a real on-disk file. Failures here are
            // non-fatal to opening the store but indicate the key DB may be
            // more permissive than intended, so surface them.
            if path.exists() {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
                    |e| {
                        rusqlite::Error::SqliteFailure(
                            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
                            Some(format!(
                                "restricting participation registry permissions to 0600: {e}"
                            )),
                        )
                    },
                )?;
            }
        }
        Self::new(conn)
    }

    /// Open an in-memory store (useful for tests).
    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        Self::new(conn)
    }

    // -- CRUD ---------------------------------------------------------------

    /// Insert a participation key, returning its computed `ParticipationID`.
    ///
    /// The VRF seed (32 bytes) is stored in the `vrf` column.
    /// Voting secrets are serialized via `OneTimeSignatureSecrets::to_msgpack()`
    /// and stored as a blob in the Rolling table.
    /// State proof secrets (if any) are stored as-is.
    ///
    /// Returns an error if a key with the same `ParticipationID` already exists
    /// (enforced by the UNIQUE constraint on `participationID`).
    pub fn insert(
        &self,
        participation: &Participation,
    ) -> Result<ParticipationID, rusqlite::Error> {
        let id = participation.id();

        // VRF: store the 32-byte seed so we can reconstruct later.
        let vrf_seed = participation.vrf.sk.seed().to_vec();

        // Voting: serialize via canonical msgpack encoding.
        let voting_blob: Vec<u8> = participation.voting.to_msgpack();

        // State proof: serialize the SignerContext (without ephemeral keys)
        // to store in the Keysets table.
        let state_proof_blob: Option<Vec<u8>> = participation
            .state_proof_secrets
            .as_ref()
            .map(|s| s.to_msgpack());

        let tx = self.conn.unchecked_transaction()?;

        tx.execute(
            INSERT_KEYSET,
            params![
                id.0.as_slice(),
                participation.parent.0.as_slice(),
                participation.first_valid.0 as i64,
                participation.last_valid.0 as i64,
                participation.key_dilution as i64,
                vrf_seed,
                state_proof_blob,
            ],
        )?;

        let pk = tx.last_insert_rowid();

        tx.execute(INSERT_ROLLING, params![pk, voting_blob])?;

        // Persist individual state proof keys to the StateProofKeys table.
        if let Some(ref secrets) = participation.state_proof_secrets {
            Self::persist_state_proof_keys_in_tx(&tx, pk, secrets)?;
        }

        tx.commit()?;

        Ok(id)
    }

    /// Get a participation record by ID (metadata only, no secrets).
    pub fn get(
        &self,
        id: &ParticipationID,
    ) -> Result<Option<ParticipationRecord>, rusqlite::Error> {
        let sql = format!("{SELECT_RECORDS} WHERE k.participationID = ?1");
        self.conn
            .query_row(&sql, params![id.0.as_slice()], Self::scan_record)
            .optional()
    }

    /// Get all participation records (metadata only).
    pub fn get_all(&self) -> Result<Vec<ParticipationRecord>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(SELECT_RECORDS)?;
        let rows = stmt.query_map([], Self::scan_record)?;
        let mut records = Vec::new();
        for r in rows {
            records.push(r?);
        }
        Ok(records)
    }

    /// Get a participation record (metadata only) for a specific round.
    ///
    /// Returns `None` if the key is not found or the round is outside the
    /// valid range.
    ///
    /// For a full `Participation` with signing-capable voting secrets, use
    /// [`get_for_round`](Self::get_for_round) instead.
    pub fn get_record_for_round(
        &self,
        id: &ParticipationID,
        round: Round,
    ) -> Result<Option<ParticipationRecord>, rusqlite::Error> {
        let sql = format!(
            "{SELECT_RECORDS} WHERE k.participationID = ?1 AND k.firstValidRound <= ?2 AND k.lastValidRound >= ?2"
        );
        self.conn
            .query_row(
                &sql,
                params![id.0.as_slice(), round.0 as i64],
                Self::scan_record,
            )
            .optional()
    }

    /// Get a full `Participation` (with signing-capable voting secrets) for a
    /// specific round.
    ///
    /// Queries both Keysets and Rolling tables by participation ID, filters by
    /// round range (`first_valid <= round <= last_valid`), deserializes the
    /// voting blob via `OneTimeSignatureSecrets::from_msgpack()`, and
    /// reconstructs the VRF keypair from the stored seed.
    ///
    /// Returns `None` if the key is not found, the round is outside the valid
    /// range, or the voting blob is empty/missing (legacy records).
    pub fn get_for_round(
        &self,
        id: &ParticipationID,
        round: Round,
    ) -> Result<Option<Participation>, rusqlite::Error> {
        let sql = format!(
            "{SELECT_RECORDS} WHERE k.participationID = ?1 AND k.firstValidRound <= ?2 AND k.lastValidRound >= ?2"
        );
        let result = self
            .conn
            .query_row(&sql, params![id.0.as_slice(), round.0 as i64], |row| {
                let raw_account: Vec<u8> = row.get(1)?;
                let first_valid: i64 = row.get(2)?;
                let last_valid: i64 = row.get(3)?;
                let key_dilution: i64 = row.get(4)?;
                let raw_vrf: Option<Vec<u8>> = row.get(5)?;
                let raw_state_proof: Option<Vec<u8>> = row.get(6)?;
                let voting_blob: Option<Vec<u8>> = row.get(12)?;

                Ok((
                    raw_account,
                    first_valid,
                    last_valid,
                    key_dilution,
                    raw_vrf,
                    raw_state_proof,
                    voting_blob,
                ))
            })
            .optional()?;

        let (
            raw_account,
            first_valid,
            last_valid,
            key_dilution,
            raw_vrf,
            raw_state_proof,
            voting_blob,
        ) = match result {
            Some(r) => r,
            None => return Ok(None),
        };

        // Voting blob must be present and non-empty.
        let voting_data = match voting_blob {
            Some(ref blob) if !blob.is_empty() => blob,
            _ => return Ok(None),
        };

        // Deserialize voting secrets.
        let voting = OneTimeSignatureSecrets::from_msgpack(voting_data).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                12,
                rusqlite::types::Type::Blob,
                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            )
        })?;

        // Reconstruct VRF keypair from seed.
        let vrf = match raw_vrf {
            Some(ref blob) if blob.len() == 32 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(blob);
                VrfKeypair::from_seed(seed)
            }
            _ => return Ok(None),
        };

        // Reconstruct account address.
        if raw_account.len() != 32 {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Blob,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "account address: expected 32 bytes, got {}",
                        raw_account.len()
                    ),
                )),
            ));
        }
        let mut parent = Address([0u8; 32]);
        parent.0.copy_from_slice(&raw_account);

        // Reconstruct state proof secrets from the SignerContext + StateProofKeys.
        let state_proof_secrets = if let Some(ref sp_blob) = raw_state_proof {
            if !sp_blob.is_empty() {
                match merklesig::Secrets::from_msgpack(sp_blob) {
                    Ok((mut secrets, _)) => {
                        // Look up the pk for this participation ID to load
                        // the ephemeral keys from StateProofKeys table.
                        let part_id_blob = id.0.as_slice();
                        let pk_opt: Option<i64> = self
                            .conn
                            .query_row(SELECT_PK, params![part_id_blob], |row| row.get(0))
                            .optional()?;
                        if let Some(pk) = pk_opt {
                            let (offset, keys) = Self::restore_state_proof_keys(
                                &self.conn,
                                pk,
                                secrets.signer_context.first_valid,
                                secrets.signer_context.key_lifetime,
                            )?;
                            secrets.ephemeral_keys = keys;
                            secrets.first_key_offset = offset;
                        }
                        Some(secrets)
                    }
                    Err(_) => None,
                }
            } else {
                None
            }
        } else {
            None
        };

        Ok(Some(Participation {
            parent,
            vrf,
            voting,
            first_valid: Round(first_valid as u64),
            last_valid: Round(last_valid as u64),
            key_dilution: key_dilution as u64,
            state_proof_secrets,
        }))
    }

    /// Update the serialized voting secrets for a participation key.
    ///
    /// Serializes `secrets` via `OneTimeSignatureSecrets::to_msgpack()` and
    /// writes the result to the `voting` BLOB in the Rolling table.
    ///
    /// This is used for forward-secure deletion persistence: after calling
    /// `OneTimeSignatureSecrets::delete_before()`, the mutated secrets are
    /// persisted back to SQLite so that old ephemeral keys are irrecoverably
    /// deleted from storage.
    pub fn update_voting_secrets(
        &self,
        id: &ParticipationID,
        secrets: &OneTimeSignatureSecrets,
    ) -> Result<(), rusqlite::Error> {
        let pk: Option<i64> = self
            .conn
            .query_row(SELECT_PK, params![id.0.as_slice()], |row| row.get(0))
            .optional()?;

        let pk = match pk {
            Some(pk) => pk,
            None => return Err(rusqlite::Error::QueryReturnedNoRows),
        };

        let voting_blob = secrets.to_msgpack();
        self.conn.execute(
            "UPDATE Rolling SET voting = ?1 WHERE pk = ?2",
            params![voting_blob, pk],
        )?;

        Ok(())
    }

    /// Delete a participation key by ID. Returns `true` if a row was deleted.
    pub fn delete(&self, id: &ParticipationID) -> Result<bool, rusqlite::Error> {
        let pk: Option<i64> = self
            .conn
            .query_row(SELECT_PK, params![id.0.as_slice()], |row| row.get(0))
            .optional()?;

        match pk {
            None => Ok(false),
            Some(pk) => {
                let tx = self.conn.unchecked_transaction()?;
                tx.execute(DELETE_STATE_PROOF_KEYS, params![pk])?;
                tx.execute(DELETE_ROLLING, params![pk])?;
                let deleted = tx.execute(DELETE_KEYSET, params![pk])?;
                tx.commit()?;
                Ok(deleted > 0)
            }
        }
    }

    // -- Lifecycle operations -----------------------------------------------

    /// Delete all records where `lastValidRound < latest_round`.
    ///
    /// Returns the number of records deleted.
    pub fn delete_expired(&self, latest_round: Round) -> Result<usize, rusqlite::Error> {
        // Find all expired PKs.
        let mut stmt = self
            .conn
            .prepare("SELECT k.pk FROM Keysets k WHERE k.lastValidRound < ?1")?;
        let pks: Vec<i64> = stmt
            .query_map(params![latest_round.0 as i64], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;

        let count = pks.len();
        if count > 0 {
            let tx = self.conn.unchecked_transaction()?;
            for pk in pks {
                tx.execute(DELETE_STATE_PROOF_KEYS, params![pk])?;
                tx.execute(DELETE_ROLLING, params![pk])?;
                tx.execute(DELETE_KEYSET, params![pk])?;
            }
            tx.commit()?;
        }
        Ok(count)
    }

    /// Returns `true` if any key has a validity window overlapping `[from, to]`.
    pub fn has_live_keys(&self, from: Round, to: Round) -> Result<bool, rusqlite::Error> {
        let exists: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM Keysets WHERE lastValidRound >= ?1 AND firstValidRound <= ?2)",
            params![from.0 as i64, to.0 as i64],
            |row| row.get(0),
        )?;
        Ok(exists)
    }

    /// Register a key as active: set `effectiveFirst` and `effectiveLast`.
    ///
    /// `on_round` must be within the key's `[firstValid, lastValid]` range.
    ///
    /// Matches Go's `Register` logic: deactivates any currently-active keys
    /// for the same account by setting their `effectiveLast = on_round - 1`.
    pub fn register(&self, id: &ParticipationID, on_round: Round) -> Result<(), rusqlite::Error> {
        let pk: Option<i64> = self
            .conn
            .query_row(SELECT_PK, params![id.0.as_slice()], |row| row.get(0))
            .optional()?;

        let pk = match pk {
            Some(pk) => pk,
            None => {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
        };

        // Look up first/last valid and account for range check.
        let (first_valid, last_valid, account_blob): (i64, i64, Vec<u8>) = self.conn.query_row(
            "SELECT firstValidRound, lastValidRound, account FROM Keysets WHERE pk = ?1",
            params![pk],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

        let on = on_round.0 as i64;
        if on < first_valid || on > last_valid {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "round {} outside valid range [{}, {}]",
                on, first_valid, last_valid,
            )));
        }

        let tx = self.conn.unchecked_transaction()?;

        // Deactivate other currently-active keys for the same account.
        // A key is "active" if effectiveLastRound != 0 AND effectiveFirstRound <= on
        // AND on <= effectiveLastRound.
        tx.execute(
            "UPDATE Rolling SET effectiveLastRound = ?1
             WHERE pk IN (
                 SELECT k.pk FROM Keysets k
                 INNER JOIN Rolling r ON k.pk = r.pk
                 WHERE k.account = ?2
                   AND k.pk != ?3
                   AND r.effectiveLastRound IS NOT NULL
                   AND r.effectiveLastRound != 0
                   AND r.effectiveFirstRound <= ?4
                   AND ?4 <= r.effectiveLastRound
             )",
            params![on - 1, account_blob, pk, on],
        )?;

        // Mark the new key as registered.
        tx.execute(
            "UPDATE Rolling SET effectiveFirstRound = ?1, effectiveLastRound = ?2 WHERE pk = ?3",
            params![on, last_valid, pk],
        )?;

        tx.commit()?;

        Ok(())
    }

    /// Record that a participation action was taken for a key at a given round.
    pub fn record(
        &self,
        id: &ParticipationID,
        round: Round,
        action: ParticipationAction,
    ) -> Result<(), rusqlite::Error> {
        let pk: Option<i64> = self
            .conn
            .query_row(SELECT_PK, params![id.0.as_slice()], |row| row.get(0))
            .optional()?;

        let pk = match pk {
            Some(pk) => pk,
            None => {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
        };

        let round_val = round.0 as i64;
        let sql = match action {
            ParticipationAction::Vote => "UPDATE Rolling SET lastVoteRound = ?1 WHERE pk = ?2",
            ParticipationAction::BlockProposal => {
                "UPDATE Rolling SET lastBlockProposalRound = ?1 WHERE pk = ?2"
            }
            ParticipationAction::StateProof => {
                "UPDATE Rolling SET lastStateProofRound = ?1 WHERE pk = ?2"
            }
        };

        self.conn.execute(sql, params![round_val, pk])?;
        Ok(())
    }

    // -- Filtered queries ---------------------------------------------------

    /// Get participation records valid for a voting round, available as of `key_round`.
    ///
    /// Filters in SQL rather than loading all records:
    /// - `firstValidRound <= voting_round AND lastValidRound >= voting_round`
    /// - `effectiveFirstRound <= key_round` (when effective_first is set)
    ///
    /// Matches Go's `VotingKeys(votingRound, keysRound)`.
    pub fn get_for_voting_round(
        &self,
        voting_round: Round,
        key_round: Round,
    ) -> Result<Vec<ParticipationRecord>, rusqlite::Error> {
        let sql = format!(
            "{SELECT_RECORDS} WHERE k.firstValidRound <= ?1 AND k.lastValidRound >= ?1
             AND (r.effectiveFirstRound IS NULL OR r.effectiveFirstRound = 0 OR r.effectiveFirstRound <= ?2)
             AND (r.effectiveLastRound IS NULL OR r.effectiveLastRound = 0 OR r.effectiveLastRound >= ?1)"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![voting_round.0 as i64, key_round.0 as i64],
            Self::scan_record,
        )?;
        let mut records = Vec::new();
        for r in rows {
            records.push(r?);
        }
        Ok(records)
    }

    /// Record a participation action for an account, resolving the active key.
    ///
    /// Finds the active participation key for `account` at `round` (where
    /// `effectiveFirst <= round <= effectiveLast`), then records the action.
    ///
    /// Returns an error if no active key is found or multiple active keys exist.
    ///
    /// Matches Go's `Record(account, round, action)`.
    pub fn record_for_account(
        &self,
        account: &Address,
        round: Round,
        action: ParticipationAction,
    ) -> Result<(), rusqlite::Error> {
        let sql = "SELECT k.pk FROM Keysets k
                   INNER JOIN Rolling r ON k.pk = r.pk
                   WHERE k.account = ?1
                     AND r.effectiveLastRound IS NOT NULL
                     AND r.effectiveLastRound != 0
                     AND r.effectiveFirstRound <= ?2
                     AND ?2 <= r.effectiveLastRound";
        let mut stmt = self.conn.prepare(sql)?;
        let pks: Vec<i64> = stmt
            .query_map(params![account.0.as_slice(), round.0 as i64], |row| {
                row.get(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let pk = match pks.len() {
            0 => {
                // No active key for this account — no-op per Go behavior.
                return Ok(());
            }
            1 => pks[0],
            _ => {
                // Multiple active keys is a bug — return error like Go.
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
        };

        let round_val = round.0 as i64;
        let update_sql = match action {
            ParticipationAction::Vote => "UPDATE Rolling SET lastVoteRound = ?1 WHERE pk = ?2",
            ParticipationAction::BlockProposal => {
                "UPDATE Rolling SET lastBlockProposalRound = ?1 WHERE pk = ?2"
            }
            ParticipationAction::StateProof => {
                "UPDATE Rolling SET lastStateProofRound = ?1 WHERE pk = ?2"
            }
        };

        self.conn.execute(update_sql, params![round_val, pk])?;
        Ok(())
    }

    // -- State proof key persistence ----------------------------------------

    /// Persist individual Falcon keys from a `Secrets` to the `StateProofKeys`
    /// table, one row per key-round.
    ///
    /// Each key is stored as its msgpack-encoded `FalconSigner` blob.
    /// Matches Go's `Secrets.Persist()` in `persistentMerkleSignatureScheme.go`.
    fn persist_state_proof_keys_in_tx(
        tx: &rusqlite::Transaction<'_>,
        pk: i64,
        secrets: &merklesig::Secrets,
    ) -> Result<(), rusqlite::Error> {
        if secrets.signer_context.key_lifetime == 0 {
            return Ok(());
        }

        let mut round = index_to_round(
            secrets.signer_context.first_valid,
            secrets.signer_context.key_lifetime,
            0,
        );

        for key in &secrets.ephemeral_keys {
            let key_blob = key.to_msgpack();
            tx.execute(INSERT_STATE_PROOF_KEY, params![pk, round as i64, key_blob])?;
            round += secrets.signer_context.key_lifetime;
        }

        Ok(())
    }

    /// Restore all Falcon keys from the `StateProofKeys` table for the given
    /// internal primary key.
    ///
    /// Returns `(first_key_offset, keys)` where `first_key_offset` is the
    /// index of the first returned key relative to the original dense array
    /// (the array that starts at `round_to_index(first_valid, …, 0)`).
    /// Keys are ordered by round (ascending), matching Go's
    /// `Secrets.RestoreAllSecrets()`.
    ///
    /// After pruning via `delete_state_proof_keys_before`, the earliest
    /// remaining key may correspond to a later index than 0.  The offset
    /// is stored on `Secrets.first_key_offset` so that `get_key()` can
    /// translate a round-based index to the correct position in the
    /// (now shorter) vector without padding with dummy entries.
    fn restore_state_proof_keys(
        conn: &Connection,
        pk: i64,
        first_valid: u64,
        key_lifetime: u64,
    ) -> Result<(u64, Vec<FalconSigner>), rusqlite::Error> {
        let mut stmt = conn.prepare(SELECT_STATE_PROOF_KEYS)?;
        let rows = stmt.query_map(params![pk], |row| {
            let round: i64 = row.get(0)?;
            let key_blob: Vec<u8> = row.get(1)?;
            Ok((round as u64, key_blob))
        })?;

        let mut round_keys: Vec<(u64, FalconSigner)> = Vec::new();
        for row in rows {
            let (round, key_blob) = row?;
            let (signer, _) = FalconSigner::from_msgpack(&key_blob).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
                )
            })?;
            round_keys.push((round, signer));
        }

        if round_keys.is_empty() || key_lifetime == 0 {
            let keys = round_keys.into_iter().map(|(_, k)| k).collect();
            return Ok((0, keys));
        }

        // Compute how many index positions precede the first remaining key.
        let first_remaining_round = round_keys[0].0;
        let first_key_offset =
            merklesig::round_to_index(first_valid, first_remaining_round, key_lifetime);

        let keys = round_keys.into_iter().map(|(_, k)| k).collect();
        Ok((first_key_offset, keys))
    }

    /// Delete state proof keys for rounds before the given round.
    ///
    /// This is used for forward-secure deletion of state proof keys.
    /// Matches Go's `DeleteStateProofKeys(id, round)`.
    pub fn delete_state_proof_keys_before(
        &self,
        id: &ParticipationID,
        round: Round,
    ) -> Result<usize, rusqlite::Error> {
        let pk: Option<i64> = self
            .conn
            .query_row(SELECT_PK, params![id.0.as_slice()], |row| row.get(0))
            .optional()?;

        match pk {
            None => Ok(0),
            Some(pk) => {
                let deleted = self
                    .conn
                    .execute(DELETE_STATE_PROOF_KEYS_BEFORE, params![pk, round.0 as i64])?;
                Ok(deleted)
            }
        }
    }

    /// Append state proof keys to an existing participation key.
    ///
    /// Looks up the internal primary key from the `ParticipationID`, reads the
    /// `SignerContext` (for `first_valid` and `key_lifetime`) from the `Keysets`
    /// table, then inserts each `FalconSigner` key into the `StateProofKeys`
    /// table at the appropriate round.
    ///
    /// `keys` is a slice of `FalconSigner` values to append.  The round for
    /// each key is computed from the existing key count in the table (i.e.
    /// keys are appended starting after the last existing key).
    ///
    /// Mirrors go-algorand's `Registry.AppendKeys`.
    pub fn append_state_proof_keys(
        &self,
        id: &ParticipationID,
        keys: &[FalconSigner],
    ) -> Result<(), rusqlite::Error> {
        if keys.is_empty() {
            return Ok(());
        }

        let pk: i64 = self
            .conn
            .query_row(SELECT_PK, params![id.0.as_slice()], |row| row.get(0))?;

        // Read the SignerContext blob from the Keysets table to get first_valid
        // and key_lifetime. The column is NULL when state proofs are disabled.
        let ctx_blob: Option<Vec<u8>> = self.conn.query_row(
            "SELECT stateProof FROM Keysets WHERE pk = ?1",
            params![pk],
            |row| row.get(0),
        )?;

        let ctx_blob = match ctx_blob {
            Some(b) if !b.is_empty() => b,
            // No state proof context — nothing to append.
            _ => return Ok(()),
        };

        let (ctx, _) = merklesig::SignerContext::from_msgpack(&ctx_blob).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Blob,
                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            )
        })?;

        // key_lifetime of 0 means state proofs are disabled; no rounds to map
        // keys to. Matches Go's behavior where round computation would degenerate.
        if ctx.key_lifetime == 0 {
            return Ok(());
        }

        // Use a transaction so the COUNT and INSERTs are atomic — prevents
        // concurrent callers from computing the same starting round.
        let tx = self.conn.unchecked_transaction()?;

        // Determine the starting round for new keys. Use MAX(round) rather
        // than COUNT(*) so that pruned (deleted) early keys don't cause
        // collisions — after pruning, COUNT would undercount the index.
        let max_round: Option<i64> = tx.query_row(
            "SELECT MAX(round) FROM StateProofKeys WHERE pk = ?1",
            params![pk],
            |row| row.get(0),
        )?;

        let mut round = match max_round {
            Some(r) => r as u64 + ctx.key_lifetime,
            None => index_to_round(ctx.first_valid, ctx.key_lifetime, 0),
        };

        for key in keys {
            let key_blob = key.to_msgpack();
            tx.execute(INSERT_STATE_PROOF_KEY, params![pk, round as i64, key_blob])?;
            round += ctx.key_lifetime;
        }

        tx.commit()?;
        Ok(())
    }

    /// Append state proof keys carrying explicit rounds (a `(round, signer)`
    /// slice) to an existing participation key.
    ///
    /// Unlike [`append_state_proof_keys`](Self::append_state_proof_keys), which
    /// recomputes each round from the existing key count, this preserves the
    /// round attached to each key. It mirrors go-algorand's
    /// `appendKeysOp.apply` (`data/account/registeryDbOps.go:268`), which
    /// inserts `(pk, key.Round, encode(key.Key))` verbatim from the
    /// `StateProofKeys` (`[]KeyRoundPair`) wire body.
    ///
    /// Returns `Ok(false)` when no record matches `id` (matches Go's silent
    /// `sql.ErrNoRows` → "nothing to do" branch); `Ok(true)` once the keys are
    /// inserted.
    pub fn append_state_proof_keys_with_rounds(
        &self,
        id: &ParticipationID,
        keys: &[(u64, FalconSigner)],
    ) -> Result<bool, rusqlite::Error> {
        if keys.is_empty() {
            return Ok(false);
        }

        let pk: Option<i64> = self
            .conn
            .query_row(SELECT_PK, params![id.0.as_slice()], |row| row.get(0))
            .optional()?;
        let pk = match pk {
            Some(pk) => pk,
            None => return Ok(false),
        };

        let tx = self.conn.unchecked_transaction()?;
        for (round, key) in keys {
            let key_blob = key.to_msgpack();
            tx.execute(INSERT_STATE_PROOF_KEY, params![pk, *round as i64, key_blob])?;
        }
        tx.commit()?;
        Ok(true)
    }

    // -- Internal helpers ---------------------------------------------------

    /// Scan a single row from the joined `Keysets`/`Rolling` query into a
    /// `ParticipationRecord`.
    fn scan_record(row: &rusqlite::Row<'_>) -> Result<ParticipationRecord, rusqlite::Error> {
        // Column indices match SELECT_RECORDS:
        //  0: participationID  1: account  2: firstValidRound  3: lastValidRound
        //  4: keyDilution  5: vrf  6: stateProof
        //  7: lastVoteRound  8: lastBlockProposalRound  9: lastStateProofRound
        // 10: effectiveFirstRound  11: effectiveLastRound  12: voting

        let raw_id: Vec<u8> = row.get(0)?;
        let raw_account: Vec<u8> = row.get(1)?;
        let first_valid: i64 = row.get(2)?;
        let last_valid: i64 = row.get(3)?;
        let key_dilution: i64 = row.get(4)?;
        let raw_vrf: Option<Vec<u8>> = row.get(5)?;
        let raw_state_proof: Option<Vec<u8>> = row.get(6)?;
        let last_vote: Option<i64> = row.get(7)?;
        let last_block_proposal: Option<i64> = row.get(8)?;
        let last_state_proof: Option<i64> = row.get(9)?;
        let effective_first: Option<i64> = row.get(10)?;
        let effective_last: Option<i64> = row.get(11)?;
        let raw_voting: Option<Vec<u8>> = row.get(12)?;

        let mut participation_id = [0u8; 32];
        if raw_id.len() == 32 {
            participation_id.copy_from_slice(&raw_id);
        }

        let mut account = Address([0u8; 32]);
        if raw_account.len() == 32 {
            account.0.copy_from_slice(&raw_account);
        }

        // Reconstruct VRF public key from stored seed.
        let vrf_public_key = raw_vrf.and_then(|blob| {
            if blob.len() == 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&blob);
                let kp = VrfKeypair::from_seed(seed);
                Some(kp.pk)
            } else {
                None
            }
        });

        // Decode state proof verifier from the SignerContext msgpack blob.
        let state_proof_verifier = raw_state_proof.and_then(|blob| {
            if blob.is_empty() {
                return None;
            }
            match merklesig::SignerContext::from_msgpack(&blob) {
                Ok((ctx, _)) => Some(ctx.get_verifier()),
                Err(_) => None,
            }
        });

        // Extract the OTS verifier (vote_id) from the voting blob.
        // The voting blob is a msgpack-encoded OneTimeSignatureSecrets;
        // we decode it and extract the 32-byte master public key.
        let vote_id = raw_voting.and_then(|blob| {
            if blob.is_empty() {
                return None;
            }
            match OneTimeSignatureSecrets::from_msgpack(&blob) {
                Ok(secrets) => Some(secrets.verifier()),
                Err(_) => None,
            }
        });

        Ok(ParticipationRecord {
            participation_id: ParticipationID(participation_id),
            account,
            first_valid: Round(first_valid as u64),
            last_valid: Round(last_valid as u64),
            key_dilution: key_dilution as u64,
            last_vote: Round(last_vote.unwrap_or(0) as u64),
            last_block_proposal: Round(last_block_proposal.unwrap_or(0) as u64),
            last_state_proof: Round(last_state_proof.unwrap_or(0) as u64),
            effective_first: Round(effective_first.unwrap_or(0) as u64),
            effective_last: Round(effective_last.unwrap_or(0) as u64),
            vrf_public_key,
            vote_id,
            state_proof_verifier,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test `Participation` key.
    fn make_test_participation(
        seed_byte: u8,
        first: u64,
        last: u64,
        dilution: u64,
    ) -> Participation {
        let vrf = VrfKeypair::from_seed([seed_byte; 32]);
        let voting = OneTimeSignatureSecrets::generate(0, 10);
        Participation {
            parent: Address([seed_byte; 32]),
            vrf,
            voting,
            first_valid: Round(first),
            last_valid: Round(last),
            key_dilution: dilution,
            state_proof_secrets: None,
        }
    }

    #[test]
    fn roundtrip_insert_get() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation(1, 100, 1000, 32);
        let expected_id = part.id();

        let id = store.insert(&part).unwrap();
        assert_eq!(id, expected_id);

        let record = store.get(&id).unwrap().expect("should find record");
        assert_eq!(record.participation_id, id);
        assert_eq!(record.account, Address([1u8; 32]));
        assert_eq!(record.first_valid, Round(100));
        assert_eq!(record.last_valid, Round(1000));
        assert_eq!(record.key_dilution, 32);
        assert_eq!(record.last_vote, Round(0));
        assert_eq!(record.last_block_proposal, Round(0));

        // VRF public key should be reconstructed from seed.
        let expected_pk = VrfKeypair::from_seed([1u8; 32]).pk;
        assert_eq!(record.vrf_public_key, Some(expected_pk));
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let id = ParticipationID([99u8; 32]);
        assert!(store.get(&id).unwrap().is_none());
    }

    #[test]
    fn get_all() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let p1 = make_test_participation(1, 100, 200, 10);
        let p2 = make_test_participation(2, 300, 400, 20);

        store.insert(&p1).unwrap();
        store.insert(&p2).unwrap();

        let all = store.get_all().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn delete_key() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation(3, 100, 200, 10);
        let id = store.insert(&part).unwrap();

        assert!(store.get(&id).unwrap().is_some());
        let deleted = store.delete(&id).unwrap();
        assert!(deleted);
        assert!(store.get(&id).unwrap().is_none());
    }

    #[test]
    fn delete_nonexistent_returns_false() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let id = ParticipationID([42u8; 32]);
        assert!(!store.delete(&id).unwrap());
    }

    #[test]
    fn delete_expired_removes_old_keys() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let old = make_test_participation(1, 10, 50, 5);
        let current = make_test_participation(2, 100, 200, 10);

        store.insert(&old).unwrap();
        store.insert(&current).unwrap();

        // Delete keys expired before round 100.
        let count = store.delete_expired(Round(100)).unwrap();
        assert_eq!(count, 1);

        let all = store.get_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].account, Address([2u8; 32]));
    }

    #[test]
    fn has_live_keys_basic() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation(1, 100, 200, 10);
        store.insert(&part).unwrap();

        assert!(store.has_live_keys(Round(100), Round(200)).unwrap());
        assert!(store.has_live_keys(Round(150), Round(180)).unwrap());
        assert!(store.has_live_keys(Round(50), Round(150)).unwrap());
        assert!(!store.has_live_keys(Round(201), Round(300)).unwrap());
        assert!(!store.has_live_keys(Round(1), Round(99)).unwrap());
    }

    #[test]
    fn register_updates_effective_rounds() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation(1, 100, 200, 10);
        let id = store.insert(&part).unwrap();

        store.register(&id, Round(150)).unwrap();

        let record = store.get(&id).unwrap().unwrap();
        assert_eq!(record.effective_first, Round(150));
        assert_eq!(record.effective_last, Round(200));
    }

    #[test]
    fn register_out_of_range_fails() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation(1, 100, 200, 10);
        let id = store.insert(&part).unwrap();

        // Round 50 is before firstValid=100.
        assert!(store.register(&id, Round(50)).is_err());
        // Round 300 is after lastValid=200.
        assert!(store.register(&id, Round(300)).is_err());
    }

    #[test]
    fn record_vote_and_block_proposal() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation(1, 100, 200, 10);
        let id = store.insert(&part).unwrap();

        store
            .record(&id, Round(110), ParticipationAction::Vote)
            .unwrap();
        store
            .record(&id, Round(120), ParticipationAction::BlockProposal)
            .unwrap();
        store
            .record(&id, Round(130), ParticipationAction::StateProof)
            .unwrap();

        let record = store.get(&id).unwrap().unwrap();
        assert_eq!(record.last_vote, Round(110));
        assert_eq!(record.last_block_proposal, Round(120));
        assert_eq!(record.last_state_proof, Round(130));
    }

    #[test]
    fn get_record_for_round_within_range() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation(1, 100, 200, 10);
        let id = store.insert(&part).unwrap();

        let result = store.get_record_for_round(&id, Round(150)).unwrap();
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.account, Address([1u8; 32]));
        assert_eq!(r.first_valid, Round(100));
        assert_eq!(r.last_valid, Round(200));
    }

    #[test]
    fn get_record_for_round_outside_range() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation(1, 100, 200, 10);
        let id = store.insert(&part).unwrap();

        assert!(store
            .get_record_for_round(&id, Round(50))
            .unwrap()
            .is_none());
        assert!(store
            .get_record_for_round(&id, Round(250))
            .unwrap()
            .is_none());
    }

    #[test]
    fn insert_duplicate_participation_id_fails() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation(1, 100, 200, 10);
        store.insert(&part).unwrap();
        // Same participation key inserted again should fail due to UNIQUE constraint.
        assert!(store.insert(&part).is_err());
    }

    #[test]
    fn register_deactivates_other_keys_for_same_account() {
        let store = ParticipationStore::open_in_memory().unwrap();
        // Two keys for the same account (same seed_byte = same address).
        let p1 = make_test_participation(1, 100, 300, 10);
        let p2 = Participation {
            parent: Address([1u8; 32]),
            vrf: VrfKeypair::from_seed([2u8; 32]),
            voting: algo_consensus_crypto::OneTimeSignatureSecrets::generate(0, 10),
            first_valid: Round(200),
            last_valid: Round(400),
            key_dilution: 10,
            state_proof_secrets: None,
        };
        let id1 = store.insert(&p1).unwrap();
        let id2 = store.insert(&p2).unwrap();

        // Register first key at round 150.
        store.register(&id1, Round(150)).unwrap();
        let r1 = store.get(&id1).unwrap().unwrap();
        assert_eq!(r1.effective_first, Round(150));
        assert_eq!(r1.effective_last, Round(300));

        // Register second key at round 200 — should deactivate first key.
        store.register(&id2, Round(200)).unwrap();

        let r1 = store.get(&id1).unwrap().unwrap();
        assert_eq!(r1.effective_last, Round(199)); // deactivated: on - 1

        let r2 = store.get(&id2).unwrap().unwrap();
        assert_eq!(r2.effective_first, Round(200));
        assert_eq!(r2.effective_last, Round(400));
    }

    #[test]
    fn record_for_account_with_active_key() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation(1, 100, 200, 10);
        let id = store.insert(&part).unwrap();
        store.register(&id, Round(100)).unwrap();

        // Record via address lookup.
        store
            .record_for_account(&Address([1u8; 32]), Round(150), ParticipationAction::Vote)
            .unwrap();

        let record = store.get(&id).unwrap().unwrap();
        assert_eq!(record.last_vote, Round(150));
    }

    #[test]
    fn record_for_account_no_active_key_is_noop() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation(1, 100, 200, 10);
        store.insert(&part).unwrap();
        // Key not registered — record_for_account should be a no-op.
        store
            .record_for_account(&Address([1u8; 32]), Round(150), ParticipationAction::Vote)
            .unwrap();
    }

    #[test]
    fn get_for_voting_round_filters_by_sql() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let p1 = make_test_participation(1, 100, 200, 10);
        let p2 = make_test_participation(2, 300, 400, 10);
        let id1 = store.insert(&p1).unwrap();
        store.insert(&p2).unwrap();

        // Register p1 at round 150 so it has effective_first = 150.
        store.register(&id1, Round(150)).unwrap();

        // voting_round=180, key_round=160 — p1 qualifies (effective_first=150 <= 160).
        let keys = store.get_for_voting_round(Round(180), Round(160)).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].account, Address([1u8; 32]));

        // voting_round=180, key_round=140 — p1 does NOT qualify (effective_first=150 > 140).
        let keys = store.get_for_voting_round(Round(180), Round(140)).unwrap();
        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn get_for_voting_round_excludes_deactivated_keys() {
        let store = ParticipationStore::open_in_memory().unwrap();
        // Two keys for the same account (same address).
        let p1 = make_test_participation(1, 100, 300, 10);
        let p2 = Participation {
            parent: Address([1u8; 32]),
            vrf: VrfKeypair::from_seed([2u8; 32]),
            voting: algo_consensus_crypto::OneTimeSignatureSecrets::generate(0, 10),
            first_valid: Round(200),
            last_valid: Round(400),
            key_dilution: 10,
            state_proof_secrets: None,
        };
        let id1 = store.insert(&p1).unwrap();
        let id2 = store.insert(&p2).unwrap();

        // Register key A at round 150.
        store.register(&id1, Round(150)).unwrap();
        // Register key B at round 200 — deactivates key A (effectiveLast = 199).
        store.register(&id2, Round(200)).unwrap();

        // Round 250: key A is deactivated (effectiveLast=199), only key B should appear.
        let keys = store.get_for_voting_round(Round(250), Round(250)).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].participation_id, id2);

        // Round 180: key A is still active (effectiveLast=199), key B not yet effective.
        let keys = store.get_for_voting_round(Round(180), Round(180)).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].participation_id, id1);
    }

    #[test]
    fn voting_keys_for_round_filtering() {
        use super::super::KeyManager;

        let store = ParticipationStore::open_in_memory().unwrap();

        // Key valid for rounds 100-200.
        let p1 = make_test_participation(1, 100, 200, 10);
        store.insert(&p1).unwrap();

        // Key valid for rounds 300-400.
        let p2 = make_test_participation(2, 300, 400, 10);
        store.insert(&p2).unwrap();

        // Round 150 should only match p1.
        let keys = store.voting_keys_for_round(Round(150), Round(150)).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].account, Address([1u8; 32]));

        // Round 350 should only match p2.
        let keys = store.voting_keys_for_round(Round(350), Round(350)).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].account, Address([2u8; 32]));

        // Round 250 matches neither.
        let keys = store.voting_keys_for_round(Round(250), Round(250)).unwrap();
        assert!(keys.is_empty());
    }

    // -- get_for_round and voting secrets roundtrip tests --------------------

    #[test]
    fn roundtrip_signing_via_get_for_round() {
        use algo_consensus_crypto::onetimesig::verify_one_time_signature;

        let store = ParticipationStore::open_in_memory().unwrap();
        let key_dilution = 10u64;
        let part = make_test_participation(1, 0, 100, key_dilution);
        let verifier = part.voting.verifier();
        let id = store.insert(&part).unwrap();

        // Retrieve the full Participation via get_for_round.
        let restored = store
            .get_for_round(&id, Round(50))
            .unwrap()
            .expect("should find key");

        // Sign a message with the restored voting secrets.
        let msg = b"test message for roundtrip signing";
        let round = 5u64;
        let sig = restored.voting.sign(msg, round, key_dilution);

        // Verify the signature with the original verifier.
        let batch = round / key_dilution;
        let offset = round % key_dilution;
        assert!(
            verify_one_time_signature(&sig, &verifier, batch, offset, msg),
            "signature from restored secrets must verify"
        );
    }

    #[test]
    fn get_for_round_restores_all_fields() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let key_dilution = 32u64;
        let part = make_test_participation(7, 100, 500, key_dilution);
        let original_verifier = part.voting.verifier();
        let original_vrf_pk = part.vrf.pk;
        let id = store.insert(&part).unwrap();

        let restored = store
            .get_for_round(&id, Round(300))
            .unwrap()
            .expect("should find key");

        assert_eq!(restored.parent, Address([7u8; 32]));
        assert_eq!(restored.first_valid, Round(100));
        assert_eq!(restored.last_valid, Round(500));
        assert_eq!(restored.key_dilution, key_dilution);
        assert_eq!(restored.voting.verifier(), original_verifier);
        assert_eq!(restored.vrf.pk, original_vrf_pk);
        assert!(restored.state_proof_secrets.is_none());
    }

    #[test]
    fn update_voting_secrets_persists_deletion() {
        use algo_consensus_crypto::onetimesig::verify_one_time_signature;

        let store = ParticipationStore::open_in_memory().unwrap();
        let key_dilution = 4u64;
        let part = make_test_participation(3, 0, 100, key_dilution);
        let verifier = part.voting.verifier();
        let id = store.insert(&part).unwrap();

        // Retrieve, delete old keys, and persist.
        let mut restored = store
            .get_for_round(&id, Round(0))
            .unwrap()
            .expect("should find key");
        restored.voting.delete_before(8, key_dilution); // advance past batch 0 and 1

        store.update_voting_secrets(&id, &restored.voting).unwrap();

        // Retrieve again and verify the deletion state was persisted.
        let restored2 = store
            .get_for_round(&id, Round(50))
            .unwrap()
            .expect("should find key");

        // Should be able to sign round 8 (batch 2, offset 0) but not round 3 (deleted).
        let sig = restored2.voting.sign(b"after delete", 8, key_dilution);
        assert!(verify_one_time_signature(
            &sig,
            &verifier,
            2,
            0,
            b"after delete"
        ));
    }

    #[test]
    fn get_for_round_outside_range_returns_none() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation(1, 100, 200, 10);
        let id = store.insert(&part).unwrap();

        // Before valid range.
        assert!(store.get_for_round(&id, Round(50)).unwrap().is_none());
        // After valid range.
        assert!(store.get_for_round(&id, Round(250)).unwrap().is_none());
    }

    #[test]
    fn get_for_round_nonexistent_id_returns_none() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let id = ParticipationID([99u8; 32]);
        assert!(store.get_for_round(&id, Round(100)).unwrap().is_none());
    }

    // -- State proof key persistence tests ----------------------------------

    /// Helper to create a `Participation` with state proof secrets.
    fn make_test_participation_with_state_proof(
        seed_byte: u8,
        first: u64,
        last: u64,
        dilution: u64,
    ) -> Participation {
        let vrf = VrfKeypair::from_seed([seed_byte; 32]);
        let voting = OneTimeSignatureSecrets::generate(0, 10);

        // Generate state proof secrets for the round range.
        let state_proof =
            merklesig::Secrets::new(first, last, merklesig::KEY_LIFETIME_DEFAULT).unwrap();

        Participation {
            parent: Address([seed_byte; 32]),
            vrf,
            voting,
            first_valid: Round(first),
            last_valid: Round(last),
            key_dilution: dilution,
            state_proof_secrets: Some(state_proof),
        }
    }

    #[test]
    fn state_proof_keys_roundtrip() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation_with_state_proof(1, 0, 1024, 32);

        let original_num_keys = part
            .state_proof_secrets
            .as_ref()
            .unwrap()
            .ephemeral_keys
            .len();
        assert!(original_num_keys > 0, "should have generated some keys");

        let original_verifier = part.state_proof_secrets.as_ref().unwrap().get_verifier();

        let id = store.insert(&part).unwrap();

        // Retrieve and verify secrets are fully restored.
        let restored = store
            .get_for_round(&id, Round(500))
            .unwrap()
            .expect("should find key");

        let restored_secrets = restored
            .state_proof_secrets
            .as_ref()
            .expect("state proof secrets should be present");

        // Number of keys should match.
        assert_eq!(
            restored_secrets.ephemeral_keys.len(),
            original_num_keys,
            "number of restored keys should match original"
        );

        // Verifier should match.
        assert_eq!(
            restored_secrets.get_verifier(),
            original_verifier,
            "verifier commitment should match after restore"
        );

        // First key should have matching public key.
        assert_eq!(
            restored_secrets.ephemeral_keys[0].pk,
            part.state_proof_secrets.as_ref().unwrap().ephemeral_keys[0].pk,
            "first falcon public key should match"
        );
    }

    #[test]
    fn state_proof_verifier_in_record() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation_with_state_proof(2, 0, 512, 16);

        let original_verifier = part.state_proof_secrets.as_ref().unwrap().get_verifier();

        let id = store.insert(&part).unwrap();

        // The ParticipationRecord should have the verifier decoded.
        let record = store.get(&id).unwrap().expect("should find record");
        let verifier = record
            .state_proof_verifier
            .expect("verifier should be present");

        assert_eq!(
            verifier.key_lifetime,
            merklesig::KEY_LIFETIME_DEFAULT,
            "key lifetime should match"
        );
        assert_eq!(
            verifier.commitment, original_verifier.commitment,
            "commitment should match"
        );
    }

    #[test]
    fn state_proof_keys_delete_before_round() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation_with_state_proof(3, 0, 2048, 32);

        let original_num_keys = part
            .state_proof_secrets
            .as_ref()
            .unwrap()
            .ephemeral_keys
            .len();
        let id = store.insert(&part).unwrap();

        // Delete keys before round 512.
        let deleted = store
            .delete_state_proof_keys_before(&id, Round(512))
            .unwrap();
        assert!(deleted > 0, "should have deleted some keys");

        // Retrieve — vector should have fewer keys, with first_key_offset
        // tracking the number of pruned entries.
        let restored = store
            .get_for_round(&id, Round(1000))
            .unwrap()
            .expect("should find key");

        let restored_secrets = restored
            .state_proof_secrets
            .as_ref()
            .expect("state proof secrets should be present");

        assert!(
            restored_secrets.ephemeral_keys.len() < original_num_keys,
            "should have fewer keys after deletion (had {}, now {})",
            original_num_keys,
            restored_secrets.ephemeral_keys.len()
        );
        assert!(
            restored_secrets.first_key_offset > 0,
            "first_key_offset should be non-zero after pruning"
        );
    }

    #[test]
    fn state_proof_keys_get_key_correct_after_pruning() {
        // Regression test for issue #110: after deleting early-round keys
        // and restoring, `get_key()` must still return the correct key for
        // remaining rounds.
        let store = ParticipationStore::open_in_memory().unwrap();

        // first_valid=0, last_valid=2048, key_lifetime=256 → 9 keys
        // (rounds 0, 256, 512, 768, 1024, 1280, 1536, 1792, 2048)
        let part = make_test_participation_with_state_proof(5, 0, 2048, 32);

        let original_secrets = part.state_proof_secrets.as_ref().unwrap();
        let key_lifetime = original_secrets.signer_context.key_lifetime;
        assert_eq!(key_lifetime, merklesig::KEY_LIFETIME_DEFAULT);

        // Capture the public keys for later comparison.
        let original_keys: Vec<_> = original_secrets
            .ephemeral_keys
            .iter()
            .map(|k| k.pk)
            .collect();

        let id = store.insert(&part).unwrap();

        // Delete keys for rounds < 512 (removes rounds 0 and 256).
        let deleted = store
            .delete_state_proof_keys_before(&id, Round(512))
            .unwrap();
        assert_eq!(deleted, 2, "should have deleted 2 keys (rounds 0, 256)");

        // Restore and verify get_key returns correct keys for remaining rounds.
        let restored = store
            .get_for_round(&id, Round(1000))
            .unwrap()
            .expect("should find key");

        let restored_secrets = restored
            .state_proof_secrets
            .as_ref()
            .expect("state proof secrets should be present");

        // Pruned rounds should return None from get_key.
        assert!(
            restored_secrets.get_key(0).is_none(),
            "pruned round 0 should return None"
        );
        assert!(
            restored_secrets.get_key(256).is_none(),
            "pruned round 256 should return None"
        );

        // Remaining rounds should return the correct key (matching the original).
        for (idx, original_pk) in original_keys.iter().enumerate().skip(2) {
            let round = merklesig::index_to_round(0, key_lifetime, idx as u64);
            let key = restored_secrets
                .get_key(round)
                .unwrap_or_else(|| panic!("get_key({}) should succeed", round));
            assert_eq!(
                key.pk, *original_pk,
                "key at round {} should match original",
                round
            );
        }
    }

    #[test]
    fn state_proof_keys_deleted_with_participation() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation_with_state_proof(4, 0, 512, 32);
        let id = store.insert(&part).unwrap();

        // Verify keys are in the DB.
        assert!(store.get(&id).unwrap().is_some());

        // Delete the participation key entirely.
        let deleted = store.delete(&id).unwrap();
        assert!(deleted);

        // The participation key and its state proof keys should be gone.
        assert!(store.get(&id).unwrap().is_none());
    }

    #[test]
    fn state_proof_none_still_works() {
        // Ensure that participation keys without state proof secrets
        // still work correctly after the type change.
        let store = ParticipationStore::open_in_memory().unwrap();
        let part = make_test_participation(1, 100, 200, 10);
        let id = store.insert(&part).unwrap();

        let record = store.get(&id).unwrap().expect("should find record");
        assert!(
            record.state_proof_verifier.is_none(),
            "verifier should be None for keys without state proof"
        );

        let full = store
            .get_for_round(&id, Round(150))
            .unwrap()
            .expect("should find key");
        assert!(
            full.state_proof_secrets.is_none(),
            "secrets should be None for keys without state proof"
        );
    }
}
