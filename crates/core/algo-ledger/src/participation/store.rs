//! Participation key persistence (SQLite-backed store).
//!
//! Matches go-algorand's `data/account/participationRegistry.go` schema
//! with `Keysets` and `Rolling` tables joined by an auto-increment primary key.
//!
//! # Blob serialization
//!
//! - **VRF**: stored as the raw 32-byte seed. Reconstructed via
//!   `VrfKeypair::from_seed`.
//! - **Voting secrets**: stored as an opaque blob. Since `OneTimeSignatureSecrets`
//!   does not yet support serde, `get_for_round` cannot currently reconstruct
//!   the full voting secrets from storage. The verifier (32-byte public key)
//!   is used for `ParticipationRecord` queries.
//! - **State proof**: stored as raw bytes (opaque blob).

use std::path::Path;

use algo_consensus_crypto::VrfKeypair;
use algo_types::{Address, Round};
use rusqlite::{params, Connection, OptionalExtension};

use super::{Participation, ParticipationAction, ParticipationID, ParticipationRecord};

#[cfg(test)]
use algo_consensus_crypto::OneTimeSignatureSecrets;

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
        conn.execute_batch(CREATE_KEYSETS)?;
        conn.execute_batch(CREATE_ROLLING)?;
        Ok(Self { conn })
    }

    /// Open (or create) a store backed by the given file path.
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
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
    /// Voting secrets are not currently serializable; an empty blob is stored.
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

        // Voting: not serializable yet — store empty blob.
        let voting_blob: Vec<u8> = Vec::new();

        // State proof: store raw bytes if present.
        let state_proof_blob: Option<Vec<u8>> = participation.state_proof_secrets.clone();

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

        let pk = self.conn.last_insert_rowid();

        tx.execute(INSERT_ROLLING, params![pk, voting_blob])?;

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
    /// # Note
    ///
    /// A full `Participation` (with signing-capable voting secrets) cannot
    /// be returned because `OneTimeSignatureSecrets` serialization is not
    /// yet supported. Use this method to get metadata and VRF info only.
    /// TODO: Add `get_for_round` returning `Participation` once OTS
    /// serialization is implemented in the crypto crate.
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
            return Err(rusqlite::Error::QueryReturnedNoRows);
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
             AND (r.effectiveFirstRound IS NULL OR r.effectiveFirstRound = 0 OR r.effectiveFirstRound <= ?2)"
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
        // Column 12 (voting blob) is not used for ParticipationRecord.

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
            state_proof_verifier: raw_state_proof,
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
}
