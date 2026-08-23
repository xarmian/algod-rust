//! StateProofKeys table writer — installs the table + persists the in-memory
//! Falcon ephemeral keys from an MSS [`merklesig::Secrets`].
//!
//! The writer accepts [`algo_consensus_crypto::merklesig::Secrets`] (the
//! type the participation pipeline produces and stores in
//! `Participation::state_proof_secrets`), NOT the parallel-keygen
//! [`algo_consensus_crypto::merklesignature::Secrets`] introduced in
//! TASK-174. TASK-174's `Secrets` is a primitive used by future writer
//! paths that want parallel Falcon keygen; the existing participation
//! flow continues to use `merklesig::Secrets`, which is what this
//! writer must persist.
//!
//! Mirrors `../go-algorand/crypto/merklesignature/persistentMerkleSignatureScheme.go`
//! lines 39-135 (v4.6.0-stable). The schema-version tracking row lives in
//! the partkey DB's `schema` table (created by [`super::install`]'s
//! `part_install_database`) so a fresh DB must already have that table
//! present before [`install_state_proof_table`] is called.
//!
//! ## Architectural note
//!
//! The Phase C plan suggested co-locating this writer with the in-memory
//! `merklesignature::Secrets` inside `algo-consensus-crypto`. That would
//! pull `rusqlite` into a pure-crypto crate, which violates the existing
//! layering (compare TASK-175's `participation::install` / `::persist` in
//! `algo-ledger`). The writer therefore lives in `algo-ledger` next to the
//! `ParticipationAccount` writer and operates on `&mut ErasableDb`. The
//! semantic mirror with Go is preserved: a single transaction wraps schema
//! install + per-key INSERTs, identical SQL, identical row layout.
//!
//! ## Schema (v1)
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS StateProofKeys (
//!     id    INTEGER PRIMARY KEY,
//!     round INTEGER,
//!     key   BLOB
//! );
//! CREATE UNIQUE INDEX IF NOT EXISTS roundIdx ON StateProofKeys (round);
//! ```
//!
//! Plus a `('merklesignaturescheme', 1)` row in the partkey DB's shared
//! `schema` table.
//!
//! ## Ephemeral-key retention
//!
//! Go's `(*Secrets).Persist` leaves `s.ephemeralKeys` populated after
//! success — the caller (`FillDBWithParticipationKeys`) holds the keys
//! for any downstream consumer. We match that exactly: `persist_secrets`
//! does not clear `secrets.ephemeral_keys`.

use algo_consensus_crypto::merklesig::{index_to_round, Secrets};
use rusqlite::{params, Transaction};
use thiserror::Error;

use crate::erasable_db::ErasableDb;

/// Tablename row in the shared `schema` table tracking MSS-table version.
///
/// Mirrors `merklesignature.merkleSignatureTableSchemaName`
/// (`persistentMerkleSignatureScheme.go:36`).
pub const MERKLE_SIGNATURE_TABLE_SCHEMA_NAME: &str = "merklesignaturescheme";

/// Current StateProofKeys table schema version.
///
/// Mirrors `merklesignature.merkleSignatureSchemaVersion`
/// (`persistentMerkleSignatureScheme.go:35`).
pub const MERKLE_SIGNATURE_SCHEMA_VERSION: i64 = 1;

/// Errors from [`install_state_proof_table`] / [`persist_secrets`].
#[derive(Debug, Error)]
pub enum StateProofPersistError {
    /// Underlying sqlite write failure.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// `key_lifetime == 0` on the `Secrets` — `Persist` cannot translate
    /// indices to rounds. Mirrors Go's `ErrKeyLifetimeIsZero`.
    #[error("key lifetime is zero")]
    KeyLifetimeIsZero,
}

/// Install the StateProofKeys table on the partkey DB.
///
/// Mirrors `merklesignature.InstallStateProofTable`
/// (`persistentMerkleSignatureScheme.go:44`):
///
/// 1. Look up the MSS row in the existing partkey `schema` table.
/// 2. If already at version 1 → no-op.
/// 3. Else CREATE TABLE IF NOT EXISTS + UNIQUE INDEX, then write the
///    version row (DELETE + INSERT, matching Go).
///
/// Assumes the partkey `schema` table already exists (created by
/// [`super::install::part_install_database`] — TASK-175). Callers
/// invoking this without first installing the partkey schema will get a
/// `Sqlite` error from the version-row lookup.
pub fn install_state_proof_table(tx: &Transaction) -> Result<(), StateProofPersistError> {
    // Look up the existing version row, if any. We deliberately distinguish
    // "row missing" (NULL via OUTER JOIN-style `query_row` Option) from
    // "row present at any version" — Go does the same via `sql.ErrNoRows`.
    let existing: Option<i64> = tx
        .query_row(
            "SELECT version FROM schema WHERE tablename = ?1",
            [MERKLE_SIGNATURE_TABLE_SCHEMA_NAME],
            |row| row.get::<_, Option<i64>>(0),
        )
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })?;

    if let Some(version) = existing {
        if version == MERKLE_SIGNATURE_SCHEMA_VERSION {
            // Already at the desired version — no-op.
            return Ok(());
        }
        // Any other version means "out of date" — fall through to the
        // install path, which will DELETE the stale row before INSERT.
    }

    tx.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS StateProofKeys (
            id    INTEGER PRIMARY KEY,
            round INTEGER,
            key   BLOB
        );
        CREATE UNIQUE INDEX IF NOT EXISTS roundIdx ON StateProofKeys (round);
        "#,
    )?;

    // Drop the stale version row (if any) and re-insert at the current
    // version. Matches Go's DELETE-then-INSERT pattern at
    // persistentMerkleSignatureScheme.go:82-88.
    tx.execute(
        "DELETE FROM schema WHERE tablename = ?1",
        [MERKLE_SIGNATURE_TABLE_SCHEMA_NAME],
    )?;
    tx.execute(
        "INSERT INTO schema (tablename, version) VALUES (?1, ?2)",
        (
            MERKLE_SIGNATURE_TABLE_SCHEMA_NAME,
            MERKLE_SIGNATURE_SCHEMA_VERSION,
        ),
    )?;
    Ok(())
}

/// Persist every ephemeral Falcon key from `secrets` into the partkey DB's
/// StateProofKeys table.
///
/// Mirrors `(*Secrets).Persist` (`persistentMerkleSignatureScheme.go:92`):
///
/// 1. Single sqlite transaction wraps the table install + per-key INSERT
///    loop.
/// 2. `round` starts at `index_to_round(first_valid, key_lifetime, 0)`
///    and increments by `key_lifetime` each iteration — identical
///    arithmetic to Go.
/// 3. Each row is `(i, round_i, msgpack(FalconSigner))` where `i` is the
///    leaf index.
///
/// Does NOT clear `secrets.ephemeral_keys` afterward — matches Go, which
/// leaves the in-memory slice populated for the caller to manage.
///
/// Idempotency: re-persisting against the same DB will fail because of
/// the UNIQUE index on `round` (matches Go, which has the same
/// guarantee). Callers must ensure they persist exactly once per DB.
pub fn persist_secrets(
    db: &mut ErasableDb,
    secrets: &Secrets,
) -> Result<(), StateProofPersistError> {
    let key_lifetime = secrets.signer_context.key_lifetime;
    if key_lifetime == 0 {
        return Err(StateProofPersistError::KeyLifetimeIsZero);
    }

    let first_valid = secrets.signer_context.first_valid;
    let mut round = index_to_round(first_valid, key_lifetime, 0);

    let tx = db.conn_mut().transaction()?;
    install_state_proof_table(&tx)?;

    {
        let mut stmt =
            tx.prepare("INSERT INTO StateProofKeys (id, round, key) VALUES (?1, ?2, ?3)")?;
        for (i, key) in secrets.ephemeral_keys.iter().enumerate() {
            // Use the canonical encoder colocated with FalconSigner so the
            // wire format always matches what the Phase B reader expects.
            let encoded = key.to_msgpack();
            stmt.execute(params![i as i64, round as i64, &encoded])?;
            round += key_lifetime;
        }
    }

    tx.commit()?;
    Ok(())
}

/// Sanity check: the partkey `schema` table must already exist (created
/// by `part_install_database`). Returns `true` if the MSS table-schema row
/// is present at the current version, regardless of whether the
/// StateProofKeys table itself exists.
#[cfg(test)]
fn mss_schema_row_is_current(conn: &rusqlite::Connection) -> bool {
    conn.query_row(
        "SELECT version FROM schema WHERE tablename = ?1",
        [MERKLE_SIGNATURE_TABLE_SCHEMA_NAME],
        |row| row.get::<_, i64>(0),
    )
    .map(|v| v == MERKLE_SIGNATURE_SCHEMA_VERSION)
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::participation::install::part_install_database;
    use algo_consensus_crypto::merklesig::Secrets as MssSecrets;
    use rusqlite::Connection;

    fn fresh_partkey_conn() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        part_install_database(&tx).unwrap();
        tx.commit().unwrap();
        conn
    }

    #[test]
    fn install_state_proof_table_is_idempotent() {
        let mut conn = fresh_partkey_conn();
        let tx = conn.transaction().unwrap();
        install_state_proof_table(&tx).unwrap();
        tx.commit().unwrap();
        // Second call must be a no-op (no error).
        let tx = conn.transaction().unwrap();
        install_state_proof_table(&tx).unwrap();
        tx.commit().unwrap();
        assert!(mss_schema_row_is_current(&conn));
    }

    #[test]
    fn install_creates_state_proof_keys_table_and_unique_round_index() {
        let mut conn = fresh_partkey_conn();
        let tx = conn.transaction().unwrap();
        install_state_proof_table(&tx).unwrap();
        tx.commit().unwrap();

        // Column introspection.
        let cols: Vec<(String, String)> = conn
            .prepare("PRAGMA table_info(StateProofKeys)")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let expected: Vec<(&str, &str)> =
            vec![("id", "INTEGER"), ("round", "INTEGER"), ("key", "BLOB")];
        assert_eq!(cols.len(), expected.len());
        for (i, (name, ty)) in expected.into_iter().enumerate() {
            assert_eq!(cols[i].0, name, "column {i} name");
            assert_eq!(cols[i].1.to_uppercase(), ty, "column {i} type");
        }

        // Unique index on `round` exists.
        let unique_round: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type='index' AND name='roundIdx' \
                 AND tbl_name='StateProofKeys'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unique_round, 1, "roundIdx must exist");
    }

    #[test]
    fn persist_writes_one_row_per_ephemeral_key_with_correct_rounds() {
        // 4-batch MSS at first_valid=256, key_lifetime=256 → rounds
        // 256, 512, 768, 1024.
        let secrets = MssSecrets::new(256, 1024, 256).expect("mss new");
        let n = secrets.ephemeral_keys.len();
        assert!(n > 0, "test precondition: non-empty MSS");

        let path = std::env::temp_dir().join(format!(
            "algod-rust-mss-persist-{}-{}.sqlite",
            "rows",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut db = ErasableDb::open(&path).unwrap();

        // Install the partkey schema first (the MSS install reads from it).
        {
            let tx = db.conn_mut().transaction().unwrap();
            part_install_database(&tx).unwrap();
            tx.commit().unwrap();
        }

        persist_secrets(&mut db, &secrets).expect("persist");

        // After persist, the StateProofKeys table holds exactly n rows
        // and the in-memory ephemeral_keys are still present (matches Go).
        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM StateProofKeys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count as usize, n);
        assert_eq!(secrets.ephemeral_keys.len(), n, "ephemeral keys retained");

        // Round values match index_to_round(first_valid, key_lifetime, i).
        let rounds: Vec<i64> = db
            .conn()
            .prepare("SELECT round FROM StateProofKeys ORDER BY id ASC")
            .unwrap()
            .query_map([], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for (i, r) in rounds.iter().enumerate() {
            let expected = index_to_round(256, 256, i as u64);
            assert_eq!(*r as u64, expected, "row {i} round");
        }

        // Per-row key blob is non-empty and round-trips through the
        // existing reader (`merklesig::FalconSigner::from_msgpack`).
        let blobs: Vec<Vec<u8>> = db
            .conn()
            .prepare("SELECT key FROM StateProofKeys ORDER BY id ASC")
            .unwrap()
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for (i, blob) in blobs.iter().enumerate() {
            assert!(!blob.is_empty(), "row {i} blob empty");
            let (decoded, _) =
                algo_consensus_crypto::merklesig::FalconSigner::from_msgpack(blob).expect("decode");
            assert_eq!(decoded.pk, secrets.ephemeral_keys[i].pk);
            assert_eq!(decoded.sk, secrets.ephemeral_keys[i].sk);
        }

        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn persist_rejects_zero_key_lifetime() {
        let mut secrets = MssSecrets::new(256, 1024, 256).expect("mss new");
        secrets.signer_context.key_lifetime = 0; // simulate corruption

        let path = std::env::temp_dir().join(format!(
            "algod-rust-mss-persist-{}-{}.sqlite",
            "zerolife",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut db = ErasableDb::open(&path).unwrap();
        {
            let tx = db.conn_mut().transaction().unwrap();
            part_install_database(&tx).unwrap();
            tx.commit().unwrap();
        }

        let err = persist_secrets(&mut db, &secrets).unwrap_err();
        assert!(matches!(err, StateProofPersistError::KeyLifetimeIsZero));

        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn persist_empty_secrets_leaves_table_empty() {
        // The `NoKeysCommitment` window (`key_lifetime+1`..`+2`) produces
        // 0 ephemeral keys. Persist must still succeed and leave the
        // table empty.
        let secrets = MssSecrets::new(257, 258, 256).expect("mss new");
        assert_eq!(secrets.ephemeral_keys.len(), 0);

        let path = std::env::temp_dir().join(format!(
            "algod-rust-mss-persist-{}-{}.sqlite",
            "empty",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut db = ErasableDb::open(&path).unwrap();
        {
            let tx = db.conn_mut().transaction().unwrap();
            part_install_database(&tx).unwrap();
            tx.commit().unwrap();
        }

        persist_secrets(&mut db, &secrets).expect("empty persist must succeed");

        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM StateProofKeys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        assert!(mss_schema_row_is_current(db.conn()));

        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}
