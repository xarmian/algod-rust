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

//! Partkey sqlite schema install + migration.
//!
//! Mirrors `../go-algorand/data/account/partInstall.go` (v4.6.0-stable). The
//! partkey DB is the single-account flavor produced by `algokey part
//! generate` — one `ParticipationAccount` row plus a `schema` table that
//! tracks the version. The companion `StateProofKeys` table is installed
//! separately by TASK-176 (`InstallStateProofTable`).
//!
//! ## Schema (v3)
//!
//! ```sql
//! CREATE TABLE ParticipationAccount (
//!     parent BLOB,
//!     vrf BLOB,
//!     voting BLOB,
//!     firstValid INTEGER,
//!     lastValid INTEGER,
//!     keyDilution INTEGER NOT NULL DEFAULT 0,
//!     stateProof BLOB
//! );
//! CREATE TABLE schema (
//!     tablename TEXT PRIMARY KEY,
//!     version INTEGER
//! );
//! INSERT INTO schema VALUES ('parttable', 3);
//! ```
//!
//! `part_migrate` accepts v1/v2 DBs and steps them forward column-by-column
//! to v3, matching `updateDB` in `partInstall.go`. Fresh DBs go directly to
//! v3 — no shimming, no deferred-cleanup tasks (per [[CONVE-197]]).

use rusqlite::Transaction;
use thiserror::Error;

/// Name of the row in the `schema` table tracking the partkey schema version.
///
/// Mirrors `account.PartTableSchemaName`.
pub const PART_TABLE_SCHEMA_NAME: &str = "parttable";

/// Current partkey schema version. Fresh DBs are installed at this version.
///
/// Mirrors `account.PartTableSchemaVersion`.
pub const PART_TABLE_SCHEMA_VERSION: i64 = 3;

/// Errors from [`part_install_database`] / [`part_migrate`].
#[derive(Debug, Error)]
pub enum InstallError {
    /// Underlying sqlite write failure.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The `schema` table is missing, malformed, or reports an unsupported
    /// version. Mirrors Go's `ErrUnsupportedSchema`.
    #[error(
        "unsupported participation file schema version (expected {})",
        PART_TABLE_SCHEMA_VERSION
    )]
    UnsupportedSchema,
}

/// Install the partkey schema on a fresh DB (idempotent at v3 only — calling
/// it twice will fail the second time because the tables already exist).
///
/// Mirrors `account.partInstallDatabase` (`partInstall.go:36`).
pub fn part_install_database(tx: &Transaction) -> Result<(), InstallError> {
    tx.execute_batch(
        r#"
        CREATE TABLE ParticipationAccount (
            parent BLOB,
            vrf BLOB,
            voting BLOB,
            firstValid INTEGER,
            lastValid INTEGER,
            keyDilution INTEGER NOT NULL DEFAULT 0,
            stateProof BLOB
        );
        CREATE TABLE schema (
            tablename TEXT PRIMARY KEY,
            version INTEGER
        );
        "#,
    )?;
    tx.execute(
        "INSERT INTO schema (tablename, version) VALUES (?1, ?2)",
        (PART_TABLE_SCHEMA_NAME, PART_TABLE_SCHEMA_VERSION),
    )?;
    Ok(())
}

/// Migrate a partkey DB from v1 or v2 → v3, or no-op if already at v3.
///
/// Mirrors `account.partMigrate` + `updateDB` (`partInstall.go:73-140`).
///
/// Returns [`InstallError::UnsupportedSchema`] when:
///
/// - the `schema` table is missing or unreadable, OR
/// - the `parttable` row is absent, OR
/// - the post-migration version is not exactly
///   [`PART_TABLE_SCHEMA_VERSION`].
pub fn part_migrate(tx: &Transaction) -> Result<(), InstallError> {
    let mut versions: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    {
        let mut stmt = tx
            .prepare("SELECT tablename, version FROM schema")
            .map_err(|_| InstallError::UnsupportedSchema)?;
        let rows = stmt
            .query_map([], |row| {
                let table: String = row.get(0)?;
                let version: i64 = row.get(1)?;
                Ok((table, version))
            })
            .map_err(|_| InstallError::UnsupportedSchema)?;
        for r in rows {
            let (t, v) = r?;
            versions.insert(t, v);
        }
    }

    let mut part_version = match versions.get(PART_TABLE_SCHEMA_NAME) {
        Some(v) => *v,
        None => return Err(InstallError::UnsupportedSchema),
    };

    part_version = update_db(tx, part_version)?;

    if part_version != PART_TABLE_SCHEMA_VERSION {
        return Err(InstallError::UnsupportedSchema);
    }
    Ok(())
}

/// Step the schema forward one version at a time until it reaches v3.
///
/// Mirrors `account.updateDB` (`partInstall.go:117-140`). Each step ALTERs
/// the `ParticipationAccount` table and bumps the recorded version. The
/// migrations are append-only column adds — no data movement.
fn update_db(tx: &Transaction, mut part_version: i64) -> Result<i64, InstallError> {
    if part_version == 1 {
        tx.execute_batch(
            "ALTER TABLE ParticipationAccount ADD keyDilution INTEGER NOT NULL DEFAULT 0",
        )?;
        part_version = 2;
        tx.execute(
            "UPDATE schema SET version=?1 WHERE tablename=?2",
            (part_version, PART_TABLE_SCHEMA_NAME),
        )?;
    }

    if part_version == 2 {
        tx.execute_batch("ALTER TABLE ParticipationAccount ADD stateProof BLOB")?;
        part_version = 3;
        tx.execute(
            "UPDATE schema SET version=?1 WHERE tablename=?2",
            (part_version, PART_TABLE_SCHEMA_NAME),
        )?;
    }

    Ok(part_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn fresh_v3() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        part_install_database(&tx).unwrap();
        tx.commit().unwrap();
        conn
    }

    #[test]
    fn install_writes_v3_schema_and_single_schema_row() {
        let conn = fresh_v3();
        let (table, version): (String, i64) = conn
            .query_row("SELECT tablename, version FROM schema", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(table, PART_TABLE_SCHEMA_NAME);
        assert_eq!(version, PART_TABLE_SCHEMA_VERSION);

        // Single row only.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn install_creates_participation_account_with_v3_columns() {
        let conn = fresh_v3();
        let columns: Vec<(String, String)> = conn
            .prepare("PRAGMA table_info(ParticipationAccount)")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();

        // Exact column list, in declaration order — must match Go's
        // partInstall.go schema byte-for-byte (modulo whitespace).
        let expected: Vec<(&str, &str)> = vec![
            ("parent", "BLOB"),
            ("vrf", "BLOB"),
            ("voting", "BLOB"),
            ("firstValid", "INTEGER"),
            ("lastValid", "INTEGER"),
            ("keyDilution", "INTEGER"),
            ("stateProof", "BLOB"),
        ];
        assert_eq!(columns.len(), expected.len(), "column count");
        for (i, (name, ty)) in expected.into_iter().enumerate() {
            assert_eq!(columns[i].0, name, "column {i} name");
            assert_eq!(columns[i].1.to_uppercase(), ty, "column {i} type");
        }
    }

    #[test]
    fn migrate_on_fresh_v3_is_no_op() {
        let mut conn = fresh_v3();
        let tx = conn.transaction().unwrap();
        part_migrate(&tx).unwrap();
        tx.commit().unwrap();

        // Version unchanged.
        let v: i64 = conn
            .query_row(
                "SELECT version FROM schema WHERE tablename=?1",
                [PART_TABLE_SCHEMA_NAME],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(v, PART_TABLE_SCHEMA_VERSION);
    }

    #[test]
    fn migrate_v1_to_v3_adds_columns_and_bumps_version() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        // Hand-roll a v1 schema: no keyDilution, no stateProof.
        tx.execute_batch(
            "CREATE TABLE ParticipationAccount (
                 parent BLOB,
                 vrf BLOB,
                 voting BLOB,
                 firstValid INTEGER,
                 lastValid INTEGER
             );
             CREATE TABLE schema (tablename TEXT PRIMARY KEY, version INTEGER);",
        )
        .unwrap();
        tx.execute(
            "INSERT INTO schema VALUES (?1, 1)",
            [PART_TABLE_SCHEMA_NAME],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO ParticipationAccount (parent, vrf, voting, firstValid, lastValid) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                &[0xab_u8; 32][..],
                &[0u8; 0][..],
                &[0u8; 0][..],
                1i64,
                100i64,
            ),
        )
        .unwrap();
        tx.commit().unwrap();

        // Run the migration.
        let tx = conn.transaction().unwrap();
        part_migrate(&tx).unwrap();
        tx.commit().unwrap();

        // Version must be at v3 now.
        let v: i64 = conn
            .query_row(
                "SELECT version FROM schema WHERE tablename=?1",
                [PART_TABLE_SCHEMA_NAME],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(v, PART_TABLE_SCHEMA_VERSION);

        // The pre-existing row must still be readable, with the new columns
        // present (defaults: keyDilution=0, stateProof=NULL).
        let (key_dilution, state_proof): (i64, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT keyDilution, stateProof FROM ParticipationAccount",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(key_dilution, 0);
        assert!(state_proof.is_none());
    }

    #[test]
    fn migrate_v2_to_v3_adds_state_proof_column() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute_batch(
            "CREATE TABLE ParticipationAccount (
                 parent BLOB,
                 vrf BLOB,
                 voting BLOB,
                 firstValid INTEGER,
                 lastValid INTEGER,
                 keyDilution INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE schema (tablename TEXT PRIMARY KEY, version INTEGER);",
        )
        .unwrap();
        tx.execute(
            "INSERT INTO schema VALUES (?1, 2)",
            [PART_TABLE_SCHEMA_NAME],
        )
        .unwrap();
        tx.commit().unwrap();

        let tx = conn.transaction().unwrap();
        part_migrate(&tx).unwrap();
        tx.commit().unwrap();

        let v: i64 = conn
            .query_row(
                "SELECT version FROM schema WHERE tablename=?1",
                [PART_TABLE_SCHEMA_NAME],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(v, PART_TABLE_SCHEMA_VERSION);

        // stateProof column must now exist.
        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(ParticipationAccount)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(cols.iter().any(|c| c == "stateProof"));
    }

    #[test]
    fn migrate_rejects_missing_schema_table() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        // No `schema` table at all.
        let err = part_migrate(&tx).unwrap_err();
        assert!(matches!(err, InstallError::UnsupportedSchema));
    }

    #[test]
    fn migrate_rejects_missing_parttable_row() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute_batch("CREATE TABLE schema (tablename TEXT PRIMARY KEY, version INTEGER);")
            .unwrap();
        let err = part_migrate(&tx).unwrap_err();
        assert!(matches!(err, InstallError::UnsupportedSchema));
    }
}
