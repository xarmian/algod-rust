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

//! SQLite-backed page CRUD for the merkle trie.
//!
//! Mirrors go-algorand's
//! `ledger/store/trackerdb/sqlitedriver/merkle_committer.go::merkleCommitter`
//! — the [`Committer`] interface that the merkle trie uses for paged
//! persistence. Each `(id, data)` row corresponds to one page of nodes
//! serialized in the format owned by [`crate::merkle_page::Page`].
//!
//! This module is the low-level read/write surface only. The
//! higher-level `MerkleTrie` calls into it for paged persistence —
//! PLAN-130 (TASK-136) wired the runtime commit path through this
//! committer, and PLAN-36 G4 (TASK-118) dropped the legacy Rust-only
//! single-blob `merkle_trie` table, so `accounthashes` is now the
//! sole on-disk trie representation.
//!
//! Both `Active` and `Staging` variants write to the **tracker**
//! schema (`main.accounthashes` or `main.catchpointaccounthashes`) and
//! do not touch the attached `blockdb` schema introduced by TASK-100.

use std::path::{Path, PathBuf};

use algo_error::AlgoError;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::merkle_cache::PageCommitter;
use crate::merkle_page::Page;

/// Which `accounthashes`-shaped table this committer reads/writes.
///
/// The committed `Active` table is the runtime trie store; the
/// `Staging` table is the catchpoint-import staging area. Mirrors
/// go-algorand's `staging` boolean argument to `MakeMerkleCommitter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitterTable {
    /// `accounthashes` — the runtime trie.
    Active,
    /// `catchpointaccounthashes` — the catchpoint import staging area
    /// that is renamed to `accounthashes` once the import succeeds.
    Staging,
}

impl CommitterTable {
    /// Name of the SQL table this variant addresses, qualified to the
    /// tracker (`main`) schema so the call site is unambiguous in the
    /// presence of the attached `blockdb` schema introduced by
    /// TASK-100.
    pub const fn table_name(self) -> &'static str {
        match self {
            CommitterTable::Active => "main.accounthashes",
            CommitterTable::Staging => "main.catchpointaccounthashes",
        }
    }

    /// Unqualified table name (for diagnostic messages and tests that
    /// inspect `sqlite_master`).
    pub const fn unqualified(self) -> &'static str {
        match self {
            CommitterTable::Active => "accounthashes",
            CommitterTable::Staging => "catchpointaccounthashes",
        }
    }
}

/// Page-level CRUD over an `accounthashes`-shaped table.
///
/// The committer holds a borrow on a [`Connection`]; the caller is
/// responsible for transactional control (BEGIN / COMMIT). Mirrors
/// `MakeMerkleCommitter` in
/// `../go-algorand/ledger/store/trackerdb/sqlitedriver/merkle_committer.go`.
pub struct SqliteMerkleCommitter<'c> {
    conn: &'c Connection,
    table: CommitterTable,
}

impl<'c> SqliteMerkleCommitter<'c> {
    /// Construct a committer for the given table.
    pub fn new(conn: &'c Connection, table: CommitterTable) -> Self {
        Self { conn, table }
    }

    /// Convenience: committer for the `accounthashes` runtime table.
    pub fn active(conn: &'c Connection) -> Self {
        Self::new(conn, CommitterTable::Active)
    }

    /// Convenience: committer for the `catchpointaccounthashes`
    /// staging table.
    pub fn staging(conn: &'c Connection) -> Self {
        Self::new(conn, CommitterTable::Staging)
    }

    /// Load the bytes of page `id`. Returns `Ok(None)` when the page
    /// does not exist, matching Go's
    /// `merkleCommitter::LoadPage` (`merkle_committer.go:67-77`,
    /// which returns `(nil, nil)` on `sql.ErrNoRows`).
    pub fn load_page_bytes(&self, id: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        let sql = format!("SELECT data FROM {} WHERE id = ?1", self.table.table_name());
        self.conn
            .query_row(&sql, params![id as i64], |row| row.get(0))
            .optional()
            .map_err(|e| AlgoError::Ledger {
                message: format!("LoadPage {} id={id}: {e}", self.table.unqualified()),
            })
    }

    /// Decode page `id` into a [`Page`]. `Ok(None)` when the page does
    /// not exist. Decoding errors are surfaced rather than masked so a
    /// corrupt row fails loudly at load time.
    pub fn load_page(&self, id: u64) -> Result<Option<Page>, AlgoError> {
        match self.load_page_bytes(id)? {
            None => Ok(None),
            Some(bytes) => Page::deserialize(&bytes)
                .map(Some)
                .map_err(|e| AlgoError::Ledger {
                    message: format!(
                        "decode {} page id={id} ({} bytes): {e}",
                        self.table.unqualified(),
                        bytes.len()
                    ),
                }),
        }
    }

    /// Persist a page. Matches Go's `StorePage`
    /// (`merkle_committer.go:57-64`): empty content deletes the row,
    /// otherwise it is an upsert. The caller serializes the page via
    /// [`Page::serialize`] beforehand so the committer doesn't need to
    /// know the in-memory shape.
    pub fn store_page_bytes(&self, id: u64, content: &[u8]) -> Result<(), AlgoError> {
        if content.is_empty() {
            self.delete_page(id)
        } else {
            let sql = format!(
                "INSERT INTO {} (id, data) VALUES (?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET data = excluded.data",
                self.table.table_name()
            );
            self.conn
                .execute(&sql, params![id as i64, content])
                .map(|_| ())
                .map_err(|e| AlgoError::Ledger {
                    message: format!(
                        "StorePage {} id={id} ({} bytes): {e}",
                        self.table.unqualified(),
                        content.len()
                    ),
                })
        }
    }

    /// Serialize and persist a page in one call.
    pub fn store_page(&self, id: u64, page: &Page) -> Result<(), AlgoError> {
        let bytes = page.serialize();
        self.store_page_bytes(id, &bytes)
    }

    /// Remove page `id` from the table. No-op if the row does not exist.
    pub fn delete_page(&self, id: u64) -> Result<(), AlgoError> {
        let sql = format!("DELETE FROM {} WHERE id = ?1", self.table.table_name());
        self.conn
            .execute(&sql, params![id as i64])
            .map(|_| ())
            .map_err(|e| AlgoError::Ledger {
                message: format!("DeletePage {} id={id}: {e}", self.table.unqualified()),
            })
    }

    /// Count rows in this committer's table. Used by the legacy-data
    /// check at open time and by tests; not on a hot path.
    #[allow(dead_code)] // referenced by tests + future TASK-138 large-N assertions
    pub fn page_count(&self) -> Result<u64, AlgoError> {
        let sql = format!("SELECT COUNT(*) FROM {}", self.table.table_name());
        let n: i64 = self
            .conn
            .query_row(&sql, [], |row| row.get(0))
            .map_err(|e| AlgoError::Ledger {
                message: format!("page_count {}: {e}", self.table.unqualified()),
            })?;
        Ok(n as u64)
    }
}

// `MerkleTrieCache` writes/reads pages through any [`PageCommitter`]; this
// bridges the SQLite-backed committer into that trait. Mirrors Go's
// `Committer` interface implementation in `merkle_committer.go`.
impl<'c> PageCommitter for SqliteMerkleCommitter<'c> {
    fn load_page(&self, id: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        self.load_page_bytes(id)
    }

    fn store_page(&self, id: u64, content: &[u8]) -> Result<(), AlgoError> {
        self.store_page_bytes(id, content)
    }
}

// ---------------------------------------------------------------------------
// OwnedSqliteCommitter — `Send`-able owned committer for `MerkleTrieCache::lazy_loader`.
// ---------------------------------------------------------------------------

/// SQLite-backed [`PageCommitter`] that owns its own [`Connection`] —
/// used by [`crate::merkle_trie::MerkleTrie::load`] to install a lazy
/// loader on the cache. The cache's `lazy_loader` is
/// `Box<dyn PageCommitter + Send>`, which the borrowed
/// [`SqliteMerkleCommitter<'c>`] cannot satisfy (its `Connection` borrow
/// is call-scoped). `OwnedSqliteCommitter` owns its connection outright
/// and therefore satisfies `Send` (rusqlite's `Connection: Send`).
///
/// **Read-only by default.** The connection is opened with
/// `SQLITE_OPEN_READ_ONLY`, since the lazy loader only ever issues
/// `SELECT data FROM accounthashes WHERE id = ?`. The trie's
/// write path uses the ledger's main connection via
/// [`SqliteMerkleCommitter`] inside a transaction; the lazy loader's
/// separate read-only connection participates in WAL concurrency.
/// Attempting `store_page` on an `OwnedSqliteCommitter` returns an error
/// — by construction the lazy loader path never writes.
///
/// In-memory databases (`Connection::open_in_memory`) cannot be
/// re-opened by path; constructors that take a path skip this committer
/// for in-memory ledgers. Callers handle that by passing `None` when no
/// path is available, in which case the trie cache has no lazy loader
/// and `get` returns `Ok(None)` on miss (the prior eager-load behavior).
pub struct OwnedSqliteCommitter {
    conn: Connection,
    table: CommitterTable,
    /// Retained for diagnostics — included in error messages so a
    /// failing lazy-load points at the actual DB file.
    path: PathBuf,
}

impl std::fmt::Debug for OwnedSqliteCommitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedSqliteCommitter")
            .field("path", &self.path)
            .field("table", &self.table)
            .finish()
    }
}

impl OwnedSqliteCommitter {
    /// Open a fresh read-only connection to `path` and bind it to
    /// `table`. The connection is independent of any other connection
    /// the ledger holds; SQLite's WAL allows the lazy loader to read
    /// concurrently with the ledger's writers.
    pub fn open(path: impl AsRef<Path>, table: CommitterTable) -> Result<Self, AlgoError> {
        let path_ref = path.as_ref();
        let conn = Connection::open_with_flags(
            path_ref,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| AlgoError::Ledger {
            message: format!("OwnedSqliteCommitter::open({}): {e}", path_ref.display()),
        })?;
        Ok(Self {
            conn,
            table,
            path: path_ref.to_path_buf(),
        })
    }

    /// Convenience: open a committer pointing at `accounthashes` (the
    /// active runtime table).
    pub fn open_active(path: impl AsRef<Path>) -> Result<Self, AlgoError> {
        Self::open(path, CommitterTable::Active)
    }
}

impl PageCommitter for OwnedSqliteCommitter {
    fn load_page(&self, id: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        let sql = format!("SELECT data FROM {} WHERE id = ?1", self.table.table_name());
        self.conn
            .query_row(&sql, params![id as i64], |row| row.get(0))
            .optional()
            .map_err(|e| AlgoError::Ledger {
                message: format!(
                    "OwnedSqliteCommitter::load_page({}, id={id}) [{}]: {e}",
                    self.path.display(),
                    self.table.unqualified()
                ),
            })
    }

    fn store_page(&self, _id: u64, _content: &[u8]) -> Result<(), AlgoError> {
        // The owned committer is the lazy LOAD path only. Writes go
        // through the ledger's main connection via [`SqliteMerkleCommitter`]
        // inside the block-apply transaction; routing them here would
        // bypass that transaction and risk consistency violations.
        Err(AlgoError::Ledger {
            message: "OwnedSqliteCommitter is read-only; writes must go through \
                      SqliteMerkleCommitter inside a transaction"
                .into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_page::{ChildEntry, PageNode, NODES_PER_PAGE};
    use rusqlite::Connection;

    fn open_with_schema() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        // Mirror the in-memory ATTACH layout used by `SqliteLedger`
        // so tests exercise the same `main.accounthashes` /
        // `main.catchpointaccounthashes` resolution the real ledger
        // does.
        conn.execute_batch(
            "ATTACH DATABASE ':memory:' AS blockdb;
             CREATE TABLE accounthashes (id INTEGER PRIMARY KEY, data BLOB);
             CREATE TABLE catchpointaccounthashes (id INTEGER PRIMARY KEY, data BLOB);",
        )
        .unwrap();
        conn
    }

    fn sample_page() -> Page {
        let mut page = Page::new();
        page.nodes.insert(1, PageNode::leaf(vec![0xaa; 32]));
        page.nodes.insert(
            2,
            PageNode::internal(
                vec![0xbb; 32],
                vec![
                    ChildEntry {
                        hash_index: 0x10,
                        child_id: 7,
                    },
                    ChildEntry {
                        hash_index: 0x90,
                        child_id: 8,
                    },
                ],
            ),
        );
        page
    }

    #[test]
    fn round_trip_through_active_table() {
        let conn = open_with_schema();
        let committer = SqliteMerkleCommitter::active(&conn);

        let page = sample_page();
        committer.store_page(42, &page).unwrap();

        assert_eq!(committer.page_count().unwrap(), 1);
        let loaded = committer.load_page(42).unwrap().expect("page exists");
        assert_eq!(loaded, page);
    }

    #[test]
    fn round_trip_through_staging_table() {
        let conn = open_with_schema();
        let committer = SqliteMerkleCommitter::staging(&conn);

        let page = sample_page();
        committer.store_page(7, &page).unwrap();
        assert_eq!(committer.page_count().unwrap(), 1);

        // Active table is untouched: staging and active are independent
        // until the orchestrator renames staging → active.
        assert_eq!(
            SqliteMerkleCommitter::active(&conn).page_count().unwrap(),
            0
        );

        let loaded = committer.load_page(7).unwrap().unwrap();
        assert_eq!(loaded, page);
    }

    #[test]
    fn load_missing_page_returns_none() {
        let conn = open_with_schema();
        let committer = SqliteMerkleCommitter::active(&conn);
        assert!(committer.load_page(999).unwrap().is_none());
        assert!(committer.load_page_bytes(999).unwrap().is_none());
    }

    #[test]
    fn empty_content_deletes_row() {
        let conn = open_with_schema();
        let committer = SqliteMerkleCommitter::active(&conn);
        let page = sample_page();
        committer.store_page(1, &page).unwrap();
        assert_eq!(committer.page_count().unwrap(), 1);

        // Mirror Go's "empty content → delete" semantic
        // (`merkle_committer.go:58-61`).
        committer.store_page_bytes(1, &[]).unwrap();
        assert_eq!(committer.page_count().unwrap(), 0);
        assert!(committer.load_page(1).unwrap().is_none());
    }

    #[test]
    fn store_is_upsert_on_id_collision() {
        let conn = open_with_schema();
        let committer = SqliteMerkleCommitter::active(&conn);
        let mut page1 = Page::new();
        page1.nodes.insert(1, PageNode::leaf(vec![0x11; 4]));
        let mut page2 = Page::new();
        page2.nodes.insert(2, PageNode::leaf(vec![0x22; 4]));

        committer.store_page(5, &page1).unwrap();
        committer.store_page(5, &page2).unwrap();
        assert_eq!(committer.page_count().unwrap(), 1);
        assert_eq!(committer.load_page(5).unwrap().unwrap(), page2);
    }

    #[test]
    fn delete_page_is_idempotent_on_missing_id() {
        let conn = open_with_schema();
        let committer = SqliteMerkleCommitter::active(&conn);
        // Deleting a row that never existed must not error — this is
        // the contract Go's `StorePage(_, nil)` relies on.
        committer.delete_page(9999).unwrap();
        assert_eq!(committer.page_count().unwrap(), 0);
    }

    #[test]
    fn full_production_size_page_round_trips_through_sql() {
        // End-to-end sanity: the production page size (116 nodes) and
        // the full mix of leaf + non-leaf nodes survives a SQL
        // round-trip. Catches buffer-sizing / binding mistakes that
        // unit tests with tiny payloads would miss.
        let conn = open_with_schema();
        let committer = SqliteMerkleCommitter::active(&conn);

        let mut page = Page::new();
        for nid in 0..NODES_PER_PAGE {
            let node = if nid % 4 == 0 {
                PageNode::internal(
                    vec![(nid & 0xff) as u8; 32],
                    vec![
                        ChildEntry {
                            hash_index: 0x01,
                            child_id: nid * 2 + 1,
                        },
                        ChildEntry {
                            hash_index: 0x80,
                            child_id: nid * 2 + 2,
                        },
                    ],
                )
            } else {
                PageNode::leaf(vec![(nid & 0xff) as u8; 36])
            };
            page.nodes.insert(nid, node);
        }
        committer.store_page(1, &page).unwrap();
        assert_eq!(committer.load_page(1).unwrap().unwrap(), page);
    }
}
