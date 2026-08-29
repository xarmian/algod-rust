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

//! Erasable sqlite accessor — mirrors go-algorand's
//! `util/db.MakeErasableAccessor` (v4.6.0-stable).
//!
//! An "erasable" sqlite DB sets `secure_delete=ON` so freed pages are
//! zeroed on the next write/checkpoint. This matters for partkey
//! databases that hold OTS secrets, VRF private keys, and Falcon
//! merkle-signature secrets — when the file is deleted or rows are
//! overwritten, the raw seed bytes must not be recoverable from the
//! page tail.
//!
//! Reference: `../go-algorand/util/db/dbutil.go:91-97` (MakeErasable
//! Accessor → makeErasableAccessor → makeAccessorImpl), `:378-380`
//! (URI params), `:132` (post-connect SynchronousModeFull).
//!
//! ## Pragma set
//!
//! Identical to Go's `makeAccessorImpl` invocation with the
//! `_secure_delete=on, _journal_mode=wal` params:
//!
//! - `PRAGMA secure_delete = ON` — zero freed pages
//! - `PRAGMA journal_mode = WAL` — write-ahead logging (matches Go's
//!   regular accessor too; secure-delete is the only differentiator)
//! - `PRAGMA busy_timeout = 1000` — 1s busy wait
//! - `PRAGMA synchronous = FULL` — full fsync (Go re-applies after
//!   connect via `SetSynchronousMode(...full, fullfsync=true)`)
//!
//! Note: the task description originally specified
//! `journal_mode = DELETE` and `auto_vacuum = FULL`. The actual Go
//! source uses WAL and does NOT set auto_vacuum. Strict conformance
//! wins — we mirror Go exactly. The "deleted bytes must be
//! unrecoverable" property comes from `secure_delete=ON` alone:
//! sqlite overwrites freed pages with zeros before they're reused
//! or returned to the OS, independent of journal mode.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};
use thiserror::Error;

/// Wrapped sqlite connection for partkey-style DBs. Open via
/// [`ErasableDb::open`] or [`ErasableDb::open_read_only`]; close via
/// [`ErasableDb::close`] (or drop) for a final fsync + WAL checkpoint.
pub struct ErasableDb {
    conn: Connection,
    path: PathBuf,
}

/// Errors from opening or operating an [`ErasableDb`].
#[derive(Debug, Error)]
pub enum Error {
    /// Underlying sqlite error (open failure, pragma failure, etc.).
    #[error("sqlite error on {path}: {source}")]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    /// Pragma was applied but a sanity-check query returned an
    /// unexpected value — flagged at open time so callers don't sign
    /// keys to a DB that isn't actually erasable.
    #[error("pragma `{pragma}` is `{actual}`, expected `{expected}` on {path}")]
    PragmaMismatch {
        path: PathBuf,
        pragma: &'static str,
        expected: &'static str,
        actual: String,
    },
}

impl ErasableDb {
    /// Open a DB read/write at `path`, applying the erasable pragma
    /// set. Mirrors `MakeErasableAccessor(path, false /* not RO */)`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_URI,
        )
    }

    /// Open a DB read-only. Mirrors `MakeErasableAccessor(path, true)`.
    /// The same pragmas are applied (Go sets them via the URI param
    /// list before the connection is even read-restricted).
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
    }

    fn open_with_flags(path: impl AsRef<Path>, flags: OpenFlags) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open_with_flags(&path, flags).map_err(|e| Error::Sqlite {
            path: path.clone(),
            source: e,
        })?;

        // Apply pragmas in the order Go's makeAccessorImpl does:
        // 1. secure_delete=ON via URI param (Go) — we apply via PRAGMA
        //    so the same code path works for both new and existing DBs.
        // 2. journal_mode=WAL (matches Go's URI param).
        // 3. busy_timeout=1000 (matches Go's URI param).
        // 4. synchronous=FULL (matches Go's post-connect call to
        //    SetSynchronousMode at dbutil.go:132).
        //
        // Each pragma's effect is verifiable post-open; we check
        // secure_delete and journal_mode below since those are the
        // ones that meaningfully change DB behaviour and are
        // safety-critical for partkey storage.
        apply_pragma(&conn, &path, "PRAGMA secure_delete = ON")?;
        apply_pragma(&conn, &path, "PRAGMA journal_mode = WAL")?;
        apply_pragma(&conn, &path, "PRAGMA busy_timeout = 1000")?;
        apply_pragma(&conn, &path, "PRAGMA synchronous = FULL")?;

        // Sanity-check secure_delete is actually on. sqlite returns
        // `1` for ON and `0` for OFF (or `2` for FAST in newer
        // versions). Anything other than 1/2 means the pragma silently
        // didn't take, which on a partkey DB is a security bug.
        let secure: i64 = conn
            .query_row("PRAGMA secure_delete", [], |row| row.get(0))
            .map_err(|e| Error::Sqlite {
                path: path.clone(),
                source: e,
            })?;
        if secure == 0 {
            return Err(Error::PragmaMismatch {
                path: path.clone(),
                pragma: "secure_delete",
                expected: "1 or 2",
                actual: secure.to_string(),
            });
        }

        // Confirm journal_mode actually became `wal`. SQLite silently
        // returns a different mode for paths it can't put into WAL
        // (e.g. `:memory:` → `memory`, network-mounted files may stay
        // `delete`). For partkey DBs we need WAL to match Go's
        // behaviour and avoid divergent crash-recovery semantics.
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(|e| Error::Sqlite {
                path: path.clone(),
                source: e,
            })?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(Error::PragmaMismatch {
                path: path.clone(),
                pragma: "journal_mode",
                expected: "wal",
                actual: mode,
            });
        }

        Ok(Self { conn, path })
    }

    /// Borrow the underlying sqlite connection.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Borrow the underlying sqlite connection mutably.
    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Path the accessor was opened against (for error messages).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Close the connection. Returns any final fsync / WAL checkpoint
    /// error. Equivalent to dropping `self`, but lets callers observe
    /// the close-time error explicitly (matches Go's
    /// `partdb.Close()` pattern in algokey).
    pub fn close(self) -> Result<(), Error> {
        let Self { conn, path } = self;
        conn.close().map_err(|(_, e)| Error::Sqlite {
            path: path.clone(),
            source: e,
        })
    }
}

fn apply_pragma(conn: &Connection, path: &Path, sql: &str) -> Result<(), Error> {
    conn.execute_batch(sql).map_err(|e| Error::Sqlite {
        path: path.to_path_buf(),
        source: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn open_applies_secure_delete_and_wal() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("p.sqlite");
        let db = ErasableDb::open(&path).unwrap();
        let secure: i64 = db
            .conn()
            .query_row("PRAGMA secure_delete", [], |r| r.get(0))
            .unwrap();
        assert!(secure == 1 || secure == 2, "secure_delete is {secure}");
        let mode: String = db
            .conn()
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        // sqlite returns the mode lowercased post-set.
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        let busy: i64 = db
            .conn()
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(busy, 1000);
        let sync: i64 = db
            .conn()
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        // FULL == 2, EXTRA == 3. Both honor `secure_delete` writes.
        assert!(sync >= 2, "synchronous level {sync} must be >= FULL(2)");
    }

    /// Round-trip: write a row, delete it, close the connection, and
    /// confirm the raw file no longer contains the secret pattern. This
    /// is the security property `secure_delete=ON` is supposed to
    /// provide — Go relies on this for partkey storage.
    #[test]
    fn secret_pattern_is_zeroed_after_delete_and_checkpoint() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("p.sqlite");
        // Use a distinctive pattern that sqlite wouldn't otherwise
        // emit — e.g. b"DELETE_ME_SECURELY_xxxxxx".
        let secret = b"DELETE_ME_SECURELY_XXXX1234567890ABCDEF" as &[u8];
        {
            let db = ErasableDb::open(&path).unwrap();
            db.conn()
                .execute_batch("CREATE TABLE k(v BLOB); INSERT INTO k(v) VALUES (zeroblob(0));")
                .unwrap();
            db.conn()
                .execute("INSERT INTO k(v) VALUES (?1)", [secret])
                .unwrap();
            db.conn().execute("DELETE FROM k", []).unwrap();
            // Force a WAL checkpoint so the page-level zeroing lands
            // on the main file before we inspect it.
            db.conn()
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .unwrap();
            db.close().unwrap();
        }
        // Inspect the raw file bytes.
        let bytes = std::fs::read(&path).unwrap();
        let still_present = bytes.windows(secret.len()).any(|w| w == secret);
        assert!(
            !still_present,
            "secret pattern still found in DB file after secure delete; \
             secure_delete=ON did not zero the page (file size: {} bytes)",
            bytes.len()
        );
    }

    /// Read-only open also applies the pragmas (so a partkey DB can
    /// be inspected without ever writing).
    #[test]
    fn read_only_open_after_setup() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("p.sqlite");
        // Initialise once read/write.
        {
            let db = ErasableDb::open(&path).unwrap();
            db.conn()
                .execute_batch("CREATE TABLE k(v BLOB); INSERT INTO k(v) VALUES (zeroblob(8));")
                .unwrap();
            db.close().unwrap();
        }
        // Reopen RO and confirm we can read.
        let db = ErasableDb::open_read_only(&path).unwrap();
        let n: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM k", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }
}
