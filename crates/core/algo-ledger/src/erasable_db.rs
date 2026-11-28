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
//! `util/db.MakeErasableAccessor` (v5.1.1-stable): `secure_delete`, `temp_store=MEMORY`
//! and `EraseWAL` (`util/db/walerase.go`).
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
    read_only: bool,
    /// go's `eraseWALAfterOverwrite` (tests only): runs inside
    /// [`ErasableDb::erase_wal`] once the log has been overwritten and before
    /// it is truncated.
    erase_wal_after_overwrite: Option<Box<dyn FnMut() + Send>>,
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
    /// `EraseWAL` failed; the text is go's (`EraseWAL: ...`).
    #[error("{0}")]
    EraseWal(String),
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
        // go's `erasableDriverName` connect hook: SQLite's temporary files
        // stay in memory. With secure_delete on, zeroing a freed page first
        // saves the page's original content in the statement or savepoint
        // journal, and a journal that spilled to disk would leave that content
        // in an unlinked, never-overwritten temp file outside the database.
        apply_pragma(&conn, &path, "PRAGMA temp_store = MEMORY")?;

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

        Ok(Self {
            conn,
            path,
            read_only: flags.contains(OpenFlags::SQLITE_OPEN_READ_ONLY),
            erase_wal_after_overwrite: None,
        })
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

    /// go's `SetEraseWALHook`: a function [`ErasableDb::erase_wal`] runs once
    /// it has overwritten the log and before it truncates it, so tests can
    /// inspect the overwritten log (afterwards, truncation leaves nothing to
    /// tell overwriting from). `None` removes it.
    #[doc(hidden)]
    pub fn set_erase_wal_hook(&mut self, hook: Option<Box<dyn FnMut() + Send>>) {
        self.erase_wal_after_overwrite = hook;
    }

    /// go's `walCheckpoint`: `PRAGMA wal_checkpoint(<mode>)` and its result,
    /// `(busy, log frames (-1 when not in WAL mode), checkpointed frames)`.
    pub fn wal_checkpoint(&self, mode: &str) -> Result<(i64, i64, i64), Error> {
        self.conn
            .query_row(&format!("PRAGMA wal_checkpoint({mode})"), [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|e| self.sqlite_err(e))
    }

    fn sqlite_err(&self, source: rusqlite::Error) -> Error {
        Error::Sqlite {
            path: self.path.clone(),
            source,
        }
    }

    /// go's `Accessor.EraseWAL` (`util/db/walerase.go`): overwrites the page
    /// images in the database's write-ahead log with zeros and truncates the
    /// log, unless the log holds nothing but the last transaction.
    ///
    /// SQLite appends the new image of every page a transaction modifies to the
    /// log and, once a checkpoint has copied the images into the database file
    /// and no reader needs them, restarts the log from the beginning at the
    /// next transaction. A frame is only ever overwritten by a later frame
    /// landing on the same offset, so the image of a page as it was before a
    /// row was deleted (the row is zeroed by secure_delete in the new image)
    /// stays readable in the file until the log is refilled that far or
    /// truncated, and truncation only unlinks the blocks. For a store whose
    /// deletions are the point, such as retired signing keys, that keeps
    /// deleted content around long after the delete.
    ///
    /// Meant to run after every write transaction. It checkpoints in RESTART
    /// mode, then inspects the log: if its frames are exactly the final page
    /// images of one transaction and nothing lies beyond them, nothing is stale;
    /// otherwise, or with `all` set (a bulk write whose rows will be deleted
    /// one at a time), it writes zero-filled pages at least as far as the file
    /// extends, which overwrites every frame in place, and checkpoints in
    /// TRUNCATE mode to drop the file to zero bytes. A call that finds readers
    /// holding the log leaves it for the next call. The zero pages become free
    /// pages of the database, at most [`WAL_ERASE_CHUNK_BYTES`] of them.
    ///
    /// The caller must be the only writer to the database, in this and any
    /// other process, from its last write transaction until this returns;
    /// before truncating, it checks that the log holds exactly the zero pages
    /// it wrote and refuses to truncate otherwise.
    pub fn erase_wal(&mut self, all: bool) -> Result<(), Error> {
        if self.read_only {
            return Ok(());
        }
        let wal_path = wal_path_of(&self.path);
        let (busy, log_frames, checkpointed) = self.wal_checkpoint("RESTART")?;
        if log_frames < 0 {
            return Ok(()); // not in WAL mode
        }
        if busy != 0 || checkpointed != log_frames {
            tracing::warn!(
                "EraseWAL: readers hold the write-ahead log of {} ({checkpointed} of {log_frames} frames checkpointed); deferred to the next write",
                self.path.display()
            );
            return Ok(());
        }

        let info = read_wal_file_info(&wal_path, log_frames, WAL_MAX_PARSED_FRAMES)
            .map_err(|e| Error::EraseWal(format!("EraseWAL: {e}")))?;
        if info.frames == 0 {
            return Ok(());
        }
        if !all && info.frames == log_frames && info.all_current() {
            return Ok(()); // only the last transaction's final images: nothing is stale
        }

        let chunks = self
            .overwrite_wal(&info)
            .map_err(|e| Error::EraseWal(format!("EraseWAL: writing zero pages: {e}")))?;
        if let Some(hook) = self.erase_wal_after_overwrite.as_mut() {
            hook(); // tests: inspect the log before it is truncated
        }

        // Truncating releases whatever the file holds, so first make sure that
        // is exactly the zero pages just written: a PASSIVE checkpoint (the
        // TRUNCATE one reports an empty log once it has reset it) gives the
        // frames of the log, which must be at least as many as were to be
        // covered, all of the current generation, committed by exactly the
        // cover transactions, and end at the end of the file.
        let (_, log_frames, _) = self.wal_checkpoint("PASSIVE")?;
        let after = read_wal_file_info(&wal_path, log_frames, log_frames)
            .map_err(|e| Error::EraseWal(format!("EraseWAL: {e}")))?;
        if log_frames < info.frames {
            return Err(Error::EraseWal(format!(
                "EraseWAL: wrote {log_frames} frames of zeros, fewer than the {} frames of the log",
                info.frames
            )));
        }
        let expected_size = WAL_HEADER_SIZE + log_frames * (WAL_FRAME_HEADER_SIZE + info.page_size);
        if !after.current || after.commits != chunks || after.size != expected_size {
            return Err(Error::EraseWal(format!(
                "EraseWAL: another writer used the write-ahead log of {} while it was being erased ({} transactions in {log_frames} frames, {} bytes); not truncated",
                self.path.display(),
                after.commits,
                after.size
            )));
        }
        let (busy, _, _) = self.wal_checkpoint("TRUNCATE")?;
        if busy != 0 {
            tracing::warn!(
                "EraseWAL: readers hold the write-ahead log of {}; it is overwritten but not truncated",
                self.path.display()
            );
        }
        Ok(())
    }

    /// go's `overwriteWAL`: writes at least `info.frames` frames of zero pages
    /// to the log, in transactions of [`WAL_ERASE_CHUNK_BYTES`] each, and
    /// returns how many transactions it committed. A transaction inserts and
    /// deletes a blob of zeros: the insert dirties one overflow page per page of
    /// the blob and the delete leaves them as zeroed free pages
    /// (secure_delete), each written once, so the commit is at least that many
    /// frames of zeros. The transactions append to one another (automatic
    /// checkpoints are off while they run), starting from the first frame
    /// since the caller's checkpoint made the log restart; each reuses the free
    /// pages of the previous one, so the database grows by at most one chunk.
    fn overwrite_wal(&self, info: &WalFileInfo) -> Result<i64, rusqlite::Error> {
        let auto_checkpoint: i64 = self
            .conn
            .query_row("PRAGMA wal_autocheckpoint", [], |r| r.get(0))?;
        self.conn.execute_batch("PRAGMA wal_autocheckpoint=0")?;
        let result = self.overwrite_wal_chunks(info);
        // go: deferred; the setting goes back whatever happened
        let restore = self
            .conn
            .execute_batch(&format!("PRAGMA wal_autocheckpoint={auto_checkpoint}"));
        let chunks = result?;
        restore?;
        Ok(chunks)
    }

    fn overwrite_wal_chunks(&self, info: &WalFileInfo) -> Result<i64, rusqlite::Error> {
        self.conn.execute_batch("PRAGMA secure_delete=ON")?;
        let chunk = (WAL_ERASE_CHUNK_BYTES / info.page_size).max(1);
        let mut chunks = 0i64;
        let mut remaining = info.frames;
        while remaining > 0 {
            let n = remaining.min(chunk);
            // the scratch table is created within the first transaction rather
            // than in one of its own, so the log's transactions are exactly the
            // chunks
            let batch = format!(
                "BEGIN; CREATE TABLE IF NOT EXISTS {WAL_ERASE_TABLE} (zeros BLOB); \
                 INSERT INTO {WAL_ERASE_TABLE} VALUES (zeroblob({})); \
                 DELETE FROM {WAL_ERASE_TABLE}; COMMIT;",
                n * info.page_size
            );
            if let Err(e) = self.conn.execute_batch(&batch) {
                let _ = self.conn.execute_batch("ROLLBACK");
                return Err(e);
            }
            chunks += 1;
            remaining -= chunk;
        }
        Ok(chunks)
    }

    /// Close the connection. Returns any final fsync / WAL checkpoint
    /// error. Equivalent to dropping `self`, but lets callers observe
    /// the close-time error explicitly (matches Go's
    /// `partdb.Close()` pattern in algokey).
    pub fn close(self) -> Result<(), Error> {
        let Self { conn, path, .. } = self;
        conn.close().map_err(|(_, e)| Error::Sqlite {
            path: path.clone(),
            source: e,
        })
    }
}

// ---- write-ahead log inspection (util/db/walerase.go) -----------------------

/// Write-ahead log file layout (<https://www.sqlite.org/walformat.html>): a
/// 32-byte header, then one frame per written page, each a 24-byte frame
/// header followed by the page image. Frames of the current generation of the
/// log carry the salts of the file header; a nonzero "database size" field
/// marks the last frame of a transaction.
pub const WAL_HEADER_SIZE: i64 = 32;
/// See [`WAL_HEADER_SIZE`].
pub const WAL_FRAME_HEADER_SIZE: i64 = 24;
/// go's `walMaxParsedFrames`: how much of the log `erase_wal` reads to decide
/// whether it is stale; a longer log is erased without looking.
pub const WAL_MAX_PARSED_FRAMES: i64 = 64;
/// go's `walEraseTable`: the scratch table `erase_wal` writes zero pages
/// through.
const WAL_ERASE_TABLE: &str = "walErase";
/// go's `walEraseChunkBytes`: the size of the blob of zeros each transaction of
/// the overwrite writes; the database grows by at most this much.
pub const WAL_ERASE_CHUNK_BYTES: i64 = 1 << 20;

/// go's `walFileInfo`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WalFileInfo {
    /// Bytes.
    pub size: i64,
    /// Frames the file extends to, a partial trailing one included.
    pub frames: i64,
    pub page_size: i64,
    /// The first `log_frames` frames were inspected (there were at most
    /// `max_parse` of them).
    pub parsed: bool,
    /// All carry the salts of the file header, i.e. belong to the current
    /// generation of the log.
    pub current: bool,
    /// Commit markers among them, one per transaction.
    pub commits: i64,
    /// A page appears more than once.
    pub repeated: bool,
}

impl WalFileInfo {
    /// go's `allCurrent`: whether the inspected frames are exactly the final
    /// page images of one committed transaction: all of the current
    /// generation, one commit marker, and no page written twice (a page spilled
    /// from the cache mid-transaction and written again at commit leaves an
    /// earlier image, which may hold content the transaction went on to
    /// delete). A log that was not inspected is not current.
    pub fn all_current(&self) -> bool {
        self.parsed && self.current && self.commits == 1 && !self.repeated
    }
}

fn wal_path_of(db: &Path) -> PathBuf {
    let mut p = db.as_os_str().to_owned();
    p.push("-wal");
    PathBuf::from(p)
}

/// go's `readWALFileInfo`: reads the write-ahead log's header and, if there
/// are at most `max_parse` of them, the headers of its first `log_frames`
/// frames. A missing log is an empty [`WalFileInfo`].
pub fn read_wal_file_info(
    path: &Path,
    log_frames: i64,
    max_parse: i64,
) -> Result<WalFileInfo, String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut info = WalFileInfo::default();
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(info),
        Err(e) => return Err(go_path_error("open", path, &e)),
    };
    let io_err = |e: std::io::Error| e.to_string();
    info.size = f.metadata().map_err(io_err)?.len() as i64;
    if info.size <= WAL_HEADER_SIZE {
        return Ok(info);
    }

    let mut header = [0u8; WAL_HEADER_SIZE as usize];
    f.read_exact(&mut header).map_err(io_err)?;
    info.page_size = i64::from(u32::from_be_bytes(header[8..12].try_into().unwrap()));
    if info.page_size < 512 {
        return Err(format!(
            "write-ahead log {} has an invalid page size {}",
            path.display(),
            info.page_size
        ));
    }
    let frame_size = WAL_FRAME_HEADER_SIZE + info.page_size;
    info.frames = (info.size - WAL_HEADER_SIZE + frame_size - 1) / frame_size;

    if log_frames > max_parse || log_frames > info.frames {
        return Ok(info);
    }
    info.parsed = true;
    info.current = true;
    let salt = &header[16..24];
    let mut pages = std::collections::HashSet::with_capacity(log_frames.max(0) as usize);
    for i in 0..log_frames {
        let mut frame = [0u8; WAL_FRAME_HEADER_SIZE as usize];
        f.seek(SeekFrom::Start((WAL_HEADER_SIZE + i * frame_size) as u64))
            .map_err(io_err)?;
        f.read_exact(&mut frame).map_err(io_err)?;
        if &frame[8..16] != salt {
            info.current = false;
            return Ok(info);
        }
        let page = u32::from_be_bytes(frame[0..4].try_into().unwrap());
        if !pages.insert(page) {
            info.repeated = true;
        }
        if u32::from_be_bytes(frame[4..8].try_into().unwrap()) != 0 {
            info.commits += 1;
        }
    }
    Ok(info)
}

/// How go's `os` package words an I/O error (`open <path>: no such file or
/// directory`).
fn go_path_error(op: &str, path: &Path, e: &std::io::Error) -> String {
    let text = e.to_string();
    let text = text.split(" (os error").next().unwrap_or(&text);
    let mut chars = text.chars();
    let text = match chars.next() {
        Some(c) => c.to_lowercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    };
    format!("{op} {}: {text}", path.display())
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

/// Ports of go-algorand v5.1.1-stable's `util/db/walerase_test.go` and
/// `TestErasableAccessorTempStoreInMemory` (`dbutil_test.go`).
#[cfg(test)]
mod wal_erase_tests {
    use super::*;
    use rand::Rng;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// go's `walEraseFixture`: a file-backed erasable database with a table of
    /// random blobs, each large enough to be recognizable and small enough to
    /// stay in its leaf page.
    struct Fixture {
        db: ErasableDb,
        path: PathBuf,
        _dir: tempfile::TempDir,
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    /// The bytes of the database file (`""`) or of one of its siblings
    /// (`"-wal"`); empty when it does not exist.
    fn file_of(path: &Path, suffix: &str) -> Vec<u8> {
        let mut p = path.as_os_str().to_owned();
        p.push(suffix);
        std::fs::read(PathBuf::from(p)).unwrap_or_default()
    }

    /// go's `walPageImages`: the page image of every frame of the log.
    fn wal_page_images_of(path: &Path) -> Vec<Vec<u8>> {
        let data = file_of(path, "-wal");
        let mut images = Vec::new();
        let step = (WAL_FRAME_HEADER_SIZE + 4096) as usize;
        let mut off = WAL_HEADER_SIZE as usize;
        while off + step <= data.len() {
            images.push(data[off + WAL_FRAME_HEADER_SIZE as usize..off + step].to_vec());
            off += step;
        }
        images
    }

    fn random_blob(len: usize) -> Vec<u8> {
        let mut blob = vec![0u8; len];
        rand::rng().fill_bytes(&mut blob);
        blob
    }

    impl Fixture {
        fn new() -> Fixture {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("erase.sqlite");
            let mut db = ErasableDb::open(&path).unwrap();
            db.conn()
                .execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB)")
                .unwrap();
            // start each test with an empty log
            db.erase_wal(true).unwrap();
            let f = Fixture {
                db,
                path,
                _dir: dir,
            };
            assert_eq!(f.wal_size(), 0);
            f
        }

        /// Adds `n` random rows in one transaction and returns their blobs.
        fn insert(&self, n: usize) -> Vec<Vec<u8>> {
            let tx = self.db.conn().unchecked_transaction().unwrap();
            let mut added = Vec::new();
            for _ in 0..n {
                let blob = random_blob(300);
                tx.execute("INSERT INTO t (v) VALUES (?1)", [&blob])
                    .unwrap();
                added.push(blob);
            }
            tx.commit().unwrap();
            added
        }

        fn exec(&self, query: &str, id: Option<i64>) {
            let tx = self.db.conn().unchecked_transaction().unwrap();
            match id {
                Some(id) => tx.execute(query, [id]).unwrap(),
                None => tx.execute(query, []).unwrap(),
            };
            tx.commit().unwrap();
        }

        fn query_int(&self, query: &str) -> i64 {
            self.db.conn().query_row(query, [], |r| r.get(0)).unwrap()
        }

        fn file(&self, suffix: &str) -> Vec<u8> {
            file_of(&self.path, suffix)
        }

        fn wal_size(&self) -> i64 {
            self.file("-wal").len() as i64
        }
    }

    /// go `TestErasableAccessorTempStoreInMemory`.
    #[test]
    fn erasable_accessor_temp_store_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        let db = ErasableDb::open(dir.path().join("erasable.sqlite")).unwrap();
        let temp_store: i64 = db
            .conn()
            .query_row("PRAGMA temp_store", [], |r| r.get(0))
            .unwrap();
        assert_eq!(temp_store, 2); // 2 is MEMORY
    }

    /// go `TestEraseWAL`.
    #[test]
    fn erase_wal() {
        let mut f = Fixture::new();

        // one transaction in the log: its frames are the current page images,
        // so a routine erase leaves them alone
        let first = f.insert(40);
        assert!(
            contains(&f.file("-wal"), &first[0]),
            "the log does not hold the written rows; the test proves nothing"
        );
        let size_before = f.wal_size();
        f.db.erase_wal(false).unwrap();
        assert_eq!(
            size_before,
            f.wal_size(),
            "a single-transaction log was rewritten"
        );
        assert!(contains(&f.file("-wal"), &first[0]));

        // a second transaction makes the first one's images stale: the delete's
        // new image of the leaf has the row zeroed (secure_delete), the
        // insert's image still holds it
        f.exec("DELETE FROM t WHERE id=?1", Some(1));
        assert!(contains(&f.file("-wal"), &first[0]));
        f.db.erase_wal(false).unwrap();
        assert_eq!(f.wal_size(), 0, "the log was not truncated");
        assert!(
            !contains(&f.file(""), &first[0]),
            "deleted row survives in the database file"
        );
        for blob in &first[1..] {
            assert!(
                contains(&f.file(""), blob),
                "live row missing from the database file"
            );
        }

        // the log restarted at the next write, so a single transaction is all
        // it holds again; all=true erases it regardless
        let second = f.insert(40);
        assert!(contains(&f.file("-wal"), &second[0]));
        f.db.erase_wal(true).unwrap();
        assert_eq!(f.wal_size(), 0);
        assert_eq!(f.query_int("SELECT count(*) FROM t"), 79);

        // the zero pages of an erase become free pages that the next erase
        // reuses: the database holds its data plus at most the largest log
        // erased, and a routine erase after a deletion does not grow it
        assert!(f.query_int("PRAGMA freelist_count") > 0);
        let pages = f.query_int("PRAGMA page_count");
        for id in [2i64, 4, 6] {
            f.exec("DELETE FROM t WHERE id=?1", Some(id));
            f.exec("DELETE FROM t WHERE id=?1", Some(id + 1));
            f.db.erase_wal(false).unwrap();
            assert_eq!(f.wal_size(), 0);
            assert_eq!(
                pages,
                f.query_int("PRAGMA page_count"),
                "the database grew on a routine erase"
            );
            assert!(!contains(&f.file(""), &first[(id - 1) as usize]));
        }

        // an empty log (nothing written since) is left alone
        f.db.erase_wal(true).unwrap();
        assert_eq!(f.wal_size(), 0);
    }

    /// go `TestEraseWALLargeLog`: a log larger than a chunk is erased and the
    /// database grows by at most a chunk of free pages.
    #[test]
    fn erase_wal_large_log() {
        let mut f = Fixture::new();

        // ~3 MB in one transaction, about three chunks of log
        let mut blobs = Vec::new();
        {
            let tx = f.db.conn().unchecked_transaction().unwrap();
            for _ in 0..3000 {
                let blob = random_blob(1000);
                tx.execute("INSERT INTO t (v) VALUES (?1)", [&blob])
                    .unwrap();
                blobs.push(blob);
            }
            tx.commit().unwrap();
        }
        assert!(f.wal_size() > 2 * WAL_ERASE_CHUNK_BYTES);
        let pages_before = f.query_int("PRAGMA page_count");
        f.db.erase_wal(true).unwrap();
        assert_eq!(f.wal_size(), 0);
        let growth = f.query_int("PRAGMA page_count") - pages_before;
        assert!(
            growth <= WAL_ERASE_CHUNK_BYTES / 4096 + 4,
            "the database grew by more than a chunk"
        );
        assert_eq!(growth, f.query_int("PRAGMA freelist_count"));
        let file = f.file("");
        for blob in &blobs[..50] {
            assert!(contains(&file, blob));
        }
        assert_eq!(f.query_int("SELECT count(*) FROM t"), 3000);

        // automatic checkpoints are back on the connection the erase used
        assert_eq!(f.query_int("PRAGMA wal_autocheckpoint"), 1000);
    }

    /// go `TestEraseWALLogAccounting`: the log inspection that decides whether
    /// a routine erase has anything to do.
    #[test]
    fn erase_wal_log_accounting() {
        let mut f = Fixture::new();
        let wal_path = wal_path_of(&f.path);

        // two transactions since the log was last restarted
        f.insert(40);
        f.exec("DELETE FROM t WHERE id=?1", Some(1));
        let (_, log_frames, _) = f.db.wal_checkpoint("PASSIVE").unwrap();
        let info = read_wal_file_info(&wal_path, log_frames, WAL_MAX_PARSED_FRAMES).unwrap();
        assert_eq!(info.page_size, 4096);
        assert_eq!(info.frames, log_frames);
        assert!(info.parsed && info.current);
        assert_eq!(info.commits, 2);
        assert!(!info.all_current());

        // after a restart the log holds one transaction but the file still
        // extends to the previous generation's frames
        f.db.erase_wal(false).unwrap(); // truncates
        f.insert(40);
        f.exec("DELETE FROM t WHERE id=?1", Some(2));
        f.db.wal_checkpoint("RESTART").unwrap();
        f.exec("DELETE FROM t WHERE id=?1", Some(3)); // restarts the log
        let (_, log_frames, _) = f.db.wal_checkpoint("PASSIVE").unwrap();
        let info = read_wal_file_info(&wal_path, log_frames, WAL_MAX_PARSED_FRAMES).unwrap();
        assert!(info.all_current());
        assert!(
            info.frames > log_frames,
            "older frames beyond the restarted log"
        );

        // a log longer than the inspection limit is not inspected
        let info = read_wal_file_info(&wal_path, log_frames, log_frames - 1).unwrap();
        assert!(!info.parsed);
        assert!(!info.all_current());

        // a missing log
        let dir = tempfile::tempdir().unwrap();
        let info =
            read_wal_file_info(&dir.path().join("none-wal"), 0, WAL_MAX_PARSED_FRAMES).unwrap();
        assert_eq!(info.frames, 0);
    }

    /// go `TestEraseWALOverwritesBeforeTruncate`: the log after the zero pages
    /// were written and before it is truncated: every frame of the old extent is
    /// overwritten (truncation alone would only release the bytes), and the only
    /// page images that are not all zeros are the few structural pages a chunk
    /// touches (the first page, the scratch table's root, the free-list trunk).
    #[test]
    fn erase_wal_overwrites_before_truncate() {
        let mut f = Fixture::new();
        let first = f.insert(40);
        f.exec("DELETE FROM t WHERE id=?1", Some(1));
        assert!(contains(&f.file("-wal"), &first[0]));
        let size_before = f.wal_size();

        let inspected = Arc::new(AtomicBool::new(false));
        let flag = inspected.clone();
        let path = f.path.clone();
        let target = first[0].clone();
        f.db.set_erase_wal_hook(Some(Box::new(move || {
            flag.store(true, Ordering::SeqCst);
            assert!(
                file_of(&path, "-wal").len() as i64 >= size_before,
                "the log was truncated before being overwritten"
            );
            assert!(
                !contains(&file_of(&path, "-wal"), &target),
                "the deleted row's image survived the overwrite"
            );
            let non_zero = wal_page_images_of(&path)
                .iter()
                .filter(|image| image.iter().any(|b| *b != 0))
                .count();
            assert!(non_zero <= 3, "more than the structural pages are not zero");
        })));
        f.db.erase_wal(false).unwrap();
        assert!(inspected.load(Ordering::SeqCst));
        assert_eq!(f.wal_size(), 0);
    }

    /// go `TestEraseWALRefusesToTruncateAfterConcurrentWrite`: a transaction
    /// another connection commits while the log is being erased is detected:
    /// the erase fails instead of truncating, so the frames are not released
    /// unerased, and the next erase covers them.
    #[test]
    fn erase_wal_refuses_to_truncate_after_concurrent_write() {
        let mut f = Fixture::new();
        f.insert(40);
        f.exec("DELETE FROM t WHERE id=?1", Some(1));

        let other = ErasableDb::open(&f.path).unwrap();
        let marker = random_blob(300);
        let path = f.path.clone();
        let hook_marker = marker.clone();
        f.db.set_erase_wal_hook(Some(Box::new(move || {
            other
                .conn()
                .execute("INSERT INTO t (v) VALUES (?1)", [&hook_marker])
                .unwrap();
            assert!(contains(&file_of(&path, "-wal"), &hook_marker));
        })));
        let err = f.db.erase_wal(false).unwrap_err().to_string();
        assert!(err.contains("another writer"), "{err}");
        assert!(
            contains(&f.file("-wal"), &marker),
            "the concurrent transaction's frames were released"
        );

        // without interference the next erase covers the leftover frames; the
        // row itself is data, still in the database
        f.db.set_erase_wal_hook(None);
        f.db.erase_wal(false).unwrap();
        assert_eq!(f.wal_size(), 0);
        assert!(contains(&f.file(""), &marker));
    }

    /// go `TestEraseWALSpilledFrames`: a single transaction whose pages were
    /// spilled from the cache and written again at commit is not taken for a
    /// log of current images: the spilled image of a page still holds a row the
    /// transaction deleted afterwards.
    #[test]
    fn erase_wal_spilled_frames() {
        let mut f = Fixture::new();
        let first = f.insert(200); // ~15 leaf pages
        f.db.erase_wal(true).unwrap();

        // a cache of two pages on the one connection, so the transaction below
        // spills as it goes
        f.db.conn().execute_batch("PRAGMA cache_size=2").unwrap();
        // dirty the first leaf, then every other leaf (spilling the first),
        // then the first leaf again: its first image still holds row 2
        f.db.conn()
            .execute_batch(
                "BEGIN; DELETE FROM t WHERE id=1; UPDATE t SET v=v WHERE id>20; \
                 DELETE FROM t WHERE id=2; COMMIT;",
            )
            .unwrap();
        let (_, log_frames, _) = f.db.wal_checkpoint("PASSIVE").unwrap();
        let info =
            read_wal_file_info(&wal_path_of(&f.path), log_frames, WAL_MAX_PARSED_FRAMES).unwrap();
        assert_eq!(log_frames, info.frames);
        assert!(info.repeated);
        assert!(!info.all_current(), "spilled images went unnoticed");
        assert!(
            contains(&f.file("-wal"), &first[1]),
            "no spilled image of the deleted row; the test proves nothing"
        );
        assert!(!contains(&f.file(""), &first[1]));

        f.db.erase_wal(false).unwrap();
        assert_eq!(f.wal_size(), 0);
        assert!(!contains(&f.file(""), &first[1]));
    }

    /// go `TestEraseWALDeferredUnderReader`: a reader that keeps the
    /// checkpoint from completing makes the erase wait for the next call
    /// rather than fail.
    #[test]
    fn erase_wal_deferred_under_reader() {
        let mut f = Fixture::new();
        let first = f.insert(40);
        f.exec("DELETE FROM t WHERE id=?1", Some(1));

        // a short busy timeout on the erasing connection so the test does not
        // wait out the default
        f.db.conn().execute_batch("PRAGMA busy_timeout=50").unwrap();

        let (holding_tx, holding_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let path = f.path.clone();
        let reader = std::thread::spawn(move || {
            let reader = ErasableDb::open_read_only(&path).unwrap();
            reader.conn().execute_batch("BEGIN").unwrap();
            let _: i64 = reader
                .conn()
                .query_row("SELECT count(*) FROM t", [], |r| r.get(0))
                .unwrap();
            holding_tx.send(()).unwrap();
            let _ = release_rx.recv();
            reader.conn().execute_batch("COMMIT").unwrap();
        });
        holding_rx.recv().unwrap();

        let size_before = f.wal_size();
        f.db.erase_wal(false).unwrap();
        assert_eq!(
            size_before,
            f.wal_size(),
            "the log changed while a reader held it"
        );
        assert!(contains(&f.file("-wal"), &first[0]));

        release_tx.send(()).unwrap();
        reader.join().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if f.db.erase_wal(false).is_ok() && f.wal_size() == 0 {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "never erased");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!contains(&f.file(""), &first[0]));
    }
}
