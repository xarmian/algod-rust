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

//! Lock-free reads of committed ledger state (issue #1764).
//!
//! REST `get_block` / `get_block_header` / account lookups and the
//! agreement `seed` / `lookup_digest` / `lookup_agreement` reads used to take
//! the `Arc<Mutex<SqliteLedger>>`, so they queued behind a slow block apply
//! that holds it. [`LedgerReadPool`] serves them from separate **read-only**
//! SQLite connections to the same tracker + block files instead.
//!
//! # Why this is safe
//!
//! * **Committed state only.** The writer applies a block inside one open
//!   transaction (`begin_block` .. `commit_block`) that also holds the
//!   block's `put_block` row. In WAL mode a reader on another connection
//!   sees only committed transactions, so a half-applied block is never
//!   visible. Every read here is a single autocommit statement (or a single
//!   multi-subselect statement), so no read transaction outlives a call and
//!   the WAL is never pinned (see `tests/wal_reader_pin_test.rs`).
//! * **Two files, no cross-file atomicity.** The tracker and block files
//!   commit one after the other (see the split-commit note on
//!   [`crate::SqliteLedger::open_split`]), so a reader can observe the
//!   tracker at round `N` while the block row for `N` is not visible yet.
//!   A *found* row is always served (its block commit finished). A *miss*
//!   is never trusted when the committed tracker round says the row should
//!   exist (`round <= committed`): it is reported as
//!   [`PoolRead::Fallback`] and the caller takes the locked path, which is
//!   authoritative. Only a miss beyond the committed round is a lock-free
//!   `NotFound`.
//! * **Any error falls back.** An open/IO/schema error never produces a
//!   wrong answer: the connection is discarded and the caller falls back to
//!   the locked path.
//! * **Connection lifecycle.** Connections hold no state across calls
//!   (no open transaction, no pinned snapshot), so a catchpoint cutover
//!   (which writes the same files through the writer connection) or a
//!   ledger reopen needs no invalidation; a stale connection after file
//!   replacement errors and is dropped, and the next call reopens.
//! * **Byte-identical.** The SQL and decoders are the ones the locked
//!   accessors use.
//!
//! In-memory ledgers have no files and therefore no pool: they keep the
//! locked path.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use algo_error::AlgoError;
use algo_types::{AccountData, AccountStatus, Address, BlockHeader};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::sqlite::{decode_account_data, decode_online_account_data, SqliteLedger};

/// Idle connections kept for reuse; bursts above this open (and later close)
/// extra connections rather than queueing.
const MAX_IDLE_CONNECTIONS: usize = 4;

/// Outcome of a lock-free read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolRead<T> {
    /// Served from committed state.
    Found(T),
    /// Definitely not committed yet / not present: beyond the committed
    /// round, so the locked path would say the same.
    NotFound,
    /// The lock-free path cannot answer authoritatively (error, or a miss
    /// at a round the tracker says is committed). Use the locked path.
    Fallback,
}

/// Read-only connection pool over a file-backed ledger's tracker + block
/// files. See the module docs.
pub struct LedgerReadPool {
    tracker_path: PathBuf,
    block_path: PathBuf,
    idle: Mutex<Vec<Connection>>,
    /// `(round, rewards_level)` of the last committed header read for a
    /// `lookup_agreement` reward fold. Only committed rounds are stored.
    rewards_cache: Mutex<Option<(u64, u64)>>,
}

impl std::fmt::Debug for LedgerReadPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerReadPool")
            .field("tracker_path", &self.tracker_path)
            .field("block_path", &self.block_path)
            .finish()
    }
}

impl LedgerReadPool {
    pub(crate) fn new(tracker_path: PathBuf, block_path: PathBuf) -> Self {
        Self {
            tracker_path,
            block_path,
            idle: Mutex::new(Vec::new()),
            rewards_cache: Mutex::new(None),
        }
    }

    fn open(&self) -> Result<Connection, rusqlite::Error> {
        let conn = Connection::open_with_flags(
            &self.tracker_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(Duration::from_secs(2))?;
        // The attached schema inherits the read-only open flags.
        conn.execute(
            "ATTACH DATABASE ?1 AS blockdb",
            params![self.block_path.to_string_lossy().as_ref()],
        )?;
        conn.set_prepared_statement_cache_capacity(32);
        Ok(conn)
    }

    /// Run `f` on a pooled connection. A connection is returned to the pool
    /// only after a successful call that left no transaction open.
    fn with_conn<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, rusqlite::Error>,
    ) -> Result<T, AlgoError> {
        let pooled = self.idle.lock().ok().and_then(|mut v| v.pop());
        let conn = match pooled {
            Some(c) => c,
            None => self.open().map_err(|e| AlgoError::Ledger {
                message: format!("read pool: open read-only connection: {e}"),
            })?,
        };
        match f(&conn) {
            Ok(v) => {
                if conn.is_autocommit() {
                    if let Ok(mut idle) = self.idle.lock() {
                        if idle.len() < MAX_IDLE_CONNECTIONS {
                            idle.push(conn);
                        }
                    }
                }
                Ok(v)
            }
            Err(e) => Err(AlgoError::Ledger {
                message: format!("read pool: {e}"),
            }),
        }
    }

    /// Number of idle pooled connections (diagnostics / tests).
    pub fn idle_connections(&self) -> usize {
        self.idle.lock().map(|v| v.len()).unwrap_or(0)
    }

    /// The committed tracker round (`acctrounds.acctbase`), the same value
    /// as [`SqliteLedger::last_committed_round`] (`None` on a never
    /// initialised database).
    pub fn committed_round(&self) -> Result<Option<u64>, AlgoError> {
        self.with_conn(|c| {
            let rnd: Option<i64> = c
                .prepare_cached("SELECT rnd FROM acctrounds WHERE id = 'acctbase'")?
                .query_row([], |row| row.get(0))
                .optional()?;
            Ok(rnd.map(|v| v.max(0) as u64))
        })
    }

    /// Resolve a block-row read: a hit is served; a miss is only trusted
    /// beyond the committed round (module docs).
    fn block_row<T>(
        &self,
        round: u64,
        sql: &'static str,
        get: impl FnOnce(&rusqlite::Row<'_>) -> Result<Option<T>, rusqlite::Error>,
    ) -> PoolRead<T> {
        let hit = self.with_conn(|c| {
            c.prepare_cached(sql)?
                .query_row(params![round as i64], get)
                .optional()
                .map(|o| o.flatten())
        });
        match hit {
            Ok(Some(v)) => PoolRead::Found(v),
            Ok(None) => match self.committed_round() {
                // Read after the miss: if the tracker had committed this
                // round by now, the miss may be the cross-file gap.
                Ok(Some(c)) if round <= c => PoolRead::Fallback,
                Ok(_) => PoolRead::NotFound,
                Err(_) => PoolRead::Fallback,
            },
            Err(e) => {
                tracing::debug!("read pool: block read for round {round} falling back: {e}");
                PoolRead::Fallback
            }
        }
    }

    /// `blockdb.blocks.blkdata` for `round`.
    pub fn block_data(&self, round: u64) -> PoolRead<Vec<u8>> {
        self.block_row(
            round,
            "SELECT blkdata FROM blockdb.blocks WHERE rnd = ?1",
            |row| row.get::<_, Vec<u8>>(0).map(Some),
        )
    }

    /// `blockdb.blocks.hdrdata` for `round`.
    pub fn block_header_data(&self, round: u64) -> PoolRead<Vec<u8>> {
        self.block_row(
            round,
            "SELECT hdrdata FROM blockdb.blocks WHERE rnd = ?1",
            |row| row.get::<_, Vec<u8>>(0).map(Some),
        )
    }

    /// `blockdb.blocks.proto` for `round`.
    pub fn block_proto(&self, round: u64) -> PoolRead<String> {
        self.block_row(
            round,
            "SELECT proto FROM blockdb.blocks WHERE rnd = ?1",
            |row| row.get::<_, String>(0).map(Some),
        )
    }

    /// `blockdb.blocks.certdata` for `round`. `Found(None)` is a present
    /// block row without a certificate (what the locked
    /// `get_block_cert` reports as `None` too), so the result is
    /// `Found(Option<..>)` only for rows that exist.
    pub fn block_cert(&self, round: u64) -> PoolRead<Option<Vec<u8>>> {
        let hit = self.with_conn(|c| {
            c.prepare_cached("SELECT certdata FROM blockdb.blocks WHERE rnd = ?1")?
                .query_row(params![round as i64], |row| {
                    row.get::<_, Option<Vec<u8>>>(0)
                })
                .optional()
        });
        match hit {
            Ok(Some(cert)) => PoolRead::Found(cert),
            Ok(None) => match self.committed_round() {
                Ok(Some(c)) if round <= c => PoolRead::Fallback,
                Ok(_) => PoolRead::NotFound,
                Err(_) => PoolRead::Fallback,
            },
            Err(_) => PoolRead::Fallback,
        }
    }

    /// The committed tracker round and the account's stored data, read in
    /// ONE statement so both come from the same tracker snapshot (what
    /// `read_account_snapshot` guaranteed by holding the lock). The account
    /// decodes exactly like [`SqliteLedger`]'s `get_account` (a missing or
    /// undecodable row is `None`).
    pub fn account_snapshot(
        &self,
        addr: &Address,
    ) -> Result<(u64, Option<AccountData>), AlgoError> {
        let (rnd, data): (Option<i64>, Option<Vec<u8>>) = self.with_conn(|c| {
            c.prepare_cached(
                "SELECT (SELECT rnd FROM acctrounds WHERE id = 'acctbase'), \
                        (SELECT data FROM accountbase WHERE address = ?1)",
            )?
            .query_row(params![addr.0.as_slice()], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
        })?;
        let acct = data.and_then(|d| decode_account_data(&d).ok());
        Ok((rnd.map(|v| v.max(0) as u64).unwrap_or(0), acct))
    }

    /// Rewards level of the committed header at `round`; `None` when the
    /// header is not readable (caller falls back).
    fn rewards_level_at(&self, round: u64) -> Option<u64> {
        if let Ok(g) = self.rewards_cache.lock() {
            if let Some((r, level)) = *g {
                if r == round {
                    return Some(level);
                }
            }
        }
        let hdr = match self.block_header_data(round) {
            PoolRead::Found(h) => h,
            _ => return None,
        };
        let level = BlockHeader::decode_from_bytes(&hdr).ok()?.rewards_level;
        if let Ok(mut g) = self.rewards_cache.lock() {
            *g = Some((round, level));
        }
        Some(level)
    }

    /// Lock-free `SqliteLedger::lookup_agreement_account`: go's
    /// `LookupAgreement(round, addr)`. `Found(None)` is "no online record /
    /// not online at `round`". A `round` above the committed round, or any
    /// unreadable input, is [`PoolRead::Fallback`] so the locked path
    /// decides (and reports its own errors).
    pub fn lookup_agreement_account(
        &self,
        addr: &Address,
        round: u64,
    ) -> PoolRead<Option<AccountData>> {
        match self.committed_round() {
            Ok(Some(c)) if round <= c => {}
            _ => return PoolRead::Fallback,
        }
        let data = self.with_conn(|c| {
            c.prepare_cached(
                "SELECT data FROM onlineaccounts WHERE address = ?1 AND updround <= ?2 \
                 ORDER BY updround DESC LIMIT 1",
            )?
            .query_row(params![addr.0.as_slice(), round as i64], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .optional()
        });
        let mut acct = match data {
            Ok(None) => return PoolRead::Found(None),
            Ok(Some(d)) => match decode_online_account_data(&d) {
                Ok(a) => a,
                Err(_) => return PoolRead::Fallback,
            },
            Err(_) => return PoolRead::Fallback,
        };
        if acct.status != AccountStatus::Online {
            return PoolRead::Found(None);
        }
        let Some(rewards_level) = self.rewards_level_at(round) else {
            return PoolRead::Fallback;
        };
        if rewards_level >= acct.rewards_base {
            let pending = crate::rewards::compute_pending_rewards(&acct, rewards_level);
            acct.micro_algos = acct.micro_algos.saturating_add(pending);
            acct.rewards_base = rewards_level;
        }
        PoolRead::Found(Some(acct))
    }
}

/// Lazily resolved handle to a ledger's [`LedgerReadPool`], held by the REST
/// adapter and the agreement bridge (which only have the
/// `Arc<Mutex<SqliteLedger>>`).
///
/// The first [`Self::get`] takes the ledger mutex once to fetch the pool's
/// `Arc`; every later call is lock-free. `None` is cached for in-memory
/// ledgers (no files).
#[derive(Debug, Default)]
pub struct LazyReadPool {
    cell: OnceLock<Option<Arc<LedgerReadPool>>>,
}

impl LazyReadPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Like [`Self::new`], but resolves the pool right away when the ledger
    /// mutex is free (the normal case at construction), so the first read
    /// never has to take it. When the mutex is busy the first [`Self::get`]
    /// resolves it instead.
    pub fn primed(ledger: &Mutex<SqliteLedger>) -> Self {
        let lazy = Self::default();
        if let Ok(l) = ledger.try_lock() {
            let _ = lazy.cell.set(l.read_pool());
        }
        lazy
    }

    /// The pool, or `None` for an in-memory ledger (or a poisoned mutex).
    pub fn get(&self, ledger: &Mutex<SqliteLedger>) -> Option<&Arc<LedgerReadPool>> {
        self.cell
            .get_or_init(|| ledger.lock().ok().and_then(|l| l.read_pool()))
            .as_ref()
    }
}

#[cfg(test)]
#[path = "read_pool_tests.rs"]
mod tests;
