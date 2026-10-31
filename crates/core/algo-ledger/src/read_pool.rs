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
use algo_types::{
    AccountData, AccountStatus, Address, AppLocalState, AppParams, AssetHolding, AssetParamsRecord,
    BlockHeader,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::sqlite::{
    decode_account_data, decode_app_local_state, decode_app_params, decode_asset_holding,
    decode_asset_params, decode_online_account_data, inspect_resource_blob, make_box_key,
    SqliteLedger, CTYPE_APP, CTYPE_ASSET,
};
use crate::store_trait::{BoxPage, LedgerStore};

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
            // An overflow is no answer from the pool: let the store decide.
            let Ok(pending) = crate::rewards::compute_pending_rewards(&acct, rewards_level) else {
                return PoolRead::Fallback;
            };
            acct.micro_algos = acct.micro_algos.saturating_add(pending);
            acct.rewards_base = rewards_level;
        }
        PoolRead::Found(Some(acct))
    }
}

// ---------------------------------------------------------------------------
// Resource reads (issue #1893)
// ---------------------------------------------------------------------------

/// The ledger reads behind the REST resource lookups (`lookup_asset_resource`,
/// `lookup_app_resource`, `lookup_application`, `lookup_asset_by_id`,
/// `lookup_assets`, `lookup_applications`, the box/kv lookups and
/// `total_boxes`).
///
/// Implemented by every [`LedgerStore`] (the locked path) and by
/// [`PoolReader`] (one read snapshot on a pooled connection), so the REST
/// adapter writes each lookup ONCE, generically, and both paths run the same
/// composition over the same SQL and decoders.
pub trait ResourceReads {
    fn get_account(&self, addr: &Address) -> Option<AccountData>;
    /// Rewards level of the committed tip (the header at the committed round,
    /// `acctrounds.acctbase`): the level go's `ledger.LookupAccount` brings an
    /// account up to (`WithUpdatedRewards`, issue #2157). `None` when it cannot
    /// be read (the pool caller then takes the locked path).
    fn committed_rewards_level(&self) -> Option<u64>;
    fn get_asset_holding(&self, addr: &Address, asset_id: u64) -> Option<AssetHolding>;
    fn get_asset_params(&self, asset_id: u64) -> Option<AssetParamsRecord>;
    fn get_app_params(&self, app_id: u64) -> Option<AppParams>;
    fn get_app_local_state(&self, addr: &Address, app_id: u64) -> Option<AppLocalState>;
    fn app_local_states_for_addr(&self, addr: &Address) -> Vec<(u64, AppLocalState)>;
    fn asset_holdings_for_addr(&self, addr: &Address) -> Vec<(u64, AssetHolding)>;
    fn created_assets_for_addr(&self, addr: &Address) -> Vec<(u64, AssetParamsRecord)>;
    fn created_apps_for_addr(&self, addr: &Address) -> Vec<(u64, AppParams)>;
    fn get_box(&self, app_id: u64, key: &[u8]) -> Option<Vec<u8>>;
    fn box_keys_for_app(&self, app_id: u64) -> Vec<Vec<u8>>;
    fn box_keys_by_prefix_paginated(
        &self,
        app_id: u64,
        prefix: &[u8],
        cursor: Option<&[u8]>,
        limit: Option<u64>,
        include_values: bool,
    ) -> (BoxPage, bool);
}

impl<T: LedgerStore + ?Sized> ResourceReads for T {
    fn get_account(&self, addr: &Address) -> Option<AccountData> {
        LedgerStore::get_account(self, addr)
    }
    fn committed_rewards_level(&self) -> Option<u64> {
        // The locked path holds the ledger, so its current rewards level is
        // the committed tip's header level (the same value the pool reads
        // from the header at `acctbase`).
        Some(LedgerStore::rewards_level(self))
    }
    fn get_asset_holding(&self, addr: &Address, asset_id: u64) -> Option<AssetHolding> {
        LedgerStore::get_asset_holding(self, addr, asset_id)
    }
    fn get_asset_params(&self, asset_id: u64) -> Option<AssetParamsRecord> {
        LedgerStore::get_asset_params(self, asset_id)
    }
    fn get_app_params(&self, app_id: u64) -> Option<AppParams> {
        LedgerStore::get_app_params(self, app_id)
    }
    fn get_app_local_state(&self, addr: &Address, app_id: u64) -> Option<AppLocalState> {
        LedgerStore::get_app_local_state(self, addr, app_id)
    }
    fn app_local_states_for_addr(&self, addr: &Address) -> Vec<(u64, AppLocalState)> {
        LedgerStore::app_local_states_for_addr(self, addr)
    }
    fn asset_holdings_for_addr(&self, addr: &Address) -> Vec<(u64, AssetHolding)> {
        LedgerStore::asset_holdings_for_addr(self, addr)
    }
    fn created_assets_for_addr(&self, addr: &Address) -> Vec<(u64, AssetParamsRecord)> {
        LedgerStore::created_assets_for_addr(self, addr)
    }
    fn created_apps_for_addr(&self, addr: &Address) -> Vec<(u64, AppParams)> {
        LedgerStore::created_apps_for_addr(self, addr)
    }
    fn get_box(&self, app_id: u64, key: &[u8]) -> Option<Vec<u8>> {
        LedgerStore::get_box(self, app_id, key)
    }
    fn box_keys_for_app(&self, app_id: u64) -> Vec<Vec<u8>> {
        LedgerStore::box_keys_for_app(self, app_id)
    }
    fn box_keys_by_prefix_paginated(
        &self,
        app_id: u64,
        prefix: &[u8],
        cursor: Option<&[u8]>,
        limit: Option<u64>,
        include_values: bool,
    ) -> (BoxPage, bool) {
        LedgerStore::box_keys_by_prefix_paginated(
            self,
            app_id,
            prefix,
            cursor,
            limit,
            include_values,
        )
    }
}

/// Resource reads over one pooled read snapshot (see
/// [`LedgerReadPool::read_resources`]). The SQL and decoders are the ones the
/// locked [`SqliteLedger`] accessors use. The locked accessors log a SQL error
/// and answer `None`/empty; here the FIRST SQL error is recorded instead and
/// makes the whole snapshot fail, so the caller falls back to the locked path
/// rather than serving a silently truncated answer.
pub struct PoolReader<'a> {
    conn: &'a Connection,
    err: std::cell::Cell<Option<rusqlite::Error>>,
}

impl PoolReader<'_> {
    fn ok<T>(&self, r: Result<T, rusqlite::Error>) -> Option<T> {
        match r {
            Ok(v) => Some(v),
            Err(e) => {
                let first = self.err.take();
                self.err.set(first.or(Some(e)));
                None
            }
        }
    }

    /// A resource blob that fails to decode is not "absent": record it as the
    /// snapshot's error so the caller takes the locked path instead of serving
    /// a list that silently disagrees with the account's totals.
    fn decoded<T>(&self, r: Result<T, AlgoError>) -> Option<T> {
        match r {
            Ok(v) => Some(v),
            Err(e) => {
                let first = self.err.take();
                self.err
                    .set(first.or(Some(rusqlite::Error::ToSqlConversionFailure(Box::new(e)))));
                None
            }
        }
    }

    fn rowid(&self, addr: &Address) -> Option<i64> {
        self.ok(self
            .conn
            .prepare_cached("SELECT rowid FROM accountbase WHERE address = ?1")
            .and_then(|mut s| {
                s.query_row(params![addr.0.as_slice()], |row| row.get(0))
                    .optional()
            }))
        .flatten()
    }

    fn creator_of(&self, id: u64) -> Option<Address> {
        let bytes: Vec<u8> = self
            .ok(self
                .conn
                .prepare_cached("SELECT creator FROM assetcreators WHERE asset = ?1")
                .and_then(|mut s| s.query_row(params![id as i64], |row| row.get(0)).optional()))
            .flatten()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(Address(arr))
    }

    fn resource_blob(&self, rowid: i64, aidx: u64, ctype: i64) -> Option<Vec<u8>> {
        self.ok(self
            .conn
            .prepare_cached(
                "SELECT data FROM resources WHERE addrid = ?1 AND aidx = ?2 AND ctype = ?3",
            )
            .and_then(|mut s| {
                s.query_row(params![rowid, aidx as i64, ctype], |row| row.get(0))
                    .optional()
            }))
        .flatten()
    }

    fn resource_rows(&self, addr: &Address, ctype: i64) -> Vec<(u64, Vec<u8>)> {
        let Some(rowid) = self.rowid(addr) else {
            return Vec::new();
        };
        self.ok(self
            .conn
            .prepare_cached("SELECT aidx, data FROM resources WHERE addrid = ?1 AND ctype = ?2")
            .and_then(|mut s| {
                let rows = s.query_map(params![rowid, ctype], |row| {
                    Ok((row.get::<_, i64>(0)? as u64, row.get::<_, Vec<u8>>(1)?))
                })?;
                rows.collect::<Result<Vec<_>, _>>()
            }))
        .unwrap_or_default()
    }

    fn kv_keys_in(&self, lower: Vec<u8>, upper: Vec<u8>) -> Vec<Vec<u8>> {
        self.ok(self
            .conn
            .prepare_cached("SELECT key FROM kvstore WHERE key >= ?1 AND key < ?2")
            .and_then(|mut s| {
                let rows = s.query_map(params![lower, upper], |row| row.get::<_, Vec<u8>>(0))?;
                rows.collect::<Result<Vec<_>, _>>()
            }))
        .unwrap_or_default()
    }
}

impl ResourceReads for PoolReader<'_> {
    fn committed_rewards_level(&self) -> Option<u64> {
        let hdr: Vec<u8> = self
            .ok(self
                .conn
                .prepare_cached(
                    "SELECT hdrdata FROM blockdb.blocks WHERE rnd =                      (SELECT rnd FROM acctrounds WHERE id = 'acctbase')",
                )
                .and_then(|mut s| s.query_row([], |row| row.get(0)).optional()))
            .flatten()?;
        Some(BlockHeader::decode_from_bytes(&hdr).ok()?.rewards_level)
    }

    fn get_account(&self, addr: &Address) -> Option<AccountData> {
        let data: Vec<u8> = self
            .ok(self
                .conn
                .prepare_cached("SELECT data FROM accountbase WHERE address = ?1")
                .and_then(|mut s| {
                    s.query_row(params![addr.0.as_slice()], |row| row.get(0))
                        .optional()
                }))
            .flatten()?;
        decode_account_data(&data).ok()
    }

    fn get_asset_holding(&self, addr: &Address, asset_id: u64) -> Option<AssetHolding> {
        let rowid = self.rowid(addr)?;
        let data = self.resource_blob(rowid, asset_id, CTYPE_ASSET)?;
        if !inspect_resource_blob(&data).has_holding {
            return None;
        }
        decode_asset_holding(&data).ok()
    }

    fn get_asset_params(&self, asset_id: u64) -> Option<AssetParamsRecord> {
        let creator = self.creator_of(asset_id)?;
        let rowid = self.rowid(&creator)?;
        let data = self.resource_blob(rowid, asset_id, CTYPE_ASSET)?;
        if !inspect_resource_blob(&data).has_ownership {
            return None;
        }
        let params = decode_asset_params(&data).ok()?;
        Some(AssetParamsRecord { params, creator })
    }

    fn get_app_params(&self, app_id: u64) -> Option<AppParams> {
        let creator = self.creator_of(app_id)?;
        let rowid = self.rowid(&creator)?;
        let data = self.resource_blob(rowid, app_id, CTYPE_APP)?;
        if !inspect_resource_blob(&data).has_ownership {
            return None;
        }
        decode_app_params(&data, creator).ok()
    }

    fn get_app_local_state(&self, addr: &Address, app_id: u64) -> Option<AppLocalState> {
        let rowid = self.rowid(addr)?;
        let data = self.resource_blob(rowid, app_id, CTYPE_APP)?;
        if !inspect_resource_blob(&data).has_holding {
            return None;
        }
        decode_app_local_state(&data).ok()
    }

    fn app_local_states_for_addr(&self, addr: &Address) -> Vec<(u64, AppLocalState)> {
        self.resource_rows(addr, CTYPE_APP)
            .into_iter()
            .filter_map(|(aidx, data)| {
                if !inspect_resource_blob(&data).has_holding {
                    return None;
                }
                Some((aidx, self.decoded(decode_app_local_state(&data))?))
            })
            .collect()
    }

    fn asset_holdings_for_addr(&self, addr: &Address) -> Vec<(u64, AssetHolding)> {
        self.resource_rows(addr, CTYPE_ASSET)
            .into_iter()
            .filter_map(|(aidx, data)| {
                if !inspect_resource_blob(&data).has_holding {
                    return None;
                }
                Some((aidx, self.decoded(decode_asset_holding(&data))?))
            })
            .collect()
    }

    fn created_assets_for_addr(&self, addr: &Address) -> Vec<(u64, AssetParamsRecord)> {
        self.resource_rows(addr, CTYPE_ASSET)
            .into_iter()
            .filter_map(|(aidx, data)| {
                if !inspect_resource_blob(&data).has_ownership {
                    return None;
                }
                let params = self.decoded(decode_asset_params(&data))?;
                Some((
                    aidx,
                    AssetParamsRecord {
                        params,
                        creator: *addr,
                    },
                ))
            })
            .collect()
    }

    fn created_apps_for_addr(&self, addr: &Address) -> Vec<(u64, AppParams)> {
        self.resource_rows(addr, CTYPE_APP)
            .into_iter()
            .filter_map(|(aidx, data)| {
                if !inspect_resource_blob(&data).has_ownership {
                    return None;
                }
                Some((aidx, self.decoded(decode_app_params(&data, *addr))?))
            })
            .collect()
    }

    fn get_box(&self, app_id: u64, key: &[u8]) -> Option<Vec<u8>> {
        let full_key = make_box_key(app_id, key);
        self.ok(self
            .conn
            .prepare_cached("SELECT value FROM kvstore WHERE key = ?1")
            .and_then(|mut s| {
                s.query_row(params![full_key], |row| row.get::<_, Vec<u8>>(0))
                    .optional()
            }))
        .flatten()
    }

    fn box_keys_for_app(&self, app_id: u64) -> Vec<Vec<u8>> {
        let prefix = make_box_key(app_id, b"");
        let prefix_len = prefix.len();
        // Same bounds as `SqliteLedger::box_keys_for_app`, including the
        // `u64::MAX` edge (upper bound `"by:"`).
        let upper = if app_id == u64::MAX {
            b"by:".to_vec()
        } else {
            make_box_key(app_id + 1, b"")
        };
        self.kv_keys_in(prefix, upper)
            .into_iter()
            .map(|full_key| full_key[prefix_len..].to_vec())
            .collect()
    }

    // The same algorithm as `LedgerStore::box_keys_by_prefix_paginated`'s
    // default (which `SqliteLedger` uses), over this snapshot's accessors.
    fn box_keys_by_prefix_paginated(
        &self,
        app_id: u64,
        prefix: &[u8],
        cursor: Option<&[u8]>,
        limit: Option<u64>,
        include_values: bool,
    ) -> (BoxPage, bool) {
        let mut names: Vec<Vec<u8>> = self
            .box_keys_for_app(app_id)
            .into_iter()
            .filter(|name| name.starts_with(prefix))
            .filter(|name| match cursor {
                Some(c) => name.as_slice() > c,
                None => true,
            })
            .collect();
        names.sort();
        let more_data = match limit {
            Some(l) => (names.len() as u64) > l,
            None => false,
        };
        if let Some(l) = limit {
            names.truncate(l as usize);
        }
        let results = names
            .into_iter()
            .map(|name| {
                let value = if include_values {
                    self.get_box(app_id, &name)
                } else {
                    None
                };
                (name, value)
            })
            .collect();
        (results, more_data)
    }
}

impl LedgerReadPool {
    /// Run `f` against ONE read snapshot of the committed tracker state and
    /// return it with the committed round (`acctrounds.acctbase`, `0` on a
    /// never-initialised database, like the locked
    /// `last_committed_round().unwrap_or(0)`) read in the same snapshot, so
    /// the round and the data can never tear across a concurrent commit.
    ///
    /// The snapshot is a short read transaction that ends before this call
    /// returns (the WAL is never pinned). Any SQL error, in `f`'s reads or
    /// the bookkeeping, is `Err` and the caller takes the locked path. A
    /// resource that is absent from the snapshot is an authoritative miss:
    /// the tracker tables live in one file and commit atomically.
    pub fn read_resources<T>(
        &self,
        f: impl FnOnce(&PoolReader<'_>) -> T,
    ) -> Result<(u64, T), AlgoError> {
        self.with_conn(|c| {
            let tx = c.unchecked_transaction()?;
            let rnd: Option<i64> = tx
                .prepare_cached("SELECT rnd FROM acctrounds WHERE id = 'acctbase'")?
                .query_row([], |row| row.get(0))
                .optional()?;
            let reader = PoolReader {
                conn: &tx,
                err: std::cell::Cell::new(None),
            };
            let out = f(&reader);
            if let Some(e) = reader.err.take() {
                return Err(e);
            }
            drop(reader);
            tx.commit()?;
            Ok((rnd.map(|v| v.max(0) as u64).unwrap_or(0), out))
        })
    }

    /// Lock-free `SqliteLedger::online_circulation_at_round` (go's
    /// `onlineCirculation`): the per-round supply snapshot else the current
    /// aggregate, less the stake expired by `vote_rnd` when the committed
    /// tip's protocol excludes it. Everything is read in one snapshot.
    ///
    /// [`PoolRead::Fallback`] when the answer is not certain to equal the
    /// locked one: `round` above the committed round, no committed tip block
    /// to take the protocol from, an unreadable header or row, or any SQL
    /// error. The locked path then decides (and reports its own errors).
    pub fn online_circulation_at_round(&self, round: u64, vote_rnd: u64) -> PoolRead<u64> {
        let res = self.with_conn(|c| {
            let tx = c.unchecked_transaction()?;
            let v = circulation_in_snapshot(&tx, round, vote_rnd)?;
            tx.commit()?;
            Ok(v)
        });
        match res {
            Ok(Some(v)) => PoolRead::Found(v),
            _ => PoolRead::Fallback,
        }
    }
}

/// `Ok(None)` = cannot answer authoritatively (see
/// [`LedgerReadPool::online_circulation_at_round`]).
fn circulation_in_snapshot(
    c: &Connection,
    round: u64,
    vote_rnd: u64,
) -> Result<Option<u64>, rusqlite::Error> {
    let committed: Option<i64> = c
        .prepare_cached("SELECT rnd FROM acctrounds WHERE id = 'acctbase'")?
        .query_row([], |row| row.get(0))
        .optional()?;
    let committed = match committed {
        Some(v) if round <= v.max(0) as u64 => v.max(0) as u64,
        _ => return Ok(None),
    };

    // Per-round supply snapshot, else the current aggregate.
    let tail: Option<Vec<u8>> = c
        .prepare_cached("SELECT data FROM onlineroundparamstail WHERE rnd = ?1")?
        .query_row(params![round as i64], |row| row.get(0))
        .optional()?;
    let total = match tail {
        Some(data) => {
            let Ok(value) = rmpv::decode::read_value(&mut &data[..]) else {
                return Ok(None);
            };
            let mut online = 0u64;
            if let Some(map) = value.as_map() {
                for (k, v) in map {
                    if k.as_str() == Some("online") {
                        online = v.as_u64().unwrap_or(0);
                        break;
                    }
                }
            }
            online
        }
        None => {
            let online: Option<i64> = c
                .prepare_cached("SELECT online FROM accounttotals WHERE id = ''")?
                .query_row([], |row| row.get(0))
                .optional()?;
            online.unwrap_or(0).max(0) as u64
        }
    };

    // The ledger's current protocol is the committed tip block's.
    let proto: Option<String> = c
        .prepare_cached("SELECT proto FROM blockdb.blocks WHERE rnd = ?1")?
        .query_row(params![committed as i64], |row| row.get(0))
        .optional()?;
    let Some(proto) = proto else {
        return Ok(None);
    };
    let exclude = algo_types::consensus::consensus_params_for_version(&proto)
        .map(|p| p.exclude_expired_circulation)
        .unwrap_or(false);
    if !exclude || round == 0 {
        return Ok(Some(total));
    }

    let hdr: Option<Vec<u8>> = c
        .prepare_cached("SELECT hdrdata FROM blockdb.blocks WHERE rnd = ?1")?
        .query_row(params![round as i64], |row| row.get(0))
        .optional()?;
    let Some(rewards_level) = hdr
        .and_then(|h| BlockHeader::decode_from_bytes(&h).ok())
        .map(|h| h.rewards_level)
    else {
        return Ok(None);
    };

    let mut stmt = c.prepare_cached(
        "SELECT o.data FROM onlineaccounts o \
         WHERE o.votelastvalid != 0 AND o.votelastvalid < ?2 \
           AND o.updround = (SELECT MAX(i.updround) FROM onlineaccounts i \
                             WHERE i.address = o.address AND i.updround <= ?1)",
    )?;
    let rows = stmt.query_map(params![round as i64, vote_rnd as i64], |row| {
        row.get::<_, Vec<u8>>(0)
    })?;
    let mut expired: u64 = 0;
    for row in rows {
        let data = row?;
        let Ok(mut account) = decode_online_account_data(&data) else {
            return Ok(None);
        };
        if account.vote_last_valid == 0 || vote_rnd <= account.vote_last_valid {
            continue;
        }
        if rewards_level >= account.rewards_base
            && crate::rewards::apply_rewards(&mut account, rewards_level).is_err()
        {
            return Ok(None);
        }
        let Some(sum) = expired.checked_add(account.micro_algos) else {
            return Ok(None);
        };
        expired = sum;
    }
    Ok(Some(total.saturating_sub(expired)))
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
