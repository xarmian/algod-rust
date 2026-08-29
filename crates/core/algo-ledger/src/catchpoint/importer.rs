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

//! Catchpoint import pipeline: staging table population from parsed chunks.
//!
//! Reads decoded [`CatchpointSnapshotChunkV6`] records and inserts them into
//! the catchpoint staging tables (`catchpointbalances`, `catchpointresources`,
//! `catchpointassetcreators`, `catchpointkvstore`, `catchpointonlineaccounts`,
//! `catchpointonlineroundparamstail`).
//!
//! Import is single-pass within a process: progress is tracked in memory on
//! the [`CatchpointImporter`] via [`ImportCheckpoint`]. If the process dies
//! mid-import, the next run starts over from chunk 0 — matching go-algorand,
//! which has no cross-process resume table for catchpoint streaming.
//!
//! After all chunks are imported, [`CatchpointImporter::atomic_cutover`]
//! atomically replaces the live tables with the staging tables.
//!
//! [`import_catchpoint_file`] is the main entry point for offline catchpoint
//! import from a file on disk.

use std::path::Path;
use std::time::Instant;

use algo_types::AccountStatus;
use rusqlite::Connection;

use super::checkpoint::ImportCheckpoint;
use super::msgp_compat::{decode_base_account_data, decode_resources_data};
use super::parser::{self, CatchpointEntry};
use super::types::{
    BalanceRecordV6, CatchpointError, CatchpointFileHeader, CatchpointSnapshotChunkV6,
    CatchpointStateProofVerificationWrapper, KVRecordV6, OnlineAccountRecordV6,
    OnlineRoundParamsRecordV6, RESOURCE_FLAGS_EMPTY_APP, RESOURCE_FLAGS_EMPTY_ASSET,
    RESOURCE_FLAGS_OWNERSHIP,
};
use crate::rewards::normalized_online_balance;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default number of chunks per batch before committing and checkpointing.
const DEFAULT_BATCH_SIZE: usize = 1000;

/// Asset creatable type (matches Go `basics.AssetCreatable = 0`).
const CTYPE_ASSET: i64 = 0;

/// App creatable type (matches Go `basics.AppCreatable = 1`).
const CTYPE_APP: i64 = 1;

// ---------------------------------------------------------------------------
// ImportStats
// ---------------------------------------------------------------------------

/// Cumulative statistics returned after a completed import.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportStats {
    pub accounts: u64,
    pub kvs: u64,
    pub online_accounts: u64,
    pub online_round_params: u64,
    pub chunks_processed: u64,
}

// ---------------------------------------------------------------------------
// ImportResult
// ---------------------------------------------------------------------------

/// Result of a completed catchpoint file import.
#[derive(Debug, Clone)]
pub struct ImportResult {
    /// The round number from the catchpoint file header.
    pub round: u64,
    /// Cumulative statistics from the import.
    pub stats: ImportStats,
    /// Wall-clock duration of the entire import (staging + cutover).
    pub duration: std::time::Duration,
}

// ---------------------------------------------------------------------------
// CatchpointImporter
// ---------------------------------------------------------------------------

/// Imports parsed catchpoint chunks into SQLite staging tables.
///
/// Usage:
/// 1. Create with [`CatchpointImporter::new`].
/// 2. Call [`prepare_staging`](Self::prepare_staging) to create tables.
/// 3. Feed chunks via [`import_chunks`](Self::import_chunks) or one at a time
///    via [`import_chunk`](Self::import_chunk).
pub struct CatchpointImporter<'a> {
    conn: &'a Connection,
    batch_size: usize,
    chunk_ordinal: u64,
    catchpoint_label: String,
    total_accounts: u64,
    total_kvs: u64,
    total_online_accounts: u64,
    total_online_round_params: u64,
    reward_unit: u64,
    /// In-memory progress checkpoint. Updated after every batch commit;
    /// reset to default on every new importer instance. Not persisted.
    checkpoint: ImportCheckpoint,
}

impl<'a> CatchpointImporter<'a> {
    /// Create a new importer targeting the given connection.
    ///
    /// `catchpoint_label` is the file's label string; it is stored on
    /// [`Self::checkpoint`] for diagnostic / test inspection.
    /// `reward_unit` is the protocol consensus reward unit used for computing
    /// normalized online balances (typically 1_000_000).
    pub fn new(conn: &'a Connection, catchpoint_label: String, reward_unit: u64) -> Self {
        let checkpoint = ImportCheckpoint {
            last_chunk_ordinal: 0,
            total_chunks: 0,
            catchpoint_label: catchpoint_label.clone(),
        };
        Self {
            conn,
            batch_size: DEFAULT_BATCH_SIZE,
            chunk_ordinal: 0,
            catchpoint_label,
            total_accounts: 0,
            total_kvs: 0,
            total_online_accounts: 0,
            total_online_round_params: 0,
            reward_unit,
            checkpoint,
        }
    }

    /// Override the default batch size (number of chunks per transaction).
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// In-memory import progress for this importer instance.
    ///
    /// Reset on every new instance; not persisted across process restarts.
    pub fn checkpoint(&self) -> &ImportCheckpoint {
        &self.checkpoint
    }

    // -----------------------------------------------------------------------
    // Staging preparation
    // -----------------------------------------------------------------------

    /// Drop any leftover staging tables and recreate them empty.
    ///
    /// Always starts fresh: progress is in-memory only (see
    /// [`ImportCheckpoint`]), so there is nothing to resume from. Any
    /// staging tables present in the DB are from a prior failed run and
    /// are unconditionally dropped before being recreated. This also
    /// renders the pre-G5 stale-`catchpointresources.ctype` concern moot —
    /// the table is dropped + recreated with the correct shape every time.
    pub fn prepare_staging(&mut self) -> Result<(), CatchpointError> {
        // Create staging tables via raw DDL (single source of truth in sqlite.rs).
        //
        // The trailing `DROP TABLE IF EXISTS catchpoint_import_state` is a
        // transitional cleanup for tracker DBs produced by older Rust
        // versions that left the now-removed table behind (PLAN-36 G4 /
        // TASK-117). Phase B's goal is that Rust-produced DBs are openable
        // by go-algorand without unknown tables — this drop guarantees that
        // any later import on such a DB scrubs the legacy artifact.
        self.conn.execute_batch(
            "
            DROP TABLE IF EXISTS catchpointassetcreators;
            DROP TABLE IF EXISTS catchpointbalances;
            DROP TABLE IF EXISTS catchpointpendinghashes;
            DROP TABLE IF EXISTS catchpointaccounthashes;
            DROP TABLE IF EXISTS catchpointresources;
            DROP TABLE IF EXISTS catchpointkvstore;
            DROP TABLE IF EXISTS catchpointonlineaccounts;
            DROP TABLE IF EXISTS catchpointonlineroundparamstail;
            DROP TABLE IF EXISTS catchpointstateproofverification;
            DROP TABLE IF EXISTS catchpoint_import_state;
            ",
        )?;

        self.conn
            .execute_batch(crate::sqlite::CATCHPOINT_STAGING_TABLES_SQL)?;

        // Reset in-memory progress in case this importer is being reused.
        self.chunk_ordinal = 0;
        self.checkpoint = ImportCheckpoint {
            last_chunk_ordinal: 0,
            total_chunks: 0,
            catchpoint_label: self.catchpoint_label.clone(),
        };

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Chunk import — main loop
    // -----------------------------------------------------------------------

    /// Import all chunks from an iterator, batching commits.
    ///
    /// Chunks are expected to arrive in ordinal order (0, 1, 2, ...). Import
    /// is single-pass: there is no resume across importer instances. The
    /// in-memory [`Self::checkpoint`] is updated after every batch commit
    /// (and again after the trailing partial batch) so callers can inspect
    /// per-batch progress within the same process.
    pub fn import_chunks(
        &mut self,
        chunks: impl Iterator<Item = Result<(u64, CatchpointSnapshotChunkV6), CatchpointError>>,
        total_chunks: u64,
    ) -> Result<ImportStats, CatchpointError> {
        let mut stats = ImportStats::default();
        let mut batch_count: usize = 0;
        let mut in_txn = false;

        let result: Result<ImportStats, CatchpointError> = (|| {
            for chunk_result in chunks {
                let (ordinal, chunk) = chunk_result?;

                if !in_txn {
                    self.conn.execute_batch("BEGIN IMMEDIATE")?;
                    in_txn = true;
                }

                self.import_chunk(ordinal, &chunk, &mut stats)?;
                batch_count += 1;

                if batch_count >= self.batch_size {
                    self.conn.execute_batch("COMMIT")?;
                    self.checkpoint.last_chunk_ordinal = ordinal;
                    self.checkpoint.total_chunks = total_chunks;
                    in_txn = false;
                    batch_count = 0;
                }
            }

            // Commit any remaining partial batch.
            if in_txn {
                self.conn.execute_batch("COMMIT")?;
                self.checkpoint.last_chunk_ordinal = self.chunk_ordinal;
                self.checkpoint.total_chunks = total_chunks;
                in_txn = false;
            }

            Ok(stats)
        })();

        // Roll back any open transaction on error so the connection is left
        // in a clean state.
        if in_txn {
            let _ = self.conn.execute_batch("ROLLBACK");
        }

        result
    }

    // -----------------------------------------------------------------------
    // Atomic cutover
    // -----------------------------------------------------------------------

    /// Atomically replace live tables with staging tables.
    ///
    /// This performs the full cutover in a single transaction:
    /// 1. DROP live tables that are being replaced.
    /// 2. RENAME staging tables to live table names.
    /// 3. Reconstruct `acctrounds` and `accounttotals` from the header.
    /// 4. DROP remaining staging tables.
    ///
    /// If the transaction fails, nothing changes (atomic rollback).
    ///
    /// This matches go-algorand's `ApplyCatchpointStagingBalances` +
    /// `ApplyCatchpointStagingTablesV7` + cleanup sequence.
    pub fn atomic_cutover(&self, header: &CatchpointFileHeader) -> Result<(), CatchpointError> {
        let round = header.balances_round as i64;
        let totals = &header.totals;

        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(CatchpointError::SqliteError)?;

        // Ensure acctrounds and accounttotals exist (they may not if the
        // database was freshly created for catchpoint import only).
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS acctrounds (
                id  TEXT PRIMARY KEY,
                rnd INTEGER
            );
            CREATE TABLE IF NOT EXISTS accounttotals (
                id                           TEXT PRIMARY KEY,
                online                       INTEGER,
                onlinerewardunits            INTEGER,
                offline                      INTEGER,
                offlinerewardunits           INTEGER,
                notparticipating             INTEGER,
                notparticipatingrewardunits  INTEGER,
                rewardslevel                 INTEGER
            );",
        )?;

        // Step 1+2: DROP live tables, RENAME staging → live.
        // Matches Go's ApplyCatchpointStagingBalances.
        tx.execute_batch(
            "DROP TABLE IF EXISTS accountbase;
            ALTER TABLE catchpointbalances RENAME TO accountbase;

            DROP TABLE IF EXISTS assetcreators;
            ALTER TABLE catchpointassetcreators RENAME TO assetcreators;

            DROP TABLE IF EXISTS resources;
            ALTER TABLE catchpointresources RENAME TO resources;

            DROP TABLE IF EXISTS kvstore;
            ALTER TABLE catchpointkvstore RENAME TO kvstore;

            DROP TABLE IF EXISTS stateproofverification;
            ALTER TABLE catchpointstateproofverification RENAME TO stateproofverification;

            DROP TABLE IF EXISTS accounthashes;
            ALTER TABLE catchpointaccounthashes RENAME TO accounthashes;",
        )?;

        // Matches Go's ApplyCatchpointStagingTablesV7.
        tx.execute_batch(
            "DROP TABLE IF EXISTS onlineaccounts;
            ALTER TABLE catchpointonlineaccounts RENAME TO onlineaccounts;

            DROP TABLE IF EXISTS onlineroundparamstail;
            ALTER TABLE catchpointonlineroundparamstail RENAME TO onlineroundparamstail;",
        )?;

        // Step 3: Reconstruct acctrounds.
        tx.execute(
            "INSERT OR REPLACE INTO acctrounds(id, rnd) VALUES('acctbase', ?1)",
            rusqlite::params![round],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO acctrounds(id, rnd) VALUES('hashbase', ?1)",
            rusqlite::params![round],
        )?;

        // Step 4: Write account totals (matches Go's AccountsPutTotals).
        tx.execute(
            "INSERT OR REPLACE INTO accounttotals(id, online, onlinerewardunits, offline, offlinerewardunits, notparticipating, notparticipatingrewardunits, rewardslevel) VALUES('', ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                totals.online.money as i64,
                totals.online.reward_units as i64,
                totals.offline.money as i64,
                totals.offline.reward_units as i64,
                totals.not_participating.money as i64,
                totals.not_participating.reward_units as i64,
                totals.rewards_level as i64,
            ],
        )?;

        // Step 5: Write catchpointstate entries (matches Go's processStagingContent).
        // Ensure the catchpointstate table exists.
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS catchpointstate (
                id TEXT PRIMARY KEY,
                intval INTEGER,
                strval TEXT
            );",
        )?;

        // Key names match Go's `trackerdb.CatchpointState*` constants
        // (centralized in `crate::catchpoint::state_keys`). Routing
        // through the constants avoids drift if Go ever renames one.
        use crate::catchpoint::state_keys;

        // catchpointCatchupLabel — the label string
        tx.execute(
            "INSERT OR REPLACE INTO catchpointstate(id, strval) VALUES(?1, ?2)",
            rusqlite::params![state_keys::CATCHUP_LABEL, &self.catchpoint_label],
        )?;

        // catchpointCatchupVersion — file version from the header
        tx.execute(
            "INSERT OR REPLACE INTO catchpointstate(id, intval) VALUES(?1, ?2)",
            rusqlite::params![state_keys::CATCHUP_VERSION, header.version as i64],
        )?;

        // catchpointCatchupBlockRound — block round from the header
        tx.execute(
            "INSERT OR REPLACE INTO catchpointstate(id, intval) VALUES(?1, ?2)",
            rusqlite::params![state_keys::CATCHUP_BLOCK_ROUND, header.blocks_round as i64],
        )?;

        // catchpointCatchupBalancesRound — balances round from the header
        tx.execute(
            "INSERT OR REPLACE INTO catchpointstate(id, intval) VALUES(?1, ?2)",
            rusqlite::params![
                state_keys::CATCHUP_BALANCES_ROUND,
                header.balances_round as i64
            ],
        )?;

        // catchpointCatchupHashRound — same as block round for V6+ (matches Go)
        tx.execute(
            "INSERT OR REPLACE INTO catchpointstate(id, intval) VALUES(?1, ?2)",
            rusqlite::params![state_keys::CATCHUP_HASH_ROUND, header.blocks_round as i64],
        )?;

        // Step 6: Clean up remaining staging tables.
        //
        // `catchpoint_import_state` is dropped here as a transitional
        // cleanup — Phase B (TASK-117) no longer creates the table, but
        // tracker DBs produced by older Rust versions may still carry one
        // from a prior interrupted import. Dropping at cutover ensures
        // such legacy artifacts can never persist into a fully imported
        // (and thus Go-openable) tracker DB.
        tx.execute_batch(
            "DROP TABLE IF EXISTS catchpointpendinghashes;
            DROP TABLE IF EXISTS catchpoint_import_state;",
        )?;

        tx.commit().map_err(CatchpointError::SqliteError)?;

        tracing::info!(
            "catchpoint cutover complete: live tables replaced at round {}",
            header.balances_round
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Single-chunk dispatch
    // -----------------------------------------------------------------------

    /// Import a single chunk, dispatching each record type to the appropriate
    /// handler.
    fn import_chunk(
        &mut self,
        ordinal: u64,
        chunk: &CatchpointSnapshotChunkV6,
        stats: &mut ImportStats,
    ) -> Result<(), CatchpointError> {
        self.chunk_ordinal = ordinal;

        for record in &chunk.balances {
            self.import_balance_record(record)?;
            self.total_accounts += 1;
            stats.accounts += 1;
        }

        for record in &chunk.kvs {
            self.import_kv_record(record)?;
            self.total_kvs += 1;
            stats.kvs += 1;
        }

        for record in &chunk.online_accounts {
            self.import_online_account(record)?;
            self.total_online_accounts += 1;
            stats.online_accounts += 1;
        }

        for record in &chunk.online_round_params {
            self.import_online_round_params(record)?;
            self.total_online_round_params += 1;
            stats.online_round_params += 1;
        }

        stats.chunks_processed += 1;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Per-record handlers
    // -----------------------------------------------------------------------

    /// Insert a balance record into `catchpointbalances` + resources +
    /// asset creators.
    fn import_balance_record(&self, record: &BalanceRecordV6) -> Result<(), CatchpointError> {
        // Decode account data to compute normalizedonlinebalance.
        let acct_data = decode_base_account_data(&record.account_data)
            .map_err(|e| CatchpointError::ImportError(format!("decode account data: {e}")))?;

        let status = AccountStatus::from(acct_data.status);
        let nob = normalized_online_balance(
            status,
            acct_data.micro_algos,
            acct_data.rewards_base,
            self.reward_unit,
        );

        // INSERT into catchpointbalances. addrid is auto-assigned by INTEGER
        // PRIMARY KEY autoincrement.
        self.conn.execute(
            "INSERT INTO catchpointbalances(address, normalizedonlinebalance, data) VALUES(?1, ?2, ?3)",
            rusqlite::params![
                record.address.as_ref(),
                nob as i64,
                record.account_data.as_ref(),
            ],
        ).or_else(|err| {
            // Handle overflowed account records (expecting_more_entries):
            // if the address already exists, we need to look up its rowid.
            if record.expecting_more_entries || is_unique_constraint_violation(&err) {
                // The account already exists — this is an overflowed record.
                // We don't re-insert the account row; we just use the existing rowid.
                Ok(0)
            } else {
                Err(err)
            }
        })?;

        // Get the rowid for this account (whether just inserted or pre-existing).
        let addrid: i64 = self.conn.query_row(
            "SELECT rowid FROM catchpointbalances WHERE address = ?1",
            rusqlite::params![record.address.as_ref()],
            |row| row.get(0),
        )?;

        // Insert resources.
        for (&aidx, resource_data) in &record.resources {
            // Decode resource to determine ctype and check ownership for asset creators table.
            let rd = decode_resources_data(resource_data)
                .map_err(|e| CatchpointError::ImportError(format!("decode resource data: {e}")))?;

            // Determine ctype: asset=0, app=1 (matches Go's basics.CreatableType).
            // Unknown/non-owning resources use -1 — the same "unknown"
            // sentinel Go uses (see G5 / DOC-24, and
            // `../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:970`
            // where the post-migration column is `NOT NULL DEFAULT -1`).
            let resource_is_asset = is_asset(rd.resource_flags, &rd);
            let resource_is_app = is_app(rd.resource_flags, &rd);
            let ctype: i64 = if resource_is_app {
                CTYPE_APP
            } else if resource_is_asset {
                CTYPE_ASSET
            } else {
                -1
            };

            self.conn.execute(
                "INSERT INTO catchpointresources(addrid, aidx, data, ctype) VALUES(?1, ?2, ?3, ?4)",
                rusqlite::params![addrid, aidx as i64, resource_data.as_ref(), ctype],
            )?;

            if is_owning(rd.resource_flags) {
                if resource_is_asset {
                    self.conn.execute(
                        "INSERT INTO catchpointassetcreators(asset, creator, ctype) VALUES(?1, ?2, ?3)",
                        rusqlite::params![aidx as i64, record.address.as_ref(), CTYPE_ASSET],
                    )?;
                }
                if resource_is_app {
                    self.conn.execute(
                        "INSERT INTO catchpointassetcreators(asset, creator, ctype) VALUES(?1, ?2, ?3)",
                        rusqlite::params![aidx as i64, record.address.as_ref(), CTYPE_APP],
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Insert a key-value record into `catchpointkvstore`.
    fn import_kv_record(&self, record: &KVRecordV6) -> Result<(), CatchpointError> {
        self.conn.execute(
            "INSERT INTO catchpointkvstore(key, value) VALUES(?1, ?2)",
            rusqlite::params![record.key.as_ref(), record.value.as_ref()],
        )?;
        Ok(())
    }

    /// Insert an online account record into `catchpointonlineaccounts`.
    fn import_online_account(&self, record: &OnlineAccountRecordV6) -> Result<(), CatchpointError> {
        self.conn.execute(
            "INSERT INTO catchpointonlineaccounts(address, updround, normalizedonlinebalance, votelastvalid, data) VALUES(?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                record.address.as_ref(),
                record.updated_round as i64,
                record.normalized_online_balance as i64,
                record.vote_last_valid as i64,
                record.data.as_ref(),
            ],
        )?;
        Ok(())
    }

    /// Insert an online round params record into
    /// `catchpointonlineroundparamstail`.
    fn import_online_round_params(
        &self,
        record: &OnlineRoundParamsRecordV6,
    ) -> Result<(), CatchpointError> {
        self.conn.execute(
            "INSERT INTO catchpointonlineroundparamstail(rnd, data) VALUES(?1, ?2)",
            rusqlite::params![record.round as i64, record.data.as_ref()],
        )?;
        Ok(())
    }

    /// Import state proof verification context data into
    /// `catchpointstateproofverification`.
    ///
    /// The raw bytes are the msgpack-encoded wrapper
    /// (`CatchpointStateProofVerificationWrapper`) containing an array of
    /// individual verification contexts. Each context is re-encoded and stored
    /// with its `lastattestedround` as the primary key.
    fn import_state_proof_verification(&self, raw_data: &[u8]) -> Result<(), CatchpointError> {
        let wrapper: CatchpointStateProofVerificationWrapper = rmp_serde::from_slice(raw_data)
            .map_err(|e| {
                CatchpointError::DecodeError(format!(
                    "state proof verification context msgpack: {e}"
                ))
            })?;

        if wrapper.data.is_empty() {
            return Ok(());
        }

        for ctx in &wrapper.data {
            let encoded = rmp_serde::to_vec_named(ctx).map_err(|e| {
                CatchpointError::ImportError(format!(
                    "re-encode state proof verification context: {e}"
                ))
            })?;

            self.conn.execute(
                "INSERT OR REPLACE INTO catchpointstateproofverification(lastattestedround, verificationContext) VALUES(?1, ?2)",
                rusqlite::params![ctx.last_attested_round as i64, encoded],
            )?;
        }

        tracing::debug!(
            "imported {} state proof verification contexts",
            wrapper.data.len()
        );

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// import_catchpoint_file — main entry point for offline catchpoint import
// ---------------------------------------------------------------------------

/// Import a catchpoint file into the database.
///
/// This is the main entry point for offline catchpoint import. It:
/// 1. Opens and parses the catchpoint tar file (auto-detecting compression).
/// 2. Reads the file header to obtain the round, totals, and catchpoint label.
/// 3. Creates staging tables and streams all chunks into them (batched).
/// 4. Performs an atomic cutover: replaces live tables with staging tables.
///
/// Import is single-pass: if the process dies mid-import, the next run
/// starts over from chunk 0 (matching go-algorand). Progress within the
/// running process is tracked in memory on the importer.
///
/// On success, the database contains the full account state at the catchpoint
/// round, ready for block replay from that point forward.
pub fn import_catchpoint_file(
    conn: &Connection,
    path: &Path,
    reward_unit: u64,
) -> Result<ImportResult, CatchpointError> {
    let start = Instant::now();

    // --- Pass 1: extract header only ---
    let header = {
        let reader = parser::open(path)?;
        let mut header: Option<CatchpointFileHeader> = None;
        reader.for_each(|entry| {
            if header.is_none() {
                if let CatchpointEntry::Header(h) = entry {
                    header = Some(h);
                }
            }
            Ok(())
        })?;
        header.ok_or(CatchpointError::MissingHeader)?
    };

    let total_chunks = header.total_chunks;
    let catchpoint_label = header.catchpoint.clone();
    let round = header.balances_round;

    tracing::info!(
        "importing catchpoint file: round={}, chunks={}, accounts={}, label={}",
        round,
        total_chunks,
        header.total_accounts,
        catchpoint_label,
    );

    // Create importer and prepare staging tables.
    let mut importer = CatchpointImporter::new(conn, catchpoint_label, reward_unit);
    importer.prepare_staging()?;

    // --- Pass 2: stream chunks directly into the importer ---
    let stats = {
        let reader = parser::open(path)?;
        let mut chunk_ordinal: u64 = 0;
        let mut stats = ImportStats::default();

        let batch_size = importer.batch_size;
        let mut batch_count: usize = 0;
        let mut in_txn = false;

        let stream_result: Result<(), CatchpointError> = reader.for_each(|entry| {
            match entry {
                CatchpointEntry::Header(_) => { /* already extracted */ }
                CatchpointEntry::Chunk(chunk) => {
                    chunk_ordinal += 1;

                    if !in_txn {
                        conn.execute_batch("BEGIN IMMEDIATE")?;
                        in_txn = true;
                    }

                    importer.import_chunk(chunk_ordinal, &chunk, &mut stats)?;
                    batch_count += 1;

                    if batch_count >= batch_size {
                        conn.execute_batch("COMMIT")?;
                        importer.checkpoint.last_chunk_ordinal = chunk_ordinal;
                        importer.checkpoint.total_chunks = total_chunks;
                        in_txn = false;
                        batch_count = 0;
                    }
                }
                CatchpointEntry::StateProofVerification(ref sp_data) => {
                    // Import state proof verification contexts into the
                    // staging table so they survive the atomic cutover.
                    if !in_txn {
                        conn.execute_batch("BEGIN IMMEDIATE")?;
                        in_txn = true;
                    }
                    importer.import_state_proof_verification(sp_data)?;
                }
            }
            Ok(())
        });

        // Roll back any open transaction on error so the connection is left
        // in a clean state.
        if let Err(e) = stream_result {
            if in_txn {
                let _ = conn.execute_batch("ROLLBACK");
            }
            return Err(e);
        }

        // Commit any remaining partial batch.
        if in_txn {
            conn.execute_batch("COMMIT")?;
            importer.checkpoint.last_chunk_ordinal = chunk_ordinal;
            importer.checkpoint.total_chunks = total_chunks;
        }

        stats
    };

    // Reject truncated catchpoint files: verify all chunks were processed.
    if stats.chunks_processed != total_chunks {
        return Err(CatchpointError::IntegrityError(format!(
            "truncated catchpoint file: expected {} chunks, got {}",
            total_chunks, stats.chunks_processed
        )));
    }

    // Atomic cutover: replace live tables with staging tables.
    importer.atomic_cutover(&header)?;

    let duration = start.elapsed();
    tracing::info!(
        "catchpoint import complete: round={}, accounts={}, kvs={}, chunks={}, duration={:.1}s",
        round,
        stats.accounts,
        stats.kvs,
        stats.chunks_processed,
        duration.as_secs_f64(),
    );

    Ok(ImportResult {
        round,
        stats,
        duration,
    })
}

// ---------------------------------------------------------------------------
// Resource flag helpers (mirrors Go's resourcesData methods)
// ---------------------------------------------------------------------------

/// Returns `true` if the ownership bit is set.
fn is_owning(flags: u8) -> bool {
    (flags & RESOURCE_FLAGS_OWNERSHIP) == RESOURCE_FLAGS_OWNERSHIP
}

/// Returns `true` if the resource is an asset resource.
///
/// Matches Go logic: either the `EmptyAsset` flag is set, or the asset fields
/// are non-empty.
fn is_asset(flags: u8, rd: &super::types::CatchpointResourcesData) -> bool {
    if (flags & RESOURCE_FLAGS_EMPTY_ASSET) == RESOURCE_FLAGS_EMPTY_ASSET {
        return true;
    }
    !is_empty_asset_fields(rd)
}

/// Returns `true` if the resource is an app resource.
fn is_app(flags: u8, rd: &super::types::CatchpointResourcesData) -> bool {
    if (flags & RESOURCE_FLAGS_EMPTY_APP) == RESOURCE_FLAGS_EMPTY_APP {
        return true;
    }
    !is_empty_app_fields(rd)
}

fn is_empty_asset_fields(rd: &super::types::CatchpointResourcesData) -> bool {
    rd.amount == 0
        && !rd.frozen
        && rd.total == 0
        && rd.decimals == 0
        && !rd.default_frozen
        && rd.unit_name.is_empty()
        && rd.asset_name.is_empty()
        && rd.url.is_empty()
        && rd.metadata_hash == [0u8; 32]
        && rd.manager == [0u8; 32]
        && rd.reserve == [0u8; 32]
        && rd.freeze == [0u8; 32]
        && rd.clawback == [0u8; 32]
}

fn is_empty_app_fields(rd: &super::types::CatchpointResourcesData) -> bool {
    rd.schema_num_uint == 0
        && rd.schema_num_byte_slice == 0
        && rd.key_value.is_empty()
        && rd.approval_program.is_empty()
        && rd.clear_state_program.is_empty()
        && rd.global_state.is_empty()
        && rd.local_state_schema_num_uint == 0
        && rd.local_state_schema_num_byte_slice == 0
        && rd.global_state_schema_num_uint == 0
        && rd.global_state_schema_num_byte_slice == 0
        && rd.extra_program_pages == 0
        && rd.version == 0
        && rd.size_sponsor == [0u8; 32]
        && !rd.foreign_box_reads
        && !rd.family_box_access
}

/// Check if a rusqlite error is a UNIQUE constraint violation.
fn is_unique_constraint_violation(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ffi::ErrorCode::ConstraintViolation,
                ..
            },
            _
        )
    )
}

// Staging table DDL is defined once in crate::sqlite::CATCHPOINT_STAGING_TABLES_SQL.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewards::REWARD_UNITS;
    use serde_bytes::ByteBuf;
    use std::collections::HashMap;

    fn mem_conn() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    /// Minimal msgpack-encoded baseAccountData: an empty map ({}).
    /// This decodes to all-default fields (status=0/Offline, balance=0, etc.).
    fn empty_account_data_blob() -> Vec<u8> {
        // fixmap with 0 entries: 0x80
        vec![0x80]
    }

    /// Minimal msgpack-encoded resourcesData with ownership flag set.
    /// This is a map with key "y" (resource_flags) = RESOURCE_FLAGS_OWNERSHIP (2).
    fn owned_asset_resource_blob() -> Vec<u8> {
        // Map with 2 entries:
        //   "a" => 100 (total supply, makes it a non-empty asset)
        //   "y" => 2 (ownership flag)
        vec![
            0x82, // fixmap(2)
            0xa1, b'a', // key "a" (fixstr 1)
            100,  // value 100 (positive fixint)
            0xa1, b'y', // key "y" (fixstr 1)
            2,    // value 2 (RESOURCE_FLAGS_OWNERSHIP)
        ]
    }

    /// Minimal msgpack-encoded resourcesData with ownership flag for an app.
    fn owned_app_resource_blob() -> Vec<u8> {
        // Map with 2 entries:
        //   "q" => [0x01] (approval_program, makes it a non-empty app)
        //   "y" => 2 (ownership flag)
        vec![
            0x82, // fixmap(2)
            0xa1, b'q', // key "q" (fixstr 1)
            0xc4, 0x01, 0x01, // value: bin8 with 1 byte [0x01]
            0xa1, b'y', // key "y" (fixstr 1)
            2,    // value 2 (RESOURCE_FLAGS_OWNERSHIP)
        ]
    }

    /// Non-owning resource blob (resource_flags = 0).
    fn non_owning_resource_blob() -> Vec<u8> {
        vec![0x80] // empty map
    }

    fn make_balance_record(
        address: [u8; 32],
        account_data: Vec<u8>,
        resources: HashMap<u64, ByteBuf>,
    ) -> BalanceRecordV6 {
        BalanceRecordV6 {
            address: ByteBuf::from(address.to_vec()),
            account_data: ByteBuf::from(account_data),
            resources,
            expecting_more_entries: false,
        }
    }

    #[test]
    fn import_empty_chunk() {
        let conn = mem_conn();
        let mut importer = CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS);
        importer.prepare_staging().unwrap();

        let chunk = CatchpointSnapshotChunkV6::default();
        let mut stats = ImportStats::default();
        importer.import_chunk(1, &chunk, &mut stats).unwrap();

        assert_eq!(stats.accounts, 0);
        assert_eq!(stats.kvs, 0);
        assert_eq!(stats.chunks_processed, 1);
    }

    #[test]
    fn import_balance_record_inserts_account() {
        let conn = mem_conn();
        let mut importer = CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS);
        importer.prepare_staging().unwrap();

        let addr = [1u8; 32];
        let record = make_balance_record(addr, empty_account_data_blob(), HashMap::new());

        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        importer.import_balance_record(&record).unwrap();
        conn.execute_batch("COMMIT").unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM catchpointbalances", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);

        // Verify address was stored correctly.
        let stored_addr: Vec<u8> = conn
            .query_row(
                "SELECT address FROM catchpointbalances WHERE addrid = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_addr, addr.to_vec());
    }

    #[test]
    fn import_balance_with_owned_asset_resource() {
        let conn = mem_conn();
        let mut importer = CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS);
        importer.prepare_staging().unwrap();

        let addr = [2u8; 32];
        let mut resources = HashMap::new();
        resources.insert(42u64, ByteBuf::from(owned_asset_resource_blob()));

        let record = make_balance_record(addr, empty_account_data_blob(), resources);

        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        importer.import_balance_record(&record).unwrap();
        conn.execute_batch("COMMIT").unwrap();

        // Verify resource was inserted.
        let rsc_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM catchpointresources", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rsc_count, 1);

        // Verify asset creator was inserted.
        let (asset, ctype): (i64, i64) = conn
            .query_row(
                "SELECT asset, ctype FROM catchpointassetcreators WHERE asset = 42",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(asset, 42);
        assert_eq!(ctype, CTYPE_ASSET);
    }

    #[test]
    fn import_balance_with_owned_app_resource() {
        let conn = mem_conn();
        let mut importer = CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS);
        importer.prepare_staging().unwrap();

        let addr = [3u8; 32];
        let mut resources = HashMap::new();
        resources.insert(99u64, ByteBuf::from(owned_app_resource_blob()));

        let record = make_balance_record(addr, empty_account_data_blob(), resources);

        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        importer.import_balance_record(&record).unwrap();
        conn.execute_batch("COMMIT").unwrap();

        let (asset, ctype): (i64, i64) = conn
            .query_row(
                "SELECT asset, ctype FROM catchpointassetcreators WHERE asset = 99",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(asset, 99);
        assert_eq!(ctype, CTYPE_APP);
    }

    #[test]
    fn import_non_owning_resource_skips_creators() {
        let conn = mem_conn();
        let mut importer = CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS);
        importer.prepare_staging().unwrap();

        let addr = [4u8; 32];
        let mut resources = HashMap::new();
        resources.insert(10u64, ByteBuf::from(non_owning_resource_blob()));

        let record = make_balance_record(addr, empty_account_data_blob(), resources);

        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        importer.import_balance_record(&record).unwrap();
        conn.execute_batch("COMMIT").unwrap();

        let creator_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM catchpointassetcreators", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(creator_count, 0);
    }

    #[test]
    fn prepare_staging_always_yields_not_null_ctype() {
        // Phase B: prepare_staging unconditionally drops and recreates the
        // staging tables (no cross-instance resume), so any leftover from
        // an older binary — including pre-G5 staging with a nullable
        // `catchpointresources.ctype` — is replaced with the canonical
        // shape declared in `CATCHPOINT_STAGING_TABLES_SQL`. Regression
        // guard against the NOT NULL DEFAULT -1 invariant silently going
        // away.
        let conn = mem_conn();

        // Seed a pre-G5 staging shape (nullable ctype) to be replaced.
        conn.execute_batch(
            "CREATE TABLE catchpointresources (
                addrid INTEGER NOT NULL,
                aidx INTEGER NOT NULL,
                data BLOB NOT NULL,
                ctype INTEGER,
                PRIMARY KEY (addrid, aidx)
            ) WITHOUT ROWID;",
        )
        .unwrap();

        let mut importer = CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS);
        importer.prepare_staging().expect("prepare_staging");

        let notnull: i64 = conn
            .query_row(
                "SELECT \"notnull\" FROM pragma_table_info('catchpointresources') WHERE name='ctype'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(notnull, 1);
    }

    #[test]
    fn import_kv_record() {
        let conn = mem_conn();
        let mut importer = CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS);
        importer.prepare_staging().unwrap();

        let record = KVRecordV6 {
            key: ByteBuf::from(b"mykey".to_vec()),
            value: ByteBuf::from(b"myvalue".to_vec()),
        };

        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        importer.import_kv_record(&record).unwrap();
        conn.execute_batch("COMMIT").unwrap();

        let value: Vec<u8> = conn
            .query_row(
                "SELECT value FROM catchpointkvstore WHERE key = ?1",
                rusqlite::params![b"mykey".as_ref()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(value, b"myvalue");
    }

    #[test]
    fn import_online_account_record() {
        let conn = mem_conn();
        let mut importer = CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS);
        importer.prepare_staging().unwrap();

        let record = OnlineAccountRecordV6 {
            address: ByteBuf::from([5u8; 32].to_vec()),
            updated_round: 100,
            normalized_online_balance: 999,
            vote_last_valid: 200,
            data: ByteBuf::from(vec![0x80]),
        };

        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        importer.import_online_account(&record).unwrap();
        conn.execute_batch("COMMIT").unwrap();

        let (updround, nob, vlv): (i64, i64, i64) = conn
            .query_row(
                "SELECT updround, normalizedonlinebalance, votelastvalid FROM catchpointonlineaccounts",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(updround, 100);
        assert_eq!(nob, 999);
        assert_eq!(vlv, 200);
    }

    #[test]
    fn import_online_round_params_record() {
        let conn = mem_conn();
        let mut importer = CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS);
        importer.prepare_staging().unwrap();

        let record = OnlineRoundParamsRecordV6 {
            round: 500,
            data: ByteBuf::from(vec![0x80]),
        };

        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        importer.import_online_round_params(&record).unwrap();
        conn.execute_batch("COMMIT").unwrap();

        let (rnd, data): (i64, Vec<u8>) = conn
            .query_row(
                "SELECT rnd, data FROM catchpointonlineroundparamstail",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(rnd, 500);
        assert_eq!(data, vec![0x80]);
    }

    #[test]
    fn import_chunks_batching() {
        let conn = mem_conn();
        let mut importer = CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS)
            .with_batch_size(2);
        importer.prepare_staging().unwrap();

        let chunks: Vec<Result<(u64, CatchpointSnapshotChunkV6), CatchpointError>> = (1..=5)
            .map(|i| {
                let mut chunk = CatchpointSnapshotChunkV6::default();
                chunk.kvs.push(KVRecordV6 {
                    key: ByteBuf::from(format!("key{i}").into_bytes()),
                    value: ByteBuf::from(format!("val{i}").into_bytes()),
                });
                Ok((i, chunk))
            })
            .collect();

        let stats = importer.import_chunks(chunks.into_iter(), 5).unwrap();
        assert_eq!(stats.chunks_processed, 5);
        assert_eq!(stats.kvs, 5);

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM catchpointkvstore", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 5);

        // After import the in-memory checkpoint reflects the last committed
        // chunk + the expected total.
        let cp = importer.checkpoint();
        assert_eq!(cp.catchpoint_label, "test#label");
        assert_eq!(cp.last_chunk_ordinal, 5);
        assert_eq!(cp.total_chunks, 5);
    }

    #[test]
    fn checkpoint_resets_on_fresh_prepare_staging() {
        // Phase B / TASK-117: there is no cross-instance resume. Creating
        // a new importer after a previous one finished must start from
        // chunk 0 with an empty in-memory checkpoint.
        let conn = mem_conn();

        // First importer imports 3 chunks then drops.
        {
            let mut importer =
                CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS)
                    .with_batch_size(10);
            importer.prepare_staging().unwrap();

            let chunks: Vec<Result<(u64, CatchpointSnapshotChunkV6), CatchpointError>> = (1..=3)
                .map(|i| {
                    let mut chunk = CatchpointSnapshotChunkV6::default();
                    chunk.kvs.push(KVRecordV6 {
                        key: ByteBuf::from(format!("key{i}").into_bytes()),
                        value: ByteBuf::from(format!("val{i}").into_bytes()),
                    });
                    Ok((i, chunk))
                })
                .collect();
            importer.import_chunks(chunks.into_iter(), 5).unwrap();
            assert_eq!(importer.checkpoint().last_chunk_ordinal, 3);
        }

        // A brand-new importer must NOT pick up any cross-process state.
        let importer2 = CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS);
        assert_eq!(importer2.checkpoint().last_chunk_ordinal, 0);
        assert_eq!(importer2.checkpoint().total_chunks, 0);
    }

    // -------------------------------------------------------------------
    // atomic_cutover tests
    // -------------------------------------------------------------------

    use crate::catchpoint::types::{AccountTotals, AlgoCount, CatchpointFileHeader};

    fn make_test_header(round: u64) -> CatchpointFileHeader {
        CatchpointFileHeader {
            version: 131, // V8
            balances_round: round,
            totals: AccountTotals {
                online: AlgoCount {
                    money: 1_000_000,
                    reward_units: 10,
                },
                offline: AlgoCount {
                    money: 2_000_000,
                    reward_units: 20,
                },
                not_participating: AlgoCount {
                    money: 3_000_000,
                    reward_units: 30,
                },
                rewards_level: 42,
            },
            catchpoint: "47000000#ABCDEF".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn atomic_cutover_renames_tables() {
        let conn = mem_conn();
        let mut importer = CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS);
        importer.prepare_staging().unwrap();

        // Insert a record into staging.
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        conn.execute(
            "INSERT INTO catchpointkvstore(key, value) VALUES(X'AA', X'BB')",
            [],
        )
        .unwrap();
        conn.execute_batch("COMMIT").unwrap();

        let header = make_test_header(47_000_000);
        importer.atomic_cutover(&header).unwrap();

        // Live kvstore table should now contain the record.
        let value: Vec<u8> = conn
            .query_row("SELECT value FROM kvstore WHERE key = X'AA'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(value, vec![0xBB]);

        // Staging table should no longer exist.
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='catchpointkvstore'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!exists);
    }

    #[test]
    fn atomic_cutover_writes_acctrounds() {
        let conn = mem_conn();
        let mut importer = CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS);
        importer.prepare_staging().unwrap();

        let header = make_test_header(47_000_000);
        importer.atomic_cutover(&header).unwrap();

        let rnd: i64 = conn
            .query_row(
                "SELECT rnd FROM acctrounds WHERE id = 'acctbase'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rnd, 47_000_000);

        let hash_rnd: i64 = conn
            .query_row(
                "SELECT rnd FROM acctrounds WHERE id = 'hashbase'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(hash_rnd, 47_000_000);
    }

    #[test]
    fn atomic_cutover_writes_go_canonical_catchpointstate_keys() {
        // G6 part 2 (TASK-106) — verify the five catchpointstate keys
        // the importer writes during cutover match Go's
        // `trackerdb.CatchpointState*` constants byte-for-byte. If a
        // future refactor regresses any of these to a Rust-only name,
        // Go would fail to find them on reopen.
        use crate::catchpoint::state_keys;

        let conn = mem_conn();
        let mut importer = CatchpointImporter::new(&conn, "47000000#abc".to_string(), REWARD_UNITS);
        importer.prepare_staging().unwrap();

        let header = make_test_header(47_000_000);
        importer.atomic_cutover(&header).unwrap();

        // Each Go-canonical key the importer is supposed to write
        // must be present in the live catchpointstate table.
        for key in [
            state_keys::CATCHUP_LABEL,
            state_keys::CATCHUP_VERSION,
            state_keys::CATCHUP_BLOCK_ROUND,
            state_keys::CATCHUP_BALANCES_ROUND,
            state_keys::CATCHUP_HASH_ROUND,
        ] {
            let exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM catchpointstate WHERE id = ?1)",
                    [key],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "missing Go-canonical catchpointstate key `{key}`");
        }

        // Every non-namespaced key actually written to the table must
        // appear in the canonical list — catches drift if a new
        // non-namespaced key is added without updating state_keys.
        let mut written: Vec<String> = Vec::new();
        let mut stmt = conn.prepare("SELECT id FROM catchpointstate").unwrap();
        let rows = stmt.query_map([], |row| row.get::<_, String>(0)).unwrap();
        for r in rows {
            written.push(r.unwrap());
        }
        for k in &written {
            if k.starts_with("algod_rust_") {
                continue;
            }
            assert!(
                state_keys::ALL_GO_CANONICAL.contains(&k.as_str()),
                "catchpointstate key `{k}` is not Go-canonical and is \
                 not namespaced; add to state_keys::ALL_GO_CANONICAL \
                 or prefix with `algod_rust_`"
            );
        }
    }

    #[test]
    fn atomic_cutover_writes_account_totals() {
        let conn = mem_conn();
        let mut importer = CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS);
        importer.prepare_staging().unwrap();

        let header = make_test_header(100);
        importer.atomic_cutover(&header).unwrap();

        let (online, online_ru, offline, offline_ru, nopart, nopart_ru, rwdlvl): (
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
        ) = conn
            .query_row(
                "SELECT online, onlinerewardunits, offline, offlinerewardunits, notparticipating, notparticipatingrewardunits, rewardslevel FROM accounttotals WHERE id = ''",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .unwrap();

        assert_eq!(online, 1_000_000);
        assert_eq!(online_ru, 10);
        assert_eq!(offline, 2_000_000);
        assert_eq!(offline_ru, 20);
        assert_eq!(nopart, 3_000_000);
        assert_eq!(nopart_ru, 30);
        assert_eq!(rwdlvl, 42);
    }

    #[test]
    fn atomic_cutover_drops_remaining_staging_tables() {
        let conn = mem_conn();
        let mut importer = CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS);
        importer.prepare_staging().unwrap();

        // Verify catchpointpendinghashes exists before cutover.
        let exists_before: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='catchpointpendinghashes'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists_before);

        let header = make_test_header(100);
        importer.atomic_cutover(&header).unwrap();

        // catchpointpendinghashes should be gone.
        let exists_after: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='catchpointpendinghashes'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!exists_after);

        // After TASK-117 the Rust-only `catchpoint_import_state` table no
        // longer exists at all — assert that it was never created during
        // import or by cutover.
        let cp_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='catchpoint_import_state'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!cp_exists);
    }

    #[test]
    fn atomic_cutover_replaces_existing_live_tables() {
        let conn = mem_conn();

        // Create pre-existing live tables with data.
        conn.execute_batch(
            "CREATE TABLE accountbase (address BLOB PRIMARY KEY, normalizedonlinebalance INTEGER, data BLOB);
            INSERT INTO accountbase VALUES(X'0101', 0, X'00');
            CREATE TABLE kvstore (key BLOB PRIMARY KEY, value BLOB);
            INSERT INTO kvstore VALUES(X'0101', X'AABB');",
        )
        .unwrap();

        // Prepare staging and insert different data.
        let mut importer = CatchpointImporter::new(&conn, "test#label".to_string(), REWARD_UNITS);
        importer.prepare_staging().unwrap();

        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        conn.execute(
            "INSERT INTO catchpointkvstore(key, value) VALUES(X'0202', X'CCDD')",
            [],
        )
        .unwrap();
        conn.execute_batch("COMMIT").unwrap();

        let header = make_test_header(100);
        importer.atomic_cutover(&header).unwrap();

        // Old data should be gone.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM kvstore WHERE key = X'0101'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);

        // New data should be present.
        let value: Vec<u8> = conn
            .query_row("SELECT value FROM kvstore WHERE key = X'0202'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(value, vec![0xCC, 0xDD]);
    }
}
