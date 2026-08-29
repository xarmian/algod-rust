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

//! Catchpoint file writer (snapshot export).
//!
//! This is the inverse of [`super::importer`]: it reads a go-algorand-shaped
//! tracker database (`accountbase`, `resources`, `kvstore`, `onlineaccounts`,
//! `onlineroundparamstail`, `stateproofverification`, `accounttotals`) and
//! produces a catchpoint file byte-compatible with go-algorand's format.
//!
//! # Reference
//!
//! The format and the write order follow go-algorand v4.6.0-stable:
//!
//! * `../go-algorand/ledger/catchpointfilewriter.go` — `catchpointFileWriter`,
//!   `readDatabaseStep`, `asyncWriter`, and the chunk constants
//!   (`BalancesPerCatchpointFileChunk = 512`,
//!   `ResourcesPerCatchpointFileChunk = 100_000`).
//! * `../go-algorand/ledger/catchpointtracker.go` — the tar entry names
//!   (`content.msgpack`, `stateProofVerificationContext.msgpack`,
//!   `balances.%d.msgpack`), the stage-1/stage-2 split, and `repackCatchpoint`
//!   / `doRepackCatchpoint`, which prepend `content.msgpack` and gzip the
//!   final archive.
//! * `../go-algorand/ledger/encoded/recordsV6.go` — the record codec tags.
//! * `../go-algorand/ledger/ledgercore/catchpointlabel.go` — the label hash.
//!
//! # File layout produced
//!
//! ```text
//! gzip(tar):
//!   content.msgpack                        CatchpointFileHeader
//!   stateProofVerificationContext.msgpack  catchpointStateProofVerificationContext
//!   balances.1.msgpack                     CatchpointSnapshotChunkV6
//!   balances.2.msgpack
//!   ...
//! ```
//!
//! Chunk entries are plain (uncompressed) msgpack, matching go-algorand's
//! *final* catchpoint file: go's stage-1 scratch file is Snappy-framed, but
//! `repackCatchpoint` decompresses it and re-emits the entries verbatim into
//! a gzip-compressed tar. This writer mirrors that end state — it also uses a
//! stage-1 scratch tar so the header (which carries the chunk count) can be
//! written first without buffering the whole snapshot in memory, but the
//! scratch file is left uncompressed since it never leaves the machine.
//!
//! # Ordering
//!
//! Account chunks are emitted in `accountbase` rowid order and resources in
//! `(addrid, aidx)` order, exactly like go's
//! `sqlitedriver.encodedAccountsBatchIter` (`SELECT rowid, address, data FROM
//! accountbase ORDER BY rowid` / `SELECT addrid, aidx, data FROM resources
//! ORDER BY addrid, aidx`). Notably this is **not** Merkle-trie order — go's
//! catchpoint file writer never walks the trie; the balances Merkle root that
//! feeds the catchpoint label is computed separately and is order-independent.
//!
//! # Encoding
//!
//! Records are encoded with hand-rolled canonical msgpack (sorted string keys,
//! `omitempty`, shortest integer form, `msgp.Raw` fields spliced in verbatim),
//! matching go-codec's `protocol.Encode`. `rmp_serde::to_vec_named` is *not*
//! used because it emits every field, in declaration order, and wraps
//! `msgp.Raw` blobs in a msgpack `bin` header.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use flate2::write::GzEncoder;
use flate2::Compression;
use rusqlite::Connection;
use sha2::{Digest, Sha512_256};

use super::types::{CatchpointError, CatchpointFileHeader, CATCHPOINT_FILE_VERSION_V8};
use super::verify::{
    build_sp_verification_blob, count_accounts, encode_account_totals, encode_mixed_map,
    encode_msgpack_bin, encode_msgpack_uint, encode_online_account_record,
    encode_online_round_params_record, hash_sp_verification_blob, make_catchpoint_label_v8,
    read_account_totals, rebuild_trie_from_db,
};

// ---------------------------------------------------------------------------
// Constants (mirroring go-algorand/ledger/catchpointfilewriter.go)
// ---------------------------------------------------------------------------

/// Number of accounts stored in each balances chunk.
/// Go: `BalancesPerCatchpointFileChunk`.
pub const BALANCES_PER_CATCHPOINT_FILE_CHUNK: usize = 512;

/// Maximum number of resources that go into a single chunk.
/// Go: `ResourcesPerCatchpointFileChunk`.
pub const RESOURCES_PER_CATCHPOINT_FILE_CHUNK: usize = 100_000;

/// Default `MaxBalLookback` (rounds of online-account history kept).
/// Go: `config.Consensus[...].MaxBalLookback` — 320 for every current version.
pub const DEFAULT_MAX_BAL_LOOKBACK: u64 = 320;

const CONTENT_FILENAME: &str = "content.msgpack";
const SP_VERIFICATION_FILENAME: &str = "stateProofVerificationContext.msgpack";

// ---------------------------------------------------------------------------
// Options / result
// ---------------------------------------------------------------------------

/// Configuration for a catchpoint export.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// Round of the account snapshot (`CatchpointFileHeader.BalancesRound`).
    pub balances_round: u64,

    /// Round of the block whose header digest anchors the label
    /// (`CatchpointFileHeader.BlocksRound`, and the round in the label).
    ///
    /// In go-algorand this is `balances_round + catchpoint_lookback`. This
    /// crate's [`super::verify::verify_catchpoint`] requires
    /// `acctrounds('acctbase') == label round`, so an export that is meant to
    /// be re-verified after import must keep the two rounds equal.
    pub blocks_round: u64,

    /// 32-byte digest of the block header at `blocks_round`.
    pub block_header_digest: [u8; 32],

    /// Include the `onlineaccounts` / `onlineroundparamstail` tables
    /// (go: `params.EnableCatchpointsWithOnlineAccounts`, true since
    /// consensus v40). When false, those chunks are omitted and their label
    /// component hashes are the hash of an empty stream.
    pub include_online_data: bool,

    /// Online-account history horizon. `Some(n)` reproduces go's
    /// `MaxBalLookback` normalization (see
    /// [`ExportOptions::online_horizon_round`]); `None` disables it.
    pub max_bal_lookback: Option<u64>,

    /// Accounts per balances chunk. Defaults to
    /// [`BALANCES_PER_CATCHPOINT_FILE_CHUNK`].
    pub accounts_per_chunk: usize,

    /// Resource cap per balances chunk. Defaults to
    /// [`RESOURCES_PER_CATCHPOINT_FILE_CHUNK`].
    pub max_resources_per_chunk: usize,

    /// Gzip the resulting tar archive (go always does for the published file).
    pub gzip: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            balances_round: 0,
            blocks_round: 0,
            block_header_digest: [0u8; 32],
            include_online_data: true,
            max_bal_lookback: Some(DEFAULT_MAX_BAL_LOOKBACK),
            accounts_per_chunk: BALANCES_PER_CATCHPOINT_FILE_CHUNK,
            max_resources_per_chunk: RESOURCES_PER_CATCHPOINT_FILE_CHUNK,
            gzip: true,
        }
    }
}

impl ExportOptions {
    /// Oldest online-account `updround` that is still inside the history
    /// window. Rows older than this get their `updround` rewritten to 0.
    ///
    /// Go: `catchpointLookbackHorizonForNextRound(rnd, params)` =
    /// `(rnd + 1).SubSaturate(MaxBalLookback)`
    /// (`../go-algorand/ledger/catchpointfilewriter.go`).
    fn online_horizon_round(&self) -> Option<u64> {
        self.max_bal_lookback
            .map(|lookback| (self.balances_round + 1).saturating_sub(lookback))
    }
}

/// Summary of a completed catchpoint export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportResult {
    /// Path of the written catchpoint file.
    pub path: PathBuf,
    /// The catchpoint label (`"{blocks_round}#{base32_hash}"`).
    pub label: String,
    /// Balances Merkle trie root that fed the label.
    pub balances_root: [u8; 32],
    /// Number of rows in `accountbase`.
    pub total_accounts: u64,
    /// Number of `balances.N.msgpack` entries written.
    pub total_chunks: u64,
    /// Number of rows in `kvstore`.
    pub total_kvs: u64,
    /// Number of exported `onlineaccounts` rows.
    pub total_online_accounts: u64,
    /// Number of exported `onlineroundparamstail` rows.
    pub total_online_round_params: u64,
    /// Largest single tar entry payload, in bytes (go: `biggestChunkLen`).
    pub biggest_chunk_len: u64,
    /// Size of the written file, in bytes.
    pub file_size: u64,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Export a catchpoint file from a go-algorand-shaped tracker database.
///
/// `conn` must expose the live (post-cutover) tables — the same ones
/// [`super::verify::verify_catchpoint`] reads. The written file is importable
/// by [`super::import_catchpoint_file`].
///
/// Mirrors the pipeline of go's `catchpointTracker.finishFirstStage` +
/// `createCatchpointFile`: compute the component hashes and the label, write
/// the snapshot chunks, then prepend the header carrying that label.
pub fn export_catchpoint_file(
    conn: &Connection,
    out_path: &Path,
    opts: &ExportOptions,
) -> Result<ExportResult, CatchpointError> {
    if opts.accounts_per_chunk == 0 || opts.max_resources_per_chunk == 0 {
        return Err(CatchpointError::ImportError(
            "accounts_per_chunk and max_resources_per_chunk must be non-zero".to_string(),
        ));
    }

    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // --- Label components -------------------------------------------------
    //
    // Go computes these in `finishFirstStage` before the file is published:
    // the balances Merkle root, the SP verification hash, and (V8+) the
    // online-accounts / online-round-params verification hashes.
    let balances_root = rebuild_trie_from_db(conn)?;
    let sp_blob = build_sp_verification_blob(conn)?;
    let sp_hash = hash_sp_verification_blob(&sp_blob);
    let totals = read_account_totals(conn)?;

    let online_accounts = if opts.include_online_data {
        read_online_accounts(conn, opts.online_horizon_round())?
    } else {
        Vec::new()
    };
    let online_round_params = if opts.include_online_data {
        read_online_round_params(conn)?
    } else {
        Vec::new()
    };

    // The online hashes must be computed over exactly the records that go
    // into the file (go hashes through the same
    // `makeCatchpointOrderedOnlineAccountsIterFactory` wrapper the writer
    // uses), otherwise a re-import + verify would recompute a different hash.
    let online_accounts_hash = hash_records(b"OA", &online_accounts);
    let online_round_params_hash = hash_records(b"ORP", &online_round_params);

    let label = make_catchpoint_label_v8(
        opts.blocks_round,
        &opts.block_header_digest,
        &balances_root,
        &totals,
        &sp_hash,
        &online_accounts_hash,
        &online_round_params_hash,
    );

    // --- Stage 1: chunks into a scratch tar -------------------------------
    let stage1_path = stage1_path_for(out_path);
    let stage1 = StageOneStats::write(
        conn,
        &stage1_path,
        opts,
        &sp_blob,
        &online_accounts,
        &online_round_params,
    );
    let stage1 = match stage1 {
        Ok(s) => s,
        Err(e) => {
            let _ = std::fs::remove_file(&stage1_path);
            return Err(e);
        }
    };

    // --- Stage 2: repack with the header first ----------------------------
    let header = CatchpointFileHeader {
        version: CATCHPOINT_FILE_VERSION_V8,
        balances_round: opts.balances_round,
        blocks_round: opts.blocks_round,
        totals: totals.clone(),
        total_accounts: count_accounts(conn)?,
        total_chunks: stage1.total_chunks,
        total_kvs: stage1.total_kvs,
        total_online_accounts: online_accounts.len() as u64,
        total_online_round_params: online_round_params.len() as u64,
        catchpoint: label.clone(),
        block_header_digest: serde_bytes::ByteBuf::from(opts.block_header_digest.to_vec()),
    };
    let header_bytes = encode_catchpoint_file_header(&header);

    let repack = repack(&stage1_path, out_path, &header_bytes, opts.gzip);
    let _ = std::fs::remove_file(&stage1_path);
    repack?;

    let file_size = std::fs::metadata(out_path)?.len();

    Ok(ExportResult {
        path: out_path.to_path_buf(),
        label,
        balances_root,
        total_accounts: header.total_accounts,
        total_chunks: stage1.total_chunks,
        total_kvs: stage1.total_kvs,
        total_online_accounts: online_accounts.len() as u64,
        total_online_round_params: online_round_params.len() as u64,
        // Go's `biggestChunkLen` covers the stage-1 entries only (it sizes the
        // repack copy buffer), so `content.msgpack` is deliberately excluded.
        biggest_chunk_len: stage1.biggest_chunk_len,
        file_size,
    })
}

/// Scratch-file path used for the stage-1 archive.
fn stage1_path_for(out_path: &Path) -> PathBuf {
    let mut s = out_path.as_os_str().to_owned();
    s.push(".stage1.tmp");
    PathBuf::from(s)
}

// ---------------------------------------------------------------------------
// Stage 1 — SP context + balances chunks into a scratch tar
// ---------------------------------------------------------------------------

struct StageOneStats {
    total_chunks: u64,
    total_kvs: u64,
    biggest_chunk_len: u64,
}

impl StageOneStats {
    fn write(
        conn: &Connection,
        stage1_path: &Path,
        opts: &ExportOptions,
        sp_blob: &[u8],
        online_accounts: &[Vec<u8>],
        online_round_params: &[Vec<u8>],
    ) -> Result<Self, CatchpointError> {
        let file = File::create(stage1_path)?;
        let mut builder = tar::Builder::new(BufWriter::new(file));

        // Entry 1: state proof verification context.
        append_entry(&mut builder, SP_VERIFICATION_FILENAME, sp_blob)?;

        let mut total_chunks = 0u64;
        let total_kvs;
        let mut biggest_chunk_len = sp_blob.len() as u64;

        {
            // Entries 2..: balances chunks. go's `readDatabaseStep` yields all
            // account chunks first, then KV chunks, then online accounts, then
            // online round params — never an empty chunk in between.
            let mut emit = |chunk: Vec<u8>| -> Result<(), CatchpointError> {
                total_chunks += 1;
                let name = format!("balances.{total_chunks}.msgpack");
                append_entry(&mut builder, &name, &chunk)?;
                if chunk.len() as u64 > biggest_chunk_len {
                    biggest_chunk_len = chunk.len() as u64;
                }
                Ok(())
            };

            write_account_chunks(conn, opts, &mut emit)?;
            total_kvs = write_kv_chunks(conn, opts, &mut emit)?;

            for group in online_accounts.chunks(opts.accounts_per_chunk) {
                emit(encode_chunk(&[], &[], &as_slices(group), &[]))?;
            }
            for group in online_round_params.chunks(opts.accounts_per_chunk) {
                emit(encode_chunk(&[], &[], &[], &as_slices(group)))?;
            }
        }

        builder.finish().map_err(CatchpointError::Io)?;
        let mut inner = builder.into_inner().map_err(CatchpointError::Io)?;
        inner.flush()?;

        Ok(StageOneStats {
            total_chunks,
            total_kvs,
            biggest_chunk_len,
        })
    }
}

/// Append one tar entry with go's mode (0600) and no owner metadata.
fn append_entry<W: Write>(
    builder: &mut tar::Builder<W>,
    name: &str,
    data: &[u8],
) -> Result<(), CatchpointError> {
    let mut header = tar::Header::new_gnu();
    header
        .set_path(name)
        .map_err(|e| CatchpointError::ImportError(format!("tar path {name}: {e}")))?;
    header.set_size(data.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    builder.append(&header, data).map_err(CatchpointError::Io)
}

/// Stream `accountbase` (+ its `resources`) into balances chunks.
fn write_account_chunks(
    conn: &Connection,
    opts: &ExportOptions,
    emit: &mut impl FnMut(Vec<u8>) -> Result<(), CatchpointError>,
) -> Result<(), CatchpointError> {
    let mut acct_stmt =
        conn.prepare("SELECT rowid, address, data FROM accountbase ORDER BY rowid")?;
    let mut res_stmt =
        conn.prepare("SELECT aidx, data FROM resources WHERE addrid = ?1 ORDER BY aidx")?;

    let mut pending: Vec<Vec<u8>> = Vec::new();
    let mut pending_resources = 0usize;

    let mut rows = acct_stmt.query([])?;
    while let Some(row) = rows.next()? {
        let addrid: i64 = row.get(0)?;
        let address: Vec<u8> = row.get(1)?;
        let account_data: Vec<u8> = row.get(2)?;

        if address.len() != 32 {
            return Err(CatchpointError::ImportError(format!(
                "bad address length {} (expected 32) in accountbase",
                address.len()
            )));
        }

        // Resources are read into a BTreeMap so the encoded map keys come out
        // ascending, matching go's `SortUint64` on `map[uint64]msgp.Raw`.
        let mut resources: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut res_rows = res_stmt.query(rusqlite::params![addrid])?;
        while let Some(res_row) = res_rows.next()? {
            let aidx: i64 = res_row.get(0)?;
            let data: Vec<u8> = res_row.get(1)?;
            resources.insert(aidx as u64, data);
        }

        let resources: Vec<(u64, Vec<u8>)> = resources.into_iter().collect();

        if resources.len() > opts.max_resources_per_chunk {
            // Oversized account: flush whatever is pending, then emit one
            // chunk per resource slice with ExpectingMoreEntries set on all
            // but the last — go's `resCb` in
            // `sqlitedriver/encodedAccountsIter.go` does the same.
            if !pending.is_empty() {
                emit(encode_chunk(&as_slices(&pending), &[], &[], &[]))?;
                pending.clear();
                pending_resources = 0;
            }
            let slices: Vec<&[(u64, Vec<u8>)]> =
                resources.chunks(opts.max_resources_per_chunk).collect();
            let last = slices.len() - 1;
            for (i, slice) in slices.into_iter().enumerate() {
                let record = encode_balance_record(&address, &account_data, slice, i != last);
                emit(encode_chunk(&[record.as_slice()], &[], &[], &[]))?;
            }
            continue;
        }

        if !pending.is_empty() && pending_resources + resources.len() > opts.max_resources_per_chunk
        {
            emit(encode_chunk(&as_slices(&pending), &[], &[], &[]))?;
            pending.clear();
            pending_resources = 0;
        }

        pending.push(encode_balance_record(
            &address,
            &account_data,
            &resources,
            false,
        ));
        pending_resources += resources.len();

        if pending.len() >= opts.accounts_per_chunk
            || pending_resources >= opts.max_resources_per_chunk
        {
            emit(encode_chunk(&as_slices(&pending), &[], &[], &[]))?;
            pending.clear();
            pending_resources = 0;
        }
    }

    if !pending.is_empty() {
        emit(encode_chunk(&as_slices(&pending), &[], &[], &[]))?;
    }

    Ok(())
}

/// Stream `kvstore` into balances chunks. Returns the number of rows written.
fn write_kv_chunks(
    conn: &Connection,
    opts: &ExportOptions,
    emit: &mut impl FnMut(Vec<u8>) -> Result<(), CatchpointError>,
) -> Result<u64, CatchpointError> {
    let mut stmt = conn.prepare("SELECT key, value FROM kvstore ORDER BY key")?;
    let mut rows = stmt.query([])?;

    let mut total = 0u64;
    let mut pending: Vec<Vec<u8>> = Vec::new();

    while let Some(row) = rows.next()? {
        let key: Vec<u8> = row.get(0)?;
        let value: Vec<u8> = row.get(1)?;
        pending.push(encode_kv_record(&key, &value));
        total += 1;
        if pending.len() >= opts.accounts_per_chunk {
            emit(encode_chunk(&[], &as_slices(&pending), &[], &[]))?;
            pending.clear();
        }
    }

    if !pending.is_empty() {
        emit(encode_chunk(&[], &as_slices(&pending), &[], &[]))?;
    }

    Ok(total)
}

fn as_slices(records: &[Vec<u8>]) -> Vec<&[u8]> {
    records.iter().map(|r| r.as_slice()).collect()
}

// ---------------------------------------------------------------------------
// Stage 2 — repack with the header first
// ---------------------------------------------------------------------------

/// Prepend `content.msgpack` and copy the stage-1 entries verbatim into the
/// final (optionally gzipped) archive.
///
/// Go: `doRepackCatchpoint` in `../go-algorand/ledger/catchpointtracker.go`.
fn repack(
    stage1_path: &Path,
    out_path: &Path,
    header_bytes: &[u8],
    gzip: bool,
) -> Result<(), CatchpointError> {
    let out = File::create(out_path)?;
    if gzip {
        // go uses gzip.BestSpeed for the published catchpoint file.
        let mut encoder = GzEncoder::new(BufWriter::new(out), Compression::fast());
        repack_into(stage1_path, &mut encoder, header_bytes)?;
        let mut inner = encoder.finish()?;
        inner.flush()?;
    } else {
        let mut writer = BufWriter::new(out);
        repack_into(stage1_path, &mut writer, header_bytes)?;
        writer.flush()?;
    }
    Ok(())
}

fn repack_into<W: Write>(
    stage1_path: &Path,
    out: &mut W,
    header_bytes: &[u8],
) -> Result<(), CatchpointError> {
    let mut builder = tar::Builder::new(out);
    append_entry(&mut builder, CONTENT_FILENAME, header_bytes)?;

    let stage1 = File::open(stage1_path)?;
    let mut archive = tar::Archive::new(BufReader::new(stage1));
    for entry in archive.entries().map_err(CatchpointError::Io)? {
        let mut entry = entry.map_err(CatchpointError::Io)?;
        let name = entry
            .path()
            .map_err(CatchpointError::Io)?
            .to_string_lossy()
            .into_owned();
        let mut data =
            Vec::with_capacity(entry.header().size().map_err(CatchpointError::Io)? as usize);
        entry.read_to_end(&mut data)?;
        append_entry(&mut builder, &name, &data)?;
    }

    builder.finish().map_err(CatchpointError::Io)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Online account / round params readers
// ---------------------------------------------------------------------------

/// Read `onlineaccounts` ordered by `(address, updround)`, applying go's
/// horizon normalization, and return the canonically-encoded records.
///
/// Go rewrites `UpdateRound` to 0 for the oldest row of an address when that
/// row is older than the `MaxBalLookback` horizon, so that every node produces
/// the same verification hash regardless of how it acquired its history. See
/// `catchpointOnlineAccountsIterWrapper.GetItem` in
/// `../go-algorand/ledger/catchpointfilewriter.go`.
fn read_online_accounts(
    conn: &Connection,
    horizon: Option<u64>,
) -> Result<Vec<Vec<u8>>, CatchpointError> {
    let mut stmt = conn.prepare(
        "SELECT address, updround, normalizedonlinebalance, votelastvalid, data \
         FROM onlineaccounts ORDER BY address, updround",
    )?;
    let mut rows = stmt.query([])?;

    let mut out = Vec::new();
    let mut prev_address: Option<[u8; 32]> = None;

    while let Some(row) = rows.next()? {
        let address: Vec<u8> = row.get(0)?;
        let updround: i64 = row.get(1)?;
        let nob: i64 = row.get(2)?;
        let vlv: i64 = row.get(3)?;
        let data: Vec<u8> = row.get(4)?;

        if address.len() != 32 {
            return Err(CatchpointError::ImportError(format!(
                "bad address length {} (expected 32) in onlineaccounts",
                address.len()
            )));
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&address);

        let mut updround = updround as u64;
        if let Some(horizon) = horizon {
            if updround < horizon {
                let first_row_for_address = prev_address != Some(addr);
                if first_row_for_address {
                    updround = 0;
                } else {
                    // go returns an error here: there must be at most one
                    // pre-horizon ("horizon") row per address.
                    return Err(CatchpointError::ImportError(format!(
                        "bad online account data: multiple horizon rows for {}",
                        hex::encode(addr)
                    )));
                }
            }
        }
        prev_address = Some(addr);

        out.push(encode_online_account_record(
            &address, updround, nob as u64, vlv as u64, &data,
        ));
    }

    Ok(out)
}

/// Read `onlineroundparamstail` ordered by `rnd`, canonically encoded.
fn read_online_round_params(conn: &Connection) -> Result<Vec<Vec<u8>>, CatchpointError> {
    let mut stmt = conn.prepare("SELECT rnd, data FROM onlineroundparamstail ORDER BY rnd")?;
    let mut rows = stmt.query([])?;

    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let rnd: i64 = row.get(0)?;
        let data: Vec<u8> = row.get(1)?;
        out.push(encode_online_round_params_record(rnd as u64, &data));
    }
    Ok(out)
}

/// Aggregate verification hash over already-encoded records.
///
/// Per record: `SHA512_256(prefix || record)`; each digest is then fed into a
/// streaming aggregate `SHA512_256`. Matches go's `calculateVerificationHash`
/// (`../go-algorand/ledger/catchupaccessor.go`) and this crate's
/// [`super::verify::calculate_online_accounts_hash`].
fn hash_records(prefix: &[u8], records: &[Vec<u8>]) -> [u8; 32] {
    let mut aggregate = Sha512_256::new();
    for record in records {
        let mut row_hasher = Sha512_256::new();
        row_hasher.update(prefix);
        row_hasher.update(record);
        aggregate.update(row_hasher.finalize());
    }
    let result = aggregate.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ---------------------------------------------------------------------------
// Canonical record encoders
// ---------------------------------------------------------------------------

/// Encode `encoded.BalanceRecordV6`.
///
/// Codec tags (already in sorted order): `a` address, `b` account data
/// (`msgp.Raw`), `c` resources (`map[uint64]msgp.Raw`), `e`
/// `ExpectingMoreEntries`. Go's `omitempty` drops zero/empty fields.
fn encode_balance_record(
    address: &[u8],
    account_data: &[u8],
    resources: &[(u64, Vec<u8>)],
    expecting_more_entries: bool,
) -> Vec<u8> {
    let mut entries: Vec<(&str, Vec<u8>)> = Vec::new();

    if address.iter().any(|&b| b != 0) {
        entries.push(("a", encode_msgpack_bin(address)));
    }
    if !account_data.is_empty() {
        // msgp.Raw: spliced in verbatim, no bin header.
        entries.push(("b", account_data.to_vec()));
    }
    if !resources.is_empty() {
        entries.push(("c", encode_uint_keyed_raw_map(resources)));
    }
    if expecting_more_entries {
        entries.push(("e", vec![0xc3]));
    }

    encode_mixed_map(&entries)
}

/// Encode `map[uint64]msgp.Raw` with ascending integer keys.
fn encode_uint_keyed_raw_map(entries: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_map_header(&mut buf, entries.len());
    for (key, value) in entries {
        buf.extend_from_slice(&encode_msgpack_uint(*key));
        buf.extend_from_slice(value);
    }
    buf
}

/// Encode `encoded.KVRecordV6` (tags `k`, `v`; both plain `[]byte`).
fn encode_kv_record(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut entries: Vec<(&str, Vec<u8>)> = Vec::new();
    if !key.is_empty() {
        entries.push(("k", encode_msgpack_bin(key)));
    }
    if !value.is_empty() {
        entries.push(("v", encode_msgpack_bin(value)));
    }
    encode_mixed_map(&entries)
}

/// Encode `CatchpointSnapshotChunkV6` (tags `bl`, `kv`, `oa`, `orp`).
fn encode_chunk(
    balances: &[&[u8]],
    kvs: &[&[u8]],
    online_accounts: &[&[u8]],
    online_round_params: &[&[u8]],
) -> Vec<u8> {
    let mut entries: Vec<(&str, Vec<u8>)> = Vec::new();
    if !balances.is_empty() {
        entries.push(("bl", encode_raw_array(balances)));
    }
    if !kvs.is_empty() {
        entries.push(("kv", encode_raw_array(kvs)));
    }
    if !online_accounts.is_empty() {
        entries.push(("oa", encode_raw_array(online_accounts)));
    }
    if !online_round_params.is_empty() {
        entries.push(("orp", encode_raw_array(online_round_params)));
    }
    encode_mixed_map(&entries)
}

/// Encode `CatchpointFileHeader`.
///
/// Codec tags sorted: `accountTotals`, `accountsCount`, `balancesRound`,
/// `blockHeaderDigest`, `blocksRound`, `catchpoint`, `chunksCount`,
/// `kvsCount`, `onlineAccountsCount`, `onlineRoundParamsCount`, `version`.
fn encode_catchpoint_file_header(header: &CatchpointFileHeader) -> Vec<u8> {
    let mut entries: Vec<(&str, Vec<u8>)> = Vec::new();

    let totals = encode_account_totals(&header.totals);
    if totals != [0x80] {
        entries.push(("accountTotals", totals));
    }
    if header.total_accounts != 0 {
        entries.push(("accountsCount", encode_msgpack_uint(header.total_accounts)));
    }
    if header.balances_round != 0 {
        entries.push(("balancesRound", encode_msgpack_uint(header.balances_round)));
    }
    if header.block_header_digest.iter().any(|&b| b != 0) {
        entries.push((
            "blockHeaderDigest",
            encode_msgpack_bin(&header.block_header_digest),
        ));
    }
    if header.blocks_round != 0 {
        entries.push(("blocksRound", encode_msgpack_uint(header.blocks_round)));
    }
    if !header.catchpoint.is_empty() {
        entries.push(("catchpoint", encode_msgpack_str(&header.catchpoint)));
    }
    if header.total_chunks != 0 {
        entries.push(("chunksCount", encode_msgpack_uint(header.total_chunks)));
    }
    if header.total_kvs != 0 {
        entries.push(("kvsCount", encode_msgpack_uint(header.total_kvs)));
    }
    if header.total_online_accounts != 0 {
        entries.push((
            "onlineAccountsCount",
            encode_msgpack_uint(header.total_online_accounts),
        ));
    }
    if header.total_online_round_params != 0 {
        entries.push((
            "onlineRoundParamsCount",
            encode_msgpack_uint(header.total_online_round_params),
        ));
    }
    if header.version != 0 {
        entries.push(("version", encode_msgpack_uint(header.version)));
    }

    encode_mixed_map(&entries)
}

fn encode_raw_array(elements: &[&[u8]]) -> Vec<u8> {
    let mut buf = Vec::new();
    let len = elements.len();
    if len <= 15 {
        buf.push(0x90 | len as u8);
    } else if len <= 0xFFFF {
        buf.push(0xDC);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xDD);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
    for element in elements {
        buf.extend_from_slice(element);
    }
    buf
}

fn write_map_header(buf: &mut Vec<u8>, len: usize) {
    if len <= 15 {
        buf.push(0x80 | len as u8);
    } else if len <= 0xFFFF {
        buf.push(0xDE);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xDF);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

fn encode_msgpack_str(s: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len <= 31 {
        buf.push(0xA0 | len as u8);
    } else if len <= 0xFF {
        buf.push(0xD9);
        buf.push(len as u8);
    } else if len <= 0xFFFF {
        buf.push(0xDA);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xDB);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
    buf.extend_from_slice(bytes);
    buf
}
