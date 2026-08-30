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

//! Round-trip tests for the catchpoint file writer (export).
//!
//! Builds a small go-algorand-shaped tracker database in memory, exports a
//! catchpoint file with [`export_catchpoint_file`], re-imports it with the
//! existing [`import_catchpoint_file`] pipeline, and asserts the resulting
//! state (and the catchpoint label) match.
//!
//! Format reference: `../go-algorand/ledger/catchpointfilewriter.go` and
//! `../go-algorand/ledger/catchpointtracker.go`.

use rusqlite::{params, Connection};

use algo_ledger::catchpoint::types::RESOURCE_FLAGS_OWNERSHIP;
use algo_ledger::catchpoint::verify::{
    calculate_online_accounts_hash, calculate_online_round_params_hash,
    calculate_sp_verification_hash, rebuild_trie_from_db,
};
use algo_ledger::catchpoint::{
    export_catchpoint_file, import_catchpoint_file, verify_catchpoint, CatchpointEntry,
    ExportOptions, CATCHPOINT_FILE_VERSION_V8,
};
use algo_ledger::rewards::REWARD_UNITS;

const CTYPE_ASSET: i64 = 0;
const CTYPE_APP: i64 = 1;

const BALANCES_ROUND: u64 = 1000;
const BLOCK_DIGEST: [u8; 32] = [7u8; 32];

// ---------------------------------------------------------------------------
// Source-database fixtures
// ---------------------------------------------------------------------------

/// DDL for the live tracker tables the exporter reads. Column shapes mirror
/// `crates/core/algo-ledger/src/sqlite.rs` (which in turn mirrors
/// `../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go`).
const SOURCE_SCHEMA: &str = "
CREATE TABLE accountbase (
    addrid INTEGER PRIMARY KEY NOT NULL,
    address BLOB NOT NULL,
    data BLOB,
    normalizedonlinebalance INTEGER
);
CREATE UNIQUE INDEX accountbase_address_idx ON accountbase (address);
CREATE TABLE resources (
    addrid INTEGER NOT NULL,
    aidx INTEGER NOT NULL,
    data BLOB NOT NULL,
    ctype INTEGER NOT NULL DEFAULT -1,
    PRIMARY KEY (addrid, aidx)
) WITHOUT ROWID;
CREATE TABLE kvstore (key BLOB PRIMARY KEY, value BLOB);
CREATE TABLE onlineaccounts (
    address BLOB NOT NULL,
    updround INTEGER NOT NULL,
    normalizedonlinebalance INTEGER NOT NULL,
    votelastvalid INTEGER NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (address, updround)
);
CREATE TABLE onlineroundparamstail (rnd INTEGER PRIMARY KEY NOT NULL, data BLOB NOT NULL);
CREATE TABLE stateproofverification (
    lastattestedround INTEGER PRIMARY KEY NOT NULL,
    verificationcontext BLOB NOT NULL
);
CREATE TABLE accounttotals (
    id TEXT PRIMARY KEY,
    online INTEGER,
    onlinerewardunits INTEGER,
    offline INTEGER,
    offlinerewardunits INTEGER,
    notparticipating INTEGER,
    notparticipatingrewardunits INTEGER,
    rewardslevel INTEGER
);
";

fn addr(n: u8) -> [u8; 32] {
    [n; 32]
}

/// Shortest-form msgpack unsigned integer, as go-codec and
/// `algo_codec::canonical_*` emit.
fn uint(v: u64) -> Vec<u8> {
    if v <= 0x7f {
        vec![v as u8]
    } else if v <= 0xFF {
        vec![0xcc, v as u8]
    } else if v <= 0xFFFF {
        let mut b = vec![0xcd];
        b.extend_from_slice(&(v as u16).to_be_bytes());
        b
    } else if v <= 0xFFFF_FFFF {
        let mut b = vec![0xce];
        b.extend_from_slice(&(v as u32).to_be_bytes());
        b
    } else {
        let mut b = vec![0xcf];
        b.extend_from_slice(&v.to_be_bytes());
        b
    }
}

/// Minimal `baseAccountData`: `{"b": micro_algos}` (codec tag `b` = MicroAlgos).
fn account_blob(micro_algos: u64) -> Vec<u8> {
    let mut blob = vec![0x81, 0xa1, b'b'];
    blob.extend_from_slice(&uint(micro_algos));
    blob
}

/// Owned asset `resourcesData`: `{"a": total, "y": OWNERSHIP}`.
fn asset_blob(total: u8) -> Vec<u8> {
    vec![
        0x82,
        0xa1,
        b'a',
        total,
        0xa1,
        b'y',
        RESOURCE_FLAGS_OWNERSHIP,
    ]
}

/// Owned app `resourcesData`: `{"q": program, "y": OWNERSHIP}`.
fn app_blob() -> Vec<u8> {
    vec![
        0x82,
        0xa1,
        b'q',
        0xc4,
        0x02,
        0x06,
        0x81,
        0xa1,
        b'y',
        RESOURCE_FLAGS_OWNERSHIP,
    ]
}

/// Minimal `BaseOnlineAccountData`: `{"Y": micro_algos}`.
fn online_blob(micro_algos: u8) -> Vec<u8> {
    vec![0x81, 0xa1, b'Y', micro_algos]
}

/// Minimal `OnlineRoundParamsData`: `{"online": supply}`.
fn online_round_params_blob(supply: u8) -> Vec<u8> {
    vec![0x81, 0xa6, b'o', b'n', b'l', b'i', b'n', b'e', supply]
}

/// `StateProofVerificationContext` blob: `{"pw": weight, "spround": round}`.
fn sp_context_blob(round: u8, weight: u8) -> Vec<u8> {
    vec![
        0x82, 0xa2, b'p', b'w', weight, 0xa7, b's', b'p', b'r', b'o', b'u', b'n', b'd', round,
    ]
}

/// Build the source tracker database with a handful of accounts, resources,
/// boxes, online accounts, round params and SP contexts.
fn build_source_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(SOURCE_SCHEMA).unwrap();

    // 5 accounts; #2 owns two assets, #4 owns an app.
    for i in 1u8..=5 {
        conn.execute(
            "INSERT INTO accountbase(addrid, address, data, normalizedonlinebalance) \
             VALUES(?1, ?2, ?3, 0)",
            params![i as i64, addr(i).to_vec(), account_blob(1_000 * i as u64)],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO resources(addrid, aidx, data, ctype) VALUES(2, 101, ?1, ?2)",
        params![asset_blob(50), CTYPE_ASSET],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO resources(addrid, aidx, data, ctype) VALUES(2, 102, ?1, ?2)",
        params![asset_blob(60), CTYPE_ASSET],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO resources(addrid, aidx, data, ctype) VALUES(4, 200, ?1, ?2)",
        params![app_blob(), CTYPE_APP],
    )
    .unwrap();

    for i in 1..=4u8 {
        conn.execute(
            "INSERT INTO kvstore(key, value) VALUES(?1, ?2)",
            params![
                format!("bx:box{i}").into_bytes(),
                format!("value{i}").into_bytes()
            ],
        )
        .unwrap();
    }

    // Online accounts, all inside the 320-round history horizon
    // (horizon = BALANCES_ROUND + 1 - 320 = 681).
    for (a, updround, vlv) in [(1u8, 900u64, 2000u64), (1, 950, 2000), (3, 990, 3000)] {
        conn.execute(
            "INSERT INTO onlineaccounts(address, updround, normalizedonlinebalance, votelastvalid, data) \
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![addr(a).to_vec(), updround as i64, 12345i64, vlv as i64, online_blob(a)],
        )
        .unwrap();
    }

    for rnd in [998u64, 999, 1000] {
        conn.execute(
            "INSERT INTO onlineroundparamstail(rnd, data) VALUES(?1, ?2)",
            params![rnd as i64, online_round_params_blob(rnd as u8 % 100)],
        )
        .unwrap();
    }

    for (round, weight) in [(10u8, 5u8), (20, 9)] {
        conn.execute(
            "INSERT INTO stateproofverification(lastattestedround, verificationcontext) \
             VALUES(?1, ?2)",
            params![round as i64, sp_context_blob(round, weight)],
        )
        .unwrap();
    }

    conn.execute(
        "INSERT INTO accounttotals VALUES('', 1000000, 10, 2000000, 20, 500000, 5, 42)",
        [],
    )
    .unwrap();

    conn
}

fn export_options() -> ExportOptions {
    ExportOptions {
        balances_round: BALANCES_ROUND,
        // verify_catchpoint requires acctrounds('acctbase') == label round,
        // and the importer sets acctrounds from BalancesRound, so the two
        // rounds must agree for a self-consistent round trip.
        blocks_round: BALANCES_ROUND,
        block_header_digest: BLOCK_DIGEST,
        ..Default::default()
    }
}

/// Run a single-text-column query and collect the rows, so two databases can
/// be compared without depending on rowid assignment.
fn rows_text(conn: &Connection, sql: &str) -> Vec<String> {
    let mut stmt = conn.prepare(sql).unwrap();
    let rows = stmt.query_map([], |row| row.get::<_, String>(0)).unwrap();
    rows.map(|r| r.unwrap()).collect()
}

const ACCOUNTS_SQL: &str =
    "SELECT hex(address) || ':' || hex(data) FROM accountbase ORDER BY rowid";
const RESOURCES_SQL: &str = "SELECT hex(a.address) || ':' || r.aidx || ':' || hex(r.data) \
     || ':' || r.ctype FROM resources r JOIN accountbase a ON a.rowid = r.addrid \
     ORDER BY a.address, r.aidx";
const KVSTORE_SQL: &str = "SELECT hex(key) || ':' || hex(value) FROM kvstore ORDER BY key";
const ONLINE_ACCOUNTS_SQL: &str = "SELECT hex(address) || ':' || updround || ':' \
     || normalizedonlinebalance || ':' || votelastvalid || ':' || hex(data) \
     FROM onlineaccounts ORDER BY address, updround";
const ONLINE_ROUND_PARAMS_SQL: &str =
    "SELECT rnd || ':' || hex(data) FROM onlineroundparamstail ORDER BY rnd";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn export_then_import_round_trips_state_and_label() {
    let src = build_source_db();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catchpoint.tar.gz");

    let result = export_catchpoint_file(&src, &path, &export_options()).unwrap();

    assert_eq!(result.total_accounts, 5);
    assert_eq!(result.total_kvs, 4);
    assert_eq!(result.total_online_accounts, 3);
    assert_eq!(result.total_online_round_params, 3);
    assert!(result.total_chunks >= 3, "{:?}", result);
    assert!(result.file_size > 0);
    assert!(result.label.starts_with(&format!("{BALANCES_ROUND}#")));

    // Re-import into a fresh database.
    let dst = Connection::open_in_memory().unwrap();
    let import = import_catchpoint_file(&dst, &path, REWARD_UNITS).unwrap();
    assert_eq!(import.round, BALANCES_ROUND);
    assert_eq!(import.stats.accounts, 5);
    assert_eq!(import.stats.kvs, 4);
    assert_eq!(import.stats.online_accounts, 3);
    assert_eq!(import.stats.online_round_params, 3);

    // Accounts (address + raw blob) must survive verbatim and in order.
    assert_eq!(rows_text(&src, ACCOUNTS_SQL), rows_text(&dst, ACCOUNTS_SQL));
    // Resources: compared by (address, aidx) since rowids are reassigned.
    assert_eq!(
        rows_text(&src, RESOURCES_SQL),
        rows_text(&dst, RESOURCES_SQL)
    );
    assert_eq!(rows_text(&src, KVSTORE_SQL), rows_text(&dst, KVSTORE_SQL));
    assert_eq!(
        rows_text(&src, ONLINE_ACCOUNTS_SQL),
        rows_text(&dst, ONLINE_ACCOUNTS_SQL)
    );
    assert_eq!(
        rows_text(&src, ONLINE_ROUND_PARAMS_SQL),
        rows_text(&dst, ONLINE_ROUND_PARAMS_SQL)
    );

    // Every label component must recompute identically on the imported DB.
    assert_eq!(
        rebuild_trie_from_db(&src).unwrap(),
        rebuild_trie_from_db(&dst).unwrap(),
        "balances merkle root changed across the round trip"
    );
    assert_eq!(
        calculate_sp_verification_hash(&src).unwrap(),
        calculate_sp_verification_hash(&dst).unwrap()
    );
    assert_eq!(
        calculate_online_accounts_hash(&src).unwrap(),
        calculate_online_accounts_hash(&dst).unwrap()
    );
    assert_eq!(
        calculate_online_round_params_hash(&src).unwrap(),
        calculate_online_round_params_hash(&dst).unwrap()
    );

    // And the importer-side verifier must accept the label we produced.
    let verified = verify_catchpoint(&dst, &BLOCK_DIGEST).unwrap();
    assert!(
        verified.success,
        "expected {} computed {}",
        verified.expected_label, verified.computed_label
    );
    assert_eq!(verified.computed_label, result.label);
    assert_eq!(verified.accounts_count, 5);
}

#[test]
fn exported_archive_has_go_layout() {
    let src = build_source_db();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catchpoint.tar.gz");
    let result = export_catchpoint_file(&src, &path, &export_options()).unwrap();

    let reader = algo_ledger::catchpoint::parser::open(&path).unwrap();
    let entries = reader.collect_entries().unwrap();

    // content.msgpack first, then the SP context, then the balances chunks.
    match &entries[0] {
        CatchpointEntry::Header(h) => {
            assert_eq!(h.version, CATCHPOINT_FILE_VERSION_V8);
            assert_eq!(h.balances_round, BALANCES_ROUND);
            assert_eq!(h.blocks_round, BALANCES_ROUND);
            assert_eq!(h.total_accounts, 5);
            assert_eq!(h.total_kvs, 4);
            assert_eq!(h.total_online_accounts, 3);
            assert_eq!(h.total_online_round_params, 3);
            assert_eq!(h.total_chunks, result.total_chunks);
            assert_eq!(h.catchpoint, result.label);
            assert_eq!(h.block_header_digest.as_ref(), &BLOCK_DIGEST[..]);
            assert_eq!(h.totals.rewards_level, 42);
            assert_eq!(h.totals.online.money, 1_000_000);
        }
        other => panic!("first entry is not the header: {other:?}"),
    }
    assert!(matches!(
        entries[1],
        CatchpointEntry::StateProofVerification(_)
    ));
    assert_eq!(entries.len() as u64, 2 + result.total_chunks);

    // gzip magic — go publishes the final catchpoint file gzip-compressed.
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(&bytes[0..2], &[0x1f, 0x8b]);
}

#[test]
fn export_splits_accounts_across_chunks() {
    let src = build_source_db();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chunked.tar");

    let opts = ExportOptions {
        accounts_per_chunk: 2,
        gzip: false,
        ..export_options()
    };
    let result = export_catchpoint_file(&src, &path, &opts).unwrap();

    // 5 accounts -> 3 account chunks, 4 kvs -> 2 chunks,
    // 3 online accounts -> 2 chunks, 3 round params -> 2 chunks.
    assert_eq!(result.total_chunks, 9);

    // Uncompressed tar is still readable and still round-trips.
    let bytes = std::fs::read(&path).unwrap();
    assert_ne!(&bytes[0..2], &[0x1f, 0x8b]);

    let dst = Connection::open_in_memory().unwrap();
    import_catchpoint_file(&dst, &path, REWARD_UNITS).unwrap();
    assert!(verify_catchpoint(&dst, &BLOCK_DIGEST).unwrap().success);
}

#[test]
fn export_splits_oversized_account_resources() {
    let src = build_source_db();
    // Give account #5 more resources than fit in one chunk.
    for aidx in 300..306u64 {
        src.execute(
            "INSERT INTO resources(addrid, aidx, data, ctype) VALUES(5, ?1, ?2, ?3)",
            params![aidx as i64, asset_blob(1), CTYPE_ASSET],
        )
        .unwrap();
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("oversized.tar.gz");
    let opts = ExportOptions {
        max_resources_per_chunk: 2,
        ..export_options()
    };
    export_catchpoint_file(&src, &path, &opts).unwrap();

    let dst = Connection::open_in_memory().unwrap();
    import_catchpoint_file(&dst, &path, REWARD_UNITS).unwrap();

    // All six resources land on the single account row for address #5.
    let count: i64 = dst
        .query_row(
            "SELECT COUNT(*) FROM resources r JOIN accountbase a ON a.rowid = r.addrid \
             WHERE a.address = ?1",
            params![addr(5).to_vec()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 6);
    assert_eq!(
        rebuild_trie_from_db(&src).unwrap(),
        rebuild_trie_from_db(&dst).unwrap()
    );
}

#[test]
fn export_zeroes_pre_horizon_online_update_round() {
    let src = build_source_db();
    // A row older than the horizon (1000 + 1 - 320 = 681) for a new address.
    src.execute(
        "INSERT INTO onlineaccounts(address, updround, normalizedonlinebalance, votelastvalid, data) \
         VALUES(?1, 100, 7, 5000, ?2)",
        params![addr(9).to_vec(), online_blob(9)],
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("horizon.tar.gz");
    export_catchpoint_file(&src, &path, &export_options()).unwrap();

    let dst = Connection::open_in_memory().unwrap();
    import_catchpoint_file(&dst, &path, REWARD_UNITS).unwrap();

    let updround: i64 = dst
        .query_row(
            "SELECT updround FROM onlineaccounts WHERE address = ?1",
            params![addr(9).to_vec()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        updround, 0,
        "pre-horizon updateRound must be normalized to 0 (go: \
         catchpointOnlineAccountsIterWrapper.GetItem)"
    );

    // The label still verifies: the exporter hashes the normalized stream.
    assert!(verify_catchpoint(&dst, &BLOCK_DIGEST).unwrap().success);
}

#[test]
fn export_without_online_data_omits_online_chunks() {
    let src = build_source_db();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("no-online.tar.gz");

    let opts = ExportOptions {
        include_online_data: false,
        ..export_options()
    };
    let result = export_catchpoint_file(&src, &path, &opts).unwrap();
    assert_eq!(result.total_online_accounts, 0);
    assert_eq!(result.total_online_round_params, 0);

    let dst = Connection::open_in_memory().unwrap();
    import_catchpoint_file(&dst, &path, REWARD_UNITS).unwrap();
    let count: i64 = dst
        .query_row("SELECT COUNT(*) FROM onlineaccounts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

// ---------------------------------------------------------------------------
// Catchpoint file-format version selection (issue #752)
// ---------------------------------------------------------------------------
//
// Mirrors go-algorand's `catchpointTracker.createCatchpoint`
// (`ledger/catchpointtracker.go:810-827`): the file-format version is
// selected from `EnableCatchpointsWithSPContexts` (v38+) and
// `EnableCatchpointsWithOnlineAccounts` (v40+), not hardcoded.

#[test]
fn select_catchpoint_file_version_matches_go() {
    use algo_ledger::catchpoint::select_catchpoint_file_version;
    use algo_ledger::catchpoint::{
        CATCHPOINT_FILE_VERSION_V6, CATCHPOINT_FILE_VERSION_V7, CATCHPOINT_FILE_VERSION_V8,
    };

    // Neither flag (pre-v38): V6.
    assert_eq!(
        select_catchpoint_file_version(false, false).unwrap(),
        CATCHPOINT_FILE_VERSION_V6
    );
    // SP contexts only (v38-v39): V7.
    assert_eq!(
        select_catchpoint_file_version(true, false).unwrap(),
        CATCHPOINT_FILE_VERSION_V7
    );
    // Both (v40+, current): V8.
    assert_eq!(
        select_catchpoint_file_version(true, true).unwrap(),
        CATCHPOINT_FILE_VERSION_V8
    );
    // Online accounts without SP contexts is invalid (go:
    // `createCatchpoint`'s own error for this combination) -- structurally
    // unreachable via the real per-version consensus table (online accounts
    // only ever activates at v40, after SP contexts at v38), but the
    // override/consensus.json path (issue #762) could still construct it.
    let err = select_catchpoint_file_version(false, true).unwrap_err();
    assert!(err.to_string().contains("SP contexts not enabled"));
}

#[test]
fn export_rejects_v6_selection_as_unimplemented() {
    // `enable_sp_contexts: false` selects V6, whose content shape (no
    // SP-verification entry at all) this writer doesn't implement --
    // exporting must fail loudly rather than silently mislabel a V8-shaped
    // file as V6.
    let src = build_source_db();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v6-unsupported.tar.gz");

    let opts = ExportOptions {
        enable_sp_contexts: false,
        include_online_data: false,
        ..export_options()
    };
    let err = export_catchpoint_file(&src, &path, &opts).unwrap_err();
    assert!(
        matches!(err, algo_ledger::catchpoint::CatchpointError::UnsupportedVersion(v) if v == algo_ledger::catchpoint::CATCHPOINT_FILE_VERSION_V6),
        "expected an UnsupportedVersion(V6) error, got: {err}"
    );
}

#[test]
fn export_with_sp_contexts_and_no_online_data_selects_v7() {
    // The combination this writer already fully supports content-wise:
    // SP-verification blob present, online-accounts tables omitted.
    let src = build_source_db();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v7.tar.gz");

    let opts = ExportOptions {
        enable_sp_contexts: true,
        include_online_data: false,
        ..export_options()
    };
    export_catchpoint_file(&src, &path, &opts).unwrap();

    use std::io::Read as _;
    let bytes = std::fs::read(&path).unwrap();
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&bytes[..]));
    let mut found_version = None;
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry.path().unwrap().to_string_lossy() == "content.msgpack" {
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            let header: algo_ledger::catchpoint::CatchpointFileHeader =
                rmp_serde::from_slice(&data).unwrap();
            found_version = Some(header.version);
        }
    }
    assert_eq!(
        found_version,
        Some(algo_ledger::catchpoint::CATCHPOINT_FILE_VERSION_V7)
    );

    // And it must still be importable (this writer's V7 content is real,
    // not just a relabeled V8 file).
    let dst = Connection::open_in_memory().unwrap();
    import_catchpoint_file(&dst, &path, REWARD_UNITS).unwrap();
}

#[test]
fn export_of_empty_ledger_produces_importable_file() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(SOURCE_SCHEMA).unwrap();
    conn.execute(
        "INSERT INTO accounttotals VALUES('', 0, 0, 0, 0, 0, 0, 0)",
        [],
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.tar.gz");
    let result = export_catchpoint_file(&conn, &path, &export_options()).unwrap();
    assert_eq!(result.total_accounts, 0);
    assert_eq!(result.total_chunks, 0);

    let dst = Connection::open_in_memory().unwrap();
    let import = import_catchpoint_file(&dst, &path, REWARD_UNITS).unwrap();
    assert_eq!(import.stats.accounts, 0);
    assert!(verify_catchpoint(&dst, &BLOCK_DIGEST).unwrap().success);
}
