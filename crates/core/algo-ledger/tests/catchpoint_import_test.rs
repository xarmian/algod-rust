//! Integration tests for catchpoint importer pipeline.
//!
//! Tests the full import flow: CatchpointImporter → staging tables → atomic cutover → live tables.
//! Uses in-memory SQLite databases with synthetic test data (no real catchpoint files needed).

use std::collections::HashMap;

use rusqlite::{params, Connection};
use serde_bytes::ByteBuf;

use algo_ledger::catchpoint::importer::CatchpointImporter;
use algo_ledger::catchpoint::types::{AccountTotals, AlgoCount, RESOURCE_FLAGS_OWNERSHIP};
use algo_ledger::catchpoint::{
    BalanceRecordV6, CatchpointError, CatchpointFileHeader, CatchpointSnapshotChunkV6, KVRecordV6,
    OnlineAccountRecordV6, OnlineRoundParamsRecordV6,
};
use algo_ledger::rewards::REWARD_UNITS;

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Create an in-memory SQLite connection for testing.
fn setup_test_db() -> Connection {
    Connection::open_in_memory().unwrap()
}

/// Build a CatchpointFileHeader with the given round and totals.
fn make_test_header(round: u64, totals: AccountTotals) -> CatchpointFileHeader {
    CatchpointFileHeader {
        version: 131, // V8
        balances_round: round,
        totals,
        total_accounts: 0,
        total_chunks: 0,
        catchpoint: format!("{round}#TEST"),
        ..Default::default()
    }
}

/// Build a simple AccountTotals for testing.
fn make_test_totals() -> AccountTotals {
    AccountTotals {
        online: AlgoCount {
            money: 1_000_000,
            reward_units: 10,
        },
        offline: AlgoCount {
            money: 2_000_000,
            reward_units: 20,
        },
        not_participating: AlgoCount {
            money: 500_000,
            reward_units: 5,
        },
        rewards_level: 42,
    }
}

/// Minimal msgpack-encoded baseAccountData: an empty map ({}).
/// Decodes to all-default fields (status=0/Offline, balance=0, etc.).
fn empty_account_data_blob() -> Vec<u8> {
    vec![0x80]
}

/// Build a BalanceRecordV6 with the given address, account data, and resources.
fn make_balance_record(
    addr_bytes: [u8; 32],
    data_bytes: Vec<u8>,
    resources: HashMap<u64, ByteBuf>,
) -> BalanceRecordV6 {
    BalanceRecordV6 {
        address: ByteBuf::from(addr_bytes.to_vec()),
        account_data: ByteBuf::from(data_bytes),
        resources,
        expecting_more_entries: false,
    }
}

/// Build a KVRecordV6 with the given key and value.
fn make_kv_record(key: &[u8], value: &[u8]) -> KVRecordV6 {
    KVRecordV6 {
        key: ByteBuf::from(key.to_vec()),
        value: ByteBuf::from(value.to_vec()),
    }
}

/// Build an owned asset resource (ownership flag + non-empty asset fields).
fn make_asset_resource(aidx: u64) -> (u64, ByteBuf) {
    let blob = vec![
        0x82, // fixmap(2)
        0xa1,
        b'a', // key "a" (total supply)
        100,  // value 100
        0xa1,
        b'y', // key "y" (resource_flags)
        RESOURCE_FLAGS_OWNERSHIP,
    ];
    (aidx, ByteBuf::from(blob))
}

/// Build an owned app resource (ownership flag + non-empty app fields).
fn make_app_resource(aidx: u64) -> (u64, ByteBuf) {
    let blob = vec![
        0x82, // fixmap(2)
        0xa1,
        b'q', // key "q" (approval_program)
        0xc4,
        0x01,
        0x01, // bin8 with 1 byte [0x01]
        0xa1,
        b'y', // key "y" (resource_flags)
        RESOURCE_FLAGS_OWNERSHIP,
    ];
    (aidx, ByteBuf::from(blob))
}

/// Build a non-owning resource (no ownership flag).
fn make_non_owning_resource(aidx: u64) -> (u64, ByteBuf) {
    let blob = vec![0x80]; // empty map, resource_flags defaults to 0
    (aidx, ByteBuf::from(blob))
}

/// Helper to count rows in a table.
fn count_rows(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

/// Helper to check if a table exists.
fn table_exists(conn: &Connection, table: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name=?1",
        params![table],
        |row| row.get(0),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_full_import_populates_all_tables() {
    let conn = setup_test_db();
    let label = "47000000#FULL_TEST".to_string();

    // Build synthetic test data:
    // - 2 balance records, one with an asset resource, one with an app resource
    // - 1 KV record
    // - 1 online account record
    // - 1 online round params record

    let addr1 = [1u8; 32];
    let addr2 = [2u8; 32];

    let (asset_aidx, asset_blob) = make_asset_resource(42);
    let (app_aidx, app_blob) = make_app_resource(99);

    let mut resources1 = HashMap::new();
    resources1.insert(asset_aidx, asset_blob);

    let mut resources2 = HashMap::new();
    resources2.insert(app_aidx, app_blob);

    let balance1 = make_balance_record(addr1, empty_account_data_blob(), resources1);
    let balance2 = make_balance_record(addr2, empty_account_data_blob(), resources2);

    let kv = make_kv_record(b"box-key-1", b"box-value-1");

    let online_account = OnlineAccountRecordV6 {
        address: ByteBuf::from([3u8; 32].to_vec()),
        updated_round: 100,
        normalized_online_balance: 999,
        vote_last_valid: 200,
        data: ByteBuf::from(vec![0x80]),
    };

    let online_round_params = OnlineRoundParamsRecordV6 {
        round: 500,
        data: ByteBuf::from(vec![0x80]),
    };

    // Build chunks
    let chunk1 = CatchpointSnapshotChunkV6 {
        balances: vec![balance1, balance2],
        kvs: vec![kv],
        online_accounts: vec![],
        online_round_params: vec![],
    };

    let chunk2 = CatchpointSnapshotChunkV6 {
        balances: vec![],
        kvs: vec![],
        online_accounts: vec![online_account],
        online_round_params: vec![online_round_params],
    };

    // Create importer and run the full pipeline
    let mut importer = CatchpointImporter::new(&conn, label, REWARD_UNITS).with_batch_size(10);
    importer.prepare_staging().unwrap();

    let chunks: Vec<Result<(u64, CatchpointSnapshotChunkV6), CatchpointError>> =
        vec![Ok((1, chunk1)), Ok((2, chunk2))];

    let stats = importer.import_chunks(chunks.into_iter(), 2).unwrap();

    // Verify stats
    assert_eq!(stats.accounts, 2);
    assert_eq!(stats.kvs, 1);
    assert_eq!(stats.online_accounts, 1);
    assert_eq!(stats.online_round_params, 1);
    assert_eq!(stats.chunks_processed, 2);

    // Perform atomic cutover
    let totals = make_test_totals();
    let header = make_test_header(47_000_000, totals);
    importer.atomic_cutover(&header).unwrap();

    // Verify accountbase (renamed from catchpointbalances)
    assert_eq!(count_rows(&conn, "accountbase"), 2);

    // Verify both addresses are present
    let addr1_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM accountbase WHERE address = ?1",
            params![addr1.as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(addr1_count, 1);

    let addr2_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM accountbase WHERE address = ?1",
            params![addr2.as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(addr2_count, 1);

    // Verify resources (renamed from catchpointresources)
    assert_eq!(count_rows(&conn, "resources"), 2);

    // Verify assetcreators (renamed from catchpointassetcreators)
    // Should have 2 entries: one for asset (ctype=0), one for app (ctype=1)
    assert_eq!(count_rows(&conn, "assetcreators"), 2);

    let asset_ctype: i64 = conn
        .query_row(
            "SELECT ctype FROM assetcreators WHERE asset = 42",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(asset_ctype, 0); // CTYPE_ASSET

    let app_ctype: i64 = conn
        .query_row(
            "SELECT ctype FROM assetcreators WHERE asset = 99",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(app_ctype, 1); // CTYPE_APP

    // Verify kvstore (renamed from catchpointkvstore)
    assert_eq!(count_rows(&conn, "kvstore"), 1);
    let kv_value: Vec<u8> = conn
        .query_row(
            "SELECT value FROM kvstore WHERE key = ?1",
            params![b"box-key-1".as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(kv_value, b"box-value-1");

    // Verify onlineaccounts (renamed from catchpointonlineaccounts)
    assert_eq!(count_rows(&conn, "onlineaccounts"), 1);
    let (oa_updround, oa_nob, oa_vlv): (i64, i64, i64) = conn
        .query_row(
            "SELECT updround, normalizedonlinebalance, votelastvalid FROM onlineaccounts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(oa_updround, 100);
    assert_eq!(oa_nob, 999);
    assert_eq!(oa_vlv, 200);

    // Verify onlineroundparamstail (renamed from catchpointonlineroundparamstail)
    assert_eq!(count_rows(&conn, "onlineroundparamstail"), 1);
    let orp_rnd: i64 = conn
        .query_row("SELECT rnd FROM onlineroundparamstail", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(orp_rnd, 500);

    // Verify acctrounds
    let acctbase_rnd: i64 = conn
        .query_row(
            "SELECT rnd FROM acctrounds WHERE id = 'acctbase'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(acctbase_rnd, 47_000_000);

    let hashbase_rnd: i64 = conn
        .query_row(
            "SELECT rnd FROM acctrounds WHERE id = 'hashbase'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(hashbase_rnd, 47_000_000);

    // Verify accounttotals
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
            "SELECT online, onlinerewardunits, offline, offlinerewardunits, \
             notparticipating, notparticipatingrewardunits, rewardslevel \
             FROM accounttotals WHERE id = ''",
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
    assert_eq!(nopart, 500_000);
    assert_eq!(nopart_ru, 5);
    assert_eq!(rwdlvl, 42);

    // Staging tables should no longer exist
    assert!(!table_exists(&conn, "catchpointbalances"));
    assert!(!table_exists(&conn, "catchpointresources"));
    assert!(!table_exists(&conn, "catchpointassetcreators"));
    assert!(!table_exists(&conn, "catchpointkvstore"));
    assert!(!table_exists(&conn, "catchpointonlineaccounts"));
    assert!(!table_exists(&conn, "catchpointonlineroundparamstail"));
    assert!(!table_exists(&conn, "catchpoint_import_state"));
}

#[test]
fn test_fresh_restart_after_interruption() {
    // Phase B / TASK-117 changed the resume model: there is no
    // cross-importer/cross-process resume table. If the importer dies
    // mid-import, the next run starts over from chunk 0 — and crucially
    // `prepare_staging` drops any staging tables left over by the
    // interrupted run so the rerun is not contaminated by partial state.
    // This test validates that contract.
    let conn = setup_test_db();
    let label = "47000000#RESTART_TEST".to_string();

    // Phase 1: Import chunks 1-2 (out of 4 total), then "interrupt" by
    // dropping the importer. The intermediate state lives in staging.
    {
        let mut importer =
            CatchpointImporter::new(&conn, label.clone(), REWARD_UNITS).with_batch_size(10);
        importer.prepare_staging().unwrap();

        let chunk1 = CatchpointSnapshotChunkV6 {
            balances: vec![],
            kvs: vec![make_kv_record(b"key1", b"val1")],
            online_accounts: vec![],
            online_round_params: vec![],
        };
        let chunk2 = CatchpointSnapshotChunkV6 {
            balances: vec![],
            kvs: vec![make_kv_record(b"key2", b"val2")],
            online_accounts: vec![],
            online_round_params: vec![],
        };

        let chunks: Vec<Result<(u64, CatchpointSnapshotChunkV6), CatchpointError>> =
            vec![Ok((1, chunk1)), Ok((2, chunk2))];

        let stats = importer.import_chunks(chunks.into_iter(), 4).unwrap();
        assert_eq!(stats.chunks_processed, 2);
        assert_eq!(stats.kvs, 2);

        // Confirm the staging table actually has the 2 partial rows
        // before we drop the importer (so the next assertion that they
        // get cleared by prepare_staging is meaningful).
        let kv_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM catchpointkvstore", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(kv_count, 2);
    }

    // Phase 2: Create a NEW importer (simulating process restart). It
    // must NOT pick up where the previous importer left off — its
    // in-memory checkpoint starts at zero and `prepare_staging` wipes
    // any leftover partial staging.
    {
        let mut importer =
            CatchpointImporter::new(&conn, label.clone(), REWARD_UNITS).with_batch_size(10);
        assert_eq!(importer.checkpoint().last_chunk_ordinal, 0);

        importer.prepare_staging().unwrap();

        // Staging table must be empty after prepare_staging — the 2 rows
        // from the interrupted run have been dropped.
        let kv_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM catchpointkvstore", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(kv_count, 0);

        // Re-import all 4 chunks from the beginning.
        let chunk1 = CatchpointSnapshotChunkV6 {
            balances: vec![],
            kvs: vec![make_kv_record(b"key1", b"val1")],
            online_accounts: vec![],
            online_round_params: vec![],
        };
        let chunk2 = CatchpointSnapshotChunkV6 {
            balances: vec![],
            kvs: vec![make_kv_record(b"key2", b"val2")],
            online_accounts: vec![],
            online_round_params: vec![],
        };
        let chunk3 = CatchpointSnapshotChunkV6 {
            balances: vec![],
            kvs: vec![make_kv_record(b"key3", b"val3")],
            online_accounts: vec![],
            online_round_params: vec![],
        };
        let chunk4 = CatchpointSnapshotChunkV6 {
            balances: vec![],
            kvs: vec![make_kv_record(b"key4", b"val4")],
            online_accounts: vec![],
            online_round_params: vec![],
        };

        let chunks: Vec<Result<(u64, CatchpointSnapshotChunkV6), CatchpointError>> = vec![
            Ok((1, chunk1)),
            Ok((2, chunk2)),
            Ok((3, chunk3)),
            Ok((4, chunk4)),
        ];

        let stats = importer.import_chunks(chunks.into_iter(), 4).unwrap();

        // All 4 chunks reprocessed from scratch.
        assert_eq!(stats.chunks_processed, 4);
        assert_eq!(stats.kvs, 4);

        // Staging table holds all 4 rows post-import.
        let kv_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM catchpointkvstore", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(kv_count, 4);

        // In-memory checkpoint reflects completion.
        assert_eq!(importer.checkpoint().last_chunk_ordinal, 4);
        assert_eq!(importer.checkpoint().total_chunks, 4);

        // Perform cutover.
        let header = make_test_header(47_000_000, make_test_totals());
        importer.atomic_cutover(&header).unwrap();
    }

    // Verify final state: all 4 KV records in the live kvstore table.
    let kv_count = count_rows(&conn, "kvstore");
    assert_eq!(kv_count, 4);

    for i in 1..=4 {
        let value: Vec<u8> = conn
            .query_row(
                "SELECT value FROM kvstore WHERE key = ?1",
                params![format!("key{i}").as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(value, format!("val{i}").into_bytes());
    }

    // No duplicates: exactly 4 rows.
    assert_eq!(count_rows(&conn, "kvstore"), 4);
}

#[test]
fn test_cutover_atomicity_on_failure() {
    let conn = setup_test_db();

    // Create pre-existing live tables with known data.
    conn.execute_batch(
        "CREATE TABLE accountbase (address BLOB PRIMARY KEY, normalizedonlinebalance INTEGER, data BLOB);
         INSERT INTO accountbase VALUES(X'AAAA', 0, X'00');
         CREATE TABLE kvstore (key BLOB PRIMARY KEY, value BLOB);
         INSERT INTO kvstore VALUES(X'0101', X'AABB');",
    )
    .unwrap();

    // Verify pre-existing data.
    let old_count = count_rows(&conn, "accountbase");
    assert_eq!(old_count, 1);
    let old_kv_count = count_rows(&conn, "kvstore");
    assert_eq!(old_kv_count, 1);

    // Import staging data with different content.
    let mut importer = CatchpointImporter::new(&conn, "test#cutover".to_string(), REWARD_UNITS)
        .with_batch_size(10);
    importer.prepare_staging().unwrap();

    // Insert different data into staging tables.
    let addr = [0xBBu8; 32];
    let chunk = CatchpointSnapshotChunkV6 {
        balances: vec![make_balance_record(
            addr,
            empty_account_data_blob(),
            HashMap::new(),
        )],
        kvs: vec![
            make_kv_record(b"new-key-1", b"new-val-1"),
            make_kv_record(b"new-key-2", b"new-val-2"),
        ],
        online_accounts: vec![],
        online_round_params: vec![],
    };

    let chunks: Vec<Result<(u64, CatchpointSnapshotChunkV6), CatchpointError>> =
        vec![Ok((1, chunk))];
    importer.import_chunks(chunks.into_iter(), 1).unwrap();

    // Perform cutover — should succeed and replace old data.
    let header = make_test_header(100, make_test_totals());
    importer.atomic_cutover(&header).unwrap();

    // Old data should be gone.
    let old_addr_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM accountbase WHERE address = X'AAAA'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(old_addr_count, 0, "old accountbase data should be replaced");

    let old_kv: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM kvstore WHERE key = X'0101'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(old_kv, 0, "old kvstore data should be replaced");

    // New data should be present.
    let new_acct_count = count_rows(&conn, "accountbase");
    assert_eq!(new_acct_count, 1, "new account should be in accountbase");

    let new_addr: Vec<u8> = conn
        .query_row("SELECT address FROM accountbase LIMIT 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(new_addr, addr.to_vec());

    let new_kv_count = count_rows(&conn, "kvstore");
    assert_eq!(new_kv_count, 2, "new KV records should be in kvstore");

    // Verify acctrounds was set.
    let rnd: i64 = conn
        .query_row(
            "SELECT rnd FROM acctrounds WHERE id = 'acctbase'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rnd, 100);
}

#[test]
fn test_creator_table_population() {
    let conn = setup_test_db();
    let label = "test#creators".to_string();

    let addr1 = [0x10u8; 32]; // Account with asset creator
    let addr2 = [0x20u8; 32]; // Account with app creator
    let addr3 = [0x30u8; 32]; // Account with non-creator resource (opted-in only)
    let addr4 = [0x40u8; 32]; // Account with both asset and app creator resources

    let (asset_aidx, asset_blob) = make_asset_resource(100);
    let (app_aidx, app_blob) = make_app_resource(200);
    let (nonown_aidx, nonown_blob) = make_non_owning_resource(300);
    let (asset_aidx2, asset_blob2) = make_asset_resource(400);
    let (app_aidx2, app_blob2) = make_app_resource(500);

    let mut resources1 = HashMap::new();
    resources1.insert(asset_aidx, asset_blob);

    let mut resources2 = HashMap::new();
    resources2.insert(app_aidx, app_blob);

    let mut resources3 = HashMap::new();
    resources3.insert(nonown_aidx, nonown_blob);

    let mut resources4 = HashMap::new();
    resources4.insert(asset_aidx2, asset_blob2);
    resources4.insert(app_aidx2, app_blob2);

    let balance1 = make_balance_record(addr1, empty_account_data_blob(), resources1);
    let balance2 = make_balance_record(addr2, empty_account_data_blob(), resources2);
    let balance3 = make_balance_record(addr3, empty_account_data_blob(), resources3);
    let balance4 = make_balance_record(addr4, empty_account_data_blob(), resources4);

    let chunk = CatchpointSnapshotChunkV6 {
        balances: vec![balance1, balance2, balance3, balance4],
        kvs: vec![],
        online_accounts: vec![],
        online_round_params: vec![],
    };

    let mut importer = CatchpointImporter::new(&conn, label, REWARD_UNITS).with_batch_size(10);
    importer.prepare_staging().unwrap();

    let chunks: Vec<Result<(u64, CatchpointSnapshotChunkV6), CatchpointError>> =
        vec![Ok((1, chunk))];
    importer.import_chunks(chunks.into_iter(), 1).unwrap();

    // Perform cutover to get live tables.
    let header = make_test_header(100, make_test_totals());
    importer.atomic_cutover(&header).unwrap();

    // Verify assetcreators table:
    // - asset 100 (ctype=0, asset creator from addr1)
    // - asset 200 (ctype=1, app creator from addr2)
    // - asset 300 should NOT be here (non-owning)
    // - asset 400 (ctype=0, asset creator from addr4)
    // - asset 500 (ctype=1, app creator from addr4)
    let total_creators = count_rows(&conn, "assetcreators");
    assert_eq!(
        total_creators, 4,
        "should have 4 creator entries (2 asset + 2 app)"
    );

    // Verify asset creator (ctype = 0)
    let (creator_100, ctype_100): (Vec<u8>, i64) = conn
        .query_row(
            "SELECT creator, ctype FROM assetcreators WHERE asset = 100",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(creator_100, addr1.to_vec());
    assert_eq!(ctype_100, 0, "asset creator should have ctype=0");

    // Verify app creator (ctype = 1)
    let (creator_200, ctype_200): (Vec<u8>, i64) = conn
        .query_row(
            "SELECT creator, ctype FROM assetcreators WHERE asset = 200",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(creator_200, addr2.to_vec());
    assert_eq!(ctype_200, 1, "app creator should have ctype=1");

    // Verify non-creator resource (asset 300) is NOT in assetcreators.
    let non_creator_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM assetcreators WHERE asset = 300",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        non_creator_count, 0,
        "non-owning resource should not be in assetcreators"
    );

    // Verify addr4's asset creator
    let (creator_400, ctype_400): (Vec<u8>, i64) = conn
        .query_row(
            "SELECT creator, ctype FROM assetcreators WHERE asset = 400",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(creator_400, addr4.to_vec());
    assert_eq!(ctype_400, 0);

    // Verify addr4's app creator
    let (creator_500, ctype_500): (Vec<u8>, i64) = conn
        .query_row(
            "SELECT creator, ctype FROM assetcreators WHERE asset = 500",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(creator_500, addr4.to_vec());
    assert_eq!(ctype_500, 1);
}

#[test]
fn test_import_stats_tracking() {
    let conn = setup_test_db();
    let label = "test#stats".to_string();

    // Build 3 chunks with known record counts:
    // Chunk 1: 2 accounts, 1 KV
    // Chunk 2: 1 account, 0 KVs, 2 online accounts
    // Chunk 3: 0 accounts, 1 KV, 0 online accounts, 3 online round params

    let chunk1 = CatchpointSnapshotChunkV6 {
        balances: vec![
            make_balance_record([0x01; 32], empty_account_data_blob(), HashMap::new()),
            make_balance_record([0x02; 32], empty_account_data_blob(), HashMap::new()),
        ],
        kvs: vec![make_kv_record(b"k1", b"v1")],
        online_accounts: vec![],
        online_round_params: vec![],
    };

    let chunk2 = CatchpointSnapshotChunkV6 {
        balances: vec![make_balance_record(
            [0x03; 32],
            empty_account_data_blob(),
            HashMap::new(),
        )],
        kvs: vec![],
        online_accounts: vec![
            OnlineAccountRecordV6 {
                address: ByteBuf::from([0x11; 32].to_vec()),
                updated_round: 10,
                normalized_online_balance: 100,
                vote_last_valid: 1000,
                data: ByteBuf::from(vec![0x80]),
            },
            OnlineAccountRecordV6 {
                address: ByteBuf::from([0x12; 32].to_vec()),
                updated_round: 20,
                normalized_online_balance: 200,
                vote_last_valid: 2000,
                data: ByteBuf::from(vec![0x80]),
            },
        ],
        online_round_params: vec![],
    };

    let chunk3 = CatchpointSnapshotChunkV6 {
        balances: vec![],
        kvs: vec![make_kv_record(b"k2", b"v2")],
        online_accounts: vec![],
        online_round_params: vec![
            OnlineRoundParamsRecordV6 {
                round: 100,
                data: ByteBuf::from(vec![0x80]),
            },
            OnlineRoundParamsRecordV6 {
                round: 200,
                data: ByteBuf::from(vec![0x80]),
            },
            OnlineRoundParamsRecordV6 {
                round: 300,
                data: ByteBuf::from(vec![0x80]),
            },
        ],
    };

    let mut importer = CatchpointImporter::new(&conn, label, REWARD_UNITS).with_batch_size(10);
    importer.prepare_staging().unwrap();

    let chunks: Vec<Result<(u64, CatchpointSnapshotChunkV6), CatchpointError>> =
        vec![Ok((1, chunk1)), Ok((2, chunk2)), Ok((3, chunk3))];

    let stats = importer.import_chunks(chunks.into_iter(), 3).unwrap();

    // Verify counts.
    assert_eq!(stats.accounts, 3, "should have 3 total accounts (2+1+0)");
    assert_eq!(stats.kvs, 2, "should have 2 total KVs (1+0+1)");
    assert_eq!(
        stats.online_accounts, 2,
        "should have 2 total online accounts (0+2+0)"
    );
    assert_eq!(
        stats.online_round_params, 3,
        "should have 3 total online round params (0+0+3)"
    );
    assert_eq!(
        stats.chunks_processed, 3,
        "should have processed all 3 chunks"
    );

    // Also verify the actual table row counts match the stats.
    let acct_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM catchpointbalances", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(acct_count, stats.accounts as i64);

    let kv_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM catchpointkvstore", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(kv_count, stats.kvs as i64);

    let oa_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM catchpointonlineaccounts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(oa_count, stats.online_accounts as i64);

    let orp_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM catchpointonlineroundparamstail",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(orp_count, stats.online_round_params as i64);
}
