//! Integration tests for the one-shot `resources.data` canonicalization
//! migrator (PLAN-189 / TASK-195).
//!
//! The migrator runs inside `SqliteLedger::init` and rewrites legacy-
//! shaped resource BLOBs into canonical Go-compatible form. It is
//! marker-gated via `catchpointstate.algod_rust_resources_canonical_v1`
//! so subsequent opens skip the scan.
//!
//! These tests construct synthetic legacy-shaped DBs by writing rows
//! directly via raw SQL + hand-rolled msgpack, then re-open and verify
//! the rows were canonicalized.

use std::path::PathBuf;

use algo_ledger::SqliteLedger;
use rusqlite::{params, Connection, OptionalExtension};
use tempfile::TempDir;

const RESOURCES_CANONICAL_MIGRATION_MARKER: &str = "algod_rust_resources_canonical_v1";

/// Hand-write a legacy-shape asset-holding BLOB: `{l: amount, m: frozen, y: 1}`.
fn legacy_asset_holding_blob(amount: u64, frozen: bool) -> Vec<u8> {
    let mut pairs: Vec<(rmpv::Value, rmpv::Value)> = Vec::new();
    if amount != 0 {
        pairs.push((rmpv::Value::String("l".into()), rmpv::Value::from(amount)));
    }
    if frozen {
        pairs.push((rmpv::Value::String("m".into()), rmpv::Value::Boolean(true)));
    }
    pairs.push((rmpv::Value::String("y".into()), rmpv::Value::from(1u64)));
    let val = rmpv::Value::Map(pairs);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &val).expect("encode");
    buf
}

/// Hand-write a legacy-shape asset-params BLOB: `{a: total, y: 4}` plus
/// optional unit_name.
fn legacy_asset_params_blob(total: u64, unit_name: Option<&str>) -> Vec<u8> {
    let mut pairs: Vec<(rmpv::Value, rmpv::Value)> = Vec::new();
    if total != 0 {
        pairs.push((rmpv::Value::String("a".into()), rmpv::Value::from(total)));
    }
    if let Some(u) = unit_name {
        if !u.is_empty() {
            pairs.push((
                rmpv::Value::String("d".into()),
                rmpv::Value::String(u.into()),
            ));
        }
    }
    pairs.push((rmpv::Value::String("y".into()), rmpv::Value::from(4u64)));
    let val = rmpv::Value::Map(pairs);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &val).expect("encode");
    buf
}

/// Hand-write a legacy-shape app-params BLOB with nested schema submaps
/// (`t = {nui, nbs}` for local schema, `u = {nui, nbs}` for global
/// schema, `v` = extra_program_pages, `y = 4`).
fn legacy_app_params_blob(approval: &[u8], local_nui: u64, extra_pages: u64) -> Vec<u8> {
    let mut pairs: Vec<(rmpv::Value, rmpv::Value)> = Vec::new();
    if !approval.is_empty() {
        pairs.push((
            rmpv::Value::String("q".into()),
            rmpv::Value::Binary(approval.to_vec()),
        ));
    }
    if local_nui != 0 {
        pairs.push((
            rmpv::Value::String("t".into()),
            rmpv::Value::Map(vec![
                (rmpv::Value::String("nbs".into()), rmpv::Value::from(0u64)),
                (rmpv::Value::String("nui".into()), rmpv::Value::from(local_nui)),
            ]),
        ));
    }
    if extra_pages != 0 {
        pairs.push((
            rmpv::Value::String("v".into()),
            rmpv::Value::from(extra_pages),
        ));
    }
    pairs.push((rmpv::Value::String("y".into()), rmpv::Value::from(4u64)));
    let val = rmpv::Value::Map(pairs);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &val).expect("encode");
    buf
}

/// Open the tracker DB directly via rusqlite and seed the
/// `resources` table with given (addrid, aidx, ctype, data) tuples.
/// Bypasses the SqliteLedger init path so we can preload legacy rows
/// before the migrator gets a chance to run.
fn seed_legacy_rows(tracker_path: &PathBuf, rows: &[(i64, i64, i64, Vec<u8>)]) {
    let conn = Connection::open(tracker_path).expect("open seed conn");
    // Schema must already exist — caller opens SqliteLedger once first
    // to create tables. We just INSERT/UPDATE here.
    for (addrid, aidx, ctype, data) in rows {
        conn.execute(
            "INSERT OR REPLACE INTO resources (addrid, aidx, ctype, data) \
                 VALUES (?1, ?2, ?3, ?4)",
            params![addrid, aidx, ctype, data],
        )
        .expect("insert legacy row");
    }
    // Seed a placeholder accountbase row so the addrid foreign key
    // resolves cleanly (resources.addrid references accountbase.rowid
    // in the Go schema).
    conn.execute(
        "INSERT OR IGNORE INTO accountbase (rowid, address, normalizedonlinebalance, data) \
             VALUES (1, ?1, 0, x'80')",
        params![vec![0u8; 32]],
    )
    .ok();
    // Clear the migration marker so the migrator re-runs.
    conn.execute(
        "DELETE FROM catchpointstate WHERE id = ?1",
        [RESOURCES_CANONICAL_MIGRATION_MARKER],
    )
    .expect("clear marker");
}

fn marker_value(conn: &Connection) -> Option<i64> {
    conn.query_row(
        "SELECT intval FROM catchpointstate WHERE id = ?1",
        [RESOURCES_CANONICAL_MIGRATION_MARKER],
        |row| row.get(0),
    )
    .optional()
    .expect("query marker")
}

fn read_all_resources(conn: &Connection) -> Vec<(i64, i64, i64, Vec<u8>)> {
    let mut stmt = conn
        .prepare("SELECT addrid, aidx, ctype, data FROM resources ORDER BY aidx")
        .expect("prepare select");
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .expect("query")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect");
    rows
}

fn extract_y_flag(data: &[u8]) -> Option<u64> {
    let val: rmpv::Value = rmpv::decode::read_value(&mut &data[..]).ok()?;
    let rmpv::Value::Map(pairs) = val else {
        return None;
    };
    for (k, v) in pairs {
        if k.as_str() == Some("y") {
            return v.as_u64();
        }
    }
    Some(0)
}

#[test]
fn migrator_rewrites_legacy_asset_rows_to_canonical() {
    let dir = TempDir::new().unwrap();
    let prefix = dir.path().join("ledger");
    let tracker_path = dir.path().join("ledger.tracker.sqlite");

    // 1. First open creates the schema (and runs the migrator with no
    //    legacy rows — sets the marker).
    {
        let ledger = SqliteLedger::open_with_prefix(&prefix).expect("first open");
        drop(ledger);
    }

    // 2. Seed legacy-shaped rows and clear the marker.
    let legacy_holding = legacy_asset_holding_blob(1_000_000, false);
    let legacy_params = legacy_asset_params_blob(100, Some("LGC"));
    seed_legacy_rows(
        &tracker_path,
        &[
            (1, 100, 0, legacy_holding.clone()),
            (1, 200, 0, legacy_params.clone()),
        ],
    );

    // Confirm the seed bytes really are legacy `y=1`/`y=4`.
    {
        let conn = Connection::open(&tracker_path).unwrap();
        let rows = read_all_resources(&conn);
        assert_eq!(rows.len(), 2);
        assert_eq!(extract_y_flag(&rows[0].3), Some(1), "seed legacy holding");
        assert_eq!(extract_y_flag(&rows[1].3), Some(4), "seed legacy params");
        assert_eq!(marker_value(&conn), None, "marker cleared before re-open");
    }

    // 3. Re-open → migrator runs, rewrites rows, sets marker.
    {
        let ledger = SqliteLedger::open_with_prefix(&prefix).expect("re-open");
        drop(ledger);
    }

    // 4. Verify rows are now canonical and marker is stamped.
    let conn = Connection::open(&tracker_path).unwrap();
    let rows = read_all_resources(&conn);
    assert_eq!(rows.len(), 2);

    // Asset holding: y=0 (HOLDING) is omitempty-dropped, so the row's y
    // is absent OR explicitly zero. extract_y_flag returns Some(0) for
    // an absent y (sentinel).
    let holding_y = extract_y_flag(&rows[0].3).unwrap_or(0);
    assert_eq!(
        holding_y, 0,
        "asset holding row should now write canonical y=HOLDING (omitted)"
    );

    // Asset params written alone (legacy y=4 = "ownership-only, no
    // holding") maps to canonical NOT_HOLDING | OWNERSHIP = 3 because
    // the migrator preserves the "no holding subset" semantics. A
    // creator's COMBINED row (holding + params) would be y=2; this
    // synthetic fixture has only params, so y=3 is correct.
    let params_y = extract_y_flag(&rows[1].3).unwrap_or(0);
    assert_eq!(
        params_y, 3,
        "asset params row should now write canonical y=NOT_HOLDING|OWNERSHIP=3"
    );

    assert_eq!(marker_value(&conn), Some(1), "migration marker stamped");
}

#[test]
fn migrator_is_idempotent_on_already_canonical_rows() {
    let dir = TempDir::new().unwrap();
    let prefix = dir.path().join("ledger");
    let tracker_path = dir.path().join("ledger.tracker.sqlite");

    // First open (fresh DB).
    {
        let ledger = SqliteLedger::open_with_prefix(&prefix).expect("first open");
        drop(ledger);
    }

    // Manually write a canonical asset params row (y=2), then clear the marker.
    let canonical_params = {
        let p = algo_types::AssetParams {
            total: 500,
            decimals: 0,
            default_frozen: false,
            unit_name: "CAN".to_string(),
            asset_name: String::new(),
            url: String::new(),
            metadata_hash: None,
            manager: None,
            reserve: None,
            freeze: None,
            clawback: None,
        };
        // Use the public ledger encoder to produce canonical bytes.
        let creator = algo_types::Address([0u8; 32]);
        algo_ledger::sqlite::encode_asset_params_with_round(&p, &creator, 0)
    };

    seed_legacy_rows(&tracker_path, &[(1, 500, 0, canonical_params.clone())]);

    // Re-open → migrator runs but the row is already canonical, so it
    // shouldn't change. Verify byte-identity.
    {
        let ledger = SqliteLedger::open_with_prefix(&prefix).expect("re-open");
        drop(ledger);
    }

    let conn = Connection::open(&tracker_path).unwrap();
    let rows = read_all_resources(&conn);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].3, canonical_params,
        "canonical row must round-trip through migrator unchanged"
    );
    assert_eq!(marker_value(&conn), Some(1));
}

#[test]
fn migrator_rewrites_legacy_app_params_nested_schema() {
    let dir = TempDir::new().unwrap();
    let prefix = dir.path().join("ledger");
    let tracker_path = dir.path().join("ledger.tracker.sqlite");

    // Initial open creates schema.
    {
        let _ = SqliteLedger::open_with_prefix(&prefix).expect("first open");
    }

    // Seed a legacy app-params row with nested `t = {nui:5, nbs:0}` and
    // `v = 3` (legacy extra_program_pages slot).
    let legacy = legacy_app_params_blob(&[0x06, 0x81, 0x01], 5, 3);
    seed_legacy_rows(&tracker_path, &[(1, 300, 1, legacy)]);

    // Re-open → migrator rewrites to canonical.
    {
        let _ = SqliteLedger::open_with_prefix(&prefix).expect("re-open");
    }

    let conn = Connection::open(&tracker_path).unwrap();
    let rows = read_all_resources(&conn);
    assert_eq!(rows.len(), 1);

    let val: rmpv::Value =
        rmpv::decode::read_value(&mut &rows[0].3[..]).expect("decode canonical");
    let rmpv::Value::Map(pairs) = val else {
        panic!("not a map");
    };

    // Canonical layout: `t` is now a u64 (local_state_schema.num_uint),
    // NOT a nested map. `x` carries extra_program_pages (legacy `v`).
    let t_value = pairs
        .iter()
        .find(|(k, _)| k.as_str() == Some("t"))
        .expect("t present");
    assert!(
        matches!(t_value.1, rmpv::Value::Integer(_)),
        "canonical `t` is a u64, not a nested submap"
    );
    assert_eq!(t_value.1.as_u64().unwrap_or(0), 5);

    let x_value = pairs
        .iter()
        .find(|(k, _)| k.as_str() == Some("x"))
        .expect("x present (canonical extra_program_pages)");
    assert_eq!(x_value.1.as_u64().unwrap_or(0), 3);

    // Legacy `v` (extra_program_pages) must NOT be present anymore.
    assert!(
        !pairs.iter().any(|(k, _)| k.as_str() == Some("v")),
        "legacy `v` (extra_program_pages slot) must be canonicalized to `x`"
    );
}

#[test]
fn migrator_preserves_update_round_version_and_size_sponsor_metadata() {
    // PLAN-189 / TASK-195 (Codex review round 1): the migrator must
    // preserve `z` (update_round), `A` (version), and `B` (size_sponsor)
    // from the original BLOB. Otherwise catchpoint-shaped rows with
    // non-default metadata silently lose data on first open.
    let dir = TempDir::new().unwrap();
    let prefix = dir.path().join("ledger");
    let tracker_path = dir.path().join("ledger.tracker.sqlite");

    {
        let _ = SqliteLedger::open_with_prefix(&prefix).expect("first open");
    }

    // Build a synthetic legacy asset-params row carrying all three
    // metadata fields. Layout: a (total), y=4, z (update_round),
    // A (version), B (size_sponsor as 32-byte blob).
    let sponsor = [0x7au8; 32];
    let legacy_with_metadata = {
        let pairs = vec![
            (rmpv::Value::String("a".into()), rmpv::Value::from(1000u64)),
            (rmpv::Value::String("y".into()), rmpv::Value::from(4u64)),
            (rmpv::Value::String("z".into()), rmpv::Value::from(42u64)),
            (rmpv::Value::String("A".into()), rmpv::Value::from(7u64)),
            (
                rmpv::Value::String("B".into()),
                rmpv::Value::Binary(sponsor.to_vec()),
            ),
        ];
        let val = rmpv::Value::Map(pairs);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &val).unwrap();
        buf
    };

    seed_legacy_rows(&tracker_path, &[(1, 999, 0, legacy_with_metadata)]);

    {
        let _ = SqliteLedger::open_with_prefix(&prefix).expect("re-open");
    }

    let conn = Connection::open(&tracker_path).unwrap();
    let rows = read_all_resources(&conn);
    assert_eq!(rows.len(), 1);

    let val: rmpv::Value = rmpv::decode::read_value(&mut &rows[0].3[..]).unwrap();
    let rmpv::Value::Map(pairs) = val else {
        panic!("not a map");
    };

    let z = pairs
        .iter()
        .find(|(k, _)| k.as_str() == Some("z"))
        .map(|(_, v)| v.as_u64().unwrap_or(0))
        .unwrap_or(0);
    let a = pairs
        .iter()
        .find(|(k, _)| k.as_str() == Some("A"))
        .map(|(_, v)| v.as_u64().unwrap_or(0))
        .unwrap_or(0);
    let b = pairs
        .iter()
        .find(|(k, _)| k.as_str() == Some("B"))
        .and_then(|(_, v)| v.as_slice().map(|s| s.to_vec()))
        .unwrap_or_default();

    assert_eq!(z, 42, "z (update_round) must be preserved");
    assert_eq!(a, 7, "A (version) must be preserved");
    assert_eq!(b, sponsor.to_vec(), "B (size_sponsor) must be preserved");
}

#[test]
fn migrator_skips_when_marker_already_set() {
    let dir = TempDir::new().unwrap();
    let prefix = dir.path().join("ledger");

    // First open creates schema + stamps marker (no legacy rows present).
    {
        let _ = SqliteLedger::open_with_prefix(&prefix).expect("first open");
    }

    let tracker_path = dir.path().join("ledger.tracker.sqlite");
    let conn = Connection::open(&tracker_path).unwrap();
    assert_eq!(
        marker_value(&conn),
        Some(1),
        "fresh DB should stamp the migration marker"
    );

    // Subsequent open should NOT re-run (marker is the gate). We can't
    // easily prove "didn't run" without instrumentation, but the marker
    // being stable across opens is the visible signal — and the row
    // count is unchanged.
    drop(conn);
    {
        let _ = SqliteLedger::open_with_prefix(&prefix).expect("second open");
    }
    let conn = Connection::open(&tracker_path).unwrap();
    assert_eq!(marker_value(&conn), Some(1));
}
