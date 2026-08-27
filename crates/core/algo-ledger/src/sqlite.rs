//! SQLite-backed ledger storage with Go-compatible schema.
//!
//! Implements `LedgerStore` using `rusqlite`, matching go-algorand's
//! trackerdb table layout. AccountData is serialized as msgpack blobs
//! using Go-compatible codec keys.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use algo_error::AlgoError;
use algo_types::{
    AccountData, AccountStatus, Address, AppLocalState, AppParams, AssetHolding, AssetParams,
    AssetParamsRecord, BlockHeader, Round, StateSchema, TealValue,
};
use rusqlite::{params, Connection, OptionalExtension};

use crate::catchpoint::verify::{encode_mixed_map, encode_msgpack_uint};
use crate::lease::LeaseTable;
use crate::rewards::{normalized_online_balance, REWARD_UNITS};
use crate::store_trait::LedgerStore;

/// Compute the normalized online balance for an account and convert to i64
/// for SQLite storage. Panics if the result does not fit in i64.
fn account_nob_i64(account: &AccountData) -> i64 {
    let nob = normalized_online_balance(
        account.status,
        account.micro_algos,
        account.rewards_base,
        REWARD_UNITS,
    );
    i64::try_from(nob).expect("normalized online balance should fit in i64")
}

// ---------------------------------------------------------------------------
// Schema DDL
// ---------------------------------------------------------------------------
//
// go-algorand splits the ledger database into two SQLite files
// (`<prefix>.tracker.sqlite` for tracker tables and `<prefix>.block.sqlite`
// for the block archive — see `../go-algorand/ledger/ledger.go:327,336`).
// We mirror that layout by opening the tracker file as the `main` schema and
// `ATTACH`-ing the block file as the `blockdb` schema on the same connection.
// All block-table SQL therefore qualifies the table as `blockdb.blocks`.

/// DDL run on the tracker connection (the `main` schema). Mirrors
/// go-algorand's `accountsSchema` plus the auxiliary tables used by the Rust
/// reimplementation. Excludes the `blocks` table — that lives in the
/// attached `blockdb` schema (`SCHEMA_BLOCK_SQL`).
const SCHEMA_TRACKER_SQL: &str = "
CREATE TABLE IF NOT EXISTS acctrounds (
    id    TEXT PRIMARY KEY,
    rnd   INTEGER
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
);

CREATE TABLE IF NOT EXISTS accountbase (
    addrid                  INTEGER PRIMARY KEY NOT NULL,
    address                 BLOB NOT NULL,
    data                    BLOB,
    normalizedonlinebalance INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS accountbase_address_idx ON accountbase (address);

CREATE INDEX IF NOT EXISTS onlineaccountbals
    ON accountbase ( normalizedonlinebalance, address, data ) WHERE normalizedonlinebalance>0;

-- `ctype` matches Go's post-migration shape:
-- `../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:970`
-- (`ALTER TABLE resources ADD COLUMN ctype INTEGER NOT NULL DEFAULT -1`).
-- Pre-existing Rust DBs with a nullable `ctype` are rebuilt to this shape
-- in `migrate_resources_ctype_not_null` during open.
CREATE TABLE IF NOT EXISTS resources (
    addrid  INTEGER NOT NULL,
    aidx    INTEGER NOT NULL,
    data    BLOB    NOT NULL,
    ctype   INTEGER NOT NULL DEFAULT -1,
    PRIMARY KEY (addrid, aidx)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS assetcreators (
    asset   INTEGER PRIMARY KEY,
    creator BLOB,
    ctype   INTEGER
);

-- Catchpoint catalog. Matches
-- `../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:60-65`
-- byte-for-byte modulo the IF NOT EXISTS clause. Phase A is reader-only;
-- the row is populated by the catchpoint tracker (out of scope for
-- PLAN-35, see PLAN-37). The table must exist with this exact shape so a
-- Go-written DB containing rows here re-opens cleanly under Rust, and a
-- Rust-initialized DB re-opens cleanly under Go.
CREATE TABLE IF NOT EXISTS storedcatchpoints (
    round     INTEGER PRIMARY KEY,
    filename  TEXT NOT NULL,
    catchpoint TEXT NOT NULL,
    filesize  size NOT NULL,
    pinned    INTEGER NOT NULL
);

-- First-stage catchpoint metadata. Matches
-- `../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:143-146`.
-- `info` is a msgp-encoded `catchpointFirstStageInfo`. Empty for the
-- reader path; the writer is downstream of PLAN-35.
CREATE TABLE IF NOT EXISTS catchpointfirststageinfo (
    round INTEGER PRIMARY KEY NOT NULL,
    info  BLOB NOT NULL
);

-- Unfinished catchpoints staging. Matches
-- `../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:148-151`.
-- Empty for the reader path; the writer is downstream of PLAN-35.
CREATE TABLE IF NOT EXISTS unfinishedcatchpoints (
    round     INTEGER PRIMARY KEY NOT NULL,
    blockhash BLOB NOT NULL
);

-- G6 part 3 (TASK-107) removed the Rust-only `algod_rust_meta` table.
-- Chain-level state is derived from `acctrounds.acctbase` + the
-- committed block's header (see `derive_chain_meta_from_latest_block`).
-- Sync-state persistence (Rust-only operational state) moved to
-- namespaced `algod_rust_sync_*` keys in `catchpointstate` — Go's own
-- k-v table, which ignores unknown keys (precedent: TASK-110's
-- `algod_rust_kvstore_null_norm_v1` marker). `DROP TABLE IF EXISTS
-- algod_rust_meta` runs at open below to clean up DBs initialized by
-- a pre-G6-part-3 binary.

-- Go-compatible paged trie storage. Matches
-- `../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:66-68`
-- byte-for-byte modulo the IF NOT EXISTS clause. Each row is one page
-- of the merkle trie serialized with the format documented on
-- `algo_ledger::merkle_page::Page`. This is the sole source of truth
-- for trie persistence; the Rust-only single-blob `merkle_trie` table
-- (DDL removed in PLAN-36 G4 / TASK-118) is no longer created. Old
-- Rust DBs may still carry an orphan `merkle_trie` row, but the
-- runtime neither reads nor writes it.
CREATE TABLE IF NOT EXISTS accounthashes (
    id   INTEGER PRIMARY KEY,
    data BLOB
);

-- Staging table for catchpoint imports. Mirrors
-- `../go-algorand/ledger/store/trackerdb/sqlitedriver/catchpoint.go:534`;
-- the orchestrator writes new pages here and renames the table to
-- `accounthashes` once the catchpoint is fully imported. Created
-- up-front by `IF NOT EXISTS` so the import path doesn't have to.
CREATE TABLE IF NOT EXISTS catchpointaccounthashes (
    id   INTEGER PRIMARY KEY,
    data BLOB
);

CREATE TABLE IF NOT EXISTS kvstore (
    key   BLOB PRIMARY KEY,
    value BLOB
);

CREATE TABLE IF NOT EXISTS txtail (
    rnd INTEGER PRIMARY KEY NOT NULL,
    data BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS onlineaccounts (
    address BLOB NOT NULL,
    updround INTEGER NOT NULL,
    normalizedonlinebalance INTEGER NOT NULL,
    votelastvalid INTEGER NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (address, updround)
);

CREATE INDEX IF NOT EXISTS onlineaccountnorm
    ON onlineaccounts (normalizedonlinebalance, address);

CREATE INDEX IF NOT EXISTS onlineaccounts_votelastvalid_idx
    ON onlineaccounts (votelastvalid);

CREATE TABLE IF NOT EXISTS onlineroundparamstail (
    rnd INTEGER NOT NULL PRIMARY KEY,
    data BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS catchpointstate (
    id TEXT PRIMARY KEY,
    intval INTEGER,
    strval TEXT
);

CREATE TABLE IF NOT EXISTS stateproofverification (
    lastattestedround INTEGER PRIMARY KEY NOT NULL,
    verificationcontext BLOB NOT NULL
);
";

/// DDL run on the attached `blockdb` schema. Mirrors
/// `../go-algorand/ledger/store/blockdb/blockdb.go:35-40` byte-for-byte
/// (modulo the `IF NOT EXISTS` clause we always use).
pub(crate) const SCHEMA_BLOCK_SQL: &str = "
CREATE TABLE IF NOT EXISTS blockdb.blocks (
    rnd INTEGER PRIMARY KEY,
    proto TEXT,
    hdrdata BLOB,
    blkdata BLOB,
    certdata BLOB
);
";

/// Suffix appended to the ledger prefix to form the tracker file path,
/// matching go-algorand's `<prefix>.tracker.sqlite` convention
/// (`../go-algorand/ledger/ledger.go:327`).
pub const TRACKER_SUFFIX: &str = ".tracker.sqlite";

/// Suffix appended to the ledger prefix to form the block file path,
/// matching go-algorand's `<prefix>.block.sqlite` convention
/// (`../go-algorand/ledger/ledger.go:336`).
pub const BLOCK_SUFFIX: &str = ".block.sqlite";

/// Derive the ledger prefix from a path that may already include a
/// `.sqlite` or `.tracker.sqlite` suffix.
///
/// Examples:
/// - `/foo/ledger` → `/foo/ledger`
/// - `/foo/ledger.sqlite` → `/foo/ledger`
/// - `/foo/ledger.tracker.sqlite` → `/foo/ledger`
/// - `/foo/ledger.block.sqlite` → `/foo/ledger`
///
/// Kept as a free function so CLI callers can normalize a `--ledger-path`
/// argument to a prefix before handing it to other tooling.
pub fn derive_ledger_prefix(path: &Path) -> std::path::PathBuf {
    let s = path.to_string_lossy();
    let trimmed = s
        .strip_suffix(TRACKER_SUFFIX)
        .or_else(|| s.strip_suffix(BLOCK_SUFFIX))
        .or_else(|| s.strip_suffix(".sqlite"))
        .unwrap_or(&s);
    std::path::PathBuf::from(trimmed.to_string())
}

/// Compute the tracker file path for a given ledger prefix.
pub fn tracker_path_for_prefix(prefix: &Path) -> std::path::PathBuf {
    let mut s = prefix.as_os_str().to_owned();
    s.push(TRACKER_SUFFIX);
    std::path::PathBuf::from(s)
}

/// Compute the block file path for a given ledger prefix.
pub fn block_path_for_prefix(prefix: &Path) -> std::path::PathBuf {
    let mut s = prefix.as_os_str().to_owned();
    s.push(BLOCK_SUFFIX);
    std::path::PathBuf::from(s)
}

/// Open a raw `rusqlite::Connection` against the ledger pair derived from
/// `path` (a prefix or legacy `.sqlite`-suffixed path). The tracker file is
/// opened as the `main` schema and the block file is attached as `blockdb`.
///
/// This is the lower-level companion to [`SqliteLedger::open`]: it returns a
/// bare connection (without running any schema DDL or loading cached chain
/// state) so callers that perform raw SQL — catchpoint import, ad-hoc
/// maintenance tooling, etc. — can address both schemas through the same
/// connection. Both schemas are switched to WAL mode and `synchronous=NORMAL`.
pub fn open_ledger_connection(path: &Path) -> Result<Connection, AlgoError> {
    let prefix = derive_ledger_prefix(path);
    let tracker = tracker_path_for_prefix(&prefix);
    let block = block_path_for_prefix(&prefix);
    let conn = Connection::open(&tracker).map_err(|e| AlgoError::Ledger {
        message: format!(
            "sqlite open error opening tracker db {}: {e}",
            tracker.display()
        ),
    })?;
    conn.execute(
        "ATTACH DATABASE ?1 AS blockdb",
        params![block.to_string_lossy().as_ref()],
    )
    .map_err(|e| AlgoError::Ledger {
        message: format!(
            "sqlite attach error opening block db {}: {e}",
            block.display()
        ),
    })?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA blockdb.journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA blockdb.synchronous=NORMAL;",
    )
    .map_err(|e| AlgoError::Ledger {
        message: format!("set pragmas on ledger connection: {e}"),
    })?;
    Ok(conn)
}

/// Return `true` if a ledger database pair (tracker file) already exists at
/// the given prefix-or-path. Mirrors the "does the on-disk DB exist?" check
/// callers used to perform against a single-file `ledger.sqlite`.
pub fn ledger_exists(path: &Path) -> bool {
    let prefix = derive_ledger_prefix(path);
    tracker_path_for_prefix(&prefix).exists()
}

/// Outcome of [`SqliteLedger::reconcile_cross_file`]. Distinguishes the
/// fresh-DB / consistent / catchpoint-imported / split-commit-gap cases
/// so callers can route to the right startup recovery path.
///
/// `BlockBehind` is the only state that signals a corrupt-on-disk
/// hazard. `CatchpointOnly` is a legitimate shape (right after a
/// standalone catchpoint import, before any blocks have been fetched);
/// callers that REQUIRE the block archive (relay, participate, follow,
/// replay) treat it like `BlockBehind`, while callers that drive a
/// recovery (sync, the catchpoint orchestrator's gossip handoff)
/// accept it and proceed to download blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossFileState {
    /// Neither the tracker nor `blockdb.blocks` has committed any rounds.
    Empty,
    /// Tracker and `blockdb.blocks` agree on the latest round, or
    /// `blockdb.blocks` is ahead of the tracker (a transient state
    /// during sync where the block is stored before the apply commits).
    /// The tracker's own `current_round` is reported for callers that
    /// want to log it.
    Consistent { round: u64 },
    /// Tracker recorded a round but `blockdb.blocks` is completely
    /// empty. Mirrors the shape produced by the standalone `algod-rust
    /// catchpoint import` command: tracker state has been bulk-loaded
    /// from a catchpoint file but no blocks have been downloaded yet.
    /// `sync` accepts this and refetches; `relay` / `participate` /
    /// `follow` / `replay` treat it as fatal because they cannot
    /// reproduce the block tail.
    CatchpointOnly { tracker_round: u64 },
    /// Tracker recorded round `tracker_round` as committed and
    /// `blockdb.blocks` contains some rows up to `block_max_round`, but
    /// the row for `tracker_round` itself is missing. This is the
    /// split-commit hazard documented on [`SqliteLedger::open_split`]:
    /// a crash between the tracker WAL fsync and the blockdb WAL fsync
    /// left the tracker ahead of the durable block archive. The caller
    /// is responsible for backfilling the missing block(s) or rejecting
    /// startup. Mirrors go-algorand's split tracker/block DB recovery
    /// (`../go-algorand/ledger/ledger.go:327,336`).
    BlockBehind {
        tracker_round: u64,
        block_max_round: u64,
    },
}

/// Remove every file backing a ledger pair (`<prefix>.tracker.sqlite`,
/// `<prefix>.block.sqlite`, and their SQLite WAL/SHM sidecars).
///
/// Matches the cleanup paths in go-algorand's tests
/// (`../go-algorand/ledger/ledger_test.go:1485-2520`) which remove the same
/// six files when a stale DB needs to be recreated. Missing files are
/// silently ignored; the first I/O error stops the cleanup and is returned.
pub fn remove_ledger_files(path: &Path) -> std::io::Result<()> {
    let prefix = derive_ledger_prefix(path);
    for suffix in [
        TRACKER_SUFFIX,
        BLOCK_SUFFIX,
        // SQLite WAL-mode sidecars created next to each DB file.
        ".tracker.sqlite-wal",
        ".tracker.sqlite-shm",
        ".block.sqlite-wal",
        ".block.sqlite-shm",
    ] {
        let mut full = prefix.as_os_str().to_owned();
        full.push(suffix);
        let target = std::path::PathBuf::from(full);
        match std::fs::remove_file(&target) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// Resource ctype constants (matches Go's `basics.AssetCreatable = 0`, `basics.AppCreatable = 1`)
const CTYPE_ASSET: i64 = 0;
const CTYPE_APP: i64 = 1;

/// Marker key written to `catchpointstate` after the G13 kvstore NULL
/// normalization has run. Namespaced with `algod_rust_` so it cannot
/// collide with Go's well-known keys (Go reads specific keys by name and
/// ignores everything else, so leaving the row in place is safe).
const KVSTORE_NULL_NORM_MARKER: &str = "algod_rust_kvstore_null_norm_v1";

/// G13: one-shot conversion of NULL `kvstore.value` rows to empty BLOBs.
/// Mirrors Go's `performKVStoreNullBlobConversion`. Persists a marker in
/// `catchpointstate` so subsequent opens skip the table scan; idempotent
/// either way.
fn normalize_kvstore_nulls(conn: &Connection) -> rusqlite::Result<()> {
    let already_done: Option<i64> = conn
        .query_row(
            "SELECT intval FROM catchpointstate WHERE id = ?1",
            [KVSTORE_NULL_NORM_MARKER],
            |row| row.get(0),
        )
        .optional()?;
    if already_done == Some(1) {
        return Ok(());
    }

    // Rewrite two shapes that break Rust's `Vec<u8>` reads:
    //   - NULL (pre-G13 Rust and pre-G13 Go)
    //   - empty TEXT (`''`, the literal Go's own
    //     `performKVStoreNullBlobConversion` writes — SQLite stores it
    //     with TEXT affinity, which rusqlite refuses to scan into
    //     `Vec<u8>`). A DB previously migrated by Go would otherwise
    //     have the marker stamped without those values ever being
    //     coerced to BLOB.
    // The `typeof(value) = 'text' AND length(value) = 0` predicate is
    // strict enough not to touch any non-empty TEXT.
    conn.execute(
        "UPDATE kvstore
             SET value = x''
             WHERE value IS NULL
                OR (typeof(value) = 'text' AND length(value) = 0)",
        [],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO catchpointstate (id, intval) VALUES (?1, 1)",
        [KVSTORE_NULL_NORM_MARKER],
    )?;
    Ok(())
}

/// Upgrade pre-G5 Rust DBs whose `resources.ctype` was declared `INTEGER`
/// (nullable) to Go's post-migration shape `INTEGER NOT NULL DEFAULT -1`.
/// SQLite can't change a column's `NOT NULL` in place, so we rebuild the
/// table when it is detected to be in the old shape.
///
/// Go reference:
/// `../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:970`
/// (the `accountsAddCreatableTypeColumn` migration) — the column shape we
/// converge on is identical, although the migration paths differ (Go's
/// adds the column via `ALTER TABLE`; we rebuild because Rust always
/// declared the column from the start).
///
/// Idempotent: a DB already in the new shape is a no-op.
fn migrate_resources_ctype_not_null(conn: &Connection) -> Result<(), AlgoError> {
    // Three on-disk shapes are possible:
    //   (a) `resources` doesn't exist at all → schema creation will have
    //       just produced the new shape; nothing to do.
    //   (b) `resources` exists but has no `ctype` column → this is a
    //       pre-ctype Go DB (the column was added by Go's
    //       `accountsAddCreatableTypeColumn` at
    //       `../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:970`).
    //       Replay that exact ALTER so subsequent code can read `r.ctype`.
    //   (c) `resources.ctype` exists but is nullable → pre-G5 Rust shape;
    //       rebuild the table to enforce NOT NULL DEFAULT -1.
    let table_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='resources')",
            [],
            |row| row.get(0),
        )
        .map_err(|e| AlgoError::Ledger {
            message: format!("query resources table existence: {e}"),
        })?;
    if !table_exists {
        // Case (a).
        return Ok(());
    }

    // `pragma_table_info` returns rows {cid, name, type, notnull, dflt_value, pk}.
    let notnull: Option<i64> = conn
        .query_row(
            "SELECT \"notnull\" FROM pragma_table_info('resources') WHERE name='ctype'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| AlgoError::Ledger {
            message: format!("query resources.ctype pragma: {e}"),
        })?;

    let Some(notnull) = notnull else {
        // Case (b): column missing. Go's `accountsAddCreatableTypeColumn`
        // adds the column AND backfills `ctype` per row (from
        // `assetcreators` and then by decoding resource blobs;
        // `../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:946-1039`).
        // Skipping the backfill would leave existing asset/app rows with
        // ctype=-1, which is treated as "unknown" by lookups filtering on
        // ctype = 0/1 (e.g. `r.ctype = ?`) and would make those resources
        // silently invisible. Porting the full backfill is the job of
        // TASK-109 / G12 (pre-v3 migration, explicitly out of scope here);
        // until then, refuse to open such a DB with a clear pointer.
        return Err(AlgoError::Ledger {
            message: "resources table is missing the `ctype` column \
                      (pre-ctype Go shape). Backfill migration is not \
                      yet ported (see PLAN-35 TASK-109 / DOC-24 §G12). \
                      Recover by re-syncing this ledger from a catchpoint."
                .to_string(),
        });
    };

    // Already in the new shape — done.
    if notnull == 1 {
        return Ok(());
    }

    // Old shape: rebuild the table with the new declaration, backfilling
    // any existing NULL ctypes to -1 (Go's "unknown" sentinel).
    conn.execute_batch(
        "BEGIN;
         CREATE TABLE resources_g5_migration (
             addrid  INTEGER NOT NULL,
             aidx    INTEGER NOT NULL,
             data    BLOB    NOT NULL,
             ctype   INTEGER NOT NULL DEFAULT -1,
             PRIMARY KEY (addrid, aidx)
         ) WITHOUT ROWID;
         INSERT INTO resources_g5_migration (addrid, aidx, data, ctype)
             SELECT addrid, aidx, data, COALESCE(ctype, -1) FROM resources;
         DROP TABLE resources;
         ALTER TABLE resources_g5_migration RENAME TO resources;
         COMMIT;",
    )
    .map_err(|e| AlgoError::Ledger {
        message: format!("rebuild resources for NOT NULL ctype: {e}"),
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Resource flag handling
// ---------------------------------------------------------------------------
//
// Every encoder + merge/strip helper writes Go-canonical bytes via
// `algo_codec::canonical_encode_resources_data`. The single source of
// truth for `ResourceFlags` enum values is
// [`algo_codec::resource_flags`] (`HOLDING = 0`, `NOT_HOLDING = 1`,
// `OWNERSHIP = 2`, `EMPTY_ASSET = 4`, `EMPTY_APP = 8` — matching
// go-algorand's `trackerdb.ResourceFlags` at
// `../go-algorand/ledger/store/trackerdb/data.go:62-75`). PLAN-189.

// Box key prefix and layout constants (matches go-algorand's avm-abi/apps.MakeBoxKey).
const BOX_PREFIX: &[u8] = b"bx:";

/// Build the full kvstore key for a box: `"bx:" + big-endian(app_id) + box_name`.
///
/// This matches go-algorand's `apps.MakeBoxKey(appIdx, name)`. `pub(crate)`
/// so `avm_context.rs` can key its per-round `kv_mods` box-delta recorder
/// (issue #570) with the same raw bytes this module uses for the box store
/// itself, keeping both sides byte-exact and consistent.
pub(crate) fn make_box_key(app_id: u64, name: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(BOX_PREFIX.len() + 8 + name.len());
    key.extend_from_slice(BOX_PREFIX);
    key.extend_from_slice(&app_id.to_be_bytes());
    key.extend_from_slice(name);
    key
}

// ---------------------------------------------------------------------------
// Msgpack encode/decode helpers for AccountData (Go-compatible codec keys)
// ---------------------------------------------------------------------------

/// Encode an `AccountData` to the byte form stored in `accountbase.data`.
///
/// PLAN-36 G8 (TASK-120) routed this through
/// [`algo_codec::canonical_encode_base_account_data`], which is the
/// authoritative byte-exact encoder for go-algorand's
/// `trackerdb.BaseAccountData` (codec tags `a`..`q`, `A`..`F`, `z`).
/// Only the base fields of `AccountData` end up in this BLOB; the
/// resource maps (`assets` / `asset_params` / `app_local_states` /
/// `app_params`) live in the separate `resources` table and are
/// encoded elsewhere.
pub(crate) fn encode_account_data(acct: &AccountData) -> Vec<u8> {
    algo_codec::canonical_encode_base_account_data(acct)
}

fn decode_account_data(data: &[u8]) -> Result<AccountData, AlgoError> {
    let val: rmpv::Value =
        rmpv::decode::read_value(&mut &data[..]).map_err(|e| AlgoError::Ledger {
            message: format!("msgpack decode error: {e}"),
        })?;

    let map = match val {
        rmpv::Value::Map(m) => m,
        _ => {
            return Err(AlgoError::Ledger {
                message: "expected msgpack map for AccountData".into(),
            })
        }
    };

    let mut acct = AccountData::default();

    for (k, v) in map {
        let key = k.as_str().unwrap_or("");
        match key {
            "a" => acct.status = AccountStatus::from(v.as_u64().unwrap_or(0) as u8),
            "b" => acct.micro_algos = v.as_u64().unwrap_or(0),
            "c" => acct.rewards_base = v.as_u64().unwrap_or(0),
            "d" => acct.rewarded_micro_algos = v.as_u64().unwrap_or(0),
            "e" => {
                if let Some(bytes) = v.as_slice() {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(bytes);
                        acct.auth_addr = Some(Address(arr));
                    }
                }
            }
            "f" => acct.total_app_schema.num_uint = v.as_u64().unwrap_or(0),
            "g" => acct.total_app_schema.num_byte_slice = v.as_u64().unwrap_or(0),
            "h" => acct.total_extra_app_pages = v.as_u64().unwrap_or(0) as u32,
            "i" => acct.total_created_assets = v.as_u64().unwrap_or(0),
            "j" => acct.total_assets_opted_in = v.as_u64().unwrap_or(0),
            "k" => acct.total_created_apps = v.as_u64().unwrap_or(0),
            "l" => acct.total_apps_opted_in = v.as_u64().unwrap_or(0),
            "m" => acct.total_boxes = v.as_u64().unwrap_or(0),
            "n" => acct.total_box_bytes = v.as_u64().unwrap_or(0),
            "o" => acct.incentive_eligible = v.as_bool().unwrap_or(false),
            "p" => acct.last_proposed = v.as_u64().unwrap_or(0),
            "q" => acct.last_heartbeat = v.as_u64().unwrap_or(0),
            "A" => {
                if let Some(bytes) = v.as_slice() {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(bytes);
                        acct.vote_id = Some(arr);
                    }
                }
            }
            "B" => {
                if let Some(bytes) = v.as_slice() {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(bytes);
                        acct.selection_id = Some(arr);
                    }
                }
            }
            "C" => acct.vote_first_valid = v.as_u64().unwrap_or(0),
            "D" => acct.vote_last_valid = v.as_u64().unwrap_or(0),
            "E" => acct.vote_key_dilution = v.as_u64().unwrap_or(0),
            "F" => {
                if let Some(bytes) = v.as_slice() {
                    if bytes.len() == 64 {
                        let mut arr = [0u8; 64];
                        arr.copy_from_slice(bytes);
                        acct.state_proof_id = Some(arr);
                    }
                }
            }
            "z" => acct.update_round = v.as_u64().unwrap_or(0),
            _ => {} // ignore unknown fields
        }
    }

    Ok(acct)
}

// ---------------------------------------------------------------------------
// Resource msgpack helpers
// ---------------------------------------------------------------------------

pub(crate) fn encode_asset_holding(h: &AssetHolding) -> Vec<u8> {
    encode_asset_holding_with_round(h, 0)
}

pub fn encode_asset_holding_with_round(h: &AssetHolding, update_round: u64) -> Vec<u8> {
    // Delegate to the canonical Go-compatible encoder. The output BLOB
    // is byte-identical to what go-algorand's `trackerdb.ResourcesData.MarshalMsg`
    // would write for the equivalent struct value, modulo Go's omitempty
    // defaults (e.g. a zero-balance opt-in encodes to `{}`).
    // PLAN-189 / TASK-191.
    let rd = algo_codec::ResourcesData {
        amount: h.amount,
        frozen: h.frozen,
        resource_flags: algo_codec::resource_flags::HOLDING,
        update_round,
        ..Default::default()
    };
    algo_codec::canonical_encode_resources_data(&rd)
}

fn decode_asset_holding(data: &[u8]) -> Result<AssetHolding, AlgoError> {
    let val: rmpv::Value =
        rmpv::decode::read_value(&mut &data[..]).map_err(|e| AlgoError::Ledger {
            message: format!("msgpack decode: {e}"),
        })?;
    let map = match val {
        rmpv::Value::Map(m) => m,
        _ => {
            return Err(AlgoError::Ledger {
                message: "expected map for asset holding".into(),
            })
        }
    };

    let mut h = AssetHolding::default();
    for (k, v) in map {
        match k.as_str().unwrap_or("") {
            "l" => h.amount = v.as_u64().unwrap_or(0),
            "m" => h.frozen = v.as_bool().unwrap_or(false),
            _ => {}
        }
    }
    Ok(h)
}

pub(crate) fn encode_asset_params(p: &AssetParams, creator: &Address) -> Vec<u8> {
    encode_asset_params_with_round(p, creator, 0)
}

pub fn encode_asset_params_with_round(
    p: &AssetParams,
    creator: &Address,
    update_round: u64,
) -> Vec<u8> {
    // Delegate to canonical encoder. Note: creator is NOT part of the
    // BLOB — go-algorand stores creator in the `assetcreators` table,
    // not in `resources.data`. We accept it in the signature only to
    // match the legacy ABI; it's intentionally unused.
    // PLAN-189 / TASK-191.
    let _ = creator;
    let rd = algo_codec::ResourcesData {
        total: p.total,
        decimals: p.decimals,
        default_frozen: p.default_frozen,
        unit_name: p.unit_name.clone(),
        asset_name: p.asset_name.clone(),
        url: p.url.clone(),
        metadata_hash: p.metadata_hash.unwrap_or([0u8; 32]),
        manager: p.manager.map(|a| a.0).unwrap_or([0u8; 32]),
        reserve: p.reserve.map(|a| a.0).unwrap_or([0u8; 32]),
        freeze: p.freeze.map(|a| a.0).unwrap_or([0u8; 32]),
        clawback: p.clawback.map(|a| a.0).unwrap_or([0u8; 32]),
        resource_flags: algo_codec::resource_flags::OWNERSHIP,
        update_round,
        ..Default::default()
    };
    algo_codec::canonical_encode_resources_data(&rd)
}

fn decode_asset_params(data: &[u8]) -> Result<AssetParams, AlgoError> {
    let val: rmpv::Value =
        rmpv::decode::read_value(&mut &data[..]).map_err(|e| AlgoError::Ledger {
            message: format!("msgpack decode: {e}"),
        })?;
    let map = match val {
        rmpv::Value::Map(m) => m,
        _ => {
            return Err(AlgoError::Ledger {
                message: "expected map for asset params".into(),
            })
        }
    };

    let mut p = AssetParams::default();
    for (k, v) in map {
        match k.as_str().unwrap_or("") {
            "a" => p.total = v.as_u64().unwrap_or(0),
            "b" => {
                let raw = v.as_u64().unwrap_or(0);
                p.decimals = u32::try_from(raw).map_err(|_| AlgoError::Ledger {
                    message: format!("asset decimals {raw} exceeds u32::MAX"),
                })?;
            }
            "c" => p.default_frozen = v.as_bool().unwrap_or(false),
            "d" => {
                if let Some(s) = v.as_str() {
                    p.unit_name = s.to_string();
                }
            }
            "e" => {
                if let Some(s) = v.as_str() {
                    p.asset_name = s.to_string();
                }
            }
            "f" => {
                if let Some(s) = v.as_str() {
                    p.url = s.to_string();
                }
            }
            "g" => {
                if let Some(bytes) = v.as_slice() {
                    let mut arr = [0u8; 32];
                    let len = bytes.len().min(32);
                    arr[..len].copy_from_slice(&bytes[..len]);
                    p.metadata_hash = Some(arr);
                }
            }
            "h" => {
                if let Some(bytes) = v.as_slice() {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(bytes);
                        p.manager = Some(Address(arr));
                    }
                }
            }
            "i" => {
                if let Some(bytes) = v.as_slice() {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(bytes);
                        p.reserve = Some(Address(arr));
                    }
                }
            }
            "j" => {
                if let Some(bytes) = v.as_slice() {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(bytes);
                        p.freeze = Some(Address(arr));
                    }
                }
            }
            "k" => {
                if let Some(bytes) = v.as_slice() {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(bytes);
                        p.clawback = Some(Address(arr));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(p)
}

// Note: pre-PLAN-189 `encode_teal_key_value` (which emitted binary-keyed
// rmpv::Value::Maps) was deleted in TASK-193 — every TEAL kv write path
// now flows through `algo_codec::canonical_encode_teal_key_value`, which
// produces Go's `map[string]TealValue` shape (msgpack STRING keys with
// raw byte content). `decode_teal_key_value` remains tolerant of both
// shapes for back-compat with legacy on-disk rows.

fn decode_teal_key_value(val: &rmpv::Value) -> BTreeMap<Vec<u8>, TealValue> {
    let mut result = BTreeMap::new();
    if let rmpv::Value::Map(pairs) = val {
        for (k, v) in pairs {
            // Canonical Go `map[string]TealValue` writes keys as msgpack
            // STRINGS holding raw bytes (`rmpv::Utf8String::as_bytes`
            // returns them regardless of UTF-8 validity). TASK-196
            // removed the legacy binary-key tolerance — only canonical
            // shape is accepted.
            let key_bytes = match k {
                rmpv::Value::String(s) => s.as_bytes().to_vec(),
                _ => continue,
            };
            if let rmpv::Value::Map(inner) = v {
                let mut tt = 0u64;
                let mut ui = 0u64;
                let mut tb = Vec::new();
                for (ik, iv) in inner {
                    match ik.as_str().unwrap_or("") {
                        "tt" => tt = iv.as_u64().unwrap_or(0),
                        "ui" => ui = iv.as_u64().unwrap_or(0),
                        "tb" => {
                            if let Some(b) = iv.as_slice() {
                                tb = b.to_vec();
                            }
                        }
                        _ => {}
                    }
                }
                let tval = match tt {
                    1 => TealValue::Bytes(tb),
                    2 => TealValue::Uint(ui),
                    _ => TealValue::Uint(ui), // default to uint
                };
                result.insert(key_bytes, tval);
            }
        }
    }
    result
}

pub(crate) fn encode_app_params(p: &AppParams) -> Vec<u8> {
    encode_app_params_with_round(p, 0)
}

pub fn encode_app_params_with_round(p: &AppParams, update_round: u64) -> Vec<u8> {
    // Delegate to canonical encoder. PLAN-189 / TASK-192.
    //
    // Field layout changes from the legacy hand-rolled encoder:
    //   local_state_schema   t (nested {nui,nbs})  →  t (nui u64), u (nbs u64)
    //   global_state_schema  u (nested {nui,nbs})  →  v (nui u64), w (nbs u64)
    //   extra_program_pages  v (u64)               →  x (u64)
    //   y (resource_flags)   4 (legacy OWNERSHIP)  →  2 (canonical OWNERSHIP)
    //   global_state         encoded with binary keys (rmpv Map)
    //                                              →  encoded with string keys
    //                                                 (Go's `map[string]TealValue`)
    let rd = build_app_resource_data(None, Some(p), update_round);
    algo_codec::canonical_encode_resources_data(&rd)
}

/// Build a canonical `algo_codec::ResourcesData` carrying the union of
/// an optional `AppLocalState` and an optional `AppParams`. Mirrors
/// [`build_asset_resource_data`] for the app side. PLAN-189 / TASK-192.
pub fn build_app_resource_data(
    local_state: Option<&AppLocalState>,
    params: Option<&AppParams>,
    update_round: u64,
) -> algo_codec::ResourcesData {
    let mut rd = algo_codec::ResourcesData {
        update_round,
        ..Default::default()
    };

    rd.resource_flags = match (local_state.is_some(), params.is_some()) {
        (true, true) => algo_codec::resource_flags::OWNERSHIP,
        (false, true) => {
            algo_codec::resource_flags::NOT_HOLDING | algo_codec::resource_flags::OWNERSHIP
        }
        (true, false) | (false, false) => algo_codec::resource_flags::HOLDING,
    };

    if let Some(s) = local_state {
        rd.schema_num_uint = s.schema.num_uint;
        rd.schema_num_byte_slice = s.schema.num_byte_slice;
        if !s.key_value.is_empty() {
            rd.key_value = algo_codec::canonical_encode_teal_key_value(&s.key_value);
        }
    }
    if let Some(p) = params {
        rd.approval_program = p.approval_program.clone();
        rd.clear_state_program = p.clear_state_program.clone();
        if !p.global_state.is_empty() {
            rd.global_state = algo_codec::canonical_encode_teal_key_value(&p.global_state);
        }
        rd.local_state_schema_num_uint = p.local_state_schema.num_uint;
        rd.local_state_schema_num_byte_slice = p.local_state_schema.num_byte_slice;
        rd.global_state_schema_num_uint = p.global_state_schema.num_uint;
        rd.global_state_schema_num_byte_slice = p.global_state_schema.num_byte_slice;
        rd.extra_program_pages = p.extra_program_pages;
        rd.version = p.version;
        rd.size_sponsor = p.size_sponsor.0;
    }

    rd
}

fn decode_app_params(data: &[u8], creator: Address) -> Result<AppParams, AlgoError> {
    let val: rmpv::Value =
        rmpv::decode::read_value(&mut &data[..]).map_err(|e| AlgoError::Ledger {
            message: format!("msgpack decode: {e}"),
        })?;
    let map = match val {
        rmpv::Value::Map(m) => m,
        _ => {
            return Err(AlgoError::Ledger {
                message: "expected map for app params".into(),
            })
        }
    };

    let mut p = AppParams {
        creator,
        approval_program: Vec::new(),
        clear_state_program: Vec::new(),
        global_state: BTreeMap::new(),
        local_state_schema: StateSchema::default(),
        global_state_schema: StateSchema::default(),
        extra_program_pages: 0,
        ..Default::default()
    };

    // Canonical Go layout only (TASK-196 removed legacy tolerance):
    //   q = approval, r = clear_state, s = global_state,
    //   t = local_state_schema.num_uint, u = local_state_schema.num_byte_slice,
    //   v = global_state_schema.num_uint, w = global_state_schema.num_byte_slice,
    //   x = extra_program_pages, A = version, B = size_sponsor.
    for (k, v) in &map {
        match k.as_str().unwrap_or("") {
            "q" => {
                if let Some(b) = v.as_slice() {
                    p.approval_program = b.to_vec();
                }
            }
            "r" => {
                if let Some(b) = v.as_slice() {
                    p.clear_state_program = b.to_vec();
                }
            }
            "s" => p.global_state = decode_teal_key_value(v),
            "t" => p.local_state_schema.num_uint = v.as_u64().unwrap_or(0),
            "u" => p.local_state_schema.num_byte_slice = v.as_u64().unwrap_or(0),
            "v" => p.global_state_schema.num_uint = v.as_u64().unwrap_or(0),
            "w" => p.global_state_schema.num_byte_slice = v.as_u64().unwrap_or(0),
            "x" => {
                let raw = v.as_u64().unwrap_or(0);
                p.extra_program_pages = u32::try_from(raw).map_err(|_| AlgoError::Ledger {
                    message: format!("extra_program_pages {raw} exceeds u32::MAX"),
                })?;
            }
            "A" => p.version = v.as_u64().unwrap_or(0),
            "B" => {
                if let Some(b) = v.as_slice() {
                    if b.len() == 32 {
                        let mut addr = [0u8; 32];
                        addr.copy_from_slice(b);
                        p.size_sponsor = Address(addr);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(p)
}

pub(crate) fn encode_app_local_state(s: &AppLocalState) -> Vec<u8> {
    encode_app_local_state_with_round(s, 0)
}

pub fn encode_app_local_state_with_round(s: &AppLocalState, update_round: u64) -> Vec<u8> {
    // Delegate to canonical encoder. PLAN-189 / TASK-193.
    //
    // Field layout changes from the legacy hand-rolled encoder:
    //   schema.num_uint        p.nui (nested submap)  →  n (u64)
    //   schema.num_byte_slice  p.nbs (nested submap)  →  o (u64)
    //   key_value              s (rmpv Map, BIN keys) →  p (rmpv Map, STR keys
    //                                                       per Go's
    //                                                       `map[string]TealValue`)
    //   y (resource_flags)     1 (legacy HOLDING bit) →  0 (canonical HOLDING,
    //                                                       omitted by canonical
    //                                                       encoder)
    //
    // The standalone local-state row's canonical `y` is HOLDING (0), which
    // the canonical encoder omits via add_u64; the resulting blob can be
    // an empty map `{}` for an opted-in account with zero schema and no
    // kv entries. `inspect_resource_blob` recognizes that shape as
    // has_holding=true (TASK-191's empty-map fallback).
    let rd = build_app_resource_data(Some(s), None, update_round);
    algo_codec::canonical_encode_resources_data(&rd)
}

fn decode_app_local_state(data: &[u8]) -> Result<AppLocalState, AlgoError> {
    let val: rmpv::Value =
        rmpv::decode::read_value(&mut &data[..]).map_err(|e| AlgoError::Ledger {
            message: format!("msgpack decode: {e}"),
        })?;
    let map = match val {
        rmpv::Value::Map(m) => m,
        _ => {
            return Err(AlgoError::Ledger {
                message: "expected map for app local state".into(),
            })
        }
    };

    let mut s = AppLocalState {
        schema: StateSchema::default(),
        key_value: BTreeMap::new(),
    };

    // Canonical Go layout only (TASK-196 removed legacy tolerance):
    //   n = schema.num_uint, o = schema.num_byte_slice, p = key_value map.
    // `s` belongs to app params (global_state) on a combined row, never
    // to the local-state subset.
    for (k, v) in map {
        match k.as_str().unwrap_or("") {
            "n" => s.schema.num_uint = v.as_u64().unwrap_or(0),
            "o" => s.schema.num_byte_slice = v.as_u64().unwrap_or(0),
            "p" => s.key_value = decode_teal_key_value(&v),
            _ => {}
        }
    }

    Ok(s)
}

// ---------------------------------------------------------------------------
// App resource blob merging helpers
// ---------------------------------------------------------------------------

/// Semantic view of a canonical resources.data BLOB.
///
/// Derived by inspecting the `y` flag plus the set of top-level keys
/// present in the BLOB. PLAN-189 / TASK-190; legacy-shape tolerance
/// removed in TASK-196.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ResourceMeta {
    /// Raw `y` field value as stored on disk. See
    /// [`algo_codec::resource_flags`] for the enum values. Prefer
    /// `has_holding` / `has_ownership` for dispatch.
    pub raw_flags: u64,
    /// `true` if the row carries asset-holding or app-local-state data.
    pub has_holding: bool,
    /// `true` if the row carries asset-params or app-params data.
    pub has_ownership: bool,
}

/// Inspect a raw `resources.data` BLOB and derive its semantic
/// holding/ownership classification by walking the canonical
/// top-level keys.
///
/// Field-presence rules (Go canonical layout):
///
/// * Asset holding: `l` (amount) or `m` (frozen) → `has_holding`.
/// * Asset params: any of `a..k` → `has_ownership`.
/// * App local-state schema: `n` (num_uint) or `o` (num_byte_slice)
///   → `has_holding`.
/// * App local-state kv: `p` (a `map[string]TealValue`) → `has_holding`.
/// * App params: `q` (approval) / `r` (clear_state) / `s`
///   (global_state) / `t..w` (flat u64 schemas) / `x` (extra_pages)
///   → `has_ownership`.
///
/// Plus the canonical `y` enum (`HOLDING=0`, `NOT_HOLDING=1`,
/// `OWNERSHIP=2`, `NOT_HOLDING|OWNERSHIP=3`, `EMPTY_ASSET=4`,
/// `EMPTY_APP=8`) layered on top — see the `match meta.raw_flags`
/// arm at the bottom of the function.
pub(crate) fn inspect_resource_blob(data: &[u8]) -> ResourceMeta {
    let val: rmpv::Value = match rmpv::decode::read_value(&mut &data[..]) {
        Ok(v) => v,
        Err(_) => return ResourceMeta::default(),
    };
    let pairs = match val {
        rmpv::Value::Map(m) => m,
        _ => return ResourceMeta::default(),
    };

    let mut meta = ResourceMeta::default();

    for (k, v) in &pairs {
        let Some(key) = k.as_str() else { continue };
        match key {
            "y" => meta.raw_flags = v.as_u64().unwrap_or(0),
            // Asset holding fields.
            "l" | "m" => meta.has_holding = true,
            // Asset params fields.
            "a" | "b" | "c" | "d" | "e" | "f" | "g" | "h" | "i" | "j" | "k" => {
                meta.has_ownership = true;
            }
            // App local-state schema + kv.
            "n" | "o" | "p" => meta.has_holding = true,
            // App params (programs, global_state, flat schemas, extra_pages).
            "q" | "r" | "s" | "t" | "u" | "v" | "w" | "x" => meta.has_ownership = true,
            _ => {}
        }
    }

    // Canonical default holding rows (e.g., zero-balance asset opt-ins
    // with amount=0, frozen=false, resource_flags=HOLDING=0) encode to
    // a completely empty map `{}` because every field is omitempty-
    // dropped including `y=0`. Without a special case we'd classify
    // such a row as having neither signal — but its existence in the
    // resources table (with an asset-holding `ctype`) means it IS a
    // holding row. Treat any blob that decoded as a non-empty *bytes*
    // sequence but produced an entirely empty *key set* as a canonical-
    // default holding row (set has_holding). PLAN-189 / TASK-191.
    let saw_any_signal = meta.has_holding || meta.has_ownership;
    let mut is_canonical_default_holding = false;
    if !saw_any_signal && meta.raw_flags == 0 {
        // We got here only after a successful msgpack decode, so the
        // input bytes were a valid (possibly empty) map. Anything we
        // saw in the key loop would have set a signal flag; reaching
        // here means the map carried only metadata keys (z/A/B) or
        // was literally `{}`.
        is_canonical_default_holding = true;
    }

    // Canonical Go `ResourceFlags` enum (`../go-algorand/ledger/store/
    // trackerdb/data.go:62-75`):
    //   y == 0  HOLDING (default; usually omitted by canonical writer)
    //   y == 1  NOT_HOLDING (no holding subset)
    //   y == 2  OWNERSHIP (params + implicit holding; creator row)
    //   y == 3  NOT_HOLDING | OWNERSHIP (params only)
    //   y == 4  EMPTY_ASSET marker
    //   y == 8  EMPTY_APP marker
    //
    // TASK-196 removed the legacy-y tolerance arms (1/4/5 read as
    // legacy bitmask). The migrator + canonical encoders have been the
    // only writers, so every on-disk row is canonical.
    match meta.raw_flags {
        2 => {
            meta.has_ownership = true;
            meta.has_holding = true;
        }
        3 => {
            meta.has_ownership = true;
            meta.has_holding = false;
        }
        _ => {}
    }

    if is_canonical_default_holding && !meta.has_ownership {
        meta.has_holding = true;
    }

    meta
}

/// Merge app-params blob fields into an existing local-state blob, producing a
/// combined blob with both ownership and holding flags set.
///
/// `existing_blob` contains local-state fields (p, s) with holding flag.
/// `new_params` is the AppParams to merge in.
/// Returns the combined blob with flags = HOLDING | OWNERSHIP.
fn merge_app_params_into_local_state(existing_blob: &[u8], new_params: &AppParams) -> Vec<u8> {
    // Decode the existing local state (tolerates both legacy and
    // canonical shapes via the updated `decode_app_local_state`), then
    // re-encode via the canonical builder with both subsets. PLAN-189 / TASK-192.
    //
    // Canonical layout avoids the legacy `s` collision entirely:
    //   local state key_value → `p`
    //   app params global_state → `s`
    // so the old hand-rolled "strip s if global_state present" logic
    // is no longer needed.
    let existing_local = decode_app_local_state(existing_blob).unwrap_or_else(|_| AppLocalState {
        schema: StateSchema::default(),
        key_value: BTreeMap::new(),
    });
    let update_round = extract_update_round(existing_blob);
    let rd = build_app_resource_data(Some(&existing_local), Some(new_params), update_round);
    algo_codec::canonical_encode_resources_data(&rd)
}

/// Merge local-state blob fields into an existing app-params blob, producing a
/// canonical combined blob (`y = OWNERSHIP`). PLAN-189 / TASK-192.
fn merge_app_local_state_into_params(existing_blob: &[u8], new_local: &AppLocalState) -> Vec<u8> {
    // Decode existing params using the dummy creator placeholder; we only
    // need the BLOB fields, not the creator address (creator lives in a
    // separate column).
    let existing_params =
        decode_app_params(existing_blob, Address([0u8; 32])).unwrap_or_else(|_| AppParams {
            creator: Address([0u8; 32]),
            approval_program: Vec::new(),
            clear_state_program: Vec::new(),
            global_state: BTreeMap::new(),
            local_state_schema: StateSchema::default(),
            global_state_schema: StateSchema::default(),
            extra_program_pages: 0,
            ..Default::default()
        });
    let update_round = extract_update_round(existing_blob);
    let rd = build_app_resource_data(Some(new_local), Some(&existing_params), update_round);
    algo_codec::canonical_encode_resources_data(&rd)
}

/// Strip ownership (app params) fields from a combined app blob,
/// keeping only the local-state subset. Returns a canonical
/// local-state-only blob (`y = HOLDING`), or None if the input cannot
/// be decoded. PLAN-189 / TASK-192.
fn strip_ownership_from_blob(data: &[u8]) -> Option<Vec<u8>> {
    rmpv::decode::read_value(&mut &data[..]).ok()?;
    let local = decode_app_local_state(data).ok()?;
    let update_round = extract_update_round(data);
    let rd = build_app_resource_data(Some(&local), None, update_round);
    Some(algo_codec::canonical_encode_resources_data(&rd))
}

/// Strip holding (app local-state) fields from a combined app blob,
/// keeping only the app-params subset. Returns a canonical app-params-only
/// blob (`y = NOT_HOLDING | OWNERSHIP`), or None if the input cannot
/// be decoded. PLAN-189 / TASK-192.
fn strip_holding_from_blob(data: &[u8]) -> Option<Vec<u8>> {
    rmpv::decode::read_value(&mut &data[..]).ok()?;
    let params = decode_app_params(data, Address([0u8; 32])).ok()?;
    let update_round = extract_update_round(data);
    let rd = build_app_resource_data(None, Some(&params), update_round);
    Some(algo_codec::canonical_encode_resources_data(&rd))
}

// ---------------------------------------------------------------------------
// Asset resource blob merging helpers
// ---------------------------------------------------------------------------
//
// All helpers in this section delegate to
// `algo_codec::canonical_encode_resources_data` for the final write so
// that merged / stripped asset blobs are byte-identical to what
// go-algorand would produce. The `y` flag follows Go's bitwise enum:
//
//   has_holding && has_ownership  → y = OWNERSHIP (NOT_HOLDING bit clear)
//   !has_holding && has_ownership → y = NOT_HOLDING | OWNERSHIP
//   has_holding && !has_ownership → y = HOLDING (omitted at canonical write)
//
// PLAN-189 / TASK-191.

/// Build a canonical `algo_codec::ResourcesData` carrying the union of
/// an optional `AssetHolding` and an optional `AssetParams`. The
/// `creator` address from `AssetParams` is intentionally NOT stored in
/// the BLOB — go-algorand keeps that in the `assetcreators` table.
pub fn build_asset_resource_data(
    holding: Option<&AssetHolding>,
    params: Option<&AssetParams>,
    update_round: u64,
) -> algo_codec::ResourcesData {
    let mut rd = algo_codec::ResourcesData {
        update_round,
        ..Default::default()
    };

    rd.resource_flags = match (holding.is_some(), params.is_some()) {
        (true, true) => algo_codec::resource_flags::OWNERSHIP,
        (false, true) => {
            algo_codec::resource_flags::NOT_HOLDING | algo_codec::resource_flags::OWNERSHIP
        }
        (true, false) | (false, false) => algo_codec::resource_flags::HOLDING,
    };

    if let Some(h) = holding {
        rd.amount = h.amount;
        rd.frozen = h.frozen;
    }
    if let Some(p) = params {
        rd.total = p.total;
        rd.decimals = p.decimals;
        rd.default_frozen = p.default_frozen;
        rd.unit_name = p.unit_name.clone();
        rd.asset_name = p.asset_name.clone();
        rd.url = p.url.clone();
        rd.metadata_hash = p.metadata_hash.unwrap_or([0u8; 32]);
        rd.manager = p.manager.map(|a| a.0).unwrap_or([0u8; 32]);
        rd.reserve = p.reserve.map(|a| a.0).unwrap_or([0u8; 32]);
        rd.freeze = p.freeze.map(|a| a.0).unwrap_or([0u8; 32]);
        rd.clawback = p.clawback.map(|a| a.0).unwrap_or([0u8; 32]);
    }

    rd
}

/// Extract the `z` (update_round) field from a raw resource blob, if
/// present. Used by merge/strip helpers that must preserve metadata
/// across the canonical re-encode.
fn extract_update_round(data: &[u8]) -> u64 {
    let Ok(val) = rmpv::decode::read_value(&mut &data[..]) else {
        return 0;
    };
    let rmpv::Value::Map(pairs) = val else {
        return 0;
    };
    for (k, v) in pairs {
        if k.as_str() == Some("z") {
            return v.as_u64().unwrap_or(0);
        }
    }
    0
}

/// Merge asset holding fields into an existing params blob, producing
/// a canonical combined blob (`y = OWNERSHIP`).
fn merge_asset_holding_into_params(
    existing_params_blob: &[u8],
    new_holding: &AssetHolding,
) -> Vec<u8> {
    let existing_params = decode_asset_params(existing_params_blob).unwrap_or_default();
    let update_round = extract_update_round(existing_params_blob);
    let rd = build_asset_resource_data(Some(new_holding), Some(&existing_params), update_round);
    algo_codec::canonical_encode_resources_data(&rd)
}

/// Merge asset params fields into an existing holding blob, producing
/// a canonical combined blob (`y = OWNERSHIP`).
fn merge_asset_params_into_holding(
    existing_holding_blob: &[u8],
    new_params: &AssetParams,
    creator: &Address,
) -> Vec<u8> {
    let _ = creator;
    let existing_holding = decode_asset_holding(existing_holding_blob).unwrap_or_default();
    let update_round = extract_update_round(existing_holding_blob);
    let rd = build_asset_resource_data(Some(&existing_holding), Some(new_params), update_round);
    algo_codec::canonical_encode_resources_data(&rd)
}

/// Strip asset holding fields from a combined blob, keeping only
/// params fields. Returns the params-only blob (`y = NOT_HOLDING |
/// OWNERSHIP`), or None if the input cannot be decoded.
fn strip_asset_holding_from_blob(data: &[u8]) -> Option<Vec<u8>> {
    rmpv::decode::read_value(&mut &data[..]).ok()?;
    let params = decode_asset_params(data).unwrap_or_default();
    let update_round = extract_update_round(data);
    let rd = build_asset_resource_data(None, Some(&params), update_round);
    Some(algo_codec::canonical_encode_resources_data(&rd))
}

/// Strip asset params fields from a combined blob, keeping only
/// holding fields. Returns the holding-only blob (`y = HOLDING`,
/// omitted), or None if the input cannot be decoded.
fn strip_asset_params_from_blob(data: &[u8]) -> Option<Vec<u8>> {
    rmpv::decode::read_value(&mut &data[..]).ok()?;
    let holding = decode_asset_holding(data).unwrap_or_default();
    let update_round = extract_update_round(data);
    let rd = build_asset_resource_data(Some(&holding), None, update_round);
    Some(algo_codec::canonical_encode_resources_data(&rd))
}

/// Set or overwrite the `"z"` (UpdateRound) field in a resource msgpack blob.
///
/// If `update_round` is 0, the blob is returned unmodified.
/// Otherwise, the `"z"` key is added or replaced in the top-level msgpack map.
pub(crate) fn set_blob_update_round(blob: &[u8], update_round: u64) -> Vec<u8> {
    if update_round == 0 {
        return blob.to_vec();
    }
    let val = match rmpv::decode::read_value(&mut &blob[..]) {
        Ok(v) => v,
        Err(_) => return blob.to_vec(),
    };
    let mut pairs: Vec<(rmpv::Value, rmpv::Value)> = Vec::new();
    if let rmpv::Value::Map(m) = val {
        for (k, v) in m {
            if k.as_str() == Some("z") {
                continue; // will be rewritten below
            }
            pairs.push((k, v));
        }
    }
    pairs.push((
        rmpv::Value::String("z".into()),
        rmpv::Value::from(update_round),
    ));
    let out = rmpv::Value::Map(pairs);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &out).expect("msgpack encode");
    buf
}

// ---------------------------------------------------------------------------
// Chain-level meta helpers
// ---------------------------------------------------------------------------

/// G12 (TASK-109): refuse to open a pre-v3 tracker DB.
///
/// Pre-v3 shape: the tracker stores each account as a single
/// msgpack blob in `accountbase` (columns: `address PRIMARY KEY,
/// data BLOB`). Assets and apps held by an account are embedded
/// inside that blob — there is no separate `resources` table. Go's
/// `performResourceTableMigration`
/// (`../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:399-534`)
/// rebuilds `accountbase` with the modern `addrid, address, data,
/// normalizedonlinebalance` shape and migrates the embedded
/// resources into a new `resources` table.
///
/// Detection: `accountbase` table exists AND `resources` does not.
/// `SCHEMA_TRACKER_SQL` always creates both, so this check MUST run
/// before the schema is created (the call site at the top of `init`
/// is what makes that work). On a fresh DB, neither table exists →
/// no-op. On a post-migration v3+ DB, both exist → no-op.
///
/// Rust will port the migration when fixture coverage is available;
/// until then we refuse to open with a structured error so the
/// silent-corruption path (empty `resources` coexisting with a
/// legacy `accountbase`) stays closed.
fn refuse_pre_v3_tracker_db(conn: &Connection) -> Result<(), AlgoError> {
    let has_accountbase: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='accountbase')",
            [],
            |row| row.get(0),
        )
        .map_err(|e| AlgoError::Ledger {
            message: format!("pre-v3 detect: accountbase probe: {e}"),
        })?;
    if !has_accountbase {
        return Ok(());
    }

    let has_resources: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='resources')",
            [],
            |row| row.get(0),
        )
        .map_err(|e| AlgoError::Ledger {
            message: format!("pre-v3 detect: resources probe: {e}"),
        })?;
    if has_resources {
        // Post-migration / fresh-DB shape; nothing to refuse.
        return Ok(());
    }

    Err(AlgoError::Ledger {
        message: "pre-v3 tracker DB detected: `accountbase` exists but `resources` \
                  does not. Go's `performResourceTableMigration` \
                  (schema.go:399-534) has not run, and the Rust port is not yet \
                  available. Recover by re-syncing this ledger from a catchpoint, \
                  or run a pre-port Go binary once to perform the migration in \
                  place. See PLAN-35 / TASK-109 / DOC-24 §G12."
            .to_string(),
    })
}

/// G6 part 3 — one-shot migration that retires `algod_rust_meta`.
///
/// 1. If the table exists and `current_round` is set, mirror that value
///    into `acctrounds.acctbase` so `derive_chain_meta_from_latest_block`
///    has a tracker round to read after the table is dropped. The Rust
///    apply path never wrote to `acctrounds` pre-G6-part-3.
/// 2. Migrate the four `sync_*` rows to `catchpointstate` with namespaced
///    `algod_rust_sync_*` ids — see `sync_state_keys` for the canonical
///    list. This preserves resume-after-restart behaviour.
/// 3. `DROP TABLE IF EXISTS algod_rust_meta`. Idempotent (the migration
///    is a no-op on DBs that were never initialized by a pre-G6-part-3
///    binary).
fn migrate_off_algod_rust_meta(conn: &Connection) -> rusqlite::Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='algod_rust_meta')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(());
    }

    // Step 1: mirror current_round → acctrounds.acctbase if missing.
    let legacy_round: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM algod_rust_meta WHERE key = 'current_round'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(bytes) = legacy_round {
        if bytes.len() == 8 {
            let rnd = u64::from_le_bytes(bytes.try_into().unwrap()) as i64;
            let acctrounds_present: Option<i64> = conn
                .query_row(
                    "SELECT rnd FROM acctrounds WHERE id = 'acctbase'",
                    [],
                    |row| row.get(0),
                )
                .optional()?;
            // Mirror only when acctrounds is missing or behind — never
            // regress an authoritative tracker round.
            let should_mirror = match acctrounds_present {
                None => true,
                Some(existing) => rnd > existing,
            };
            if should_mirror {
                conn.execute(
                    "INSERT OR REPLACE INTO acctrounds (id, rnd) VALUES ('acctbase', ?1)",
                    [rnd],
                )?;
            }
        }
    }

    // Step 2: migrate sync_* rows to namespaced catchpointstate ids.
    // Ensure the destination exists (it always should — schema creates
    // it — but be defensive in case migration runs before the rest of
    // the schema is in place during exotic flows).
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS catchpointstate (
             id     TEXT PRIMARY KEY,
             intval INTEGER,
             strval TEXT
         );",
    )?;
    for (legacy_key, new_key) in [
        ("sync_state", "algod_rust_sync_state"),
        ("sync_catchpoint_label", "algod_rust_sync_catchpoint_label"),
        ("sync_catchpoint_file", "algod_rust_sync_catchpoint_file"),
    ] {
        let val: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM algod_rust_meta WHERE key = ?1",
                [legacy_key],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(bytes) = val {
            let s = String::from_utf8(bytes).unwrap_or_default();
            conn.execute(
                "INSERT OR REPLACE INTO catchpointstate (id, strval) VALUES (?1, ?2)",
                rusqlite::params![new_key, s],
            )?;
        }
    }
    // sync_catchpoint_round was stored as string LE bytes of a decimal
    // (set_sync_meta uses `value.as_bytes()` on `round.to_string()`); we
    // round-trip through string here.
    let round_str: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM algod_rust_meta WHERE key = 'sync_catchpoint_round'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(bytes) = round_str {
        let s = String::from_utf8(bytes).unwrap_or_default();
        if let Ok(n) = s.parse::<i64>() {
            conn.execute(
                "INSERT OR REPLACE INTO catchpointstate (id, intval) VALUES (?1, ?2)",
                rusqlite::params!["algod_rust_sync_catchpoint_round", n],
            )?;
        }
    }

    // Step 3: verify the migrated round is recoverable from the
    // block header before dropping the legacy table. Otherwise an
    // upgraded DB whose `algod_rust_meta` had a committed round but
    // whose `blockdb.blocks` row for that round is missing or
    // undecodable would silently regress to zero-defaults on next
    // open. (Reachable because the apply path treats put_block
    // failures as warnings, not commit blockers.)
    //
    // We only enforce this when `algod_rust_meta` had a NON-ZERO
    // committed round to lose. A genesis-initialized DB writes
    // `current_round = 0` before any block exists (and so before
    // any `blockdb.blocks` row exists); treating that as a recovery
    // target would refuse the drop on legitimate first-open scenarios
    // — there is no committed state there to protect.
    let legacy_round_value: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM algod_rust_meta WHERE key = 'current_round'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let had_committed_round = matches!(
        legacy_round_value,
        Some(ref bytes) if bytes.len() == 8 && {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(bytes);
            u64::from_le_bytes(arr) > 0
        }
    );
    if had_committed_round {
        // `derive_chain_meta_from_latest_block` returns Ok(None) for
        // any condition that would land startup on zero defaults
        // (missing acctrounds, missing header, undecodable header).
        // Treat any of those as a refusal signal — the operator must
        // either keep running the pre-G6-part-3 binary or recover
        // via catchpoint re-sync.
        let derivable = derive_chain_meta_from_latest_block(conn).map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(
                format!("verify derivation before dropping algod_rust_meta: {e}").into(),
            )
        })?;
        if derivable.is_none() {
            return Err(rusqlite::Error::ToSqlConversionFailure(
                "algod_rust_meta retirement aborted: legacy cache had a committed round \
                 but the corresponding block header is missing or undecodable in \
                 blockdb.blocks. Dropping the cache would lose the committed round on \
                 next open. Recover by re-syncing this ledger from a catchpoint, or \
                 keep running the pre-G6-part-3 binary until that's possible."
                    .into(),
            ));
        }
    }

    // Step 4: drop the legacy table.
    conn.execute_batch("DROP TABLE IF EXISTS algod_rust_meta;")?;
    Ok(())
}

/// Snapshot of cached chain-level state derived from a block header.
/// Mirrors the subset of fields the runtime currently caches in the
/// (Rust-only) `algod_rust_meta` table — keeping the shape identical
/// lets the init path swap one source for the other without touching
/// downstream callers.
#[derive(Debug)]
pub(crate) struct ChainMetaFromHeader {
    pub current_round: Round,
    pub rewards_level: u64,
    pub rewards_rate: u64,
    pub rewards_residue: u64,
    pub rewards_recalculation_round: u64,
    pub fee_sink: Address,
    pub rewards_pool: Address,
    pub genesis_id: String,
    pub genesis_hash: [u8; 32],
    pub protocol: String,
    pub txn_counter: u64,
}

/// G6 part 1 — derive cached chain-level state from the **committed
/// tracker round**'s block header. The tracker round comes from
/// `acctrounds` (Go's `accountsRound`, id=`'acctbase'`), not from
/// `MAX(rnd) FROM blockdb.blocks`: the block archive is allowed to be
/// ahead of the tracker (sync writes blocks before applying them), and
/// trusting the archive MAX would advance `current_round`, rewards
/// state, and `txn_counter` past the committed accountbase round —
/// `next_round()` would then skip the next real block.
///
/// Returns `None` when `acctrounds` has no row yet (Rust-only DBs
/// before genesis apply, or freshly-opened empty DBs); the caller falls
/// back to the legacy `algod_rust_meta` table. Also returns `None` if
/// the corresponding header is missing or fails to decode.
///
/// Go's tracker has no `algod_rust_meta` analogue: it reads
/// `acctrounds.acctbase` and reconstructs live chain state from that
/// header on demand. This helper is the Phase-A reader-side
/// equivalent. Source: DOC-24 §G6; `BlockHeader` / `RewardsState` in
/// `../go-algorand/data/bookkeeping/block.go`.
pub(crate) fn derive_chain_meta_from_latest_block(
    conn: &Connection,
) -> Result<Option<ChainMetaFromHeader>, AlgoError> {
    // Tracker round = committed accountbase round (matches Go's
    // `accountsRound`). NULL/missing row → fall back to legacy meta.
    // Committed round = `acctrounds.acctbase` (Go's `accountsRound`).
    // The Rust apply path mirrors `current_round` into this row on every
    // `commit_block`; the catchpoint importer seeds it at cutover.
    // Pre-G6-part-3 DBs that only had the round cached in the legacy
    // `algod_rust_meta.current_round` have been migrated into
    // `acctrounds` by `migrate_off_algod_rust_meta` before this helper
    // ever runs.
    let acctrounds_rnd: Option<i64> = conn
        .query_row(
            "SELECT rnd FROM acctrounds WHERE id = 'acctbase'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| AlgoError::Ledger {
            message: format!("derive chain meta: acctrounds query: {e}"),
        })?;
    let Some(rnd) = acctrounds_rnd else {
        return Ok(None);
    };
    if rnd < 0 {
        tracing::warn!(
            "derive chain meta: acctrounds 'acctbase' is negative ({rnd}); skipping derivation"
        );
        return Ok(None);
    }
    if rnd == 0 {
        // Fresh / never-initialized DBs commonly have acctrounds at 0
        // with no matching block at round 0. Treat as "nothing to
        // derive yet" so genesis init can populate from scratch.
        // Genuine round-0 ledgers with a real header at 0 are
        // exercised exclusively in tests; production catchpoints
        // never produce a round-0 acctbase.
        let header_at_zero: Option<Vec<u8>> = conn
            .query_row(
                "SELECT hdrdata FROM blockdb.blocks WHERE rnd = 0",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| AlgoError::Ledger {
                message: format!("derive chain meta: round-0 probe: {e}"),
            })?;
        if header_at_zero.is_none() {
            return Ok(None);
        }
    }

    let hdrdata: Option<Vec<u8>> = conn
        .query_row(
            "SELECT hdrdata FROM blockdb.blocks WHERE rnd = ?1",
            params![rnd],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| AlgoError::Ledger {
            message: format!("derive chain meta: hdrdata fetch for round {rnd}: {e}"),
        })?;
    let Some(hdrdata) = hdrdata else {
        // Tracker has been told it's at round N but blockdb has no
        // matching header. This is the split-commit gap documented on
        // `reconcile_cross_file`; fall back rather than guessing.
        tracing::warn!(
            "derive chain meta: no header at tracker round {rnd}; falling back to legacy meta"
        );
        return Ok(None);
    };

    // Tolerate malformed headers by falling back to the legacy meta
    // table rather than refusing to open. In production a header that
    // failed to decode is a real corruption signal worth investigating,
    // but for Phase A we'd rather degrade to the algod_rust_meta cache
    // than brick the node — and unit tests that seed raw byte fixtures
    // (`put_block(_, _, b"hdr", _)`) rely on this behaviour.
    let hdr: BlockHeader = match rmp_serde::from_slice(&hdrdata) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(
                "derive chain meta: failed to decode BlockHeader at round {rnd} ({e}); \
                 falling back to algod_rust_meta"
            );
            return Ok(None);
        }
    };

    Ok(Some(ChainMetaFromHeader {
        current_round: hdr.round,
        rewards_level: hdr.rewards_level,
        rewards_rate: hdr.rewards_rate,
        rewards_residue: hdr.rewards_residue,
        rewards_recalculation_round: hdr.rewards_recalculation_round.0,
        fee_sink: hdr.fee_sink,
        rewards_pool: hdr.rewards_pool,
        genesis_id: hdr.genesis_id,
        genesis_hash: hdr.genesis_hash,
        protocol: hdr.current_protocol,
        txn_counter: hdr.txn_counter,
    }))
}

// ---------------------------------------------------------------------------
// SqliteLedger
// ---------------------------------------------------------------------------

/// SQLite-backed ledger storage implementing `LedgerStore`.
///
/// Uses a Go-compatible schema (matching go-algorand's trackerdb) for
/// account and resource storage. Chain-level metadata is stored in an
/// `algod_rust_meta` table.
/// Pre-mutation record for SQLite trie tracking.
enum SqlitePreMutation {
    Account {
        addr: Address,
        old_data: Option<Box<AccountData>>,
    },
    Resource {
        addr: Address,
        index: u64,
        old_blob: Option<Vec<u8>>,
        ctype: i64,
        old_affinity: u32,
    },
    Kv {
        /// Full kvstore key (e.g. "bx:" + big-endian app_id + box_name).
        full_key: Vec<u8>,
        /// Old value before mutation (None if key didn't exist).
        old_value: Option<Vec<u8>>,
    },
}

/// A read-only point-in-time snapshot of the ledger database.
///
/// Holds a separate SQLite connection with a deferred read transaction,
/// providing MVCC snapshot isolation in WAL mode. Account lookups through
/// this snapshot see a consistent view of the database as it existed when
/// the snapshot was created, regardless of concurrent writes on the main
/// connection.
///
/// The read transaction is released when this struct is dropped.
pub struct ReadSnapshot {
    conn: Connection,
}

impl ReadSnapshot {
    /// Look up an account by address from the snapshot connection.
    ///
    /// Returns the decoded `AccountData` if the account exists, or `None`
    /// if it does not. This read is isolated from concurrent writes.
    pub fn get_account(&self, addr: &Address) -> Option<AccountData> {
        let result: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT data FROM accountbase WHERE address = ?1",
                params![addr.0.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .unwrap_or_else(|e| {
                tracing::error!("ReadSnapshot: SQLite error querying account: {}", e);
                None
            });

        result.and_then(|data| {
            decode_account_data(&data)
                .map_err(|e| {
                    tracing::error!("ReadSnapshot: failed to decode account data: {}", e);
                    e
                })
                .ok()
        })
    }
}

impl Drop for ReadSnapshot {
    fn drop(&mut self) {
        // End the read transaction. Errors are non-fatal — the connection
        // will be closed immediately after this anyway.
        let _ = self.conn.execute_batch("ROLLBACK");
    }
}

pub struct SqliteLedger {
    conn: Connection,
    /// Ledger prefix for the on-disk database pair, or `None` for in-memory
    /// databases. The tracker file lives at `<prefix>.tracker.sqlite` and the
    /// block file at `<prefix>.block.sqlite`, matching
    /// `../go-algorand/ledger/ledger.go:327,336`. Used to open read-only
    /// snapshot connections for point-in-time account lookups without holding
    /// the main ledger mutex.
    db_prefix: Option<std::path::PathBuf>,
    /// In-memory lease table (leases are short-lived, no persistence needed).
    lease_table: LeaseTable,
    /// Snapshot of `lease_table` taken at `begin_block`, restored by
    /// `rollback_block`. The SQLite/trie rollback does not cover the in-memory
    /// lease table, so without this a partially-applied-then-rolled-back block
    /// (e.g. a group whose later transaction fails under Execute mode) would
    /// leave the earlier transactions' leases recorded, rejecting future
    /// transactions that reuse them as duplicates until expiry. `None` outside a
    /// `begin_block`/`commit_block` span.
    lease_snapshot: Option<LeaseTable>,
    /// Cached chain-level state (loaded from DB, flushed on commit).
    current_round: Round,
    rewards_level: u64,
    rewards_rate: u64,
    rewards_residue: u64,
    rewards_recalculation_round: u64,
    fee_sink: Address,
    rewards_pool: Address,
    genesis_id: String,
    genesis_hash: [u8; 32],
    protocol: String,
    /// Transaction counter from the latest committed block header.
    txn_counter: u64,
    /// Savepoint counter for nested transactions.
    savepoint_counter: AtomicU64,
    /// Whether we are inside a begin_block/commit_block transaction.
    in_block: bool,
    /// Merkle trie for account/resource state tracking.
    trie: Option<crate::merkle_trie::MerkleTrie>,
    /// Pre-mutation records for trie updates.
    pre_mutations: Vec<SqlitePreMutation>,
    /// Eviction target for the trie's in-memory page cache. `None` →
    /// [`crate::merkle_cache::DEFAULT_CACHED_NODES_TARGET`] (9000,
    /// matching go-algorand's `TrieCachedNodesCount`). Applied at
    /// `load_trie` time and to any trie set via `enable_trie` /
    /// `rebuild_trie_from_db`. PLAN-144 TASK-147.
    trie_cache_target: Option<usize>,
    /// In-memory rolling window of recent [`crate::state_delta::StateDelta`]s,
    /// keyed by round. Populated by [`Self::apply_block_caching_delta`] (used
    /// by the live sync driver in `bin/algod-rust`) and served by the REST API
    /// adapter's `get_state_delta_for_round`. Window size is
    /// [`crate::delta_cache::DEFAULT_WINDOW_SIZE`] (320 rounds), matching
    /// go-algorand's in-memory delta retention in `accountUpdates.deltas`
    /// (`../go-algorand/ledger/acctupdates.go` @ `v4.6.0-stable`). The cache is
    /// in-memory only — it does not survive a restart, matching Go.
    /// PLAN-36 TASK-128.
    delta_cache: crate::delta_cache::DeltaCache,

    /// Optional per-transaction-group state-delta tracer backing the
    /// `GET /v2/deltas/txn/group/...` endpoints (TASK-257). `None` by default,
    /// matching go-algorand's opt-in `TxnGroupDeltaTracer`; when absent the
    /// endpoints report 501. Enabled via [`Self::enable_group_delta_tracer`].
    group_delta_tracer: Option<crate::txn_group_delta_tracer::TxnGroupDeltaTracer>,

    /// Accumulated `accounttotals` per-status money/reward-unit deltas for
    /// the block currently open between `begin_block`/`commit_block`.
    /// Populated incrementally by `set_account`/`remove_account` and
    /// flushed to the `accounttotals` row as a single UPDATE in
    /// `commit_block` — see [`AccountTotalsDelta`] and issue #523.
    pending_totals_delta: AccountTotalsDelta,
}

/// In-memory accumulator for the per-round change to the `accounttotals`
/// aggregate row, mirroring go-algorand's `roundCowState.CalculateTotals`
/// (`ledger/eval/cow.go`): `DelAccount(previous) + AddAccount(updated)` for
/// every account touched during block application (`ledger/ledgercore/totals.go`
/// `AccountTotals.AddAccount`/`DelAccount`). Values are signed and summed
/// in `i128` to avoid overflow across a block's worth of deltas before the
/// single clamped flush to the `i64` SQLite columns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct AccountTotalsDelta {
    online_money: i128,
    online_reward_units: i128,
    offline_money: i128,
    offline_reward_units: i128,
    not_participating_money: i128,
    not_participating_reward_units: i128,
}

impl AccountTotalsDelta {
    fn is_zero(&self) -> bool {
        *self == Self::default()
    }

    /// Fold in one account snapshot's contribution to its status bucket,
    /// with `sign` `1` for an addition (new state) or `-1` for a removal
    /// (previous state) — mirrors go's `AddAccount`/`DelAccount` pair.
    ///
    /// `money` is the reward-extrapolated balance (go's `AccountData.Money`,
    /// `ledger/ledgercore/accountdata.go`): this repo's rewards model
    /// already stores each account's balance with rewards eagerly folded
    /// in up to that account's own `rewards_base` (see `rewards.rs`), so
    /// the extrapolation to the ledger's current `rewards_level` is just
    /// `compute_pending_rewards`.
    fn fold(&mut self, account: &AccountData, rewards_level: u64, sign: i128) {
        let pending = crate::rewards::compute_pending_rewards(account, rewards_level);
        let money = sign * (account.micro_algos as i128 + pending as i128);
        let reward_units = sign * (account.micro_algos / crate::rewards::REWARD_UNITS) as i128;
        match account.status {
            AccountStatus::Online => {
                self.online_money += money;
                self.online_reward_units += reward_units;
            }
            AccountStatus::Offline => {
                self.offline_money += money;
                self.offline_reward_units += reward_units;
            }
            AccountStatus::NotParticipating => {
                self.not_participating_money += money;
                self.not_participating_reward_units += reward_units;
            }
        }
    }
}

/// Whether the current `apply_block_with_delta` builder produces a
/// `StateDelta` that is safe to cache and return through the REST
/// `GET /v2/deltas/:round` endpoint for `block`. Consulted only by
/// `apply_block_caching_delta`, i.e. the *sync* path
/// (`bin/algod-rust/src/commands/sync.rs`) that replays blocks received
/// from peers. The `--dev`-mode self-produced-block path
/// (`bin/algod-rust/src/dev_producer.rs`) always runs `ApplyMode::Execute`
/// to build the block in the first place, so it calls
/// `SqliteLedger::cache_state_delta` directly with the real delta it
/// already has in hand and never consults this gate at all.
///
/// `Pay` and `Keyreg` payloads touch only the account-base fields of the
/// accounts already collected by `apply::collect_txn_addresses`, so they
/// were always admitted. Issue #586 then made `app_resources` /
/// `asset_resources` / `creatables` / `totals` real (previously
/// `TODO(#190)`-stubbed) for `Acfg` / `Axfer` / `Afrz` / `Appl`'s
/// **top-level** transaction fields (`apply.rs`'s step "2b"/"3b" resource-key
/// collection) — issue #603 widens this gate to admit `Acfg` / `Axfer` /
/// `Afrz` accordingly, since none of those three types can spawn inner
/// transactions, so top-level-only resource-key collection is already
/// complete for them.
///
/// `Appl` stays excluded: an approval program's `itxn_submit` can create/
/// update/destroy assets and apps, transfer assets, and opt other accounts'
/// apps in/out via *inner* transactions, but `apply.rs`'s resource-key
/// collection only walks `block.payset` (top-level transactions), never
/// inner transactions embedded in an `appl` call's `EvalDelta` — a real gap,
/// not just an unexercised one (see issue #604). Admitting `Appl` blocks
/// here before #604 is resolved would cache-and-serve a `StateDelta` that
/// silently omits inner-txn-only resource/creatable entries.
///
/// `Hb` (heartbeat) is intentionally excluded: `apply::apply_heartbeat`
/// mutates the heartbeat **target**'s `last_heartbeat`, but the target
/// address isn't currently included in the diff's address set, so a
/// heartbeat for an off-payset target would produce an incomplete `accts`
/// delta. `Stpf` / `Unknown(_)` remain excluded — `state_proof_next` is
/// still `TODO(#586)`-stubbed regardless of payset content.
///
/// See `apply_block_caching_delta` for the rest of the contract, including
/// the per-field gaps that remain even on cached rounds (#190, #604).
pub(crate) fn block_state_delta_is_complete(block: &algo_types::Block) -> bool {
    use algo_types::TxnType;
    block.payset.iter().all(|stx| {
        matches!(
            stx.txn.txn_type,
            TxnType::Pay | TxnType::Keyreg | TxnType::Acfg | TxnType::Axfer | TxnType::Afrz
        )
    })
}

/// Whether `block` contains any `appl` transaction (issue #574).
///
/// Box create/put/replace/resize/splice/delete only ever happen inside AVM
/// execution (`avm_context.rs`'s box-mutation call sites), and
/// go-algorand's own `ApplyData`/`EvalDelta` carries no box-content field
/// at all (`../go-algorand/data/transactions/teal.go`,
/// `data/transactions/transaction.go`) — box mutations are ledger-level
/// `KvMods`, entirely outside `ApplyData`. A block replayed purely from
/// recorded `EvalDelta` (`ApplyMode::Replay`) therefore can never observe a
/// box mutation, by construction. go-algorand itself has no
/// "replay-from-recorded-delta" fast path for normal block application —
/// `ledger/eval/eval.go`'s `Eval()` (used for every synced block, not just
/// proposal validation) always calls `eval.TransactionGroup()`, which runs
/// the AVM for real. `apply_block_caching_delta` uses this predicate to
/// route any block containing an `appl` call through `ApplyMode::Execute`
/// instead of the cheaper `Replay` path, so box storage stays correct for
/// normally-synced nodes too. Blocks with no `appl` transactions (even
/// `Acfg`/`Axfer`/`Afrz`/`Stpf`/`Hb`, none of which can touch box storage)
/// keep using the cheap Replay path.
fn block_has_app_call(block: &algo_types::Block) -> bool {
    use algo_types::TxnType;
    block
        .payset
        .iter()
        .any(|stx| stx.txn.txn_type == TxnType::Appl)
}

impl SqliteLedger {
    /// Open or create a SQLite ledger database pair.
    ///
    /// `path` may be either a bare prefix (e.g. `/foo/ledger`) or a legacy
    /// single-file path with a `.sqlite` / `.tracker.sqlite` / `.block.sqlite`
    /// suffix; the suffix is stripped to recover the prefix. The tracker
    /// database opens at `<prefix>.tracker.sqlite` and the block database is
    /// attached as the `blockdb` schema from `<prefix>.block.sqlite`,
    /// matching go-algorand's layout (`../go-algorand/ledger/ledger.go:327,336`).
    pub fn open(path: &Path) -> Result<Self, AlgoError> {
        let prefix = derive_ledger_prefix(path);
        Self::open_with_prefix(&prefix)
    }

    /// Open a ledger database pair using an explicit prefix (no suffix
    /// stripping). The tracker and block files are derived as
    /// `<prefix>.tracker.sqlite` and `<prefix>.block.sqlite`.
    pub fn open_with_prefix(prefix: &Path) -> Result<Self, AlgoError> {
        let tracker = tracker_path_for_prefix(prefix);
        let block = block_path_for_prefix(prefix);
        Self::open_split(&tracker, &block, Some(prefix.to_path_buf()))
    }

    /// Open a tracker + block database pair from fully explicit paths.
    ///
    /// `prefix` is the canonical prefix recorded on the resulting ledger
    /// instance; pass `None` only for ephemeral databases that should not be
    /// re-openable via `open_read_snapshot`.
    pub fn open_split(
        tracker_path: &Path,
        block_path: &Path,
        prefix: Option<std::path::PathBuf>,
    ) -> Result<Self, AlgoError> {
        let conn = Connection::open(tracker_path).map_err(|e| AlgoError::Ledger {
            message: format!(
                "sqlite open error opening tracker db {}: {e}",
                tracker_path.display()
            ),
        })?;
        // ATTACH the block file as the `blockdb` schema. Mirrors go-algorand's
        // two-file layout while keeping all SQL routed through a single
        // connection. The block file is parameter-bound to avoid quoting
        // issues with paths that contain a quote character.
        //
        // Cross-file commit semantics: SQLite uses a multi-database commit
        // sequence for transactions that touch both schemas. In WAL mode the
        // ordering is well-defined (each WAL is fsync'd in turn) but is NOT
        // a true atomic commit across files — a crash mid-commit can leave
        // the tracker and block schemas at adjacent rounds, with the tracker
        // ahead by at most one. This mirrors go-algorand's behavior (the
        // tracker and block DBs are also independent there) and is handled
        // by the sync/replay startup paths, which resume from
        // `last_committed_round()` and re-fetch any missing tail block. The
        // caller MUST NOT assume that "tracker says round N" implies
        // "blockdb contains round N's row".
        conn.execute(
            "ATTACH DATABASE ?1 AS blockdb",
            params![block_path.to_string_lossy().as_ref()],
        )
        .map_err(|e| AlgoError::Ledger {
            message: format!(
                "sqlite attach error opening block db {}: {e}",
                block_path.display()
            ),
        })?;
        Self::init(conn, prefix)
    }

    /// Open an in-memory database pair (for testing). Both the tracker and
    /// the attached `blockdb` schema are in-memory; no physical files are
    /// created and `open_read_snapshot` is unavailable.
    ///
    /// This deliberately keeps a single connection (with `ATTACH DATABASE
    /// ':memory:' AS blockdb`) — there is no separate on-disk file pair to
    /// reopen, so the production two-file behavior does not apply to
    /// in-memory tests.
    pub fn open_in_memory() -> Result<Self, AlgoError> {
        let conn = Connection::open_in_memory().map_err(|e| AlgoError::Ledger {
            message: format!("sqlite open error: {e}"),
        })?;
        // A fresh anonymous in-memory database is created per ATTACH call,
        // so the attached blockdb is fully isolated from the main schema.
        conn.execute_batch("ATTACH DATABASE ':memory:' AS blockdb;")
            .map_err(|e| AlgoError::Ledger {
                message: format!("sqlite attach in-memory blockdb error: {e}"),
            })?;
        Self::init(conn, None)
    }

    fn init(conn: Connection, db_prefix: Option<std::path::PathBuf>) -> Result<Self, AlgoError> {
        // Enable WAL mode for better concurrent read performance. ATTACH-ed
        // databases inherit their own journal mode, so we explicitly switch
        // both schemas to WAL. (`PRAGMA blockdb.journal_mode=WAL` is a no-op
        // for the in-memory case.)
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA blockdb.journal_mode=WAL;")
            .map_err(|e| AlgoError::Ledger {
                message: format!("pragma error: {e}"),
            })?;

        // G12 (TASK-109): refuse pre-v3 tracker DBs cleanly before
        // schema creation. Go's `performResourceTableMigration`
        // (`../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:399-534`)
        // splits the legacy single-`accountdata`-blob layout into the
        // modern `accountbase` + `resources` shape. Rust hasn't ported
        // that migration yet; opening such a DB would silently create
        // an empty `resources` table via `CREATE IF NOT EXISTS` and
        // leave the asset/app data stranded in `accountdata`. Detect
        // and refuse before the schema runs so the silent-corruption
        // path is closed.
        refuse_pre_v3_tracker_db(&conn)?;

        // Create tables if they don't exist. The block schema is run against
        // the `blockdb` schema; the tracker schema is the default `main`.
        conn.execute_batch(SCHEMA_TRACKER_SQL)
            .map_err(|e| AlgoError::Ledger {
                message: format!("schema creation error (tracker): {e}"),
            })?;
        conn.execute_batch(SCHEMA_BLOCK_SQL)
            .map_err(|e| AlgoError::Ledger {
                message: format!("schema creation error (block): {e}"),
            })?;

        // Upgrade pre-G5 Rust DBs whose `resources.ctype` is nullable to
        // Go's post-migration shape (NOT NULL DEFAULT -1). See DOC-24 §G5
        // and `../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:970`.
        migrate_resources_ctype_not_null(&conn)?;

        // G13: normalize NULL kvstore values to empty blobs (one-shot).
        // Mirrors Go's `performKVStoreNullBlobConversion`
        // (`../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:358-362`).
        // Without it, a Rust reader on a Go-written DB would see NULL where
        // Go intends an empty box value, and a `Vec<u8>` column read would
        // error instead of returning the empty value.
        //
        // We write `x''` (empty BLOB literal) rather than Go's `''` (empty
        // TEXT literal) because rusqlite's column-type checks treat them
        // differently: a TEXT-typed empty value reads back as
        // `InvalidColumnType` under `row.get::<_, Vec<u8>>`, while a BLOB
        // empty reads cleanly as `Vec::new()`. Semantically identical to
        // Go (both are "not NULL, length zero").
        //
        // Performance: `kvstore.value` is not indexed, so a NULL-check
        // would scan the entire box store on every open. Persist a marker
        // in `catchpointstate` (Go's own k-v table — Go ignores unknown
        // keys) and skip the UPDATE once the migration has run.
        normalize_kvstore_nulls(&conn).map_err(|e| AlgoError::Ledger {
            message: format!("kvstore NULL normalization error: {e}"),
        })?;

        // G6 part 2 (TASK-106): rename any legacy Rust-only
        // `catchpointstate` keys to their Go-canonical equivalents.
        // Currently a no-op — Rust has only ever written Go-canonical
        // keys — but the call point is wired in so a future rename
        // lands here without churn at the init site. See
        // `crate::catchpoint::state_keys` for the canonical list.
        crate::catchpoint::state_keys::migrate_legacy_keys(&conn).map_err(|e| {
            AlgoError::Ledger {
                message: format!("catchpointstate key migration error: {e}"),
            }
        })?;

        // G6 part 3 (TASK-107): retire the legacy Rust-only
        // `algod_rust_meta` table.
        //
        // 1. Migration: an upgrade from a pre-G6-part-3 binary leaves
        //    the round cached in `algod_rust_meta.current_round` but
        //    NOT in `acctrounds.acctbase` (Rust's apply path didn't
        //    mirror it back). Copy the value across before dropping
        //    so derivation has a tracker round to read on next open.
        // 2. Sync-state migration: the four `sync_*` keys move to
        //    `catchpointstate` with `algod_rust_sync_*` namespaced ids
        //    (precedent: TASK-110's kvstore-null marker; Go ignores
        //    unknown keys, so the rows are safe to leave behind when
        //    a Go binary reopens the DB).
        // 3. Drop the table.
        migrate_off_algod_rust_meta(&conn).map_err(|e| AlgoError::Ledger {
            message: format!("algod_rust_meta retirement error: {e}"),
        })?;

        // Trie persistence (PLAN-35 G2 / PLAN-36 G4 / DOC-24):
        //
        // The runtime trie is persisted exclusively as Go-compatible
        // pages in `accounthashes` (see `crate::merkle_committer`).
        // PLAN-35 G2 (TASK-136) ported the page-shaped format and
        // PLAN-36 G4 (TASK-118) dropped the Rust-only single-blob
        // `merkle_trie` table from the schema. Older Rust DBs that
        // were initialized before G4 may still carry an orphan
        // `merkle_trie` row; the runtime ignores it and a fresh
        // tracker DB contains no such table. Existing-DB migration
        // (DROP / recovery from the legacy blob) is intentionally
        // out of scope for Phase B writer parity — recovery is via
        // catchpoint re-sync, which lands the new format.

        // Load cached chain-level state. Sole source: derive from
        // `acctrounds.acctbase` (Go's tracker round) + that round's
        // `BlockHeader` in `blockdb.blocks`. G6 part 3 removed the
        // legacy `algod_rust_meta` fallback; a fresh DB with neither
        // source populated lands on zero-defaults, which the genesis
        // / catchpoint init paths overwrite before the runtime is
        // exposed to consumers.
        let (
            current_round,
            rewards_level,
            rewards_rate,
            rewards_residue,
            rewards_recalculation_round,
            fee_sink,
            rewards_pool,
            genesis_id,
            genesis_hash,
            protocol,
            txn_counter,
        ) = match derive_chain_meta_from_latest_block(&conn)? {
            Some(m) => (
                m.current_round,
                m.rewards_level,
                m.rewards_rate,
                m.rewards_residue,
                m.rewards_recalculation_round,
                m.fee_sink,
                m.rewards_pool,
                m.genesis_id,
                m.genesis_hash,
                m.protocol,
                m.txn_counter,
            ),
            None => (
                Round(0),
                0,
                0,
                0,
                0,
                Address::ZERO,
                Address::ZERO,
                String::new(),
                [0u8; 32],
                String::new(),
                0,
            ),
        };

        Ok(Self {
            conn,
            db_prefix,
            lease_table: LeaseTable::new(),
            lease_snapshot: None,
            current_round,
            rewards_level,
            rewards_rate,
            rewards_residue,
            rewards_recalculation_round,
            fee_sink,
            rewards_pool,
            genesis_id,
            genesis_hash,
            protocol,
            txn_counter,
            savepoint_counter: AtomicU64::new(0),
            in_block: false,
            trie: None,
            pre_mutations: Vec::new(),
            trie_cache_target: None,
            delta_cache: crate::delta_cache::DeltaCache::with_default_window(),
            group_delta_tracer: None,
            pending_totals_delta: AccountTotalsDelta::default(),
        })
    }

    /// Return a reference to the in-memory lease table.
    ///
    /// Used by the block evaluator to snapshot the current lease state
    /// while holding the ledger lock.
    pub fn lease_table(&self) -> &LeaseTable {
        &self.lease_table
    }

    /// Open a read-only snapshot connection to the same database files.
    ///
    /// The returned [`ReadSnapshot`] holds a separate SQLite connection with
    /// a deferred read transaction, which in WAL mode provides a
    /// point-in-time consistent view of the tracker database. This allows the
    /// block evaluator to read account data without re-acquiring the main
    /// ledger mutex, eliminating the risk of seeing data from a different
    /// round if the ledger advances concurrently (e.g., from catchup).
    ///
    /// Only the tracker file is opened here — `ReadSnapshot` exists solely
    /// for account lookups, which never touch the block archive.
    ///
    /// Returns `None` for in-memory databases (which cannot share state
    /// across connections).
    pub fn open_read_snapshot(&self) -> Option<ReadSnapshot> {
        let prefix = self.db_prefix.as_ref()?;
        let tracker_path = tracker_path_for_prefix(prefix);
        let conn = match Connection::open_with_flags(
            &tracker_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("failed to open read snapshot: {}", e);
                return None;
            }
        };
        // Begin a deferred read transaction. In WAL mode this pins the
        // reader to the current database state, so subsequent reads see a
        // consistent snapshot even if the writer commits new data.
        if let Err(e) = conn.execute_batch("BEGIN DEFERRED") {
            tracing::warn!("failed to open read snapshot: {}", e);
            return None;
        }
        Some(ReadSnapshot { conn })
    }

    /// Load the trie from the paged `accounthashes` table, or rebuild from
    /// DB contents if no paged state exists.
    ///
    /// PLAN-130 TASK-136 swap: the runtime trie is persisted as pages
    /// in `accounthashes` (the Go-compatible format), via
    /// [`crate::merkle_committer::SqliteMerkleCommitter`]. PLAN-36 G4
    /// (TASK-118) dropped the legacy Rust-only `merkle_trie`
    /// single-blob table from the schema, so the page-shaped store is
    /// now the sole on-disk trie representation.
    pub fn load_trie(&mut self) -> Result<(), AlgoError> {
        // PLAN-144 TASK-146: lazy on-demand page loading.
        //
        // For on-disk ledgers we install an owned read-only
        // [`crate::merkle_committer::OwnedSqliteCommitter`] as the
        // trie cache's `lazy_loader`. Subsequent page reads go through
        // that connection (SQLite WAL allows concurrent readers); the
        // write path still uses [`SqliteMerkleCommitter`] against
        // `self.conn` inside the block transaction.
        //
        // For in-memory ledgers (`db_prefix is None`) the lazy loader
        // can't be constructed — `Connection::open_in_memory` returns a
        // distinct DB per call. In-memory ledgers therefore skip the
        // lazy path and rebuild from `accountbase` / `resources` /
        // `kvstore`; this matches the historical behavior, since
        // in-memory DBs never survive process restart anyway.
        let load_result: Result<Option<crate::merkle_trie::MerkleTrie>, AlgoError> =
            match self.db_prefix.as_ref() {
                Some(prefix) => {
                    let tracker = tracker_path_for_prefix(prefix);
                    match crate::merkle_committer::OwnedSqliteCommitter::open_active(&tracker) {
                        Ok(owned) => crate::merkle_trie::MerkleTrie::load(Box::new(owned)),
                        Err(e) => {
                            tracing::warn!(
                                "merkle_trie: could not open owned lazy-loader for {}: {e}",
                                tracker.display()
                            );
                            Ok(None)
                        }
                    }
                }
                None => Ok(None),
            };
        let trie = match load_result {
            Ok(Some(t)) => t,
            Ok(None) => {
                tracing::debug!(
                    "merkle_trie: no accounthashes metadata page found (or in-memory ledger); rebuilding from DB"
                );
                self.rebuild_trie_from_db()?
            }
            Err(e) => {
                tracing::warn!("merkle_trie: accounthashes load failed ({e}); rebuilding from DB");
                self.rebuild_trie_from_db()?
            }
        };

        self.trie = Some(trie);
        // Re-apply the configured cache target. `load_trie` is also
        // called from `rollback_block`, so the target must stick across
        // reloads.
        self.apply_trie_cache_target();
        self.pre_mutations.clear();
        Ok(())
    }

    /// Rebuild the trie from all accounts and resources currently in the DB.
    fn rebuild_trie_from_db(&self) -> Result<crate::merkle_trie::MerkleTrie, AlgoError> {
        use crate::trie_hash::{
            account_hash_v6, extract_raw_affinity, kv_hash_v6, resource_hash_v6_with_kind,
            HashKind, ELEMENT_SIZE,
        };

        let mut trie = crate::merkle_trie::MerkleTrie::new(ELEMENT_SIZE);

        // 1. Process all accounts from accountbase.
        {
            let mut stmt = self
                .conn
                .prepare("SELECT address, data FROM accountbase")
                .map_err(|e| AlgoError::Ledger {
                    message: format!("prepare accounts for trie rebuild: {e}"),
                })?;

            let rows = stmt
                .query_map([], |row| {
                    let addr_bytes: Vec<u8> = row.get(0)?;
                    let data: Vec<u8> = row.get(1)?;
                    Ok((addr_bytes, data))
                })
                .map_err(|e| AlgoError::Ledger {
                    message: format!("query accounts for trie rebuild: {e}"),
                })?;

            for row in rows {
                let (addr_bytes, data) = row.map_err(|e| AlgoError::Ledger {
                    message: format!("read account row: {e}"),
                })?;
                if addr_bytes.len() != 32 {
                    return Err(AlgoError::Ledger {
                        message: format!(
                            "bad address length {} (expected 32) in accountbase",
                            addr_bytes.len()
                        ),
                    });
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&addr_bytes);
                let addr = Address(arr);
                let acct = decode_account_data(&data)?;
                let elem = account_hash_v6(&addr, &acct);
                trie.add(&elem).map_err(|e| AlgoError::Ledger {
                    message: format!("trie add account: {e}"),
                })?;
            }
        }

        // 2. Process all resources.
        {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT r.addrid, r.aidx, r.ctype, r.data, a.address, a.data \
                     FROM resources r \
                     JOIN accountbase a ON a.rowid = r.addrid",
                )
                .map_err(|e| AlgoError::Ledger {
                    message: format!("prepare resources for trie rebuild: {e}"),
                })?;

            let rows = stmt
                .query_map([], |row| {
                    let _addrid: i64 = row.get(0)?;
                    let aidx: i64 = row.get(1)?;
                    let ctype: i64 = row.get(2)?;
                    let rdata: Vec<u8> = row.get(3)?;
                    let addr_bytes: Vec<u8> = row.get(4)?;
                    let acct_data: Vec<u8> = row.get(5)?;
                    Ok((aidx, ctype, rdata, addr_bytes, acct_data))
                })
                .map_err(|e| AlgoError::Ledger {
                    message: format!("query resources for trie rebuild: {e}"),
                })?;

            for row in rows {
                let (aidx, ctype, rdata, addr_bytes, _acct_data) =
                    row.map_err(|e| AlgoError::Ledger {
                        message: format!("read resource row: {e}"),
                    })?;
                if addr_bytes.len() != 32 {
                    return Err(AlgoError::Ledger {
                        message: format!(
                            "bad address length {} (expected 32) for resource aidx={aidx}",
                            addr_bytes.len()
                        ),
                    });
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&addr_bytes);
                let addr = Address(arr);

                // Use the resource's own UpdateRound for affinity, matching Go's
                // ResourcesHashBuilderV6 which passes resData.UpdateRound.
                let affinity = extract_raw_affinity(&rdata);

                let kind = if ctype == CTYPE_APP {
                    HashKind::App
                } else {
                    HashKind::Asset
                };

                let elem = resource_hash_v6_with_kind(&addr, aidx as u64, &rdata, affinity, kind);
                trie.add(&elem).map_err(|e| AlgoError::Ledger {
                    message: format!("trie add resource: {e}"),
                })?;
            }
        }

        // 3. Process all KV (box) entries from kvstore.
        {
            let mut stmt = self
                .conn
                .prepare("SELECT key, value FROM kvstore")
                .map_err(|e| AlgoError::Ledger {
                    message: format!("prepare kvstore for trie rebuild: {e}"),
                })?;

            let rows = stmt
                .query_map([], |row| {
                    let key: Vec<u8> = row.get(0)?;
                    let value: Vec<u8> = row.get(1)?;
                    Ok((key, value))
                })
                .map_err(|e| AlgoError::Ledger {
                    message: format!("query kvstore for trie rebuild: {e}"),
                })?;

            for row in rows {
                let (key, value) = row.map_err(|e| AlgoError::Ledger {
                    message: format!("read kvstore row: {e}"),
                })?;
                let elem = kv_hash_v6(&key, &value);
                trie.add(&elem).map_err(|e| AlgoError::Ledger {
                    message: format!("trie add kv: {e}"),
                })?;
            }
        }

        Ok(trie)
    }

    /// Record the old resource blob before mutation, for trie tracking.
    fn record_resource_pre_mutation(&mut self, addr: &Address, index: u64, ctype: i64) {
        if self.trie.is_some() {
            let old_blob = self.get_rowid(addr).and_then(|rowid| {
                self.conn
                    .query_row(
                        "SELECT data FROM resources WHERE addrid = ?1 AND aidx = ?2 AND ctype = ?3",
                        params![rowid, index as i64, ctype],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .optional()
                    .unwrap_or(None)
            });
            // Derive affinity from the resource blob, not the account,
            // matching Go's ResourcesHashBuilderV6 which uses resData.UpdateRound.
            let old_affinity = old_blob
                .as_ref()
                .map(|b| crate::trie_hash::extract_raw_affinity(b))
                .unwrap_or(0);
            self.pre_mutations.push(SqlitePreMutation::Resource {
                addr: *addr,
                index,
                old_blob,
                ctype,
                old_affinity,
            });
        }
    }

    /// Begin a block-level transaction.
    pub fn begin_block(&mut self) -> Result<(), AlgoError> {
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| AlgoError::Ledger {
                message: format!("begin block error: {e}"),
            })?;
        // Snapshot the in-memory lease table so rollback_block can restore it —
        // the SQLite/trie transaction does not cover it.
        self.lease_snapshot = Some(self.lease_table.clone());
        self.in_block = true;
        // Issue #523: start this block's `accounttotals` delta accumulator
        // clean. Guards against `set_account`/`remove_account` calls made
        // outside any begin_block/commit_block span (a supported pattern in
        // this codebase's own tests, and genesis/catchpoint bootstrap code)
        // leaking into the next real block's flush.
        self.pending_totals_delta = AccountTotalsDelta::default();
        Ok(())
    }

    /// Commit the current block-level transaction and flush chain state.
    /// Override the in-memory page-cache size for the trie. Takes
    /// effect immediately on the currently loaded trie (if any) and is
    /// applied to any future trie reloaded via `load_trie` /
    /// `enable_trie`. Eviction occurs at the end of every successful
    /// [`SqliteLedger::commit_block`] so the in-memory cache is
    /// bounded by `target` after every block. PLAN-144 TASK-147.
    pub fn set_trie_cache_target(&mut self, target: usize) {
        self.trie_cache_target = Some(target);
        self.apply_trie_cache_target();
    }

    /// Apply the configured `trie_cache_target` (or
    /// [`crate::merkle_cache::DEFAULT_CACHED_NODES_TARGET`] when unset)
    /// to the currently loaded trie, if any.
    fn apply_trie_cache_target(&mut self) {
        let target = self
            .trie_cache_target
            .unwrap_or(crate::merkle_cache::DEFAULT_CACHED_NODES_TARGET);
        if let Some(t) = self.trie.as_mut() {
            t.set_cache_target(target);
        }
    }

    // ---- Delta cache helpers below; see PLAN-36 TASK-128 ----

    /// Look up a recent state delta from the in-memory rolling window.
    ///
    /// Returns `Some(StateDelta)` when `round` falls inside the cache window
    /// (default 320 rounds back from the latest cached round) and `None`
    /// otherwise. Mirrors go-algorand's `accountUpdates.deltas` window served
    /// from `daemon/algod/api/server/v2/handlers.go::GetLedgerStateDelta`.
    ///
    /// The returned delta is a clone — the cache continues to own its entry
    /// so the next block-apply can evict it safely.
    pub fn get_cached_state_delta(&self, round: u64) -> Option<crate::state_delta::StateDelta> {
        self.delta_cache.get(round).cloned()
    }

    /// Insert (or overwrite) a state delta into the in-memory rolling window.
    ///
    /// The cache evicts entries older than `round - window_size + 1` after the
    /// insert, so callers don't need to evict explicitly. Public so tests and
    /// alternative apply drivers (catchpoint replay, future block producer)
    /// can populate the cache without going through
    /// [`Self::apply_block_caching_delta`].
    pub fn cache_state_delta(&mut self, round: u64, delta: crate::state_delta::StateDelta) {
        self.delta_cache.insert(round, delta);
    }

    /// Smallest round currently present in the in-memory delta cache.
    ///
    /// Used by callers that need to distinguish "round outside the rolling
    /// window" (caller should respond `NotFound`) from "round inside the
    /// window but never cached" (an internal invariant violation). Returns
    /// `0` before any delta has been inserted.
    pub fn delta_cache_min_round(&self) -> u64 {
        self.delta_cache.min_round()
    }

    /// Number of entries currently held in the delta cache. Test helper.
    pub fn delta_cache_len(&self) -> usize {
        self.delta_cache.len()
    }

    /// Reconstruct an application's full box-name/value map as of `round`
    /// (a round strictly older than the latest committed round), by walking
    /// the in-memory delta cache's `kv_mods` backward from latest down to
    /// `round + 1` and applying each touched key's `old_data` on top of the
    /// current committed state (issue #570).
    ///
    /// Returns `None` when `round` is not reconstructable: at or beyond
    /// latest (the caller should use the normal, non-historical lookup
    /// instead), or older than [`Self::delta_cache_min_round`] -- the
    /// `DeltaCache`'s rolling window, analogous to go-algorand's own
    /// `RoundOffsetError` for a round outside `accountUpdates.deltas`'
    /// lookback (`ledger/acctupdates.go`).
    ///
    /// Walking backward and taking the *last-applied* (i.e. smallest-round)
    /// touch's `old_data` for each key is what recovers the value at the
    /// round boundary: `kv_mods` for round `r` records the box's value
    /// immediately before `r`'s block was applied, so the smallest `r` in
    /// `(round, latest]` that touched a given key tells us exactly what
    /// that key held at the end of `round`. A key untouched anywhere in
    /// that range is unchanged since `round`, so the current committed
    /// value is already correct and needs no adjustment.
    pub fn reconstruct_box_state_at_round(
        &self,
        app_id: u64,
        round: u64,
    ) -> Option<HashMap<Vec<u8>, Vec<u8>>> {
        let latest = self.current_round().0;
        if round >= latest {
            return None;
        }
        if round < self.delta_cache_min_round() {
            return None;
        }

        // Start from the current committed box state for this app.
        let mut state: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        for name in self.box_keys_for_app(app_id) {
            if let Some(v) = self.get_box(app_id, &name) {
                state.insert(name, v);
            }
        }

        let app_prefix = make_box_key(app_id, b"");
        for r in (round + 1..=latest).rev() {
            let Some(delta) = self.delta_cache.get(r) else {
                continue;
            };
            for (key, kv_delta) in &delta.kv_mods {
                let Some(name) = key.strip_prefix(app_prefix.as_slice()) else {
                    continue;
                };
                if kv_delta.old_data.is_empty() {
                    state.remove(name);
                } else {
                    state.insert(name.to_vec(), kv_delta.old_data.clone());
                }
            }
        }

        Some(state)
    }

    /// Historical variant of [`box_keys_by_prefix_paginated`
    /// default](crate::store_trait::LedgerStore::box_keys_by_prefix_paginated):
    /// filters, sorts, and paginates [`Self::reconstruct_box_state_at_round`]'s
    /// output the same way the live path does, so callers get identical
    /// ordering/pagination semantics for a historical round (issue #570).
    /// Returns `None` when the round can't be reconstructed (see
    /// `reconstruct_box_state_at_round`).
    #[allow(clippy::type_complexity)]
    pub fn lookup_kv_pairs_by_prefix_at_round(
        &self,
        app_id: u64,
        round: u64,
        prefix: &[u8],
        cursor: Option<&[u8]>,
        limit: Option<u64>,
        include_values: bool,
    ) -> Option<(crate::store_trait::BoxPage, bool)> {
        let state = self.reconstruct_box_state_at_round(app_id, round)?;

        let mut names: Vec<Vec<u8>> = state
            .keys()
            .filter(|name| name.starts_with(prefix))
            .filter(|name| match cursor {
                Some(c) => name.as_slice() > c,
                None => true,
            })
            .cloned()
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
                    state.get(&name).cloned()
                } else {
                    None
                };
                (name, value)
            })
            .collect();

        Some((results, more_data))
    }

    /// Apply a block and, when safe, populate the in-memory delta cache as
    /// a side effect.
    ///
    /// The cache is populated only when [`block_state_delta_is_complete`]
    /// reports the block's payset is fully covered by the current
    /// [`crate::apply::apply_block_with_delta`] builder — practically that
    /// means a payset of only `Pay` / `Keyreg` / `Hb` transactions. Blocks
    /// that contain `Acfg` / `Axfer` / `Afrz` / `Appl` / `Stpf` transactions
    /// (or any unrecognized type) skip the delta build entirely — the REST
    /// endpoint returns `NotFound` for those rounds, which is strictly
    /// preferable to serving a known-incomplete `StateDelta` (app / asset /
    /// kv deltas, `creatables`, and `state_proof_next` are all still
    /// `TODO(#190)`-stubbed in the builder). Of those uncached blocks, one
    /// containing an `appl` call still runs [`crate::apply::ApplyMode::Execute`]
    /// (real AVM execution) rather than the cheaper bare
    /// [`crate::apply::apply_block`] Replay path — see [`block_has_app_call`]
    /// (issue #574) for why: box mutations only happen inside AVM
    /// execution, and go-algorand's own `EvalDelta`/`ApplyData` carries no
    /// box-content field for `Replay` to fall back on.
    ///
    /// **Known limitation even on cached rounds** (#190): a few
    /// `StateDelta` fields are still unconditionally defaulted by
    /// `apply_block_with_delta` regardless of payset content —
    /// `totals` (zero), `prev_timestamp` (zero), and `state_proof_next`
    /// (zero). Consumers that rely on these fields must wait for #190 to
    /// land before trusting the response. The `accts` / `txids` /
    /// `txleases` / `hdr` fields are computed correctly under the gating
    /// rule above, which is the primary use case today (account-balance /
    /// keyreg replay).
    ///
    /// The wider node-level apply driver
    /// (`bin/algod-rust/src/commands/sync.rs`) calls this instead of the
    /// bare `apply_block` so a node serving REST populates the cache as a
    /// normal side effect of block application.
    /// Enable per-transaction-group delta tracking with the given lookback
    /// window, so the `GET /v2/deltas/txn/group/...` endpoints serve data
    /// instead of 501. Opt-in, matching go-algorand's configured tracer.
    pub fn enable_group_delta_tracer(&mut self, lookback: u64) {
        self.group_delta_tracer = Some(crate::txn_group_delta_tracer::TxnGroupDeltaTracer::new(
            lookback,
        ));
    }

    /// Whether the per-group delta tracer is enabled.
    pub fn group_delta_tracer_enabled(&self) -> bool {
        self.group_delta_tracer.is_some()
    }

    /// The per-group delta for a transaction ID or group ID, if retained.
    pub fn txn_group_delta_for_id(
        &self,
        id: &algo_types::Digest,
    ) -> Option<crate::state_delta::StateDeltaSubset> {
        self.group_delta_tracer
            .as_ref()
            .and_then(|t| t.get_delta_for_id(id).cloned())
    }

    /// All per-group deltas (with their IDs) for a round, if the round is
    /// retained. Returns `None` when the round is outside the window or
    /// uncaptured (so the handler can report 404, matching go).
    pub fn txn_group_deltas_for_round(
        &self,
        round: u64,
    ) -> Option<Vec<crate::txn_group_delta_tracer::TxnGroupDelta>> {
        self.group_delta_tracer
            .as_ref()
            .and_then(|t| t.get_deltas_for_round(round).map(|g| g.to_vec()))
    }

    pub fn apply_block_caching_delta(
        &mut self,
        block: &algo_types::Block,
    ) -> Result<(), AlgoError> {
        if block_state_delta_is_complete(block) {
            let round = block.round.0;
            // Feed the per-group delta tracer (opt-in) on a scratch SAVEPOINT
            // that is rolled back, so the authoritative per-round commit below
            // is unchanged. The Execute-mode group capture and the Replay-mode
            // per-round delta both commit the block, so they cannot share one
            // apply; the scratch apply keeps them independent.
            if let Some(mut tracer) = self.group_delta_tracer.take() {
                // The SQLite SAVEPOINT rolls back account/DB state, but the
                // apply path also mutates in-memory ledger fields (the round
                // counter, rewards state, reward addresses, txn counter, and
                // lease table) that the savepoint does not cover. Save and
                // restore exactly those so the scratch capture leaves the ledger
                // identical for the authoritative apply below.
                let saved_round = self.current_round();
                let saved_level = self.rewards_level();
                let saved_rate = self.rewards_rate();
                let saved_residue = self.rewards_residue();
                let saved_recalc = self.rewards_recalculation_round();
                let saved_fee_sink = self.fee_sink();
                let saved_rewards_pool = self.rewards_pool();
                let saved_txn_counter = self.txn_counter();
                // The in-memory lease table is not covered by the savepoint
                // either; without restoring it the authoritative apply below
                // sees the scratch apply's leases as duplicates and rejects any
                // block whose transactions carry a nonzero lease.
                let saved_leases = self.lease_table.clone();
                // Trie-tracking pre-mutations are an append-only in-memory log
                // (cleared only at commit, which this path does not call), so the
                // scratch apply's entries must be truncated away or they would be
                // consumed by the authoritative commit's trie finalization.
                let saved_pre_mutations_len = self.pre_mutations.len();
                // Issue #523: the scratch apply's `set_account`/`remove_account`
                // calls also accumulate into `pending_totals_delta`; without
                // restoring it the authoritative apply below would double-count
                // every account touched by the scratch run on top of its own.
                let saved_totals_delta = self.pending_totals_delta;

                let sp = self.snapshot(&[]);
                let _ = crate::apply::apply_block_capturing_group_deltas(self, block, &mut tracer);
                self.restore_snapshot(sp);
                self.pre_mutations.truncate(saved_pre_mutations_len);
                self.pending_totals_delta = saved_totals_delta;

                self.set_current_round(saved_round);
                self.set_rewards_level(saved_level);
                self.set_rewards_rate(saved_rate);
                self.set_rewards_residue(saved_residue);
                self.set_rewards_recalculation_round(saved_recalc);
                self.set_fee_sink(saved_fee_sink);
                self.set_rewards_pool(saved_rewards_pool);
                self.set_txn_counter(saved_txn_counter);
                self.lease_table = saved_leases;

                self.group_delta_tracer = Some(tracer);
            }
            let delta = crate::apply::apply_block_with_delta(self, block)?;
            self.cache_state_delta(round, delta);
            Ok(())
        } else {
            // Incomplete block: still advance the group window so stale deltas
            // are evicted on schedule (the round itself stays unretained →
            // endpoints report it unavailable).
            if let Some(t) = self.group_delta_tracer.as_mut() {
                t.advance(block.round.0);
            }
            // Payset contains a transaction type the builder doesn't yet
            // fully cover. Leave the cache empty — the handler will return
            // `NotFound` for this round rather than a partial delta. Still
            // advance the rolling window so stale entries from earlier
            // cached rounds are evicted on schedule even when long runs of
            // unsupported blocks intervene.
            //
            // Issue #574: a block containing an `appl` call must still run
            // the AVM for real (`ApplyMode::Execute`), or box mutations
            // (create/put/replace/resize/splice/delete) are silently never
            // applied to `LedgerStore` — see `block_has_app_call`'s doc
            // comment for why `ApplyMode::Replay` can never observe them.
            // Blocks with no `appl` transaction (Acfg/Axfer/Afrz/Stpf/Hb)
            // cannot touch box storage, so they keep the cheaper Replay
            // path.
            if block_has_app_call(block) {
                crate::apply::apply_block_with_mode(self, block, crate::apply::ApplyMode::Execute)?;
            } else {
                crate::apply::apply_block(self, block)?;
            }
            self.delta_cache.advance(block.round.0);
            Ok(())
        }
    }

    /// Flush the block's accumulated `accounttotals` delta ([`AccountTotalsDelta`])
    /// to the persisted row, then reset the accumulator.
    ///
    /// Mirrors go-algorand's `roundCowState.CalculateTotals` writing
    /// `cb.mods.Totals` once per round (`ledger/eval/cow.go`) rather than on
    /// every individual account touch:
    ///
    /// ```go
    /// totals := cb.prevTotals
    /// totals.ApplyRewards(mods.Hdr.RewardsLevel, &ot)
    /// for addr, delta := range accountDeltas { ... DelAccount/AddAccount ... }
    /// ```
    ///
    /// `ApplyRewards` (`ledger/ledgercore/totals.go`) bumps `Online`/`Offline`
    /// (never `NotParticipating` — it doesn't earn rewards) by
    /// `(newLevel - oldLevel) * RewardUnits`, using the reward-unit counts
    /// *as of before this round's account touches* — i.e. computed from the
    /// same row snapshot this function also applies `delta` to, before either
    /// is written back. This matters because most rounds in a low-activity
    /// network (e.g. a smoke-test cluster with no real transaction traffic)
    /// touch no accounts at all (`delta.is_zero()`), yet `RewardsLevel` still
    /// advances every round the pool has a nonzero rate — skipping the flush
    /// on `delta.is_zero()` alone would leave every online/offline account's
    /// accrued-but-untouched rewards permanently unreflected in `GetSupply`.
    ///
    /// No-op if the row hasn't been seeded yet — e.g. a raw `SqliteLedger` in
    /// tests that never called `seed_account_totals_from_genesis` /
    /// catchpoint import. Values are clamped to `[0, i64::MAX]` on the way
    /// into the `i64` columns: a negative result would indicate an accounting
    /// bug upstream (conservation of money means a correctly-computed delta
    /// can't drive a bucket below zero), but this is a persistence layer, not
    /// the place to panic on untrusted-input-adjacent arithmetic — see
    /// CLAUDE.md's Result-not-panics bar.
    fn flush_pending_account_totals_delta(&mut self) -> Result<(), AlgoError> {
        let delta = std::mem::take(&mut self.pending_totals_delta);
        let row: Option<(i64, i64, i64, i64, i64, i64, i64)> = self
            .conn
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
            .optional()
            .map_err(|e| AlgoError::Ledger {
                message: format!("flush_pending_account_totals_delta read error: {e}"),
            })?;
        let Some((online, online_ru, offline, offline_ru, notpart, notpart_ru, row_level)) = row
        else {
            // Row not seeded — nothing to maintain incrementally (e.g. a
            // catchpoint-only or unseeded test ledger).
            return Ok(());
        };
        let new_level = self.rewards_level;
        let row_level = row_level.max(0) as u64;
        if delta.is_zero() && new_level == row_level {
            return Ok(());
        }
        // Rewards accrued since the row's last flush, using the PRE-round
        // reward-unit counts (`online_ru`/`offline_ru`, not yet touched by
        // `delta` below) — matches go's `ApplyRewards` running before
        // `AddAccount`/`DelAccount` each round.
        let level_delta = new_level.saturating_sub(row_level) as i128;
        let online_rewards_bump = online_ru as i128 * level_delta;
        let offline_rewards_bump = offline_ru as i128 * level_delta;

        let clamp =
            |base: i64, d: i128| -> i64 { (base as i128 + d).clamp(0, i64::MAX as i128) as i64 };
        let new_online = clamp(online, online_rewards_bump + delta.online_money);
        let new_online_ru = clamp(online_ru, delta.online_reward_units);
        let new_offline = clamp(offline, offline_rewards_bump + delta.offline_money);
        let new_offline_ru = clamp(offline_ru, delta.offline_reward_units);
        let new_notpart = clamp(notpart, delta.not_participating_money);
        let new_notpart_ru = clamp(notpart_ru, delta.not_participating_reward_units);
        self.conn
            .execute(
                "UPDATE accounttotals SET online = ?1, onlinerewardunits = ?2, offline = ?3, \
                 offlinerewardunits = ?4, notparticipating = ?5, notparticipatingrewardunits = ?6, \
                 rewardslevel = ?7 WHERE id = ''",
                params![
                    new_online,
                    new_online_ru,
                    new_offline,
                    new_offline_ru,
                    new_notpart,
                    new_notpart_ru,
                    new_level as i64,
                ],
            )
            .map_err(|e| AlgoError::Ledger {
                message: format!("flush_pending_account_totals_delta write error: {e}"),
            })?;
        Ok(())
    }

    pub fn commit_block(&mut self) -> Result<(), AlgoError> {
        // Flush chain-level state to meta table.
        self.flush_chain_state()?;

        // Issue #523: flush this block's accumulated `accounttotals` delta —
        // must run before COMMIT so it lands atomically with the account
        // writes it summarizes, and rolls back with them on failure.
        self.flush_pending_account_totals_delta()?;

        // Issue #519: append this round's online-supply snapshot to
        // `onlineroundparamstail` on every commit, not just catchpoint import.
        // Mirrors go-algorand's `onlineAccounts.newBlockImpl` appending
        // `OnlineRoundParamsData` every block and `onlineAccounts.commitRound`
        // pruning entries older than `MaxBalLookback` via
        // `AccountsPruneOnlineRoundParams` (`ledger/acctonline.go`). Without a
        // live writer, `online_supply_at_round`/`online_circulation_at_round`
        // (shared by sortition's `AgreementLedgerBridge::circulation` and
        // `GetSupply`'s `online-stake`) silently fall back to today's
        // aggregate for any round the last catchpoint import didn't cover.
        self.record_online_supply_snapshot()?;

        // Persist the trie if enabled. Paged commit via the same SQLite
        // transaction we're about to COMMIT — page writes happen against
        // `accounthashes` (PLAN-130 TASK-136). PLAN-36 G4 (TASK-118)
        // dropped the legacy `merkle_trie` single-blob table; the
        // runtime no longer creates, reads, or writes it.
        if let Some(ref mut trie) = self.trie {
            let committer = crate::merkle_committer::SqliteMerkleCommitter::active(&self.conn);
            trie.commit(&committer)?;
            // PLAN-144 TASK-147: bound runtime cache memory. On the
            // first commit for a freshly-built (`rebuild_trie_from_db`)
            // trie the cache has no lazy loader installed — install one
            // now so subsequent `evict` is safe. Only disk ledgers
            // (with a tracker file we can re-open read-only) get a
            // loader; in-memory ledgers skip eviction (cache stays
            // unbounded, which is acceptable for the test-only paths
            // that build in-memory ledgers).
            if !trie.has_lazy_loader() {
                if let Some(prefix) = self.db_prefix.as_ref() {
                    let tracker = tracker_path_for_prefix(prefix);
                    match crate::merkle_committer::OwnedSqliteCommitter::open_active(&tracker) {
                        Ok(owned) => {
                            trie.set_lazy_loader(Box::new(owned));
                            tracing::debug!(
                                "merkle_trie: installed OwnedSqliteCommitter as lazy loader (post first commit)"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "merkle_trie: could not install lazy loader for {}: {e} (eviction will be skipped)",
                                tracker.display()
                            );
                        }
                    }
                }
            }
            // Eviction is safe immediately after commit (dirty=false)
            // and lazy load (PLAN-144 TASK-146) re-fetches evicted
            // pages on demand if subsequent blocks touch them.
            // `MerkleTrie::evict` is a no-op when no loader is
            // installed.
            match trie.evict() {
                Ok(evicted) => {
                    tracing::debug!(
                        "merkle_trie: evicted {evicted} pages; cache_nodes={} target={}",
                        trie.cached_node_count(),
                        trie.cache_target()
                    );
                }
                Err(e) => {
                    // Defensive: evict refuses on a dirty trie; we just
                    // committed so this shouldn't happen, but surface
                    // rather than silently swallow.
                    tracing::warn!("merkle_trie: post-commit evict failed: {e}");
                }
            }
        }

        self.conn
            .execute_batch("COMMIT")
            .map_err(|e| AlgoError::Ledger {
                message: format!("commit block error: {e}"),
            })?;
        // The committed lease changes stand; discard the rollback snapshot.
        self.lease_snapshot = None;
        self.in_block = false;
        Ok(())
    }

    /// Rollback the current block-level transaction, discarding all changes
    /// made since `begin_block`. Used by the replay CLI when `apply_block` fails.
    pub fn rollback_block(&mut self) -> Result<(), AlgoError> {
        // Clear pre-mutation records — they are for the rolled-back block.
        self.pre_mutations.clear();
        // Discard the rolled-back block's accumulated `accounttotals` delta
        // (issue #523) — its account writes are being undone by the SQL
        // ROLLBACK below, so the totals delta must not survive to the next
        // block's flush.
        self.pending_totals_delta = AccountTotalsDelta::default();

        // Restore the in-memory lease table to its pre-block state — the SQLite
        // ROLLBACK below does not cover it, so leases recorded by partially-
        // applied transactions must be undone or they poison future submissions.
        if let Some(snapshot) = self.lease_snapshot.take() {
            self.lease_table = snapshot;
        }

        self.conn
            .execute_batch("ROLLBACK")
            .map_err(|e| AlgoError::Ledger {
                message: format!("rollback block error: {e}"),
            })?;
        self.in_block = false;

        // Reload the trie from the last committed state (DB was rolled back).
        if self.trie.is_some() {
            self.load_trie()?;
        }

        Ok(())
    }

    /// Get the last committed round (for resume capability).
    ///
    /// Sole source: `acctrounds.acctbase` (Go's `accountsRound`).
    /// Apply mirrors `current_round` here via `flush_chain_state`;
    /// catchpoint cutover seeds it; the legacy `algod_rust_meta`
    /// cache was retired in G6 part 3 (TASK-107) — pre-existing rows
    /// are migrated into `acctrounds` by `migrate_off_algod_rust_meta`
    /// during open. Returns `None` only when the row doesn't exist
    /// (truly fresh / never-initialized DB).
    pub fn last_committed_round(&self) -> Result<Option<u64>, AlgoError> {
        let rnd: Option<i64> = self
            .conn
            .query_row(
                "SELECT rnd FROM acctrounds WHERE id = 'acctbase'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| AlgoError::Ledger {
                message: format!("acctrounds query error: {e}"),
            })?;
        Ok(rnd.map(|v| v.max(0) as u64))
    }

    /// Highest round currently stored in the attached block database, or
    /// `None` if the table is empty.
    ///
    /// Used together with [`Self::last_committed_round`] to detect the
    /// cross-file split-commit gap documented on [`Self::open_split`]: if
    /// the tracker reports round `N` but `blockdb.blocks` only goes up to
    /// `M < N`, the tail block was not durably written. Callers can use
    /// the gap to decide between bailing out, refetching, or rolling
    /// forward.
    pub fn max_block_round_in_blockdb(&self) -> Result<Option<u64>, AlgoError> {
        // G6 part 3: filter out the synthesized header rows that
        // `initialize_meta_from_catchpoint` writes (empty `blkdata`).
        // Those rows exist only so `derive_chain_meta_from_latest_block`
        // has a header to read post-cutover-but-pre-lookback. They are
        // NOT real archived blocks, so they must not count here —
        // otherwise `reconcile_cross_file` would classify a freshly
        // catchpoint-imported ledger as `Consistent` and let relay /
        // follow / participate paths skip the lookback safety gate.
        //
        // SQLite `MAX()` over an empty filtered result returns NULL,
        // so collect into Option<i64>.
        let raw: Option<i64> = self
            .conn
            .query_row(
                "SELECT MAX(rnd) FROM blockdb.blocks WHERE blkdata IS NOT NULL AND length(blkdata) > 0",
                [],
                |row| row.get(0),
            )
            .map_err(|e| AlgoError::Ledger {
                message: format!("max_block_round_in_blockdb query error: {e}"),
            })?;
        Ok(raw.map(|v| v as u64))
    }

    /// Result of cross-file (tracker vs `blockdb`) consistency checks
    /// at startup. See [`Self::reconcile_cross_file`].
    fn _consistency_state_doc(&self) {}

    /// Inspect the tracker / block-DB round pair and report the disk-
    /// layout state.
    ///
    /// Returns:
    /// - [`CrossFileState::Empty`] when no rounds have been committed yet
    ///   (fresh DB or post-`remove_ledger_files`).
    /// - [`CrossFileState::Consistent`] when the tracker round has a
    ///   matching row in `blockdb.blocks`, or `blockdb.blocks` is ahead
    ///   of the tracker.
    /// - [`CrossFileState::CatchpointOnly`] when the tracker has rounds
    ///   but `blockdb.blocks` is fully empty — the legitimate shape
    ///   after a standalone `catchpoint import`.
    /// - [`CrossFileState::BlockBehind`] when the tracker round is
    ///   missing from `blockdb.blocks` even though `blockdb.blocks` has
    ///   other rows — the cross-file split-commit hazard documented on
    ///   [`Self::open_split`]. The caller must backfill the missing
    ///   block(s) or refuse to start.
    pub fn reconcile_cross_file(&self) -> Result<CrossFileState, AlgoError> {
        let tracker = self.last_committed_round()?;
        let block_max = self.max_block_round_in_blockdb()?;
        let state = match (tracker, block_max) {
            (None, _) => CrossFileState::Empty,
            // Tracker reports round 0 with no blocks committed — fresh
            // DB just after schema creation, not a gap.
            (Some(0), None) => CrossFileState::Empty,
            // Tracker has rounds but blockdb is completely empty.
            // Catchpoint import shape; not a crash hazard, but callers
            // that need blocks should reject it.
            (Some(t), None) => CrossFileState::CatchpointOnly { tracker_round: t },
            // Tracker behind blockdb (block stored before tracker apply
            // committed — happens during sync). Not the hazard.
            (Some(t), Some(b)) if t <= b => CrossFileState::Consistent { round: t },
            // Tracker ahead of blockdb max with at least one stored
            // block. The row for the tracker round itself is missing —
            // double-check, since a previous run may have committed the
            // exact round but pruned older ones.
            (Some(t), Some(b)) => {
                // Mirror `max_block_round_in_blockdb`'s payload filter:
                // a synthesized catchpoint-seed row (empty `blkdata`)
                // is not a real archived block and must not satisfy
                // the row-present check.
                let row_present: bool = self
                    .conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM blockdb.blocks \
                         WHERE rnd = ?1 AND blkdata IS NOT NULL AND length(blkdata) > 0)",
                        params![t as i64],
                        |row| row.get(0),
                    )
                    .map_err(|e| AlgoError::Ledger {
                        message: format!("reconcile_cross_file row probe error: {e}"),
                    })?;
                if row_present {
                    CrossFileState::Consistent { round: t }
                } else {
                    CrossFileState::BlockBehind {
                        tracker_round: t,
                        block_max_round: b,
                    }
                }
            }
        };
        Ok(state)
    }

    /// Check whether the `accounttotals` row has been populated —
    /// either by the catchpoint importer or by
    /// [`put_account_totals_seed`]. Used by the mixed-cluster relay
    /// bootstrap as the "already seeded" sentinel; presence of the
    /// row is the safe check even for networks whose online stake is
    /// legitimately zero (where `online_stake()` returns Ok(0) from
    /// both a populated and an empty table).
    pub fn has_account_totals(&self) -> Result<bool, AlgoError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM accounttotals WHERE id = ''",
                [],
                |row| row.get(0),
            )
            .map_err(|e| AlgoError::Ledger {
                message: format!("query accounttotals count error: {e}"),
            })?;
        Ok(count > 0)
    }

    /// Discard any `accounttotals` delta accumulated so far in the current
    /// block (issue #523's [`AccountTotalsDelta`]) without flushing it.
    ///
    /// Used by [`crate::genesis::seed_account_totals_from_genesis`]: the
    /// genesis allocations it seeds were written via `set_account` (which
    /// accumulates a delta), but the seed row it writes already reflects
    /// those same accounts directly, so the accumulated delta would
    /// double-count them if left to flush at the next `commit_block`.
    pub fn discard_pending_account_totals_delta(&mut self) {
        self.pending_totals_delta = AccountTotalsDelta::default();
    }

    /// Seed the `accounttotals` row from genesis-time totals (PLAN-32
    /// / TASK-95). A brand-new ledger has no `accounttotals` row at all
    /// until something writes one, so the mixed-cluster relay would
    /// otherwise see `online_stake() == 0` on every call, which breaks
    /// `Certificate::authenticate`'s `circulation()` lookup. As of issue
    /// #523, `apply_block` maintains this row incrementally after genesis
    /// (`set_account`/`remove_account` accumulate a delta, flushed here in
    /// `commit_block`'s call to `flush_pending_account_totals_delta`), so
    /// this seed only needs to establish the correct round-0 baseline.
    ///
    /// Per-status reward-unit columns are seeded from the caller (go's
    /// `AccountTotals.RewardUnits()` feeds the per-round rewards-level
    /// advance); the rewards-level column is left zero (genesis level).
    ///
    /// Safe to call multiple times; it `INSERT OR REPLACE`s the row.
    #[allow(clippy::too_many_arguments)]
    pub fn put_account_totals_seed(
        &mut self,
        online_money: u64,
        online_reward_units: u64,
        offline_money: u64,
        offline_reward_units: u64,
        not_participating_money: u64,
        not_participating_reward_units: u64,
    ) -> Result<(), AlgoError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO accounttotals(id, online, onlinerewardunits, \
                 offline, offlinerewardunits, notparticipating, \
                 notparticipatingrewardunits, rewardslevel) \
                 VALUES('', ?1, ?2, ?3, ?4, ?5, ?6, 0)",
                params![
                    online_money as i64,
                    online_reward_units as i64,
                    offline_money as i64,
                    offline_reward_units as i64,
                    not_participating_money as i64,
                    not_participating_reward_units as i64,
                ],
            )
            .map_err(|e| AlgoError::Ledger {
                message: format!("put_account_totals_seed error: {e}"),
            })?;
        Ok(())
    }

    /// Query the total online stake from the `accounttotals` table.
    ///
    /// Returns the `online` column (total microAlgos of all online accounts)
    /// from the `accounttotals` row with `id = ''`. This is the value used by
    /// go-algorand for circulation / committee membership checks.
    ///
    /// Returns `Ok(0)` if the table is empty or the row is missing (e.g.,
    /// fresh database before catchpoint import).
    pub fn online_stake(&self) -> Result<u64, AlgoError> {
        let result: Option<i64> = self
            .conn
            .query_row(
                "SELECT online FROM accounttotals WHERE id = ''",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| AlgoError::Ledger {
                message: format!("query accounttotals error: {e}"),
            })?;
        Ok(result.unwrap_or(0).max(0) as u64)
    }

    /// Query the total *participating* money from the `accounttotals` table.
    ///
    /// Returns `online + offline` (microAlgos) from the `accounttotals` row with
    /// `id = ''` — go's `AccountTotals.Participating()` (`Online.Money +
    /// Offline.Money`, excluding NotParticipating). This is the `total_money`
    /// value reported by the `/v2/ledger/supply` endpoint.
    ///
    /// Returns `Ok(0)` if the table is empty or the row is missing.
    pub fn participating_money(&self) -> Result<u64, AlgoError> {
        let result: Option<(i64, i64)> = self
            .conn
            .query_row(
                "SELECT online, offline FROM accounttotals WHERE id = ''",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| AlgoError::Ledger {
                message: format!("query accounttotals participating money error: {e}"),
            })?;
        let (online, offline) = result.unwrap_or((0, 0));
        Ok((online.max(0) as u64).saturating_add(offline.max(0) as u64))
    }

    /// Query the total reward units from the `accounttotals` table.
    ///
    /// Returns `onlinerewardunits + offlinerewardunits` from the
    /// `accounttotals` row with `id = ''` — go's `AccountTotals.RewardUnits()`
    /// (`Online.RewardUnits + Offline.RewardUnits`, excluding NotParticipating).
    /// This is the divisor in the per-round rewards-level advance.
    ///
    /// Returns `Ok(0)` if the table is empty or the row is missing.
    pub fn total_reward_units(&self) -> Result<u64, AlgoError> {
        let result: Option<(i64, i64)> = self
            .conn
            .query_row(
                "SELECT onlinerewardunits, offlinerewardunits FROM accounttotals WHERE id = ''",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| AlgoError::Ledger {
                message: format!("query accounttotals reward units error: {e}"),
            })?;
        let (online, offline) = result.unwrap_or((0, 0));
        Ok((online.max(0) as u64).saturating_add(offline.max(0) as u64))
    }

    /// Compute the current `accounttotals` aggregate as
    /// [`crate::state_delta::AccountTotals`] (issue #586), including this
    /// block's not-yet-flushed `pending_totals_delta` and this round's
    /// rewards-level bump.
    ///
    /// This is a read-only peek used by
    /// [`crate::apply::apply_block_with_delta_mode`] to populate
    /// `StateDelta::totals` *mid-block*, before `commit_block` has run
    /// [`Self::flush_pending_account_totals_delta`] to persist the same
    /// arithmetic into the row. Deliberately reimplements that function's
    /// formula independently (see its doc comment for the derivation from
    /// go's `roundCowState.CalculateTotals`/`AccountTotals.ApplyRewards`)
    /// rather than sharing code with it, so a bug in this peek can never
    /// perturb the tested persist path that `commit_block` depends on.
    ///
    /// Returns [`AccountTotals::default`] (all-zero) if the `accounttotals`
    /// row hasn't been seeded yet (fresh/catchpoint-only ledger) — matching
    /// [`Self::online_stake`]/[`Self::participating_money`]'s same
    /// "unseeded ⇒ zero" convention, and if the query itself fails (should
    /// not happen outside catastrophic DB corruption) — this is an
    /// infallible accessor by design (mirroring `rewards_level()` and
    /// friends), so a freak SQL error degrades to zero totals rather than
    /// panicking or forcing a `Result` onto every caller.
    pub fn account_totals(&self) -> crate::state_delta::AccountTotals {
        use crate::state_delta::{AccountTotals, AlgoCount};
        let row: Option<(i64, i64, i64, i64, i64, i64, i64)> = self
            .conn
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
            .optional()
            .unwrap_or(None);
        let Some((online, online_ru, offline, offline_ru, notpart, notpart_ru, row_level)) = row
        else {
            return AccountTotals::default();
        };
        let delta = self.pending_totals_delta;
        let new_level = self.rewards_level;
        let row_level_u = row_level.max(0) as u64;
        let level_delta = new_level.saturating_sub(row_level_u) as i128;
        let online_rewards_bump = online_ru as i128 * level_delta;
        let offline_rewards_bump = offline_ru as i128 * level_delta;
        let clamp =
            |base: i64, d: i128| -> u64 { (base as i128 + d).clamp(0, i64::MAX as i128) as u64 };
        AccountTotals {
            online: AlgoCount {
                money: clamp(online, online_rewards_bump + delta.online_money),
                reward_units: clamp(online_ru, delta.online_reward_units),
            },
            offline: AlgoCount {
                money: clamp(offline, offline_rewards_bump + delta.offline_money),
                reward_units: clamp(offline_ru, delta.offline_reward_units),
            },
            not_participating: AlgoCount {
                money: clamp(notpart, delta.not_participating_money),
                reward_units: clamp(notpart_ru, delta.not_participating_reward_units),
            },
            rewards_level: new_level,
        }
    }

    /// Query the online supply for a specific round from the
    /// `onlineroundparamstail` table.
    ///
    /// The `data` column contains msgpack-encoded `OnlineRoundParamsData`
    /// with codec key `"online"` holding the online supply for that round.
    ///
    /// Returns `Ok(None)` if the round is not in the tail table.
    pub fn online_supply_at_round(&self, round: u64) -> Result<Option<u64>, AlgoError> {
        let data: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT data FROM onlineroundparamstail WHERE rnd = ?1",
                params![round as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| AlgoError::Ledger {
                message: format!("query onlineroundparamstail error: {e}"),
            })?;

        let data = match data {
            Some(d) => d,
            None => return Ok(None),
        };

        // Parse msgpack to extract the "online" field.
        let value: rmpv::Value =
            rmpv::decode::read_value(&mut &data[..]).map_err(|e| AlgoError::Ledger {
                message: format!("decode onlineroundparamstail msgpack error: {e}"),
            })?;

        if let Some(map) = value.as_map() {
            for (k, v) in map {
                if k.as_str() == Some("online") {
                    return Ok(Some(v.as_u64().unwrap_or(0)));
                }
            }
        }
        Ok(Some(0))
    }

    /// Record the total online stake for `round` in the per-round online-supply
    /// tail (`onlineroundparamstail`), keyed by round.
    ///
    /// Mirrors the shape go-algorand persists in `OnlineRoundParamsData`
    /// (`ledger/acctonline.go`) -- a msgpack map with the `"online"` key read
    /// back by [`Self::online_supply_at_round`]. Low-level primitive used by
    /// both catchpoint import (`catchpoint/importer.rs`) and the live writer
    /// [`Self::record_online_supply_snapshot`] invoked from every
    /// [`Self::commit_block`] (issue #519); also usable directly to
    /// backfill/seed known per-round snapshots in tests.
    pub fn put_online_supply_at_round(&self, round: u64, online: u64) -> Result<(), AlgoError> {
        let data = encode_mixed_map(&[("online", encode_msgpack_uint(online))]);
        self.conn
            .execute(
                "INSERT OR REPLACE INTO onlineroundparamstail (rnd, data) VALUES (?1, ?2)",
                params![round as i64, data],
            )
            .map_err(|e| AlgoError::Ledger {
                message: format!("insert onlineroundparamstail error: {e}"),
            })?;
        Ok(())
    }

    /// Delete all `onlineroundparamstail` rows for rounds strictly older than
    /// `before_round`.
    ///
    /// Mirrors go-algorand's `AccountsPruneOnlineRoundParams`
    /// (`ledger/store/trackerdb/sqlitedriver/accountsV2.go`): `DELETE FROM
    /// onlineroundparamstail WHERE rnd < ?`.
    fn prune_online_supply_before(&self, before_round: u64) -> Result<(), AlgoError> {
        self.conn
            .execute(
                "DELETE FROM onlineroundparamstail WHERE rnd < ?1",
                params![before_round as i64],
            )
            .map_err(|e| AlgoError::Ledger {
                message: format!("prune onlineroundparamstail error: {e}"),
            })?;
        Ok(())
    }

    /// Append the current round's online-supply snapshot to
    /// `onlineroundparamstail` and prune snapshots that have fallen outside
    /// the `MaxBalLookback` retention window. Called from every
    /// [`Self::commit_block`] (issue #519) so the table is a live, bounded
    /// history rather than something only catchpoint import populates.
    ///
    /// Retention is based on go-algorand's `onlineAccounts.commitRound`
    /// (`ledger/acctonline.go`): `onlineAccountsForgetBefore = (newBase +
    /// 1).SubSaturate(MaxBalLookback)`. Read literally that keeps rows
    /// `>= round + 1 - MaxBalLookback`, one round short of the exact
    /// lookback round `agreement.BalanceRound`/`round - MaxBalLookback`
    /// needs. Go gets away with the literal formula because `newBase` is
    /// the *durably committed* round, which trails the live agreement
    /// round by at least one round of deferred-commit lag (see the
    /// `dcc.newBase()`/`ao.cachedDBRoundOnline` bookkeeping in the same
    /// file) -- so by the time go prunes, the round it needs has already
    /// been retained by that lag. `commit_block` here writes and prunes
    /// synchronously for every round with no such lag, so `newBase` here
    /// *is* `round`; reusing go's formula verbatim prunes the exact
    /// lookback round in the same commit that would have served it
    /// (issue #529). Using `round.saturating_sub(MaxBalLookback)` (one
    /// round earlier than go's literal formula) keeps `round -
    /// MaxBalLookback` -- the exact round queried -- alive without
    /// retaining more history than that. This crate's catchpoint export
    /// (`ExportOptions::online_horizon_round`, `catchpoint/writer.rs`)
    /// keeps go's literal formula, which is correct there since a
    /// catchpoint always describes an already-durable round.
    ///
    /// Go additionally extends retention to cover the state-proof voters
    /// lookback (`ao.voters.lowestRound`) when that is smaller than the
    /// `MaxBalLookback` cutoff. algod-rust does not yet track state-proof
    /// voter history in this table, so only the `MaxBalLookback` bound is
    /// applied here; revisit if/when voter-lookback tracking lands.
    fn record_online_supply_snapshot(&self) -> Result<(), AlgoError> {
        let round = self.current_round.0;
        let online = self.online_stake()?;
        self.put_online_supply_at_round(round, online)?;

        let max_bal_lookback = algo_types::consensus::consensus_params_for_version(&self.protocol)
            .map(|p| p.max_bal_lookback)
            .unwrap_or(crate::catchpoint::writer::DEFAULT_MAX_BAL_LOOKBACK);
        let forget_before = round.saturating_sub(max_bal_lookback);
        self.prune_online_supply_before(forget_before)
    }

    /// Returns the total online stake to report as "circulation" at `round`:
    /// the per-round snapshot from [`Self::online_supply_at_round`] if one is
    /// recorded, else the current aggregate online stake ([`Self::online_stake`]),
    /// minus the stake behind participation keys that will have expired by
    /// `vote_rnd` when the current protocol's `exclude_expired_circulation`
    /// is set.
    ///
    /// This is the single accessor behind both agreement's lookback-round
    /// circulation query (`AgreementLedgerBridge::circulation`, used for
    /// sortition/committee sizing) and `GET /v2/ledger/supply`'s `online-stake`
    /// field -- mirrors go-algorand's `onlineAccounts.onlineCirculation`
    /// (`ledger/acctonline.go`): `rnd` is the round the total is drawn from,
    /// `vote_rnd` is the round agreement is voting for (a `VoteLastValid`
    /// strictly less than `vote_rnd` counts as expired). Go skips the
    /// subtraction entirely for `rnd == 0` (the first `MaxBalLookback`
    /// rounds still use genesis balances); this mirrors that.
    ///
    /// Go computes the expired-stake subtraction from the exact historical
    /// online-account snapshot at `rnd`. algod-rust does not yet persist a
    /// live per-account online history (only catchpoint import populates
    /// `onlineaccounts`), so -- consistent with this function's existing
    /// current-aggregate fallback for the total itself -- the expired-stake
    /// scan reads the *current* `accountbase` online-account set via
    /// [`Self::expired_online_stake`] rather than a `rnd`-historical one.
    ///
    /// `total` and `expired` are drawn from two independently-maintained
    /// bookkeeping paths -- `accounttotals`'s incrementally-updated
    /// aggregate vs. a fresh per-account rewards-applied scan -- which can
    /// disagree by a small amount when reward accrual has been applied to
    /// one but not yet folded into the other (live-verified while adding
    /// this exclusion: issue #518). Go's own `OverflowTracker.SubA` assumes
    /// both figures come from one consistent snapshot and never diverge;
    /// algod-rust's two-path approximation cannot make that same guarantee,
    /// so unlike go this saturates at 0 rather than erroring -- a
    /// public REST endpoint must never 500 over bookkeeping skew between
    /// two otherwise-correct internal figures.
    pub fn online_circulation_at_round(&self, round: u64, vote_rnd: u64) -> Result<u64, AlgoError> {
        let total = if let Some(supply) = self.online_supply_at_round(round)? {
            supply
        } else {
            self.online_stake()?
        };

        let exclude_expired = algo_types::consensus::consensus_params_for_version(&self.protocol)
            .map(|p| p.exclude_expired_circulation)
            .unwrap_or(false);
        if !exclude_expired || round == 0 {
            return Ok(total);
        }

        let expired = self.expired_online_stake(vote_rnd)?;
        Ok(total.saturating_sub(expired))
    }

    /// Sum the stake held by currently-online accounts (`accountbase`,
    /// `normalizedonlinebalance > 0`) whose participation key has a nonzero
    /// `VoteLastValid` strictly less than `vote_rnd`.
    ///
    /// Mirrors go-algorand's `onlineAccounts.expiredOnlineCirculation` /
    /// `onlineAcctsExpiredByRound` predicate (`ledger/acctonline.go`):
    /// `d.Status == basics.Online && d.VoteLastValid != 0 && voteRnd >
    /// d.VoteLastValid`.
    fn expired_online_stake(&self, vote_rnd: u64) -> Result<u64, AlgoError> {
        let mut stmt = self
            .conn
            .prepare("SELECT data FROM accountbase WHERE normalizedonlinebalance > 0")
            .map_err(|e| AlgoError::Ledger {
                message: format!("prepare expired_online_stake query error: {e}"),
            })?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|e| AlgoError::Ledger {
                message: format!("query expired_online_stake error: {e}"),
            })?;

        let mut expired_stake: u64 = 0;
        for row in rows {
            let data = row.map_err(|e| AlgoError::Ledger {
                message: format!("read expired_online_stake row error: {e}"),
            })?;
            let account = decode_account_data(&data).map_err(|e| AlgoError::Ledger {
                message: format!("decode expired_online_stake account error: {e}"),
            })?;
            if account.status == AccountStatus::Online
                && account.vote_last_valid != 0
                && vote_rnd > account.vote_last_valid
            {
                expired_stake =
                    expired_stake
                        .checked_add(account.micro_algos)
                        .ok_or_else(|| AlgoError::Ledger {
                            message: "expired_online_stake: overflow totaling expired stake"
                                .to_string(),
                        })?;
            }
        }
        Ok(expired_stake)
    }

    /// Select up to `max_count` currently-online accounts (`accountbase`,
    /// `normalizedonlinebalance > 0`) whose participation key has expired as
    /// of `current_round` -- candidates for a self-produced block's
    /// `expired_participation_accounts` header field.
    ///
    /// Mirrors the expiry half of go-algorand's
    /// `generateKnockOfflineAccountsList` (`ledger/eval/eval.go`, v41): a
    /// candidate has a nonempty vote key, a nonzero balance (go skips
    /// `MicroAlgosWithRewards.IsZero()` -- closing accounts), and
    /// `VoteLastValid != 0 && VoteLastValid < current_round` (`current_round`
    /// being the round of the block being built, i.e. go's `eval.Round()`).
    /// This covers only the expiry list, not go's absent/suspend list
    /// (`AbsentParticipationAccounts`, gated on the payouts feature) -- that
    /// is a separate mechanism (issue #526 is scoped to expiry only) -- and
    /// does not exclude the node's own participating addresses, since
    /// dev-mode block production holds no participation keys of its own.
    ///
    /// Selection order among more candidates than `max_count` is not
    /// consensus-significant: go's own selection iterates a Go map, whose
    /// iteration order is randomized per process ("different nodes may
    /// propose different lists of addresses based on node state" -- see the
    /// doc comment on `generateKnockOfflineAccountsList`), so any
    /// deterministic order is equally valid here. This returns addresses in
    /// ascending byte order for reproducible tests.
    pub fn expired_participation_account_candidates(
        &self,
        current_round: u64,
        max_count: usize,
    ) -> Result<Vec<Address>, AlgoError> {
        if max_count == 0 {
            return Ok(Vec::new());
        }
        let mut stmt = self
            .conn
            .prepare(
                "SELECT address, data FROM accountbase WHERE normalizedonlinebalance > 0 \
                 ORDER BY address",
            )
            .map_err(|e| AlgoError::Ledger {
                message: format!(
                    "prepare expired_participation_account_candidates query error: {e}"
                ),
            })?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| AlgoError::Ledger {
                message: format!("query expired_participation_account_candidates error: {e}"),
            })?;

        let mut out = Vec::new();
        for row in rows {
            let (addr_bytes, data) = row.map_err(|e| AlgoError::Ledger {
                message: format!("read expired_participation_account_candidates row error: {e}"),
            })?;
            let account = decode_account_data(&data).map_err(|e| AlgoError::Ledger {
                message: format!(
                    "decode expired_participation_account_candidates account error: {e}"
                ),
            })?;
            if account.micro_algos == 0 {
                continue;
            }
            let has_vote_key = account.vote_id.is_some_and(|v| v != [0u8; 32]);
            if !has_vote_key {
                continue;
            }
            if account.vote_last_valid != 0 && account.vote_last_valid < current_round {
                let addr_arr: [u8; 32] =
                    addr_bytes
                        .try_into()
                        .map_err(|v: Vec<u8>| AlgoError::Ledger {
                            message: format!(
                                "expired_participation_account_candidates: bad address length {} \
                                 (expected 32)",
                                v.len()
                            ),
                        })?;
                out.push(Address(addr_arr));
                if out.len() >= max_count {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Look up an account's online data at a specific round from the
    /// `onlineaccounts` table.
    ///
    /// Returns the most recent entry for this address where `updround <= round`.
    /// The `data` column contains msgpack-encoded online account data.
    ///
    /// Returns `Ok(None)` if no entry exists for this address at or before
    /// the given round.
    pub fn get_online_account_at_round(
        &self,
        addr: &Address,
        round: u64,
    ) -> Result<Option<AccountData>, AlgoError> {
        let data: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT data FROM onlineaccounts WHERE address = ?1 AND updround <= ?2 \
                 ORDER BY updround DESC LIMIT 1",
                params![addr.0.as_slice(), round as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| AlgoError::Ledger {
                message: format!("query onlineaccounts error: {e}"),
            })?;

        match data {
            Some(d) => decode_account_data(&d)
                .map(Some)
                .map_err(|e| AlgoError::Ledger {
                    message: format!("decode onlineaccounts data error: {e}"),
                }),
            None => Ok(None),
        }
    }

    /// Persist the committed tracker round to `acctrounds.acctbase`
    /// (Go's `accountsRound`) and ensure a recoverable header exists
    /// at that round in `blockdb.blocks`.
    ///
    /// G6 part 3 retired the `algod_rust_meta` chain-meta cache;
    /// rewards state, genesis fields, protocol, fee_sink,
    /// rewards_pool, and txn_counter are recovered on next open by
    /// `derive_chain_meta_from_latest_block` from this round's
    /// header. Normal apply flows have already written that header
    /// via `put_block` before `commit_block` runs, so the synthesized
    /// fallback below is a no-op (INSERT OR IGNORE skips the existing
    /// row).
    ///
    /// The synthesized fallback matters for two paths that commit
    /// without calling `put_block`:
    ///   - Genesis seeding (relay / participate first-boot): writes
    ///     accountbase + accounttotals at round 0 via begin_block
    ///     → populate_store → commit_block, never puts a real block.
    ///     Without this synthesized row, the chain meta would be
    ///     lost on next restart.
    ///   - Defensive recovery: if a previous run's `put_block` was
    ///     lost as a warning but `commit_block` succeeded, this
    ///     restores the gap with the in-memory state we are about
    ///     to lose.
    fn flush_chain_state(&self) -> Result<(), AlgoError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO acctrounds (id, rnd) VALUES ('acctbase', ?1)",
                params![self.current_round.0 as i64],
            )
            .map_err(|e| AlgoError::Ledger {
                message: format!("acctrounds flush error: {e}"),
            })?;

        // Synthesize a minimal header carrying the cached chain meta
        // and INSERT OR IGNORE — real blocks written via `put_block`
        // already occupy the row, so this is a no-op for them.
        let hdr = algo_types::BlockHeader {
            round: self.current_round,
            genesis_id: self.genesis_id.clone(),
            genesis_hash: self.genesis_hash,
            current_protocol: self.protocol.clone(),
            fee_sink: self.fee_sink,
            rewards_pool: self.rewards_pool,
            rewards_level: self.rewards_level,
            rewards_rate: self.rewards_rate,
            rewards_residue: self.rewards_residue,
            rewards_recalculation_round: Round(self.rewards_recalculation_round),
            txn_counter: self.txn_counter,
            ..algo_types::BlockHeader::default()
        };
        let hdrdata = rmp_serde::to_vec_named(&hdr).map_err(|e| AlgoError::Ledger {
            message: format!("encode synthesized flush header: {e}"),
        })?;
        self.conn
            .execute(
                "INSERT OR IGNORE INTO blockdb.blocks (rnd, proto, hdrdata, blkdata) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    self.current_round.0 as i64,
                    self.protocol,
                    hdrdata,
                    &[] as &[u8]
                ],
            )
            .map_err(|e| AlgoError::Ledger {
                message: format!("synthesized header flush error: {e}"),
            })?;
        Ok(())
    }

    // ---- Internal helpers ----

    /// Get the rowid for an address in accountbase, or None.
    fn get_rowid(&self, addr: &Address) -> Option<i64> {
        self.conn
            .query_row(
                "SELECT rowid FROM accountbase WHERE address = ?1",
                params![addr.0.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .unwrap_or_else(|e| {
                tracing::warn!("SQLite error querying rowid: {}", e);
                None
            })
    }

    /// Get or insert an account row and return its rowid.
    fn get_or_insert_rowid(&self, addr: &Address) -> Result<i64, AlgoError> {
        if let Some(rowid) = self.get_rowid(addr) {
            return Ok(rowid);
        }
        // Insert a default account (Offline, zero balance → NOB is 0).
        let default_account = AccountData::default();
        let nob = account_nob_i64(&default_account);
        let default_data = encode_account_data(&default_account);
        self.conn
            .execute(
                "INSERT INTO accountbase (address, normalizedonlinebalance, data) VALUES (?1, ?2, ?3)",
                params![addr.0.as_slice(), nob, default_data],
            )
            .map_err(|e| AlgoError::Ledger {
                message: format!("insert account error: {e}"),
            })?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Read the raw resource blob for an app resource (ctype=CTYPE_APP) at the given rowid/aidx.
    /// Returns None if no row exists.
    fn get_app_resource_blob(&self, rowid: i64, app_id: u64) -> Option<Vec<u8>> {
        self.conn
            .query_row(
                "SELECT data FROM resources WHERE addrid = ?1 AND aidx = ?2 AND ctype = ?3",
                params![rowid, app_id as i64, CTYPE_APP],
                |row| row.get(0),
            )
            .optional()
            .unwrap_or_else(|e| {
                tracing::warn!("SQLite error reading app resource blob: {}", e);
                None
            })
    }

    /// Read the raw resource blob for an asset resource (ctype=CTYPE_ASSET) at the given rowid/aidx.
    /// Returns None if no row exists.
    fn get_asset_resource_blob(&self, rowid: i64, asset_id: u64) -> Option<Vec<u8>> {
        self.conn
            .query_row(
                "SELECT data FROM resources WHERE addrid = ?1 AND aidx = ?2 AND ctype = ?3",
                params![rowid, asset_id as i64, CTYPE_ASSET],
                |row| row.get(0),
            )
            .optional()
            .unwrap_or_else(|e| {
                tracing::warn!("SQLite error reading asset resource blob: {}", e);
                None
            })
    }

    /// Query the creator address from assetcreators for a given asset/app id.
    fn get_creator_from_assetcreators(&self, id: u64) -> Option<Address> {
        let result: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT creator FROM assetcreators WHERE asset = ?1",
                params![id as i64],
                |row| row.get(0),
            )
            .optional()
            .unwrap_or_else(|e| {
                tracing::warn!("SQLite error querying assetcreators: {}", e);
                None
            });

        result.and_then(|bytes| {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(Address(arr))
            } else {
                None
            }
        })
    }

    // ---- Catchpoint staging table helpers ----

    /// Accessor for the underlying SQLite connection.
    #[allow(dead_code)] // Used by catchpoint importer (Wave 2+).
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Create all catchpoint staging tables in a single transaction.
    ///
    /// These tables mirror the Go `catchpoint*` staging tables used during
    /// catchpoint import. Data is staged here before the cutover to live tables.
    pub fn create_catchpoint_staging_tables(&self) -> Result<(), AlgoError> {
        self.conn
            .execute_batch(CATCHPOINT_STAGING_TABLES_SQL)
            .map_err(|e| AlgoError::Ledger {
                message: format!("create catchpoint staging tables error: {e}"),
            })
    }

    /// Drop all catchpoint staging tables.
    pub fn drop_catchpoint_staging_tables(&self) -> Result<(), AlgoError> {
        self.conn
            .execute_batch(
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
                ",
            )
            .map_err(|e| AlgoError::Ledger {
                message: format!("drop catchpoint staging tables error: {e}"),
            })
    }
}

/// Initialize the `algod_rust_meta` table after a catchpoint import.
///
/// This populates the chain-level metadata that `SqliteLedger::init` reads
/// on startup. Should be called after `atomic_cutover` completes, within the
/// same database connection.
///
/// # Arguments
///
/// * `conn` — open SQLite connection (same one used for catchpoint import)
/// * `round` — the balances round from the catchpoint header
/// * `genesis_id` — the genesis ID for the network (e.g. "mainnet-v1.0")
/// * `genesis_hash` — the 32-byte genesis hash
/// * `protocol` — the consensus protocol version string
/// * `txn_counter` — transaction counter from the catchpoint round; used to
///   seed asset/app ID generation in the first post-import block. Typically
///   derived from `MAX(asset) FROM assetcreators` when the catchpoint file
///   header does not carry this field directly.
/// * `rewards_level` — cumulative rewards level from the catchpoint header's
///   `AccountTotals.rewards_level`
pub fn initialize_meta_from_catchpoint(
    conn: &Connection,
    round: u64,
    genesis_id: &str,
    genesis_hash: &[u8; 32],
    protocol: &str,
    txn_counter: u64,
    rewards_level: u64,
) -> Result<(), AlgoError> {
    // G6 part 3: the legacy `algod_rust_meta` table is gone. Instead,
    // seed the canonical sources that `SqliteLedger::init` reads on
    // next open:
    //   - `acctrounds.acctbase = round` (already written by the
    //     catchpoint importer's `atomic_cutover`, but we set it again
    //     defensively for callers that invoke this function outside
    //     of the importer).
    //   - A synthesized minimal `BlockHeader` at `round` in
    //     `blockdb.blocks`. The header carries the genesis fields,
    //     protocol, `txn_counter`, and `rewards_level` from the
    //     catchpoint header so derivation produces the same values
    //     the old meta cache used to expose. The rewards-state fields
    //     not present in the catchpoint header (rate, residue,
    //     recalculation round, fee sink, rewards pool) default to
    //     zero — they are corrected by the first applied post-import
    //     block, the same behaviour the legacy meta path had.
    //
    // If lookback download later writes the real round-N header into
    // `blockdb.blocks`, this synthesized row is overwritten via
    // `put_block`'s `ON CONFLICT DO UPDATE`.
    let hdr = algo_types::BlockHeader {
        round: Round(round),
        genesis_id: genesis_id.to_string(),
        genesis_hash: *genesis_hash,
        current_protocol: protocol.to_string(),
        txn_counter,
        rewards_level,
        ..algo_types::BlockHeader::default()
    };

    let hdrdata = rmp_serde::to_vec_named(&hdr).map_err(|e| AlgoError::Ledger {
        message: format!("encode synthesized catchpoint header: {e}"),
    })?;
    // The catchpoint flow opens a bare connection via
    // `open_ledger_connection`, which deliberately does NOT run
    // `SCHEMA_BLOCK_SQL` — lookback download is what conventionally
    // creates `blockdb.blocks`. Create it defensively here so the
    // seed write doesn't fail with "no such table" when
    // `initialize_meta_from_catchpoint` runs before any block has
    // been written.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS blockdb.blocks (
             rnd INTEGER PRIMARY KEY,
             proto TEXT,
             hdrdata BLOB,
             blkdata BLOB,
             certdata BLOB
         );",
    )
    .map_err(|e| AlgoError::Ledger {
        message: format!("ensure blockdb.blocks exists: {e}"),
    })?;
    // Use a zero-length blkdata placeholder; the real block payload
    // arrives via lookback download. Downstream readers that hit the
    // payload before lookback completes already need to tolerate
    // missing transactions for the catchpoint round.
    conn.execute(
        "INSERT INTO blockdb.blocks (rnd, proto, hdrdata, blkdata) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(rnd) DO UPDATE SET proto=excluded.proto, hdrdata=excluded.hdrdata",
        params![round as i64, protocol, hdrdata, &[] as &[u8]],
    )
    .map_err(|e| AlgoError::Ledger {
        message: format!("seed catchpoint block header: {e}"),
    })?;

    conn.execute(
        "INSERT OR REPLACE INTO acctrounds (id, rnd) VALUES ('acctbase', ?1)",
        params![round as i64],
    )
    .map_err(|e| AlgoError::Ledger {
        message: format!("seed acctrounds: {e}"),
    })?;

    tracing::info!(
        "initialized chain meta from catchpoint: round={}, genesis_id={}, protocol={}, \
         txn_counter={}, rewards_level={}",
        round,
        genesis_id,
        protocol,
        txn_counter,
        rewards_level,
    );

    Ok(())
}

/// DDL for catchpoint staging tables (matches go-algorand exactly).
///
/// This is the single source of truth for staging table schemas. The
/// catchpoint importer references this constant via
/// `crate::sqlite::catchpoint_staging_ddl()`.
pub(crate) const CATCHPOINT_STAGING_TABLES_SQL: &str = "
CREATE TABLE IF NOT EXISTS catchpointassetcreators (
    asset INTEGER PRIMARY KEY,
    creator BLOB,
    ctype INTEGER
);

CREATE TABLE IF NOT EXISTS catchpointbalances (
    addrid INTEGER PRIMARY KEY NOT NULL,
    address BLOB NOT NULL,
    data BLOB,
    normalizedonlinebalance INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS catchpointbalances_address_idx
    ON catchpointbalances (address);

CREATE INDEX IF NOT EXISTS catchpointbalances_nob_idx
    ON catchpointbalances ( normalizedonlinebalance, address, data ) WHERE normalizedonlinebalance>0;

CREATE TABLE IF NOT EXISTS catchpointpendinghashes (
    data BLOB
);

CREATE TABLE IF NOT EXISTS catchpointaccounthashes (
    id INTEGER PRIMARY KEY,
    data BLOB
);

-- G5: `ctype` matches the live `resources` shape — the catchpoint
-- importer renames this staging table over `resources` at cutover, so
-- it must declare the same `NOT NULL DEFAULT -1` shape or cutover would
-- bypass the invariant.
CREATE TABLE IF NOT EXISTS catchpointresources (
    addrid INTEGER NOT NULL,
    aidx INTEGER NOT NULL,
    data BLOB NOT NULL,
    ctype INTEGER NOT NULL DEFAULT -1,
    PRIMARY KEY (addrid, aidx)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS catchpointkvstore (
    key BLOB PRIMARY KEY,
    value BLOB
);

CREATE TABLE IF NOT EXISTS catchpointonlineaccounts (
    address BLOB NOT NULL,
    updround INTEGER NOT NULL,
    normalizedonlinebalance INTEGER NOT NULL,
    votelastvalid INTEGER NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (address, updround)
);

CREATE INDEX IF NOT EXISTS catchpointonlineaccounts_norm_idx
    ON catchpointonlineaccounts ( normalizedonlinebalance, address );

CREATE INDEX IF NOT EXISTS catchpointonlineaccounts_vlv_idx
    ON catchpointonlineaccounts ( votelastvalid );

CREATE TABLE IF NOT EXISTS catchpointonlineroundparamstail (
    rnd INTEGER NOT NULL PRIMARY KEY,
    data BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS catchpointstateproofverification (
    lastattestedround INTEGER PRIMARY KEY NOT NULL,
    verificationContext BLOB NOT NULL
);
";

// ---------------------------------------------------------------------------
// LedgerStore implementation
// ---------------------------------------------------------------------------

impl LedgerStore for SqliteLedger {
    type Snapshot = String; // SAVEPOINT name

    // ---- Accounts ----

    fn get_account(&self, addr: &Address) -> Option<AccountData> {
        let result: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT data FROM accountbase WHERE address = ?1",
                params![addr.0.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .unwrap_or_else(|e| {
                tracing::warn!("SQLite error querying account: {}", e);
                None
            });

        result.and_then(|data| decode_account_data(&data).ok())
    }

    fn set_account(&mut self, addr: &Address, account: AccountData) {
        let old = self.get_account(addr);
        // Issue #523: fold this write's status/balance change into the
        // block-level `accounttotals` delta accumulator (flushed once at
        // `commit_block`) — see `AccountTotalsDelta::fold`.
        let level = self.rewards_level;
        if let Some(old) = &old {
            self.pending_totals_delta.fold(old, level, -1);
        }
        self.pending_totals_delta.fold(&account, level, 1);
        if self.trie.is_some() {
            self.pre_mutations.push(SqlitePreMutation::Account {
                addr: *addr,
                old_data: old.map(Box::new),
            });
        }
        let data = encode_account_data(&account);
        // Compute normalizedonlinebalance using Go's formula (rewards-adjusted
        // balance estimate at round 0). See NormalizedOnlineAccountBalance in
        // go-algorand data/basics/userBalance.go.
        let nob = account_nob_i64(&account);
        // Use ON CONFLICT ... DO UPDATE instead of INSERT OR REPLACE to preserve
        // the rowid. INSERT OR REPLACE deletes and re-inserts, which changes the
        // rowid and orphans resources table entries that reference addrid.
        self.conn
            .execute(
                "INSERT INTO accountbase (address, normalizedonlinebalance, data) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(address) DO UPDATE SET normalizedonlinebalance = excluded.normalizedonlinebalance, data = excluded.data",
                params![addr.0.as_slice(), nob, data],
            )
            .expect("set_account");
    }

    fn remove_account(&mut self, addr: &Address) {
        let old = self.get_account(addr);
        // Issue #523: fold the removal (no replacement state) into the
        // block-level `accounttotals` delta accumulator — see `set_account`.
        if let Some(old) = &old {
            self.pending_totals_delta.fold(old, self.rewards_level, -1);
        }
        if self.trie.is_some() {
            self.pre_mutations.push(SqlitePreMutation::Account {
                addr: *addr,
                old_data: old.map(Box::new),
            });
        }
        // Also remove all resources for this account.
        if let Some(rowid) = self.get_rowid(addr) {
            let _ = self
                .conn
                .execute("DELETE FROM resources WHERE addrid = ?1", params![rowid]);
        }
        let _ = self.conn.execute(
            "DELETE FROM accountbase WHERE address = ?1",
            params![addr.0.as_slice()],
        );
    }

    // ---- Asset Holdings ----

    fn get_asset_holding(&self, addr: &Address, asset_id: u64) -> Option<AssetHolding> {
        let rowid = self.get_rowid(addr)?;
        let data: Vec<u8> = self
            .conn
            .query_row(
                "SELECT data FROM resources WHERE addrid = ?1 AND aidx = ?2 AND ctype = ?3",
                params![rowid, asset_id as i64, CTYPE_ASSET],
                |row| row.get(0),
            )
            .optional()
            .unwrap_or_else(|e| {
                tracing::warn!("SQLite error querying asset holding: {}", e);
                None
            })?;

        // Check that the blob has the holding flag set (could be params-only).
        let meta = inspect_resource_blob(&data);
        if !meta.has_holding {
            return None;
        }

        decode_asset_holding(&data).ok()
    }

    fn set_asset_holding(&mut self, addr: &Address, asset_id: u64, holding: AssetHolding) {
        self.record_resource_pre_mutation(addr, asset_id, CTYPE_ASSET);
        let rowid = self.get_or_insert_rowid(addr).expect("get_or_insert_rowid");
        let update_round = self.current_round.0;

        // Check if an existing blob has ownership (params) flag set; if so, merge.
        let data = if let Some(existing) = self.get_asset_resource_blob(rowid, asset_id) {
            let meta = inspect_resource_blob(&existing);
            if meta.has_ownership {
                // Existing blob has asset params — merge holding into it.
                merge_asset_holding_into_params(&existing, &holding)
            } else {
                encode_asset_holding(&holding)
            }
        } else {
            encode_asset_holding(&holding)
        };
        // Stamp the resource blob with the current round's UpdateRound.
        let data = set_blob_update_round(&data, update_round);

        self.conn
            .execute(
                "INSERT OR REPLACE INTO resources (addrid, aidx, data, ctype) VALUES (?1, ?2, ?3, ?4)",
                params![rowid, asset_id as i64, data, CTYPE_ASSET],
            )
            .expect("set_asset_holding");
    }

    fn remove_asset_holding(&mut self, addr: &Address, asset_id: u64) {
        self.record_resource_pre_mutation(addr, asset_id, CTYPE_ASSET);
        let update_round = self.current_round.0;
        if let Some(rowid) = self.get_rowid(addr) {
            // Check if the blob also has ownership (asset params) data.
            if let Some(existing) = self.get_asset_resource_blob(rowid, asset_id) {
                let meta = inspect_resource_blob(&existing);
                if meta.has_ownership {
                    // Both flags set — strip holding, keep asset params.
                    if let Some(stripped) = strip_asset_holding_from_blob(&existing) {
                        let stripped = set_blob_update_round(&stripped, update_round);
                        let _ = self.conn.execute(
                            "UPDATE resources SET data = ?1 WHERE addrid = ?2 AND aidx = ?3 AND ctype = ?4",
                            params![stripped, rowid, asset_id as i64, CTYPE_ASSET],
                        );
                    }
                } else {
                    // Only holding — delete the whole row.
                    let _ = self.conn.execute(
                        "DELETE FROM resources WHERE addrid = ?1 AND aidx = ?2 AND ctype = ?3",
                        params![rowid, asset_id as i64, CTYPE_ASSET],
                    );
                }
            }
        }
    }

    fn has_asset_holding(&self, addr: &Address, asset_id: u64) -> bool {
        self.get_asset_holding(addr, asset_id).is_some()
    }

    fn remove_all_asset_holdings_for_asset(&mut self, asset_id: u64) {
        // Find all (addrid, data, address) rows for this asset_id with a holding flag.
        let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT r.addrid, r.data, a.address FROM resources r \
                     JOIN accountbase a ON a.rowid = r.addrid \
                     WHERE r.aidx = ?1 AND r.ctype = ?2",
                )
                .expect("prepare remove_all_asset_holdings_for_asset");
            stmt.query_map(params![asset_id as i64, CTYPE_ASSET], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .expect("query remove_all_asset_holdings_for_asset")
            .filter_map(|r| r.ok())
            .collect()
        };

        // Track which addresses had holdings removed for counter updates.
        let mut affected_addrs: Vec<Address> = Vec::new();

        let update_round = self.current_round.0;
        for (rowid, data, addr_bytes) in &rows {
            let meta = inspect_resource_blob(data);
            if !meta.has_holding {
                continue; // no holding in this blob
            }
            // Record this address for counter update.
            if addr_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(addr_bytes);
                affected_addrs.push(Address(arr));
            }
            if meta.has_ownership {
                // Both flags set — strip holding, keep asset params.
                if let Some(stripped) = strip_asset_holding_from_blob(data) {
                    let stripped = set_blob_update_round(&stripped, update_round);
                    let _ = self.conn.execute(
                        "UPDATE resources SET data = ?1 WHERE addrid = ?2 AND aidx = ?3 AND ctype = ?4",
                        params![stripped, rowid, asset_id as i64, CTYPE_ASSET],
                    );
                }
            } else {
                // Only holding — delete the whole row.
                let _ = self.conn.execute(
                    "DELETE FROM resources WHERE addrid = ?1 AND aidx = ?2 AND ctype = ?3",
                    params![rowid, asset_id as i64, CTYPE_ASSET],
                );
            }
        }

        // Decrement total_assets_opted_in for each affected account.
        for addr in affected_addrs {
            let mut acct = self.get_or_default_account(&addr);
            acct.total_assets_opted_in = acct.total_assets_opted_in.saturating_sub(1);
            self.set_account(&addr, acct);
        }
    }

    // ---- Asset Params ----

    fn get_asset_params(&self, asset_id: u64) -> Option<AssetParamsRecord> {
        // Get creator from assetcreators table.
        let creator = self.get_creator_from_assetcreators(asset_id)?;

        // Get params from resources table using creator's rowid.
        let rowid = self.get_rowid(&creator)?;
        let data: Vec<u8> = self
            .conn
            .query_row(
                "SELECT data FROM resources WHERE addrid = ?1 AND aidx = ?2 AND ctype = ?3",
                params![rowid, asset_id as i64, CTYPE_ASSET],
                |row| row.get(0),
            )
            .optional()
            .unwrap_or_else(|e| {
                tracing::warn!("SQLite error querying asset params: {}", e);
                None
            })?;

        // Check that the blob has the ownership flag set.
        let meta = inspect_resource_blob(&data);
        if !meta.has_ownership {
            return None;
        }

        let params = decode_asset_params(&data).ok()?;
        Some(AssetParamsRecord { params, creator })
    }

    fn set_asset_params(&mut self, asset_id: u64, record: AssetParamsRecord) {
        self.record_resource_pre_mutation(&record.creator, asset_id, CTYPE_ASSET);
        let rowid = self
            .get_or_insert_rowid(&record.creator)
            .expect("get_or_insert_rowid");
        let update_round = self.current_round.0;

        // Check if an existing blob has holding flag set; if so, merge.
        let data = if let Some(existing) = self.get_asset_resource_blob(rowid, asset_id) {
            let meta = inspect_resource_blob(&existing);
            if meta.has_holding {
                // Existing blob has asset holding — merge params into it.
                merge_asset_params_into_holding(&existing, &record.params, &record.creator)
            } else {
                encode_asset_params(&record.params, &record.creator)
            }
        } else {
            encode_asset_params(&record.params, &record.creator)
        };
        // Stamp the resource blob with the current round's UpdateRound.
        let data = set_blob_update_round(&data, update_round);

        // Upsert into resources.
        self.conn
            .execute(
                "INSERT OR REPLACE INTO resources (addrid, aidx, data, ctype) VALUES (?1, ?2, ?3, ?4)",
                params![rowid, asset_id as i64, data, CTYPE_ASSET],
            )
            .expect("set_asset_params resource");

        // Upsert into assetcreators.
        self.conn
            .execute(
                "INSERT OR REPLACE INTO assetcreators (asset, creator, ctype) VALUES (?1, ?2, ?3)",
                params![asset_id as i64, record.creator.0.as_slice(), CTYPE_ASSET],
            )
            .expect("set_asset_params assetcreators");
    }

    fn remove_asset_params(&mut self, asset_id: u64) {
        // Record pre-mutation for trie tracking.
        if self.trie.is_some() {
            if let Some(creator) = self.get_creator_from_assetcreators(asset_id) {
                self.record_resource_pre_mutation(&creator, asset_id, CTYPE_ASSET);
            }
        }
        let update_round = self.current_round.0;
        // Get creator to find the rowid.
        if let Some(creator) = self.get_creator_from_assetcreators(asset_id) {
            if let Some(rowid) = self.get_rowid(&creator) {
                // Check if the blob also has holding data.
                if let Some(existing) = self.get_asset_resource_blob(rowid, asset_id) {
                    let meta = inspect_resource_blob(&existing);
                    if meta.has_holding {
                        // Both flags set — strip params, keep holding.
                        if let Some(stripped) = strip_asset_params_from_blob(&existing) {
                            let stripped = set_blob_update_round(&stripped, update_round);
                            let _ = self.conn.execute(
                                "UPDATE resources SET data = ?1 WHERE addrid = ?2 AND aidx = ?3 AND ctype = ?4",
                                params![stripped, rowid, asset_id as i64, CTYPE_ASSET],
                            );
                        }
                    } else {
                        // Only ownership — delete the whole row.
                        let _ = self.conn.execute(
                            "DELETE FROM resources WHERE addrid = ?1 AND aidx = ?2 AND ctype = ?3",
                            params![rowid, asset_id as i64, CTYPE_ASSET],
                        );
                    }
                }
            }
        }
        // Always remove from assetcreators.
        let _ = self.conn.execute(
            "DELETE FROM assetcreators WHERE asset = ?1",
            params![asset_id as i64],
        );
    }

    fn has_asset_params(&self, asset_id: u64) -> bool {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM assetcreators WHERE asset = ?1 AND ctype = ?2",
                params![asset_id as i64, CTYPE_ASSET],
                |row| row.get(0),
            )
            .unwrap_or(0);
        count > 0
    }

    // ---- App Params ----

    fn get_app_params(&self, app_id: u64) -> Option<AppParams> {
        let creator = self.get_creator_from_assetcreators(app_id)?;
        let rowid = self.get_rowid(&creator)?;
        let data: Vec<u8> = self
            .conn
            .query_row(
                "SELECT data FROM resources WHERE addrid = ?1 AND aidx = ?2 AND ctype = ?3",
                params![rowid, app_id as i64, CTYPE_APP],
                |row| row.get(0),
            )
            .optional()
            .unwrap_or_else(|e| {
                tracing::warn!("SQLite error querying app params: {}", e);
                None
            })?;

        // Check that the blob has the ownership flag set.
        let meta = inspect_resource_blob(&data);
        if !meta.has_ownership {
            return None;
        }

        decode_app_params(&data, creator).ok()
    }

    fn set_app_params(&mut self, app_id: u64, params: AppParams) {
        let creator = params.creator;
        self.record_resource_pre_mutation(&creator, app_id, CTYPE_APP);
        let rowid = self
            .get_or_insert_rowid(&creator)
            .expect("get_or_insert_rowid");
        let update_round = self.current_round.0;

        // Check if a local-state blob already exists at this key; if so, merge.
        let data = if let Some(existing) = self.get_app_resource_blob(rowid, app_id) {
            let meta = inspect_resource_blob(&existing);
            if meta.has_holding {
                // Existing blob has local state — merge app params into it.
                merge_app_params_into_local_state(&existing, &params)
            } else {
                encode_app_params(&params)
            }
        } else {
            encode_app_params(&params)
        };
        // Stamp the resource blob with the current round's UpdateRound.
        let data = set_blob_update_round(&data, update_round);

        self.conn
            .execute(
                "INSERT OR REPLACE INTO resources (addrid, aidx, data, ctype) VALUES (?1, ?2, ?3, ?4)",
                params![rowid, app_id as i64, data, CTYPE_APP],
            )
            .expect("set_app_params resource");

        self.conn
            .execute(
                "INSERT OR REPLACE INTO assetcreators (asset, creator, ctype) VALUES (?1, ?2, ?3)",
                params![app_id as i64, creator.0.as_slice(), CTYPE_APP],
            )
            .expect("set_app_params assetcreators");
    }

    fn remove_app_params(&mut self, app_id: u64) {
        // Record pre-mutation for trie tracking.
        if self.trie.is_some() {
            if let Some(creator) = self.get_creator_from_assetcreators(app_id) {
                self.record_resource_pre_mutation(&creator, app_id, CTYPE_APP);
            }
        }
        let update_round = self.current_round.0;
        if let Some(creator) = self.get_creator_from_assetcreators(app_id) {
            if let Some(rowid) = self.get_rowid(&creator) {
                // Check if the blob also has holding (local state) data.
                if let Some(existing) = self.get_app_resource_blob(rowid, app_id) {
                    let meta = inspect_resource_blob(&existing);
                    if meta.has_holding {
                        // Both flags set — strip ownership, keep local state.
                        if let Some(stripped) = strip_ownership_from_blob(&existing) {
                            let stripped = set_blob_update_round(&stripped, update_round);
                            let _ = self.conn.execute(
                                "UPDATE resources SET data = ?1 WHERE addrid = ?2 AND aidx = ?3 AND ctype = ?4",
                                params![stripped, rowid, app_id as i64, CTYPE_APP],
                            );
                        }
                    } else {
                        // Only ownership — delete the whole row.
                        let _ = self.conn.execute(
                            "DELETE FROM resources WHERE addrid = ?1 AND aidx = ?2 AND ctype = ?3",
                            params![rowid, app_id as i64, CTYPE_APP],
                        );
                    }
                }
            }
        }
        let _ = self.conn.execute(
            "DELETE FROM assetcreators WHERE asset = ?1 AND ctype = ?2",
            params![app_id as i64, CTYPE_APP],
        );
    }

    fn has_app_params(&self, app_id: u64) -> bool {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM assetcreators WHERE asset = ?1 AND ctype = ?2",
                params![app_id as i64, CTYPE_APP],
                |row| row.get(0),
            )
            .unwrap_or(0);
        count > 0
    }

    fn app_params_created_by(&self, creator: &Address) -> Vec<AppParams> {
        let rowid = match self.get_rowid(creator) {
            Some(r) => r,
            None => return Vec::new(),
        };

        let mut stmt = self
            .conn
            .prepare("SELECT aidx, data FROM resources WHERE addrid = ?1 AND ctype = ?2")
            .expect("prepare app_params_created_by");

        let results: Vec<AppParams> = stmt
            .query_map(params![rowid, CTYPE_APP], |row| {
                let data: Vec<u8> = row.get(1)?;
                Ok(data)
            })
            .expect("query app_params_created_by")
            .filter_map(|r| r.ok())
            .filter_map(|data| {
                // Only include blobs with ownership flag.
                let meta = inspect_resource_blob(&data);
                if !meta.has_ownership {
                    return None;
                }
                decode_app_params(&data, *creator).ok()
            })
            .collect();

        results
    }

    // ---- App Local States ----

    fn get_app_local_state(&self, addr: &Address, app_id: u64) -> Option<AppLocalState> {
        let rowid = self.get_rowid(addr)?;
        // Go stores both app params and app local state in the same resources
        // table — params under creator's addrid, local state under the user's addrid,
        // both with the same aidx (app_id) and ctype=CTYPE_APP.
        // The resource blob's "y" flags distinguish them.
        let data: Vec<u8> = self
            .conn
            .query_row(
                "SELECT data FROM resources WHERE addrid = ?1 AND aidx = ?2 AND ctype = ?3",
                params![rowid, app_id as i64, CTYPE_APP],
                |row| row.get(0),
            )
            .optional()
            .unwrap_or_else(|e| {
                tracing::warn!("SQLite error querying app local state: {}", e);
                None
            })?;

        // Check that the blob has the holding flag set.
        let meta = inspect_resource_blob(&data);
        if !meta.has_holding {
            // No holding flag — this is app params only, not local state.
            return None;
        }

        decode_app_local_state(&data).ok()
    }

    fn set_app_local_state(&mut self, addr: &Address, app_id: u64, local_state: AppLocalState) {
        self.record_resource_pre_mutation(addr, app_id, CTYPE_APP);
        let rowid = self.get_or_insert_rowid(addr).expect("get_or_insert_rowid");
        let update_round = self.current_round.0;

        // Check if an app-params blob already exists at this key; if so, merge.
        let data = if let Some(existing) = self.get_app_resource_blob(rowid, app_id) {
            let meta = inspect_resource_blob(&existing);
            if meta.has_ownership {
                // Existing blob has app params — merge local state into it.
                merge_app_local_state_into_params(&existing, &local_state)
            } else {
                encode_app_local_state(&local_state)
            }
        } else {
            encode_app_local_state(&local_state)
        };
        // Stamp the resource blob with the current round's UpdateRound.
        let data = set_blob_update_round(&data, update_round);

        self.conn
            .execute(
                "INSERT OR REPLACE INTO resources (addrid, aidx, data, ctype) VALUES (?1, ?2, ?3, ?4)",
                params![rowid, app_id as i64, data, CTYPE_APP],
            )
            .expect("set_app_local_state");
    }

    fn remove_app_local_state(&mut self, addr: &Address, app_id: u64) {
        self.record_resource_pre_mutation(addr, app_id, CTYPE_APP);
        let update_round = self.current_round.0;
        if let Some(rowid) = self.get_rowid(addr) {
            // Check if the blob also has ownership (app params) data.
            if let Some(existing) = self.get_app_resource_blob(rowid, app_id) {
                let meta = inspect_resource_blob(&existing);
                if meta.has_ownership {
                    // Both flags set — strip holding, keep app params.
                    if let Some(stripped) = strip_holding_from_blob(&existing) {
                        let stripped = set_blob_update_round(&stripped, update_round);
                        let _ = self.conn.execute(
                            "UPDATE resources SET data = ?1 WHERE addrid = ?2 AND aidx = ?3 AND ctype = ?4",
                            params![stripped, rowid, app_id as i64, CTYPE_APP],
                        );
                    }
                } else {
                    // Only holding — delete the whole row.
                    let _ = self.conn.execute(
                        "DELETE FROM resources WHERE addrid = ?1 AND aidx = ?2 AND ctype = ?3",
                        params![rowid, app_id as i64, CTYPE_APP],
                    );
                }
            }
        }
    }

    fn has_app_local_state(&self, addr: &Address, app_id: u64) -> bool {
        self.get_app_local_state(addr, app_id).is_some()
    }

    fn remove_all_app_local_states_for_app(&mut self, app_id: u64) {
        // Find all (addrid, data, address) rows for this app_id with a holding flag (local state).
        let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT r.addrid, r.data, a.address FROM resources r \
                     JOIN accountbase a ON a.rowid = r.addrid \
                     WHERE r.aidx = ?1 AND r.ctype = ?2",
                )
                .expect("prepare remove_all_app_local_states_for_app");
            stmt.query_map(params![app_id as i64, CTYPE_APP], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .expect("query remove_all_app_local_states_for_app")
            .filter_map(|r| r.ok())
            .collect()
        };

        // Track affected addresses and their local schemas for counter updates.
        let mut affected: Vec<(Address, StateSchema)> = Vec::new();

        let update_round = self.current_round.0;
        for (rowid, data, addr_bytes) in &rows {
            let meta = inspect_resource_blob(data);
            if !meta.has_holding {
                continue; // no local state in this blob
            }
            // Decode the local state schema before removing.
            if addr_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(addr_bytes);
                let local_schema = decode_app_local_state(data)
                    .map(|ls| ls.schema)
                    .unwrap_or_default();
                affected.push((Address(arr), local_schema));
            }
            if meta.has_ownership {
                // Both flags set — strip local state, keep app params.
                if let Some(stripped) = strip_holding_from_blob(data) {
                    let stripped = set_blob_update_round(&stripped, update_round);
                    let _ = self.conn.execute(
                        "UPDATE resources SET data = ?1 WHERE addrid = ?2 AND aidx = ?3 AND ctype = ?4",
                        params![stripped, rowid, app_id as i64, CTYPE_APP],
                    );
                }
            } else {
                // Only local state — delete the whole row.
                let _ = self.conn.execute(
                    "DELETE FROM resources WHERE addrid = ?1 AND aidx = ?2 AND ctype = ?3",
                    params![rowid, app_id as i64, CTYPE_APP],
                );
            }
        }

        // Decrement total_apps_opted_in and subtract local schema for each affected account.
        for (addr, local_schema) in affected {
            let mut acct = self.get_or_default_account(&addr);
            acct.total_apps_opted_in = acct.total_apps_opted_in.saturating_sub(1);
            acct.total_app_schema = acct.total_app_schema.sub_schema(&local_schema);
            self.set_account(&addr, acct);
        }
    }

    fn app_local_states_for_addr(&self, addr: &Address) -> Vec<(u64, AppLocalState)> {
        let rowid = match self.get_rowid(addr) {
            Some(r) => r,
            None => return Vec::new(),
        };

        let mut stmt = self
            .conn
            .prepare("SELECT aidx, data FROM resources WHERE addrid = ?1 AND ctype = ?2")
            .expect("prepare app_local_states_for_addr");

        let results: Vec<(u64, AppLocalState)> = stmt
            .query_map(params![rowid, CTYPE_APP], |row| {
                let aidx: i64 = row.get(0)?;
                let data: Vec<u8> = row.get(1)?;
                Ok((aidx, data))
            })
            .expect("query app_local_states_for_addr")
            .filter_map(|r| r.ok())
            .filter_map(|(aidx, data)| {
                // Check that the holding flag is set (local state present).
                let meta = inspect_resource_blob(&data);
                if !meta.has_holding {
                    return None; // no local state in this blob
                }
                let local = decode_app_local_state(&data).ok()?;
                Some((aidx as u64, local))
            })
            .collect();

        results
    }

    fn asset_holdings_for_addr(&self, addr: &Address) -> Vec<(u64, AssetHolding)> {
        let rowid = match self.get_rowid(addr) {
            Some(r) => r,
            None => return Vec::new(),
        };

        let mut stmt = self
            .conn
            .prepare("SELECT aidx, data FROM resources WHERE addrid = ?1 AND ctype = ?2")
            .expect("prepare asset_holdings_for_addr");

        let results: Vec<(u64, AssetHolding)> = stmt
            .query_map(params![rowid, CTYPE_ASSET], |row| {
                let aidx: i64 = row.get(0)?;
                let data: Vec<u8> = row.get(1)?;
                Ok((aidx, data))
            })
            .expect("query asset_holdings_for_addr")
            .filter_map(|r| r.ok())
            .filter_map(|(aidx, data)| {
                // Check that the holding flag is set.
                let meta = inspect_resource_blob(&data);
                if !meta.has_holding {
                    return None;
                }
                let holding = decode_asset_holding(&data).ok()?;
                Some((aidx as u64, holding))
            })
            .collect();

        results
    }

    fn created_assets_for_addr(&self, addr: &Address) -> Vec<(u64, AssetParamsRecord)> {
        let rowid = match self.get_rowid(addr) {
            Some(r) => r,
            None => return Vec::new(),
        };

        let mut stmt = self
            .conn
            .prepare("SELECT aidx, data FROM resources WHERE addrid = ?1 AND ctype = ?2")
            .expect("prepare created_assets_for_addr");

        let results: Vec<(u64, AssetParamsRecord)> = stmt
            .query_map(params![rowid, CTYPE_ASSET], |row| {
                let aidx: i64 = row.get(0)?;
                let data: Vec<u8> = row.get(1)?;
                Ok((aidx, data))
            })
            .expect("query created_assets_for_addr")
            .filter_map(|r| r.ok())
            .filter_map(|(aidx, data)| {
                // Only include blobs with ownership flag (creator/params data).
                let meta = inspect_resource_blob(&data);
                if !meta.has_ownership {
                    return None;
                }
                let params = decode_asset_params(&data).ok()?;
                Some((
                    aidx as u64,
                    AssetParamsRecord {
                        params,
                        creator: *addr,
                    },
                ))
            })
            .collect();

        results
    }

    fn created_apps_for_addr(&self, addr: &Address) -> Vec<(u64, AppParams)> {
        let rowid = match self.get_rowid(addr) {
            Some(r) => r,
            None => return Vec::new(),
        };

        let mut stmt = self
            .conn
            .prepare("SELECT aidx, data FROM resources WHERE addrid = ?1 AND ctype = ?2")
            .expect("prepare created_apps_for_addr");

        let results: Vec<(u64, AppParams)> = stmt
            .query_map(params![rowid, CTYPE_APP], |row| {
                let aidx: i64 = row.get(0)?;
                let data: Vec<u8> = row.get(1)?;
                Ok((aidx, data))
            })
            .expect("query created_apps_for_addr")
            .filter_map(|r| r.ok())
            .filter_map(|(aidx, data)| {
                // Only include blobs with ownership flag.
                let meta = inspect_resource_blob(&data);
                if !meta.has_ownership {
                    return None;
                }
                decode_app_params(&data, *addr)
                    .ok()
                    .map(|p| (aidx as u64, p))
            })
            .collect();

        results
    }

    // ---- Box Storage ----

    fn get_box(&self, app_id: u64, key: &[u8]) -> Option<Vec<u8>> {
        let full_key = make_box_key(app_id, key);
        self.conn
            .query_row(
                "SELECT value FROM kvstore WHERE key = ?1",
                params![full_key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .unwrap_or(None)
    }

    fn set_box(&mut self, app_id: u64, key: &[u8], value: Vec<u8>) {
        let full_key = make_box_key(app_id, key);

        // Record pre-mutation for trie tracking.
        if self.trie.is_some() {
            let old_value = self
                .conn
                .query_row(
                    "SELECT value FROM kvstore WHERE key = ?1",
                    params![full_key],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
                .unwrap_or(None);
            self.pre_mutations.push(SqlitePreMutation::Kv {
                full_key: full_key.clone(),
                old_value,
            });
        }

        self.conn
            .execute(
                "INSERT INTO kvstore (key, value) VALUES (?1, ?2) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![full_key, value],
            )
            .expect("set_box upsert");
    }

    fn delete_box(&mut self, app_id: u64, key: &[u8]) -> bool {
        let full_key = make_box_key(app_id, key);

        // Record pre-mutation for trie tracking.
        if self.trie.is_some() {
            let old_value = self
                .conn
                .query_row(
                    "SELECT value FROM kvstore WHERE key = ?1",
                    params![full_key],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
                .unwrap_or(None);
            if old_value.is_some() {
                self.pre_mutations.push(SqlitePreMutation::Kv {
                    full_key: full_key.clone(),
                    old_value,
                });
            }
        }

        let rows = self
            .conn
            .execute("DELETE FROM kvstore WHERE key = ?1", params![full_key])
            .expect("delete_box");
        rows > 0
    }

    fn box_keys_for_app(&self, app_id: u64) -> Vec<Vec<u8>> {
        // Build the prefix: "bx:" + big-endian app_id
        let prefix = make_box_key(app_id, b"");
        let prefix_len = prefix.len();

        // Use a range query: keys that start with the prefix.
        // SQLite BLOB comparison works lexicographically, so we query for
        // keys >= prefix AND < prefix with the last byte incremented (or use
        // LIKE with the X'...' hex literal). A simpler approach: fetch all
        // matching keys and strip the prefix in Rust.
        let mut stmt = self
            .conn
            .prepare("SELECT key FROM kvstore WHERE key >= ?1 AND key < ?2")
            .expect("prepare box_keys_for_app");

        // Upper bound: increment the last byte of the app_id portion.
        // Since the prefix is "bx:" + 8-byte BE app_id, the upper bound is
        // "bx:" + BE(app_id + 1). For app_id == u64::MAX this would overflow,
        // so handle that edge case by using "by:" as the upper bound (next
        // prefix after "bx:"), which constrains results to keys that start
        // with "bx:" and avoids matching unrelated kvstore keys.
        let results: Vec<Vec<u8>> = if app_id == u64::MAX {
            let upper = b"by:".to_vec();
            stmt.query_map(params![prefix, upper], |row| row.get::<_, Vec<u8>>(0))
                .expect("query box_keys_for_app")
                .map(|r| r.expect("read box key row"))
                .map(|full_key| full_key[prefix_len..].to_vec())
                .collect()
        } else {
            let upper = make_box_key(app_id + 1, b"");
            stmt.query_map(params![prefix, upper], |row| row.get::<_, Vec<u8>>(0))
                .expect("query box_keys_for_app")
                .map(|r| r.expect("read box key row"))
                .map(|full_key| full_key[prefix_len..].to_vec())
                .collect()
        };

        results
    }

    // ---- Leases ----

    fn check_lease(
        &self,
        sender: &Address,
        lease: &[u8; 32],
        current_round: u64,
    ) -> Result<(), AlgoError> {
        self.lease_table.check(sender, lease, current_round)
    }

    fn record_lease(&mut self, sender: &Address, lease: &[u8; 32], last_valid: u64) {
        self.lease_table.record(sender, lease, last_valid);
    }

    fn purge_expired_leases(&mut self, current_round: u64) {
        self.lease_table.purge_expired(current_round);
    }

    // ---- Chain-level state (getters) ----

    fn current_round(&self) -> Round {
        self.current_round
    }

    fn rewards_level(&self) -> u64 {
        self.rewards_level
    }

    fn rewards_rate(&self) -> u64 {
        self.rewards_rate
    }

    fn rewards_residue(&self) -> u64 {
        self.rewards_residue
    }

    fn rewards_recalculation_round(&self) -> u64 {
        self.rewards_recalculation_round
    }

    fn fee_sink(&self) -> Address {
        self.fee_sink
    }

    fn rewards_pool(&self) -> Address {
        self.rewards_pool
    }

    fn genesis_id(&self) -> &str {
        &self.genesis_id
    }

    fn genesis_hash(&self) -> &[u8; 32] {
        &self.genesis_hash
    }

    fn protocol(&self) -> &str {
        &self.protocol
    }

    fn txn_counter(&self) -> u64 {
        self.txn_counter
    }

    fn account_totals(&self) -> crate::state_delta::AccountTotals {
        SqliteLedger::account_totals(self)
    }

    // ---- Chain-level state (setters) ----

    fn set_current_round(&mut self, round: Round) {
        self.current_round = round;
    }

    fn set_rewards_level(&mut self, level: u64) {
        self.rewards_level = level;
    }

    fn set_rewards_rate(&mut self, rate: u64) {
        self.rewards_rate = rate;
    }

    fn set_rewards_residue(&mut self, residue: u64) {
        self.rewards_residue = residue;
    }

    fn set_rewards_recalculation_round(&mut self, round: u64) {
        self.rewards_recalculation_round = round;
    }

    fn set_fee_sink(&mut self, addr: Address) {
        self.fee_sink = addr;
    }

    fn set_rewards_pool(&mut self, addr: Address) {
        self.rewards_pool = addr;
    }

    fn set_genesis_id(&mut self, id: String) {
        self.genesis_id = id;
    }

    fn set_genesis_hash(&mut self, hash: [u8; 32]) {
        self.genesis_hash = hash;
    }

    fn set_protocol(&mut self, protocol: String) {
        self.protocol = protocol;
    }

    fn set_txn_counter(&mut self, counter: u64) {
        self.txn_counter = counter;
    }

    // ---- Snapshot / Restore (SAVEPOINTs) ----
    //
    // NOTE: `snapshot` and `restore_snapshot` only revert database-stored state
    // (accounts, resources, assetcreators, meta). They do NOT revert cached
    // chain-level fields (current_round, rewards_level, fee_sink, etc.) on the
    // SqliteLedger struct. Those cached fields are only modified inside
    // `apply_block`, which has its own save/restore logic for chain-level state
    // before calling into transaction processing. SAVEPOINTs are used for
    // per-transaction rollback within a block, where chain-level state does not
    // change.

    fn snapshot(&self, _addrs: &[Address]) -> String {
        let n = self.savepoint_counter.fetch_add(1, Ordering::Relaxed);
        let name = format!("sp_{n}");
        self.conn
            .execute_batch(&format!("SAVEPOINT {name}"))
            .expect("savepoint");
        name
    }

    fn snapshot_with_ids(
        &self,
        _addrs: &[Address],
        _asset_ids: &[u64],
        _app_ids: &[u64],
    ) -> String {
        // SQLite SAVEPOINTs capture all changes, no need to filter by addr/id.
        self.snapshot(_addrs)
    }

    fn restore_snapshot(&mut self, snapshot: String) {
        // `ROLLBACK TO SAVEPOINT` reverts the changes made since the savepoint
        // but does NOT remove the savepoint from the transaction stack — the
        // savepoint (and, when it is the outermost one with no enclosing
        // BEGIN, the implicit transaction SQLite opened for it) stays active.
        // We must also `RELEASE` it. For the outermost savepoint the RELEASE
        // commits the now-empty (already rolled-back) implicit transaction and
        // closes it; for a savepoint nested inside an explicit BEGIN (the
        // block-apply path) the RELEASE merely pops it off the stack, leaving
        // the enclosing transaction open and the rolled-back state intact.
        //
        // Without the RELEASE the simulate path (which calls `snapshot`
        // directly, with no surrounding BEGIN) leaves a lingering open
        // transaction, so the next write fails with "cannot start a
        // transaction within a transaction" (BT-298). go-algorand's simulator
        // (ledger/simulation/simulator.go) evaluates against an eval snapshot
        // and never mutates the real ledger; this keeps the SQLite ledger
        // exactly as simulate found it, with no open transaction left behind.
        self.conn
            .execute_batch(&format!(
                "ROLLBACK TO SAVEPOINT {snapshot}; RELEASE SAVEPOINT {snapshot};"
            ))
            .expect("rollback to and release savepoint");
    }

    // ---- Min balance ----

    fn min_balance_with_state(&self, addr: &Address, account: &AccountData) -> u64 {
        let flat = crate::params::min_balance(account);
        let mut extra: u64 = 0;

        // Opted-in apps: add local state schema cost.
        for (_app_id, local_state) in self.app_local_states_for_addr(addr) {
            extra += crate::state::schema_min_balance(&local_state.schema);
        }

        // Created apps: add global state schema cost.
        for app in self.app_params_created_by(addr) {
            extra += crate::state::schema_min_balance(&app.global_state_schema);
        }

        flat + extra
    }

    // ---- Trie integration ----

    fn enable_trie(&mut self) {
        // Try to load persisted trie from DB; fall back to empty on error.
        if self.load_trie().is_err() {
            self.trie = Some(crate::merkle_trie::MerkleTrie::new(
                crate::trie_hash::ELEMENT_SIZE,
            ));
        }
        self.apply_trie_cache_target();
        self.pre_mutations.clear();
    }

    fn trie_enabled(&self) -> bool {
        self.trie.is_some()
    }

    fn finalize_trie_updates(&mut self) -> Option<[u8; 32]> {
        use crate::trie_hash::{
            account_hash_v6, extract_raw_affinity, kv_hash_v6, resource_hash_v6_with_kind, HashKind,
        };

        // Take the trie out of self to avoid borrow conflicts.
        let mut trie = self.trie.take()?;
        let mutations = std::mem::take(&mut self.pre_mutations);

        for mutation in mutations {
            match mutation {
                SqlitePreMutation::Account { addr, old_data } => {
                    // Delete old element.
                    if let Some(ref old) = old_data {
                        let old_elem = account_hash_v6(&addr, old);
                        if let Err(e) = trie.delete(&old_elem) {
                            tracing::warn!("trie delete account failed: {}", e);
                        }
                    }
                    // Add new element if account still exists.
                    if let Some(new_data) = self.get_account(&addr) {
                        let new_elem = account_hash_v6(&addr, &new_data);
                        if let Err(e) = trie.add(&new_elem) {
                            tracing::warn!("trie add account failed: {}", e);
                        }
                    }
                }
                SqlitePreMutation::Resource {
                    addr,
                    index,
                    old_blob,
                    ctype,
                    old_affinity,
                } => {
                    let kind = if ctype == CTYPE_APP {
                        HashKind::App
                    } else {
                        HashKind::Asset
                    };

                    // Delete old element using captured old_affinity (from old blob).
                    if let Some(ref old) = old_blob {
                        let old_elem =
                            resource_hash_v6_with_kind(&addr, index, old, old_affinity, kind);
                        if let Err(e) = trie.delete(&old_elem) {
                            tracing::warn!("trie delete resource failed: {}", e);
                        }
                    }

                    // Read current blob from DB and derive affinity from it,
                    // matching Go's ResourcesHashBuilderV6 which uses resData.UpdateRound.
                    let new_blob = self.get_rowid(&addr).and_then(|rowid| {
                        self.conn
                            .query_row(
                                "SELECT data FROM resources WHERE addrid = ?1 AND aidx = ?2 AND ctype = ?3",
                                params![rowid, index as i64, ctype],
                                |row| row.get::<_, Vec<u8>>(0),
                            )
                            .optional()
                            .unwrap_or(None)
                    });
                    if let Some(ref new) = new_blob {
                        let new_affinity = extract_raw_affinity(new);
                        let new_elem =
                            resource_hash_v6_with_kind(&addr, index, new, new_affinity, kind);
                        if let Err(e) = trie.add(&new_elem) {
                            tracing::warn!("trie add resource failed: {}", e);
                        }
                    }
                }
                SqlitePreMutation::Kv {
                    full_key,
                    old_value,
                } => {
                    // Delete old trie element if the key previously existed.
                    if let Some(ref old_val) = old_value {
                        let old_elem = kv_hash_v6(&full_key, old_val);
                        if let Err(e) = trie.delete(&old_elem) {
                            tracing::warn!("trie delete kv failed: {}", e);
                        }
                    }

                    // Add new trie element if the key still exists in the kvstore.
                    let new_value: Option<Vec<u8>> = self
                        .conn
                        .query_row(
                            "SELECT value FROM kvstore WHERE key = ?1",
                            params![full_key],
                            |row| row.get::<_, Vec<u8>>(0),
                        )
                        .optional()
                        .unwrap_or(None);
                    if let Some(ref new_val) = new_value {
                        let new_elem = kv_hash_v6(&full_key, new_val);
                        if let Err(e) = trie.add(&new_elem) {
                            tracing::warn!("trie add kv failed: {}", e);
                        }
                    }
                }
            }
        }

        // Note: No H2 cascade needed. Resource trie elements use the resource's
        // own UpdateRound for affinity (extracted from the blob via extract_raw_affinity),
        // not the account's. This matches Go's ResourcesHashBuilderV6 which passes
        // resData.UpdateRound. Account affinity changes do not affect resource elements.

        let root = match trie.root_hash() {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("merkle_trie: root_hash failed during apply: {e}");
                // Restore the trie so the caller can recover / retry.
                self.trie = Some(trie);
                return None;
            }
        };
        self.trie = Some(trie);
        Some(root)
    }

    // ---- Block / Certificate Storage ----

    fn put_block(
        &mut self,
        round: u64,
        proto: &str,
        hdrdata: &[u8],
        blkdata: &[u8],
    ) -> Result<(), AlgoError> {
        self.conn
            .execute(
                "INSERT INTO blockdb.blocks (rnd, proto, hdrdata, blkdata) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(rnd) DO UPDATE SET proto=excluded.proto, hdrdata=excluded.hdrdata, blkdata=excluded.blkdata",
                params![round as i64, proto, hdrdata, blkdata],
            )
            .map_err(|e| AlgoError::Ledger {
                message: format!("put_block error: {e}"),
            })?;
        Ok(())
    }

    fn get_block_data(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        self.conn
            .query_row(
                "SELECT blkdata FROM blockdb.blocks WHERE rnd = ?1",
                params![round as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| AlgoError::Ledger {
                message: format!("get_block_data error: {e}"),
            })
    }

    fn get_block_header_data(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        self.conn
            .query_row(
                "SELECT hdrdata FROM blockdb.blocks WHERE rnd = ?1",
                params![round as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| AlgoError::Ledger {
                message: format!("get_block_header_data error: {e}"),
            })
    }

    fn get_block_cert(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        self.conn
            .query_row(
                "SELECT certdata FROM blockdb.blocks WHERE rnd = ?1",
                params![round as i64],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()
            .map(|opt| opt.flatten())
            .map_err(|e| AlgoError::Ledger {
                message: format!("get_block_cert error: {e}"),
            })
    }

    fn get_block_proto(&self, round: u64) -> Result<Option<String>, AlgoError> {
        self.conn
            .query_row(
                "SELECT proto FROM blockdb.blocks WHERE rnd = ?1",
                params![round as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| AlgoError::Ledger {
                message: format!("get_block_proto error: {e}"),
            })
    }

    fn put_block_cert(&mut self, round: u64, certdata: &[u8]) -> Result<(), AlgoError> {
        let rows_affected = self
            .conn
            .execute(
                "UPDATE blockdb.blocks SET certdata = ?2 WHERE rnd = ?1",
                params![round as i64, certdata],
            )
            .map_err(|e| AlgoError::Ledger {
                message: format!("put_block_cert error: {e}"),
            })?;
        if rows_affected == 0 {
            return Err(AlgoError::Ledger {
                message: format!("put_block_cert: no block row for round {round}"),
            });
        }
        Ok(())
    }

    // ---- TxTail Storage ----

    fn put_txtail(&mut self, round: u64, data: &[u8]) -> Result<(), AlgoError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO txtail (rnd, data) VALUES (?1, ?2)",
                params![round as i64, data],
            )
            .map_err(|e| AlgoError::Ledger {
                message: format!("put_txtail error: {e}"),
            })?;
        Ok(())
    }

    fn get_txtail(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        self.conn
            .query_row(
                "SELECT data FROM txtail WHERE rnd = ?1",
                params![round as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| AlgoError::Ledger {
                message: format!("get_txtail error: {e}"),
            })
    }

    // ---- Pruning ----

    fn forget_before(&mut self, round: u64) -> Result<(), AlgoError> {
        self.conn
            .execute(
                "DELETE FROM blockdb.blocks WHERE rnd < ?1",
                params![round as i64],
            )
            .map_err(|e| AlgoError::Ledger {
                message: format!("forget_before blocks error: {e}"),
            })?;
        self.conn
            .execute("DELETE FROM txtail WHERE rnd < ?1", params![round as i64])
            .map_err(|e| AlgoError::Ledger {
                message: format!("forget_before txtail error: {e}"),
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // total_reward_units (TASK-275)
    // ---------------------------------------------------------------------

    #[test]
    fn total_reward_units_missing_row_is_zero() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        assert_eq!(ledger.total_reward_units().unwrap(), 0);
    }

    #[test]
    fn total_reward_units_sums_online_and_offline() {
        // go's AccountTotals.RewardUnits() = Online.RewardUnits + Offline.RewardUnits
        // (NotParticipating excluded). Seed the row directly with distinct
        // per-status reward-unit counts to isolate the SUM query.
        let ledger = SqliteLedger::open_in_memory().unwrap();
        ledger
            .conn
            .execute(
                "INSERT OR REPLACE INTO accounttotals(id, online, onlinerewardunits, \
                 offline, offlinerewardunits, notparticipating, \
                 notparticipatingrewardunits, rewardslevel) \
                 VALUES('', 0, 30, 0, 12, 0, 99, 0)",
                [],
            )
            .unwrap();
        // 30 + 12 = 42; the NotParticipating 99 must be excluded.
        assert_eq!(ledger.total_reward_units().unwrap(), 42);
    }

    // ---------------------------------------------------------------------
    // ResourceMeta / inspect_resource_blob (TASK-190)
    // ---------------------------------------------------------------------

    fn rmpv_map(pairs: &[(&str, rmpv::Value)]) -> Vec<u8> {
        let val = rmpv::Value::Map(
            pairs
                .iter()
                .map(|(k, v)| (rmpv::Value::String((*k).into()), v.clone()))
                .collect(),
        );
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &val).expect("rmpv encode");
        buf
    }

    #[test]
    fn inspect_canonical_asset_holding_row() {
        // Canonical Go asset holding: y omitted (defaults to 0=HOLDING), l/m fields.
        let bytes = rmpv_map(&[
            ("l", rmpv::Value::from(1000u64)),
            ("m", rmpv::Value::Boolean(false)),
        ]);
        let meta = inspect_resource_blob(&bytes);
        assert!(meta.has_holding);
        assert!(!meta.has_ownership);
        assert_eq!(meta.raw_flags, 0);
    }

    #[test]
    fn inspect_canonical_asset_params_row() {
        // Canonical Go asset params (creator's own row): y=2 (OWNERSHIP),
        // a..k fields. Under Go semantics y=2 has NOT_HOLDING clear, so
        // the row holds implicitly (creator carries amount/frozen even
        // if both are zero and omitempty-dropped).
        let bytes = rmpv_map(&[
            ("a", rmpv::Value::from(1_000_000u64)),
            ("y", rmpv::Value::from(2u64)),
        ]);
        let meta = inspect_resource_blob(&bytes);
        assert!(
            meta.has_holding,
            "y=2 has NOT_HOLDING clear → implicit holding"
        );
        assert!(meta.has_ownership);
        assert_eq!(meta.raw_flags, 2);
    }

    #[test]
    fn inspect_canonical_app_local_state_row() {
        // Canonical app local state: y omitted/0, n/o flat u64 schema, p as kv map.
        let bytes = rmpv_map(&[
            ("n", rmpv::Value::from(3u64)),
            ("o", rmpv::Value::from(0u64)),
            (
                "p",
                rmpv::Value::Map(vec![(
                    rmpv::Value::Binary(b"k".to_vec()),
                    rmpv::Value::Map(vec![]),
                )]),
            ),
        ]);
        let meta = inspect_resource_blob(&bytes);
        assert!(meta.has_holding);
        assert!(!meta.has_ownership);
    }

    #[test]
    fn inspect_canonical_app_params_row() {
        // Canonical app params: y=2, q/r programs, t/u/v/w/x flat schema, s as global_state.
        let bytes = rmpv_map(&[
            ("q", rmpv::Value::Binary(vec![0x80])),
            ("r", rmpv::Value::Binary(vec![0x80])),
            (
                "s",
                rmpv::Value::Map(vec![(
                    rmpv::Value::Binary(b"k".to_vec()),
                    rmpv::Value::Map(vec![]),
                )]),
            ),
            ("t", rmpv::Value::from(0u64)),
            ("u", rmpv::Value::from(0u64)),
            ("v", rmpv::Value::from(0u64)),
            ("w", rmpv::Value::from(0u64)),
            ("x", rmpv::Value::from(0u64)),
            ("y", rmpv::Value::from(2u64)),
        ]);
        let meta = inspect_resource_blob(&bytes);
        // y=2 implies holding under Go semantics — the creator's own
        // local-state defaults to existing. Combined rows are valid.
        assert!(meta.has_holding);
        assert!(meta.has_ownership, "q/r/w/x must signal app params row");
    }

    #[test]
    fn inspect_empty_blob_is_default() {
        let meta = inspect_resource_blob(&[]);
        assert!(!meta.has_holding);
        assert!(!meta.has_ownership);
        assert_eq!(meta.raw_flags, 0);
    }

    #[test]
    fn inspect_canonical_default_holding_blob() {
        // Canonical asset holding with all-default fields encodes to
        // `{}` (empty map) because Go's omitempty drops y=0 along with
        // amount=0/frozen=false. The inspector must still classify it
        // as has_holding so callers don't drop the row.
        let bytes = rmpv_map(&[]);
        let meta = inspect_resource_blob(&bytes);
        assert!(
            meta.has_holding,
            "empty canonical map must classify as has_holding"
        );
        assert!(!meta.has_ownership);
    }

    #[test]
    fn inspect_canonical_default_holding_with_only_metadata() {
        // Canonical holding row carrying only the optional `z`
        // (update_round) metadata key — still has no data signals and
        // y is omitted because resource_flags=HOLDING=0.
        let bytes = rmpv_map(&[("z", rmpv::Value::from(1234u64))]);
        let meta = inspect_resource_blob(&bytes);
        assert!(meta.has_holding);
        assert!(!meta.has_ownership);
    }

    #[test]
    fn inspect_canonical_y2_implies_holding_plus_ownership() {
        // y=2 (OWNERSHIP) under Go bitwise semantics: NOT_HOLDING clear,
        // so the row holds AND carries params. Even with no field-presence
        // signals (a default-valued creator row), both predicates must
        // be true.
        let bytes = rmpv_map(&[("y", rmpv::Value::from(2u64))]);
        let meta = inspect_resource_blob(&bytes);
        assert!(meta.has_ownership);
        assert!(meta.has_holding);
    }

    #[test]
    fn inspect_canonical_y3_is_ownership_only() {
        // y=3 (NOT_HOLDING | OWNERSHIP) — params row that does NOT hold.
        // No field-presence required; raw_flags signal alone is enough.
        let bytes = rmpv_map(&[("y", rmpv::Value::from(3u64))]);
        let meta = inspect_resource_blob(&bytes);
        assert!(meta.has_ownership);
        assert!(!meta.has_holding);
    }

    #[test]
    fn inspect_canonical_not_holding_ownership_clears_holding() {
        // y=3 = NOT_HOLDING | OWNERSHIP. Even if a row somehow carried
        // legacy holding fields, the canonical NOT_HOLDING bit must
        // suppress has_holding.
        let bytes = rmpv_map(&[
            // Field-presence would otherwise set has_holding=true.
            ("l", rmpv::Value::from(0u64)),
            ("y", rmpv::Value::from(3u64)),
        ]);
        let meta = inspect_resource_blob(&bytes);
        assert!(meta.has_ownership);
        assert!(!meta.has_holding, "NOT_HOLDING bit must clear has_holding");
    }

    #[test]
    fn inspect_malformed_blob_is_default() {
        let meta = inspect_resource_blob(b"\xff\xff\xff\xff");
        assert!(!meta.has_holding);
        assert!(!meta.has_ownership);
    }

    // ---------------------------------------------------------------------
    // Asset encoder canonical delegation (TASK-191)
    // ---------------------------------------------------------------------

    #[test]
    fn encode_asset_holding_matches_canonical_encoder() {
        let h = AssetHolding {
            amount: 1_000_000,
            frozen: false,
        };
        let actual = encode_asset_holding_with_round(&h, 42);

        // Reference: build the equivalent ResourcesData and call
        // the canonical encoder directly.
        let rd = algo_codec::ResourcesData {
            amount: 1_000_000,
            frozen: false,
            resource_flags: algo_codec::resource_flags::HOLDING,
            update_round: 42,
            ..Default::default()
        };
        let expected = algo_codec::canonical_encode_resources_data(&rd);

        assert_eq!(actual, expected);
    }

    #[test]
    fn encode_asset_holding_default_is_empty_map() {
        // Canonical zero-balance opt-in: amount=0, frozen=false,
        // update_round=0 → every field omitempty-dropped → `{}` (0x80).
        let h = AssetHolding {
            amount: 0,
            frozen: false,
        };
        let bytes = encode_asset_holding_with_round(&h, 0);
        assert_eq!(
            bytes,
            vec![0x80],
            "canonical default holding must be empty map"
        );
        // And the inspector must still classify it as has_holding so
        // get_asset_holding doesn't silently drop it.
        let meta = inspect_resource_blob(&bytes);
        assert!(meta.has_holding);
    }

    #[test]
    fn encode_asset_holding_round_trip_via_decoder() {
        let cases = [
            AssetHolding {
                amount: 0,
                frozen: false,
            },
            AssetHolding {
                amount: 1,
                frozen: false,
            },
            AssetHolding {
                amount: 0,
                frozen: true,
            },
            AssetHolding {
                amount: u64::MAX,
                frozen: true,
            },
        ];
        for h in cases {
            let bytes = encode_asset_holding_with_round(&h, 0);
            let decoded = decode_asset_holding(&bytes).expect("decode");
            assert_eq!(decoded.amount, h.amount);
            assert_eq!(decoded.frozen, h.frozen);
        }
    }

    #[test]
    fn encode_asset_params_matches_canonical_encoder() {
        let creator = Address([7u8; 32]);
        let p = algo_types::AssetParams {
            total: 1_000_000,
            decimals: 6,
            default_frozen: false,
            unit_name: "TST".to_string(),
            asset_name: "TestAsset".to_string(),
            url: "https://example".to_string(),
            metadata_hash: Some([9u8; 32]),
            manager: Some(Address([1u8; 32])),
            reserve: Some(Address([2u8; 32])),
            freeze: None,
            clawback: None,
        };
        let actual = encode_asset_params_with_round(&p, &creator, 100);

        let rd = algo_codec::ResourcesData {
            total: 1_000_000,
            decimals: 6,
            default_frozen: false,
            unit_name: "TST".to_string(),
            asset_name: "TestAsset".to_string(),
            url: "https://example".to_string(),
            metadata_hash: [9u8; 32],
            manager: [1u8; 32],
            reserve: [2u8; 32],
            freeze: [0u8; 32],
            clawback: [0u8; 32],
            resource_flags: algo_codec::resource_flags::OWNERSHIP,
            update_round: 100,
            ..Default::default()
        };
        let expected = algo_codec::canonical_encode_resources_data(&rd);

        assert_eq!(actual, expected);
    }

    #[test]
    fn encode_asset_params_round_trip_via_decoder() {
        let creator = Address([7u8; 32]);
        let p = algo_types::AssetParams {
            total: 5_000,
            decimals: 2,
            default_frozen: true,
            unit_name: "U".to_string(),
            asset_name: "A".to_string(),
            url: "".to_string(),
            metadata_hash: None,
            manager: Some(Address([3u8; 32])),
            reserve: None,
            freeze: None,
            clawback: Some(Address([4u8; 32])),
        };
        let bytes = encode_asset_params_with_round(&p, &creator, 0);
        let decoded = decode_asset_params(&bytes).expect("decode");
        assert_eq!(decoded.total, p.total);
        assert_eq!(decoded.decimals, p.decimals);
        assert_eq!(decoded.default_frozen, p.default_frozen);
        assert_eq!(decoded.unit_name, p.unit_name);
        assert_eq!(decoded.asset_name, p.asset_name);
        assert_eq!(decoded.manager, p.manager);
        assert_eq!(decoded.reserve, p.reserve);
        assert_eq!(decoded.clawback, p.clawback);
    }

    #[test]
    fn encode_asset_params_canonical_y_value() {
        // Canonical OWNERSHIP = 2, NOT legacy 4. The on-disk y byte
        // must reflect Go's enum value.
        let creator = Address([7u8; 32]);
        let p = algo_types::AssetParams {
            total: 1,
            ..Default::default()
        };
        let bytes = encode_asset_params_with_round(&p, &creator, 0);
        let val: rmpv::Value = rmpv::decode::read_value(&mut &bytes[..]).expect("decode");
        let rmpv::Value::Map(pairs) = val else {
            panic!("not a map")
        };
        let y = pairs.iter().find(|(k, _)| k.as_str() == Some("y"));
        let y_val = y.expect("y present").1.as_u64().expect("y u64");
        assert_eq!(y_val, 2, "canonical OWNERSHIP = 2");
    }

    // ---------------------------------------------------------------------
    // App params canonical delegation (TASK-192)
    // ---------------------------------------------------------------------

    #[test]
    fn encode_app_params_matches_canonical_encoder() {
        let mut global = BTreeMap::new();
        global.insert(b"k1".to_vec(), TealValue::Uint(42));
        let p = AppParams {
            creator: Address([0u8; 32]),
            approval_program: vec![0x06, 0x81, 0x01],
            clear_state_program: vec![0x06],
            global_state: global.clone(),
            local_state_schema: StateSchema {
                num_uint: 5,
                num_byte_slice: 7,
            },
            global_state_schema: StateSchema {
                num_uint: 11,
                num_byte_slice: 13,
            },
            extra_program_pages: 2,
            ..Default::default()
        };
        let actual = encode_app_params_with_round(&p, 99);

        let rd = algo_codec::ResourcesData {
            approval_program: vec![0x06, 0x81, 0x01],
            clear_state_program: vec![0x06],
            global_state: algo_codec::canonical_encode_teal_key_value(&global),
            local_state_schema_num_uint: 5,
            local_state_schema_num_byte_slice: 7,
            global_state_schema_num_uint: 11,
            global_state_schema_num_byte_slice: 13,
            extra_program_pages: 2,
            resource_flags: algo_codec::resource_flags::NOT_HOLDING
                | algo_codec::resource_flags::OWNERSHIP,
            update_round: 99,
            ..Default::default()
        };
        let expected = algo_codec::canonical_encode_resources_data(&rd);

        assert_eq!(actual, expected);
    }

    #[test]
    fn encode_app_params_canonical_y_value() {
        // Standalone app params row: NOT_HOLDING | OWNERSHIP = 3.
        let p = AppParams {
            creator: Address([0u8; 32]),
            approval_program: vec![0x06],
            clear_state_program: vec![0x06],
            global_state: BTreeMap::new(),
            local_state_schema: StateSchema::default(),
            global_state_schema: StateSchema::default(),
            extra_program_pages: 0,
            ..Default::default()
        };
        let bytes = encode_app_params_with_round(&p, 0);
        let val: rmpv::Value = rmpv::decode::read_value(&mut &bytes[..]).expect("decode");
        let rmpv::Value::Map(pairs) = val else {
            panic!("not a map")
        };
        let y = pairs.iter().find(|(k, _)| k.as_str() == Some("y"));
        let y_val = y.expect("y present").1.as_u64().expect("y u64");
        assert_eq!(
            y_val, 3,
            "canonical app params standalone = NOT_HOLDING|OWNERSHIP = 3"
        );
    }

    #[test]
    fn encode_app_params_round_trip_via_decoder() {
        let mut global = BTreeMap::new();
        global.insert(b"k".to_vec(), TealValue::Bytes(b"v".to_vec()));
        let p = AppParams {
            creator: Address([7u8; 32]),
            approval_program: vec![0xff; 8],
            clear_state_program: vec![0xee; 4],
            global_state: global,
            local_state_schema: StateSchema {
                num_uint: 1,
                num_byte_slice: 2,
            },
            global_state_schema: StateSchema {
                num_uint: 3,
                num_byte_slice: 4,
            },
            extra_program_pages: 1,
            version: 5,
            size_sponsor: Address([3u8; 32]),
        };
        let bytes = encode_app_params_with_round(&p, 0);
        let decoded = decode_app_params(&bytes, p.creator).expect("decode");
        assert_eq!(decoded.approval_program, p.approval_program);
        assert_eq!(decoded.clear_state_program, p.clear_state_program);
        assert_eq!(
            decoded.local_state_schema.num_uint,
            p.local_state_schema.num_uint
        );
        assert_eq!(
            decoded.local_state_schema.num_byte_slice,
            p.local_state_schema.num_byte_slice
        );
        assert_eq!(
            decoded.global_state_schema.num_uint,
            p.global_state_schema.num_uint
        );
        assert_eq!(
            decoded.global_state_schema.num_byte_slice,
            p.global_state_schema.num_byte_slice
        );
        assert_eq!(decoded.extra_program_pages, p.extra_program_pages);
        // Issue #602: version/size_sponsor (trackerdb codec "A"/"B") must
        // survive the encode/decode round trip.
        assert_eq!(decoded.version, p.version);
        assert_eq!(decoded.size_sponsor, p.size_sponsor);
    }

    #[test]
    fn decode_teal_key_value_preserves_non_utf8_string_keys() {
        // Go's canonical TealKeyValue encodes raw byte keys as msgpack
        // STRINGS (Go's `string` is a byte sequence, not necessarily
        // UTF-8). Round-trip a key with invalid UTF-8 bytes through the
        // canonical encoder + the (legacy) decoder.
        let key = vec![0xff, 0xfe, 0xfd];
        let mut kv = BTreeMap::new();
        kv.insert(key.clone(), TealValue::Uint(7));
        let encoded = algo_codec::canonical_encode_teal_key_value(&kv);
        // Wrap it as a Value via rmpv decode and run our decoder.
        let val = rmpv::decode::read_value(&mut &encoded[..]).expect("decode rmpv");
        let decoded = decode_teal_key_value(&val);
        let got = decoded.get(&key);
        assert!(got.is_some(), "non-UTF-8 key must survive decode");
        assert!(matches!(got.unwrap(), TealValue::Uint(7)));
    }

    /// Build a canonical app local-state blob using only the local-state
    /// subset of `build_app_resource_data`. Test helper. PLAN-189.
    fn build_canonical_app_local_state_blob(als: &AppLocalState) -> Vec<u8> {
        let rd = build_app_resource_data(Some(als), None, 0);
        algo_codec::canonical_encode_resources_data(&rd)
    }

    #[test]
    fn decode_app_local_state_kv_with_schema_named_keys_round_trips() {
        // Canonical app local state with zero schemas (n/o omitted) and
        // a kv map containing entries keyed "nui"/"nbs" round-trips
        // correctly — there's no ambiguous-`p` interpretation anymore.
        let mut kv = BTreeMap::new();
        kv.insert(b"nui".to_vec(), TealValue::Uint(123));
        let als = AppLocalState {
            schema: StateSchema::default(),
            key_value: kv,
        };
        let bytes = build_canonical_app_local_state_blob(&als);
        let decoded = decode_app_local_state(&bytes).expect("decode");
        let got = decoded.key_value.get(b"nui".as_slice());
        assert!(matches!(got, Some(TealValue::Uint(123))));
        assert_eq!(decoded.schema.num_uint, 0);
        assert_eq!(decoded.schema.num_byte_slice, 0);
    }

    #[test]
    fn decode_app_local_state_ignores_global_state_in_combined_row() {
        // Canonical combined app row: creator's local state AT `p`,
        // app params global_state AT `s`. The local-state decoder must
        // return ONLY the `p` kv, never overwrite from `s`. PLAN-189 /
        // TASK-192 (Codex round 2).
        let mut local_kv = BTreeMap::new();
        local_kv.insert(b"local_key".to_vec(), TealValue::Uint(100));
        let local = AppLocalState {
            schema: StateSchema::default(),
            key_value: local_kv,
        };
        let mut global = BTreeMap::new();
        global.insert(b"global_key".to_vec(), TealValue::Uint(999));
        let params = AppParams {
            creator: Address([0u8; 32]),
            approval_program: vec![0x06],
            clear_state_program: vec![0x06],
            global_state: global,
            local_state_schema: StateSchema::default(),
            global_state_schema: StateSchema::default(),
            extra_program_pages: 0,
            ..Default::default()
        };
        let rd = build_app_resource_data(Some(&local), Some(&params), 0);
        let bytes = algo_codec::canonical_encode_resources_data(&rd);
        let decoded = decode_app_local_state(&bytes).expect("decode");
        assert_eq!(
            decoded.key_value.len(),
            1,
            "local-state decoder must NOT pull in `s` (global_state) entries"
        );
        let local_val = decoded.key_value.get(b"local_key".as_slice());
        assert!(local_val.is_some(), "local kv preserved");
        assert!(matches!(local_val.unwrap(), TealValue::Uint(100)));
        assert!(
            !decoded.key_value.contains_key(b"global_key".as_slice()),
            "global state must not leak into local-state decode"
        );
    }

    // ---------------------------------------------------------------------
    // App local-state canonical delegation (TASK-193)
    // ---------------------------------------------------------------------

    #[test]
    fn encode_app_local_state_matches_canonical_encoder() {
        let mut kv = BTreeMap::new();
        kv.insert(b"key1".to_vec(), TealValue::Uint(42));
        kv.insert(b"key2".to_vec(), TealValue::Bytes(b"value".to_vec()));
        let s = AppLocalState {
            schema: StateSchema {
                num_uint: 3,
                num_byte_slice: 5,
            },
            key_value: kv.clone(),
        };
        let actual = encode_app_local_state_with_round(&s, 77);

        let rd = algo_codec::ResourcesData {
            schema_num_uint: 3,
            schema_num_byte_slice: 5,
            key_value: algo_codec::canonical_encode_teal_key_value(&kv),
            resource_flags: algo_codec::resource_flags::HOLDING,
            update_round: 77,
            ..Default::default()
        };
        let expected = algo_codec::canonical_encode_resources_data(&rd);

        assert_eq!(actual, expected);
    }

    #[test]
    fn encode_app_local_state_default_is_empty_map() {
        // Empty opted-in row with zero schema and no kv: every field
        // is omitempty-dropped (n=0, o=0, p empty, y=HOLDING=0 → all gone).
        // Resulting blob is just `{}` (0x80).
        let s = AppLocalState {
            schema: StateSchema::default(),
            key_value: BTreeMap::new(),
        };
        let bytes = encode_app_local_state_with_round(&s, 0);
        assert_eq!(bytes, vec![0x80]);
        // And the inspector still sees has_holding=true.
        let meta = inspect_resource_blob(&bytes);
        assert!(meta.has_holding);
    }

    #[test]
    fn encode_app_local_state_round_trip_via_decoder() {
        let mut kv = BTreeMap::new();
        kv.insert(b"hello".to_vec(), TealValue::Bytes(b"world".to_vec()));
        let s = AppLocalState {
            schema: StateSchema {
                num_uint: 2,
                num_byte_slice: 1,
            },
            key_value: kv,
        };
        let bytes = encode_app_local_state_with_round(&s, 0);
        let decoded = decode_app_local_state(&bytes).expect("decode");
        assert_eq!(decoded.schema.num_uint, 2);
        assert_eq!(decoded.schema.num_byte_slice, 1);
        let entry = decoded.key_value.get(b"hello".as_slice()).expect("kv key");
        assert!(matches!(entry, TealValue::Bytes(b) if b == b"world"));
    }

    // ---------------------------------------------------------------------

    #[test]
    fn test_open_in_memory() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        assert_eq!(ledger.current_round(), Round(0));
        assert!(ledger.last_committed_round().unwrap().is_none());
    }

    #[test]
    fn test_account_round_trip() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let addr = Address([1u8; 32]);

        assert!(ledger.get_account(&addr).is_none());

        let acct = AccountData {
            micro_algos: 5_000_000,
            status: AccountStatus::Online,
            rewards_base: 100,
            total_assets_opted_in: 3,
            vote_first_valid: 1000,
            vote_last_valid: 2000,
            vote_key_dilution: 10,
            ..Default::default()
        };

        ledger.set_account(&addr, acct.clone());

        let loaded = ledger.get_account(&addr).unwrap();
        assert_eq!(loaded.micro_algos, 5_000_000);
        assert_eq!(loaded.status, AccountStatus::Online);
        assert_eq!(loaded.rewards_base, 100);
        assert_eq!(loaded.total_assets_opted_in, 3);
        assert_eq!(loaded.vote_first_valid, 1000);
        assert_eq!(loaded.vote_last_valid, 2000);
        assert_eq!(loaded.vote_key_dilution, 10);
    }

    #[test]
    fn test_account_remove() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let addr = Address([2u8; 32]);

        ledger.set_account(&addr, AccountData::default());
        assert!(ledger.get_account(&addr).is_some());

        ledger.remove_account(&addr);
        assert!(ledger.get_account(&addr).is_none());
    }

    #[test]
    fn test_asset_holding_round_trip() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let addr = Address([3u8; 32]);

        ledger.set_account(&addr, AccountData::default());
        ledger.set_asset_holding(
            &addr,
            42,
            AssetHolding {
                amount: 1000,
                frozen: true,
            },
        );

        let h = ledger.get_asset_holding(&addr, 42).unwrap();
        assert_eq!(h.amount, 1000);
        assert!(h.frozen);
        assert!(ledger.has_asset_holding(&addr, 42));
        assert!(!ledger.has_asset_holding(&addr, 99));

        ledger.remove_asset_holding(&addr, 42);
        assert!(!ledger.has_asset_holding(&addr, 42));
    }

    #[test]
    fn test_asset_params_round_trip() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let creator = Address([4u8; 32]);
        ledger.set_account(&creator, AccountData::default());

        let params = AssetParams {
            total: 1_000_000,
            decimals: 6,
            unit_name: "ALGO".into(),
            asset_name: "Algorand".into(),
            ..Default::default()
        };

        ledger.set_asset_params(
            10,
            AssetParamsRecord {
                params: params.clone(),
                creator,
            },
        );

        assert!(ledger.has_asset_params(10));
        let loaded = ledger.get_asset_params(10).unwrap();
        assert_eq!(loaded.params.total, 1_000_000);
        assert_eq!(loaded.params.decimals, 6);
        assert_eq!(loaded.params.unit_name, "ALGO");
        assert_eq!(loaded.creator, creator);

        ledger.remove_asset_params(10);
        assert!(!ledger.has_asset_params(10));
    }

    #[test]
    fn test_app_params_round_trip() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let creator = Address([5u8; 32]);
        ledger.set_account(&creator, AccountData::default());

        let params = AppParams {
            creator,
            approval_program: vec![0x06, 0x81, 0x01],
            clear_state_program: vec![0x06, 0x81, 0x01],
            global_state: BTreeMap::new(),
            local_state_schema: StateSchema {
                num_uint: 2,
                num_byte_slice: 1,
            },
            global_state_schema: StateSchema {
                num_uint: 4,
                num_byte_slice: 2,
            },
            extra_program_pages: 1,
            ..Default::default()
        };

        ledger.set_app_params(20, params.clone());
        assert!(ledger.has_app_params(20));

        let loaded = ledger.get_app_params(20).unwrap();
        assert_eq!(loaded.creator, creator);
        assert_eq!(loaded.approval_program, vec![0x06, 0x81, 0x01]);
        assert_eq!(loaded.local_state_schema.num_uint, 2);
        assert_eq!(loaded.global_state_schema.num_uint, 4);
        assert_eq!(loaded.extra_program_pages, 1);

        // Test app_params_created_by
        let created = ledger.app_params_created_by(&creator);
        assert_eq!(created.len(), 1);

        ledger.remove_app_params(20);
        assert!(!ledger.has_app_params(20));
    }

    #[test]
    fn test_app_local_state_round_trip() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let addr = Address([6u8; 32]);
        ledger.set_account(&addr, AccountData::default());

        let local = AppLocalState {
            schema: StateSchema {
                num_uint: 2,
                num_byte_slice: 1,
            },
            key_value: BTreeMap::new(),
        };

        ledger.set_app_local_state(&addr, 30, local.clone());
        assert!(ledger.has_app_local_state(&addr, 30));

        let loaded = ledger.get_app_local_state(&addr, 30).unwrap();
        assert_eq!(loaded.schema.num_uint, 2);

        let all = ledger.app_local_states_for_addr(&addr);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, 30);

        ledger.remove_app_local_state(&addr, 30);
        assert!(!ledger.has_app_local_state(&addr, 30));
    }

    #[test]
    fn test_chain_state_round_trip() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();

        ledger.set_current_round(Round(42));
        ledger.set_rewards_level(1000);
        ledger.set_rewards_rate(50);
        ledger.set_fee_sink(Address([0xAA; 32]));
        ledger.set_genesis_id("testnet-v1.0".into());
        ledger.set_protocol("v42".into());

        assert_eq!(ledger.current_round(), Round(42));
        assert_eq!(ledger.rewards_level(), 1000);
        assert_eq!(ledger.rewards_rate(), 50);
        assert_eq!(ledger.fee_sink(), Address([0xAA; 32]));
        assert_eq!(ledger.genesis_id(), "testnet-v1.0");
        assert_eq!(ledger.protocol(), "v42");

        // G6 part 3: flush_chain_state now writes acctrounds.acctbase
        // (the legacy algod_rust_meta cache is gone).
        ledger.flush_chain_state().unwrap();
        let acctbase: i64 = ledger
            .conn
            .query_row(
                "SELECT rnd FROM acctrounds WHERE id = 'acctbase'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(acctbase, 42);
    }

    /// `online_circulation_at_round` (shared by `AgreementLedgerBridge::circulation`
    /// -- sortition's lookback query -- and `GetSupply`'s `online-stake` field,
    /// go-algorand v4.6.0-stable issue #508) must prefer a recorded per-round
    /// snapshot over the current aggregate, so a caller asking for an OLD
    /// round's circulation gets that round's value, not today's.
    #[test]
    fn online_circulation_at_round_prefers_per_round_snapshot_over_current_aggregate() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        // Current aggregate: 9,000,000 online microAlgos.
        ledger
            .put_account_totals_seed(9_000_000, 0, 0, 0, 0, 0)
            .unwrap();
        // A different value recorded for round 100 (as catchpoint import would
        // populate `onlineroundparamstail`).
        ledger.put_online_supply_at_round(100, 1_234_000).unwrap();

        assert_eq!(
            ledger.online_circulation_at_round(100, 100).unwrap(),
            1_234_000,
            "a recorded per-round snapshot must win over the current aggregate",
        );
    }

    /// Without a per-round snapshot, `online_circulation_at_round` falls back
    /// to the current aggregate online stake -- the only data available for a
    /// live (non-catchpoint-imported) node.
    #[test]
    fn online_circulation_at_round_falls_back_to_current_aggregate() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        ledger
            .put_account_totals_seed(5_500_000, 0, 0, 0, 0, 0)
            .unwrap();

        assert_eq!(
            ledger.online_circulation_at_round(200, 200).unwrap(),
            5_500_000,
            "no snapshot recorded for round 200 -> fall back to the current aggregate",
        );
    }

    /// Issue #519: normal block application (not just catchpoint import) must
    /// append a per-round online-supply snapshot to `onlineroundparamstail` on
    /// every `commit_block`, mirroring go-algorand's `onlineAccounts.newBlockImpl`
    /// appending `OnlineRoundParamsData` every block (`ledger/acctonline.go`).
    /// Without a live writer, `online_supply_at_round` returns `None` (and
    /// `online_circulation_at_round` silently falls back to today's aggregate)
    /// for any round the last catchpoint import didn't cover.
    #[test]
    fn commit_block_appends_online_supply_snapshot_for_each_round() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();

        ledger.begin_block().unwrap();
        ledger.set_current_round(Round(1));
        ledger
            .put_account_totals_seed(1_000_000, 0, 0, 0, 0, 0)
            .unwrap();
        ledger.commit_block().unwrap();

        ledger.begin_block().unwrap();
        ledger.set_current_round(Round(2));
        ledger
            .put_account_totals_seed(2_500_000, 0, 0, 0, 0, 0)
            .unwrap();
        ledger.commit_block().unwrap();

        ledger.begin_block().unwrap();
        ledger.set_current_round(Round(3));
        ledger
            .put_account_totals_seed(3_000_000, 0, 0, 0, 0, 0)
            .unwrap();
        ledger.commit_block().unwrap();

        // Each committed round's snapshot must be independently retrievable --
        // not just the latest/current aggregate -- with no catchpoint import
        // involved anywhere in this test.
        assert_eq!(
            ledger.online_supply_at_round(1).unwrap(),
            Some(1_000_000),
            "round 1's historical online supply must be recorded by normal block apply"
        );
        assert_eq!(
            ledger.online_supply_at_round(2).unwrap(),
            Some(2_500_000),
            "round 2's historical online supply must be recorded by normal block apply"
        );
        assert_eq!(
            ledger.online_supply_at_round(3).unwrap(),
            Some(3_000_000),
            "round 3's historical online supply must be recorded by normal block apply"
        );

        // The lookback-round accessor used by sortition and GetSupply must see
        // the true historical value at an old round, not the current aggregate.
        assert_eq!(ledger.online_circulation_at_round(1, 1).unwrap(), 1_000_000);
    }

    /// TDD regression for issue #586: `StateDelta::totals` must reflect the
    /// real post-apply `AccountTotals` *immediately*, before `commit_block`
    /// has run `flush_pending_account_totals_delta` to persist it into the
    /// `accounttotals` row. `apply::apply_block_with_delta` calls
    /// `SqliteLedger::account_totals()` mid-block (between `begin_block` and
    /// `commit_block`), so it must peek `pending_totals_delta` + the current
    /// `rewards_level` bump rather than reading the (still stale) row
    /// directly -- exercising exactly the gap `online_stake()`/
    /// `participating_money()` don't cover, since those are only ever
    /// asserted post-`commit_block` elsewhere in this file (e.g.
    /// `apply_block_proposer_payout_updates_accounttotals_and_supply` below).
    #[test]
    fn issue_586_account_totals_reflects_pending_delta_before_commit() {
        use algo_types::{Block, SignedTransaction};

        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        ledger.begin_block().unwrap();
        ledger.set_account(
            &sender,
            AccountData {
                micro_algos: 5_000_000,
                status: AccountStatus::Online,
                ..Default::default()
            },
        );
        ledger.set_account(
            &receiver,
            AccountData {
                micro_algos: 0,
                status: AccountStatus::Online,
                ..Default::default()
            },
        );
        ledger.set_account(&fee_sink, AccountData::default());
        ledger
            .put_account_totals_seed(5_000_000, 5, 0, 0, 0, 0)
            .unwrap();
        ledger.discard_pending_account_totals_delta();
        ledger.commit_block().unwrap();

        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "pay".into();
        stx.txn.sender = sender;
        stx.txn.receiver = receiver;
        stx.txn.amount = 1_000_000;
        stx.txn.fee = 1_000;

        let block = Block {
            round: Round(1),
            fee_sink,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![stx],
            ..Block::default()
        };

        ledger.begin_block().unwrap();
        let delta = crate::apply::apply_block_with_delta(&mut ledger, &block).unwrap();

        // Mid-block (before commit_block flushes the row): sender
        // 5_000_000 -> 3_999_000, receiver 0 -> 1_000_000, both Online, fee
        // absorbed by the (untracked-status) fee sink and excluded from
        // "online". `account_totals()` must already reflect this via the
        // pending delta, not the still-unflushed 5_000_000/0 seed row.
        assert_eq!(delta.totals.online.money, 3_999_000 + 1_000_000);
        assert_eq!(delta.totals.online.reward_units, 3 + 1);

        ledger.commit_block().unwrap();
        assert_eq!(
            ledger.online_stake().unwrap(),
            3_999_000 + 1_000_000,
            "post-commit row must agree with the pre-commit peek"
        );
    }

    /// Issue #523: a live mixed-cluster run (3 go-algorand relays + 1
    /// algod-rust participant, `ops/mixed-cluster/`) showed `GET
    /// /v2/ledger/supply`'s `online-money`/`total-money` diverging from
    /// go-algorand by the cumulative sum of every block's proposer payout
    /// (30,000,000,000,000 microAlgos over 150 rounds). Root cause:
    /// `apply_block` never credited the proposer's payout (no counterpart
    /// to go's `BlockEvaluator.performPayout`, `ledger/eval/eval.go`) *and*
    /// `accounttotals` was never incrementally maintained after genesis
    /// seeding (no counterpart to `roundCowState.CalculateTotals`,
    /// `ledger/eval/cow.go`) — so neither the account balance nor the
    /// aggregate ever moved.
    ///
    /// This pins the whole path end-to-end: seed a genesis-style
    /// `accounttotals` row, apply one block crediting a proposer payout to
    /// an *online* proposer, and assert `participating_money()` /
    /// `online_stake()` (the exact values `GetSupply` reports as
    /// `total-money` / `online-money`) increase by the payout.
    #[test]
    fn apply_block_proposer_payout_updates_accounttotals_and_supply() {
        use algo_types::Block;

        let fee_sink = Address([3u8; 32]);
        let proposer = Address([9u8; 32]);

        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        ledger.begin_block().unwrap();
        ledger.set_account(
            &fee_sink,
            AccountData {
                micro_algos: 5_000_000,
                status: AccountStatus::NotParticipating,
                ..Default::default()
            },
        );
        ledger.set_account(
            &proposer,
            AccountData {
                micro_algos: 1_000_000,
                status: AccountStatus::Online,
                ..Default::default()
            },
        );
        // Seed the aggregate row to match the accounts just written (mirrors
        // `seed_account_totals_from_genesis`): fee sink is NotParticipating
        // (excluded from `Participating()`), proposer is Online.
        ledger
            .put_account_totals_seed(1_000_000, 0, 0, 0, 5_000_000, 0)
            .unwrap();
        ledger.discard_pending_account_totals_delta();
        ledger.commit_block().unwrap();

        assert_eq!(ledger.online_stake().unwrap(), 1_000_000);
        assert_eq!(ledger.participating_money().unwrap(), 1_000_000);

        let block = Block {
            round: Round(1),
            fee_sink,
            proposer,
            proposer_payout: 200_000,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            ..Block::default()
        };
        ledger.begin_block().unwrap();
        crate::apply::apply_block(&mut ledger, &block).unwrap();
        ledger.commit_block().unwrap();

        assert_eq!(
            ledger.get_account(&proposer).unwrap().micro_algos,
            1_200_000,
            "proposer's on-disk balance must reflect the payout"
        );
        assert_eq!(
            ledger.online_stake().unwrap(),
            1_200_000,
            "accounttotals.online (GetSupply's online-money) must grow by the payout"
        );
        assert_eq!(
            ledger.participating_money().unwrap(),
            1_200_000,
            "accounttotals online+offline (GetSupply's total-money) must grow by the payout"
        );
    }

    /// Issue #523 (live-cluster follow-up): a block that advances
    /// `RewardsLevel` but touches no accounts at all (the common case in a
    /// low-activity network — no transactions, just heartbeats) must still
    /// grow `accounttotals.online`/`offline` by the aggregate rewards bump,
    /// mirroring go's `AccountTotals.ApplyRewards`
    /// (`ledger/ledgercore/totals.go`): `(newLevel - oldLevel) *
    /// RewardUnits`, applied to the *pre-round* reward-unit counts, added
    /// for `Online` and `Offline` (never `NotParticipating`, which doesn't
    /// earn rewards).
    ///
    /// A live 4-node mixed-cluster run caught this: `RewardsRate` is
    /// nonzero from genesis (seeded from the rewards pool balance), so
    /// `RewardsLevel` climbs every few rounds even with zero real
    /// transaction traffic — but `set_account`/`remove_account` are only
    /// called for accounts a block's payset (or end-of-block processing)
    /// actually touches, so the online stakeholders (who never move funds)
    /// would otherwise never have their accrued rewards folded into
    /// `GetSupply`'s `online-money`/`total-money`, and the two nodes'
    /// reported supply would diverge more with every reward-bearing round.
    #[test]
    fn apply_block_rewards_level_advance_grows_totals_for_untouched_accounts() {
        use algo_types::Block;

        let fee_sink = Address([3u8; 32]);
        let online_addr = Address([11u8; 32]);
        let offline_addr = Address([12u8; 32]);

        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        ledger.begin_block().unwrap();
        ledger.set_account(
            &fee_sink,
            AccountData {
                micro_algos: 100_000,
                status: AccountStatus::NotParticipating,
                ..Default::default()
            },
        );
        // 5 online reward units (5,000,000 microAlgos / 1,000,000 per unit)
        // and 3 offline reward units — chosen distinct so a bug that
        // conflates the two buckets would be caught.
        ledger.set_account(
            &online_addr,
            AccountData {
                micro_algos: 5_000_000,
                status: AccountStatus::Online,
                ..Default::default()
            },
        );
        ledger.set_account(
            &offline_addr,
            AccountData {
                micro_algos: 3_000_000,
                status: AccountStatus::Offline,
                ..Default::default()
            },
        );
        ledger
            .put_account_totals_seed(5_000_000, 5, 3_000_000, 3, 100_000, 0)
            .unwrap();
        ledger.discard_pending_account_totals_delta();
        ledger.commit_block().unwrap();

        // Advance RewardsLevel by 4, with an empty payset — no account is
        // ever touched by this block.
        let block = Block {
            round: Round(1),
            fee_sink,
            rewards_level: 4,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            ..Block::default()
        };
        ledger.begin_block().unwrap();
        crate::apply::apply_block(&mut ledger, &block).unwrap();
        ledger.commit_block().unwrap();

        // online: 5,000,000 + 5 reward units * 4 levels = 5,000,020
        // offline: 3,000,000 + 3 reward units * 4 levels = 3,000,012
        assert_eq!(
            ledger.online_stake().unwrap(),
            5_000_020,
            "untouched online reward units must accrue the rewards-level bump"
        );
        assert_eq!(
            ledger.participating_money().unwrap(),
            5_000_020 + 3_000_012,
            "GetSupply's total-money (online+offline) must include the offline bump too"
        );
    }

    /// Issue #518: `online_circulation_at_round` must exclude stake behind
    /// expired-but-still-online participation keys when the current
    /// protocol's `exclude_expired_circulation` is set (v38+), mirroring
    /// go-algorand's `onlineAccounts.onlineCirculation` subtracting
    /// `expiredOnlineCirculation` (`ledger/acctonline.go`). An online
    /// account whose `VoteLastValid` is strictly less than the queried
    /// `vote_rnd` must be excluded; an online account whose participation
    /// key is still valid at `vote_rnd` must remain included.
    #[test]
    fn online_circulation_at_round_excludes_expired_participation_key_stake() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        ledger.set_protocol(algo_types::consensus::CONSENSUS_V41.to_string());

        // Total online stake: 1,000,000 (expired) + 4,000,000 (still valid).
        ledger
            .put_account_totals_seed(5_000_000, 0, 0, 0, 0, 0)
            .unwrap();

        let expired_addr = Address([21u8; 32]);
        ledger.set_account(
            &expired_addr,
            AccountData {
                micro_algos: 1_000_000,
                status: AccountStatus::Online,
                vote_last_valid: 100,
                ..Default::default()
            },
        );

        let valid_addr = Address([22u8; 32]);
        ledger.set_account(
            &valid_addr,
            AccountData {
                micro_algos: 4_000_000,
                status: AccountStatus::Online,
                vote_last_valid: 1_000,
                ..Default::default()
            },
        );

        // vote_rnd = 200: expired_addr's VoteLastValid (100) < 200, so its
        // 1,000,000 stake must be excluded. valid_addr's VoteLastValid
        // (1,000) >= 200, so its 4,000,000 stake remains included.
        assert_eq!(
            ledger.online_circulation_at_round(50, 200).unwrap(),
            4_000_000,
            "expired participation-key stake must be excluded from circulation"
        );
    }

    /// Issue #518: without the exclusion (pre-v38 protocol, or `round == 0`
    /// per go's genesis-balance carve-out), `online_circulation_at_round`
    /// must return the raw total with no subtraction.
    #[test]
    fn online_circulation_at_round_skips_exclusion_pre_v38_and_at_round_zero() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        ledger.set_protocol(algo_types::consensus::CONSENSUS_V41.to_string());
        ledger
            .put_account_totals_seed(5_000_000, 0, 0, 0, 0, 0)
            .unwrap();
        let expired_addr = Address([23u8; 32]);
        ledger.set_account(
            &expired_addr,
            AccountData {
                micro_algos: 1_000_000,
                status: AccountStatus::Online,
                vote_last_valid: 100,
                ..Default::default()
            },
        );

        // round == 0: go carves this out explicitly (still using genesis
        // balances for the first MaxBalLookback rounds).
        assert_eq!(
            ledger.online_circulation_at_round(0, 200).unwrap(),
            5_000_000,
            "round == 0 must skip the expired-stake exclusion"
        );

        // Pre-v38 protocol: ExcludeExpiredCirculation defaults to false.
        ledger.set_protocol(algo_types::consensus::CONSENSUS_V7.to_string());
        assert_eq!(
            ledger.online_circulation_at_round(50, 200).unwrap(),
            5_000_000,
            "pre-v38 protocol must skip the expired-stake exclusion"
        );
    }

    /// Issue #518 (live-verified follow-up finding): `total`
    /// (`accounttotals.online`, an incrementally-maintained aggregate) and
    /// `expired` (a fresh per-account scan of `accountbase`, which folds
    /// rewards eagerly) are computed via two independent bookkeeping paths
    /// that can disagree by a small amount when reward accrual has been
    /// applied to one but not yet folded into the other -- observed live
    /// against a real dual-node dev-mode harness while adding this
    /// exclusion (`bin/algod-rust/tests/live_online_circulation_expiry.rs`).
    /// A public REST endpoint (`GET /v2/ledger/supply`'s `online-stake`)
    /// must never 500 over that skew: `online_circulation_at_round` must
    /// saturate at 0 rather than erroring when the scanned `expired` figure
    /// exceeds the aggregate `total`.
    #[test]
    fn online_circulation_at_round_saturates_when_expired_exceeds_aggregate_total() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        ledger.set_protocol(algo_types::consensus::CONSENSUS_V41.to_string());
        // Aggregate total (accounttotals.online) deliberately seeded LOWER
        // than the expired account's own stored balance, reproducing the
        // live-observed bookkeeping skew.
        ledger
            .put_account_totals_seed(1_000_000, 0, 0, 0, 0, 0)
            .unwrap();
        let expired_addr = Address([24u8; 32]);
        ledger.set_account(
            &expired_addr,
            AccountData {
                micro_algos: 4_000_000, // > the 1,000,000 aggregate total above
                status: AccountStatus::Online,
                vote_last_valid: 100,
                ..Default::default()
            },
        );

        let result = ledger.online_circulation_at_round(50, 200);
        assert_eq!(
            result.unwrap(),
            0,
            "expired stake exceeding the aggregate total must saturate to 0, not error"
        );
    }

    /// Issue #519: the live per-round writer must bound table growth by pruning
    /// rows older than the `MaxBalLookback` retention window, mirroring
    /// go-algorand's `onlineAccounts.commitRound` calling
    /// `AccountsPruneOnlineRoundParams(onlineAccountsForgetBefore)` where
    /// `onlineAccountsForgetBefore = (newBase + 1).SubSaturate(MaxBalLookback)`
    /// (`ledger/acctonline.go`).
    #[test]
    fn commit_block_prunes_online_supply_snapshots_beyond_lookback_window() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        ledger.set_protocol(algo_types::consensus::CONSENSUS_V41.to_string());

        ledger.begin_block().unwrap();
        ledger.set_current_round(Round(1));
        ledger
            .put_account_totals_seed(1_000_000, 0, 0, 0, 0, 0)
            .unwrap();
        ledger.commit_block().unwrap();
        assert_eq!(ledger.online_supply_at_round(1).unwrap(), Some(1_000_000));

        // Jump far enough ahead that round 1 falls outside the 320-round
        // MaxBalLookback retention window: forget_before = (500+1)-320 = 181.
        ledger.begin_block().unwrap();
        ledger.set_current_round(Round(500));
        ledger
            .put_account_totals_seed(5_000_000, 0, 0, 0, 0, 0)
            .unwrap();
        ledger.commit_block().unwrap();

        assert_eq!(
            ledger.online_supply_at_round(1).unwrap(),
            None,
            "snapshot older than the MaxBalLookback retention window must be pruned"
        );
        assert_eq!(
            ledger.online_supply_at_round(500).unwrap(),
            Some(5_000_000),
            "the just-committed round's snapshot must remain"
        );
    }

    /// Issue #529: the snapshot for the *exact* lookback round
    /// (`round - MaxBalLookback`, the round `agreement::balance_round`
    /// computes and that `get_supply`/sortition actually query) must
    /// survive the very `commit_block` call at `round` that would prune
    /// it. The previous retention formula, `(round + 1).saturating_sub(
    /// max_bal_lookback)`, kept rounds `>= round - 319` -- one round
    /// short of `round - 320` -- so the exact lookback round was pruned
    /// in the same commit that would have served it, silently
    /// collapsing `online_circulation_at_round` to the current-round
    /// aggregate forever (go-algorand's `onlineAccounts.commitRound`,
    /// `ledger/acctonline.go`, has an equivalent-looking formula but its
    /// DB commit round trails the live agreement round by at least one
    /// round of deferral, which the immediate-commit-per-round rust
    /// writer does not have, so it must keep one extra round).
    #[test]
    fn commit_block_retains_snapshot_at_exact_lookback_boundary() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        ledger.set_protocol(algo_types::consensus::CONSENSUS_V41.to_string());

        let max_bal_lookback = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V41,
        )
        .unwrap()
        .max_bal_lookback;
        assert_eq!(max_bal_lookback, 320, "test assumes v41's MaxBalLookback");

        ledger.begin_block().unwrap();
        ledger.set_current_round(Round(1));
        ledger
            .put_account_totals_seed(1_000_000, 0, 0, 0, 0, 0)
            .unwrap();
        ledger.commit_block().unwrap();

        // Commit every round up to round 1 + MaxBalLookback = 321, the
        // round at which `balance_round(321) == 1` is the exact lookback
        // round that must still be retrievable.
        let target_round = 1 + max_bal_lookback;
        for r in 2..=target_round {
            ledger.begin_block().unwrap();
            ledger.set_current_round(Round(r));
            ledger
                .put_account_totals_seed(1_000_000, 0, 0, 0, 0, 0)
                .unwrap();
            ledger.commit_block().unwrap();
        }

        assert_eq!(
            ledger.online_supply_at_round(1).unwrap(),
            Some(1_000_000),
            "the exact lookback round's snapshot (round {} - MaxBalLookback {} = round 1) \
             must survive the commit at round {target_round}",
            target_round,
            max_bal_lookback,
        );
    }

    #[test]
    fn test_begin_commit_block() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();

        ledger.set_current_round(Round(1));
        ledger.begin_block().unwrap();

        let addr = Address([7u8; 32]);
        ledger.set_account(
            &addr,
            AccountData {
                micro_algos: 100,
                ..Default::default()
            },
        );

        ledger.commit_block().unwrap();

        // Chain state should be flushed.
        let round = ledger.last_committed_round().unwrap();
        assert_eq!(round, Some(1));
    }

    #[test]
    fn test_savepoint_rollback() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        ledger.begin_block().unwrap();

        let addr = Address([8u8; 32]);
        ledger.set_account(
            &addr,
            AccountData {
                micro_algos: 1000,
                ..Default::default()
            },
        );

        let sp = ledger.snapshot(&[addr]);

        // Mutate
        ledger.set_account(
            &addr,
            AccountData {
                micro_algos: 500,
                ..Default::default()
            },
        );
        assert_eq!(ledger.get_account(&addr).unwrap().micro_algos, 500);

        // Rollback
        ledger.restore_snapshot(sp);
        assert_eq!(ledger.get_account(&addr).unwrap().micro_algos, 1000);

        ledger.commit_block().unwrap();
    }

    #[test]
    fn simulate_snapshot_does_not_leak_open_txn() {
        // BT-298 regression: the simulate path takes a `snapshot` directly on
        // the ledger (with NO enclosing `begin_block`), evaluates, then
        // `restore_snapshot`s. A top-level SAVEPOINT opens an implicit SQLite
        // transaction; `ROLLBACK TO SAVEPOINT` alone leaves it open, so the
        // NEXT write (`begin_block` → `BEGIN IMMEDIATE`) failed with "cannot
        // start a transaction within a transaction". `restore_snapshot` must
        // also RELEASE the savepoint so the implicit transaction closes.
        let mut ledger = SqliteLedger::open_in_memory().unwrap();

        let addr = Address([3u8; 32]);
        ledger.set_account(
            &addr,
            AccountData {
                micro_algos: 2000,
                ..Default::default()
            },
        );

        // Simulate-style snapshot/restore with no surrounding block txn.
        let sp = ledger.snapshot(&[addr]);
        ledger.set_account(
            &addr,
            AccountData {
                micro_algos: 1,
                ..Default::default()
            },
        );
        ledger.restore_snapshot(sp);

        // State was rolled back...
        assert_eq!(ledger.get_account(&addr).unwrap().micro_algos, 2000);

        // ...and no open transaction lingers, so a subsequent write (the
        // "submit") succeeds rather than erroring with a nested-transaction.
        ledger
            .begin_block()
            .expect("begin_block after simulate must succeed (no lingering txn)");
        ledger.commit_block().unwrap();
    }

    #[test]
    fn test_lease_in_memory() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let sender = Address([9u8; 32]);
        let lease = [0xAA; 32];

        assert!(ledger.check_lease(&sender, &lease, 100).is_ok());
        ledger.record_lease(&sender, &lease, 200);
        assert!(ledger.check_lease(&sender, &lease, 100).is_err());
        ledger.purge_expired_leases(201);
        assert!(ledger.check_lease(&sender, &lease, 100).is_ok());
    }

    #[test]
    fn rollback_block_restores_lease_table() {
        // A lease recorded during a block that is then rolled back must not
        // persist — the SQLite ROLLBACK does not cover the in-memory lease
        // table, so begin_block snapshots it and rollback_block restores it.
        // Otherwise a partially-applied-then-failed block would wedge future
        // transactions that reuse the lease (Codex PR #410).
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let sender = Address([7u8; 32]);
        let lease = [0xAB; 32];

        ledger.begin_block().unwrap();
        ledger.record_lease(&sender, &lease, 1000);
        // Within the block the lease is active (a reuse would be rejected).
        assert!(ledger.check_lease(&sender, &lease, 100).is_err());
        ledger.rollback_block().unwrap();

        // After rollback the lease is gone — reusable.
        assert!(
            ledger.check_lease(&sender, &lease, 100).is_ok(),
            "rolled-back lease must not persist",
        );
    }

    #[test]
    fn commit_block_keeps_lease_table() {
        // Committed lease changes stand (the snapshot is discarded, not restored).
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let sender = Address([8u8; 32]);
        let lease = [0xCD; 32];

        ledger.begin_block().unwrap();
        ledger.record_lease(&sender, &lease, 1000);
        ledger.commit_block().unwrap();

        assert!(
            ledger.check_lease(&sender, &lease, 100).is_err(),
            "committed lease must persist",
        );
    }

    #[test]
    fn test_msgpack_account_omitempty() {
        // Default account should produce a small msgpack map (empty or near-empty).
        let acct = AccountData::default();
        let encoded = encode_account_data(&acct);
        let decoded = decode_account_data(&encoded).unwrap();
        assert_eq!(decoded, acct);
    }

    #[test]
    fn test_msgpack_account_full() {
        let acct = AccountData {
            micro_algos: 10_000_000,
            rewards_base: 500,
            rewarded_micro_algos: 1000,
            status: AccountStatus::Online,
            vote_id: Some([0xAA; 32]),
            selection_id: Some([0xBB; 32]),
            state_proof_id: Some([0xCC; 64]),
            vote_first_valid: 100,
            vote_last_valid: 200,
            vote_key_dilution: 10,
            auth_addr: Some(Address([0xDD; 32])),
            total_assets_opted_in: 5,
            total_created_assets: 2,
            total_apps_opted_in: 3,
            total_created_apps: 1,
            total_extra_app_pages: 2,
            total_app_schema: StateSchema {
                num_uint: 4,
                num_byte_slice: 2,
            },
            incentive_eligible: true,
            last_proposed: 10,
            last_heartbeat: 15,
            total_box_bytes: 100,
            total_boxes: 5,
            update_round: 42,
            asset_params: BTreeMap::new(),
            assets: BTreeMap::new(),
            app_local_states: BTreeMap::new(),
            app_params: BTreeMap::new(),
        };
        let encoded = encode_account_data(&acct);
        let decoded = decode_account_data(&encoded).unwrap();
        assert_eq!(decoded, acct);
    }

    #[test]
    fn test_min_balance_with_state_sqlite() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let addr = Address([10u8; 32]);

        let account = AccountData {
            total_apps_opted_in: 1,
            ..Default::default()
        };
        ledger.set_account(&addr, account.clone());

        ledger.set_app_local_state(
            &addr,
            100,
            AppLocalState {
                schema: StateSchema {
                    num_uint: 2,
                    num_byte_slice: 1,
                },
                key_value: BTreeMap::new(),
            },
        );

        let mb = ledger.min_balance_with_state(&addr, &account);
        // Flat: 100_000 (base) + 100_000 (1 opted-in app) = 200_000
        // Schema: 3 * 25_000 + 2 * 3_500 + 1 * 25_000 = 107_000
        assert_eq!(mb, 200_000 + 107_000);
    }

    #[test]
    fn test_app_params_and_local_state_same_address_merge() {
        // Scenario: address is both the creator of app 50 AND opts into app 50.
        // Both write to resources(addrid=same_rowid, aidx=50, ctype=2).
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let addr = Address([11u8; 32]);
        ledger.set_account(&addr, AccountData::default());

        let params = AppParams {
            creator: addr,
            approval_program: vec![0x06, 0x81, 0x01],
            clear_state_program: vec![0x06, 0x81, 0x01],
            global_state: BTreeMap::new(),
            local_state_schema: StateSchema {
                num_uint: 2,
                num_byte_slice: 0,
            },
            global_state_schema: StateSchema {
                num_uint: 4,
                num_byte_slice: 0,
            },
            extra_program_pages: 0,
            ..Default::default()
        };

        let local = AppLocalState {
            schema: StateSchema {
                num_uint: 2,
                num_byte_slice: 0,
            },
            key_value: BTreeMap::new(),
        };

        // Set app params first, then local state.
        ledger.set_app_params(50, params.clone());
        ledger.set_app_local_state(&addr, 50, local.clone());

        // Both should be retrievable.
        let loaded_params = ledger.get_app_params(50).unwrap();
        assert_eq!(loaded_params.approval_program, vec![0x06, 0x81, 0x01]);
        assert_eq!(loaded_params.global_state_schema.num_uint, 4);

        let loaded_local = ledger.get_app_local_state(&addr, 50).unwrap();
        assert_eq!(loaded_local.schema.num_uint, 2);

        // Verify has_* methods work.
        assert!(ledger.has_app_params(50));
        assert!(ledger.has_app_local_state(&addr, 50));

        // Remove local state — app params should survive.
        ledger.remove_app_local_state(&addr, 50);
        assert!(ledger.has_app_params(50));
        assert!(!ledger.has_app_local_state(&addr, 50));

        let loaded_params2 = ledger.get_app_params(50).unwrap();
        assert_eq!(loaded_params2.approval_program, vec![0x06, 0x81, 0x01]);
    }

    #[test]
    fn test_app_params_and_local_state_reverse_order() {
        // Same as above but set local state first, then app params.
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let addr = Address([12u8; 32]);
        ledger.set_account(&addr, AccountData::default());

        let local = AppLocalState {
            schema: StateSchema {
                num_uint: 3,
                num_byte_slice: 1,
            },
            key_value: BTreeMap::new(),
        };

        let params = AppParams {
            creator: addr,
            approval_program: vec![0x06, 0x20, 0x01],
            clear_state_program: vec![0x06],
            global_state: BTreeMap::new(),
            local_state_schema: StateSchema::default(),
            global_state_schema: StateSchema::default(),
            extra_program_pages: 0,
            ..Default::default()
        };

        // Local state first, then params.
        ledger.set_app_local_state(&addr, 60, local.clone());
        ledger.set_app_params(60, params.clone());

        assert!(ledger.has_app_params(60));
        assert!(ledger.has_app_local_state(&addr, 60));

        let loaded_params = ledger.get_app_params(60).unwrap();
        assert_eq!(loaded_params.approval_program, vec![0x06, 0x20, 0x01]);

        let loaded_local = ledger.get_app_local_state(&addr, 60).unwrap();
        assert_eq!(loaded_local.schema.num_uint, 3);

        // Remove app params — local state should survive.
        ledger.remove_app_params(60);
        assert!(!ledger.has_app_params(60));
        assert!(ledger.has_app_local_state(&addr, 60));

        let loaded_local2 = ledger.get_app_local_state(&addr, 60).unwrap();
        assert_eq!(loaded_local2.schema.num_uint, 3);
    }

    #[test]
    fn test_asset_params_and_holding_same_address_merge() {
        // Scenario: address is both the creator of asset 70 AND holds asset 70.
        // Both write to resources(addrid=same_rowid, aidx=70, ctype=1).
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let addr = Address([14u8; 32]);
        ledger.set_account(&addr, AccountData::default());

        let params = AssetParams {
            total: 1_000_000,
            decimals: 6,
            unit_name: "TEST".into(),
            asset_name: "TestAsset".into(),
            manager: Some(addr),
            ..Default::default()
        };

        let holding = AssetHolding {
            amount: 500_000,
            frozen: false,
        };

        // Set params first, then holding.
        ledger.set_asset_params(
            70,
            AssetParamsRecord {
                params: params.clone(),
                creator: addr,
            },
        );
        ledger.set_asset_holding(&addr, 70, holding.clone());

        // Both should be retrievable.
        let loaded_params = ledger.get_asset_params(70).unwrap();
        assert_eq!(loaded_params.params.total, 1_000_000);
        assert_eq!(loaded_params.params.decimals, 6);
        assert_eq!(loaded_params.params.unit_name, "TEST");
        assert_eq!(loaded_params.params.asset_name, "TestAsset");
        assert_eq!(loaded_params.params.manager, Some(addr));
        assert_eq!(loaded_params.creator, addr);

        let loaded_holding = ledger.get_asset_holding(&addr, 70).unwrap();
        assert_eq!(loaded_holding.amount, 500_000);
        assert!(!loaded_holding.frozen);

        // Verify has_* methods work.
        assert!(ledger.has_asset_params(70));
        assert!(ledger.has_asset_holding(&addr, 70));

        // Remove holding — asset params should survive.
        ledger.remove_asset_holding(&addr, 70);
        assert!(ledger.has_asset_params(70));
        assert!(!ledger.has_asset_holding(&addr, 70));

        let loaded_params2 = ledger.get_asset_params(70).unwrap();
        assert_eq!(loaded_params2.params.total, 1_000_000);
        assert_eq!(loaded_params2.params.unit_name, "TEST");
    }

    #[test]
    fn test_asset_params_and_holding_reverse_order() {
        // Same as above but set holding first, then params.
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let addr = Address([15u8; 32]);
        ledger.set_account(&addr, AccountData::default());

        let holding = AssetHolding {
            amount: 999,
            frozen: true,
        };

        let params = AssetParams {
            total: 10_000,
            decimals: 2,
            unit_name: "REV".into(),
            asset_name: "Reverse".into(),
            ..Default::default()
        };

        // Holding first, then params.
        ledger.set_asset_holding(&addr, 80, holding.clone());
        ledger.set_asset_params(
            80,
            AssetParamsRecord {
                params: params.clone(),
                creator: addr,
            },
        );

        assert!(ledger.has_asset_params(80));
        assert!(ledger.has_asset_holding(&addr, 80));

        let loaded_params = ledger.get_asset_params(80).unwrap();
        assert_eq!(loaded_params.params.total, 10_000);
        assert_eq!(loaded_params.params.decimals, 2);
        assert_eq!(loaded_params.params.unit_name, "REV");

        let loaded_holding = ledger.get_asset_holding(&addr, 80).unwrap();
        assert_eq!(loaded_holding.amount, 999);
        assert!(loaded_holding.frozen);

        // Remove params — holding should survive.
        ledger.remove_asset_params(80);
        assert!(!ledger.has_asset_params(80));
        assert!(ledger.has_asset_holding(&addr, 80));

        let loaded_holding2 = ledger.get_asset_holding(&addr, 80).unwrap();
        assert_eq!(loaded_holding2.amount, 999);
        assert!(loaded_holding2.frozen);
    }

    #[test]
    fn test_rollback_block() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let addr = Address([13u8; 32]);

        ledger.begin_block().unwrap();
        ledger.set_account(
            &addr,
            AccountData {
                micro_algos: 999,
                ..Default::default()
            },
        );
        ledger.rollback_block().unwrap();

        // Account should not exist after rollback.
        assert!(ledger.get_account(&addr).is_none());
        assert!(!ledger.in_block);
    }

    #[test]
    fn test_trie_persist_and_load() {
        use crate::store_trait::LedgerStore;

        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        ledger.enable_trie();
        assert!(ledger.trie_enabled());

        // Add some accounts.
        let addr1 = Address([20u8; 32]);
        let addr2 = Address([21u8; 32]);
        ledger.set_account(
            &addr1,
            AccountData {
                micro_algos: 1_000_000,
                update_round: 1,
                ..Default::default()
            },
        );
        ledger.set_account(
            &addr2,
            AccountData {
                micro_algos: 2_000_000,
                update_round: 1,
                ..Default::default()
            },
        );

        // Finalize trie and get root hash.
        let root1 = ledger.finalize_trie_updates().unwrap();
        assert_ne!(root1, [0u8; 32]);

        // Persist trie via commit_block.
        ledger.begin_block().unwrap();
        ledger.commit_block().unwrap();

        // Load trie from DB.
        ledger.load_trie().unwrap();
        let trie = ledger.trie.as_mut().unwrap();
        let root2 = trie.root_hash().unwrap();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_trie_rebuild_from_db() {
        use crate::store_trait::LedgerStore;

        let mut ledger = SqliteLedger::open_in_memory().unwrap();

        // Add accounts without trie enabled first.
        let addr1 = Address([30u8; 32]);
        let addr2 = Address([31u8; 32]);
        ledger.set_account(
            &addr1,
            AccountData {
                micro_algos: 500_000,
                update_round: 5,
                ..Default::default()
            },
        );
        ledger.set_account(
            &addr2,
            AccountData {
                micro_algos: 750_000,
                update_round: 5,
                ..Default::default()
            },
        );

        // Now enable trie — should rebuild from DB since no persisted trie exists.
        ledger.enable_trie();
        assert!(ledger.trie_enabled());

        let trie = ledger.trie.as_mut().unwrap();
        let root = trie.root_hash().unwrap();
        // With 2 accounts in DB, trie should be non-empty.
        assert_ne!(root, [0u8; 32]);
        assert_eq!(trie.len(), 2);
    }

    /// Regression (TASK-257): enabling the per-group delta tracer must not
    /// change the committed trie. The scratch capture appends trie
    /// pre-mutations that the savepoint does not roll back; if they leaked they
    /// would be consumed by the authoritative commit's `finalize_trie_updates`
    /// and corrupt the root.
    #[test]
    fn group_tracer_does_not_leak_trie_pre_mutations() {
        use crate::store_trait::LedgerStore;
        use algo_types::{Block, SignedTransaction};

        let a = Address([1u8; 32]);
        let b = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let make_block = || {
            let mut stx = SignedTransaction::default();
            stx.txn.txn_type = "pay".into();
            stx.txn.sender = a;
            stx.txn.receiver = b;
            stx.txn.amount = 100_000;
            stx.txn.fee = 1000;
            stx.txn.last_valid = Round(1000);
            Block {
                round: Round(1),
                fee_sink,
                current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
                payset: vec![stx],
                ..Block::default()
            }
        };

        let committed_root = |tracer_on: bool| -> [u8; 32] {
            let mut l = SqliteLedger::open_in_memory().unwrap();
            l.set_account(
                &a,
                AccountData {
                    micro_algos: 5_000_000,
                    ..Default::default()
                },
            );
            l.set_account(&b, AccountData::default());
            l.set_account(&fee_sink, AccountData::default());
            // Build the trie from the seeded accounts, then apply the block.
            l.enable_trie();
            if tracer_on {
                l.enable_group_delta_tracer(8);
            }
            l.begin_block().unwrap();
            l.apply_block_caching_delta(&make_block()).unwrap();
            l.finalize_trie_updates();
            l.commit_block().unwrap();
            l.trie.as_mut().unwrap().root_hash().unwrap()
        };

        assert_eq!(
            committed_root(false),
            committed_root(true),
            "enabling the group tracer must not change the committed trie root"
        );
    }

    /// Build a v8 program that `box_put`s a fixed-size value into `name` and
    /// approves, for issue #570's historical-box-reconstruction tests.
    fn box_put_program(name: &str, value: &str) -> Vec<u8> {
        let source = format!(
            "#pragma version 8\nbyte \"{name}\"\nbyte \"{value}\"\nbox_put\nint 1\nreturn\n"
        );
        algo_avm::assembler::assemble_string(&source)
            .expect("box_put program must assemble")
            .program
    }

    /// Build a v8 program that `box_del`s `name` and approves.
    fn box_del_program(name: &str) -> Vec<u8> {
        let source = format!("#pragma version 8\nbyte \"{name}\"\nbox_del\npop\nint 1\nreturn\n");
        algo_avm::assembler::assemble_string(&source)
            .expect("box_del program must assemble")
            .program
    }

    /// Apply `stx` as round `round`'s sole payset entry in Execute mode
    /// (so any box opcodes really run), caching the resulting `StateDelta`
    /// into the ledger's `DeltaCache` the same way a real Execute-mode
    /// apply driver would (issue #570 -- `apply_block_caching_delta`
    /// itself stays Replay-mode-only; see `apply_block_with_delta_mode`'s
    /// doc comment for why).
    fn apply_execute_round(
        ledger: &mut SqliteLedger,
        round: u64,
        fee_sink: Address,
        stx: algo_types::SignedTransaction,
    ) {
        use algo_types::Block;
        let block = Block {
            round: Round(round),
            fee_sink,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![stx],
            ..Block::default()
        };
        ledger.begin_block().unwrap();
        let delta = crate::apply::apply_block_with_delta_mode(
            ledger,
            &block,
            crate::apply::ApplyMode::Execute,
        )
        .unwrap();
        ledger.cache_state_delta(round, delta);
        ledger.commit_block().unwrap();
    }

    /// TDD regression for issue #574: the *real* default sync path
    /// (`apply_block_caching_delta`, called unconditionally by
    /// `bin/algod-rust/src/commands/sync.rs`'s non-`--avm-execute` branch,
    /// which is the default) must still replicate box mutations from `appl`
    /// transactions.
    ///
    /// Before the fix, `apply_block_caching_delta` routed any block whose
    /// payset failed `block_state_delta_is_complete` (which excludes `Appl`
    /// among other types) to the bare `apply_block` helper -- always
    /// `ApplyMode::Replay`. Replay mode never runs the AVM, so it never
    /// reaches the box-mutation call sites in `avm_context.rs`; a normally
    /// synced node would silently never see this `box_put`, even though the
    /// app call was itself successful (go-algorand's own `EvalDelta` /
    /// `ApplyData` has no box-content field, so nothing in the block itself
    /// could have replayed the box write either -- see issue #574).
    #[test]
    fn apply_block_caching_delta_replicates_box_put_for_real_sync_path() {
        use algo_types::{AppParams, Block, BoxRef, SignedTransaction, StateSchema, Transaction};
        use serde_bytes::ByteBuf;

        let creator = Address([1u8; 32]);
        let sender = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let app_id = 950u64;

        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        ledger.set_account(
            &creator,
            AccountData {
                micro_algos: 50_000_000,
                total_created_apps: 1,
                ..Default::default()
            },
        );
        ledger.set_account(
            &sender,
            AccountData {
                micro_algos: 50_000_000,
                ..Default::default()
            },
        );
        ledger.set_account(&fee_sink, AccountData::default());
        ledger.set_app_params(
            app_id,
            AppParams {
                creator,
                approval_program: box_put_program("mybox", "hello"),
                clear_state_program: vec![0x08, 0x81, 0x01], // v8, pushint 1
                global_state: BTreeMap::new(),
                local_state_schema: StateSchema {
                    num_uint: 0,
                    num_byte_slice: 0,
                },
                global_state_schema: StateSchema {
                    num_uint: 0,
                    num_byte_slice: 0,
                },
                extra_program_pages: 0,
                ..Default::default()
            },
        );

        let stx = SignedTransaction {
            txn: Transaction {
                txn_type: "appl".into(),
                sender,
                fee: 1_000,
                first_valid: Round(1),
                last_valid: Round(1000),
                application_id: app_id,
                on_completion: 0,
                boxes: Some(vec![BoxRef {
                    index: 0,
                    name: Some(ByteBuf::from(b"mybox".to_vec())),
                }]),
                ..Default::default()
            },
            ..Default::default()
        };

        let block = Block {
            round: Round(1),
            fee_sink,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![stx],
            ..Block::default()
        };

        // This is exactly what `commands/sync.rs`'s default (non-
        // `--avm-execute`) branch calls per received block.
        ledger.begin_block().unwrap();
        ledger.apply_block_caching_delta(&block).unwrap();
        ledger.commit_block().unwrap();

        assert_eq!(
            ledger.get_box(app_id, b"mybox"),
            Some(b"hello".to_vec()),
            "box_put via an appl transaction must be reflected in box \
             storage even when the block arrives through the default \
             (Replay-mode-gated) sync path, not just the --avm-execute / \
             dev-mode Execute path"
        );
    }

    /// TDD regression for issue #570's box-list `round` reconstruction:
    /// across a box created, mutated, and deleted at three different
    /// rounds, `reconstruct_box_state_at_round` must recover the exact
    /// value the box held at the end of each historical round.
    #[test]
    fn reconstruct_box_state_at_round_across_create_mutate_delete() {
        use algo_types::{AppParams, BoxRef, SignedTransaction, StateSchema, Transaction};
        use serde_bytes::ByteBuf;

        let creator = Address([1u8; 32]);
        let sender = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let app_id = 900u64;

        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        ledger.set_account(
            &creator,
            AccountData {
                micro_algos: 50_000_000,
                total_created_apps: 1,
                ..Default::default()
            },
        );
        ledger.set_account(
            &sender,
            AccountData {
                micro_algos: 50_000_000,
                ..Default::default()
            },
        );
        ledger.set_account(&fee_sink, AccountData::default());
        ledger.set_app_params(
            app_id,
            AppParams {
                creator,
                approval_program: box_put_program("mybox", "aaaaa"),
                clear_state_program: vec![0x08, 0x81, 0x01], // v8, pushint 1
                global_state: BTreeMap::new(),
                local_state_schema: StateSchema {
                    num_uint: 0,
                    num_byte_slice: 0,
                },
                global_state_schema: StateSchema {
                    num_uint: 0,
                    num_byte_slice: 0,
                },
                extra_program_pages: 0,
                ..Default::default()
            },
        );

        let appl_txn = |fee: u64| SignedTransaction {
            txn: Transaction {
                txn_type: "appl".into(),
                sender,
                fee,
                first_valid: Round(1),
                last_valid: Round(1000),
                application_id: app_id,
                on_completion: 0,
                boxes: Some(vec![BoxRef {
                    index: 0,
                    name: Some(ByteBuf::from(b"mybox".to_vec())),
                }]),
                ..Default::default()
            },
            ..Default::default()
        };

        // Round 1: create the box with "aaaaa".
        apply_execute_round(&mut ledger, 1, fee_sink, appl_txn(1_000));

        // Round 2: mutate to "bbbbb" (same size, box_put requires it).
        ledger.set_app_params(
            app_id,
            AppParams {
                creator,
                approval_program: box_put_program("mybox", "bbbbb"),
                clear_state_program: vec![0x08, 0x81, 0x01],
                global_state: BTreeMap::new(),
                local_state_schema: StateSchema {
                    num_uint: 0,
                    num_byte_slice: 0,
                },
                global_state_schema: StateSchema {
                    num_uint: 0,
                    num_byte_slice: 0,
                },
                extra_program_pages: 0,
                ..Default::default()
            },
        );
        apply_execute_round(&mut ledger, 2, fee_sink, appl_txn(1_001));

        // Round 3: delete the box.
        ledger.set_app_params(
            app_id,
            AppParams {
                creator,
                approval_program: box_del_program("mybox"),
                clear_state_program: vec![0x08, 0x81, 0x01],
                global_state: BTreeMap::new(),
                local_state_schema: StateSchema {
                    num_uint: 0,
                    num_byte_slice: 0,
                },
                global_state_schema: StateSchema {
                    num_uint: 0,
                    num_byte_slice: 0,
                },
                extra_program_pages: 0,
                ..Default::default()
            },
        );
        apply_execute_round(&mut ledger, 3, fee_sink, appl_txn(1_002));

        // Current (round 3) state: box deleted.
        assert_eq!(ledger.get_box(app_id, b"mybox"), None);

        // Historical reconstruction.
        let at_round_2 = ledger
            .reconstruct_box_state_at_round(app_id, 2)
            .expect("round 2 is within the delta cache window");
        assert_eq!(
            at_round_2.get(b"mybox".as_slice()),
            Some(&b"bbbbb".to_vec())
        );

        let at_round_1 = ledger
            .reconstruct_box_state_at_round(app_id, 1)
            .expect("round 1 is within the delta cache window");
        assert_eq!(
            at_round_1.get(b"mybox".as_slice()),
            Some(&b"aaaaa".to_vec())
        );

        let at_round_0 = ledger
            .reconstruct_box_state_at_round(app_id, 0)
            .expect("round 0 is within the delta cache window");
        assert!(
            !at_round_0.contains_key(b"mybox".as_slice()),
            "box did not exist before round 1"
        );

        // "Latest" (round 3) and beyond are not historical queries.
        assert!(ledger.reconstruct_box_state_at_round(app_id, 3).is_none());
        assert!(ledger.reconstruct_box_state_at_round(app_id, 4).is_none());

        // Paginated wrapper matches the raw reconstruction for the same round.
        let (page, more) = ledger
            .lookup_kv_pairs_by_prefix_at_round(app_id, 1, b"", None, None, true)
            .expect("round 1 is within the delta cache window");
        assert!(!more);
        assert_eq!(page, vec![(b"mybox".to_vec(), Some(b"aaaaa".to_vec()))]);
    }

    /// A round older than the `DeltaCache`'s retained window must fail to
    /// reconstruct (issue #570's acceptance criterion: still 400s, but for
    /// the documented window-boundary reason rather than a blanket
    /// "not supported").
    #[test]
    fn reconstruct_box_state_at_round_outside_window_returns_none() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        // Directly advance the delta cache's window past round 1 without
        // going through 320 real rounds, mirroring how `DeltaCache::advance`
        // is exercised in `delta_cache.rs`'s own unit tests.
        ledger
            .delta_cache
            .advance(1 + crate::delta_cache::DEFAULT_WINDOW_SIZE as u64);
        ledger.set_current_round(Round(1 + crate::delta_cache::DEFAULT_WINDOW_SIZE as u64));

        assert!(ledger.reconstruct_box_state_at_round(1, 0).is_none());
    }

    #[test]
    fn test_trie_rollback_reloads() {
        use crate::store_trait::LedgerStore;

        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        ledger.enable_trie();

        // Add an account and commit.
        let addr = Address([40u8; 32]);
        ledger.begin_block().unwrap();
        ledger.set_account(
            &addr,
            AccountData {
                micro_algos: 100,
                update_round: 1,
                ..Default::default()
            },
        );
        let _ = ledger.finalize_trie_updates();
        ledger.commit_block().unwrap();

        let root_after_commit = ledger.trie.as_mut().unwrap().root_hash().unwrap();

        // Start a new block, mutate, then rollback.
        ledger.begin_block().unwrap();
        ledger.set_account(
            &addr,
            AccountData {
                micro_algos: 999,
                update_round: 2,
                ..Default::default()
            },
        );
        let _ = ledger.finalize_trie_updates();

        // Trie hash should differ after mutation.
        let root_during_block = ledger.trie.as_mut().unwrap().root_hash().unwrap();
        assert_ne!(root_after_commit, root_during_block);

        // Rollback should reload trie to committed state.
        ledger.rollback_block().unwrap();
        let root_after_rollback = ledger.trie.as_mut().unwrap().root_hash().unwrap();
        assert_eq!(root_after_commit, root_after_rollback);
    }

    /// PLAN-36 TASK-128 / issue #603: the payset-completeness gate that
    /// controls whether `apply_block_caching_delta` caches a delta.
    /// Pay / Keyreg / Acfg / Axfer / Afrz blocks (including the
    /// empty-payset case) pass; `Appl` / Stpf / Hb, or an `Unknown(_)`
    /// fallback — fails the gate so the REST endpoint stays at
    /// `NotFound` rather than serving a known-incomplete delta. `Appl` is
    /// excluded because its resource-key collection doesn't yet recurse
    /// into inner transactions (issue #604). `Hb` is excluded because the
    /// heartbeat target address isn't included in the diff's address set
    /// (see `block_state_delta_is_complete`).
    #[test]
    fn test_block_state_delta_is_complete_gate() {
        use algo_types::{Block, SignedTransaction, Transaction, TxnType};

        fn block_with_types(types: &[TxnType]) -> Block {
            Block {
                payset: types
                    .iter()
                    .map(|t| SignedTransaction {
                        txn: Transaction {
                            txn_type: t.clone(),
                            ..Default::default()
                        },
                        ..Default::default()
                    })
                    .collect(),
                ..Block::default()
            }
        }

        // Empty payset is trivially "delta-complete".
        assert!(block_state_delta_is_complete(&block_with_types(&[])));
        // Pure Pay / Keyreg / Acfg / Axfer / Afrz payloads pass (issue
        // #603 widened the gate to admit the latter three now that #586
        // makes their top-level resource-key collection complete).
        assert!(block_state_delta_is_complete(&block_with_types(&[
            TxnType::Pay
        ])));
        assert!(block_state_delta_is_complete(&block_with_types(&[
            TxnType::Pay,
            TxnType::Keyreg,
        ])));
        assert!(block_state_delta_is_complete(&block_with_types(&[
            TxnType::Acfg,
            TxnType::Axfer,
            TxnType::Afrz,
        ])));
        assert!(block_state_delta_is_complete(&block_with_types(&[
            TxnType::Pay,
            TxnType::Keyreg,
            TxnType::Acfg,
            TxnType::Axfer,
            TxnType::Afrz,
        ])));
        // Any other transaction type fails the gate. `Appl` is excluded
        // because its resource-key collection doesn't recurse into inner
        // transactions (issue #604). `Hb` is excluded because
        // `apply::collect_txn_addresses` does not include the heartbeat
        // target — the resulting `accts` diff would be incomplete for
        // off-payset targets.
        for unsupported in [
            TxnType::Appl,
            TxnType::Stpf,
            TxnType::Hb,
            TxnType::Unknown(String::new()),
            TxnType::Unknown("future-type".into()),
        ] {
            assert!(
                !block_state_delta_is_complete(&block_with_types(std::slice::from_ref(
                    &unsupported
                ))),
                "expected gate to reject {unsupported:?}"
            );
            // Single bad txn taints an otherwise-pure block.
            assert!(
                !block_state_delta_is_complete(&block_with_types(&[TxnType::Pay, unsupported,])),
                "mixed payset should fail the gate"
            );
        }
    }

    /// PLAN-36 TASK-128: `cache_state_delta` / `get_cached_state_delta`
    /// implement the rolling-window contract the REST adapter relies on.
    /// Exercises the trio of API methods directly (no apply needed) so
    /// the test is independent of unrelated apply-path regressions.
    #[test]
    fn test_delta_cache_round_trip_and_eviction() {
        use crate::state_delta::StateDelta;

        let mut ledger = SqliteLedger::open_in_memory().unwrap();

        // Empty cache: any round is None.
        assert!(ledger.get_cached_state_delta(0).is_none());
        assert_eq!(ledger.delta_cache_len(), 0);

        // Inside the window: round survives.
        ledger.cache_state_delta(10, StateDelta::default());
        assert!(ledger.get_cached_state_delta(10).is_some());
        assert_eq!(ledger.delta_cache_len(), 1);

        // Eviction: insert a round far enough ahead to push round 10 out
        // of the default 320-round window. After insert, min_round should
        // be 11 (latest - window_size + 1).
        let latest = 10 + crate::delta_cache::DEFAULT_WINDOW_SIZE as u64;
        ledger.cache_state_delta(latest, StateDelta::default());
        assert!(ledger.get_cached_state_delta(10).is_none());
        assert!(ledger.get_cached_state_delta(latest).is_some());
        assert_eq!(ledger.delta_cache_min_round(), 11);
    }

    #[test]
    fn test_legacy_merkle_trie_table_absent() {
        // PLAN-36 G4 (TASK-118) dropped the Rust-only single-blob
        // `merkle_trie` table from the schema. A freshly-opened
        // tracker DB must not contain it; the paged `accounthashes`
        // table is the sole on-disk trie representation.
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let legacy_count: i64 = ledger
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='merkle_trie'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_count, 0, "merkle_trie table should not be created");

        let paged_count: i64 = ledger
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='accounthashes'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(paged_count, 1, "accounthashes table must exist");
    }

    #[test]
    fn test_put_get_block() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let hdrdata = b"header-bytes";
        let blkdata = b"block-bytes";
        ledger.put_block(10, "v41", hdrdata, blkdata).unwrap();

        let got_blk = ledger.get_block_data(10).unwrap().unwrap();
        assert_eq!(got_blk, blkdata);

        let got_hdr = ledger.get_block_header_data(10).unwrap().unwrap();
        assert_eq!(got_hdr, hdrdata);
    }

    #[test]
    fn test_put_get_txtail() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        let data = b"txtail-payload";
        ledger.put_txtail(5, data).unwrap();

        let got = ledger.get_txtail(5).unwrap().unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn test_forget_before() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        for rnd in 1..=10u64 {
            ledger
                .put_block(rnd, "v41", &[rnd as u8], &[rnd as u8])
                .unwrap();
            ledger.put_txtail(rnd, &[rnd as u8]).unwrap();
        }

        ledger.forget_before(6).unwrap();

        // Rounds 1-5 should be gone.
        for rnd in 1..=5u64 {
            assert!(ledger.get_block_data(rnd).unwrap().is_none());
            assert!(ledger.get_txtail(rnd).unwrap().is_none());
        }
        // Rounds 6-10 should remain.
        for rnd in 6..=10u64 {
            assert!(ledger.get_block_data(rnd).unwrap().is_some());
            assert!(ledger.get_txtail(rnd).unwrap().is_some());
        }
    }

    #[test]
    fn test_block_not_found() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        assert!(ledger.get_block_data(999).unwrap().is_none());
        assert!(ledger.get_block_header_data(999).unwrap().is_none());
        assert!(ledger.get_txtail(999).unwrap().is_none());
    }

    #[test]
    fn test_put_block_cert() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        ledger.put_block(7, "v41", b"hdr", b"blk").unwrap();
        ledger.put_block_cert(7, b"cert-data").unwrap();

        // Verify cert via raw SQL since there's no get_block_cert method.
        let certdata: Option<Vec<u8>> = ledger
            .conn
            .query_row(
                "SELECT certdata FROM blockdb.blocks WHERE rnd = ?1",
                params![7i64],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(certdata.unwrap(), b"cert-data");
    }

    #[test]
    fn test_put_block_overwrites_preserves_cert() {
        let mut ledger = SqliteLedger::open_in_memory().unwrap();
        ledger.put_block(3, "v40", b"hdr1", b"blk1").unwrap();
        ledger.put_block_cert(3, b"cert-data").unwrap();

        // Re-insert block data — certificate should be preserved.
        ledger.put_block(3, "v41", b"hdr2", b"blk2").unwrap();

        let got_blk = ledger.get_block_data(3).unwrap().unwrap();
        assert_eq!(got_blk, b"blk2");

        let got_hdr = ledger.get_block_header_data(3).unwrap().unwrap();
        assert_eq!(got_hdr, b"hdr2");

        // Verify cert was NOT erased by the re-insert.
        let got_cert = ledger.get_block_cert(3).unwrap();
        assert_eq!(got_cert, Some(b"cert-data".to_vec()));
    }

    // ------------------------------------------------------------------
    // Two-file (tracker + block) layout tests — mirrors go-algorand's
    // `<prefix>.tracker.sqlite` + `<prefix>.block.sqlite` pair
    // (`../go-algorand/ledger/ledger.go:327,336`).
    // ------------------------------------------------------------------

    #[test]
    fn derive_ledger_prefix_strips_known_suffixes() {
        use std::path::PathBuf;
        assert_eq!(
            derive_ledger_prefix(&PathBuf::from("/var/lib/algod/ledger")),
            PathBuf::from("/var/lib/algod/ledger")
        );
        assert_eq!(
            derive_ledger_prefix(&PathBuf::from("/var/lib/algod/ledger.sqlite")),
            PathBuf::from("/var/lib/algod/ledger")
        );
        assert_eq!(
            derive_ledger_prefix(&PathBuf::from("/var/lib/algod/ledger.tracker.sqlite")),
            PathBuf::from("/var/lib/algod/ledger")
        );
        assert_eq!(
            derive_ledger_prefix(&PathBuf::from("/var/lib/algod/ledger.block.sqlite")),
            PathBuf::from("/var/lib/algod/ledger")
        );
    }

    #[test]
    fn open_with_prefix_creates_two_files_with_split_schemas() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");

        // Open once to create the pair.
        let ledger = SqliteLedger::open_with_prefix(&prefix).expect("open prefix");
        drop(ledger);

        // Both files exist on disk after open.
        let tracker_path = tracker_path_for_prefix(&prefix);
        let block_path = block_path_for_prefix(&prefix);
        assert!(
            tracker_path.exists(),
            "tracker file should be created at {}",
            tracker_path.display()
        );
        assert!(
            block_path.exists(),
            "block file should be created at {}",
            block_path.display()
        );

        // The blocks table lives in the block DB only — verify the two
        // files have the schemas we expect by opening each independently.
        let tracker_conn = Connection::open(&tracker_path).unwrap();
        let tracker_has_blocks: bool = tracker_conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='blocks')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !tracker_has_blocks,
            "tracker DB must not contain the `blocks` table (it lives in the block DB)"
        );
        let tracker_has_accountbase: bool = tracker_conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='accountbase')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            tracker_has_accountbase,
            "tracker DB must contain accountbase"
        );

        let block_conn = Connection::open(&block_path).unwrap();
        let block_has_blocks: bool = block_conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='blocks')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(block_has_blocks, "block DB must contain the `blocks` table");
        let block_has_accountbase: bool = block_conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='accountbase')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !block_has_accountbase,
            "block DB must not contain accountbase (it lives in the tracker DB)"
        );
    }

    #[test]
    fn tracker_schema_declares_go_catchpoint_tables() {
        // G3 — verify the three tracker tables that go-algorand's
        // `accountsSchema` / first-stage / unfinished-catchpoints DDL
        // declares are all present after a fresh open. They are empty in
        // the reader path, but their existence is a prerequisite for Go
        // re-opening a Rust-initialized DB and for Rust reading a
        // Go-initialized DB without hitting a "no such table" on
        // catchpoint-related queries.
        //
        // Go reference:
        //   ../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:60-65
        //     (storedcatchpoints)
        //   ../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:143-146
        //     (catchpointfirststageinfo)
        //   ../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:148-151
        //     (unfinishedcatchpoints)
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");
        let _ = SqliteLedger::open_with_prefix(&prefix).expect("open ledger");

        let tracker_conn = Connection::open(tracker_path_for_prefix(&prefix)).unwrap();
        for table in [
            "storedcatchpoints",
            "catchpointfirststageinfo",
            "unfinishedcatchpoints",
        ] {
            let exists: bool = tracker_conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "tracker DB must contain table `{table}` (G3)");
        }

        // Smoke check: writing a row to each table with Go's column
        // shapes succeeds. This guards against type/NOT-NULL drift.
        tracker_conn
            .execute(
                "INSERT INTO storedcatchpoints (round, filename, catchpoint, filesize, pinned) \
                 VALUES (1, 'cp.tar', 'abc', 100, 0)",
                [],
            )
            .expect("insert storedcatchpoints");
        tracker_conn
            .execute(
                "INSERT INTO catchpointfirststageinfo (round, info) VALUES (1, x'00')",
                [],
            )
            .expect("insert catchpointfirststageinfo");
        tracker_conn
            .execute(
                "INSERT INTO unfinishedcatchpoints (round, blockhash) VALUES (1, x'00')",
                [],
            )
            .expect("insert unfinishedcatchpoints");
    }

    #[test]
    fn resources_ctype_rejects_null_on_fresh_db() {
        // G5 — fresh DBs declare `resources.ctype` as `NOT NULL DEFAULT -1`
        // (matches Go's post-migration shape:
        // `../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:970`).
        // Inserting an explicit NULL must fail with a constraint error.
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");
        let _ = SqliteLedger::open_with_prefix(&prefix).expect("open ledger");

        let conn = Connection::open(tracker_path_for_prefix(&prefix)).unwrap();

        // Confirm pragma reports NOT NULL.
        let notnull: i64 = conn
            .query_row(
                "SELECT \"notnull\" FROM pragma_table_info('resources') WHERE name='ctype'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(notnull, 1, "resources.ctype must be NOT NULL (G5)");

        // Confirm default is -1.
        let dflt: String = conn
            .query_row(
                "SELECT dflt_value FROM pragma_table_info('resources') WHERE name='ctype'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(dflt, "-1", "resources.ctype default must be -1 (G5)");

        // Explicit NULL insert is rejected.
        let err = conn
            .execute(
                "INSERT INTO resources (addrid, aidx, data, ctype) VALUES (1, 2, x'00', NULL)",
                [],
            )
            .expect_err("NULL ctype insert must fail");
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("not null") || msg.to_lowercase().contains("constraint"),
            "expected a NOT NULL constraint error, got: {msg}"
        );

        // Inserting without specifying ctype uses the default (-1).
        conn.execute(
            "INSERT INTO resources (addrid, aidx, data) VALUES (1, 2, x'00')",
            [],
        )
        .unwrap();
        let ctype: i64 = conn
            .query_row(
                "SELECT ctype FROM resources WHERE addrid=1 AND aidx=2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ctype, -1);
    }

    #[test]
    fn resources_ctype_migration_upgrades_old_shape_db() {
        // G5 — a tracker DB created with the old Rust shape
        // (`ctype INTEGER` nullable) is rebuilt on next open to
        // `ctype INTEGER NOT NULL DEFAULT -1`, and any pre-existing
        // NULL ctype values are backfilled to -1.
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");
        let tracker_path = tracker_path_for_prefix(&prefix);
        let block_path = block_path_for_prefix(&prefix);

        // Seed a tracker DB with the old shape and a row with NULL ctype.
        {
            let conn = Connection::open(&tracker_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE resources (
                    addrid  INTEGER NOT NULL,
                    aidx    INTEGER NOT NULL,
                    data    BLOB    NOT NULL,
                    ctype   INTEGER,
                    PRIMARY KEY (addrid, aidx)
                ) WITHOUT ROWID;",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO resources (addrid, aidx, data, ctype) VALUES (1, 2, x'aa', NULL)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO resources (addrid, aidx, data, ctype) VALUES (3, 4, x'bb', 0)",
                [],
            )
            .unwrap();
        }
        // Create the block file the open path expects.
        Connection::open(&block_path).unwrap();

        // Open via the production path — migration runs as part of init.
        let _ = SqliteLedger::open_with_prefix(&prefix).expect("open with migration");

        let conn = Connection::open(&tracker_path).unwrap();

        // Schema now reports NOT NULL.
        let notnull: i64 = conn
            .query_row(
                "SELECT \"notnull\" FROM pragma_table_info('resources') WHERE name='ctype'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(notnull, 1, "ctype must be NOT NULL after migration");

        // The previously-NULL row is now -1; the other row is untouched.
        let row1: i64 = conn
            .query_row(
                "SELECT ctype FROM resources WHERE addrid=1 AND aidx=2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(row1, -1, "NULL ctype must be backfilled to -1");
        let row2: i64 = conn
            .query_row(
                "SELECT ctype FROM resources WHERE addrid=3 AND aidx=4",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(row2, 0, "non-NULL ctype must be preserved");

        // Idempotent: re-opening doesn't rebuild again or break anything.
        drop(conn);
        let _ = SqliteLedger::open_with_prefix(&prefix).expect("reopen is idempotent");
        let conn = Connection::open(&tracker_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM resources", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn resources_ctype_migration_refuses_pre_ctype_go_db() {
        // G5 — a tracker DB whose `resources` table predates Go's own
        // ctype migration has no `ctype` column at all. Opening such a
        // DB must refuse with a clear error rather than silently adding
        // the column without backfill: Go's `accountsAddCreatableTypeColumn`
        // populates ctype per row from `assetcreators` + decoded resource
        // blobs, and skipping that step would make existing asset/app
        // rows (which downstream queries filter on `ctype IN (0,1)`)
        // invisible at runtime. The deeper port lives in TASK-109 / G12,
        // which is explicitly out of scope for TASK-104.
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");
        let tracker_path = tracker_path_for_prefix(&prefix);
        let block_path = block_path_for_prefix(&prefix);

        {
            let conn = Connection::open(&tracker_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE resources (
                    addrid  INTEGER NOT NULL,
                    aidx    INTEGER NOT NULL,
                    data    BLOB    NOT NULL,
                    PRIMARY KEY (addrid, aidx)
                ) WITHOUT ROWID;",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO resources (addrid, aidx, data) VALUES (1, 2, x'cc')",
                [],
            )
            .unwrap();
        }
        Connection::open(&block_path).unwrap();

        let err = match SqliteLedger::open_with_prefix(&prefix) {
            Ok(_) => panic!("opening a pre-ctype DB must fail"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("missing the `ctype` column"),
            "error should mention missing ctype column; got: {msg}"
        );
        assert!(
            msg.contains("TASK-109") || msg.contains("G12"),
            "error should point to the G12 follow-up; got: {msg}"
        );
    }

    #[test]
    fn kvstore_null_values_are_normalized_to_empty_blob_on_open() {
        // G13 — Go runs `UPDATE kvstore SET value = '' WHERE value IS NULL`
        // on init (`../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go:358-362`).
        // A Go-written DB can therefore contain box rows whose `value` is
        // an intentional empty BLOB, but pre-G13 it stored those as NULL.
        // Verify the migration runs at `open` time and is idempotent.
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");
        let tracker_path = tracker_path_for_prefix(&prefix);
        let block_path = block_path_for_prefix(&prefix);

        // Seed a Go-style kvstore with a NULL row and a non-NULL row.
        {
            let conn = Connection::open(&tracker_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE kvstore (key BLOB PRIMARY KEY, value BLOB);
                 INSERT INTO kvstore (key, value) VALUES (x'01', NULL);
                 INSERT INTO kvstore (key, value) VALUES (x'02', x'aabb');",
            )
            .unwrap();
        }
        Connection::open(&block_path).unwrap();

        let _ = SqliteLedger::open_with_prefix(&prefix).expect("open runs migration");

        let conn = Connection::open(&tracker_path).unwrap();
        // NULL row is now empty.
        let v1: Vec<u8> = conn
            .query_row("SELECT value FROM kvstore WHERE key = x'01'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(v1, Vec::<u8>::new(), "NULL kvstore value must become empty");
        // Non-NULL row is untouched.
        let v2: Vec<u8> = conn
            .query_row("SELECT value FROM kvstore WHERE key = x'02'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(v2, vec![0xaa, 0xbb], "non-NULL value must be preserved");
        // Marker is persisted so subsequent opens skip the table scan.
        let marker: i64 = conn
            .query_row(
                "SELECT intval FROM catchpointstate WHERE id = 'algod_rust_kvstore_null_norm_v1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(marker, 1);

        // After the marker is set, a NULL written post-migration is NOT
        // auto-rewritten on reopen — confirming the marker actually
        // gates the UPDATE rather than the UPDATE running unconditionally.
        conn.execute("INSERT INTO kvstore (key, value) VALUES (x'03', NULL)", [])
            .unwrap();
        drop(conn);
        let _ = SqliteLedger::open_with_prefix(&prefix).expect("reopen is idempotent");
        let conn = Connection::open(&tracker_path).unwrap();
        let v3: Option<Vec<u8>> = conn
            .query_row("SELECT value FROM kvstore WHERE key = x'03'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            v3, None,
            "marker must prevent re-scan; post-migration NULLs stay NULL"
        );
    }

    #[test]
    fn chain_metadata_derives_from_latest_block_header_when_no_algod_rust_meta() {
        // G6 part 1 — a Go-generated DB has no `algod_rust_meta` table
        // populated. Verify the runtime falls back to deriving chain
        // metadata from the latest block header instead. We exercise
        // the helper directly (so the test doesn't depend on the
        // genesis-init machinery) plus the production `open` path with
        // an empty meta table.
        use algo_types::BlockHeader;

        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");

        // Synthesize a real msgpack-encoded BlockHeader and write it
        // through the production put_block path. This is the same
        // shape Go's `daemon/algod/api/server/v2` returns when callers
        // ask for `/v2/blocks/{r}`'s header.
        let mut hdr = BlockHeader {
            round: Round(7),
            ..Default::default()
        };
        hdr.genesis_id = "test-net-v1".to_string();
        hdr.genesis_hash = [0xab; 32];
        hdr.current_protocol = "vTest".to_string();
        hdr.fee_sink = Address([0x11; 32]);
        hdr.rewards_pool = Address([0x22; 32]);
        hdr.rewards_level = 100;
        hdr.rewards_rate = 200;
        hdr.rewards_residue = 300;
        hdr.rewards_recalculation_round = Round(400);
        hdr.txn_counter = 12345;
        let hdrdata = rmp_serde::to_vec_named(&hdr).unwrap();

        {
            let mut ledger = SqliteLedger::open_with_prefix(&prefix).expect("open");
            ledger.put_block(7, "vTest", &hdrdata, b"blk").unwrap();
            // Tell the tracker its committed round is 7 (matches Go's
            // `accountsRound`). Derivation deliberately reads from
            // here rather than `MAX(rnd) FROM blockdb.blocks` so
            // archive-ahead-of-tracker DBs don't advance state past
            // the committed round.
            ledger
                .conn
                .execute(
                    "INSERT OR REPLACE INTO acctrounds (id, rnd) VALUES ('acctbase', 7)",
                    [],
                )
                .unwrap();
            // No algod_rust_meta to wipe — G6 part 3 dropped it.
        }

        // Re-open: the runtime must derive from the header now.
        let ledger = SqliteLedger::open_with_prefix(&prefix).expect("reopen");
        assert_eq!(ledger.current_round, Round(7));
        assert_eq!(ledger.genesis_id, "test-net-v1");
        assert_eq!(ledger.genesis_hash, [0xab; 32]);
        assert_eq!(ledger.protocol, "vTest");
        assert_eq!(ledger.fee_sink, Address([0x11; 32]));
        assert_eq!(ledger.rewards_pool, Address([0x22; 32]));
        assert_eq!(ledger.rewards_level, 100);
        assert_eq!(ledger.rewards_rate, 200);
        assert_eq!(ledger.rewards_residue, 300);
        assert_eq!(ledger.rewards_recalculation_round, 400);
        assert_eq!(ledger.txn_counter, 12345);

        // Direct helper coverage: invoke the derivation against the
        // same connection and confirm the shape matches.
        let derived = derive_chain_meta_from_latest_block(&ledger.conn)
            .unwrap()
            .expect("derivation must succeed with a real header");
        assert_eq!(derived.current_round, Round(7));
        assert_eq!(derived.genesis_id, "test-net-v1");
    }

    #[test]
    fn chain_metadata_derivation_uses_tracker_round_not_blockdb_max() {
        // G6 part 1 regression — the block archive is allowed to be
        // ahead of the tracker (sync writes blocks before applying).
        // Derivation must NOT pick up the future header from
        // `MAX(rnd) FROM blockdb.blocks`; that would silently advance
        // `current_round`, rewards state, and `txn_counter` past the
        // committed accountbase round and cause `next_round()` to skip
        // the next real block.
        use algo_types::BlockHeader;

        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");

        // Round 3: the committed tracker round.
        let mut committed = BlockHeader {
            round: Round(3),
            ..Default::default()
        };
        committed.current_protocol = "vCommitted".to_string();
        committed.txn_counter = 33;
        let committed_bytes = rmp_serde::to_vec_named(&committed).unwrap();

        // Round 5: a future block already in the archive but not yet
        // applied by the tracker.
        let mut future = BlockHeader {
            round: Round(5),
            ..Default::default()
        };
        future.current_protocol = "vFuture".to_string();
        future.txn_counter = 999;
        let future_bytes = rmp_serde::to_vec_named(&future).unwrap();

        {
            let mut ledger = SqliteLedger::open_with_prefix(&prefix).expect("open");
            ledger
                .put_block(3, "vCommitted", &committed_bytes, b"b3")
                .unwrap();
            ledger
                .put_block(5, "vFuture", &future_bytes, b"b5")
                .unwrap();
            ledger
                .conn
                .execute(
                    "INSERT OR REPLACE INTO acctrounds (id, rnd) VALUES ('acctbase', 3)",
                    [],
                )
                .unwrap();
            // algod_rust_meta no longer exists (G6 part 3).
        }

        let ledger = SqliteLedger::open_with_prefix(&prefix).expect("reopen");
        assert_eq!(ledger.current_round, Round(3), "must use tracker round");
        assert_eq!(ledger.protocol, "vCommitted");
        assert_eq!(ledger.txn_counter, 33);
    }

    #[test]
    fn last_committed_round_reads_acctrounds_when_meta_is_empty() {
        // G6 part 1 regression — `last_committed_round` previously
        // read only `algod_rust_meta.current_round`. On a Go-generated
        // DB (empty meta, populated `acctrounds`) it returned None and
        // `reconcile_cross_file` would mis-classify the DB as Empty.
        // Verify the new max(acctrounds, meta) path returns the
        // tracker round.
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");
        {
            let mut ledger = SqliteLedger::open_with_prefix(&prefix).expect("open");
            ledger.put_block(42, "v41", b"hdr", b"blk").unwrap();
            ledger
                .conn
                .execute(
                    "INSERT OR REPLACE INTO acctrounds (id, rnd) VALUES ('acctbase', 42)",
                    [],
                )
                .unwrap();
            // algod_rust_meta no longer exists (G6 part 3).
        }
        let ledger = SqliteLedger::open_with_prefix(&prefix).expect("reopen");
        assert_eq!(ledger.last_committed_round().unwrap(), Some(42));
    }

    #[test]
    fn chain_metadata_does_not_regress_when_rust_apply_advances_past_acctrounds() {
        // G6 part 1 regression — Rust's `commit_block` writes
        // `current_round` to `algod_rust_meta` but does NOT update
        // `acctrounds.acctbase` (that's a writer-side change deferred
        // to a later G6 task). After a catchpoint import (which seeds
        // `acctrounds` at the catchpoint round) followed by applying
        // additional blocks, reopen would regress `current_round`
        // back to the catchpoint round if derivation trusted
        // `acctrounds` alone. We instead take the max of acctrounds
        // and the meta cache.
        use algo_types::BlockHeader;

        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");

        // Catchpoint round 100; Rust then applies blocks up to 103.
        let mut hdr100 = BlockHeader {
            round: Round(100),
            ..Default::default()
        };
        hdr100.current_protocol = "vCatchpoint".to_string();
        hdr100.txn_counter = 100;
        let hdr100_bytes = rmp_serde::to_vec_named(&hdr100).unwrap();
        let mut hdr103 = BlockHeader {
            round: Round(103),
            ..Default::default()
        };
        hdr103.current_protocol = "vApplied".to_string();
        hdr103.txn_counter = 103;
        let hdr103_bytes = rmp_serde::to_vec_named(&hdr103).unwrap();

        {
            let mut ledger = SqliteLedger::open_with_prefix(&prefix).expect("open");
            ledger
                .put_block(100, "vCatchpoint", &hdr100_bytes, b"b100")
                .unwrap();
            ledger
                .put_block(103, "vApplied", &hdr103_bytes, b"b103")
                .unwrap();
            // Post-G6-part-3 invariant: apply mirrors current_round
            // into acctrounds.acctbase on every commit_block, so by
            // the time we reopen the row already points at 103.
            ledger
                .conn
                .execute(
                    "INSERT OR REPLACE INTO acctrounds (id, rnd) VALUES ('acctbase', 103)",
                    [],
                )
                .unwrap();
        }

        let ledger = SqliteLedger::open_with_prefix(&prefix).expect("reopen");
        assert_eq!(ledger.current_round, Round(103));
        assert_eq!(ledger.protocol, "vApplied");
        assert_eq!(ledger.txn_counter, 103);
    }

    #[test]
    fn algod_rust_meta_retire_migrates_round_into_acctrounds_and_drops_table() {
        // G6 part 3 — a DB initialized by a pre-G6-part-3 binary has
        // `algod_rust_meta.current_round` populated but no
        // `acctrounds.acctbase` (Rust's apply path never mirrored the
        // round across). Reopen must:
        //   1. Copy `current_round` from the legacy table into
        //      `acctrounds.acctbase` so derivation has a tracker round.
        //   2. Drop the legacy table so subsequent reopens never see it.
        // Idempotent: re-opening after the migration is a no-op.
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");
        let tracker_path = tracker_path_for_prefix(&prefix);
        let block_path = block_path_for_prefix(&prefix);

        // Synthesize a real header at round 57 so derivation succeeds
        // once the migration has populated acctrounds.
        let mut hdr = algo_types::BlockHeader {
            round: Round(57),
            ..Default::default()
        };
        hdr.current_protocol = "vLegacy".to_string();
        hdr.txn_counter = 57_000;
        let hdrdata = rmp_serde::to_vec_named(&hdr).unwrap();

        {
            let mut ledger = SqliteLedger::open_with_prefix(&prefix).expect("open");
            ledger.put_block(57, "vLegacy", &hdrdata, b"blk").unwrap();
            // Seed the legacy table as a pre-G6-part-3 binary would.
            ledger
                .conn
                .execute_batch(
                    "CREATE TABLE algod_rust_meta (
                         key   TEXT PRIMARY KEY,
                         value BLOB
                     );",
                )
                .unwrap();
            ledger
                .conn
                .execute(
                    "INSERT INTO algod_rust_meta (key, value) VALUES ('current_round', ?1)",
                    params![57u64.to_le_bytes().to_vec()],
                )
                .unwrap();
            // Explicitly clear acctrounds — the migration must repopulate it.
            ledger
                .conn
                .execute("DELETE FROM acctrounds WHERE id = 'acctbase'", [])
                .unwrap();
        }

        let ledger = SqliteLedger::open_with_prefix(&prefix).expect("reopen runs migration");
        assert_eq!(ledger.current_round, Round(57));
        assert_eq!(ledger.protocol, "vLegacy");
        assert_eq!(ledger.txn_counter, 57_000);

        let conn = Connection::open(&tracker_path).unwrap();
        // Legacy table is gone.
        let table_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='algod_rust_meta')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!table_exists, "algod_rust_meta must be dropped");
        // Tracker round was migrated.
        let acctbase: i64 = conn
            .query_row(
                "SELECT rnd FROM acctrounds WHERE id = 'acctbase'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(acctbase, 57);

        // Idempotent: reopen again still works.
        drop(conn);
        let _ = SqliteLedger::open_with_prefix(&prefix).expect("idempotent reopen");
        let _ = block_path;
    }

    #[test]
    fn pre_v3_tracker_db_is_refused_with_structured_error() {
        // G12 (TASK-109) — a tracker DB with the pre-v3 shape
        // (`accountbase` table present in its legacy
        // `address PRIMARY KEY, data BLOB` shape, no `resources`)
        // must be refused at open time. The Rust port of
        // `performResourceTableMigration` is a future task; until
        // then, silently coexisting an empty `resources` table with
        // the legacy single-blob `accountbase` would strand the
        // embedded asset/app data and corrupt downstream lookups.
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");
        let tracker_path = tracker_path_for_prefix(&prefix);
        let block_path = block_path_for_prefix(&prefix);

        // Seed the pre-v3 tracker shape directly — only the
        // table-name signals the refusal check uses, not the row
        // bytes. Note the legacy two-column shape (no `addrid`, no
        // `normalizedonlinebalance`) — what Go's
        // `performResourceTableMigration` migrates AWAY from.
        {
            let conn = Connection::open(&tracker_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE accountbase (
                     address BLOB PRIMARY KEY,
                     data    BLOB
                 );",
            )
            .unwrap();
        }
        // The block file must exist or the ATTACH step fails for a
        // reason unrelated to G12.
        Connection::open(&block_path).unwrap();

        let err = match SqliteLedger::open_with_prefix(&prefix) {
            Ok(_) => panic!("opening a pre-v3 tracker DB must fail"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("pre-v3 tracker DB detected"),
            "error must name the detection signal; got: {msg}"
        );
        assert!(
            msg.contains("TASK-109") || msg.contains("G12"),
            "error must point at the follow-up task; got: {msg}"
        );

        // The legacy table is left in place so operators can
        // downgrade or feed the DB through a pre-port Go binary.
        let conn = Connection::open(&tracker_path).unwrap();
        let still_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='accountbase')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            still_exists,
            "legacy accountbase must be preserved when open is refused"
        );
        // And `resources` must NOT have been silently created by
        // `SCHEMA_TRACKER_SQL` after the refusal — refusal MUST
        // happen before schema creation.
        let resources_created: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='resources')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !resources_created,
            "schema creation must not run after refusal; an empty `resources` \
             coexisting with the legacy accountbase is the corruption we're \
             preventing"
        );
    }

    #[test]
    fn pre_v3_check_does_not_block_fresh_or_v3_dbs() {
        // G12 sanity — a fresh DB has neither `accountbase` nor
        // `resources` yet; the check must be a no-op so schema
        // creation runs and both tables come into existence. A
        // post-migration v3+ DB has both tables; the check must also
        // accept that.
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");

        // Fresh open creates both tables.
        {
            let ledger = SqliteLedger::open_with_prefix(&prefix).expect("fresh open");
            for t in ["accountbase", "resources"] {
                let present: bool = ledger
                    .conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                        [t],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert!(present, "{t} must exist after fresh open");
            }
        }

        // Reopen the same DB — both tables exist now, refusal must
        // not trigger.
        let _ = SqliteLedger::open_with_prefix(&prefix).expect("v3+ reopen");
    }

    #[test]
    fn flush_chain_state_synthesizes_header_for_genesis_round_zero() {
        // G6 part 3 regression — genesis seeding (relay first-boot)
        // calls `begin_block` → populate_store → `commit_block` at
        // round 0 without ever calling `put_block`. Without a
        // recoverable header, the chain meta (genesis_id, protocol,
        // fee_sink, rewards_pool) would be lost on next restart.
        // `flush_chain_state` must synthesize a round-0 header from
        // the in-memory state.
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");
        {
            let mut ledger = SqliteLedger::open_with_prefix(&prefix).expect("open");
            ledger.set_genesis_id("test-genesis".to_string());
            ledger.set_genesis_hash([0x77; 32]);
            ledger.set_protocol("vGenesis".to_string());
            ledger.set_fee_sink(Address([0x11; 32]));
            ledger.set_rewards_pool(Address([0x22; 32]));
            ledger.set_current_round(Round(0));
            // Mirror the genesis-seed flow: begin/commit without put_block.
            ledger.begin_block().unwrap();
            ledger.commit_block().unwrap();
        }

        let ledger = SqliteLedger::open_with_prefix(&prefix).expect("reopen");
        assert_eq!(ledger.current_round, Round(0));
        assert_eq!(ledger.genesis_id, "test-genesis");
        assert_eq!(ledger.genesis_hash, [0x77; 32]);
        assert_eq!(ledger.protocol, "vGenesis");
        assert_eq!(ledger.fee_sink, Address([0x11; 32]));
        assert_eq!(ledger.rewards_pool, Address([0x22; 32]));
    }

    #[test]
    fn algod_rust_meta_retire_allows_drop_when_legacy_round_is_zero_genesis() {
        // G6 part 3 regression — a genesis-initialized pre-G6-part-3
        // DB writes `current_round = 0` to the legacy cache before
        // any block lands in `blockdb.blocks`. The retirement check
        // must NOT treat that as a "committed round to protect"
        // (there is no committed state) and must allow the drop.
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");

        {
            let ledger = SqliteLedger::open_with_prefix(&prefix).expect("open");
            ledger
                .conn
                .execute_batch(
                    "CREATE TABLE algod_rust_meta (
                         key   TEXT PRIMARY KEY,
                         value BLOB
                     );",
                )
                .unwrap();
            // Genesis init wrote current_round = 0 (LE bytes); other
            // genesis fields would normally also be present but the
            // round check is what gates the refusal.
            ledger
                .conn
                .execute(
                    "INSERT INTO algod_rust_meta (key, value) VALUES ('current_round', ?1)",
                    params![0u64.to_le_bytes().to_vec()],
                )
                .unwrap();
        }

        // Reopen must succeed (not refuse) and the legacy table must
        // be dropped — there's nothing committed to recover.
        let _ = SqliteLedger::open_with_prefix(&prefix).expect("reopen succeeds on genesis-only");
        let conn = Connection::open(tracker_path_for_prefix(&prefix)).unwrap();
        let still_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='algod_rust_meta')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!still_exists, "genesis-only legacy meta must be dropped");
    }

    #[test]
    fn reconcile_cross_file_treats_synthesized_catchpoint_row_as_catchpoint_only() {
        // G6 part 3 regression — `initialize_meta_from_catchpoint`
        // seeds `blockdb.blocks` with a header-only row (empty
        // `blkdata`) so `derive_chain_meta_from_latest_block` can
        // recover chain meta before lookback download completes. The
        // safety gate `reconcile_cross_file` must NOT count that
        // synthesized row as a real block — otherwise relay / follow
        // / participate paths would skip lookback coverage checks on
        // a ledger that has no archived history.
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");
        let ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();

        // Simulate the post-cutover state: acctrounds + synthesized
        // header at round 1000, no payload.
        let mut hdr = algo_types::BlockHeader {
            round: Round(1000),
            ..Default::default()
        };
        hdr.current_protocol = "vSynth".to_string();
        let hdrdata = rmp_serde::to_vec_named(&hdr).unwrap();
        ledger
            .conn
            .execute(
                "INSERT INTO blockdb.blocks (rnd, proto, hdrdata, blkdata) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![1000i64, "vSynth", hdrdata, &[] as &[u8]],
            )
            .unwrap();
        ledger
            .conn
            .execute(
                "INSERT OR REPLACE INTO acctrounds (id, rnd) VALUES ('acctbase', 1000)",
                [],
            )
            .unwrap();

        assert_eq!(
            ledger.reconcile_cross_file().unwrap(),
            CrossFileState::CatchpointOnly {
                tracker_round: 1000
            },
            "synthesized header (empty blkdata) must not count as a real block"
        );
        assert_eq!(
            ledger.max_block_round_in_blockdb().unwrap(),
            None,
            "max_block_round must ignore synthesized rows"
        );

        // Once lookback writes a real payload, the state flips.
        ledger
            .conn
            .execute(
                "UPDATE blockdb.blocks SET blkdata = ?1 WHERE rnd = 1000",
                params![b"realblock".as_ref()],
            )
            .unwrap();
        assert_eq!(
            ledger.reconcile_cross_file().unwrap(),
            CrossFileState::Consistent { round: 1000 }
        );
        assert_eq!(ledger.max_block_round_in_blockdb().unwrap(), Some(1000));
    }

    #[test]
    fn algod_rust_meta_retire_refuses_when_block_header_is_missing() {
        // G6 part 3 regression — if the legacy `algod_rust_meta` had a
        // committed round but `blockdb.blocks` doesn't have the
        // corresponding header (e.g. a previous put_block was lost as
        // a warning rather than committed), dropping the legacy
        // cache would regress startup to zero-defaults. The migration
        // must refuse instead.
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");

        {
            let ledger = SqliteLedger::open_with_prefix(&prefix).expect("open");
            ledger
                .conn
                .execute_batch(
                    "CREATE TABLE algod_rust_meta (
                         key   TEXT PRIMARY KEY,
                         value BLOB
                     );",
                )
                .unwrap();
            // current_round=99 in the legacy cache, but no block at 99.
            ledger
                .conn
                .execute(
                    "INSERT INTO algod_rust_meta (key, value) VALUES ('current_round', ?1)",
                    params![99u64.to_le_bytes().to_vec()],
                )
                .unwrap();
        }

        let err = match SqliteLedger::open_with_prefix(&prefix) {
            Ok(_) => panic!("reopen must refuse to drop the cache without a header"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("algod_rust_meta retirement aborted"),
            "expected refusal message; got: {msg}"
        );

        // Legacy table is still present so the operator can
        // downgrade or fix the gap.
        let conn = Connection::open(tracker_path_for_prefix(&prefix)).unwrap();
        let still_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='algod_rust_meta')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            still_exists,
            "algod_rust_meta must be preserved when migration refuses"
        );
    }

    #[test]
    fn kvstore_normalization_coerces_go_text_empty_to_blob() {
        // G13 regression — a DB previously migrated by Go has
        // `kvstore.value = ''` for old NULLs, which SQLite stores as
        // TEXT (not BLOB). Rust's `row.get::<_, Vec<u8>>` rejects TEXT,
        // so the Rust open must coerce those values to BLOB empty
        // before stamping the migration marker (otherwise the marker
        // would permanently skip the repair).
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");
        let tracker_path = tracker_path_for_prefix(&prefix);
        let block_path = block_path_for_prefix(&prefix);

        {
            let conn = Connection::open(&tracker_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE kvstore (key BLOB PRIMARY KEY, value BLOB);
                 INSERT INTO kvstore (key, value) VALUES (x'01', NULL);
                 INSERT INTO kvstore (key, value) VALUES (x'02', x'aabb');
                 -- Replay Go's `performKVStoreNullBlobConversion`
                 -- exactly, leaving an empty-TEXT value behind.
                 UPDATE kvstore SET value = '' WHERE value IS NULL;",
            )
            .unwrap();
            // Sanity check: the seeded value really is TEXT.
            let stored_type: String = conn
                .query_row(
                    "SELECT typeof(value) FROM kvstore WHERE key = x'01'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(stored_type, "text");
        }
        Connection::open(&block_path).unwrap();

        let _ = SqliteLedger::open_with_prefix(&prefix).expect("open runs migration");

        let conn = Connection::open(&tracker_path).unwrap();
        // Empty TEXT was coerced to empty BLOB.
        let stored_type: String = conn
            .query_row(
                "SELECT typeof(value) FROM kvstore WHERE key = x'01'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_type, "blob");
        let v1: Vec<u8> = conn
            .query_row("SELECT value FROM kvstore WHERE key = x'01'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(v1, Vec::<u8>::new());
        // Non-empty values are still untouched.
        let v2: Vec<u8> = conn
            .query_row("SELECT value FROM kvstore WHERE key = x'02'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(v2, vec![0xaa, 0xbb]);
    }

    #[test]
    fn catchpointresources_ctype_matches_live_resources_shape() {
        // G5 — `catchpointresources` is renamed over `resources` by the
        // catchpoint cutover, so its `ctype` declaration must match the
        // live shape. Verified by initializing a connection with the
        // catchpoint-staging DDL (which lives in a separate constant)
        // and checking pragma reports NOT NULL.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(CATCHPOINT_STAGING_TABLES_SQL).unwrap();
        let notnull: i64 = conn
            .query_row(
                "SELECT \"notnull\" FROM pragma_table_info('catchpointresources') WHERE name='ctype'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            notnull, 1,
            "catchpointresources.ctype must be NOT NULL (matches live resources)"
        );
    }

    #[test]
    fn open_path_accepts_legacy_sqlite_suffix_and_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        // Pass a legacy `.sqlite` path; `open` derives the prefix.
        let legacy = dir.path().join("ledger.sqlite");

        {
            let mut ledger = SqliteLedger::open(&legacy).expect("open legacy");
            ledger.put_block(42, "v41", b"hdr", b"blk").unwrap();
            ledger.put_block_cert(42, b"cert").unwrap();
        }

        // Reopen via the bare prefix — block data round-trips.
        let prefix = dir.path().join("ledger");
        let ledger = SqliteLedger::open_with_prefix(&prefix).expect("reopen prefix");

        assert_eq!(
            ledger.get_block_data(42).unwrap().as_deref(),
            Some(b"blk".as_ref())
        );
        assert_eq!(
            ledger.get_block_header_data(42).unwrap().as_deref(),
            Some(b"hdr".as_ref())
        );
        assert_eq!(
            ledger.get_block_cert(42).unwrap().as_deref(),
            Some(b"cert".as_ref())
        );
    }

    #[test]
    fn reconcile_cross_file_distinguishes_empty_consistent_catchpoint_and_block_behind() {
        // Empty DB: both tracker and blockdb are bare. Should report Empty.
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");
        let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
        assert_eq!(
            ledger.reconcile_cross_file().unwrap(),
            CrossFileState::Empty
        );

        // Consistent: tracker advanced to round 5 and blockdb has a row
        // for round 5.
        ledger.put_block(5, "v41", b"hdr", b"blk").unwrap();
        ledger
            .conn
            .execute(
                "INSERT OR REPLACE INTO acctrounds (id, rnd) VALUES ('acctbase', 5)",
                [],
            )
            .unwrap();
        assert_eq!(
            ledger.reconcile_cross_file().unwrap(),
            CrossFileState::Consistent { round: 5 }
        );

        // Split-commit gap: bump tracker to round 7 without adding the
        // matching blockdb row, but leave the round-5 row in place. This
        // is the post-crash shape we must catch.
        ledger
            .conn
            .execute(
                "INSERT OR REPLACE INTO acctrounds (id, rnd) VALUES ('acctbase', 7)",
                [],
            )
            .unwrap();
        assert_eq!(
            ledger.reconcile_cross_file().unwrap(),
            CrossFileState::BlockBehind {
                tracker_round: 7,
                block_max_round: 5,
            }
        );

        // Catchpoint-only: blockdb fully empty but tracker has a round.
        // Legitimate shape right after `catchpoint import`; reported
        // distinctly so callers can opt in (sync proceeds, relay
        // refuses).
        ledger
            .conn
            .execute("DELETE FROM blockdb.blocks", [])
            .unwrap();
        assert_eq!(
            ledger.reconcile_cross_file().unwrap(),
            CrossFileState::CatchpointOnly { tracker_round: 7 }
        );

        // Tracker behind blockdb (block stored before tracker apply
        // commits — transient sync state): still Consistent.
        ledger.put_block(10, "v41", b"hdr", b"blk").unwrap();
        ledger
            .conn
            .execute(
                "INSERT OR REPLACE INTO acctrounds (id, rnd) VALUES ('acctbase', 8)",
                [],
            )
            .unwrap();
        assert_eq!(
            ledger.reconcile_cross_file().unwrap(),
            CrossFileState::Consistent { round: 8 }
        );

        // Tracker-round row present even though it isn't the max
        // (pruning case): Consistent — the hazard is about the exact
        // tracker-round row, not the max.
        ledger.put_block(8, "v41", b"hdr", b"blk").unwrap();
        assert_eq!(
            ledger.reconcile_cross_file().unwrap(),
            CrossFileState::Consistent { round: 8 }
        );
    }

    #[test]
    fn open_split_with_go_style_paths_reads_back_blocks_and_accounts() {
        // Simulates the manual smoke test in the TASK-100 acceptance criteria:
        // a Go-style tracker.sqlite + block.sqlite pair is present in a tmp
        // dir; we point algod-rust at it and verify both schemas are
        // accessible. (A real Go-generated DB carries production data; here
        // we just verify the layout/wiring.)
        let dir = tempfile::tempdir().unwrap();
        let tracker = dir.path().join("ledger.tracker.sqlite");
        let block = dir.path().join("ledger.block.sqlite");

        let mut ledger =
            SqliteLedger::open_split(&tracker, &block, Some(dir.path().join("ledger")))
                .expect("open split");
        ledger.put_block(1, "v41", b"hdr1", b"blk1").unwrap();
        ledger.put_block(2, "v41", b"hdr2", b"blk2").unwrap();

        // latest_round / get_block_data / get_block_header_data all work.
        assert_eq!(
            ledger.get_block_data(1).unwrap().as_deref(),
            Some(b"blk1".as_ref())
        );
        assert_eq!(
            ledger.get_block_header_data(2).unwrap().as_deref(),
            Some(b"hdr2".as_ref())
        );

        // Confirm the two files actually exist where we expect.
        assert!(tracker.exists());
        assert!(block.exists());
    }
}
