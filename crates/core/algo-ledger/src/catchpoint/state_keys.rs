//! Canonical key constants for the `catchpointstate` table.
//!
//! `catchpointstate` is Go's k-v table (id TEXT PRIMARY KEY, intval INTEGER,
//! strval TEXT) used by the tracker to persist catchpoint-related state
//! across restarts. Both Go and Rust read/write this table, so the keys
//! MUST agree byte-for-byte. Go's source of truth lives in
//! `../go-algorand/ledger/store/trackerdb/catchpoint.go`; the constants
//! below mirror that file exactly.
//!
//! G6 part 2 audit (TASK-106): Rust already wrote Go-canonical key names
//! inline at every callsite. This module centralizes them so future
//! contributors can't drift, and the per-constant `// Go: ...` comments
//! make the mapping explicit. The accompanying tests at the bottom of
//! the file pin the literal strings as a regression net.
//!
//! Any Rust-specific key (e.g. the kvstore-NULL-normalization marker
//! from TASK-110) lives outside this module and is namespaced with an
//! `algod_rust_` prefix to make the non-canonical status obvious.

/// `lastCatchpoint` — Go: `trackerdb.CatchpointStateLastCatchpoint`.
pub const LAST_CATCHPOINT: &str = "lastCatchpoint";

/// `writingFirstStageInfo` — Go: `trackerdb.CatchpointStateWritingFirstStageInfo`.
pub const WRITING_FIRST_STAGE_INFO: &str = "writingFirstStageInfo";

/// `writingCatchpoint` — Go: `trackerdb.CatchpointStateWritingCatchpoint`.
pub const WRITING_CATCHPOINT: &str = "writingCatchpoint";

/// `catchpointCatchupState` — Go: `trackerdb.CatchpointStateCatchupState`.
pub const CATCHUP_STATE: &str = "catchpointCatchupState";

/// `catchpointCatchupLabel` — Go: `trackerdb.CatchpointStateCatchupLabel`.
pub const CATCHUP_LABEL: &str = "catchpointCatchupLabel";

/// `catchpointCatchupBlockRound` — Go: `trackerdb.CatchpointStateCatchupBlockRound`.
pub const CATCHUP_BLOCK_ROUND: &str = "catchpointCatchupBlockRound";

/// `catchpointCatchupBalancesRound` — Go: `trackerdb.CatchpointStateCatchupBalancesRound`.
pub const CATCHUP_BALANCES_ROUND: &str = "catchpointCatchupBalancesRound";

/// `catchpointCatchupHashRound` — Go: `trackerdb.CatchpointStateCatchupHashRound`.
pub const CATCHUP_HASH_ROUND: &str = "catchpointCatchupHashRound";

/// `catchpointLookback` — Go: `trackerdb.CatchpointStateCatchpointLookback`.
pub const CATCHPOINT_LOOKBACK: &str = "catchpointLookback";

/// `catchpointCatchupVersion` — Go: `trackerdb.CatchpointStateCatchupVersion`.
pub const CATCHUP_VERSION: &str = "catchpointCatchupVersion";

/// Full set of Go-canonical catchpointstate keys, for use by audit / test
/// code (e.g. asserting a migration touched only canonical keys).
pub const ALL_GO_CANONICAL: &[&str] = &[
    LAST_CATCHPOINT,
    WRITING_FIRST_STAGE_INFO,
    WRITING_CATCHPOINT,
    CATCHUP_STATE,
    CATCHUP_LABEL,
    CATCHUP_BLOCK_ROUND,
    CATCHUP_BALANCES_ROUND,
    CATCHUP_HASH_ROUND,
    CATCHPOINT_LOOKBACK,
    CATCHUP_VERSION,
];

/// G6 part 2 — migrate Rust-only catchpointstate keys to their Go-canonical
/// equivalents at open time. Currently a no-op: the Rust runtime has only
/// ever written Go-canonical keys (`catchpointCatchupLabel`,
/// `catchpointCatchupVersion`, `catchpointCatchupBlockRound`,
/// `catchpointCatchupBalancesRound`, `catchpointCatchupHashRound`) into
/// the table, plus the namespaced `algod_rust_*` markers that are
/// deliberately Rust-private and stay as-is.
///
/// The function exists so a future Rust-private key that needs to be
/// renamed has an obvious place to land — and so the centralized key
/// constants are the only thing callers need to import.
pub fn migrate_legacy_keys(_conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    // Intentionally empty — see doc comment. The function signature
    // matches sibling migration helpers (`migrate_resources_ctype_not_null`,
    // `normalize_kvstore_nulls`) so it can be wired into `init` if a
    // rename ever becomes necessary.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin every constant's literal value. If any of these change,
    /// either Go has changed its constants too (verify
    /// `../go-algorand/ledger/store/trackerdb/catchpoint.go`) or Rust
    /// is silently breaking interop.
    #[test]
    fn constants_match_go_canonical_strings() {
        assert_eq!(LAST_CATCHPOINT, "lastCatchpoint");
        assert_eq!(WRITING_FIRST_STAGE_INFO, "writingFirstStageInfo");
        assert_eq!(WRITING_CATCHPOINT, "writingCatchpoint");
        assert_eq!(CATCHUP_STATE, "catchpointCatchupState");
        assert_eq!(CATCHUP_LABEL, "catchpointCatchupLabel");
        assert_eq!(CATCHUP_BLOCK_ROUND, "catchpointCatchupBlockRound");
        assert_eq!(CATCHUP_BALANCES_ROUND, "catchpointCatchupBalancesRound");
        assert_eq!(CATCHUP_HASH_ROUND, "catchpointCatchupHashRound");
        assert_eq!(CATCHPOINT_LOOKBACK, "catchpointLookback");
        assert_eq!(CATCHUP_VERSION, "catchpointCatchupVersion");
    }

    #[test]
    fn all_go_canonical_is_complete_and_unique() {
        // Sanity: the index list must contain every per-name constant
        // and have no duplicates.
        let names = [
            LAST_CATCHPOINT,
            WRITING_FIRST_STAGE_INFO,
            WRITING_CATCHPOINT,
            CATCHUP_STATE,
            CATCHUP_LABEL,
            CATCHUP_BLOCK_ROUND,
            CATCHUP_BALANCES_ROUND,
            CATCHUP_HASH_ROUND,
            CATCHPOINT_LOOKBACK,
            CATCHUP_VERSION,
        ];
        assert_eq!(names.len(), ALL_GO_CANONICAL.len());
        for n in &names {
            assert!(ALL_GO_CANONICAL.contains(n), "missing: {n}");
        }
        let mut sorted: Vec<&str> = ALL_GO_CANONICAL.to_vec();
        sorted.sort();
        let mut dedup = sorted.clone();
        dedup.dedup();
        assert_eq!(sorted.len(), dedup.len(), "duplicate canonical key");
    }

    #[test]
    fn migrate_legacy_keys_on_empty_db_is_no_op() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE catchpointstate (
                 id TEXT PRIMARY KEY,
                 intval INTEGER,
                 strval TEXT
             );",
        )
        .unwrap();
        // Seed Go-canonical entries; the migration should leave them.
        conn.execute(
            "INSERT INTO catchpointstate (id, strval) VALUES (?1, 'cp#abc')",
            [CATCHUP_LABEL],
        )
        .unwrap();
        migrate_legacy_keys(&conn).unwrap();
        let val: String = conn
            .query_row(
                "SELECT strval FROM catchpointstate WHERE id = ?1",
                [CATCHUP_LABEL],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(val, "cp#abc");
    }
}
