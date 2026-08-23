//! In-memory import progress tracking for [`CatchpointImporter`].
//!
//! Progress is carried as a struct field on the importer — it is **not**
//! persisted to disk. If the process dies mid-import the import restarts
//! from scratch on the next run, matching go-algorand's behaviour: Go's
//! catchpoint importer is single-pass within a process and has no
//! cross-process resume table (`../go-algorand/ledger/catchpointtracker.go`
//! @ v4.6.0-stable).
//!
//! Phase B (PLAN-36 / TASK-117) dropped the Rust-only `catchpoint_import_state`
//! SQLite table so that Go can open a tracker DB Rust produced.

/// Catchpoint import progress carried in memory on
/// [`super::importer::CatchpointImporter`].
///
/// Reset on every fresh importer instance — not persisted across process
/// restarts. Useful for diagnostics and for tests that inspect import
/// state without poking at the importer's private fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImportCheckpoint {
    /// Ordinal of the last chunk that was fully committed in this process.
    pub last_chunk_ordinal: u64,
    /// Total number of chunks expected in the catchpoint file.
    pub total_chunks: u64,
    /// The catchpoint label string (e.g. `"47000000#..."`).
    pub catchpoint_label: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty() {
        let cp = ImportCheckpoint::default();
        assert_eq!(cp.last_chunk_ordinal, 0);
        assert_eq!(cp.total_chunks, 0);
        assert!(cp.catchpoint_label.is_empty());
    }

    #[test]
    fn construct_and_compare() {
        let a = ImportCheckpoint {
            last_chunk_ordinal: 3,
            total_chunks: 10,
            catchpoint_label: "47000000#ABCD".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
