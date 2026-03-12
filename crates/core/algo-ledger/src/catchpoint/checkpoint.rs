//! Checkpoint persistence for resumable catchpoint imports.
//!
//! Stores the last successfully committed chunk ordinal so that a
//! crashed or interrupted import can resume where it left off.

use rusqlite::Connection;

use super::CatchpointError;

/// In-progress import state that is persisted to SQLite for resume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportCheckpoint {
    /// Ordinal of the last chunk that was fully committed.
    pub last_chunk_ordinal: u64,
    /// Total number of chunks expected in the catchpoint file.
    pub total_chunks: u64,
    /// The catchpoint label string (e.g. "47000000#...").
    pub catchpoint_label: String,
}

/// Create the checkpoint table if it does not already exist.
pub fn create_checkpoint_table(conn: &Connection) -> Result<(), CatchpointError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS catchpoint_import_state (
            key   TEXT PRIMARY KEY,
            value TEXT
        );",
    )?;
    Ok(())
}

/// Read the current checkpoint, returning `None` if no checkpoint exists.
pub fn read_checkpoint(conn: &Connection) -> Result<Option<ImportCheckpoint>, CatchpointError> {
    // If the table doesn't exist yet, there's no checkpoint.
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='catchpoint_import_state'",
            [],
            |row| row.get(0),
        )?;
    if !table_exists {
        return Ok(None);
    }

    let ordinal = read_key(conn, "last_chunk_ordinal")?;
    let total = read_key(conn, "total_chunks")?;
    let label = read_key(conn, "catchpoint_label")?;

    match (ordinal, total, label) {
        (Some(ord), Some(tot), Some(lbl)) => {
            let last_chunk_ordinal = ord.parse::<u64>().map_err(|e| {
                CatchpointError::CheckpointError(format!("invalid last_chunk_ordinal value: {e}"))
            })?;
            let total_chunks = tot.parse::<u64>().map_err(|e| {
                CatchpointError::CheckpointError(format!("invalid total_chunks value: {e}"))
            })?;
            Ok(Some(ImportCheckpoint {
                last_chunk_ordinal,
                total_chunks,
                catchpoint_label: lbl,
            }))
        }
        // All three keys must be present for a valid checkpoint.
        _ => Ok(None),
    }
}

/// Update (upsert) the checkpoint after a batch commit.
pub fn update_checkpoint(
    conn: &Connection,
    ordinal: u64,
    total: u64,
    label: &str,
) -> Result<(), CatchpointError> {
    upsert_key(conn, "last_chunk_ordinal", &ordinal.to_string())?;
    upsert_key(conn, "total_chunks", &total.to_string())?;
    upsert_key(conn, "catchpoint_label", label)?;
    Ok(())
}

/// Clear the checkpoint (e.g. after successful cutover or abort).
pub fn clear_checkpoint(conn: &Connection) -> Result<(), CatchpointError> {
    // If the table doesn't exist, nothing to clear.
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='catchpoint_import_state'",
            [],
            |row| row.get(0),
        )?;
    if !table_exists {
        return Ok(None).map(|_: Option<()>| ());
    }
    conn.execute_batch("DELETE FROM catchpoint_import_state;")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Read a single key from the checkpoint table.
fn read_key(conn: &Connection, key: &str) -> Result<Option<String>, CatchpointError> {
    use rusqlite::OptionalExtension;

    let val: Option<String> = conn
        .query_row(
            "SELECT value FROM catchpoint_import_state WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()?;
    Ok(val)
}

/// Insert or replace a single key in the checkpoint table.
fn upsert_key(conn: &Connection, key: &str, value: &str) -> Result<(), CatchpointError> {
    conn.execute(
        "INSERT OR REPLACE INTO catchpoint_import_state (key, value) VALUES (?1, ?2)",
        rusqlite::params![key, value],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_conn() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn read_checkpoint_no_table_returns_none() {
        let conn = mem_conn();
        assert_eq!(read_checkpoint(&conn).unwrap(), None);
    }

    #[test]
    fn read_checkpoint_empty_table_returns_none() {
        let conn = mem_conn();
        create_checkpoint_table(&conn).unwrap();
        assert_eq!(read_checkpoint(&conn).unwrap(), None);
    }

    #[test]
    fn round_trip_checkpoint() {
        let conn = mem_conn();
        create_checkpoint_table(&conn).unwrap();

        update_checkpoint(&conn, 42, 100, "47000000#ABCD").unwrap();

        let cp = read_checkpoint(&conn).unwrap().expect("checkpoint");
        assert_eq!(cp.last_chunk_ordinal, 42);
        assert_eq!(cp.total_chunks, 100);
        assert_eq!(cp.catchpoint_label, "47000000#ABCD");
    }

    #[test]
    fn update_overwrites_previous() {
        let conn = mem_conn();
        create_checkpoint_table(&conn).unwrap();

        update_checkpoint(&conn, 10, 50, "label1").unwrap();
        update_checkpoint(&conn, 20, 50, "label1").unwrap();

        let cp = read_checkpoint(&conn).unwrap().expect("checkpoint");
        assert_eq!(cp.last_chunk_ordinal, 20);
    }

    #[test]
    fn clear_checkpoint_removes_all() {
        let conn = mem_conn();
        create_checkpoint_table(&conn).unwrap();
        update_checkpoint(&conn, 5, 10, "lbl").unwrap();

        clear_checkpoint(&conn).unwrap();
        assert_eq!(read_checkpoint(&conn).unwrap(), None);
    }

    #[test]
    fn clear_checkpoint_no_table_is_ok() {
        let conn = mem_conn();
        // Should not error even without the table.
        clear_checkpoint(&conn).unwrap();
    }
}
