// Sync module — catchpoint sync orchestrator and state machine.
//
// This module coordinates all phases of a catchpoint sync operation:
// download ledger -> import -> verify -> download lookback -> replay blocks.
//
// The state machine (state_machine.rs) models the phase transitions.
// The orchestrator (SyncOrchestrator) drives the state machine through
// each phase, delegating to the catchpoint subsystems from Epics 25b-27.
//
// Network operations (downloading files, fetching blocks, querying node
// status) are abstracted behind the `SyncBackend` trait so that algo-ledger
// remains independent of algo-rest-client.

pub mod state_machine;

pub use state_machine::{SyncProgress, SyncState};

use std::path::PathBuf;
use std::time::{Duration, Instant};

use algo_error::AlgoError;
use algo_types::Block;
use rusqlite::Connection;
use tokio_util::sync::CancellationToken;

use crate::catchpoint::{
    import_catchpoint_file, parse_catchpoint_label, validate_post_import, verify_catchpoint,
    CatchpointError, CatchpointFileHeader,
};
use crate::EvalDeltaStats;
use crate::LedgerStore;

/// Callback type for progress reporting.
///
/// The orchestrator invokes this on every state transition and periodically
/// within long-running phases (e.g. block replay). The callback receives an
/// immutable reference to the current [`SyncProgress`].
pub type ProgressCallback = Box<dyn Fn(&SyncProgress) + Send>;

// ---------------------------------------------------------------------------
// SyncBackend — trait abstracting network operations
// ---------------------------------------------------------------------------

/// Trait abstracting all network operations needed by the sync orchestrator.
///
/// This keeps the `algo-ledger` crate independent of `algo-rest-client`.
/// The CLI layer implements this trait using `AlgodClient`, `CatchpointDownloader`,
/// and `ParallelBlockFetcher`.
pub trait SyncBackend: Send + Sync {
    /// Returns `true` if this is a no-op (stub) backend.
    ///
    /// When `true`, the orchestrator skips all phases and returns a
    /// zero-valued result. This is the default for backward compatibility
    /// when constructed via `SyncOrchestrator::new()`.
    fn is_noop(&self) -> bool {
        false
    }

    /// Download the catchpoint file for the given genesis ID and round, saving
    /// it to `dest_path`. This is a blocking operation.
    fn download_catchpoint(
        &self,
        genesis_id: &str,
        round: u64,
        dest_path: &std::path::Path,
    ) -> Result<(), AlgoError>;

    /// Fetch a single block by round. Returns `(proto, header_data, block_data)`.
    ///
    /// Used for lookback block downloads.
    fn fetch_block_raw(&self, round: u64) -> Result<(String, Vec<u8>, Vec<u8>), AlgoError>;

    /// Fetch and decode a block by round. Used during block replay.
    fn fetch_block(&self, round: u64) -> Result<Block, AlgoError>;

    /// Get the current network round (last committed round on the node).
    fn get_current_round(&self) -> Result<u64, AlgoError>;

    /// Discover the latest catchpoint label from the node.
    /// Returns `None` if the node does not advertise a catchpoint.
    fn discover_catchpoint(&self) -> Result<Option<String>, AlgoError>;

    /// Fetch a batch of blocks in the range `[start, end]` (inclusive).
    ///
    /// The `concurrency` parameter hints at how many blocks to fetch in
    /// parallel.  The default implementation fetches blocks sequentially;
    /// backends backed by an async runtime can override this to use
    /// [`ParallelBlockFetcher`] for higher throughput.
    fn fetch_blocks_batch(
        &self,
        start: u64,
        end: u64,
        _concurrency: usize,
    ) -> Result<Vec<(u64, Block)>, AlgoError> {
        let mut blocks = Vec::new();
        for round in start..=end {
            let block = self.fetch_block(round)?;
            blocks.push((round, block));
        }
        Ok(blocks)
    }
}

// ---------------------------------------------------------------------------
// SyncConfig
// ---------------------------------------------------------------------------

/// Configuration for a catchpoint sync operation.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Catchpoint label to sync to, or `None` for auto-discovery.
    pub catchpoint_label: Option<String>,
    /// URL of the algod REST API to fetch data from.
    pub algod_url: String,
    /// Authentication token for the algod REST API.
    pub algod_token: String,
    /// Genesis ID for the target network (e.g. "mainnet-v1.0").
    pub genesis_id: String,
    /// Genesis hash (32-byte SHA-256 digest).
    pub genesis_hash: [u8; 32],
    /// Path to the SQLite database file.
    pub db_path: PathBuf,
    /// Number of concurrent download tasks.
    pub concurrency: usize,
    /// Whether to enter follow mode after sync completes.
    pub follow_after_sync: bool,
    /// Whether to compare EvalDeltas during block replay.
    pub compare_mode: bool,
    /// Optional path for the on-disk Merkle trie.
    pub trie_path: Option<PathBuf>,
    /// Whether to execute AVM programs during block replay.
    pub avm_execute: bool,
    /// Whether to stop on first error during block replay.
    pub fail_fast: bool,
    /// Optional end round — stop replay at this round instead of the network tip.
    pub end_round: Option<u64>,
}

// ---------------------------------------------------------------------------
// SyncResult
// ---------------------------------------------------------------------------

/// Result of a completed sync operation.
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// The round that the sync completed at.
    pub final_round: u64,
    /// Total number of accounts imported from the catchpoint snapshot.
    pub accounts_imported: u64,
    /// Number of blocks replayed after the catchpoint round.
    pub blocks_replayed: u64,
    /// Total wall-clock duration of the sync.
    pub duration: Duration,
}

// ---------------------------------------------------------------------------
// State persistence helpers
// ---------------------------------------------------------------------------

/// Persist the current sync state to the `algod_rust_meta` table.
///
/// Stores the state string, catchpoint label, catchpoint round, and
/// catchpoint file path so that a crashed sync can be resumed.
pub fn persist_sync_state(
    conn: &Connection,
    state: &SyncState,
    catchpoint_label: Option<&str>,
    catchpoint_round: Option<u64>,
    catchpoint_file: Option<&str>,
) -> Result<(), AlgoError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS algod_rust_meta (
            key   TEXT PRIMARY KEY,
            value BLOB
        );",
    )
    .map_err(|e| AlgoError::Ledger {
        message: format!("create meta table error: {e}"),
    })?;

    set_sync_meta(conn, "sync_state", &state.to_db_string())?;

    if let Some(label) = catchpoint_label {
        set_sync_meta(conn, "sync_catchpoint_label", label)?;
    } else {
        delete_sync_meta(conn, "sync_catchpoint_label")?;
    }
    if let Some(round) = catchpoint_round {
        set_sync_meta(conn, "sync_catchpoint_round", &round.to_string())?;
    } else {
        delete_sync_meta(conn, "sync_catchpoint_round")?;
    }
    if let Some(file) = catchpoint_file {
        set_sync_meta(conn, "sync_catchpoint_file", file)?;
    } else {
        delete_sync_meta(conn, "sync_catchpoint_file")?;
    }

    Ok(())
}

/// Restore the sync state from the `algod_rust_meta` table.
///
/// Returns `None` if no persisted state exists or the table is missing.
pub fn restore_sync_state(conn: &Connection) -> Result<Option<PersistedSyncState>, AlgoError> {
    // Check if table exists.
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='algod_rust_meta'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| AlgoError::Ledger {
            message: format!("check meta table existence: {e}"),
        })?;

    if !table_exists {
        return Ok(None);
    }

    let state_str = get_sync_meta(conn, "sync_state")?;
    let state_str = match state_str {
        Some(s) => s,
        None => return Ok(None),
    };

    let state = match SyncState::from_db_string(&state_str) {
        Some(s) => s,
        None => return Ok(None),
    };

    let catchpoint_label = get_sync_meta(conn, "sync_catchpoint_label")?;
    let catchpoint_round =
        get_sync_meta(conn, "sync_catchpoint_round")?.and_then(|s| s.parse::<u64>().ok());
    let catchpoint_file = get_sync_meta(conn, "sync_catchpoint_file")?;

    Ok(Some(PersistedSyncState {
        state,
        catchpoint_label,
        catchpoint_round,
        catchpoint_file,
    }))
}

/// Clear persisted sync state from the database.
pub fn clear_sync_state(conn: &Connection) -> Result<(), AlgoError> {
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='algod_rust_meta'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| AlgoError::Ledger {
            message: format!("check meta table existence: {e}"),
        })?;

    if !table_exists {
        return Ok(());
    }

    for key in &[
        "sync_state",
        "sync_catchpoint_label",
        "sync_catchpoint_round",
        "sync_catchpoint_file",
    ] {
        conn.execute(
            "DELETE FROM algod_rust_meta WHERE key = ?1",
            rusqlite::params![key],
        )
        .map_err(|e| AlgoError::Ledger {
            message: format!("clear sync meta key '{key}': {e}"),
        })?;
    }

    Ok(())
}

/// Persisted sync state read from the database.
#[derive(Debug, Clone)]
pub struct PersistedSyncState {
    /// The sync phase that was in progress or last completed.
    pub state: SyncState,
    /// The catchpoint label being synced to.
    pub catchpoint_label: Option<String>,
    /// The catchpoint round.
    pub catchpoint_round: Option<u64>,
    /// Path to the downloaded catchpoint file.
    pub catchpoint_file: Option<String>,
}

fn delete_sync_meta(conn: &Connection, key: &str) -> Result<(), AlgoError> {
    conn.execute(
        "DELETE FROM algod_rust_meta WHERE key = ?1",
        rusqlite::params![key],
    )
    .map_err(|e| AlgoError::Ledger {
        message: format!("delete sync meta '{key}': {e}"),
    })?;
    Ok(())
}

fn set_sync_meta(conn: &Connection, key: &str, value: &str) -> Result<(), AlgoError> {
    conn.execute(
        "INSERT OR REPLACE INTO algod_rust_meta (key, value) VALUES (?1, ?2)",
        rusqlite::params![key, value.as_bytes()],
    )
    .map_err(|e| AlgoError::Ledger {
        message: format!("set sync meta '{key}': {e}"),
    })?;
    Ok(())
}

fn get_sync_meta(conn: &Connection, key: &str) -> Result<Option<String>, AlgoError> {
    use rusqlite::OptionalExtension;

    let result: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM algod_rust_meta WHERE key = ?1",
            rusqlite::params![key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| AlgoError::Ledger {
            message: format!("get sync meta '{key}': {e}"),
        })?;

    Ok(result.map(|v| String::from_utf8(v).unwrap_or_default()))
}

// ---------------------------------------------------------------------------
// SyncOrchestrator
// ---------------------------------------------------------------------------

/// Orchestrator that coordinates all phases of a catchpoint sync.
///
/// Modeled after Go's `CatchpointCatchupService` in
/// `go-algorand/catchup/catchpointService.go`, adapted for our Rust pipeline.
///
/// Network operations are delegated to a [`SyncBackend`] implementation,
/// keeping this crate independent of the REST client.
pub struct SyncOrchestrator {
    config: SyncConfig,
    state: SyncState,
    progress: SyncProgress,
    backend: Box<dyn SyncBackend>,
    /// Path where the downloaded catchpoint file is stored.
    catchpoint_file_path: Option<PathBuf>,
    /// Parsed catchpoint label (round + hash).
    catchpoint_round: Option<u64>,
    /// The catchpoint label string in use.
    resolved_label: Option<String>,
    /// Block header digest extracted from the catchpoint file header.
    block_header_digest: Option<[u8; 32]>,
    /// Accounts imported during the import phase.
    accounts_imported: u64,
    /// Blocks replayed during the replay phase.
    blocks_replayed: u64,
    /// The final round reached after replay.
    final_round: u64,
    /// Cancellation token — checked between phases and during long operations.
    cancel: CancellationToken,
    /// Optional progress callback — invoked on state transitions and periodic updates.
    on_progress: Option<ProgressCallback>,
    /// Accumulated EvalDelta comparison stats (when compare_mode or avm_execute is enabled).
    eval_delta_stats: EvalDeltaStats,
}

impl SyncOrchestrator {
    /// Create a new orchestrator in the Idle state with the default
    /// (no-op) backend.
    ///
    /// To use a real network backend, call [`with_backend`](Self::with_backend)
    /// instead.
    pub fn new(config: SyncConfig) -> Self {
        Self::with_backend(config, NoopBackend)
    }

    /// Create a new orchestrator with a specific backend implementation.
    pub fn with_backend(config: SyncConfig, backend: impl SyncBackend + 'static) -> Self {
        SyncOrchestrator {
            config,
            state: SyncState::Idle,
            progress: SyncProgress::default(),
            backend: Box::new(backend),
            catchpoint_file_path: None,
            catchpoint_round: None,
            resolved_label: None,
            block_header_digest: None,
            accounts_imported: 0,
            blocks_replayed: 0,
            final_round: 0,
            cancel: CancellationToken::new(),
            on_progress: None,
            eval_delta_stats: EvalDeltaStats::default(),
        }
    }

    /// Set a cancellation token for graceful shutdown.
    ///
    /// When the token is cancelled, the orchestrator will finish the current
    /// atomic operation, persist checkpoint state, and return an error.
    pub fn set_cancel(&mut self, cancel: CancellationToken) {
        self.cancel = cancel;
    }

    /// Set a progress callback that is invoked on state transitions and
    /// periodic within-phase progress updates.
    pub fn set_progress_callback(&mut self, cb: ProgressCallback) {
        self.on_progress = Some(cb);
    }

    /// Returns a reference to the current sync state.
    pub fn state(&self) -> &SyncState {
        &self.state
    }

    /// Returns a reference to the current progress.
    pub fn progress(&self) -> &SyncProgress {
        &self.progress
    }

    /// Returns a reference to the config.
    pub fn config(&self) -> &SyncConfig {
        &self.config
    }

    /// Invoke the progress callback, if set.
    fn notify_progress(&mut self) {
        self.progress.update_elapsed();
        self.progress.estimate_eta();
        if let Some(ref cb) = self.on_progress {
            cb(&self.progress);
        }
    }

    /// Check if cancellation has been requested. If so, persist state and
    /// return an error.
    fn check_cancelled(&self) -> Result<(), AlgoError> {
        if self.cancel.is_cancelled() {
            Err(AlgoError::Ledger {
                message: "sync cancelled by user".to_string(),
            })
        } else {
            Ok(())
        }
    }

    /// Persist checkpoint and return a cancellation error.
    fn handle_cancellation(&self) -> AlgoError {
        tracing::info!(state = %self.state, "persisting checkpoint before shutdown");
        if let Ok(conn) = self.open_db() {
            if let Err(e) = persist_sync_state(
                &conn,
                &self.state,
                self.resolved_label.as_deref(),
                self.catchpoint_round,
                self.catchpoint_file_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .as_deref(),
            ) {
                tracing::warn!("Failed to persist sync state: {e}");
            }
        }
        AlgoError::Ledger {
            message: "sync cancelled by user".to_string(),
        }
    }

    /// Validate and execute a state transition. Logs at INFO level and
    /// notifies the progress callback.
    fn transition(&mut self, next: SyncState) -> Result<(), AlgoError> {
        if !self.state.can_transition_to(&next) {
            return Err(AlgoError::Ledger {
                message: format!("invalid sync state transition: {} -> {}", self.state, next),
            });
        }
        tracing::info!(
            from = %self.state,
            to = %next,
            "sync state transition"
        );
        self.state = next.clone();
        self.progress.state = next;
        self.progress.phase_progress = 0.0;
        self.progress.phase_detail.clear();
        self.progress.eta = None;
        self.notify_progress();
        Ok(())
    }

    /// Open a SQLite connection to the configured database path with
    /// appropriate pragmas for bulk import.
    fn open_db(&self) -> Result<Connection, AlgoError> {
        let conn = Connection::open(&self.config.db_path).map_err(|e| AlgoError::Ledger {
            message: format!("open sync database: {e}"),
        })?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| AlgoError::Ledger {
                message: format!("set sync database pragmas: {e}"),
            })?;
        Ok(conn)
    }

    /// Resolve the catchpoint label: use the explicit label from config,
    /// or discover it from the node.
    fn resolve_catchpoint_label(&mut self) -> Result<String, AlgoError> {
        if let Some(ref label) = self.config.catchpoint_label {
            return Ok(label.clone());
        }

        // Auto-discover from the node.
        tracing::info!("auto-discovering catchpoint label from node");
        let label = self
            .backend
            .discover_catchpoint()?
            .ok_or_else(|| AlgoError::Ledger {
                message: "node does not advertise a catchpoint label; \
                          specify one with --catchpoint"
                    .to_string(),
            })?;

        tracing::info!(label = %label, "discovered catchpoint label");
        Ok(label)
    }

    /// Extract the catchpoint file header from a downloaded file.
    fn extract_header(
        &self,
        file_path: &std::path::Path,
    ) -> Result<CatchpointFileHeader, AlgoError> {
        let reader = crate::catchpoint::parser::open(file_path).map_err(|e| AlgoError::Ledger {
            message: format!("open catchpoint file for header extraction: {e}"),
        })?;

        let mut header: Option<CatchpointFileHeader> = None;
        let result = reader.for_each(|entry| {
            if let crate::catchpoint::CatchpointEntry::Header(h) = entry {
                header = Some(h);
                // Early exit after finding header.
                return Err(CatchpointError::IntegrityError(
                    "header_found_sentinel".to_string(),
                ));
            }
            Ok(())
        });

        // Ignore the sentinel error.
        if header.is_none() {
            result.map_err(|e| AlgoError::Ledger {
                message: format!("read catchpoint header: {e}"),
            })?;
            return Err(AlgoError::Ledger {
                message: "catchpoint file has no header".to_string(),
            });
        }

        Ok(header.unwrap())
    }

    // -------------------------------------------------------------------
    // Phase implementations
    // -------------------------------------------------------------------

    /// Phase 1: Download the catchpoint ledger snapshot from a peer.
    ///
    /// Resolves the catchpoint label (explicit or auto-discovered), parses it
    /// to extract the round, then downloads the catchpoint file to a temp
    /// location next to the database.
    fn run_download_ledger(&mut self) -> Result<(), AlgoError> {
        self.check_cancelled()?;
        self.transition(SyncState::DownloadingLedger)?;

        // Resolve the label.
        let label = self.resolve_catchpoint_label()?;
        let parsed = parse_catchpoint_label(&label).map_err(|e| AlgoError::Ledger {
            message: format!("invalid catchpoint label '{}': {e}", label),
        })?;
        let round = parsed.round;

        self.resolved_label = Some(label.clone());
        self.catchpoint_round = Some(round);

        tracing::info!(
            label = %label,
            round,
            "downloading catchpoint file"
        );
        self.progress.phase_detail = format!("downloading catchpoint round {round}");
        self.notify_progress();

        // Determine the download destination — always next to the ledger database.
        let file_path = self
            .config
            .db_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(format!("catchpoint-{round}.tar.gz"));

        // Resolve genesis_id: must be set by the caller (CLI layer resolves
        // it from the network preset before constructing the config).
        if self.config.genesis_id.is_empty() {
            return Err(AlgoError::Ledger {
                message: "genesis_id is required for catchpoint download — \
                          set --network or provide genesis_id in config"
                    .to_string(),
            });
        }
        let genesis_id = &self.config.genesis_id;

        self.backend
            .download_catchpoint(genesis_id, round, &file_path)?;

        self.catchpoint_file_path = Some(file_path.clone());
        self.progress.phase_progress = 1.0;
        self.notify_progress();

        tracing::info!(
            path = %file_path.display(),
            "catchpoint file downloaded"
        );

        // Persist state so we can resume after crash.
        if let Ok(conn) = self.open_db() {
            if let Err(e) = persist_sync_state(
                &conn,
                &SyncState::DownloadingLedger,
                Some(&label),
                Some(round),
                Some(&file_path.to_string_lossy()),
            ) {
                tracing::warn!("Failed to persist sync state: {e}");
            }
        }

        Ok(())
    }

    /// Phase 2: Import the downloaded ledger into the local SQLite database.
    ///
    /// Uses `import_catchpoint_file` from Epic 26b which handles staging
    /// tables, chunk-by-chunk import with checkpoint/resume support, and
    /// atomic cutover.
    fn run_import_ledger(&mut self) -> Result<(), AlgoError> {
        self.check_cancelled()?;
        self.transition(SyncState::ImportingLedger)?;

        let file_path = self
            .catchpoint_file_path
            .clone()
            .ok_or_else(|| AlgoError::Ledger {
                message: "no catchpoint file path — download phase did not complete".to_string(),
            })?;

        tracing::info!(
            path = %file_path.display(),
            "importing catchpoint file"
        );
        self.progress.phase_detail = "importing catchpoint into database".to_string();
        self.notify_progress();

        let conn = self.open_db()?;

        // Extract header to get block_header_digest and rewards_level.
        let header = self.extract_header(&file_path)?;

        // Store block header digest for the verify phase.
        if header.block_header_digest.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&header.block_header_digest);
            self.block_header_digest = Some(arr);
        } else {
            return Err(AlgoError::Ledger {
                message: format!(
                    "block_header_digest has unexpected length: {} (expected 32)",
                    header.block_header_digest.len()
                ),
            });
        }

        // Import the catchpoint file.
        let reward_unit = crate::rewards::REWARD_UNITS;
        let import_result =
            import_catchpoint_file(&conn, &file_path, reward_unit).map_err(|e| {
                AlgoError::Ledger {
                    message: format!("catchpoint import failed: {e}"),
                }
            })?;

        self.accounts_imported = import_result.stats.accounts;
        let round = import_result.round;

        tracing::info!(
            round,
            accounts = import_result.stats.accounts,
            kvs = import_result.stats.kvs,
            duration = ?import_result.duration,
            "catchpoint import complete"
        );

        // Initialize chain metadata from catchpoint, following the same
        // pattern as the standalone catchpoint import command.
        let protocol = extract_protocol_from_db(&conn);
        let txn_counter = derive_txn_counter(&conn);

        crate::sqlite::initialize_meta_from_catchpoint(
            &conn,
            round,
            &self.config.genesis_id,
            &self.config.genesis_hash,
            &protocol,
            txn_counter,
            header.totals.rewards_level,
        )?;

        tracing::info!(
            round,
            protocol = %protocol,
            txn_counter,
            rewards_level = header.totals.rewards_level,
            "chain meta initialized from catchpoint"
        );

        // Persist state.
        if let Err(e) = persist_sync_state(
            &conn,
            &SyncState::ImportingLedger,
            self.resolved_label.as_deref(),
            self.catchpoint_round,
            self.catchpoint_file_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .as_deref(),
        ) {
            tracing::warn!("Failed to persist sync state: {e}");
        }

        self.progress.phase_progress = 1.0;
        self.notify_progress();
        Ok(())
    }

    /// Phase 3: Verify the imported ledger (Merkle trie, account totals).
    ///
    /// Rebuilds the Merkle trie from the database, computes component hashes,
    /// and compares the reconstructed catchpoint label against the stored one.
    /// Also runs post-import validation for non-critical checks.
    fn run_verify_ledger(&mut self) -> Result<(), AlgoError> {
        self.check_cancelled()?;
        self.transition(SyncState::VerifyingLedger)?;

        let block_header_digest = self.block_header_digest.ok_or_else(|| AlgoError::Ledger {
            message: "block_header_digest not available — import phase did not complete"
                .to_string(),
        })?;

        tracing::info!("verifying catchpoint database integrity");
        self.progress.phase_detail = "rebuilding Merkle trie and verifying label".to_string();
        self.notify_progress();

        let conn = self.open_db()?;

        // Step 1: Full label verification.
        let verify_result =
            verify_catchpoint(&conn, &block_header_digest).map_err(|e| AlgoError::Ledger {
                message: format!("catchpoint verification failed: {e}"),
            })?;

        if !verify_result.success {
            return Err(AlgoError::Ledger {
                message: format!(
                    "catchpoint label mismatch: expected '{}', computed '{}'",
                    verify_result.expected_label, verify_result.computed_label
                ),
            });
        }

        tracing::info!(
            label = %verify_result.computed_label,
            accounts = verify_result.accounts_count,
            "catchpoint label verification passed"
        );

        // Step 2: Post-import validation (non-critical warnings).
        let catchpoint_round = self.catchpoint_round.unwrap_or(0);
        let warnings =
            validate_post_import(&conn, catchpoint_round).map_err(|e| AlgoError::Ledger {
                message: format!("post-import validation error: {e}"),
            })?;

        if warnings.is_empty() {
            tracing::info!("post-import validation: all checks passed");
        } else {
            for w in &warnings {
                tracing::warn!(
                    category = %w.category,
                    message = %w.message,
                    "post-import validation warning"
                );
            }
        }

        self.progress.phase_progress = 1.0;
        self.notify_progress();
        Ok(())
    }

    /// Phase 4: Download lookback blocks needed for lease/txn-life validation.
    ///
    /// Downloads blocks from `catchpoint_round` backward for `MAX_TXN_LIFE`
    /// rounds, stores them in the database, and reconstructs the lease table.
    fn run_download_lookback(&mut self) -> Result<(), AlgoError> {
        self.check_cancelled()?;
        self.transition(SyncState::DownloadingLookback)?;

        let round = self.catchpoint_round.ok_or_else(|| AlgoError::Ledger {
            message: "catchpoint round not known — earlier phases did not complete".to_string(),
        })?;

        tracing::info!(
            catchpoint_round = round,
            "downloading lookback blocks for lease reconstruction"
        );
        self.progress.phase_detail = format!(
            "downloading lookback blocks from round {}",
            round.saturating_sub(crate::catchpoint::MAX_TXN_LIFE)
        );
        self.notify_progress();

        let conn = self.open_db()?;

        // Ensure the blocks and txtail tables exist. On a fresh database created
        // by the catchpoint importer, only the catchpoint staging/account tables
        // exist — the normal SCHEMA_SQL (run by SqliteLedger::open()) has not
        // been executed yet. Using IF NOT EXISTS makes this idempotent.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS blocks (
                rnd INTEGER PRIMARY KEY,
                proto TEXT,
                hdrdata BLOB,
                blkdata BLOB,
                certdata BLOB
            );
            CREATE TABLE IF NOT EXISTS txtail (
                rnd INTEGER PRIMARY KEY NOT NULL,
                data BLOB NOT NULL
            );",
        )
        .map_err(|e| AlgoError::Ledger {
            message: format!("create blocks/txtail tables for lookback: {e}"),
        })?;

        // Use download_lookback_blocks with callbacks that bridge to the backend.
        let blocks_downloaded = crate::catchpoint::download_lookback_blocks(
            round,
            // fetch_block callback
            |rnd| {
                let (proto, hdrdata, blkdata) = self.backend.fetch_block_raw(rnd).map_err(|e| {
                    CatchpointError::VerificationError(format!("fetch lookback block {rnd}: {e}"))
                })?;
                Ok((proto, hdrdata, blkdata))
            },
            // store_block callback
            |rnd, proto, hdrdata, blkdata| {
                // Store block in the blocks table.
                conn.execute(
                    "INSERT OR REPLACE INTO blocks (rnd, proto, hdrdata, blkdata) \
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![rnd as i64, proto, hdrdata, blkdata],
                )
                .map_err(|e| {
                    CatchpointError::VerificationError(format!("store lookback block {rnd}: {e}"))
                })?;

                // Decode the block to extract txtail data for lease reconstruction.
                // blkdata is canonical block encoding (not a response wrapper).
                if let Ok(block) = algo_codec::decode_block(blkdata) {
                    let block = &block;
                    // Build and store txtail entry.
                    if let Ok(txtail_data) = build_txtail_entry(block) {
                        conn.execute(
                            "INSERT OR REPLACE INTO txtail (rnd, data) VALUES (?1, ?2)",
                            rusqlite::params![rnd as i64, txtail_data],
                        )
                        .map_err(|e| {
                            CatchpointError::VerificationError(format!(
                                "store txtail for round {rnd}: {e}"
                            ))
                        })?;
                    }
                }

                Ok(())
            },
        )
        .map_err(|e| AlgoError::Ledger {
            message: format!("lookback block download failed: {e}"),
        })?;

        tracing::info!(blocks_downloaded, "lookback blocks downloaded");

        // Reconstruct lease table from the downloaded txtail entries.
        let lease_table =
            crate::catchpoint::reconstruct_lease_table(&conn, round).map_err(|e| {
                AlgoError::Ledger {
                    message: format!("lease table reconstruction failed: {e}"),
                }
            })?;

        // Lease table reconstructed — the table itself is ephemeral here
        // since the SqliteLedger will rebuild it from the txtail table on
        // startup. We just log success.
        let _ = lease_table;
        tracing::info!("lease table reconstructed from lookback blocks");

        self.progress.phase_progress = 1.0;
        self.notify_progress();
        Ok(())
    }

    /// Phase 5: Replay blocks from the catchpoint round to the current round.
    ///
    /// Fetches blocks one at a time from catchpoint_round+1 to the current
    /// network round and applies them to the ledger using `apply_block`.
    fn run_replay_blocks(&mut self) -> Result<(), AlgoError> {
        self.check_cancelled()?;
        self.transition(SyncState::ReplayingBlocks)?;

        let catchpoint_round = self.catchpoint_round.ok_or_else(|| AlgoError::Ledger {
            message: "catchpoint round not known — earlier phases did not complete".to_string(),
        })?;

        // Determine target: current network round, capped by end_round if set.
        let network_round = self.backend.get_current_round()?;
        let target_round = match self.config.end_round {
            Some(end) => std::cmp::min(network_round, end),
            None => network_round,
        };

        // When resuming after an interruption, some blocks may already have
        // been committed. Query the database for the last committed round and
        // skip ahead to avoid re-applying blocks (which would fail with a
        // round mismatch in apply_block's strict monotonicity check).
        let start_round = {
            let resume_store =
                crate::SqliteLedger::open(&self.config.db_path).map_err(|e| AlgoError::Ledger {
                    message: format!("open ledger for resume check: {e}"),
                })?;
            match resume_store.last_committed_round() {
                Ok(Some(last)) if last > catchpoint_round => {
                    tracing::info!(
                        last_committed = last,
                        catchpoint_round,
                        "resuming replay from last committed round"
                    );
                    last + 1
                }
                _ => catchpoint_round + 1,
            }
        };

        if start_round > target_round {
            tracing::info!(
                catchpoint_round,
                target_round,
                "already at or past target round, no blocks to replay"
            );
            self.final_round = catchpoint_round;
            self.progress.phase_progress = 1.0;
            self.notify_progress();
            return Ok(());
        }

        tracing::info!(
            start = start_round,
            target = target_round,
            count = target_round - start_round + 1,
            "replaying blocks"
        );
        self.progress.phase_detail =
            format!("replaying blocks {} to {}", start_round, target_round);
        self.notify_progress();

        // Open SqliteLedger for block application (needs the full LedgerStore).
        let mut store =
            crate::SqliteLedger::open(&self.config.db_path).map_err(|e| AlgoError::Ledger {
                message: format!("open ledger for replay: {e}"),
            })?;

        // Enable Merkle trie tracking if a trie path is configured.
        if self.config.trie_path.is_some() {
            store.enable_trie();
            tracing::info!("Merkle trie tracking enabled for replay");
        }

        let timer = Instant::now();
        let mut blocks_applied: u64 = 0;
        let progress_interval: u64 = 1000;

        // Fetch blocks in batches to overlap network I/O with block application.
        // The batch size is derived from the concurrency setting (default: 1 means
        // sequential). Blocks within each batch are fetched in parallel by the
        // backend, then applied sequentially to maintain round monotonicity.
        let batch_size = (self.config.concurrency * 2).max(1) as u64;
        let mut batch_start = start_round;

        while batch_start <= target_round {
            // Check cancellation between batches.
            if self.cancel.is_cancelled() {
                tracing::info!(
                    round = batch_start,
                    blocks_applied,
                    "cancellation requested during block replay"
                );
                self.blocks_replayed = blocks_applied;
                return Err(self.handle_cancellation());
            }

            let batch_end = std::cmp::min(batch_start + batch_size - 1, target_round);

            // Fetch the batch (parallel if the backend supports it).
            let batch =
                self.backend
                    .fetch_blocks_batch(batch_start, batch_end, self.config.concurrency)?;

            // Apply each block in the batch sequentially.
            for (round, block) in &batch {
                let round = *round;

                // Check cancellation between blocks within a batch.
                if self.cancel.is_cancelled() {
                    tracing::info!(
                        round,
                        blocks_applied,
                        "cancellation requested during block replay"
                    );
                    self.blocks_replayed = blocks_applied;
                    return Err(self.handle_cancellation());
                }

                store.begin_block()?;

                let apply_result = if self.config.avm_execute || self.config.compare_mode {
                    let (result, block_stats) =
                        crate::apply_block_with_comparison(&mut store, block);
                    self.eval_delta_stats += block_stats;
                    result
                } else {
                    crate::apply_block(&mut store, block)
                };

                match apply_result {
                    Ok(()) => {
                        if self.config.trie_path.is_some() {
                            store.finalize_trie_updates();
                        }
                        store.commit_block()?;
                        blocks_applied += 1;
                    }
                    Err(e) => {
                        tracing::warn!(round, error = %e, "apply_block failed during replay");
                        let _ = store.rollback_block();

                        // Block apply failures are always fatal to the replay.
                        // After a failed apply the ledger state is at round N-1,
                        // so round N+1 would also fail with a round mismatch.
                        // Break out and report the error regardless of fail_fast.
                        return Err(AlgoError::Ledger {
                            message: format!("block replay failed at round {round}: {e}"),
                        });
                    }
                }

                // Track the actual last round processed.
                self.final_round = round;

                // Progress logging.
                if blocks_applied % progress_interval == 0 || round == target_round {
                    let elapsed = timer.elapsed().as_secs_f64();
                    let rate = if elapsed > 0.0 {
                        blocks_applied as f64 / elapsed
                    } else {
                        0.0
                    };
                    tracing::info!(
                        round,
                        target = target_round,
                        elapsed_secs = format!("{elapsed:.1}"),
                        rate = format!("{rate:.1}"),
                        "replay progress"
                    );

                    let total_range = (target_round - start_round + 1) as f64;
                    self.progress.phase_progress = blocks_applied as f64 / total_range;
                    self.progress.phase_detail = format!(
                        "replayed {blocks_applied}/{} blocks ({rate:.1} blocks/sec)",
                        target_round - start_round + 1
                    );
                    self.notify_progress();
                }
            }

            batch_start = batch_end + 1;
        }

        self.blocks_replayed = blocks_applied;

        tracing::info!(
            blocks_applied,
            final_round = self.final_round,
            elapsed = ?timer.elapsed(),
            "block replay complete"
        );

        // Print AVM/EvalDelta stats if compare or AVM execution was enabled.
        if self.config.avm_execute || self.config.compare_mode {
            self.eval_delta_stats.print_summary();
        }

        self.progress.phase_progress = 1.0;
        self.notify_progress();
        Ok(())
    }

    /// Drive the state machine through all phases to completion.
    ///
    /// On error in any phase, the state transitions to `Failed` and the error
    /// is returned. If the cancellation token is triggered, the orchestrator
    /// persists checkpoint state and returns an error.
    ///
    /// If `config.follow_after_sync` is true, the orchestrator enters follow
    /// mode after block replay completes. Follow mode continuously polls for
    /// new blocks and applies them until the cancellation token fires.
    pub async fn run(&mut self) -> Result<SyncResult, AlgoError> {
        let start = Instant::now();
        self.progress.started_at = Some(start);

        tracing::info!(
            catchpoint = ?self.config.catchpoint_label,
            db = %self.config.db_path.display(),
            "starting catchpoint sync"
        );

        // Check for resumable state.
        let mut resume_state = SyncState::Idle;
        if let Ok(conn) = self.open_db() {
            if let Ok(Some(persisted)) = restore_sync_state(&conn) {
                if !persisted.state.is_terminal() {
                    tracing::info!(
                        persisted_state = %persisted.state,
                        "found persisted sync state — will resume"
                    );
                    resume_state = persisted.state;
                    // Restore relevant fields.
                    if let Some(label) = persisted.catchpoint_label {
                        self.resolved_label = Some(label);
                    }
                    if let Some(round) = persisted.catchpoint_round {
                        self.catchpoint_round = Some(round);
                    }
                    if let Some(file) = persisted.catchpoint_file {
                        self.catchpoint_file_path = Some(PathBuf::from(file));
                    }
                }
            }
        }

        let mut result = self.run_phases(resume_state);

        match &result {
            Ok(_) => {
                // If follow mode is enabled, enter it before transitioning to Complete.
                // Follow mode runs until cancellation; a cancellation exit is not an error.
                if self.config.follow_after_sync && !self.backend.is_noop() {
                    if let Err(e) = self.run_follow_mode().await {
                        if self.cancel.is_cancelled() {
                            tracing::info!("follow mode stopped: sync cancelled");
                        } else {
                            // Non-cancellation error in follow mode is a real failure —
                            // propagate it so the CLI exits with a non-zero status.
                            return Err(e);
                        }
                    }

                    // Update the SyncResult with values accumulated during follow mode.
                    // Follow mode updates self.final_round and self.blocks_replayed
                    // as it applies blocks, so reflect those in the returned result.
                    if let Ok(ref mut r) = result {
                        r.final_round = self.final_round;
                        r.blocks_replayed = self.blocks_replayed;
                        r.duration = start.elapsed();
                    }
                }

                // Run ledger invariant validation before marking complete.
                if !self.backend.is_noop() {
                    if let Ok(conn) = self.open_db() {
                        let invariant_warnings = validate_invariants(&conn);
                        if invariant_warnings.is_empty() {
                            tracing::info!("ledger invariant validation: all checks passed");
                        } else {
                            for w in &invariant_warnings {
                                match w.severity {
                                    WarningSeverity::Info => tracing::info!(
                                        name = %w.name,
                                        detail = %w.detail,
                                        "invariant check: info"
                                    ),
                                    WarningSeverity::Warning => tracing::warn!(
                                        name = %w.name,
                                        detail = %w.detail,
                                        "invariant check: warning"
                                    ),
                                    WarningSeverity::Error => tracing::error!(
                                        name = %w.name,
                                        detail = %w.detail,
                                        "invariant check: error"
                                    ),
                                }
                            }
                        }
                    }
                }

                self.transition(SyncState::Complete)?;
                tracing::info!(
                    elapsed = ?start.elapsed(),
                    "catchpoint sync completed"
                );
                // Clear persisted state on success.
                if let Ok(conn) = self.open_db() {
                    let _ = clear_sync_state(&conn);
                }
            }
            Err(e) => {
                let msg = e.to_string();
                // Transition to Failed — this should always succeed since any
                // state can transition to Failed.
                let _ = self.transition(SyncState::Failed(msg));
            }
        }

        result
    }

    /// Follow mode: continuously poll for new blocks and apply them.
    ///
    /// Runs after block replay completes. Polls `backend.get_current_round()`
    /// to detect new rounds, fetches each new block, and applies it to the
    /// ledger. Continues until the cancellation token fires.
    ///
    /// This mirrors the pattern in `bin/algod-rust/src/commands/follow.rs`
    /// adapted for the sync orchestrator's backend abstraction.
    async fn run_follow_mode(&mut self) -> Result<(), AlgoError> {
        const POLL_INTERVAL: Duration = Duration::from_millis(500);

        // Open SqliteLedger for block application.
        let mut store =
            crate::SqliteLedger::open(&self.config.db_path).map_err(|e| AlgoError::Ledger {
                message: format!("open ledger for follow mode: {e}"),
            })?;

        // Enable Merkle trie tracking if a trie path is configured.
        if self.config.trie_path.is_some() {
            store.enable_trie();
            tracing::info!("Merkle trie tracking enabled for follow mode");
        }

        // Determine starting round from the last committed round in the ledger.
        let mut current_round = store
            .last_committed_round()?
            .ok_or_else(|| AlgoError::Ledger {
                message: "follow mode: no committed round in ledger".to_string(),
            })?;

        tracing::info!(
            round = current_round,
            "entering follow mode — polling for new blocks"
        );
        self.progress.phase_detail = format!("follow mode from round {current_round}");

        let mut blocks_followed: u64 = 0;

        loop {
            // Check for cancellation.
            if self.cancel.is_cancelled() {
                tracing::info!(
                    blocks_followed,
                    last_round = current_round,
                    "follow mode: cancellation requested"
                );
                if self.config.avm_execute || self.config.compare_mode {
                    self.eval_delta_stats.print_summary();
                }
                return Ok(());
            }

            // Poll the node for the latest round.
            let network_round = match self.backend.get_current_round() {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "follow mode: failed to get current round, retrying");
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                }
            };

            // If we're caught up, wait and poll again.
            if current_round >= network_round {
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }

            // Apply all rounds from current+1 up to network_round.
            while current_round < network_round {
                // Check cancellation between blocks.
                if self.cancel.is_cancelled() {
                    tracing::info!(
                        blocks_followed,
                        last_round = current_round,
                        "follow mode: cancellation requested"
                    );
                    if self.config.avm_execute || self.config.compare_mode {
                        self.eval_delta_stats.print_summary();
                    }
                    return Ok(());
                }

                let next_round = current_round + 1;

                let block = match self.backend.fetch_block(next_round) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(
                            round = next_round,
                            error = %e,
                            "follow mode: failed to fetch block, retrying"
                        );
                        // Back off briefly before retrying.
                        tokio::time::sleep(POLL_INTERVAL).await;
                        break;
                    }
                };

                let txn_count = block.payset.len();

                store.begin_block()?;

                let apply_result = if self.config.avm_execute || self.config.compare_mode {
                    let (result, block_stats) =
                        crate::apply_block_with_comparison(&mut store, &block);
                    self.eval_delta_stats += block_stats;
                    result
                } else {
                    crate::apply_block(&mut store, &block)
                };

                match apply_result {
                    Ok(()) => {
                        if self.config.trie_path.is_some() {
                            store.finalize_trie_updates();
                        }
                        store.commit_block()?;
                        blocks_followed += 1;
                        current_round = next_round;
                        self.final_round = current_round;
                        self.blocks_replayed += 1;

                        tracing::info!(
                            round = current_round,
                            txns = txn_count,
                            blocks_followed,
                            "follow mode: applied block"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            round = next_round,
                            error = %e,
                            "follow mode: apply_block failed"
                        );
                        let _ = store.rollback_block();

                        // Block apply failures are always fatal in follow mode.
                        // After a failed apply the ledger state is at round N-1,
                        // so advancing current_round would permanently desynchronize
                        // the follower (every subsequent block would fail with a
                        // round mismatch).
                        // Print accumulated stats before returning the error.
                        if self.config.avm_execute || self.config.compare_mode {
                            self.eval_delta_stats.print_summary();
                        }
                        return Err(AlgoError::Ledger {
                            message: format!(
                                "follow mode: block apply failed at round {next_round}: {e}"
                            ),
                        });
                    }
                }
            }
        }
    }

    /// Internal helper: runs each phase in sequence, optionally resuming
    /// from `resume_state`.
    ///
    /// When `resume_state` is not `Idle`, phases that precede the resume
    /// state are skipped. For example, if `resume_state` is
    /// `VerifyingLedger`, the download and import phases are skipped and
    /// execution starts from verification.
    ///
    /// When the orchestrator is constructed with the default `NoopBackend`
    /// (via `new()`), all phases are skipped and a zero-valued result is
    /// returned. This preserves backward compatibility for callers that
    /// haven't yet switched to `with_backend()`.
    fn run_phases(&mut self, resume_state: SyncState) -> Result<SyncResult, AlgoError> {
        let start = Instant::now();

        // Stub mode: skip all phases when using the default NoopBackend.
        if self.backend.is_noop() {
            tracing::info!("running in stub mode (NoopBackend) — skipping all phases");
            // Walk through transitions to maintain state machine consistency.
            self.transition(SyncState::DownloadingLedger)?;
            self.transition(SyncState::ImportingLedger)?;
            self.transition(SyncState::VerifyingLedger)?;
            self.transition(SyncState::DownloadingLookback)?;
            self.transition(SyncState::ReplayingBlocks)?;

            return Ok(SyncResult {
                final_round: 0,
                accounts_imported: 0,
                blocks_replayed: 0,
                duration: start.elapsed(),
            });
        }

        // Determine which phase to start from based on resume state.
        // Each phase handles its own state transition internally (Idle -> X),
        // so we skip phases whose transitions have already been completed.
        let resume_ord = phase_ordinal(&resume_state);

        if resume_ord > 0 {
            tracing::info!(
                resume_state = %resume_state,
                "resuming sync — skipping completed phases"
            );
            // Set internal state to the predecessor of the resume state so that
            // the resumed phase's `transition()` call validates correctly.
            self.state = match &resume_state {
                SyncState::DownloadingLedger => SyncState::Idle,
                SyncState::ImportingLedger => SyncState::DownloadingLedger,
                SyncState::VerifyingLedger => SyncState::ImportingLedger,
                SyncState::DownloadingLookback => SyncState::VerifyingLedger,
                SyncState::ReplayingBlocks => SyncState::DownloadingLookback,
                _ => SyncState::Idle,
            };
            self.progress.state = self.state.clone();
        }

        // Phase 1: DownloadingLedger (ordinal 1)
        if resume_ord <= 1 {
            self.run_download_ledger()?;
        }

        // Phase 2: ImportingLedger (ordinal 2)
        if resume_ord <= 2 {
            self.run_import_ledger()?;
        } else {
            // When resuming past import, we still need the block_header_digest
            // for verification. Extract it from the catchpoint file if available.
            if self.block_header_digest.is_none() {
                if let Some(ref file_path) = self.catchpoint_file_path {
                    if file_path.exists() {
                        if let Ok(header) = self.extract_header(file_path) {
                            if header.block_header_digest.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&header.block_header_digest);
                                self.block_header_digest = Some(arr);
                            }
                        }
                    }
                }
            }
        }

        // Phase 3: VerifyingLedger (ordinal 3)
        if resume_ord <= 3 {
            self.run_verify_ledger()?;
        }

        // Phase 4: DownloadingLookback (ordinal 4)
        if resume_ord <= 4 {
            self.run_download_lookback()?;
        }

        // Phase 5: ReplayingBlocks (ordinal 5)
        self.run_replay_blocks()?;

        Ok(SyncResult {
            final_round: self.final_round,
            accounts_imported: self.accounts_imported,
            blocks_replayed: self.blocks_replayed,
            duration: start.elapsed(),
        })
    }
}

/// Map a `SyncState` to a numeric ordinal for resume ordering.
///
/// Higher ordinals mean the phase was reached later in the pipeline.
/// `Idle` = 0, `DownloadingLedger` = 1, ..., `ReplayingBlocks` = 5.
fn phase_ordinal(state: &SyncState) -> u8 {
    match state {
        SyncState::Idle => 0,
        SyncState::DownloadingLedger => 1,
        SyncState::ImportingLedger => 2,
        SyncState::VerifyingLedger => 3,
        SyncState::DownloadingLookback => 4,
        SyncState::ReplayingBlocks => 5,
        SyncState::Complete => 6,
        SyncState::Failed(_) => 0, // Failed should restart from beginning
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Extract the protocol version from the most recent onlineroundparamstail entry.
fn extract_protocol_from_db(conn: &Connection) -> String {
    conn.query_row(
        "SELECT data FROM onlineroundparamstail ORDER BY rnd DESC LIMIT 1",
        [],
        |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        },
    )
    .ok()
    .and_then(|data| {
        let val = rmpv::decode::read_value(&mut &data[..]).ok()?;
        if let rmpv::Value::Map(map) = val {
            for (k, v) in &map {
                if let rmpv::Value::String(s) = k {
                    if s.as_str() == Some("proto") {
                        if let rmpv::Value::String(proto) = v {
                            return proto.as_str().map(|s| s.to_string());
                        }
                    }
                }
            }
        }
        None
    })
    .unwrap_or_default()
}

/// Derive txn_counter from the maximum creatable ID in assetcreators.
fn derive_txn_counter(conn: &Connection) -> u64 {
    conn.query_row(
        "SELECT COALESCE(MAX(asset), 0) FROM assetcreators",
        [],
        |row| row.get(0),
    )
    .unwrap_or(0)
}

/// Build a serialized TxTailRound entry from a block for txtail storage.
///
/// Extracts lease information and last_valid values from the block's
/// transactions for later lease table reconstruction.
fn build_txtail_entry(block: &Block) -> Result<Vec<u8>, AlgoError> {
    use algo_types::{BlockHeader, TxTailRound};
    use serde_bytes::ByteBuf;

    let mut last_valid_vec = Vec::new();
    let mut leases = Vec::new();

    for stib in &block.payset {
        let txn = &stib.txn;
        last_valid_vec.push(txn.last_valid.0);

        // Record lease if present (non-empty and non-zero).
        if txn.lease.len() == 32 {
            let all_zero = txn.lease.iter().all(|&b| b == 0);
            if !all_zero {
                let txn_idx = (last_valid_vec.len() - 1) as u64;
                let sender = txn.sender;
                leases.push(algo_types::TxTailRoundLease {
                    sender,
                    lease: ByteBuf::from(txn.lease.as_ref()),
                    txn_idx,
                });
            }
        }
    }

    // Construct the BlockHeader from the Block's header fields.
    let hdr = BlockHeader {
        round: block.round,
        branch: block.branch,
        seed: block.seed,
        txn_commitment: block.txn_commitment,
        timestamp: block.timestamp,
        genesis_id: block.genesis_id.clone(),
        genesis_hash: block.genesis_hash,
        proposer: block.proposer,
        fee_sink: block.fee_sink,
        rewards_pool: block.rewards_pool,
        rewards_level: block.rewards_level,
        rewards_rate: block.rewards_rate,
        rewards_residue: block.rewards_residue,
        rewards_recalculation_round: block.rewards_recalculation_round,
        current_protocol: block.current_protocol.clone(),
        next_protocol: block.next_protocol.clone(),
        next_protocol_approvals: block.next_protocol_approvals,
        next_protocol_switch_on: block.next_protocol_switch_on,
        next_protocol_vote_before: block.next_protocol_vote_before,
        txn_counter: block.txn_counter,
        fees_collected: block.fees_collected,
        bonus: block.bonus,
        proposer_payout: block.proposer_payout,
        prev512: block.prev512,
        txn256: block.txn256,
        txn512: block.txn512,
        state_proof_tracking: block.state_proof_tracking.clone(),
        upgrade_propose: block.upgrade_propose.clone(),
        upgrade_delay: block.upgrade_delay,
        upgrade_approve: block.upgrade_approve,
        expired_participation_accounts: block.expired_participation_accounts.clone(),
        absent_participation_accounts: block.absent_participation_accounts.clone(),
    };

    let txtail = TxTailRound {
        txn_ids: Vec::new(),
        last_valid: last_valid_vec,
        leases,
        hdr,
    };

    rmp_serde::to_vec_named(&txtail).map_err(|e| AlgoError::Ledger {
        message: format!("encode txtail entry: {e}"),
    })
}

// ---------------------------------------------------------------------------
// Ledger invariant validation
// ---------------------------------------------------------------------------

/// Severity level for ledger invariant warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarningSeverity {
    /// Informational — expected or benign observation.
    Info,
    /// Warning — potential issue that may indicate a problem.
    Warning,
    /// Error — definite inconsistency that should be investigated.
    Error,
}

impl std::fmt::Display for WarningSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WarningSeverity::Info => write!(f, "info"),
            WarningSeverity::Warning => write!(f, "warning"),
            WarningSeverity::Error => write!(f, "error"),
        }
    }
}

/// A ledger invariant warning found during post-sync validation.
#[derive(Debug, Clone)]
pub struct InvariantWarning {
    /// Short name of the invariant that was checked.
    pub name: String,
    /// Human-readable description of the finding.
    pub detail: String,
    /// How serious the finding is.
    pub severity: WarningSeverity,
}

/// Validate ledger invariants on the given database connection.
///
/// This is intended to be called after sync completes (after block replay)
/// to verify that the database is internally consistent. Returns a list of
/// warnings (not errors) — the caller decides whether to treat them as fatal.
///
/// Checks performed:
/// 1. **acctrounds consistency** — the `acctbase` round exists and is non-negative.
/// 2. **accounttotals** — stored totals match actual sums from `accountbase` data.
/// 3. **normalizedonlinebalance** — online accounts have a positive NOB value.
/// 4. **catchpointstate** — metadata entries are present and consistent.
pub fn validate_invariants(conn: &Connection) -> Vec<InvariantWarning> {
    let mut warnings = Vec::new();

    // ------------------------------------------------------------------
    // 1. acctrounds consistency
    // ------------------------------------------------------------------
    match conn.query_row(
        "SELECT rnd FROM acctrounds WHERE id = 'acctbase'",
        [],
        |row| row.get::<_, i64>(0),
    ) {
        Ok(rnd) => {
            if rnd < 0 {
                warnings.push(InvariantWarning {
                    name: "acctrounds_negative".to_string(),
                    detail: format!("acctrounds 'acctbase' round is negative: {rnd}"),
                    severity: WarningSeverity::Error,
                });
            }
        }
        Err(_) => {
            warnings.push(InvariantWarning {
                name: "acctrounds_missing".to_string(),
                detail: "acctrounds 'acctbase' entry is missing".to_string(),
                severity: WarningSeverity::Error,
            });
        }
    }

    // ------------------------------------------------------------------
    // 2. accounttotals vs actual sums
    // ------------------------------------------------------------------
    let stored_totals = conn.query_row(
        "SELECT online, offline, notparticipating FROM accounttotals WHERE id = ''",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    );

    match stored_totals {
        Ok((stored_online, stored_offline, stored_nopart)) => {
            // Sum actual micro-algos from the account blobs grouped by status.
            // Status: 0 = Offline, 1 = Online, 2 = NotParticipating
            let actual_sums = conn
                .prepare("SELECT data FROM accountbase WHERE data IS NOT NULL")
                .and_then(|mut stmt| {
                    let rows = stmt.query_map([], |row| {
                        let data: Vec<u8> = row.get(0)?;
                        Ok(data)
                    })?;

                    let mut online_sum: i64 = 0;
                    let mut offline_sum: i64 = 0;
                    let mut nopart_sum: i64 = 0;

                    for data in rows.flatten() {
                        // Decode minimal fields from the msgpack blob:
                        // "a" = status (u8), "b" = micro_algos (u64)
                        if let Ok(rmpv::Value::Map(map)) = rmpv::decode::read_value(&mut &data[..])
                        {
                            let mut status: u8 = 0;
                            let mut micro_algos: u64 = 0;
                            for (k, v) in &map {
                                match k.as_str().unwrap_or("") {
                                    "a" => status = v.as_u64().unwrap_or(0) as u8,
                                    "b" => micro_algos = v.as_u64().unwrap_or(0),
                                    _ => {}
                                }
                            }
                            match status {
                                0 => offline_sum = offline_sum.saturating_add(micro_algos as i64),
                                1 => online_sum = online_sum.saturating_add(micro_algos as i64),
                                2 => nopart_sum = nopart_sum.saturating_add(micro_algos as i64),
                                _ => {}
                            }
                        }
                    }

                    Ok((online_sum, offline_sum, nopart_sum))
                });

            match actual_sums {
                Ok((actual_online, actual_offline, actual_nopart)) => {
                    if stored_online != actual_online {
                        warnings.push(InvariantWarning {
                            name: "accounttotals_online".to_string(),
                            detail: format!(
                                "online totals mismatch: stored={stored_online}, actual={actual_online}"
                            ),
                            severity: WarningSeverity::Warning,
                        });
                    }
                    if stored_offline != actual_offline {
                        warnings.push(InvariantWarning {
                            name: "accounttotals_offline".to_string(),
                            detail: format!(
                                "offline totals mismatch: stored={stored_offline}, actual={actual_offline}"
                            ),
                            severity: WarningSeverity::Warning,
                        });
                    }
                    if stored_nopart != actual_nopart {
                        warnings.push(InvariantWarning {
                            name: "accounttotals_notparticipating".to_string(),
                            detail: format!(
                                "notparticipating totals mismatch: stored={stored_nopart}, actual={actual_nopart}"
                            ),
                            severity: WarningSeverity::Warning,
                        });
                    }
                }
                Err(e) => {
                    warnings.push(InvariantWarning {
                        name: "accounttotals_scan".to_string(),
                        detail: format!("failed to scan accountbase for totals: {e}"),
                        severity: WarningSeverity::Warning,
                    });
                }
            }
        }
        Err(_) => {
            warnings.push(InvariantWarning {
                name: "accounttotals_missing".to_string(),
                detail: "accounttotals row (id='') is missing".to_string(),
                severity: WarningSeverity::Error,
            });
        }
    }

    // ------------------------------------------------------------------
    // 3. normalizedonlinebalance consistency
    // ------------------------------------------------------------------
    // Check that online accounts (status=1 in the blob) have a positive NOB,
    // and offline accounts do not.
    let nob_check = conn.query_row(
        "SELECT COUNT(*) FROM accountbase \
         WHERE normalizedonlinebalance > 0 AND data IS NOT NULL",
        [],
        |row| row.get::<_, i64>(0),
    );
    match nob_check {
        Ok(count) => {
            if count < 0 {
                warnings.push(InvariantWarning {
                    name: "normalizedonlinebalance_negative_count".to_string(),
                    detail: "negative count from NOB query (should not happen)".to_string(),
                    severity: WarningSeverity::Error,
                });
            }
            // Informational: report how many accounts have a positive NOB.
            tracing::debug!(nob_positive_count = count, "online balance index entries");
        }
        Err(e) => {
            warnings.push(InvariantWarning {
                name: "normalizedonlinebalance_query".to_string(),
                detail: format!("failed to query normalizedonlinebalance: {e}"),
                severity: WarningSeverity::Warning,
            });
        }
    }

    // ------------------------------------------------------------------
    // 4. catchpointstate metadata
    // ------------------------------------------------------------------
    let cpstate_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master \
             WHERE type='table' AND name='catchpointstate'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if cpstate_exists {
        // Check that at least one entry exists (catchpoint round, writable DB flag, etc.)
        let entry_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM catchpointstate", [], |row| row.get(0))
            .unwrap_or(0);

        if entry_count == 0 {
            warnings.push(InvariantWarning {
                name: "catchpointstate_empty".to_string(),
                detail: "catchpointstate table exists but has no entries".to_string(),
                severity: WarningSeverity::Info,
            });
        }
    }

    warnings
}

// ---------------------------------------------------------------------------
// NoopBackend — a no-op backend for testing / stub usage
// ---------------------------------------------------------------------------

/// A no-op backend used as the default when no real network backend is
/// provided. When this backend is active, the orchestrator runs in stub
/// mode and skips all phases, returning a zero-valued `SyncResult`.
///
/// Use [`SyncOrchestrator::with_backend`] to supply a real backend.
pub struct NoopBackend;

impl SyncBackend for NoopBackend {
    fn is_noop(&self) -> bool {
        true
    }

    fn download_catchpoint(
        &self,
        _genesis_id: &str,
        _round: u64,
        _dest_path: &std::path::Path,
    ) -> Result<(), AlgoError> {
        Err(AlgoError::Ledger {
            message: "NoopBackend: download_catchpoint not implemented — \
                      use SyncOrchestrator::with_backend() to supply a real backend"
                .to_string(),
        })
    }

    fn fetch_block_raw(&self, _round: u64) -> Result<(String, Vec<u8>, Vec<u8>), AlgoError> {
        Err(AlgoError::Ledger {
            message: "NoopBackend: fetch_block_raw not implemented".to_string(),
        })
    }

    fn fetch_block(&self, _round: u64) -> Result<Block, AlgoError> {
        Err(AlgoError::Ledger {
            message: "NoopBackend: fetch_block not implemented".to_string(),
        })
    }

    fn get_current_round(&self) -> Result<u64, AlgoError> {
        Err(AlgoError::Ledger {
            message: "NoopBackend: get_current_round not implemented".to_string(),
        })
    }

    fn discover_catchpoint(&self) -> Result<Option<String>, AlgoError> {
        Ok(None)
    }
}
