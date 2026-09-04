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

// Sync state machine — models catchpoint sync phases.
//
// Mirrors Go's CatchpointCatchupState from go-algorand/ledger/catchupaccessor.go
// but adapted for our pipeline: download ledger -> import -> verify -> download
// lookback blocks -> replay blocks -> complete.

use std::fmt;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// SyncState
// ---------------------------------------------------------------------------

/// Sync state enum — mirrors Go's CatchpointCatchupState with phases that
/// match our Rust pipeline (Epic 26b importer, Epic 27 verification, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SyncState {
    /// Not started — initial state before any work begins.
    #[default]
    Idle,
    /// Downloading the catchpoint ledger snapshot from a peer.
    DownloadingLedger,
    /// Importing the downloaded ledger into the local database.
    ImportingLedger,
    /// Verifying the imported ledger (Merkle trie, account totals, etc.).
    VerifyingLedger,
    /// Downloading lookback blocks needed for lease/txn-life validation.
    DownloadingLookback,
    /// Replaying blocks from the catchpoint round forward to the current round.
    ReplayingBlocks,
    /// All phases completed successfully.
    Complete,
    /// An unrecoverable error occurred.
    Failed(String),
}

impl SyncState {
    /// Returns the next expected state in the happy path, or `None` if this
    /// state is terminal (Complete or Failed).
    pub fn next(&self) -> Option<SyncState> {
        match self {
            SyncState::Idle => Some(SyncState::DownloadingLedger),
            SyncState::DownloadingLedger => Some(SyncState::ImportingLedger),
            SyncState::ImportingLedger => Some(SyncState::VerifyingLedger),
            SyncState::VerifyingLedger => Some(SyncState::DownloadingLookback),
            SyncState::DownloadingLookback => Some(SyncState::ReplayingBlocks),
            SyncState::ReplayingBlocks => Some(SyncState::Complete),
            SyncState::Complete | SyncState::Failed(_) => None,
        }
    }

    /// Returns true if the state is terminal (Complete or Failed).
    pub fn is_terminal(&self) -> bool {
        matches!(self, SyncState::Complete | SyncState::Failed(_))
    }

    /// Validates whether a transition from `self` to `next` is allowed.
    ///
    /// Allowed transitions:
    /// - Any state can transition to `Failed` (error at any point).
    /// - Each non-terminal state can transition to its `next()` state.
    /// - `Idle` can transition to itself (no-op restart).
    pub fn can_transition_to(&self, next: &SyncState) -> bool {
        // Any state can fail.
        if matches!(next, SyncState::Failed(_)) {
            return true;
        }

        // Terminal states cannot transition to anything (except Failed, handled above).
        if self.is_terminal() {
            return false;
        }

        // Allow the happy-path forward transition.
        if let Some(expected) = self.next() {
            if *next == expected {
                return true;
            }
        }

        false
    }

    // -------------------------------------------------------------------
    // SQLite persistence helpers — simple string mapping, no serde needed
    // -------------------------------------------------------------------

    /// Serialize state to a string for SQLite persistence.
    pub fn to_db_string(&self) -> String {
        match self {
            SyncState::Idle => "idle".to_string(),
            SyncState::DownloadingLedger => "downloading_ledger".to_string(),
            SyncState::ImportingLedger => "importing_ledger".to_string(),
            SyncState::VerifyingLedger => "verifying_ledger".to_string(),
            SyncState::DownloadingLookback => "downloading_lookback".to_string(),
            SyncState::ReplayingBlocks => "replaying_blocks".to_string(),
            SyncState::Complete => "complete".to_string(),
            SyncState::Failed(msg) => format!("failed:{msg}"),
        }
    }

    /// Deserialize state from a SQLite string.  Returns `None` if the string
    /// is not a recognized state.
    pub fn from_db_string(s: &str) -> Option<SyncState> {
        match s {
            "idle" => Some(SyncState::Idle),
            "downloading_ledger" => Some(SyncState::DownloadingLedger),
            "importing_ledger" => Some(SyncState::ImportingLedger),
            "verifying_ledger" => Some(SyncState::VerifyingLedger),
            "downloading_lookback" => Some(SyncState::DownloadingLookback),
            "replaying_blocks" => Some(SyncState::ReplayingBlocks),
            "complete" => Some(SyncState::Complete),
            other => other
                .strip_prefix("failed:")
                .map(|msg| SyncState::Failed(msg.to_string())),
        }
    }
}

impl fmt::Display for SyncState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncState::Idle => write!(f, "Idle"),
            SyncState::DownloadingLedger => write!(f, "Downloading ledger snapshot"),
            SyncState::ImportingLedger => write!(f, "Importing ledger into database"),
            SyncState::VerifyingLedger => write!(f, "Verifying ledger integrity"),
            SyncState::DownloadingLookback => write!(f, "Downloading lookback blocks"),
            SyncState::ReplayingBlocks => write!(f, "Replaying blocks"),
            SyncState::Complete => write!(f, "Sync complete"),
            SyncState::Failed(msg) => write!(f, "Failed: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// SyncProgress
// ---------------------------------------------------------------------------

/// Tracks progress within the current sync phase for user-facing status.
#[derive(Debug, Clone)]
pub struct SyncProgress {
    /// Current sync state.
    pub state: SyncState,
    /// Progress within the current phase, from 0.0 to 1.0.
    pub phase_progress: f64,
    /// Human-readable detail for the current phase
    /// (e.g. "Downloaded 50/100 MB", "Imported 1000/5000 accounts").
    pub phase_detail: String,
    /// Total elapsed time since the sync operation started.
    pub elapsed: Duration,
    /// When the sync operation started (wall-clock instant).
    pub started_at: Option<Instant>,
    /// Estimated time remaining for the current phase, if calculable.
    pub eta: Option<Duration>,

    // -- Granular catchpoint-catchup counters (issue #941) --------------
    //
    // Mirror go-algorand's `catchup.CatchpointCatchupStats`
    // (`catchup/catchpointService.go`), surfaced by `node.go`'s
    // `catchpointCatchupStatus` on `StatusReport`'s eight
    // `CatchpointCatchup*` fields (`daemon/algod/api/server/v2/handlers.go`'s
    // status handler copies them verbatim into `GET /v2/status`'s
    // `catchpoint-total-accounts`/etc. JSON fields). Populated during the
    // `ImportingLedger` phase (from `catchpoint::importer::import_catchpoint_file_with_progress`,
    // mirroring go's `updateLedgerFetcherProgress`), the `VerifyingLedger`
    // phase (mirroring go's `updateVerifiedCounts`), and the
    // `DownloadingLookback` phase (mirroring go's
    // `updateBlockRetrievalStatistics`). All zero before/outside those
    // phases, exactly like go's stats struct before `CatchpointCatchupService`
    // has made progress.
    /// Total accounts in the catchpoint file, from the file header
    /// (go: `CatchpointCatchupStats.TotalAccounts`).
    pub catchpoint_total_accounts: u64,
    /// Accounts imported into the local database so far
    /// (go: `CatchpointCatchupStats.ProcessedAccounts`).
    pub catchpoint_processed_accounts: u64,
    /// Accounts confirmed against the rebuilt Merkle trie during verification
    /// (go: `CatchpointCatchupStats.VerifiedAccounts`).
    pub catchpoint_verified_accounts: u64,
    /// Total key-value ("box") entries in the catchpoint file, from the file
    /// header (go: `CatchpointCatchupStats.TotalKVs`).
    pub catchpoint_total_kvs: u64,
    /// Key-value entries imported into the local database so far
    /// (go: `CatchpointCatchupStats.ProcessedKVs`).
    pub catchpoint_processed_kvs: u64,
    /// Key-value entries confirmed against the rebuilt Merkle trie during
    /// verification (go: `CatchpointCatchupStats.VerifiedKVs`).
    pub catchpoint_verified_kvs: u64,
    /// Total lookback blocks that need to be downloaded/backfilled after the
    /// catchpoint round (go: `CatchpointCatchupStats.TotalBlocks`).
    pub catchpoint_total_blocks: u64,
    /// Lookback blocks successfully downloaded and stored so far
    /// (go: `CatchpointCatchupStats.AcquiredBlocks`).
    pub catchpoint_acquired_blocks: u64,
}

impl Default for SyncProgress {
    fn default() -> Self {
        SyncProgress {
            state: SyncState::default(),
            phase_progress: 0.0,
            phase_detail: String::new(),
            elapsed: Duration::ZERO,
            started_at: None,
            eta: None,
            catchpoint_total_accounts: 0,
            catchpoint_processed_accounts: 0,
            catchpoint_verified_accounts: 0,
            catchpoint_total_kvs: 0,
            catchpoint_processed_kvs: 0,
            catchpoint_verified_kvs: 0,
            catchpoint_total_blocks: 0,
            catchpoint_acquired_blocks: 0,
        }
    }
}

impl SyncProgress {
    /// Update the elapsed duration from the start instant.
    pub fn update_elapsed(&mut self) {
        if let Some(start) = self.started_at {
            self.elapsed = start.elapsed();
        }
    }

    /// Estimate time remaining based on current phase progress and elapsed time.
    ///
    /// Updates the `eta` field. Returns `None` if progress is zero or complete.
    pub fn estimate_eta(&mut self) {
        if self.phase_progress > 0.0 && self.phase_progress < 1.0 {
            let remaining_fraction = 1.0 - self.phase_progress;
            let elapsed_secs = self.elapsed.as_secs_f64();
            let eta_secs = elapsed_secs * remaining_fraction / self.phase_progress;
            self.eta = Some(Duration::from_secs_f64(eta_secs));
        } else {
            self.eta = None;
        }
    }
}
