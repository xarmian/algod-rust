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

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use algo_ledger::sync::state_machine::{SyncProgress, SyncState};
use algo_ledger::sync::{
    clear_sync_state, persist_sync_state, restore_sync_state, validate_invariants, SyncConfig,
    SyncOrchestrator, WarningSeverity,
};
use rusqlite::Connection;

// ---------------------------------------------------------------------------
// Helper: build a default SyncConfig for tests
// ---------------------------------------------------------------------------

fn test_config() -> SyncConfig {
    SyncConfig {
        catchpoint_label: Some("44000000#ABCDEFG".to_string()),
        algod_url: "http://localhost:4001".to_string(),
        algod_token: "a".repeat(64),
        genesis_id: "testnet-v1.0".to_string(),
        genesis_hash: [0u8; 32],
        db_path: PathBuf::from("/tmp/test-sync.db"),
        concurrency: 4,
        follow_after_sync: false,
        compare_mode: false,
        trie_path: None,
        avm_execute: false,
        fail_fast: true,
        end_round: None,
    }
}

// ===========================================================================
// SyncState tests
// ===========================================================================

#[test]
fn test_state_happy_path_transitions() {
    // Walk the full happy path: Idle -> ... -> Complete
    let states = [
        SyncState::Idle,
        SyncState::DownloadingLedger,
        SyncState::ImportingLedger,
        SyncState::VerifyingLedger,
        SyncState::DownloadingLookback,
        SyncState::ReplayingBlocks,
        SyncState::Complete,
    ];

    for window in states.windows(2) {
        let current = &window[0];
        let next = &window[1];
        assert!(
            current.can_transition_to(next),
            "expected {} -> {} to be valid",
            current,
            next
        );
    }
}

#[test]
fn test_state_next_returns_correct_successor() {
    assert_eq!(SyncState::Idle.next(), Some(SyncState::DownloadingLedger));
    assert_eq!(
        SyncState::DownloadingLedger.next(),
        Some(SyncState::ImportingLedger)
    );
    assert_eq!(
        SyncState::ImportingLedger.next(),
        Some(SyncState::VerifyingLedger)
    );
    assert_eq!(
        SyncState::VerifyingLedger.next(),
        Some(SyncState::DownloadingLookback)
    );
    assert_eq!(
        SyncState::DownloadingLookback.next(),
        Some(SyncState::ReplayingBlocks)
    );
    assert_eq!(SyncState::ReplayingBlocks.next(), Some(SyncState::Complete));
    assert_eq!(SyncState::Complete.next(), None);
    assert_eq!(SyncState::Failed("oops".into()).next(), None);
}

#[test]
fn test_state_invalid_transitions_rejected() {
    // Cannot skip phases.
    assert!(
        !SyncState::Idle.can_transition_to(&SyncState::ImportingLedger),
        "should not skip DownloadingLedger"
    );
    assert!(
        !SyncState::DownloadingLedger.can_transition_to(&SyncState::VerifyingLedger),
        "should not skip ImportingLedger"
    );

    // Cannot go backwards.
    assert!(
        !SyncState::ImportingLedger.can_transition_to(&SyncState::DownloadingLedger),
        "should not go backwards"
    );

    // Terminal states cannot transition to non-Failed states.
    assert!(
        !SyncState::Complete.can_transition_to(&SyncState::Idle),
        "Complete should not transition to Idle"
    );
    assert!(
        !SyncState::Complete.can_transition_to(&SyncState::DownloadingLedger),
        "Complete should not restart"
    );
    assert!(
        !SyncState::Failed("err".into()).can_transition_to(&SyncState::Idle),
        "Failed should not transition to Idle"
    );
}

#[test]
fn test_state_invalid_transitions_exhaustive() {
    // Comprehensive: each non-terminal state should reject transitions to
    // all states except its immediate successor and Failed.
    let all_states = [
        SyncState::Idle,
        SyncState::DownloadingLedger,
        SyncState::ImportingLedger,
        SyncState::VerifyingLedger,
        SyncState::DownloadingLookback,
        SyncState::ReplayingBlocks,
        SyncState::Complete,
    ];

    for state in &all_states {
        if state.is_terminal() {
            continue;
        }
        let expected_next = state.next().unwrap();
        for target in &all_states {
            if *target == expected_next {
                continue; // valid transition
            }
            if matches!(target, SyncState::Failed(_)) {
                continue; // always valid
            }
            assert!(
                !state.can_transition_to(target),
                "{} should NOT transition to {}",
                state,
                target
            );
        }
    }
}

#[test]
fn test_any_state_can_transition_to_failed() {
    let states = [
        SyncState::Idle,
        SyncState::DownloadingLedger,
        SyncState::ImportingLedger,
        SyncState::VerifyingLedger,
        SyncState::DownloadingLookback,
        SyncState::ReplayingBlocks,
        SyncState::Complete,
        SyncState::Failed("previous error".into()),
    ];

    for state in &states {
        assert!(
            state.can_transition_to(&SyncState::Failed("new error".into())),
            "{} should be able to transition to Failed",
            state
        );
    }
}

#[test]
fn test_is_terminal() {
    assert!(!SyncState::Idle.is_terminal());
    assert!(!SyncState::DownloadingLedger.is_terminal());
    assert!(!SyncState::ImportingLedger.is_terminal());
    assert!(!SyncState::VerifyingLedger.is_terminal());
    assert!(!SyncState::DownloadingLookback.is_terminal());
    assert!(!SyncState::ReplayingBlocks.is_terminal());
    assert!(SyncState::Complete.is_terminal());
    assert!(SyncState::Failed("err".into()).is_terminal());
}

#[test]
fn test_is_terminal_with_various_failed_messages() {
    assert!(SyncState::Failed(String::new()).is_terminal());
    assert!(SyncState::Failed("short".into()).is_terminal());
    assert!(SyncState::Failed("a very long error message with many details".into()).is_terminal());
    assert!(SyncState::Failed("error: with: colons".into()).is_terminal());
}

#[test]
fn test_display_formatting() {
    assert_eq!(format!("{}", SyncState::Idle), "Idle");
    assert_eq!(
        format!("{}", SyncState::DownloadingLedger),
        "Downloading ledger snapshot"
    );
    assert_eq!(
        format!("{}", SyncState::ImportingLedger),
        "Importing ledger into database"
    );
    assert_eq!(
        format!("{}", SyncState::VerifyingLedger),
        "Verifying ledger integrity"
    );
    assert_eq!(
        format!("{}", SyncState::DownloadingLookback),
        "Downloading lookback blocks"
    );
    assert_eq!(
        format!("{}", SyncState::ReplayingBlocks),
        "Replaying blocks"
    );
    assert_eq!(format!("{}", SyncState::Complete), "Sync complete");
    assert_eq!(
        format!("{}", SyncState::Failed("disk full".into())),
        "Failed: disk full"
    );
}

#[test]
fn test_display_every_state_is_nonempty() {
    let states = [
        SyncState::Idle,
        SyncState::DownloadingLedger,
        SyncState::ImportingLedger,
        SyncState::VerifyingLedger,
        SyncState::DownloadingLookback,
        SyncState::ReplayingBlocks,
        SyncState::Complete,
        SyncState::Failed("err".into()),
    ];
    for state in &states {
        let display = format!("{state}");
        assert!(
            !display.is_empty(),
            "Display for {state:?} should not be empty"
        );
    }
}

// ===========================================================================
// String serialization round-trip (SQLite persistence)
// ===========================================================================

#[test]
fn test_db_string_round_trip() {
    let states = vec![
        SyncState::Idle,
        SyncState::DownloadingLedger,
        SyncState::ImportingLedger,
        SyncState::VerifyingLedger,
        SyncState::DownloadingLookback,
        SyncState::ReplayingBlocks,
        SyncState::Complete,
        SyncState::Failed("something went wrong".into()),
    ];

    for state in states {
        let serialized = state.to_db_string();
        let deserialized =
            SyncState::from_db_string(&serialized).expect("round-trip should succeed");
        assert_eq!(state, deserialized, "round-trip failed for: {}", serialized);
    }
}

#[test]
fn test_db_string_known_values() {
    assert_eq!(SyncState::Idle.to_db_string(), "idle");
    assert_eq!(
        SyncState::DownloadingLedger.to_db_string(),
        "downloading_ledger"
    );
    assert_eq!(
        SyncState::ImportingLedger.to_db_string(),
        "importing_ledger"
    );
    assert_eq!(
        SyncState::VerifyingLedger.to_db_string(),
        "verifying_ledger"
    );
    assert_eq!(
        SyncState::DownloadingLookback.to_db_string(),
        "downloading_lookback"
    );
    assert_eq!(
        SyncState::ReplayingBlocks.to_db_string(),
        "replaying_blocks"
    );
    assert_eq!(SyncState::Complete.to_db_string(), "complete");
    assert_eq!(
        SyncState::Failed("timeout".into()).to_db_string(),
        "failed:timeout"
    );
}

#[test]
fn test_db_string_unrecognized_returns_none() {
    assert_eq!(SyncState::from_db_string("garbage"), None);
    assert_eq!(SyncState::from_db_string(""), None);
    assert_eq!(SyncState::from_db_string("IDLE"), None); // case sensitive
}

#[test]
fn test_db_string_failed_with_empty_message() {
    let state = SyncState::Failed(String::new());
    let serialized = state.to_db_string();
    assert_eq!(serialized, "failed:");
    let deserialized = SyncState::from_db_string(&serialized).unwrap();
    assert_eq!(deserialized, SyncState::Failed(String::new()));
}

#[test]
fn test_db_string_failed_with_colons_in_message() {
    let state = SyncState::Failed("error: something: details".into());
    let serialized = state.to_db_string();
    assert_eq!(serialized, "failed:error: something: details");
    let deserialized = SyncState::from_db_string(&serialized).unwrap();
    assert_eq!(
        deserialized,
        SyncState::Failed("error: something: details".into())
    );
}

#[test]
fn test_db_string_failed_with_special_chars() {
    let messages = vec![
        "error\nwith\nnewlines",
        "error\twith\ttabs",
        "error with 'single quotes'",
        "error with \"double quotes\"",
        "error with unicode: \u{1f600}",
        "error with null-like: \\0",
        "error:with:many:colons:in:message",
    ];

    for msg in messages {
        let state = SyncState::Failed(msg.to_string());
        let serialized = state.to_db_string();
        let deserialized = SyncState::from_db_string(&serialized).unwrap();
        assert_eq!(
            deserialized,
            SyncState::Failed(msg.to_string()),
            "round-trip failed for message: {msg:?}"
        );
    }
}

// ===========================================================================
// SyncProgress tests
// ===========================================================================

#[test]
fn test_sync_progress_default() {
    let progress = SyncProgress::default();
    assert_eq!(progress.state, SyncState::Idle);
    assert_eq!(progress.phase_progress, 0.0);
    assert!(progress.phase_detail.is_empty());
    assert!(progress.started_at.is_none());
}

#[test]
fn test_sync_progress_eta_at_zero_progress() {
    let mut progress = SyncProgress {
        elapsed: Duration::from_secs(10),
        ..SyncProgress::default()
    };
    progress.estimate_eta();
    assert!(
        progress.eta.is_none(),
        "ETA should be None when progress is 0.0"
    );
}

#[test]
fn test_sync_progress_eta_at_complete() {
    let mut progress = SyncProgress {
        elapsed: Duration::from_secs(10),
        phase_progress: 1.0,
        ..SyncProgress::default()
    };
    progress.estimate_eta();
    assert!(
        progress.eta.is_none(),
        "ETA should be None when progress is 1.0 (complete)"
    );
}

#[test]
fn test_sync_progress_eta_at_half() {
    let mut progress = SyncProgress {
        elapsed: Duration::from_secs(10),
        phase_progress: 0.5,
        ..SyncProgress::default()
    };
    progress.estimate_eta();
    let eta = progress
        .eta
        .expect("ETA should be Some when progress is 0.5");
    // At 50% done after 10s, ETA should be approximately 10s remaining.
    let eta_secs = eta.as_secs_f64();
    assert!(
        (eta_secs - 10.0).abs() < 0.1,
        "ETA should be ~10s, got {eta_secs}"
    );
}

#[test]
fn test_sync_progress_eta_at_quarter() {
    let mut progress = SyncProgress {
        elapsed: Duration::from_secs(30),
        phase_progress: 0.25,
        ..SyncProgress::default()
    };
    progress.estimate_eta();
    let eta = progress
        .eta
        .expect("ETA should be Some when progress is 0.25");
    // At 25% done after 30s, ETA should be approximately 90s remaining.
    let eta_secs = eta.as_secs_f64();
    assert!(
        (eta_secs - 90.0).abs() < 0.1,
        "ETA should be ~90s, got {eta_secs}"
    );
}

#[test]
fn test_sync_progress_update_elapsed() {
    let mut progress = SyncProgress {
        started_at: Some(Instant::now()),
        ..SyncProgress::default()
    };
    // Small sleep not needed — just verify update_elapsed does not panic
    // and sets a non-zero elapsed when started_at is set.
    progress.update_elapsed();
    // Elapsed should be very small but >= 0.
    // Elapsed is set (may be zero if the instant is very close).
    // Just verify update_elapsed() does not panic.
}

#[test]
fn test_sync_progress_update_elapsed_without_start() {
    let mut progress = SyncProgress::default();
    assert!(progress.started_at.is_none());
    progress.update_elapsed();
    // Should remain zero when started_at is not set.
    assert_eq!(progress.elapsed, Duration::ZERO);
}

// ===========================================================================
// SyncOrchestrator tests
// ===========================================================================

#[test]
fn test_orchestrator_initial_state() {
    let orch = SyncOrchestrator::new(test_config());
    assert_eq!(*orch.state(), SyncState::Idle);
    assert_eq!(orch.progress().state, SyncState::Idle);
    assert_eq!(orch.progress().phase_progress, 0.0);
}

#[test]
fn test_orchestrator_config_accessible() {
    let orch = SyncOrchestrator::new(test_config());
    assert_eq!(orch.config().genesis_id, "testnet-v1.0");
    assert_eq!(orch.config().concurrency, 4);
    assert_eq!(
        orch.config().catchpoint_label,
        Some("44000000#ABCDEFG".to_string())
    );
}

#[tokio::test]
async fn test_orchestrator_run_stubs_complete() {
    let mut orch = SyncOrchestrator::new(test_config());
    let result = orch.run().await;
    assert!(
        result.is_ok(),
        "stub run should succeed: {:?}",
        result.err()
    );
    assert_eq!(*orch.state(), SyncState::Complete);
}

#[tokio::test]
async fn test_orchestrator_run_result_fields() {
    let mut orch = SyncOrchestrator::new(test_config());
    let result = orch.run().await.expect("stub run should succeed");
    // Stubs report zero for placeholder values.
    assert_eq!(result.final_round, 0);
    assert_eq!(result.accounts_imported, 0);
    assert_eq!(result.blocks_replayed, 0);
    assert!(result.duration.as_nanos() > 0, "duration should be nonzero");
}

#[tokio::test]
async fn test_orchestrator_progress_callback_invoked() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = call_count.clone();

    let mut orch = SyncOrchestrator::new(test_config());
    orch.set_progress_callback(Box::new(move |_progress| {
        counter.fetch_add(1, Ordering::SeqCst);
    }));

    let result = orch.run().await;
    assert!(result.is_ok(), "stub run should succeed");

    // NoopBackend walks through all state transitions (Idle -> DL -> Import ->
    // Verify -> Lookback -> Replay), each transition notifies once, plus the
    // final Complete transition. Should be at least 6 calls.
    let count = call_count.load(Ordering::SeqCst);
    assert!(
        count >= 6,
        "progress callback should be invoked at least 6 times (once per transition), got {count}"
    );
}

#[tokio::test]
async fn test_orchestrator_cancellation_before_run() {
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel(); // Cancel immediately before run()

    let mut orch = SyncOrchestrator::new(test_config());
    orch.set_cancel(cancel);

    // With NoopBackend, phases are skipped via transition(), so cancellation
    // is only checked within actual phase implementations (which are never
    // called for NoopBackend). The stub path should still complete.
    let result = orch.run().await;
    // NoopBackend doesn't check cancellation in its fast path,
    // so it should still succeed.
    assert!(
        result.is_ok(),
        "noop run should still succeed even with pre-cancelled token"
    );
    assert_eq!(*orch.state(), SyncState::Complete);
}

// ===========================================================================
// SyncConfig tests
// ===========================================================================

#[test]
fn test_sync_config_defaults() {
    let config = test_config();
    assert!(!config.follow_after_sync);
    assert!(!config.compare_mode);
    assert!(!config.avm_execute);
    assert!(config.fail_fast);
    assert!(config.trie_path.is_none());
}

#[test]
fn test_sync_config_various_constructions() {
    let config = SyncConfig {
        catchpoint_label: None,
        algod_url: "http://example.com:8080".to_string(),
        algod_token: "b".repeat(64),
        genesis_id: "mainnet-v1.0".to_string(),
        genesis_hash: [0xABu8; 32],
        db_path: PathBuf::from("/var/data/ledger.db"),
        concurrency: 16,
        follow_after_sync: true,
        compare_mode: true,
        trie_path: Some(PathBuf::from("/var/data/trie")),
        avm_execute: true,
        fail_fast: false,
        end_round: None,
    };

    assert!(config.catchpoint_label.is_none());
    assert_eq!(config.concurrency, 16);
    assert!(config.follow_after_sync);
    assert!(config.compare_mode);
    assert!(config.avm_execute);
    assert!(!config.fail_fast);
    assert_eq!(config.trie_path, Some(PathBuf::from("/var/data/trie")));
}

#[tokio::test]
async fn test_follow_after_sync_skipped_for_noop() {
    // Even with follow_after_sync=true, NoopBackend should skip follow mode
    // because is_noop() returns true.
    let mut config = test_config();
    config.follow_after_sync = true;

    let mut orch = SyncOrchestrator::new(config);
    let result = orch.run().await;
    assert!(
        result.is_ok(),
        "noop run with follow_after_sync=true should succeed: {:?}",
        result.err()
    );
    assert_eq!(*orch.state(), SyncState::Complete);
}

// ===========================================================================
// State persistence tests (using in-memory SQLite)
// ===========================================================================

fn create_test_db() -> Connection {
    // G6 part 3: sync-state persistence moved off `algod_rust_meta`
    // onto namespaced rows in `catchpointstate`.
    let conn = Connection::open_in_memory().expect("failed to open in-memory db");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS catchpointstate (
             id     TEXT PRIMARY KEY,
             intval INTEGER,
             strval TEXT
         );",
    )
    .expect("failed to create catchpointstate table");
    conn
}

#[test]
fn test_persist_and_restore_sync_state() {
    let conn = create_test_db();

    let state = SyncState::ImportingLedger;
    persist_sync_state(
        &conn,
        &state,
        Some("44000000#ABCDEFG"),
        Some(44_000_000),
        Some("/tmp/catchpoint.tar.gz"),
    )
    .expect("persist should succeed");

    let restored = restore_sync_state(&conn)
        .expect("restore should not error")
        .expect("restored state should be Some");

    assert_eq!(restored.state, SyncState::ImportingLedger);
    assert_eq!(
        restored.catchpoint_label,
        Some("44000000#ABCDEFG".to_string())
    );
    assert_eq!(restored.catchpoint_round, Some(44_000_000));
    assert_eq!(
        restored.catchpoint_file,
        Some("/tmp/catchpoint.tar.gz".to_string())
    );
}

#[test]
fn test_persist_failed_state_with_special_chars() {
    let conn = create_test_db();

    let state = SyncState::Failed("error: something: with: colons\nand newlines".into());
    persist_sync_state(&conn, &state, None, None, None).expect("persist should succeed");

    let restored = restore_sync_state(&conn)
        .expect("restore should not error")
        .expect("restored state should be Some");

    assert_eq!(restored.state, state);
}

#[test]
fn test_clear_sync_state_removes_data() {
    let conn = create_test_db();

    persist_sync_state(
        &conn,
        &SyncState::DownloadingLedger,
        Some("12345#HASH"),
        Some(12345),
        Some("/path/to/file"),
    )
    .expect("persist should succeed");

    // Verify state is present.
    assert!(restore_sync_state(&conn).unwrap().is_some());

    // Clear it.
    clear_sync_state(&conn).expect("clear should succeed");

    // Verify state is gone.
    let restored = restore_sync_state(&conn).expect("restore should not error");
    assert!(
        restored.is_none(),
        "state should be None after clear, got {:?}",
        restored
    );
}

#[test]
fn test_restore_from_empty_db_returns_none() {
    let conn = Connection::open_in_memory().expect("failed to open in-memory db");
    // No tables at all — restore should return None.
    let restored = restore_sync_state(&conn).expect("restore should not error on empty db");
    assert!(
        restored.is_none(),
        "should return None on empty db, got {:?}",
        restored
    );
}

#[test]
fn test_restore_from_empty_meta_table_returns_none() {
    let conn = create_test_db();
    // Meta table exists but has no rows.
    let restored = restore_sync_state(&conn).expect("restore should not error");
    assert!(
        restored.is_none(),
        "should return None when meta table is empty, got {:?}",
        restored
    );
}

#[test]
fn test_persist_overwrite() {
    let conn = create_test_db();

    // Persist initial state.
    persist_sync_state(&conn, &SyncState::Idle, None, None, None)
        .expect("first persist should succeed");

    // Overwrite with a new state.
    persist_sync_state(
        &conn,
        &SyncState::ReplayingBlocks,
        Some("99999#XYZ"),
        Some(99999),
        None,
    )
    .expect("overwrite should succeed");

    let restored = restore_sync_state(&conn)
        .expect("restore should not error")
        .expect("restored state should be Some");

    assert_eq!(restored.state, SyncState::ReplayingBlocks);
    assert_eq!(restored.catchpoint_label, Some("99999#XYZ".to_string()));
    assert_eq!(restored.catchpoint_round, Some(99999));
}

#[test]
fn test_clear_on_empty_db_does_not_error() {
    let conn = Connection::open_in_memory().expect("failed to open in-memory db");
    // No meta table — clear should be a no-op.
    let result = clear_sync_state(&conn);
    assert!(result.is_ok(), "clear on empty db should not error");
}

#[test]
fn test_persist_all_states_round_trip_via_db() {
    let conn = create_test_db();

    let states = vec![
        SyncState::Idle,
        SyncState::DownloadingLedger,
        SyncState::ImportingLedger,
        SyncState::VerifyingLedger,
        SyncState::DownloadingLookback,
        SyncState::ReplayingBlocks,
        SyncState::Complete,
        SyncState::Failed("database error: disk full".into()),
    ];

    for state in states {
        persist_sync_state(&conn, &state, None, None, None).expect("persist should succeed");
        let restored = restore_sync_state(&conn)
            .expect("restore should not error")
            .expect("restored state should be Some");
        assert_eq!(
            restored.state, state,
            "DB round-trip failed for state: {:?}",
            state
        );
    }
}

// ===========================================================================
// WarningSeverity tests
// ===========================================================================

#[test]
fn test_warning_severity_display() {
    assert_eq!(format!("{}", WarningSeverity::Info), "info");
    assert_eq!(format!("{}", WarningSeverity::Warning), "warning");
    assert_eq!(format!("{}", WarningSeverity::Error), "error");
}

#[test]
fn test_warning_severity_equality() {
    assert_eq!(WarningSeverity::Info, WarningSeverity::Info);
    assert_eq!(WarningSeverity::Warning, WarningSeverity::Warning);
    assert_eq!(WarningSeverity::Error, WarningSeverity::Error);
    assert_ne!(WarningSeverity::Info, WarningSeverity::Warning);
    assert_ne!(WarningSeverity::Warning, WarningSeverity::Error);
}

// ===========================================================================
// Ledger invariant validation tests
// ===========================================================================

/// Create an in-memory DB with the minimal schema needed for invariant checks.
fn create_invariant_test_db() -> Connection {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch(
        "
        CREATE TABLE acctrounds (
            id    TEXT PRIMARY KEY,
            rnd   INTEGER
        );

        CREATE TABLE accounttotals (
            id                           TEXT PRIMARY KEY,
            online                       INTEGER,
            onlinerewardunits            INTEGER,
            offline                      INTEGER,
            offlinerewardunits           INTEGER,
            notparticipating             INTEGER,
            notparticipatingrewardunits  INTEGER,
            rewardslevel                 INTEGER
        );

        CREATE TABLE accountbase (
            addrid                  INTEGER PRIMARY KEY NOT NULL,
            address                 BLOB NOT NULL,
            data                    BLOB,
            normalizedonlinebalance INTEGER
        );

        CREATE TABLE catchpointstate (
            id TEXT PRIMARY KEY,
            intval INTEGER,
            strval TEXT
        );
        ",
    )
    .expect("create schema");
    conn
}

/// Encode a minimal account data blob with status and micro_algos.
fn encode_minimal_account(status: u8, micro_algos: u64) -> Vec<u8> {
    let mut pairs: Vec<(rmpv::Value, rmpv::Value)> = Vec::new();
    if status != 0 {
        pairs.push((
            rmpv::Value::String("a".into()),
            rmpv::Value::from(status as u64),
        ));
    }
    if micro_algos != 0 {
        pairs.push((
            rmpv::Value::String("b".into()),
            rmpv::Value::from(micro_algos),
        ));
    }
    let val = rmpv::Value::Map(pairs);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &val).expect("msgpack encode");
    buf
}

#[test]
fn test_validate_invariants_all_pass() {
    let conn = create_invariant_test_db();

    // Set up consistent data: round=100, two accounts (one online, one offline).
    conn.execute(
        "INSERT INTO acctrounds (id, rnd) VALUES ('acctbase', 100)",
        [],
    )
    .unwrap();

    // Online account: 1000 micro-algos
    let online_data = encode_minimal_account(1, 1000);
    conn.execute(
        "INSERT INTO accountbase (addrid, address, data, normalizedonlinebalance) \
         VALUES (1, X'0101010101010101010101010101010101010101010101010101010101010101', ?1, 100)",
        rusqlite::params![online_data],
    )
    .unwrap();

    // Offline account: 2000 micro-algos
    let offline_data = encode_minimal_account(0, 2000);
    conn.execute(
        "INSERT INTO accountbase (addrid, address, data, normalizedonlinebalance) \
         VALUES (2, X'0202020202020202020202020202020202020202020202020202020202020202', ?1, 0)",
        rusqlite::params![offline_data],
    )
    .unwrap();

    // Matching totals.
    conn.execute(
        "INSERT INTO accounttotals (id, online, onlinerewardunits, offline, offlinerewardunits, \
         notparticipating, notparticipatingrewardunits, rewardslevel) \
         VALUES ('', 1000, 0, 2000, 0, 0, 0, 0)",
        [],
    )
    .unwrap();

    // Catchpointstate with an entry.
    conn.execute(
        "INSERT INTO catchpointstate (id, intval) VALUES ('dbRound', 100)",
        [],
    )
    .unwrap();

    let warnings = validate_invariants(&conn);
    assert!(
        warnings.is_empty(),
        "expected no warnings, got: {:?}",
        warnings
            .iter()
            .map(|w| format!("[{}] {}", w.name, w.detail))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_validate_invariants_missing_acctrounds() {
    let conn = create_invariant_test_db();
    // No acctrounds row inserted.

    // Add empty accounttotals to avoid that warning dominating.
    conn.execute(
        "INSERT INTO accounttotals (id, online, onlinerewardunits, offline, offlinerewardunits, \
         notparticipating, notparticipatingrewardunits, rewardslevel) \
         VALUES ('', 0, 0, 0, 0, 0, 0, 0)",
        [],
    )
    .unwrap();

    let warnings = validate_invariants(&conn);
    let acctrounds_warning = warnings.iter().find(|w| w.name == "acctrounds_missing");
    assert!(
        acctrounds_warning.is_some(),
        "expected acctrounds_missing warning, got: {:?}",
        warnings.iter().map(|w| &w.name).collect::<Vec<_>>()
    );
    assert_eq!(acctrounds_warning.unwrap().severity, WarningSeverity::Error);
}

#[test]
fn test_validate_invariants_totals_mismatch() {
    let conn = create_invariant_test_db();

    conn.execute(
        "INSERT INTO acctrounds (id, rnd) VALUES ('acctbase', 50)",
        [],
    )
    .unwrap();

    // One online account with 5000 micro-algos.
    let online_data = encode_minimal_account(1, 5000);
    conn.execute(
        "INSERT INTO accountbase (addrid, address, data, normalizedonlinebalance) \
         VALUES (1, X'0101010101010101010101010101010101010101010101010101010101010101', ?1, 50)",
        rusqlite::params![online_data],
    )
    .unwrap();

    // Stored totals say online=9999 (mismatch with actual 5000).
    conn.execute(
        "INSERT INTO accounttotals (id, online, onlinerewardunits, offline, offlinerewardunits, \
         notparticipating, notparticipatingrewardunits, rewardslevel) \
         VALUES ('', 9999, 0, 0, 0, 0, 0, 0)",
        [],
    )
    .unwrap();

    let warnings = validate_invariants(&conn);
    let totals_warning = warnings.iter().find(|w| w.name == "accounttotals_online");
    assert!(
        totals_warning.is_some(),
        "expected accounttotals_online warning"
    );
    assert_eq!(totals_warning.unwrap().severity, WarningSeverity::Warning);
    assert!(totals_warning.unwrap().detail.contains("9999"));
    assert!(totals_warning.unwrap().detail.contains("5000"));
}

#[test]
fn test_validate_invariants_missing_accounttotals() {
    let conn = create_invariant_test_db();

    conn.execute(
        "INSERT INTO acctrounds (id, rnd) VALUES ('acctbase', 10)",
        [],
    )
    .unwrap();

    // No accounttotals row.
    let warnings = validate_invariants(&conn);
    let missing = warnings.iter().find(|w| w.name == "accounttotals_missing");
    assert!(missing.is_some(), "expected accounttotals_missing warning");
    assert_eq!(missing.unwrap().severity, WarningSeverity::Error);
}

#[test]
fn test_validate_invariants_empty_catchpointstate() {
    let conn = create_invariant_test_db();

    conn.execute(
        "INSERT INTO acctrounds (id, rnd) VALUES ('acctbase', 10)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO accounttotals (id, online, onlinerewardunits, offline, offlinerewardunits, \
         notparticipating, notparticipatingrewardunits, rewardslevel) \
         VALUES ('', 0, 0, 0, 0, 0, 0, 0)",
        [],
    )
    .unwrap();
    // catchpointstate table exists but is empty.

    let warnings = validate_invariants(&conn);
    let cp_warning = warnings.iter().find(|w| w.name == "catchpointstate_empty");
    assert!(
        cp_warning.is_some(),
        "expected catchpointstate_empty warning"
    );
    assert_eq!(cp_warning.unwrap().severity, WarningSeverity::Info);
}

#[test]
fn test_validate_invariants_no_catchpointstate_table() {
    // Database without the catchpointstate table at all.
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch(
        "
        CREATE TABLE acctrounds (id TEXT PRIMARY KEY, rnd INTEGER);
        CREATE TABLE accounttotals (
            id TEXT PRIMARY KEY, online INTEGER, onlinerewardunits INTEGER,
            offline INTEGER, offlinerewardunits INTEGER,
            notparticipating INTEGER, notparticipatingrewardunits INTEGER,
            rewardslevel INTEGER
        );
        CREATE TABLE accountbase (
            addrid INTEGER PRIMARY KEY NOT NULL, address BLOB NOT NULL,
            data BLOB, normalizedonlinebalance INTEGER
        );
        INSERT INTO acctrounds (id, rnd) VALUES ('acctbase', 5);
        INSERT INTO accounttotals VALUES ('', 0, 0, 0, 0, 0, 0, 0);
        ",
    )
    .unwrap();

    let warnings = validate_invariants(&conn);
    // No catchpointstate_empty warning since the table doesn't exist.
    let cp_warning = warnings
        .iter()
        .find(|w| w.name.starts_with("catchpointstate"));
    assert!(
        cp_warning.is_none(),
        "should not warn about catchpointstate when table doesn't exist"
    );
}

#[test]
fn test_validate_invariants_multiple_account_statuses() {
    let conn = create_invariant_test_db();

    conn.execute(
        "INSERT INTO acctrounds (id, rnd) VALUES ('acctbase', 200)",
        [],
    )
    .unwrap();

    // Online: 1000
    let d1 = encode_minimal_account(1, 1000);
    conn.execute(
        "INSERT INTO accountbase (addrid, address, data, normalizedonlinebalance) \
         VALUES (1, X'0101010101010101010101010101010101010101010101010101010101010101', ?1, 10)",
        rusqlite::params![d1],
    )
    .unwrap();

    // Offline: 2000
    let d2 = encode_minimal_account(0, 2000);
    conn.execute(
        "INSERT INTO accountbase (addrid, address, data, normalizedonlinebalance) \
         VALUES (2, X'0202020202020202020202020202020202020202020202020202020202020202', ?1, 0)",
        rusqlite::params![d2],
    )
    .unwrap();

    // NotParticipating: 3000
    let d3 = encode_minimal_account(2, 3000);
    conn.execute(
        "INSERT INTO accountbase (addrid, address, data, normalizedonlinebalance) \
         VALUES (3, X'0303030303030303030303030303030303030303030303030303030303030303', ?1, 0)",
        rusqlite::params![d3],
    )
    .unwrap();

    // Matching totals.
    conn.execute(
        "INSERT INTO accounttotals (id, online, onlinerewardunits, offline, offlinerewardunits, \
         notparticipating, notparticipatingrewardunits, rewardslevel) \
         VALUES ('', 1000, 0, 2000, 0, 3000, 0, 0)",
        [],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO catchpointstate (id, intval) VALUES ('dbRound', 200)",
        [],
    )
    .unwrap();

    let warnings = validate_invariants(&conn);
    assert!(
        warnings.is_empty(),
        "expected no warnings with 3 matching status categories, got: {:?}",
        warnings
            .iter()
            .map(|w| format!("[{}] {}", w.name, w.detail))
            .collect::<Vec<_>>()
    );
}
