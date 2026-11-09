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

//! Issue #2141: the import's atomic cutover and the resume marker that
//! records it must commit together, so the marker and the live tables can
//! never disagree.
//!
//! The invariant every test below asserts after a failure or a kill: the
//! marker is at `ImportingLedger` or later if and only if the live tables are
//! the imported snapshot. Failures are injected with the orchestrator's
//! instance-scoped [`ImportFailpoint`]s; the hard-kill tests re-run this test
//! binary as a child that is killed (or aborts itself) around the cutover.

use super::*;
use crate::catchpoint::writer::{export_catchpoint_file, ExportOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub(super) const ROUND: u64 = 500;

struct CopyBackend {
    source_file: PathBuf,
}

impl SyncBackend for CopyBackend {
    fn download_catchpoint(
        &self,
        _genesis_id: &str,
        _round: u64,
        dest_path: &Path,
    ) -> Result<(), AlgoError> {
        std::fs::copy(&self.source_file, dest_path)
            .map(|_| ())
            .map_err(|e| AlgoError::Ledger {
                message: format!("copy failed: {e}"),
            })
    }
    fn fetch_block_raw(&self, _round: u64) -> Result<(String, Vec<u8>, Vec<u8>), AlgoError> {
        Err(AlgoError::Network {
            message: "not served".to_string(),
        })
    }
    fn fetch_block(&self, _round: u64) -> Result<Block, AlgoError> {
        unimplemented!("not exercised")
    }
    fn get_current_round(&self) -> Result<u64, AlgoError> {
        unimplemented!("not exercised")
    }
    fn discover_catchpoint(&self) -> Result<Option<String>, AlgoError> {
        Ok(None)
    }
}

fn config(db_path: PathBuf, label: &str) -> SyncConfig {
    SyncConfig {
        catchpoint_label: Some(label.to_string()),
        algod_url: String::new(),
        algod_token: String::new(),
        genesis_id: "test".to_string(),
        genesis_hash: [0u8; 32],
        db_path,
        concurrency: 1,
        follow_after_sync: false,
        compare_mode: false,
        trie_path: None,
        avm_execute: false,
        fail_fast: false,
        end_round: None,
        accounts_rebuild_synchronous_mode: 1,
        catchup_block_download_retry_attempts:
            crate::catchpoint::DEFAULT_CATCHUP_BLOCK_DOWNLOAD_RETRY_ATTEMPTS,
        handoff_min_lag_rounds: DEFAULT_HANDOFF_MIN_LAG_ROUNDS,
    }
}

/// Export a tiny (empty-account) catchpoint file at `ROUND`; returns its
/// path and label.
fn export_tiny_catchpoint(dir: &Path) -> (PathBuf, String) {
    export_tiny_catchpoint_as(dir, "source-catchpoint.tar.gz", 7)
}

/// [`export_tiny_catchpoint`] to `dir/name`, with the block header digest
/// `digest` (so another digest gives another label for the same round).
pub(super) fn export_tiny_catchpoint_as(dir: &Path, name: &str, digest: u8) -> (PathBuf, String) {
    export_tiny_catchpoint_at(dir, name, digest, ROUND)
}

/// [`export_tiny_catchpoint_as`] at `round` instead of [`ROUND`].
fn export_tiny_catchpoint_at(dir: &Path, name: &str, digest: u8, round: u64) -> (PathBuf, String) {
    let src = Connection::open_in_memory().unwrap();
    src.execute_batch(
        "CREATE TABLE accountbase (addrid INTEGER PRIMARY KEY NOT NULL, address BLOB NOT NULL, data BLOB, normalizedonlinebalance INTEGER);
        CREATE TABLE resources (addrid INTEGER NOT NULL, aidx INTEGER NOT NULL, data BLOB NOT NULL, ctype INTEGER NOT NULL DEFAULT -1, PRIMARY KEY (addrid, aidx)) WITHOUT ROWID;
        CREATE TABLE kvstore (key BLOB PRIMARY KEY, value BLOB);
        CREATE TABLE onlineaccounts (address BLOB NOT NULL, updround INTEGER NOT NULL, normalizedonlinebalance INTEGER NOT NULL, votelastvalid INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (address, updround));
        CREATE TABLE onlineroundparamstail (rnd INTEGER PRIMARY KEY NOT NULL, data BLOB NOT NULL);
        CREATE TABLE stateproofverification (lastattestedround INTEGER PRIMARY KEY NOT NULL, verificationcontext BLOB NOT NULL);
        CREATE TABLE accounttotals (id TEXT PRIMARY KEY, online INTEGER, onlinerewardunits INTEGER, offline INTEGER, offlinerewardunits INTEGER, notparticipating INTEGER, notparticipatingrewardunits INTEGER, rewardslevel INTEGER);
        INSERT INTO accounttotals VALUES('', 0, 0, 0, 0, 0, 0, 0);",
    )
    .unwrap();
    let path = dir.join(name);
    let exported = export_catchpoint_file(
        &src,
        &path,
        &ExportOptions {
            balances_round: round,
            blocks_round: round,
            block_header_digest: [digest; 32],
            ..Default::default()
        },
    )
    .unwrap();
    (path, exported.label)
}

fn orchestrator(db_path: PathBuf, label: &str, source: &Path) -> SyncOrchestrator {
    SyncOrchestrator::with_backend(
        config(db_path, label),
        CopyBackend {
            source_file: source.to_path_buf(),
        },
    )
}

/// Whether the live tables are the imported snapshot.
fn snapshot_is_live(conn: &Connection) -> bool {
    conn.query_row(
        "SELECT rnd FROM acctrounds WHERE id = 'acctbase'",
        [],
        |row| row.get::<_, i64>(0),
    )
    .is_ok_and(|rnd| rnd == ROUND as i64)
}

/// The invariant: the marker is at `ImportingLedger` or later iff the live
/// tables are the snapshot. Returns whether the ledger is cut over.
fn assert_marker_agrees_with_ledger(
    db_path: &Path,
    label: &str,
    source: &Path,
    what: &str,
) -> bool {
    let conn = orchestrator(db_path.to_path_buf(), label, source)
        .open_db()
        .unwrap();
    let live = snapshot_is_live(&conn);
    let marker = restore_sync_state(&conn).unwrap();
    let says_cut_over = marker
        .as_ref()
        .is_some_and(|m| phase_ordinal(&m.state) >= phase_ordinal(&SyncState::ImportingLedger));
    assert_eq!(
        says_cut_over, live,
        "{what}: marker {marker:?} disagrees with the ledger (snapshot live: {live})"
    );
    // The persisted flag itself (not just the state ordinal) must equal
    // "the live tables are the snapshot", both as read back and as the raw row.
    if let Some(m) = &marker {
        assert_eq!(m.cut_over, Some(live), "{what}: flag of {m:?}");
        assert_eq!(m.is_cut_over(), live, "{what}");
    }
    let raw: Option<i64> = conn
        .query_row(
            "SELECT intval FROM catchpointstate WHERE id = 'algod_rust_sync_cut_over'",
            [],
            |row| row.get(0),
        )
        .ok();
    assert_eq!(
        raw,
        marker.as_ref().map(|_| i64::from(live)),
        "{what}: raw cut-over flag row"
    );
    live
}

/// A new "process" that resumes the marker and is aborted straight away, as
/// `DELETE /v2/catchup` would right after a restart. Returns the run's error.
fn resume_and_abort(db_path: PathBuf, label: &str, source: &Path) -> String {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .build()
        .unwrap();
    let mut o = orchestrator(db_path, label, source);
    let token = CancellationToken::new();
    token.cancel();
    o.set_abort(token.clone());
    o.set_cancel(token);
    rt.block_on(o.run()).unwrap_err().to_string()
}

#[test]
fn a_failure_at_any_point_around_the_cutover_leaves_marker_and_ledger_agreeing() {
    let src = tempfile::tempdir().unwrap();
    let (file, label) = export_tiny_catchpoint(src.path());
    for (failpoint, cut_over) in [
        (ImportFailpoint::BeforeCutoverCommit, false),
        (ImportFailpoint::AfterCutoverCommit, true),
        (ImportFailpoint::InitializeMetaFails, true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("ledger");
        let what = format!("{failpoint:?}");

        let mut o = orchestrator(db.clone(), &label, &file);
        o.run_download_ledger().unwrap();
        o.set_import_failpoint(Some(failpoint));
        assert!(o.run_import_ledger().is_err(), "{what}");
        drop(o);

        let live = assert_marker_agrees_with_ledger(&db, &label, &file, &what);
        assert_eq!(live, cut_over, "{what}");

        // The next process resumes the marker and the user aborts at once.
        let err = resume_and_abort(db.clone(), &label, &file);
        let live = assert_marker_agrees_with_ledger(&db, &label, &file, &format!("{what}+abort"));
        assert_eq!(
            live, cut_over,
            "{what}: an abort must not change the ledger"
        );
        if cut_over {
            // An abort after the cutover keeps the marker (#2136/#2180).
            assert!(!err.contains("aborted by user"), "{what}: {err}");
            let conn = orchestrator(db.clone(), &label, &file).open_db().unwrap();
            assert!(restore_sync_state(&conn).unwrap().is_some(), "{what}");
        } else {
            // Before the cutover the abort discards everything.
            assert!(err.contains("aborted by user"), "{what}: {err}");
            let conn = orchestrator(db.clone(), &label, &file).open_db().unwrap();
            assert!(restore_sync_state(&conn).unwrap().is_none(), "{what}");
        }
    }
}

#[test]
fn a_marker_at_the_import_state_without_a_cutover_is_not_taken_for_one() {
    // The import state is entered before the cutover: a shutdown inside it
    // persists `ImportingLedger` while the live tables are untouched.
    let src = tempfile::tempdir().unwrap();
    let (file, label) = export_tiny_catchpoint(src.path());
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger");
    let mut o = orchestrator(db.clone(), &label, &file);
    o.run_download_ledger().unwrap();
    o.transition(SyncState::ImportingLedger).unwrap();
    let _ = o.handle_cancellation();
    drop(o);
    let conn = orchestrator(db.clone(), &label, &file).open_db().unwrap();
    assert!(!snapshot_is_live(&conn));
    drop(conn);
    // A resumed abort must discard it: nothing was cut over.
    let err = resume_and_abort(db.clone(), &label, &file);
    assert!(err.contains("aborted by user"), "{err}");
    let conn = orchestrator(db, &label, &file).open_db().unwrap();
    assert!(restore_sync_state(&conn).unwrap().is_none());
}

// ---- hard kills ----------------------------------------------------------

const CHILD_ENV: &str = "CUTOVER_KILL_CHILD_DIR";
const FILE_ENV: &str = "CUTOVER_KILL_FILE";
const LABEL_ENV: &str = "CUTOVER_KILL_LABEL";
const ABORT_ENV: &str = "CUTOVER_KILL_ABORT_AFTER_COMMIT";

/// The child half. Not a test on its own: with `CUTOVER_KILL_CHILD_DIR` unset
/// it returns at once. Otherwise it imports the catchpoint into a fresh ledger
/// directory over and over (recording the current one in `current`) until the
/// parent kills it; with `CUTOVER_KILL_ABORT_AFTER_COMMIT` set it instead
/// aborts the process right after the first cutover commit.
#[test]
fn cutover_kill_child() {
    let Ok(dir) = std::env::var(CHILD_ENV) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let file = PathBuf::from(std::env::var(FILE_ENV).unwrap());
    let label = std::env::var(LABEL_ENV).unwrap();
    let abort_after_commit = std::env::var(ABORT_ENV).is_ok();
    for i in 0u32.. {
        let run_dir = dir.join(format!("run-{i}"));
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::write(dir.join("current"), i.to_string()).unwrap();
        let mut o = orchestrator(run_dir.join("ledger"), &label, &file);
        if abort_after_commit {
            o.set_import_failpoint(Some(ImportFailpoint::AbortAfterCutoverCommit));
        }
        o.run_download_ledger().unwrap();
        o.run_import_ledger().unwrap();
        if abort_after_commit {
            unreachable!("the failpoint aborts the process");
        }
    }
}

fn spawn_child(
    dir: &Path,
    file: &Path,
    label: &str,
    abort_after_commit: bool,
) -> std::process::Child {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "--exact",
        "sync::cutover_marker_tests::cutover_kill_child",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(CHILD_ENV, dir)
    .env(FILE_ENV, file)
    .env(LABEL_ENV, label)
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    if abort_after_commit {
        cmd.env(ABORT_ENV, "1");
    }
    cmd.spawn().unwrap()
}

fn current_run(dir: &Path) -> Option<PathBuf> {
    let i = std::fs::read_to_string(dir.join("current")).ok()?;
    let run = dir.join(format!("run-{}", i.trim()));
    let prefix = crate::derive_ledger_prefix(&run.join("ledger"));
    crate::tracker_path_for_prefix(&prefix)
        .exists()
        .then_some(run)
}

/// The process dies (abort, no unwinding) right after the cutover commits:
/// the marker committed with it.
#[test]
fn a_process_death_right_after_the_cutover_commit_leaves_the_marker_cut_over() {
    let src = tempfile::tempdir().unwrap();
    let (file, label) = export_tiny_catchpoint(src.path());
    let dir = tempfile::tempdir().unwrap();
    let mut child = spawn_child(dir.path(), &file, &label, true);
    let status = child.wait().unwrap();
    assert!(!status.success(), "the child must have aborted");
    let run = dir.path().join("run-0");
    let live = assert_marker_agrees_with_ledger(&run.join("ledger"), &label, &file, "abort");
    assert!(live, "the cutover had committed before the abort");
}

/// Kill the importing process at pseudo-random points (hard kill, no
/// cleanup): whatever the moment, the marker and the ledger agree after a
/// reopen. `CUTOVER_KILL_COUNT` raises the kill count.
#[test]
fn randomized_hard_kills_never_leave_marker_and_ledger_disagreeing() {
    let kills: u32 = std::env::var("CUTOVER_KILL_COUNT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);
    let src = tempfile::tempdir().unwrap();
    let (file, label) = export_tiny_catchpoint(src.path());
    let (mut cut, mut not_cut, mut no_db) = (0u32, 0u32, 0u32);
    // xorshift: deterministic per kill index, spread over the import's life.
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for kill in 0..kills {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let delay_ms = 300 + x % 700;
        let dir = tempfile::tempdir().unwrap();
        let mut child = spawn_child(dir.path(), &file, &label, false);
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        child.kill().unwrap();
        child.wait().unwrap();
        let Some(run) = current_run(dir.path()) else {
            no_db += 1;
            continue;
        };
        let live = assert_marker_agrees_with_ledger(
            &run.join("ledger"),
            &label,
            &file,
            &format!("kill {kill} after {delay_ms} ms"),
        );
        if live {
            cut += 1;
        } else {
            not_cut += 1;
        }
    }
    eprintln!(
        "{kills} hard kills: {cut} cut over, {not_cut} not cut over, {no_db} before the ledger existed"
    );
}

// ---- the marker's contents and its rollback ------------------------------

#[test]
fn the_cutover_commits_a_complete_cut_over_marker() {
    let src = tempfile::tempdir().unwrap();
    let (file, label) = export_tiny_catchpoint(src.path());
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger");
    let mut o = orchestrator(db.clone(), &label, &file);
    o.run_download_ledger().unwrap();
    o.set_import_failpoint(Some(ImportFailpoint::AfterCutoverCommit));
    assert!(o.run_import_ledger().is_err());
    let conn = o.open_db().unwrap();
    let marker = restore_sync_state(&conn).unwrap().unwrap();
    assert_eq!(marker.state, SyncState::ImportingLedger);
    assert_eq!(marker.cut_over, Some(true));
    assert_eq!(marker.catchpoint_label.as_deref(), Some(label.as_str()));
    assert_eq!(marker.catchpoint_round, Some(ROUND));
    assert_eq!(
        marker.catchpoint_file.as_deref(),
        o.catchpoint_file_path.as_ref().and_then(|p| p.to_str())
    );
}

#[test]
fn a_failed_cutover_rolls_its_marker_back_with_it() {
    let src = tempfile::tempdir().unwrap();
    let (file, label) = export_tiny_catchpoint(src.path());
    let dir = tempfile::tempdir().unwrap();
    let mut o = orchestrator(dir.path().join("ledger"), &label, &file);
    o.run_download_ledger().unwrap();
    o.set_import_failpoint(Some(ImportFailpoint::BeforeCutoverCommit));
    assert!(o.run_import_ledger().is_err());
    let conn = o.open_db().unwrap();
    let marker = restore_sync_state(&conn).unwrap().unwrap();
    assert_eq!(marker.state, SyncState::DownloadingLedger);
    assert_eq!(marker.cut_over, Some(false));
    assert!(!snapshot_is_live(&conn));
}

#[test]
fn rolling_the_cutover_back_restores_the_pre_catchup_marker_in_the_same_transaction() {
    let src = tempfile::tempdir().unwrap();
    let (file, label) = export_tiny_catchpoint(src.path());
    let dir = tempfile::tempdir().unwrap();
    let mut o = orchestrator(dir.path().join("ledger"), &label, &file);
    o.run_download_ledger().unwrap();
    o.run_import_ledger().unwrap();
    let conn = o.open_db().unwrap();
    assert!(snapshot_is_live(&conn));

    // A rollback whose marker write fails rolls the whole rollback back.
    let backup = o.cutover_backup.take().unwrap();
    let importer = crate::catchpoint::CatchpointImporter::new(&conn, String::new(), 1);
    let failing = |_: &Connection| -> Result<(), CatchpointError> {
        Err(CatchpointError::CutoverError("injected".to_string()))
    };
    assert!(importer
        .rollback_cutover_with_hook(&backup, Some(&failing))
        .is_err());
    assert!(snapshot_is_live(&conn), "the tables must not be restored");
    let marker = restore_sync_state(&conn).unwrap().unwrap();
    assert_eq!(marker.state, SyncState::ImportingLedger);
    assert_eq!(marker.cut_over, Some(true));
    o.cutover_backup = Some(backup);

    // A failed verification rolls back through the orchestrator: tables and
    // marker return to the pre-catchup state together.
    o.block_header_digest = Some([0xffu8; 32]);
    assert!(o.run_verify_ledger().is_err());
    assert!(!snapshot_is_live(&conn));
    let marker = restore_sync_state(&conn).unwrap().unwrap();
    assert_eq!(marker.state, SyncState::DownloadingLedger);
    assert_eq!(marker.cut_over, Some(false));
    assert!(!o.ledger_cut_over());
}

#[test]
fn a_marker_without_the_flag_falls_back_to_its_state() {
    let mk = |state, cut_over| PersistedSyncState {
        state,
        catchpoint_label: None,
        catchpoint_round: None,
        catchpoint_file: None,
        cut_over,
    };
    // Written before the flag existed: from the import state on, cut over.
    assert!(!mk(SyncState::DownloadingLedger, None).is_cut_over());
    assert!(mk(SyncState::ImportingLedger, None).is_cut_over());
    assert!(mk(SyncState::VerifyingLedger, None).is_cut_over());
    // The flag wins when recorded.
    assert!(!mk(SyncState::ImportingLedger, Some(false)).is_cut_over());
    assert!(mk(SyncState::DownloadingLedger, Some(true)).is_cut_over());
}

// ---- review follow-ups ---------------------------------------------------

fn tokens_cancelled_orchestrator(o: &mut SyncOrchestrator) {
    let token = CancellationToken::new();
    token.cancel();
    o.set_abort(token.clone());
    o.set_cancel(token);
}

/// A flag left over from an earlier `run` on the same orchestrator must not
/// leak into a run that finds no marker.
#[test]
fn a_second_run_on_the_same_orchestrator_does_not_inherit_the_cut_over_flag() {
    let src = tempfile::tempdir().unwrap();
    let (file, label) = export_tiny_catchpoint(src.path());
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger");
    let mut first = orchestrator(db.clone(), &label, &file);
    first.run_download_ledger().unwrap();
    first.run_import_ledger().unwrap();
    drop(first);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .build()
        .unwrap();
    let mut o = orchestrator(db.clone(), &label, &file);
    tokens_cancelled_orchestrator(&mut o);
    rt.block_on(o.run()).unwrap_err();
    assert!(o.ledger_cut_over(), "the marker says cut over");

    // No marker any more (and nothing cut over): a fresh run on the same
    // orchestrator is not cut over either, so its abort discards.
    let conn = o.open_db().unwrap();
    clear_sync_state(&conn).unwrap();
    drop(conn);
    let err = rt.block_on(o.run()).unwrap_err().to_string();
    assert!(!o.ledger_cut_over(), "stale flag carried over");
    assert!(err.contains("aborted by user"), "{err}");
}

/// A rollback whose marker write fails must not consume the backup: the
/// snapshot is still live, the marker still says so, and a retry restores.
#[test]
fn a_failed_rollback_keeps_its_backup_and_a_retry_restores_the_ledger() {
    let src = tempfile::tempdir().unwrap();
    let (file, label) = export_tiny_catchpoint(src.path());
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger");
    let mut o = orchestrator(db.clone(), &label, &file);
    o.run_download_ledger().unwrap();
    o.run_import_ledger().unwrap();
    let conn = o.open_db().unwrap();

    o.set_import_failpoint(Some(ImportFailpoint::RollbackMarkerWriteFails));
    assert!(!o.rollback_cutover_on_failure(&conn, "test"));
    assert!(o.cutover_backup.is_some(), "the backup must survive");
    assert!(o.ledger_cut_over());
    drop(conn);
    assert!(assert_marker_agrees_with_ledger(
        &db,
        &label,
        &file,
        "failed rollback"
    ));

    o.set_import_failpoint(None);
    let conn = o.open_db().unwrap();
    assert!(o.rollback_cutover_on_failure(&conn, "retry"));
    drop(conn);
    assert!(!assert_marker_agrees_with_ledger(
        &db,
        &label,
        &file,
        "retried rollback"
    ));
    assert!(!o.ledger_cut_over());
}

fn header_rows(conn: &Connection) -> i64 {
    conn.query_row("SELECT count(*) FROM blockdb.blocks", [], |r| r.get(0))
        .unwrap()
}

/// The process dies after the rollback committed but before the synthesized
/// header rows were deleted: the next run removes them.
#[test]
fn header_rows_left_by_a_crash_after_the_rollback_are_cleaned_by_the_next_run() {
    let src = tempfile::tempdir().unwrap();
    let (file, label) = export_tiny_catchpoint(src.path());
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger");
    let mut o = orchestrator(db.clone(), &label, &file);
    o.run_download_ledger().unwrap();
    o.run_import_ledger().unwrap();
    {
        let conn = o.open_db().unwrap();
        assert!(header_rows(&conn) > 0, "initialize_meta wrote a header row");
    }
    o.set_import_failpoint(Some(ImportFailpoint::CrashAfterRollbackCommit));
    o.block_header_digest = Some([0xffu8; 32]);
    assert!(o.run_verify_ledger().is_err());
    drop(o);
    {
        let conn = orchestrator(db.clone(), &label, &file).open_db().unwrap();
        assert!(!snapshot_is_live(&conn), "the rollback had committed");
        assert!(header_rows(&conn) > 0, "the crash left the header row");
    }

    // Next run: a shutdown (not an abort), so the marker is kept.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .build()
        .unwrap();
    let mut next = orchestrator(db.clone(), &label, &file);
    let token = CancellationToken::new();
    token.cancel();
    next.set_cancel(token);
    rt.block_on(next.run()).unwrap_err();
    let conn = next.open_db().unwrap();
    assert_eq!(header_rows(&conn), 0, "orphan header rows must be removed");
    let pending: i64 = conn
        .query_row(
            "SELECT count(*) FROM catchpointstate WHERE id = 'algod_rust_sync_header_cleanup'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pending, 0, "the pending-cleanup record must be cleared");
}

/// A failed marker write must leave no dangling savepoint (it would hold the
/// write lock on an autocommit connection), even if the savepoint rollback
/// fails too.
#[test]
fn a_failed_marker_write_never_leaves_a_savepoint_open() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE catchpointstate (id TEXT PRIMARY KEY, intval INTEGER, strval TEXT);
         CREATE TRIGGER boom BEFORE INSERT ON catchpointstate
         BEGIN SELECT RAISE(ABORT, 'boom'); END;",
    )
    .unwrap();
    let err = persist_sync_state_with_cut_over(
        &conn,
        &SyncState::ImportingLedger,
        Some("l"),
        Some(1),
        None,
        Some(true),
    )
    .unwrap_err();
    assert!(err.to_string().contains("boom"), "{err}");
    assert!(
        conn.is_autocommit(),
        "dangling savepoint after a failed write"
    );
    conn.execute_batch("DROP TRIGGER boom").unwrap();
    persist_sync_state_with_cut_over(&conn, &SyncState::Idle, None, None, None, Some(false))
        .unwrap();

    // The savepoint rollback itself failing: the original error survives and
    // the savepoint is still released.
    conn.execute_batch("SAVEPOINT sync_marker").unwrap();
    let err = end_marker_savepoint(
        &conn,
        Err(AlgoError::Ledger {
            message: "original".to_string(),
        }),
        "ROLLBACK TO no_such_savepoint",
    )
    .unwrap_err();
    assert!(err.to_string().contains("original"), "{err}");
    assert!(
        conn.is_autocommit(),
        "savepoint left open after a failed rollback"
    );
}

// ---- issue #2181: abandoning a stuck cut-over catchup ---------------------

const A_ROUND: u64 = 600;
const B_ROUND: u64 = 500;
/// The round the replay of A advanced the ledger to.
const A_REPLAYED_TO: i64 = 650;

/// A ledger that REALLY imported catchpoint A (a cut-over snapshot at round
/// 600) and was then replayed past it: the rows the lookback download and the
/// replay write beyond the snapshot (blocks 595..=650, their `txtail` rows, a
/// voters snapshot), `acctbase` advanced to 650 and the marker at
/// `ReplayingBlocks`, cut over. Returns A's label and file.
fn ledger_replayed_past_a(db: &Path, dir: &Path) -> (String, PathBuf) {
    let (file, label) = export_tiny_catchpoint_at(dir, "a.tar.gz", 1, A_ROUND);
    let mut o = orchestrator(db.to_path_buf(), &label, &file);
    o.run_download_ledger().unwrap();
    o.run_import_ledger().unwrap();
    let conn = o.open_db().unwrap();
    // The tables the lookback download and the replay write to (the same
    // definitions the ledger's schema uses).
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS txtail (rnd INTEGER PRIMARY KEY NOT NULL, data BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS votersnapshot (round INTEGER PRIMARY KEY NOT NULL, voterscommitment BLOB NOT NULL, onlinetotalweight INTEGER NOT NULL);",
    )
    .unwrap();
    for rnd in 595..=A_REPLAYED_TO {
        conn.execute(
            "INSERT OR REPLACE INTO blockdb.blocks (rnd, proto, hdrdata, blkdata) \
             VALUES (?1, 'test', x'00', x'00')",
            [rnd],
        )
        .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO txtail (rnd, data) VALUES (?1, x'00')",
            [rnd],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT OR REPLACE INTO votersnapshot (round, voterscommitment, onlinetotalweight) \
         VALUES (640, x'00', 1)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO acctrounds (id, rnd) VALUES ('acctbase', ?1)",
        [A_REPLAYED_TO],
    )
    .unwrap();
    let marker_file = o
        .catchpoint_file_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned());
    persist_sync_state_with_cut_over(
        &conn,
        &SyncState::ReplayingBlocks,
        Some(&label),
        Some(A_ROUND),
        marker_file.as_deref(),
        Some(true),
    )
    .unwrap();
    (label, file)
}

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get(0)).unwrap()
}

/// Everything A's cut-over wrote beyond its snapshot.
fn a_leftovers(conn: &Connection) -> (i64, i64, i64) {
    (
        count(conn, "SELECT COUNT(*) FROM blockdb.blocks WHERE rnd > 500"),
        count(conn, "SELECT COUNT(*) FROM txtail WHERE rnd >= 595"),
        count(conn, "SELECT COUNT(*) FROM votersnapshot"),
    )
}

fn run_b(
    db: &Path,
    b_label: &str,
    b_file: &Path,
    discard: bool,
    failpoint: Option<ImportFailpoint>,
) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .build()
        .unwrap();
    let mut o = orchestrator(db.to_path_buf(), b_label, b_file);
    // The lookback blocks are not served: fail fast instead of retrying with
    // the production backoff.
    o.lookback_retry_backoff = |_| 0;
    o.config.catchup_block_download_retry_attempts = 0;
    o.set_discard_cut_over_catchup(discard);
    o.set_import_failpoint(failpoint);
    // The run ends in an error later (the lookback blocks are not served);
    // what it leaves behind is what the tests look at.
    let _ = rt.block_on(o.run());
}

/// Issue #2181: abandoning a catchup that was imported AND replayed removes
/// everything it wrote beyond its snapshot, so B (a LOWER round than A) starts
/// from the state a fresh import would: no blocks, `txtail` or voters rows
/// above B's round survive B's import.
#[test]
fn abandoning_a_replayed_catchup_leaves_nothing_above_the_new_round() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger");
    let (a_label, _a_file) = ledger_replayed_past_a(&db, dir.path());
    let conn = orchestrator(db.clone(), &a_label, &_a_file)
        .open_db()
        .unwrap();
    assert_eq!(a_leftovers(&conn), (56, 56, 1), "the replayed ledger setup");
    drop(conn);

    let (b_file, b_label) = export_tiny_catchpoint_at(dir.path(), "b.tar.gz", 2, B_ROUND);
    run_b(&db, &b_label, &b_file, true, None);

    let conn = orchestrator(db.clone(), &b_label, &b_file)
        .open_db()
        .unwrap();
    assert_eq!(a_leftovers(&conn), (0, 0, 0), "A's leftovers are gone");
    let marker = restore_sync_state(&conn).unwrap().expect("a marker");
    assert_eq!(marker.catchpoint_label.as_deref(), Some(b_label.as_str()));
    assert_ne!(marker.catchpoint_label.as_deref(), Some(a_label.as_str()));
    assert!(marker.is_cut_over(), "{marker:?}");
    // The imported snapshot is B's (round 500), not A's replayed round.
    assert_eq!(
        count(&conn, "SELECT rnd FROM acctrounds WHERE id = 'acctbase'"),
        B_ROUND as i64
    );
    // The pending-discard record is gone once the blocks are.
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM catchpointstate WHERE id = 'algod_rust_sync_discard_blocks'"
        ),
        0
    );
}

/// Issue #2181: if B's import fails (before or after its cutover commit) the
/// marker names B and a later run resumes B: it never resumes A's snapshot,
/// and A's leftovers stay gone throughout.
#[test]
fn a_failed_import_of_the_new_label_leaves_a_marker_that_resumes_it() {
    for failpoint in [
        ImportFailpoint::BeforeCutoverCommit,
        ImportFailpoint::AfterCutoverCommit,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("ledger");
        let (a_label, a_file) = ledger_replayed_past_a(&db, dir.path());
        let (b_file, b_label) = export_tiny_catchpoint_at(dir.path(), "b.tar.gz", 2, B_ROUND);

        run_b(&db, &b_label, &b_file, true, Some(failpoint));
        let conn = orchestrator(db.clone(), &a_label, &a_file)
            .open_db()
            .unwrap();
        let marker = restore_sync_state(&conn).unwrap().expect("a marker");
        assert_eq!(
            marker.catchpoint_label.as_deref(),
            Some(b_label.as_str()),
            "{failpoint:?}: {marker:?}"
        );
        assert!(marker.is_cut_over(), "{failpoint:?}: {marker:?}");
        assert_eq!(a_leftovers(&conn), (0, 0, 0), "{failpoint:?}");
        drop(conn);

        // The next process (the escape is no longer needed: same label)
        // resumes B.
        run_b(&db, &b_label, &b_file, false, None);
        let conn = orchestrator(db.clone(), &a_label, &a_file)
            .open_db()
            .unwrap();
        let marker = restore_sync_state(&conn).unwrap().expect("a marker");
        assert_eq!(
            marker.catchpoint_label.as_deref(),
            Some(b_label.as_str()),
            "{failpoint:?} resumed: {marker:?}"
        );
        assert_eq!(a_leftovers(&conn), (0, 0, 0), "{failpoint:?} resumed");
        assert_eq!(
            count(&conn, "SELECT rnd FROM acctrounds WHERE id = 'acctbase'"),
            B_ROUND as i64,
            "{failpoint:?}: B's snapshot is live after the resume"
        );
    }
}

/// Issue #2181: a block-row cleanup that did not finish (a crash after the
/// marker rewrite committed) is finished by the next run, which finds the
/// record the rewrite wrote.
#[test]
fn a_discard_interrupted_before_the_block_rows_are_deleted_is_finished_next_run() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger");
    let (a_label, a_file) = ledger_replayed_past_a(&db, dir.path());
    let (b_file, b_label) = export_tiny_catchpoint_at(dir.path(), "b.tar.gz", 2, B_ROUND);
    // The state a crash right after the discard transaction leaves: marker
    // for B, tracker rows gone, the record present, the block rows still there.
    {
        let conn = orchestrator(db.clone(), &a_label, &a_file)
            .open_db()
            .unwrap();
        let tx = conn.unchecked_transaction().unwrap();
        persist_sync_state_with_cut_over(
            &tx,
            &SyncState::ImportingLedger,
            Some(&b_label),
            Some(B_ROUND),
            None,
            Some(true),
        )
        .unwrap();
        discard_cut_over_leftovers(&tx).unwrap();
        tx.commit().unwrap();
        assert!(count(&conn, "SELECT COUNT(*) FROM blockdb.blocks WHERE rnd > 500") > 0);
    }
    run_b(&db, &b_label, &b_file, false, None);
    let conn = orchestrator(db, &b_label, &b_file).open_db().unwrap();
    assert_eq!(a_leftovers(&conn), (0, 0, 0));
}
