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

const ROUND: u64 = 500;

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
    let path = dir.join("source-catchpoint.tar.gz");
    let exported = export_catchpoint_file(
        &src,
        &path,
        &ExportOptions {
            balances_round: ROUND,
            blocks_round: ROUND,
            block_header_digest: [7u8; 32],
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
