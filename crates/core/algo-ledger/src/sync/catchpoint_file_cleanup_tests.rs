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

//! Issues #2139, #2143 and #2144: how a catchup abort, a rejected-snapshot
//! rollback, a stale-marker restart and the run-start sweep find and delete
//! catchpoint files.
//!
//! The resume marker is data read back from the node's own database, so every
//! deletion based on it must stay inside the ledger directory and keep to the
//! sync's own `catchpoint-*` names (#2143); an abort must find the file its
//! marker names even when the run never loaded it into memory (#2144); and
//! leftovers no marker references are swept at the start of a run (#2139).

use super::*;
use std::path::Path;

const LABEL: &str = "5000#L1";
const ROUND: u64 = 5_000;

/// A backend that only ever stops the run: `cancel` (and `abort`, when set,
/// as a user abort) fires on the first download or block request, so a run
/// ends there.
struct StopAtLookbackBackend {
    cancel: CancellationToken,
    abort: Option<CancellationToken>,
}

impl StopAtLookbackBackend {
    fn stop(&self) -> AlgoError {
        if let Some(abort) = &self.abort {
            abort.cancel();
        }
        self.cancel.cancel();
        cancelled_error()
    }
}

impl SyncBackend for StopAtLookbackBackend {
    fn download_catchpoint(
        &self,
        _genesis_id: &str,
        _round: u64,
        _dest_path: &Path,
    ) -> Result<(), AlgoError> {
        Err(self.stop())
    }
    fn fetch_block_raw(&self, _round: u64) -> Result<(String, Vec<u8>, Vec<u8>), AlgoError> {
        Err(self.stop())
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

fn config(db_path: PathBuf, label: Option<&str>) -> SyncConfig {
    SyncConfig {
        catchpoint_label: label.map(str::to_string),
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

/// A scratch ledger directory `<tmp>/<name>/ledger-dir` (the catchpoint
/// directory) next to an `outside` directory that must never be touched.
struct Scratch {
    root: PathBuf,
    dir: PathBuf,
    outside: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "algo-ledger-sync-test-cleanup-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("ledger-dir");
        let outside = root.join("outside");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        Self { root, dir, outside }
    }

    fn orchestrator(
        &self,
        label: Option<&str>,
        backend: impl SyncBackend + 'static,
    ) -> SyncOrchestrator {
        SyncOrchestrator::with_backend(config(self.dir.join("ledger"), label), backend)
    }

    /// A file with `name` in `dir`, containing its own name.
    fn file(&self, dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, name.as_bytes()).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn persist_marker(orchestrator: &SyncOrchestrator, state: SyncState, file: Option<&Path>) {
    let conn = orchestrator.open_db().unwrap();
    persist_sync_state(
        &conn,
        &state,
        Some(LABEL),
        Some(ROUND),
        file.map(|f| f.to_string_lossy().into_owned()).as_deref(),
    )
    .unwrap();
}

/// A symlink `link` -> `target`; false when the platform (or its privileges)
/// does not allow creating one.
fn try_symlink(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        false
    }
}

/// The marker paths that must never lead to a deletion: outside the
/// directory (plain, and through `..`), inside it under a name the sync
/// never gives its files, and a symlink to an outside file.
fn hostile_marker_paths(s: &Scratch) -> Vec<(&'static str, PathBuf, PathBuf)> {
    let mut cases = Vec::new();
    let victim = s.file(&s.outside, "catchpoint-victim.tar.gz");
    cases.push(("outside the directory", victim.clone(), victim));
    let victim = s.file(&s.outside, "catchpoint-dotdot.tar.gz");
    let via_dotdot = s
        .dir
        .join("..")
        .join("outside")
        .join("catchpoint-dotdot.tar.gz");
    cases.push(("through ..", via_dotdot, victim));
    let important = s.file(&s.dir, "important.db");
    cases.push(("a bad name", important.clone(), important));
    let target = s.file(&s.outside, "secret.tar.gz");
    let link = s.dir.join("catchpoint-link.tar.gz");
    if try_symlink(&target, &link) {
        cases.push(("a symlink", link, target));
    }
    cases
}

/// Issue #2143: an abort of a resumed run whose marker names a path outside
/// the catchpoint directory, through `..`, under a foreign name or through a
/// symlink, leaves that path alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_abort_refuses_marker_paths_that_are_not_catchpoint_files_of_the_directory() {
    let s = Scratch::new("abort-hostile");
    for (what, path, victim) in hostile_marker_paths(&s) {
        let cancel = CancellationToken::new();
        let abort = CancellationToken::new();
        let mut orchestrator = s.orchestrator(
            None,
            StopAtLookbackBackend {
                cancel: cancel.clone(),
                abort: Some(abort.clone()),
            },
        );
        let (cancel_now, abort_now) = (cancel.clone(), abort.clone());
        orchestrator.set_cancel(cancel);
        orchestrator.set_abort(abort);
        persist_marker(&orchestrator, SyncState::DownloadingLedger, Some(&path));
        // The user aborts as the resumed run starts.
        abort_now.cancel();
        cancel_now.cancel();
        let err = orchestrator
            .run()
            .await
            .expect_err("an aborted run must not succeed")
            .to_string();
        assert!(err.contains("aborted"), "{what}: {err}");
        assert!(
            victim.exists(),
            "an abort deleted {} through a marker path {what}",
            victim.display()
        );
    }
}

/// Issue #2143: a rejected snapshot's rollback does not delete a path outside
/// the catchpoint directory either.
#[test]
fn a_rejected_snapshot_rollback_refuses_marker_paths_that_are_not_catchpoint_files() {
    let s = Scratch::new("rollback-hostile");
    for (what, path, victim) in hostile_marker_paths(&s) {
        let mut orchestrator = s.orchestrator(
            None,
            StopAtLookbackBackend {
                cancel: CancellationToken::new(),
                abort: None,
            },
        );
        orchestrator.catchpoint_file_path = Some(path);
        let conn = orchestrator.open_db().unwrap();
        orchestrator.rollback_after_verify_failure(&conn, "test rejection", true);
        assert!(
            victim.exists(),
            "a rollback deleted {} through a marker path {what}",
            victim.display()
        );
    }
}

/// Issue #2143: a marker naming a bad path is not used by a resumed run
/// either (the import re-reads it): the run ignores it and keeps the file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resumed_run_does_not_load_a_marker_path_that_is_not_a_catchpoint_file() {
    let s = Scratch::new("resume-hostile");
    for (what, path, victim) in hostile_marker_paths(&s) {
        let cancel = CancellationToken::new();
        let mut orchestrator = s.orchestrator(
            None,
            StopAtLookbackBackend {
                cancel: cancel.clone(),
                abort: None,
            },
        );
        orchestrator.set_cancel(cancel);
        persist_marker(&orchestrator, SyncState::DownloadingLookback, Some(&path));
        orchestrator
            .run()
            .await
            .expect_err("the stopped run must not succeed");
        assert!(
            orchestrator.catchpoint_file_path.is_none(),
            "a resumed run loaded a marker path {what}"
        );
        assert!(victim.exists(), "{what}: {} was deleted", victim.display());
    }
}

/// Issue #2143: the stale-marker restart (a marker for another label) refuses
/// the same paths, while still removing the stale catchpoint file it names
/// inside the directory.
#[test]
fn a_stale_restart_refuses_marker_paths_that_are_not_catchpoint_files() {
    let s = Scratch::new("stale-hostile");
    for (what, path, victim) in hostile_marker_paths(&s) {
        let mut orchestrator = s.orchestrator(
            Some("6000#L2"),
            StopAtLookbackBackend {
                cancel: CancellationToken::new(),
                abort: None,
            },
        );
        persist_marker(&orchestrator, SyncState::DownloadingLedger, Some(&path));
        let conn = orchestrator.open_db().unwrap();
        let persisted = restore_sync_state(&conn).unwrap().unwrap();
        orchestrator
            .start_over_for_requested_label(&conn, &persisted, false)
            .unwrap();
        assert!(
            victim.exists(),
            "a stale restart deleted {} through a marker path {what}",
            victim.display()
        );
    }
}

/// Issue #2143, normal case: a marker's catchpoint file inside the directory
/// (and its `.tmp`) is still removed by an abort.
#[test]
fn an_abort_still_removes_a_normal_download_and_its_tmp() {
    let s = Scratch::new("abort-normal");
    let file = s.file(&s.dir, "catchpoint-5000.tar.gz");
    let tmp = s.file(&s.dir, "catchpoint-5000.tar.tmp");
    let mut orchestrator = s.orchestrator(
        None,
        StopAtLookbackBackend {
            cancel: CancellationToken::new(),
            abort: None,
        },
    );
    persist_marker(&orchestrator, SyncState::DownloadingLedger, Some(&file));
    orchestrator.stop_aborted_catchup();
    assert!(!file.exists() && !tmp.exists());
}

/// Issue #2144 (a): an abort of a run that never loaded the marker's file
/// path into memory still removes the file the marker names (and its `.tmp`).
#[test]
fn an_abort_removes_the_file_its_marker_names_when_the_path_was_never_loaded() {
    let s = Scratch::new("abort-unloaded");
    // Named differently from `catchpoint-<round>.tar.gz`, so only the
    // marker's recorded path can find it.
    let file = s.file(&s.dir, "catchpoint-resumed.tar.gz");
    let tmp = s.file(&s.dir, "catchpoint-resumed.tar.tmp");
    let mut orchestrator = s.orchestrator(
        None,
        StopAtLookbackBackend {
            cancel: CancellationToken::new(),
            abort: None,
        },
    );
    persist_marker(&orchestrator, SyncState::DownloadingLookback, Some(&file));
    assert!(orchestrator.catchpoint_file_path.is_none());
    orchestrator.stop_aborted_catchup();
    assert!(!file.exists(), "the marker's file is left behind");
    assert!(!tmp.exists(), "the marker's partial file is left behind");
}

/// Issue #2144 (a): with no path anywhere in memory or in the marker, an
/// abort derives `catchpoint-<round>.tar.gz` and its `.tmp` from the round.
#[test]
fn an_abort_derives_the_file_from_the_round_of_the_requested_label() {
    let s = Scratch::new("abort-by-round");
    let file = s.file(&s.dir, "catchpoint-5000.tar.gz");
    let tmp = s.file(&s.dir, "catchpoint-5000.tar.tmp");
    let mut orchestrator = s.orchestrator(
        Some("5000#MFRGGZDFMY4TQ43ONRSGM5TFNQYTMZLMN5XGK3TWMVYGK4DBOJXXK3DFEBRW63DFOA"),
        StopAtLookbackBackend {
            cancel: CancellationToken::new(),
            abort: None,
        },
    );
    orchestrator.stop_aborted_catchup();
    assert!(!file.exists() && !tmp.exists());
}

/// Issue #2139: a run removes the `catchpoint-*.tar.gz` / `.tmp` files no
/// marker references (a partial download, a file an abort could not remove),
/// and leaves the file the marker names and unrelated files alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_sweeps_orphaned_catchpoint_files_but_not_referenced_or_unrelated_ones() {
    let s = Scratch::new("sweep");
    let kept = s.file(&s.dir, "catchpoint-5000.tar.gz");
    let orphans = [
        s.file(&s.dir, "catchpoint-4000.tar.gz"),
        s.file(&s.dir, "catchpoint-4000.tar.tmp"),
        s.file(&s.dir, "catchpoint-3000.tmp"),
    ];
    let unrelated = [
        s.file(&s.dir, "notes.txt"),
        s.file(&s.dir, "other-4000.tar.gz"),
        s.file(&s.dir, "catchpoint-4000.txt"),
        s.file(&s.outside, "catchpoint-9000.tar.gz"),
    ];
    let subdir = s.dir.join("catchpoint-2000.tar.gz");
    std::fs::create_dir(&subdir).unwrap();

    let cancel = CancellationToken::new();
    let mut orchestrator = s.orchestrator(
        None,
        StopAtLookbackBackend {
            cancel: cancel.clone(),
            abort: None,
        },
    );
    orchestrator.set_cancel(cancel);
    persist_marker(&orchestrator, SyncState::DownloadingLookback, Some(&kept));
    orchestrator
        .run()
        .await
        .expect_err("the stopped run must not succeed");

    assert!(kept.exists(), "the file the marker names must stay");
    for orphan in &orphans {
        assert!(!orphan.exists(), "{} was not swept", orphan.display());
    }
    for other in &unrelated {
        assert!(other.exists(), "{} must not be swept", other.display());
    }
    assert!(subdir.is_dir(), "a directory must not be swept");
}

/// Issue #2139: with no marker at all, every orphan goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_with_no_marker_sweeps_every_orphaned_catchpoint_file() {
    let s = Scratch::new("sweep-no-marker");
    let orphan = s.file(&s.dir, "catchpoint-7000.tar.gz");
    let tmp = s.file(&s.dir, "catchpoint-7000.tar.tmp");
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut orchestrator = s.orchestrator(
        None,
        StopAtLookbackBackend {
            cancel: cancel.clone(),
            abort: None,
        },
    );
    orchestrator.set_cancel(cancel);
    let _ = orchestrator.run().await;
    assert!(!orphan.exists() && !tmp.exists());
}

/// Issue #2143: the sweep does not follow a symlink named like a catchpoint
/// file out of the directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sweep_does_not_follow_a_symlink_out_of_the_directory() {
    let s = Scratch::new("sweep-symlink");
    let target = s.file(&s.outside, "precious.tar.gz");
    let link = s.dir.join("catchpoint-1.tmp");
    if !try_symlink(&target, &link) {
        return;
    }
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut orchestrator = s.orchestrator(
        None,
        StopAtLookbackBackend {
            cancel: cancel.clone(),
            abort: None,
        },
    );
    orchestrator.set_cancel(cancel);
    let _ = orchestrator.run().await;
    assert!(target.exists(), "the sweep followed a symlink");
}
