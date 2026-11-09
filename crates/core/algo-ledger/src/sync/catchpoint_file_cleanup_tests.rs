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
            .start_over_for_requested_label(&conn, &persisted, false, false)
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
    let file = s.file(&s.dir, &format!("catchpoint-{REQUESTED_ROUND}.tar.gz"));
    let tmp = s.file(&s.dir, &format!("catchpoint-{REQUESTED_ROUND}.tar.tmp"));
    let mut orchestrator = s.orchestrator(
        Some(REQUESTED_LABEL),
        StopAtLookbackBackend {
            cancel: CancellationToken::new(),
            abort: None,
        },
    );
    orchestrator.stop_aborted_catchup();
    assert!(!file.exists() && !tmp.exists());
}

/// A valid label for round 22507000, used as the requested catchpoint.
const REQUESTED_LABEL: &str = "22507000#XJUJGKAUVK2LVO5OWR46UHSDXIZ52VO5BTLJQQHRFCWAXUAIKMOQ";
const REQUESTED_ROUND: u64 = 22_507_000;

/// Set `path`'s modification time to `hours` ago.
fn age(path: &Path, hours: u64) {
    let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(hours * 3600))
        .unwrap();
}

/// Run `orchestrator` (whose backend stops it) to its end and return.
async fn run_to_the_stop(s: &Scratch, label: Option<&str>, marker: Option<(SyncState, &Path)>) {
    let cancel = CancellationToken::new();
    let mut orchestrator = s.orchestrator(
        label,
        StopAtLookbackBackend {
            cancel: cancel.clone(),
            abort: None,
        },
    );
    orchestrator.set_cancel(cancel);
    if let Some((state, file)) = marker {
        persist_marker(&orchestrator, state, Some(file));
    }
    let _ = orchestrator.run().await;
}

/// Issue #2139 / #2144: the run-start sweep always removes a partial
/// `catchpoint-*.tmp` (incomplete by construction) but leaves a complete
/// `catchpoint-*.tar.gz` alone unless it is provably an orphan, and never
/// touches the file the marker names or unrelated names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sweep_removes_partial_downloads_and_keeps_fresh_complete_ones() {
    let s = Scratch::new("sweep");
    let kept = s.file(&s.dir, "catchpoint-5000.tar.gz");
    let kept_tmp = s.file(&s.dir, "catchpoint-5000.tar.tmp");
    let partials = [
        s.file(&s.dir, "catchpoint-4000.tar.tmp"),
        s.file(&s.dir, "catchpoint-3000.tmp"),
    ];
    // A complete download whose marker write failed, or one an operator
    // staged: fresh, so it may well be wanted.
    let fresh_complete = s.file(&s.dir, "catchpoint-4000.tar.gz");
    let unrelated = [
        s.file(&s.dir, "notes.txt"),
        s.file(&s.dir, "other-4000.tar.gz"),
        s.file(&s.dir, "catchpoint-4000.txt"),
        s.file(&s.outside, "catchpoint-9000.tar.gz"),
    ];
    let subdir = s.dir.join("catchpoint-2000.tar.gz");
    std::fs::create_dir(&subdir).unwrap();

    run_to_the_stop(&s, None, Some((SyncState::DownloadingLookback, &kept))).await;

    assert!(kept.exists(), "the file the marker names must stay");
    assert!(!kept_tmp.exists(), "a .tmp is never complete");
    for partial in &partials {
        assert!(!partial.exists(), "{} was not swept", partial.display());
    }
    assert!(
        fresh_complete.exists(),
        "a fresh complete download must not be swept"
    );
    for other in &unrelated {
        assert!(other.exists(), "{} must not be swept", other.display());
    }
    assert!(subdir.is_dir(), "a directory must not be swept");
}

/// Issue #2144: a complete file older than a day is an orphan, but not when
/// it is the requested round's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sweep_removes_an_old_complete_file_but_not_the_requested_rounds() {
    let s = Scratch::new("sweep-old");
    let old_other = s.file(&s.dir, "catchpoint-4000.tar.gz");
    age(&old_other, 25);
    let old_requested = s.file(&s.dir, &format!("catchpoint-{REQUESTED_ROUND}.tar.gz"));
    age(&old_requested, 25);
    let young_other = s.file(&s.dir, "catchpoint-3000.tar.gz");
    age(&young_other, 23);

    run_to_the_stop(&s, Some(REQUESTED_LABEL), None).await;

    assert!(!old_other.exists(), "an old complete orphan must go");
    assert!(
        old_requested.exists(),
        "the requested round's file must stay, however old"
    );
    assert!(
        young_other.exists(),
        "a complete file under a day must stay"
    );
}

/// Issue #2144: once a later catchup completed (a terminal marker for another
/// round) and a catchpoint is requested, a complete file for yet another round
/// is an orphan at once; the requested round's file is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sweep_removes_a_complete_file_of_an_earlier_round_after_a_completed_catchup() {
    let s = Scratch::new("sweep-completed");
    let earlier = s.file(&s.dir, "catchpoint-4000.tar.gz");
    let requested = s.file(&s.dir, &format!("catchpoint-{REQUESTED_ROUND}.tar.gz"));
    let done = s.file(&s.dir, "catchpoint-100.tar.gz");

    run_to_the_stop(
        &s,
        Some(REQUESTED_LABEL),
        Some((SyncState::Complete, &done)),
    )
    .await;

    assert!(!earlier.exists(), "an earlier round's file must go");
    assert!(requested.exists(), "the requested round's file must stay");
}

/// Issue #2144: with no catchpoint requested a terminal marker alone does not
/// make a fresh complete file an orphan.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sweep_keeps_a_fresh_complete_file_when_nothing_is_requested() {
    let s = Scratch::new("sweep-none-requested");
    let staged = s.file(&s.dir, "catchpoint-4000.tar.gz");
    let done = s.file(&s.dir, "catchpoint-100.tar.gz");
    run_to_the_stop(&s, None, Some((SyncState::Complete, &done))).await;
    assert!(staged.exists());
}

/// Issue #2139: with no marker at all, partial downloads still go.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_with_no_marker_sweeps_partial_downloads() {
    let s = Scratch::new("sweep-no-marker");
    let orphan = s.file(&s.dir, "catchpoint-7000.tar.old.tmp");
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

/// A backend whose download copies `source` to the destination, counting
/// downloads, optionally leaving the downloader's partial `.tmp` behind.
struct CopyingBackend {
    source: PathBuf,
    downloads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    leave_tmp: bool,
    cancel: CancellationToken,
}

impl SyncBackend for CopyingBackend {
    fn download_catchpoint(
        &self,
        _genesis_id: &str,
        _round: u64,
        dest_path: &Path,
    ) -> Result<(), AlgoError> {
        self.downloads
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.leave_tmp {
            std::fs::write(dest_path.with_extension("tmp"), b"partial").unwrap();
        }
        std::fs::copy(&self.source, dest_path)
            .map(|_| ())
            .map_err(|e| AlgoError::Ledger {
                message: format!("copy failed: {e}"),
            })
    }
    fn fetch_block_raw(&self, _round: u64) -> Result<(String, Vec<u8>, Vec<u8>), AlgoError> {
        self.cancel.cancel();
        Err(cancelled_error())
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

/// Issue #2084 / #2143: a downloaded file whose own label differs from the
/// requested one is rejected and deleted through the checked helper: the
/// file AND the downloader's `.tmp` go.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_label_mismatch_rejection_removes_the_file_and_its_tmp() {
    use super::cutover_marker_tests::export_tiny_catchpoint_as;
    let s = Scratch::new("label-mismatch");
    let (served, _served_label) = export_tiny_catchpoint_as(&s.outside, "served.tar.gz", 7);
    let (_, requested_label) = export_tiny_catchpoint_as(&s.outside, "other.tar.gz", 8);
    let downloads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancel = CancellationToken::new();
    let mut orchestrator = s.orchestrator(
        Some(&requested_label),
        CopyingBackend {
            source: served,
            downloads: downloads.clone(),
            leave_tmp: true,
            cancel: cancel.clone(),
        },
    );
    orchestrator.set_cancel(cancel);
    let err = orchestrator
        .run()
        .await
        .expect_err("a mismatching file must be rejected")
        .to_string();
    assert!(err.contains("mismatch"), "{err}");
    let round = super::cutover_marker_tests::ROUND;
    assert!(!s.dir.join(format!("catchpoint-{round}.tar.gz")).exists());
    assert!(!s.dir.join(format!("catchpoint-{round}.tar.tmp")).exists());
}

/// Issue #2144: a complete download of the requested catchpoint already in
/// the ledger directory (kept by the sweep) is reused, not downloaded again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_complete_download_of_the_requested_catchpoint_is_reused() {
    use super::cutover_marker_tests::{export_tiny_catchpoint_as, ROUND};
    let s = Scratch::new("reuse");
    let name = format!("catchpoint-{ROUND}.tar.gz");
    let (existing, label) = export_tiny_catchpoint_as(&s.dir, &name, 7);
    let downloads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancel = CancellationToken::new();
    let mut orchestrator = s.orchestrator(
        Some(&label),
        CopyingBackend {
            source: existing.clone(),
            downloads: downloads.clone(),
            leave_tmp: false,
            cancel: cancel.clone(),
        },
    );
    orchestrator.set_cancel(cancel);
    let _ = orchestrator.run().await;
    assert_eq!(
        downloads.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the complete file in the ledger directory was downloaded again"
    );
    assert!(existing.exists());
}

/// Issue #2144: a complete file for the requested round that is NOT the
/// requested catchpoint (another label) is not reused: it is downloaded
/// afresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_complete_file_of_another_label_is_not_reused() {
    use super::cutover_marker_tests::{export_tiny_catchpoint_as, ROUND};
    let s = Scratch::new("no-reuse");
    let name = format!("catchpoint-{ROUND}.tar.gz");
    export_tiny_catchpoint_as(&s.dir, &name, 8);
    let (served, label) = export_tiny_catchpoint_as(&s.outside, "served.tar.gz", 7);
    let downloads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancel = CancellationToken::new();
    let mut orchestrator = s.orchestrator(
        Some(&label),
        CopyingBackend {
            source: served,
            downloads: downloads.clone(),
            leave_tmp: false,
            cancel: cancel.clone(),
        },
    );
    orchestrator.set_cancel(cancel);
    let _ = orchestrator.run().await;
    assert_eq!(downloads.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Resume a run over a marker naming `marker_path`; returns the file path the
/// run loaded from it.
async fn loaded_marker_path(s: &Scratch, marker_path: &Path) -> Option<PathBuf> {
    let cancel = CancellationToken::new();
    let mut orchestrator = s.orchestrator(
        None,
        StopAtLookbackBackend {
            cancel: cancel.clone(),
            abort: None,
        },
    );
    orchestrator.set_cancel(cancel);
    persist_marker(
        &orchestrator,
        SyncState::DownloadingLookback,
        Some(marker_path),
    );
    let _ = orchestrator.run().await;
    orchestrator.catchpoint_file_path.clone()
}

/// Issue #2144: a marker path that cannot be resolved as written (relative,
/// after a restart with another working directory) still finds the intact
/// file of that name in the ledger directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relative_marker_path_resumes_with_the_ledger_directory_file() {
    let s = Scratch::new("resume-relative");
    let file = s.file(&s.dir, "catchpoint-5000.tar.gz");
    let loaded = loaded_marker_path(&s, Path::new("catchpoint-5000.tar.gz")).await;
    assert_eq!(loaded.as_deref(), Some(file.as_path()));
}

/// Issue #2144: an absolute marker path from another directory resumes with
/// the file of the same name in the ledger directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_marker_path_from_another_directory_resumes_with_the_ledger_directory_file() {
    let s = Scratch::new("resume-moved");
    let file = s.file(&s.dir, "catchpoint-5000.tar.gz");
    let moved = s.outside.join("catchpoint-5000.tar.gz");
    let loaded = loaded_marker_path(&s, &moved).await;
    assert_eq!(loaded.as_deref(), Some(file.as_path()));
    assert!(file.exists());
}

/// Issue #2144: a marker whose file is gone from the ledger directory loads
/// nothing, so the run downloads afresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_marker_file_missing_from_the_ledger_directory_is_not_loaded() {
    let s = Scratch::new("resume-missing");
    let loaded = loaded_marker_path(&s, &s.dir.join("catchpoint-5000.tar.gz")).await;
    assert_eq!(loaded, None);
}

/// Issue #2143: a dangling symlink (and a valid one) at a catchpoint name in
/// the directory is removed as a link, never followed: an abort removes the
/// link and leaves its target.
#[cfg(unix)]
#[test]
fn an_abort_removes_symlinks_at_catchpoint_names_but_not_their_targets() {
    let s = Scratch::new("abort-symlinks");
    let target = s.file(&s.outside, "target.bin");
    let valid = s.dir.join("catchpoint-5000.tar.gz");
    std::os::unix::fs::symlink(&target, &valid).unwrap();
    let dangling = s.dir.join("catchpoint-5000.tar.tmp");
    std::os::unix::fs::symlink(s.outside.join("missing"), &dangling).unwrap();
    let mut orchestrator = s.orchestrator(
        None,
        StopAtLookbackBackend {
            cancel: CancellationToken::new(),
            abort: None,
        },
    );
    persist_marker(&orchestrator, SyncState::DownloadingLedger, Some(&valid));
    orchestrator.stop_aborted_catchup();
    assert!(
        std::fs::symlink_metadata(&valid).is_err(),
        "the valid link stays"
    );
    assert!(
        std::fs::symlink_metadata(&dangling).is_err(),
        "the dangling link stays"
    );
    assert!(target.exists(), "the link's target was removed");
}

/// Issue #2143: the sweep removes a dangling `.tmp` symlink as a link.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sweep_removes_a_dangling_tmp_symlink() {
    let s = Scratch::new("sweep-dangling");
    let dangling = s.dir.join("catchpoint-9.tmp");
    std::os::unix::fs::symlink(s.outside.join("missing"), &dangling).unwrap();
    run_to_the_stop(&s, None, None).await;
    assert!(std::fs::symlink_metadata(&dangling).is_err());
}

/// Issue #2143: every deletion of a catchpoint file goes through the checked
/// helper. The only raw `remove_file` in the sync code is the helper's own
/// `unlink_catchpoint_file`.
#[test]
fn no_catchpoint_file_is_deleted_outside_the_checked_helper() {
    fn production(source: &str) -> &str {
        source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .unwrap()
            .split("\n#[cfg(test)]\n")
            .next()
            .unwrap()
    }
    let sources = [
        (
            "sync/lookback_prefetch.rs",
            include_str!("lookback_prefetch.rs"),
        ),
        ("sync/state_machine.rs", include_str!("state_machine.rs")),
        (
            "catchpoint/importer.rs",
            include_str!("../catchpoint/importer.rs"),
        ),
    ];
    for (name, source) in sources {
        assert!(
            !production(source).contains("remove_file("),
            "{name} deletes a file directly"
        );
    }
    let production_mod = include_str!("mod.rs")
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .unwrap();
    let deletions = production_mod.matches("remove_file(").count();
    assert_eq!(
        deletions, 1,
        "sync/mod.rs must delete catchpoint files only through unlink_catchpoint_file"
    );
    let at = production_mod.find("remove_file(").unwrap();
    let fn_at = production_mod.find("fn unlink_catchpoint_file").unwrap();
    assert!(
        fn_at < at && at - fn_at < 300,
        "the one deletion is the helper's"
    );
}
