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

//! Automatic (interval-driven) catchpoint generation support (issue #770).
//!
//! This module holds the pieces of the automatic-catchpoint feature that
//! don't need a live SQLite connection: the configuration record consulted
//! by `SqliteLedger::commit_block`, the filename convention for
//! auto-generated files, and the retention/pruning policy that mirrors
//! go-algorand's `catchpointTracker.recordCatchpointFile`
//! (`../go-algorand/ledger/catchpointtracker.go:1419-1453`).
//!
//! # Retention policy (go parity notes)
//!
//! Go tracks catchpoint files as rows in a database table and deletes at
//! most 2 oldest rows per commit (a deliberate incremental-catchup
//! throttle: `recordCatchpointFile`'s doc comment). algod-rust has no such
//! per-file index table -- catchpoint files are just named
//! `<round>.catchpoint.tar[.gz]` on disk -- so [`prune_catchpoint_files`]
//! recovers the round ordering by parsing the filename and deletes
//! everything beyond the retained count in one pass rather than 2 files at
//! a time. The *end state* after any given round is identical (only the
//! newest `file_history_length` files survive); only the incremental
//! pacing differs, which is an internal throttling detail with no
//! observable effect on which files exist after the pass completes.
//!
//! `file_history_length == 0` means "don't keep any" (go writes then
//! immediately deletes; this deletes everything including the file just
//! written) and `-1` means "unlimited" (matches
//! `config.Local.CatchpointFileHistoryLength`'s doc comment).
//!
//! # Crash-safety vs. go's persisted first-stage/unfinished-catchpoints
//! # tables (issue #1080)
//!
//! Go additionally persists a `CatchpointStateWritingFirstStageInfo` flag
//! and an `unfinishedcatchpoints` table (`ledger/store/trackerdb/sqlitedriver/catchpoint.go`)
//! so that a restart can detect and *redo* an interrupted first-stage or
//! second-stage generation (`ledger/catchpointtracker.go`'s
//! `finishFirstStageAfterCrash` / `finishCatchpointsAfterCrash`). That
//! machinery exists because go splits generation into two stages that run
//! at different rounds (`CatchpointLookback` rounds apart) and persists an
//! intermediate artifact between them; algod-rust's `maybe_spawn_automatic_catchpoint`
//! has no such split -- it recomputes everything in one shot, synchronously
//! triggered by `round % interval == 0`, from already-committed and durable
//! ledger state -- so there is no intermediate cross-round artifact for a
//! persisted table to protect, and porting go's schema verbatim would track
//! state that no code path here ever needs to resume. That part of the gap
//! is architectural and out of scope.
//!
//! What *is* in scope, and was a real gap until this issue: a crash or
//! `kill -9` during [`super::writer::export_catchpoint_file`]'s own
//! internal stage-1 scratch-file write left a `*.stage1.tmp` file on disk
//! forever, since it isn't a valid catchpoint (so it's never served or
//! counted toward retention) but also was never swept by
//! [`prune_catchpoint_files`] (see [`is_stale_write_temp_file`]) -- a
//! narrower, single-file version of the "corrupted/partial file surviving a
//! restart" gap the issue asked about, now closed the same way the
//! final-archive `.tmp` file already was (issue #794).

use std::path::{Path, PathBuf};

/// Configuration for automatic, interval-driven catchpoint generation,
/// resolved once at node startup from `config.json`
/// (`algo_config::Local::stores_catchpoints`) and handed to
/// `SqliteLedger::configure_automatic_catchpoints`.
#[derive(Debug, Clone)]
pub struct AutoCatchpointConfig {
    /// Generate a catchpoint every `interval` rounds (`round % interval ==
    /// 0`). Must be non-zero -- callers should not construct this with
    /// `interval == 0`; `SqliteLedger` treats it as "disabled" defensively
    /// but the resolved config should never reach that state.
    pub interval: u64,
    /// Retention policy: `-1` unlimited, `0` keep none, `N > 0` keep the
    /// newest `N` files. Matches `config.Local.CatchpointFileHistoryLength`.
    pub file_history_length: i64,
    /// Directory generated catchpoint files are written to and pruned
    /// from. Matches `config.Local.CatchpointDir`.
    pub dir: PathBuf,
}

/// Filename convention for an automatically-generated catchpoint file at
/// `round`, matching the manual `algod-rust catchpoint export` CLI's own
/// `"{round}.catchpoint.tar.gz"` convention (`bin/algod-rust/src/commands/catchpoint.rs`)
/// so both paths' output lands in a single, uniformly-prunable naming
/// scheme.
pub fn catchpoint_filename(round: u64) -> String {
    format!("{round}.catchpoint.tar.gz")
}

/// Parse the round number out of a catchpoint filename produced by
/// [`catchpoint_filename`] (or the CLI's `--no-gzip` `.tar` variant).
/// Returns `None` for anything that doesn't match `<digits>.catchpoint.tar[.gz]`.
fn parse_round_from_filename(name: &str) -> Option<u64> {
    let rest = name
        .strip_suffix(".catchpoint.tar.gz")
        .or_else(|| name.strip_suffix(".catchpoint.tar"))?;
    rest.parse::<u64>().ok()
}

/// Returns `true` for a leftover write-temp scratch file from an
/// interrupted export (issue #794): [`super::writer::export_catchpoint_file`]
/// writes the final archive to `<final-name>.tmp` and only `rename`s it
/// onto the real name on success, so any `*.catchpoint.tar[.gz].tmp` file
/// found on disk is necessarily stale (either an in-progress export was
/// killed mid-write, or the process crashed before the rename) -- a
/// still-running export's temp file never reaches this scan because
/// `maybe_spawn_automatic_catchpoint` never overlaps two exports and prune
/// only runs after one has already finished.
///
/// This also recognizes the *stage-1* scratch file
/// (`*.catchpoint.tar[.gz].stage1.tmp`, [`super::writer::export_catchpoint_file`]'s
/// `stage1_path_for`) as stale for exactly the same reason (issue #1080): a
/// crash between that file's creation and its normal end-of-export removal
/// (either the `Ok`/`Err` cleanup in `export_catchpoint_file` itself, or the
/// final `repack` step folding it into the published archive) leaves it on
/// disk permanently, since -- unlike go-algorand, which persists a
/// `CatchpointStateWritingFirstStageInfo` flag and an `unfinishedcatchpoints`
/// table so a restart can detect and redo an interrupted first/second stage
/// (`../go-algorand/ledger/catchpointtracker.go`'s `finishFirstStageAfterCrash`
/// / `finishCatchpointsAfterCrash`) -- algod-rust's single-stage,
/// filename-keyed scheme has no persisted "generation in progress" flag of
/// its own and nothing else ever revisits a past round's scratch file.
/// Without this, a killed/crashed process leaks one `.stage1.tmp` file per
/// interrupted attempt, forever; sweeping it here on the very next prune
/// pass closes that gap using the same mechanism already used for the
/// final-archive `.tmp` file, appropriate for an architecture that has no
/// separate first/second stage to resume -- see this module's doc comment
/// and issue #1080 for why replicating go's persisted-table approach itself
/// remains out of scope.
fn is_stale_write_temp_file(name: &str) -> bool {
    if let Some(rest) = name.strip_suffix(".stage1.tmp") {
        return rest.ends_with(".catchpoint.tar.gz") || rest.ends_with(".catchpoint.tar");
    }
    name.strip_suffix(".tmp")
        .map(|rest| rest.ends_with(".catchpoint.tar.gz") || rest.ends_with(".catchpoint.tar"))
        .unwrap_or(false)
}

/// Apply the retention policy to `dir`: keep only the newest `keep`
/// catchpoint files (by round, parsed from the filename), deleting the
/// rest. `keep == -1` is a no-op (unlimited retention); `keep == 0`
/// deletes every catchpoint file in `dir`, including one just written.
///
/// Also removes any stale write-temp scratch file left behind by an
/// export that was interrupted before its atomic rename completed (issue
/// #794) -- unconditionally, regardless of `keep`, since such a file is
/// never a valid catchpoint and `parse_round_from_filename` already
/// refuses to treat it as one.
///
/// Other non-catchpoint files in `dir` are left untouched. Returns the
/// paths actually removed (for testing / logging); a per-file removal
/// error is logged by the caller and does not abort the rest of the pass
/// -- one locked/in-use file on a given platform should not prevent
/// pruning the others.
pub fn prune_catchpoint_files(dir: &Path, keep: i64) -> std::io::Result<Vec<PathBuf>> {
    let mut entries: Vec<(u64, PathBuf)> = Vec::new();
    let mut stale_temp_files: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if is_stale_write_temp_file(name) {
            stale_temp_files.push(entry.path());
            continue;
        }
        if let Some(round) = parse_round_from_filename(name) {
            entries.push((round, entry.path()));
        }
    }

    if keep < 0 {
        // Unlimited retention of real catchpoint files -- but a
        // crash-leftover temp file is still garbage regardless of
        // retention policy.
        let mut removed = Vec::with_capacity(stale_temp_files.len());
        for path in stale_temp_files {
            match std::fs::remove_file(&path) {
                Ok(()) => removed.push(path),
                Err(e) => tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "automatic catchpoint: failed to remove stale write-temp file"
                ),
            }
        }
        return Ok(removed);
    }

    entries.sort_by_key(|(round, _)| *round);

    let keep = keep as usize;
    let to_remove_count = entries.len().saturating_sub(keep);
    let mut removed = Vec::with_capacity(to_remove_count + stale_temp_files.len());
    for path in stale_temp_files {
        match std::fs::remove_file(&path) {
            Ok(()) => removed.push(path),
            Err(e) => tracing::warn!(
                path = %path.display(),
                error = %e,
                "automatic catchpoint: failed to remove stale write-temp file"
            ),
        }
    }
    for (_, path) in entries.into_iter().take(to_remove_count) {
        // Best-effort: a single file that can't be removed (e.g. held open
        // by another process) shouldn't abort pruning the rest.
        match std::fs::remove_file(&path) {
            Ok(()) => removed.push(path),
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "automatic catchpoint: failed to prune old catchpoint file"
                );
            }
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_round_from_gzip_filename() {
        assert_eq!(
            parse_round_from_filename("20000.catchpoint.tar.gz"),
            Some(20000)
        );
    }

    #[test]
    fn parses_round_from_plain_tar_filename() {
        assert_eq!(
            parse_round_from_filename("20000.catchpoint.tar"),
            Some(20000)
        );
    }

    #[test]
    fn rejects_unrelated_filenames() {
        assert_eq!(parse_round_from_filename("not-a-catchpoint.txt"), None);
        assert_eq!(parse_round_from_filename("abc.catchpoint.tar.gz"), None);
    }

    fn touch(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"x").unwrap();
    }

    #[test]
    fn prune_keeps_newest_n_files() {
        let dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-prune-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        for round in [10_000u64, 20_000, 30_000, 40_000] {
            touch(&dir, &catchpoint_filename(round));
        }
        // An unrelated file must survive pruning untouched.
        touch(&dir, "README.txt");

        let removed = prune_catchpoint_files(&dir, 2).unwrap();
        assert_eq!(removed.len(), 2);

        let remaining: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(remaining.contains(&"30000.catchpoint.tar.gz".to_string()));
        assert!(remaining.contains(&"40000.catchpoint.tar.gz".to_string()));
        assert!(!remaining.contains(&"10000.catchpoint.tar.gz".to_string()));
        assert!(!remaining.contains(&"20000.catchpoint.tar.gz".to_string()));
        assert!(remaining.contains(&"README.txt".to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_zero_removes_everything() {
        let dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-prune-zero-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        touch(&dir, &catchpoint_filename(1_000));
        touch(&dir, &catchpoint_filename(2_000));

        let removed = prune_catchpoint_files(&dir, 0).unwrap();
        assert_eq!(removed.len(), 2);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_negative_one_is_unlimited_noop() {
        let dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-prune-unlimited-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        touch(&dir, &catchpoint_filename(1_000));
        touch(&dir, &catchpoint_filename(2_000));

        let removed = prune_catchpoint_files(&dir, -1).unwrap();
        assert_eq!(removed.len(), 0);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_fewer_files_than_keep_is_noop() {
        let dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-prune-fewer-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        touch(&dir, &catchpoint_filename(1_000));

        let removed = prune_catchpoint_files(&dir, 5).unwrap();
        assert_eq!(removed.len(), 0);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Stale write-temp cleanup (issue #794)
    // -----------------------------------------------------------------------

    #[test]
    fn recognizes_write_temp_scratch_filenames() {
        assert!(is_stale_write_temp_file("20000.catchpoint.tar.gz.tmp"));
        assert!(is_stale_write_temp_file("20000.catchpoint.tar.tmp"));
        // A real catchpoint file, or an unrelated file, is not a temp file.
        assert!(!is_stale_write_temp_file("20000.catchpoint.tar.gz"));
        assert!(!is_stale_write_temp_file("20000.catchpoint.tar"));
        assert!(!is_stale_write_temp_file("README.txt"));
        // The *other* scratch convention (`export_catchpoint_file`'s stage-1
        // archive) is normally cleaned up by the exporter itself on both the
        // success and the in-process-error paths, but a hard crash or a
        // killed process skips that cleanup entirely -- so it must also be
        // recognized as stale here (issue #1080), the same way the
        // final-archive `.tmp` file already is.
        assert!(is_stale_write_temp_file(
            "20000.catchpoint.tar.gz.stage1.tmp"
        ));
        assert!(is_stale_write_temp_file("20000.catchpoint.tar.stage1.tmp"));
    }

    #[test]
    fn prune_removes_stale_write_temp_file_regardless_of_retention() {
        let dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-prune-stale-temp-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        touch(&dir, &catchpoint_filename(10_000));
        touch(&dir, &catchpoint_filename(20_000));
        // A crash-leftover from an interrupted export at round 30000 --
        // `20000` and `10000` above are real, finished, renamed files;
        // this one never made it past the atomic rename.
        touch(&dir, "30000.catchpoint.tar.gz.tmp");

        // Even with unlimited retention (-1), the stale temp file is
        // garbage and must go.
        let removed = prune_catchpoint_files(&dir, -1).unwrap();
        assert_eq!(removed, vec![dir.join("30000.catchpoint.tar.gz.tmp")]);

        let remaining: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(remaining.contains(&"10000.catchpoint.tar.gz".to_string()));
        assert!(remaining.contains(&"20000.catchpoint.tar.gz".to_string()));
        assert!(!remaining.iter().any(|n| n.ends_with(".tmp")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_removes_stale_write_temp_file_alongside_normal_retention() {
        let dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-prune-stale-temp-retention-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        touch(&dir, &catchpoint_filename(10_000));
        touch(&dir, &catchpoint_filename(20_000));
        touch(&dir, "30000.catchpoint.tar.gz.tmp");

        let removed = prune_catchpoint_files(&dir, 1).unwrap();
        assert_eq!(removed.len(), 2, "removed: {removed:?}");

        let remaining: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(remaining, vec!["20000.catchpoint.tar.gz".to_string()]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Stage-1 crash-mid-generation cleanup (issue #1080)
    //
    // `export_catchpoint_file` writes its chunked scratch archive to
    // `<final-name>.stage1.tmp` before it has a completed header to prepend,
    // and only removes that scratch file itself once stage 2 (`repack`) has
    // either succeeded or the pipeline has returned a normal `Err`. A process
    // crash or `kill -9` during stage 1 skips that removal entirely, so
    // without this the file survives every future run untouched: it doesn't
    // parse as a real catchpoint round (so it's never served or counted
    // against retention), but nothing ever revisits or deletes it either --
    // a permanent, unbounded disk-space leak, one file per interrupted
    // attempt. This is the "real crash-mid-generation gap" investigation
    // question from issue #1080.
    // -----------------------------------------------------------------------

    #[test]
    fn prune_removes_stale_stage1_scratch_file_left_by_a_crash_mid_first_stage() {
        let dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-prune-stale-stage1-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        touch(&dir, &catchpoint_filename(10_000));
        // Simulates `export_catchpoint_file`'s `stage1_path_for` scratch file
        // for a round-20000 export that was killed before stage 1 finished
        // (so it never reached the `Ok`/`Err` cleanup, nor `repack`, which
        // would otherwise have removed it).
        touch(&dir, "20000.catchpoint.tar.gz.stage1.tmp");

        let removed = prune_catchpoint_files(&dir, -1).unwrap();
        assert_eq!(
            removed,
            vec![dir.join("20000.catchpoint.tar.gz.stage1.tmp")]
        );

        let remaining: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(remaining.contains(&"10000.catchpoint.tar.gz".to_string()));
        assert!(
            !remaining.iter().any(|n| n.contains("stage1.tmp")),
            "a crash-leftover stage-1 scratch file must not survive a prune pass: {remaining:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
