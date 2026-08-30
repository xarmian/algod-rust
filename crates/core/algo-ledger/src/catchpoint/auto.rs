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
fn is_stale_write_temp_file(name: &str) -> bool {
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
        // archive) is a distinct, already-cleaned-up-by-the-exporter file
        // and must not be swept here.
        assert!(!is_stale_write_temp_file(
            "20000.catchpoint.tar.gz.stage1.tmp"
        ));
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
}
