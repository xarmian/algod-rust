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

//! Serve a previously-exported catchpoint file's bytes back out to a caller
//! (a peer doing fast-catchup, or the node's own catchpoint-serving REST
//! endpoint) — the ledger-side building block go-algorand calls
//! `GetCatchpointStream` (issue #957).
//!
//! # Reference
//!
//! * `../go-algorand/ledger/catchpointtracker.go:1460` —
//!   `catchpointTracker.GetCatchpointStream(round)`. Returns a
//!   `ReadCloseSizer` (a `Read`/`Close` handle with a known `Size()`) for the
//!   catchpoint file recorded for `round`, opened read-only.
//! * `../go-algorand/ledger/store/trackerdb/catchpoint.go:146` —
//!   `MakeCatchpointFilePath(round)`, the `round/256`-bucketed subdirectory
//!   nesting scheme mirrored here as [`make_catchpoint_file_path`].
//!
//! # Why this crate's version is simpler than go's
//!
//! Go's `GetCatchpointStream` is a two-step lookup: it first asks a SQLite
//! `catchpoints` table for the *recorded* relative path of `round`'s file
//! (which is free-form — go's own `TestCatchpointGetCatchpointStream` stores
//! plain `"<round>.catchpoint"`, not a nested path), and only falls back to
//! the conventional `MakeCatchpointFilePath` nested location when the
//! database has no record for `round` at all (e.g. after an import that
//! never went through `recordCatchpointFile`).
//!
//! algod-rust has no such per-file index table (issue #770's design note in
//! [`super::auto`]): every catchpoint file this crate writes uses the single
//! flat-filename convention [`super::catchpoint_filename`]. So
//! [`get_catchpoint_stream`] collapses go's two-step lookup into: try the
//! flat conventional name first (the *only* name anything in this crate
//! actually writes), then fall back to the `round/256`-nested
//! [`make_catchpoint_file_path`] location for parity with a peer/import that
//! placed the file there directly. Both checks are local-disk lookups only —
//! nothing here talks to the network; wiring this function into an actual
//! REST/gossip endpoint that a peer can call during fast-catchup is issue
//! #955's scope (server-side `LedgerService`), not this one's — see that
//! issue's cross-reference comment on #957 for the split rationale.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use super::auto::catchpoint_filename;
use super::types::CatchpointError;

/// Build the `round/256`-bucketed nested path of a catchpoint file for
/// `round`, relative to the catchpoints directory — e.g. round `257` nests
/// one level deep (`01/<catchpoint_filename(257)>`), round `65536` nests two
/// levels deep, and so on, exactly mirroring go's `MakeCatchpointFilePath`
/// algorithm (`irnd := int64(round) / 256`, then repeatedly
/// `filepath.Join(outStr, fmt.Sprintf("%02x", irnd%256))` while
/// `irnd /= 256 > 0`) with the leaf filename following this crate's own
/// [`super::catchpoint_filename`] convention (`<round>.catchpoint.tar.gz`)
/// rather than go's bare `<round>.catchpoint`.
///
/// A round below 256 (so `round / 256 == 0`) has no subdirectory component
/// at all — the loop never runs — matching go's `TestMakeCatchpointFilePath`
/// cases for rounds 10 and 100.
pub fn make_catchpoint_file_path(round: u64) -> PathBuf {
    let mut components: Vec<String> = Vec::new();
    let mut irnd = round / 256;
    while irnd > 0 {
        components.push(format!("{:02x}", irnd % 256));
        irnd /= 256;
    }
    // Go appends each successive (higher-order) byte after the previous
    // one via `filepath.Join(outStr, ...)`, so the *first* byte computed
    // (the low-order byte of `round/256`) ends up as the outermost
    // directory and the last-computed (highest-order) byte as the
    // innermost, immediately above the file itself.
    let mut path = PathBuf::new();
    for component in &components {
        path.push(component);
    }
    path.push(catchpoint_filename(round));
    path
}

/// A previously-exported catchpoint file, opened read-only, with its size
/// known up front (go's `ReadCloseSizer`).
///
/// Implements [`Read`]; dropping it closes the underlying file (go's
/// `Close()` is Rust's `Drop`).
#[derive(Debug)]
pub struct CatchpointStream {
    file: File,
    size: u64,
}

impl CatchpointStream {
    /// Size of the underlying file, in bytes — go's `Size() (int64, error)`.
    /// Always `Ok` here since the size was captured from a successful
    /// `metadata()` call at open time.
    pub fn size(&self) -> u64 {
        self.size
    }
}

impl Read for CatchpointStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

/// Return a readable, size-known stream of the catchpoint file for `round`,
/// looked up under `catchpoint_dir`.
///
/// Tries, in order:
/// 1. The flat conventional name ([`super::catchpoint_filename`]) — the only
///    location any exporter in this crate ever writes to.
/// 2. The `round/256`-nested location ([`make_catchpoint_file_path`]) — go's
///    on-disk convention, kept as a fallback for a file placed there
///    directly (e.g. copied in from a go-algorand node) rather than through
///    this crate's own writer.
///
/// Returns [`CatchpointError::NotFound`] if neither location has a file for
/// `round` — mirroring go's `ledgercore.ErrNoEntry{}` return from
/// `GetCatchpointStream` when no catchpoint is known for the round.
pub fn get_catchpoint_stream(
    catchpoint_dir: &Path,
    round: u64,
) -> Result<CatchpointStream, CatchpointError> {
    let flat_path = catchpoint_dir.join(catchpoint_filename(round));
    if let Some(stream) = try_open(&flat_path)? {
        return Ok(stream);
    }

    let nested_path = catchpoint_dir.join(make_catchpoint_file_path(round));
    if let Some(stream) = try_open(&nested_path)? {
        return Ok(stream);
    }

    Err(CatchpointError::NotFound(round))
}

/// Open `path` and capture its size, returning `Ok(None)` for a
/// not-found error (so the caller can fall back to the next candidate
/// path) and `Err` for any other I/O failure (permissions, etc. — a real
/// error the caller should surface rather than silently trying the next
/// path).
fn try_open(path: &Path) -> Result<Option<CatchpointStream>, CatchpointError> {
    match File::open(path) {
        Ok(file) => {
            let size = file.metadata()?.len();
            Ok(Some(CatchpointStream { file, size }))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CatchpointError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // make_catchpoint_file_path — oracle values from go's
    // TestMakeCatchpointFilePath (`../go-algorand/ledger/catchpointtracker_test.go`),
    // adapted to this crate's `.catchpoint.tar.gz` leaf-name convention.
    // -----------------------------------------------------------------

    fn expect(components: &[&str], round: u64) -> PathBuf {
        let mut p = PathBuf::new();
        for c in components {
            p.push(c);
        }
        p.push(catchpoint_filename(round));
        p
    }

    #[test]
    fn round_below_256_has_no_nesting() {
        assert_eq!(make_catchpoint_file_path(10), expect(&[], 10));
        assert_eq!(make_catchpoint_file_path(100), expect(&[], 100));
    }

    #[test]
    fn round_257_nests_one_level() {
        // 257 / 256 = 1 -> "01"
        assert_eq!(make_catchpoint_file_path(257), expect(&["01"], 257));
    }

    #[test]
    fn round_511_nests_same_as_257() {
        // 511 / 256 = 1 -> "01" (511 is still in the same 256-round bucket)
        assert_eq!(make_catchpoint_file_path(511), expect(&["01"], 511));
    }

    #[test]
    fn round_512_nests_into_the_next_bucket() {
        // 512 / 256 = 2 -> "02"
        assert_eq!(make_catchpoint_file_path(512), expect(&["02"], 512));
    }

    #[test]
    fn round_65536_nests_two_levels() {
        // 65536 / 256 = 256 -> low byte "00", high byte "01" -> "00/01"
        assert_eq!(
            make_catchpoint_file_path(65536),
            expect(&["00", "01"], 65536)
        );
        assert_eq!(
            make_catchpoint_file_path(65537),
            expect(&["00", "01"], 65537)
        );
    }

    #[test]
    fn round_193609727_and_193609728_straddle_a_bucket_boundary() {
        // Go's oracle: 193609727 -> "3f/8a/0b/...", 193609728 -> "40/8a/0b/..."
        assert_eq!(
            make_catchpoint_file_path(193_609_727),
            expect(&["3f", "8a", "0b"], 193_609_727)
        );
        assert_eq!(
            make_catchpoint_file_path(193_609_728),
            expect(&["40", "8a", "0b"], 193_609_728)
        );
    }

    #[test]
    fn round_16777216_nests_three_levels() {
        // 16777216 / 256 = 65536 -> "00/00/01"
        assert_eq!(
            make_catchpoint_file_path(16_777_216),
            expect(&["00", "00", "01"], 16_777_216)
        );
    }

    // -----------------------------------------------------------------
    // get_catchpoint_stream
    // -----------------------------------------------------------------

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-stream-test-{tag}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn serves_a_file_at_the_flat_conventional_path() {
        let dir = tmp_dir("flat");
        let round = 42u64;
        std::fs::write(dir.join(catchpoint_filename(round)), b"catchpoint-bytes").unwrap();

        let mut stream = get_catchpoint_stream(&dir, round).unwrap();
        assert_eq!(stream.size(), 16);
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"catchpoint-bytes");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn falls_back_to_the_nested_path_when_the_flat_file_is_absent() {
        let dir = tmp_dir("nested-fallback");
        // Round 257 nests under "01/" -- put the file only there, matching
        // e.g. a file copied in from a go-algorand-style layout, not one
        // this crate's own writer produced.
        let round = 257u64;
        let nested = dir.join(make_catchpoint_file_path(round));
        std::fs::create_dir_all(nested.parent().unwrap()).unwrap();
        std::fs::write(&nested, b"nested-catchpoint-bytes").unwrap();

        let mut stream = get_catchpoint_stream(&dir, round).unwrap();
        assert_eq!(stream.size(), 23);
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"nested-catchpoint-bytes");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn flat_path_takes_priority_over_a_stale_nested_file() {
        let dir = tmp_dir("priority");
        let round = 257u64;
        std::fs::write(dir.join(catchpoint_filename(round)), b"flat-wins").unwrap();
        let nested = dir.join(make_catchpoint_file_path(round));
        std::fs::create_dir_all(nested.parent().unwrap()).unwrap();
        std::fs::write(&nested, b"stale-nested-should-not-be-served").unwrap();

        let mut stream = get_catchpoint_stream(&dir, round).unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"flat-wins");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn errors_with_not_found_when_no_file_exists_for_the_round() {
        let dir = tmp_dir("missing");
        let err = get_catchpoint_stream(&dir, 999).unwrap_err();
        assert!(matches!(err, CatchpointError::NotFound(999)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn errors_with_not_found_when_the_catchpoint_directory_itself_is_missing() {
        // Should surface as "not found", not an I/O panic or a different
        // error variant -- a node that has never generated/received any
        // catchpoint yet has no catchpoints directory at all.
        let dir = tmp_dir("no-such-dir").join("does-not-exist");
        let err = get_catchpoint_stream(&dir, 1).unwrap_err();
        assert!(matches!(err, CatchpointError::NotFound(1)));
    }
}
