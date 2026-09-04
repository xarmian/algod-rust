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

//! Small filesystem helpers ported from go-algorand's `util` package.
//!
//! # Reference
//!
//! `../go-algorand/util/io.go` -- `MoveFile`, `moveFileByCopying`, `IsEmpty`.
//!
//! [`move_file`] backs the catchpoint writer's atomic-rename step
//! ([`super::writer`]): a plain `std::fs::rename` fails with `EXDEV` if the
//! temp file and the final path ever end up on different filesystems/mount
//! points, whereas go's `MoveFile` degrades gracefully via a copy-then-
//! delete-source fallback. Porting it here closes that gap (issue #971).

use std::fs::{self, File};
use std::io;
use std::path::Path;

/// Move a file from `src` to `dst`.
///
/// Tries a same-filesystem `rename` first (the fast, atomic path); if that
/// fails for any reason -- most notably `EXDEV` when `src` and `dst` live on
/// different filesystems -- falls back to copying `src` to a temp file next
/// to `dst`, renaming the temp file onto `dst`, and then removing `src`.
///
/// Go: `MoveFile` in `../go-algorand/util/io.go`.
pub fn move_file(src: &Path, dst: &Path) -> io::Result<()> {
    move_file_via(src, dst, |s: &Path, d: &Path| fs::rename(s, d))
}

/// Same as [`move_file`], but the same-filesystem rename attempt goes
/// through `rename_fn` instead of `std::fs::rename`.
///
/// This is what lets the cross-filesystem fallback path be exercised in
/// tests without needing a real second mounted filesystem (which, per
/// go-algorand's own `TestMoveFileAcrossFilesystems`, requires Linux +
/// administrator privileges and is skipped outside CI): a test can pass a
/// `rename_fn` that always fails, forcing the same `moveFileByCopying` path
/// a genuine `EXDEV` would take.
fn move_file_via<F>(src: &Path, dst: &Path, rename_fn: F) -> io::Result<()>
where
    F: FnOnce(&Path, &Path) -> io::Result<()>,
{
    match rename_fn(src, dst) {
        Ok(()) => Ok(()),
        // `std::fs::rename()` may have failed because src and dst are on
        // different filesystems. Fall back to moving the file by copying
        // and deleting the source file, matching go's `MoveFile`.
        Err(_) => move_file_by_copying(src, dst),
    }
}

fn move_file_by_copying(src: &Path, dst: &Path) -> io::Result<()> {
    // `symlink_metadata` (Go: `os.Lstat`) is used specifically to detect if
    // `src` is a symlink. We could support moving symlinks by deleting `src`
    // and creating a new symlink at `dst`, but we don't currently expect to
    // encounter that case, so it has not been implemented -- matching go.
    let src_meta = fs::symlink_metadata(src)?;
    if !src_meta.is_file() {
        return Err(io::Error::other(format!(
            "cannot move source file '{}': it is not a regular file ({:?})",
            src.display(),
            src_meta.file_type()
        )));
    }

    if let Ok(dst_meta) = fs::symlink_metadata(dst) {
        if dst_meta.is_dir() {
            return Err(io::Error::other(format!(
                "cannot move source file '{}' to destination '{}': destination is a directory",
                src.display(),
                dst.display()
            )));
        }
        if is_same_file(src, dst) {
            return Err(io::Error::other(format!(
                "cannot move source file '{}' to destination '{}': source and destination are the same file",
                src.display(),
                dst.display()
            )));
        }
    }

    let dst_dir = dst.parent().unwrap_or_else(|| Path::new("."));
    let dst_base = dst
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let (tmp_dst, tmp_file) = create_temp_file(dst_dir, &dst_base)?;
    drop(tmp_file);

    if let Err(e) = fs::copy(src, &tmp_dst) {
        // If the copy fails, try to clean up the temporary file.
        let _ = fs::remove_file(&tmp_dst);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp_dst, dst) {
        // If the rename fails, try to clean up the temporary file.
        let _ = fs::remove_file(&tmp_dst);
        return Err(e);
    }
    if let Err(e) = fs::remove_file(src) {
        // Don't try to clean up the destination file here. Duplicate data
        // is better than lost/incomplete data.
        return Err(io::Error::other(format!(
            "failed to remove source file '{}' after moving it to '{}': {}",
            src.display(),
            dst.display(),
            e
        )));
    }
    Ok(())
}

/// Best-effort `os.SameFile` equivalent: true if `a` and `b` resolve (after
/// following any `..`/`.` components and symlinks in their existing parent
/// directories) to the same path on disk.
fn is_same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => false,
    }
}

/// Create a uniquely-named `<base>.tmp-*` file in `dir`, returning its path
/// and the open handle (closed immediately by the caller, mirroring go's
/// `os.CreateTemp` + `Close` in `moveFileByCopying`).
fn create_temp_file(dir: &Path, base: &str) -> io::Result<(std::path::PathBuf, File)> {
    for attempt in 0..1000u32 {
        let candidate = dir.join(format!("{base}.tmp-{}-{attempt}", std::process::id()));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(f) => return Ok((candidate, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("failed to create a unique temp file"))
}

/// True iff `path` exists, is a directory, and contains no files anywhere
/// in its subtree (empty subdirectories don't count as content).
///
/// Go: `IsEmpty` in `../go-algorand/util/io.go`.
pub fn is_empty(path: &Path) -> bool {
    fn walk(dir: &Path) -> io::Result<bool> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                if !walk(&entry.path())? {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }
        Ok(true)
    }
    walk(path).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_file(path: &Path, contents: &[u8]) {
        let mut f = File::create(path).unwrap();
        f.write_all(contents).unwrap();
    }

    // --- IsEmpty --------------------------------------------------------

    #[test]
    fn is_empty_true_for_deeply_nested_empty_dirs() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("this/is/a/long/path");
        fs::create_dir_all(&nested).unwrap();
        assert!(is_empty(&nested));
    }

    #[test]
    fn is_empty_false_once_a_file_exists() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("this/is/a/long/path");
        fs::create_dir_all(&nested).unwrap();
        write_file(&nested.join("file.txt"), b"x");
        assert!(!is_empty(&nested));
    }

    #[test]
    fn is_empty_false_for_missing_path() {
        let root = tempfile::tempdir().unwrap();
        assert!(!is_empty(&root.path().join("does-not-exist")));
    }

    // --- move_file: simple same-filesystem case -------------------------

    fn assert_move_file_simple(src: &Path, dst: &Path) {
        assert!(!src.exists());
        assert!(!dst.exists());

        write_file(src, b"test file contents");

        move_file(src, dst).unwrap();

        assert!(dst.is_file());
        assert!(!src.exists());
        assert_eq!(fs::read(dst).unwrap(), b"test file contents");
    }

    #[test]
    fn move_file_simple() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("dst.txt");
        assert_move_file_simple(&src, &dst);
    }

    // --- move_file: cross-filesystem fallback (mocked rename failure) ---
    //
    // A real cross-device rename (EXDEV) can't be forced portably in CI
    // (go-algorand's own `TestMoveFileAcrossFilesystems` requires a
    // Linux host with a separately-mounted tmpfs and is skipped
    // everywhere else). Instead, inject a `rename_fn` that always fails,
    // which forces `move_file_via` down the exact same
    // `move_file_by_copying` fallback path a genuine EXDEV would take.

    #[test]
    fn move_file_falls_back_to_copying_when_rename_fails() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("dst.txt");
        write_file(&src, b"cross-device contents");

        let always_fails =
            |_: &Path, _: &Path| Err(io::Error::from_raw_os_error(18) /* EXDEV */);

        move_file_via(&src, &dst, always_fails).unwrap();

        assert!(dst.is_file());
        assert!(!src.exists());
        assert_eq!(fs::read(&dst).unwrap(), b"cross-device contents");
    }

    // --- move_file: go's 5 edge cases ------------------------------------

    #[test]
    fn move_file_source_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("dst.txt");

        let err = move_file(&src, &dst).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn move_file_source_is_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root.txt");
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("dst.txt");

        write_file(&root, b"root contents");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&root, &src).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&root, &src).unwrap();

        // A plain rename should work in this case (it's what move_file
        // tries first), so the top-level move_file call succeeds.
        move_file(&src, &dst).unwrap();
        // Undo the move.
        move_file(&dst, &src).unwrap();

        // But moveFileByCopying itself should refuse, since symlink moves
        // aren't implemented (matching go).
        let err = move_file_by_copying(&src, &dst).unwrap_err();
        assert!(
            err.to_string().contains("it is not a regular file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn move_file_source_and_destination_are_same() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("folder")).unwrap();

        let src = dir.path().join("src.txt");
        let dst = dir.path().join("folder/../src.txt");

        assert_ne!(src, dst);

        write_file(&src, b"contents");

        let err = move_file_by_copying(&src, &dst).unwrap_err();
        assert!(
            err.to_string()
                .contains("source and destination are the same file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn move_file_destination_is_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("dst.txt");

        write_file(&src, b"contents");
        fs::create_dir(&dst).unwrap();

        let err = move_file(&src, &dst).unwrap_err();
        assert!(
            err.to_string().contains("destination is a directory"),
            "unexpected error: {err}"
        );
    }
}
