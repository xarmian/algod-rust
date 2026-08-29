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

//! Data-directory resolution + kmd-directory resolution.
//!
//! Ports Go's `cmd/util/datadir/datadir.go` (`ResolveDataDir`,
//! `EnsureFirstDataDir`, `EnsureSingleDataDir`, `GetDataDirs`,
//! `OnDataDirs`) and `cmd/goal/commands.go:240-270`
//! (`resolveKmdDataDir`) at `v4.6.0-stable`.
//!
//! Precedence rules:
//! - Algod data dir: explicit `-d` flag(s) (multi-value) > `$ALGORAND_DATA`
//!   > error `errorNoDataDirectory`.
//! - Kmd data dir: explicit `-k` flag > `$ALGORAND_KMD` > if the algod
//!   data dir is "private" (no `system.json` with `shared_server: true`),
//!   then `<data_dir>/kmd-v0.5`; otherwise `~/.algorand/<genesis_id>/kmd-v0.5`.
//!
//! Error text MUST stay byte-identical to Go's `messages.go` constants —
//! operators grep for these strings.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Mirrors `cmd/goal/messages.go:errorNoDataDirectory`. NOTE the
/// two-space sequence after the first period — that's how Go ships it.
pub const ERROR_NO_DATA_DIRECTORY: &str =
    "Data directory not specified.  Please use -d or set $ALGORAND_DATA in your environment. Exiting.";

/// Mirrors `cmd/goal/messages.go:errorOneDataDirSupported`.
pub const ERROR_ONE_DATA_DIR_SUPPORTED: &str =
    "Only one data directory can be specified for this command.";

/// Mirrors `cmd/util/datadir/messages.go:infoDataDir` (printed once per
/// data dir when iterating multiple). Note: the format string includes
/// the brackets but not the trailing newline (Go's `reportInfof` adds
/// the newline).
pub const INFO_DATA_DIR_FMT: &str = "[Data Directory: ";

/// Filename of the kmd data dir within an algod data dir when the algod
/// data dir is "private" (the standard developer setup). Tracks
/// `../go-algorand/nodecontrol/kmdControl.go:40`
/// (`DefaultKMDDataDir = "kmd-v0.5"`).
pub const DEFAULT_KMD_DATA_DIR: &str = "kmd-v0.5";

/// `config.GenesisJSONFile` — `../go-algorand/config/config.go:53`.
pub const GENESIS_JSON_FILE: &str = "genesis.json";

/// `libgoal/system.go` reads `system.json` to determine whether the
/// algod data dir is "private". Default (file missing) is private.
pub const SYSTEM_JSON_FILE: &str = "system.json";

/// Standard algod connection files inside a data dir.
pub const ALGOD_NET_FILE: &str = "algod.net";
pub const ALGOD_TOKEN_FILE: &str = "algod.token";
pub const ALGOD_ADMIN_TOKEN_FILE: &str = "algod.admin.token";

/// Env-var name for the implicit algod data dir
/// (`libgoal.go:getDataDir`).
pub const ALGORAND_DATA_ENV: &str = "ALGORAND_DATA";

/// Env-var name for the implicit kmd data dir
/// (`commands.go:resolveKmdDataDir`).
pub const ALGORAND_KMD_ENV: &str = "ALGORAND_KMD";

/// Errors surfaced by the resolver. Top-level callers map these onto
/// Go-compatible exit codes + stderr messages (e.g.
/// `Self::NoDataDirectory => print ERROR_NO_DATA_DIRECTORY; exit 1`).
#[derive(Debug)]
pub enum DataDirError {
    /// No `-d` and no `$ALGORAND_DATA`. Print `ERROR_NO_DATA_DIRECTORY`
    /// and exit 1, matching Go's `reportErrorln(errorNoDataDirectory)`.
    NoDataDirectory,
    /// Multiple `-d` flags supplied to a single-data-dir command.
    OnlyOneDataDirSupported,
    /// I/O error reading a data-dir-relative file.
    Io { path: PathBuf, source: io::Error },
    /// Genesis file present but its JSON could not be parsed.
    GenesisParse { path: PathBuf, message: String },
}

impl std::fmt::Display for DataDirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDataDirectory => f.write_str(ERROR_NO_DATA_DIRECTORY),
            Self::OnlyOneDataDirSupported => f.write_str(ERROR_ONE_DATA_DIR_SUPPORTED),
            Self::Io { path, source } => write!(f, "{}: {}", path.display(), source),
            Self::GenesisParse { path, message } => {
                write!(f, "{}: invalid genesis.json: {}", path.display(), message)
            }
        }
    }
}

impl std::error::Error for DataDirError {}

/// Read `$ALGORAND_DATA` if set + non-empty. Factored out so unit tests
/// can supply an explicit env value (Rust's `std::env::set_var` is
/// thread-hostile in a parallel test binary).
fn algorand_data_env() -> Option<OsString> {
    env::var_os(ALGORAND_DATA_ENV).filter(|s| !s.is_empty())
}

/// Apply Go's `ResolveDataDir` + `GetDataDirs` precedence to the
/// `-d`/`--datadir` list from the CLI.
///
/// - Non-empty `cli_d`: returns the list as-is, with the first entry
///   canonicalized to an absolute path (matching Go's
///   `EnsureFirstDataDir` → `filepath.Abs(DataDirs[0])`; subsequent
///   entries are returned untouched, matching
///   `GetDataDirs(...) = append(... , DataDirs[1:]...)`).
/// - Empty `cli_d`: falls back to `$ALGORAND_DATA` (raw, no abs — Go's
///   `ResolveDataDir` only abs-es `DataDirs[0]`).
/// - Both empty: `DataDirError::NoDataDirectory`.
pub fn resolve_data_dirs(cli_d: &[PathBuf]) -> Result<Vec<PathBuf>, DataDirError> {
    resolve_data_dirs_with_env(cli_d, algorand_data_env().as_deref())
}

/// Test seam for [`resolve_data_dirs`] — accepts the env value
/// explicitly so unit tests don't race on `std::env::set_var`.
pub fn resolve_data_dirs_with_env(
    cli_d: &[PathBuf],
    env_value: Option<&std::ffi::OsStr>,
) -> Result<Vec<PathBuf>, DataDirError> {
    if let Some(first) = cli_d.first() {
        let mut out = Vec::with_capacity(cli_d.len());
        // Mirror Go's `filepath.Abs`: makes the path absolute relative
        // to cwd but does NOT resolve symlinks and does NOT require the
        // path to exist. `fs::canonicalize` would do both and would
        // diverge from `goal` (see Codex review round 1 of TASK-221).
        out.push(absolutize(first));
        for d in &cli_d[1..] {
            out.push(d.clone());
        }
        return Ok(out);
    }
    if let Some(env) = env_value {
        if !env.is_empty() {
            return Ok(vec![PathBuf::from(env)]);
        }
    }
    Err(DataDirError::NoDataDirectory)
}

/// Mirror Go's `filepath.Abs`: make the path absolute relative to cwd
/// (without requiring it to exist and without resolving symlinks) and
/// lexically `Clean` it — i.e. collapse `.` / `..` / repeated
/// separators purely on path components, never touching the
/// filesystem. Diverging from this on relative `-d` / `-k` paths
/// would break the byte-exact contract operators script against.
fn absolutize(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match env::current_dir() {
            Ok(cwd) => cwd.join(path),
            // If we can't read cwd, fall back to the raw input — Go's
            // filepath.Abs returns an error in this case; we degrade
            // to a non-cleaned path rather than panic.
            Err(_) => path.to_path_buf(),
        }
    };
    lexically_clean(&absolute)
}

/// Lexical `filepath.Clean`: collapse `.`, `..`, and redundant
/// separators without touching the filesystem. Matches Go's
/// `path/filepath.Clean` for the inputs we care about (no Windows
/// volume prefixes — those would need extra handling).
fn lexically_clean(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    let mut popped_root = false;
    for c in path.components() {
        match c {
            Component::Prefix(p) => {
                out.push(p.as_os_str());
            }
            Component::RootDir => {
                out.push(c.as_os_str());
                popped_root = true;
            }
            Component::CurDir => {}
            Component::ParentDir => {
                // If the last segment is a normal component, drop it.
                // If we're at the root (or before any normal segment
                // on a relative path), keep `..`.
                let popped = match out.components().next_back() {
                    Some(Component::Normal(_)) => {
                        out.pop();
                        true
                    }
                    _ => false,
                };
                if !popped && !popped_root {
                    out.push("..");
                }
            }
            Component::Normal(s) => {
                out.push(s);
            }
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

/// Mirrors `EnsureFirstDataDir`. Returns the first data dir after
/// resolution, or `NoDataDirectory` if none.
pub fn ensure_first_data_dir(cli_d: &[PathBuf]) -> Result<PathBuf, DataDirError> {
    let dirs = resolve_data_dirs(cli_d)?;
    Ok(dirs.into_iter().next().expect("non-empty by construction"))
}

/// Mirrors `EnsureSingleDataDir`. Errors if more than one was supplied.
pub fn ensure_single_data_dir(cli_d: &[PathBuf]) -> Result<PathBuf, DataDirError> {
    if cli_d.len() > 1 {
        return Err(DataDirError::OnlyOneDataDirSupported);
    }
    ensure_first_data_dir(cli_d)
}

/// Mirrors `OnDataDirs(action func(string))`. Iterates resolved data
/// dirs; if more than one, prints `[Data Directory: <dir>]` to `stdout`
/// before each callback (matches Go's `reportInfof(infoDataDir, dir)`).
///
/// Callbacks that fail are left to the caller — Go's `OnDataDirs`
/// has the action handle its own errors via `reportErrorf`.
pub fn on_data_dirs<F>(cli_d: &[PathBuf], mut action: F) -> Result<(), DataDirError>
where
    F: FnMut(&Path),
{
    let dirs = resolve_data_dirs(cli_d)?;
    let do_report = dirs.len() > 1;
    for dir in &dirs {
        if do_report {
            println!("{}{}]", INFO_DATA_DIR_FMT, dir.display());
        }
        action(dir);
    }
    Ok(())
}

/// Read `<data_dir>/algod.net`, trim trailing whitespace.
pub fn read_algod_net(data_dir: &Path) -> Result<String, DataDirError> {
    read_trimmed(&data_dir.join(ALGOD_NET_FILE))
}

/// Read `<data_dir>/algod.token`, trim trailing whitespace.
pub fn read_algod_token(data_dir: &Path) -> Result<String, DataDirError> {
    read_trimmed(&data_dir.join(ALGOD_TOKEN_FILE))
}

/// Read `<data_dir>/algod.admin.token`, trim trailing whitespace.
pub fn read_algod_admin_token(data_dir: &Path) -> Result<String, DataDirError> {
    read_trimmed(&data_dir.join(ALGOD_ADMIN_TOKEN_FILE))
}

fn read_trimmed(path: &Path) -> Result<String, DataDirError> {
    let s = fs::read_to_string(path).map_err(|source| DataDirError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(s.trim().to_string())
}

/// Port of `libgoal/system.go:AlgorandDataIsPrivate`. A data dir is
/// "private" unless its `system.json` is parseable AND sets
/// `shared_server: true`. Missing or unparseable file ⇒ private (the
/// developer default).
pub fn is_algorand_data_private(data_dir: &Path) -> bool {
    if data_dir.as_os_str().is_empty() {
        return true;
    }
    let path = data_dir.join(SYSTEM_JSON_FILE);
    let Ok(text) = fs::read_to_string(&path) else {
        return true;
    };
    // Be tolerant of unknown fields — only `shared_server` matters here.
    #[derive(serde::Deserialize, Default)]
    struct SystemConfig {
        #[serde(default)]
        shared_server: bool,
    }
    match serde_json::from_str::<SystemConfig>(&text) {
        Ok(sc) => !sc.shared_server,
        Err(_) => true,
    }
}

/// Read `<data_dir>/genesis.json` and return the effective Genesis ID
/// (`"<network>-<schema_id>"`), per
/// `../go-algorand/data/bookkeeping/genesis.go:101-103`. The codec tag
/// in Go is `network`/`id`, and the file is JSON; we read those two
/// fields with `serde_json` and stay tolerant of unknown fields.
pub fn read_genesis_id(data_dir: &Path) -> Result<String, DataDirError> {
    let path = data_dir.join(GENESIS_JSON_FILE);
    let text = fs::read_to_string(&path).map_err(|source| DataDirError::Io {
        path: path.clone(),
        source,
    })?;
    #[derive(serde::Deserialize)]
    struct Genesis {
        #[serde(default)]
        network: String,
        #[serde(default)]
        id: String,
    }
    let g: Genesis = serde_json::from_str(&text).map_err(|e| DataDirError::GenesisParse {
        path: path.clone(),
        message: e.to_string(),
    })?;
    Ok(format!("{}-{}", g.network, g.id))
}

/// Port of `cmd/goal/commands.go:resolveKmdDataDir`. Precedence:
/// 1. `kmd_dir_flag` (CLI `-k/--kmddir`) — absolutized.
/// 2. `$ALGORAND_KMD` — absolutized.
/// 3. If the algod data dir is private → `<data_dir>/kmd-v0.5`
///    (absolutized).
/// 4. Otherwise → `<global_config_root>/<genesis_id>/kmd-v0.5`.
///
/// `global_config_root` defaults to `~/.algorand` (per
/// `config.GetGlobalConfigFileRoot`); test code may override via
/// [`resolve_kmd_data_dir_with`].
pub fn resolve_kmd_data_dir(
    kmd_dir_flag: Option<&Path>,
    algod_data_dir: &Path,
) -> Result<PathBuf, DataDirError> {
    resolve_kmd_data_dir_with(
        kmd_dir_flag,
        env::var_os(ALGORAND_KMD_ENV).as_deref(),
        algod_data_dir,
        algorand_data_env().as_deref(),
        &global_config_file_root().unwrap_or_default(),
    )
}

/// Test seam for [`resolve_kmd_data_dir`]. `algod_data_env` mirrors
/// Go's fallback `dataDir = datadir.ResolveDataDir()` applied inside
/// `resolveKmdDataDir` when the input data dir is empty.
pub fn resolve_kmd_data_dir_with(
    kmd_dir_flag: Option<&Path>,
    kmd_env: Option<&std::ffi::OsStr>,
    algod_data_dir: &Path,
    algod_data_env: Option<&std::ffi::OsStr>,
    global_config_root: &Path,
) -> Result<PathBuf, DataDirError> {
    if let Some(p) = kmd_dir_flag {
        return Ok(absolutize(p));
    }
    if let Some(env) = kmd_env {
        if !env.is_empty() {
            return Ok(absolutize(Path::new(env)));
        }
    }
    // Go: `if dataDir == "" { dataDir = datadir.ResolveDataDir() }`.
    let effective: PathBuf = if algod_data_dir.as_os_str().is_empty() {
        match algod_data_env.filter(|s| !s.is_empty()) {
            Some(env) => PathBuf::from(env),
            None => PathBuf::new(),
        }
    } else {
        algod_data_dir.to_path_buf()
    };
    if is_algorand_data_private(&effective) {
        return Ok(absolutize(&effective.join(DEFAULT_KMD_DATA_DIR)));
    }
    let genesis_id = read_genesis_id(&effective)?;
    Ok(global_config_root
        .join(genesis_id)
        .join(DEFAULT_KMD_DATA_DIR))
}

/// `~/.algorand` (mirrors `config.GetGlobalConfigFileRoot`). Unlike Go,
/// we don't `mkdir` here — that's the caller's responsibility if it
/// matters.
pub fn global_config_file_root() -> Option<PathBuf> {
    let home = env::var_os("HOME")?;
    if home.is_empty() {
        return None;
    }
    Some(PathBuf::from(home).join(".algorand"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    /// Turn a Unix-style absolute path literal (e.g. `"/tmp/x"`) into one
    /// that `Path::is_absolute()` recognizes on the current platform.
    /// `absolutize()` deliberately mirrors Go's platform-aware
    /// `filepath.Abs` (a bare `/tmp/x` is NOT absolute on Windows, which
    /// requires a drive prefix), so tests asserting exact `absolutize()`
    /// output need a literal that's genuinely absolute everywhere.
    #[cfg(windows)]
    fn plat_abs(unix_path: &str) -> PathBuf {
        PathBuf::from(format!("C:{}", unix_path.replace('/', "\\")))
    }
    #[cfg(not(windows))]
    fn plat_abs(unix_path: &str) -> PathBuf {
        PathBuf::from(unix_path)
    }

    #[test]
    fn no_d_no_env_returns_error_with_go_exact_message() {
        let err = resolve_data_dirs_with_env(&[], None).unwrap_err();
        assert!(matches!(err, DataDirError::NoDataDirectory));
        // Byte-exact match — operators grep for the literal Go string.
        assert_eq!(err.to_string(), ERROR_NO_DATA_DIRECTORY);
    }

    #[test]
    fn env_only_falls_through_when_cli_empty() {
        let dirs = resolve_data_dirs_with_env(&[], Some(OsStr::new("/tmp/foo"))).unwrap();
        assert_eq!(dirs, vec![PathBuf::from("/tmp/foo")]);
    }

    #[test]
    fn env_empty_string_is_treated_as_unset() {
        let err = resolve_data_dirs_with_env(&[], Some(OsStr::new(""))).unwrap_err();
        assert!(matches!(err, DataDirError::NoDataDirectory));
    }

    #[test]
    fn cli_wins_over_env_and_first_entry_is_absolutized() {
        let d = tmp();
        let a = d.path().join("a");
        let b = PathBuf::from("relative/b");
        std::fs::create_dir(&a).unwrap();
        let cli = vec![a.clone(), b.clone()];
        let dirs =
            resolve_data_dirs_with_env(&cli, Some(OsStr::new("/should/not/be/used"))).unwrap();
        assert_eq!(dirs.len(), 2);
        assert!(
            dirs[0].is_absolute(),
            "first entry must be absolute: {:?}",
            dirs[0]
        );
        // Second entry preserved verbatim (Go's GetDataDirs uses `DataDirs[1:]...`).
        assert_eq!(dirs[1], b);
    }

    #[test]
    fn multi_d_iterates_in_argv_order() {
        let d = tmp();
        let a = d.path().join("a");
        let b = d.path().join("b");
        let c = d.path().join("c");
        for p in [&a, &b, &c] {
            std::fs::create_dir(p).unwrap();
        }
        let cli = vec![a.clone(), b.clone(), c.clone()];
        let mut seen: Vec<PathBuf> = Vec::new();
        on_data_dirs(&cli, |dir| seen.push(dir.to_path_buf())).unwrap();
        assert_eq!(seen.len(), 3, "all dirs visited");
        // First entry comes back absolutized; check the suffix instead
        // of the full path so the test doesn't depend on cwd.
        assert!(seen[0].ends_with("a"));
        assert_eq!(seen[1], b);
        assert_eq!(seen[2], c);
    }

    #[test]
    fn ensure_single_rejects_multi() {
        let cli = vec![PathBuf::from("a"), PathBuf::from("b")];
        let err = ensure_single_data_dir(&cli).unwrap_err();
        assert!(matches!(err, DataDirError::OnlyOneDataDirSupported));
        assert_eq!(err.to_string(), ERROR_ONE_DATA_DIR_SUPPORTED);
    }

    #[test]
    fn is_private_default_when_system_json_missing() {
        let d = tmp();
        assert!(is_algorand_data_private(d.path()));
    }

    #[test]
    fn is_private_false_when_shared_server_true() {
        let d = tmp();
        std::fs::write(d.path().join(SYSTEM_JSON_FILE), r#"{"shared_server":true}"#).unwrap();
        assert!(!is_algorand_data_private(d.path()));
    }

    #[test]
    fn is_private_true_when_shared_server_false() {
        let d = tmp();
        std::fs::write(
            d.path().join(SYSTEM_JSON_FILE),
            r#"{"shared_server":false}"#,
        )
        .unwrap();
        assert!(is_algorand_data_private(d.path()));
    }

    #[test]
    fn algod_net_token_files_round_trip() {
        let d = tmp();
        std::fs::write(d.path().join(ALGOD_NET_FILE), "127.0.0.1:8080\n").unwrap();
        std::fs::write(d.path().join(ALGOD_TOKEN_FILE), "deadbeef\n").unwrap();
        std::fs::write(d.path().join(ALGOD_ADMIN_TOKEN_FILE), "cafe\n").unwrap();
        assert_eq!(read_algod_net(d.path()).unwrap(), "127.0.0.1:8080");
        assert_eq!(read_algod_token(d.path()).unwrap(), "deadbeef");
        assert_eq!(read_algod_admin_token(d.path()).unwrap(), "cafe");
    }

    #[test]
    fn read_genesis_id_concatenates_network_and_id() {
        let d = tmp();
        std::fs::write(
            d.path().join(GENESIS_JSON_FILE),
            r#"{"network":"testnet","id":"v1"}"#,
        )
        .unwrap();
        assert_eq!(read_genesis_id(d.path()).unwrap(), "testnet-v1");
    }

    #[test]
    fn kmd_dir_flag_wins() {
        let d = tmp();
        let flag = plat_abs("/tmp/explicit-kmd");
        let got = resolve_kmd_data_dir_with(
            Some(&flag),
            Some(OsStr::new("/env/should/lose")),
            d.path(),
            None,
            Path::new("/global/should/lose"),
        )
        .unwrap();
        assert_eq!(got, plat_abs("/tmp/explicit-kmd"));
    }

    #[test]
    fn kmd_env_wins_when_no_flag() {
        let d = tmp();
        let env_kmd = plat_abs("/tmp/env-kmd");
        let got = resolve_kmd_data_dir_with(
            None,
            Some(env_kmd.as_os_str()),
            d.path(),
            None,
            Path::new("/global/should/lose"),
        )
        .unwrap();
        assert_eq!(got, plat_abs("/tmp/env-kmd"));
    }

    #[test]
    fn kmd_private_data_dir_uses_default_kmd_subdir() {
        let d = tmp();
        // No system.json ⇒ private (the developer default).
        let got =
            resolve_kmd_data_dir_with(None, None, d.path(), None, Path::new("/global")).unwrap();
        let expected = absolutize(&d.path().join(DEFAULT_KMD_DATA_DIR));
        assert_eq!(got, expected);
    }

    #[test]
    fn kmd_shared_server_uses_global_config_root_with_genesis_id() {
        let d = tmp();
        std::fs::write(d.path().join(SYSTEM_JSON_FILE), r#"{"shared_server":true}"#).unwrap();
        std::fs::write(
            d.path().join(GENESIS_JSON_FILE),
            r#"{"network":"mainnet","id":"v1"}"#,
        )
        .unwrap();
        let got =
            resolve_kmd_data_dir_with(None, None, d.path(), None, Path::new("/global/.algorand"))
                .unwrap();
        assert_eq!(got, PathBuf::from("/global/.algorand/mainnet-v1/kmd-v0.5"));
    }

    #[test]
    fn kmd_empty_data_dir_falls_back_to_algorand_data_env() {
        // Regression guard (Codex review of TASK-221 round 1): when
        // both -k and $ALGORAND_KMD are unset AND the algod data dir
        // arg is empty, Go's resolveKmdDataDir calls
        // `datadir.ResolveDataDir()` to recover from $ALGORAND_DATA.
        // We must not return `<cwd>/kmd-v0.5`.
        let d = tmp();
        // Make `d` a "private" data dir (no system.json).
        let got = resolve_kmd_data_dir_with(
            None,
            None,
            Path::new(""),
            Some(d.path().as_os_str()),
            Path::new("/global"),
        )
        .unwrap();
        let expected = absolutize(&d.path().join(DEFAULT_KMD_DATA_DIR));
        assert_eq!(got, expected);
    }

    #[test]
    fn lexical_clean_collapses_dot_and_double_dot() {
        // Regression guard (Codex review of TASK-221 round 2): Go's
        // filepath.Abs calls Clean lexically. `..` must walk up the
        // path, and `.` must drop, without touching the filesystem.
        assert_eq!(
            lexically_clean(Path::new("/a/b/../c")),
            PathBuf::from("/a/c")
        );
        assert_eq!(lexically_clean(Path::new("/a/./b")), PathBuf::from("/a/b"));
        assert_eq!(lexically_clean(Path::new("/a//b")), PathBuf::from("/a/b"));
        assert_eq!(lexically_clean(Path::new("/..")), PathBuf::from("/"));
        assert_eq!(lexically_clean(Path::new("./a/b")), PathBuf::from("a/b"));
        assert_eq!(lexically_clean(Path::new("a/b/..")), PathBuf::from("a"));
        // `..` at the start of a relative path stays.
        assert_eq!(lexically_clean(Path::new("../a")), PathBuf::from("../a"));
        // Empty path normalizes to ".".
        assert_eq!(lexically_clean(Path::new("")), PathBuf::from("."));
    }

    #[test]
    fn first_d_entry_preserves_symlink_path() {
        // Regression guard (Codex review round 1): Go's filepath.Abs
        // does NOT resolve symlinks; fs::canonicalize would. Verify
        // that a symlinked path comes back as the symlink, not its
        // target.
        #[cfg(unix)]
        {
            let d = tmp();
            let real = d.path().join("real");
            let link = d.path().join("link");
            std::fs::create_dir(&real).unwrap();
            std::os::unix::fs::symlink(&real, &link).unwrap();
            let dirs = resolve_data_dirs_with_env(std::slice::from_ref(&link), None).unwrap();
            assert_eq!(
                dirs[0], link,
                "first -d entry must preserve the symlink path",
            );
        }
    }
}
