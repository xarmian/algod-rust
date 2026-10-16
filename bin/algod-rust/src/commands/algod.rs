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

//! go-compatible `algod -d <datadir>` launcher (issue #1990).
//!
//! go-algorand's `cmd/algod/main.go` derives everything from the data
//! directory: `genesis.json` gives the genesis ID, the ledger lives at
//! `<dir>/<genesisID>/ledger.*`, `config.json` supplies the network and REST
//! settings, `algod.lock` guarantees a single instance and `algod.pid` lets
//! `goal node stop` find the process. `participate` takes explicit paths for
//! all of that, so this module is the translation layer: [`plan`] turns the
//! go-style flags into an equivalent `participate` argument vector (a pure
//! function, unit-tested without starting anything) and [`InstanceGuard`]
//! provides the lock and pid file.
//!
//! Flag mapping (go `cmd/algod/main.go:50-62`): `-d` data dir (else
//! `$ALGORAND_DATA`), `-g` genesis file, `-G` print genesis ID, `-v` version,
//! `-o` log to stdout (algod-rust always logs to stdout/stderr, so a no-op),
//! `-p` phonebook override (`;`-separated), `-l` REST listen address.
//! `-s`/`-t`/`--seed` (telemetry session / telemetry override / math seed)
//! are accepted and ignored because algod-rust has no telemetry; `-x`
//! (initialize the ledger and exit) is rejected with an explicit message.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// go's `-d`/`-g`/... flags, already parsed by clap.
#[derive(Debug, Default, Clone)]
pub struct AlgodArgs {
    pub data_dir: Option<PathBuf>,
    pub genesis: Option<PathBuf>,
    pub print_genesis_id: bool,
    pub version: bool,
    pub init_and_exit: bool,
    pub peers: Option<String>,
    pub listen: Option<String>,
}

/// What [`plan`] decided.
#[derive(Debug)]
pub enum Outcome {
    /// Print this and exit 0 (`-v`, `-G`).
    Print(String),
    /// Start the node.
    Launch(LaunchPlan),
}

#[derive(Debug)]
pub struct LaunchPlan {
    /// Absolute data directory (where `algod.lock`/`algod.pid` live).
    pub data_dir: PathBuf,
    /// go's `Genesis.ID()`: `<network>-<id>`.
    pub genesis_id: String,
    /// argv for the equivalent `algod-rust participate ...` (element 0 is the
    /// program name).
    pub participate_argv: Vec<String>,
}

/// Turn go's flags into an [`Outcome`], in the order go's `run()` checks them
/// (`cmd/algod/main.go:75-`): resolve the data dir (`-d`, else
/// `$ALGORAND_DATA`), `-v`, "data directory not specified", genesis load,
/// `-G`, "data directory does not appear to be valid".
pub fn plan(args: &AlgodArgs, algorand_data_env: Option<&str>) -> Result<Outcome, String> {
    let data_dir = args
        .data_dir
        .clone()
        .or_else(|| algorand_data_env.filter(|v| !v.is_empty()).map(PathBuf::from));

    if args.version {
        return Ok(Outcome::Print(format!(
            "algod-rust {}",
            env!("CARGO_PKG_VERSION")
        )));
    }

    let Some(data_dir) = data_dir else {
        return Err(
            "Data directory not specified.  Please use -d or set $ALGORAND_DATA in your environment."
                .to_string(),
        );
    };

    if args.init_and_exit {
        return Err(
            "-x (initialize the ledger and exit) is not supported by algod-rust".to_string(),
        );
    }

    // go's `loadGenesis(dataDir, genesisPath)`: the error text carries the
    // `-g` value as given (empty when defaulted), not the resolved path.
    let genesis_arg = args
        .genesis
        .as_ref()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let genesis_path = args
        .genesis
        .clone()
        .unwrap_or_else(|| data_dir.join("genesis.json"));
    let genesis_text = std::fs::read_to_string(&genesis_path)
        .map_err(|e| format!("Error loading genesis file ({genesis_arg}): {e}"))?;
    let genesis = algo_ledger::genesis::parse_genesis_json(&genesis_text)
        .map_err(|e| format!("Error loading genesis file ({genesis_arg}): {e}"))?;
    let genesis_id = format!("{}-{}", genesis.network, genesis.id);

    if args.print_genesis_id {
        return Ok(Outcome::Print(genesis_id));
    }

    if std::fs::metadata(&data_dir).is_err() {
        return Err(format!(
            "Data directory {} does not appear to be valid",
            data_dir.display()
        ));
    }
    let abs = std::fs::canonicalize(&data_dir).map_err(|_| {
        format!(
            "Can't convert data directory's path to absolute, {}",
            data_dir.display()
        )
    })?;
    // `canonicalize` yields a verbatim (`\\?\`) path on Windows; keep the plain form.
    let abs = strip_verbatim(abs);
    let genesis_dir = abs.join(&genesis_id);
    // go: `log.Fatalf("Cannot load config: %v", err)` for anything but a
    // missing file. `participate` itself would only warn and use defaults.
    validate_config(&abs)?;
    let genesis_abs = match args.genesis.as_deref() {
        None => abs.join("genesis.json"),
        Some(g) => genesis_path_abs(g),
    };

    let mut argv: Vec<String> = vec![
        "algod-rust".into(),
        "participate".into(),
        "--ledger-path".into(),
        path_str(&genesis_dir.join("ledger")),
        "--partkey-path".into(),
        path_str(&genesis_dir.join("partregistry.sqlite")),
        "--genesis-id".into(),
        genesis_id.clone(),
        "--network".into(),
        genesis.network.clone(),
        "--genesis-json".into(),
        path_str(&genesis_abs),
        "--genesis-path".into(),
        path_str(&genesis_abs),
        "--data-dir".into(),
        path_str(&abs),
    ];

    // `-p` replaces the phonebook (and, in go, disables DNS bootstrap, which
    // `participate` only consults when `--peers` is empty).
    if let Some(peers) = args.peers.as_deref().filter(|p| !p.is_empty()) {
        let list: Vec<&str> = peers
            .split(';')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .collect();
        if !list.is_empty() {
            argv.push("--peers".into());
            argv.push(list.join(","));
        }
    }
    // `-l` overrides `EndpointAddress`; otherwise `participate` reads it from
    // `<data-dir>/config.json` itself.
    if let Some(listen) = args.listen.as_deref().filter(|l| !l.is_empty()) {
        argv.push("--rest-listen".into());
        argv.push(listen.to_string());
    }
    // go's `NetAddress` is deliberately not a `config.Local` field in
    // algod-rust (see `algo_config`'s #788 note); the launcher is the one
    // place that reads it, and a listening node relays, as in go.
    if let Some(net_address) = config_net_address(&abs) {
        argv.push("--listen-address".into());
        argv.push(net_address);
        argv.push("--relay-messages".into());
    }

    Ok(Outcome::Launch(LaunchPlan {
        data_dir: abs,
        genesis_id,
        participate_argv: argv,
    }))
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().to_string()
}

/// The genesis file as an absolute path (`-g` may be relative to the cwd).
fn genesis_path_abs(genesis_path: &Path) -> PathBuf {
    if genesis_path.is_absolute() {
        return genesis_path.to_path_buf();
    }
    std::fs::canonicalize(genesis_path)
        .map(strip_verbatim)
        .unwrap_or_else(|_| {
            std::env::current_dir()
                .map(|cwd| cwd.join(genesis_path))
                .unwrap_or_else(|_| genesis_path.to_path_buf())
        })
}

#[cfg(windows)]
fn strip_verbatim(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => p,
    }
}

#[cfg(not(windows))]
fn strip_verbatim(p: PathBuf) -> PathBuf {
    p
}

/// go refuses to start on a `config.json` it cannot load (`cmd/algod/main.go`);
/// a missing file is fine. `NetAddress` must be a string when present.
fn validate_config(data_dir: &Path) -> Result<(), String> {
    if let Err(e) = algo_config::Local::load_from_data_dir(data_dir) {
        return Err(format!("Cannot load config: {e}"));
    }
    if let Ok(text) = std::fs::read_to_string(data_dir.join("config.json")) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
            if value.get("NetAddress").is_some_and(|v| !v.is_string()) {
                return Err("Cannot load config: NetAddress must be a string".to_string());
            }
        }
    }
    Ok(())
}

/// `NetAddress` from `<data-dir>/config.json`, normalised to `host:port`
/// (go accepts `:4161` for "all interfaces"). `None` when absent or empty.
fn config_net_address(data_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(data_dir.join("config.json")).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let addr = value.get("NetAddress")?.as_str()?.trim().to_string();
    if addr.is_empty() {
        None
    } else if addr.starts_with(':') {
        Some(format!("0.0.0.0{addr}"))
    } else {
        Some(addr)
    }
}

/// Holds `algod.lock` and `algod.pid` for the life of the process.
pub struct InstanceGuard {
    _lock: File,
    pid_path: PathBuf,
}

impl InstanceGuard {
    /// go: `flock.New(<dir>/algod.lock).TryLock()` (`cmd/algod/main.go`), then
    /// `algod.pid` (`daemon/algod/server.go`) holding this process id.
    pub fn acquire(data_dir: &Path) -> Result<Self, String> {
        let lock_path = data_dir.join("algod.lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| format!("unexpected failure in establishing algod.lock: {e} \n"))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(
                    "failed to lock algod.lock; is an instance of algod already running in this data directory?"
                        .to_string(),
                );
            }
            Err(TryLockError::Error(e)) => {
                return Err(format!(
                    "unexpected failure in establishing algod.lock: {e} \n"
                ));
            }
        }
        let pid_path = data_dir.join("algod.pid");
        let mut pid_file = File::create(&pid_path)
            .map_err(|e| format!("failed to write {}: {e}", pid_path.display()))?;
        writeln!(pid_file, "{}", std::process::id())
            .map_err(|e| format!("failed to write {}: {e}", pid_path.display()))?;
        Ok(Self {
            _lock: lock,
            pid_path,
        })
    }
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.pid_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Commands};
    use clap::Parser;

    const GENESIS: &str = include_str!("../../../../docker/localnet-rust/data/genesis.json");

    /// A data dir holding a go-layout `genesis.json` (and optionally a
    /// `config.json`).
    fn data_dir(config: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("genesis.json"), GENESIS).expect("genesis");
        if let Some(c) = config {
            std::fs::write(dir.path().join("config.json"), c).expect("config");
        }
        dir
    }

    fn args_for(dir: &Path) -> AlgodArgs {
        AlgodArgs {
            data_dir: Some(dir.to_path_buf()),
            ..AlgodArgs::default()
        }
    }

    fn launch(args: &AlgodArgs) -> LaunchPlan {
        match plan(args, None).expect("plan") {
            Outcome::Launch(p) => p,
            other => panic!("expected a launch plan, got {other:?}"),
        }
    }

    fn flag_value<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
        argv.iter()
            .position(|a| a == flag)
            .and_then(|i| argv.get(i + 1))
            .map(String::as_str)
    }

    #[test]
    fn missing_data_dir_is_gos_error_text() {
        let err = plan(&AlgodArgs::default(), None).unwrap_err();
        assert_eq!(
            err,
            "Data directory not specified.  Please use -d or set $ALGORAND_DATA in your environment."
        );
    }

    #[test]
    fn algorand_data_env_is_the_fallback_for_dash_d() {
        let dir = data_dir(None);
        let env = dir.path().to_string_lossy().to_string();
        match plan(&AlgodArgs::default(), Some(&env)).expect("plan") {
            Outcome::Launch(p) => assert_eq!(p.genesis_id, "localnet-rust-v1"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn version_and_genesis_id_print_without_starting() {
        let dir = data_dir(None);
        let v = AlgodArgs {
            version: true,
            ..AlgodArgs::default()
        };
        match plan(&v, None).expect("plan") {
            Outcome::Print(s) => assert!(s.starts_with("algod-rust "), "{s}"),
            other => panic!("{other:?}"),
        }
        let g = AlgodArgs {
            print_genesis_id: true,
            ..args_for(dir.path())
        };
        match plan(&g, None).expect("plan") {
            Outcome::Print(s) => assert_eq!(s, "localnet-rust-v1"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_missing_genesis_file_is_reported_like_go() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = plan(&args_for(dir.path()), None).unwrap_err();
        // go prints the -g value (empty when defaulted), then the OS error
        assert!(err.starts_with("Error loading genesis file (): "), "{err}");
    }

    #[test]
    fn a_nonexistent_data_dir_is_rejected_after_the_genesis_loads() {
        let elsewhere = tempfile::tempdir().expect("tempdir");
        let genesis = elsewhere.path().join("g.json");
        std::fs::write(&genesis, GENESIS).expect("genesis");
        let args = AlgodArgs {
            data_dir: Some(elsewhere.path().join("nope")),
            genesis: Some(genesis),
            ..AlgodArgs::default()
        };
        let err = plan(&args, None).unwrap_err();
        assert!(err.contains("does not appear to be valid"), "{err}");
    }

    #[test]
    fn init_and_exit_is_refused_explicitly() {
        let dir = data_dir(None);
        let args = AlgodArgs {
            init_and_exit: true,
            ..args_for(dir.path())
        };
        let err = plan(&args, None).unwrap_err();
        assert!(err.contains("-x"), "{err}");
    }

    #[test]
    fn the_plan_derives_go_layout_paths_from_the_data_dir() {
        let dir = data_dir(None);
        let p = launch(&args_for(dir.path()));
        assert_eq!(p.genesis_id, "localnet-rust-v1");
        let argv = &p.participate_argv;
        assert_eq!(argv[1], "participate");
        let abs = strip_verbatim(std::fs::canonicalize(dir.path()).expect("abs"));
        let genesis_dir = abs.join("localnet-rust-v1");
        assert_eq!(
            flag_value(argv, "--ledger-path").map(Path::new),
            Some(genesis_dir.join("ledger").as_path())
        );
        assert_eq!(
            flag_value(argv, "--partkey-path").map(Path::new),
            Some(genesis_dir.join("partregistry.sqlite").as_path())
        );
        assert_eq!(flag_value(argv, "--genesis-id"), Some("localnet-rust-v1"));
        assert_eq!(flag_value(argv, "--network"), Some("localnet-rust"));
        assert_eq!(
            flag_value(argv, "--data-dir").map(Path::new),
            Some(abs.as_path())
        );
        assert_eq!(
            flag_value(argv, "--genesis-json").map(Path::new),
            Some(abs.join("genesis.json").as_path())
        );
        assert_eq!(
            flag_value(argv, "--genesis-path").map(Path::new),
            Some(abs.join("genesis.json").as_path())
        );
        // nothing the flags did not ask for
        assert!(flag_value(argv, "--peers").is_none());
        assert!(flag_value(argv, "--rest-listen").is_none());
        assert!(flag_value(argv, "--listen-address").is_none());
        assert!(!argv.iter().any(|a| a == "--relay-messages"));
    }

    #[test]
    fn dash_g_overrides_the_genesis_file() {
        let dir = data_dir(None);
        let other = tempfile::tempdir().expect("tempdir");
        let g = other.path().join("custom.json");
        std::fs::write(&g, GENESIS).expect("genesis");
        let args = AlgodArgs {
            genesis: Some(g.clone()),
            ..args_for(dir.path())
        };
        let p = launch(&args);
        assert_eq!(
            flag_value(&p.participate_argv, "--genesis-json").map(Path::new),
            Some(g.as_path())
        );
    }

    #[test]
    fn dash_p_and_dash_l_override_peers_and_rest_address() {
        let dir = data_dir(None);
        let args = AlgodArgs {
            peers: Some("10.0.0.1:4160;10.0.0.2:4160".into()),
            listen: Some("0.0.0.0:8080".into()),
            ..args_for(dir.path())
        };
        let p = launch(&args);
        assert_eq!(
            flag_value(&p.participate_argv, "--peers"),
            Some("10.0.0.1:4160,10.0.0.2:4160")
        );
        assert_eq!(
            flag_value(&p.participate_argv, "--rest-listen"),
            Some("0.0.0.0:8080")
        );
    }

    #[test]
    fn config_json_net_address_becomes_the_gossip_listener() {
        // go's NetAddress ":4161" means all interfaces; participate wants host:port
        let dir = data_dir(Some(r#"{"NetAddress": ":4161"}"#));
        let p = launch(&args_for(dir.path()));
        assert_eq!(
            flag_value(&p.participate_argv, "--listen-address"),
            Some("0.0.0.0:4161")
        );
        // a listening node relays, as go's NetAddress != "" nodes do
        assert!(p.participate_argv.iter().any(|a| a == "--relay-messages"));

        let dir = data_dir(Some(r#"{"NetAddress": "127.0.0.1:4161"}"#));
        let p = launch(&args_for(dir.path()));
        assert_eq!(
            flag_value(&p.participate_argv, "--listen-address"),
            Some("127.0.0.1:4161")
        );
    }

    #[test]
    fn dash_p_drops_empty_segments_and_trims_whitespace() {
        let dir = data_dir(None);
        let args = AlgodArgs {
            peers: Some(" 10.0.0.1:4160 ;; 10.0.0.2:4160;".into()),
            ..args_for(dir.path())
        };
        let p = launch(&args);
        assert_eq!(
            flag_value(&p.participate_argv, "--peers"),
            Some("10.0.0.1:4160,10.0.0.2:4160")
        );
    }

    #[test]
    fn a_malformed_config_json_refuses_to_start_like_go() {
        // go: `log.Fatalf("Cannot load config: %v", err)` unless the file is absent
        let dir = data_dir(Some("{ this is not json"));
        let err = plan(&args_for(dir.path()), None).unwrap_err();
        assert!(err.starts_with("Cannot load config: "), "{err}");

        // a NetAddress that is not a string is a config error too
        let dir = data_dir(Some(r#"{"NetAddress": 4161}"#));
        let err = plan(&args_for(dir.path()), None).unwrap_err();
        assert!(err.starts_with("Cannot load config: "), "{err}");

        // a missing config.json is fine (defaults)
        let dir = data_dir(None);
        plan(&args_for(dir.path()), None).expect("no config.json is not an error");
    }

    #[test]
    fn a_relative_dash_g_is_resolved_against_the_cwd_not_the_data_dir() {
        let dir = data_dir(None);
        // a file name that exists only relative to the current directory
        let name = format!("algod-launcher-test-genesis-{}.json", std::process::id());
        let cwd = std::env::current_dir().expect("cwd");
        let path = cwd.join(&name);
        std::fs::write(&path, GENESIS).expect("genesis in cwd");
        let args = AlgodArgs {
            genesis: Some(PathBuf::from(&name)),
            ..args_for(dir.path())
        };
        let result = plan(&args, None);
        let _ = std::fs::remove_file(&path);
        let p = match result.expect("plan") {
            Outcome::Launch(p) => p,
            other => panic!("{other:?}"),
        };
        let got = flag_value(&p.participate_argv, "--genesis-json").expect("flag");
        assert!(
            Path::new(got).is_absolute() && got.ends_with(&name),
            "relative -g must become an absolute path to that file, got {got}"
        );
    }

    #[test]
    fn the_plan_is_a_valid_participate_command_line() {
        let dir = data_dir(Some(r#"{"NetAddress": ":4161"}"#));
        let args = AlgodArgs {
            peers: Some("10.0.0.1:4160".into()),
            listen: Some("0.0.0.0:8080".into()),
            ..args_for(dir.path())
        };
        let p = launch(&args);
        let cli = Cli::try_parse_from(&p.participate_argv).expect("argv parses");
        assert!(matches!(cli.command, Commands::Participate { .. }));
    }

    #[test]
    fn a_second_instance_on_one_data_dir_is_refused_like_go() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = InstanceGuard::acquire(dir.path()).expect("first");
        let err = InstanceGuard::acquire(dir.path()).err().expect("second must fail");
        assert_eq!(
            err,
            "failed to lock algod.lock; is an instance of algod already running in this data directory?"
        );
        drop(first);
        InstanceGuard::acquire(dir.path()).expect("re-acquire after release");
    }

    #[test]
    fn the_pid_file_holds_this_process_and_is_removed_on_exit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_path = dir.path().join("algod.pid");
        {
            let _guard = InstanceGuard::acquire(dir.path()).expect("acquire");
            let text = std::fs::read_to_string(&pid_path).expect("pid file");
            assert_eq!(text.trim(), std::process::id().to_string());
        }
        assert!(!pid_path.exists(), "algod.pid must go away with the process");
    }
}
