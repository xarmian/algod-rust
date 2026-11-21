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

//! `goal node create` and `goal node clone` (issue #2512): ports of
//! `createCmd` and `cloneCmd` of `../go-algorand/cmd/goal/node.go` and of
//! `nodecontrol.NodeController.Clone`. Both only touch the local disk.

use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use crate::data_dir::{self, go_os_error};
use crate::groups::node::{CloneArgs, CreateArgs};

/// The genesis files `goal` bundles (`cmd/goal/bundle_genesis_json.sh`: the
/// files of `installer/genesis/<network>` without their trailing newline).
const GENESIS_MAINNET: &[u8] = include_bytes!("../genesis/mainnet.json");
const GENESIS_TESTNET: &[u8] = include_bytes!("../genesis/testnet.json");
const GENESIS_BETANET: &[u8] = include_bytes!("../genesis/betanet.json");
const GENESIS_DEVNET: &[u8] = include_bytes!("../genesis/devnet.json");

/// go's `reportErrorf`: the text and a newline on stderr, exit 1.
fn fail(msg: &str) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::from(1)
}

/// go's `isValidIP`: `host:port` with a non-empty host that is an IP address
/// and a non-empty port.
fn is_valid_ip(user_input: &str) -> bool {
    let Some((host, port)) = split_host_port(user_input) else {
        return false;
    };
    if port.is_empty() || host.is_empty() {
        return false;
    }
    host.parse::<std::net::IpAddr>().is_ok()
}

/// go's `net.SplitHostPort`: `[v6]:port` or `host:port` where host has no
/// colon.
fn split_host_port(hostport: &str) -> Option<(&str, &str)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = after.strip_prefix(':')?;
        if port.contains(':') {
            return None;
        }
        return Some((host, port));
    }
    let i = hostport.rfind(':')?;
    let host = &hostport[..i];
    if host.contains(':') || hostport[i + 1..].contains(['[', ']']) || host.contains(['[', ']']) {
        return None;
    }
    Some((host, &hostport[i + 1..]))
}

/// `goal node create`.
pub fn run_create(args: CreateArgs) -> ExitCode {
    let genesis: &[u8] = match args.network.as_str() {
        "mainnet" => GENESIS_MAINNET,
        "testnet" => GENESIS_TESTNET,
        "betanet" => GENESIS_BETANET,
        "devnet" => GENESIS_DEVNET,
        _ => return fail("Error during node creation: passed network name invalid"),
    };
    let ip_failure = |ip: &str| {
        format!(
            "Parsing passed IP {ip} failed: need a valid IPv4 or IPv6 address with a specified \
             port number"
        )
    };

    let mut net_address = "";
    if !args.relay.is_empty() {
        if is_valid_ip(&args.relay) {
            net_address = &args.relay;
        } else {
            return fail(&ip_failure(&args.relay));
        }
    }
    let mut endpoint_address = None;
    if !args.api.is_empty() {
        if is_valid_ip(&args.api) {
            endpoint_address = Some(args.api.as_str());
        } else {
            return fail(&ip_failure(&args.api));
        }
    }
    let choices = ConfigChoices {
        archival: args.archival || !args.relay.is_empty(),
        net_address,
        endpoint_address,
        run_hosted: args.hosted,
    };

    // the destination must not exist (a file counts), and is created with
    // go's `os.MkdirAll(dest, 0766)`
    let dest = Path::new(&args.destination);
    if std::fs::metadata(dest).is_ok() {
        return fail("Error during node creation: destination folder already exists");
    }
    if mkdir_all(dest, 0o766).is_err() {
        return fail("Error during node creation: could not create destination folder");
    }
    if let Err(e) = std::fs::write(dest.join("genesis.json"), genesis) {
        return fail(&format!(
            "Error during node creation: {}",
            path_error("open", &dest.join("genesis.json"), &e)
        ));
    }
    let saved = std::fs::write(
        dest.join("config.json"),
        config_text(&choices, args.full_config),
    )
    .map_err(|e| path_error("open", &dest.join("config.json"), &e));
    match saved {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&format!("Error during node creation: {e}")),
    }
}

/// go's `config.GetDefaultLocal()` as `Local.SaveAllToDisk` writes it (go
/// v5.0.5-stable, config version 38): tab indented, in the order of go's
/// struct. `node create` only ever changes the fields of [`ConfigChoices`], so
/// its config.json is this text with those values replaced.
const LOCAL_DEFAULT: &str = include_str!("../genesis/local_default.json");

/// What `node create` sets on go's default `Local`.
struct ConfigChoices<'a> {
    archival: bool,
    net_address: &'a str,
    endpoint_address: Option<&'a str>,
    run_hosted: bool,
}

/// The config.json go's `Local.SaveAllToDisk` (`full`: every field, one more
/// newline) or `SaveToDisk` (`codecs.WriteNonDefaultValues`: the lines of the
/// fields that differ from the defaults, `Version` always) writes.
fn config_text(c: &ConfigChoices<'_>, full: bool) -> String {
    let json = |s: &str| serde_json::to_string(s).expect("a string is JSON");
    let endpoint = c.endpoint_address.map(json);
    let overrides: [(&str, String); 6] = [
        ("Archival", c.archival.to_string()),
        ("NetAddress", json(c.net_address)),
        ("RunHosted", c.run_hosted.to_string()),
        ("EnableLedgerService", c.archival.to_string()),
        ("EnableBlockService", c.archival.to_string()),
        ("EndpointAddress", endpoint.unwrap_or_default()),
    ];
    let mut lines: Vec<String> = Vec::new();
    for line in LOCAL_DEFAULT.lines() {
        let key = line
            .strip_prefix("\t\"")
            .and_then(|l| l.split_once("\": "))
            .map(|(k, v)| (k, v.trim_end_matches(',')));
        let Some((key, default_value)) = key else {
            lines.push(line.to_string());
            continue;
        };
        let comma = if line.ends_with(',') { "," } else { "" };
        let new_value = overrides
            .iter()
            .find(|(k, v)| *k == key && !(key == "EndpointAddress" && v.is_empty()))
            .map(|(_, v)| v.as_str());
        match new_value {
            Some(v) => {
                if full || v != default_value {
                    lines.push(format!("\t\"{key}\": {v}{comma}"));
                }
            }
            None if full || key == "Version" => lines.push(line.to_string()),
            None => {}
        }
    }
    if full {
        return lines.join("\n") + "\n";
    }
    // the last value line carries no comma
    if lines.len() > 2 {
        let i = lines.len() - 2;
        if lines[i].ends_with(',') {
            lines[i].pop();
        }
    }
    lines.join("\n")
}

/// go's `os.MkdirAll(path, perm)`: every missing component gets `perm`.
fn mkdir_all(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
}

/// go's `*os.PathError` text: `<op> <path>: <reason>`.
fn path_error(op: &str, path: &Path, e: &io::Error) -> String {
    format!("{op} {}: {}", path.display(), go_os_error(e))
}

/// go's `filepath.Clean` of a joined path (lexical: `.`, `..` and repeated
/// separators removed).
fn go_clean(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    let mut depth = 0usize;
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if depth > 0 {
                    out.pop();
                    depth -= 1;
                } else if !out.has_root() {
                    out.push("..");
                }
            }
            Component::Normal(s) => {
                out.push(s);
                depth += 1;
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

/// go's `os.RemoveAll`: nothing to do for a missing path (or `""`).
fn remove_all(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// go's `os.Mkdir(path, mode)` where an existing directory is not an error
/// (`!os.IsExist(err)`).
fn mkdir_like(path: &Path, source_mode: u32) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(source_mode & 0o777).create(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(path_error("mkdir", path, &e)),
    }
}

/// go's `util.CopyFile`: `Ok(None)` copied, `Ok(Some(path_error))` when
/// `os.Stat`/`Open`/`Create` failed (a `*os.PathError`), `Err` for any other
/// failure.
fn copy_file(src: &Path, dst: &Path) -> Result<Option<String>, String> {
    let meta = match std::fs::metadata(src) {
        Ok(m) => m,
        Err(e) => return Ok(Some(path_error("stat", src, &e))),
    };
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", src.display()));
    }
    let mut source = match std::fs::File::open(src) {
        Ok(f) => f,
        Err(e) => return Ok(Some(path_error("open", src, &e))),
    };
    let mut destination = match std::fs::File::create(dst) {
        Ok(f) => f,
        Err(e) => return Ok(Some(path_error("open", dst, &e))),
    };
    io::copy(&mut source, &mut destination).map_err(|e| e.to_string())?;
    Ok(None)
}

/// `goal node clone`.
pub fn run_clone(args: CloneArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    // go: `util.ExeDir()` then `datadir.EnsureSingleDataDir()`
    let data_dir = match data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => return fail(&e.to_string()),
    };
    match clone_node(&data_dir, &args.targetdir, !args.noledger) {
        Ok(()) => {
            println!("Node cloned successfully to: {}", args.targetdir);
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("Error cloning the node: {e}")),
    }
}

/// go's `NodeController.Clone(targetDir, copyLedger)`.
fn clone_node(data_dir: &Path, target: &str, copy_ledger: bool) -> Result<(), String> {
    let target_dir = Path::new(target);
    remove_all(target_dir)
        .map_err(|e| format!("unable to delete directory '{target}' : {}", go_os_error(&e)))?;

    let source_mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(data_dir)
            .map_err(|e| path_error("stat", data_dir, &e))?
            .permissions()
            .mode()
    };
    mkdir_like(target_dir, source_mode)?;

    // the core files, silently skipping those that do not exist
    for file in ["genesis.json", "config.json", "phonebook.json"] {
        let src = data_dir.join(file);
        if std::fs::metadata(&src).is_ok() {
            copy_file(&src, &target_dir.join(file))?;
        }
    }

    if copy_ledger {
        let genesis_id = data_dir::read_genesis_id(data_dir).map_err(|e| e.to_string())?;
        let genesis_folder = data_dir.join(&genesis_id);
        let folder_mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(&genesis_folder)
                .map_err(|e| path_error("stat", &genesis_folder, &e))?
                .permissions()
                .mode()
        };
        let target_genesis_folder = go_clean(&target_dir.join(&genesis_id));
        mkdir_like(&target_genesis_folder, folder_mode)?;
        for file in [
            "ledger.block.sqlite",
            "ledger.block.sqlite-shm",
            "ledger.block.sqlite-wal",
            "ledger.tracker.sqlite",
            "ledger.tracker.sqlite-shm",
            "ledger.tracker.sqlite-wal",
        ] {
            let src = genesis_folder.join(file);
            let dest = target_genesis_folder.join(file);
            let failure = copy_file(&src, &dest).map_err(|e| e.to_string());
            match failure {
                Ok(None) => {}
                Ok(Some(e)) | Err(e) => {
                    return Err(format!(
                        "unable to copy '{}' to '{}' : {e}",
                        src.display(),
                        dest.display()
                    ));
                }
            }
        }
    }
    Ok(())
}
