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

//! `goal network create` / `pregen` -- port of `cmd/goal/network.go`
//! (issue #1993). The heavy lifting is `algo-netdeploy`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use algo_netdeploy::create::{create_network_from_template, CreateOptions};
use algo_netdeploy::genesis_gen::generate_genesis_files;
use algo_netdeploy::template::NetworkTemplate;
use algo_netdeploy::DEFAULT_NETWORK_TEMPLATE;

use crate::groups::network::{CreateArgs, PregenArgs, StartArgs};

/// `messages.go`.
const INFO_NETWORK_ALREADY_EXISTS: &str = "Network Root Directory '{}' already exists and is not empty";
const ERROR_CREATE_NETWORK: &str = "Error creating private network: ";
const INFO_NETWORK_CREATED: &str = "Network {} created under {}";
const ERROR_LOADING_NETWORK: &str = "Error loading deployed network: ";
const ERROR_STARTING_NETWORK: &str = "Error starting deployed network: ";
const ERROR_NODE_FAILED_TO_START: &str = "Algorand node failed to start: ";
const INFO_NODE_START: &str = "Algorand node successfully started!";

fn fail(message: impl AsRef<str>) -> ExitCode {
    eprintln!("{}", message.as_ref());
    ExitCode::from(1)
}

/// go: cobra's `MarkFlagRequired("rootdir")`.
fn require_rootdir(rootdir: Option<PathBuf>) -> Result<PathBuf, ExitCode> {
    match rootdir {
        Some(p) if !p.as_os_str().is_empty() => Ok(absolute(&p)),
        _ => Err(fail("Error: required flag(s) \"rootdir\" not set")),
    }
}

fn absolute(p: &Path) -> PathBuf {
    if p.is_absolute() {
        return p.to_path_buf();
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(p))
        .unwrap_or_else(|_| p.to_path_buf())
}

/// go: `util.FileExists(dir) && !util.IsEmpty(dir)`.
fn exists_and_not_empty(dir: &Path) -> bool {
    dir.exists() && !algo_netdeploy::create::is_empty(dir)
}

/// go: `util.CopyFolder`.
fn copy_folder(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_folder(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn read_template(file: Option<&Path>) -> Result<String, String> {
    match file {
        None => Ok(DEFAULT_NETWORK_TEMPLATE.to_string()),
        Some(f) => std::fs::read_to_string(absolute(f)).map_err(|e| e.to_string()),
    }
}

/// Port of `networkCreateCmd` (`network.go:118-176`).
pub fn run_create(rootdir: Option<PathBuf>, args: CreateArgs) -> ExitCode {
    let root = match require_rootdir(rootdir) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let template_text = match read_template(args.template.as_deref()) {
        Ok(t) => t,
        Err(e) => return fail(format!("{ERROR_CREATE_NETWORK}{e}")),
    };
    // make sure the target directory does not exist or is empty
    if exists_and_not_empty(&root) {
        return fail(INFO_NETWORK_ALREADY_EXISTS.replacen("{}", &root.display().to_string(), 1));
    }

    // pregendir: copy the pregenerated files in first
    if let Some(pregen) = &args.pregendir {
        if let Err(e) = copy_folder(&absolute(pregen), &root) {
            // a half-copied root would make the next attempt fail on "not empty"
            if !args.noclean {
                let _ = std::fs::remove_dir_all(&root);
            }
            return fail(format!("{ERROR_CREATE_NETWORK}{e}"));
        }
    }

    let opts = CreateOptions {
        name: args.network.clone().unwrap_or_default(),
        dev_mode_override: args.dev_mode,
    };
    let mut out = std::io::stdout();
    let network = match create_network_from_template(&root, &template_text, &opts, &mut out) {
        Ok(n) => n,
        Err(e) => {
            if args.noclean {
                println!(" ** failed ** - Preserving network rootdir '{}'", root.display());
            } else {
                // don't leave a partial network directory if create failed
                if let Err(rm) = std::fs::remove_dir_all(&root) {
                    eprintln!("warning: could not remove the partial network at {}: {rm}", root.display());
                }
            }
            return fail(format!("{ERROR_CREATE_NETWORK}{e}"));
        }
    };

    if !args.noimportkeys {
        if let Err(e) = import_root_keys(&network) {
            return fail(format!("{ERROR_CREATE_NETWORK}{e}"));
        }
    }
    println!(
        "{}",
        INFO_NETWORK_CREATED
            .replacen("{}", network.name(), 1)
            .replacen("{}", &root.display().to_string(), 1)
    );
    if args.start {
        return start_all(&network);
    }
    ExitCode::SUCCESS
}

/// go: `netdeploy.Network.Start`'s key import -- for every node that owns
/// wallets, start its (private) kmd, import the root keys into the
/// `unencrypted-default-wallet` (what `goal account importrootkey -u` does),
/// and stop kmd again.
fn import_root_keys(network: &algo_netdeploy::create::Network) -> Result<(), String> {
    use crate::groups::account::ImportRootKeyArgs;
    use crate::kmdcontrol::KmdController;

    for (name, dir) in &network.node_dirs {
        if !network.node_has_wallet.get(name).copied().unwrap_or(false) {
            continue;
        }
        // (kmd insists on an absolute data dir; `-r` may be relative)
        let node_dir = absolute(&network.root_dir).join(dir);
        let kmd_dir = node_dir.join(crate::data_dir::DEFAULT_KMD_DATA_DIR);
        let controller = KmdController::new(&kmd_dir);
        // (a kmd that was already running is left running)
        let we_started = !controller
            .start(crate::kmdcontrol::DEFAULT_KMD_TIMEOUT_SECS)
            .map_err(|e| format!("failed to start kmd for node {name}: {e}"))?;
        let code = crate::cmd::account::run_importrootkey(
            ImportRootKeyArgs { unencrypted: true, wallet: None, password: None },
            vec![node_dir],
            Some(kmd_dir),
        );
        let stopped = if we_started { controller.stop().map(|_| ()) } else { Ok(()) };
        if code != ExitCode::SUCCESS {
            return Err(format!("failed to import the root keys of node {name}"));
        }
        if let Err(e) = stopped {
            // the keys are in; a kmd we cannot stop (e.g. on Windows) is not fatal
            eprintln!("warning: could not stop kmd for node {name}: {e}");
        }
    }
    Ok(())
}

/// go: `getNetworkAndBinDir`.
fn load_deployed(rootdir: Option<PathBuf>) -> Result<algo_netdeploy::create::Network, ExitCode> {
    let root = require_rootdir(rootdir)?;
    algo_netdeploy::create::load_network(&root)
        .map_err(|e| fail(format!("{ERROR_LOADING_NETWORK}{e}")))
}

/// Relays first, then the other nodes (go: `Network.Start`).
fn start_order(network: &algo_netdeploy::create::Network) -> Vec<PathBuf> {
    let mut dirs = network.relay_data_dirs();
    dirs.extend(network.node_data_dirs());
    dirs
}

/// go: `strings.TrimPrefix(relayAddress, "http://")`, and a relay that
/// listens on every interface is reached on loopback (go dials `[::]:port`,
/// which the OS routes to this host; spelled out here so it holds for any
/// resolver).
fn relay_peer_address(listening: &str) -> String {
    let addr = listening.trim().trim_start_matches("http://");
    let Some((host, port)) = addr.rsplit_once(':') else {
        return addr.to_string();
    };
    match host.trim_matches(|c| c == '[' || c == ']') {
        "" | "0.0.0.0" | "::" => format!("127.0.0.1:{port}"),
        _ => addr.to_string(),
    }
}

/// The `-p` of a non-relay node (go: `startNodes`): every relay's address
/// joined with `;`, or just the relays its template `PeerList` names.
fn node_peer_arg(
    peer_list: &str,
    relays: &[(String, String)],
) -> Result<Option<String>, String> {
    if peer_list.is_empty() {
        let all: Vec<&str> = relays.iter().map(|(_, a)| a.as_str()).collect();
        return Ok((!all.is_empty()).then(|| all.join(";")));
    }
    let mut picked = Vec::new();
    for name in peer_list.split(';') {
        match relays.iter().find(|(n, _)| n == name) {
            Some((_, addr)) => picked.push(addr.as_str()),
            None => return Err(format!("relay {name} is not defined in the network")),
        }
    }
    Ok(Some(picked.join(";")))
}

fn dir_name(dir: &Path) -> String {
    dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()
}

fn start_one(dir: &Path, peer: Option<String>) -> Result<(), String> {
    crate::nodecontrol::NodeController::new(dir)
        .start_algod(&crate::nodecontrol::StartArgs {
            peer_address: peer,
            ..Default::default()
        })
        .map(|_| ())
}

/// go: `getRelayAddress` -- the daemon writes `algod-listen.net` a moment
/// after it answers `/health`; retry for a while.
fn wait_listening_address(dir: &Path) -> Result<String, String> {
    let nc = crate::nodecontrol::NodeController::new(dir);
    let mut last = String::new();
    for _ in 0..300 {
        match nc.listening_address() {
            Ok(a) => return Ok(relay_peer_address(&a)),
            Err(e) => last = e,
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(last)
}

/// go: `GetPeerAddresses` -- the relays that currently publish an address.
fn running_relay_addresses(network: &algo_netdeploy::create::Network) -> Vec<String> {
    network
        .relay_data_dirs()
        .iter()
        .filter_map(|d| crate::nodecontrol::NodeController::new(d).listening_address().ok())
        .map(|a| relay_peer_address(&a))
        .collect()
}

/// Port of `networkStartCmd` (`network.go:204-225`).
pub fn run_start(rootdir: Option<PathBuf>, args: StartArgs) -> ExitCode {
    let network = match load_deployed(rootdir) {
        Ok(n) => n,
        Err(code) => return code,
    };
    if let Some(name) = args.node.as_deref().filter(|n| !n.is_empty()) {
        // (a lone node of a multi-node network would run disconnected)
        let Some(dir) = network.node_dir(name) else {
            return fail(format!("{ERROR_NODE_FAILED_TO_START}node {name} not found"));
        };
        // go: `StartNode` -- the relays that are up
        let relays = running_relay_addresses(&network);
        let peer = (!relays.is_empty()).then(|| relays.join(";"));
        if let Err(e) = start_one(&dir, peer) {
            return fail(format!("{ERROR_NODE_FAILED_TO_START}{e}"));
        }
        println!("{INFO_NODE_START}");
        return ExitCode::SUCCESS;
    }
    start_all(&network)
}

/// go: `Network.Start` -- relays first (each pointed at the previous one),
/// then the other nodes pointed at the relays.
fn start_all(network: &algo_netdeploy::create::Network) -> ExitCode {
    let mut relays: Vec<(String, String)> = Vec::new();
    for dir in network.relay_data_dirs() {
        let previous = relays.last().map(|(_, a)| a.clone());
        if let Err(e) = start_one(&dir, previous) {
            return fail(format!("{ERROR_STARTING_NETWORK}{e}"));
        }
        match wait_listening_address(&dir) {
            Ok(addr) => relays.push((dir_name(&dir), addr)),
            Err(e) => {
                return fail(format!(
                    "{ERROR_STARTING_NETWORK}relay {} did not publish its listening address (algod-listen.net): {e}; does its config.json have a NetAddress?",
                    dir_name(&dir)
                ))
            }
        }
    }
    for dir in network.node_data_dirs() {
        let name = dir_name(&dir);
        let peer_list = network
            .cfg
            .template
            .nodes
            .iter()
            .find(|n| n.name == name)
            .map(|n| n.peer_list.as_str())
            .unwrap_or("");
        let peer = match node_peer_arg(peer_list, &relays) {
            Ok(p) => p,
            Err(e) => return fail(format!("{ERROR_STARTING_NETWORK}{e}")),
        };
        if let Err(e) = start_one(&dir, peer) {
            return fail(format!("{ERROR_STARTING_NETWORK}{e}"));
        }
    }
    println!("Network Started under {}", network.root_dir.display());
    ExitCode::SUCCESS
}

/// go: `Network.Stop` -- every node, errors ignored, relays last.
fn stop_all(network: &algo_netdeploy::create::Network) {
    let mut dirs = network.node_data_dirs();
    dirs.extend(network.relay_data_dirs());
    for dir in dirs {
        let _ = crate::nodecontrol::NodeController::new(&dir).stop_algod();
    }
}

/// Port of `networkStopCmd` (`network.go:242-251`).
pub fn run_stop(rootdir: Option<PathBuf>) -> ExitCode {
    let network = match load_deployed(rootdir) {
        Ok(n) => n,
        Err(code) => return code,
    };
    stop_all(&network);
    println!("Network Stopped under {}", network.root_dir.display());
    ExitCode::SUCCESS
}

/// Port of `networkRestartCmd` (`network.go:227-240`).
pub fn run_restart(rootdir: Option<PathBuf>) -> ExitCode {
    let network = match load_deployed(rootdir) {
        Ok(n) => n,
        Err(code) => return code,
    };
    stop_all(&network);
    start_all(&network)
}

/// Port of `networkStatusCmd` (`network.go:253-270`): the first node that
/// cannot be reached is an error, as in go.
pub fn run_status(rootdir: Option<PathBuf>) -> ExitCode {
    let network = match load_deployed(rootdir) {
        Ok(n) => n,
        Err(code) => return code,
    };
    for dir in start_order(&network) {
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        match crate::cmd::node::status_text(&dir) {
            Ok(text) => print!("\n[{name}]\n{text}\n"),
            Err(e) => return fail(format!("\n[{name}]\n ** Error getting status: {e} **\n")),
        }
    }
    println!();
    ExitCode::SUCCESS
}

/// Port of `networkDeleteCmd` (`network.go:272-286`): stop everything, then
/// remove the network root.
pub fn run_delete(rootdir: Option<PathBuf>) -> ExitCode {
    let network = match load_deployed(rootdir) {
        Ok(n) => n,
        Err(code) => return code,
    };
    stop_all(&network);
    if let Err(e) = std::fs::remove_dir_all(&network.root_dir) {
        return fail(format!("Error stopping or deleting network: {e}\n"));
    }
    println!("Network Deleted under {}", network.root_dir.display());
    ExitCode::SUCCESS
}

/// Port of `networkPregenCmd` (`network.go:296-347`).
pub fn run_pregen(rootdir: Option<PathBuf>, args: PregenArgs) -> ExitCode {
    if rootdir.is_some_and(|r| !r.as_os_str().is_empty()) {
        return fail("This command does not take a network directory as an argument. Use --pregendir flag instead.");
    }
    let Some(pregen) = args.pregendir.as_deref().filter(|p| !p.as_os_str().is_empty()) else {
        return fail("Error: required flag(s) \"pregendir\" not set");
    };
    let pregen = absolute(pregen);
    let template_text = match read_template(args.template.as_deref()) {
        Ok(t) => t,
        Err(e) => return fail(format!("{ERROR_CREATE_NETWORK}{e}")),
    };
    // make sure the target directory does not exist or is empty
    if exists_and_not_empty(&pregen) {
        return fail(INFO_NETWORK_ALREADY_EXISTS.replacen("{}", &pregen.display().to_string(), 1));
    }
    let template = match NetworkTemplate::from_json(&template_text) {
        Ok(t) => t,
        Err(e) => return fail(format!("Error in loading template: {e}\n")),
    };
    if let Err(e) = template.validate() {
        return fail(format!("Error in template validation: {e}\n"));
    }
    let mut out = std::io::stdout();
    if let Err(e) = generate_genesis_files(&template.genesis, &pregen, &mut out) {
        return fail(format!("Cannot write genesis files: {e}"));
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_rootdir_is_gos_required_flag_error() {
        assert!(require_rootdir(None).is_err());
        assert!(require_rootdir(Some(PathBuf::new())).is_err());
        assert!(require_rootdir(Some(PathBuf::from("net"))).is_ok());
    }

    #[test]
    fn relay_addresses_are_loopback_when_the_relay_listens_everywhere() {
        assert_eq!(relay_peer_address("127.0.0.1:4161
"), "127.0.0.1:4161");
        assert_eq!(relay_peer_address("http://10.1.2.3:4160"), "10.1.2.3:4160");
        assert_eq!(relay_peer_address("0.0.0.0:4161"), "127.0.0.1:4161");
        assert_eq!(relay_peer_address("[::]:4161"), "127.0.0.1:4161");
        assert_eq!(relay_peer_address(":4161"), "127.0.0.1:4161");
        assert_eq!(relay_peer_address("relay.example:4161"), "relay.example:4161");
    }

    #[test]
    fn nodes_get_every_relay_or_the_ones_their_peer_list_names() {
        let relays = vec![
            ("R1".to_string(), "127.0.0.1:1".to_string()),
            ("R2".to_string(), "127.0.0.1:2".to_string()),
        ];
        assert_eq!(node_peer_arg("", &relays).unwrap().as_deref(), Some("127.0.0.1:1;127.0.0.1:2"));
        assert_eq!(node_peer_arg("R2", &relays).unwrap().as_deref(), Some("127.0.0.1:2"));
        assert_eq!(node_peer_arg("R2;R1", &relays).unwrap().as_deref(), Some("127.0.0.1:2;127.0.0.1:1"));
        assert_eq!(node_peer_arg("", &[]).unwrap(), None);
        assert_eq!(
            node_peer_arg("Nope", &relays).unwrap_err(),
            "relay Nope is not defined in the network"
        );
    }

    #[test]
    fn emptiness_follows_go() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!exists_and_not_empty(&tmp.path().join("missing")));
        assert!(!exists_and_not_empty(tmp.path()));
        // go's IsEmpty only counts files: the image's empty /algod/data is "empty"
        std::fs::create_dir_all(tmp.path().join("data/sub")).unwrap();
        assert!(!exists_and_not_empty(tmp.path()));
        std::fs::write(tmp.path().join("data/sub/f"), "x").unwrap();
        assert!(exists_and_not_empty(tmp.path()));
    }

    #[test]
    fn copy_folder_copies_recursively() {
        let tmp = tempfile::tempdir().unwrap();
        let from = tmp.path().join("from");
        std::fs::create_dir_all(from.join("sub")).unwrap();
        std::fs::write(from.join("a"), "1").unwrap();
        std::fs::write(from.join("sub/b"), "2").unwrap();
        let to = tmp.path().join("to");
        copy_folder(&from, &to).unwrap();
        assert_eq!(std::fs::read_to_string(to.join("sub/b")).unwrap(), "2");
        assert_eq!(std::fs::read_to_string(to.join("a")).unwrap(), "1");
    }
}
