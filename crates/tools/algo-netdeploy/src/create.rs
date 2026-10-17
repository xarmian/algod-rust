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

//! Creating a private network on disk: port of `netdeploy.CreateNetworkFromTemplate`
//! and `NetworkTemplate.createNodeDirectories` / `createConfigFile`
//! (`netdeploy/network.go`, `netdeploy/networkTemplate.go`).
//!
//! Layout (go's): `<root>/genesis.json`, the generated `*.rootkey` /
//! `*.partkey` files, one directory per node holding `genesis.json`,
//! `config.json` and `<genesisID>/<keys of that node's wallets>`, and
//! `<root>/network.json`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::genesis_gen::{generate_genesis_files, root_key_filename, GenError};
use crate::template::{decode_override, NetworkTemplate, NodeConfig, TemplateError};

pub const NETWORK_CONFIG_FILE: &str = "network.json";
pub const GENESIS_FILE: &str = "genesis.json";

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("{0}")]
    Template(#[from] TemplateError),
    #[error("{0}")]
    Gen(#[from] GenError),
    #[error("{0}")]
    Msg(String),
}

fn msg<T>(m: impl Into<String>) -> Result<T, CreateError> {
    Err(CreateError::Msg(m.into()))
}

/// go: `NetworkCfg` (`network.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct NetworkCfg {
    #[serde(rename = "Name", default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Relay directories, relative to the root directory.
    #[serde(rename = "RelayDirs", default, skip_serializing_if = "Vec::is_empty")]
    pub relay_dirs: Vec<String>,
    #[serde(rename = "Template", default)]
    pub template: NetworkTemplate,
}

/// A created network.
#[derive(Debug, Clone)]
pub struct Network {
    pub root_dir: PathBuf,
    pub cfg: NetworkCfg,
    /// Non-relay node name -> directory name (relative to the root).
    pub node_dirs: BTreeMap<String, String>,
    /// Node name -> whether the node was given any wallet key files.
    pub node_has_wallet: BTreeMap<String, bool>,
}

impl Network {
    pub fn name(&self) -> &str {
        &self.cfg.name
    }
}

impl Network {
    /// go: `RelayDataDirs` -- the relay node directories, in creation order.
    pub fn relay_data_dirs(&self) -> Vec<PathBuf> {
        self.cfg.relay_dirs.iter().map(|d| self.root_dir.join(d)).collect()
    }

    /// go: `NodeDataDirs` -- the non-relay node directories, by node name.
    pub fn node_data_dirs(&self) -> Vec<PathBuf> {
        self.node_dirs.values().map(|d| self.root_dir.join(d)).collect()
    }

    /// go: `GetNodeDir` -- the directory of the relay or node called `name`.
    pub fn node_dir(&self, name: &str) -> Option<PathBuf> {
        self.node_dirs
            .get(name)
            .map(String::as_str)
            .or_else(|| self.cfg.relay_dirs.iter().map(String::as_str).find(|d| *d == name))
            .map(|d| self.root_dir.join(d))
    }
}

/// go: `netdeploy.LoadNetwork` -- read `<root>/network.json`.
pub fn load_network(root_dir: &Path) -> Result<Network, CreateError> {
    let path = root_dir.join(NETWORK_CONFIG_FILE);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| CreateError::Msg(format!("open {}: {e}", path.display())))?;
    let cfg: NetworkCfg = serde_json::from_str(&text)
        .map_err(|e| CreateError::Msg(format!("{}: {e}", path.display())))?;
    let node_dirs = cfg
        .template
        .nodes
        .iter()
        .filter(|n| !n.is_relay)
        .map(|n| (n.name.clone(), n.name.clone()))
        .collect();
    let node_has_wallet = cfg
        .template
        .nodes
        .iter()
        .map(|n| (n.name.clone(), !n.wallets.is_empty()))
        .collect();
    Ok(Network {
        root_dir: root_dir.to_path_buf(),
        cfg,
        node_dirs,
        node_has_wallet,
    })
}

#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    /// `--network`; falls back to the template's `Genesis.NetworkName`.
    pub name: String,
    /// `--devMode`: go's `OverrideDevMode`.
    pub dev_mode_override: bool,
}

/// go: `isRootKeyFilename`.
pub fn is_root_key_filename(name: &str) -> bool {
    name.strip_suffix(".rootkey").is_some_and(|s| !s.is_empty())
}

/// go: `IsPartKeyFilename` -- `<name>.<first>.<last>.partkey`.
pub fn is_part_key_filename(name: &str) -> bool {
    part_key_wallet(name).is_some()
}

/// The wallet name of a participation key file name, if it is one.
fn part_key_wallet(name: &str) -> Option<&str> {
    let stem = name.strip_suffix(".partkey")?;
    let (rest, last) = stem.rsplit_once('.')?;
    let (wallet, first) = rest.rsplit_once('.')?;
    if wallet.is_empty() || first.parse::<u64>().is_err() || last.parse::<u64>().is_err() {
        return None;
    }
    Some(wallet)
}

/// go: `config.MatchesRootKeyFilename`.
pub fn matches_root_key_filename(wallet: &str, name: &str) -> bool {
    name == root_key_filename(wallet)
}

/// go: `config.MatchesPartKeyFilename`.
pub fn matches_part_key_filename(wallet: &str, name: &str) -> bool {
    part_key_wallet(name) == Some(wallet)
}

/// go: `createConfigFile` -- the non-default settings of a private-network
/// node's `config.json`.
pub fn node_config_json(
    node: &NodeConfig,
    num_other_nodes: usize,
    relays_count: usize,
) -> Result<Map<String, Value>, CreateError> {
    let mut cfg = Map::new();
    cfg.insert("GossipFanout".into(), json!(num_other_nodes));
    // override the default :8080 REST endpoint, and disable SRV lookup
    cfg.insert("EndpointAddress".into(), json!("127.0.0.1:0"));
    cfg.insert("DNSBootstrapID".into(), json!(""));
    cfg.insert("EnableProfiler".into(), json!(true));
    cfg.insert("EnableRuntimeMetrics".into(), json!(true));
    cfg.insert("EnableExperimentalAPI".into(), json!(true));
    if relays_count == 0 {
        cfg.insert("DisableNetworking".into(), json!(true));
    }
    if node.is_relay {
        // relays listen on any localhost port
        cfg.insert("NetAddress".into(), json!("127.0.0.1:0"));
        cfg.insert("Archival".into(), json!(false));
        // to save blocks beyond MaxTxnLife=13
        cfg.insert("MaxBlockHistoryLookback".into(), json!(20000));
    } else {
        // non-relays should not open incoming connections
        cfg.insert("IncomingConnectionsLimit".into(), json!(0));
    }
    if let Some(over) = decode_override(&node.config_json_override)
        .map_err(|e| CreateError::Msg(format!("invalid ConfigJSONOverride: {e}")))?
    {
        for (k, v) in over {
            cfg.insert(k, v);
        }
    }
    Ok(cfg)
}

fn copy_file(from: &Path, to: &Path) -> Result<(), CreateError> {
    std::fs::copy(from, to)
        .map(|_| ())
        .map_err(|e| CreateError::Msg(format!("copying {} to {}: {e}", from.display(), to.display())))
}

fn dir_is_empty(dir: &Path) -> bool {
    is_empty(dir)
}

/// go: `util.IsEmpty` -- true when the tree under `path` holds no files
/// (directories alone do not count; an unreadable tree is not empty).
pub fn is_empty(path: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(path) else {
        return !path.exists();
    };
    for entry in entries {
        let Ok(entry) = entry else { return false };
        match entry.file_type() {
            Ok(t) if t.is_dir() => {
                if !is_empty(&entry.path()) {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

/// go: `CreateNetworkFromTemplate` (key import into kmd is the caller's step).
pub fn create_network_from_template(
    root_dir: &Path,
    template_text: &str,
    opts: &CreateOptions,
    log: &mut (dyn Write + Send),
) -> Result<Network, CreateError> {
    let mut template = NetworkTemplate::from_json(template_text)?;
    if opts.dev_mode_override {
        template.override_dev_mode();
    }
    template.validate()?;

    let name = if opts.name.is_empty() {
        template.genesis.network_name.clone()
    } else {
        opts.name.clone()
    };
    if name.is_empty() {
        return msg(
            "unnamed network. Use the \"network\" flag or \"Genesis.NetworkName\" in the network template",
        );
    }

    // create the root directory so genesis.json and the node directories fit in
    std::fs::create_dir_all(root_dir)
        .map_err(|e| CreateError::Msg(format!("creating {}: {e}", root_dir.display())))?;
    let mut genesis = template.genesis.clone();
    genesis.network_name = name.clone();
    generate_genesis_files(&genesis, root_dir, log)?;

    let (relay_dirs, node_dirs, node_has_wallet) = create_node_directories(&template, root_dir)?;

    let cfg = NetworkCfg {
        name,
        relay_dirs,
        template,
    };
    let mut text = serde_json::to_string_pretty(&cfg).map_err(|e| CreateError::Msg(e.to_string()))?;
    text.push('\n');
    std::fs::write(root_dir.join(NETWORK_CONFIG_FILE), text)
        .map_err(|e| CreateError::Msg(format!("writing network.json: {e}")))?;

    Ok(Network {
        root_dir: root_dir.to_path_buf(),
        cfg,
        node_dirs,
        node_has_wallet,
    })
}

type NodeDirs = (Vec<String>, BTreeMap<String, String>, BTreeMap<String, bool>);

/// go: `createNodeDirectories`.
fn create_node_directories(template: &NetworkTemplate, root: &Path) -> Result<NodeDirs, CreateError> {
    let genesis_file = root.join(GENESIS_FILE);
    let genesis_text = std::fs::read_to_string(&genesis_file)
        .map_err(|e| CreateError::Msg(format!("reading {}: {e}", genesis_file.display())))?;
    let genesis: Value =
        serde_json::from_str(&genesis_text).map_err(|e| CreateError::Msg(e.to_string()))?;
    // go: `Genesis.ID()` = network + "-" + schema id
    let genesis_id = format!(
        "{}-{}",
        genesis["network"].as_str().unwrap_or_default(),
        genesis["id"].as_str().unwrap_or_default()
    );

    let relays_count = template.relay_count();
    let mut relay_dirs = Vec::new();
    let mut node_dirs = BTreeMap::new();
    let mut node_has_wallet = BTreeMap::new();

    for node in &template.nodes {
        let node_dir = root.join(&node.name);
        match std::fs::create_dir(&node_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // some flexibility for docker and pre-mounted volumes
                if !dir_is_empty(&node_dir) {
                    return msg(format!("duplicate node directory detected: {e}"));
                }
            }
            Err(e) => return msg(format!("creating {}: {e}", node_dir.display())),
        }
        copy_file(&genesis_file, &node_dir.join(GENESIS_FILE))?;

        if node.is_relay {
            relay_dirs.push(node.name.clone());
        } else {
            node_dirs.insert(node.name.clone(), node.name.clone());
        }

        let genesis_dir = node_dir.join(&genesis_id);
        std::fs::create_dir(&genesis_dir)
            .map_err(|e| CreateError::Msg(format!("creating {}: {e}", genesis_dir.display())))?;

        let mut has_wallet = false;
        let mut entries: Vec<String> = std::fs::read_dir(root)
            .map_err(|e| CreateError::Msg(format!("reading {}: {e}", root.display())))?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        entries.sort();
        for name in entries {
            if !(is_root_key_filename(&name) || is_part_key_filename(&name)) {
                continue;
            }
            for wallet in &node.wallets {
                if (matches_root_key_filename(&wallet.name, &name) && !wallet.participation_only)
                    || matches_part_key_filename(&wallet.name, &name)
                {
                    copy_file(&root.join(&name), &genesis_dir.join(&name))?;
                    has_wallet = true;
                }
            }
        }
        node_has_wallet.insert(node.name.clone(), has_wallet);

        // config.json for this node
        let cfg = node_config_json(node, template.nodes.len().saturating_sub(1), relays_count)?;
        let mut text = serde_json::to_string_pretty(&Value::Object(cfg))
            .map_err(|e| CreateError::Msg(e.to_string()))?;
        text.push('\n');
        std::fs::write(node_dir.join("config.json"), text)
            .map_err(|e| CreateError::Msg(format!("writing config.json: {e}")))?;
    }
    Ok((relay_dirs, node_dirs, node_has_wallet))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_TEMPLATE: &str = include_str!("default_template.json");

    fn quick(template: &str) -> String {
        // keep key generation fast in tests
        template.replace("30000", "40")
    }

    fn create(tmp: &Path, template: &str, opts: &CreateOptions) -> Result<Network, CreateError> {
        let mut log: Vec<u8> = Vec::new();
        create_network_from_template(&tmp.join("net"), &quick(template), opts, &mut log)
    }

    #[test]
    fn key_file_name_rules_match_gos() {
        assert!(is_root_key_filename("Wallet1.rootkey"));
        assert!(!is_root_key_filename(".rootkey"));
        assert!(!is_root_key_filename("Wallet1.partkey"));
        assert!(is_part_key_filename("Wallet1.0.30000.partkey"));
        assert!(is_part_key_filename("My.Wallet.5.9.partkey"));
        assert!(!is_part_key_filename("Wallet1.x.30000.partkey"));
        assert!(!is_part_key_filename("Wallet1.partkey"));
        assert!(matches_root_key_filename("W", "W.rootkey"));
        assert!(!matches_root_key_filename("W", "W2.rootkey"));
        assert!(matches_part_key_filename("W", "W.0.10.partkey"));
        assert!(matches_part_key_filename("My.Wallet", "My.Wallet.5.9.partkey"));
        assert!(!matches_part_key_filename("W", "W2.0.10.partkey"));
    }

    #[test]
    fn the_default_template_creates_gos_directory_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let net = create(tmp.path(), DEFAULT_TEMPLATE, &CreateOptions::default()).unwrap();
        assert_eq!(net.name(), "Default Network Template");
        let root = tmp.path().join("net");
        assert!(root.join("genesis.json").is_file());
        assert!(root.join("network.json").is_file());
        let node = root.join("Node");
        assert!(node.join("genesis.json").is_file());
        assert!(node.join("config.json").is_file());
        // genesis id = network + "-" + schema id
        let gdir = node.join("Default Network Template-v1");
        assert!(gdir.is_dir(), "genesis directory");
        for f in [
            "Wallet1.rootkey",
            "Wallet2.rootkey",
            "Wallet3.rootkey",
            "Wallet1.0.40.partkey",
            "Wallet2.0.40.partkey",
        ] {
            assert!(gdir.join(f).is_file(), "{f} copied into the node's genesis dir");
        }
        assert_eq!(net.node_dirs["Node"], "Node");
        assert!(net.cfg.relay_dirs.is_empty());
        assert!(net.node_has_wallet["Node"]);
    }

    #[test]
    fn network_json_round_trips_with_the_template() {
        let tmp = tempfile::tempdir().unwrap();
        let net = create(tmp.path(), DEFAULT_TEMPLATE, &CreateOptions { name: "mynet".into(), ..Default::default() }).unwrap();
        let text = std::fs::read_to_string(tmp.path().join("net/network.json")).unwrap();
        let back: NetworkCfg = serde_json::from_str(&text).unwrap();
        assert_eq!(back, net.cfg);
        assert_eq!(back.name, "mynet");
        assert!(text.contains("\"Template\""), "{text}");
        // the explicit name wins, and it is the genesis network name
        let genesis = std::fs::read_to_string(tmp.path().join("net/genesis.json")).unwrap();
        assert!(genesis.contains("\"network\": \"mynet\""), "{genesis}");
        assert!(tmp.path().join("net/Node/mynet-v1").is_dir());
    }

    #[test]
    fn dev_mode_override_marks_the_genesis_and_keeps_one_node() {
        let tmp = tempfile::tempdir().unwrap();
        let net = create(tmp.path(), DEFAULT_TEMPLATE, &CreateOptions { dev_mode_override: true, ..Default::default() }).unwrap();
        assert!(net.cfg.template.genesis.dev_mode);
        let genesis = std::fs::read_to_string(tmp.path().join("net/genesis.json")).unwrap();
        assert!(genesis.contains("\"devmode\": true"), "{genesis}");
    }

    #[test]
    fn an_unnamed_network_and_an_invalid_template_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let unnamed = DEFAULT_TEMPLATE.replace("Default Network Template", "");
        let e = create(tmp.path(), &unnamed, &CreateOptions::default()).unwrap_err();
        assert_eq!(
            e.to_string(),
            "unnamed network. Use the \"network\" flag or \"Genesis.NetworkName\" in the network template"
        );
        let bad = DEFAULT_TEMPLATE.replace("\"Stake\": 20", "\"Stake\": 5");
        let e = create(tmp.path(), &bad, &CreateOptions::default()).unwrap_err();
        assert!(e.to_string().starts_with("invalid template: Genesis account allocations must total 100"), "{e}");
    }

    #[test]
    fn node_config_matches_gos_private_network_settings() {
        let relay = NodeConfig { name: "r".into(), is_relay: true, ..Default::default() };
        let node = NodeConfig { name: "n".into(), ..Default::default() };
        let r = node_config_json(&relay, 2, 1).unwrap();
        assert_eq!(r["GossipFanout"], 2);
        assert_eq!(r["EndpointAddress"], "127.0.0.1:0");
        assert_eq!(r["DNSBootstrapID"], "");
        assert_eq!(r["NetAddress"], "127.0.0.1:0");
        assert_eq!(r["Archival"], false);
        assert_eq!(r["MaxBlockHistoryLookback"], 20000);
        assert!(!r.contains_key("DisableNetworking"));
        assert!(!r.contains_key("IncomingConnectionsLimit"));
        let n = node_config_json(&node, 0, 0).unwrap();
        assert_eq!(n["IncomingConnectionsLimit"], 0);
        assert_eq!(n["DisableNetworking"], true, "no relays -> networking off");
        assert!(!n.contains_key("NetAddress"));
        // ConfigJSONOverride wins over everything above
        let over = NodeConfig {
            name: "o".into(),
            config_json_override: r#"{"EndpointAddress": "0.0.0.0:8080", "EnableFollowMode": true}"#.into(),
            ..Default::default()
        };
        let o = node_config_json(&over, 0, 1).unwrap();
        assert_eq!(o["EndpointAddress"], "0.0.0.0:8080");
        assert_eq!(o["EnableFollowMode"], true);
    }

    #[test]
    fn a_relay_plus_node_template_gets_relay_and_node_directories() {
        let template = r#"{"Genesis": {"NetworkName": "two", "LastPartKeyRound": 30,
            "Wallets": [{"Name": "A", "Stake": 50, "Online": true}, {"Name": "B", "Stake": 50, "Online": true}]},
            "Nodes": [{"Name": "Relay", "IsRelay": true, "Wallets": [{"Name": "A"}]},
                      {"Name": "N1", "Wallets": [{"Name": "B", "ParticipationOnly": true}]}]}"#;
        let tmp = tempfile::tempdir().unwrap();
        let net = create(tmp.path(), template, &CreateOptions::default()).unwrap();
        assert_eq!(net.cfg.relay_dirs, vec!["Relay"]);
        assert_eq!(net.node_dirs.keys().collect::<Vec<_>>(), ["N1"]);
        let gdir = tmp.path().join("net/N1/two-v1");
        assert!(gdir.join("B.0.30.partkey").is_file(), "participation key copied");
        assert!(!gdir.join("B.rootkey").exists(), "ParticipationOnly skips the root key");
        assert!(tmp.path().join("net/Relay/two-v1/A.rootkey").is_file());
        let cfg: Value = serde_json::from_str(&std::fs::read_to_string(tmp.path().join("net/Relay/config.json")).unwrap()).unwrap();
        assert_eq!(cfg["NetAddress"], "127.0.0.1:0");
    }

    #[test]
    fn a_non_empty_existing_node_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("net/Node")).unwrap();
        std::fs::write(tmp.path().join("net/Node/stale"), "x").unwrap();
        let e = create(tmp.path(), DEFAULT_TEMPLATE, &CreateOptions::default()).unwrap_err();
        assert!(e.to_string().starts_with("duplicate node directory detected: "), "{e}");
    }

    #[test]
    fn a_created_network_loads_back_with_its_relays_and_nodes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("net");
        let json = r#"{"Genesis": {"NetworkName": "loadnet", "FirstPartKeyRound": 0, "LastPartKeyRound": 20,
            "Wallets": [{"Name": "W1", "Stake": 100, "Online": true}]},
            "Nodes": [{"Name": "Relay", "IsRelay": true, "Wallets": []},
                      {"Name": "N1", "Wallets": [{"Name": "W1"}]}]}"#;
        let mut sink: Vec<u8> = Vec::new();
        let created = create_network_from_template(&root, json, &CreateOptions::default(), &mut sink).unwrap();
        let loaded = load_network(&root).unwrap();
        assert_eq!(loaded.name(), created.name());
        assert_eq!(loaded.relay_data_dirs(), vec![root.join("Relay")]);
        assert_eq!(loaded.node_data_dirs(), vec![root.join("N1")]);
        assert_eq!(loaded.node_dir("Relay"), Some(root.join("Relay")));
        assert_eq!(loaded.node_dir("N1"), Some(root.join("N1")));
        assert_eq!(loaded.node_dir("nope"), None);
    }

    #[test]
    fn loading_a_directory_without_network_json_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let e = load_network(tmp.path()).unwrap_err();
        assert!(e.to_string().contains("network.json"), "{e}");
    }

    #[test]
    fn emptiness_counts_files_not_directories() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(is_empty(tmp.path()));
        assert!(is_empty(&tmp.path().join("missing")));
        std::fs::create_dir_all(tmp.path().join("a/b")).unwrap();
        assert!(is_empty(tmp.path()), "empty directories are empty");
        std::fs::write(tmp.path().join("a/b/f"), "x").unwrap();
        assert!(!is_empty(tmp.path()));
    }
}
