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

//! Private-network templates: port of `netdeploy/networkTemplate.go` (the
//! `NetworkTemplate` type, loading and `Validate`), `gen/walletData.go`
//! (`GenesisData`, `WalletData`) and `netdeploy/remote/nodeConfig.go`
//! (`NodeConfigGoal`). Field names are go's (`NetworkName`, `Wallets`, ...)
//! so the same template files load, and `network.json` embeds them the way
//! go writes them.

use serde::{Deserialize, Serialize};

/// go: `gen.DefaultGenesis.RewardsPoolBalance` --
/// `defaultIncentivePoolBalanceAtInception = 125e6 * 1e6`.
pub const DEFAULT_REWARDS_POOL_BALANCE: u64 = 125_000_000 * 1_000_000;
/// go: `gen.DefaultGenesis.LastPartKeyRound`.
pub const DEFAULT_LAST_PART_KEY_ROUND: u64 = 3_000_000;

/// go: `gen.WalletData`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct WalletData {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Stake")]
    pub stake: f64,
    #[serde(rename = "Online")]
    pub online: bool,
}

/// go: `gen.GenesisData`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GenesisData {
    #[serde(rename = "NetworkName")]
    pub network_name: String,
    #[serde(rename = "VersionModifier")]
    pub version_modifier: String,
    #[serde(rename = "ConsensusProtocol")]
    pub consensus_protocol: String,
    #[serde(rename = "FirstPartKeyRound")]
    pub first_part_key_round: u64,
    #[serde(rename = "LastPartKeyRound")]
    pub last_part_key_round: u64,
    #[serde(rename = "PartKeyDilution")]
    pub part_key_dilution: u64,
    #[serde(rename = "Wallets")]
    pub wallets: Vec<WalletData>,
    /// Base32 address; empty (or the zero address) means go's default sink.
    #[serde(rename = "FeeSink")]
    pub fee_sink: String,
    /// Base32 address; empty (or the zero address) means go's default pool.
    #[serde(rename = "RewardsPool")]
    pub rewards_pool: String,
    #[serde(rename = "RewardsPoolBalance")]
    pub rewards_pool_balance: u64,
    #[serde(rename = "DevMode")]
    pub dev_mode: bool,
    #[serde(rename = "Comment")]
    pub comment: String,
}

impl Default for GenesisData {
    /// go: `gen.DefaultGenesis` (the initial state of every `GenesisData`).
    fn default() -> Self {
        Self {
            network_name: String::new(),
            version_modifier: String::new(),
            consensus_protocol: String::new(),
            first_part_key_round: 0,
            last_part_key_round: DEFAULT_LAST_PART_KEY_ROUND,
            part_key_dilution: 0,
            wallets: Vec::new(),
            fee_sink: String::new(),
            rewards_pool: String::new(),
            rewards_pool_balance: DEFAULT_REWARDS_POOL_BALANCE,
            dev_mode: false,
            comment: String::new(),
        }
    }
}

/// go: `remote.NodeWalletData`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NodeWalletData {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "ParticipationOnly")]
    pub participation_only: bool,
}

/// go: `remote.NodeConfigGoal`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NodeConfig {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "IsRelay", skip_serializing_if = "is_false")]
    pub is_relay: bool,
    #[serde(rename = "Wallets")]
    pub wallets: Vec<NodeWalletData>,
    #[serde(rename = "P2PPeerID", skip_serializing_if = "String::is_empty")]
    pub p2p_peer_id: String,
    /// Raw JSON merged into `config.json` after the other modifications.
    #[serde(rename = "ConfigJSONOverride", skip_serializing_if = "String::is_empty")]
    pub config_json_override: String,
    /// Semicolon separated peers to connect to; only for non-relays.
    #[serde(rename = "PeerList", skip_serializing_if = "String::is_empty")]
    pub peer_list: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// go: `netdeploy.NetworkTemplate`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NetworkTemplate {
    #[serde(rename = "Genesis")]
    pub genesis: GenesisData,
    #[serde(rename = "Nodes")]
    pub nodes: Vec<NodeConfig>,
}

/// Errors from loading or validating a template; the `Display` text is go's.
#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Decode(String),
}

impl NetworkTemplate {
    /// go: `LoadTemplateFromReader` -- `json.Decoder` semantics (unknown
    /// fields are ignored).
    pub fn from_json(text: &str) -> Result<Self, TemplateError> {
        serde_json::from_str(text).map_err(|e| TemplateError::Decode(e.to_string()))
    }

    /// go: `OverrideDevMode`.
    pub fn override_dev_mode(&mut self) {
        self.genesis.dev_mode = true;
        if let Some(first) = self.nodes.first_mut() {
            first.is_relay = false;
        }
    }

    /// go: `NetworkTemplate.Validate`.
    pub fn validate(&self) -> Result<(), TemplateError> {
        let invalid = |m: String| Err(TemplateError::Invalid(format!("invalid template: {m}")));

        // Genesis wallet percentages must add up to 100; names must be unique.
        let mut total = 0.0_f64;
        let mut accounts = std::collections::HashSet::new();
        for wallet in &self.genesis.wallets {
            if wallet.stake < 0.0 {
                return invalid(format!(
                    "negative stake on Genesis account {}",
                    wallet.name
                ));
            }
            total += wallet.stake;
            if !accounts.insert(wallet.name.to_uppercase()) {
                return invalid(format!("duplicate Genesis account {}", wallet.name));
            }
        }
        const EPSILON: f64 = 0.000_000_1;
        let total_int = total.trunc() as i64;
        if total_int != 100 && !(total_int < 100 && total > 100.0 - EPSILON) {
            return invalid(format!(
                "Genesis account allocations must total 100 (actual {total})"
            ));
        }

        // No wallet can be assigned to more than one node.
        let mut wallets = std::collections::HashSet::new();
        for node in &self.nodes {
            for wallet in &node.wallets {
                if !wallets.insert(wallet.name.to_uppercase()) {
                    return invalid(format!(
                        "Wallet '{}' assigned to multiple nodes",
                        wallet.name
                    ));
                }
            }
        }

        // At least one relay is required.
        if self.nodes.len() > 1 && self.relay_count() == 0 {
            return invalid(
                "at least one relay is required when more than a single node presents"
                    .to_string(),
            );
        }

        // ConfigJSONOverride must decode.
        for node in &self.nodes {
            if let Err(e) = decode_override(&node.config_json_override) {
                return invalid(format!("unable to decode ConfigJSONOverride: {e}"));
            }
        }

        // Follow nodes cannot be relays; relays cannot have a peer list.
        for node in &self.nodes {
            if node.is_relay && is_follow_mode(&node.config_json_override) {
                return invalid("follower nodes may not be relays".to_string());
            }
            if node.is_relay && !node.peer_list.is_empty() {
                return invalid("relays may not have a peer list".to_string());
            }
        }

        if self.genesis.dev_mode && self.nodes.len() != 1 {
            if self.relay_count() != 1 {
                return invalid("devmode configurations may have at most one relay".to_string());
            }
            for node in &self.nodes {
                if !node.is_relay && !is_follow_mode(&node.config_json_override) {
                    return invalid(
                        "devmode configurations may only contain one relay and follower nodes"
                            .to_string(),
                    );
                }
            }
        }
        Ok(())
    }

    /// go: `countRelayNodes`.
    pub fn relay_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.is_relay).count()
    }
}

/// go: `decodeJSONOverride` -- empty is fine, otherwise a JSON object.
/// (go also rejects unknown `config.Local` fields; algod-rust's own config
/// loader reports those when the node starts.)
pub fn decode_override(
    text: &str,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>, String> {
    if text.is_empty() {
        return Ok(None);
    }
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::Object(m)) => Ok(Some(m)),
        Ok(_) => Err("json: cannot unmarshal into a config object".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// go: `isEnableFollowMode`.
pub fn is_follow_mode(override_json: &str) -> bool {
    decode_override(override_json)
        .ok()
        .flatten()
        .and_then(|m| m.get("EnableFollowMode").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_TEMPLATE: &str = include_str!("default_template.json");

    fn t(json: &str) -> NetworkTemplate {
        NetworkTemplate::from_json(json).expect("template")
    }

    fn err_of(template: &NetworkTemplate) -> String {
        template.validate().expect_err("must be invalid").to_string()
    }

    #[test]
    fn the_default_template_is_valid_and_has_gos_wallets() {
        let tpl = t(DEFAULT_TEMPLATE);
        tpl.validate().expect("default template validates");
        assert_eq!(tpl.genesis.network_name, "Default Network Template");
        assert_eq!(tpl.genesis.rewards_pool_balance, 0);
        assert_eq!(tpl.genesis.last_part_key_round, 30000);
        let names: Vec<_> = tpl.genesis.wallets.iter().map(|w| w.name.as_str()).collect();
        assert_eq!(names, ["Wallet1", "Wallet2", "Wallet3"]);
        assert!(tpl.genesis.wallets[0].online && !tpl.genesis.wallets[2].online);
        assert_eq!(tpl.nodes.len(), 1);
    }

    #[test]
    fn an_empty_genesis_takes_gos_defaults() {
        let tpl = t(r#"{"Genesis": {"Wallets": [{"Name": "W", "Stake": 100}]}, "Nodes": []}"#);
        assert_eq!(tpl.genesis.last_part_key_round, 3_000_000);
        assert_eq!(tpl.genesis.rewards_pool_balance, 125_000_000_000_000);
        assert_eq!(tpl.genesis.first_part_key_round, 0);
    }

    #[test]
    fn stake_must_total_100_with_gos_messages() {
        let tpl = t(r#"{"Genesis": {"Wallets": [{"Name": "A", "Stake": 60}, {"Name": "B", "Stake": 30}]}}"#);
        assert_eq!(
            err_of(&tpl),
            "invalid template: Genesis account allocations must total 100 (actual 90)"
        );
        // a rounding error just under 100 is forgiven
        let tpl = t(r#"{"Genesis": {"Wallets": [{"Name": "A", "Stake": 33.33333333}, {"Name": "B", "Stake": 33.33333333}, {"Name": "C", "Stake": 33.33333334}]}}"#);
        tpl.validate().expect("rounding is fine");
        let tpl = t(r#"{"Genesis": {"Wallets": [{"Name": "A", "Stake": -1}, {"Name": "B", "Stake": 101}]}}"#);
        assert_eq!(err_of(&tpl), "invalid template: negative stake on Genesis account A");
    }

    #[test]
    fn wallet_names_are_unique_case_insensitively_and_belong_to_one_node() {
        let tpl = t(r#"{"Genesis": {"Wallets": [{"Name": "a", "Stake": 50}, {"Name": "A", "Stake": 50}]}}"#);
        assert_eq!(err_of(&tpl), "invalid template: duplicate Genesis account A");
        let tpl = t(r#"{"Genesis": {"Wallets": [{"Name": "W", "Stake": 100}]},
            "Nodes": [{"Name": "n1", "IsRelay": true, "Wallets": [{"Name": "W"}]},
                      {"Name": "n2", "Wallets": [{"Name": "w"}]}]}"#);
        assert_eq!(err_of(&tpl), "invalid template: Wallet 'w' assigned to multiple nodes");
    }

    #[test]
    fn a_multi_node_template_needs_a_relay_and_relays_follow_the_rules() {
        let tpl = t(r#"{"Genesis": {"Wallets": [{"Name": "W", "Stake": 100}]},
            "Nodes": [{"Name": "n1"}, {"Name": "n2"}]}"#);
        assert_eq!(
            err_of(&tpl),
            "invalid template: at least one relay is required when more than a single node presents"
        );
        let tpl = t(r#"{"Genesis": {"Wallets": [{"Name": "W", "Stake": 100}]},
            "Nodes": [{"Name": "r", "IsRelay": true, "PeerList": "1.2.3.4:4160"}]}"#);
        assert_eq!(err_of(&tpl), "invalid template: relays may not have a peer list");
        let tpl = t(r#"{"Genesis": {"Wallets": [{"Name": "W", "Stake": 100}]},
            "Nodes": [{"Name": "r", "IsRelay": true, "ConfigJSONOverride": "{\"EnableFollowMode\": true}"}]}"#);
        assert_eq!(err_of(&tpl), "invalid template: follower nodes may not be relays");
        let tpl = t(r#"{"Genesis": {"Wallets": [{"Name": "W", "Stake": 100}]},
            "Nodes": [{"Name": "r", "ConfigJSONOverride": "{not json"}]}"#);
        assert!(err_of(&tpl).starts_with("invalid template: unable to decode ConfigJSONOverride: "));
    }

    #[test]
    fn devmode_templates_follow_gos_rules() {
        // one node is always fine
        let mut tpl = t(DEFAULT_TEMPLATE);
        tpl.genesis.dev_mode = true;
        tpl.validate().expect("single node devmode");
        // two nodes: exactly one relay, the rest followers
        let tpl = t(r#"{"Genesis": {"DevMode": true, "Wallets": [{"Name": "W", "Stake": 100}]},
            "Nodes": [{"Name": "a", "IsRelay": true}, {"Name": "b", "IsRelay": true}]}"#);
        assert_eq!(err_of(&tpl), "invalid template: devmode configurations may have at most one relay");
        let tpl = t(r#"{"Genesis": {"DevMode": true, "Wallets": [{"Name": "W", "Stake": 100}]},
            "Nodes": [{"Name": "a", "IsRelay": true}, {"Name": "b"}]}"#);
        assert_eq!(
            err_of(&tpl),
            "invalid template: devmode configurations may only contain one relay and follower nodes"
        );
        let tpl = t(r#"{"Genesis": {"DevMode": true, "Wallets": [{"Name": "W", "Stake": 100}]},
            "Nodes": [{"Name": "a", "IsRelay": true}, {"Name": "b", "ConfigJSONOverride": "{\"EnableFollowMode\": true}"}]}"#);
        tpl.validate().expect("relay + follower");
    }

    #[test]
    fn the_dev_mode_override_turns_on_devmode_and_unrelays_the_first_node() {
        let mut tpl = t(r#"{"Genesis": {"Wallets": [{"Name": "W", "Stake": 100}]},
            "Nodes": [{"Name": "a", "IsRelay": true}]}"#);
        tpl.override_dev_mode();
        assert!(tpl.genesis.dev_mode);
        assert!(!tpl.nodes[0].is_relay);
    }

    #[test]
    fn a_template_round_trips_in_gos_field_names() {
        let tpl = t(DEFAULT_TEMPLATE);
        let text = serde_json::to_string(&tpl).unwrap();
        assert!(text.contains("\"NetworkName\":\"Default Network Template\""), "{text}");
        assert!(text.contains("\"Wallets\":[{\"Name\":\"Wallet1\",\"Stake\":40.0,\"Online\":true}"), "{text}");
        assert!(!text.contains("IsRelay"), "IsRelay is omitted when false (go omitempty)");
        assert_eq!(t(&text), tpl);
    }
}
