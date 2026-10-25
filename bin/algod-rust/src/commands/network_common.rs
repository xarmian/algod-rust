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

//! Shared network defaults used by observe, sync, and other commands.

/// Default DNS bootstrap ID template (matches go-algorand's default).
pub const DNS_BOOTSTRAP_TEMPLATE: &str =
    "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)";

/// A built-in network preset: everything `--network <name>` needs to know
/// about a chain, kept in one table ([`PRESETS`]) so adding a chain (voimain,
/// aramidmain, ...) is one row plus its fixtures rather than a hunt through
/// every `match network { "mainnet" => ... }` (issue #2069, epic #2068).
///
/// The genesis *hash* is deliberately not duplicated here: it lives in
/// [`algo_types::Network`] (the algokey keyreg table) and is reached via
/// [`NetworkPreset::genesis_hash`]; a test pins that it equals the hash of
/// the embedded genesis JSON.
#[derive(Debug, Clone, Copy)]
pub struct NetworkPreset {
    /// `--network` value (lower-case).
    pub name: &'static str,
    /// Full genesis id (`"{network}-{id}"`, the string in block headers).
    pub genesis_id: &'static str,
    /// Whether `genesis_id` is fixed network-wide (a catchup preset). False
    /// for `devnet`, whose real genesis id varies per deployment.
    pub fixed_genesis_id: bool,
    /// Byte-exact genesis.json for this chain, if vendored in the repo.
    pub genesis_json: Option<&'static str>,
    /// Default public algod REST endpoint used for catchup/follow.
    pub rest_url: Option<&'static str>,
    /// `DNSBootstrapID` template; `None` means go-algorand's default
    /// ([`DNS_BOOTSTRAP_TEMPLATE`]).
    pub dns_bootstrap_id: Option<&'static str>,
    /// Static `latest.catchpoint` index (go's `goal node catchup NETWORK`
    /// source); `None` when the chain has none and the peer's
    /// `/v2/status.last-catchpoint` is the only discovery source.
    pub catchpoint_index_url: Option<&'static str>,
    /// Bundled `consensus.json` for chains with custom consensus protocols
    /// (none yet; reserved for aramidmain, issue #2070).
    #[allow(dead_code)] // first consumer lands with aramidmain (#2070)
    pub consensus_json: Option<&'static str>,
}

#[cfg(test)]
impl NetworkPreset {
    /// 32-byte genesis hash (from the shared [`algo_types::Network`] table).
    pub fn genesis_hash(&self) -> Option<[u8; 32]> {
        algo_types::Network::from_str_ci(self.name)
            .ok()
            .map(|n| n.genesis_hash().0)
    }
}

/// All built-in presets. See [`NetworkPreset`].
pub const PRESETS: &[NetworkPreset] = &[
    NetworkPreset {
        name: "mainnet",
        genesis_id: "mainnet-v1.0",
        fixed_genesis_id: true,
        genesis_json: None,
        rest_url: Some("https://mainnet-api.4160.nodely.dev"),
        dns_bootstrap_id: None,
        catchpoint_index_url: Some(
            "https://algorand-catchpoints.s3.us-east-2.amazonaws.com/channel/mainnet/latest.catchpoint",
        ),
        consensus_json: None,
    },
    NetworkPreset {
        name: "testnet",
        genesis_id: "testnet-v1.0",
        fixed_genesis_id: true,
        genesis_json: None,
        rest_url: Some("https://testnet-api.4160.nodely.dev"),
        dns_bootstrap_id: None,
        catchpoint_index_url: Some(
            "https://algorand-catchpoints.s3.us-east-2.amazonaws.com/channel/testnet/latest.catchpoint",
        ),
        consensus_json: None,
    },
    NetworkPreset {
        name: "betanet",
        genesis_id: "betanet-v1.0",
        fixed_genesis_id: true,
        genesis_json: None,
        rest_url: None,
        dns_bootstrap_id: None,
        catchpoint_index_url: Some(
            "https://algorand-catchpoints.s3.us-east-2.amazonaws.com/channel/betanet/latest.catchpoint",
        ),
        consensus_json: None,
    },
    NetworkPreset {
        name: "devnet",
        genesis_id: "devnet-v1.0",
        fixed_genesis_id: false,
        genesis_json: None,
        rest_url: None,
        dns_bootstrap_id: None,
        catchpoint_index_url: None,
        consensus_json: None,
    },
    // DIVERGENCE DIV-005: voimain preset (Voi mainnet) is algod-rust-only.
    // Voi mainnet. The DNS bootstrap template is the `DNSBootstrapID` of the
    // Voi node image's own config (VoiNetwork/voi-node
    // `configuration/mainnet/participation/config.json`);
    // `_algobootstrap._tcp.voimain.mainnet-voi.network` resolves to
    // `r-eu-*.mainnet-voi.network:5011` relays. No static catchpoint index
    // exists; the public algod advertises `last-catchpoint` in /v2/status.
    NetworkPreset {
        name: "voimain",
        genesis_id: "voimain-v1.0",
        fixed_genesis_id: true,
        genesis_json: Some(include_str!(
            "../../genesis/voimain-genesis.json"
        )),
        rest_url: Some("https://mainnet-api.voi.nodely.dev"),
        dns_bootstrap_id: Some(
            "<network>.mainnet-voi.network?backup=<network>.mainnet-voi.net&dedup=<name>.mainnet-voi.(network|net)",
        ),
        catchpoint_index_url: None,
        consensus_json: None,
    },
];

/// Look up a preset by `--network` name.
pub fn preset(name: &str) -> Option<&'static NetworkPreset> {
    PRESETS.iter().find(|p| p.name == name)
}

/// The preset's vendored genesis.json, but only when it is the genesis of
/// the chain the ledger actually runs: `resolved_genesis_id` is the id
/// resolved from the opened ledger (not the raw `--genesis-id`), so a node
/// started with `--network voimain` on a different genesis (custom
/// `--genesis-json`, other `--genesis-id`) never serves the wrong document.
pub fn vendored_genesis_json(network: &str, resolved_genesis_id: &str) -> Option<&'static str> {
    preset(network)
        .filter(|p| p.genesis_id == resolved_genesis_id)
        .and_then(|p| p.genesis_json)
}

/// The DNS bootstrap template to use for `network`: an explicit CLI override
/// wins; else a preset-specific template when `configured` is still
/// go-algorand's stock default (an operator-customised `DNSBootstrapID` in
/// `config.json` is respected); else `configured`.
///
/// The returned flag is the `default_template_overridden` argument for
/// [`algo_network::Discovery::new`]: true for a CLI override or a preset
/// template (so the hardcoded devnet/betanet override map is not consulted),
/// otherwise `cli_override.is_some()` semantics are unchanged.
pub fn effective_dns_bootstrap<'a>(
    network: &str,
    cli_override: Option<&'a str>,
    configured: &'a str,
) -> (&'a str, bool) {
    if let Some(o) = cli_override {
        return (o, true);
    }
    if configured == DNS_BOOTSTRAP_TEMPLATE {
        if let Some(t) = preset(network).and_then(|p| p.dns_bootstrap_id) {
            return (t, true);
        }
    }
    (configured, false)
}

/// Translate a go-style signed connection-limit field (where a negative
/// value, per go's own `version[N]:"-1"` defaults, means "unbounded") into
/// `algo-network`'s unsigned representation. Negative becomes
/// [`algo_network::UNBOUNDED_BROADCAST_CONNECTIONS_LIMIT`] (`u32::MAX`,
/// used generically here for any "no cap" sentinel, not just the
/// broadcast-specific one); non-negative values are clamped rather than
/// wrapped if they somehow exceed `u32::MAX`. Shared by `relay` and
/// `participate` (issue #748) for `MaxConnectionsPerIP`,
/// `IncomingConnectionsLimit`, and `BroadcastConnectionsLimit`.
pub fn resolve_unsigned_limit(value: i64) -> u32 {
    if value < 0 {
        algo_network::UNBOUNDED_BROADCAST_CONNECTIONS_LIMIT
    } else {
        u32::try_from(value).unwrap_or(u32::MAX)
    }
}

/// Resolve `config.json`'s catchpoint fields into the
/// [`algo_ledger::catchpoint::AutoCatchpointConfig`] the live block-apply
/// loop needs, or `None` when automatic generation should stay disabled
/// (issue #770). Shared by `relay` and `participate`, mirroring how
/// `resolve_unsigned_limit` above is shared for connection-limit fields.
///
/// Mirrors go's own `CatchpointDir` fallback semantics: even when
/// [`algo_config::Local::stores_catchpoints`] resolves to `true`, an empty
/// `CatchpointDir` leaves nowhere to write files, so generation is
/// disabled (with a warning) rather than writing into the current working
/// directory or panicking.
pub fn resolve_automatic_catchpoint_config(
    node_config: &algo_config::Local,
) -> Option<algo_ledger::catchpoint::AutoCatchpointConfig> {
    if !node_config.stores_catchpoints() {
        return None;
    }
    if node_config.catchpoint_dir.is_empty() {
        tracing::warn!(
            "CatchpointTracking/CatchpointInterval resolve to automatic catchpoint \
             generation, but CatchpointDir is empty; disabling automatic generation \
             (set CatchpointDir in config.json to enable it)"
        );
        return None;
    }
    Some(algo_ledger::catchpoint::AutoCatchpointConfig {
        interval: node_config.catchpoint_interval,
        file_history_length: node_config.catchpoint_file_history_length,
        dir: std::path::PathBuf::from(&node_config.catchpoint_dir),
    })
}

/// Resolve `config.json`'s `EnableAccountUpdatesStats`/
/// `AccountUpdatesStatsInterval` into the
/// [`algo_ledger::acctupdates_stats::AccountUpdatesStatsConfig`] the live
/// block-apply loop needs, or `None` when the periodic AccountUpdates
/// telemetry-equivalent event should stay disabled (issue #1187). Shared by
/// `relay` and `participate`, mirroring
/// [`resolve_automatic_catchpoint_config`] just above.
pub fn resolve_account_updates_stats_config(
    node_config: &algo_config::Local,
) -> Option<algo_ledger::acctupdates_stats::AccountUpdatesStatsConfig> {
    if !node_config.enable_account_updates_stats {
        return None;
    }
    Some(algo_ledger::acctupdates_stats::AccountUpdatesStatsConfig {
        interval: std::time::Duration::from_nanos(
            node_config.account_updates_stats_interval.max(0) as u64,
        ),
    })
}

/// Resolve `config.json`'s `MaxBlockHistoryLookback`/`Archival`/catchpoint
/// fields into the [`algo_ledger::store_trait::RetentionConfig`] the live
/// block-apply loop's per-block pruning needs (issue #1354), mirroring
/// go-algorand's `Ledger.notifyCommit`/`calcMinCatchpointRoundsLookback`
/// (`ledger/ledger.go`). Shared by `relay` and `participate`, following the
/// same pattern as [`resolve_automatic_catchpoint_config`]/
/// [`resolve_account_updates_stats_config`] above.
///
/// The catchpoint floor is pre-resolved here (rather than passed through as
/// raw fields) so `algo_ledger` doesn't need to depend on `algo_config` just
/// to reproduce this one gate: `2 * CatchpointInterval` when the node
/// stores catchpoints (`Local::stores_catchpoints()`) AND
/// `CatchpointFileHistoryLength != 0` (go's own `calcMinCatchpointRoundsLookback`
/// bails to `0` when the file-history length is exactly zero — a `-1`
/// "keep all catchpoint files forever" setting does NOT disable this floor,
/// only an exact `0` does), else `0` (no catchpoint-derived floor).
pub fn resolve_retention_config(
    node_config: &algo_config::Local,
) -> algo_ledger::store_trait::RetentionConfig {
    let catchpoint_min_rounds_lookback =
        if node_config.stores_catchpoints() && node_config.catchpoint_file_history_length != 0 {
            2 * node_config.catchpoint_interval
        } else {
            0
        };
    algo_ledger::store_trait::RetentionConfig {
        max_block_history_lookback: node_config.max_block_history_lookback,
        catchpoint_min_rounds_lookback,
        archival: node_config.archival,
    }
}

/// Resolve the effective `WebsocketNetworkConfig::gossip_fanout` for a
/// command that may or may not be acting as a listen server, applying go's
/// `enrichNetworkingConfig` `GossipFanout` bump (`config/config.go:170-179`,
/// [`algo_config::Local::gossip_fanout_for_listen_server`]) only when
/// `is_listen_server` is true, then flooring the result at `peers_count` —
/// the pre-existing, algod-rust-only heuristic (not from go) that a node
/// should target at least as many outgoing connections as it was given
/// static peer addresses for. Shared by `relay` (always a listen server)
/// and `participate` (a listen server only once `--listen-address`
/// resolves to `Some`) — issue #788.
pub fn resolve_gossip_fanout(
    node_config: &algo_config::Local,
    is_listen_server: bool,
    peers_count: usize,
) -> usize {
    let base = if is_listen_server {
        node_config.gossip_fanout_for_listen_server()
    } else {
        node_config.gossip_fanout
    };
    peers_count.max(base.max(0) as usize)
}

/// Whether a transport that would otherwise be active (per its own
/// mode-selection logic) should actually listen and/or dial out, folding in
/// `DisableNetworking` (issue #1189, go: `DisableNetworking bool`
/// `version[16]:"false"`) on top of that decision. Go: `node.go`'s and
/// `follower_node.go`'s identical `startNetwork` closures both skip
/// `node.net.Start()` entirely under this flag ("disables all the incoming
/// and outgoing communication a node would perform"), regardless of what
/// mode the network would otherwise have run in.
///
/// `relay` (unconditionally a listen server) and `participate`
/// (mode-dependent, via `p2p_transport::NetworkMode::ws_listener_active`/
/// `p2p_active`) both call this with the same precedence:
/// `DisableNetworking` always wins over an otherwise-active mode.
pub fn networking_active(mode_active: bool, disable_networking: bool) -> bool {
    mode_active && !disable_networking
}

/// Resolve `config.json`'s `FallbackDNSResolverAddress` into the `Option<String>`
/// [`algo_network::HickorySrvResolver::new`] expects (issue #1312).
///
/// Go's `FallbackDNSResolverAddress string` (`config/localTemplate.go`) is
/// threaded straight into `resolveSRVRecords`/`readFromSRV`
/// (`network/wsNetwork.go`, `tools/network/bootstrap.go`), where an empty
/// string means "no fallback configured" — the DNSSEC resolver chain then
/// goes straight from the system resolver to the default public resolvers on
/// failure, skipping the fallback step entirely
/// (`tools/network/bootstrap.go`'s `readFromSRV`: `if fallbackDNSResolverAddress != ""`).
/// `HickorySrvResolver` mirrors that chain already (`fallback_resolver`); this
/// just maps the empty-string sentinel onto `None` so a stock/unset config
/// doesn't try to stand up a resolver against `""`.
pub fn resolve_fallback_dns_resolver(fallback_dns_resolver_address: &str) -> Option<String> {
    if fallback_dns_resolver_address.is_empty() {
        None
    } else {
        Some(fallback_dns_resolver_address.to_string())
    }
}

/// Map a network name to its genesis ID.
///
/// Returns `None` for unknown networks.
pub fn genesis_id_for(network: &str) -> Option<&'static str> {
    preset(network).map(|p| p.genesis_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every preset's name/genesis id/hash/embedded genesis are mutually
    /// consistent, and the shared algokey table knows every preset.
    #[test]
    fn presets_are_internally_consistent() {
        let mut seen = std::collections::HashSet::new();
        for p in PRESETS {
            assert!(seen.insert(p.name), "duplicate preset {}", p.name);
            assert!(p.genesis_id.starts_with(&format!("{}-", p.name)));
            assert!(p.genesis_hash().is_some(), "{}: no genesis hash", p.name);
            if let Some(json) = p.genesis_json {
                let g = algo_ledger::genesis::parse_genesis_json(json).unwrap();
                assert_eq!(format!("{}-{}", g.network, g.id), p.genesis_id);
                assert_eq!(
                    Some(algo_ledger::genesis::genesis_hash(&g)),
                    p.genesis_hash(),
                    "{}: embedded genesis hash != preset hash",
                    p.name
                );
            }
            if let Some(t) = p.dns_bootstrap_id {
                algo_network::dns_bootstrap::parse_dns_bootstrap(t, p.name, true)
                    .unwrap_or_else(|e| panic!("{}: bad DNS template: {e}", p.name));
            }
        }
    }

    #[test]
    fn vendored_genesis_only_served_for_matching_resolved_id() {
        let g = vendored_genesis_json("voimain", "voimain-v1.0").expect("voimain genesis");
        assert!(g.contains("voimain"));
        // Mismatch (e.g. custom genesis under --network voimain): never served.
        assert_eq!(vendored_genesis_json("voimain", "mychain-v1"), None);
        assert_eq!(vendored_genesis_json("voimain", ""), None);
        // Presets without a vendored genesis, and unknown networks.
        assert_eq!(vendored_genesis_json("mainnet", "mainnet-v1.0"), None);
        assert_eq!(vendored_genesis_json("nope", "voimain-v1.0"), None);
    }

    #[test]
    fn voimain_preset_matches_live_chain_facts() {
        let p = preset("voimain").expect("voimain preset");
        assert_eq!(p.genesis_id, "voimain-v1.0");
        assert_eq!(
            data_encoding::BASE64.encode(&p.genesis_hash().unwrap()),
            "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk="
        );
        assert_eq!(p.rest_url, Some("https://mainnet-api.voi.nodely.dev"));
        assert!(p.genesis_json.is_some());
        assert!(p.catchpoint_index_url.is_none());
        assert_eq!(genesis_id_for("voimain"), Some("voimain-v1.0"));
    }

    /// `--network voimain` parses on the subcommands that take a network.
    #[test]
    fn cli_accepts_voimain_network() {
        use crate::cli::{Cli, Commands};
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "algod-rust",
            "participate",
            "--ledger-path",
            "l",
            "--partkey-path",
            "p",
            "--network",
            "voimain",
        ]);
        match cli.map(|c| c.command) {
            Ok(Commands::Participate { network, .. }) => assert_eq!(network, "voimain"),
            other => panic!(
                "participate --network voimain did not parse: {:?}",
                other.err()
            ),
        }
        assert!(Cli::try_parse_from(["algod-rust", "observe", "--network", "voimain"]).is_ok());
    }

    #[test]
    fn effective_dns_bootstrap_precedence() {
        let voi = preset("voimain").unwrap().dns_bootstrap_id.unwrap();
        assert_eq!(
            effective_dns_bootstrap("voimain", None, DNS_BOOTSTRAP_TEMPLATE),
            (voi, true)
        );
        assert_eq!(
            effective_dns_bootstrap("voimain", Some("x.example"), DNS_BOOTSTRAP_TEMPLATE),
            ("x.example", true)
        );
        assert_eq!(
            effective_dns_bootstrap("voimain", None, "custom.example"),
            ("custom.example", false)
        );
        assert_eq!(
            effective_dns_bootstrap("mainnet", None, DNS_BOOTSTRAP_TEMPLATE),
            (DNS_BOOTSTRAP_TEMPLATE, false)
        );
    }

    #[test]
    fn genesis_id_for_known_networks() {
        assert_eq!(genesis_id_for("mainnet"), Some("mainnet-v1.0"));
        assert_eq!(genesis_id_for("testnet"), Some("testnet-v1.0"));
        assert_eq!(genesis_id_for("devnet"), Some("devnet-v1.0"));
        assert_eq!(genesis_id_for("betanet"), Some("betanet-v1.0"));
    }

    #[test]
    fn genesis_id_for_unknown_network() {
        assert_eq!(genesis_id_for("foonet"), None);
    }

    /// Issue #770: a stock default config must not enable automatic
    /// catchpoint generation (matches `Local::stores_catchpoints`'s own
    /// "stock default = false" behavior).
    #[test]
    fn resolve_automatic_catchpoint_config_none_for_stock_default() {
        assert!(resolve_automatic_catchpoint_config(&algo_config::Local::default()).is_none());
    }

    /// Even with `CatchpointTracking` resolving to "stores", an empty
    /// `CatchpointDir` must disable automatic generation rather than
    /// writing into an unspecified location.
    #[test]
    fn resolve_automatic_catchpoint_config_none_when_dir_is_empty() {
        let cfg = algo_config::Local {
            catchpoint_interval: 10_000,
            catchpoint_tracking: 2, // Stored
            catchpoint_dir: String::new(),
            ..algo_config::Local::default()
        };
        assert!(resolve_automatic_catchpoint_config(&cfg).is_none());
    }

    /// The happy path: Stored mode with a non-empty `CatchpointDir`
    /// resolves to a populated `AutoCatchpointConfig` carrying the
    /// configured interval/history-length/dir through unchanged.
    #[test]
    fn resolve_automatic_catchpoint_config_populated_when_enabled() {
        let cfg = algo_config::Local {
            catchpoint_interval: 5_000,
            catchpoint_file_history_length: 10,
            catchpoint_tracking: 2, // Stored
            catchpoint_dir: "/data/catchpoints".to_string(),
            ..algo_config::Local::default()
        };
        let resolved = resolve_automatic_catchpoint_config(&cfg).unwrap();
        assert_eq!(resolved.interval, 5_000);
        assert_eq!(resolved.file_history_length, 10);
        assert_eq!(resolved.dir, std::path::PathBuf::from("/data/catchpoints"));
    }

    // --- `resolve_retention_config` (issue #1354) ---------------------------

    /// A stock default config resolves to the all-default
    /// `RetentionConfig` (no lookback override, no catchpoint floor, not
    /// archival) -- identical to the pre-#1354 consensus-only behavior.
    #[test]
    fn resolve_retention_config_stock_default_is_all_default() {
        let resolved = resolve_retention_config(&algo_config::Local::default());
        assert_eq!(
            resolved,
            algo_ledger::store_trait::RetentionConfig::default()
        );
    }

    /// `MaxBlockHistoryLookback`/`Archival` pass through unchanged. With
    /// `CatchpointInterval` explicitly disabled, `stores_catchpoints() ==
    /// false` leaves the catchpoint floor at `0` (note: leaving
    /// `CatchpointInterval` at its stock nonzero default here would make
    /// `stores_catchpoints()` resolve to `true` too, since
    /// `CatchpointTracking`'s default Automatic mode follows `archival` —
    /// that's correct go-mirroring behavior, just not what this test is
    /// isolating).
    #[test]
    fn resolve_retention_config_lookback_and_archival_pass_through() {
        let cfg = algo_config::Local {
            max_block_history_lookback: 22_000,
            archival: true,
            catchpoint_interval: 0,
            ..algo_config::Local::default()
        };
        assert!(!cfg.stores_catchpoints());
        let resolved = resolve_retention_config(&cfg);
        assert_eq!(resolved.max_block_history_lookback, 22_000);
        assert!(resolved.archival);
        assert_eq!(resolved.catchpoint_min_rounds_lookback, 0);
    }

    /// A node that stores catchpoints resolves the catchpoint floor to
    /// `2 * CatchpointInterval`, mirroring go's
    /// `calcMinCatchpointRoundsLookback`.
    #[test]
    fn resolve_retention_config_catchpoint_floor_when_storing_catchpoints() {
        let cfg = algo_config::Local {
            catchpoint_interval: 10_000,
            catchpoint_tracking: 2, // Stored
            ..algo_config::Local::default()
        };
        assert!(cfg.stores_catchpoints());
        let resolved = resolve_retention_config(&cfg);
        assert_eq!(resolved.catchpoint_min_rounds_lookback, 20_000);
    }

    /// `CatchpointFileHistoryLength == 0` disables the catchpoint floor
    /// even when the node otherwise stores catchpoints -- matches go's
    /// `calcMinCatchpointRoundsLookback`'s explicit
    /// `CatchpointFileHistoryLength == 0` bail-out.
    #[test]
    fn resolve_retention_config_catchpoint_floor_disabled_when_history_length_zero() {
        let cfg = algo_config::Local {
            catchpoint_interval: 10_000,
            catchpoint_tracking: 2, // Stored
            catchpoint_file_history_length: 0,
            ..algo_config::Local::default()
        };
        assert!(cfg.stores_catchpoints());
        let resolved = resolve_retention_config(&cfg);
        assert_eq!(resolved.catchpoint_min_rounds_lookback, 0);
    }

    /// `CatchpointFileHistoryLength == -1` ("keep all catchpoint files
    /// forever") does NOT disable the floor -- only an exact `0` does, per
    /// go's `l.cfg.CatchpointFileHistoryLength == 0` check (verified
    /// directly against `ledger/ledger.go`, not just the field's doc
    /// comment).
    #[test]
    fn resolve_retention_config_catchpoint_floor_kept_when_history_length_negative_one() {
        let cfg = algo_config::Local {
            catchpoint_interval: 10_000,
            catchpoint_tracking: 2, // Stored
            catchpoint_file_history_length: -1,
            ..algo_config::Local::default()
        };
        assert!(cfg.stores_catchpoints());
        let resolved = resolve_retention_config(&cfg);
        assert_eq!(resolved.catchpoint_min_rounds_lookback, 20_000);
    }

    // --- `resolve_gossip_fanout` (issue #788) -------------------------------

    /// A listen server (`relay`, always; `participate`, once
    /// `--listen-address` resolves) with a stock (un-overridden)
    /// `GossipFanout` gets go's relay default (8), not the ordinary
    /// default (4) — the core `enrichNetworkingConfig` parity fix.
    #[test]
    fn resolve_gossip_fanout_listen_server_bumps_stock_default() {
        let cfg = algo_config::Local::default();
        assert_eq!(resolve_gossip_fanout(&cfg, true, 0), 8);
    }

    /// A non-listen-server node (e.g. `participate` with no
    /// `--listen-address`) keeps the ordinary default (4) — go never
    /// applies `defaultRelayGossipFanout` to a node with no listen
    /// address.
    #[test]
    fn resolve_gossip_fanout_non_listen_server_keeps_ordinary_default() {
        let cfg = algo_config::Local::default();
        assert_eq!(resolve_gossip_fanout(&cfg, false, 0), 4);
    }

    /// An explicit `config.json` override survives the listen-server bump
    /// untouched, whether or not the node is a listen server.
    #[test]
    fn resolve_gossip_fanout_preserves_explicit_override_either_way() {
        let cfg = algo_config::Local {
            gossip_fanout: 20,
            ..algo_config::Local::default()
        };
        assert_eq!(resolve_gossip_fanout(&cfg, true, 0), 20);
        assert_eq!(resolve_gossip_fanout(&cfg, false, 0), 20);
    }

    /// `--peers` acts as a floor regardless of the resolved base value —
    /// the algod-rust-only heuristic layered on top of go's own logic.
    #[test]
    fn resolve_gossip_fanout_peers_count_floors_the_result() {
        let cfg = algo_config::Local::default();
        assert_eq!(resolve_gossip_fanout(&cfg, true, 12), 12);
        assert_eq!(resolve_gossip_fanout(&cfg, false, 12), 12);
    }

    // --- `resolve_fallback_dns_resolver` (issue #1312) ----------------------

    /// A stock/unset config (`FallbackDNSResolverAddress == ""`) resolves to
    /// `None` — matching go's "no fallback configured" semantics rather than
    /// trying to build a resolver targeting an empty address.
    #[test]
    fn resolve_fallback_dns_resolver_empty_is_none() {
        assert_eq!(resolve_fallback_dns_resolver(""), None);
    }

    /// A configured fallback address is passed through unchanged.
    #[test]
    fn resolve_fallback_dns_resolver_configured_is_some() {
        assert_eq!(
            resolve_fallback_dns_resolver("8.8.8.8"),
            Some("8.8.8.8".to_string())
        );
    }

    // --- `networking_active` (issue #1189) ----------------------------------

    /// An otherwise-active transport stays active when `DisableNetworking`
    /// is off — the stock default case.
    #[test]
    fn networking_active_stays_active_when_not_disabled() {
        assert!(networking_active(true, false));
    }

    /// `DisableNetworking: true` overrides an otherwise-active transport —
    /// the core parity fix (go: `!cfg.DisableNetworking` guards
    /// `node.net.Start()`).
    #[test]
    fn networking_active_disabled_overrides_an_active_mode() {
        assert!(!networking_active(true, true));
    }

    /// A transport that was never active for its own mode-selection reasons
    /// (e.g. `P2pOnly` mode asking about the WS listener) stays inactive
    /// either way.
    #[test]
    fn networking_active_inactive_mode_stays_inactive_either_way() {
        assert!(!networking_active(false, false));
        assert!(!networking_active(false, true));
    }
}
