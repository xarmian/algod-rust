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
    match network {
        "mainnet" => Some("mainnet-v1.0"),
        "testnet" => Some("testnet-v1.0"),
        "devnet" => Some("devnet-v1.0"),
        "betanet" => Some("betanet-v1.0"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
