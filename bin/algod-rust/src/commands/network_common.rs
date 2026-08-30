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
}
