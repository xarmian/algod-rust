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
}
