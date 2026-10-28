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

pub mod algocfg;
pub mod algod;
pub mod autopsy;
pub mod bench;
pub mod bench_replay;
pub mod capture;
pub mod capture_wire;
pub mod catchpoint;
pub mod catchpoint_sync;
pub mod catchupsrv;
pub mod dual_gossip_node;
pub mod follow;
pub mod health_monitor;
pub mod heartbeat_service;
pub mod loadgen;
pub mod network_common;
pub mod node;
pub mod observe;
pub mod p2p_transport;
pub mod participate;
pub mod relay;
pub mod replay;
pub mod stateproof_service;
pub mod sync;
#[cfg(test)]
pub(crate) mod test_support;
pub mod validate;

/// Block until the process is asked to stop: Ctrl+C (SIGINT) or, on unix,
/// SIGTERM. SIGTERM is what `docker stop`, systemd and `goal node stop` send;
/// go's `algod` shuts down gracefully on it (closes its ledger, removes
/// `algod.pid`), whereas the default SIGTERM disposition kills the process
/// with no cleanup (issue #1990).
pub async fn wait_for_shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r,
            _ = term.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

/// Resolve a network name to an (algod_url, algod_token, network_name) tuple.
///
/// Presets with a public REST endpoint ("mainnet", "testnet", "voimain";
/// see `network_common::PRESETS`) use that endpoint.
/// "custom" requires an explicit `--algod-url`.
pub fn resolve_network(
    network: &str,
    algod_url: Option<&str>,
    algod_token: &str,
) -> anyhow::Result<(String, String, &'static str)> {
    if network == "custom" {
        let url = algod_url
            .ok_or_else(|| anyhow::anyhow!("--algod-url is required when --network=custom"))?;
        return Ok((url.to_string(), algod_token.to_string(), "custom"));
    }
    // Presets with a public REST endpoint (mainnet, testnet, voimain, ...).
    match network_common::preset(network).and_then(|p| p.rest_url.map(|u| (p.name, u))) {
        Some((name, url)) => Ok((url.to_string(), String::new(), name)),
        None => {
            let known: Vec<&str> = network_common::PRESETS
                .iter()
                .filter(|p| p.rest_url.is_some())
                .map(|p| p.name)
                .collect();
            if network_common::preset(network).is_some() {
                // A real preset (betanet, devnet) that just has no public
                // default REST endpoint: not an "unknown network".
                anyhow::bail!(
                    "network '{}' has no default REST endpoint: use {}, or custom with --algod-url",
                    network,
                    known.join(", ")
                );
            }
            anyhow::bail!(
                "unknown network '{}': use {}, or custom",
                network,
                known.join(", ")
            );
        }
    }
}

#[cfg(test)]
mod resolve_network_tests {
    use super::resolve_network;

    #[test]
    fn voimain_resolves_to_public_voi_endpoint() {
        let (url, token, name) = resolve_network("voimain", None, "").unwrap();
        assert_eq!(url, "https://mainnet-api.voi.nodely.dev");
        assert!(token.is_empty());
        assert_eq!(name, "voimain");
    }

    #[test]
    fn mainnet_testnet_unchanged() {
        assert_eq!(
            resolve_network("mainnet", None, "").unwrap().0,
            "https://mainnet-api.4160.nodely.dev"
        );
        assert_eq!(
            resolve_network("testnet", None, "").unwrap().0,
            "https://testnet-api.4160.nodely.dev"
        );
    }

    #[test]
    fn preset_without_rest_endpoint_is_not_called_unknown() {
        for n in ["betanet", "devnet"] {
            let e = resolve_network(n, None, "").unwrap_err().to_string();
            assert!(!e.contains("unknown network"), "{e}");
            assert!(e.contains(n) && e.contains("--algod-url"), "{e}");
        }
    }

    #[test]
    fn unknown_network_lists_presets() {
        let e = resolve_network("foonet", None, "").unwrap_err().to_string();
        assert!(e.contains("voimain") && e.contains("mainnet"), "{e}");
    }
}
