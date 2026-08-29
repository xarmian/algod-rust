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

//! Kademlia DHT configuration for the `algo-p2p` transport.
//!
//! Mirrors go-algorand's `network/p2p/dht/dht.go` `MakeDHT`: a thin
//! wrapper around a Kademlia implementation configured with an
//! Algorand-specific protocol prefix. Go wraps `go-libp2p-kad-dht`; this
//! crate wraps `rust-libp2p`'s own [`libp2p::kad`] `NetworkBehaviour` —
//! nothing here reimplements Kademlia itself, only the Algorand-specific
//! configuration go's `MakeDHT` applies on top of it.
//!
//! The actual host wiring (composing the DHT behaviour into the swarm,
//! bootstrap, and deadline-safe routing lookups) lives in
//! [`crate::host`], which is where go's `CapabilitiesDiscovery` /
//! `p2pNetwork` glue those pieces together.

use libp2p::StreamProtocol;

/// Algorand's DHT protocol-name pattern:
/// `/algorand/kad/<network-id>/kad/1.0.0`.
///
/// Go: `network/p2p/dht/dht.go` `dhtProtocolPrefix` produces only the
/// *prefix* half of this:
/// ```go
/// func dhtProtocolPrefix(networkID algoproto.NetworkID) protocol.ID {
///     return protocol.ID(fmt.Sprintf("/algorand/kad/%s", networkID))
/// }
/// ```
/// — passed to `go-libp2p-kad-dht`'s `dht.ProtocolPrefix(...)` option. That
/// library does NOT use the prefix as the wire protocol string verbatim:
/// `go-libp2p-kad-dht@v0.28.0`'s `makeDHT` (`dht.go`) computes
/// `v1proto := cfg.ProtocolPrefix + kad1` where `kad1 = protocol.ID("/kad/1.0.0")`,
/// and negotiates DHT streams under `v1proto`, not `cfg.ProtocolPrefix`
/// alone. Missing this suffix here does not fail closed — it silently
/// produces a *different, non-overlapping* protocol string, so a rust
/// host's own `get_closest_peers` calls fail to reach a real go-algorand
/// peer at all (rust-libp2p's kad simply has no shared protocol to open a
/// stream over) while a `libp2p::kad::Behaviour::add_address`-seeded
/// connection to that peer still looks perfectly healthy at the transport
/// layer, which is why this went uncaught until a live multi-node
/// interop run against a real go-algorand DHT (`ops/mixed-cluster-p2p/`,
/// issue #560) surfaced it — #539's own tests only ever connect two
/// `P2pHost`s to each other, which stayed protocol-compatible with
/// *itself* even without the suffix.
pub fn dht_protocol_name(network_id: &str) -> StreamProtocol {
    StreamProtocol::try_from_owned(format!("/algorand/kad/{network_id}/kad/1.0.0"))
        .expect("a network-id-derived protocol name is always a valid StreamProtocol")
}

/// Build the [`libp2p::kad::Config`] used by [`crate::host::P2pHost`]'s DHT
/// behaviour.
///
/// Go's `MakeDHT` additionally sets `dht.DisableValues()` (this DHT is
/// only ever used for peer routing, never as a key/value store) and
/// `dht.Mode(...)` (server if the node has a listen address, client
/// otherwise). This crate's `kad::Behaviour` defaults to
/// `auto_mode: true` (client until an external address is confirmed, then
/// server) — the direct rust-libp2p equivalent of go's listen-address-based
/// default — and simply never calls `put_record`/`get_record`, which
/// achieves the same "no arbitrary value store" behavior as go's explicit
/// `DisableValues()` without needing a config knob for it. This does *not*
/// extend to `start_providing`/`get_providers` (provider records): that is
/// a separate DHT mechanism, unaffected by `DisableValues()` in both
/// go-libp2p and rust-libp2p, and is exactly what [`crate::capabilities`]
/// (#541) uses for capability advertisement — mirroring go-algorand's own
/// `capabilities.go`, which likewise calls DHT `Provide`/`FindProvidersAsync`
/// on a `DisableValues()`-configured DHT.
/// rust-libp2p's default periodic routing-table refresh
/// (`periodic_bootstrap_interval = 5 minutes`, in [`libp2p::kad::Config`])
/// is left as-is: go-algorand's `MakeDHT` does not override
/// `go-libp2p-kad-dht`'s own refresh cadence either, so both sides simply
/// inherit their underlying Kademlia library's default.
pub fn dht_config(network_id: &str) -> libp2p::kad::Config {
    libp2p::kad::Config::new(dht_protocol_name(network_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_name_includes_network_id() {
        let proto = dht_protocol_name("testnet-v1.0");
        assert_eq!(proto.as_ref(), "/algorand/kad/testnet-v1.0/kad/1.0.0");
    }

    /// Regression guard for issue #560's finding: go-libp2p-kad-dht
    /// appends `/kad/1.0.0` to whatever `ProtocolPrefix` go-algorand
    /// configures — this crate's protocol string must include that exact
    /// suffix or a real go-algorand DHT peer negotiates no shared
    /// protocol at all (see this function's doc comment for the full
    /// citation).
    #[test]
    fn protocol_name_matches_go_libp2p_kad_dhts_v1_suffix() {
        let proto = dht_protocol_name("p2pinterop");
        assert_eq!(proto.as_ref(), "/algorand/kad/p2pinterop/kad/1.0.0");
    }

    #[test]
    fn different_network_ids_yield_different_protocol_names() {
        assert_ne!(
            dht_protocol_name("mainnet-v1.0"),
            dht_protocol_name("testnet-v1.0")
        );
    }
}
