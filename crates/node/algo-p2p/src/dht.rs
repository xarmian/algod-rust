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

/// Algorand's DHT protocol-name pattern: `/algorand/kad/<network-id>`.
///
/// Go: `network/p2p/dht/dht.go` `dhtProtocolPrefix`:
/// ```go
/// func dhtProtocolPrefix(networkID algoproto.NetworkID) protocol.ID {
///     return protocol.ID(fmt.Sprintf("/algorand/kad/%s", networkID))
/// }
/// ```
pub fn dht_protocol_name(network_id: &str) -> StreamProtocol {
    StreamProtocol::try_from_owned(format!("/algorand/kad/{network_id}"))
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
/// default — and simply never calls `put_record`/`get_record`/
/// `start_providing`, which achieves the same "no value store" behavior as
/// go's explicit `DisableValues()` without needing a config knob for it.
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
        assert_eq!(proto.as_ref(), "/algorand/kad/testnet-v1.0");
    }

    #[test]
    fn different_network_ids_yield_different_protocol_names() {
        assert_ne!(
            dht_protocol_name("mainnet-v1.0"),
            dht_protocol_name("testnet-v1.0")
        );
    }
}
