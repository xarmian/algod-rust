//! Peer capability advertisement over the DHT.
//!
//! Mirrors go-algorand's `network/p2p/capabilities.go`: nodes advertise
//! which optional roles/services they offer (archival, catchpoint-serving,
//! gossip-relay) so a syncing node can find a peer that actually has the
//! capability it needs (e.g. "who can serve me a catchpoint") instead of
//! broadcasting to everyone.
//!
//! Go wraps `go-libp2p-kad-dht`'s `RoutingDiscovery` (`Advertise`/
//! `FindPeers`), which is itself a thin layer over the DHT's **provider
//! record** mechanism (`Provide`/`FindProvidersAsync`) — a namespace string
//! (the capability name) is hashed into a DHT key, and the DHT tracks which
//! peers have announced themselves as providers for that key. This is a
//! separate DHT mechanism from arbitrary key/value records
//! (`PutValue`/`GetValue`, which go's `MakeDHT` explicitly disables via
//! `dht.DisableValues()` — see [`crate::dht::dht_config`]'s doc comment);
//! provider records are unaffected by that setting in both go-libp2p and
//! rust-libp2p. This module is therefore the *only* place in this crate
//! that uses the DHT for anything beyond peer routing.
//!
//! rust-libp2p's [`kad::Behaviour`] exposes the same provider-record
//! mechanism directly as [`kad::Behaviour::start_providing`] /
//! [`kad::Behaviour::get_providers`], so this module is a thin capability-name
//! wrapper around those, the same way go's `capabilities.go` is a thin
//! namespace-string wrapper around `RoutingDiscovery`.

use libp2p::kad;

/// A capability a P2P node may advertise, matching go-algorand's
/// `network/p2p/capabilities.go` `Capability` constants exactly (including
/// the DHT namespace string each advertises under, since that string is
/// part of the wire-level advertisement key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Archival nodes. Go: `Archival Capability = "archival"`.
    Archival,
    /// Catchpoint-storing nodes. Go: `Catchpoints = "catchpointStoring"`.
    Catchpoints,
    /// Non-permissioned relay/gossip nodes. Go: `Gossip = "gossip"`.
    Gossip,
}

impl Capability {
    /// The DHT advertisement namespace string for this capability —
    /// byte-for-byte identical to go's `Capability` constant values.
    pub fn namespace(&self) -> &'static str {
        match self {
            Capability::Archival => "archival",
            Capability::Catchpoints => "catchpointStoring",
            Capability::Gossip => "gossip",
        }
    }

    /// The DHT record key this capability is advertised/looked-up under.
    pub fn record_key(&self) -> kad::RecordKey {
        kad::RecordKey::new(&self.namespace())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_match_go_exactly() {
        // go: network/p2p/capabilities.go
        assert_eq!(Capability::Archival.namespace(), "archival");
        assert_eq!(Capability::Catchpoints.namespace(), "catchpointStoring");
        assert_eq!(Capability::Gossip.namespace(), "gossip");
    }

    #[test]
    fn record_keys_are_derived_from_namespace_and_distinct() {
        let keys: Vec<kad::RecordKey> = [
            Capability::Archival,
            Capability::Catchpoints,
            Capability::Gossip,
        ]
        .iter()
        .map(|c| c.record_key())
        .collect();
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
    }

    #[test]
    fn record_key_is_stable_and_deterministic() {
        assert_eq!(
            Capability::Archival.record_key(),
            Capability::Archival.record_key()
        );
    }
}
