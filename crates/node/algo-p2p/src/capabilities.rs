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
    ///
    /// **Not** the raw namespace bytes. Go's `RoutingDiscovery` (wrapping
    /// `go-libp2p-kad-dht`, `network/p2p/capabilities.go`'s
    /// `CapabilitiesDiscovery.advertise`/`findPeers`) derives the actual
    /// wire-level provider-record key from the namespace via
    /// `go-libp2p`'s `p2p/discovery/routing.nsToCid`:
    /// ```go
    /// func nsToCid(ns string) (cid.Cid, error) {
    ///     h, err := mh.Sum([]byte(ns), mh.SHA2_256, -1)
    ///     return cid.NewCidV1(cid.Raw, h), err
    /// }
    /// ```
    /// and `IpfsDHT.Provide`/`classicProvide`
    /// (`go-libp2p-kad-dht@v0.38.0/routing.go`) then uses `key.Hash()` —
    /// the CID's underlying **multihash bytes**, not the CID's own
    /// version/codec-prefixed encoding — as the actual `GetClosestPeers`/
    /// provider-store key: `[multihash code 0x12, length 0x20, 32-byte
    /// SHA-256 digest]`, 34 bytes total. A raw-namespace-bytes key (e.g.
    /// `b"gossip"`, 7 bytes) is a completely different, non-overlapping
    /// DHT key from what any real go-algorand peer advertises under or
    /// looks up — silently breaking `start_providing`/`get_providers`
    /// interop the same way #560/#563's missing `/kad/1.0.0` protocol
    /// suffix silently broke `get_closest_peers` interop (issue #564).
    pub fn record_key(&self) -> kad::RecordKey {
        use sha2::{Digest, Sha256};
        const MULTIHASH_SHA2_256_CODE: u8 = 0x12;
        const MULTIHASH_SHA2_256_LEN: u8 = 0x20; // 32 bytes, fits in one varint byte.

        let digest = Sha256::digest(self.namespace().as_bytes());
        let mut multihash = Vec::with_capacity(2 + digest.len());
        multihash.push(MULTIHASH_SHA2_256_CODE);
        multihash.push(MULTIHASH_SHA2_256_LEN);
        multihash.extend_from_slice(&digest);
        kad::RecordKey::new(&multihash)
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

    /// Regression guard for issue #564's investigation: the DHT provider
    /// key must be go's `nsToCid(ns).Hash()` — a 34-byte SHA-256
    /// multihash (`0x12, 0x20`, then the digest) — not the raw namespace
    /// bytes. Expected bytes independently computed as
    /// `hashlib.sha256(b"gossip").hexdigest()` prefixed with the
    /// multihash header `1220`, confirmed against go's own
    /// `nsToCid`/`Provide` (`go-libp2p@v0.47.0`
    /// `p2p/discovery/routing/routing.go`,
    /// `go-libp2p-kad-dht@v0.38.0/routing.go`) by source reading, not
    /// just computed independently — see this function's doc comment.
    #[test]
    fn record_key_matches_gos_multihash_derivation() {
        let key = Capability::Gossip.record_key();
        let expected =
            hex::decode("1220dd73a2f7c7982c61006be12e1bbb3e8c9ea6b6e8baf7cc5e307514015fc2fd23")
                .expect("valid hex");
        assert_eq!(key.to_vec(), expected);
    }

    /// The old (buggy) derivation used the raw namespace bytes directly —
    /// assert the fixed key is neither that nor merely "some other
    /// length," to catch a future accidental revert to
    /// `RecordKey::new(&namespace)`.
    #[test]
    fn record_key_is_not_the_raw_namespace_bytes() {
        let key = Capability::Gossip.record_key();
        assert_ne!(key.to_vec(), Capability::Gossip.namespace().as_bytes());
        assert_eq!(
            key.to_vec().len(),
            34,
            "sha256 multihash is always 34 bytes"
        );
    }
}
