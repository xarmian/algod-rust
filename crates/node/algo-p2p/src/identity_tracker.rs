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

//! Peer-identity connection deduplication, mirroring go-algorand's
//! `identityTracker` (`../go-algorand/network/netidentity.go`).
//!
//! # What this is, and what it deliberately is not (yet)
//!
//! go-algorand runs an optional 3-message "Identity Challenge Exchange"
//! (`netidentity.go`'s module doc comment has the full protocol) so two
//! nodes that end up with more than one concurrent connection between them
//! — e.g. both dialed each other at once, or a peer reconnected before the
//! old socket timed out — can recognize that both connections claim the
//! *same* on-chain identity key and close the redundant one, rather than
//! keeping two sockets alive for one logical peer. The exchange itself
//! (challenge/response signing and verification) is a separate concern from
//! *bookkeeping* which identity is currently claimed by which peer — go
//! keeps the exchange in `netidentity.go` alongside a small
//! `identityTracker` interface with exactly two operations:
//!
//! ```text
//! type identityTracker interface {
//!     removeIdentity(p *wsPeer)
//!     setIdentity(p *wsPeer) bool
//! }
//! ```
//!
//! implemented by `publicKeyIdentTracker`, a plain
//! `map[crypto.PublicKey]*wsPeer` guarded by a mutex (go: `peersLock`, held
//! by the caller — `wsNetwork` — not by the tracker itself).
//!
//! [`IdentityTracker`] ports exactly that bookkeeping: given a claimed
//! identity key and a peer identifier, `set_identity` either claims the
//! identity (if free) or confirms the *same* peer already holds it, and
//! rejects (returns `false`) only when a genuinely different peer holds it
//! — this is the signal go-algorand's `identityVerificationHandler` uses to
//! decide "this connection is a duplicate, disconnect it." `remove_identity`
//! releases a claim, but — mirroring go's `removeIdentity`'s own
//! `t.peersByID[p.identity] == p` guard — only if the entry still belongs
//! to the same peer that is being removed (so a peer that already lost a
//! `set_identity` race can't accidentally evict whichever peer *did* win
//! it).
//!
//! This crate has no `wsPeer`/`wsNetwork` equivalent yet (algod-rust's
//! WS-gossip transport lives in `algo-network`, a sibling crate this
//! transport-foundation crate deliberately has no dependency on — see this
//! crate's `lib.rs` doc comment), and the identity-challenge signing itself
//! is out of scope for this issue. So [`IdentityTracker`] is generic over
//! both the identity-key type `K` and the peer-handle type `P`, and — per
//! this issue's explicit safe-scoping note — is **not wired into any live
//! connection-acceptance path**: nothing in [`crate::host`] calls it.
//! Wiring it into a real dedup decision requires the identity-challenge
//! exchange itself (message signing/verification against a live peer
//! connection) plus multi-node interop testing this single-repo change
//! cannot safely provide, so this module stands alone as a directly-tested,
//! algorithm-faithful port, ready for that future wiring.
//!
//! Reference: `../go-algorand/network/netidentity.go`
//! (`identityTracker`, `publicKeyIdentTracker`, `NewIdentityTracker`,
//! `setIdentity`, `removeIdentity`), `network/netidentity_test.go`
//! (`TestNewIdentityTracker`, `TestIdentityTrackerSetIdentity`,
//! `TestIdentityTrackerRemoveIdentity`).

use std::collections::HashMap;
use std::hash::Hash;

/// Deduplicates peers by identity key: at most one peer handle may hold any
/// given identity key at a time.
///
/// `K` is the identity's public-key type (go: `crypto.PublicKey`); `P` is
/// whatever a caller uses to identify a peer/connection (go: `*wsPeer`,
/// compared by pointer identity — this port uses `PartialEq` instead, so a
/// caller should pick a `P` for which equality means "the same peer/
/// connection", e.g. a connection id, a `libp2p::PeerId`, or an `Arc`
/// compared by pointer via `Arc::ptr_eq`-backed `PartialEq`).
///
/// This type performs no locking of its own — go's `publicKeyIdentTracker`
/// likewise relies entirely on its caller (`wsNetwork.peersLock`) for
/// concurrency safety; a concurrent Rust caller should wrap this in a
/// `Mutex`/`RwLock` the same way.
#[derive(Debug, Default)]
pub struct IdentityTracker<K, P> {
    peers_by_id: HashMap<K, P>,
}

impl<K, P> IdentityTracker<K, P>
where
    K: Eq + Hash,
    P: PartialEq,
{
    /// Go: `NewIdentityTracker`.
    pub fn new() -> Self {
        Self {
            peers_by_id: HashMap::new(),
        }
    }

    /// Attempt to claim `identity` for `peer`.
    ///
    /// Returns `true` if the identity was unclaimed (now claimed by `peer`)
    /// or was already claimed by this exact `peer` (idempotent — go:
    /// "if the peer was already there, or if it was added"). Returns
    /// `false` only if a *different* peer already holds `identity` — the
    /// caller (mirroring go's `identityVerificationHandler`) should treat
    /// that as "this connection is a duplicate" and disconnect it.
    ///
    /// Go: `publicKeyIdentTracker.setIdentity`.
    pub fn set_identity(&mut self, identity: K, peer: P) -> bool {
        match self.peers_by_id.get(&identity) {
            None => {
                self.peers_by_id.insert(identity, peer);
                true
            }
            Some(existing) => existing == &peer,
        }
    }

    /// Release `peer`'s claim on `identity`, but only if `identity` is
    /// still held by exactly this `peer` — a peer that lost a
    /// [`set_identity`] race (and was therefore never actually stored) must
    /// not be able to evict whichever peer *did* win it.
    ///
    /// Go: `publicKeyIdentTracker.removeIdentity`.
    ///
    /// [`set_identity`]: IdentityTracker::set_identity
    pub fn remove_identity(&mut self, identity: &K, peer: &P) {
        if self.peers_by_id.get(identity) == Some(peer) {
            self.peers_by_id.remove(identity);
        }
    }

    /// The peer currently holding `identity`, if any.
    pub fn get(&self, identity: &K) -> Option<&P> {
        self.peers_by_id.get(identity)
    }

    /// Number of identities currently claimed.
    pub fn len(&self) -> usize {
        self.peers_by_id.len()
    }

    /// True if no identity is currently claimed. Go: `TestNewIdentityTracker`'s
    /// `require.Empty(t, tracker.peersByID)`.
    pub fn is_empty(&self) -> bool {
        self.peers_by_id.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Key = [u8; 4];

    /// Go: `TestNewIdentityTracker` — `NewIdentityTracker()` starts with an
    /// empty `peersByID` map.
    #[test]
    fn new_tracker_starts_empty() {
        let tracker: IdentityTracker<Key, &str> = IdentityTracker::new();
        assert!(tracker.is_empty());
        assert_eq!(tracker.len(), 0);
    }

    /// Go: `TestIdentityTrackerSetIdentity`.
    #[test]
    fn set_identity_claims_free_slot_and_is_idempotent_for_same_peer() {
        let mut tracker: IdentityTracker<Key, &str> = IdentityTracker::new();
        let id: Key = [0u8; 4];

        assert!(tracker.get(&id).is_none());
        assert!(tracker.set_identity(id, "peer-a"));
        assert_eq!(tracker.get(&id), Some(&"peer-a"));

        // Re-claiming with the same peer must still return true (idempotent).
        assert!(tracker.set_identity(id, "peer-a"));

        // A different peer claiming the same identity must be rejected.
        assert!(!tracker.set_identity(id, "peer-b"));

        // The original claim must be unchanged.
        assert_eq!(tracker.get(&id), Some(&"peer-a"));
    }

    /// Go: `TestIdentityTrackerRemoveIdentity`.
    #[test]
    fn remove_identity_only_evicts_the_owning_peer() {
        let mut tracker: IdentityTracker<Key, &str> = IdentityTracker::new();
        let id: Key = [0u8; 4];

        assert!(tracker.set_identity(id, "peer-a"));
        assert_eq!(tracker.get(&id), Some(&"peer-a"));

        // Removing a peer that does not own this identity's entry must not
        // remove it, even if that peer's own identity key happens to
        // collide (mirrors go's "peer who does not exist in the map (but
        // whose identity does)" scenario).
        tracker.remove_identity(&id, &"peer-b");
        assert_eq!(
            tracker.get(&id),
            Some(&"peer-a"),
            "removing a non-owning peer must not evict the real owner"
        );

        tracker.remove_identity(&id, &"peer-a");
        assert!(tracker.get(&id).is_none());
    }

    #[test]
    fn remove_identity_on_unclaimed_key_is_a_no_op() {
        let mut tracker: IdentityTracker<Key, &str> = IdentityTracker::new();
        let id: Key = [1u8; 4];
        tracker.remove_identity(&id, &"peer-a");
        assert!(tracker.is_empty());
    }

    /// Two distinct identity keys are tracked independently.
    #[test]
    fn distinct_identities_are_independent() {
        let mut tracker: IdentityTracker<Key, &str> = IdentityTracker::new();
        let id_a: Key = [1, 0, 0, 0];
        let id_b: Key = [2, 0, 0, 0];

        assert!(tracker.set_identity(id_a, "peer-a"));
        assert!(tracker.set_identity(id_b, "peer-b"));
        assert_eq!(tracker.len(), 2);

        tracker.remove_identity(&id_a, &"peer-a");
        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.get(&id_b), Some(&"peer-b"));
    }
}
