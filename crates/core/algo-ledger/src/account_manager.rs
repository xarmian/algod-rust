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

//! Port of go-algorand's `data.AccountManager` (`data/accountManager.go`).
//!
//! Wraps a [`ParticipationStore`] behind the same small, production-facing
//! API surface go's `AccountManager` gives the node: a `Keys()`-equivalent
//! read of the currently-registered participation set, a
//! `StateProofKeys(round)`-equivalent aggregation across every participation
//! registered for state proofs, and a `DeleteOldKeys()`-equivalent call site
//! for forward-secure key pruning.
//!
//! Unlike go's `AccountManager` (which owns an in-memory `partKeys` map of
//! non-ephemeral keys on top of the registry, used only for a since-removed
//! `ephemeral` bookkeeping path), algod-rust's [`ParticipationStore`] is
//! always the single source of truth -- there is no separate in-memory key
//! set to keep in sync, so `AccountManager` here is a thin, borrowing
//! wrapper rather than an owning one. Concurrency is handled the same way
//! every other production consumer of [`ParticipationStore`] already
//! handles it (e.g. `node.rs` wraps its `ParticipationStore` in
//! `Arc<Mutex<_>>` before handing references to background services) --
//! this type adds no locking of its own, matching
//! [`AgreementKeyManagerBridge`](crate::agreement_key_manager::AgreementKeyManagerBridge)'s
//! existing pattern.

use algo_types::Round;

use crate::participation::{
    delete_old_key_material, GetStateProofSecretsError, Participation, ParticipationRecord,
    ParticipationStore,
};

/// Port of go-algorand's `data.AccountManager`.
///
/// Borrows a [`ParticipationStore`] and exposes the same small set of
/// production entry points go's node code calls through `AccountManager`:
/// [`keys`](Self::keys), [`state_proof_keys`](Self::state_proof_keys), and
/// [`delete_old_keys`](Self::delete_old_keys).
pub struct AccountManager<'a> {
    store: &'a ParticipationStore,
}

impl<'a> AccountManager<'a> {
    /// Wrap a participation store.
    ///
    /// Matches go's `MakeAccountManager(log, registry)` (minus the logger
    /// parameter -- algod-rust uses `tracing` directly).
    pub fn new(store: &'a ParticipationStore) -> Self {
        Self { store }
    }

    /// Returns the participation records valid for round `rnd`.
    ///
    /// Port of go's `AccountManager.Keys(rnd)`
    /// (`../go-algorand/data/accountManager.go:65`): filters every
    /// registered participation by `OverlapsInterval(rnd, rnd)`. Unlike go
    /// (which also loads that round's signing secrets per key via
    /// `GetForRound`, logging and skipping any that fail to load), this
    /// returns metadata-only [`ParticipationRecord`]s -- the production
    /// signing-key lookup path
    /// ([`AgreementKeyManagerBridge::voting_keys`](crate::agreement_key_manager::AgreementKeyManagerBridge::voting_keys))
    /// already resolves secrets per (account, round) against
    /// [`ParticipationStore::get_for_voting_round`], and duplicating that
    /// here would just be a second, divergent implementation of the same
    /// selection.
    pub fn keys(&self, rnd: Round) -> Vec<ParticipationRecord> {
        let all = match self.store.get_all() {
            Ok(records) => records,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "AccountManager.Keys: error while loading records from participation registry"
                );
                return Vec::new();
            }
        };
        all.into_iter()
            .filter(|record| record.overlaps_interval(rnd, rnd))
            .collect()
    }

    /// Returns the state-proof-signing participations valid for round `rnd`,
    /// aggregated across every participation registered for state proofs --
    /// including multiple overlapping registrations for the same account
    /// (e.g. during a key rotation window).
    ///
    /// Port of go's `AccountManager.StateProofKeys(rnd)`
    /// (`../go-algorand/data/accountManager.go:80`): for every registered
    /// participation whose `StateProof` field is present and which overlaps
    /// `rnd`, resolves that round's state-proof secrets and collects them.
    ///
    /// A participation with no state-proof material at all (go's
    /// `part.StateProof == nil`; here, [`ParticipationRecord::state_proof_verifier`]
    /// is `None`) is skipped up front, exactly like go's outer
    /// `part.StateProof != nil` guard -- it is never passed to
    /// [`ParticipationStore::get_state_proof_secrets_for_round`], so it can
    /// never produce a
    /// [`GetStateProofSecretsError::StateProofVerifierNotFound`] in the
    /// first place. Should that error still occur for a participation that
    /// *does* carry verifier metadata (a state-proof-registered key with no
    /// resolvable secrets for this specific round -- an edge case go's own
    /// registry can also hit), it is swallowed without a warning, matching
    /// go's test-observed behavior (`TestGetStateProofKeysDontLogErrorOnNilStateProof`)
    /// that this specific error is never surfaced as a logged failure. Any
    /// other error (e.g. record not found, sqlite failure) is still logged,
    /// matching go's generic `manager.log.Warnf(...)` for every other
    /// `GetStateProofSecretsForRound` failure.
    pub fn state_proof_keys(&self, rnd: Round) -> Vec<Participation> {
        let all = match self.store.get_all() {
            Ok(records) => records,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "AccountManager.StateProofKeys: error while loading records from \
                     participation registry"
                );
                return Vec::new();
            }
        };

        let mut out = Vec::new();
        for record in all {
            if record.state_proof_verifier.is_none() {
                continue;
            }
            if !record.overlaps_interval(rnd, rnd) {
                continue;
            }
            match self
                .store
                .get_state_proof_secrets_for_round(&record.participation_id, rnd)
            {
                Ok(participation) => out.push(participation),
                Err(GetStateProofSecretsError::StateProofVerifierNotFound(_)) => {
                    // Swallowed, not logged -- matches go's
                    // TestGetStateProofKeysDontLogErrorOnNilStateProof.
                }
                Err(e) => {
                    tracing::warn!(
                        participation_id = %record.participation_id.to_base32(),
                        error = %e,
                        "AccountManager.StateProofKeys: could not load state proof keys from \
                         participation registry"
                    );
                }
            }
        }
        out
    }

    /// Deletes old key material for forward security: fully-expired
    /// participations (`lastValid < current_round`), plus forward-secure
    /// trimming of ephemeral one-time-signature keys for rounds already
    /// passed within each remaining participation's validity window.
    ///
    /// Port of go's `AccountManager.DeleteOldKeys(latestHdr, agreementProto)`
    /// (`../go-algorand/data/accountManager.go:170`), specialized to
    /// algod-rust's design: go additionally trims an in-memory
    /// `partKeys` map of non-ephemeral keys it owns on top of the registry;
    /// algod-rust has no such secondary map ([`ParticipationStore`] is
    /// always the single source of truth), so this delegates directly to
    /// [`delete_old_key_material`], which already performs both the
    /// registry's `DeleteExpired` step and the per-key forward-secure trim.
    ///
    /// This is the production call site
    /// [`delete_old_key_material`]/[`KeyManager::delete_old_keys`](crate::participation::KeyManager::delete_old_keys)
    /// previously lacked (issue #1493) -- wired into
    /// `stateproof_service::run_loop`'s per-round maintenance step, mirroring
    /// go's `node.go` calling `AccountManager.DeleteOldKeys` on every new
    /// block.
    ///
    /// Returns the number of records affected (fully deleted + trimmed), or
    /// `0` and a logged warning on a store error -- go's version doesn't
    /// return a count at all (it just logs internally), so `0`-on-error here
    /// is purely a caller convenience, not a meaningful "nothing to do"
    /// signal on its own.
    pub fn delete_old_keys(&self, current_round: Round, default_key_dilution: u64) -> usize {
        match delete_old_key_material(self.store, current_round, default_key_dilution) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "AccountManager.DeleteOldKeys: error while deleting expired records from \
                     participation registry"
                );
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_consensus_crypto::merklesig;
    use algo_types::Address;

    // ------------------------------------------------------------------
    // Port of go-algorand's data/accountManager_test.go.
    //
    // `TestAccountManagerKeys` / `TestAccountManagerKeysRegistry` differ
    // upstream only in whether the registry is a mock or a real sqlite-backed
    // one -- algod-rust has a single `ParticipationStore` implementation, so
    // both collapse into `account_manager_keys_counts_registered_participations`
    // below.
    // ------------------------------------------------------------------

    /// Port of go's `testAccountManagerKeys` (the shared body of
    /// `TestAccountManagerKeys`/`TestAccountManagerKeysRegistry`,
    /// `../go-algorand/data/accountManager_test.go#L103`): register several
    /// participations, then confirm `Keys()` returns exactly that many
    /// records at a round they're all valid for.
    #[test]
    fn account_manager_keys_counts_registered_participations() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let num_part_keys = 10;
        for i in 0..num_part_keys {
            let account = Address([i as u8; 32]);
            let part = Participation::generate(account, Round(0), Round(100), 10_000, 0).unwrap();
            store.insert(&part).unwrap();
        }

        let manager = AccountManager::new(&store);
        assert_eq!(
            manager.keys(Round(1)).len(),
            num_part_keys,
            "incorrect number of keys"
        );
        assert_eq!(store.get_all().unwrap().len(), num_part_keys);
    }

    /// Port of go's `TestAccountManagerOverlappingStateProofKeys`
    /// (`../go-algorand/data/accountManager_test.go#L192`): two
    /// participations for the *same* account, with overlapping state-proof
    /// validity windows (`[0, 2*lifetime]` and `[lifetime, 3*lifetime]`),
    /// registered one at a time. `StateProofKeys(round)` must aggregate
    /// across both once the second is registered, returning one entry per
    /// overlapping participation.
    #[test]
    fn state_proof_keys_aggregates_overlapping_participations_for_one_account() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let manager = AccountManager::new(&store);
        let account = Address([7u8; 32]);
        let lifetime = merklesig::KEY_LIFETIME_DEFAULT;

        let part1 = Participation::generate(
            account,
            Round(0),
            Round(lifetime * 2),
            3,
            merklesig::KEY_LIFETIME_DEFAULT,
        )
        .unwrap();
        store.insert(&part1).unwrap();

        assert_eq!(manager.state_proof_keys(Round(lifetime)).len(), 1);
        assert_eq!(manager.state_proof_keys(Round(lifetime * 2)).len(), 1);

        let part2 = Participation::generate(
            account,
            Round(lifetime),
            Round(lifetime * 3),
            3,
            merklesig::KEY_LIFETIME_DEFAULT,
        )
        .unwrap();
        store.insert(&part2).unwrap();

        assert_eq!(manager.state_proof_keys(Round(0)).len(), 1);
        assert_eq!(manager.state_proof_keys(Round(lifetime)).len(), 2);
        assert_eq!(manager.state_proof_keys(Round(lifetime * 2)).len(), 2);
        assert_eq!(manager.state_proof_keys(Round(lifetime * 3)).len(), 1);
    }

    /// Port of go's `TestAccountManagerRemoveStateProofKeysForExpiredAccounts`
    /// (`../go-algorand/data/accountManager_test.go#L254`): a state-proof
    /// participation must disappear from `StateProofKeys` once
    /// `DeleteOldKeys` is called past its `lastValid` round.
    #[test]
    fn delete_old_keys_removes_expired_state_proof_participations() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let manager = AccountManager::new(&store);
        let account = Address([9u8; 32]);
        let lifetime = merklesig::KEY_LIFETIME_DEFAULT;

        let part1 = Participation::generate(
            account,
            Round(0),
            Round(lifetime * 2),
            3,
            merklesig::KEY_LIFETIME_DEFAULT,
        )
        .unwrap();
        let last_valid = part1.last_valid;
        store.insert(&part1).unwrap();

        for i in 1..=2u64 {
            assert_eq!(
                manager.state_proof_keys(Round(i * lifetime)).len(),
                1,
                "round {}",
                i * lifetime
            );
        }

        manager.delete_old_keys(Round(last_valid.0 + 1), 10_000);

        for i in 1..=2u64 {
            assert_eq!(
                manager.state_proof_keys(Round(i * lifetime)).len(),
                0,
                "round {} after expiry",
                i * lifetime
            );
        }
    }

    /// Port of go's `TestGetStateProofKeysDontLogErrorOnNilStateProof`
    /// (`../go-algorand/data/accountManager_test.go#L301`): a participation
    /// with no state-proof material at all must not cause `StateProofKeys`
    /// to emit any WARN/ERROR-level log line -- it's filtered out by the
    /// outer `state_proof_verifier.is_none()` guard before
    /// `get_state_proof_secrets_for_round` (the only possible source of
    /// `StateProofVerifierNotFound`) is ever called.
    #[test]
    fn state_proof_keys_nil_state_proof_participation_logs_nothing() {
        use tracing_subscriber::layer::SubscriberExt;

        let store = ParticipationStore::open_in_memory().unwrap();
        let manager = AccountManager::new(&store);
        let account = Address([11u8; 32]);
        // key_lifetime = 0 -> Participation::generate produces no
        // state_proof_secrets at all (mirrors go's part.StateProofSecrets =
        // nil / a never-appended-to participation).
        let part = Participation::generate(account, Round(0), Round(100), 10_000, 0).unwrap();
        store.insert(&part).unwrap();

        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        struct CapturingLayer {
            events: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        }
        impl<S> tracing_subscriber::Layer<S> for CapturingLayer
        where
            S: tracing::Subscriber,
        {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                if *event.metadata().level() <= tracing::Level::WARN {
                    self.events
                        .lock()
                        .unwrap()
                        .push(event.metadata().name().to_string());
                }
            }
        }
        let layer = CapturingLayer {
            events: events.clone(),
        };
        let subscriber = tracing_subscriber::registry().with(layer);

        let results =
            tracing::subscriber::with_default(subscriber, || manager.state_proof_keys(Round(1)));

        assert!(results.is_empty(), "no state proof material registered");
        assert!(
            events.lock().unwrap().is_empty(),
            "expected no WARN/ERROR-level log events, got: {:?}",
            events.lock().unwrap()
        );
    }
}
