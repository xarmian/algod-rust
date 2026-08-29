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

//! Thread-safe phonebook for managing peer addresses with rate limiting.
//!
//! Mirrors go-algorand's `network/phonebook/phonebook.go`. The phonebook
//! stores addresses of nodes we might contact, tracks connection timing for
//! rate limiting, and supports role-based filtering and persistent peers that
//! survive peer-list replacements.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;

use crate::peer_role::{Role, RoleSet};

/// Sentinel value: when passed to [`Phonebook::get_addresses`], retrieves all
/// eligible addresses regardless of count.
const GET_ALL_ADDRESSES: usize = usize::MAX;

/// Data associated with a single phonebook entry (address).
///
/// Mirrors Go's `addressData` struct.
#[derive(Debug, Clone)]
struct AddressData {
    /// Time before which we should not retry connecting to this address.
    retry_after: Option<Instant>,

    /// Log of recent connection times used to enforce the rate limit within a
    /// sliding time window.
    recent_connection_times: Vec<Instant>,

    /// The set of network names (e.g. DNS bootstrap domains) to which this
    /// address belongs.
    network_names: HashSet<String>,

    /// The roles this address serves, with independent persistence tracking.
    roles: RoleSet,
}

impl AddressData {
    /// Creates a new entry for the given network name and role.
    fn new(network_name: &str, role: Role, persistent: bool) -> Self {
        let mut network_names = HashSet::new();
        network_names.insert(network_name.to_string());
        Self {
            retry_after: None,
            recent_connection_times: Vec::new(),
            network_names,
            roles: RoleSet::new(role, persistent),
        }
    }
}

/// Thread-safe phonebook that stores peer addresses with connection rate
/// limiting and role-based filtering.
///
/// All public methods take `&self` and use an internal [`RwLock`] for
/// synchronization.
pub struct Phonebook {
    inner: RwLock<PhonebookInner>,
}

/// The mutable interior of [`Phonebook`], protected by an `RwLock`.
#[derive(Debug)]
struct PhonebookInner {
    /// Maximum number of connections allowed within the rate-limiting window.
    connections_rate_limiting_count: usize,

    /// Duration of the sliding window for connection rate limiting.
    connections_rate_limiting_window: Duration,

    /// Map from address string to its associated data.
    data: HashMap<String, AddressData>,
}

impl Phonebook {
    /// Creates a new phonebook with the given rate-limiting parameters.
    ///
    /// # Arguments
    ///
    /// * `connections_rate_limiting_count` - Maximum number of connections
    ///   allowed to a single address within the rate-limiting window.
    /// * `connections_rate_limiting_window` - Duration of the sliding window
    ///   for connection rate limiting.
    pub fn new(
        connections_rate_limiting_count: usize,
        connections_rate_limiting_window: Duration,
    ) -> Self {
        Self {
            inner: RwLock::new(PhonebookInner {
                connections_rate_limiting_count,
                connections_rate_limiting_window,
                data: HashMap::new(),
            }),
        }
    }

    /// Returns up to `n` addresses that match the given role and whose
    /// retry-after time has passed.
    ///
    /// The returned addresses are randomly shuffled. If `n` is
    /// [`GET_ALL_ADDRESSES`] or greater than the number of eligible addresses,
    /// all eligible addresses are returned (shuffled).
    pub fn get_addresses(&self, n: usize, role: Role) -> Vec<String> {
        let inner = self.inner.read().unwrap();
        let filtered = inner.filter_retry_time(role);
        shuffle_select(filtered, n)
    }

    /// Updates the retry-after time for the given address.
    ///
    /// If the address is not in the phonebook, this is a no-op.
    pub fn update_retry_after(&self, addr: &str, retry_after: Instant) {
        let mut inner = self.inner.write().unwrap();
        if let Some(entry) = inner.data.get_mut(addr) {
            entry.retry_after = Some(retry_after);
        }
    }

    /// Calculates and returns the wait time to prevent exceeding the
    /// connection rate limit for the given address.
    ///
    /// # Returns
    ///
    /// A tuple of `(addr_in_phonebook, wait_time, provisional_time)`:
    ///
    /// * `addr_in_phonebook` - `true` if the address exists in this phonebook.
    /// * `wait_time` - `Duration::ZERO` if the connection can proceed
    ///   immediately; otherwise the caller must wait this long.
    /// * `provisional_time` - When `wait_time` is zero, this is the
    ///   provisional connection time that was appended to the recent times
    ///   list. The caller should pass this to [`update_connection_time`] after
    ///   the connection is established.
    ///
    /// [`update_connection_time`]: Phonebook::update_connection_time
    pub fn get_connection_wait_time(&self, addr: &str) -> (bool, Duration, Instant) {
        let mut inner = self.inner.write().unwrap();
        let cur_time = Instant::now();

        if !inner.data.contains_key(addr) {
            return (false, Duration::ZERO, cur_time);
        }

        // Remove expired entries from recent_connection_times.
        let window = inner.connections_rate_limiting_window;
        let mut num_to_remove = 0;
        let mut time_since = Duration::ZERO;

        {
            let times = &inner.data[addr].recent_connection_times;
            while num_to_remove < times.len() {
                time_since = cur_time.duration_since(times[num_to_remove]);
                if time_since >= window {
                    num_to_remove += 1;
                } else {
                    break;
                }
            }
        }

        // Remove expired elements.
        if num_to_remove > 0 {
            let entry = inner.data.get_mut(addr).unwrap();
            entry.recent_connection_times.drain(..num_to_remove);
        }

        // If at the rate limit, return the wait time.
        let num_elts = inner.data[addr].recent_connection_times.len();
        if num_elts >= inner.connections_rate_limiting_count {
            let wait = window.saturating_sub(time_since);
            return (true, wait, cur_time);
        }

        // There is capacity: append a provisional time and return zero wait.
        let provisional_time = Instant::now();
        inner
            .data
            .get_mut(addr)
            .unwrap()
            .recent_connection_times
            .push(provisional_time);

        (true, Duration::ZERO, provisional_time)
    }

    /// Updates the provisional connection time recorded by
    /// [`get_connection_wait_time`] with the current time.
    ///
    /// If the provisional time is not found (e.g. it expired and was removed),
    /// the current time is appended instead.
    ///
    /// Returns `true` if the address was found in the phonebook.
    ///
    /// [`get_connection_wait_time`]: Phonebook::get_connection_wait_time
    pub fn update_connection_time(&self, addr: &str, provisional_time: Instant) -> bool {
        let mut inner = self.inner.write().unwrap();

        let entry = match inner.data.get_mut(addr) {
            Some(e) => e,
            None => return false,
        };

        let now = Instant::now();

        // Find the provisional time and update it.
        for t in entry.recent_connection_times.iter_mut() {
            if *t == provisional_time {
                *t = now;
                return true;
            }
        }

        // Not found (expired). Append current time.
        entry.recent_connection_times.push(now);
        true
    }

    /// Merges a set of addresses for the given network name and role.
    ///
    /// * New addresses in `dns_addresses` are added.
    /// * Existing addresses not in `dns_addresses` that belong to `network_name`
    ///   (and are not persistent for this role) are removed.
    /// * Existing addresses that appear in `dns_addresses` have their network
    ///   name and role updated.
    /// * Persistent peers for this role are never removed.
    pub fn replace_peer_list(&self, dns_addresses: &[String], network_name: &str, role: Role) {
        let mut inner = self.inner.write().unwrap();

        // Build a map of items to remove: entries belonging to network_name
        // that are not persistent for this role.
        let mut remove_items: HashSet<String> = HashSet::new();

        // We need to collect keys first to avoid borrow issues.
        let keys: Vec<String> = inner.data.keys().cloned().collect();
        for k in &keys {
            let pbd = inner.data.get_mut(k).unwrap();
            if pbd.network_names.contains(network_name) && !pbd.roles.is_persistent(role) {
                if pbd.roles.is(role) {
                    // This entry's role IS exactly the role -> mark for removal.
                    remove_items.insert(k.clone());
                } else if pbd.roles.has(role) {
                    // This entry HAS the role (among others) -> just remove
                    // the role bit, don't mark for removal.
                    pbd.roles.remove(role);
                }
            }
        }

        // Process the new address list.
        for addr in dns_addresses {
            if let Some(pb_data) = inner.data.get_mut(addr.as_str()) {
                // Already exists: update network name and role.
                pb_data.network_names.insert(network_name.to_string());
                pb_data.roles.add(role);
                // Do not remove this entry.
                remove_items.remove(addr);
            } else {
                // New entry.
                inner
                    .data
                    .insert(addr.clone(), AddressData::new(network_name, role, false));
            }
        }

        // Remove entries that were missing in dns_addresses.
        for k in &remove_items {
            inner.delete_phonebook_entry(k, network_name);
        }
    }

    /// Adds persistent peers that survive [`replace_peer_list`] calls.
    ///
    /// If a peer already exists, its role is updated to include the given role
    /// as persistent. If it does not exist, it is created with the given
    /// network name and role marked as persistent.
    ///
    /// [`replace_peer_list`]: Phonebook::replace_peer_list
    pub fn add_persistent_peers(&self, dns_addresses: &[String], network_name: &str, role: Role) {
        let mut inner = self.inner.write().unwrap();

        for addr in dns_addresses {
            if let Some(pb_data) = inner.data.get_mut(addr.as_str()) {
                pb_data.roles.add_persistent(role);
            } else {
                inner
                    .data
                    .insert(addr.clone(), AddressData::new(network_name, role, true));
            }
        }
    }

    /// Returns the number of addresses in the phonebook.
    pub fn len(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.data.len()
    }

    /// Returns `true` if the phonebook contains no addresses.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl PhonebookInner {
    /// Returns all addresses whose retry-after time has passed and that have
    /// the given role.
    fn filter_retry_time(&self, role: Role) -> Vec<String> {
        let now = Instant::now();
        let mut out = Vec::with_capacity(self.data.len());
        for (addr, entry) in &self.data {
            let past_retry = match entry.retry_after {
                Some(t) => now >= t,
                None => true, // no retry_after set means it's available
            };
            if past_retry && entry.roles.has(role) {
                out.push(addr.clone());
            }
        }
        out
    }

    /// Removes the network name from the entry. If no network names remain,
    /// the entire entry is deleted.
    fn delete_phonebook_entry(&mut self, entry_name: &str, network_name: &str) {
        if let Some(entry) = self.data.get_mut(entry_name) {
            entry.network_names.remove(network_name);
            if entry.network_names.is_empty() {
                self.data.remove(entry_name);
            }
        }
    }
}

/// Shuffles and selects up to `n` elements from `set`.
///
/// If `n >= set.len()` or `n == GET_ALL_ADDRESSES`, returns a shuffled copy of
/// the entire set. Otherwise, performs a partial Fisher-Yates shuffle to select
/// exactly `n` random elements.
fn shuffle_select(mut set: Vec<String>, n: usize) -> Vec<String> {
    if set.is_empty() {
        return set;
    }
    let mut rng = rand::thread_rng();
    if n >= set.len() || n == GET_ALL_ADDRESSES {
        set.shuffle(&mut rng);
        return set;
    }
    // Partial Fisher-Yates shuffle: pick n elements.
    // This mirrors Go's shuffleSelect which does a partial shuffle.
    for i in 0..n {
        let j = i + rand::Rng::gen_range(&mut rng, 0..set.len() - i);
        set.swap(i, j);
    }
    set.truncate(n);
    set
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_role::{ARCHIVAL_ROLE, RELAY_ROLE};
    use std::collections::HashSet;
    use std::thread;
    use std::time::{Duration, Instant};

    /// Helper: create a phonebook and populate it with the given addresses
    /// as relay peers in the "" network.
    fn make_phonebook_with(addrs: &[&str], rate_count: usize, rate_window: Duration) -> Phonebook {
        let pb = Phonebook::new(rate_count, rate_window);
        let addr_strings: Vec<String> = addrs.iter().map(|s| s.to_string()).collect();
        pb.replace_peer_list(&addr_strings, "", RELAY_ROLE);
        pb
    }

    // -----------------------------------------------------------------------
    // Phonebook::new / length
    // -----------------------------------------------------------------------

    #[test]
    fn new_phonebook_is_empty() {
        let pb = Phonebook::new(1, Duration::from_secs(1));
        assert_eq!(pb.len(), 0);
    }

    // -----------------------------------------------------------------------
    // get_addresses
    // -----------------------------------------------------------------------

    #[test]
    fn get_addresses_returns_all_when_n_exceeds_count() {
        let addrs = ["a", "b", "c", "d", "e"];
        let pb = make_phonebook_with(&addrs, 1, Duration::from_secs(1));

        let result = pb.get_addresses(10, RELAY_ROLE);
        assert_eq!(result.len(), addrs.len());

        let result_set: HashSet<String> = result.into_iter().collect();
        for a in &addrs {
            assert!(result_set.contains(*a), "missing address {}", a);
        }
    }

    #[test]
    fn get_addresses_returns_subset() {
        let addrs = ["a", "b", "c", "d", "e"];
        let pb = make_phonebook_with(&addrs, 1, Duration::from_secs(1));

        let result = pb.get_addresses(2, RELAY_ROLE);
        assert_eq!(result.len(), 2);

        let addr_set: HashSet<&str> = addrs.iter().copied().collect();
        for r in &result {
            assert!(addr_set.contains(r.as_str()), "unexpected address {}", r);
        }
    }

    #[test]
    fn get_addresses_filters_by_role() {
        let relays = vec![
            "relay1".to_string(),
            "relay2".to_string(),
            "relay3".to_string(),
        ];
        let archivers = vec![
            "archiver1".to_string(),
            "archiver2".to_string(),
            "archiver3".to_string(),
        ];

        let pb = Phonebook::new(1, Duration::from_nanos(1));
        pb.replace_peer_list(&relays, "default", RELAY_ROLE);
        pb.replace_peer_list(&archivers, "default", ARCHIVAL_ROLE);

        assert_eq!(pb.len(), 6);

        // Relay queries should only return relay entries.
        for _ in 0..100 {
            let entries = pb.get_addresses(3, RELAY_ROLE);
            for entry in &entries {
                assert!(
                    entry.contains("relay"),
                    "relay query returned non-relay: {}",
                    entry
                );
            }
        }

        // Archival queries should only return archiver entries.
        for _ in 0..100 {
            let entries = pb.get_addresses(3, ARCHIVAL_ROLE);
            for entry in &entries {
                assert!(
                    entry.contains("archiver"),
                    "archival query returned non-archiver: {}",
                    entry
                );
            }
        }
    }

    #[test]
    fn get_addresses_respects_retry_after() {
        let pb = make_phonebook_with(&["a", "b"], 1, Duration::from_secs(1));

        // Set retry_after far in the future for "a".
        pb.update_retry_after("a", Instant::now() + Duration::from_secs(3600));

        // Only "b" should be returned.
        for _ in 0..50 {
            let result = pb.get_addresses(10, RELAY_ROLE);
            assert_eq!(result.len(), 1);
            assert_eq!(result[0], "b");
        }
    }

    #[test]
    fn get_addresses_empty_phonebook() {
        let pb = Phonebook::new(1, Duration::from_secs(1));
        let result = pb.get_addresses(10, RELAY_ROLE);
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // update_retry_after
    // -----------------------------------------------------------------------

    #[test]
    fn update_retry_after_nonexistent_is_noop() {
        let pb = Phonebook::new(1, Duration::from_secs(1));
        // Should not panic.
        pb.update_retry_after("nonexistent", Instant::now());
        assert_eq!(pb.len(), 0);
    }

    // -----------------------------------------------------------------------
    // get_connection_wait_time / update_connection_time
    // -----------------------------------------------------------------------

    #[test]
    fn connection_wait_time_addr_not_in_phonebook() {
        let pb = Phonebook::new(3, Duration::from_secs(10));
        let (in_pb, _wait, _prov) = pb.get_connection_wait_time("unknown");
        assert!(!in_pb);
        assert!(!pb.update_connection_time("unknown", Instant::now()));
    }

    #[test]
    fn connection_wait_time_below_limit() {
        let pb = make_phonebook_with(&["addr1"], 3, Duration::from_secs(3600));

        // First connection: should not wait.
        let (in_pb, wait, prov) = pb.get_connection_wait_time("addr1");
        assert!(in_pb);
        assert_eq!(wait, Duration::ZERO);
        assert!(pb.update_connection_time("addr1", prov));

        // Second connection: should not wait.
        let (in_pb, wait, prov) = pb.get_connection_wait_time("addr1");
        assert!(in_pb);
        assert_eq!(wait, Duration::ZERO);
        assert!(pb.update_connection_time("addr1", prov));

        // Third connection: should not wait (at limit - 1... limit is 3).
        let (in_pb, wait, prov) = pb.get_connection_wait_time("addr1");
        assert!(in_pb);
        assert_eq!(wait, Duration::ZERO);
        assert!(pb.update_connection_time("addr1", prov));

        // Fourth connection: should wait (at limit).
        let (in_pb, wait, _prov) = pb.get_connection_wait_time("addr1");
        assert!(in_pb);
        assert!(
            wait > Duration::ZERO,
            "expected nonzero wait, got {:?}",
            wait
        );
    }

    #[test]
    fn connection_wait_time_expires_old_entries() {
        let window = Duration::from_millis(2);
        let pb = make_phonebook_with(&["addr1"], 3, window);

        // Add 3 connections.
        for _ in 0..3 {
            let (_, wait, prov) = pb.get_connection_wait_time("addr1");
            assert_eq!(wait, Duration::ZERO);
            pb.update_connection_time("addr1", prov);
        }

        // Let the window expire.
        thread::sleep(Duration::from_millis(10));

        // Should be able to connect again without waiting.
        let (_, wait, prov) = pb.get_connection_wait_time("addr1");
        assert_eq!(wait, Duration::ZERO);
        pb.update_connection_time("addr1", prov);

        // After expiry, old entries are removed. Only the new one should remain.
        let inner = pb.inner.read().unwrap();
        assert_eq!(inner.data["addr1"].recent_connection_times.len(), 1);
    }

    #[test]
    fn update_connection_time_expired_provisional() {
        // Test the case where the provisional time has expired and was removed.
        let window = Duration::from_millis(2);
        let pb = make_phonebook_with(&["addr1"], 3, window);

        let (_, _, prov) = pb.get_connection_wait_time("addr1");

        // Let the provisional time expire.
        thread::sleep(Duration::from_millis(10));

        // Trigger cleanup by getting wait time again (this removes the old entry).
        let _ = pb.get_connection_wait_time("addr1");

        // The original provisional time was cleaned up, but update should
        // still succeed (appends now).
        assert!(pb.update_connection_time("addr1", prov));
    }

    #[test]
    fn connection_times_separate_per_address() {
        let pb = make_phonebook_with(&["addr1", "addr2"], 2, Duration::from_secs(3600));

        // Fill up addr1.
        for _ in 0..2 {
            let (_, wait, prov) = pb.get_connection_wait_time("addr1");
            assert_eq!(wait, Duration::ZERO);
            pb.update_connection_time("addr1", prov);
        }

        // addr1 should now require waiting.
        let (_, wait, _) = pb.get_connection_wait_time("addr1");
        assert!(wait > Duration::ZERO);

        // addr2 should still be available.
        let (_, wait, _) = pb.get_connection_wait_time("addr2");
        assert_eq!(wait, Duration::ZERO);
    }

    // -----------------------------------------------------------------------
    // replace_peer_list
    // -----------------------------------------------------------------------

    #[test]
    fn replace_peer_list_adds_new_and_removes_old() {
        let pb = Phonebook::new(1, Duration::from_nanos(1));

        let initial = vec!["a".to_string(), "b".to_string()];
        pb.replace_peer_list(&initial, "default", RELAY_ROLE);

        let mut result = pb.get_addresses(10, RELAY_ROLE);
        result.sort();
        assert_eq!(result, vec!["a", "b"]);

        // Replace with a different list.
        let replacement = vec!["b".to_string(), "c".to_string()];
        pb.replace_peer_list(&replacement, "default", RELAY_ROLE);

        let mut result = pb.get_addresses(10, RELAY_ROLE);
        result.sort();
        assert_eq!(result, vec!["b", "c"]);
    }

    #[test]
    fn replace_peer_list_multi_role() {
        // Mirrors Go's TestReplacePeerList.
        let pb = Phonebook::new(1, Duration::from_nanos(1));

        pb.replace_peer_list(&["a".to_string(), "b".to_string()], "default", RELAY_ROLE);
        let mut res = pb.get_addresses(4, RELAY_ROLE);
        res.sort();
        assert_eq!(res, vec!["a", "b"]);

        pb.replace_peer_list(&["c".to_string()], "default", ARCHIVAL_ROLE);
        let res = pb.get_addresses(4, ARCHIVAL_ROLE);
        assert_eq!(res, vec!["c"]);

        // Make b archival in addition to relay.
        pb.replace_peer_list(
            &["b".to_string(), "c".to_string()],
            "default",
            ARCHIVAL_ROLE,
        );
        let mut res = pb.get_addresses(4, RELAY_ROLE);
        res.sort();
        assert_eq!(res, vec!["a", "b"]);
        let mut res = pb.get_addresses(4, ARCHIVAL_ROLE);
        res.sort();
        assert_eq!(res, vec!["b", "c"]);

        // Update relays (same list).
        pb.replace_peer_list(&["a".to_string(), "b".to_string()], "default", RELAY_ROLE);
        let mut res = pb.get_addresses(4, RELAY_ROLE);
        res.sort();
        assert_eq!(res, vec!["a", "b"]);
        let mut res = pb.get_addresses(4, ARCHIVAL_ROLE);
        res.sort();
        assert_eq!(res, vec!["b", "c"]);

        // Exclude b from archival.
        pb.replace_peer_list(&["c".to_string()], "default", ARCHIVAL_ROLE);
        let mut res = pb.get_addresses(4, RELAY_ROLE);
        res.sort();
        assert_eq!(res, vec!["a", "b"]);
        let res = pb.get_addresses(4, ARCHIVAL_ROLE);
        assert_eq!(res, vec!["c"]);
    }

    #[test]
    fn replace_peer_list_duplicate_filtering() {
        // Mirrors Go's TestMultiPhonebookDuplicateFiltering.
        let set: Vec<String> = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let pha: Vec<String> = set[..7].to_vec();
        let phb: Vec<String> = set[3..].to_vec();

        let pb = Phonebook::new(1, Duration::from_millis(1));
        pb.replace_peer_list(&pha, "pha", RELAY_ROLE);
        pb.replace_peer_list(&phb, "phb", RELAY_ROLE);

        // All 10 unique addresses should be present.
        let result = pb.get_addresses(20, RELAY_ROLE);
        assert_eq!(result.len(), 10);

        let result_set: HashSet<String> = result.into_iter().collect();
        for s in &set {
            assert!(result_set.contains(s), "missing {}", s);
        }
    }

    #[test]
    fn replace_peer_list_different_networks() {
        let pb = Phonebook::new(1, Duration::from_nanos(1));

        let pha = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let phb = vec!["d".to_string(), "e".to_string()];

        pb.replace_peer_list(&pha, "net1", RELAY_ROLE);
        pb.replace_peer_list(&phb, "net2", RELAY_ROLE);

        assert_eq!(pb.len(), 5);

        // Replacing net1 should not affect net2.
        pb.replace_peer_list(&["a".to_string()], "net1", RELAY_ROLE);
        assert_eq!(pb.len(), 3); // a (net1), d (net2), e (net2)

        let mut result = pb.get_addresses(10, RELAY_ROLE);
        result.sort();
        assert_eq!(result, vec!["a", "d", "e"]);
    }

    // -----------------------------------------------------------------------
    // add_persistent_peers
    // -----------------------------------------------------------------------

    #[test]
    fn persistent_peers_survive_replace() {
        // Mirrors Go's TestMultiPhonebookPersistentPeers.
        let persistent = vec!["a".to_string()];
        let set: Vec<String> = ["b", "c", "d", "e", "f", "g", "h", "i", "j", "k"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let pha: Vec<String> = set[..5].to_vec();
        let phb: Vec<String> = set[5..].to_vec();

        let pb = Phonebook::new(1, Duration::from_millis(1));
        pb.add_persistent_peers(&persistent, "pha", RELAY_ROLE);
        pb.add_persistent_peers(&persistent, "phb", RELAY_ROLE);
        pb.replace_peer_list(&pha, "pha", RELAY_ROLE);
        pb.replace_peer_list(&phb, "phb", RELAY_ROLE);

        let all = pb.get_addresses(20, RELAY_ROLE);
        assert_eq!(all.len(), 11); // 10 + 1 persistent
        assert!(all.contains(&"a".to_string()));
    }

    #[test]
    fn persistent_peer_role_update() {
        // Check that role of persistent peer gets updated with add_persistent_peers.
        let persistent = vec!["a".to_string()];

        let pb = Phonebook::new(1, Duration::from_millis(1));
        pb.add_persistent_peers(&persistent, "phc", RELAY_ROLE);
        pb.add_persistent_peers(&persistent, "phc", ARCHIVAL_ROLE);

        let relay_addrs = pb.get_addresses(10, RELAY_ROLE);
        assert_eq!(relay_addrs.len(), 1);
        let arch_addrs = pb.get_addresses(10, ARCHIVAL_ROLE);
        assert_eq!(arch_addrs.len(), 1);
    }

    #[test]
    fn persistent_peer_role_survives_replace() {
        // Check that role of persistent peer survives ReplacePeerList.
        let persistent = vec!["a".to_string()];
        let pb = Phonebook::new(1, Duration::from_millis(1));
        pb.add_persistent_peers(&persistent, "phc", ARCHIVAL_ROLE);

        // Replace with "a" as relay.
        pb.replace_peer_list(&["a".to_string()], "phc", RELAY_ROLE);

        let relay_addrs = pb.get_addresses(10, RELAY_ROLE);
        assert_eq!(relay_addrs.len(), 1);
        let arch_addrs = pb.get_addresses(10, ARCHIVAL_ROLE);
        assert_eq!(arch_addrs.len(), 1);
    }

    #[test]
    fn add_persistent_existing_entry() {
        let pb = Phonebook::new(1, Duration::from_nanos(1));

        // Add as non-persistent first.
        pb.replace_peer_list(&["a".to_string()], "net1", RELAY_ROLE);

        // Now add as persistent.
        pb.add_persistent_peers(&["a".to_string()], "net1", ARCHIVAL_ROLE);

        // Should have both roles.
        assert_eq!(pb.get_addresses(10, RELAY_ROLE).len(), 1);
        assert_eq!(pb.get_addresses(10, ARCHIVAL_ROLE).len(), 1);

        // Should survive replace.
        pb.replace_peer_list(&[], "net1", ARCHIVAL_ROLE);
        assert_eq!(
            pb.get_addresses(10, ARCHIVAL_ROLE).len(),
            1,
            "persistent archival role should survive replace"
        );
    }

    // -----------------------------------------------------------------------
    // shuffle_select
    // -----------------------------------------------------------------------

    #[test]
    fn shuffle_select_empty() {
        let result = shuffle_select(vec![], 5);
        assert!(result.is_empty());
    }

    #[test]
    fn shuffle_select_all() {
        let input: Vec<String> = vec!["a", "b", "c"].into_iter().map(String::from).collect();
        let result = shuffle_select(input.clone(), GET_ALL_ADDRESSES);
        assert_eq!(result.len(), 3);
        let result_set: HashSet<String> = result.into_iter().collect();
        let input_set: HashSet<String> = input.into_iter().collect();
        assert_eq!(result_set, input_set);
    }

    #[test]
    fn shuffle_select_partial() {
        let input: Vec<String> = vec!["a", "b", "c", "d", "e"]
            .into_iter()
            .map(String::from)
            .collect();
        for _ in 0..100 {
            let result = shuffle_select(input.clone(), 2);
            assert_eq!(result.len(), 2);
            let input_set: HashSet<String> = input.iter().cloned().collect();
            for r in &result {
                assert!(input_set.contains(r));
            }
            // No duplicates.
            let result_set: HashSet<&String> = result.iter().collect();
            assert_eq!(result_set.len(), 2);
        }
    }

    // -----------------------------------------------------------------------
    // Thread safety
    // -----------------------------------------------------------------------

    #[test]
    fn concurrent_access() {
        use std::sync::Arc;

        let pb = Arc::new(Phonebook::new(10, Duration::from_secs(1)));

        // Populate.
        let addrs: Vec<String> = (0..20).map(|i| format!("addr{}", i)).collect();
        pb.replace_peer_list(&addrs, "net", RELAY_ROLE);

        let mut handles = vec![];

        // Spawn readers.
        for _ in 0..4 {
            let pb_clone = Arc::clone(&pb);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = pb_clone.get_addresses(5, RELAY_ROLE);
                    let _ = pb_clone.len();
                }
            }));
        }

        // Spawn writers.
        for i in 0..4 {
            let pb_clone = Arc::clone(&pb);
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    let addr = format!("new_addr_{}_{}", i, j);
                    pb_clone.replace_peer_list(&[addr], "net", RELAY_ROLE);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Phonebook should still be functional.
        assert!(!pb.is_empty());
    }

    // -----------------------------------------------------------------------
    // delete_phonebook_entry
    // -----------------------------------------------------------------------

    #[test]
    fn delete_entry_removes_network_name() {
        let pb = Phonebook::new(1, Duration::from_nanos(1));

        // Add "a" to two networks.
        pb.replace_peer_list(&["a".to_string()], "net1", RELAY_ROLE);
        pb.replace_peer_list(&["a".to_string()], "net2", RELAY_ROLE);

        assert_eq!(pb.len(), 1);

        // Replace net1 without "a" -> removes net1 from a's network_names,
        // but "a" should still exist because it's in net2.
        pb.replace_peer_list(&[], "net1", RELAY_ROLE);
        assert_eq!(pb.len(), 1);

        // Replace net2 without "a" -> removes net2. No networks left -> deleted.
        pb.replace_peer_list(&[], "net2", RELAY_ROLE);
        assert_eq!(pb.len(), 0);
    }
}
