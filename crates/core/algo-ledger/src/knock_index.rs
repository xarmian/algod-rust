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

//! In-memory candidate index for the proposer's knock-offline selection
//! (issue #1885, follow-up of #1817).
//!
//! [`crate::apply::knock_offline_lists`] must consider every online account
//! that could be listed as expired or absent. Decoding all of them per
//! proposal is O(online accounts). Only a small subset can ever qualify at a
//! given round, and which subset is a function of two numbers per account:
//!
//! * `vote_last_valid` of an account holding a (non-zero) vote key: it is an
//!   expiry candidate exactly when `vote_last_valid < round`;
//! * `last_seen` of an `IncentiveEligible` account: it is an absence
//!   candidate only if the active challenge can fail it (`last_seen <
//!   challenge.round`) or its lag exceeds the minimum allowable one
//!   (`last_seen != 0 && last_seen + ABSENT_FACTOR < round`).
//!
//! The index keeps those two keys in ordered sets so the candidate addresses
//! for a round are range queries; only candidates are then decoded and fed to
//! the unchanged exact per-account checks, so the proposed lists are
//! identical to those of a full scan (the superset property is tested against
//! `knock_offline_lists_full_scan_oracle`).

use algo_types::{AccountData, AccountStatus, Address};
use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::apply::ABSENT_FACTOR;

/// Fall back to streaming the whole ordered online set when more than
/// `1/DEFAULT_FALLBACK_DIVISOR` of the indexed accounts are candidates: a
/// point lookup per candidate costs ~30x a streamed row.
pub(crate) const DEFAULT_FALLBACK_DIVISOR: usize = 16;

/// Index keys of one online account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Keys {
    /// `Some(vote_last_valid)` when the account holds a non-zero vote key.
    vlv: Option<u64>,
    /// `Some(last_seen)` when the account is `IncentiveEligible`.
    seen: Option<u64>,
}

/// Keys for `acct`, or `None` when it is not a member of the online set the
/// knock-offline stream walks (`normalizedonlinebalance > 0` and status
/// `Online`), or can never be listed.
pub(crate) fn keys_of(
    acct: &AccountData,
    nob_positive: bool,
) -> Option<(Option<u64>, Option<u64>)> {
    if !nob_positive || acct.status != AccountStatus::Online {
        return None;
    }
    let vlv = acct
        .vote_id
        .is_some_and(|v| v != [0u8; 32])
        .then_some(acct.vote_last_valid);
    let seen = acct
        .incentive_eligible
        .then(|| crate::heartbeat::last_seen(acct.last_proposed, acct.last_heartbeat));
    if vlv.is_none() && seen.is_none() {
        return None;
    }
    Some((vlv, seen))
}

#[derive(Debug, Default)]
pub(crate) struct KnockIndex {
    keys: BTreeMap<[u8; 32], Keys>,
    by_vlv: BTreeSet<(u64, [u8; 32])>,
    by_seen: BTreeSet<(u64, [u8; 32])>,
    /// Addresses whose entry may disagree with the committed database (the
    /// index was built while a block's uncommitted writes were visible, which
    /// a rollback can undo). They are never answered from the index; the next
    /// commit re-reads them.
    pub(crate) unsettled: HashSet<Address>,
}

impl KnockIndex {
    pub(crate) fn len(&self) -> usize {
        self.keys.len()
    }

    /// Set (or, with `None`, drop) the entry of `addr`.
    pub(crate) fn set(&mut self, addr: &Address, keys: Option<(Option<u64>, Option<u64>)>) {
        if let Some(old) = self.keys.remove(&addr.0) {
            if let Some(v) = old.vlv {
                self.by_vlv.remove(&(v, addr.0));
            }
            if let Some(s) = old.seen {
                self.by_seen.remove(&(s, addr.0));
            }
        }
        let Some((vlv, seen)) = keys else {
            return;
        };
        if let Some(v) = vlv {
            self.by_vlv.insert((v, addr.0));
        }
        if let Some(s) = seen {
            self.by_seen.insert((s, addr.0));
        }
        self.keys.insert(addr.0, Keys { vlv, seen });
    }

    /// The indexed addresses that may be listed at `round` (a superset of
    /// the actually listable ones), excluding `skip`. `challenge_round` is the
    /// active challenge's round, 0 when none. `None` as soon as more than
    /// `limit` candidates are found (the caller then streams the whole set).
    pub(crate) fn candidates(
        &self,
        round: u64,
        challenge_round: u64,
        skip: &HashSet<Address>,
        limit: usize,
    ) -> Option<BTreeSet<[u8; 32]>> {
        let mut out = BTreeSet::new();
        let min = [0u8; 32];
        for (_, a) in self.by_vlv.range(..(round, min)) {
            if !skip.contains(&Address(*a)) {
                out.insert(*a);
                if out.len() > limit {
                    return None;
                }
            }
        }
        // `last_seen + ABSENT_FACTOR < round` with a seen account, or a seen
        // round the challenge can fail.
        let lag_bound = round.saturating_sub(ABSENT_FACTOR);
        let (lo, hi) = if challenge_round > 0 {
            (0, lag_bound.max(challenge_round))
        } else {
            (1, lag_bound)
        };
        if lo < hi {
            for (_, a) in self.by_seen.range((lo, min)..(hi, min)) {
                if !skip.contains(&Address(*a)) {
                    out.insert(*a);
                    if out.len() > limit {
                        return None;
                    }
                }
            }
        }
        Some(out)
    }

    /// Whether the indexed keys equal `want` (used by consistency checks).
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn snapshot(&self) -> Vec<([u8; 32], Option<u64>, Option<u64>)> {
        self.keys.iter().map(|(a, k)| (*a, k.vlv, k.seen)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `candidates` is exactly the brute-force predicate the exact checks can
    /// accept, including the active-challenge range.
    #[test]
    fn candidates_match_the_brute_force_predicate() {
        let mut state = 7u64;
        let mut next = move |m: u64| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) % m
        };
        let mut index = KnockIndex::default();
        let mut model = Vec::new();
        for i in 0..400u32 {
            let mut a = [0u8; 32];
            a[..4].copy_from_slice(&i.to_be_bytes());
            let vlv = (next(3) != 0).then(|| next(40));
            let seen = (next(3) != 0).then(|| next(40));
            if vlv.is_none() && seen.is_none() {
                continue;
            }
            index.set(&Address(a), Some((vlv, seen)));
            model.push((a, vlv, seen));
        }
        // Replace and drop entries: the sets must follow.
        for (a, _, _) in model.iter().take(50) {
            index.set(&Address(*a), None);
        }
        let model: Vec<_> = model.into_iter().skip(50).collect();
        let skip: HashSet<Address> = model.iter().take(5).map(|(a, _, _)| Address(*a)).collect();
        for round in [0u64, 5, 21, 30, 45, 80] {
            for ch in [0u64, 3, 17, 60] {
                let got = index.candidates(round, ch, &skip, usize::MAX).unwrap();
                assert!(index.candidates(round, ch, &skip, got.len()).is_some());
                if !got.is_empty() {
                    assert!(index.candidates(round, ch, &skip, got.len() - 1).is_none());
                }
                let want: BTreeSet<[u8; 32]> = model
                    .iter()
                    .filter(|(a, vlv, seen)| {
                        !skip.contains(&Address(*a))
                            && (vlv.is_some_and(|v| v < round)
                                || seen.is_some_and(|s| {
                                    (s != 0 && s + ABSENT_FACTOR < round) || s < ch
                                }))
                    })
                    .map(|(a, _, _)| *a)
                    .collect();
                assert_eq!(got, want, "round={round} challenge={ch}");
            }
        }
    }
}
