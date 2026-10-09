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

//! Round-selection logic for the `wrong-committee-weight` case (#1778).
//!
//! The case needs a round where the injected account wins **zero** proposer
//! seats. The expected seat count is `NumProposers * stake_share`, so an
//! account holding about 10% of the stake misses a given round with
//! probability about `exp(-2)` (~13.5%). The search polls the node for the
//! current round and probes `last + 2`; because the chain advances more slowly
//! than the poll interval, consecutive polls usually yield the *same* round,
//! and re-evaluating a round that was already a miss is not a fresh draw. The
//! old fixed "40 probes" therefore amounted to only ~13 independent draws on a
//! 2.7 s/round cluster and failed roughly 1 run in 7.
//!
//! [`RoundSearch`] counts only distinct rounds and is bounded by wall-clock
//! time (and optionally a cap on distinct rounds), so the search retries until
//! a suitable round exists or the bound is genuinely exhausted.

use std::collections::HashSet;
use std::time::Duration;

/// What the caller should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchStep {
    /// Evaluate sortition for this (not yet tried) round.
    Probe(u64),
    /// The candidate round was already tried; sleep and poll again.
    Wait,
    /// The time budget (or distinct-round cap) is spent without a hit.
    Exhausted {
        /// Number of distinct rounds that were evaluated.
        distinct_rounds: usize,
    },
}

/// Bounded search over distinct future rounds.
#[derive(Debug, Clone)]
pub struct RoundSearch {
    tried: HashSet<u64>,
    budget: Duration,
    max_rounds: usize,
}

impl RoundSearch {
    /// `budget` is the wall-clock bound; `max_rounds == 0` means no cap on
    /// distinct rounds.
    pub fn new(budget: Duration, max_rounds: usize) -> Self {
        Self {
            tried: HashSet::new(),
            budget,
            max_rounds,
        }
    }

    /// Number of distinct rounds evaluated so far.
    pub fn distinct_rounds(&self) -> usize {
        self.tried.len()
    }

    /// Decide the next step given the node's last committed round and the time
    /// spent so far. The first poll always yields a probe, so a zero budget
    /// still evaluates one round.
    pub fn step(&mut self, last_round: u64, elapsed: Duration) -> SearchStep {
        let exhausted = SearchStep::Exhausted {
            distinct_rounds: self.tried.len(),
        };
        if self.max_rounds != 0 && self.tried.len() >= self.max_rounds {
            return exhausted;
        }
        let candidate = last_round.saturating_add(2);
        if !self.tried.contains(&candidate) {
            if elapsed >= self.budget && !self.tried.is_empty() {
                return exhausted;
            }
            self.tried.insert(candidate);
            return SearchStep::Probe(candidate);
        }
        if elapsed >= self.budget {
            return exhausted;
        }
        SearchStep::Wait
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn repeated_polls_of_the_same_round_are_not_new_draws() {
        let mut r = RoundSearch::new(s(300), 0);
        assert_eq!(r.step(10, s(0)), SearchStep::Probe(12));
        assert_eq!(r.step(10, s(1)), SearchStep::Wait);
        assert_eq!(r.step(10, s(2)), SearchStep::Wait);
        assert_eq!(r.step(11, s(3)), SearchStep::Probe(13));
        assert_eq!(r.distinct_rounds(), 2);
    }

    #[test]
    fn keeps_retrying_past_the_old_forty_probe_limit() {
        let mut r = RoundSearch::new(s(300), 0);
        let mut probes = 0;
        for i in 0..200u64 {
            // 3 polls per round, as on a 2.7 s/round cluster polled at 0.9 s.
            if let SearchStep::Probe(_) = r.step(100 + i / 3, s(i)) {
                probes += 1;
            }
        }
        assert!(probes > 40, "distinct rounds probed: {probes}");
    }

    #[test]
    fn exhausted_after_the_time_budget_when_no_new_round() {
        let mut r = RoundSearch::new(s(10), 0);
        assert_eq!(r.step(5, s(0)), SearchStep::Probe(7));
        assert_eq!(r.step(5, s(9)), SearchStep::Wait);
        assert_eq!(
            r.step(5, s(10)),
            SearchStep::Exhausted { distinct_rounds: 1 }
        );
    }

    #[test]
    fn a_new_round_after_the_deadline_is_not_probed() {
        let mut r = RoundSearch::new(s(10), 0);
        assert_eq!(r.step(5, s(0)), SearchStep::Probe(7));
        assert_eq!(
            r.step(6, s(11)),
            SearchStep::Exhausted { distinct_rounds: 1 }
        );
    }

    #[test]
    fn zero_budget_still_evaluates_one_round_then_fails() {
        let mut r = RoundSearch::new(s(0), 0);
        assert_eq!(r.step(5, s(0)), SearchStep::Probe(7));
        assert_eq!(
            r.step(6, s(0)),
            SearchStep::Exhausted { distinct_rounds: 1 }
        );
    }

    #[test]
    fn distinct_round_cap_is_honoured() {
        let mut r = RoundSearch::new(s(1000), 2);
        assert_eq!(r.step(1, s(0)), SearchStep::Probe(3));
        assert_eq!(r.step(2, s(1)), SearchStep::Probe(4));
        assert_eq!(
            r.step(3, s(2)),
            SearchStep::Exhausted { distinct_rounds: 2 }
        );
    }
}
