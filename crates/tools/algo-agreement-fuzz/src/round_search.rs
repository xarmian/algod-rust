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

    /// Record that `round` was actually evaluated (a successful seed fetch
    /// and sortition draw). Only then does it stop being a candidate and
    /// count toward the cap, so a probe that failed on a transient error is
    /// retried rather than silently consumed.
    pub fn mark_tried(&mut self, round: u64) {
        self.tried.insert(round);
    }

    /// Decide the next step given the node's last committed round and the time
    /// spent so far. The first poll always yields a probe, so a zero budget
    /// still evaluates one round. `Probe` does not consume the round: call
    /// [`Self::mark_tried`] once it has really been evaluated.
    pub fn step(&self, last_round: u64, elapsed: Duration) -> SearchStep {
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
            return SearchStep::Probe(candidate);
        }
        if elapsed >= self.budget {
            return exhausted;
        }
        SearchStep::Wait
    }
}

/// Exponential backoff for transient REST failures inside the search loop:
/// 1 s, 2 s, 4 s, then capped at 8 s; [`Backoff::reset`] after a success.
#[derive(Debug, Clone, Default)]
pub struct Backoff {
    failures: u32,
}

impl Backoff {
    /// Delay to sleep after one more failure.
    pub fn next_delay(&mut self) -> Duration {
        let secs = 1u64 << self.failures.min(3);
        self.failures = self.failures.saturating_add(1);
        Duration::from_secs(secs)
    }

    /// Forget past failures after a successful call.
    pub fn reset(&mut self) {
        self.failures = 0;
    }

    /// Consecutive failures so far.
    pub fn failures(&self) -> u32 {
        self.failures
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn probe(r: &mut RoundSearch, last: u64, t: u64) -> SearchStep {
        let step = r.step(last, s(t));
        if let SearchStep::Probe(round) = step {
            r.mark_tried(round);
        }
        step
    }

    #[test]
    fn repeated_polls_of_the_same_round_are_not_new_draws() {
        let mut r = RoundSearch::new(s(300), 0);
        assert_eq!(probe(&mut r, 10, 0), SearchStep::Probe(12));
        assert_eq!(probe(&mut r, 10, 1), SearchStep::Wait);
        assert_eq!(probe(&mut r, 10, 2), SearchStep::Wait);
        assert_eq!(probe(&mut r, 11, 3), SearchStep::Probe(13));
        assert_eq!(r.distinct_rounds(), 2);
    }

    #[test]
    fn a_probe_that_was_not_evaluated_is_retried() {
        let r = RoundSearch::new(s(300), 0);
        // The caller hit a transient error before evaluating round 12 and
        // never called mark_tried: the same round is offered again.
        assert_eq!(r.step(10, s(0)), SearchStep::Probe(12));
        assert_eq!(r.step(10, s(1)), SearchStep::Probe(12));
        assert_eq!(r.distinct_rounds(), 0);
    }

    #[test]
    fn failed_probes_do_not_count_toward_the_cap() {
        let mut r = RoundSearch::new(s(1000), 1);
        assert_eq!(r.step(1, s(0)), SearchStep::Probe(3));
        assert_eq!(r.step(1, s(1)), SearchStep::Probe(3));
        r.mark_tried(3);
        assert_eq!(
            r.step(2, s(2)),
            SearchStep::Exhausted { distinct_rounds: 1 }
        );
    }

    #[test]
    fn keeps_retrying_past_the_old_forty_probe_limit() {
        let mut r = RoundSearch::new(s(300), 0);
        let mut probes = 0;
        for i in 0..200u64 {
            // 3 polls per round, as on a 2.7 s/round cluster polled at 0.9 s.
            if let SearchStep::Probe(_) = probe(&mut r, 100 + i / 3, i) {
                probes += 1;
            }
        }
        assert!(probes > 40, "distinct rounds probed: {probes}");
    }

    #[test]
    fn exhausted_after_the_time_budget_when_no_new_round() {
        let mut r = RoundSearch::new(s(10), 0);
        assert_eq!(probe(&mut r, 5, 0), SearchStep::Probe(7));
        assert_eq!(probe(&mut r, 5, 9), SearchStep::Wait);
        assert_eq!(
            probe(&mut r, 5, 10),
            SearchStep::Exhausted { distinct_rounds: 1 }
        );
    }

    #[test]
    fn a_new_round_after_the_deadline_is_not_probed() {
        let mut r = RoundSearch::new(s(10), 0);
        assert_eq!(probe(&mut r, 5, 0), SearchStep::Probe(7));
        assert_eq!(
            probe(&mut r, 6, 11),
            SearchStep::Exhausted { distinct_rounds: 1 }
        );
    }

    #[test]
    fn zero_budget_still_evaluates_one_round_then_fails() {
        let mut r = RoundSearch::new(s(0), 0);
        assert_eq!(probe(&mut r, 5, 0), SearchStep::Probe(7));
        assert_eq!(
            probe(&mut r, 6, 0),
            SearchStep::Exhausted { distinct_rounds: 1 }
        );
    }

    #[test]
    fn distinct_round_cap_is_honoured() {
        let mut r = RoundSearch::new(s(1000), 2);
        assert_eq!(probe(&mut r, 1, 0), SearchStep::Probe(3));
        assert_eq!(probe(&mut r, 2, 1), SearchStep::Probe(4));
        assert_eq!(
            probe(&mut r, 3, 2),
            SearchStep::Exhausted { distinct_rounds: 2 }
        );
    }

    #[test]
    fn backoff_doubles_caps_and_resets() {
        let mut b = Backoff::default();
        let got: Vec<u64> = (0..6).map(|_| b.next_delay().as_secs()).collect();
        assert_eq!(got, vec![1, 2, 4, 8, 8, 8]);
        assert_eq!(b.failures(), 6);
        b.reset();
        assert_eq!(b.next_delay(), s(1));
    }
}
