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

//! Tracking of a block that fails to apply deterministically (issue #1677).
//!
//! go-algorand's `catchup/service.go` `fetchAndWrite` returns a wrapped
//! "ledger write failed" error for a block that cannot be validated or
//! committed (logging it once through `protocolErrorOnce` /
//! `logEvalPanicOnce` for the unrecoverable classes) and the surrounding
//! `periodicSync` loop simply retries on its stuck-ledger cadence; go never
//! commits such a block and exposes no dedicated status field for it.
//!
//! algod-rust retried the same block every ~8 s forever, logging one
//! `permanent error writing block` line per attempt. This tracker adds the
//! missing piece: when the *same* error is produced for the *same* block
//! twice in a row the node is "stalled on an invalid block". The state is
//! entered once (one ERROR log), the retry cadence backs off exponentially,
//! the state and a failure counter are exposed through `/v2/status` and
//! `/metrics`, and it is cleared (one INFO log) when a block commits.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Smallest retry delay once stalled; matches the periodic-sync cadence
/// (two 4 s ticks), doubled for every further identical failure.
pub const STALL_BACKOFF_BASE: Duration = Duration::from_secs(8);
/// Cap on the stalled retry delay: a stuck node still re-checks every 5 min
/// (a peer may serve a different, valid block for the round).
pub const STALL_BACKOFF_MAX: Duration = Duration::from_secs(300);

/// Consecutive identical failures of one block before the node is reported
/// stalled. One failure may be a transient fault; two identical ones are
/// treated as deterministic.
pub const STALL_THRESHOLD: u64 = 2;

/// What a call to [`ApplyStallTracker::record_failure`] / `record_commit`
/// changed, so the caller can emit exactly one log per transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StallTransition {
    /// First time this (round, error) pair was seen.
    NewFailure,
    /// Same (round, error) seen again, below the stall threshold.
    Repeat,
    /// The threshold was just crossed: log the ERROR now.
    Entered,
    /// Already stalled; the failure repeated (log at debug only).
    StillStalled,
    /// A commit ended the stalled state (log the INFO now).
    Left { round: u64, failures: u64 },
    /// Nothing to report.
    None,
}

/// Point-in-time view of a stall, exposed on `/v2/status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyStall {
    /// The block round that fails to apply.
    pub round: u64,
    /// The (identical) error produced on each attempt.
    pub error: String,
    /// Consecutive identical failures of this block.
    pub consecutive_failures: u64,
    /// Unix time (seconds) of the first failure of this block.
    pub since_unix_secs: u64,
}

#[derive(Debug)]
struct Inner {
    round: u64,
    error: String,
    consecutive: u64,
    since_unix_secs: u64,
    last_failure: Instant,
    stalled: bool,
}

/// Shared (via `Arc`) between the ledger bridge that records failures, the
/// catchup service that backs off, and the REST/metrics adapter.
#[derive(Debug, Default)]
pub struct ApplyStallTracker {
    inner: Mutex<Option<Inner>>,
    failures_total: AtomicU64,
}

impl ApplyStallTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `round` failed to apply with `error`.
    pub fn record_failure(&self, round: u64, error: &str) -> StallTransition {
        self.failures_total.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_mut() {
            Some(s) if s.round == round && s.error == error => {
                s.consecutive += 1;
                s.last_failure = Instant::now();
                if s.stalled {
                    StallTransition::StillStalled
                } else if s.consecutive >= STALL_THRESHOLD {
                    s.stalled = true;
                    StallTransition::Entered
                } else {
                    StallTransition::Repeat
                }
            }
            _ => {
                // A different block or a different error: not (yet) a
                // deterministic repeat. Start over.
                *guard = Some(Inner {
                    round,
                    error: error.to_string(),
                    consecutive: 1,
                    since_unix_secs: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    last_failure: Instant::now(),
                    stalled: false,
                });
                StallTransition::NewFailure
            }
        }
    }

    /// Record that a block committed: any failure history is obsolete.
    pub fn record_commit(&self) -> StallTransition {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match guard.take() {
            Some(s) if s.stalled => StallTransition::Left {
                round: s.round,
                failures: s.consecutive,
            },
            _ => StallTransition::None,
        }
    }

    /// The stall, if the node is currently stalled on an invalid block.
    pub fn stall(&self) -> Option<ApplyStall> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.as_ref().filter(|s| s.stalled).map(|s| ApplyStall {
            round: s.round,
            error: s.error.clone(),
            consecutive_failures: s.consecutive,
            since_unix_secs: s.since_unix_secs,
        })
    }

    /// Total apply failures ever recorded (monotonic).
    pub fn failures_total(&self) -> u64 {
        self.failures_total.load(Ordering::Relaxed)
    }

    /// Retry delay for the `consecutive`-th identical failure:
    /// `STALL_BACKOFF_BASE * 2^(consecutive - STALL_THRESHOLD)`, capped.
    pub fn backoff_for(consecutive: u64) -> Duration {
        let exp = consecutive.saturating_sub(STALL_THRESHOLD).min(16) as u32;
        (STALL_BACKOFF_BASE * 2u32.saturating_pow(exp)).min(STALL_BACKOFF_MAX)
    }

    /// While stalled, how long the catchup service must still wait before
    /// retrying the failing block; `None` when not stalled or the wait is over.
    pub fn retry_in(&self) -> Option<Duration> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let s = guard.as_ref().filter(|s| s.stalled)?;
        let wait = Self::backoff_for(s.consecutive).checked_sub(s.last_failure.elapsed())?;
        (!wait.is_zero()).then_some(wait)
    }

    /// Prometheus text exposition of the stall state.
    pub fn to_prometheus_text(&self) -> String {
        let stall = self.stall();
        let mut out = String::new();
        out.push_str(
            "# HELP algod_rust_ledger_apply_failures_total Block apply failures recorded by the ledger bridge.\n\
             # TYPE algod_rust_ledger_apply_failures_total counter\n",
        );
        out.push_str(&format!(
            "algod_rust_ledger_apply_failures_total {}\n",
            self.failures_total()
        ));
        out.push_str(
            "# HELP algod_rust_sync_stalled_on_invalid_block 1 while the node is stalled on a block that deterministically fails to apply.\n\
             # TYPE algod_rust_sync_stalled_on_invalid_block gauge\n",
        );
        out.push_str(&format!(
            "algod_rust_sync_stalled_on_invalid_block {}\n",
            u8::from(stall.is_some())
        ));
        out.push_str(
            "# HELP algod_rust_sync_stalled_block_round Round of the block the node is stalled on (0 when not stalled).\n\
             # TYPE algod_rust_sync_stalled_block_round gauge\n",
        );
        out.push_str(&format!(
            "algod_rust_sync_stalled_block_round {}\n",
            stall.map(|s| s.round).unwrap_or(0)
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_failure_is_not_a_stall() {
        let t = ApplyStallTracker::new();
        assert_eq!(t.record_failure(10, "boom"), StallTransition::NewFailure);
        assert!(t.stall().is_none());
        assert!(t.retry_in().is_none());
    }

    #[test]
    fn identical_repeat_enters_stall_once() {
        let t = ApplyStallTracker::new();
        t.record_failure(10, "boom");
        assert_eq!(t.record_failure(10, "boom"), StallTransition::Entered);
        assert_eq!(t.record_failure(10, "boom"), StallTransition::StillStalled);
        let s = t.stall().expect("stalled");
        assert_eq!((s.round, s.consecutive_failures), (10, 3));
        assert_eq!(s.error, "boom");
        assert_eq!(t.failures_total(), 3);
    }

    #[test]
    fn different_error_or_block_restarts_the_count() {
        let t = ApplyStallTracker::new();
        t.record_failure(10, "a");
        assert_eq!(t.record_failure(10, "b"), StallTransition::NewFailure);
        assert_eq!(t.record_failure(11, "b"), StallTransition::NewFailure);
        assert!(t.stall().is_none());
    }

    #[test]
    fn commit_clears_stall_and_reports_leaving() {
        let t = ApplyStallTracker::new();
        t.record_failure(10, "boom");
        t.record_failure(10, "boom");
        assert_eq!(
            t.record_commit(),
            StallTransition::Left {
                round: 10,
                failures: 2
            }
        );
        assert!(t.stall().is_none());
        assert_eq!(t.record_commit(), StallTransition::None);
    }

    #[test]
    fn commit_clears_unstalled_history_silently() {
        let t = ApplyStallTracker::new();
        t.record_failure(10, "boom");
        assert_eq!(t.record_commit(), StallTransition::None);
        // history gone: the next failure of the same block starts over.
        assert_eq!(t.record_failure(10, "boom"), StallTransition::NewFailure);
    }

    #[test]
    fn backoff_grows_exponentially_and_is_capped() {
        assert_eq!(ApplyStallTracker::backoff_for(2), Duration::from_secs(8));
        assert_eq!(ApplyStallTracker::backoff_for(3), Duration::from_secs(16));
        assert_eq!(ApplyStallTracker::backoff_for(4), Duration::from_secs(32));
        assert_eq!(ApplyStallTracker::backoff_for(7), Duration::from_secs(256));
        assert_eq!(ApplyStallTracker::backoff_for(8), STALL_BACKOFF_MAX);
        assert_eq!(ApplyStallTracker::backoff_for(10_000), STALL_BACKOFF_MAX);
    }

    #[test]
    fn retry_in_reflects_backoff_while_stalled() {
        let t = ApplyStallTracker::new();
        t.record_failure(10, "boom");
        t.record_failure(10, "boom");
        let w = t.retry_in().expect("must wait");
        assert!(w <= Duration::from_secs(8) && w > Duration::from_secs(6));
    }

    #[test]
    fn prometheus_text_reports_state() {
        let t = ApplyStallTracker::new();
        assert!(t
            .to_prometheus_text()
            .contains("algod_rust_sync_stalled_on_invalid_block 0\n"));
        t.record_failure(77, "x");
        t.record_failure(77, "x");
        let text = t.to_prometheus_text();
        assert!(text.contains("algod_rust_sync_stalled_on_invalid_block 1\n"));
        assert!(text.contains("algod_rust_sync_stalled_block_round 77\n"));
        assert!(text.contains("algod_rust_ledger_apply_failures_total 2\n"));
    }
}
