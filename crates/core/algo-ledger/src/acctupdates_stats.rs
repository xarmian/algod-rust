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

//! Periodic "AccountUpdates telemetry event" (issue #1187) — algod-rust's
//! equivalent of go-algorand's `telemetryspec.AccountsUpdateMetrics` event,
//! gated by `algo_config::Local::enable_account_updates_stats` /
//! `account_updates_stats_interval`.
//!
//! # go-algorand's shape
//!
//! `accountUpdates.prepareCommit` (`ledger/acctupdates.go`) decides, once
//! per deferred commit, whether `now.Sub(au.lastMetricsLogTime) >=
//! au.logAccountUpdatesInterval` (gated by
//! `au.logAccountUpdatesMetrics` = `cfg.EnableAccountUpdatesStats`); if so it
//! times four sub-phases of that commit — old-account preload, in-memory
//! accounts writing, merkle-trie update, and the database commit itself —
//! into a `telemetryspec.AccountsUpdateMetrics` struct, and
//! `accountUpdates.postCommit` logs it as one telemetry event
//! (`au.log.Metrics(telemetryspec.Accounts, dcc.stats, details)`) per
//! *batch* (go batches several rounds' worth of deltas into one deferred
//! commit, so `RoundsCount` can be > 1).
//!
//! # algod-rust's shape
//!
//! `SqliteLedger::commit_block` is synchronous and always commits exactly
//! one round per call — there is no batched, multi-round deferred commit,
//! and therefore no separate "preload old accounts before the batch" phase
//! to time. This module's [`AccountUpdatesStatsSample`] maps directly onto
//! `commit_block_uncleaned`'s existing phases:
//!
//! | go (`AccountsUpdateMetrics`) | algod-rust (`AccountUpdatesStatsSample`) |
//! |---|---|
//! | `StartRound` | `start_round` |
//! | `RoundsCount` (batch size) | *(always exactly 1 round per event; omitted as a field, documented in the emitted event's `rounds_count = 1u64` literal instead)* |
//! | `OldAccountPreloadDuration` | *(no algod-rust phase preloads old account rows before a commit; omitted)* |
//! | `AccountsWritingDuration` | `accounts_writing_duration` (`flush_pending_account_totals_delta` + the online-supply/online-account-history writes) |
//! | `MerkleTrieUpdateDuration` | `merkle_trie_update_duration` (`MerkleTrie::commit`) |
//! | `DatabaseCommitDuration` | `database_commit_duration` (the SQLite `COMMIT`) |
//! | `UpdatedAccountsCount` | `updated_accounts_count` (accounts touched this round, from `pending_online_touched`) |
//! | `UpdatedResourcesCount` / `UpdatedCreatablesCount` | *(no per-round resource/creatable touch-count tracking exists in `SqliteLedger` yet; omitted rather than faked)* |

use std::time::{Duration, Instant};

/// Configuration for the periodic AccountUpdates stats event, resolved once
/// at node startup from `config.json`
/// (`algo_config::Local::enable_account_updates_stats` /
/// `account_updates_stats_interval`) and handed to
/// `SqliteLedger::configure_account_updates_stats`.
#[derive(Debug, Clone, Copy)]
pub struct AccountUpdatesStatsConfig {
    /// Minimum wall-clock time between two consecutive events — go's
    /// `AccountUpdatesStatsInterval`. Callers should not construct this
    /// with a zero interval; `SqliteLedger` treats it as "always due"
    /// defensively (matching `Duration::ZERO`'s natural `>=` semantics)
    /// rather than panicking, but the resolved config should never reach
    /// that state in practice.
    pub interval: Duration,
}

/// One round's worth of measured commit-phase durations and counts,
/// gathered incrementally by `SqliteLedger::commit_block_uncleaned` and
/// emitted as a single `tracing` event by [`log_event`] when due.
#[derive(Debug, Default, Clone, Copy)]
pub struct AccountUpdatesStatsSample {
    pub start_round: u64,
    pub accounts_writing_duration: Duration,
    pub merkle_trie_update_duration: Duration,
    pub database_commit_duration: Duration,
    pub updated_accounts_count: u64,
}

/// Emit the periodic AccountUpdates telemetry-equivalent `tracing` event —
/// algod-rust's answer to go's `au.log.Metrics(telemetryspec.Accounts,
/// dcc.stats, details)` (`ledger/acctupdates.go`'s `postCommit`). `info`
/// level with a dedicated `target` so operators can filter/route it
/// independently of ordinary block-apply log noise, the same operational
/// role go's dedicated telemetry-event stream serves.
pub fn log_event(sample: &AccountUpdatesStatsSample) {
    tracing::info!(
        target: "algo_ledger::acctupdates_stats",
        start_round = sample.start_round,
        rounds_count = 1u64,
        accounts_writing_duration_ns = sample.accounts_writing_duration.as_nanos() as u64,
        merkle_trie_update_duration_ns = sample.merkle_trie_update_duration.as_nanos() as u64,
        database_commit_duration_ns = sample.database_commit_duration.as_nanos() as u64,
        updated_accounts_count = sample.updated_accounts_count,
        "AccountsUpdate telemetry event"
    );
}

/// Tracks whether the configured interval has elapsed since the last
/// emitted event — go's `au.lastMetricsLogTime` check in `prepareCommit`.
#[derive(Debug, Default)]
pub struct AccountUpdatesStatsGate {
    last_logged: Option<Instant>,
}

impl AccountUpdatesStatsGate {
    /// Returns `true` (and immediately records "now" as the new
    /// last-logged time, matching go setting `au.lastMetricsLogTime = now`
    /// at decision time rather than after the metrics finish being
    /// gathered) if `interval` has elapsed since the previous `true`
    /// result, or this is the first call ever made.
    pub fn due(&mut self, interval: Duration) -> bool {
        let now = Instant::now();
        let due = match self.last_logged {
            None => true,
            Some(last) => now.duration_since(last) >= interval,
        };
        if due {
            self.last_logged = Some(now);
        }
        due
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_fires_on_first_call_then_waits_out_the_interval() {
        let mut gate = AccountUpdatesStatsGate::default();
        // First call is always due, regardless of interval.
        assert!(gate.due(Duration::from_secs(3600)));
        // Immediately again: not due yet (interval hasn't elapsed).
        assert!(!gate.due(Duration::from_secs(3600)));
    }

    #[test]
    fn gate_is_immediately_due_with_a_zero_interval() {
        let mut gate = AccountUpdatesStatsGate::default();
        assert!(gate.due(Duration::ZERO));
        // Duration::ZERO elapsed is always >= Duration::ZERO.
        assert!(gate.due(Duration::ZERO));
    }
}
