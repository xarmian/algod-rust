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

//! TDD regression for issue #770: automatic, interval-driven catchpoint
//! generation wired into the live block-apply loop
//! (`SqliteLedger::commit_block`), not just the one-shot
//! `algod-rust catchpoint export` CLI.
//!
//! Applies a small run of rounds against an on-disk `SqliteLedger` with
//! `AutoCatchpointConfig { interval: 2, file_history_length: 2, .. }`
//! configured, waits for any in-flight background export to finish, and
//! asserts:
//!
//! 1. A catchpoint file is written at every round that is a multiple of
//!    `interval` (and *only* at those rounds).
//! 2. Retention: only the newest `file_history_length` files survive.

use algo_ledger::catchpoint::AutoCatchpointConfig;
use algo_ledger::sqlite::SqliteLedger;
use algo_ledger::LedgerStore;

fn temp_ledger_path(test_name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "algod-rust-catchpoint-auto-test-{test_name}-{}",
        std::process::id()
    ))
}

fn temp_catchpoint_dir(test_name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "algod-rust-catchpoint-auto-dir-{test_name}-{}",
        std::process::id()
    ))
}

/// Apply `rounds` trivial rounds (an `accounttotals` seed write each time,
/// mirroring `sqlite.rs`'s own `commit_block_appends_online_supply_snapshot_for_each_round`
/// unit test) and commit each one.
///
/// Waits for any automatic catchpoint export the just-committed round
/// triggered before moving to the next round. In production, a node's
/// round cadence (seconds) is vastly longer than an export's real-world
/// duration, so the next catchpoint round never arrives before the
/// previous export finishes; blocking here reproduces that same
/// non-overlapping ordering deterministically instead of relying on
/// this test process's incidental round-commit speed racing a
/// background thread's OS-scheduled start.
fn apply_rounds(ledger: &mut SqliteLedger, rounds: u64) {
    for round in 1..=rounds {
        ledger.begin_block().unwrap();
        ledger.set_current_round(algo_types::Round(round));
        ledger
            .put_account_totals_seed(1_000_000 + round, 0, 0, 0, 0, 0)
            .unwrap();
        ledger.commit_block().unwrap();
        ledger.wait_for_pending_catchpoint_export();
    }
}

#[test]
fn automatic_catchpoint_generation_fires_at_interval_rounds_and_prunes_old_files() {
    let ledger_path = temp_ledger_path("interval-and-prune");
    let catchpoint_dir = temp_catchpoint_dir("interval-and-prune");
    std::fs::create_dir_all(&catchpoint_dir).unwrap();

    {
        let mut ledger = SqliteLedger::open(&ledger_path).unwrap();
        ledger.configure_automatic_catchpoints(Some(AutoCatchpointConfig {
            interval: 2,
            file_history_length: 2,
            dir: catchpoint_dir.clone(),
        }));

        // 6 rounds with interval=2 -> catchpoint rounds are 2, 4, 6.
        apply_rounds(&mut ledger, 6);

        // The background export thread is fire-and-forget in production;
        // for a deterministic test, block until the last one finishes.
        ledger.wait_for_pending_catchpoint_export();
    }

    let mut names: Vec<String> = std::fs::read_dir(&catchpoint_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();

    // file_history_length=2 -> only the newest 2 of {2,4,6} survive: 4, 6.
    assert_eq!(
        names,
        vec![
            "4.catchpoint.tar.gz".to_string(),
            "6.catchpoint.tar.gz".to_string(),
        ],
        "expected catchpoints only at interval rounds 4 and 6 (round 2 pruned by file_history_length=2), got {names:?}"
    );

    let _ = std::fs::remove_dir_all(&catchpoint_dir);
    let _ = std::fs::remove_file(algo_ledger::sqlite::tracker_path_for_prefix(&ledger_path));
    let _ = std::fs::remove_file(algo_ledger::sqlite::block_path_for_prefix(&ledger_path));
}

#[test]
fn automatic_catchpoint_generation_disabled_when_not_configured() {
    let ledger_path = temp_ledger_path("disabled-by-default");
    let catchpoint_dir = temp_catchpoint_dir("disabled-by-default");
    std::fs::create_dir_all(&catchpoint_dir).unwrap();

    {
        // No `configure_automatic_catchpoints` call at all -- must be a
        // complete no-op, matching `CatchpointInterval == 0`/unset.
        let mut ledger = SqliteLedger::open(&ledger_path).unwrap();
        apply_rounds(&mut ledger, 10);
        ledger.wait_for_pending_catchpoint_export();
    }

    let count = std::fs::read_dir(&catchpoint_dir).unwrap().count();
    assert_eq!(
        count, 0,
        "no catchpoint files should be written when automatic generation is not configured"
    );

    let _ = std::fs::remove_dir_all(&catchpoint_dir);
    let _ = std::fs::remove_file(algo_ledger::sqlite::tracker_path_for_prefix(&ledger_path));
    let _ = std::fs::remove_file(algo_ledger::sqlite::block_path_for_prefix(&ledger_path));
}

#[test]
fn automatic_catchpoint_generation_zero_interval_is_a_noop() {
    let ledger_path = temp_ledger_path("zero-interval");
    let catchpoint_dir = temp_catchpoint_dir("zero-interval");
    std::fs::create_dir_all(&catchpoint_dir).unwrap();

    {
        let mut ledger = SqliteLedger::open(&ledger_path).unwrap();
        // interval == 0 must behave identically to `None` (defensive —
        // `Local::stores_catchpoints()` already implies interval > 0, but
        // the ledger-side guard must not divide/modulo by zero either).
        ledger.configure_automatic_catchpoints(Some(AutoCatchpointConfig {
            interval: 0,
            file_history_length: -1,
            dir: catchpoint_dir.clone(),
        }));
        apply_rounds(&mut ledger, 6);
        ledger.wait_for_pending_catchpoint_export();
    }

    let count = std::fs::read_dir(&catchpoint_dir).unwrap().count();
    assert_eq!(count, 0);

    let _ = std::fs::remove_dir_all(&catchpoint_dir);
    let _ = std::fs::remove_file(algo_ledger::sqlite::tracker_path_for_prefix(&ledger_path));
    let _ = std::fs::remove_file(algo_ledger::sqlite::block_path_for_prefix(&ledger_path));
}
