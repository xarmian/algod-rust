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
//!    `interval` (and *only* at those rounds) once the ledger is past
//!    `CatchpointLookback`.
//! 2. Retention: only the newest `file_history_length` files survive.
//!
//! Also covers the issue #1054 regression: automatic export must stamp
//! `blocks_round == balances_round + CatchpointLookback` (320, the
//! fallback `DEFAULT_MAX_BAL_LOOKBACK` used when the ledger's protocol is
//! unset, as in these tests) rather than `balances_round == blocks_round`,
//! and must skip exporting entirely below that threshold rather than
//! underflowing — mirroring the real go-algorand catchup client's
//! `StoreBalancesRound` (`ledger/catchupaccessor.go`), which computes
//! `balancesRound := blk.Round() - CatchpointLookback` and fails that
//! subtraction for any label round at or below the lookback.

use algo_ledger::catchpoint::AutoCatchpointConfig;
use algo_ledger::sqlite::SqliteLedger;
use algo_ledger::LedgerStore;

/// `CatchpointLookback`'s fallback value for an unset/unrecognized
/// consensus version (`crate::catchpoint::DEFAULT_MAX_BAL_LOOKBACK`,
/// go: `MaxBalLookback`) -- these tests never configure a genesis/protocol,
/// so the ledger's `self.protocol` is always `""` and the automatic-export
/// path falls back to this value.
const CATCHPOINT_LOOKBACK: u64 = 320;

/// Read a catchpoint file's `content.msgpack` header back out of the
/// gzipped tar archive, mirroring `catchpoint_export_test.rs`'s own helper.
fn read_catchpoint_header(path: &std::path::Path) -> algo_ledger::catchpoint::CatchpointFileHeader {
    use std::io::Read as _;
    let bytes = std::fs::read(path).unwrap();
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&bytes[..]));
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry.path().unwrap().to_string_lossy() == "content.msgpack" {
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            return rmp_serde::from_slice(&data).unwrap();
        }
    }
    panic!("content.msgpack entry not found in {}", path.display());
}

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
            interval: 100,
            file_history_length: 2,
            dir: catchpoint_dir.clone(),
        }));

        // interval=100 up to round 700 -> candidate rounds 100..700. Only
        // rounds strictly above CatchpointLookback (320) actually export
        // (issue #1054): 400, 500, 600, 700.
        apply_rounds(&mut ledger, 700);

        // The background export thread is fire-and-forget in production;
        // for a deterministic test, block until the last one finishes.
        ledger.wait_for_pending_catchpoint_export();
    }

    let mut names: Vec<String> = std::fs::read_dir(&catchpoint_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();

    // file_history_length=2 -> only the newest 2 of {400,500,600,700} survive: 600, 700.
    assert_eq!(
        names,
        vec![
            "600.catchpoint.tar.gz".to_string(),
            "700.catchpoint.tar.gz".to_string(),
        ],
        "expected catchpoints only at interval rounds 600 and 700 (100/200/300 skipped as \
         within CatchpointLookback of genesis, 400/500 pruned by file_history_length=2), \
         got {names:?}"
    );

    let _ = std::fs::remove_dir_all(&catchpoint_dir);
    let _ = std::fs::remove_file(algo_ledger::sqlite::tracker_path_for_prefix(&ledger_path));
    let _ = std::fs::remove_file(algo_ledger::sqlite::block_path_for_prefix(&ledger_path));
}

#[test]
fn automatic_catchpoint_export_skips_rounds_at_or_below_catchpoint_lookback() {
    // Issue #1054: a real go-algorand catchup client's `StoreBalancesRound`
    // underflows its `uint64` subtraction (`blk.Round() - CatchpointLookback`)
    // for any label round at or below the lookback. algod-rust must never
    // produce such a catchpoint in the first place.
    let ledger_path = temp_ledger_path("skip-below-lookback");
    let catchpoint_dir = temp_catchpoint_dir("skip-below-lookback");
    std::fs::create_dir_all(&catchpoint_dir).unwrap();

    {
        let mut ledger = SqliteLedger::open(&ledger_path).unwrap();
        ledger.configure_automatic_catchpoints(Some(AutoCatchpointConfig {
            interval: 80,
            file_history_length: -1,
            dir: catchpoint_dir.clone(),
        }));

        // Candidate rounds 80, 160, 240, 320 are all <= CATCHPOINT_LOOKBACK
        // (320) and must be skipped entirely.
        apply_rounds(&mut ledger, CATCHPOINT_LOOKBACK);
        ledger.wait_for_pending_catchpoint_export();
    }

    let count = std::fs::read_dir(&catchpoint_dir).unwrap().count();
    assert_eq!(
        count, 0,
        "no catchpoint should be exported at or below CatchpointLookback ({CATCHPOINT_LOOKBACK})"
    );

    let _ = std::fs::remove_dir_all(&catchpoint_dir);
    let _ = std::fs::remove_file(algo_ledger::sqlite::tracker_path_for_prefix(&ledger_path));
    let _ = std::fs::remove_file(algo_ledger::sqlite::block_path_for_prefix(&ledger_path));
}

#[test]
fn automatic_catchpoint_export_stamps_balances_round_below_blocks_round_by_lookback() {
    // Issue #1054's core invariant: once exporting does happen, the file's
    // `blocksRound` (the label round, and the round a catchup client
    // downloads/verifies a real block for) and `balancesRound` (the round
    // whose account state the balance chunks reflect) must differ by
    // exactly `CatchpointLookback`, matching go-algorand's
    // `finishCatchpoint`/`StoreBalancesRound` relationship -- not the old
    // `balances_round == blocks_round == round` behavior this issue fixes.
    let ledger_path = temp_ledger_path("balances-round-offset");
    let catchpoint_dir = temp_catchpoint_dir("balances-round-offset");
    std::fs::create_dir_all(&catchpoint_dir).unwrap();

    let round: u64 = CATCHPOINT_LOOKBACK + 10;
    {
        let mut ledger = SqliteLedger::open(&ledger_path).unwrap();
        ledger.configure_automatic_catchpoints(Some(AutoCatchpointConfig {
            interval: round,
            file_history_length: -1,
            dir: catchpoint_dir.clone(),
        }));
        apply_rounds(&mut ledger, round);
        ledger.wait_for_pending_catchpoint_export();
    }

    let path = catchpoint_dir.join(format!("{round}.catchpoint.tar.gz"));
    assert!(
        path.exists(),
        "expected a catchpoint at round {round} (> CatchpointLookback), found: {:?}",
        std::fs::read_dir(&catchpoint_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect::<Vec<_>>()
    );

    let header = read_catchpoint_header(&path);
    assert_eq!(
        header.blocks_round, round,
        "blocks_round must be the just-committed round"
    );
    assert_eq!(
        header.balances_round,
        round - CATCHPOINT_LOOKBACK,
        "balances_round must trail blocks_round by exactly CatchpointLookback"
    );
    assert_eq!(
        header.blocks_round - header.balances_round,
        CATCHPOINT_LOOKBACK,
        "blocks_round and balances_round must differ by exactly CatchpointLookback \
         (go: ledger/catchupaccessor.go's StoreBalancesRound)"
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
