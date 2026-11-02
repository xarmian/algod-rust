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

//! Issue #2166 -- the tracker WAL under the pool follower's snapshot handover.
//!
//! The transaction pool keeps one `ReadSnapshot` (a SQLite read transaction)
//! alive between blocks and, after each commit, drops it and opens the next
//! (`pool.on_new_block` -> `recompute_block_evaluator`). So a snapshot is alive
//! across every commit: the writer never meets a moment with no WAL reader, and
//! SQLite only restarts a WAL from its start when every frame is backfilled and
//! no reader holds a WAL read mark. The WAL file therefore grew by a block's
//! frames (~80 KB on betanet) per round for as long as the node followed the
//! chain (1.28 GB after ~15 minutes against go's 126 MB).
//!
//! These tests replay that exact sequence through the real ledger and measure
//! the tracker WAL file.

use std::path::Path;

use algo_ledger::{tracker_path_for_prefix, LedgerStore as _, SqliteLedger};
use algo_types::{Address, Round};

/// Commits per run. Each commit is a few WAL frames; the run writes tens of MB
/// of WAL when nothing ever restarts it.
const ROUNDS: u64 = 1500;

fn wal_len(db: &Path) -> u64 {
    let mut p = db.as_os_str().to_owned();
    p.push("-wal");
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

/// Commit `ROUNDS` blocks, handing the snapshot over after each one the way the
/// pool follower does (old snapshot alive during the commit; then drop it and
/// open the next one). Returns the peak tracker WAL file size.
fn follow(handover: bool) -> u64 {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    let tracker = tracker_path_for_prefix(&prefix);

    let probe = Address([7u8; 32]);
    let mut snapshot = handover.then(|| {
        let s = ledger.open_read_snapshot().expect("file-backed snapshot");
        let _ = s.get_account(&probe); // the evaluator's first read takes the read mark
        s
    });
    let mut peak = 0;
    for round in 1..=ROUNDS {
        ledger.begin_block().unwrap();
        ledger.set_current_round(Round(round));
        ledger.commit_block().unwrap();
        peak = peak.max(wal_len(&tracker));
        if handover {
            // `recompute_block_evaluator`: `evaluator = None`, then rebuild.
            drop(snapshot.take());
            let s = ledger.open_read_snapshot().expect("file-backed snapshot");
            let _ = s.get_account(&probe);
            snapshot = Some(s);
        }
    }
    drop(snapshot);
    peak
}

#[test]
fn wal_stays_bounded_while_the_pool_hands_its_snapshot_over_each_block() {
    let no_reader = follow(false);
    let handover = follow(true);
    println!("tracker WAL peak: no reader={no_reader}B snapshot handover={handover}B");
    // With no reader SQLite's own bound applies (a few MB). With a snapshot
    // alive across every commit the WAL must stay in the same ballpark; it was
    // several times larger (and growing without bound) before the fix.
    assert!(
        handover <= no_reader.max(4 * 1024 * 1024) * 2,
        "tracker WAL grew to {handover}B with a snapshot handover per block \
         (no-reader run: {no_reader}B)"
    );
}

/// Durability is unchanged by the checkpoint `open_read_snapshot` now runs: a
/// process killed after some commits (files copied as they are on disk, the
/// `-shm` index dropped, no clean close) recovers every committed round from the
/// WAL on reopen, whether it sits in the database file or only in the WAL tail.
#[test]
fn killed_process_recovers_every_committed_round_from_the_wal() {
    use algo_ledger::block_path_for_prefix;

    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    let probe = Address([7u8; 32]);
    let mut snapshot = None;
    let last = 300u64;
    for round in 1..=last {
        ledger.begin_block().unwrap();
        ledger.set_current_round(Round(round));
        ledger.commit_block().unwrap();
        // Hand the snapshot over on most rounds, so the WAL holds a mix of
        // backfilled frames and an un-checkpointed tail when the "kill" lands.
        if round % 7 != 0 {
            drop(snapshot.take());
            let s = ledger.open_read_snapshot().unwrap();
            let _ = s.get_account(&probe);
            snapshot = Some(s);
        }
    }
    assert!(
        wal_len(&tracker_path_for_prefix(&prefix)) > 0,
        "the scenario needs a live WAL file to recover from"
    );

    // The "kill": copy the files as they are, without the shared-memory index,
    // while the original handles are still open (nothing was closed cleanly).
    let crashed = tempfile::tempdir().unwrap();
    let crashed_prefix = crashed.path().join("ledger");
    for (from, to) in [
        (
            tracker_path_for_prefix(&prefix),
            tracker_path_for_prefix(&crashed_prefix),
        ),
        (
            block_path_for_prefix(&prefix),
            block_path_for_prefix(&crashed_prefix),
        ),
    ] {
        std::fs::copy(&from, &to).unwrap();
        let mut wal_from = from.as_os_str().to_owned();
        wal_from.push("-wal");
        let mut wal_to = to.as_os_str().to_owned();
        wal_to.push("-wal");
        if Path::new(&wal_from).exists() {
            std::fs::copy(&wal_from, &wal_to).unwrap();
        }
    }
    let reopened = SqliteLedger::open_with_prefix(&crashed_prefix).unwrap();
    assert_eq!(reopened.last_committed_round().unwrap(), Some(last));
    assert_eq!(reopened.current_round(), Round(last));
}
