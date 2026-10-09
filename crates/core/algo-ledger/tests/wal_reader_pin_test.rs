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

//! Issue #1683 -- the "why" documentation test for the WAL pin.
//!
//! This exercises raw SQLite WAL semantics only (the real
//! `SqliteLedger::open_read_snapshot` reader against a second connection
//! standing in for the catchup's write connection); it does NOT cover the
//! production wiring. That is `participate_wal_pin_tests.rs` in `algod-rust`
//! (pause/reload of the real `ParticipateAgreementControl`). What this file
//! documents and measures: an open `ReadSnapshot` that has performed a read
//! pins the WAL -- `wal_checkpoint(TRUNCATE)` reports busy and the WAL file
//! cannot be reset -- so the WAL grows for as long as the reader lives
//! (~10.5M frames, ~43 GB on mainnet), and it is released the moment the
//! reader is dropped. Run with `--nocapture` to see the measured WAL sizes.

use algo_ledger::{tracker_path_for_prefix, SqliteLedger};
use algo_types::Address;
use rusqlite::{params, Connection};
use std::path::Path;
use std::time::Instant;

const ROWS_PER_BATCH: usize = 20;
const BATCHES: usize = 40;

fn wal_len(tracker: &Path) -> u64 {
    let mut p = tracker.as_os_str().to_owned();
    p.push("-wal");
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

/// `PRAGMA wal_checkpoint(mode)` -> (busy, wal frames, checkpointed frames).
fn checkpoint(conn: &Connection, mode: &str) -> (i64, i64, i64) {
    conn.query_row(&format!("PRAGMA wal_checkpoint({mode})"), [], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })
    .unwrap()
}

/// Write `BATCHES` committed transactions of ~`ROWS_PER_BATCH` 4 KiB rows
/// each (an import-shaped write load), running a PASSIVE checkpoint after
/// every batch -- what SQLite's autocheckpoint does on the committing
/// connection. Returns the peak WAL file size seen.
fn write_import_load(writer: &Connection, tracker: &Path) -> u64 {
    let mut peak = 0;
    let blob = vec![0xABu8; 4096];
    for b in 0..BATCHES {
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        for i in 0..ROWS_PER_BATCH {
            let mut addr = [0u8; 32];
            addr[..8].copy_from_slice(&((b * ROWS_PER_BATCH + i) as u64 + 1).to_le_bytes());
            addr[31] = 0xEE;
            writer
                .execute(
                    "INSERT INTO accountbase (address, normalizedonlinebalance, data) \
                     VALUES (?1, 0, ?2)",
                    params![addr.to_vec(), blob],
                )
                .unwrap();
        }
        writer.execute_batch("COMMIT").unwrap();
        checkpoint(writer, "PASSIVE");
        peak = peak.max(wal_len(tracker));
    }
    peak
}

fn open_pair() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    SqliteLedger,
    Connection,
) {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let ledger = SqliteLedger::open_with_prefix(&prefix).expect("open ledger");
    let tracker = tracker_path_for_prefix(&prefix);
    let writer = Connection::open(&tracker).unwrap();
    // The catchup connection checkpoints explicitly below; make that
    // deterministic by disabling the automatic one.
    writer.execute_batch("PRAGMA wal_autocheckpoint=0").unwrap();
    // A busy TRUNCATE must report busy at once, not after the 5 s default
    // busy wait.
    writer.busy_timeout(std::time::Duration::ZERO).unwrap();
    (dir, tracker, ledger, writer)
}

/// RED/GREEN proof of the pin: while a `ReadSnapshot` that has performed a
/// read is alive, the WAL cannot be reset, and truncation reports busy;
/// dropping it releases the WAL.
#[test]
fn open_read_snapshot_pins_the_wal_until_dropped() {
    let (_dir, tracker, ledger, writer) = open_pair();

    let snap = ledger.open_read_snapshot().expect("file-backed snapshot");
    // The evaluator reads the rewards pool at creation, which is what turns
    // the deferred BEGIN into a real WAL read mark.
    let _ = snap.get_account(&Address([1u8; 32]));

    let pinned_peak = write_import_load(&writer, &tracker);
    let pinned_len = wal_len(&tracker);
    let started = Instant::now();
    let (busy, frames, ckpt) = checkpoint(&writer, "TRUNCATE");
    let pinned_ckpt = started.elapsed();
    assert_eq!(busy, 1, "TRUNCATE must report busy while the reader lives");
    assert!(ckpt < frames, "checkpoint cannot cover the reader's range");
    assert_eq!(
        wal_len(&tracker),
        pinned_len,
        "the WAL file must not be reset while pinned"
    );

    drop(snap);
    let started = Instant::now();
    let (busy, _, _) = checkpoint(&writer, "TRUNCATE");
    let released_ckpt = started.elapsed();
    assert_eq!(busy, 0, "TRUNCATE succeeds once the reader is released");
    assert_eq!(wal_len(&tracker), 0, "WAL reset after release");
    println!(
        "pinned: wal_peak={pinned_peak}B truncate_busy_after={pinned_ckpt:?}; \
         released: truncate={released_ckpt:?}"
    );
}

/// Fixed behaviour: with no reader alive during the write load, the periodic
/// PASSIVE checkpoints keep the WAL bounded and TRUNCATE is never busy.
#[test]
fn wal_stays_bounded_when_the_snapshot_is_released_before_the_import() {
    let (_dir, tracker, ledger, writer) = open_pair();

    let snap = ledger.open_read_snapshot().expect("file-backed snapshot");
    let _ = snap.get_account(&Address([1u8; 32]));
    drop(snap); // what `TransactionPool::set_evaluator_paused(true)` does at pause

    let released_peak = write_import_load(&writer, &tracker);
    let (busy, _, _) = checkpoint(&writer, "TRUNCATE");
    assert_eq!(busy, 0);
    assert_eq!(wal_len(&tracker), 0);

    // Same load with a pinning reader, for the before/after comparison.
    let (_dir2, tracker2, ledger2, writer2) = open_pair();
    let snap2 = ledger2.open_read_snapshot().unwrap();
    let _ = snap2.get_account(&Address([1u8; 32]));
    let pinned_peak = write_import_load(&writer2, &tracker2);
    println!("WAL peak: pinned={pinned_peak}B released={released_peak}B");
    assert!(
        released_peak * 4 < pinned_peak,
        "released WAL peak ({released_peak}) must stay far below pinned ({pinned_peak})"
    );
    drop(snap2);
}
