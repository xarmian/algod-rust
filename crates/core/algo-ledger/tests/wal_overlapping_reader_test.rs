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
//! the tracker WAL file, pin the documented limit of the fix (any *other*
//! long-lived reader still pins the WAL), kill a ledger process at random
//! points (including inside the snapshot-time checkpoint) and reopen it, and
//! hold an `#[ignore]`d micro benchmark of the per-block cost of the checkpoint.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use algo_ledger::follow_timing::follow_timing;
use algo_ledger::{tracker_path_for_prefix, LedgerStore as _, SqliteLedger};
use algo_types::{Address, Round};
use rusqlite::Connection;

/// Commits per handover run. ~16 KB of WAL frames each: without the fix the
/// run writes ~3 MB of WAL that nothing restarts.
const ROUNDS: u64 = 200;

fn wal_len(db: &Path) -> u64 {
    let mut p = db.as_os_str().to_owned();
    p.push("-wal");
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

/// `PRAGMA wal_checkpoint(PASSIVE)` through a second handle: (busy, WAL frames,
/// checkpointed frames).
fn probe(tracker: &Path) -> (i64, i64, i64) {
    Connection::open(tracker)
        .unwrap()
        .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap()
}

/// The checkpoint counters are process-wide; tests asserting on them take this.
static COUNTERS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn commit_round(ledger: &mut SqliteLedger, round: u64) {
    ledger.begin_block().unwrap();
    ledger.set_current_round(Round(round));
    ledger.commit_block().unwrap();
}

/// Commit `rounds` blocks, handing the snapshot over after each one the way the
/// pool follower does (old snapshot alive during the commit; then drop it and
/// open the next one). Returns the peak tracker WAL file size and the largest
/// WAL frame count seen right after a handover.
fn follow(handover: bool, rounds: u64) -> (u64, i64) {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    // The property does not depend on the fsync level; NORMAL keeps this fast.
    ledger.set_synchronous_mode(1).unwrap();
    let tracker = tracker_path_for_prefix(&prefix);

    let probe_addr = Address([7u8; 32]);
    let mut snapshot = handover.then(|| {
        let s = ledger.open_read_snapshot().expect("file-backed snapshot");
        let _ = s.get_account(&probe_addr); // the evaluator's first read takes the read mark
        s
    });
    let (mut peak, mut max_frames) = (0, 0);
    for round in 1..=rounds {
        commit_round(&mut ledger, round);
        peak = peak.max(wal_len(&tracker));
        if handover {
            // `recompute_block_evaluator`: `evaluator = None`, then rebuild.
            drop(snapshot.take());
            let s = ledger.open_read_snapshot().expect("file-backed snapshot");
            let _ = s.get_account(&probe_addr);
            snapshot = Some(s);
            if round % 10 == 0 {
                // The WAL was restarted: only the last commit's frames are in it.
                let (_, log, _) = probe(&tracker);
                max_frames = max_frames.max(log);
            }
        }
    }
    drop(snapshot);
    (peak, max_frames)
}

#[test]
fn wal_stays_bounded_while_the_pool_hands_its_snapshot_over_each_block() {
    let _guard = COUNTERS.lock().unwrap_or_else(|e| e.into_inner());
    let timed_before = follow_timing().snapshot_checkpoint.count();
    let partial_before = follow_timing().snapshot_checkpoint_partial.get();
    let (no_reader, _) = follow(false, ROUNDS);
    let (handover, frames) = follow(true, ROUNDS);
    println!(
        "tracker WAL peak: no reader={no_reader}B handover={handover}B, \
         frames after a handover <= {frames}"
    );
    // With the fix the WAL is restarted at every block: a few hundred KB
    // (230 KB measured). Without it, the 200 rounds leave ~3 MB and thousands of
    // frames in the WAL.
    assert!(
        handover < 512 * 1024,
        "tracker WAL grew to {handover}B with a snapshot handover per block \
         (no-reader run: {no_reader}B)"
    );
    assert!(
        frames < 200,
        "the WAL was not restarted: {frames} frames still in it after a handover"
    );
    assert!(follow_timing().snapshot_checkpoint.count() >= timed_before + ROUNDS);
    assert_eq!(
        follow_timing().snapshot_checkpoint_partial.get(),
        partial_before,
        "no reader other than the snapshot handover exists, so no checkpoint may be partial"
    );
}

/// The documented limit of the #2166 fix: it only covers the pool's snapshot
/// handover. Any other long-lived reader of the tracker file (the lazy trie
/// loader, a catchpoint export snapshot -- #2206 --, an external tool) pins the
/// WAL for as long as it lives, and the checkpoint reports it as partial.
#[test]
fn a_foreign_long_lived_reader_still_pins_the_wal() {
    let _guard = COUNTERS.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    ledger.set_synchronous_mode(1).unwrap();
    let tracker = tracker_path_for_prefix(&prefix);
    commit_round(&mut ledger, 1);

    let foreign = Connection::open_with_flags(
        &tracker,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    foreign.execute_batch("BEGIN DEFERRED").unwrap();
    let _: i64 = foreign
        .query_row("SELECT count(*) FROM accountbase", [], |r| r.get(0))
        .unwrap();

    let partial_before = follow_timing().snapshot_checkpoint_partial.get();
    let mut snapshot = None;
    for round in 2..=ROUNDS {
        commit_round(&mut ledger, round);
        drop(snapshot.take());
        snapshot = ledger.open_read_snapshot();
    }
    let pinned = wal_len(&tracker);
    assert!(
        pinned > 2 * 1024 * 1024,
        "a foreign reader is expected to pin the WAL (it grew to {pinned}B); if this now \
         stays small the documented limit in DIV-008 is out of date"
    );
    assert!(follow_timing().snapshot_checkpoint_partial.get() > partial_before);

    foreign.execute_batch("ROLLBACK").unwrap();
    drop(snapshot);
    commit_round(&mut ledger, ROUNDS + 1);
    let released = ledger.open_read_snapshot();
    commit_round(&mut ledger, ROUNDS + 2);
    drop(released);
    println!("foreign reader pinned the WAL at {pinned}B");
}

/// A snapshot opened inside a block span skips the checkpoint and says so.
#[test]
fn snapshot_inside_a_block_span_is_counted() {
    let _guard = COUNTERS.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = SqliteLedger::open_with_prefix(&dir.path().join("ledger")).unwrap();
    let before = follow_timing().snapshot_checkpoint_skipped_in_block.get();
    ledger.begin_block().unwrap();
    let snap = ledger.open_read_snapshot();
    assert!(snap.is_some());
    assert_eq!(
        follow_timing().snapshot_checkpoint_skipped_in_block.get(),
        before + 1
    );
    drop(snap);
    ledger.rollback_block().unwrap();
}

/// Documentation of what the pre-fix-shaped test above is *not*: the files are
/// copied at a quiescent point, so this proves only that a ledger whose last
/// process died without a clean close (WAL tail not checkpointed, `-shm`
/// dropped) reopens with every committed round. Recovery from a kill in the
/// middle of a checkpoint is `kill_mid_checkpoint_recovers_*` below.
#[test]
fn copy_of_live_files_without_shm_reopens_with_every_committed_round() {
    use algo_ledger::block_path_for_prefix;

    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    let probe_addr = Address([7u8; 32]);
    let mut snapshot = None;
    let last = 300u64;
    for round in 1..=last {
        commit_round(&mut ledger, round);
        if round % 7 != 0 {
            drop(snapshot.take());
            let s = ledger.open_read_snapshot().unwrap();
            let _ = s.get_account(&probe_addr);
            snapshot = Some(s);
        }
    }
    assert!(
        wal_len(&tracker_path_for_prefix(&prefix)) > 0,
        "the scenario needs a live WAL file to recover from"
    );

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

// ---- kill mid-checkpoint ------------------------------------------------

const CHILD_ENV: &str = "WAL_KILL_CHILD_DIR";

/// Child half of `kill_mid_checkpoint_recovers_*`: with the env var set, resume
/// the ledger in that directory and commit blocks with a snapshot handover
/// (checkpoint included) until killed, reporting each committed round on stdout
/// AFTER its commit returned. Without the env var it is a no-op test.
#[test]
fn wal_kill_child() {
    let Ok(dir) = std::env::var(CHILD_ENV) else {
        return;
    };
    let prefix = PathBuf::from(dir).join("ledger");
    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    let probe_addr = Address([7u8; 32]);
    let mut round = ledger.last_committed_round().unwrap().unwrap_or(0);
    let mut snapshot = None;
    let stdout = std::io::stdout();
    loop {
        round += 1;
        commit_round(&mut ledger, round);
        {
            let mut out = stdout.lock();
            writeln!(out, "R {round}").unwrap();
            out.flush().unwrap();
        }
        drop(snapshot.take());
        let s = ledger.open_read_snapshot().unwrap();
        let _ = s.get_account(&probe_addr);
        snapshot = Some(s);
    }
}

fn integrity_ok(path: &Path) -> bool {
    let c = Connection::open(path).unwrap();
    let r: String = c
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    r == "ok"
}

/// Kill a ledger process (hard kill, no cleanup) 40 times at pseudo-random
/// points while it commits blocks with snapshot handovers -- so kills land in
/// commits and in the snapshot-time checkpoint (frames partly backfilled) --
/// and after every kill reopen the same directory: every round the child had
/// reported committed is present, nothing is half applied, and both database
/// files pass `PRAGMA integrity_check`.
///
/// A kill can also land between the tracker's and the block archive's commit
/// (two files, not atomic: tracker one round ahead). That window is independent
/// of checkpointing and `SqliteLedger::open` currently refuses such a ledger
/// (tracked in #2209); such a kill is counted, both files must still pass the
/// integrity check, and the run continues on a fresh ledger.
#[test]
fn kill_mid_checkpoint_recovers_every_reported_round() {
    if std::env::var(CHILD_ENV).is_ok() {
        return; // never recurse when running as the child
    }
    use algo_ledger::block_path_for_prefix;
    let exe = std::env::current_exe().unwrap();
    let mut dir = tempfile::tempdir().unwrap();
    let mut seed = 0x2166_u64;
    let (mut clean, mut split, mut total_progress) = (0u32, 0u32, 0u64);
    for kill in 0..40 {
        let prefix = dir.path().join("ledger");
        let mut child = Command::new(&exe)
            .args([
                "--exact",
                "wal_kill_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let reader = std::thread::spawn(move || {
            let mut last = 0u64;
            for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
                if let Some(n) = line.strip_prefix("R ") {
                    last = n.parse().unwrap();
                }
            }
            last
        });
        // xorshift: 400..1400 ms of child life (open + a few dozen rounds).
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        std::thread::sleep(Duration::from_millis(400 + seed % 1000));
        child.kill().unwrap();
        child.wait().unwrap();
        let reported = reader.join().unwrap();
        total_progress += reported;

        let mut was_split = false;
        match SqliteLedger::open_with_prefix(&prefix) {
            Ok(ledger) => {
                let committed = ledger.last_committed_round().unwrap().unwrap_or(0);
                assert!(
                    committed >= reported,
                    "kill {kill}: child reported round {reported} committed but the                      reopened ledger is at {committed}"
                );
                assert_eq!(ledger.current_round(), Round(committed), "kill {kill}");
                clean += 1;
            }
            Err(e) => {
                let t = Connection::open(tracker_path_for_prefix(&prefix)).unwrap();
                let b = Connection::open(block_path_for_prefix(&prefix)).unwrap();
                let acct: i64 = t
                    .query_row("SELECT rnd FROM acctrounds WHERE id='acctbase'", [], |r| {
                        r.get(0)
                    })
                    .unwrap();
                let bmax: i64 = b
                    .query_row("SELECT max(rnd) FROM blocks", [], |r| r.get(0))
                    .unwrap();
                assert!(
                    acct == bmax + 1 && bmax as u64 >= reported,
                    "kill {kill}: reopen failed outside the split-commit window: {e};                      reported={reported} acctbase={acct} blocks max={bmax}"
                );
                split += 1;
                was_split = true;
            }
        }
        assert!(
            integrity_ok(&tracker_path_for_prefix(&prefix)),
            "kill {kill}"
        );
        assert!(integrity_ok(&block_path_for_prefix(&prefix)), "kill {kill}");
        if was_split {
            // The ledger cannot be reopened: continue on a fresh one.
            dir = tempfile::tempdir().unwrap();
        }
    }
    assert!(
        clean >= 10 && total_progress > 100,
        "too few clean reopen checks to prove anything: clean={clean} split={split}          rounds={total_progress}"
    );
    println!("40 kills: {clean} clean reopens, {split} in the tracker/block split window, {total_progress} rounds");
}

// ---- cost of the checkpoint ------------------------------------------------

/// Per-block cost of the snapshot-time checkpoint under the ledger lock.
/// `cargo test -p algo-ledger --test wal_overlapping_reader_test -- --ignored
/// --nocapture bench`. "Old open" is the pre-#2166 body of `open_read_snapshot`
/// (open a read-only connection, `BEGIN DEFERRED`) without the checkpoint.
#[test]
#[ignore = "benchmark: prints timings, asserts nothing"]
fn bench_snapshot_checkpoint_cost() {
    fn run(sync: i64, old_open: bool) -> (Duration, Duration) {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");
        let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
        ledger.set_synchronous_mode(sync).unwrap();
        let tracker = tracker_path_for_prefix(&prefix);
        let probe_addr = Address([7u8; 32]);
        let rounds = 300u64;
        let (mut commit_t, mut open_t) = (Duration::ZERO, Duration::ZERO);
        let mut keep: Option<Box<dyn std::any::Any>> = None;
        for round in 1..=rounds {
            let t = Instant::now();
            commit_round(&mut ledger, round);
            commit_t += t.elapsed();
            drop(keep.take());
            let t = Instant::now();
            if old_open {
                let c = Connection::open_with_flags(
                    &tracker,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )
                .unwrap();
                c.execute_batch("BEGIN DEFERRED").unwrap();
                open_t += t.elapsed();
                let _: i64 = c
                    .query_row("SELECT count(*) FROM acctrounds", [], |r| r.get(0))
                    .unwrap();
                keep = Some(Box::new(c));
            } else {
                let s = ledger.open_read_snapshot().unwrap();
                open_t += t.elapsed();
                let _ = s.get_account(&probe_addr);
                keep = Some(Box::new(s));
            }
        }
        (commit_t / rounds as u32, open_t / rounds as u32)
    }
    for sync in [2, 1] {
        let (c_old, o_old) = run(sync, true);
        let (c_new, o_new) = run(sync, false);
        println!(
            "synchronous={sync}: commit old={c_old:?} new={c_new:?}; \
             snapshot open (under the ledger lock) old={o_old:?} new={o_new:?}"
        );
    }
}
