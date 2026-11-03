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

// ---- kill / crash recovery ----------------------------------------------
//
// Issue #2209. A block commit touches two files: the block archive
// (`blockdb.blocks`) and the tracker. go-algorand commits the block to blockdb
// first and lets the trackers lag (`Ledger.AddValidatedBlock`: `blockQ.putBlock`
// then `trackers.newBlock`), so a crash leaves trackers <= blocks. SQLite
// commits a multi-database transaction tracker-first, so a block row written
// inside the span's transaction used to become durable AFTER the tracker
// commit. Inside a block span `put_block` / `put_block_cert` now only buffer,
// and `commit_block` commits the buffered rows to the block file before it
// commits the tracker transaction (DIV-009). These tests prove every crash
// point leaves a ledger that reopens and finishes with the state of an
// uninterrupted run, with the block file next to the tracker and in another
// directory.

const CHILD_ENV: &str = "WAL_KILL_CHILD_DIR";
const TARGET_ENV: &str = "WAL_KILL_CHILD_TARGET";
const FAILPOINT_ENV: &str = "WAL_KILL_FAILPOINT";
const LATE_PUT_ENV: &str = "WAL_KILL_LATE_PUT";
const PRUNE_ENV: &str = "WAL_KILL_PRUNE";
const SPLIT_ENV: &str = "WAL_KILL_SPLIT";

/// Where the block file of a ledger lives: next to the tracker, or (the
/// configured block DB directory) in a `cold` directory beside it.
fn split_dir(prefix: &Path) -> PathBuf {
    prefix.parent().unwrap().join("cold")
}

fn block_file(prefix: &Path) -> PathBuf {
    if split_dir(prefix).is_dir() {
        split_dir(prefix).join("ledger.block.sqlite")
    } else {
        algo_ledger::block_path_for_prefix(prefix)
    }
}

/// Open the ledger the way the node does: `open_split` with the tracker and
/// block file wherever `block_file` puts them.
fn open_ledger(prefix: &Path) -> Result<SqliteLedger, algo_error::AlgoError> {
    SqliteLedger::open_split(
        &tracker_path_for_prefix(prefix),
        &block_file(prefix),
        Some(prefix.to_path_buf()),
    )
}

fn test_header(round: u64) -> Vec<u8> {
    let hdr = algo_types::BlockHeader {
        round: Round(round),
        current_protocol: "test".to_string(),
        ..algo_types::BlockHeader::default()
    };
    rmp_serde::to_vec_named(&hdr).unwrap()
}

fn test_block(round: u64) -> Vec<u8> {
    format!("block body {round}").into_bytes()
}

fn test_cert(round: u64) -> Vec<u8> {
    format!("cert {round}").into_bytes()
}

/// One block the way the follower commits it: archive rows first inside the
/// span (`put_block`, `put_block_cert`), then the state change, then commit.
fn commit_block_round(ledger: &mut SqliteLedger, round: u64) {
    commit_block_round_ordered(ledger, round, true);
}

/// `archive_first = false` writes the state change BEFORE the block rows, the
/// order `apply_block` (sync, replay, catchup) uses: its own `put_block` runs
/// after tracker rows are already written in the span.
fn commit_block_round_ordered(ledger: &mut SqliteLedger, round: u64, archive_first: bool) {
    commit_block_round_full(ledger, round, archive_first, None);
}

/// `prune = Some(w)` also forgets the blocks below `round - w` inside the span
/// (`apply_block` does that per block when the archive is bounded).
fn commit_block_round_full(
    ledger: &mut SqliteLedger,
    round: u64,
    archive_first: bool,
    prune: Option<u64>,
) {
    let set_state = |ledger: &mut SqliteLedger| {
        ledger.set_account(
            &Address([7u8; 32]),
            algo_types::AccountData {
                micro_algos: round * 1000,
                ..Default::default()
            },
        );
    };
    ledger.begin_block().unwrap();
    if !archive_first {
        set_state(ledger);
    }
    ledger
        .put_block(round, "test", &test_header(round), &test_block(round))
        .unwrap();
    ledger.put_block_cert(round, &test_cert(round)).unwrap();
    if let Some(w) = prune {
        ledger.forget_before(round.saturating_sub(w)).unwrap();
    }
    if archive_first {
        set_state(ledger);
    }
    ledger.set_current_round(Round(round));
    ledger.commit_block().unwrap();
}

/// Child half of the crash tests: resume the ledger in `CHILD_ENV`, commit
/// blocks with a snapshot handover (checkpoint included) until killed (or until
/// `TARGET_ENV`), reporting each committed round on stdout AFTER its commit
/// returned. `WAL_KILL_FAILPOINT` (`name:after`) aborts it at a named commit
/// step (`SqliteLedger::set_failpoint`). Without the env var it is a no-op test.
#[test]
fn wal_kill_child() {
    let Ok(dir) = std::env::var(CHILD_ENV) else {
        return;
    };
    let target: u64 = std::env::var(TARGET_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(u64::MAX);
    let prefix = PathBuf::from(dir).join("ledger");
    if std::env::var(SPLIT_ENV).is_ok() {
        std::fs::create_dir_all(split_dir(&prefix)).unwrap();
    }
    let mut ledger = open_ledger(&prefix).unwrap();
    if let Ok(spec) = std::env::var(FAILPOINT_ENV) {
        let (name, after) = spec.split_once(':').unwrap();
        ledger.set_failpoint(name, after.parse().unwrap());
    }
    let archive_first = std::env::var(LATE_PUT_ENV).is_err();
    let prune = std::env::var(PRUNE_ENV).ok().and_then(|v| v.parse().ok());
    let probe_addr = Address([7u8; 32]);
    let mut round = ledger.last_committed_round().unwrap().unwrap_or(0);
    let mut snapshot = None;
    let stdout = std::io::stdout();
    while round < target {
        round += 1;
        commit_block_round_full(&mut ledger, round, archive_first, prune);
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

/// How a child process is started.
#[derive(Clone, Copy, Default)]
struct ChildOpts<'a> {
    target: Option<u64>,
    failpoint: Option<(&'a str, u64)>,
    late_put: bool,
    prune: Option<u64>,
    split: bool,
}

fn spawn_child(dir: &Path, o: ChildOpts) -> std::process::Child {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "--exact",
        "wal_kill_child",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(CHILD_ENV, dir)
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    if let Some(t) = o.target {
        cmd.env(TARGET_ENV, t.to_string());
    }
    if let Some((name, after)) = o.failpoint {
        cmd.env(FAILPOINT_ENV, format!("{name}:{after}"));
    }
    if o.late_put {
        cmd.env(LATE_PUT_ENV, "1");
    }
    if let Some(w) = o.prune {
        cmd.env(PRUNE_ENV, w.to_string());
    }
    if o.split {
        cmd.env(SPLIT_ENV, "1");
    }
    cmd.spawn().unwrap()
}

/// The highest round the child reported (its stdout is drained on a thread).
fn reported_rounds(child: &mut std::process::Child) -> std::thread::JoinHandle<u64> {
    let out = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        let mut last = 0u64;
        for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
            if let Some(n) = line.strip_prefix("R ") {
                last = n.parse().unwrap();
            }
        }
        last
    })
}

/// `(tracker round, highest block archive round)` read straight from the files.
fn raw_rounds(prefix: &Path) -> (i64, i64) {
    let t = Connection::open(tracker_path_for_prefix(prefix)).unwrap();
    let b = Connection::open(block_file(prefix)).unwrap();
    let acct = t
        .query_row("SELECT rnd FROM acctrounds WHERE id='acctbase'", [], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    let bmax = b
        .query_row("SELECT coalesce(max(rnd), 0) FROM blocks", [], |r| r.get(0))
        .unwrap();
    (acct, bmax)
}

/// What a clean reopen must satisfy after any crash: the ledger opens (never
/// refused), every round the child reported is committed, every committed round
/// from `from` on has its block and certificate, the tracker is never ahead of
/// the archive, and both files pass `PRAGMA integrity_check`.
fn assert_reopens_from(prefix: &Path, reported: u64, from: u64, what: &str) -> SqliteLedger {
    let (acct, bmax) = raw_rounds(prefix);
    assert!(
        acct <= bmax,
        "{what}: tracker round {acct} is ahead of the block archive {bmax}"
    );
    let ledger = open_ledger(prefix).unwrap_or_else(|e| {
        panic!("{what}: reopen refused: {e}; acctbase={acct} blocks max={bmax}")
    });
    let committed = ledger.last_committed_round().unwrap().unwrap_or(0);
    assert!(
        committed >= reported,
        "{what}: child reported round {reported} committed but the reopened ledger is at {committed}"
    );
    assert_eq!(ledger.current_round(), Round(committed), "{what}");
    for round in from.max(1)..=committed {
        assert_eq!(
            ledger.get_block_data(round).unwrap().as_deref(),
            Some(test_block(round).as_slice()),
            "{what}: committed round {round} lost its block"
        );
        assert_eq!(
            ledger.get_block_cert(round).unwrap().as_deref(),
            Some(test_cert(round).as_slice()),
            "{what}: committed round {round} lost its certificate"
        );
    }
    assert!(integrity_ok(&tracker_path_for_prefix(prefix)), "{what}");
    assert!(integrity_ok(&block_file(prefix)), "{what}");
    ledger
}

fn assert_reopens(prefix: &Path, reported: u64, what: &str) -> SqliteLedger {
    assert_reopens_from(prefix, reported, 1, what)
}

/// Balance, last committed round and every block with its certificate.
type StateDigest = (u64, Option<u64>, Vec<(Vec<u8>, Vec<u8>)>);

/// Committed state of a ledger, for equality against an uninterrupted run.
fn state_digest_from(ledger: &SqliteLedger, from: u64, last: u64) -> StateDigest {
    let balance = ledger
        .get_account(&Address([7u8; 32]))
        .map(|a| a.micro_algos)
        .unwrap();
    let blocks = (from.max(1)..=last)
        .map(|r| {
            (
                ledger.get_block_data(r).unwrap().unwrap(),
                ledger.get_block_cert(r).unwrap().unwrap(),
            )
        })
        .collect();
    (balance, ledger.last_committed_round().unwrap(), blocks)
}

fn state_digest(ledger: &SqliteLedger, last: u64) -> StateDigest {
    state_digest_from(ledger, 1, last)
}

fn reference_digest_pruned(last: u64, prune: Option<u64>) -> StateDigest {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = SqliteLedger::open_with_prefix(&dir.path().join("ledger")).unwrap();
    for round in 1..=last {
        commit_block_round_full(&mut ledger, round, true, prune);
    }
    state_digest_from(&ledger, prune.map_or(1, |w| last.saturating_sub(w)), last)
}

fn reference_digest(last: u64) -> StateDigest {
    reference_digest_pruned(last, None)
}

/// Run a child to the failpoint, check the crashed files, reopen, let the
/// follower finish to `last` and compare with the uninterrupted run.
fn crash_and_resume(
    point: &str,
    after: u64,
    o: ChildOpts,
    last: u64,
    reference: &StateDigest,
    what: &str,
) {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let o = ChildOpts {
        target: Some(last),
        failpoint: Some((point, after)),
        ..o
    };
    if o.split {
        std::fs::create_dir_all(split_dir(&prefix)).unwrap();
    }
    let mut child = spawn_child(dir.path(), o);
    let reader = reported_rounds(&mut child);
    let status = child.wait().unwrap();
    let reported = reader.join().unwrap();
    assert!(!status.success(), "{what}: the failpoint did not fire");

    // The block that crashed pruned below its own `round - w` too.
    let from = o.prune.map_or(1, |w| (reported + 1).saturating_sub(w));
    let (acct, bmax) = raw_rounds(&prefix);
    match point {
        // The archive is durable one block ahead of the tracker.
        "after_archive_commit" => assert_eq!(bmax, acct + 1, "{what}: acct {acct} blocks {bmax}"),
        _ => assert_eq!(acct, bmax, "{what}"),
    }
    drop(assert_reopens_from(&prefix, reported, from, what));

    // The follower resumes (re-commits whatever the crash left over).
    let mut resume = spawn_child(
        dir.path(),
        ChildOpts {
            failpoint: None,
            ..o
        },
    );
    let reader = reported_rounds(&mut resume);
    assert!(resume.wait().unwrap().success(), "{what}: resume failed");
    reader.join().unwrap();
    let from = o.prune.map_or(1, |w| last.saturating_sub(w));
    let ledger = assert_reopens_from(&prefix, last, from, &format!("{what}, after resume"));
    assert_eq!(state_digest_from(&ledger, from, last), *reference, "{what}");
}

/// Deterministic crash points. Each aborts the committing process (no cleanup)
/// at a named step of the Nth block commit; the reopened ledger must hold every
/// reported round, never have the tracker ahead of the archive, and after the
/// follower resumes, finish with exactly the state of an uninterrupted run.
/// Run for both write orders (the block rows first, as the follower does, and
/// AFTER the state change, as `apply_block` does for sync, replay and catchup:
/// the archive ordering lives in `commit_block`, not in the caller) and with
/// the block file next to the tracker and in another directory.
#[test]
fn every_commit_step_crash_reopens_and_resumes_to_the_uninterrupted_state() {
    if std::env::var(CHILD_ENV).is_ok() {
        return;
    }
    const FINAL: u64 = 30;
    let reference = reference_digest(FINAL);
    // before_archive_commit: nothing of the block is durable. after_archive_commit:
    // the block row is durable, the tracker has not committed (the window of
    // #2209, now archive-ahead). after_tracker_commit: all done.
    for split in [false, true] {
        for late_put in [false, true] {
            for point in [
                "before_archive_commit",
                "after_archive_commit",
                "after_tracker_commit",
            ] {
                for after in [0u64, 1, 2, 7, 11] {
                    let what = format!(
                        "failpoint {point} after {after} (late put: {late_put}, split dirs: {split})"
                    );
                    let o = ChildOpts {
                        late_put,
                        split,
                        ..Default::default()
                    };
                    crash_and_resume(point, after, o, FINAL, &reference, &what);
                }
            }
        }
    }
}

/// A crash between the archive commit (which also pruned old blocks) and the
/// tracker commit (which has not yet pruned its own tail) reopens and goes on:
/// the archive is only ever pruned BELOW rounds the tracker has long
/// committed, so nothing the tracker or the lookback still needs is gone.
#[test]
fn crash_after_an_archive_commit_that_pruned_reopens_and_continues() {
    if std::env::var(CHILD_ENV).is_ok() {
        return;
    }
    const FINAL: u64 = 30;
    const WINDOW: u64 = 5;
    let reference = reference_digest_pruned(FINAL, Some(WINDOW));
    for point in ["after_archive_commit", "after_tracker_commit"] {
        for after in [8u64, 9, 15] {
            let what = format!("pruned failpoint {point} after {after}");
            let o = ChildOpts {
                prune: Some(WINDOW),
                ..Default::default()
            };
            crash_and_resume(point, after, o, FINAL, &reference, &what);
        }
    }
}

/// What another connection (a crash-recovery view of the file) sees.
fn archived(prefix: &Path, round: u64) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let c = Connection::open(block_file(prefix)).unwrap();
    c.query_row(
        "SELECT blkdata, certdata FROM blocks WHERE rnd = ?1",
        [round as i64],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .unwrap_or((None, None))
}

/// A block that does not commit changes nothing in the block archive: its
/// buffered rows are dropped, and a row (and certificate) that already
/// existed -- a block written ahead by sync -- is untouched, not overwritten.
#[test]
fn rolled_back_block_leaves_the_archive_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    commit_block_round(&mut ledger, 1);

    // A new round: nothing reaches the file, in the span or after the abort.
    ledger.begin_block().unwrap();
    ledger
        .put_block(2, "test", &test_header(2), &test_block(2))
        .unwrap();
    ledger.put_block_cert(2, &test_cert(2)).unwrap();
    assert_eq!(
        ledger.get_block_data(2).unwrap().as_deref(),
        Some(test_block(2).as_slice()),
        "the span reads its own buffered block"
    );
    assert_eq!(
        archived(&prefix, 2),
        (None, None),
        "not archived before commit"
    );
    ledger.rollback_block().unwrap();
    assert!(ledger.get_block_data(2).unwrap().is_none());
    assert_eq!(archived(&prefix, 2), (None, None));
    assert_eq!(ledger.last_committed_round().unwrap(), Some(1));

    // A pre-existing row and certificate (sync wrote them ahead) are untouched
    // by an aborted re-commit with different bytes.
    ledger
        .put_block(2, "test", &test_header(2), &test_block(2))
        .unwrap();
    ledger.put_block_cert(2, &test_cert(2)).unwrap();
    ledger.begin_block().unwrap();
    ledger
        .put_block(2, "test", &test_header(2), b"other body")
        .unwrap();
    ledger.put_block_cert(2, b"other cert").unwrap();
    ledger.rollback_block().unwrap();
    assert_eq!(
        archived(&prefix, 2),
        (Some(test_block(2)), Some(test_cert(2))),
        "an aborted block must not overwrite an archived row"
    );
    // A cert-only update of an archived row is aborted just the same.
    ledger.begin_block().unwrap();
    ledger.put_block_cert(2, b"other cert").unwrap();
    ledger.rollback_block().unwrap();
    assert_eq!(archived(&prefix, 2).1, Some(test_cert(2)));

    // And the ledger carries on: the row written ahead is committed over.
    commit_block_round(&mut ledger, 2);
    assert_eq!(ledger.last_committed_round().unwrap(), Some(2));
    assert_eq!(
        archived(&prefix, 2),
        (Some(test_block(2)), Some(test_cert(2)))
    );
}

/// A block whose round the sync path already wrote ahead of the tracker (row
/// and certificate in the archive, tracker behind) commits over it.
#[test]
fn a_block_written_ahead_by_sync_is_committed_over() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    commit_block_round(&mut ledger, 1);
    ledger
        .put_block(2, "test", &test_header(2), &test_block(2))
        .unwrap();
    ledger.put_block_cert(2, &test_cert(2)).unwrap();
    assert_eq!(raw_rounds(&prefix), (1, 2));
    drop(ledger);
    let mut ledger = assert_reopens(&prefix, 1, "written ahead");
    commit_block_round_ordered(&mut ledger, 2, false);
    commit_block_round(&mut ledger, 3);
    assert_eq!(state_digest(&ledger, 3), reference_digest(3));
}

/// A savepoint (`snapshot` / `restore_snapshot`, as group rollback uses) open
/// inside a block span survives the commit: the archive write must not end
/// the span's transaction.
#[test]
fn savepoint_inside_a_block_span_commits() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    commit_block_round(&mut ledger, 1);
    ledger.begin_block().unwrap();
    ledger
        .put_block(2, "test", &test_header(2), &test_block(2))
        .unwrap();
    let snap = ledger.snapshot(&[Address([7u8; 32])]);
    ledger.set_account(
        &Address([7u8; 32]),
        algo_types::AccountData {
            micro_algos: 1,
            ..Default::default()
        },
    );
    ledger.restore_snapshot(snap); // a rolled-back group
    ledger.put_block_cert(2, &test_cert(2)).unwrap();
    let snap = ledger.snapshot(&[Address([7u8; 32])]);
    ledger.set_account(
        &Address([7u8; 32]),
        algo_types::AccountData {
            micro_algos: 2000,
            ..Default::default()
        },
    );
    ledger.set_current_round(Round(2));
    drop(snap); // a group that kept its changes
    ledger.commit_block().unwrap();
    assert_eq!(state_digest(&ledger, 2), reference_digest(2));
    drop(assert_reopens(&prefix, 2, "savepoint span"));
}

/// The block file lives wherever it is attached, not next to the tracker (the
/// block DB directory is configurable): the commit must write THAT file, read
/// back through the ledger and the read pool, create no stray file next to the
/// tracker, and reopen.
#[test]
fn blocks_are_committed_to_the_attached_file_when_it_is_in_another_directory() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    std::fs::create_dir_all(split_dir(&prefix)).unwrap();
    let attached = block_file(&prefix);
    assert_ne!(attached, algo_ledger::block_path_for_prefix(&prefix));
    let mut ledger = open_ledger(&prefix).unwrap();
    let pool = ledger.read_pool().unwrap();
    for round in 1..=5 {
        commit_block_round(&mut ledger, round);
    }
    for round in 1..=5 {
        assert_eq!(
            archived(&prefix, round),
            (Some(test_block(round)), Some(test_cert(round))),
            "round {round} is in the attached file"
        );
        assert_eq!(
            ledger.get_block_data(round).unwrap().as_deref(),
            Some(test_block(round).as_slice())
        );
        assert_eq!(
            pool.block_data(round),
            algo_ledger::read_pool::PoolRead::Found(test_block(round))
        );
    }
    assert!(
        !algo_ledger::block_path_for_prefix(&prefix).exists(),
        "a stray <prefix>.block.sqlite appeared next to the tracker"
    );
    drop(ledger);
    drop(assert_reopens(&prefix, 5, "split dirs"));
}

/// The tracker COMMIT fails after the block archive was committed (disk full,
/// SQLITE_BUSY): the block was never applied, so readers must not see it, the
/// archive row the block created is removed again, and the follower's retry of
/// the same round commits. If removing the row fails too, the row stays hidden
/// from the read pool and is removed by the next `begin_block`; a crash with the
/// row still there is the ordinary archive-ahead state.
#[test]
fn a_failed_tracker_commit_does_not_expose_the_block() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    let pool = ledger.read_pool().unwrap();
    commit_block_round(&mut ledger, 1);

    let failing_commit = |ledger: &mut SqliteLedger| {
        ledger.begin_block().unwrap();
        ledger
            .put_block(2, "test", &test_header(2), &test_block(2))
            .unwrap();
        ledger.put_block_cert(2, &test_cert(2)).unwrap();
        ledger.set_current_round(Round(2));
        assert!(ledger.commit_block().is_err());
    };

    // The delete works: the created row is gone, nothing is visible anywhere.
    ledger.inject_tracker_commit_failures(1);
    failing_commit(&mut ledger);
    assert_eq!(archived(&prefix, 2), (None, None));
    assert_eq!(
        pool.block_data(2),
        algo_ledger::read_pool::PoolRead::NotFound
    );
    assert_eq!(ledger.last_committed_round().unwrap(), Some(1));
    commit_block_round(&mut ledger, 2);
    assert_eq!(
        pool.block_data(2),
        algo_ledger::read_pool::PoolRead::Found(test_block(2))
    );

    // The delete fails too: the row is on disk but hidden from the pool.
    ledger.inject_tracker_commit_failures(1);
    ledger.inject_orphan_delete_failures(1);
    ledger.begin_block().unwrap();
    ledger
        .put_block(3, "test", &test_header(3), &test_block(3))
        .unwrap();
    ledger.set_current_round(Round(3));
    assert!(ledger.commit_block().is_err());
    assert_eq!(
        archived(&prefix, 3).0,
        Some(test_block(3)),
        "orphan on disk"
    );
    assert_eq!(
        pool.block_data(3),
        algo_ledger::read_pool::PoolRead::NotFound
    );
    // The next begin_block reconciles it.
    ledger.begin_block().unwrap();
    ledger.rollback_block().unwrap();
    assert_eq!(archived(&prefix, 3), (None, None));
    assert_eq!(
        pool.block_data(3),
        algo_ledger::read_pool::PoolRead::NotFound
    );
    commit_block_round(&mut ledger, 3);
    assert_eq!(
        pool.block_data(3),
        algo_ledger::read_pool::PoolRead::Found(test_block(3))
    );

    // A crash with the orphan still on disk is the archive-ahead state.
    ledger.inject_tracker_commit_failures(1);
    ledger.inject_orphan_delete_failures(10);
    ledger.begin_block().unwrap();
    ledger
        .put_block(4, "test", &test_header(4), &test_block(4))
        .unwrap();
    ledger.set_current_round(Round(4));
    assert!(ledger.commit_block().is_err());
    assert_eq!(archived(&prefix, 4).0, Some(test_block(4)));
    drop(ledger);
    let mut ledger = assert_reopens(&prefix, 3, "orphan row left on disk");
    commit_block_round(&mut ledger, 4);
    assert_eq!(state_digest(&ledger, 4), reference_digest(4));
}

/// `forget_before` keeps its place among the block writes of a span: pruning
/// below M and then storing a round below M keeps that round, storing it first
/// and pruning after removes it (what the immediate statements did).
#[test]
fn forget_before_keeps_its_order_among_the_buffered_writes() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    for round in 1..=10 {
        commit_block_round(&mut ledger, round);
    }
    ledger.begin_block().unwrap();
    ledger.forget_before(8).unwrap();
    assert!(
        ledger.get_block_data(3).unwrap().is_none(),
        "the span sees the prune"
    );
    ledger
        .put_block(5, "test", &test_header(5), &test_block(5))
        .unwrap();
    ledger
        .put_block(6, "test", &test_header(6), &test_block(6))
        .unwrap();
    ledger.forget_before(6).unwrap(); // removes nothing but 5: 6 is not below 6
    assert!(ledger.get_block_data(5).unwrap().is_none());
    assert!(ledger.get_block_data(6).unwrap().is_some());
    ledger.set_current_round(Round(10));
    ledger.commit_block().unwrap();
    for round in 1..=10 {
        let present = archived(&prefix, round).0.is_some();
        // prune(8) -> only 8..10 remain; put 5 and 6; prune(6) -> 5 goes.
        assert_eq!(present, round >= 8 || round == 6, "round {round}");
    }
}

/// Kill a ledger process (hard kill, no cleanup) at pseudo-random points while
/// it commits blocks with snapshot handovers -- kills land in archive commits,
/// tracker commits, the window between them and the snapshot-time checkpoint --
/// and after every kill reopen the same directory: it must open (no tolerated
/// "split window"), every reported round is present, the tracker is never ahead
/// of the archive, both files pass `PRAGMA integrity_check`. The children keep
/// resuming the SAME ledger, and at the end its state equals an uninterrupted
/// run over the same rounds. `WAL_KILL_COUNT` raises the kill count.
fn randomized_kills(split: bool) {
    let kills: u32 = std::env::var("WAL_KILL_COUNT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    if split {
        std::fs::create_dir_all(split_dir(&prefix)).unwrap();
    }
    let mut seed = 0x2209_u64;
    let (mut ahead, mut total_progress) = (0u32, 0u64);
    let mut reported_max = 0u64;
    for kill in 0..kills {
        let what = format!("kill {kill} (split dirs: {split})");
        let before = if tracker_path_for_prefix(&prefix).exists() {
            raw_rounds(&prefix).0 as u64
        } else {
            0
        };
        let mut child = spawn_child(
            dir.path(),
            ChildOpts {
                late_put: kill % 2 == 1,
                split,
                ..Default::default()
            },
        );
        let reader = reported_rounds(&mut child);
        // xorshift: 250..750 ms of child life (open + a few dozen rounds).
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        std::thread::sleep(Duration::from_millis(250 + seed % 500));
        child.kill().unwrap();
        child.wait().unwrap();
        let reported = reader.join().unwrap();
        reported_max = reported_max.max(reported);
        total_progress += reported.saturating_sub(before);

        let (acct, bmax) = raw_rounds(&prefix);
        if bmax > acct {
            ahead += 1; // killed between the archive commit and the tracker commit
        }
        drop(assert_reopens(&prefix, reported, &what));
    }
    assert!(
        total_progress > 100,
        "too little progress to prove anything: {total_progress}"
    );
    // Finish on the same ledger and compare with an uninterrupted run.
    let mut ledger = assert_reopens(&prefix, 0, "final");
    let committed = ledger.last_committed_round().unwrap().unwrap();
    assert!(
        committed >= reported_max,
        "reported {reported_max} committed {committed}"
    );
    let last = committed + 3;
    for round in committed + 1..=last {
        commit_block_round(&mut ledger, round);
    }
    assert_eq!(state_digest(&ledger, last), reference_digest(last));
    println!(
        "{kills} kills (split dirs: {split}): {ahead} landed with the archive one block ahead of the tracker, {total_progress} reported commits, final round {last}"
    );
}

#[test]
fn kill_mid_commit_recovers_every_reported_round() {
    if std::env::var(CHILD_ENV).is_ok() {
        return;
    }
    randomized_kills(false);
}

/// The same with the block file in another directory than the tracker.
#[test]
fn kill_mid_commit_recovers_every_reported_round_with_split_dirs() {
    if std::env::var(CHILD_ENV).is_ok() {
        return;
    }
    randomized_kills(true);
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

/// Per-block commit cost (`begin_block` .. `commit_block`, including the block
/// and certificate writes) of the deferred archive commit (DIV-009). Run the
/// same test on the previous commit for the baseline: `cargo test -p algo-ledger
/// --release --test wal_overlapping_reader_test -- --ignored --nocapture
/// bench_block_commit`.
#[test]
#[ignore = "benchmark: prints timings, asserts nothing"]
fn bench_block_commit_archive_first() {
    fn run(sync: i64) -> Duration {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = SqliteLedger::open_with_prefix(&dir.path().join("ledger")).unwrap();
        ledger.set_synchronous_mode(sync).unwrap();
        let rounds = 400u64;
        let blk = vec![0xAB; 60_000]; // a betanet-sized block body
        let mut total = Duration::ZERO;
        for round in 1..=rounds {
            let t = Instant::now();
            ledger.begin_block().unwrap();
            ledger
                .put_block(round, "test", &test_header(round), &blk)
                .unwrap();
            ledger.put_block_cert(round, &test_cert(round)).unwrap();
            ledger.set_account(
                &Address([7u8; 32]),
                algo_types::AccountData {
                    micro_algos: round * 1000,
                    ..Default::default()
                },
            );
            ledger.set_current_round(Round(round));
            ledger.commit_block().unwrap();
            total += t.elapsed();
        }
        total / rounds as u32
    }
    for sync in [2, 1] {
        for _ in 0..3 {
            println!("synchronous={sync}: block commit {:?}", run(sync));
        }
    }
}
