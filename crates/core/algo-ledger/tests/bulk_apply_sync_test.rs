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

//! Bulk apply: the tracker runs at `synchronous=NORMAL` while a catchup pass
//! is applying many blocks in a row (issue #2315, DIV-011).
//!
//! Every block commit costs two `fsync`s at the configured `FULL`: the block
//! archive and the tracker. Replaying 2,000 blocks made 4,168 of them, go-algorand
//! 584, and the replay spent about 4 s of 5.3 s waiting for them. In bulk mode
//! the archive keeps `FULL` and the tracker drops to `NORMAL` (WAL: no `fsync`
//! per commit). That keeps the DIV-009 order: the archive commit of a block is
//! durable before the tracker commit that depends on it is issued, so a power
//! loss can only leave the tracker BEHIND the archive, the state a crash
//! between the two commits already produced. These tests pin the settings and
//! prove that a tracker lagging by any number of blocks reopens and finishes
//! with the state of an uninterrupted run.

use std::path::Path;

use algo_ledger::{
    block_path_for_prefix, tracker_path_for_prefix, CrossFileState, LedgerStore as _, SqliteLedger,
};
use algo_types::{Address, Round};
use rusqlite::Connection;

fn test_header(round: u64) -> Vec<u8> {
    let hdr = algo_types::BlockHeader {
        round: Round(round),
        current_protocol: "test".to_string(),
        ..algo_types::BlockHeader::default()
    };
    rmp_serde::to_vec_named(&hdr).unwrap()
}

/// One block the way `apply_block` commits it: state change, then the block
/// rows, then commit.
fn commit_block_round(ledger: &mut SqliteLedger, round: u64) {
    ledger.begin_block().unwrap();
    ledger.set_account(
        &Address([7u8; 32]),
        algo_types::AccountData {
            micro_algos: round * 1000,
            ..Default::default()
        },
    );
    ledger
        .put_block(
            round,
            "test",
            &test_header(round),
            format!("block body {round}").as_bytes(),
        )
        .unwrap();
    ledger
        .put_block_cert(round, format!("cert {round}").as_bytes())
        .unwrap();
    ledger.set_current_round(Round(round));
    ledger.commit_block().unwrap();
}

/// Balance, last committed round and every block with its certificate.
type StateDigest = (u64, Option<u64>, Vec<(Vec<u8>, Vec<u8>)>);

fn state_digest(ledger: &SqliteLedger, last: u64) -> StateDigest {
    let balance = ledger
        .get_account(&Address([7u8; 32]))
        .map(|a| a.micro_algos)
        .unwrap();
    let blocks = (1..=last)
        .map(|r| {
            (
                ledger.get_block_data(r).unwrap().unwrap(),
                ledger.get_block_cert(r).unwrap().unwrap(),
            )
        })
        .collect();
    (balance, ledger.last_committed_round().unwrap(), blocks)
}

fn reference_digest(last: u64) -> StateDigest {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = SqliteLedger::open_with_prefix(&dir.path().join("ledger")).unwrap();
    for round in 1..=last {
        commit_block_round(&mut ledger, round);
    }
    state_digest(&ledger, last)
}

/// `file` and its `-wal` (if any) copied to `to_dir`, without the `-shm`.
fn copy_with_wal(file: &Path, to: &Path) {
    std::fs::copy(file, to).unwrap();
    let mut wal_from = file.as_os_str().to_owned();
    wal_from.push("-wal");
    let mut wal_to = to.as_os_str().to_owned();
    wal_to.push("-wal");
    if Path::new(&wal_from).exists() {
        std::fs::copy(&wal_from, &wal_to).unwrap();
    }
}

fn remove_with_sidecars(file: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut p = file.as_os_str().to_owned();
        p.push(suffix);
        let _ = std::fs::remove_file(Path::new(&p));
    }
}

#[test]
fn bulk_apply_runs_the_tracker_at_normal_and_leaves_the_archive_at_full() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = SqliteLedger::open_with_prefix(&dir.path().join("ledger")).unwrap();
    ledger.set_synchronous_mode(2).unwrap();
    assert_eq!(ledger.tracker_synchronous_mode().unwrap(), 2);
    assert_eq!(ledger.archive_synchronous_mode(), 2);

    ledger.set_bulk_apply(true).unwrap();
    assert_eq!(ledger.tracker_synchronous_mode().unwrap(), 1, "NORMAL");
    assert_eq!(
        ledger.archive_synchronous_mode(),
        2,
        "the archive must stay durable before the tracker commit is issued"
    );

    // A configuration change while bulk is on keeps the tracker lowered.
    ledger.set_synchronous_mode(3).unwrap();
    assert_eq!(ledger.tracker_synchronous_mode().unwrap(), 1);
    assert_eq!(ledger.archive_synchronous_mode(), 3);

    ledger.set_bulk_apply(false).unwrap();
    assert_eq!(ledger.tracker_synchronous_mode().unwrap(), 3, "restored");
}

#[test]
fn bulk_apply_never_raises_a_configured_lower_mode() {
    for configured in [0, 1] {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = SqliteLedger::open_with_prefix(&dir.path().join("ledger")).unwrap();
        ledger.set_synchronous_mode(configured).unwrap();
        ledger.set_bulk_apply(true).unwrap();
        assert_eq!(ledger.tracker_synchronous_mode().unwrap(), configured);
        ledger.set_bulk_apply(false).unwrap();
        assert_eq!(ledger.tracker_synchronous_mode().unwrap(), configured);
    }
}

#[test]
fn bulk_apply_is_idempotent_and_blocks_commit_in_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = SqliteLedger::open_with_prefix(&dir.path().join("ledger")).unwrap();
    ledger.set_bulk_apply(true).unwrap();
    ledger.set_bulk_apply(true).unwrap();
    for round in 1..=20 {
        commit_block_round(&mut ledger, round);
    }
    ledger.set_bulk_apply(false).unwrap();
    ledger.set_bulk_apply(false).unwrap();
    assert_eq!(state_digest(&ledger, 20), reference_digest(20));
}

/// What a power loss leaves when the tracker's unsynced tail is lost: the
/// tracker at round `last - k`, the (synced) archive at `last`.
#[test]
fn a_tracker_lagging_the_archive_by_k_blocks_reopens_and_resumes() {
    let last = 60u64;
    let reference = reference_digest(last);
    for k in [1u64, 2, 7, 40, 59] {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");
        let tracker = tracker_path_for_prefix(&prefix);
        let saved = tempfile::tempdir().unwrap();
        let saved_tracker = saved.path().join("tracker.sqlite");

        let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
        ledger.set_bulk_apply(true).unwrap();
        for round in 1..=last {
            commit_block_round(&mut ledger, round);
            if round == last - k {
                copy_with_wal(&tracker, &saved_tracker);
            }
        }
        drop(ledger);

        // The tracker as it was `k` blocks ago, the archive as it is now.
        remove_with_sidecars(&tracker);
        copy_with_wal(&saved_tracker, &tracker);
        assert!(block_path_for_prefix(&prefix).exists());

        let mut ledger = SqliteLedger::open_with_prefix(&prefix)
            .unwrap_or_else(|e| panic!("k={k}: a lagging tracker must reopen, got {e}"));
        assert_eq!(
            ledger.last_committed_round().unwrap(),
            Some(last - k),
            "k={k}"
        );
        assert_eq!(ledger.current_round(), Round(last - k), "k={k}");

        // The precondition the whole argument rests on: the archive covers
        // every committed round, a consistent state. (With staging, DIV-011,
        // the block file may hold fewer than `last` rounds: the rest was
        // staged in the newer tracker the power loss took away.)
        let max = ledger.max_block_round_in_blockdb().unwrap().unwrap_or(0);
        assert!(
            max >= last - k,
            "k={k}: archive {max} behind the tracker {}",
            last - k
        );
        assert!(
            matches!(
                ledger.reconcile_cross_file().unwrap(),
                CrossFileState::Consistent { round } if round == last - k
            ),
            "k={k}: {:?}",
            ledger.reconcile_cross_file().unwrap()
        );

        // The catchup loop re-applies the rounds the tracker lost: their
        // blocks are already archived (`put_block` replaces the row).
        for round in (last - k + 1)..=last {
            commit_block_round(&mut ledger, round);
        }
        assert_eq!(state_digest(&ledger, last), reference, "k={k}");
    }
}

/// A WAL torn at an arbitrary byte (the unsynced tail of a power loss may be
/// partly written): the tracker reopens consistent at SOME earlier round, the
/// archive is untouched, and re-applying the lost rounds ends on the state of
/// an uninterrupted run.
#[test]
fn a_tracker_wal_torn_at_any_byte_reopens_at_an_earlier_round_and_resumes() {
    let last = 80u64;
    let reference = reference_digest(last);
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let tracker = tracker_path_for_prefix(&prefix);
    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    ledger.set_bulk_apply(true).unwrap();
    for round in 1..=last {
        commit_block_round(&mut ledger, round);
    }
    let mut wal = tracker.as_os_str().to_owned();
    wal.push("-wal");
    let wal = std::path::PathBuf::from(wal);
    let wal_bytes = std::fs::read(&wal).unwrap();
    assert!(
        wal_bytes.len() > 100_000,
        "the scenario needs a long live WAL"
    );
    let main_bytes = std::fs::read(&tracker).unwrap();
    let block_file = block_path_for_prefix(&prefix);
    let block_bytes = std::fs::read(&block_file).unwrap();
    let mut block_wal = block_file.as_os_str().to_owned();
    block_wal.push("-wal");
    let block_wal_bytes = std::fs::read(std::path::PathBuf::from(&block_wal)).ok();
    drop(ledger);

    let mut earlier = 0;
    for cut in (0..=16).map(|i| wal_bytes.len() * i / 16 + usize::from(i % 2 == 1) * 13) {
        let cut = cut.min(wal_bytes.len());
        let crashed = tempfile::tempdir().unwrap();
        let crashed_prefix = crashed.path().join("ledger");
        let crashed_tracker = tracker_path_for_prefix(&crashed_prefix);
        let crashed_block = block_path_for_prefix(&crashed_prefix);
        std::fs::write(&crashed_tracker, &main_bytes).unwrap();
        let mut w = crashed_tracker.as_os_str().to_owned();
        w.push("-wal");
        std::fs::write(std::path::PathBuf::from(w), &wal_bytes[..cut]).unwrap();
        // The archive is durable: all of it.
        std::fs::write(&crashed_block, &block_bytes).unwrap();
        if let Some(b) = &block_wal_bytes {
            let mut w = crashed_block.as_os_str().to_owned();
            w.push("-wal");
            std::fs::write(std::path::PathBuf::from(w), b).unwrap();
        }

        let mut ledger = SqliteLedger::open_with_prefix(&crashed_prefix)
            .unwrap_or_else(|e| panic!("cut={cut}: a torn tracker WAL must reopen, got {e}"));
        let committed = ledger.last_committed_round().unwrap().unwrap_or(0);
        assert!(committed <= last, "cut={cut}");
        assert_eq!(ledger.current_round(), Round(committed), "cut={cut}");
        let max = ledger.max_block_round_in_blockdb().unwrap().unwrap_or(0);
        assert!(
            max >= committed,
            "cut={cut}: archive {max} behind the tracker {committed}"
        );
        if committed < last {
            earlier += 1;
        }
        for round in (committed + 1)..=last {
            commit_block_round(&mut ledger, round);
        }
        assert_eq!(state_digest(&ledger, last), reference, "cut={cut}");
    }
    assert!(
        earlier > 4,
        "most cuts must lose rounds ({earlier} of 17 did)"
    );
}

/// A change of the bulk flag made while a block span is open (pragmas are
/// ignored in a transaction) is applied at the next block boundary instead of
/// being lost: the tracker must not stay at `NORMAL` after bulk mode ended.
#[test]
fn a_bulk_flag_flipped_inside_a_span_is_applied_after_the_span() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = SqliteLedger::open_with_prefix(&dir.path().join("ledger")).unwrap();
    ledger.set_bulk_apply(true).unwrap();
    assert_eq!(ledger.tracker_synchronous_mode().unwrap(), 1);

    // Off, with a span open (a failed ROLLBACK can keep one open).
    ledger.begin_block().unwrap();
    ledger.set_bulk_apply(false).unwrap();
    assert_eq!(
        ledger.tracker_synchronous_mode().unwrap(),
        1,
        "the pragma cannot change inside the transaction"
    );
    ledger.set_current_round(Round(1));
    ledger.commit_block().unwrap();
    assert_eq!(
        ledger.tracker_synchronous_mode().unwrap(),
        2,
        "restored as soon as the span is closed"
    );

    // On, inside a span: applied at the next block boundary too.
    ledger.begin_block().unwrap();
    ledger.set_bulk_apply(true).unwrap();
    ledger.set_current_round(Round(2));
    ledger.commit_block().unwrap();
    assert_eq!(ledger.tracker_synchronous_mode().unwrap(), 1);
}

// ---- staged block archive (DIV-011, issue #2315 step 2) --------------------
//
// During a bulk apply a block's archive rows are written to a staging table in
// the TRACKER, in the block's own tracker transaction, and moved to the block
// file in one transaction every `STAGE_MAX_BLOCKS` (64) blocks and when the
// bulk apply ends. The tracker therefore never commits a round whose block is
// in neither file, and the block file costs one `fsync` per 64 blocks instead
// of one per block.

/// Rows the block FILE holds (another connection, as any outside reader).
fn file_rounds(prefix: &Path) -> Vec<i64> {
    let c = Connection::open(block_path_for_prefix(prefix)).unwrap();
    let mut st = c.prepare("SELECT rnd FROM blocks ORDER BY rnd").unwrap();
    st.query_map([], |r| r.get(0))
        .unwrap()
        .map(|x| x.unwrap())
        .collect()
}

/// Rows staged in the TRACKER file.
fn staged_rows(prefix: &Path) -> i64 {
    let c = Connection::open(tracker_path_for_prefix(prefix)).unwrap();
    c.query_row("SELECT count(*) FROM algod_rust_staged_archive", [], |r| {
        r.get(0)
    })
    .unwrap()
}

#[test]
fn bulk_apply_stages_blocks_and_moves_them_in_batches() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    ledger.set_bulk_apply(true).unwrap();
    for round in 1..=150u64 {
        commit_block_round(&mut ledger, round);
        // Every committed block is readable through the ledger at all times,
        // staged or moved.
        assert_eq!(
            ledger.get_block_data(round).unwrap(),
            Some(format!("block body {round}").into_bytes()),
            "round {round}"
        );
        assert_eq!(
            ledger.get_block_cert(round).unwrap(),
            Some(format!("cert {round}").into_bytes()),
            "round {round}"
        );
    }
    // Moved at 64 and 128: the block file has exactly those, the rest is
    // staged (a block row and a certificate per round).
    assert_eq!(file_rounds(&prefix), (1..=128).collect::<Vec<i64>>());
    assert_eq!(staged_rows(&prefix), 2 * 22);
    for round in 1..=150u64 {
        assert!(
            ledger.get_block_data(round).unwrap().is_some(),
            "round {round}"
        );
    }

    // The end of the bulk apply moves the rest.
    ledger.set_bulk_apply(false).unwrap();
    assert_eq!(file_rounds(&prefix), (1..=150).collect::<Vec<i64>>());
    assert_eq!(staged_rows(&prefix), 0);
    assert_eq!(state_digest(&ledger, 150), reference_digest(150));
}

/// A process that stops (or crashes) with blocks staged: the next open moves
/// them to the block file before anything reads it.
#[test]
fn staged_blocks_left_behind_are_moved_at_the_next_open() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    ledger.set_bulk_apply(true).unwrap();
    for round in 1..=100u64 {
        commit_block_round(&mut ledger, round);
    }
    drop(ledger); // no set_bulk_apply(false): rounds 65..=100 stay staged
    assert_eq!(file_rounds(&prefix).last(), Some(&64));
    assert!(staged_rows(&prefix) > 0);

    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    assert_eq!(file_rounds(&prefix), (1..=100).collect::<Vec<i64>>());
    assert_eq!(staged_rows(&prefix), 0);
    assert!(matches!(
        ledger.reconcile_cross_file().unwrap(),
        CrossFileState::Consistent { round: 100 }
    ));
    for round in 101..=120 {
        commit_block_round(&mut ledger, round);
    }
    assert_eq!(state_digest(&ledger, 120), reference_digest(120));
}

/// Power loss during a bulk apply: the tracker as it was at round `t` (its
/// staged rows included, they are in the same file and transaction), the
/// block file as it was at round `a`, earlier OR later than `t`. Whatever the
/// combination, the ledger reopens consistent and resumes to the state of an
/// uninterrupted run.
#[test]
fn a_power_loss_during_staging_never_leaves_the_tracker_ahead_of_its_blocks() {
    let last = 200u64;
    let reference = reference_digest(last);
    // (tracker snapshot round, block file snapshot round)
    for (t, a) in [
        (100u64, 64u64),
        (127, 64),
        (128, 128),
        (140, 128),
        (90, 128),
        (63, 0),
        (150, 192),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("ledger");
        let tracker = tracker_path_for_prefix(&prefix);
        let block = block_path_for_prefix(&prefix);
        let saved = tempfile::tempdir().unwrap();
        let saved_tracker = saved.path().join("tracker.sqlite");
        let saved_block = saved.path().join("block.sqlite");

        let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
        ledger.set_bulk_apply(true).unwrap();
        if a == 0 {
            copy_with_wal(&block, &saved_block);
        }
        for round in 1..=last {
            commit_block_round(&mut ledger, round);
            if round == t {
                copy_with_wal(&tracker, &saved_tracker);
            }
            if round == a {
                copy_with_wal(&block, &saved_block);
            }
        }
        drop(ledger);
        remove_with_sidecars(&tracker);
        remove_with_sidecars(&block);
        copy_with_wal(&saved_tracker, &tracker);
        copy_with_wal(&saved_block, &block);

        let mut ledger = SqliteLedger::open_with_prefix(&prefix)
            .unwrap_or_else(|e| panic!("t={t} a={a}: reopen refused: {e}"));
        assert_eq!(
            ledger.last_committed_round().unwrap(),
            Some(t),
            "t={t} a={a}"
        );
        let max = ledger.max_block_round_in_blockdb().unwrap().unwrap_or(0);
        assert!(
            max >= t,
            "t={t} a={a}: tracker {t} ahead of its blocks {max}"
        );
        assert!(
            matches!(
                ledger.reconcile_cross_file().unwrap(),
                CrossFileState::Consistent { .. }
            ),
            "t={t} a={a}"
        );
        for round in 1..=t {
            assert!(
                ledger.get_block_data(round).unwrap().is_some(),
                "t={t} a={a}: round {round}"
            );
        }
        for round in (t + 1)..=last {
            commit_block_round(&mut ledger, round);
        }
        assert_eq!(state_digest(&ledger, last), reference, "t={t} a={a}");
    }
}

/// Outside a bulk apply nothing is staged: the DIV-009 path, one archive
/// commit per block.
#[test]
fn without_bulk_apply_every_block_goes_straight_to_the_block_file() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    for round in 1..=10u64 {
        commit_block_round(&mut ledger, round);
        assert_eq!(file_rounds(&prefix).last(), Some(&(round as i64)));
    }
    assert_eq!(staged_rows(&prefix), 0);
}

/// Blocks staged, then a write outside a block span (here a prune): the staged
/// writes are applied first, so the prune still removes what it must.
#[test]
fn a_prune_outside_a_span_applies_the_staged_writes_first() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let mut ledger = SqliteLedger::open_with_prefix(&prefix).unwrap();
    ledger.set_bulk_apply(true).unwrap();
    for round in 1..=30u64 {
        commit_block_round(&mut ledger, round);
    }
    assert!(file_rounds(&prefix).is_empty());
    ledger.forget_before(10).unwrap();
    assert_eq!(file_rounds(&prefix), (10..=30).collect::<Vec<i64>>());
    assert_eq!(ledger.get_block_data(5).unwrap(), None);
    assert!(ledger.get_block_data(10).unwrap().is_some());
    assert_eq!(staged_rows(&prefix), 0);
}
