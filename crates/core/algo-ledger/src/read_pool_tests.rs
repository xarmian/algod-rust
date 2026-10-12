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

//! Tests for the lock-free read pool (issue #1764).

use super::*;
use crate::store_trait::LedgerStore;
use algo_types::Round;
use std::time::Instant;

fn file_ledger() -> (tempfile::TempDir, SqliteLedger) {
    let dir = tempfile::tempdir().unwrap();
    let ledger = SqliteLedger::open_with_prefix(&dir.path().join("ledger")).unwrap();
    (dir, ledger)
}

fn addr(n: u8) -> Address {
    Address([n; 32])
}

fn hdr(round: u64) -> Vec<u8> {
    format!("hdr-{round}").into_bytes()
}

fn blk(round: u64) -> Vec<u8> {
    format!("blk-{round}").into_bytes()
}

fn acct(micro_algos: u64) -> AccountData {
    AccountData {
        micro_algos,
        ..Default::default()
    }
}

/// Open a block for `round` and write its rows, without committing.
fn stage(l: &mut SqliteLedger, round: u64, a: u8, algos: u64) {
    l.begin_block().unwrap();
    l.set_current_round(Round(round));
    l.put_block(round, "v41", &hdr(round), &blk(round)).unwrap();
    if round.is_multiple_of(2) {
        l.put_block_cert(round, format!("cert-{round}").as_bytes())
            .unwrap();
    }
    l.set_account(&addr(a), acct(algos));
}

fn commit(l: &mut SqliteLedger, round: u64, a: u8, algos: u64) {
    stage(l, round, a, algos);
    l.commit_block().unwrap();
}

/// Every pool read for rounds `0..=max_round+2` equals the locked accessor.
fn assert_matches_locked(l: &SqliteLedger, pool: &LedgerReadPool, max_round: u64) {
    let committed = l.last_committed_round().unwrap();
    assert_eq!(pool.committed_round().unwrap(), committed);
    for r in 0..=max_round + 2 {
        let reads = [
            (
                "block_data",
                pool.block_data(r),
                l.get_block_data(r).unwrap(),
            ),
            (
                "header_data",
                pool.block_header_data(r),
                l.get_block_header_data(r).unwrap(),
            ),
        ];
        for (name, pooled, locked) in reads {
            match (pooled, locked) {
                (PoolRead::Found(a), Some(b)) => assert_eq!(a, b, "{name} round {r}"),
                (PoolRead::NotFound, None) => {}
                // A miss at a committed round defers to the locked path.
                (PoolRead::Fallback, None) if r <= committed.unwrap_or(0) => {}
                (p, b) => panic!("{name} round {r}: pool {p:?} vs locked {b:?}"),
            }
        }
        match (pool.block_proto(r), l.get_block_proto(r).unwrap()) {
            (PoolRead::Found(a), Some(b)) => assert_eq!(a, b),
            (PoolRead::NotFound, None) => {}
            (PoolRead::Fallback, None) if r <= committed.unwrap_or(0) => {}
            (p, b) => panic!("proto round {r}: pool {p:?} vs locked {b:?}"),
        }
        match (pool.block_cert(r), l.get_block_cert(r).unwrap()) {
            (PoolRead::Found(a), b) => assert_eq!(a, b, "cert round {r}"),
            (PoolRead::NotFound, None) => {}
            (PoolRead::Fallback, None) if r <= committed.unwrap_or(0) => {}
            (p, b) => panic!("cert round {r}: pool {p:?} vs locked {b:?}"),
        }
    }
    for a in 0..6u8 {
        let (round, got) = pool.account_snapshot(&addr(a)).unwrap();
        assert_eq!(round, committed.unwrap_or(0));
        assert_eq!(got, l.get_account(&addr(a)), "account {a}");
    }
}

#[test]
fn in_memory_ledger_has_no_read_pool() {
    assert!(SqliteLedger::open_in_memory()
        .unwrap()
        .read_pool()
        .is_none());
    let (_d, l) = file_ledger();
    assert!(l.read_pool().is_some());
}

/// Differential: across a random sequence of commits and rolled-back blocks
/// the lock-free reads equal the locked accessors byte for byte.
#[test]
fn matches_locked_path_across_random_commit_sequences() {
    let (_d, mut l) = file_ledger();
    let pool = l.read_pool().unwrap();
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut round = 0u64;
    assert_matches_locked(&l, &pool, round);
    for _ in 0..60 {
        let r = next();
        let a = (r % 6) as u8;
        let algos = (r >> 8) % 1_000_000;
        if r.is_multiple_of(4) {
            // A rolled-back block must leave no trace.
            stage(&mut l, round + 1, a, algos);
            l.rollback_block().unwrap();
        } else {
            round += 1;
            commit(&mut l, round, a, algos);
        }
        assert_matches_locked(&l, &pool, round);
    }
}

/// An open (uncommitted) block is invisible to the lock-free reads, and stays
/// invisible after a rollback; it appears only once committed.
#[test]
fn never_serves_uncommitted_data_during_an_open_block() {
    let (_d, mut l) = file_ledger();
    let pool = l.read_pool().unwrap();
    commit(&mut l, 1, 1, 100);

    stage(&mut l, 2, 1, 999);
    assert_eq!(pool.block_data(2), PoolRead::NotFound);
    assert_eq!(pool.block_header_data(2), PoolRead::NotFound);
    assert_eq!(pool.committed_round().unwrap(), Some(1));
    let (round, a) = pool.account_snapshot(&addr(1)).unwrap();
    assert_eq!((round, a.unwrap().micro_algos), (1, 100));

    l.rollback_block().unwrap();
    assert_eq!(pool.block_data(2), PoolRead::NotFound);

    commit(&mut l, 2, 1, 999);
    assert_eq!(pool.block_data(2), PoolRead::Found(blk(2)));
    let (round, a) = pool.account_snapshot(&addr(1)).unwrap();
    assert_eq!((round, a.unwrap().micro_algos), (2, 999));
}

/// A miss at a round the tracker has committed is not trusted (the cross-file
/// gap / pruned history): the caller must use the locked path.
#[test]
fn miss_at_a_committed_round_falls_back_instead_of_not_found() {
    let (_d, mut l) = file_ledger();
    let pool = l.read_pool().unwrap();
    commit(&mut l, 1, 1, 1);
    commit(&mut l, 2, 1, 2);
    l.forget_before(2).unwrap();
    assert_eq!(pool.block_data(1), PoolRead::Fallback);
    assert_eq!(pool.block_data(2), PoolRead::Found(blk(2)));
    assert_eq!(pool.block_data(3), PoolRead::NotFound);
}

/// The point of the issue: reads complete while another thread holds the
/// ledger mutex (a slow apply).
#[test]
fn reads_complete_while_the_ledger_mutex_is_held() {
    let (_d, mut l) = file_ledger();
    commit(&mut l, 1, 1, 100);
    let ledger = Arc::new(Mutex::new(l));
    let lazy = LazyReadPool::new();
    let pool = lazy.get(&ledger).expect("file-backed pool").clone();

    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = {
        let ledger = Arc::clone(&ledger);
        std::thread::spawn(move || {
            let _g = ledger.lock().unwrap();
            locked_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(20));
        })
    };
    locked_rx.recv().unwrap();

    let t = Instant::now();
    assert_eq!(pool.block_data(1), PoolRead::Found(blk(1)));
    assert!(matches!(pool.block_header_data(1), PoolRead::Found(_)));
    assert_eq!(pool.committed_round().unwrap(), Some(1));
    assert_eq!(
        pool.account_snapshot(&addr(1))
            .unwrap()
            .1
            .unwrap()
            .micro_algos,
        100
    );
    let elapsed = t.elapsed();
    // A second `get` is a cached, lock-free OnceLock read.
    assert!(lazy.get(&ledger).is_some());
    release_tx.send(()).unwrap();
    holder.join().unwrap();
    assert!(
        elapsed < Duration::from_secs(2),
        "reads waited behind the held ledger mutex: {elapsed:?}"
    );
}

/// Read connections hold no snapshot between calls: the WAL can be truncated
/// while pooled connections sit idle.
#[test]
fn idle_pooled_connections_do_not_pin_the_wal() {
    let (dir, mut l) = file_ledger();
    let pool = l.read_pool().unwrap();
    for r in 1..=5 {
        commit(&mut l, r, 1, r);
    }
    let _ = pool.block_data(3);
    let _ = pool.account_snapshot(&addr(1)).unwrap();
    assert!(pool.idle_connections() >= 1);

    let w = Connection::open(crate::sqlite::tracker_path_for_prefix(
        &dir.path().join("ledger"),
    ))
    .unwrap();
    w.busy_timeout(Duration::ZERO).unwrap();
    let busy: i64 = w
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))
        .unwrap();
    assert_eq!(busy, 0, "an idle read connection pinned the WAL");
}

/// Concurrent writer + readers: a visible block row implies its state is
/// committed (the tracker round is already >= that round), and the committed
/// round / account snapshot never go backwards or tear.
#[test]
fn concurrent_readers_never_see_a_block_ahead_of_its_state() {
    let (_d, l) = file_ledger();
    let pool = l.read_pool().unwrap();
    let ledger = Arc::new(Mutex::new(l));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let pool = Arc::clone(&pool);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut last = 0u64;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let committed = pool.committed_round().unwrap().unwrap_or(0);
                    assert!(committed >= last, "committed round went backwards");
                    last = committed;
                    // Probe the next round: any visible block must be backed
                    // by a committed tracker round.
                    let probe = committed + 1;
                    if let PoolRead::Found(b) = pool.block_data(probe) {
                        assert_eq!(b, blk(probe));
                        let after = pool.committed_round().unwrap().unwrap_or(0);
                        assert!(
                            after >= probe,
                            "block {probe} visible but tracker only at {after}"
                        );
                    }
                    // account balance == the round the writer wrote it at
                    let (r, a) = pool.account_snapshot(&addr(1)).unwrap();
                    let bal = a.map(|a| a.micro_algos).unwrap_or(0);
                    assert_eq!(bal, r, "account/round tear");
                }
            })
        })
        .collect();
    for r in 1..=150u64 {
        let mut g = ledger.lock().unwrap();
        commit(&mut g, r, 1, r);
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for h in readers {
        h.join().unwrap();
    }
}

/// `lookup_agreement_account` matches the locked accessor, including the
/// pending-rewards fold, offline rows and rounds beyond the commit.
#[test]
fn lookup_agreement_matches_locked_path() {
    let (_d, mut l) = file_ledger();
    let pool = l.read_pool().unwrap();
    let online = AccountData {
        micro_algos: 5_000_000,
        status: AccountStatus::Online,
        vote_id: Some([7u8; 32]),
        selection_id: Some([8u8; 32]),
        vote_last_valid: 1_000_000,
        vote_key_dilution: 100,
        rewards_base: 0,
        ..Default::default()
    };
    let offline = AccountData {
        micro_algos: 7,
        ..Default::default()
    };
    for r in 1..=4u64 {
        l.begin_block().unwrap();
        l.set_current_round(Round(r));
        l.put_block_header_fixture(r, r * 1_000).unwrap();
        if r == 2 {
            l.put_online_account_at_round(&addr(1), r, &online).unwrap();
        }
        if r == 3 {
            l.put_online_account_at_round(&addr(2), r, &online).unwrap();
            l.put_online_account_at_round(&addr(2), r + 1, &offline)
                .unwrap();
        }
        l.commit_block().unwrap();
    }
    let mut served = 0;
    for a in 0..4u8 {
        for round in 0..=4u64 {
            let locked = l.lookup_agreement_account(&addr(a), round);
            match (pool.lookup_agreement_account(&addr(a), round), locked) {
                (PoolRead::Found(got), Ok(want)) => {
                    assert_eq!(got, want, "addr {a} round {round}");
                    served += 1;
                }
                // The locked path errors for a round with no readable header;
                // the pool defers to it.
                (PoolRead::Fallback, _) => {}
                (p, l) => panic!("addr {a} round {round}: pool {p:?} vs locked {l:?}"),
            }
        }
    }
    assert!(served >= 8, "pool served too few lookups ({served})");
    // Beyond the committed round the pool refuses to answer.
    assert_eq!(
        pool.lookup_agreement_account(&addr(1), 5),
        PoolRead::Fallback
    );
}

/// Before/after latency under a held ledger mutex (a simulated 400 ms block
/// apply): the locked accessor waits out the hold, the pool does not.
/// Run with `--nocapture` to see the numbers recorded in the PR body.
#[test]
fn latency_under_a_held_ledger_mutex_before_and_after() {
    const HOLD: Duration = Duration::from_millis(400);
    let (_d, mut l) = file_ledger();
    commit(&mut l, 1, 1, 100);
    let ledger = Arc::new(Mutex::new(l));
    let pool = ledger.lock().unwrap().read_pool().unwrap();

    let hold_lock = |ledger: &Arc<Mutex<SqliteLedger>>| {
        let (tx, rx) = std::sync::mpsc::channel();
        let ledger = Arc::clone(ledger);
        let h = std::thread::spawn(move || {
            let _g = ledger.lock().unwrap();
            tx.send(()).unwrap();
            std::thread::sleep(HOLD);
        });
        rx.recv().unwrap();
        h
    };

    let h = hold_lock(&ledger);
    let t = Instant::now();
    let _ = ledger.lock().unwrap().get_block_data(1).unwrap();
    let locked = t.elapsed();
    h.join().unwrap();

    let h = hold_lock(&ledger);
    let t = Instant::now();
    assert!(matches!(pool.block_data(1), PoolRead::Found(_)));
    let _ = pool.account_snapshot(&addr(1)).unwrap();
    let lock_free = t.elapsed();
    h.join().unwrap();

    println!(
        "held-lock read latency: before (locked) = {locked:?}, after (lock-free) = {lock_free:?}"
    );
    assert!(locked >= HOLD / 2, "locked path should wait out the hold");
    assert!(lock_free < HOLD / 2, "lock-free path must not wait");
}
