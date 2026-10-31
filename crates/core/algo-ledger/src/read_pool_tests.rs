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
        assert_eq!(got, LedgerStore::get_account(l, &addr(a)), "account {a}");
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

/// Before/after latency under a held ledger mutex (a simulated 1 s block
/// apply): the locked accessor waits out the hold, the pool does not. The
/// hold is long so the `HOLD / 2` bound keeps a wide margin when the test
/// thread is descheduled under heavy parallel load (it failed once at 400 ms).
/// Run with `--nocapture` to see the numbers recorded in the PR body.
#[test]
fn latency_under_a_held_ledger_mutex_before_and_after() {
    const HOLD: Duration = Duration::from_millis(1000);
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

// ---------------------------------------------------------------------------
// Issue #1893: resource lookups, boxes and circulation through the pool
// ---------------------------------------------------------------------------

use algo_types::{AssetParams, StateSchema, TealValue};

const BOX_NAMES: [&[u8]; 6] = [b"", b"a", b"ab", b"b", b"zz", b"\xff\x00"];

fn creator_of(id: u64) -> Address {
    addr((id % 4) as u8 + 1)
}

fn asset_record(id: u64, total: u64) -> AssetParamsRecord {
    AssetParamsRecord {
        params: AssetParams {
            total,
            decimals: (id % 3) as u32,
            asset_name: format!("asset-{id}").into_bytes(),
            ..Default::default()
        },
        creator: creator_of(id),
    }
}

fn app_record(id: u64, tag: u8) -> AppParams {
    AppParams {
        creator: creator_of(id),
        approval_program: vec![tag, id as u8],
        clear_state_program: vec![tag],
        global_state: [(b"g".to_vec(), TealValue::Uint(id))].into_iter().collect(),
        ..Default::default()
    }
}

fn local_state(v: u64) -> AppLocalState {
    AppLocalState {
        schema: StateSchema::default(),
        key_value: [(b"k".to_vec(), TealValue::Uint(v))].into_iter().collect(),
    }
}

/// Everything the REST resource lookups read, over addresses 0..=5, ids
/// 0..=6, box apps 0..=3 (+ `u64::MAX`) and a grid of pagination parameters.
#[derive(Debug, PartialEq)]
struct Probe {
    accounts: Vec<Option<AccountData>>,
    holdings: Vec<Option<AssetHolding>>,
    asset_params: Vec<Option<AssetParamsRecord>>,
    app_params: Vec<Option<AppParams>>,
    locals: Vec<Option<AppLocalState>>,
    holding_lists: Vec<Vec<(u64, AssetHolding)>>,
    local_lists: Vec<Vec<(u64, AppLocalState)>>,
    created_lists: Vec<Vec<(u64, AppParams)>>,
    boxes: Vec<Option<Vec<u8>>>,
    box_keys: Vec<Vec<Vec<u8>>>,
    pages: Vec<(BoxPage, bool)>,
}

fn probe<R: ResourceReads + ?Sized>(r: &R) -> Probe {
    let mut p = Probe {
        accounts: vec![],
        holdings: vec![],
        asset_params: vec![],
        app_params: vec![],
        locals: vec![],
        holding_lists: vec![],
        local_lists: vec![],
        created_lists: vec![],
        boxes: vec![],
        box_keys: vec![],
        pages: vec![],
    };
    for a in 0..=5u8 {
        let who = addr(a);
        p.accounts.push(r.get_account(&who));
        p.holding_lists.push(r.asset_holdings_for_addr(&who));
        p.local_lists.push(r.app_local_states_for_addr(&who));
        p.created_lists.push(r.created_apps_for_addr(&who));
        for id in 0..=6u64 {
            p.holdings.push(r.get_asset_holding(&who, id));
            p.locals.push(r.get_app_local_state(&who, id));
        }
    }
    for id in 0..=6u64 {
        p.asset_params.push(r.get_asset_params(id));
        p.app_params.push(r.get_app_params(id));
    }
    for app in [0u64, 1, 2, 3, u64::MAX] {
        for name in BOX_NAMES {
            p.boxes.push(r.get_box(app, name));
        }
        p.box_keys.push(r.box_keys_for_app(app));
        for prefix in [&b""[..], b"a", b"zz"] {
            for cursor in [None, Some(&b"a"[..]), Some(&b"ab"[..])] {
                for limit in [None, Some(0), Some(1), Some(2)] {
                    for values in [false, true] {
                        p.pages.push(
                            r.box_keys_by_prefix_paginated(app, prefix, cursor, limit, values),
                        );
                    }
                }
            }
        }
    }
    p
}

fn assert_resources_match(l: &SqliteLedger, pool: &LedgerReadPool) {
    let want = probe(l);
    let (round, got) = pool.read_resources(|r| probe(r)).expect("pool snapshot");
    assert_eq!(round, l.last_committed_round().unwrap().unwrap_or(0));
    assert_eq!(got, want);
}

fn stage_ops(l: &mut SqliteLedger, round: u64, ops: impl FnOnce(&mut SqliteLedger)) {
    l.begin_block().unwrap();
    l.set_current_round(Round(round));
    l.put_block(round, "v41", &hdr(round), &blk(round)).unwrap();
    ops(l);
}

/// Differential: random commit / rollback sequences over assets, holdings,
/// apps, local state, boxes and accounts. At every step the pool snapshot
/// equals the locked accessors, and an open block is invisible to it.
#[test]
fn resource_reads_match_locked_path_across_random_commit_rollback_sequences() {
    let (_d, mut l) = file_ledger();
    let pool = l.read_pool().unwrap();
    let mut seed = 0xD1B5_4A32_D192_ED03u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut round = 0u64;
    assert_resources_match(&l, &pool);
    let mut saw_state = false;
    for step in 0..120 {
        let n_ops = 1 + (next() % 3) as usize;
        let ops: Vec<u64> = (0..n_ops).map(|_| next()).collect();
        let apply = move |l: &mut SqliteLedger| {
            for r in &ops {
                let a = addr((r >> 8) as u8 % 4 + 1);
                let id = (r >> 16) % 5 + 1;
                let name = BOX_NAMES[((r >> 24) % BOX_NAMES.len() as u64) as usize];
                let app = (r >> 32) % 3 + 1;
                match r % 12 {
                    0 => l.set_asset_params(id, asset_record(id, r >> 40)),
                    1 => l.set_asset_holding(
                        &a,
                        id,
                        AssetHolding {
                            amount: r >> 44,
                            frozen: r & 1 == 0,
                        },
                    ),
                    2 => l.remove_asset_holding(&a, id),
                    3 => l.remove_asset_params(id),
                    4 => l.set_app_params(id, app_record(id, (r >> 40) as u8)),
                    5 => l.set_app_local_state(&a, id, local_state(r >> 44)),
                    6 => l.remove_app_local_state(&a, id),
                    7 => l.remove_app_params(id),
                    8 | 9 => l.set_box(app, name, (r >> 40).to_be_bytes().to_vec()),
                    10 => {
                        l.delete_box(app, name);
                    }
                    _ => l.set_account(
                        &a,
                        AccountData {
                            micro_algos: r >> 40,
                            total_boxes: (r >> 20) % 7,
                            ..Default::default()
                        },
                    ),
                }
            }
        };
        let before = probe(&l);
        stage_ops(&mut l, round + 1, apply);
        // The open block is invisible to the lock-free snapshot.
        let (r_open, during) = pool.read_resources(|r| probe(r)).unwrap();
        assert_eq!(r_open, round, "step {step}");
        assert_eq!(during, before, "open block leaked at step {step}");
        if next().is_multiple_of(4) {
            l.rollback_block().unwrap();
        } else {
            l.commit_block().unwrap();
            round += 1;
        }
        assert_resources_match(&l, &pool);
        let (_, p) = pool.read_resources(|r| probe(r)).unwrap();
        saw_state |= p.asset_params.iter().any(Option::is_some)
            && p.app_params.iter().any(Option::is_some)
            && p.boxes.iter().any(Option::is_some);
    }
    assert!(saw_state, "the random walk never produced state");
}

/// A resource that exists only inside an unfinished block is a miss, and it
/// appears once committed.
#[test]
fn resource_reads_see_a_resource_only_after_its_block_commits() {
    let (_d, mut l) = file_ledger();
    let pool = l.read_pool().unwrap();
    stage_ops(&mut l, 1, |l| {
        l.set_asset_params(1, asset_record(1, 10));
        l.set_asset_holding(
            &addr(2),
            1,
            AssetHolding {
                amount: 3,
                frozen: true,
            },
        );
        l.set_app_params(2, app_record(2, 9));
        l.set_app_local_state(&addr(1), 2, local_state(5));
        l.set_box(2, b"ab", b"v".to_vec());
    });
    let (_, p) = pool.read_resources(|r| probe(r)).unwrap();
    assert!(p.asset_params.iter().all(Option::is_none));
    assert!(p.boxes.iter().all(Option::is_none));
    l.commit_block().unwrap();
    let (round, p) = pool.read_resources(|r| probe(r)).unwrap();
    assert_eq!(round, 1);
    assert!(p.asset_params[1].is_some() && p.app_params[2].is_some());
    assert_eq!(
        pool.read_resources(|r| r.get_box(2, b"ab")).unwrap().1,
        Some(b"v".to_vec())
    );
    assert_resources_match(&l, &pool);
}

/// A SQL error inside the snapshot is surfaced (so the REST adapter takes the
/// locked path) rather than answered as an empty result.
#[test]
fn resource_snapshot_sql_error_is_reported_not_swallowed() {
    let (dir, mut l) = file_ledger();
    let pool = l.read_pool().unwrap();
    commit(&mut l, 1, 1, 1);
    assert!(pool.read_resources(|r| r.get_account(&addr(1))).is_ok());
    // Break the schema out from under the pooled connection.
    let w = Connection::open(crate::sqlite::tracker_path_for_prefix(
        &dir.path().join("ledger"),
    ))
    .unwrap();
    w.execute_batch("ALTER TABLE kvstore RENAME TO kvstore_gone;")
        .unwrap();
    assert!(
        pool.read_resources(|r| r.get_box(1, b"x")).is_err(),
        "a missing table must be an error, not a silent miss"
    );
}

/// Seed a committed history with online accounts, supply snapshots and
/// headers for the circulation tests.
fn circulation_ledger() -> (tempfile::TempDir, SqliteLedger) {
    let (d, mut l) = file_ledger();
    l.set_protocol(algo_types::consensus::CONSENSUS_V41.to_string());
    l.put_account_totals_seed(9_000_000, 0, 0, 0, 0, 0).unwrap();
    let online = |micro_algos, vote_last_valid| AccountData {
        micro_algos,
        status: AccountStatus::Online,
        vote_id: Some([7u8; 32]),
        selection_id: Some([8u8; 32]),
        vote_last_valid,
        vote_key_dilution: 100,
        rewards_base: 0,
        ..Default::default()
    };
    for r in 1..=5u64 {
        l.begin_block().unwrap();
        l.set_current_round(Round(r));
        l.put_block_header_fixture(r, r * 1_000).unwrap();
        if r == 1 {
            l.put_online_account_at_round(&addr(1), r, &online(5_000_000, 3))
                .unwrap();
            l.put_online_account_at_round(&addr(2), r, &online(2_000_000, 50))
                .unwrap();
        }
        if r == 3 {
            l.put_online_account_at_round(&addr(3), r, &online(1_000_000, 4))
                .unwrap();
            l.put_online_supply_at_round(3, 7_654_321).unwrap();
        }
        if r == 4 {
            l.put_online_account_at_round(&addr(2), r, &AccountData::default())
                .unwrap();
        }
        l.commit_block().unwrap();
    }
    (d, l)
}

/// Pool circulation equals the locked accessor for every (round, vote round)
/// including the expired-stake exclusion and the per-round supply snapshot;
/// rounds beyond the commit defer to the locked path.
#[test]
fn circulation_matches_locked_path() {
    let (_d, l) = circulation_ledger();
    let pool = l.read_pool().unwrap();
    let mut differing_from_total = 0;
    for round in 0..=5u64 {
        for vote_rnd in [0u64, 1, 3, 4, 5, 49, 50, 51, 1_000] {
            let want = l.online_circulation_at_round(round, vote_rnd).unwrap();
            match pool.online_circulation_at_round(round, vote_rnd) {
                PoolRead::Found(got) => {
                    assert_eq!(got, want, "round {round} vote {vote_rnd}");
                    if got != 9_000_000 && got != 7_654_321 {
                        differing_from_total += 1;
                    }
                }
                other => panic!("round {round} vote {vote_rnd}: {other:?} vs {want}"),
            }
        }
    }
    assert!(
        differing_from_total > 0,
        "the expired-stake exclusion was never exercised"
    );
    assert_eq!(pool.online_circulation_at_round(6, 1), PoolRead::Fallback);
}

/// Every newly covered read completes while another thread holds the ledger
/// mutex, and the locked equivalent waits it out (before/after numbers).
/// Run with `--nocapture` to see them.
#[test]
fn new_pool_reads_do_not_wait_for_a_held_ledger_mutex() {
    // 1 s: keeps the `HOLD / 2` bound wide when the test thread is
    // descheduled under heavy parallel load (failed once at 300 ms).
    const HOLD: Duration = Duration::from_millis(1000);
    let (_d, mut l) = circulation_ledger();
    stage_ops(&mut l, 6, |l| {
        l.set_asset_params(1, asset_record(1, 10));
        l.set_asset_holding(
            &addr(2),
            1,
            AssetHolding {
                amount: 3,
                frozen: false,
            },
        );
        l.set_app_params(2, app_record(2, 9));
        l.set_app_local_state(&addr(1), 2, local_state(5));
        l.set_box(2, b"ab", b"v".to_vec());
        l.set_box(2, b"b", b"w".to_vec());
    });
    l.commit_block().unwrap();
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

    // Locked ("before"): the same composed reads need the mutex.
    let h = hold_lock(&ledger);
    let t = Instant::now();
    {
        let g = ledger.lock().unwrap();
        let _ = probe(&*g);
        let _ = g.online_circulation_at_round(5, 4).unwrap();
    }
    let locked = t.elapsed();
    h.join().unwrap();

    // Lock-free ("after"), each read timed on its own while the mutex is held.
    let h = hold_lock(&ledger);
    let mut times = Vec::new();
    macro_rules! timed {
        ($name:expr, $body:expr) => {{
            let t = Instant::now();
            let v = $body;
            times.push(($name, t.elapsed()));
            v
        }};
    }
    let asset = timed!(
        "lookup_asset_by_id",
        pool.read_resources(|r| r.get_asset_params(1)).unwrap()
    );
    let holding = timed!(
        "lookup_asset_resource",
        pool.read_resources(|r| (r.get_asset_holding(&addr(2), 1), r.get_asset_params(1)))
            .unwrap()
    );
    let app = timed!(
        "lookup_application",
        pool.read_resources(|r| r.get_app_params(2)).unwrap()
    );
    let local = timed!(
        "lookup_app_resource",
        pool.read_resources(|r| (r.get_app_local_state(&addr(1), 2), r.get_app_params(2)))
            .unwrap()
    );
    let assets = timed!(
        "lookup_assets",
        pool.read_resources(|r| r.asset_holdings_for_addr(&addr(2)))
            .unwrap()
    );
    let apps = timed!(
        "lookup_applications",
        pool.read_resources(|r| (
            r.app_local_states_for_addr(&addr(1)),
            r.created_apps_for_addr(&addr(1))
        ))
        .unwrap()
    );
    let kv = timed!(
        "lookup_kv",
        pool.read_resources(|r| r.get_box(2, b"ab")).unwrap()
    );
    let keys = timed!(
        "box keys",
        pool.read_resources(|r| r.box_keys_for_app(2)).unwrap()
    );
    let page = timed!(
        "box page",
        pool.read_resources(|r| r.box_keys_by_prefix_paginated(2, b"", None, Some(1), true))
            .unwrap()
    );
    let circ = timed!("circulation", pool.online_circulation_at_round(5, 4));
    h.join().unwrap();

    assert_eq!(asset.0, 6);
    assert!(asset.1.is_some() && holding.1 .0.is_some() && app.1.is_some());
    assert!(local.1 .0.is_some() && !assets.1.is_empty() && !apps.1 .0.is_empty());
    assert_eq!(kv.1, Some(b"v".to_vec()));
    assert_eq!(keys.1.len(), 2);
    assert!(page.1 .1, "limit 1 of 2 boxes has more data");
    assert!(matches!(circ, PoolRead::Found(_)));

    let worst = times.iter().map(|(_, d)| *d).max().unwrap();
    println!("held-lock latency (resource/box/circulation reads): locked = {locked:?}");
    for (name, d) in &times {
        println!("  lock-free {name}: {d:?}");
    }
    assert!(locked >= HOLD / 2, "locked path should wait out the hold");
    assert!(worst < HOLD / 2, "lock-free reads waited: {worst:?}");
}

/// Issue #2155: a resource row the pool cannot decode is a snapshot error (the
/// REST adapter then takes the locked path), not a silently shorter list that
/// disagrees with the account's totals.
#[test]
fn undecodable_resource_row_is_reported_not_dropped() {
    let (dir, mut l) = file_ledger();
    let pool = l.read_pool().unwrap();
    stage(&mut l, 1, 1, 10);
    l.set_asset_params(
        7,
        AssetParamsRecord {
            params: algo_types::AssetParams {
                total: 5,
                ..Default::default()
            },
            creator: addr(1),
        },
    );
    l.commit_block().unwrap();
    let (_, ok) = pool
        .read_resources(|r| r.created_assets_for_addr(&addr(1)))
        .unwrap();
    assert_eq!(ok.len(), 1);

    // `{"y": 1, "b": 2^40}`: an ownership row whose decimals overflow u32.
    let corrupt: Vec<u8> = [
        &[0x82, 0xa1, b'y', 0x01, 0xa1, b'b', 0xcf][..],
        &(1u64 << 40).to_be_bytes()[..],
    ]
    .concat();
    let w = Connection::open(crate::sqlite::tracker_path_for_prefix(
        &dir.path().join("ledger"),
    ))
    .unwrap();
    w.execute(
        "UPDATE resources SET data = ?1 WHERE aidx = 7 AND ctype = ?2",
        params![corrupt, CTYPE_ASSET],
    )
    .unwrap();
    assert!(
        pool.read_resources(|r| r.created_assets_for_addr(&addr(1)))
            .is_err(),
        "an undecodable created-asset row must fail the snapshot"
    );
}
