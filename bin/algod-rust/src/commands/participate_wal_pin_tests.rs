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

//! Issue #1683: pausing the node for a live catchpoint catchup must release
//! the pool's pending block evaluator -- whose ledger read snapshot would
//! otherwise pin the tracker WAL for the whole import/verify/replay -- and
//! keep it released until the catchup's own WAL checkpoint has run, even when
//! a block commits late or `reload_ledger` wakes the pool follower.

use super::tests::test_agreement_control_with;
use super::*;
use crate::live_catchup::NormalSyncControl;
use algo_types::consensus::CONSENSUS_V41;

const GENESIS_ID: &str = "net-x";
const GENESIS_HASH: [u8; 32] = [0xAA; 32];
const FEE_SINK: Address = Address([0xF1; 32]);
const REWARDS_POOL: Address = Address([0xF2; 32]);

fn block_for_round(round: u64) -> algo_types::Block {
    algo_types::Block {
        round: Round(round),
        current_protocol: CONSENSUS_V41.to_string(),
        fee_sink: FEE_SINK,
        rewards_pool: REWARDS_POOL,
        genesis_id: GENESIS_ID.to_string(),
        genesis_hash: GENESIS_HASH,
        timestamp: 1_000 + round as i64,
        ..algo_types::Block::default()
    }
}

/// Commit an (empty) block for `round` through the ledger's own connection:
/// puts fresh frames in the tracker WAL, beyond any earlier reader's mark.
fn commit_round(ledger: &Arc<Mutex<SqliteLedger>>, round: u64) {
    let block = block_for_round(round);
    let mut l = ledger.lock().unwrap();
    l.begin_block().unwrap();
    l.put_block(
        round,
        &block.current_protocol,
        &canonical_encode_block_header_from_block(&block),
        &canonical_encode_block(&block),
    )
    .unwrap();
    l.set_current_round(Round(round));
    l.commit_block().unwrap();
}

/// A file-backed ledger committed through genesis, plus a primed pool whose
/// pending evaluator holds a read snapshot (the production shape: the
/// evaluator reads the rewards-pool balance at creation in
/// `start_simple_evaluator`, which is what takes the WAL read mark).
fn file_backed_fixture(prefix: &Path) -> (Arc<Mutex<SqliteLedger>>, Arc<TransactionPool>) {
    let ledger = Arc::new(Mutex::new(
        SqliteLedger::open_with_prefix(prefix).expect("file-backed ledger"),
    ));
    {
        let mut l = ledger.lock().unwrap();
        l.begin_block().unwrap();
        let block = block_for_round(0);
        l.put_block(
            0,
            &block.current_protocol,
            &canonical_encode_block_header_from_block(&block),
            &canonical_encode_block(&block),
        )
        .unwrap();
        l.set_current_round(Round(0));
        l.set_fee_sink(FEE_SINK);
        l.set_rewards_pool(REWARDS_POOL);
        l.set_genesis_id(GENESIS_ID.to_string());
        l.set_genesis_hash(GENESIS_HASH);
        l.set_protocol(CONSENSUS_V41.to_string());
        l.set_account(
            &REWARDS_POOL,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );
        l.commit_block().unwrap();
    }
    let pool = Arc::new(TransactionPool::new(
        PoolConfig::default(),
        Arc::new(PoolLedgerAdapter::new(ledger.clone())) as Arc<dyn algo_pool::traits::PoolLedger>,
    ));
    pool.ensure_evaluator_primed();
    (ledger, pool)
}

/// `PRAGMA wal_checkpoint(TRUNCATE)` over a private connection, as the
/// catchup's own connection would run it, returning the `busy` flag. It
/// creates nothing and writes no rows; with no wait (`busy_timeout=0`) it
/// reports busy exactly while some reader still holds a snapshot of the WAL.
fn truncate_busy(tracker: &Path) -> i64 {
    let conn = rusqlite::Connection::open(tracker).unwrap();
    conn.execute_batch("PRAGMA busy_timeout=0").unwrap();
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))
        .unwrap()
}

type Fixture = (
    ParticipateAgreementControl,
    PathBuf,
    Arc<Mutex<SqliteLedger>>,
    Arc<TransactionPool>,
);

fn fixture() -> Fixture {
    let mut handles = None;
    let (control, tmp_dir) = test_agreement_control_with(|prefix| {
        let (ledger, pool) = file_backed_fixture(prefix);
        handles = Some((ledger.clone(), pool.clone()));
        (ledger, pool)
    });
    let (ledger, pool) = handles.unwrap();
    (control, tmp_dir, ledger, pool)
}

#[tokio::test]
async fn pause_releases_the_pool_evaluator_so_the_wal_can_be_truncated() {
    let (control, tmp_dir, ledger, pool) = fixture();
    let tracker = control.resolved_paths.tracker_path.clone();

    // Frames beyond the evaluator's read mark, so a pinned WAL cannot reset.
    commit_round(&ledger, 1);
    assert!(pool.has_evaluator(), "fixture primes an evaluator");
    assert_eq!(
        truncate_busy(&tracker),
        1,
        "before pause the evaluator's read snapshot pins the WAL"
    );

    control.pause().await;

    assert!(!pool.has_evaluator(), "pause must drop the evaluator");
    assert!(pool.is_evaluator_paused());
    assert_eq!(
        truncate_busy(&tracker),
        0,
        "after pause nothing pins the WAL: TRUNCATE must not be busy"
    );

    drop((pool, ledger, control));
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

/// The pool follower can process a block that committed just before the
/// pause, or be woken by `reload_ledger`; neither may rebuild the evaluator
/// (and so re-pin the WAL) while the catchup runs. Red proof: without the
/// pause flag the late `on_new_block` rebuilds it and TRUNCATE turns busy.
#[tokio::test]
async fn late_block_during_pause_does_not_rebuild_the_evaluator() {
    let (control, tmp_dir, ledger, pool) = fixture();
    let tracker = control.resolved_paths.tracker_path.clone();

    control.pause().await;
    assert_eq!(truncate_busy(&tracker), 0);

    // A block commits and the follower hands it to the pool.
    commit_round(&ledger, 2);
    pool.on_new_block(&algo_types::Block::default(), &Default::default());
    pool.ensure_evaluator_primed();

    assert!(
        !pool.has_evaluator(),
        "a late block must not rebuild the evaluator while paused"
    );
    assert_eq!(
        truncate_busy(&tracker),
        0,
        "nothing re-pinned the WAL during the pause"
    );

    drop((pool, ledger, control));
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

/// A successful reload resumes the pool only after the checkpoint and
/// rebuilds the evaluator against the fresh ledger handle.
#[tokio::test]
async fn successful_reload_resumes_and_reprimes_the_pool() {
    let (control, tmp_dir, ledger, pool) = fixture();
    let tracker = control.resolved_paths.tracker_path.clone();

    control.pause().await;
    commit_round(&ledger, 1);
    control.reload_ledger().await;

    assert!(!pool.is_evaluator_paused(), "reload must resume the pool");
    assert!(
        pool.has_evaluator(),
        "reload re-primes against the new handle"
    );
    // The re-primed evaluator pins again, as in normal operation.
    commit_round(&ledger, 2);
    assert_eq!(truncate_busy(&tracker), 1);

    drop((pool, ledger, control));
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

/// A failed reload must not leave the pool paused, and must not build an
/// evaluator on the stale ledger handle; the next block rebuilds it.
#[tokio::test]
async fn failed_reload_unpauses_without_building_an_evaluator() {
    let (mut control, tmp_dir, ledger, pool) = fixture();
    let tracker = control.resolved_paths.tracker_path.clone();

    control.pause().await;
    commit_round(&ledger, 1);
    // The directory does not exist, so the reopen fails.
    control.resolved_paths.tracker_path = tmp_dir
        .join("no")
        .join("such")
        .join("dir")
        .join("ledger.tracker.sqlite");
    control.reload_ledger().await;

    assert!(
        !pool.is_evaluator_paused(),
        "failure path must not stay paused"
    );
    assert!(
        !pool.has_evaluator(),
        "no evaluator on the stale handle after a failed reload"
    );
    assert_eq!(truncate_busy(&tracker), 0, "nothing pins the WAL");

    pool.on_new_block(&algo_types::Block::default(), &Default::default());
    assert!(pool.has_evaluator(), "the next block rebuilds it");

    drop((pool, ledger, control));
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

/// `resume()` is the safety net for any path that never reached a
/// successful `reload_ledger` (e.g. an aborted catchup): it clears the pause.
#[tokio::test]
async fn resume_clears_a_pause_left_behind() {
    let (control, tmp_dir, _ledger, pool) = fixture();

    control.pause().await;
    assert!(pool.is_evaluator_paused());
    control.resume().await;
    assert!(!pool.is_evaluator_paused());
    control.pause().await;

    drop((pool, control));
    let _ = std::fs::remove_dir_all(&tmp_dir);
}
