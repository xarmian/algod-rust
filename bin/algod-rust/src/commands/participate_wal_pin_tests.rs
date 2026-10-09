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
//! the pool's pending block evaluator, whose ledger read snapshot would
//! otherwise pin the tracker WAL for the whole import/verify/replay.

use super::tests::test_agreement_control_with;
use super::*;
use crate::live_catchup::NormalSyncControl;
use algo_types::consensus::CONSENSUS_V41;

const GENESIS_ID: &str = "net-x";
const GENESIS_HASH: [u8; 32] = [0xAA; 32];
const FEE_SINK: Address = Address([0xF1; 32]);
const REWARDS_POOL: Address = Address([0xF2; 32]);

/// A file-backed ledger committed through genesis, plus a primed pool whose
/// pending evaluator holds a read snapshot (the production shape).
fn file_backed_fixture(prefix: &Path) -> (Arc<Mutex<SqliteLedger>>, Arc<TransactionPool>) {
    let ledger = Arc::new(Mutex::new(
        SqliteLedger::open_with_prefix(prefix).expect("file-backed ledger"),
    ));
    let block = algo_types::Block {
        round: Round(0),
        current_protocol: CONSENSUS_V41.to_string(),
        fee_sink: FEE_SINK,
        rewards_pool: REWARDS_POOL,
        genesis_id: GENESIS_ID.to_string(),
        genesis_hash: GENESIS_HASH,
        timestamp: 1_000,
        ..algo_types::Block::default()
    };
    {
        let mut l = ledger.lock().unwrap();
        l.begin_block().unwrap();
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

/// `PRAGMA wal_checkpoint(TRUNCATE)` over a private connection (what a
/// catchup's own connection would do): the `busy` flag.
fn truncate_busy(tracker: &Path) -> i64 {
    let conn = rusqlite::Connection::open(tracker).unwrap();
    conn.execute_batch("PRAGMA busy_timeout=0").unwrap();
    // Put at least one frame in the WAL so the checkpoint has work to do.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS wal_probe(x); INSERT INTO wal_probe VALUES (1);",
    )
    .unwrap();
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))
        .unwrap()
}

#[tokio::test]
async fn pause_releases_the_pool_evaluator_so_the_wal_can_be_truncated() {
    let mut pool_handle = None;
    let (control, tmp_dir) = test_agreement_control_with(|prefix| {
        let (ledger, pool) = file_backed_fixture(prefix);
        pool_handle = Some(pool.clone());
        (ledger, pool)
    });
    let pool = pool_handle.unwrap();
    let tracker = control.resolved_paths.tracker_path.clone();

    assert!(pool.has_evaluator(), "fixture primes an evaluator");
    assert_eq!(
        truncate_busy(&tracker),
        1,
        "before pause the evaluator's read snapshot pins the WAL"
    );

    control.pause().await;

    assert!(!pool.has_evaluator(), "pause must drop the evaluator");
    assert_eq!(
        truncate_busy(&tracker),
        0,
        "after pause nothing pins the WAL: TRUNCATE must not be busy"
    );

    // The pool recovers on the next block, as the follower drives it.
    pool.on_new_block(&algo_types::Block::default(), &Default::default());
    assert!(pool.has_evaluator(), "on_new_block rebuilds the evaluator");

    drop(pool);
    drop(control);
    let _ = std::fs::remove_dir_all(&tmp_dir);
}
