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

//! Issue #2162 -- a snapshot taken outside any transaction (what
//! `POST /v2/transactions/simulate` does) is rolled back, never committed.
//!
//! Before: `snapshot` opened a SAVEPOINT in autocommit mode, so the implicit
//! transaction it started was COMMITTED by the `RELEASE SAVEPOINT` of
//! `restore_snapshot` even though every write had been rolled back: each
//! simulate request wrote the rolled-back pages to the tracker WAL and synced
//! it (about 410 of its ~550 microseconds).

use std::path::Path;

use algo_ledger::{tracker_path_for_prefix, LedgerStore as _, SqliteLedger};
use algo_types::{AccountData, Address};

const A: Address = Address([0x11; 32]);
const B: Address = Address([0x22; 32]);

fn wal_len(prefix: &Path) -> u64 {
    let mut p = tracker_path_for_prefix(prefix).into_os_string();
    p.push("-wal");
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

fn funded(prefix: &Path) -> SqliteLedger {
    let mut l = SqliteLedger::open_with_prefix(prefix).unwrap();
    l.begin_block().unwrap();
    for who in [A, B] {
        l.set_account(
            &who,
            AccountData {
                micro_algos: 1_000_000,
                ..Default::default()
            },
        );
    }
    l.commit_block().unwrap();
    l
}

/// One simulate-shaped cycle: snapshot, write two accounts, restore.
fn cycle(l: &mut SqliteLedger) {
    let snap = l.snapshot(&[A, B]);
    for who in [A, B] {
        let mut a = l.get_account(&who).unwrap();
        a.micro_algos -= 1;
        l.set_account(&who, a);
    }
    l.restore_snapshot(snap);
}

#[test]
fn a_snapshot_outside_a_transaction_writes_nothing_to_the_wal() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let mut l = funded(&prefix);
    // Settle: the first cycles may create the WAL files themselves.
    cycle(&mut l);
    let before = wal_len(&prefix);
    for _ in 0..200 {
        cycle(&mut l);
    }
    assert_eq!(
        wal_len(&prefix),
        before,
        "200 rolled-back snapshot cycles must not commit anything to the tracker WAL"
    );
}

#[test]
fn the_rolled_back_writes_are_gone_and_the_ledger_stays_usable() {
    let dir = tempfile::tempdir().unwrap();
    let mut l = funded(&dir.path().join("ledger"));
    cycle(&mut l);
    for who in [A, B] {
        assert_eq!(l.get_account(&who).unwrap().micro_algos, 1_000_000);
    }
    // No transaction is left open: a block can begin and commit.
    l.begin_block().unwrap();
    let mut a = l.get_account(&A).unwrap();
    a.micro_algos += 5;
    l.set_account(&A, a);
    l.commit_block().unwrap();
    assert_eq!(l.get_account(&A).unwrap().micro_algos, 1_000_005);
}

#[test]
fn a_snapshot_inside_a_block_still_nests_and_keeps_the_blocks_writes() {
    let dir = tempfile::tempdir().unwrap();
    let mut l = funded(&dir.path().join("ledger"));
    l.begin_block().unwrap();
    let mut a = l.get_account(&A).unwrap();
    a.micro_algos += 7;
    l.set_account(&A, a);
    // The inner snapshot reverts only what happened after it.
    let snap = l.snapshot(&[A, B]);
    let mut b = l.get_account(&B).unwrap();
    b.micro_algos -= 9;
    l.set_account(&B, b);
    l.restore_snapshot(snap);
    l.commit_block().unwrap();
    assert_eq!(l.get_account(&A).unwrap().micro_algos, 1_000_007);
    assert_eq!(l.get_account(&B).unwrap().micro_algos, 1_000_000);
}
