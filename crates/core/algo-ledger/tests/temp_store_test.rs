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

//! SQLite temporary storage stays in memory (issue #2316, DIV-012).
//!
//! Profiling the small-corpus replay showed 213 of its 380 MB of writes going
//! to deleted temp files: the statement and sub-journals SQLite keeps for each
//! SAVEPOINT (go-algorand's per-group rollback points here) spill to a file
//! once they pass 64 KiB. With `temp_store=MEMORY` they stay in memory.

#[cfg(target_os = "linux")]
use algo_ledger::LedgerStore as _;
use algo_ledger::SqliteLedger;
#[cfg(target_os = "linux")]
use algo_types::{AccountData, Address, Round};

#[test]
fn the_ledger_connection_keeps_temporary_storage_in_memory() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = SqliteLedger::open_with_prefix(&dir.path().join("ledger")).unwrap();
    assert_eq!(ledger.temp_store_mode().unwrap(), 2);
}

/// A block that changes many existing accounts inside a savepoint writes far
/// more than 64 KiB of sub-journal; none of it may reach a temp file.
#[cfg(target_os = "linux")]
#[test]
fn a_savepoint_that_changes_many_pages_opens_no_temp_file() {
    fn deleted_fds() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .flatten()
            .filter(|e| {
                std::fs::read_link(e.path())
                    .map(|p| p.to_string_lossy().ends_with("(deleted)"))
                    .unwrap_or(false)
            })
            .count()
    }
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = SqliteLedger::open_with_prefix(&dir.path().join("ledger")).unwrap();
    let addr = |i: u32| {
        let mut a = [0u8; 32];
        a[..4].copy_from_slice(&i.to_be_bytes());
        Address(a)
    };
    // Existing accounts, committed: their pages are what a savepoint journals.
    ledger.begin_block().unwrap();
    for i in 0..6000u32 {
        ledger.set_account(
            &addr(i),
            AccountData {
                micro_algos: 1_000_000 + u64::from(i),
                ..Default::default()
            },
        );
    }
    ledger.set_current_round(Round(1));
    ledger.commit_block().unwrap();

    let before = deleted_fds();
    ledger.begin_block().unwrap();
    let all: Vec<Address> = (0..6000u32).map(addr).collect();
    let snap = ledger.snapshot(&all);
    for i in 0..6000u32 {
        ledger.set_account(
            &addr(i),
            AccountData {
                micro_algos: 7 + u64::from(i),
                ..Default::default()
            },
        );
    }
    // The journal is held open by the savepoint right now.
    assert_eq!(deleted_fds(), before, "a savepoint spilled to a temp file");
    ledger.restore_snapshot(snap);
    ledger.rollback_block().unwrap();
}
