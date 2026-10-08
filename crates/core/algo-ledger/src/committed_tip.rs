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

//! Lock-free view of the last committed ledger tip (issue #1758).
//!
//! `AgreementLedgerBridge::ensure_block` holds the single ledger mutex across
//! `put_block` + `apply_block` + `commit_block`, so on a heavy app-call block
//! (1-2.4 s of apply) every other user of that mutex waits. go-algorand serves
//! `Latest()`/`BlockHdr(Latest)` from tracker state that is only updated once
//! a round is committed, never from state the evaluator is still building.
//!
//! This module is the equivalent: [`SqliteLedger::commit_block`] publishes an
//! immutable [`CommittedTip`] after a successful commit, and readers that only
//! need the committed tip (next round, `/v2/status`) read it without taking
//! the ledger mutex. The tip is never visible before the commit succeeded, and
//! any ledger mutation that does not go through that commit publication
//! invalidates it, so readers fall back to the locked path (exactly the
//! behaviour before this module existed).
//!
//! [`SqliteLedger::commit_block`]: crate::sqlite::SqliteLedger::commit_block

use std::sync::{Arc, RwLock};
use std::time::Instant;

use algo_types::BlockHeader;

/// Immutable snapshot of everything `/v2/status` and `next_round` read from
/// the ledger, captured after a successful commit.
#[derive(Debug, Clone)]
pub struct CommittedTip {
    /// The ledger's in-memory `current_round` (last committed round).
    pub current_round: u64,
    /// `acctrounds.acctbase`, the round `/v2/status` reports as `last-round`.
    pub last_committed_round: u64,
    /// The ledger's live protocol string at commit time.
    pub protocol: String,
    /// Header of `last_committed_round`, if the block store has one.
    pub latest_header: Option<BlockHeader>,
    /// Label of the most recently exported catchpoint (empty if none).
    pub last_catchpoint_label: String,
    /// Instant of the most recent successful commit in this process.
    pub last_commit_wall_time: Option<Instant>,
}

/// Shared, cheaply clonable handle to the published [`CommittedTip`].
#[derive(Debug, Clone, Default)]
pub struct CommittedTipHandle {
    cell: Arc<RwLock<Option<Arc<CommittedTip>>>>,
}

impl CommittedTipHandle {
    /// The currently published tip, or `None` when it is invalid (a ledger
    /// mutation happened that no commit has re-published yet) or was never
    /// published. `None` means "take the ledger lock and read it there".
    pub fn get(&self) -> Option<Arc<CommittedTip>> {
        self.cell
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(Arc::clone)
    }

    pub(crate) fn publish(&self, tip: CommittedTip) {
        *self.cell.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(tip));
    }

    pub(crate) fn invalidate(&self) {
        *self.cell.write().unwrap_or_else(|e| e.into_inner()) = None;
    }
}
