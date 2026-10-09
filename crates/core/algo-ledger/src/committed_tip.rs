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
//! the ledger mutex. The tip is always an immutable snapshot of *committed*
//! state (round, header and label are read back from the database, never
//! from in-memory setters), it is never visible before the commit succeeded,
//! and any ledger mutation that does not go through a publication
//! invalidates it, so readers fall back to the locked path (exactly the
//! behaviour before this module existed). Fallbacks are counted in
//! `algod_rust_committed_tip_fallback_total` so a permanent fallback is
//! visible.
//!
//! [`SqliteLedger::commit_block`]: crate::sqlite::SqliteLedger::commit_block

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use algo_types::BlockHeader;

/// Immutable snapshot of everything `/v2/status` and `next_round` read from
/// the ledger, captured from committed state.
#[derive(Debug, Clone)]
pub struct CommittedTip {
    /// Last committed round (`acctrounds.acctbase`; equal to the ledger's
    /// in-memory `current_round`, publication is refused otherwise).
    pub current_round: u64,
    /// The round `/v2/status` reports as `last-round`.
    pub last_committed_round: u64,
    /// Protocol of the latest committed block.
    pub protocol: String,
    /// Header of `last_committed_round`, if the block store has one.
    pub latest_header: Option<Arc<BlockHeader>>,
    /// Label of the most recently exported catchpoint (empty if none).
    pub last_catchpoint_label: String,
    /// Instant of the most recent successful commit in this process.
    pub last_commit_wall_time: Option<Instant>,
}

static NEXT_OWNER_ID: AtomicU64 = AtomicU64::new(1);
static FALLBACK_TOTAL: AtomicU64 = AtomicU64::new(0);

/// A fresh publisher id; every `SqliteLedger` takes one.
pub(crate) fn next_owner_id() -> u64 {
    NEXT_OWNER_ID.fetch_add(1, Ordering::Relaxed)
}

/// Times a reader found no valid tip and took the ledger mutex instead.
pub fn committed_tip_fallback_total() -> u64 {
    FALLBACK_TOTAL.load(Ordering::Relaxed)
}

/// Prometheus text for `algod_rust_committed_tip_fallback_total`.
pub fn committed_tip_prometheus_text() -> String {
    let mut out = String::new();
    out.push_str("# HELP algod_rust_committed_tip_fallback_total ");
    out.push_str("Reads that found no valid committed tip and took the ledger mutex.\n");
    out.push_str("# TYPE algod_rust_committed_tip_fallback_total counter\n");
    out.push_str(&format!(
        "algod_rust_committed_tip_fallback_total {}\n",
        committed_tip_fallback_total()
    ));
    out
}

#[derive(Debug, Default)]
struct Shared {
    cell: RwLock<Option<Arc<CommittedTip>>>,
    /// Id of the ledger allowed to publish/invalidate (0 = unclaimed).
    owner: AtomicU64,
    /// Set once a locked path observed a poisoned ledger mutex: the tip is
    /// never served or published again.
    poisoned: AtomicBool,
}

/// Shared, cheaply clonable handle to the published [`CommittedTip`].
#[derive(Debug, Clone, Default)]
pub struct CommittedTipHandle {
    shared: Arc<Shared>,
}

impl CommittedTipHandle {
    /// The currently published tip, or `None` when it is invalid, was never
    /// published or the ledger mutex is poisoned. `None` means "take the
    /// ledger lock and read it there"; the fallback is counted.
    pub fn read(&self) -> Option<Arc<CommittedTip>> {
        let tip = self.get();
        if tip.is_none() {
            FALLBACK_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        tip
    }

    /// Like [`Self::read`] without counting a fallback.
    pub fn get(&self) -> Option<Arc<CommittedTip>> {
        if self.shared.poisoned.load(Ordering::Acquire) {
            return None;
        }
        self.shared
            .cell
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(Arc::clone)
    }

    /// Record that the ledger mutex was observed poisoned: clears the tip and
    /// stops any further serving or publication.
    pub fn poison(&self) {
        if !self.shared.poisoned.swap(true, Ordering::AcqRel) {
            tracing::error!(
                "ledger mutex poisoned: committed tip disabled, reads use the locked path"
            );
        }
        self.clear();
    }

    pub(crate) fn claim(&self, owner: u64) {
        self.shared.owner.store(owner, Ordering::Release);
    }

    pub(crate) fn is_unclaimed(&self) -> bool {
        self.shared.owner.load(Ordering::Acquire) == 0
    }

    /// Publish `tip` if `owner` is the current publisher and not poisoned.
    pub(crate) fn publish(&self, owner: u64, tip: CommittedTip) {
        if self.shared.owner.load(Ordering::Acquire) != owner
            || self.shared.poisoned.load(Ordering::Acquire)
        {
            return;
        }
        *self.shared.cell.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(tip));
    }

    /// Invalidate the tip, but only when `owner` is the current publisher, so
    /// a ledger that never published (e.g. a failed reload) cannot wipe the
    /// live tip.
    pub(crate) fn invalidate_if_owner(&self, owner: u64, why: &str) {
        if self.shared.owner.load(Ordering::Acquire) != owner {
            return;
        }
        let mut cell = self.shared.cell.write().unwrap_or_else(|e| e.into_inner());
        if cell.take().is_some() {
            tracing::debug!(
                why,
                "committed tip invalidated; readers use the locked path"
            );
        }
    }

    fn clear(&self) {
        *self.shared.cell.write().unwrap_or_else(|e| e.into_inner()) = None;
    }
}
