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

//! Startup replay of the archived rounds above the tracker round (issue #2210).
//!
//! The block archive commits BEFORE the tracker (issue #2209, as in go), so a
//! crash between the two leaves the archive at most one block ahead of the
//! tracker; sync also writes blocks ahead of applying them. go-algorand opens
//! its ledger by replaying the blocks in `blockdb` that the trackers have not
//! seen yet (`trackerRegistry.loadFromDisk`, `ledger/tracker.go`, called from
//! `OpenLedger` in `ledger/ledger.go`; present since rel/beta-2.0.5), so a
//! restarted node is at the archive's tip without asking a peer. This is the
//! same step: [`replay_archived_tail`] applies every archived block (with its
//! certificate) above the tracker round through the normal apply path.
//!
//! Failure is not fatal. A missing or undecodable block or certificate, or a
//! block the apply rejects, stops the replay (the block's own transaction is
//! rolled back) and is reported in [`ArchiveReplay::stopped`]; the node starts
//! at the round it reached and catches up from the network.

use algo_error::AlgoError;
use tracing::{info, warn};

use crate::sqlite::SqliteLedger;
use crate::store_trait::LedgerStore;

/// Log a progress line every this many replayed rounds.
const PROGRESS_EVERY: u64 = 1000;

/// What [`replay_archived_tail`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveReplay {
    /// The tracker round when the replay started (`0` for a fresh tracker).
    pub from_round: u64,
    /// Rounds applied from the archive.
    pub applied: u64,
    /// The first round that could not be replayed and why; `None` when the
    /// whole archived tail was applied (or there was none).
    pub stopped: Option<(u64, String)>,
}

/// Apply the archived rounds above the tracker round, in order, each in its
/// own block span (as the follower commits a block), stopping at the first
/// round that is not replayable.
///
/// Call at startup, before anything else reads or writes the ledger. Returns
/// `Err` only when the tracker or the archive cannot be queried at all.
pub fn replay_archived_tail(ledger: &mut SqliteLedger) -> Result<ArchiveReplay, AlgoError> {
    let tracker = ledger.last_committed_round()?.unwrap_or(0);
    let mut report = ArchiveReplay {
        from_round: tracker,
        applied: 0,
        stopped: None,
    };
    let Some(archive_max) = ledger.max_block_round_in_blockdb()? else {
        return Ok(report);
    };
    if archive_max <= tracker {
        return Ok(report);
    }
    info!(
        tracker_round = tracker,
        archive_round = archive_max,
        "replaying archived rounds above the tracker round"
    );
    let check_payouts = !ledger.is_devmode_chain();
    for round in tracker + 1..=archive_max {
        match replay_round(ledger, round, check_payouts) {
            Ok(()) => {
                report.applied += 1;
                if report.applied.is_multiple_of(PROGRESS_EVERY) {
                    info!(round, "archive replay progress");
                }
            }
            Err(reason) => {
                warn!(
                    round,
                    %reason,
                    "archive replay stopped; the rest is left for catchup"
                );
                report.stopped = Some((round, reason));
                break;
            }
        }
    }
    if report.applied > 0 {
        info!(
            from_round = tracker,
            applied = report.applied,
            tracker_round = tracker + report.applied,
            "archived rounds replayed into the tracker"
        );
    }
    Ok(report)
}

/// One round: read its archived block and certificate, apply, commit. The
/// archive row already exists, so nothing is written to it. A failure rolls
/// the block span back and is returned as text.
fn replay_round(ledger: &mut SqliteLedger, round: u64, check_payouts: bool) -> Result<(), String> {
    let block_bytes = ledger
        .get_block_data(round)
        .map_err(|e| format!("read archived block: {e}"))?
        .filter(|b| !b.is_empty())
        .ok_or_else(|| "no archived block".to_string())?;
    let has_cert = ledger
        .get_block_cert(round)
        .map_err(|e| format!("read archived certificate: {e}"))?
        .is_some_and(|c| !c.is_empty());
    if !has_cert {
        return Err("no archived certificate".to_string());
    }
    let block = algo_codec::decode_block(&block_bytes)
        .map_err(|e| format!("decode archived block: {e}"))?;
    if block.round.0 != round {
        return Err(format!(
            "archived block of round {round} carries round {}",
            block.round.0
        ));
    }
    ledger
        .begin_block()
        .map_err(|e| format!("begin block: {e}"))?;
    if let Err(e) = crate::apply::apply_block_executing_app_calls_for(ledger, &block, check_payouts)
    {
        let _ = ledger.rollback_block();
        return Err(format!("apply: {e}"));
    }
    ledger
        .commit_block()
        .map_err(|e| format!("commit block: {e}"))
}
