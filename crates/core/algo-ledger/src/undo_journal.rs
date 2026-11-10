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

//! Per-round undo data, so `simulate` can serve a historical
//! `Request.Round` (issue #2148).
//!
//! go's `Simulator.Simulate` reads accounts, apps, assets, boxes and `Totals`
//! as of `Request.Round` from the tracker, back to its `dbRound`. This
//! ledger keeps only the latest state, so each applied block also retains its
//! pre-images: the value every account, holding, asset/app param, local state
//! and box had immediately before the block first touched it (the data
//! [`crate::recording_store::RecordingStore`] already collects for the delta
//! of the block), plus the account totals before the block. Rewinding the
//! latest state to round `start` is then: for every key touched in rounds
//! `start + 1 ..= latest`, write the pre-image of the EARLIEST of those rounds.
//!
//! DIVERGENCE DIV-007: the journal holds the last `window` rounds and is memory-only: after a
//! restart it starts empty, so the earliest servable round is the latest round
//! until `window` new blocks are applied (go's `dbRound` likewise only moves
//! forward from the committed round).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParamsRecord, Round,
};

use crate::state_delta::AccountTotals;

/// How many recent rounds a node retains undo data for: go's default
/// `MaxAcctLookback`, the distance its tracker `dbRound` trails the latest
/// round, and so the oldest round its `simulate` serves.
pub const NODE_UNDO_WINDOW_ROUNDS: u64 = 320;

/// What one applied block overwrote: pre-images, `None` = the key did not
/// exist before the block created it.
#[derive(Debug, Default, Clone)]
pub struct RoundUndo {
    /// The round of the block these are the pre-images of.
    pub round: Round,
    /// Account totals before the block (go `Totals(round - 1)`).
    pub totals_before: AccountTotals,
    pub accounts: HashMap<Address, Option<AccountData>>,
    pub asset_holdings: HashMap<(Address, u64), Option<AssetHolding>>,
    pub asset_params: HashMap<u64, Option<AssetParamsRecord>>,
    pub app_params: HashMap<u64, Option<AppParams>>,
    pub app_local_states: HashMap<(Address, u64), Option<AppLocalState>>,
    pub boxes: HashMap<(u64, Vec<u8>), Option<Vec<u8>>>,
}

/// The keys of a rewind with the value each had at the requested round.
pub type Rewind = RoundUndo;

/// The default memory budget of a journal: the pre-images of the oldest rounds
/// are dropped beyond it, so the earliest servable round moves forward instead
/// of the node's memory growing with how busy the chain is.
pub const DEFAULT_UNDO_BUDGET_BYTES: usize = 16 * 1024 * 1024;

/// A map node costs about a key, a value and some pointers per entry.
const MAP_ENTRY: usize = 48;

fn teal_kv_bytes(m: &std::collections::BTreeMap<Vec<u8>, algo_types::TealValue>) -> usize {
    m.iter()
        .map(|(k, v)| {
            MAP_ENTRY
                + k.len()
                + std::mem::size_of::<algo_types::TealValue>()
                + match v {
                    algo_types::TealValue::Bytes(b) => b.len(),
                    _ => 0,
                }
        })
        .sum()
}

fn app_params_bytes(p: &AppParams) -> usize {
    std::mem::size_of::<AppParams>()
        + p.approval_program.len()
        + p.clear_state_program.len()
        + teal_kv_bytes(&p.global_state)
}

fn account_bytes(a: &AccountData) -> usize {
    use std::mem::size_of;
    size_of::<AccountData>()
        + a.assets.len() * (MAP_ENTRY + size_of::<AssetHolding>())
        + a.asset_params.len() * (MAP_ENTRY + size_of::<algo_types::AssetParams>() + 256)
        + a.app_local_states
            .values()
            .map(|l| MAP_ENTRY + size_of::<AppLocalState>() + teal_kv_bytes(&l.key_value))
            .sum::<usize>()
        + a.app_params
            .values()
            .map(|p| MAP_ENTRY + app_params_bytes(p))
            .sum::<usize>()
}

impl RoundUndo {
    /// An estimate of the heap this round's pre-images hold: the sizes of the
    /// stored values and keys plus a per-entry map overhead. Not exact (the
    /// allocator rounds up), but proportional to what is retained, which is
    /// what a budget needs.
    pub fn approx_bytes(&self) -> usize {
        use std::mem::size_of;
        const ENTRY: usize = 64; // hash map slot + key
        let accounts: usize = self
            .accounts
            .values()
            .map(|a| ENTRY + a.as_ref().map_or(0, account_bytes))
            .sum();
        let holdings = self.asset_holdings.len() * (ENTRY + size_of::<AssetHolding>());
        let asset_params = self.asset_params.len() * (ENTRY + 512);
        let app_params: usize = self
            .app_params
            .values()
            .map(|p| ENTRY + p.as_ref().map_or(0, app_params_bytes))
            .sum();
        let locals: usize = self
            .app_local_states
            .values()
            .map(|l| {
                ENTRY
                    + size_of::<AppLocalState>()
                    + l.as_ref().map_or(0, |l| teal_kv_bytes(&l.key_value))
            })
            .sum();
        let boxes: usize = self
            .boxes
            .iter()
            .map(|((_, name), v)| ENTRY + name.len() + v.as_ref().map_or(0, Vec::len))
            .sum();
        size_of::<Self>() + accounts + holdings + asset_params + app_params + locals + boxes
    }
}

/// The retained undo data of the most recent rounds.
#[derive(Debug)]
pub struct UndoJournal {
    window: u64,
    budget_bytes: usize,
    retained_bytes: usize,
    rounds: VecDeque<(Arc<RoundUndo>, usize)>,
}

impl Default for UndoJournal {
    fn default() -> Self {
        Self {
            window: 0,
            budget_bytes: DEFAULT_UNDO_BUDGET_BYTES,
            retained_bytes: 0,
            rounds: VecDeque::new(),
        }
    }
}

impl UndoJournal {
    /// How many rounds are retained; `0` (the default) retains nothing.
    pub fn window(&self) -> u64 {
        self.window
    }

    /// Set the retention window, dropping what no longer fits.
    pub fn set_window(&mut self, window: u64) {
        self.window = window;
        self.trim();
    }

    /// Set the memory budget (an estimate, see [`RoundUndo::approx_bytes`]).
    pub fn set_budget_bytes(&mut self, budget: usize) {
        self.budget_bytes = budget;
        self.trim();
    }

    /// The estimated bytes and the number of rounds retained.
    pub fn retained(&self) -> (usize, usize) {
        (self.retained_bytes, self.rounds.len())
    }

    /// Drop the oldest rounds beyond the window or the byte budget. The newest
    /// round is always kept (so the rounds stay contiguous up to the latest and
    /// `latest - 1` stays servable), even if it alone exceeds the budget.
    fn trim(&mut self) {
        while self.rounds.len() as u64 > self.window
            || (self.retained_bytes > self.budget_bytes && self.rounds.len() > 1)
        {
            match self.rounds.pop_front() {
                Some((_, bytes)) => self.retained_bytes -= bytes,
                None => break,
            }
        }
    }

    /// Retain the undo data of a block that was just applied. A block that
    /// does not directly follow the newest retained round (a gap: a replay
    /// that skipped the journal, a reorg) empties the journal first, so the
    /// retained rounds are always contiguous.
    pub fn push(&mut self, undo: RoundUndo) {
        if self.window == 0 {
            return;
        }
        if let Some((last, _)) = self.rounds.back() {
            if last.round.0 + 1 != undo.round.0 {
                self.clear();
            }
        }
        let bytes = undo.approx_bytes();
        self.retained_bytes += bytes;
        self.rounds.push_back((Arc::new(undo), bytes));
        self.trim();
    }

    /// Forget everything (the ledger moved without recording, e.g. a
    /// catchpoint restore).
    pub fn clear(&mut self) {
        self.rounds.clear();
        self.retained_bytes = 0;
    }

    /// The oldest round `start` that [`Self::rewind_to`] can serve, given the
    /// ledger's latest round: `oldest retained round - 1`, or `latest` when
    /// nothing (contiguous up to `latest`) is retained.
    pub fn earliest_start(&self, latest: Round) -> Round {
        match (self.rounds.front(), self.rounds.back()) {
            (Some((first, _)), Some((last, _))) if last.round == latest => Round(first.round.0 - 1),
            _ => latest,
        }
    }

    /// The state of every key touched in rounds `start + 1 ..= latest`, as it
    /// was at the end of round `start`; `None` if `start` is not servable.
    /// The totals are those before round `start + 1`.
    pub fn rewind_to(&self, start: Round, latest: Round) -> Option<Rewind> {
        if start >= latest || start < self.earliest_start(latest) {
            return None;
        }
        let mut out = Rewind::default();
        let mut first = true;
        for (undo, _) in self.rounds.iter().filter(|(u, _)| u.round > start) {
            if first {
                out.totals_before = undo.totals_before.clone();
                first = false;
            }
            for (k, v) in &undo.accounts {
                out.accounts.entry(*k).or_insert_with(|| v.clone());
            }
            for (k, v) in &undo.asset_holdings {
                out.asset_holdings.entry(*k).or_insert_with(|| v.clone());
            }
            for (k, v) in &undo.asset_params {
                out.asset_params.entry(*k).or_insert_with(|| v.clone());
            }
            for (k, v) in &undo.app_params {
                out.app_params.entry(*k).or_insert_with(|| v.clone());
            }
            for (k, v) in &undo.app_local_states {
                out.app_local_states.entry(*k).or_insert_with(|| v.clone());
            }
            for (k, v) in &undo.boxes {
                out.boxes.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        out.round = start;
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn undo(round: u64, addr: u8, before: Option<u64>) -> RoundUndo {
        let mut u = RoundUndo {
            round: Round(round),
            ..Default::default()
        };
        u.accounts.insert(
            Address([addr; 32]),
            before.map(|m| AccountData {
                micro_algos: m,
                ..Default::default()
            }),
        );
        u
    }

    #[test]
    fn the_earliest_pre_image_after_start_wins() {
        let mut j = UndoJournal::default();
        j.set_window(10);
        j.push(undo(5, 1, Some(100)));
        j.push(undo(6, 1, Some(90)));
        j.push(undo(7, 2, None));
        // at the end of round 5 account 1 held what round 6 saw before it
        let r = j.rewind_to(Round(5), Round(7)).unwrap();
        assert_eq!(
            r.accounts[&Address([1; 32])].as_ref().unwrap().micro_algos,
            90
        );
        assert_eq!(r.accounts[&Address([2; 32])], None);
        // at the end of round 4 it held round 5's pre-image
        let r = j.rewind_to(Round(4), Round(7)).unwrap();
        assert_eq!(
            r.accounts[&Address([1; 32])].as_ref().unwrap().micro_algos,
            100
        );
        // before the window: not servable
        assert!(j.rewind_to(Round(3), Round(7)).is_none());
        assert_eq!(j.earliest_start(Round(7)), Round(4));
    }

    #[test]
    fn the_window_is_bounded_and_a_gap_restarts_the_journal() {
        let mut j = UndoJournal::default();
        j.set_window(2);
        for r in 1..=4 {
            j.push(undo(r, 1, Some(r)));
        }
        assert_eq!(j.earliest_start(Round(4)), Round(2));
        // a block that skips a round empties it
        j.push(undo(9, 1, Some(9)));
        assert_eq!(j.earliest_start(Round(9)), Round(8));
        // a journal that is not current serves nothing but `latest`
        assert_eq!(j.earliest_start(Round(12)), Round(12));
        assert!(j.rewind_to(Round(9), Round(12)).is_none());
    }

    #[test]
    fn the_byte_budget_evicts_the_oldest_rounds_and_moves_the_earliest_start() {
        let one = undo(1, 1, Some(1)).approx_bytes();
        let mut j = UndoJournal::default();
        j.set_window(100);
        // room for three rounds
        j.set_budget_bytes(one * 3 + one / 2);
        for r in 1..=5 {
            j.push(undo(r, 1, Some(r)));
        }
        assert_eq!(j.retained().1, 3, "the oldest two were evicted");
        assert!(j.retained().0 <= one * 3 + one / 2);
        // rounds 3..=5 retained: the earliest servable start is 2
        assert_eq!(j.earliest_start(Round(5)), Round(2));
        assert!(j.rewind_to(Round(2), Round(5)).is_some());
        assert!(j.rewind_to(Round(1), Round(5)).is_none());
        // a tiny budget keeps the newest round only
        j.set_budget_bytes(1);
        assert_eq!(j.retained().1, 1);
        assert_eq!(j.earliest_start(Round(5)), Round(4));
        assert!(j.rewind_to(Round(4), Round(5)).is_some());
        // the accounting returns to zero with the journal
        j.clear();
        assert_eq!(j.retained(), (0, 0));
    }

    #[test]
    fn a_zero_window_retains_nothing() {
        let mut j = UndoJournal::default();
        j.push(undo(1, 1, None));
        assert_eq!(j.earliest_start(Round(1)), Round(1));
        assert!(j.rewind_to(Round(0), Round(1)).is_none());
    }
}
