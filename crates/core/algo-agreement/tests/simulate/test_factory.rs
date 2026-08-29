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

// Test `KeyManager` + `BlockFactory` shims for the full-consensus simulate
// harness.
//
// Both expose the per-account info the agreement protocol needs from
// the supplied `TestAccount`s, with no I/O / disk / DB plumbing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use algo_agreement::{
    AgreementError, AgreementKeyManager, BlockFactory, ParticipationAction, ParticipationRecord,
    UnfinishedBlock,
};
use algo_types::{Address, Block, Round};

use super::test_account::TestAccount;

/// Snapshot of every recorded participation action — exposed for tests
/// that want to assert "account X participated in round Y as proposer".
#[derive(Debug, Clone, Default)]
pub struct ParticipationLog {
    /// `(address, round, action)` tuples in the order they were recorded.
    pub entries: Vec<(Address, Round, ParticipationAction)>,
}

impl ParticipationLog {
    /// True if any account participated as a proposer in `round`.
    pub fn proposed_in(&self, round: Round) -> bool {
        self.entries
            .iter()
            .any(|(_, r, a)| *r == round && *a == ParticipationAction::Proposed)
    }

    /// All addresses that participated in `round`.
    #[allow(dead_code)] // exposed for future drill-down assertions.
    pub fn participants_in(&self, round: Round) -> Vec<Address> {
        self.entries
            .iter()
            .filter_map(|(a, r, _)| (*r == round).then_some(*a))
            .collect()
    }
}

/// A `KeyManager` backed by a fixed list of test accounts. Returns the
/// same `ParticipationRecord` set for every voting round (validity
/// window enforcement is handled by each record's
/// `vote_first_valid` / `vote_last_valid`).
pub struct TestKeyManager {
    /// Cached records, one per supplied account.
    records: Vec<ParticipationRecord>,
    /// Recorded actions, mirroring Go's `account.ParticipationActionsHistory`.
    log: Arc<Mutex<ParticipationLog>>,
}

impl TestKeyManager {
    /// Build a key manager exposing the given accounts as voting keys.
    pub fn new(accounts: &[TestAccount]) -> Self {
        let records = accounts
            .iter()
            .map(|a| ParticipationRecord {
                address: a.address,
                vote_id: a.vote_id,
                selection_id: a.selection_id(),
                vote_first_valid: a.vote_first_valid,
                vote_last_valid: a.vote_last_valid,
                vote_key_dilution: a.vote_key_dilution,
            })
            .collect();
        Self {
            records,
            log: Arc::new(Mutex::new(ParticipationLog::default())),
        }
    }

    /// Returns a clone of the participation log handle so the test can
    /// read it after `simulate(...)` returns.
    pub fn log(&self) -> Arc<Mutex<ParticipationLog>> {
        Arc::clone(&self.log)
    }
}

impl AgreementKeyManager for TestKeyManager {
    fn voting_keys(&self, _voting_round: Round, _keys_round: Round) -> Vec<ParticipationRecord> {
        self.records.clone()
    }

    fn record(&self, account: &Address, round: Round, action: ParticipationAction) {
        self.log
            .lock()
            .unwrap()
            .entries
            .push((*account, round, action));
    }
}

// ---------------------------------------------------------------------------
// AutoBlockFactory
// ---------------------------------------------------------------------------

/// `BlockFactory` that fabricates a fresh default `Block` for every
/// requested round.
///
/// Mirrors Go's `testBlockFactory{}.AssembleBlock(r, _)` shape from
/// `simulate_test.go:104`. Block contents don't matter for the
/// agreement state machine — only the round, proposer, and
/// finalize-time seed do.
pub struct AutoBlockFactory;

impl BlockFactory for AutoBlockFactory {
    fn assemble_block(
        &self,
        round: Round,
        _addresses: &[Address],
    ) -> Result<Box<dyn UnfinishedBlock>, AgreementError> {
        let block = Block {
            round,
            ..Block::default()
        };
        Ok(Box::new(AutoUnfinishedBlock { block, round }))
    }
}

/// Per-round unfinished block. `finish_block` writes the seed +
/// proposer + eligibility into the block header (mirroring Go's
/// `testValidatedBlock.FinishBlock`).
struct AutoUnfinishedBlock {
    block: Block,
    round: Round,
}

impl UnfinishedBlock for AutoUnfinishedBlock {
    fn finish_block(&self, seed: algo_agreement::Seed, proposer: Address, eligible: bool) -> Block {
        let mut b = self.block.clone();
        b.seed = seed.0;
        b.proposer = proposer;
        if !eligible {
            b.proposer_payout = 0;
        }
        b
    }

    fn round(&self) -> Round {
        self.round
    }
}

// ---------------------------------------------------------------------------
// PrevRoundGuardBlockFactory
// ---------------------------------------------------------------------------

/// `BlockFactory` that enforces the ordering guarantee production block
/// assembly depends on: assembling round `N` reads round `N-1`'s block
/// header out of the ledger (`TransactionPool::assemble_empty_block`), so
/// round `N-1` MUST already be committed when the `Assemble` action runs.
///
/// Regression guard for issue #482: the agreement main loop used to execute
/// the batch's `Pseudonode(Assemble N)` action *before* handing the same
/// batch's `Ensure(block N-1)` to the demux thread, so the ledger's latest
/// committed round was still `N-2` and every proposal attempt failed with
/// `cannot get prev header for N-1`. Any factory failure recorded here means
/// the ordering has regressed.
pub struct PrevRoundGuardBlockFactory {
    /// Reads the ledger's next (i.e. first uncommitted) round.
    next_round: Box<dyn Fn() -> Round + Send + Sync>,
    /// `(requested round, ledger next_round)` for each rejected assembly.
    failures: Arc<Mutex<Vec<(Round, Round)>>>,
}

impl PrevRoundGuardBlockFactory {
    /// Build a factory reading committed progress through `next_round`.
    pub fn new(next_round: impl Fn() -> Round + Send + Sync + 'static) -> Self {
        Self {
            next_round: Box::new(next_round),
            failures: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Handle to the recorded failures, readable after the run finishes.
    pub fn failures(&self) -> Arc<Mutex<Vec<(Round, Round)>>> {
        Arc::clone(&self.failures)
    }
}

impl BlockFactory for PrevRoundGuardBlockFactory {
    fn assemble_block(
        &self,
        round: Round,
        addresses: &[Address],
    ) -> Result<Box<dyn UnfinishedBlock>, AgreementError> {
        let next = (self.next_round)();
        if next.0 < round.0 {
            // Round `round - 1` is not committed yet — exactly the
            // production failure mode from issue #482.
            self.failures.lock().unwrap().push((round, next));
            return Err(AgreementError::Other(format!(
                "assembleEmptyBlock: cannot get prev header for {}: ledger is only at round {}",
                Round(round.0.saturating_sub(1)),
                next.0.saturating_sub(1),
            )));
        }
        AutoBlockFactory.assemble_block(round, addresses)
    }
}

// ---------------------------------------------------------------------------
// SigningKeyMap helper
// ---------------------------------------------------------------------------

/// Build the `signing_keys` map required by `Parameters`, taking
/// ownership of each account's secrets.
///
/// Returns the map plus a reusable `Vec<Address>` so tests can later
/// query the participation log.
pub fn signing_keys_from_accounts(
    accounts: Vec<TestAccount>,
) -> (
    HashMap<Address, algo_agreement::AccountSigningKeys>,
    Vec<Address>,
) {
    let mut map = HashMap::with_capacity(accounts.len());
    let mut addrs = Vec::with_capacity(accounts.len());
    for a in accounts {
        let TestAccount {
            address, vrf, ots, ..
        } = a;
        addrs.push(address);
        map.insert(address, algo_agreement::AccountSigningKeys { vrf, ots });
    }
    (map, addrs)
}
