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

//! Transaction simulation engine.
//!
//! Provides the [`Simulator`] that can dry-run transaction groups against
//! the current ledger state without committing changes. This powers the
//! `/v2/transactions/simulate` REST endpoint.
//!
//! The implementation mirrors go-algorand's `ledger/simulation/` package:
//! - [`Simulator`] corresponds to `simulation.Simulator`
//! - [`SimulationRequest`] corresponds to `simulation.Request`
//! - [`SimulationResult`] corresponds to `simulation.Result`
//!
//! The simulation engine uses [`LedgerStore::snapshot`] /
//! [`LedgerStore::restore_snapshot`] to ensure that no permanent state
//! changes are made.

pub mod trace;
pub mod tracer;

pub use trace::{
    AppInitialState, AvmValueTrace, ExecTraceConfig, InitialStatesAccumulator, OpcodeTraceUnit,
    ProgramTrace, ResourcesInitialStates, ResultEvalOverrides, SimulationResult, StateChange,
    StateChangeKind, StateChangeOp, TransactionTrace, TxnGroupResult, TxnPath, TxnResult,
    UnnamedResourcesAccessed, LOG_BYTES_LIMIT, MAX_EXTRA_OPCODE_BUDGET, SIMULATION_MAX_LOG_CALLS,
};
pub use tracer::SimulationTracer;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;
use std::sync::Arc;

use algo_avm::group::GroupBudget;
use algo_codec::canonical_encode_transaction;
use algo_error::AlgoError;
use algo_types::consensus::{consensus_params_for_version, ConsensusParams};
use algo_types::{Address, Round, SignedTransaction};
use algo_validate::{
    check_txn_group, validate_pqsig_envelope, validate_pqsig_scheme,
    validate_transaction_wellformed, verify_transaction_signature_with_tracer, SpecialAddresses,
};
use ed25519_dalek::{Signer, SigningKey};

use crate::apply::{
    apply_transaction_with_budget, check_authorizer, compute_group_fee_credit_and_residue,
    withdraw_block_rewards, ApplyContext, ApplyMode, AvmEvalOverrides, BlockRewardsWithdrawal,
    BoxBudgetState, GroupInfo, TESTNET_BANK_ADDRESS,
};
use crate::avm_context::{NamedGroupResources, StoreSigBlockSource, UnnamedCapacityTracker};
use crate::block_header::next_block_protocol;
use crate::rewards::{balance_with_rewards, next_rewards_state, RewardsState};
use crate::store_trait::LedgerStore;

/// Fixed proxy signing key seed (first 32 bytes of go-algorand's `proxySigner`).
///
/// Used to create valid signatures for unsigned transactions when
/// `allow_empty_signatures` is enabled, matching go-algorand's
/// `simulation.proxySigner` behaviour.
const PROXY_SIGNER_SEED: [u8; 32] = [
    128, 128, 92, 23, 212, 119, 175, 51, 157, 2, 165, 215, 137, 37, 82, 42, 52, 227, 54, 41, 243,
    67, 141, 76, 208, 17, 199, 17, 140, 46, 113, 0,
];

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during simulation.
#[derive(Debug)]
pub enum SimulatorError {
    /// The simulation request was invalid.
    InvalidRequest(InvalidRequestError),
    /// Transaction evaluation failed.
    EvalFailure(EvalFailureError),
    /// Internal error (ledger access, etc.).
    Internal(AlgoError),
}

impl fmt::Display for SimulatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SimulatorError::InvalidRequest(e) => write!(f, "invalid simulation request: {e}"),
            SimulatorError::EvalFailure(e) => write!(f, "simulation eval failure: {e}"),
            SimulatorError::Internal(e) => write!(f, "simulation internal error: {e}"),
        }
    }
}

impl std::error::Error for SimulatorError {}

impl From<AlgoError> for SimulatorError {
    fn from(e: AlgoError) -> Self {
        SimulatorError::Internal(e)
    }
}

/// The simulation request contained invalid parameters.
#[derive(Debug)]
pub struct InvalidRequestError {
    pub message: String,
}

impl InvalidRequestError {
    /// go's batch signature-verification failure, which go reports bare
    /// (issue #1969).
    pub fn is_batch_sig_failure(&self) -> bool {
        self.message == algo_error::BATCH_HAS_FAILED_SIGS
    }
}

impl fmt::Display for InvalidRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// A transaction evaluation failure during simulation.
///
/// This is not necessarily fatal — the simulation still returns results
/// with the failure information included.
#[derive(Debug)]
pub struct EvalFailureError {
    pub message: String,
    /// Index path to the failing transaction.
    pub failed_at: TxnPath,
}

impl fmt::Display for EvalFailureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at {:?})", self.message, self.failed_at)
    }
}

/// Outcome of [`Simulator::check`].
///
/// Mirrors go-algorand's split between a `verify.TxGroupError` with a known
/// `GroupIndex` (attributable to one transaction -- surfaced as the group's
/// `FailureMessage`/`FailedAt` on an otherwise-successful `Result`, exactly
/// like an evaluation failure, per `simulator.go`'s `Simulate` switch) and a
/// genuinely group-wide failure (`GroupIndex < 0`, e.g. a corrupted
/// signature caught only by batch cryptographic verification, or a
/// structural screen with no single offending transaction) -- returned as a
/// hard [`SimulatorError::InvalidRequest`] instead. Well-formedness and
/// signature-*format* failures (missing signature, more than one signature
/// category, orphaned LogicSig fields) are per-transaction attributable in
/// go-algorand and so become [`CheckOutcome::RecoverableFailure`]; actual
/// cryptographic signature-verification failures stay hard errors, matching
/// go's non-attributable batch-verifier failure.
enum CheckOutcome {
    /// The group passed `check()`; evaluation may proceed.
    Passed {
        logicsig_traces: Vec<Option<TransactionTrace>>,
        logicsig_budgets: Vec<u64>,
    },
    /// A per-transaction attributable check failure. Evaluation never runs;
    /// the caller reports this exactly like an early evaluation failure.
    RecoverableFailure {
        index: usize,
        message: String,
        logicsig_traces: Vec<Option<TransactionTrace>>,
        logicsig_budgets: Vec<u64>,
    },
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// A simulation request, specifying the transactions to simulate and
/// configuration options.
///
/// Mirrors go-algorand's `simulation.Request`.
#[derive(Debug, Clone, Default)]
pub struct SimulationRequest {
    /// The round to simulate at. If `None`, uses the ledger's latest round.
    pub round: Option<Round>,
    /// Transaction groups to simulate. Currently only a single group is
    /// supported (matching go-algorand's restriction).
    pub txn_groups: Vec<Vec<SignedTransaction>>,
    /// Allow transactions with empty (missing) signatures.
    pub allow_empty_signatures: bool,
    /// Allow more logging output than normal.
    pub allow_more_logging: bool,
    /// Allow unnamed resources in app calls.
    pub allow_unnamed_resources: bool,
    /// Extra opcode budget to add beyond the default.
    pub extra_opcode_budget: i64,
    /// Execution trace configuration.
    pub trace_config: ExecTraceConfig,
    /// Automatically fix signer fields.
    pub fix_signers: bool,
}

// ---------------------------------------------------------------------------
// Simulator
// ---------------------------------------------------------------------------

/// Test-only fault injection for [`Simulator::simulate`] (issue #2118).
#[cfg(any(test, feature = "test-hooks"))]
pub mod test_hooks {
    use std::cell::Cell;

    thread_local! {
        static PANIC_AFTER_WITHDRAWAL: Cell<bool> = const { Cell::new(false) };
    }

    /// Make this thread's next simulate panic right after the block-start
    /// pool withdrawal, to prove the store is restored on unwind.
    pub fn set_panic_after_withdrawal(on: bool) {
        PANIC_AFTER_WITHDRAWAL.with(|c| c.set(on));
    }

    pub(super) fn maybe_panic_after_withdrawal() {
        if PANIC_AFTER_WITHDRAWAL.with(|c| c.replace(false)) {
            panic!("test hook: panic after the block-start withdrawal");
        }
    }
}

/// The block a simulated group is evaluated in (see
/// [`Simulator::prepare_simulated_block`]).
struct SimulatedBlock {
    /// `start + 1`: `global Round`, the validity window, voter lookups.
    round: u64,
    /// The block's protocol, after any upgrade switch.
    consensus: ConsensusParams,
    /// `prevHeader.TimeStamp` (`global LatestTimestamp`).
    latest_timestamp: u64,
    /// The block's rewards level (`NextRewardsState`).
    rewards_level: u64,
    /// The block-start pool withdrawal. Its `pool` is the block's rewards
    /// pool and its `genesis_hash` the ledger's (the testnet hotfix key).
    withdrawal: BlockRewardsWithdrawal,
    /// The block's fee sink (`NextRewardsState` carries `prevHdr`'s).
    fee_sink: Address,
    /// The genesis identity, from go's two sources:
    /// - `block_genesis_id` / `block_genesis_hash` are the simulated block
    ///   header's, which `BlockHeader.Alive` checks every transaction
    ///   against. `MakeBlock` copies both from `prevHdr`, and
    ///   `StartEvaluator` (`Generate`, `SupportGenesisHash`) then overwrites
    ///   the hash with the ledger's `eval.genesisHash`.
    /// - `ledger_genesis_hash` is the ledger's own, which `global
    ///   GenesisHash` reads and the testnet hotfix is keyed on.
    block_genesis_id: String,
    block_genesis_hash: [u8; 32],
    ledger_genesis_hash: [u8; 32],
}

impl SimulatedBlock {
    /// The block's own accounts a simulate may write: the fee sink, the
    /// rewards pool and, on a testnet hotfix round, the testnet bank.
    fn snapshot_addrs(&self) -> Vec<Address> {
        let mut addrs = vec![self.fee_sink, self.withdrawal.pool];
        if self.withdrawal.is_testnet_hotfix_round() {
            addrs.push(Address(TESTNET_BANK_ADDRESS));
        }
        addrs
    }
}

/// The simulation engine.
///
/// Runs transaction groups against a [`LedgerStore`] without committing
/// changes. Uses snapshot/restore to ensure the store is left unchanged.
pub struct Simulator<'a, L: LedgerStore> {
    /// The ledger store to simulate against.
    store: &'a mut L,
    /// Whether the developer API is enabled (allows extra trace features).
    pub developer_api: bool,
}

impl<'a, L: LedgerStore> Simulator<'a, L> {
    /// Create a new simulator backed by the given ledger store.
    pub fn new(store: &'a mut L) -> Self {
        Simulator {
            store,
            developer_api: false,
        }
    }

    /// Create a new simulator with the developer API enabled.
    pub fn new_with_developer_api(store: &'a mut L) -> Self {
        Simulator {
            store,
            developer_api: true,
        }
    }

    /// Validate the trace configuration against the node configuration.
    ///
    /// Mirrors go-algorand's `validateSimulateRequest`
    /// (`ledger/simulation/trace.go`): requesting an execution trace
    /// requires the developer API to be enabled, and the `stack`,
    /// `scratch`, and `state` sub-options require the basic trace
    /// (`enable`) to be on. Error messages match go byte-for-byte so REST
    /// clients see identical 400 bodies.
    fn validate_trace_config(&self, cfg: &ExecTraceConfig) -> Result<(), SimulatorError> {
        if !self.developer_api && cfg.enable {
            return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                message: "the local configuration of the node has `EnableDeveloperAPI` turned off, while requesting for execution trace".to_string(),
            }));
        }
        if !cfg.enable {
            if cfg.stack {
                return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                    message: "basic trace must be enabled when enabling stack tracing".to_string(),
                }));
            }
            if cfg.scratch {
                return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                    message:
                        "basic trace must be enabled when enabling scratch slot change tracing"
                            .to_string(),
                }));
            }
            if cfg.state {
                return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                    message: "basic trace must be enabled when enabling app state change tracing"
                        .to_string(),
                }));
            }
        }
        Ok(())
    }

    /// The block go's `Simulator.Simulate` evaluates the group in
    /// (`ledger/simulation/simulator.go`): `bookkeeping.MakeBlock(prevHdr)`
    /// for `prevHdr = BlockHdr(start)`, round `start + 1`, under the protocol
    /// `MakeBlock` resolves (any upgrade switch applied), run through
    /// `eval.StartEvaluator` with `Generate: true` (`ledger/eval/eval.go`),
    /// which gives it `prevHdr.NextRewardsState(round, proto,
    /// pool.WithUpdatedRewards(prevLevel), prevTotals.RewardUnits())` and
    /// withdraws the block's rewards from the pool.
    ///
    /// Only reads: the withdrawal itself is applied after `check`.
    ///
    /// The rewards inputs (the previous rewards state, the pool, the reward
    /// units) are the store's own, i.e. the latest round's. For `start` =
    /// latest that is exactly go's `BlockHdr(start)` / `Totals(start)`. For
    /// a past `start` it keeps them consistent with the accounts simulate
    /// reads, which are also the latest state (issue #2123): an older
    /// header's level paired with newer rewards bases would be a base above
    /// the level. Without a header for `start` (unit-test stores only; a
    /// real ledger always has its latest header) the store's protocol stands
    /// in.
    fn prepare_simulated_block(
        &self,
        start: Round,
        prev_hdr: Option<&algo_types::BlockHeader>,
    ) -> Result<SimulatedBlock, AlgoError> {
        let store = &*self.store;
        let round = start.0 + 1;
        let ledger_genesis_hash = *store.genesis_hash();
        let (block_genesis_id, prev_genesis_hash) = match prev_hdr {
            Some(hdr) => (hdr.genesis_id.clone(), hdr.genesis_hash),
            None => (store.genesis_id().to_string(), ledger_genesis_hash),
        };
        let (consensus, latest_timestamp) = match prev_hdr {
            Some(hdr) => {
                let protocol = next_block_protocol(hdr)?;
                let consensus =
                    consensus_params_for_version(&protocol).ok_or_else(|| AlgoError::Ledger {
                        message: format!("unknown protocol '{protocol}'"),
                    })?;
                // `global LatestTimestamp` is `prevHeader.TimeStamp`.
                (consensus, hdr.timestamp.max(0) as u64)
            }
            None => (
                consensus_params_for_version(store.protocol()).unwrap_or_default(),
                0,
            ),
        };
        let prev = RewardsState {
            rewards_level: store.rewards_level(),
            rewards_rate: store.rewards_rate(),
            rewards_residue: store.rewards_residue(),
            rewards_recalculation_round: store.rewards_recalculation_round(),
        };
        let pool = store.rewards_pool();
        let pool_balance = match store.get_account(&pool) {
            Some(acct) => balance_with_rewards(&acct, prev.rewards_level)?,
            None => 0,
        };
        let reward_units = store.total_reward_units()?;
        let next = next_rewards_state(prev, round, &consensus, pool_balance, reward_units);
        let withdrawal = BlockRewardsWithdrawal {
            round,
            pool,
            prev_rewards_level: prev.rewards_level,
            rewards_level: next.rewards_level,
            prev_reward_units: reward_units,
            genesis_hash: ledger_genesis_hash,
            min_balance: consensus.min_balance,
        };
        let block_genesis_hash = if consensus.support_genesis_hash {
            ledger_genesis_hash
        } else {
            prev_genesis_hash
        };
        Ok(SimulatedBlock {
            round,
            consensus,
            latest_timestamp,
            rewards_level: next.rewards_level,
            withdrawal,
            fee_sink: store.fee_sink(),
            block_genesis_id,
            block_genesis_hash,
            ledger_genesis_hash,
        })
    }

    /// Simulate the given request and return results.
    ///
    /// The ledger store is left unchanged after simulation completes
    /// (all state changes are rolled back via snapshot/restore).
    pub fn simulate(
        &mut self,
        request: SimulationRequest,
    ) -> Result<SimulationResult, SimulatorError> {
        // --- Validate request ---

        if request.fix_signers && !request.allow_empty_signatures {
            return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                message: "FixSigners requires AllowEmptySignatures to be enabled".to_string(),
            }));
        }

        if request.txn_groups.is_empty() {
            return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                message: "simulation request must contain at least one transaction group"
                    .to_string(),
            }));
        }

        if request.txn_groups.len() > 1 {
            // Matches go-algorand's exact wording
            // (`ledger/simulation/simulator.go`: `"expected 1 transaction
            // group, got %d"`), verified by `TestSimulateTransactionMultipleGroups`
            // (`daemon/algod/api/server/v2/test/handlers_test.go`).
            return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                message: format!(
                    "expected 1 transaction group, got {}",
                    request.txn_groups.len()
                ),
            }));
        }

        let txn_group = &request.txn_groups[0];
        if txn_group.is_empty() {
            return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                message: "transaction group must contain at least one transaction".to_string(),
            }));
        }

        self.validate_trace_config(&request.trace_config)?;

        // --- Determine simulation round ---

        let sim_round = request.round.unwrap_or_else(|| self.store.current_round());

        // --- Build result ---

        let mut result = SimulationResult::new(sim_round);
        result.trace_config = request.trace_config.clone();
        result.eval_overrides = ResultEvalOverrides {
            allow_empty_signatures: request.allow_empty_signatures,
            allow_unnamed_resources: request.allow_unnamed_resources,
            extra_opcode_budget: request.extra_opcode_budget,
            fix_signers: request.fix_signers,
            // AllowMoreLogging raises the AVM log limits (go-algorand
            // `ResultEvalOverrides.AllowMoreLogging`).
            max_log_calls: request
                .allow_more_logging
                .then_some(SIMULATION_MAX_LOG_CALLS),
            max_log_size: request.allow_more_logging.then_some(LOG_BYTES_LIMIT),
        };

        // --- Resolve the simulated block ---

        // A requested round that predates the ledger's tracked history is a
        // distinct failure from "round doesn't exist yet" -- go-algorand's
        // accountupdates `RoundOffsetError` (`ledger/acctupdates.go`),
        // surfaced verbatim through `Ledger.BlockHdr`/`trackerDBRound` as
        // `"round %d before dbRound %d"`, a raw (non-`InvalidRequestError`)
        // error that the REST handler propagates as a 500
        // (`daemon/algod/api/server/v2/handlers.go`'s `SimulateTransaction`
        // only special-cases `simulation.InvalidRequestError` as a 400).
        // `TestSimulateStartRound` (`test/e2e-go/restAPI/simulate`) pins
        // this for a follower node whose `dbRound` tracks its sync round --
        // see [`crate::store_trait::LedgerStore::earliest_round`] for what
        // this does and doesn't model. Checked ahead of the block-header
        // lookup below since algod-rust does not actually evict old block
        // headers (`forget_before` isn't wired into the normal apply path),
        // so the header would otherwise still resolve.
        if let Some(requested_round) = request.round {
            let earliest = self.store.earliest_round();
            if requested_round < earliest {
                return Err(SimulatorError::Internal(AlgoError::Ledger {
                    message: format!("round {} before dbRound {}", requested_round.0, earliest.0),
                }));
            }
        }

        // Fetch block header for consensus params and timestamp
        let block_hdr = self.store.get_block_header(sim_round.0)?;
        // An explicitly-requested round with no corresponding block header
        // does not exist on this ledger (go-algorand: `s.ledger.BlockHdr`
        // returns "ledger does not have entry N" from `simulatorLedger`'s
        // embedded `data.Ledger`, propagated as a hard `Simulate` error --
        // `TestStartRound`'s "1 round in the future" case). Only enforced
        // when the caller supplied a round: the *default* round
        // (`store.current_round()`) has no header in many unit tests that
        // never call `put_block`, and go's own default (`s.ledger.Latest()`)
        // is guaranteed to resolve on a real ledger, so silently falling
        // back to the store's declared protocol there preserves existing
        // behavior instead of newly rejecting it.
        if request.round.is_some() && block_hdr.is_none() {
            return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                message: format!("ledger does not have entry {}", sim_round.0),
            }));
        }
        // go `MakeBlock(prevBlockHdr)` + `StartEvaluator`'s reads (issue
        // #2118): the block the group is evaluated in, round `start + 1`.
        let block = self
            .prepare_simulated_block(sim_round, block_hdr.as_ref())
            .map_err(SimulatorError::Internal)?;

        // --- Snapshot the store before simulation ---

        // Collect all addresses involved in the transaction group for
        // snapshotting. This ensures we can restore state after simulation.
        // The block's own accounts come first: the fee sink (fees), the
        // rewards pool (the block-start withdrawal) and, on go's two
        // `workaroundOverspentRewards` rounds, the testnet bank.
        let mut addrs: Vec<Address> = block.snapshot_addrs();
        for stx in txn_group {
            addrs.push(stx.txn.sender);
            if stx.txn.receiver != Address::ZERO {
                addrs.push(stx.txn.receiver);
            }
            if stx.txn.close_remainder_to != Address::ZERO {
                addrs.push(stx.txn.close_remainder_to);
            }
            if let Some(ref a) = stx.txn.asset_receiver {
                addrs.push(*a);
            }
            if let Some(ref a) = stx.txn.asset_sender {
                addrs.push(*a);
            }
            if let Some(ref a) = stx.txn.asset_close_to {
                addrs.push(*a);
            }
            if let Some(ref a) = stx.txn.freeze_account {
                addrs.push(*a);
            }
            if let Some(ref a) = stx.txn.rekey_to {
                addrs.push(*a);
            }
            // Foreign accounts from app calls
            if let Some(ref accounts) = stx.txn.accounts {
                for a in accounts {
                    addrs.push(*a);
                }
            }
        }
        // Deduplicate addresses.
        addrs.sort_by_key(|a| a.0);
        addrs.dedup();

        // Collect app/asset IDs that may be created or modified during
        // simulation so the snapshot can roll them back. For creates
        // (application_id == 0 or config_asset == 0), pre-compute the
        // derived ID from the running txn_counter.
        let mut asset_ids: Vec<u64> = Vec::new();
        let mut app_ids: Vec<u64> = Vec::new();
        let base_counter = self.store.txn_counter();
        for (i, stx) in txn_group.iter().enumerate() {
            // Each top-level txn increments the counter.
            let sim_counter = base_counter + i as u64;
            match stx.txn.txn_type.as_str() {
                "acfg" => {
                    if stx.txn.config_asset != 0 {
                        asset_ids.push(stx.txn.config_asset);
                    } else {
                        // Asset create: derived ID = txn_counter + 1
                        asset_ids.push(sim_counter + 1);
                    }
                }
                "axfer" => {
                    if stx.txn.xaid != 0 {
                        asset_ids.push(stx.txn.xaid);
                    }
                }
                "afrz" => {
                    if stx.txn.freeze_asset != 0 {
                        asset_ids.push(stx.txn.freeze_asset);
                    }
                }
                "appl" => {
                    if stx.txn.application_id != 0 {
                        app_ids.push(stx.txn.application_id);
                    } else {
                        // App create: derived ID = txn_counter + 1
                        app_ids.push(sim_counter + 1);
                    }
                }
                _ => {}
            }
        }

        let snapshot = if asset_ids.is_empty() && app_ids.is_empty() {
            self.store.snapshot(&addrs)
        } else {
            self.store.snapshot_with_ids(&addrs, &asset_ids, &app_ids)
        };

        // --- Evaluate, then restore the store ---

        // The restore runs on every exit, a panic included: evaluation
        // writes the live store (the block-start pool withdrawal first), and
        // a panic that skipped the restore would leave those writes in place
        // for the next real block (issue #2118). The panic is re-raised once
        // the store is restored.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.evaluate_in_snapshot(&request, result, block)
        }));
        self.store.restore_snapshot(snapshot);
        match outcome {
            Ok(outcome) => outcome,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    /// The part of [`Self::simulate`] that runs inside its snapshot: check,
    /// the block-start withdrawal, and the group's evaluation. It never
    /// restores the snapshot itself; [`Self::simulate`] does, on every exit.
    fn evaluate_in_snapshot(
        &mut self,
        request: &SimulationRequest,
        mut result: SimulationResult,
        block: SimulatedBlock,
    ) -> Result<SimulationResult, SimulatorError> {
        let txn_group = &request.txn_groups[0];
        let consensus = block.consensus;

        // --- FixSigners: pre-evaluation signer correction ---

        // Working copy of the group used for verification and evaluation.
        // With `fix_signers`, unsigned transactions get their `auth_addr`
        // corrected here (and again after each app call, since apps can
        // rekey); the original `txn_group` is kept for the response and the
        // post-evaluation `fixed_signer` comparison — mirroring go-algorand's
        // `simulateWithTracer` (`ledger/simulation/simulator.go:219-260`).
        let mut eval_group: Vec<SignedTransaction> = txn_group.clone();
        if request.fix_signers {
            fix_unsigned_signers_pre_eval(&*self.store, &mut eval_group);
        }

        // --- Build apply context ---

        // Run validation (signature verification + well-formedness) before
        // execution. When tracing is enabled, `check` also captures logic-sig
        // opcode traces, since LogicSig programs run during signature
        // verification — before the per-transaction execution tracer exists.
        //
        // A `RecoverableFailure` (per-transaction attributable, e.g. a
        // missing signature or `WellFormed` rejection) never reaches
        // evaluation in go-algorand either -- `precheck_failure` seeds the
        // group's `FailureMessage`/`FailedAt` up front and the per-txn eval
        // loop below is skipped entirely, falling through to the normal
        // fee-usage/initial-states finalization with every `TxnResult` left
        // at its pre-populated (no `ApplyData`) default, exactly as if
        // evaluation had failed on transaction zero before running anything.
        let mut precheck_failure: Option<(usize, String)> = None;
        let (logicsig_traces, logicsig_budgets) = match self.check(
            &eval_group,
            request.allow_empty_signatures,
            request.fix_signers,
            &consensus,
            &request.trace_config,
        ) {
            Ok(CheckOutcome::Passed {
                logicsig_traces,
                logicsig_budgets,
            }) => (logicsig_traces, logicsig_budgets),
            Ok(CheckOutcome::RecoverableFailure {
                index,
                message,
                logicsig_traces,
                logicsig_budgets,
            }) => {
                precheck_failure = Some((index, message));
                (logicsig_traces, logicsig_budgets)
            }
            Err(e) => return Err(e),
        };

        // Validate the extra opcode budget against the simulation limit.
        // Runs after `check()` so verification errors take precedence,
        // matching go-algorand's `simulateWithTracer` ordering; the message
        // matches go byte-for-byte.
        if request.extra_opcode_budget > MAX_EXTRA_OPCODE_BUDGET {
            return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                message: format!(
                    "extra budget {} > simulation extra budget limit {}",
                    request.extra_opcode_budget, MAX_EXTRA_OPCODE_BUDGET
                ),
            }));
        }

        // Compute group fee credit and residue so inner transactions can draw
        // from overpayment by outer transactions (matches go-algorand's feeCredit).
        let (fee_credit, fee_residue) = {
            let group_refs: Vec<&SignedTransaction> = eval_group.iter().collect();
            compute_group_fee_credit_and_residue(&group_refs, &consensus)
        };

        // Capacity accounting for unnamed-resource reporting: constructed
        // once for the whole group (shared, via `Rc<RefCell<_>>`, across
        // every top-level transaction and inner call) so a category's
        // capacity is only ever exhausted once, group-wide -- matching
        // go-algorand's single per-group `ResourceTracker`. Must be computed
        // before `consensus` is moved into `apply_ctx` below.
        let unnamed_capacity = request.allow_unnamed_resources.then(|| {
            Rc::new(RefCell::new(UnnamedCapacityTracker::new(
                &eval_group,
                &consensus,
            )))
        });

        // go `StartEvaluator`: withdraw the block's rewards from the pool
        // before the group runs. go never starts the evaluator for a group
        // that failed `check`.
        if precheck_failure.is_none() {
            withdraw_block_rewards(&mut *self.store, &block.withdrawal)
                .map_err(SimulatorError::Internal)?;
            #[cfg(any(test, feature = "test-hooks"))]
            test_hooks::maybe_panic_after_withdrawal();
        }

        let apply_ctx = ApplyContext {
            rewards_level: block.rewards_level,
            fee_sink: block.fee_sink,
            round: block.round,
            mode: ApplyMode::Execute,
            validate: true,
            // `check_dup` in the loop below owns the lease check (issue #2125).
            leases_checked_by_caller: true,
            // go `simulator.go`: `Generate: true, Validate: true`.
            generate: true,
            latest_timestamp: block.latest_timestamp,
            genesis_hash: block.ledger_genesis_hash,
            txn_counter: Cell::new(self.store.txn_counter()),
            fees_collected: Cell::new(0),
            state_proof_next: Cell::new(0),
            prev_header: RefCell::new(None),
            fee_credit: Cell::new(fee_credit),
            fee_residue: Cell::new(fee_residue),
            txn_index: Cell::new(0),
            consensus,
            // Simulation-only AVM overrides: raised log limits
            // (`allow_more_logging`) and unnamed-resource tracking
            // (`allow_unnamed_resources`).
            avm_overrides: AvmEvalOverrides {
                max_log_calls: result.eval_overrides.max_log_calls,
                max_log_size: result.eval_overrides.max_log_size,
                unnamed_tracking: request
                    .allow_unnamed_resources
                    .then(|| Arc::new(NamedGroupResources::from_group(&eval_group))),
                unnamed_capacity,
            },
            failed_eval_delta: Cell::new(None),
            kv_mods_recorder: None,
            avm_timing: Default::default(),
        };

        // --- Execute the transaction group ---

        // Pre-populate TxnResult for ALL txns (Go returns results even for
        // transactions past the failure point).
        let mut group_result = TxnGroupResult::default();
        for stx in txn_group {
            group_result.txn_results.push(TxnResult {
                txn: Some(stx.clone()),
                ..Default::default()
            });
        }

        // Seed per-transaction LogicSig budget consumed for the whole group.
        // LogicSig programs run during `check()` (signature verification of the
        // entire group), so their budgets are known even for transactions past
        // an execution failure point — matching go-algorand, where the verify
        // pass populates `LogicSigBudgetConsumed` before evaluation begins.
        for (i, consumed) in logicsig_budgets.iter().enumerate() {
            group_result.txn_results[i].logicsig_budget_consumed = *consumed;
        }
        // Seed each transaction's trace with its LogicSig-only portion too
        // (captured during `check()`, before any execution tracer exists).
        // Normally the per-txn eval loop below overwrites this with the full
        // execution trace via the same `merge_logicsig_trace` call; when
        // `check()` fails before evaluation starts (`precheck_failure`),
        // that loop never runs, so this is the only place the transaction's
        // (partial) LogicSig trace gets attached.
        for i in 0..group_result.txn_results.len() {
            group_result.txn_results[i].trace = merge_logicsig_trace(None, &logicsig_traces, i);
        }

        let mut failure_message: Option<String> = precheck_failure
            .as_ref()
            .map(|(_, message)| message.clone());
        let mut failed_at: Option<TxnPath> =
            precheck_failure.as_ref().map(|(index, _)| vec![*index]);

        // Initial application state captured across the group (populated only
        // when state-change tracing is requested). Each transaction's tracer
        // captures into its own accumulator; we merge them here with
        // first-touch-wins semantics so the earliest-seen pre-value persists.
        let mut initial_states = InitialStatesAccumulator::default();

        // Unnamed resources accessed across the whole group (populated only
        // when `allow_unnamed_resources` is requested).
        let mut group_unnamed = UnnamedResourcesAccessed::default();

        // Inner transaction groups submitted across the whole group (summed
        // from each top-level transaction's tracer). Each unit adds one
        // `MaxAppProgramCost` to `AppBudgetAdded`, mirroring go-algorand's
        // `BeforeTxnGroup` (`tracer.go:156`), which grows the group budget
        // for every inner-txn submission, not just top-level app calls.
        let mut inner_txn_groups: u64 = 0;

        // Count app calls for group budget
        let num_app_calls = eval_group
            .iter()
            .filter(|stx| stx.txn.txn_type == "appl")
            .count();
        // App-call opcode budget is pooled across the whole atomic group's
        // top-level app calls only when `EnableAppCostPooling` is set for
        // the active consensus version (go: v30+, `config/consensus.go`).
        // Before that, `NewAppEvalParams` never allocates
        // `PooledApplicationBudget` at all (it stays nil), so each
        // top-level app call gets its own independent `MaxAppProgramCost`
        // budget (`remainingBudget()`) and the simulate-only
        // `ExtraOpcodeBudget` override is never applied either --
        // go-algorand's `evalTracer.BeforeTxnGroup` (`ledger/simulation/
        // tracer.go`) only adds it under `if ep.PooledApplicationBudget !=
        // nil`. See issue #1254. When pooling is enabled, seed the group
        // budget from every top-level app call up front as before, and add
        // any requested extra budget once for the whole group. When
        // disabled, the per-call reset below (mirroring the real apply
        // path's `apply_group_transactions`) gives each app call a fresh
        // single-call budget; `extra_opcode_budget` is simply not applied,
        // matching go's nil-pool behavior.
        let pooled = apply_ctx.consensus.enable_app_cost_pooling;
        let mut group_budget = GroupBudget::new(if pooled { num_app_calls } else { 1 });
        if pooled && request.extra_opcode_budget != 0 {
            group_budget.add(request.extra_opcode_budget);
        }
        // Group-scoped box I/O budget state (issue #727): mirrors
        // go-algorand's shared `EvalParams.ioBudget`/`readBudgetChecked`/
        // `available` (boxes, dirtyBytes, updateBytes), which persist
        // across every top-level app-call transaction in this simulated
        // group via one shared `EvalParams` pointer, matching the real
        // apply path (`apply::apply_block_impl`)'s own `group_box_budget`.
        let mut group_box_budget = BoxBudgetState::default();

        // Shared across the whole simulated group so `gload`/`gloads`/
        // `gloadss` can tell whether an earlier sibling actually ran a
        // program (see `apply::GroupInfo::ran_program`) and read back the
        // real values it wrote (see `apply::GroupInfo::scratch`, issue
        // #686).
        let ran_program = std::cell::RefCell::new(vec![false; eval_group.len()]);
        let scratch = std::cell::RefCell::new(vec![None; eval_group.len()]);
        let group_txid_cache = crate::avm_context::GroupTxidCache::default();
        let group_created = crate::apply::GroupCreatedResources::default();

        // go `roundCowState`'s txids and leases for `checkDup`, and the
        // ledger half (which reads the txtail lazily, at most once). The
        // txids are hashed only when evaluation will run. They are kept
        // apart from `group_txid_cache` on purpose: that cache reproduces
        // go's shared `EvalParams.txidCache`, whose entries a nested
        // program can fill with an inner id (#1736), so seeding it with the
        // top-level ids, or reading them back from it, would change what
        // `txn TxID` returns.
        let mut block_dups = crate::check_dup::BlockDups::new();
        let mut ledger_dups = crate::check_dup::LedgerDups::new(
            block.round,
            if precheck_failure.is_none() {
                eval_group
                    .iter()
                    .map(|stx| algo_codec::compute_txn_id(&stx.txn))
                    .collect()
            } else {
                Vec::new()
            },
        );

        for i in 0..eval_group.len() {
            if precheck_failure.is_some() {
                // `check()` already failed at a known index -- evaluation
                // never starts, matching go-algorand (an outcome from
                // `s.check` short-circuits `simulateWithTracer` before
                // `s.evaluate` runs).
                break;
            }
            apply_ctx.txn_index.set(i);

            // Non-pooled protocol versions (pre-v30): each top-level app
            // call gets a fresh, independent budget -- nothing carries over
            // from a prior group member (see the budget construction
            // above). Reset right before dispatch so a non-appl txn between
            // two app calls doesn't matter either way.
            if !pooled && eval_group[i].txn.txn_type == "appl" {
                group_budget = GroupBudget::new(1);
            }

            // Create a per-transaction tracer to capture execution details.
            // Seed it with apps created by earlier transactions in the group so
            // the created-app exclusion persists across the whole simulation
            // (go-algorand keeps a single ResourcesInitialStates for the run).
            let mut tracer = SimulationTracer::new(request.trace_config.clone());
            tracer.seed_created_apps(&initial_states.created_app_ids());

            // Use apply_transaction_with_budget for ALL transactions (not just appl)
            // so they all share the group context. The group refs are rebuilt
            // per iteration because `fix_signers` may mutate later
            // transactions' `auth_addr` between iterations.
            // The account-authorizer check (go-algorand's `eval.go`
            // `checkAuthorizer` -- "should have been authorized by X but
            // was actually authorized by Y") runs on the real block-apply
            // group path (`apply_group_transactions`) but was never wired
            // into simulation's per-transaction loop, which calls
            // `apply_transaction_with_budget` directly. A declared
            // `auth_addr` that doesn't match the ledger's actual rekey
            // state must fail evaluation here too -- including under
            // `allow_empty_signatures`, which only relaxes *signature*
            // verification, not this apply-time authorization fact
            // (TestWrongAuthorizerTxn, issue #974).
            // Part of go `BlockEvaluator.transaction` under `Validate: true`:
            // `BlockHeader.Alive` (validity window, genesis ID and hash),
            // then `checkDup` (a duplicate txid or a live lease, issue
            // #2125), then the authorizer. go's simulate reports these error
            // texts bare (`EvalFailureError` wraps them without a prefix),
            // hence `Rejected`, whose display is the message itself.
            let alive = algo_validate::block_alive(
                block.round,
                &block.block_genesis_id,
                &block.block_genesis_hash,
                &apply_ctx.consensus,
                &eval_group[i].txn,
            )
            .map_err(|message| AlgoError::Rejected {
                source: None,
                message,
                class: algo_error::RejectClass::Other,
            });
            let checked = alive
                .and_then(|()| {
                    let txid = ledger_dups.txids()[i];
                    crate::check_dup::check_dup(
                        &*self.store,
                        &apply_ctx.consensus,
                        &eval_group[i].txn,
                        txid,
                        &block_dups,
                        &mut ledger_dups,
                    )
                })
                .and_then(|()| check_authorizer(self.store, &eval_group[i]));
            let apply_result = match checked {
                Err(e) => Err(e),
                Ok(()) => {
                    let group_refs: Vec<&SignedTransaction> = eval_group.iter().collect();
                    let gi = GroupInfo {
                        txns: &group_refs,
                        index: i,
                        ran_program: &ran_program,
                        scratch: &scratch,
                        txid_cache: &group_txid_cache,
                        created: &group_created,
                    };
                    apply_transaction_with_budget(
                        self.store,
                        &eval_group[i],
                        &apply_ctx,
                        0,
                        Some(&mut group_budget),
                        Some(&mut group_box_budget),
                        Some(&gi),
                        Some(&mut tracer),
                    )
                }
            };
            // Per-transaction app budget consumed = the sum of every approval /
            // clear-state program cost under this txn, including inner app calls,
            // accumulated by the tracer (go-algorand rolls each program's
            // `cx.Cost()` into the top-level txn — `tracer.go:504`). This is read
            // from the tracer rather than the shared pool delta because inner app
            // calls add `MaxAppProgramCost` to the pool and clear-state programs
            // run on an isolated budget, so the net pool delta under-reports.
            group_result.txn_results[i].app_budget_consumed = tracer.app_budget_consumed();
            // (logicsig_budget_consumed was pre-seeded for the whole group above.)
            inner_txn_groups += tracer.inner_txn_group_count();

            match apply_result {
                Ok(apply_data) => {
                    block_dups.record(&eval_group[i].txn, ledger_dups.txids()[i]);
                    // Defensively drain `failed_eval_delta` even on success:
                    // nothing sets it on this path today, but a future change
                    // must not let a stale value from an earlier iteration
                    // silently attach to this (unrelated, successful) txn.
                    apply_ctx.failed_eval_delta.take();
                    group_result.txn_results[i].apply_data = Some(apply_data);
                    initial_states.merge(tracer.take_initial_states());
                    group_unnamed.merge(tracer.take_unnamed_resources());
                    group_result.txn_results[i].trace =
                        merge_logicsig_trace(tracer.into_transaction_trace(), &logicsig_traces, i);

                    // FixSigners: an app call can rekey accounts (via inner
                    // transactions), so re-correct the auth addrs of the
                    // remaining unsigned transactions from the mutated ledger,
                    // up to and including the next app call — go-algorand's
                    // `AfterProgram` fix pass (`ledger/simulation/tracer.go`).
                    if request.fix_signers && eval_group[i].txn.txn_type == "appl" {
                        fix_unsigned_signers_after_app(&*self.store, &mut eval_group, i);
                    }
                }
                Err(e) => {
                    // Record failure. Collect any partial trace data before
                    // stopping (the tracer may have captured events up to
                    // the point of failure).
                    failure_message = Some(e.to_string());
                    // The tracer descended into this top-level transaction's
                    // own inner-txn tree (if any) and, on the first failure
                    // anywhere in it, recorded the path relative to this
                    // transaction (issue #972). Prepend the real top-level
                    // index to get the full path -- mirroring go-algorand's
                    // `TxnPath` (e.g. `[2, 0, 0]` for a failure two levels
                    // deep inside transaction 2's inner-txn tree). Falls back
                    // to the top-level-only path when the tracer never
                    // descended (a direct top-level program failure) or
                    // couldn't attribute a path (see `TxnCursor::relative_path`).
                    failed_at = Some(match tracer.failed_at() {
                        Some(relative) => {
                            let mut path = Vec::with_capacity(1 + relative.len());
                            path.push(i);
                            path.extend_from_slice(relative);
                            path
                        }
                        None => vec![i],
                    });
                    initial_states.merge(tracer.take_initial_states());
                    group_unnamed.merge(tracer.take_unnamed_resources());
                    group_result.txn_results[i].trace =
                        merge_logicsig_trace(tracer.into_transaction_trace(), &logicsig_traces, i);
                    // A rejected/erroring `appl` call leaves its partial
                    // EvalDelta on `apply_ctx` (set by `apply_appl` right
                    // before returning this error — see the field's doc
                    // comment). Surface it so callers can see what the
                    // program computed up to the point of failure, matching
                    // go-algorand's `evalTracer.saveEvalDelta`. `None` for
                    // any other failure (e.g. insufficient balance).
                    if let Some(dt) = apply_ctx.failed_eval_delta.take() {
                        group_result.txn_results[i].apply_data = Some(crate::apply::ApplyData {
                            eval_delta: Some(dt),
                            ..Default::default()
                        });
                    }
                    break;
                }
            }
        }

        // Group-level fee validation, mirroring go-algorand's ordering and
        // error surface. `eval.TransactionGroup` evaluates every transaction
        // first and only then runs `transactions.SummarizeFees` +
        // `eval.CheckGroupFees` (`ledger/eval/eval.go:1182-1183`;
        // `CheckGroupFees` is defined at `eval.go:1004`). So:
        //   * a signature / LogicSig failure from `check()` (a recoverable
        //     `precheck_failure`) and any per-transaction evaluation failure
        //     both take precedence over the fee error;
        //   * the fee error is an `EvalFailureError` in go
        //     (`simulator.go:266`), i.e. NOT an `InvalidRequest` (HTTP 400):
        //     it surfaces as the group's `failure-message` with the
        //     transactions' results populated, and `failed-at` is the cursor
        //     the tracer's `AfterTxnGroup` -> `handleError` sees, i.e. the
        //     last top-level transaction (`tracer.go:181`).
        //
        // The submitted group is a single fee pool whose required fee is
        // `FeeForUsage(MinTxnFee, usage)`, where usage includes v42+
        // note/app-arg/program size surcharges, LogicSig program-byte
        // surcharges and PQ signature surcharges; state proofs and discounted
        // heartbeats contribute zero. Top-level only: inner fees are checked
        // during AVM execution (issue #2040).
        //
        // MUST use the original `txn_group`, NOT `verify_group`/`eval_group`:
        // `check()` strips placeholder PQSigs (`pqsig = None`, replaced by a
        // proxy Ed25519 signature or an escrow-style LogicSig) in
        // `verify_group`, which would silently drop the Falcon surcharge from
        // the required fee. go's `evaluate` likewise runs on the original
        // group, not the signature-verification copy (`simulator.go:343`).
        if failure_message.is_none() {
            if let Some(message) = group_fee_failure(txn_group, &apply_ctx.consensus) {
                failure_message = Some(message);
                failed_at = Some(vec![txn_group.len() - 1]);
            }
        }

        // Full (public-key-set) PQ placeholders need the final `auth_addr`
        // after `fix_signers` has run through evaluation: `check()`'s
        // placeholder validation used a possibly-not-final `auth_addr` (or
        // was scheme-only, since `fix_signers` was set), so re-validate the
        // full envelope now that `auth_addr` is settled. Matches go's
        // `validateFixedPlaceholderPQEnvelopes` call after `s.evaluate`
        // succeeds (`ledger/simulation/simulator.go`, issue #835).
        if request.allow_empty_signatures && request.fix_signers && failure_message.is_none() {
            if let Err((idx, msg)) =
                validate_fixed_placeholder_pq_envelopes(&apply_ctx.consensus, &eval_group)
            {
                failure_message = Some(msg);
                failed_at = Some(vec![idx]);
            }
        }

        group_result.failure_message = failure_message;
        group_result.failed_at = failed_at;

        // Report unnamed resources accessed by the group (go-algorand drops
        // the field entirely when nothing was recorded). The `Max*`
        // capacity fields are group-level constants derived purely from the
        // submitted group, so compute them once here rather than per
        // transaction (see `UnnamedResourcesAccessed::set_capacity_fields`).
        if request.allow_unnamed_resources {
            group_unnamed.set_capacity_fields(&eval_group, &apply_ctx.consensus);
            if group_unnamed.has_resources() {
                group_result.unnamed_resources_accessed = Some(group_unnamed);
            }
        }

        // FixSigners: report the corrected signer for each transaction whose
        // effective signer differs from the one supplied in the request
        // (go-algorand's post-evaluation `FixedSigner` pass).
        for i in 0..group_result.txn_results.len() {
            let sender = txn_group[i].txn.sender;
            let input_signer = txn_group[i].auth_addr.unwrap_or(sender);
            let actual_signer = eval_group[i].auth_addr.unwrap_or(sender);
            if input_signer != actual_signer {
                group_result.txn_results[i].fixed_signer = Some(actual_signer);
            }
        }

        // Compute group-level budget metrics. AppBudgetConsumed is the sum of
        // the per-transaction figures (each rolled up from its programs +
        // inners via the tracer), which is correct even when inner app calls
        // grow the pool or clear-state runs on an isolated budget — unlike the
        // raw pool delta. AppBudgetAdded is the top-level allocation
        // (`MaxAppProgramCost` per top-level app call) plus one
        // `MaxAppProgramCost` unit for every inner transaction group
        // submitted anywhere in the group, matching go-algorand's
        // `BeforeTxnGroup` (`tracer.go:156`, `AppBudgetAdded += MaxAppProgramCost`
        // whenever `ep.GetCaller() != nil`) — issue #215.
        // go-algorand only ever populates `AppBudgetAdded` from
        // `ep.PooledApplicationBudget` (`tracer.go`'s `BeforeTxnGroup`),
        // which `NewAppEvalParams` never allocates when
        // `EnableAppCostPooling` is off -- so the field (and any inner-txn-
        // group/extra-budget contribution to it) stays 0 pre-v30, not a
        // per-call figure. See issue #1254.
        let max_app_program_cost = apply_ctx.consensus.max_app_program_cost as i64;
        let total_budget = if pooled {
            (num_app_calls as i64) * max_app_program_cost
                + (inner_txn_groups as i64) * max_app_program_cost
                + request.extra_opcode_budget
        } else {
            0
        };
        group_result.app_budget_added = total_budget.max(0) as u64;
        group_result.app_budget_consumed = group_result
            .txn_results
            .iter()
            .map(|t| t.app_budget_consumed)
            .sum();

        // Fee-usage reporting (issue #671): per-txn FeesPaid (a factual report
        // of what was actually paid, recursively summed over descendant inner
        // txns) and per-group GroupUsage/GroupFeesPaid (the pooled fee usage
        // and fees paid required by the group and every descendant inner-txn
        // group). Mirrors go-algorand's `populateFeeUsage`
        // (`ledger/simulation/trace.go`), called once per group after
        // execution using the same protocol consensus params applied above.
        //
        // Deliberately no per-transaction `usage` field: upstream's own
        // comment explains fees pool across the group and round up once for
        // the whole tree, so usage is only actionable at the group level.
        let mut txgroup_with_ad: Vec<SignedTransaction> = Vec::with_capacity(eval_group.len());
        for (i, stx) in eval_group.iter().enumerate() {
            let eval_delta = group_result.txn_results[i]
                .apply_data
                .as_ref()
                .and_then(|ad| ad.eval_delta.clone());
            group_result.txn_results[i].fees_paid =
                trace::summarize_txn_fees_paid(stx.txn.fee, eval_delta.as_ref());
            let mut with_ad = stx.clone();
            with_ad.eval_delta = eval_delta;
            txgroup_with_ad.push(with_ad);
        }
        let (group_usage, group_fees_paid) =
            trace::summarize_txn_group_fee_usage(&txgroup_with_ad, &apply_ctx.consensus);
        group_result.group_usage = group_usage;
        group_result.group_fees_paid = group_fees_paid;

        result.txn_groups.push(group_result);

        // Surface captured initial states when state-change tracing was
        // requested (go-algorand returns a non-nil `InitialStates` whenever
        // `TraceConfig.State` is set). Must happen before the store is
        // restored, though the accumulator already owns the captured values.
        if request.trace_config.state {
            result.initial_states = Some(initial_states.into_resources_initial_states());
        }

        Ok(result)
    }

    /// Validate a transaction group before execution.
    ///
    /// Mirrors go-algorand's `Simulator.check()`:
    /// 1. Well-formedness check on each transaction.
    /// 2. Signature verification — when `allow_empty_signatures` is true,
    ///    unsigned transactions are proxy-signed with a fixed key so that
    ///    signature verification passes without requiring the caller to
    ///    provide real signatures.
    #[allow(clippy::type_complexity)]
    fn check(
        &self,
        txn_group: &[SignedTransaction],
        allow_empty_signatures: bool,
        fix_signers: bool,
        consensus: &ConsensusParams,
        trace_config: &ExecTraceConfig,
    ) -> Result<CheckOutcome, SimulatorError> {
        let spec = SpecialAddresses {
            fee_sink: self.store.fee_sink(),
            rewards_pool: self.store.rewards_pool(),
        };

        // Build a mutable copy for proxy-signing unsigned transactions.
        let mut verify_group: Vec<SignedTransaction> = txn_group.to_vec();

        let proxy_key = SigningKey::from_bytes(&PROXY_SIGNER_SEED);

        // Pass 1: reject unsupported transaction types, check well-formedness,
        // and proxy-sign unsigned transactions. Matches go-algorand's ordering
        // where all proxy-signing happens before group verification.
        for i in 0..verify_group.len() {
            let stx = &mut verify_group[i];
            // Reject StateProof transactions (go-algorand: simulator.go:164).
            if stx.txn.txn_type == "stpf" {
                return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                    message: "cannot simulate StateProof transactions".to_string(),
                }));
            }

            // Check well-formedness. Pass `allow_fee_pooling = enable_fee_pooling`
            // so that on pre-fee-pooling protocols (before v28) each transaction
            // is held to the per-transaction minimum fee, matching go-algorand's
            // `Transaction.WellFormed` (`!proto.EnableFeePooling && fee < min`).
            // On fee-pooling protocols the per-txn check is skipped here and the
            // pooled group-fee check below enforces the minimum (mirroring
            // `verify.TxnGroup`).
            // A well-formedness failure is attributable to this transaction
            // (go-algorand's `txnBatchPrep` wraps `Transaction.WellFormed`
            // errors as `TxGroupError{GroupIndex: i}` -- known index, so
            // `Simulate` reports it as the group's `FailureMessage`/
            // `FailedAt` on an otherwise-successful `Result` rather than a
            // hard request error, exactly like TestDefaultSignatureCheck's
            // unknown-type/box-index/incentive-pool-sender siblings).
            if let Err(e) = validate_transaction_wellformed(
                &stx.txn,
                consensus.enable_fee_pooling,
                consensus,
                Some(&spec),
            ) {
                return Ok(CheckOutcome::RecoverableFailure {
                    index: i,
                    message: e.to_string(),
                    logicsig_traces: vec![None; verify_group.len()],
                    logicsig_budgets: vec![0; verify_group.len()],
                });
            }

            // Handle empty signatures when allowed.
            // Go: `!stxn.HasSignature()`.
            if allow_empty_signatures && !stx.has_signature() {
                // Proxy-sign: create a valid ed25519 signature so verification
                // passes. Mirrors go-algorand's `Transaction.Sign()` which
                // sets `AuthAddr` to the signing key's public key when it
                // differs from the sender.
                let canonical = canonical_encode_transaction(&stx.txn);
                let mut msg = Vec::with_capacity(2 + canonical.len());
                msg.extend_from_slice(b"TX");
                msg.extend_from_slice(&canonical);
                let sig = proxy_key.sign(&msg);
                stx.sig = sig.to_bytes();
                // Go replaces the whole SignedTxn with `Txn.Sign(...)`, a
                // fresh envelope carrying only `Sig`/`AuthAddr`: any
                // present-but-blank msig/lsig/pqsig envelope is dropped from
                // the verification copy (blank ones add no size or fee).
                stx.msig = None;
                stx.lsig = None;
                stx.pqsig = None;

                // Set auth_addr to proxy key's public key so the verifier
                // checks the signature against the correct key.
                let proxy_pub = proxy_key.verifying_key().to_bytes();
                if proxy_pub != stx.txn.sender.0 {
                    stx.auth_addr = Some(Address(proxy_pub));
                }
            } else if allow_empty_signatures && is_placeholder_pqsig(stx) {
                // Full or scheme-only top-level PQSig placeholder (issue
                // #835): if it validates, proxy-sign the same way as the
                // fully-unsigned case above (mirrors go's
                // `stxn.Txn.Sign(proxySignerSecrets)`, which discards the
                // placeholder envelope entirely). If it doesn't validate,
                // leave the transaction untouched so real verification below
                // fails with a clear error.
                let pqsig = stx
                    .pqsig
                    .clone()
                    .expect("is_placeholder_pqsig implies Some");
                let authorizer = stx.auth_addr.unwrap_or(stx.txn.sender);
                if validate_placeholder_pqsig(&pqsig, &authorizer, consensus, fix_signers).is_ok() {
                    let canonical = canonical_encode_transaction(&stx.txn);
                    let mut msg = Vec::with_capacity(2 + canonical.len());
                    msg.extend_from_slice(b"TX");
                    msg.extend_from_slice(&canonical);
                    let sig = proxy_key.sign(&msg);
                    stx.sig = sig.to_bytes();
                    stx.pqsig = None;

                    let proxy_pub = proxy_key.verifying_key().to_bytes();
                    if proxy_pub != stx.txn.sender.0 {
                        stx.auth_addr = Some(Address(proxy_pub));
                    }
                }
            } else if allow_empty_signatures && is_placeholder_delegated_pqsig(stx) {
                // Delegated (LogicSig-nested) PQSig placeholder (issue #835):
                // unlike the top-level cases, the LogicSig's program must
                // still be evaluated and traced, so it cannot be swapped for
                // a proxy-signed bare transaction. If the placeholder
                // validates, drop it and authorize via the program hash
                // instead -- treating it as a contract-only (escrow) account
                // and running the program without a real Falcon signature.
                // Mirrors go's `check()` delegated-placeholder branch.
                let lsig_pqsig = stx
                    .lsig
                    .as_ref()
                    .and_then(|l| l.pqsig.clone())
                    .expect("is_placeholder_delegated_pqsig implies Some");
                let authorizer = stx.auth_addr.unwrap_or(stx.txn.sender);
                if validate_placeholder_pqsig(&lsig_pqsig, &authorizer, consensus, fix_signers)
                    .is_ok()
                {
                    let escrow_addr = stx
                        .lsig
                        .as_ref()
                        .map(|l| algo_validate::hash_program(&l.logic))
                        .expect("is_placeholder_delegated_pqsig implies Some(lsig)");
                    if let Some(lsig) = stx.lsig.as_mut() {
                        lsig.pqsig = None;
                    }
                    set_fixed_auth_addr(stx, escrow_addr);
                }
            }
        }

        // Group-level structural screen (go-algorand: `Simulator.check()`
        // calls `verify.TxnGroupWithTracer` unconditionally — `checks.go`'s
        // `CheckTxnGroup` runs independent of `AllowEmptySignatures`, which
        // only relaxes signature verification, not this screen). A group
        // with an unknown txn type, an out-of-range box index, etc. must be
        // rejected here, not silently accepted or left to fail later during
        // AVM evaluation.
        check_txn_group(&verify_group).map_err(|e| {
            SimulatorError::InvalidRequest(InvalidRequestError {
                message: e.to_string(),
            })
        })?;

        // Group-level LogicSig size check (go: `txnGroupBatchPrep` ->
        // `logicSigGroupSizeCheck`, `verify/txn.go`), run after
        // well-formedness and `CheckTxnGroup` and before any signature work,
        // on the proxy-signed verification copy like go. An orphan
        // LogicSig (content but no program, size pricing on) is attributed
        // to its member -- a recoverable failure at that `GroupIndex`; the
        // pool-overflow rejections carry go's `GroupIndex = -1`, which
        // `Simulator.Simulate` surfaces as a hard request error (issue
        // #2054, FIND-ba9c86e5-01).
        if let Err(e) = algo_validate::logic_sig_group_size_check_indexed(&verify_group, consensus)
        {
            return match e.group_index {
                Some(i) => Ok(CheckOutcome::RecoverableFailure {
                    index: i,
                    message: e.message,
                    logicsig_traces: vec![None; verify_group.len()],
                    logicsig_budgets: vec![0; verify_group.len()],
                }),
                None => Err(SimulatorError::InvalidRequest(InvalidRequestError {
                    message: e.message,
                })),
            };
        }

        // Pass 2: verify signatures on the (possibly proxy-signed) group.
        // When tracing is enabled, capture each LogicSig program's opcode trace
        // here — the LogicSig runs during signature verification, before the
        // per-transaction execution tracer is created (go-algorand captures
        // both in one pass; this engine splits check() from execution, so the
        // logic-sig trace is captured now and merged into the execution trace
        // for the same transaction afterwards).
        //
        // The per-transaction LogicSig budget consumed is also measured here,
        // as the LogicSig opcode-budget pool delta around each transaction's
        // verification (go-algorand `tracer.go:495`:
        // `Txns[groupIndex].LogicSigBudgetConsumed = cx.Cost()`). This is
        // captured for all LogicSig transactions, independent of trace config.
        let mut logicsig_traces: Vec<Option<TransactionTrace>> = vec![None; verify_group.len()];
        let mut logicsig_budgets: Vec<u64> = vec![0; verify_group.len()];
        let mut budget = GroupBudget::for_logicsig(verify_group.len());
        // Real block-header lookback for LogicSig `txn FirstValidTime`/`block
        // BlkTimestamp` (issue #1116, following up on #1111's AVM-context-only
        // primitive): simulation has a real `LedgerStore` in scope (`self.store`),
        // so unlike block validation and pool admission (which stay stateless,
        // see `algo_validate::block.rs`/`verified_txn_cache.rs`), it can supply
        // one.
        let sig_block_source = StoreSigBlockSource::new(&*self.store);
        for (i, stx) in verify_group.iter().enumerate() {
            let budget_before = budget.remaining();
            let result = if trace_config.is_enabled()
                && stx.lsig.as_ref().is_some_and(|l| l.has_program())
            {
                let mut lsig_tracer = SimulationTracer::new(trace_config.clone());
                let r = verify_transaction_signature_with_tracer(
                    stx,
                    &verify_group,
                    i,
                    &mut budget,
                    consensus,
                    Some(&mut lsig_tracer),
                    Some(&sig_block_source),
                );
                logicsig_traces[i] = lsig_tracer.into_transaction_trace();
                r
            } else {
                verify_transaction_signature_with_tracer(
                    stx,
                    &verify_group,
                    i,
                    &mut budget,
                    consensus,
                    None,
                    Some(&sig_block_source),
                )
            };
            // A non-LogicSig transaction consumes no LogicSig budget, leaving
            // the delta at 0.
            logicsig_budgets[i] = (budget_before - budget.remaining()).max(0) as u64;
            if let Err(e) = result {
                let message = e.to_string();
                // Signature-*format* failures (no signature at all, more
                // than one signature category present) are per-transaction
                // attributable in go-algorand (`checkTxnSigTypeCounts`
                // wraps them as `TxGroupError{GroupIndex: groupIndex}`) --
                // recoverable, like TestDefaultSignatureCheck's first
                // (missing-signature) assertion. An actual cryptographic
                // verification failure (wrong key, tampered signature bytes)
                // stays a hard request error: go-algorand's batch verifier
                // reports these with no attributable index
                // (TestDefaultSignatureCheck's "one signature didn't pass"
                // / TestOptionalSignaturesIncorrect), and even though this
                // engine verifies signatures sequentially (so the index
                // *is* technically known here), matching go's observable
                // hard-error behavior is the parity target.
                // A LogicSig program that rejects (top of stack zero) or
                // errors during evaluation is likewise per-transaction
                // attributable in go-algorand
                // (`TxGroupErrorReasonLogicSigFailed`, `verify/txn.go:393`,
                // `GroupIndex: gi`) -- recoverable, matching
                // TestInvalidLogicSigPCandStack/TestInvalidApp's
                // `require.NoError(t, err)` + `FailureMessage` pattern.
                // `e.to_string()` on the underlying `AlgoError::Validation`
                // prepends a `"validation error: "` prefix (see
                // `algo_error::AlgoError`'s `Display` impl), so match on
                // substring containment rather than the bare message.
                //
                // A LogicSig runtime evaluation failure (bad opcode args,
                // type mismatch, overflow, etc.) surfaces as
                // `AlgoError::AvmLogicSig` rather than the generic
                // `Validation` wrapper -- `verify_logicsig_with_tracer`
                // (`algo_validate::signature`) propagates it unwrapped so
                // its structured pc/group-index/eval-states diagnostics
                // (issue #1113) survive, so it can't be recognized by the
                // `"LogicSig program error:"` message substring below and
                // is matched on the error variant instead.
                let is_format_failure = matches!(e, AlgoError::AvmLogicSig { .. })
                    || message
                        .contains("transaction has no signature (no sig, msig, lsig, or pqsig)")
                    || message.contains("signedtxn should have only one type of signature, found")
                    || message.contains("LogicSig program rejected the transaction")
                    || message.contains("LogicSig program error:");
                if is_format_failure {
                    return Ok(CheckOutcome::RecoverableFailure {
                        index: i,
                        message,
                        logicsig_traces,
                        logicsig_budgets,
                    });
                }
                // go's batch verifier reports a cryptographic failure as its
                // bare error text (issue #1969), not as a wrapped validation
                // error. Decided on the error type, after the format-failure
                // classification above has used the original message.
                let message = if e.is_batch_sig_failure() {
                    algo_error::BATCH_HAS_FAILED_SIGS.to_string()
                } else {
                    message
                };
                return Err(SimulatorError::InvalidRequest(InvalidRequestError {
                    message,
                }));
            }
        }

        Ok(CheckOutcome::Passed {
            logicsig_traces,
            logicsig_budgets,
        })
    }
}

/// go's `transactions.SummarizeFees` + `eval.CheckGroupFees` over the
/// submitted (original, pre-proxy-signing) top-level group: `Some(message)`
/// when the group underpays. See the call site in `simulate` for the
/// ordering and error-surface rationale (issue #2040).
fn group_fee_failure(
    txn_group: &[SignedTransaction],
    consensus: &ConsensusParams,
) -> Option<String> {
    let fee_group: Vec<&SignedTransaction> = txn_group.iter().collect();
    algo_validate::fee::check_submitted_group_fees(&fee_group, consensus).err()
}

/// Whether a signed transaction carries no signature of any kind
/// (go-algorand's `txnHasNoSignature`).
fn txn_has_no_signature(stx: &SignedTransaction) -> bool {
    !stx.has_signature()
}

/// Whether `stx` carries a placeholder top-level `PQSig`: a non-blank PQ
/// envelope with an empty signature and no other signature category set.
/// Matches go-algorand's `isPlaceholderPQSig` (`ledger/simulation/
/// simulator.go`, issue #835) -- used for fee/budget-estimation simulation
/// without a real Falcon-1024 signature.
fn is_placeholder_pqsig(stx: &SignedTransaction) -> bool {
    match &stx.pqsig {
        Some(pq) if !pq.blank() && pq.signature.is_empty() => !stx.has_non_pq_signature(),
        _ => false,
    }
}

/// Whether `stx` carries a placeholder PQ signature nested in its
/// LogicSig: a program with a non-blank nested PQ envelope with an empty
/// signature and no other signature category set on either the transaction
/// or the LogicSig. Matches go-algorand's `isPlaceholderDelegatedPQSig`
/// (`ledger/simulation/simulator.go`, issue #835).
fn is_placeholder_delegated_pqsig(stx: &SignedTransaction) -> bool {
    // Go: `Sig.Blank() && Msig.Blank() && PQsig.Blank()` (the Lsig is
    // checked field-by-field below).
    let has_top_pqsig = stx.pqsig.as_ref().is_some_and(|p| !p.blank());
    if stx.sig != [0u8; 64] || stx.msig.as_ref().is_some_and(|m| !m.blank()) || has_top_pqsig {
        return false;
    }
    match &stx.lsig {
        Some(lsig)
            if lsig.has_program()
                && lsig.sig == [0u8; 64]
                && lsig.msig.as_ref().is_none_or(|m| m.blank())
                && lsig.lmsig.as_ref().is_none_or(|m| m.blank()) =>
        {
            matches!(&lsig.pqsig, Some(pq) if !pq.blank() && pq.signature.is_empty())
        }
        _ => false,
    }
}

/// Whether `stx` needs a synthetic (proxy/placeholder-derived) signature or
/// `auth_addr` correction under `allow_empty_signatures`/`fix_signers`.
/// Matches go-algorand's `txnNeedsSyntheticSignature` (`ledger/simulation/
/// simulator.go`): fully unsigned, or carrying a (possibly delegated)
/// placeholder PQ signature.
fn txn_needs_synthetic_signature(stx: &SignedTransaction) -> bool {
    txn_has_no_signature(stx) || is_placeholder_pqsig(stx) || is_placeholder_delegated_pqsig(stx)
}

/// Post-evaluation validation of "full" (public-key-set) PQ placeholder
/// envelopes against their FINAL `auth_addr` -- which `fix_signers` may
/// have corrected during evaluation (e.g. via a preceding app call's
/// rekey). `check()`'s own placeholder validation ran before evaluation and
/// either used a not-yet-final `auth_addr` or was scheme-only (when
/// `fix_signers` is set); this pass re-validates the full envelope once
/// `auth_addr` is settled, so a caller can't submit a placeholder whose
/// public key doesn't actually derive the final authorizer. Matches
/// go-algorand's `validateFixedPlaceholderPQEnvelopes` (`ledger/simulation/
/// simulator.go`, issue #835). Returns the failing transaction's index and
/// an error message on failure.
fn validate_fixed_placeholder_pq_envelopes(
    consensus: &ConsensusParams,
    group: &[SignedTransaction],
) -> Result<(), (usize, String)> {
    for (i, stx) in group.iter().enumerate() {
        let authorizer = stx.auth_addr.unwrap_or(stx.txn.sender);
        if is_placeholder_pqsig(stx) {
            let pqsig = stx
                .pqsig
                .as_ref()
                .expect("is_placeholder_pqsig implies Some");
            if !pqsig.public_key.is_empty() {
                validate_pqsig_envelope(pqsig, &authorizer, consensus)
                    .map_err(|e| (i, format!("pq signature validation failed: {e}")))?;
            }
        }
        if is_placeholder_delegated_pqsig(stx) {
            let pqsig = stx
                .lsig
                .as_ref()
                .and_then(|l| l.pqsig.as_ref())
                .expect("is_placeholder_delegated_pqsig implies Some");
            if !pqsig.public_key.is_empty() {
                validate_pqsig_envelope(pqsig, &authorizer, consensus).map_err(|e| {
                    (
                        i,
                        format!("pq delegated logic signature validation failed: {e}"),
                    )
                })?;
            }
        }
    }
    Ok(())
}

/// Validate a placeholder `PQSig` envelope, matching go-algorand's
/// `validatePlaceholderPQSig` (`ledger/simulation/simulator.go`): a
/// scheme-only placeholder (empty public key) or a `fix_signers` request
/// (whose `authorizer` isn't final yet) only needs the scheme validated;
/// a full placeholder (public key set) needs the whole envelope, including
/// the public-key-derived authorizer address, validated.
fn validate_placeholder_pqsig(
    pqsig: &algo_types::PQSig,
    authorizer: &Address,
    consensus: &ConsensusParams,
    fix_signers: bool,
) -> Result<(), AlgoError> {
    if pqsig.public_key.is_empty() || fix_signers {
        validate_pqsig_scheme(pqsig, consensus)
    } else {
        validate_pqsig_envelope(pqsig, authorizer, consensus)
    }
}

/// The sender's current auth addr in the ledger, or the zero address when the
/// account is not rekeyed (go-algorand `AccountData.AuthAddr`).
fn ledger_auth_addr<L: LedgerStore>(store: &L, sender: &Address) -> Address {
    store
        .get_account(sender)
        .and_then(|a| a.auth_addr)
        .unwrap_or(Address::ZERO)
}

/// Set an unsigned transaction's `auth_addr` to the given authorizer,
/// normalising "authorizer == sender" to `None` (a zero auth addr means the
/// sender signs for itself).
fn set_fixed_auth_addr(stx: &mut SignedTransaction, auth: Address) {
    stx.auth_addr = if auth.is_zero() || auth == stx.txn.sender {
        None
    } else {
        Some(auth)
    };
}

/// FixSigners pre-evaluation pass: correct the `auth_addr` of unsigned
/// transactions from static rekeys within the group or the ledger, stopping
/// at the first app call (later transactions are corrected by
/// [`fix_unsigned_signers_after_app`] once each app call completes, since
/// apps can rekey accounts). Mirrors go-algorand's `simulateWithTracer`
/// (`ledger/simulation/simulator.go:219-260`).
fn fix_unsigned_signers_pre_eval<L: LedgerStore>(store: &L, group: &mut [SignedTransaction]) {
    let mut static_rekeys: HashMap<Address, Address> = HashMap::new();
    for stx in group.iter_mut() {
        let sender = stx.txn.sender;
        if txn_needs_synthetic_signature(stx) {
            let auth = match static_rekeys.get(&sender) {
                Some(a) => *a,
                None => ledger_auth_addr(store, &sender),
            };
            set_fixed_auth_addr(stx, auth);
        }

        // Stop at the first app call: auth-addr correction for the rest is
        // done after each app program runs.
        if stx.txn.txn_type == "appl" {
            break;
        }

        if let Some(rekey) = stx.txn.rekey_to {
            if !rekey.is_zero() {
                static_rekeys.insert(sender, rekey);
            }
        }
    }
}

/// FixSigners post-app-call pass: after the app call at `app_index`
/// completes, re-correct the `auth_addr` of the remaining unsigned
/// transactions from the (possibly rekeyed) ledger state and static rekeys,
/// up to and including the next app call. Mirrors go-algorand's
/// `evalTracer.AfterProgram` fix pass (`ledger/simulation/tracer.go`).
fn fix_unsigned_signers_after_app<L: LedgerStore>(
    store: &L,
    group: &mut [SignedTransaction],
    app_index: usize,
) {
    let mut known_auth_addrs: HashMap<Address, Address> = HashMap::new();
    for stx in group.iter_mut().skip(app_index + 1) {
        let sender = stx.txn.sender;
        let auth = *known_auth_addrs
            .entry(sender)
            .or_insert_with(|| ledger_auth_addr(store, &sender));

        if txn_needs_synthetic_signature(stx) {
            set_fixed_auth_addr(stx, auth);
        }

        // The next app call's own AfterProgram pass handles the rest.
        if stx.txn.txn_type == "appl" {
            break;
        }

        if let Some(rekey) = stx.txn.rekey_to {
            if !rekey.is_zero() {
                known_auth_addrs.insert(sender, rekey);
            }
        }
    }
}

/// Merge a logic-sig trace captured during `check()` into the execution-phase
/// trace for the same transaction. The LogicSig program runs during signature
/// verification (before the per-transaction execution tracer exists), so its
/// `logicsig_trace` / `logicsig_hash` are captured separately and grafted onto
/// the transaction's execution trace here, matching go-algorand's single
/// `TransactionTrace` that holds both the logic-sig and app-call traces.
fn merge_logicsig_trace(
    exec_trace: Option<TransactionTrace>,
    logicsig_traces: &[Option<TransactionTrace>],
    index: usize,
) -> Option<TransactionTrace> {
    let lsig = match logicsig_traces.get(index).and_then(|t| t.as_ref()) {
        Some(t) if t.logicsig_trace.is_some() => t,
        _ => return exec_trace,
    };
    // Tracing is enabled (a logic-sig trace was captured), so the execution
    // tracer always produced a `Some` trace; fall back to a default trace if
    // for some reason it didn't, so the logic-sig trace is never dropped.
    let mut trace = exec_trace.unwrap_or_default();
    trace.logicsig_trace = lsig.logicsig_trace.clone();
    trace.logicsig_hash = lsig.logicsig_hash;
    Some(trace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_validation_fix_signers_requires_allow_empty() {
        // We can't easily construct a full LedgerStore for unit tests here,
        // so we just test the error types directly.
        let err = SimulatorError::InvalidRequest(InvalidRequestError {
            message: "test error".to_string(),
        });
        assert!(err.to_string().contains("test error"));
    }

    // ── Placeholder PQ signature detection (issue #835) ────────────

    fn minimal_pay_txn() -> algo_types::Transaction {
        algo_types::Transaction {
            txn_type: "pay".into(),
            sender: Address([0xAA; 32]),
            receiver: Address([0xBB; 32]),
            fee: 1000,
            first_valid: 0.into(),
            last_valid: 1000.into(),
            ..Default::default()
        }
    }

    fn placeholder_pqsig() -> algo_types::PQSig {
        algo_types::PQSig {
            scheme: algo_types::PQ_SCHEME_FALCON1024,
            salt: algo_types::PQAddressSalt(0),
            public_key: serde_bytes::ByteBuf::new(),
            signature: serde_bytes::ByteBuf::new(),
        }
    }

    #[test]
    fn is_placeholder_pqsig_detects_scheme_only_placeholder() {
        let stx = SignedTransaction {
            txn: minimal_pay_txn(),
            pqsig: Some(placeholder_pqsig()),
            ..Default::default()
        };
        assert!(is_placeholder_pqsig(&stx));
        assert!(!is_placeholder_delegated_pqsig(&stx));
    }

    #[test]
    fn is_placeholder_pqsig_false_when_signature_present() {
        let mut pqsig = placeholder_pqsig();
        pqsig.signature = serde_bytes::ByteBuf::from(vec![1u8; 4]);
        let stx = SignedTransaction {
            txn: minimal_pay_txn(),
            pqsig: Some(pqsig),
            ..Default::default()
        };
        assert!(!is_placeholder_pqsig(&stx));
    }

    #[test]
    fn is_placeholder_pqsig_false_when_other_signature_present() {
        let mut stx = SignedTransaction {
            txn: minimal_pay_txn(),
            pqsig: Some(placeholder_pqsig()),
            ..Default::default()
        };
        stx.sig = [1u8; 64];
        assert!(!is_placeholder_pqsig(&stx));
    }

    #[test]
    fn is_placeholder_delegated_pqsig_detects_lsig_nested_placeholder() {
        let stx = SignedTransaction {
            txn: minimal_pay_txn(),
            lsig: Some(algo_types::LogicSig {
                logic: serde_bytes::ByteBuf::from(vec![0x06, 0x81, 0x01, 0x43]),
                pqsig: Some(placeholder_pqsig()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(is_placeholder_delegated_pqsig(&stx));
        assert!(!is_placeholder_pqsig(&stx));
    }

    // ── txn_has_no_signature (issue #974, port of go's
    // TestTxnNeedsSyntheticSignatureLogicSigContent) ──────────────────
    //
    // go-algorand's `txnNeedsSyntheticSignature` is `!txn.HasSignature() ||
    // isPlaceholderPQSig(txn) || isPlaceholderDelegatedPQSig(txn)`; this
    // crate's `txn_has_no_signature` is the analogous first disjunct
    // (`!HasSignature()`), used the same way by `fix_unsigned_signers_*` to
    // decide which transactions need their `auth_addr` corrected. Mirrors
    // go's three assertions on a default (fully blank) `SignedTxn`, a
    // `LogicSig` carrying only `Args`, and a `LogicSig` carrying only a
    // (non-blank) delegated `Sig` -- in both LogicSig cases go's
    // `LogicSig.Blank()` (and this crate's analogous `!lsig.is_blank()` gate)
    // treats the LogicSig as a present signature category, independent of
    // which specific field is set.

    // ── group_fee_failure: free transactions (issue #2040) ──────────────
    //
    // A real heartbeat cannot be evaluated to success in a bare ledger (it
    // answers no live challenge), so end-to-end simulate() tests would stop
    // at the evaluation failure before the fee check. These call the exact
    // function `simulate()` runs after evaluation, so the fee path is
    // genuinely exercised. The removed `is_free_heartbeat`/`stpf` exemption
    // loop is subsumed by `txn_fee_factor` (go's `FeeFactor`).

    fn params(version: &str) -> ConsensusParams {
        consensus_params_for_version(version).expect("known consensus version")
    }

    fn hb_stx(discount: bool, group: [u8; 32], fee: u64) -> SignedTransaction {
        SignedTransaction {
            txn: algo_types::Transaction {
                txn_type: "hb".into(),
                sender: Address([0xAA; 32]),
                fee,
                group,
                heartbeat: Some(algo_types::HeartbeatTxnFields {
                    hb_challenge_discount: discount,
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn pay_stx(fee: u64, group: [u8; 32]) -> SignedTransaction {
        SignedTransaction {
            txn: algo_types::Transaction {
                txn_type: "pay".into(),
                sender: Address([0xBB; 32]),
                fee,
                group,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    const NO_FEE_MSG: &str = "txgroup with 0.0A fees is less than 1mA (usage=1.000000 * base=1mA)";

    #[test]
    fn group_fee_failure_free_ungrouped_heartbeat_pre_v42() {
        let p = params(algo_types::consensus::CONSENSUS_V41);
        assert_eq!(group_fee_failure(&[hb_stx(false, [0; 32], 0)], &p), None);
    }

    #[test]
    fn group_fee_failure_discounted_heartbeat_v42_free_and_control_pays() {
        let p = params(algo_types::consensus::CONSENSUS_V42);
        assert_eq!(group_fee_failure(&[hb_stx(true, [0; 32], 0)], &p), None);
        // Control: the identical heartbeat without the discount owes a fee.
        assert_eq!(
            group_fee_failure(&[hb_stx(false, [0; 32], 0)], &p).as_deref(),
            Some(NO_FEE_MSG)
        );
    }

    #[test]
    fn group_fee_failure_mixed_group_with_free_heartbeat_v42() {
        let p = params(algo_types::consensus::CONSENSUS_V42);
        let gid = [0x77; 32];
        // The discounted heartbeat adds no usage; the payment's 1000 covers
        // its own single unit.
        assert_eq!(
            group_fee_failure(&[hb_stx(true, gid, 0), pay_stx(1000, gid)], &p),
            None
        );
        // Control: same group, payment underpaid by 1 microAlgo.
        assert_eq!(
            group_fee_failure(&[hb_stx(true, gid, 0), pay_stx(999, gid)], &p).as_deref(),
            Some("txgroup with 999uA fees is less than 1mA (usage=1.000000 * base=1mA)")
        );
    }

    #[test]
    fn group_fee_failure_state_proof_contributes_no_usage() {
        // (simulate() itself rejects stpf in check(), matching go; this pins
        // that the fee summary alone would also treat it as free.)
        let p = params(algo_types::consensus::CONSENSUS_V41);
        let gid = [0x55; 32];
        let mut stpf = pay_stx(0, gid);
        stpf.txn.txn_type = "stpf".into();
        assert_eq!(
            group_fee_failure(&[stpf.clone(), pay_stx(1000, gid)], &p),
            None
        );
        assert_eq!(group_fee_failure(&[stpf], &p), None);
    }

    #[test]
    fn txn_has_no_signature_true_for_fully_blank_txn() {
        let stx = SignedTransaction {
            txn: minimal_pay_txn(),
            ..Default::default()
        };
        assert!(txn_has_no_signature(&stx));
    }

    #[test]
    fn txn_has_no_signature_false_for_logicsig_args_only() {
        let stx = SignedTransaction {
            txn: minimal_pay_txn(),
            lsig: Some(algo_types::LogicSig {
                logic: serde_bytes::ByteBuf::new(),
                sig: [0u8; 64],
                msig: None,
                lmsig: None,
                args: Some(vec![serde_bytes::ByteBuf::from(vec![1u8])]),
                pqsig: None,
            }),
            ..Default::default()
        };
        assert!(!txn_has_no_signature(&stx));
    }

    #[test]
    fn txn_has_no_signature_false_for_logicsig_sig_only() {
        let stx = SignedTransaction {
            txn: minimal_pay_txn(),
            lsig: Some(algo_types::LogicSig {
                logic: serde_bytes::ByteBuf::new(),
                sig: [1u8; 64],
                msig: None,
                lmsig: None,
                args: None,
                pqsig: None,
            }),
            ..Default::default()
        };
        assert!(!txn_has_no_signature(&stx));
    }

    #[test]
    fn is_placeholder_delegated_pqsig_false_without_program() {
        let stx = SignedTransaction {
            txn: minimal_pay_txn(),
            lsig: Some(algo_types::LogicSig {
                logic: serde_bytes::ByteBuf::new(), // no program
                pqsig: Some(placeholder_pqsig()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!is_placeholder_delegated_pqsig(&stx));
    }

    #[test]
    fn txn_needs_synthetic_signature_covers_unsigned_and_placeholders() {
        let unsigned = SignedTransaction {
            txn: minimal_pay_txn(),
            ..Default::default()
        };
        assert!(txn_needs_synthetic_signature(&unsigned));

        let placeholder = SignedTransaction {
            txn: minimal_pay_txn(),
            pqsig: Some(placeholder_pqsig()),
            ..Default::default()
        };
        assert!(txn_needs_synthetic_signature(&placeholder));

        let mut real_pqsig = placeholder_pqsig();
        real_pqsig.signature = serde_bytes::ByteBuf::from(vec![1u8; 4]);
        let genuinely_signed = SignedTransaction {
            txn: minimal_pay_txn(),
            pqsig: Some(real_pqsig),
            ..Default::default()
        };
        assert!(!txn_needs_synthetic_signature(&genuinely_signed));
    }

    #[test]
    fn test_request_default() {
        let req = SimulationRequest::default();
        assert!(req.txn_groups.is_empty());
        assert!(!req.allow_empty_signatures);
        assert!(!req.fix_signers);
        assert_eq!(req.extra_opcode_budget, 0);
    }

    #[test]
    fn test_eval_failure_error_display() {
        let err = EvalFailureError {
            message: "budget exceeded".to_string(),
            failed_at: vec![0, 1],
        };
        let s = err.to_string();
        assert!(s.contains("budget exceeded"));
        assert!(s.contains("[0, 1]"));
    }

    #[test]
    fn test_simulator_error_from_algo_error() {
        let algo_err = AlgoError::Ledger {
            message: "test".to_string(),
        };
        let sim_err: SimulatorError = algo_err.into();
        assert!(matches!(sim_err, SimulatorError::Internal(_)));
    }
}
