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

pub mod agreement_bridge;
pub mod agreement_key_manager;
pub mod apply;
pub mod apply_stateproof;
pub mod avm_context;
pub mod block_entry;
pub mod block_header;
pub mod catchpoint;
pub mod catchup_service;
pub mod delta_cache;
pub mod erasable_db;
pub mod eval_compare;
pub mod eval_delta;
pub mod genesis;
pub mod heartbeat;
pub mod lease;
pub mod merkle_cache;
pub mod merkle_committer;
pub mod merkle_page;
pub mod merkle_trie;
pub mod params;
pub mod participation;
pub(crate) mod recording_store;
pub mod rewards;
pub mod simulation;
pub mod sqlite;
pub mod state;
pub mod state_delta;
pub mod store_trait;
pub mod sync;
pub mod trie_hash;
pub mod txn_group_delta_tracer;
pub mod txtail_cache;

pub use apply::{
    apply_acfg, apply_afrz, apply_axfer, apply_block, apply_block_capturing_apply_data,
    apply_block_capturing_apply_data_with_delta, apply_block_capturing_group_deltas,
    apply_block_validating, apply_block_with_comparison, apply_block_with_delta,
    apply_block_with_delta_mode, apply_block_with_mode, apply_keyreg, apply_pay, apply_transaction,
    apply_transaction_with_budget, apply_transaction_with_tracer, ApplyContext, ApplyData,
    ApplyMode, BoxBudgetState, GroupInfo, InnerApplyData,
};
pub use avm_context::{type_enum, LedgerAvmContext};
pub use block_header::{compute_load, make_next_block_header, next_bonus, next_congestion_tax};
pub use eval_compare::{
    compare_eval_delta, CompareResult, EvalDeltaMismatchDetail, EvalDeltaStats, FieldMismatch,
    MismatchCategory,
};
pub use eval_delta::{parse_eval_delta, DeltaAction, EvalDelta, ValueDelta};
pub use genesis::{
    make_genesis_block, parse_genesis_json, populate_store, seed_account_totals_from_genesis,
    GenesisAllocation, GenesisJson,
};
pub use heartbeat::{
    bits_match, find_challenge, last_seen, Challenge, ChallengePeriod, HeaderProvider,
    StoreHeaderProvider,
};
pub use lease::LeaseTable;
pub use params::min_balance;
pub use rewards::{
    apply_rewards, compute_pending_rewards, next_rewards_state, normalized_online_balance,
    RewardsState, REWARD_UNITS,
};
pub use sqlite::{
    block_path_for_prefix, derive_ledger_prefix, ledger_exists, open_ledger_connection,
    open_ledger_connection_with_sync_mode, remove_ledger_files, tracker_path_for_prefix,
    CrossFileState, ReadSnapshot, SqliteLedger, BLOCK_SUFFIX, TRACKER_SUFFIX,
};
pub use state::{schema_min_balance, LedgerState, StateSnapshot};
pub use store_trait::LedgerStore;
pub use txn_group_delta_tracer::{TxnGroupDelta, TxnGroupDeltaTracer};

pub use delta_cache::{DeltaCache, DEFAULT_WINDOW_SIZE};

pub use agreement_bridge::AgreementLedgerBridge;
pub use agreement_key_manager::AgreementKeyManagerBridge;
pub use catchup_service::{
    BlockFetcher, CatchupLedger, CatchupService, FetchError, FetchedBlockCert,
};
pub use state_delta::{
    AccountBaseData, AccountDeltas, AccountTotals, AlgoCount, AppLocalStateDelta, AppParamsDelta,
    AppResourceRecord, AssetHoldingDelta, AssetParamsDelta, AssetResourceRecord, BalanceRecord,
    IncludedTransactions, KvValueDelta, LedgercoreAccountData, ModifiedCreatable, StateDelta,
    StateDeltaSubset, Txlease, VotingData,
};
