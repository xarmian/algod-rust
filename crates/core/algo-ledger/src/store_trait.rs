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

use algo_error::AlgoError;
use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParamsRecord, BlockHeader,
    Round,
};

/// One page of `(box_name, value)` results from
/// [`LedgerStore::box_keys_by_prefix_paginated`]. `value` is `None` unless
/// `include_values` was requested.
pub type BoxPage = Vec<(Vec<u8>, Option<Vec<u8>>)>;

/// Node-level block/txtail retention overrides (issue #1354), consulted by
/// the per-block commit pruning path (`apply.rs`) alongside the
/// consensus-derived retention window (`MaxTxnLife + DeeperBlockHeaderHistory`).
///
/// Mirrors the three inputs go-algorand's `Ledger.notifyCommit`
/// (`ledger/ledger.go`) combines with the tracker-derived floor:
///
/// 1. `max_block_history_lookback` — go's `config.Local.MaxBlockHistoryLookback`,
///    an explicit operator override that can *extend* retention further back
///    than the consensus-derived window. `0` means unconfigured (no override).
/// 2. `catchpoint_min_rounds_lookback` — go's `Ledger.calcMinCatchpointRoundsLookback`,
///    pre-resolved by the caller to `2 * CatchpointInterval` when the node
///    stores catchpoints (`Local::stores_catchpoints()`) and
///    `CatchpointFileHistoryLength != 0`, else `0`. Kept as a single
///    pre-computed round count (rather than raw `catchpoint_interval` +
///    `stores_catchpoints` fields) so this crate does not need to depend on
///    `algo_config` just to reproduce that resolution.
/// 3. `archival` — go's `Ledger.archival`: when `true`, retain everything
///    (`forget_before` is never called with a nonzero round), overriding both
///    of the above.
///
/// The default (`max_block_history_lookback: 0`, `catchpoint_min_rounds_lookback: 0`,
/// `archival: false`) reproduces exactly the consensus-only pruning behavior
/// from issue #1350 -- i.e. a store that never calls
/// [`LedgerStore::configure_retention`] (not all stores expose that method;
/// see [`crate::sqlite::SqliteLedger::configure_retention`] and
/// [`crate::state::LedgerState::configure_retention`]) behaves exactly
/// as it did before this type existed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionConfig {
    /// Go: `config.Local.MaxBlockHistoryLookback`. `0` = unconfigured.
    pub max_block_history_lookback: u64,
    /// Pre-resolved `2 * CatchpointInterval` catchpoint floor, or `0` when
    /// the node doesn't store catchpoints (or `CatchpointFileHistoryLength
    /// == 0`). See this type's doc comment.
    pub catchpoint_min_rounds_lookback: u64,
    /// Go: `Ledger.archival`. When `true`, retain everything.
    pub archival: bool,
}

/// Minimal per-account online-participation data as of a historical
/// "balance round" -- the subset of go-algorand's `basics.OnlineAccountData`
/// that the `voter_params_get` AVM opcode (0x74) exposes. See
/// [`LedgerStore::voter_agreement_data_at_round`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VoterAgreementData {
    /// Online balance with rewards applied, as of the balance round. Zero
    /// for an account that was not online at that round (matches go's
    /// all-zero `basics.OnlineAccountData{}` for a non-online lookup).
    pub micro_algos: u64,
    /// Whether the account had opted into block payouts (`IncentiveEligible`)
    /// as of the balance round.
    pub incentive_eligible: bool,
}

/// Abstraction over ledger storage backends.
///
/// Both the in-memory `LedgerState` and a future SQLite backend implement
/// this trait. Methods use owned values (not `&mut` references) so that
/// non-in-memory backends can serialize/deserialize without lifetime issues.
///
/// Used via generics (`<L: LedgerStore>`) for monomorphization — object
/// safety is NOT required.
pub trait LedgerStore {
    /// Opaque snapshot handle for rollback.
    ///
    /// For in-memory: `StateSnapshot` (cloned data).
    /// For SQLite: a SAVEPOINT identifier.
    type Snapshot;

    // ---- Accounts ----

    /// Get a copy of the account data, or `None` if the address has no record.
    fn get_account(&self, addr: &Address) -> Option<AccountData>;

    /// Write account data for the given address (insert or overwrite).
    fn set_account(&mut self, addr: &Address, account: AccountData);

    /// Get a copy of the account data, returning `Default::default()` if absent.
    ///
    /// Does NOT insert a default record — the caller must `set_account` to persist.
    fn get_or_default_account(&self, addr: &Address) -> AccountData {
        self.get_account(addr).unwrap_or_default()
    }

    /// Remove the account record entirely.
    fn remove_account(&mut self, addr: &Address);

    // ---- Asset Holdings ----

    fn get_asset_holding(&self, addr: &Address, asset_id: u64) -> Option<AssetHolding>;
    fn set_asset_holding(&mut self, addr: &Address, asset_id: u64, holding: AssetHolding);
    fn remove_asset_holding(&mut self, addr: &Address, asset_id: u64);
    fn has_asset_holding(&self, addr: &Address, asset_id: u64) -> bool {
        self.get_asset_holding(addr, asset_id).is_some()
    }

    /// Remove ALL asset holdings for a given asset ID, across all addresses.
    ///
    /// Used during rollback cleanup: when a nested inner transaction created an
    /// asset and various accounts opted in, rolling back the creator's params
    /// alone is insufficient — all holdings referencing that asset must also be
    /// removed. This handles non-snapshotted accounts that were touched by
    /// nested inner transactions.
    fn remove_all_asset_holdings_for_asset(&mut self, asset_id: u64);

    // ---- Asset Params ----

    fn get_asset_params(&self, asset_id: u64) -> Option<AssetParamsRecord>;
    fn set_asset_params(&mut self, asset_id: u64, record: AssetParamsRecord);
    fn remove_asset_params(&mut self, asset_id: u64);
    fn has_asset_params(&self, asset_id: u64) -> bool {
        self.get_asset_params(asset_id).is_some()
    }

    // ---- App Params ----

    fn get_app_params(&self, app_id: u64) -> Option<AppParams>;
    fn set_app_params(&mut self, app_id: u64, params: AppParams);
    fn remove_app_params(&mut self, app_id: u64);
    fn has_app_params(&self, app_id: u64) -> bool {
        self.get_app_params(app_id).is_some()
    }

    /// Get app params, inserting a default if absent, and return the value.
    ///
    /// This mirrors the `entry().or_insert_with()` pattern used in eval_delta.
    /// The default is constructed via the provided closure.
    fn get_or_insert_app_params(
        &mut self,
        app_id: u64,
        default: impl FnOnce() -> AppParams,
    ) -> AppParams {
        match self.get_app_params(app_id) {
            Some(p) => p,
            None => {
                let p = default();
                self.set_app_params(app_id, p.clone());
                p
            }
        }
    }

    /// Iterate over all app params where the creator matches the given address.
    ///
    /// Returns a `Vec` to avoid lifetime issues with non-in-memory backends.
    fn app_params_created_by(&self, creator: &Address) -> Vec<AppParams>;

    // ---- App Local States ----

    fn get_app_local_state(&self, addr: &Address, app_id: u64) -> Option<AppLocalState>;
    fn set_app_local_state(&mut self, addr: &Address, app_id: u64, local_state: AppLocalState);
    fn remove_app_local_state(&mut self, addr: &Address, app_id: u64);
    fn has_app_local_state(&self, addr: &Address, app_id: u64) -> bool {
        self.get_app_local_state(addr, app_id).is_some()
    }

    /// Remove ALL app local states for a given app ID, across all addresses.
    ///
    /// Used during rollback cleanup: when a nested inner transaction created an
    /// app and various accounts opted in, rolling back the creator's params
    /// alone is insufficient — all local states referencing that app must also
    /// be removed. This handles non-snapshotted accounts that were touched by
    /// nested inner transactions.
    fn remove_all_app_local_states_for_app(&mut self, app_id: u64);

    /// Get app local state, inserting a default if absent, and return the value.
    ///
    /// Mirrors the `entry().or_insert_with()` pattern used in eval_delta.
    fn get_or_insert_app_local_state(
        &mut self,
        addr: &Address,
        app_id: u64,
        default: impl FnOnce() -> AppLocalState,
    ) -> AppLocalState {
        match self.get_app_local_state(addr, app_id) {
            Some(s) => s,
            None => {
                let s = default();
                self.set_app_local_state(addr, app_id, s.clone());
                s
            }
        }
    }

    /// Collect all app local states for a given address.
    ///
    /// Returns `Vec<(u64, AppLocalState)>` — the app ID and local state.
    fn app_local_states_for_addr(&self, addr: &Address) -> Vec<(u64, AppLocalState)>;

    /// Collect all asset holdings for a given address.
    ///
    /// Returns `Vec<(u64, AssetHolding)>` — the asset ID and holding.
    fn asset_holdings_for_addr(&self, addr: &Address) -> Vec<(u64, AssetHolding)>;

    /// Collect all created asset params for a given address.
    ///
    /// Returns `Vec<(u64, AssetParamsRecord)>` — the asset ID and params record.
    fn created_assets_for_addr(&self, addr: &Address) -> Vec<(u64, AssetParamsRecord)>;

    /// Collect all created app params for a given address.
    ///
    /// Returns `Vec<(u64, AppParams)>` — the app ID and params.
    fn created_apps_for_addr(&self, addr: &Address) -> Vec<(u64, AppParams)>;

    // ---- Box Storage ----

    /// Read a box value. Returns `None` if the box does not exist.
    fn get_box(&self, app_id: u64, key: &[u8]) -> Option<Vec<u8>>;

    /// Create or overwrite a box with the given value.
    fn set_box(&mut self, app_id: u64, key: &[u8], value: Vec<u8>);

    /// Delete a box. Returns `true` if the box existed and was removed.
    fn delete_box(&mut self, app_id: u64, key: &[u8]) -> bool;

    /// Check whether a box exists and return its length. Returns `None` if it
    /// does not exist.
    fn box_len(&self, app_id: u64, key: &[u8]) -> Option<usize> {
        self.get_box(app_id, key).map(|v| v.len())
    }

    /// Enumerate all box names (raw keys, not the full KV-store keys) for a
    /// given application.
    ///
    /// Used by the REST API to implement `GET /v2/applications/{id}/boxes`.
    /// The returned `Vec<u8>` items are the raw box names without the
    /// `"bx:" + app_id` prefix.
    fn box_keys_for_app(&self, app_id: u64) -> Vec<Vec<u8>>;

    /// Enumerate box names (and optionally values) for an application,
    /// filtered by `prefix` and paginated via an exclusive-start `cursor`,
    /// in ascending byte-lexicographic order by raw box name.
    ///
    /// `cursor`, when `Some`, excludes any box name that is
    /// lexicographically `<=` the cursor (the cursor itself is never
    /// re-returned, matching go-algorand's `LookupKeysByPrefixCursor` in
    /// `ledger/store/trackerdb/generickv/accounts_reader.go`). `limit`,
    /// when `Some`, caps the number of returned entries; the second
    /// element of the return tuple reports whether at least one more
    /// qualifying box exists beyond what was returned (used to decide
    /// whether the REST layer should emit a `next-token`).
    ///
    /// Default implementation built on [`Self::box_keys_for_app`] and
    /// [`Self::get_box`] — correct for every backend without requiring a
    /// bespoke range-scan implementation per storage engine, matching this
    /// endpoint's `effort:medium` scope (see issue #536). A backend may
    /// override this with a native sorted range scan if profiling ever
    /// shows this endpoint as a bottleneck.
    fn box_keys_by_prefix_paginated(
        &self,
        app_id: u64,
        prefix: &[u8],
        cursor: Option<&[u8]>,
        limit: Option<u64>,
        include_values: bool,
    ) -> (BoxPage, bool) {
        let mut names: Vec<Vec<u8>> = self
            .box_keys_for_app(app_id)
            .into_iter()
            .filter(|name| name.starts_with(prefix))
            .filter(|name| match cursor {
                Some(c) => name.as_slice() > c,
                None => true,
            })
            .collect();
        names.sort();

        let more_data = match limit {
            Some(l) => (names.len() as u64) > l,
            None => false,
        };
        if let Some(l) = limit {
            names.truncate(l as usize);
        }

        let results = names
            .into_iter()
            .map(|name| {
                let value = if include_values {
                    self.get_box(app_id, &name)
                } else {
                    None
                };
                (name, value)
            })
            .collect();

        (results, more_data)
    }

    // ---- Leases ----

    /// Check whether a lease is active for (sender, lease) at the given round.
    fn check_lease(
        &self,
        sender: &Address,
        lease: &[u8; 32],
        current_round: u64,
    ) -> Result<(), AlgoError>;

    /// Record a lease for (sender, lease) with the given last_valid round.
    fn record_lease(&mut self, sender: &Address, lease: &[u8; 32], last_valid: u64);

    /// Remove all leases whose last_valid is strictly less than `current_round`.
    fn purge_expired_leases(&mut self, current_round: u64);

    // ---- Chain-level state (getters) ----

    fn current_round(&self) -> Round;

    /// The earliest round this store can resolve historical ledger state
    /// for -- go-algorand's accountupdates `dbRound` concept
    /// (`ledger/acctupdates.go`'s `RoundOffsetError`), which distinguishes
    /// "round genuinely predates the ledger's tracked history"
    /// (`RoundOffsetError`, `"round %d before dbRound %d"`) from "round
    /// doesn't exist yet" (`ledgercore.ErrNoEntry`, `"ledger does not have
    /// entry"`). algod-rust does not implement real multi-round historical
    /// state pruning (`forget_before` is not yet wired into the normal
    /// apply path -- see its `TODO` in `apply.rs`), so this defaults to
    /// genesis (round 0, i.e. "no restriction") and is only ever advanced
    /// explicitly -- currently by a follower node's `SetSyncRound`
    /// (`bin/algod-rust`'s `FollowerSyncRoundState`), which reproduces go's
    /// actual restriction for that scenario without claiming to model
    /// general-purpose ledger pruning.
    fn earliest_round(&self) -> Round {
        Round(0)
    }

    /// Advance the earliest round this store can serve historical queries
    /// for. See [`Self::earliest_round`].
    fn set_earliest_round(&mut self, round: Round) {
        let _ = round;
    }

    fn rewards_level(&self) -> u64;
    fn rewards_rate(&self) -> u64;
    fn rewards_residue(&self) -> u64;
    fn rewards_recalculation_round(&self) -> u64;
    fn fee_sink(&self) -> Address;
    fn rewards_pool(&self) -> Address;
    fn genesis_id(&self) -> &str;
    fn genesis_hash(&self) -> &[u8; 32];
    fn protocol(&self) -> &str;

    /// Transaction counter from the latest committed block header.
    ///
    /// Mirrors go-algorand's `prevHeader.TxnCounter` — used as the base
    /// for creatable ID generation in the next block.
    fn txn_counter(&self) -> u64;

    /// Aggregate account totals (money/reward-units by participation
    /// status, current rewards level), matching go-algorand's
    /// `ledgercore.AccountTotals`. Used to populate `StateDelta::totals`
    /// (issue #586) after a block apply.
    ///
    /// Default implementation returns the all-zero value — correct only
    /// for a backend that genuinely tracks no totals at all. Both real
    /// implementors (`SqliteLedger`, which maintains an incremental
    /// `accounttotals` row per issue #523/#530, and `LedgerState`, which
    /// scans its full in-memory account map) override this with a real
    /// computation; this default exists purely so the method doesn't force
    /// a third, hypothetical implementor to plumb totals tracking just to
    /// compile.
    fn account_totals(&self) -> crate::state_delta::AccountTotals {
        crate::state_delta::AccountTotals::default()
    }

    // ---- Chain-level state (setters) ----

    fn set_current_round(&mut self, round: Round);
    fn set_rewards_level(&mut self, level: u64);
    fn set_rewards_rate(&mut self, rate: u64);
    fn set_rewards_residue(&mut self, residue: u64);
    fn set_rewards_recalculation_round(&mut self, round: u64);
    fn set_fee_sink(&mut self, addr: Address);
    fn set_rewards_pool(&mut self, addr: Address);
    fn set_genesis_id(&mut self, id: String);
    fn set_genesis_hash(&mut self, hash: [u8; 32]);
    fn set_protocol(&mut self, protocol: String);
    fn set_txn_counter(&mut self, counter: u64);

    // ---- Snapshot / Restore ----

    /// Create a snapshot covering the given addresses (accounts, holdings,
    /// local states) for later rollback.
    fn snapshot(&self, addrs: &[Address]) -> Self::Snapshot;

    /// Create a snapshot that also covers specific asset param and app param
    /// IDs, in addition to address-based state.
    fn snapshot_with_ids(
        &self,
        addrs: &[Address],
        asset_ids: &[u64],
        app_ids: &[u64],
    ) -> Self::Snapshot;

    /// Restore state from a previous snapshot, reverting all changes made
    /// since the snapshot was taken.
    fn restore_snapshot(&mut self, snapshot: Self::Snapshot);

    // ---- Min balance ----

    /// Compute the minimum balance for an account, including schema-based
    /// costs from opted-in and created apps.
    ///
    /// Matches go-algorand's `AccountData.MinBalance` (`data/basics/
    /// userBalance.go`): the schema cost is derived once from the
    /// account's own aggregate `total_app_schema` field, which is already
    /// maintained by every op that changes an app's schema footprint on
    /// this account. Implementations must not additionally rescan the
    /// account's app local states / created app params and re-add their
    /// schema cost -- that double-counts it (see issue #989).
    fn min_balance_with_state(&self, addr: &Address, account: &AccountData) -> u64;

    // ---- Trie integration ----

    /// Enable Merkle trie tracking for this store.
    ///
    /// When enabled, mutations to accounts and resources are tracked so that
    /// the trie can be incrementally updated after each block.
    fn enable_trie(&mut self) {}

    /// Check whether trie tracking is enabled.
    fn trie_enabled(&self) -> bool {
        false
    }

    /// After a block is applied, process all recorded mutations and update the
    /// Merkle trie. Returns the new trie root hash, or `None` if the trie is
    /// not enabled.
    fn finalize_trie_updates(&mut self) -> Option<[u8; 32]> {
        None
    }

    // ---- Block / Certificate Storage ----

    /// Store a block with header data, full block data, and protocol version.
    fn put_block(
        &mut self,
        round: u64,
        proto: &str,
        hdrdata: &[u8],
        blkdata: &[u8],
    ) -> Result<(), AlgoError> {
        let _ = (round, proto, hdrdata, blkdata);
        Ok(())
    }

    /// Retrieve raw block data (full block) by round.
    fn get_block_data(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        let _ = round;
        Ok(None)
    }

    /// Retrieve raw block header data by round.
    fn get_block_header_data(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        let _ = round;
        Ok(None)
    }

    /// Retrieve and decode a block header by round.
    ///
    /// Default implementation calls [`get_block_header_data`] and decodes
    /// via `BlockHeader::decode_from_reader`.
    fn get_block_header(&self, round: u64) -> Result<Option<BlockHeader>, AlgoError> {
        match self.get_block_header_data(round)? {
            Some(data) => {
                let hdr = BlockHeader::decode_from_reader(&mut data.as_slice())?;
                Ok(Some(hdr))
            }
            None => Ok(None),
        }
    }

    /// Retrieve certificate data for a block round.
    fn get_block_cert(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        let _ = round;
        Ok(None)
    }

    /// Retrieve the protocol version string for a block round.
    fn get_block_proto(&self, round: u64) -> Result<Option<String>, AlgoError> {
        let _ = round;
        Ok(None)
    }

    /// Store a certificate for a block round.
    fn put_block_cert(&mut self, round: u64, certdata: &[u8]) -> Result<(), AlgoError> {
        let _ = (round, certdata);
        Ok(())
    }

    // ---- TxTail Storage ----

    /// Store a txtail entry (serialized `TxTailRound`) for a round.
    fn put_txtail(&mut self, round: u64, data: &[u8]) -> Result<(), AlgoError> {
        let _ = (round, data);
        Ok(())
    }

    /// Retrieve a txtail entry by round.
    fn get_txtail(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        let _ = round;
        Ok(None)
    }

    // ---- Pruning ----

    /// Delete blocks and txtail entries before the given round.
    fn forget_before(&mut self, round: u64) -> Result<(), AlgoError> {
        let _ = round;
        Ok(())
    }

    /// The node-level retention overrides configured for this store (issue
    /// #1354). See [`RetentionConfig`]'s doc comment for the semantics.
    ///
    /// Default: the all-default [`RetentionConfig`], which reproduces the
    /// consensus-only pruning window exactly as it behaved before this
    /// method existed (issue #1350) -- a store need only override this (and
    /// expose its own `configure_retention` setter) if it wants to honor
    /// `MaxBlockHistoryLookback`/catchpoint-floor/archival overrides.
    fn retention_config(&self) -> RetentionConfig {
        RetentionConfig::default()
    }

    // ---- State-proof verification-context tracker ----
    //
    // Mirrors go-algorand's `spVerificationTracker`/`StateProofVerificationContext`
    // persistence (`ledger/spverificationtracker.go`, the `stateproofverification`
    // DB table): a cache of the data needed to verify a future `StateProofTx`
    // (voters commitment, online total weight, protocol version), keyed by the
    // last-attested round the eventual proof will cover, populated when the
    // relevant "voters round" block is applied and independent of whether that
    // block's own header is still retained. See `apply_stateproof.rs`'s
    // `resolve_verification_context`.

    /// Store a state-proof verification-context blob, keyed by the round the
    /// eventual state proof will attest to (`last_attested_round`).
    fn put_state_proof_verification_context(
        &mut self,
        last_attested_round: u64,
        data: &[u8],
    ) -> Result<(), AlgoError> {
        let _ = (last_attested_round, data);
        Ok(())
    }

    /// Retrieve a state-proof verification-context blob by its
    /// `last_attested_round` key.
    fn get_state_proof_verification_context(
        &self,
        last_attested_round: u64,
    ) -> Result<Option<Vec<u8>>, AlgoError> {
        let _ = last_attested_round;
        Ok(None)
    }

    /// Delete verification-context entries whose `last_attested_round` is
    /// strictly less than `before_round` (matches go's
    /// `DeleteOldSPContexts`: entries are only needed until a state proof
    /// covering that round has actually been applied and `StateProofNext`
    /// has advanced past it).
    fn delete_state_proof_verification_contexts_before(
        &mut self,
        before_round: u64,
    ) -> Result<(), AlgoError> {
        let _ = before_round;
        Ok(())
    }

    // ---- Voters snapshot cache (issue #780) ----
    //
    // Mirrors go-algorand's `ledger/voters.go::votersTracker` in-memory
    // `votersForRoundCache`: a snapshot of the top online participants'
    // vector-commitment root and the network-wide online total weight, taken
    // at each "voters round" `r` where `(r + StateProofVotersLookback) %
    // StateProofInterval == 0`, and consumed `StateProofVotersLookback`
    // rounds later when the block at the next `StateProofInterval` multiple
    // is produced/validated. See `crate::voters_tracker`.

    /// Return every online account, for state-proof voter-set selection.
    /// Restricted to accounts with `AccountStatus::Online` -- matches go's
    /// `TopOnlineAccounts`, which is only ever fed already-online candidates.
    ///
    /// No default (empty) implementation: an override that silently returned
    /// nothing would make every voters snapshot vacuous (an empty voters
    /// commitment/zero total weight) without any visible error, which is far
    /// worse than a compile-time reminder to implement this for a new
    /// backend.
    fn online_accounts(&self) -> Vec<(Address, AccountData)>;

    // ---- Balance-round-lookback online-participation queries (issue #1215) ----
    //
    // Both back the incentive-opcode pair `voter_params_get`/`online_stake`
    // (AVM v11+, go commit `98fdd2a09`) via `LedgerAvmContext`
    // (`avm_context.rs`). go-algorand answers both from the historical
    // "balance round" (`agreement.BalanceRound`, i.e.
    // `2*SeedRefreshInterval*SeedLookback` rounds back from the round being
    // built -- see `ledger/eval/eval.go::roundCowBase.balanceRound`), not
    // current ledger state, so the round is a caller-supplied parameter
    // here rather than implicit "now".
    //
    // No default implementation, for the same reason as `online_accounts`
    // above: silently falling back to zero/empty would make every real
    // v11+ TEAL program using these opcodes observe wrong (not just
    // unavailable) consensus data.

    /// Per-account online-participation data as of `round`, for the subset
    /// of go-algorand's `basics.OnlineAccountData` that `voter_params_get`
    /// (opcode 0x74, `data/transactions/logic/eval.go::opVoterParamsGet`)
    /// needs: online balance with rewards applied, and whether the account
    /// had opted into block payouts (`IncentiveEligible`).
    ///
    /// An account that was not online (or unknown) at `round` returns
    /// [`VoterAgreementData::default`] (all zero), matching go's
    /// `basics.OnlineAccountData{}` sentinel returned by
    /// `InternalLedger.LookupAgreement` for a non-online account -- see
    /// `AgreementLedgerBridge::lookup_agreement` (`agreement_bridge.rs`),
    /// which implements the same historical-then-current-state fallback for
    /// the agreement/sortition path that this mirrors for the AVM path.
    fn voter_agreement_data_at_round(
        &self,
        round: u64,
        addr: &Address,
    ) -> Result<VoterAgreementData, AlgoError>;

    /// Total online stake ("circulation") to report as of `round`, adjusted
    /// for the stake behind participation keys that will have expired by
    /// `vote_rnd`. Backs the `online_stake` opcode (0x75,
    /// `data/transactions/logic/eval.go::opOnlineStake` /
    /// `ledger/eval/eval.go::roundCowBase.onlineStake`), which calls
    /// `Ledger.OnlineCirculation(brnd, x.rnd+1)` -- the same accessor
    /// `AgreementLedgerBridge::circulation` already uses for agreement's
    /// sortition/committee-sizing lookback.
    fn online_stake_at_round(&self, round: u64, vote_rnd: u64) -> Result<u64, AlgoError>;

    /// Store a voters snapshot -- `(voters_commitment, online_total_weight)`
    /// -- keyed by the round it was taken at (go's `votersForRoundCache` map
    /// key).
    fn put_voters_snapshot(
        &mut self,
        round: u64,
        voters_commitment: Vec<u8>,
        online_total_weight: u64,
    ) -> Result<(), AlgoError> {
        let _ = (round, voters_commitment, online_total_weight);
        Ok(())
    }

    /// Retrieve a voters snapshot by its round key.
    fn get_voters_snapshot(&self, round: u64) -> Result<Option<(Vec<u8>, u64)>, AlgoError> {
        let _ = round;
        Ok(None)
    }

    /// Every round currently holding a cached voters snapshot -- used by the
    /// retention sweep (go's `removeOldVoters`) to decide what to delete.
    fn voters_snapshot_rounds(&self) -> Result<Vec<u64>, AlgoError> {
        Ok(Vec::new())
    }

    /// Delete the voters snapshot recorded at `round`, if any.
    fn delete_voters_snapshot(&mut self, round: u64) -> Result<(), AlgoError> {
        let _ = round;
        Ok(())
    }

    // ---- Voters snapshot: full participant array (issue #912) ----
    //
    // The compact `(voters_commitment, online_total_weight)` pair above is
    // sufficient to *verify* a state-proof transaction that already exists
    // in a block (`apply_stateproof.rs`), but building/signing one requires
    // the full selected voters-round participant array -- go's
    // `ledgercore.VotersForRound.Participants`/`.Tree`, fetched via
    // `Ledger.VotersForStateProof(lookback)` (`stateproof/abstractions.go:44`)
    // and persisted (once the state-proof round is actually reached) in the
    // `stateproof` package's own `provers` table (`stateproof/db.go`,
    // `persistProver`/`getProver`) -- see `crate::voters_tracker`'s module
    // doc and issue #912 for the full root-cause writeup.
    //
    // Retained at the *same* round key and pruned on the *same* schedule as
    // the compact snapshot above (`crate::voters_tracker::
    // prune_voters_snapshots`) -- go's `deleteStaleProver` retention
    // (`stateproof/builder.go:593`) tracks `StateProofNextRound`, which is
    // already what `should_remove_voters_snapshot`'s existing recovery-
    // window arithmetic bounds, so no separate pruning schedule is needed
    // (see this crate's `voters_tracker.rs` module doc, and issue #912's PR
    // description, for why `stateproof_worker::PROVERS_CACHE_LENGTH` -- which
    // bounds go's *in-memory* prover cache, not disk retention -- does not
    // apply here).

    /// Store the full, address-tagged participant array selected for the
    /// voters snapshot at `round`, alongside the compact commitment
    /// [`Self::put_voters_snapshot`] stores. Called at the same point, in
    /// the same transaction, as [`Self::put_voters_snapshot`] -- see
    /// `crate::voters_tracker::record_voters_snapshot`.
    ///
    /// The address tag on each participant (issue #814's live-daemon-wiring
    /// scope, extending issue #912's original participant-only persistence)
    /// is what lets a signing/proving daemon build `Address -> position`
    /// (go: `voters.AddrToPos`) for a signature it receives over gossip,
    /// long after the snapshot round's own live account state may be gone.
    fn put_voters_participants(
        &mut self,
        round: u64,
        participants: &[(
            algo_types::Address,
            algo_consensus_crypto::stateproof::Participant,
        )],
    ) -> Result<(), AlgoError> {
        let _ = (round, participants);
        Ok(())
    }

    /// Retrieve the full, address-tagged participant array recorded for the
    /// voters snapshot at `round`, if any. The vector-commitment tree itself
    /// is not stored -- `crate::voters::commit_participants` deterministically
    /// rebuilds it (byte-for-byte, including the root) from the participant
    /// half of this array alone; see `crate::voters_tracker::
    /// voters_participants_and_tree`.
    fn get_voters_participants(
        &self,
        round: u64,
    ) -> Result<
        Option<
            Vec<(
                algo_types::Address,
                algo_consensus_crypto::stateproof::Participant,
            )>,
        >,
        AlgoError,
    > {
        let _ = round;
        Ok(None)
    }

    /// Delete the participant array recorded at `round`, if any. Called
    /// alongside [`Self::delete_voters_snapshot`] by
    /// `crate::voters_tracker::prune_voters_snapshots`.
    fn delete_voters_participants(&mut self, round: u64) -> Result<(), AlgoError> {
        let _ = round;
        Ok(())
    }
}
