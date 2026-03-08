use algo_avm::eval::{run_approval_program, run_clear_state_program};
use algo_avm::group::GroupBudget;
use algo_error::AlgoError;
use algo_types::{
    AccountStatus, Address, AppLocalState, AppParams, AssetHolding, AssetParams, AssetParamsRecord,
    Block, Round, SignedTransaction,
};
use sha2::{Digest, Sha512_256};

use crate::avm_context::LedgerAvmContext;
use crate::eval_delta::{apply_eval_delta, parse_eval_delta};
use crate::rewards::apply_rewards;

// NOTE: LedgerStore is referenced via full path `crate::store_trait::LedgerStore`
// in function bounds rather than imported at module level. This prevents
// `use super::*` in the test module from bringing the trait into scope,
// which would shadow LedgerState's inherent `get_or_default_account(&mut self)
// -> &mut AccountData` with the trait's `get_or_default_account(&self) -> AccountData`.

/// Determines whether the ledger replays recorded block data or actively
/// executes AVM programs to produce results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyMode {
    /// Use recorded EvalDelta from block data (backward compatible).
    Replay,
    /// Run AVM programs to produce results.
    Execute,
}

/// Context derived from the block header, passed to transaction application.
pub struct ApplyContext {
    pub rewards_level: u64,
    pub fee_sink: Address,
    pub round: u64,
    /// Controls whether EvalDeltas come from block data or AVM execution.
    pub mode: ApplyMode,
    /// Latest confirmed timestamp (for AVM context).
    pub latest_timestamp: u64,
    /// Genesis hash (for AVM context).
    pub genesis_hash: [u8; 32],
}

impl ApplyContext {
    /// Create a Replay-mode context with zero timestamp and genesis hash.
    /// Primarily for tests and backward compatibility.
    pub fn new_replay(rewards_level: u64, fee_sink: Address, round: u64) -> Self {
        Self {
            rewards_level,
            fee_sink,
            round,
            mode: ApplyMode::Replay,
            latest_timestamp: 0,
            genesis_hash: [0u8; 32],
        }
    }
}

/// Apply a full block to the ledger state.
///
/// Updates rewards parameters from the block header, then applies each
/// transaction in payset order. Finally updates `current_round`.
///
/// On error, rewards state is restored to its pre-block values. Note that
/// account mutations from earlier successful transactions in the payset are
/// NOT rolled back — the caller should treat the state as corrupted on error.
/// In practice, committed blocks are already validated and should never
/// produce errors — the checks here are defensive safety nets.
pub fn apply_block<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    block: &Block,
) -> Result<(), AlgoError> {
    // Validate round monotonicity.
    let expected = Round(store.current_round().0 + 1);
    if block.round != expected {
        return Err(AlgoError::Ledger {
            message: format!("expected round {}, got {}", expected, block.round),
        });
    }

    // Save rewards state and addresses for rollback on error.
    let prev_rewards_level = store.rewards_level();
    let prev_rewards_rate = store.rewards_rate();
    let prev_rewards_residue = store.rewards_residue();
    let prev_rewards_recalc = store.rewards_recalculation_round();
    let prev_fee_sink = store.fee_sink();
    let prev_rewards_pool = store.rewards_pool();

    // Update rewards state and reward addresses from block header.
    store.set_rewards_level(block.rewards_level);
    store.set_rewards_rate(block.rewards_rate);
    store.set_rewards_residue(block.rewards_residue);
    store.set_rewards_recalculation_round(block.rewards_recalculation_round.0);
    store.set_fee_sink(block.fee_sink);
    store.set_rewards_pool(block.rewards_pool);

    let mut gh = [0u8; 32];
    if block.genesis_hash.len() == 32 {
        gh.copy_from_slice(&block.genesis_hash);
    }

    let ctx = ApplyContext {
        rewards_level: block.rewards_level,
        fee_sink: block.fee_sink,
        round: block.round.0,
        mode: ApplyMode::Replay,
        latest_timestamp: block.timestamp as u64,
        genesis_hash: gh,
    };

    let result = (|| {
        match ctx.mode {
            ApplyMode::Replay => {
                // Replay mode: process transactions individually (no AVM execution).
                for stx in &block.payset {
                    apply_transaction(store, stx, &ctx, 0)?;
                }
            }
            ApplyMode::Execute => {
                // Execute mode: detect transaction groups, create group budgets,
                // and pass them through to apply_appl for AVM execution.
                let groups = detect_transaction_groups(&block.payset);
                for group in &groups {
                    let num_app_calls = group
                        .iter()
                        .filter(|stx| stx.txn.txn_type == "appl")
                        .count();
                    let mut group_budget = GroupBudget::new(num_app_calls);

                    for stx in group {
                        if stx.txn.txn_type == "appl" {
                            apply_transaction_with_budget(
                                store,
                                stx,
                                &ctx,
                                0,
                                Some(&mut group_budget),
                            )?;
                        } else {
                            apply_transaction(store, stx, &ctx, 0)?;
                        }
                    }
                }
            }
        }
        Ok(())
    })();

    if result.is_err() {
        // Restore rewards state and addresses on failure.
        store.set_rewards_level(prev_rewards_level);
        store.set_rewards_rate(prev_rewards_rate);
        store.set_rewards_residue(prev_rewards_residue);
        store.set_rewards_recalculation_round(prev_rewards_recalc);
        store.set_fee_sink(prev_fee_sink);
        store.set_rewards_pool(prev_rewards_pool);
        return result;
    }

    store.set_current_round(block.round);
    store.purge_expired_leases(block.round.0);

    Ok(())
}

/// Detect transaction groups within a block's payset.
///
/// Consecutive transactions sharing the same non-empty `group` hash form an
/// atomic group. Transactions with an empty group hash are treated as their
/// own single-transaction group.
fn detect_transaction_groups(payset: &[SignedTransaction]) -> Vec<Vec<&SignedTransaction>> {
    let mut groups: Vec<Vec<&SignedTransaction>> = Vec::new();
    let mut i = 0;
    while i < payset.len() {
        let stx = &payset[i];
        if stx.txn.group.is_empty() {
            // Standalone transaction.
            groups.push(vec![stx]);
            i += 1;
        } else {
            // Atomic group: collect consecutive transactions with the same group hash.
            let group_hash = &stx.txn.group;
            let mut group = vec![stx];
            i += 1;
            while i < payset.len() && payset[i].txn.group == *group_hash {
                group.push(&payset[i]);
                i += 1;
            }
            groups.push(group);
        }
    }
    groups
}

/// Apply a single signed transaction with a group budget for AVM execution.
///
/// Same as `apply_transaction` but threads the group budget through to
/// `apply_appl` for Execute-mode pooled budget accounting.
fn apply_transaction_with_budget<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
    depth: u32,
    group_budget: Option<&mut GroupBudget>,
) -> Result<(), AlgoError> {
    apply_transaction_inner(store, stx, ctx, depth, group_budget)
}

/// Apply a single signed transaction to the ledger state.
///
/// Matches go-algorand's `applyTransaction` ordering:
/// 1. Snapshot touched accounts, then apply rewards.
/// 2. Handle rekey_to (before type-specific dispatch).
/// 3. Dispatch by transaction type (fee + type-specific logic).
/// 4. Debit rewards pool for any rewards distributed.
/// 5. Check min balance for all touched accounts.
///
/// On error, touched account data is restored to pre-reward state.
///
/// **Note:** This per-transaction API passes `None` for the group budget,
/// so each app call in Execute mode gets an isolated `GroupBudget(1)` (700
/// opcodes). For correct pooled-budget semantics across atomic groups, use
/// `apply_block()` which detects groups and threads a shared `GroupBudget`.
/// A public group-aware API (`apply_group()`) is planned for Epic 23 (#27).
pub fn apply_transaction<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
    depth: u32,
) -> Result<(), AlgoError> {
    apply_transaction_inner(store, stx, ctx, depth, None)
}

/// Core transaction application logic, shared by `apply_transaction` and
/// `apply_transaction_with_budget`.
fn apply_transaction_inner<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
    depth: u32,
    group_budget: Option<&mut GroupBudget>,
) -> Result<(), AlgoError> {
    let txn = &stx.txn;

    // State proof transactions are protocol-injected and skip all processing
    // (no rewards, no fees, no state changes).
    if txn.txn_type == "stpf" {
        return Ok(());
    }

    // Convert lease bytes to [u8; 32] for lease table operations.
    let lease_arr: [u8; 32] = if txn.lease.is_empty() {
        [0u8; 32]
    } else {
        <[u8; 32]>::try_from(txn.lease.as_ref()).map_err(|_| AlgoError::Ledger {
            message: format!("invalid lease length {}, expected 32", txn.lease.len()),
        })?
    };

    // Check lease before any state changes.
    store.check_lease(&txn.sender, &lease_arr, ctx.round)?;

    // Collect addresses for reward application (only actual transaction participants
    // per go-algorand: sender, receiver, close-to, asset participants, freeze target).
    let mut reward_addrs = Vec::with_capacity(6);
    reward_addrs.push(txn.sender);
    if !txn.receiver.is_zero() && txn.receiver != txn.sender {
        reward_addrs.push(txn.receiver);
    }
    if !txn.close_remainder_to.is_zero()
        && txn.close_remainder_to != txn.sender
        && txn.close_remainder_to != txn.receiver
    {
        reward_addrs.push(txn.close_remainder_to);
    }
    // Asset transfer: receiver, sender (clawback source), close-to.
    if let Some(ar) = txn.asset_receiver {
        if !ar.is_zero() && !reward_addrs.contains(&ar) {
            reward_addrs.push(ar);
        }
    }
    if let Some(asnd) = txn.asset_sender {
        if !asnd.is_zero() && !reward_addrs.contains(&asnd) {
            reward_addrs.push(asnd);
        }
    }
    if let Some(ac) = txn.asset_close_to {
        if !ac.is_zero() && !reward_addrs.contains(&ac) {
            reward_addrs.push(ac);
        }
    }
    // Asset freeze: target account.
    if let Some(fa) = txn.freeze_account {
        if !fa.is_zero() && !reward_addrs.contains(&fa) {
            reward_addrs.push(fa);
        }
    }

    // Extend with additional addresses needed for snapshot/rollback only
    // (these do NOT receive rewards — only transaction participants do).
    let mut touched = reward_addrs.clone();
    // Application accounts array: EvalDelta local deltas can mutate these.
    if let Some(ref accounts) = txn.accounts {
        for acct in accounts {
            if !acct.is_zero() && !touched.contains(acct) {
                touched.push(*acct);
            }
        }
    }

    // Determine asset/app IDs to snapshot for rollback, and include
    // creator addresses that may differ from the transaction sender.
    let mut asset_ids_to_snap = Vec::new();
    let mut app_ids_to_snap = Vec::new();
    match txn.txn_type.as_str() {
        "acfg" => {
            if txn.config_asset != 0 {
                asset_ids_to_snap.push(txn.config_asset);
                // Snapshot the asset creator for destroy/reconfig rollback.
                if let Some(params) = store.get_asset_params(txn.config_asset) {
                    if !touched.contains(&params.creator) {
                        touched.push(params.creator);
                    }
                }
            }
            if stx.apply_data_config_asset != 0 {
                asset_ids_to_snap.push(stx.apply_data_config_asset);
            }
        }
        "axfer" => {
            if txn.xaid != 0 {
                asset_ids_to_snap.push(txn.xaid);
            }
        }
        "afrz" => {
            if txn.freeze_asset != 0 {
                asset_ids_to_snap.push(txn.freeze_asset);
            }
        }
        "appl" => {
            if txn.application_id != 0 {
                app_ids_to_snap.push(txn.application_id);
                // Snapshot the app creator for delete rollback.
                if let Some(params) = store.get_app_params(txn.application_id) {
                    if !touched.contains(&params.creator) {
                        touched.push(params.creator);
                    }
                }
            }
            if stx.apply_data_application_id != 0 {
                app_ids_to_snap.push(stx.apply_data_application_id);
            }
        }
        _ => {}
    }

    // Snapshot all accounts that may be mutated (touched + fee_sink + rewards_pool)
    // for rollback. The rewards pool must be included because it is debited for
    // distributed rewards, and a later min-balance check failure must restore it.
    let mut snapshot_addrs = touched.clone();
    if !snapshot_addrs.contains(&ctx.fee_sink) {
        snapshot_addrs.push(ctx.fee_sink);
    }
    {
        let rp = store.rewards_pool();
        if !snapshot_addrs.contains(&rp) {
            snapshot_addrs.push(rp);
        }
    }

    let snapshot = if asset_ids_to_snap.is_empty() && app_ids_to_snap.is_empty() {
        store.snapshot(&snapshot_addrs)
    } else {
        store.snapshot_with_ids(&snapshot_addrs, &asset_ids_to_snap, &app_ids_to_snap)
    };

    // Execute all transaction logic inside a closure so that ANY error
    // (fee, type-specific, EvalDelta, rewards-pool debit, rekey) triggers
    // a full rollback via restore_snapshot.
    let result = (|| -> Result<(), AlgoError> {
        // Apply rewards to transaction participants only (not snapshot-only addresses).
        let mut total_rewards: u64 = 0;
        for addr in &reward_addrs {
            let mut account = store.get_or_default_account(addr);
            total_rewards += apply_rewards(&mut account, ctx.rewards_level);
            store.set_account(addr, account);
        }

        // Handle rekey_to BEFORE type-specific apply (matching Go's ordering:
        // rewards -> rekey -> type-specific dispatch).
        if let Some(rekey_addr) = txn.rekey_to {
            let mut account = store.get_or_default_account(&txn.sender);
            if rekey_addr == txn.sender || rekey_addr.is_zero() {
                account.auth_addr = None;
            } else {
                account.auth_addr = Some(rekey_addr);
            }
            store.set_account(&txn.sender, account);
        }

        // Dispatch by transaction type.
        match txn.txn_type.as_str() {
            "pay" => apply_pay(store, stx, ctx)?,
            "acfg" => apply_acfg(store, stx, ctx)?,
            "axfer" => apply_axfer(store, stx, ctx)?,
            "afrz" => apply_afrz(store, stx, ctx)?,
            "appl" => apply_appl(store, stx, ctx, depth, group_budget)?,
            "keyreg" => apply_keyreg(store, stx, ctx)?,
            other => {
                return Err(AlgoError::Ledger {
                    message: format!("unknown transaction type: {}", other),
                });
            }
        }

        // Apply EvalDelta if present. For "appl" transactions, EvalDelta is
        // already applied inside apply_appl() before on_completion structural
        // changes, so we skip it here to avoid double-application.
        if txn.txn_type != "appl" {
            if let Some(ref dt) = stx.eval_delta {
                let delta = parse_eval_delta(dt)?;
                apply_eval_delta(stx, &delta, store, ctx, depth)?;
            }
        }

        // Debit rewards pool for distributed rewards.
        if total_rewards > 0 {
            let rewards_pool_addr = store.rewards_pool();
            let mut pool = store.get_or_default_account(&rewards_pool_addr);
            if pool.micro_algos < total_rewards {
                return Err(AlgoError::Ledger {
                    message: format!(
                        "rewards pool balance {} insufficient for {} in rewards",
                        pool.micro_algos, total_rewards,
                    ),
                });
            }
            pool.micro_algos -= total_rewards;
            store.set_account(&rewards_pool_addr, pool);
        }

        // Check min balance for all touched accounts after the transaction.
        // Go checks all modified accounts per-transaction (skipping FeeSink,
        // RewardsPool, StateProofSender, and zeroed-out accounts).
        {
            let rewards_pool_addr = store.rewards_pool();
            for addr in &snapshot_addrs {
                // Skip special accounts that are exempt from min balance checks.
                if *addr == ctx.fee_sink || *addr == rewards_pool_addr {
                    continue;
                }
                if let Some(account) = store.get_account(addr) {
                    // Zeroed-out accounts (will be deleted) are OK.
                    if account == algo_types::AccountData::default() {
                        continue;
                    }
                    let min_bal = store.min_balance_with_state(addr, &account);
                    if account.micro_algos < min_bal {
                        return Err(AlgoError::Ledger {
                            message: format!(
                                "account {} balance {} below minimum balance {}",
                                addr, account.micro_algos, min_bal,
                            ),
                        });
                    }
                }
            }
        }

        // Record lease on success (no-op for empty/zero leases).
        store.record_lease(&txn.sender, &lease_arr, txn.last_valid.0);

        // Set update_round on all touched accounts (including fee_sink).
        // This tracks which round last modified each account, used by the
        // Merkle trie V6 hash builder as affinity bytes.
        for addr in &snapshot_addrs {
            let mut account = store.get_or_default_account(addr);
            if account.update_round < ctx.round {
                account.update_round = ctx.round;
                store.set_account(addr, account);
            }
        }

        Ok(())
    })();

    if result.is_err() {
        store.restore_snapshot(snapshot);
    }

    result
}

/// Debit fee from sender and credit to fee_sink.
fn apply_fee<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    sender: &Address,
    fee: u64,
    fee_sink: &Address,
) -> Result<(), AlgoError> {
    let mut sender_account = store.get_or_default_account(sender);
    if sender_account.micro_algos < fee {
        return Err(AlgoError::Ledger {
            message: format!(
                "sender {} has insufficient balance {} for fee {}",
                sender, sender_account.micro_algos, fee,
            ),
        });
    }
    sender_account.micro_algos -= fee;
    store.set_account(sender, sender_account);

    let mut fee_sink_account = store.get_or_default_account(fee_sink);
    fee_sink_account.micro_algos += fee;
    store.set_account(fee_sink, fee_sink_account);

    Ok(())
}

/// Apply a payment transaction.
///
/// Debits `amount + fee` from sender, credits `amount` to receiver,
/// credits `fee` to fee_sink. If `close_remainder_to` is set, moves
/// the sender's remaining balance to that address.
fn apply_pay<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
) -> Result<(), AlgoError> {
    let txn = &stx.txn;
    let total_debit = txn
        .amount
        .checked_add(txn.fee)
        .ok_or_else(|| AlgoError::Ledger {
            message: format!("amount {} + fee {} overflows u64", txn.amount, txn.fee,),
        })?;

    // Check sender has enough for amount + fee.
    {
        let mut sender = store.get_or_default_account(&txn.sender);
        if sender.micro_algos < total_debit {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} has insufficient balance {} for payment {} + fee {}",
                    txn.sender, sender.micro_algos, txn.amount, txn.fee,
                ),
            });
        }
        sender.micro_algos -= total_debit;
        store.set_account(&txn.sender, sender);
    }

    // Credit receiver.
    if txn.amount > 0 {
        let mut receiver = store.get_or_default_account(&txn.receiver);
        receiver.micro_algos += txn.amount;
        store.set_account(&txn.receiver, receiver);
    }

    // Credit fee_sink.
    {
        let mut fee_sink = store.get_or_default_account(&ctx.fee_sink);
        fee_sink.micro_algos += txn.fee;
        store.set_account(&ctx.fee_sink, fee_sink);
    }

    // Handle close_remainder_to.
    if !txn.close_remainder_to.is_zero() {
        let sender = store.get_or_default_account(&txn.sender);

        // Cannot close account with opted-in or created assets/apps.
        if sender.total_assets_opted_in > 0 {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} cannot close: has {} opted-in assets",
                    txn.sender, sender.total_assets_opted_in,
                ),
            });
        }
        if sender.total_created_assets > 0 {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} cannot close: has {} created assets",
                    txn.sender, sender.total_created_assets,
                ),
            });
        }
        if sender.total_apps_opted_in > 0 {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} cannot close: has {} opted-in apps",
                    txn.sender, sender.total_apps_opted_in,
                ),
            });
        }
        if sender.total_created_apps > 0 {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} cannot close: has {} created apps",
                    txn.sender, sender.total_created_apps,
                ),
            });
        }
        if sender.total_boxes > 0 {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} cannot close: has {} outstanding boxes",
                    txn.sender, sender.total_boxes,
                ),
            });
        }
        if sender.total_box_bytes > 0 {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} cannot close: has {} outstanding box bytes",
                    txn.sender, sender.total_box_bytes,
                ),
            });
        }

        let close_amount = sender.micro_algos;
        // Go calls CloseAccount() which zeros the entire account record.
        // Reset to default to match that behavior.
        store.set_account(&txn.sender, algo_types::AccountData::default());

        let mut close_to = store.get_or_default_account(&txn.close_remainder_to);
        close_to.micro_algos += close_amount;
        store.set_account(&txn.close_remainder_to, close_to);
    }

    Ok(())
}

/// Apply an asset config transaction (create, reconfigure, or destroy).
fn apply_acfg<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
) -> Result<(), AlgoError> {
    let txn = &stx.txn;

    // Debit fee first.
    apply_fee(store, &txn.sender, txn.fee, &ctx.fee_sink)?;

    if txn.config_asset == 0 {
        // ── Create ──
        let new_asset_id = stx.apply_data_config_asset;
        if new_asset_id == 0 {
            return Err(AlgoError::Ledger {
                message: "acfg create: apply_data_config_asset (caid) is zero".to_string(),
            });
        }

        let txn_params = txn.asset_params.as_ref().cloned().unwrap_or_default();
        let total = txn_params.total;

        let record = AssetParamsRecord {
            params: txn_params,
            creator: txn.sender,
        };
        store.set_asset_params(new_asset_id, record);

        // Creator gets the full supply and an opt-in holding.
        store.set_asset_holding(
            &txn.sender,
            new_asset_id,
            AssetHolding {
                amount: total,
                frozen: false,
            },
        );

        let mut sender_account = store.get_or_default_account(&txn.sender);
        sender_account.total_created_assets += 1;
        sender_account.total_assets_opted_in += 1;
        store.set_account(&txn.sender, sender_account);
    } else {
        // ── Reconfigure or Destroy ──
        let asset_id = txn.config_asset;
        let existing = store
            .get_asset_params(asset_id)
            .ok_or_else(|| AlgoError::Ledger {
                message: format!("acfg: asset {} does not exist", asset_id),
            })?;

        // Sender must be the manager.
        let existing_manager = existing.params.manager.unwrap_or(Address::ZERO);
        if existing_manager.is_zero() || txn.sender != existing_manager {
            return Err(AlgoError::Ledger {
                message: format!(
                    "acfg: sender {} is not the manager of asset {}",
                    txn.sender, asset_id,
                ),
            });
        }

        let creator = existing.creator;
        let txn_params = txn.asset_params.as_ref().cloned().unwrap_or_default();

        if txn_params == AssetParams::default() {
            // ── Destroy ──
            // Verify creator holds full supply.
            let holding =
                store
                    .get_asset_holding(&creator, asset_id)
                    .ok_or_else(|| AlgoError::Ledger {
                        message: format!(
                            "acfg destroy: creator {} has no holding for asset {}",
                            creator, asset_id,
                        ),
                    })?;
            let params_total = existing.params.total;
            if holding.amount != params_total {
                return Err(AlgoError::Ledger {
                    message: format!(
                        "acfg destroy: creator holds {} but total supply is {} for asset {}",
                        holding.amount, params_total, asset_id,
                    ),
                });
            }

            // Remove asset params and creator holding.
            // NOTE: This intentionally does NOT remove other accounts' zero-balance
            // holdings for this asset. In go-algorand, asset destruction only removes
            // the creator's holding and the asset params. Other opted-in accounts with
            // zero balance keep their stale holdings — they must explicitly close-out
            // via an axfer with asset_close_to to reclaim their min-balance.
            store.remove_asset_params(asset_id);
            store.remove_asset_holding(&creator, asset_id);

            let mut creator_account = store.get_or_default_account(&creator);
            creator_account.total_created_assets =
                creator_account.total_created_assets.saturating_sub(1);
            creator_account.total_assets_opted_in =
                creator_account.total_assets_opted_in.saturating_sub(1);
            store.set_account(&creator, creator_account);
        } else {
            // ── Reconfigure ──
            let mut updated_params = existing.params.clone();

            // Only update roles that are currently non-zero.
            if updated_params.manager.is_some_and(|a| !a.is_zero()) {
                updated_params.manager = txn_params.manager;
            }
            if updated_params.reserve.is_some_and(|a| !a.is_zero()) {
                updated_params.reserve = txn_params.reserve;
            }
            if updated_params.freeze.is_some_and(|a| !a.is_zero()) {
                updated_params.freeze = txn_params.freeze;
            }
            if updated_params.clawback.is_some_and(|a| !a.is_zero()) {
                updated_params.clawback = txn_params.clawback;
            }

            let mut record = existing;
            record.params = updated_params;
            store.set_asset_params(asset_id, record);
        }
    }

    Ok(())
}

/// Apply an asset transfer transaction (opt-in, transfer, clawback, close-to).
fn apply_axfer<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
) -> Result<(), AlgoError> {
    let txn = &stx.txn;

    // Debit fee first.
    apply_fee(store, &txn.sender, txn.fee, &ctx.fee_sink)?;

    let asset_id = txn.xaid;
    if asset_id == 0 {
        return Err(AlgoError::Ledger {
            message: "axfer: asset ID (xaid) is zero".to_string(),
        });
    }

    let asset_receiver = txn.asset_receiver.ok_or_else(|| AlgoError::Ledger {
        message: "axfer: asset_receiver (arcv) is missing".to_string(),
    })?;

    let clawback_source = txn.asset_sender.filter(|a| !a.is_zero());
    let from_addr = clawback_source.unwrap_or(txn.sender);
    let is_clawback = clawback_source.is_some();

    // ── Clawback cannot use close-to (go-algorand: "cannot close asset by clawback") ──
    if is_clawback && txn.asset_close_to.is_some_and(|a| !a.is_zero()) {
        return Err(AlgoError::Ledger {
            message: format!("axfer: cannot close asset by clawback (asset {})", asset_id,),
        });
    }

    // ── Clawback authorization ──
    if is_clawback {
        let params = store
            .get_asset_params(asset_id)
            .ok_or_else(|| AlgoError::Ledger {
                message: format!("axfer: asset {} does not exist", asset_id),
            })?;
        let clawback = params.params.clawback.unwrap_or(Address::ZERO);
        if txn.sender != clawback {
            return Err(AlgoError::Ledger {
                message: format!(
                    "axfer clawback: sender {} is not the clawback address for asset {}",
                    txn.sender, asset_id,
                ),
            });
        }
    }

    // ── Opt-in detection ──
    let is_optin = asset_receiver == txn.sender
        && txn.asset_amount == 0
        && !is_clawback
        && txn.asset_close_to.is_none();

    if is_optin {
        if store.has_asset_holding(&txn.sender, asset_id) {
            // Go does NOT error on duplicate opt-in — it falls through to the
            // transfer path which is a 0-amount self-transfer no-op. Match that
            // behavior by simply returning Ok.
        } else {
            let params = store
                .get_asset_params(asset_id)
                .ok_or_else(|| AlgoError::Ledger {
                    message: format!("axfer opt-in: asset {} does not exist", asset_id),
                })?;
            let default_frozen = params.params.default_frozen;
            store.set_asset_holding(
                &txn.sender,
                asset_id,
                AssetHolding {
                    amount: 0,
                    frozen: default_frozen,
                },
            );
            let mut sender_account = store.get_or_default_account(&txn.sender);
            sender_account.total_assets_opted_in += 1;
            store.set_account(&txn.sender, sender_account);
        }
    } else {
        // ── Frozen check (only for non-clawback) ──
        if !is_clawback {
            let from_holding = store
                .get_asset_holding(&from_addr, asset_id)
                .ok_or_else(|| AlgoError::Ledger {
                    message: format!("axfer: {} has no holding for asset {}", from_addr, asset_id,),
                })?;
            if from_holding.frozen {
                return Err(AlgoError::Ledger {
                    message: format!(
                        "axfer: {} holding for asset {} is frozen",
                        from_addr, asset_id,
                    ),
                });
            }
        }

        // ── Transfer ──
        // Both sender and receiver must be opted in, even for zero-amount transfers.
        if !store.has_asset_holding(&from_addr, asset_id) {
            return Err(AlgoError::Ledger {
                message: format!("axfer: {} has no holding for asset {}", from_addr, asset_id),
            });
        }
        if !store.has_asset_holding(&asset_receiver, asset_id) {
            return Err(AlgoError::Ledger {
                message: format!(
                    "axfer: receiver {} has no holding for asset {} (not opted in)",
                    asset_receiver, asset_id,
                ),
            });
        }
        // Check receiver frozen (non-clawback only, matching go-algorand).
        if !is_clawback {
            if let Some(recv_holding) = store.get_asset_holding(&asset_receiver, asset_id) {
                if recv_holding.frozen {
                    return Err(AlgoError::Ledger {
                        message: format!(
                            "axfer: receiver {} holding for asset {} is frozen",
                            asset_receiver, asset_id,
                        ),
                    });
                }
            }
        }
        if txn.asset_amount > 0 {
            // Debit from.
            let mut from_holding = store.get_asset_holding(&from_addr, asset_id).unwrap();
            if from_holding.amount < txn.asset_amount {
                return Err(AlgoError::Ledger {
                    message: format!(
                        "axfer: {} holding {} insufficient for transfer {} of asset {}",
                        from_addr, from_holding.amount, txn.asset_amount, asset_id,
                    ),
                });
            }
            from_holding.amount -= txn.asset_amount;
            store.set_asset_holding(&from_addr, asset_id, from_holding);

            // Credit receiver.
            let mut recv_holding = store.get_asset_holding(&asset_receiver, asset_id).unwrap();
            recv_holding.amount += txn.asset_amount;
            store.set_asset_holding(&asset_receiver, asset_id, recv_holding);
        }

        // ── Close-to ──
        if let Some(close_to) = txn.asset_close_to {
            if !close_to.is_zero() {
                // Close the source account's holding. For non-clawback, from_addr == txn.sender.
                // (Clawback + close-to is rejected above, so from_addr is always txn.sender here.)
                let close_from = from_addr;

                // The creator of the asset cannot close their holding.
                // Go: HasAssetParams(source, ct.XferAsset) -> "cannot close asset ID in allocating account"
                // Also determine if we bypass frozen checks: allowed when closing
                // to the asset creator (go-algorand: bypassFreeze = HasAssetParams(closeTo)).
                let bypass_freeze = if let Some(params_record) = store.get_asset_params(asset_id) {
                    if params_record.creator == close_from {
                        return Err(AlgoError::Ledger {
                            message: "cannot close asset ID in allocating account".to_string(),
                        });
                    }
                    params_record.creator == close_to
                } else {
                    false
                };

                let from_holding =
                    store
                        .get_asset_holding(&close_from, asset_id)
                        .ok_or_else(|| AlgoError::Ledger {
                            message: format!(
                                "axfer close: {} has no holding for asset {}",
                                close_from, asset_id,
                            ),
                        })?;
                let remaining = from_holding.amount;

                // Check frozen on the sender's holding (unless bypassed).
                if from_holding.frozen && !bypass_freeze {
                    return Err(AlgoError::Ledger {
                        message: format!(
                            "axfer close: {} holding for asset {} is frozen",
                            close_from, asset_id,
                        ),
                    });
                }

                if remaining > 0 {
                    // Check frozen on close-to's holding (unless bypassed).
                    let mut close_holding = store
                        .get_asset_holding(&close_to, asset_id)
                        .ok_or_else(|| AlgoError::Ledger {
                            message: format!(
                                "axfer close: {} has no holding for asset {} (not opted in)",
                                close_to, asset_id,
                            ),
                        })?;
                    if close_holding.frozen && !bypass_freeze {
                        return Err(AlgoError::Ledger {
                            message: format!(
                                "axfer close: receiver {} holding for asset {} is frozen",
                                close_to, asset_id,
                            ),
                        });
                    }
                    close_holding.amount += remaining;
                    store.set_asset_holding(&close_to, asset_id, close_holding);
                }

                // Remove sender holding.
                store.remove_asset_holding(&close_from, asset_id);

                let mut sender_account = store.get_or_default_account(&close_from);
                sender_account.total_assets_opted_in =
                    sender_account.total_assets_opted_in.saturating_sub(1);
                store.set_account(&close_from, sender_account);
            }
        }
    }

    Ok(())
}

/// Apply an asset freeze transaction.
fn apply_afrz<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
) -> Result<(), AlgoError> {
    let txn = &stx.txn;

    // Debit fee first.
    apply_fee(store, &txn.sender, txn.fee, &ctx.fee_sink)?;

    let asset_id = txn.freeze_asset;
    if asset_id == 0 {
        return Err(AlgoError::Ledger {
            message: "afrz: freeze asset ID (faid) is zero".to_string(),
        });
    }

    // Look up asset params to verify sender is the freeze address.
    let params = store
        .get_asset_params(asset_id)
        .ok_or_else(|| AlgoError::Ledger {
            message: format!("afrz: asset {} does not exist", asset_id),
        })?;
    let freeze_addr = params.params.freeze.unwrap_or(Address::ZERO);
    if freeze_addr.is_zero() || txn.sender != freeze_addr {
        return Err(AlgoError::Ledger {
            message: format!(
                "afrz: sender {} is not the freeze address for asset {}",
                txn.sender, asset_id,
            ),
        });
    }

    let target = txn.freeze_account.ok_or_else(|| AlgoError::Ledger {
        message: "afrz: freeze_account (fadd) is missing".to_string(),
    })?;

    let mut holding =
        store
            .get_asset_holding(&target, asset_id)
            .ok_or_else(|| AlgoError::Ledger {
                message: format!("afrz: {} has no holding for asset {}", target, asset_id,),
            })?;
    holding.frozen = txn.asset_frozen;
    store.set_asset_holding(&target, asset_id, holding);

    Ok(())
}

/// On-completion action constants for application calls.
const ON_COMPLETION_OPT_IN: u64 = 1;
const ON_COMPLETION_CLOSE_OUT: u64 = 2;
const ON_COMPLETION_CLEAR_STATE: u64 = 3;
const ON_COMPLETION_UPDATE: u64 = 4;
const ON_COMPLETION_DELETE: u64 = 5;

/// Compute SHA-512/256 hash of program bytes for AVM context.
fn program_hash(program: &[u8]) -> [u8; 32] {
    let mut h = Sha512_256::new();
    h.update(b"Program");
    h.update(program);
    h.finalize().into()
}

/// Apply an application call transaction.
///
/// Handles creation, opt-in, close-out, clear-state, update, delete, and no-op.
/// EvalDelta is applied BEFORE the on_completion structural changes (matching
/// go-algorand ordering): TEAL executes first (writing state via EvalDelta),
/// then the runtime performs close-out/delete cleanup. This prevents EvalDelta's
/// `or_insert_with` calls from recreating entries that close-out/delete removed.
///
/// In `Execute` mode, the AVM programs are run to produce state changes
/// directly. In `Replay` mode, the recorded EvalDelta from the block is used.
/// The optional `group_budget` is consumed only in `Execute` mode.
fn apply_appl<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
    depth: u32,
    group_budget: Option<&mut GroupBudget>,
) -> Result<(), AlgoError> {
    let txn = &stx.txn;

    // Debit fee first.
    apply_fee(store, &txn.sender, txn.fee, &ctx.fee_sink)?;

    let is_create = txn.application_id == 0;
    let app_id = if is_create {
        stx.apply_data_application_id
    } else {
        txn.application_id
    };

    // For non-create calls, verify the app exists in state.
    // Exception: ClearState always succeeds even if app is deleted (lets users reclaim local state).
    if !is_create && txn.on_completion != ON_COMPLETION_CLEAR_STATE && !store.has_app_params(app_id)
    {
        return Err(AlgoError::Ledger {
            message: format!("appl: app {} does not exist", app_id),
        });
    }

    if is_create {
        // App creation: create AppParams entry.
        if app_id == 0 {
            return Err(AlgoError::Ledger {
                message: "appl create: apply_data_application_id (apid) is zero".to_string(),
            });
        }

        let approval = txn
            .approval_program
            .as_ref()
            .map(|b| b.to_vec())
            .unwrap_or_default();
        let clear = txn
            .clear_state_program
            .as_ref()
            .map(|b| b.to_vec())
            .unwrap_or_default();

        let global_schema = txn.global_state_schema.clone().unwrap_or_default();
        let local_schema = txn.local_state_schema.clone().unwrap_or_default();
        let extra_pages = txn.extra_program_pages;

        store.set_app_params(
            app_id,
            AppParams {
                creator: txn.sender,
                approval_program: approval,
                clear_state_program: clear,
                global_state: std::collections::BTreeMap::new(),
                local_state_schema: local_schema,
                global_state_schema: global_schema.clone(),
                extra_program_pages: extra_pages,
            },
        );

        let mut sender_account = store.get_or_default_account(&txn.sender);
        sender_account.total_created_apps += 1;
        sender_account.total_extra_app_pages += extra_pages;
        // Update aggregate schema: creator stores global state.
        sender_account.total_app_schema =
            sender_account.total_app_schema.add_schema(&global_schema);
        store.set_account(&txn.sender, sender_account);
    }

    // Record whether local state exists BEFORE EvalDelta, so the OptIn branch
    // can correctly detect a new opt-in even if EvalDelta creates a placeholder entry.
    let had_local_state = store.has_app_local_state(&txn.sender, app_id);

    // EvalDelta sourcing: Replay uses recorded block data, Execute runs AVM.
    match ctx.mode {
        ApplyMode::Replay => {
            // Apply EvalDelta BEFORE on_completion structural changes (matching go-algorand).
            // TEAL executes first (writing global/local state), then the runtime performs
            // structural close-out/delete. This ordering prevents EvalDelta from recreating
            // entries that close-out or delete would remove.
            if let Some(ref dt) = stx.eval_delta {
                let delta = parse_eval_delta(dt)?;
                apply_eval_delta(stx, &delta, store, ctx, depth)?;
            }
        }
        ApplyMode::Execute => {
            // Look up app params to get the program bytes.
            let app_params = store.get_app_params(app_id);
            let creator = app_params
                .as_ref()
                .map(|p| p.creator.0)
                .unwrap_or([0u8; 32]);

            if txn.on_completion == ON_COMPLETION_CLEAR_STATE {
                // ClearState: run clear-state program with isolated budget.
                // If program rejects or errors, roll back any store mutations
                // made during AVM execution (IsolateClearState semantics), then
                // proceed to the on-completion branch which clears local state.
                let clear_program = app_params
                    .map(|p| p.clear_state_program.clone())
                    .unwrap_or_default();

                if !clear_program.is_empty() {
                    let ph = program_hash(&clear_program);

                    // Snapshot store BEFORE AVM execution so we can roll back
                    // any state mutations if the program rejects/errors.
                    // We snapshot the sender, any accounts in the txn's accounts
                    // array, and the app's global state (via app_ids).
                    let mut cs_addrs = vec![txn.sender];
                    if let Some(ref accounts) = txn.accounts {
                        for acct in accounts {
                            if !acct.is_zero() && !cs_addrs.contains(acct) {
                                cs_addrs.push(*acct);
                            }
                        }
                    }
                    let cs_snapshot = store.snapshot_with_ids(&cs_addrs, &[], &[app_id]);

                    let group = vec![stx.clone()];
                    let mut avm_ctx = LedgerAvmContext::new(
                        store,
                        group,
                        0, // group_index (single-txn group for now)
                        ctx.round,
                        ctx.latest_timestamp,
                        app_id,
                        creator,
                        true, // app_mode
                        ph,
                        ctx.genesis_hash,
                    );
                    let result = run_clear_state_program(&clear_program, &mut avm_ctx);
                    if !result.approved {
                        // ClearState rejection: roll back any state changes the
                        // program made during execution. The on-completion branch
                        // below will still clear local state regardless.
                        store.restore_snapshot(cs_snapshot);
                    }
                }
            } else {
                // Non-ClearState: run approval program.
                //
                // No separate snapshot is needed here: if the program rejects,
                // apply_appl returns Err, which propagates to apply_transaction_inner's
                // closure. That outer closure's error path restores the snapshot
                // taken at the top of apply_transaction_inner, reverting all state
                // changes (including any AVM writes) for the entire transaction.
                let approval_program = app_params
                    .map(|p| p.approval_program.clone())
                    .unwrap_or_default();

                if approval_program.is_empty() {
                    return Err(AlgoError::Ledger {
                        message: format!("appl execute: app {} has empty approval program", app_id),
                    });
                }

                let ph = program_hash(&approval_program);
                let group = vec![stx.clone()];
                let mut avm_ctx = LedgerAvmContext::new(
                    store,
                    group,
                    0, // group_index
                    ctx.round,
                    ctx.latest_timestamp,
                    app_id,
                    creator,
                    true, // app_mode
                    ph,
                    ctx.genesis_hash,
                );

                // Use the group budget if provided, otherwise create a single-call budget.
                let mut fallback_budget = GroupBudget::new(1);
                let budget = group_budget.unwrap_or(&mut fallback_budget);
                let result = run_approval_program(&approval_program, &mut avm_ctx, budget)?;

                if !result.approved {
                    return Err(AlgoError::Ledger {
                        message: format!(
                            "appl execute: app {} approval program rejected transaction{}",
                            app_id,
                            result
                                .error
                                .as_ref()
                                .map(|e| format!(": {}", e))
                                .unwrap_or_default()
                        ),
                    });
                }
            }
        }
    }

    match txn.on_completion {
        ON_COMPLETION_OPT_IN => {
            // Reject duplicate opt-in.
            if had_local_state {
                return Err(AlgoError::Ledger {
                    message: format!(
                        "appl opt-in: {} is already opted into app {}",
                        txn.sender, app_id,
                    ),
                });
            }
            {
                let local_schema = if is_create {
                    txn.local_state_schema.clone().unwrap_or_default()
                } else {
                    store
                        .get_app_params(app_id)
                        .map(|p| p.local_state_schema.clone())
                        .unwrap_or_default()
                };

                // Insert or update with the correct schema (EvalDelta may have
                // already created a placeholder with default schema).
                let mut local = store
                    .get_app_local_state(&txn.sender, app_id)
                    .unwrap_or_else(|| AppLocalState {
                        schema: local_schema.clone(),
                        key_value: std::collections::BTreeMap::new(),
                    });
                local.schema = local_schema.clone();
                store.set_app_local_state(&txn.sender, app_id, local);

                let mut sender_account = store.get_or_default_account(&txn.sender);
                sender_account.total_apps_opted_in += 1;
                // Update aggregate schema: sender stores local state.
                sender_account.total_app_schema =
                    sender_account.total_app_schema.add_schema(&local_schema);
                store.set_account(&txn.sender, sender_account);
            }
        }
        ON_COMPLETION_CLOSE_OUT => {
            // CloseOut requires the sender to be opted in.
            let local_state = store
                .get_app_local_state(&txn.sender, app_id)
                .ok_or_else(|| AlgoError::Ledger {
                    message: format!(
                        "appl close-out: {} is not opted into app {}",
                        txn.sender, app_id,
                    ),
                })?;
            let local_schema = local_state.schema.clone();
            store.remove_app_local_state(&txn.sender, app_id);
            let mut sender_account = store.get_or_default_account(&txn.sender);
            sender_account.total_apps_opted_in =
                sender_account.total_apps_opted_in.saturating_sub(1);
            // Subtract local schema from aggregate.
            sender_account.total_app_schema =
                sender_account.total_app_schema.sub_schema(&local_schema);
            store.set_account(&txn.sender, sender_account);
        }
        ON_COMPLETION_CLEAR_STATE => {
            // ClearState removes local state if present (does not fail if absent).
            if let Some(local_state) = store.get_app_local_state(&txn.sender, app_id) {
                let local_schema = local_state.schema.clone();
                store.remove_app_local_state(&txn.sender, app_id);
                let mut sender_account = store.get_or_default_account(&txn.sender);
                sender_account.total_apps_opted_in =
                    sender_account.total_apps_opted_in.saturating_sub(1);
                // Subtract local schema from aggregate.
                sender_account.total_app_schema =
                    sender_account.total_app_schema.sub_schema(&local_schema);
                store.set_account(&txn.sender, sender_account);
            }
        }
        ON_COMPLETION_DELETE => {
            // Only the creator can delete the app.
            if let Some(existing) = store.get_app_params(app_id) {
                if txn.sender != existing.creator {
                    return Err(AlgoError::Ledger {
                        message: format!(
                            "appl delete: sender {} is not the creator of app {}",
                            txn.sender, app_id,
                        ),
                    });
                }
                // Remove the app — decrement the CREATOR's counters, not sender's.
                let creator = existing.creator;
                let global_schema = existing.global_state_schema.clone();
                store.remove_app_params(app_id);
                let mut creator_account = store.get_or_default_account(&creator);
                creator_account.total_created_apps =
                    creator_account.total_created_apps.saturating_sub(1);
                creator_account.total_extra_app_pages = creator_account
                    .total_extra_app_pages
                    .saturating_sub(existing.extra_program_pages);
                // Subtract global schema from aggregate.
                creator_account.total_app_schema =
                    creator_account.total_app_schema.sub_schema(&global_schema);
                store.set_account(&creator, creator_account);
            }
        }
        ON_COMPLETION_UPDATE => {
            // Only the creator can update the app programs.
            if let Some(mut app) = store.get_app_params(app_id) {
                if txn.sender != app.creator {
                    return Err(AlgoError::Ledger {
                        message: format!(
                            "appl update: sender {} is not the creator of app {}",
                            txn.sender, app_id,
                        ),
                    });
                }
                // Update the app programs only — extra_program_pages are immutable
                // post-creation in go-algorand.
                if let Some(ref approval) = txn.approval_program {
                    app.approval_program = approval.to_vec();
                }
                if let Some(ref clear) = txn.clear_state_program {
                    app.clear_state_program = clear.to_vec();
                }
                store.set_app_params(app_id, app);
            }
        }
        0 => {
            // NoOp — no structural state changes beyond EvalDelta.
        }
        other => {
            return Err(AlgoError::Ledger {
                message: format!("appl: unknown on_completion value {}", other),
            });
        }
    }

    Ok(())
}

/// Apply a key registration transaction.
///
/// Transitions account participation status:
/// - `non_participation == true`: set NotParticipating (irreversible), clear all keys
/// - `vote_pk` present with non-empty bytes: go Online, copy key material
/// - Otherwise (offline keyreg): go Offline, clear all keys
///
/// Fee is already handled by the caller (`apply_transaction` deducts fee before dispatch).
fn apply_keyreg<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
) -> Result<(), AlgoError> {
    let txn = &stx.txn;

    // Debit fee first.
    apply_fee(store, &txn.sender, txn.fee, &ctx.fee_sink)?;

    // Guard: NotParticipating is irreversible.
    {
        let account = store.get_or_default_account(&txn.sender);
        if account.status == AccountStatus::NotParticipating {
            return Err(AlgoError::Ledger {
                message: format!(
                    "keyreg: account {} has status NotParticipating (irreversible)",
                    txn.sender,
                ),
            });
        }
    }

    // Go checks: if VotePK.IsEmpty() || SelectionPK.IsEmpty() -> offline/nonpart,
    // else -> online.  We must check BOTH keys to determine online vs offline.
    let vote_pk_empty = !txn.vote_pk.as_ref().is_some_and(|pk| !pk.is_empty());
    let selection_pk_empty = !txn.selection_pk.as_ref().is_some_and(|pk| !pk.is_empty());

    if vote_pk_empty || selection_pk_empty {
        // ── Offline or non-participating ──
        let mut account = store.get_or_default_account(&txn.sender);
        if txn.non_participation {
            account.status = AccountStatus::NotParticipating;
        } else {
            account.status = AccountStatus::Offline;
        }
        account.vote_id = None;
        account.selection_id = None;
        account.state_proof_id = None;
        account.vote_first_valid = 0;
        account.vote_last_valid = 0;
        account.vote_key_dilution = 0;
        store.set_account(&txn.sender, account);
    } else if txn.vote_pk.as_ref().is_some_and(|pk| !pk.is_empty()) {
        // ── Online keyreg ──
        let vote_bytes = txn.vote_pk.as_ref().unwrap();
        if vote_bytes.len() != 32 {
            return Err(AlgoError::Ledger {
                message: format!("keyreg: vote_pk length {} != 32", vote_bytes.len(),),
            });
        }
        let mut vote_id = [0u8; 32];
        vote_id.copy_from_slice(vote_bytes);

        let sel_bytes = txn.selection_pk.as_ref().ok_or_else(|| AlgoError::Ledger {
            message: "keyreg online: selection_pk is missing".to_string(),
        })?;
        if sel_bytes.len() != 32 {
            return Err(AlgoError::Ledger {
                message: format!("keyreg: selection_pk length {} != 32", sel_bytes.len(),),
            });
        }
        let mut selection_id = [0u8; 32];
        selection_id.copy_from_slice(sel_bytes);

        let state_proof_id = if let Some(ref sp_bytes) = txn.state_proof_pk {
            if !sp_bytes.is_empty() {
                if sp_bytes.len() != 64 {
                    return Err(AlgoError::Ledger {
                        message: format!("keyreg: state_proof_pk length {} != 64", sp_bytes.len(),),
                    });
                }
                let mut sp_id = [0u8; 64];
                sp_id.copy_from_slice(sp_bytes);
                Some(sp_id)
            } else {
                None
            }
        } else {
            None
        };

        // Validate participation parameters.
        if txn.vote_key_dilution == 0 {
            return Err(AlgoError::Ledger {
                message: "keyreg online: vote_key_dilution must be > 0".to_string(),
            });
        }
        if txn.vote_last < txn.vote_first {
            return Err(AlgoError::Ledger {
                message: format!(
                    "keyreg online: vote_last {} < vote_first {}",
                    txn.vote_last, txn.vote_first
                ),
            });
        }

        // D14: Round-based keyreg coherency check (Go: EnableKeyregCoherencyCheck, enabled since v28).
        // VoteLast must be beyond the current round, and VoteFirst must start by next round.
        let round = ctx.round;
        if txn.vote_last <= round {
            return Err(AlgoError::Ledger {
                message: format!(
                    "keyreg online: vote_last {} <= current round {} (expired participation key)",
                    txn.vote_last, round,
                ),
            });
        }
        if txn.vote_first > round + 1 {
            return Err(AlgoError::Ledger {
                message: format!(
                    "keyreg online: vote_first {} > round+1 {} (first voting round too far in future)",
                    txn.vote_first, round + 1,
                ),
            });
        }

        let mut account = store.get_or_default_account(&txn.sender);
        account.status = AccountStatus::Online;
        account.vote_id = Some(vote_id);
        account.selection_id = Some(selection_id);
        account.state_proof_id = state_proof_id;
        account.vote_first_valid = txn.vote_first;
        account.vote_last_valid = txn.vote_last;
        account.vote_key_dilution = txn.vote_key_dilution;

        // D15: Incentive eligibility and last heartbeat (Go: Payouts.Enabled, since v40).
        // Go sets IncentiveEligible = true when fee >= Payouts.GoOnlineFee && Payouts.Enabled.
        // Go sets LastHeartbeat = round + lookback when Payouts.Enabled.
        // Payouts.GoOnlineFee = 2_000_000 (2 Algos), Payouts.Enabled since v40.
        // lookback = 2 * SeedRefreshInterval * SeedLookback = 2 * 80 * 2 = 320.
        const PAYOUTS_GO_ONLINE_FEE: u64 = 2_000_000;
        const BALANCE_LOOKBACK: u64 = 320; // 2 * SeedRefreshInterval(80) * SeedLookback(2)

        // TODO(conformance): Gate on Payouts.Enabled once consensus params are version-aware.
        // Currently assumes v40+ where Payouts is enabled.
        account.last_heartbeat = round + BALANCE_LOOKBACK;

        // TODO(conformance): Gate on Payouts.Enabled once consensus params are version-aware.
        // Currently assumes v40+ where Payouts is enabled.
        if txn.fee >= PAYOUTS_GO_ONLINE_FEE {
            account.incentive_eligible = true;
        }

        store.set_account(&txn.sender, account);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::LedgerState;

    fn make_state_with_accounts(balances: &[(Address, u64)], fee_sink: Address) -> LedgerState {
        let mut state = LedgerState::new();
        state.fee_sink = fee_sink;
        for (addr, balance) in balances {
            let account = state.get_or_default_account(addr);
            account.micro_algos = *balance;
        }
        state
    }

    fn pay_txn(sender: Address, receiver: Address, amount: u64, fee: u64) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "pay".to_string();
        stx.txn.sender = sender;
        stx.txn.receiver = receiver;
        stx.txn.amount = amount;
        stx.txn.fee = fee;
        stx
    }

    #[test]
    fn test_simple_payment() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (receiver, 500_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let stx = pay_txn(sender, receiver, 200_000, 1_000);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 799_000);
        assert_eq!(state.get_account(&receiver).unwrap().micro_algos, 700_000);
        assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 1_000);
    }

    #[test]
    fn test_insufficient_balance() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 100), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let stx = pay_txn(sender, receiver, 200, 1_000);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        // Verify state was not mutated (rollback).
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 100);
    }

    #[test]
    fn test_close_remainder_to() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let close_to = Address([4u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (sender, 1_000_000),
                (receiver, 0),
                (close_to, 0),
                (fee_sink, 0),
            ],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let mut stx = pay_txn(sender, receiver, 100_000, 1_000);
        stx.txn.close_remainder_to = close_to;

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 0);
        assert_eq!(state.get_account(&receiver).unwrap().micro_algos, 100_000);
        // close_to gets remainder: 1_000_000 - 100_000 - 1_000 = 899_000
        assert_eq!(state.get_account(&close_to).unwrap().micro_algos, 899_000);
        assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 1_000);
    }

    #[test]
    fn test_close_with_assets_fails() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let close_to = Address([4u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        state.get_or_default_account(&sender).total_assets_opted_in = 1;

        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let mut stx = pay_txn(sender, receiver, 0, 1_000);
        stx.txn.close_remainder_to = close_to;

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_min_balance_check() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 200_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        // Try to send 100_000 + 1_000 fee, leaving 99_000 < min_balance (100_000)
        let stx = pay_txn(sender, receiver, 100_000, 1_000);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_rekey_to() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let auth = Address([5u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(sender, 1_000_000), (receiver, 100_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let mut stx = pay_txn(sender, receiver, 1_000, 1_000);
        stx.txn.rekey_to = Some(auth);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();
        assert_eq!(state.get_account(&sender).unwrap().auth_addr, Some(auth),);

        // Rekey back to self clears auth_addr.
        let mut stx2 = pay_txn(sender, receiver, 1_000, 1_000);
        stx2.txn.rekey_to = Some(sender);

        apply_transaction(&mut state, &stx2, &ctx, 0).unwrap();
        assert_eq!(state.get_account(&sender).unwrap().auth_addr, None);
    }

    #[test]
    fn test_stpf_is_noop() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "stpf".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = 0;

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();
        // Balance unchanged — stpf is a no-op.
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 1_000_000);
    }

    #[test]
    fn test_unknown_type_returns_error() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "bogus".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = 2_000;

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        // Balance unchanged — unknown type is rejected.
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 1_000_000);
    }

    #[test]
    fn test_keyreg_offline_debits_fee() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "keyreg".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = 2_000;

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 998_000);
        assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 2_000);
        assert_eq!(
            state.get_account(&sender).unwrap().status,
            AccountStatus::Offline,
        );
    }

    #[test]
    fn test_non_pay_min_balance_check() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        // Sender at exactly min_balance (100_000). Fee of 1_000 drops below.
        let mut state = make_state_with_accounts(&[(sender, 100_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "keyreg".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = 1_000;

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        // Verify rollback — sender balance unchanged.
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 100_000);
    }

    #[test]
    fn test_rewards_pool_debited() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let rewards_pool = Address([4u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (sender, 5_000_000),
                (receiver, 100_000),
                (fee_sink, 0),
                (rewards_pool, 10_000_000),
            ],
            fee_sink,
        );
        state.rewards_pool = rewards_pool;

        let ctx = ApplyContext::new_replay(10, fee_sink, 1);
        let stx = pay_txn(sender, receiver, 1_000, 1_000);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Sender had 5 Algos = 5 reward units. Pending = (10 - 0) * 5 = 50.
        // Rewards pool should be debited by 50.
        assert_eq!(
            state.get_account(&rewards_pool).unwrap().micro_algos,
            10_000_000 - 50
        );
    }

    #[test]
    fn test_error_rollback_with_rewards() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let rewards_pool = Address([4u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (sender, 5_000_000),
                (receiver, 0),
                (fee_sink, 0),
                (rewards_pool, 10_000_000),
            ],
            fee_sink,
        );
        state.rewards_pool = rewards_pool;

        let ctx = ApplyContext::new_replay(10, fee_sink, 1);
        // Sender has 5M but tries to send 10M — will fail.
        // Rewards would have been applied (50) bumping to 5_000_050, still < 10M.
        let stx = pay_txn(sender, receiver, 10_000_000, 1_000);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());

        // Verify full rollback — sender balance and rewards_base unchanged.
        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.micro_algos, 5_000_000);
        assert_eq!(acct.rewards_base, 0);
        assert_eq!(acct.rewarded_micro_algos, 0);

        // Rewards pool should NOT have been debited.
        assert_eq!(
            state.get_account(&rewards_pool).unwrap().micro_algos,
            10_000_000
        );
    }

    #[test]
    fn test_fee_sink_rolled_back_on_close_failure() {
        let sender = Address([1u8; 32]);
        let receiver = Address([2u8; 32]);
        let close_to = Address([4u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 100)], fee_sink);
        state.get_or_default_account(&sender).total_assets_opted_in = 1;

        let ctx = ApplyContext::new_replay(0, fee_sink, 1);
        let mut stx = pay_txn(sender, receiver, 0, 1_000);
        stx.txn.close_remainder_to = close_to;

        // This fails because sender has opted-in assets.
        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());

        // Fee sink should be rolled back — fee was credited inside apply_pay
        // but the close check failed, so the whole transaction is reverted.
        assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 100);
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // Asset Config (acfg) tests
    // -----------------------------------------------------------------------

    /// Helper: build an acfg create transaction.
    fn acfg_create_txn(
        sender: Address,
        fee: u64,
        asset_id: u64,
        params: AssetParams,
    ) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "acfg".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = fee;
        stx.txn.config_asset = 0; // 0 = create
        stx.txn.asset_params = Some(params);
        stx.apply_data_config_asset = asset_id;
        stx
    }

    /// Helper: create an asset in state and return the asset_id.
    fn create_asset_in_state(
        state: &mut LedgerState,
        ctx: &ApplyContext,
        creator: Address,
        asset_id: u64,
        params: AssetParams,
    ) {
        let stx = acfg_create_txn(creator, 1_000, asset_id, params);
        apply_transaction(state, &stx, ctx, 0).unwrap();
    }

    #[test]
    fn test_acfg_create() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 10_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000_000,
            decimals: 6,
            default_frozen: false,
            unit_name: "TST".to_string(),
            asset_name: "Test Asset".to_string(),
            manager: Some(sender),
            reserve: Some(sender),
            freeze: Some(sender),
            clawback: Some(sender),
            ..Default::default()
        };
        let stx = acfg_create_txn(sender, 1_000, 42, params.clone());
        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Verify asset params record.
        let record = state.get_asset_params(42).unwrap();
        assert_eq!(record.creator, sender);
        assert_eq!(record.params.total, 1_000_000);
        assert_eq!(record.params.decimals, 6);
        assert_eq!(record.params.unit_name, "TST");

        // Creator holds full supply.
        let holding = state.get_asset_holding(&sender, 42).unwrap();
        assert_eq!(holding.amount, 1_000_000);
        assert!(!holding.frozen);

        // Account counters incremented.
        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.total_created_assets, 1);
        assert_eq!(acct.total_assets_opted_in, 1);

        // Fee deducted.
        assert_eq!(acct.micro_algos, 10_000_000 - 1_000);
    }

    #[test]
    fn test_acfg_create_default_frozen() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 10_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 500,
            default_frozen: true,
            manager: Some(sender),
            ..Default::default()
        };
        let stx = acfg_create_txn(sender, 1_000, 50, params);
        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Per Go semantics, creator holding is always unfrozen on create
        // (the implementation sets frozen: false for the creator).
        let holding = state.get_asset_holding(&sender, 50).unwrap();
        assert_eq!(holding.amount, 500);
        assert!(!holding.frozen);
    }

    #[test]
    fn test_acfg_create_missing_caid_fails() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 10_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "acfg".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = 1_000;
        stx.txn.config_asset = 0;
        stx.apply_data_config_asset = 0; // missing!

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("caid"));
    }

    #[test]
    fn test_acfg_destroy() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 10_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        // Create asset first.
        let params = AssetParams {
            total: 1_000,
            manager: Some(sender),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, sender, 42, params);

        // Destroy: config_asset = existing ID, asset_params = default (empty).
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "acfg".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = 1_000;
        stx.txn.config_asset = 42;
        // No asset_params means destroy.

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Params and holding removed.
        assert!(state.get_asset_params(42).is_none());
        assert!(state.get_asset_holding(&sender, 42).is_none());

        // Counters decremented.
        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.total_created_assets, 0);
        assert_eq!(acct.total_assets_opted_in, 0);
    }

    #[test]
    fn test_acfg_destroy_not_full_supply_fails() {
        let sender = Address([1u8; 32]);
        let other = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(sender, 10_000_000), (other, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        // Create asset with total=1000.
        let params = AssetParams {
            total: 1_000,
            manager: Some(sender),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, sender, 42, params);

        // Opt-in other and transfer some supply.
        state.asset_holdings.insert(
            (other, 42),
            AssetHolding {
                amount: 0,
                frozen: false,
            },
        );
        state.get_or_default_account(&other).total_assets_opted_in += 1;

        // Manually move 100 units from creator to other.
        state.asset_holdings.get_mut(&(sender, 42)).unwrap().amount = 900;
        state.asset_holdings.get_mut(&(other, 42)).unwrap().amount = 100;

        // Attempt destroy — should fail because creator doesn't hold full supply.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "acfg".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = 1_000;
        stx.txn.config_asset = 42;

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("total supply"));
    }

    #[test]
    fn test_acfg_reconfig() {
        let sender = Address([1u8; 32]);
        let new_manager = Address([5u8; 32]);
        let new_reserve = Address([6u8; 32]);
        let new_freeze = Address([7u8; 32]);
        let new_clawback = Address([8u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 10_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(sender),
            reserve: Some(sender),
            freeze: Some(sender),
            clawback: Some(sender),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, sender, 42, params);

        // Reconfigure: change all role addresses.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "acfg".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = 1_000;
        stx.txn.config_asset = 42;
        stx.txn.asset_params = Some(AssetParams {
            manager: Some(new_manager),
            reserve: Some(new_reserve),
            freeze: Some(new_freeze),
            clawback: Some(new_clawback),
            ..Default::default()
        });

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        let record = state.get_asset_params(42).unwrap();
        assert_eq!(record.params.manager, Some(new_manager));
        assert_eq!(record.params.reserve, Some(new_reserve));
        assert_eq!(record.params.freeze, Some(new_freeze));
        assert_eq!(record.params.clawback, Some(new_clawback));
        // Total should be unchanged.
        assert_eq!(record.params.total, 1_000);
    }

    #[test]
    fn test_acfg_reconfig_unauthorized() {
        let creator = Address([1u8; 32]);
        let attacker = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (attacker, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Attacker tries to reconfigure.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "acfg".to_string();
        stx.txn.sender = attacker;
        stx.txn.fee = 1_000;
        stx.txn.config_asset = 42;
        stx.txn.asset_params = Some(AssetParams {
            manager: Some(attacker),
            ..Default::default()
        });

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not the manager"));
    }

    #[test]
    fn test_acfg_reconfig_cleared_role_locked() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 10_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(sender),
            reserve: Some(sender),
            freeze: Some(sender),
            clawback: Some(sender),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, sender, 42, params);

        // Clear the manager (set to zero address).
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "acfg".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = 1_000;
        stx.txn.config_asset = 42;
        stx.txn.asset_params = Some(AssetParams {
            manager: Some(Address::ZERO),
            reserve: Some(sender),
            freeze: Some(sender),
            clawback: Some(sender),
            ..Default::default()
        });

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Now manager is zero — any further reconfig should fail.
        let mut stx2 = SignedTransaction::default();
        stx2.txn.txn_type = "acfg".to_string();
        stx2.txn.sender = sender;
        stx2.txn.fee = 1_000;
        stx2.txn.config_asset = 42;
        stx2.txn.asset_params = Some(AssetParams {
            manager: Some(sender),
            ..Default::default()
        });

        let result = apply_transaction(&mut state, &stx2, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not the manager"));
    }

    // -----------------------------------------------------------------------
    // Asset Transfer (axfer) tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_axfer_optin() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        // Create asset with default_frozen = true.
        let params = AssetParams {
            total: 1_000,
            default_frozen: true,
            manager: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in: axfer to self, amount 0.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".to_string();
        stx.txn.sender = user;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 0;
        stx.txn.asset_receiver = Some(user);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Holding created with default_frozen.
        let holding = state.get_asset_holding(&user, 42).unwrap();
        assert_eq!(holding.amount, 0);
        assert!(holding.frozen); // default_frozen = true

        // Counter incremented.
        assert_eq!(state.get_account(&user).unwrap().total_assets_opted_in, 1);
    }

    #[test]
    fn test_axfer_optin_duplicate_fails() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // First opt-in succeeds.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".to_string();
        stx.txn.sender = user;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 0;
        stx.txn.asset_receiver = Some(user);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Second opt-in is a no-op (matches Go behavior — no error).
        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();
        // Holding unchanged, count unchanged.
        assert_eq!(state.get_asset_holding(&user, 42).unwrap().amount, 0);
        assert_eq!(state.get_account(&user).unwrap().total_assets_opted_in, 1);
    }

    #[test]
    fn test_axfer_transfer() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 0,
                frozen: false,
            },
        );
        state.get_or_default_account(&user).total_assets_opted_in += 1;

        // Transfer 300 from creator to user.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".to_string();
        stx.txn.sender = creator;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 300;
        stx.txn.asset_receiver = Some(user);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        assert_eq!(state.get_asset_holding(&creator, 42).unwrap().amount, 700);
        assert_eq!(state.get_asset_holding(&user, 42).unwrap().amount, 300);
    }

    #[test]
    fn test_axfer_transfer_insufficient_fails() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 0,
                frozen: false,
            },
        );
        state.get_or_default_account(&user).total_assets_opted_in += 1;

        // Try to transfer more than creator holds.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".to_string();
        stx.txn.sender = creator;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 2_000; // > 1_000 total supply
        stx.txn.asset_receiver = Some(user);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("insufficient"));
    }

    #[test]
    fn test_axfer_transfer_not_opted_in_fails() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Transfer to user who hasn't opted in.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".to_string();
        stx.txn.sender = creator;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 100;
        stx.txn.asset_receiver = Some(user);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not opted in"));
    }

    #[test]
    fn test_axfer_clawback() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let clawback_addr = Address([5u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (creator, 10_000_000),
                (user, 10_000_000),
                (clawback_addr, 10_000_000),
                (fee_sink, 0),
            ],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            clawback: Some(clawback_addr),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user and give them some tokens.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 500,
                frozen: false,
            },
        );
        state.get_or_default_account(&user).total_assets_opted_in += 1;
        // Adjust creator holding.
        state.asset_holdings.get_mut(&(creator, 42)).unwrap().amount = 500;

        // Clawback: sender=clawback_addr, asset_sender=user (source), receiver=creator.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".to_string();
        stx.txn.sender = clawback_addr;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 200;
        stx.txn.asset_sender = Some(user);
        stx.txn.asset_receiver = Some(creator);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        assert_eq!(state.get_asset_holding(&user, 42).unwrap().amount, 300);
        assert_eq!(state.get_asset_holding(&creator, 42).unwrap().amount, 700);
    }

    #[test]
    fn test_axfer_clawback_unauthorized_fails() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let attacker = Address([5u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (creator, 10_000_000),
                (user, 10_000_000),
                (attacker, 10_000_000),
                (fee_sink, 0),
            ],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            clawback: Some(creator), // creator is clawback, not attacker
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 500,
                frozen: false,
            },
        );
        state.get_or_default_account(&user).total_assets_opted_in += 1;

        // Attacker tries clawback.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".to_string();
        stx.txn.sender = attacker;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 100;
        stx.txn.asset_sender = Some(user);
        stx.txn.asset_receiver = Some(attacker);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not the clawback"));
    }

    #[test]
    fn test_axfer_close_to() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let close_target = Address([4u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (creator, 10_000_000),
                (user, 10_000_000),
                (close_target, 10_000_000),
                (fee_sink, 0),
            ],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user and give them 300 tokens.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 300,
                frozen: false,
            },
        );
        state.get_or_default_account(&user).total_assets_opted_in += 1;

        // Opt-in close_target.
        state.asset_holdings.insert(
            (close_target, 42),
            AssetHolding {
                amount: 0,
                frozen: false,
            },
        );
        state
            .get_or_default_account(&close_target)
            .total_assets_opted_in += 1;

        // Close asset holding: transfer 100 to creator, close remainder to close_target.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".to_string();
        stx.txn.sender = user;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 100;
        stx.txn.asset_receiver = Some(creator);
        stx.txn.asset_close_to = Some(close_target);

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        // Creator gets the 100 transferred (had 1000 from create).
        assert_eq!(state.get_asset_holding(&creator, 42).unwrap().amount, 1100);
        // close_target gets the remaining 200.
        assert_eq!(
            state.get_asset_holding(&close_target, 42).unwrap().amount,
            200
        );
        // User holding removed.
        assert!(state.get_asset_holding(&user, 42).is_none());
        // Counter decremented.
        assert_eq!(state.get_account(&user).unwrap().total_assets_opted_in, 0);
    }

    #[test]
    fn test_axfer_transfer_frozen_fails() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            freeze: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user with frozen holding.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 500,
                frozen: true,
            },
        );
        state.get_or_default_account(&user).total_assets_opted_in += 1;

        // User tries to transfer from frozen holding.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "axfer".to_string();
        stx.txn.sender = user;
        stx.txn.fee = 1_000;
        stx.txn.xaid = 42;
        stx.txn.asset_amount = 100;
        stx.txn.asset_receiver = Some(creator);

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("frozen"));
    }

    // -----------------------------------------------------------------------
    // Asset Freeze (afrz) tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_afrz_freeze() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            freeze: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 100,
                frozen: false,
            },
        );
        state.get_or_default_account(&user).total_assets_opted_in += 1;

        // Freeze user's holding.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "afrz".to_string();
        stx.txn.sender = creator;
        stx.txn.fee = 1_000;
        stx.txn.freeze_asset = 42;
        stx.txn.freeze_account = Some(user);
        stx.txn.asset_frozen = true;

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        assert!(state.get_asset_holding(&user, 42).unwrap().frozen);
    }

    #[test]
    fn test_afrz_unfreeze() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            freeze: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user with frozen holding.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 100,
                frozen: true,
            },
        );
        state.get_or_default_account(&user).total_assets_opted_in += 1;

        // Unfreeze.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "afrz".to_string();
        stx.txn.sender = creator;
        stx.txn.fee = 1_000;
        stx.txn.freeze_asset = 42;
        stx.txn.freeze_account = Some(user);
        stx.txn.asset_frozen = false;

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        assert!(!state.get_asset_holding(&user, 42).unwrap().frozen);
    }

    #[test]
    fn test_afrz_unauthorized_fails() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let attacker = Address([5u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (creator, 10_000_000),
                (user, 10_000_000),
                (attacker, 10_000_000),
                (fee_sink, 0),
            ],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            freeze: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // Opt-in user.
        state.asset_holdings.insert(
            (user, 42),
            AssetHolding {
                amount: 100,
                frozen: false,
            },
        );
        state.get_or_default_account(&user).total_assets_opted_in += 1;

        // Attacker tries to freeze.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "afrz".to_string();
        stx.txn.sender = attacker;
        stx.txn.fee = 1_000;
        stx.txn.freeze_asset = 42;
        stx.txn.freeze_account = Some(user);
        stx.txn.asset_frozen = true;

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not the freeze address"));
    }

    #[test]
    fn test_afrz_no_holding_fails() {
        let creator = Address([1u8; 32]);
        let user = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(
            &[(creator, 10_000_000), (user, 10_000_000), (fee_sink, 0)],
            fee_sink,
        );
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let params = AssetParams {
            total: 1_000,
            manager: Some(creator),
            freeze: Some(creator),
            ..Default::default()
        };
        create_asset_in_state(&mut state, &ctx, creator, 42, params);

        // User has NOT opted in — no holding.
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "afrz".to_string();
        stx.txn.sender = creator;
        stx.txn.fee = 1_000;
        stx.txn.freeze_asset = 42;
        stx.txn.freeze_account = Some(user);
        stx.txn.asset_frozen = true;

        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no holding"));
    }

    // -----------------------------------------------------------------------
    // Key Registration (keyreg) tests
    // -----------------------------------------------------------------------

    fn keyreg_online_txn(sender: Address, fee: u64) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "keyreg".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = fee;
        stx.txn.vote_pk = Some(serde_bytes::ByteBuf::from(vec![1u8; 32]));
        stx.txn.selection_pk = Some(serde_bytes::ByteBuf::from(vec![2u8; 32]));
        stx.txn.state_proof_pk = Some(serde_bytes::ByteBuf::from(vec![3u8; 64]));
        // vote_first <= round+1 and vote_last > round to pass coherency checks.
        // Tests use round=1, so vote_first=1, vote_last=200.
        stx.txn.vote_first = 1;
        stx.txn.vote_last = 200;
        stx.txn.vote_key_dilution = 10;
        stx
    }

    fn keyreg_offline_txn(sender: Address, fee: u64) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "keyreg".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = fee;
        // No keys, non_participation=false => offline
        stx
    }

    fn keyreg_nonpart_txn(sender: Address, fee: u64) -> SignedTransaction {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "keyreg".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = fee;
        stx.txn.non_participation = true;
        stx
    }

    #[test]
    fn test_keyreg_online() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let stx = keyreg_online_txn(sender, 1_000);
        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.status, AccountStatus::Online);
        assert_eq!(acct.vote_id, Some([1u8; 32]));
        assert_eq!(acct.selection_id, Some([2u8; 32]));
        assert_eq!(acct.state_proof_id, Some([3u8; 64]));
        assert_eq!(acct.vote_first_valid, 1);
        assert_eq!(acct.vote_last_valid, 200);
        assert_eq!(acct.vote_key_dilution, 10);
        // Fee deducted.
        assert_eq!(acct.micro_algos, 999_000);
        // D15: last_heartbeat = round(1) + lookback(320) = 321.
        assert_eq!(acct.last_heartbeat, 321);
        // Fee < 2_000_000, so incentive_eligible remains false.
        assert!(!acct.incentive_eligible);
    }

    #[test]
    fn test_keyreg_offline() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        // Set account to Online with keys first.
        {
            let acct = state.get_or_default_account(&sender);
            acct.status = AccountStatus::Online;
            acct.vote_id = Some([1u8; 32]);
            acct.selection_id = Some([2u8; 32]);
            acct.state_proof_id = Some([3u8; 64]);
            acct.vote_first_valid = 100;
            acct.vote_last_valid = 200;
            acct.vote_key_dilution = 10;
        }
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let stx = keyreg_offline_txn(sender, 1_000);
        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.status, AccountStatus::Offline);
        assert_eq!(acct.vote_id, None);
        assert_eq!(acct.selection_id, None);
        assert_eq!(acct.state_proof_id, None);
        assert_eq!(acct.vote_first_valid, 0);
        assert_eq!(acct.vote_last_valid, 0);
        assert_eq!(acct.vote_key_dilution, 0);
    }

    #[test]
    fn test_keyreg_nonpart() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let stx = keyreg_nonpart_txn(sender, 1_000);
        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.status, AccountStatus::NotParticipating);
        assert_eq!(acct.vote_id, None);
        assert_eq!(acct.selection_id, None);
        assert_eq!(acct.state_proof_id, None);
    }

    #[test]
    fn test_keyreg_nonpart_irreversible() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        // Set account to NotParticipating.
        state.get_or_default_account(&sender).status = AccountStatus::NotParticipating;

        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        // Attempt online keyreg — should fail.
        let stx = keyreg_online_txn(sender, 1_000);
        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("NotParticipating"),
            "expected NotParticipating error, got: {}",
            err_msg,
        );

        // Account should be unchanged (rollback).
        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.status, AccountStatus::NotParticipating);
        assert_eq!(acct.micro_algos, 1_000_000); // fee rolled back
    }

    #[test]
    fn test_keyreg_online_then_offline() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        // Go online.
        let stx_on = keyreg_online_txn(sender, 1_000);
        apply_transaction(&mut state, &stx_on, &ctx, 0).unwrap();
        assert_eq!(
            state.get_account(&sender).unwrap().status,
            AccountStatus::Online
        );
        assert!(state.get_account(&sender).unwrap().vote_id.is_some());

        // Go offline.
        let stx_off = keyreg_offline_txn(sender, 1_000);
        apply_transaction(&mut state, &stx_off, &ctx, 0).unwrap();

        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.status, AccountStatus::Offline);
        assert_eq!(acct.vote_id, None);
        assert_eq!(acct.selection_id, None);
        assert_eq!(acct.state_proof_id, None);
        assert_eq!(acct.vote_first_valid, 0);
        assert_eq!(acct.vote_last_valid, 0);
        assert_eq!(acct.vote_key_dilution, 0);
        // Two fees deducted.
        assert_eq!(acct.micro_algos, 998_000);
    }

    #[test]
    fn test_keyreg_rewards_stop_for_nonpart() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let rewards_pool = Address([4u8; 32]);

        let mut state = make_state_with_accounts(
            &[
                (sender, 5_000_000),
                (fee_sink, 0),
                (rewards_pool, 10_000_000),
            ],
            fee_sink,
        );
        state.rewards_pool = rewards_pool;

        // Set account Online with rewards_base=0.
        {
            let acct = state.get_or_default_account(&sender);
            acct.status = AccountStatus::Online;
            acct.rewards_base = 0;
        }

        // Verify pending rewards are > 0 at rewards_level=10.
        use crate::rewards::compute_pending_rewards;
        let pending = compute_pending_rewards(state.get_account(&sender).unwrap(), 10);
        assert!(pending > 0, "expected pending rewards > 0, got {}", pending);

        // Apply nonpart keyreg.
        let ctx = ApplyContext::new_replay(10, fee_sink, 1);
        let stx = keyreg_nonpart_txn(sender, 1_000);
        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

        let acct = state.get_account(&sender).unwrap();
        assert_eq!(acct.status, AccountStatus::NotParticipating);

        // After becoming NotParticipating, compute_pending_rewards returns 0.
        let pending_after = compute_pending_rewards(acct, 20);
        assert_eq!(pending_after, 0);
    }

    #[test]
    fn test_keyreg_online_zero_dilution_rejected() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let mut stx = keyreg_online_txn(sender, 1_000);
        stx.txn.vote_key_dilution = 0;
        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("vote_key_dilution"),
            "error should mention vote_key_dilution"
        );
        // Balance unchanged (rollback).
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 1_000_000);
    }

    #[test]
    fn test_keyreg_online_vote_last_before_first_rejected() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext::new_replay(0, fee_sink, 1);

        let mut stx = keyreg_online_txn(sender, 1_000);
        stx.txn.vote_first = 200;
        stx.txn.vote_last = 100;
        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("vote_last"),
            "error should mention vote_last"
        );
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 1_000_000);
    }

    #[test]
    fn test_detect_transaction_groups() {
        // Build a payset with mixed standalone and grouped transactions:
        // [standalone_A, group_B1, group_B2, group_B3, standalone_C]

        let mut standalone_a = SignedTransaction::default();
        standalone_a.txn.txn_type = "pay".to_string();
        standalone_a.txn.sender = Address([1u8; 32]);
        // Empty group hash => standalone.

        let group_hash = serde_bytes::ByteBuf::from(vec![42u8; 32]);

        let mut group_b1 = SignedTransaction::default();
        group_b1.txn.txn_type = "appl".to_string();
        group_b1.txn.sender = Address([2u8; 32]);
        group_b1.txn.group = group_hash.clone();

        let mut group_b2 = SignedTransaction::default();
        group_b2.txn.txn_type = "pay".to_string();
        group_b2.txn.sender = Address([3u8; 32]);
        group_b2.txn.group = group_hash.clone();

        let mut group_b3 = SignedTransaction::default();
        group_b3.txn.txn_type = "axfer".to_string();
        group_b3.txn.sender = Address([4u8; 32]);
        group_b3.txn.group = group_hash.clone();

        let mut standalone_c = SignedTransaction::default();
        standalone_c.txn.txn_type = "pay".to_string();
        standalone_c.txn.sender = Address([5u8; 32]);

        let payset = vec![standalone_a, group_b1, group_b2, group_b3, standalone_c];
        let groups = detect_transaction_groups(&payset);

        // Should produce 3 groups: [standalone_A], [B1, B2, B3], [standalone_C].
        assert_eq!(groups.len(), 3, "expected 3 groups, got {}", groups.len());

        // First group: standalone A.
        assert_eq!(groups[0].len(), 1);
        assert_eq!(groups[0][0].txn.sender, Address([1u8; 32]));

        // Second group: atomic group of 3.
        assert_eq!(groups[1].len(), 3);
        assert_eq!(groups[1][0].txn.sender, Address([2u8; 32]));
        assert_eq!(groups[1][1].txn.sender, Address([3u8; 32]));
        assert_eq!(groups[1][2].txn.sender, Address([4u8; 32]));

        // Third group: standalone C.
        assert_eq!(groups[2].len(), 1);
        assert_eq!(groups[2][0].txn.sender, Address([5u8; 32]));
    }

    #[test]
    fn test_detect_transaction_groups_empty() {
        let groups = detect_transaction_groups(&[]);
        assert!(groups.is_empty());
    }

    #[test]
    fn test_detect_transaction_groups_all_standalone() {
        let mut stx1 = SignedTransaction::default();
        stx1.txn.sender = Address([1u8; 32]);
        let mut stx2 = SignedTransaction::default();
        stx2.txn.sender = Address([2u8; 32]);

        let payset = vec![stx1, stx2];
        let groups = detect_transaction_groups(&payset);

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 1);
        assert_eq!(groups[1].len(), 1);
    }

    #[test]
    fn test_detect_transaction_groups_two_different_groups() {
        let group_a = serde_bytes::ByteBuf::from(vec![10u8; 32]);
        let group_b = serde_bytes::ByteBuf::from(vec![20u8; 32]);

        let mut a1 = SignedTransaction::default();
        a1.txn.sender = Address([1u8; 32]);
        a1.txn.group = group_a.clone();

        let mut a2 = SignedTransaction::default();
        a2.txn.sender = Address([2u8; 32]);
        a2.txn.group = group_a.clone();

        let mut b1 = SignedTransaction::default();
        b1.txn.sender = Address([3u8; 32]);
        b1.txn.group = group_b.clone();

        let mut b2 = SignedTransaction::default();
        b2.txn.sender = Address([4u8; 32]);
        b2.txn.group = group_b.clone();

        let payset = vec![a1, a2, b1, b2];
        let groups = detect_transaction_groups(&payset);

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 2);
        assert_eq!(groups[0][0].txn.sender, Address([1u8; 32]));
        assert_eq!(groups[0][1].txn.sender, Address([2u8; 32]));
        assert_eq!(groups[1].len(), 2);
        assert_eq!(groups[1][0].txn.sender, Address([3u8; 32]));
        assert_eq!(groups[1][1].txn.sender, Address([4u8; 32]));
    }
}
