use algo_error::AlgoError;
use algo_types::{
    Address, AppLocalState, AppParams, AssetHolding, AssetParams, AssetParamsRecord, Block, Round,
    SignedTransaction,
};

use crate::eval_delta::{apply_eval_delta, parse_eval_delta};
use crate::rewards::apply_rewards;
use crate::state::LedgerState;

/// Context derived from the block header, passed to transaction application.
pub struct ApplyContext {
    pub rewards_level: u64,
    pub fee_sink: Address,
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
pub fn apply_block(state: &mut LedgerState, block: &Block) -> Result<(), AlgoError> {
    // Validate round monotonicity.
    let expected = Round(state.current_round.0 + 1);
    if block.round != expected {
        return Err(AlgoError::Ledger {
            message: format!("expected round {}, got {}", expected, block.round),
        });
    }

    // Save rewards state and addresses for rollback on error.
    let prev_rewards_level = state.rewards_level;
    let prev_rewards_rate = state.rewards_rate;
    let prev_rewards_residue = state.rewards_residue;
    let prev_rewards_recalc = state.rewards_recalculation_round;
    let prev_fee_sink = state.fee_sink;
    let prev_rewards_pool = state.rewards_pool;

    // Update rewards state and reward addresses from block header.
    state.rewards_level = block.rewards_level;
    state.rewards_rate = block.rewards_rate;
    state.rewards_residue = block.rewards_residue;
    state.rewards_recalculation_round = block.rewards_recalculation_round.0;
    state.fee_sink = block.fee_sink;
    state.rewards_pool = block.rewards_pool;

    let ctx = ApplyContext {
        rewards_level: block.rewards_level,
        fee_sink: block.fee_sink,
    };

    let result = (|| {
        for stx in &block.payset {
            apply_transaction(state, stx, &ctx, 0)?;
        }
        Ok(())
    })();

    if result.is_err() {
        // Restore rewards state and addresses on failure.
        state.rewards_level = prev_rewards_level;
        state.rewards_rate = prev_rewards_rate;
        state.rewards_residue = prev_rewards_residue;
        state.rewards_recalculation_round = prev_rewards_recalc;
        state.fee_sink = prev_fee_sink;
        state.rewards_pool = prev_rewards_pool;
        return result;
    }

    state.current_round = block.round;
    Ok(())
}

/// Apply a single signed transaction to the ledger state.
///
/// 1. Snapshot touched accounts, then apply rewards.
/// 2. Dispatch by transaction type.
/// 3. Handle rekey_to if present.
/// 4. Debit rewards pool for any rewards distributed.
///
/// On error, touched account data is restored to pre-reward state.
pub fn apply_transaction(
    state: &mut LedgerState,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
    depth: u32,
) -> Result<(), AlgoError> {
    let txn = &stx.txn;

    // State proof transactions are protocol-injected and skip all processing
    // (no rewards, no fees, no state changes).
    if txn.txn_type == "stpf" {
        return Ok(());
    }

    // Collect unique touched addresses for reward application.
    let mut touched = Vec::with_capacity(6);
    touched.push(txn.sender);
    if !txn.receiver.is_zero() && txn.receiver != txn.sender {
        touched.push(txn.receiver);
    }
    if !txn.close_remainder_to.is_zero()
        && txn.close_remainder_to != txn.sender
        && txn.close_remainder_to != txn.receiver
    {
        touched.push(txn.close_remainder_to);
    }
    // Asset transfer: receiver, sender (clawback source), close-to.
    if let Some(ar) = txn.asset_receiver {
        if !ar.is_zero() && !touched.contains(&ar) {
            touched.push(ar);
        }
    }
    if let Some(asnd) = txn.asset_sender {
        if !asnd.is_zero() && !touched.contains(&asnd) {
            touched.push(asnd);
        }
    }
    if let Some(ac) = txn.asset_close_to {
        if !ac.is_zero() && !touched.contains(&ac) {
            touched.push(ac);
        }
    }
    // Asset freeze: target account.
    if let Some(fa) = txn.freeze_account {
        if !fa.is_zero() && !touched.contains(&fa) {
            touched.push(fa);
        }
    }

    // Determine asset/app IDs to snapshot for rollback.
    let mut asset_ids_to_snap = Vec::new();
    let mut app_ids_to_snap = Vec::new();
    match txn.txn_type.as_str() {
        "acfg" => {
            if txn.config_asset != 0 {
                asset_ids_to_snap.push(txn.config_asset);
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
            }
            if stx.apply_data_application_id != 0 {
                app_ids_to_snap.push(stx.apply_data_application_id);
            }
        }
        _ => {}
    }

    // Snapshot all accounts that may be mutated (touched + fee_sink) for rollback.
    let mut snapshot_addrs = touched.clone();
    if !snapshot_addrs.contains(&ctx.fee_sink) {
        snapshot_addrs.push(ctx.fee_sink);
    }

    let snapshot = if asset_ids_to_snap.is_empty() && app_ids_to_snap.is_empty() {
        state.snapshot(&snapshot_addrs)
    } else {
        state.snapshot_with_ids(&snapshot_addrs, &asset_ids_to_snap, &app_ids_to_snap)
    };

    // Execute all transaction logic inside a closure so that ANY error
    // (fee, type-specific, EvalDelta, rewards-pool debit, rekey) triggers
    // a full rollback via restore_snapshot.
    let result = (|| -> Result<(), AlgoError> {
        // Apply rewards to all touched accounts before processing the transaction.
        let mut total_rewards: u64 = 0;
        for addr in &touched {
            let account = state.get_or_default_account(addr);
            total_rewards += apply_rewards(account, ctx.rewards_level);
        }

        // Dispatch by transaction type.
        match txn.txn_type.as_str() {
            "pay" => apply_pay(state, stx, ctx)?,
            "acfg" => apply_acfg(state, stx, ctx)?,
            "axfer" => apply_axfer(state, stx, ctx)?,
            "afrz" => apply_afrz(state, stx, ctx)?,
            "appl" => apply_appl(state, stx, ctx)?,
            _ => {
                // Placeholder for future epics (keyreg, etc.):
                // debit fee from sender and credit fee_sink, then check min balance.
                apply_fee_with_min_balance(state, &txn.sender, txn.fee, &ctx.fee_sink)?;
            }
        }

        // Apply EvalDelta if present (mainly for appl, but any type can have it
        // due to inner transactions in recorded blocks).
        if let Some(ref dt) = stx.eval_delta {
            let delta = parse_eval_delta(dt)?;
            apply_eval_delta(stx, &delta, state, ctx, depth)?;
        }

        // Debit rewards pool for distributed rewards.
        if total_rewards > 0 {
            let rewards_pool_addr = state.rewards_pool;
            let pool = state.get_or_default_account(&rewards_pool_addr);
            if pool.micro_algos < total_rewards {
                return Err(AlgoError::Ledger {
                    message: format!(
                        "rewards pool balance {} insufficient for {} in rewards",
                        pool.micro_algos, total_rewards,
                    ),
                });
            }
            pool.micro_algos -= total_rewards;
        }

        // Handle rekey_to.
        if let Some(rekey_addr) = txn.rekey_to {
            let account = state.get_or_default_account(&txn.sender);
            if rekey_addr == txn.sender || rekey_addr.is_zero() {
                account.auth_addr = None;
            } else {
                account.auth_addr = Some(rekey_addr);
            }
        }

        Ok(())
    })();

    if result.is_err() {
        state.restore_snapshot(snapshot);
    }

    result
}

/// Debit fee from sender and credit to fee_sink.
fn apply_fee(
    state: &mut LedgerState,
    sender: &Address,
    fee: u64,
    fee_sink: &Address,
) -> Result<(), AlgoError> {
    let sender_account = state.get_or_default_account(sender);
    if sender_account.micro_algos < fee {
        return Err(AlgoError::Ledger {
            message: format!(
                "sender {} has insufficient balance {} for fee {}",
                sender, sender_account.micro_algos, fee,
            ),
        });
    }
    sender_account.micro_algos -= fee;

    let fee_sink_account = state.get_or_default_account(fee_sink);
    fee_sink_account.micro_algos += fee;

    Ok(())
}

/// Debit fee from sender, credit fee_sink, and validate min balance.
fn apply_fee_with_min_balance(
    state: &mut LedgerState,
    sender: &Address,
    fee: u64,
    fee_sink: &Address,
) -> Result<(), AlgoError> {
    apply_fee(state, sender, fee, fee_sink)?;
    check_min_balance(state, sender, "after fee")?;
    Ok(())
}

/// Check that sender's balance meets the schema-aware minimum balance.
fn check_min_balance(state: &LedgerState, addr: &Address, context: &str) -> Result<(), AlgoError> {
    if let Some(account) = state.get_account(addr) {
        let min_bal = state.min_balance_with_state(addr, account);
        if account.micro_algos < min_bal {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} balance {} below minimum balance {} {}",
                    addr, account.micro_algos, min_bal, context,
                ),
            });
        }
    }
    Ok(())
}

/// Apply a payment transaction.
///
/// Debits `amount + fee` from sender, credits `amount` to receiver,
/// credits `fee` to fee_sink. If `close_remainder_to` is set, moves
/// the sender's remaining balance to that address.
fn apply_pay(
    state: &mut LedgerState,
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
        let sender = state.get_or_default_account(&txn.sender);
        if sender.micro_algos < total_debit {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} has insufficient balance {} for payment {} + fee {}",
                    txn.sender, sender.micro_algos, txn.amount, txn.fee,
                ),
            });
        }
        sender.micro_algos -= total_debit;
    }

    // Credit receiver.
    if txn.amount > 0 {
        let receiver = state.get_or_default_account(&txn.receiver);
        receiver.micro_algos += txn.amount;
    }

    // Credit fee_sink.
    {
        let fee_sink = state.get_or_default_account(&ctx.fee_sink);
        fee_sink.micro_algos += txn.fee;
    }

    // Handle close_remainder_to.
    if !txn.close_remainder_to.is_zero() {
        let sender = state.get_or_default_account(&txn.sender);

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

        let close_amount = sender.micro_algos;
        sender.micro_algos = 0;
        sender.rewards_base = 0;

        let close_to = state.get_or_default_account(&txn.close_remainder_to);
        close_to.micro_algos += close_amount;
    } else {
        // Validate minimum balance when not closing.
        check_min_balance(state, &txn.sender, "after payment")?;
    }

    Ok(())
}

/// Apply an asset config transaction (create, reconfigure, or destroy).
fn apply_acfg(
    state: &mut LedgerState,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
) -> Result<(), AlgoError> {
    let txn = &stx.txn;

    // Debit fee first.
    apply_fee(state, &txn.sender, txn.fee, &ctx.fee_sink)?;

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
        state.asset_params.insert(new_asset_id, record);

        // Creator gets the full supply and an opt-in holding.
        state.asset_holdings.insert(
            (txn.sender, new_asset_id),
            AssetHolding {
                amount: total,
                frozen: false,
            },
        );

        let sender_account = state.get_or_default_account(&txn.sender);
        sender_account.total_created_assets += 1;
        sender_account.total_assets_opted_in += 1;
    } else {
        // ── Reconfigure or Destroy ──
        let asset_id = txn.config_asset;
        let existing = state
            .asset_params
            .get(&asset_id)
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
            let holding = state
                .asset_holdings
                .get(&(creator, asset_id))
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
            state.asset_params.remove(&asset_id);
            state.asset_holdings.remove(&(creator, asset_id));

            let creator_account = state.get_or_default_account(&creator);
            creator_account.total_created_assets =
                creator_account.total_created_assets.saturating_sub(1);
            creator_account.total_assets_opted_in =
                creator_account.total_assets_opted_in.saturating_sub(1);
        } else {
            // ── Reconfigure ──
            // Clone existing params for mutation (borrow checker).
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

            let record = state.asset_params.get_mut(&asset_id).unwrap();
            record.params = updated_params;
        }
    }

    // Check min balance for sender after the operation.
    check_min_balance(state, &txn.sender, "after acfg operation")?;

    Ok(())
}

/// Apply an asset transfer transaction (opt-in, transfer, clawback, close-to).
fn apply_axfer(
    state: &mut LedgerState,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
) -> Result<(), AlgoError> {
    let txn = &stx.txn;

    // Debit fee first.
    apply_fee(state, &txn.sender, txn.fee, &ctx.fee_sink)?;

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

    // ── Clawback authorization ──
    if is_clawback {
        let params = state
            .asset_params
            .get(&asset_id)
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
        // Check if already opted in.
        if state.asset_holdings.contains_key(&(txn.sender, asset_id)) {
            return Err(AlgoError::Ledger {
                message: format!(
                    "axfer opt-in: {} already opted in to asset {}",
                    txn.sender, asset_id,
                ),
            });
        }
        let params = state
            .asset_params
            .get(&asset_id)
            .ok_or_else(|| AlgoError::Ledger {
                message: format!("axfer opt-in: asset {} does not exist", asset_id),
            })?;
        let default_frozen = params.params.default_frozen;
        state.asset_holdings.insert(
            (txn.sender, asset_id),
            AssetHolding {
                amount: 0,
                frozen: default_frozen,
            },
        );
        let sender_account = state.get_or_default_account(&txn.sender);
        sender_account.total_assets_opted_in += 1;
    } else {
        // ── Frozen check (only for non-clawback) ──
        if !is_clawback {
            let from_holding = state
                .asset_holdings
                .get(&(from_addr, asset_id))
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
        if txn.asset_amount > 0 {
            // Debit from.
            let from_holding = state
                .asset_holdings
                .get_mut(&(from_addr, asset_id))
                .ok_or_else(|| AlgoError::Ledger {
                    message: format!("axfer: {} has no holding for asset {}", from_addr, asset_id,),
                })?;
            if from_holding.amount < txn.asset_amount {
                return Err(AlgoError::Ledger {
                    message: format!(
                        "axfer: {} holding {} insufficient for transfer {} of asset {}",
                        from_addr, from_holding.amount, txn.asset_amount, asset_id,
                    ),
                });
            }
            from_holding.amount -= txn.asset_amount;

            // Credit receiver.
            let recv_holding = state
                .asset_holdings
                .get_mut(&(asset_receiver, asset_id))
                .ok_or_else(|| AlgoError::Ledger {
                    message: format!(
                        "axfer: receiver {} has no holding for asset {} (not opted in)",
                        asset_receiver, asset_id,
                    ),
                })?;
            recv_holding.amount += txn.asset_amount;
        }

        // ── Close-to ──
        if let Some(close_to) = txn.asset_close_to {
            if !close_to.is_zero() {
                // Get remaining balance from sender (the from_addr for non-clawback is txn.sender).
                // For close-to, the "from" is always the txn sender, not the clawback source.
                let close_from = txn.sender;
                let remaining = state
                    .asset_holdings
                    .get(&(close_from, asset_id))
                    .map(|h| h.amount)
                    .unwrap_or(0);

                if remaining > 0 {
                    // Credit close-to.
                    let close_holding = state
                        .asset_holdings
                        .get_mut(&(close_to, asset_id))
                        .ok_or_else(|| AlgoError::Ledger {
                            message: format!(
                                "axfer close: {} has no holding for asset {} (not opted in)",
                                close_to, asset_id,
                            ),
                        })?;
                    close_holding.amount += remaining;
                }

                // Remove sender holding.
                state.asset_holdings.remove(&(close_from, asset_id));

                let sender_account = state.get_or_default_account(&close_from);
                sender_account.total_assets_opted_in =
                    sender_account.total_assets_opted_in.saturating_sub(1);
            }
        }
    }

    // Check min balance for sender after the operation.
    check_min_balance(state, &txn.sender, "after axfer operation")?;

    Ok(())
}

/// Apply an asset freeze transaction.
fn apply_afrz(
    state: &mut LedgerState,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
) -> Result<(), AlgoError> {
    let txn = &stx.txn;

    // Debit fee first.
    apply_fee(state, &txn.sender, txn.fee, &ctx.fee_sink)?;

    let asset_id = txn.freeze_asset;
    if asset_id == 0 {
        return Err(AlgoError::Ledger {
            message: "afrz: freeze asset ID (faid) is zero".to_string(),
        });
    }

    // Look up asset params to verify sender is the freeze address.
    let params = state
        .asset_params
        .get(&asset_id)
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

    let holding = state
        .asset_holdings
        .get_mut(&(target, asset_id))
        .ok_or_else(|| AlgoError::Ledger {
            message: format!("afrz: {} has no holding for asset {}", target, asset_id,),
        })?;
    holding.frozen = txn.asset_frozen;

    // Check min balance for sender after fee.
    check_min_balance(state, &txn.sender, "after afrz fee")?;

    Ok(())
}

/// On-completion action constants for application calls.
const ON_COMPLETION_OPT_IN: u64 = 1;
const ON_COMPLETION_CLOSE_OUT: u64 = 2;
const ON_COMPLETION_CLEAR_STATE: u64 = 3;
const ON_COMPLETION_UPDATE: u64 = 4;
const ON_COMPLETION_DELETE: u64 = 5;

/// Apply an application call transaction.
///
/// Handles creation, opt-in, close-out, clear-state, update, delete, and no-op.
/// The primary state effects (global/local state changes) come from the EvalDelta,
/// which is applied separately after the type-specific dispatch.
fn apply_appl(
    state: &mut LedgerState,
    stx: &SignedTransaction,
    ctx: &ApplyContext,
) -> Result<(), AlgoError> {
    let txn = &stx.txn;

    // Debit fee first.
    apply_fee(state, &txn.sender, txn.fee, &ctx.fee_sink)?;

    let is_create = txn.application_id == 0;
    let app_id = if is_create {
        stx.apply_data_application_id
    } else {
        txn.application_id
    };

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
        let extra_pages = txn.extra_program_pages as u32;

        state.app_params.insert(
            app_id,
            AppParams {
                creator: txn.sender,
                approval_program: approval,
                clear_state_program: clear,
                global_state: std::collections::BTreeMap::new(),
                local_state_schema: local_schema,
                global_state_schema: global_schema,
                extra_program_pages: extra_pages,
            },
        );

        let sender_account = state.get_or_default_account(&txn.sender);
        sender_account.total_created_apps += 1;
        sender_account.total_extra_app_pages += extra_pages;
    }

    match txn.on_completion {
        ON_COMPLETION_OPT_IN => {
            // Create local state for sender if not already present.
            let local_schema = if is_create {
                txn.local_state_schema.clone().unwrap_or_default()
            } else {
                state
                    .app_params
                    .get(&app_id)
                    .map(|p| p.local_state_schema.clone())
                    .unwrap_or_default()
            };

            use std::collections::hash_map::Entry;
            if let Entry::Vacant(e) = state.app_local_states.entry((txn.sender, app_id)) {
                e.insert(AppLocalState {
                    schema: local_schema,
                    key_value: std::collections::BTreeMap::new(),
                });
                let sender_account = state.get_or_default_account(&txn.sender);
                sender_account.total_apps_opted_in += 1;
            }
        }
        ON_COMPLETION_CLOSE_OUT | ON_COMPLETION_CLEAR_STATE => {
            // Remove sender's local state for this app.
            if state
                .app_local_states
                .remove(&(txn.sender, app_id))
                .is_some()
            {
                let sender_account = state.get_or_default_account(&txn.sender);
                sender_account.total_apps_opted_in =
                    sender_account.total_apps_opted_in.saturating_sub(1);
            }
        }
        ON_COMPLETION_DELETE => {
            // Remove the app — decrement the CREATOR's counters, not sender's.
            if let Some(params) = state.app_params.remove(&app_id) {
                let creator = params.creator;
                let creator_account = state.get_or_default_account(&creator);
                creator_account.total_created_apps =
                    creator_account.total_created_apps.saturating_sub(1);
                creator_account.total_extra_app_pages = creator_account
                    .total_extra_app_pages
                    .saturating_sub(params.extra_program_pages);
            }
        }
        ON_COMPLETION_UPDATE => {
            // Update the app programs only — extra_program_pages are immutable
            // post-creation in go-algorand.
            if let Some(app) = state.app_params.get_mut(&app_id) {
                if let Some(ref approval) = txn.approval_program {
                    app.approval_program = approval.to_vec();
                }
                if let Some(ref clear) = txn.clear_state_program {
                    app.clear_state_program = clear.to_vec();
                }
            }
        }
        _ => {
            // NoOp (0) or unknown — no structural state changes beyond EvalDelta.
        }
    }

    // Check min balance for sender after the operation.
    check_min_balance(state, &txn.sender, "after appl operation")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };
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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };
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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };
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

        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };
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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };
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

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };
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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "stpf".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = 0;

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();
        // Balance unchanged — stpf is a no-op.
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 1_000_000);
    }

    #[test]
    fn test_unknown_type_debits_fee() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        let mut state = make_state_with_accounts(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "keyreg".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = 2_000;

        apply_transaction(&mut state, &stx, &ctx, 0).unwrap();
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 998_000);
        assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 2_000);
    }

    #[test]
    fn test_non_pay_min_balance_check() {
        let sender = Address([1u8; 32]);
        let fee_sink = Address([3u8; 32]);

        // Sender at exactly min_balance (100_000). Fee of 1_000 drops below.
        let mut state = make_state_with_accounts(&[(sender, 100_000), (fee_sink, 0)], fee_sink);
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };
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
                (receiver, 0),
                (fee_sink, 0),
                (rewards_pool, 10_000_000),
            ],
            fee_sink,
        );
        state.rewards_pool = rewards_pool;

        let ctx = ApplyContext {
            rewards_level: 10,
            fee_sink,
        };
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

        let ctx = ApplyContext {
            rewards_level: 10,
            fee_sink,
        };
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

        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };
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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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

        // Second opt-in fails.
        let result = apply_transaction(&mut state, &stx, &ctx, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already opted in"));
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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
        let ctx = ApplyContext {
            rewards_level: 0,
            fee_sink,
        };

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
}
