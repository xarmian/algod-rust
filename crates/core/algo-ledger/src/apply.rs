use algo_error::AlgoError;
use algo_types::{AccountData, Address, Block, Round, SignedTransaction};

use crate::params::min_balance;
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
            apply_transaction(state, stx, &ctx)?;
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
) -> Result<(), AlgoError> {
    let txn = &stx.txn;

    // State proof transactions are protocol-injected and skip all processing
    // (no rewards, no fees, no state changes).
    if txn.txn_type == "stpf" {
        return Ok(());
    }

    // Collect unique touched addresses for reward application.
    let mut touched = Vec::with_capacity(3);
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

    // Snapshot all accounts that may be mutated (touched + fee_sink) for rollback.
    let mut snapshot_addrs = touched.clone();
    if !snapshot_addrs.contains(&ctx.fee_sink) {
        snapshot_addrs.push(ctx.fee_sink);
    }
    let snapshots: Vec<(Address, AccountData)> = snapshot_addrs
        .iter()
        .map(|addr| {
            let data = state.get_or_default_account(addr).clone();
            (*addr, data)
        })
        .collect();

    // Apply rewards to all touched accounts before processing the transaction.
    let mut total_rewards: u64 = 0;
    for addr in &touched {
        let account = state.get_or_default_account(addr);
        total_rewards += apply_rewards(account, ctx.rewards_level);
    }

    // Dispatch by transaction type, with rollback on error.
    let result = match txn.txn_type.as_str() {
        "pay" => apply_pay(state, stx, ctx),
        _ => {
            // Placeholder for future epics (axfer, acfg, afrz, appl, keyreg):
            // debit fee from sender and credit fee_sink, then check min balance.
            apply_fee_with_min_balance(state, &txn.sender, txn.fee, &ctx.fee_sink)
        }
    };

    if result.is_err() {
        // Restore touched accounts to pre-reward state.
        for (addr, data) in snapshots {
            state.accounts.insert(addr, data);
        }
        return result;
    }

    // Debit rewards pool for distributed rewards.
    if total_rewards > 0 {
        let pool = state.get_or_default_account(&state.rewards_pool.clone());
        pool.micro_algos = pool.micro_algos.saturating_sub(total_rewards);
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

    let sender_account = state.get_or_default_account(sender);
    let min_bal = min_balance(sender_account);
    if sender_account.micro_algos < min_bal {
        return Err(AlgoError::Ledger {
            message: format!(
                "sender {} balance {} below minimum balance {} after fee",
                sender, sender_account.micro_algos, min_bal,
            ),
        });
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
        let sender = state.get_or_default_account(&txn.sender);
        let min_bal = min_balance(sender);
        if sender.micro_algos < min_bal {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} balance {} below minimum balance {}",
                    txn.sender, sender.micro_algos, min_bal,
                ),
            });
        }
    }

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

        apply_transaction(&mut state, &stx, &ctx).unwrap();

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

        let result = apply_transaction(&mut state, &stx, &ctx);
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

        apply_transaction(&mut state, &stx, &ctx).unwrap();

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

        let result = apply_transaction(&mut state, &stx, &ctx);
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

        let result = apply_transaction(&mut state, &stx, &ctx);
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

        apply_transaction(&mut state, &stx, &ctx).unwrap();
        assert_eq!(state.get_account(&sender).unwrap().auth_addr, Some(auth),);

        // Rekey back to self clears auth_addr.
        let mut stx2 = pay_txn(sender, receiver, 1_000, 1_000);
        stx2.txn.rekey_to = Some(sender);

        apply_transaction(&mut state, &stx2, &ctx).unwrap();
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

        apply_transaction(&mut state, &stx, &ctx).unwrap();
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
        stx.txn.txn_type = "acfg".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = 2_000;

        apply_transaction(&mut state, &stx, &ctx).unwrap();
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
        stx.txn.txn_type = "acfg".to_string();
        stx.txn.sender = sender;
        stx.txn.fee = 1_000;

        let result = apply_transaction(&mut state, &stx, &ctx);
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

        apply_transaction(&mut state, &stx, &ctx).unwrap();

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

        let result = apply_transaction(&mut state, &stx, &ctx);
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
        let result = apply_transaction(&mut state, &stx, &ctx);
        assert!(result.is_err());

        // Fee sink should be rolled back — fee was credited inside apply_pay
        // but the close check failed, so the whole transaction is reverted.
        assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 100);
        assert_eq!(state.get_account(&sender).unwrap().micro_algos, 1_000_000);
    }
}
