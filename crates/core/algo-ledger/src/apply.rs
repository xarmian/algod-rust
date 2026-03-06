use algo_error::AlgoError;
use algo_types::{Address, Block, Round, SignedTransaction};

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
pub fn apply_block(state: &mut LedgerState, block: &Block) -> Result<(), AlgoError> {
    // Validate round monotonicity.
    let expected = Round(state.current_round.0 + 1);
    if block.round != expected {
        return Err(AlgoError::Ledger {
            message: format!("expected round {}, got {}", expected, block.round),
        });
    }

    // Update rewards state from block header.
    state.rewards_level = block.rewards_level;
    state.rewards_rate = block.rewards_rate;
    state.rewards_residue = block.rewards_residue;
    state.rewards_recalculation_round = block.rewards_recalculation_round.0;

    let ctx = ApplyContext {
        rewards_level: block.rewards_level,
        fee_sink: block.fee_sink,
    };

    for stx in &block.payset {
        apply_transaction(state, stx, &ctx)?;
    }

    state.current_round = block.round;
    Ok(())
}

/// Apply a single signed transaction to the ledger state.
///
/// 1. Apply rewards to all uniquely touched accounts (sender, receiver,
///    close_remainder_to).
/// 2. Dispatch by transaction type.
/// 3. Handle rekey_to if present.
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

    // Apply rewards to all touched accounts before processing the transaction.
    for addr in &touched {
        let account = state.get_or_default_account(addr);
        apply_rewards(account, ctx.rewards_level);
    }

    // Dispatch by transaction type.
    match txn.txn_type.as_str() {
        "pay" => apply_pay(state, stx, ctx)?,
        _ => {
            // Placeholder for future epics (axfer, acfg, afrz, appl, keyreg):
            // just debit fee from sender and credit fee_sink.
            apply_fee(state, &txn.sender, txn.fee, &ctx.fee_sink)?;
        }
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

        // Cannot close account with opted-in assets or apps.
        if sender.total_assets_opted_in > 0 {
            return Err(AlgoError::Ledger {
                message: format!(
                    "sender {} cannot close: has {} opted-in assets",
                    txn.sender, sender.total_assets_opted_in,
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
}
