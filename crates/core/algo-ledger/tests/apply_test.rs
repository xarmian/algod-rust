//! Integration tests for apply.rs — covers edge cases NOT in the inline unit tests.

use serde_bytes::ByteBuf;

use algo_ledger::{apply_block, apply_transaction, ApplyContext, LedgerState};
use algo_types::{AccountStatus, Address, Block, Round, SignedTransaction};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_state(balances: &[(Address, u64)], fee_sink: Address) -> LedgerState {
    let mut state = LedgerState::new();
    state.fee_sink = fee_sink;
    for (addr, bal) in balances {
        let acct = state.get_or_default_account(addr);
        acct.micro_algos = *bal;
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

fn minimal_block(fee_sink: Address, round: u64, payset: Vec<SignedTransaction>) -> Block {
    Block {
        round: Round(round),
        branch: ByteBuf::from(vec![]),
        seed: ByteBuf::from(vec![]),
        txn_commitment: ByteBuf::from(vec![]),
        timestamp: 0,
        genesis_id: String::new(),
        genesis_hash: ByteBuf::from(vec![]),
        proposer: Address::ZERO,
        fee_sink,
        rewards_pool: Address::ZERO,
        rewards_level: 0,
        rewards_rate: 0,
        rewards_residue: 0,
        rewards_recalculation_round: Round(0),
        current_protocol: String::new(),
        next_protocol: String::new(),
        next_protocol_approvals: 0,
        next_protocol_switch_on: Round(0),
        next_protocol_vote_before: Round(0),
        txn_counter: 0,
        fees_collected: 0,
        bonus: 0,
        proposer_payout: 0,
        prev512: ByteBuf::from(vec![]),
        txn256: ByteBuf::from(vec![]),
        txn512: ByteBuf::from(vec![]),
        state_proof_tracking: None,
        payset,
    }
}

// ---------------------------------------------------------------------------
// 1. Reward deduplication: sender == receiver applies rewards only once
// ---------------------------------------------------------------------------

#[test]
fn test_reward_dedup_sender_eq_receiver() {
    let addr = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let rewards_pool = Address([4u8; 32]);

    let mut state = make_state(
        &[(addr, 5_000_000), (fee_sink, 0), (rewards_pool, 10_000_000)],
        fee_sink,
    );
    state.rewards_pool = rewards_pool;
    // Set rewards_base so there are pending rewards.
    state.get_or_default_account(&addr).rewards_base = 0;
    state.get_or_default_account(&addr).status = AccountStatus::Online;

    let ctx = ApplyContext {
        rewards_level: 10,
        fee_sink,
    };

    // sender == receiver: rewards should be applied once, not twice.
    let stx = pay_txn(addr, addr, 0, 1_000);
    apply_transaction(&mut state, &stx, &ctx).unwrap();

    let acct = state.get_account(&addr).unwrap();
    // Pending rewards = (10 - 0) * (5_000_000 / 1_000_000) = 50
    // Balance after rewards: 5_000_050, then fee deducted: 5_000_050 - 1_000 = 4_999_050
    // Amount is 0 so no debit/credit for that.
    assert_eq!(acct.micro_algos, 4_999_050);
    assert_eq!(acct.rewarded_micro_algos, 50);
    assert_eq!(acct.rewards_base, 10);
}

// ---------------------------------------------------------------------------
// 2. apply_block with multiple transactions
// ---------------------------------------------------------------------------

#[test]
fn test_apply_block_multiple_txns() {
    let a = Address([1u8; 32]);
    let b = Address([2u8; 32]);
    let c = Address([4u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(a, 1_000_000), (b, 500_000), (c, 0), (fee_sink, 0)],
        fee_sink,
    );

    let txn1 = pay_txn(a, b, 200_000, 1_000); // a -> b: 200k
    let txn2 = pay_txn(b, c, 100_000, 1_000); // b -> c: 100k
    let txn3 = pay_txn(a, c, 50_000, 1_000); // a -> c: 50k

    let block = minimal_block(fee_sink, 1, vec![txn1, txn2, txn3]);
    apply_block(&mut state, &block).unwrap();

    // a: 1_000_000 - 200_000 - 1_000 - 50_000 - 1_000 = 748_000
    assert_eq!(state.get_account(&a).unwrap().micro_algos, 748_000);
    // b: 500_000 + 200_000 - 100_000 - 1_000 = 599_000
    assert_eq!(state.get_account(&b).unwrap().micro_algos, 599_000);
    // c: 0 + 100_000 + 50_000 = 150_000
    assert_eq!(state.get_account(&c).unwrap().micro_algos, 150_000);
    // fee_sink: 1_000 * 3 = 3_000
    assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 3_000);
}

// ---------------------------------------------------------------------------
// 3. apply_block updates rewards state and current_round
// ---------------------------------------------------------------------------

#[test]
fn test_apply_block_updates_rewards_state() {
    let fee_sink = Address([3u8; 32]);
    let mut state = make_state(&[(fee_sink, 0)], fee_sink);
    state.current_round = Round(41);

    let mut block = minimal_block(fee_sink, 42, vec![]);
    block.rewards_level = 1234;
    block.rewards_rate = 5678;
    block.rewards_residue = 91011;
    block.rewards_recalculation_round = Round(500_000);

    apply_block(&mut state, &block).unwrap();

    assert_eq!(state.rewards_level, 1234);
    assert_eq!(state.rewards_rate, 5678);
    assert_eq!(state.rewards_residue, 91011);
    assert_eq!(state.rewards_recalculation_round, 500_000);
    assert_eq!(state.current_round, Round(42));
}

// ---------------------------------------------------------------------------
// 4. Close-remainder with sender == close_to
// ---------------------------------------------------------------------------

#[test]
fn test_close_remainder_sender_eq_close_to() {
    let sender = Address([1u8; 32]);
    let receiver = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(sender, 1_000_000), (receiver, 0), (fee_sink, 0)],
        fee_sink,
    );
    let ctx = ApplyContext {
        rewards_level: 0,
        fee_sink,
    };

    // close_remainder_to == sender: after paying amount+fee, remainder goes
    // back to sender. The close logic zeroes sender first, then credits close_to.
    let mut stx = pay_txn(sender, receiver, 100_000, 1_000);
    stx.txn.close_remainder_to = sender;

    apply_transaction(&mut state, &stx, &ctx).unwrap();

    // sender balance after debit: 1_000_000 - 100_000 - 1_000 = 899_000
    // close logic: remainder = 899_000, set to 0, then credit close_to (== sender) += 899_000
    // So sender ends with 899_000.
    assert_eq!(state.get_account(&sender).unwrap().micro_algos, 899_000);
    assert_eq!(state.get_account(&receiver).unwrap().micro_algos, 100_000);
    assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 1_000);
}

// ---------------------------------------------------------------------------
// 5. Payment to self — fee is still deducted
// ---------------------------------------------------------------------------

#[test]
fn test_payment_to_self_fee_deducted() {
    let addr = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(&[(addr, 1_000_000), (fee_sink, 0)], fee_sink);
    let ctx = ApplyContext {
        rewards_level: 0,
        fee_sink,
    };

    // Pay 200_000 to self with 1_000 fee.
    let stx = pay_txn(addr, addr, 200_000, 1_000);
    apply_transaction(&mut state, &stx, &ctx).unwrap();

    // Debit (amount + fee) then credit amount back to same account.
    // Net effect: only fee is lost.
    // 1_000_000 - 200_000 - 1_000 + 200_000 = 999_000
    assert_eq!(state.get_account(&addr).unwrap().micro_algos, 999_000);
    assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 1_000);
}

// ---------------------------------------------------------------------------
// 6. Fee pooling for stpf — fee=0 no error, balances unchanged
// ---------------------------------------------------------------------------

#[test]
fn test_stpf_zero_fee_no_error() {
    let sender = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(&[(sender, 500_000), (fee_sink, 0)], fee_sink);
    let ctx = ApplyContext {
        rewards_level: 0,
        fee_sink,
    };

    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "stpf".to_string();
    stx.txn.sender = sender;
    stx.txn.fee = 0;

    apply_transaction(&mut state, &stx, &ctx).unwrap();

    assert_eq!(state.get_account(&sender).unwrap().micro_algos, 500_000);
    assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 0);
}

#[test]
fn test_stpf_nonzero_fee_still_noop() {
    // Even if fee is set, stpf branch doesn't debit it.
    let sender = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(&[(sender, 500_000), (fee_sink, 0)], fee_sink);
    let ctx = ApplyContext {
        rewards_level: 0,
        fee_sink,
    };

    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "stpf".to_string();
    stx.txn.sender = sender;
    stx.txn.fee = 5_000;

    apply_transaction(&mut state, &stx, &ctx).unwrap();

    // stpf is a complete no-op — fee field is ignored.
    assert_eq!(state.get_account(&sender).unwrap().micro_algos, 500_000);
    assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 0);
}

// ---------------------------------------------------------------------------
// 7. Rekey on non-pay txn (unknown-type path)
// ---------------------------------------------------------------------------

#[test]
fn test_rekey_on_acfg_txn() {
    let sender = Address([1u8; 32]);
    let auth = Address([5u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
    let ctx = ApplyContext {
        rewards_level: 0,
        fee_sink,
    };

    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "acfg".to_string();
    stx.txn.sender = sender;
    stx.txn.fee = 1_000;
    stx.txn.rekey_to = Some(auth);

    apply_transaction(&mut state, &stx, &ctx).unwrap();

    // Fee should be deducted (unknown-type path).
    assert_eq!(state.get_account(&sender).unwrap().micro_algos, 999_000);
    // auth_addr should be set.
    assert_eq!(state.get_account(&sender).unwrap().auth_addr, Some(auth));
}

#[test]
fn test_rekey_clear_on_non_pay() {
    let sender = Address([1u8; 32]);
    let auth = Address([5u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
    state.get_or_default_account(&sender).auth_addr = Some(auth);

    let ctx = ApplyContext {
        rewards_level: 0,
        fee_sink,
    };

    // Rekey back to self on a keyreg txn.
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "keyreg".to_string();
    stx.txn.sender = sender;
    stx.txn.fee = 1_000;
    stx.txn.rekey_to = Some(sender);

    apply_transaction(&mut state, &stx, &ctx).unwrap();

    assert_eq!(state.get_account(&sender).unwrap().auth_addr, None);
}

// ---------------------------------------------------------------------------
// 8. Close with opted-in apps fails
// ---------------------------------------------------------------------------

#[test]
fn test_close_with_opted_in_apps_fails() {
    let sender = Address([1u8; 32]);
    let receiver = Address([2u8; 32]);
    let close_to = Address([4u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(&[(sender, 1_000_000), (fee_sink, 0)], fee_sink);
    state.get_or_default_account(&sender).total_apps_opted_in = 2;

    let ctx = ApplyContext {
        rewards_level: 0,
        fee_sink,
    };
    let mut stx = pay_txn(sender, receiver, 0, 1_000);
    stx.txn.close_remainder_to = close_to;

    let result = apply_transaction(&mut state, &stx, &ctx);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("opted-in apps"),
        "error should mention opted-in apps, got: {}",
        err_msg,
    );
}
