//! Integration tests for apply.rs — covers edge cases NOT in the inline unit tests.

use serde_bytes::ByteBuf;

use algo_ledger::{apply_block, apply_transaction, ApplyContext, LedgerState};
use algo_types::{AccountStatus, Address, AssetParams, Block, Round, SignedTransaction, TealValue};

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
    apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

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

    apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

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
    apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

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

    apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

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

    apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

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

    // Use acfg create with proper apply_data_config_asset to test rekey on non-pay.
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "acfg".to_string();
    stx.txn.sender = sender;
    stx.txn.fee = 1_000;
    stx.txn.rekey_to = Some(auth);
    stx.apply_data_config_asset = 42;

    apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

    // Fee should be deducted + min balance increases for created asset + opt-in.
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

    apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

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

    let result = apply_transaction(&mut state, &stx, &ctx, 0);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("opted-in apps"),
        "error should mention opted-in apps, got: {}",
        err_msg,
    );
}

// ---------------------------------------------------------------------------
// Helpers for asset/app integration tests
// ---------------------------------------------------------------------------

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
    stx.txn.config_asset = 0;
    stx.txn.asset_params = Some(params);
    stx.apply_data_config_asset = asset_id;
    stx
}

fn axfer_optin_txn(sender: Address, fee: u64, asset_id: u64) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "axfer".to_string();
    stx.txn.sender = sender;
    stx.txn.fee = fee;
    stx.txn.xaid = asset_id;
    stx.txn.asset_amount = 0;
    stx.txn.asset_receiver = Some(sender);
    stx
}

fn axfer_transfer_txn(
    sender: Address,
    receiver: Address,
    amount: u64,
    fee: u64,
    asset_id: u64,
) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "axfer".to_string();
    stx.txn.sender = sender;
    stx.txn.fee = fee;
    stx.txn.xaid = asset_id;
    stx.txn.asset_amount = amount;
    stx.txn.asset_receiver = Some(receiver);
    stx
}

fn afrz_txn(
    sender: Address,
    target: Address,
    asset_id: u64,
    freeze: bool,
    fee: u64,
) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "afrz".to_string();
    stx.txn.sender = sender;
    stx.txn.fee = fee;
    stx.txn.freeze_asset = asset_id;
    stx.txn.freeze_account = Some(target);
    stx.txn.asset_frozen = freeze;
    stx
}

fn axfer_close_txn(
    sender: Address,
    receiver: Address,
    close_to: Address,
    amount: u64,
    fee: u64,
    asset_id: u64,
) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "axfer".to_string();
    stx.txn.sender = sender;
    stx.txn.fee = fee;
    stx.txn.xaid = asset_id;
    stx.txn.asset_amount = amount;
    stx.txn.asset_receiver = Some(receiver);
    stx.txn.asset_close_to = Some(close_to);
    stx
}

fn appl_create_txn(
    sender: Address,
    fee: u64,
    app_id: u64,
    on_completion: u64,
) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "appl".to_string();
    stx.txn.sender = sender;
    stx.txn.fee = fee;
    stx.txn.application_id = 0;
    stx.txn.on_completion = on_completion;
    stx.txn.approval_program = Some(serde_bytes::ByteBuf::from(vec![0x06, 0x81, 0x01]));
    stx.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(vec![0x06, 0x81, 0x01]));
    stx.apply_data_application_id = app_id;
    stx
}

fn appl_optin_txn(sender: Address, fee: u64, app_id: u64) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "appl".to_string();
    stx.txn.sender = sender;
    stx.txn.fee = fee;
    stx.txn.application_id = app_id;
    stx.txn.on_completion = 1; // ON_COMPLETION_OPT_IN
    stx
}

// ---------------------------------------------------------------------------
// 9. Asset full lifecycle (multi-block)
// ---------------------------------------------------------------------------

#[test]
fn test_asset_full_lifecycle() {
    let creator = Address([1u8; 32]);
    let user = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (user, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );

    let asset_id = 100u64;

    // Block 1: Create asset.
    let create_params = AssetParams {
        total: 10_000,
        manager: Some(creator),
        freeze: Some(creator),
        clawback: Some(creator),
        ..Default::default()
    };
    let block1 = minimal_block(
        fee_sink,
        1,
        vec![acfg_create_txn(creator, 1_000, asset_id, create_params)],
    );
    apply_block(&mut state, &block1).unwrap();

    assert!(state.get_asset_params(asset_id).is_some());
    assert_eq!(
        state.get_asset_holding(&creator, asset_id).unwrap().amount,
        10_000
    );

    // Block 2: User opts in.
    let block2 = minimal_block(fee_sink, 2, vec![axfer_optin_txn(user, 1_000, asset_id)]);
    apply_block(&mut state, &block2).unwrap();

    assert_eq!(state.get_asset_holding(&user, asset_id).unwrap().amount, 0);

    // Block 3: Transfer 500 from creator to user.
    let block3 = minimal_block(
        fee_sink,
        3,
        vec![axfer_transfer_txn(creator, user, 500, 1_000, asset_id)],
    );
    apply_block(&mut state, &block3).unwrap();

    assert_eq!(
        state.get_asset_holding(&creator, asset_id).unwrap().amount,
        9_500
    );
    assert_eq!(
        state.get_asset_holding(&user, asset_id).unwrap().amount,
        500
    );

    // Block 4: Freeze user's holding.
    let block4 = minimal_block(
        fee_sink,
        4,
        vec![afrz_txn(creator, user, asset_id, true, 1_000)],
    );
    apply_block(&mut state, &block4).unwrap();

    assert!(state.get_asset_holding(&user, asset_id).unwrap().frozen);

    // Block 5: Unfreeze and close-out user (transfer remaining to creator).
    let unfreeze = afrz_txn(creator, user, asset_id, false, 1_000);
    let close_out = axfer_close_txn(user, creator, creator, 0, 1_000, asset_id);
    let block5 = minimal_block(fee_sink, 5, vec![unfreeze, close_out]);
    apply_block(&mut state, &block5).unwrap();

    assert!(state.get_asset_holding(&user, asset_id).is_none());
    assert_eq!(
        state.get_asset_holding(&creator, asset_id).unwrap().amount,
        10_000
    );

    // Block 6: Destroy asset.
    let mut destroy_stx = SignedTransaction::default();
    destroy_stx.txn.txn_type = "acfg".to_string();
    destroy_stx.txn.sender = creator;
    destroy_stx.txn.fee = 1_000;
    destroy_stx.txn.config_asset = asset_id;
    let block6 = minimal_block(fee_sink, 6, vec![destroy_stx]);
    apply_block(&mut state, &block6).unwrap();

    assert!(state.get_asset_params(asset_id).is_none());
    assert!(state.get_asset_holding(&creator, asset_id).is_none());
    assert_eq!(state.get_account(&creator).unwrap().total_created_assets, 0);
}

// ---------------------------------------------------------------------------
// 10. Min balance tracks assets
// ---------------------------------------------------------------------------

#[test]
fn test_min_balance_tracks_assets() {
    let creator = Address([1u8; 32]);
    let user = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (user, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );
    let ctx = ApplyContext {
        rewards_level: 0,
        fee_sink,
    };

    // Base min balance for user (no assets/apps): 100_000
    let base_min = algo_ledger::min_balance(state.get_account(&user).unwrap());
    assert_eq!(base_min, 100_000);

    // Create asset.
    let params = AssetParams {
        total: 1_000,
        manager: Some(creator),
        ..Default::default()
    };
    let stx = acfg_create_txn(creator, 1_000, 42, params);
    apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

    // Creator: min_balance increases for created asset + opted-in holding.
    let creator_min = algo_ledger::min_balance(state.get_account(&creator).unwrap());
    // base + 1 created asset * 100k + 1 opted-in * 100k = 300_000
    assert_eq!(creator_min, 300_000);

    // User opts in.
    let optin = axfer_optin_txn(user, 1_000, 42);
    apply_transaction(&mut state, &optin, &ctx, 0).unwrap();

    let user_min = algo_ledger::min_balance(state.get_account(&user).unwrap());
    // base + 1 opted-in * 100k = 200_000
    assert_eq!(user_min, 200_000);

    // User closes out.
    let close = axfer_close_txn(user, creator, creator, 0, 1_000, 42);
    apply_transaction(&mut state, &close, &ctx, 0).unwrap();

    let user_min_after = algo_ledger::min_balance(state.get_account(&user).unwrap());
    assert_eq!(user_min_after, 100_000);

    // Destroy asset.
    let mut destroy = SignedTransaction::default();
    destroy.txn.txn_type = "acfg".to_string();
    destroy.txn.sender = creator;
    destroy.txn.fee = 1_000;
    destroy.txn.config_asset = 42;
    apply_transaction(&mut state, &destroy, &ctx, 0).unwrap();

    let creator_min_after = algo_ledger::min_balance(state.get_account(&creator).unwrap());
    assert_eq!(creator_min_after, 100_000);
}

// ---------------------------------------------------------------------------
// 11. App create and opt-in
// ---------------------------------------------------------------------------

#[test]
fn test_appl_create_and_optin() {
    let creator = Address([1u8; 32]);
    let user = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (user, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );
    let ctx = ApplyContext {
        rewards_level: 0,
        fee_sink,
    };

    let app_id = 200u64;

    // Create app (on_completion=0 NoOp for create is fine; opt-in=1 on create
    // also creates local state for creator).
    let mut stx = appl_create_txn(creator, 1_000, app_id, 0);
    stx.txn.local_state_schema = Some(algo_types::StateSchema {
        num_uint: 2,
        num_byte_slice: 1,
    });
    stx.txn.global_state_schema = Some(algo_types::StateSchema {
        num_uint: 1,
        num_byte_slice: 0,
    });
    apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

    // AppParams should exist.
    let app = state.get_app_params(app_id).unwrap();
    assert_eq!(app.local_state_schema.num_uint, 2);
    assert_eq!(app.global_state_schema.num_uint, 1);
    assert_eq!(state.get_account(&creator).unwrap().total_created_apps, 1);

    // User opts in.
    let optin = appl_optin_txn(user, 1_000, app_id);
    apply_transaction(&mut state, &optin, &ctx, 0).unwrap();

    // Local state should exist.
    let local = state.get_app_local_state(&user, app_id).unwrap();
    assert_eq!(local.schema.num_uint, 2);
    assert_eq!(local.schema.num_byte_slice, 1);
    assert_eq!(state.get_account(&user).unwrap().total_apps_opted_in, 1);
}

// ---------------------------------------------------------------------------
// 12. EvalDelta global state
// ---------------------------------------------------------------------------

#[test]
fn test_eval_delta_global_state() {
    let creator = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(&[(creator, 50_000_000), (fee_sink, 0)], fee_sink);
    let ctx = ApplyContext {
        rewards_level: 0,
        fee_sink,
    };

    let app_id = 300u64;

    // Create app.
    let create = appl_create_txn(creator, 1_000, app_id, 0);
    apply_transaction(&mut state, &create, &ctx, 0).unwrap();

    // App call (NoOp) with global delta setting a uint key.
    let mut call = SignedTransaction::default();
    call.txn.txn_type = "appl".to_string();
    call.txn.sender = creator;
    call.txn.fee = 1_000;
    call.txn.application_id = app_id;
    call.txn.on_completion = 0; // NoOp

    // Build eval_delta as rmpv::Value.
    call.eval_delta = Some(rmpv::Value::Map(vec![(
        rmpv::Value::String("gd".into()),
        rmpv::Value::Map(vec![(
            rmpv::Value::String("counter".into()),
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::String("at".into()),
                    rmpv::Value::Integer(1.into()),
                ),
                (
                    rmpv::Value::String("ui".into()),
                    rmpv::Value::Integer(42.into()),
                ),
            ]),
        )]),
    )]));

    apply_transaction(&mut state, &call, &ctx, 0).unwrap();

    // Verify global state was updated.
    let app = state.get_app_params(app_id).unwrap();
    let val = app.global_state.get(b"counter".as_slice()).unwrap();
    assert_eq!(*val, TealValue::Uint(42));
}

// ---------------------------------------------------------------------------
// 13. EvalDelta inner transactions
// ---------------------------------------------------------------------------

#[test]
fn test_eval_delta_inner_txns() {
    let creator = Address([1u8; 32]);
    let receiver = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (receiver, 0), (fee_sink, 0)],
        fee_sink,
    );
    let ctx = ApplyContext {
        rewards_level: 0,
        fee_sink,
    };

    let app_id = 400u64;

    // Create app.
    let create = appl_create_txn(creator, 1_000, app_id, 0);
    apply_transaction(&mut state, &create, &ctx, 0).unwrap();

    // Build an inner payment txn as rmpv::Value (msgpack-encoded SignedTransaction).
    let mut inner_pay = SignedTransaction::default();
    inner_pay.txn.txn_type = "pay".to_string();
    inner_pay.txn.sender = creator;
    inner_pay.txn.receiver = receiver;
    inner_pay.txn.amount = 100_000;
    inner_pay.txn.fee = 1_000;

    let inner_bytes = rmp_serde::to_vec_named(&inner_pay).unwrap();
    let inner_val: rmpv::Value = rmpv::decode::read_value(&mut &inner_bytes[..]).unwrap();

    // App call with inner txn in eval_delta.
    let mut call = SignedTransaction::default();
    call.txn.txn_type = "appl".to_string();
    call.txn.sender = creator;
    call.txn.fee = 1_000;
    call.txn.application_id = app_id;
    call.txn.on_completion = 0;
    call.eval_delta = Some(rmpv::Value::Map(vec![(
        rmpv::Value::String("itx".into()),
        rmpv::Value::Array(vec![inner_val]),
    )]));

    let creator_before = state.get_account(&creator).unwrap().micro_algos;
    apply_transaction(&mut state, &call, &ctx, 0).unwrap();

    // Receiver should have gotten the inner payment.
    assert_eq!(state.get_account(&receiver).unwrap().micro_algos, 100_000);

    // Creator should have been debited: outer fee + inner (amount + fee).
    let creator_after = state.get_account(&creator).unwrap().micro_algos;
    assert_eq!(creator_before - creator_after, 1_000 + 100_000 + 1_000);
}
