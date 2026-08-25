//! Integration tests for apply.rs — covers edge cases NOT in the inline unit tests.

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
    stx.txn.txn_type = "pay".into();
    stx.txn.sender = sender;
    stx.txn.receiver = receiver;
    stx.txn.amount = amount;
    stx.txn.fee = fee;
    stx
}

fn minimal_block(fee_sink: Address, round: u64, payset: Vec<SignedTransaction>) -> Block {
    Block {
        round: Round(round),
        branch: [0u8; 32],
        seed: [0u8; 32],
        txn_commitment: [0u8; 32],
        timestamp: 0,
        genesis_id: String::new(),
        genesis_hash: [0u8; 32],
        proposer: Address::ZERO,
        fee_sink,
        rewards_pool: Address::ZERO,
        rewards_level: 0,
        rewards_rate: 0,
        rewards_residue: 0,
        rewards_recalculation_round: Round(0),
        current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
        next_protocol: String::new(),
        next_protocol_approvals: 0,
        next_protocol_switch_on: Round(0),
        next_protocol_vote_before: Round(0),
        txn_counter: 0,
        fees_collected: 0,
        bonus: 0,
        proposer_payout: 0,
        prev512: [0u8; 64],
        txn256: [0u8; 32],
        txn512: [0u8; 64],
        state_proof_tracking: None,
        upgrade_propose: String::new(),
        upgrade_delay: 0,
        upgrade_approve: false,
        expired_participation_accounts: None,
        absent_participation_accounts: None,
        load: 0,
        congestion_tax: 0,
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

    let ctx = ApplyContext::new_replay(10, fee_sink, 1);

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
    let ctx = ApplyContext::new_replay(0, fee_sink, 1);

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
    let ctx = ApplyContext::new_replay(0, fee_sink, 1);

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
    let ctx = ApplyContext::new_replay(0, fee_sink, 1);

    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "stpf".into();
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
    let ctx = ApplyContext::new_replay(0, fee_sink, 1);

    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "stpf".into();
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
    let ctx = ApplyContext::new_replay(0, fee_sink, 1);

    // Use acfg create to test rekey on non-pay.
    // Set txn_counter so txn_counter + 1 == 42.
    ctx.txn_counter.set(41);
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "acfg".into();
    stx.txn.sender = sender;
    stx.txn.fee = 1_000;
    stx.txn.rekey_to = Some(auth);

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

    let ctx = ApplyContext::new_replay(0, fee_sink, 1);

    // Rekey back to self on a keyreg txn.
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "keyreg".into();
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

    let ctx = ApplyContext::new_replay(0, fee_sink, 1);
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

fn acfg_create_txn(sender: Address, fee: u64, params: AssetParams) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "acfg".into();
    stx.txn.sender = sender;
    stx.txn.fee = fee;
    stx.txn.config_asset = 0;
    stx.txn.asset_params = Some(params);
    stx
}

fn axfer_optin_txn(sender: Address, fee: u64, asset_id: u64) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "axfer".into();
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
    stx.txn.txn_type = "axfer".into();
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
    stx.txn.txn_type = "afrz".into();
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
    stx.txn.txn_type = "axfer".into();
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
    stx.txn.txn_type = "appl".into();
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
    stx.txn.txn_type = "appl".into();
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

    // Set txn_counter so apply_acfg computes txn_counter + 1 == asset_id.
    state.txn_counter = asset_id - 1;

    // Block 1: Create asset.
    let create_params = AssetParams {
        total: 10_000,
        manager: Some(creator),
        freeze: Some(creator),
        clawback: Some(creator),
        ..Default::default()
    };
    let mut block1 = minimal_block(
        fee_sink,
        1,
        vec![acfg_create_txn(creator, 1_000, create_params)],
    );
    block1.txn_counter = asset_id; // persist counter after this block
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
    destroy_stx.txn.txn_type = "acfg".into();
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
    let ctx = ApplyContext::new_replay(0, fee_sink, 1);

    // Base min balance for user (no assets/apps): 100_000
    let base_min = algo_ledger::min_balance(state.get_account(&user).unwrap());
    assert_eq!(base_min, 100_000);

    // Create asset.
    // Set txn_counter so txn_counter + 1 == 42.
    ctx.txn_counter.set(41);
    let params = AssetParams {
        total: 1_000,
        manager: Some(creator),
        ..Default::default()
    };
    let stx = acfg_create_txn(creator, 1_000, params);
    apply_transaction(&mut state, &stx, &ctx, 0).unwrap();

    // Creator: min_balance increases for opted-in holding (which includes creator holding).
    // total_assets_opted_in already counts creator holdings, so no separate created-asset cost.
    let creator_min = algo_ledger::min_balance(state.get_account(&creator).unwrap());
    // base + 1 opted-in * 100k = 200_000
    assert_eq!(creator_min, 200_000);

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
    destroy.txn.txn_type = "acfg".into();
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
    let ctx = ApplyContext::new_replay(0, fee_sink, 1);

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
    let ctx = ApplyContext::new_replay(0, fee_sink, 1);

    let app_id = 300u64;

    // Create app.
    let create = appl_create_txn(creator, 1_000, app_id, 0);
    apply_transaction(&mut state, &create, &ctx, 0).unwrap();

    // App call (NoOp) with global delta setting a uint key.
    let mut call = SignedTransaction::default();
    call.txn.txn_type = "appl".into();
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
    let ctx = ApplyContext::new_replay(0, fee_sink, 1);

    let app_id = 400u64;

    // Create app.
    let create = appl_create_txn(creator, 1_000, app_id, 0);
    apply_transaction(&mut state, &create, &ctx, 0).unwrap();

    // Build an inner payment txn as rmpv::Value (msgpack-encoded SignedTransaction).
    let mut inner_pay = SignedTransaction::default();
    inner_pay.txn.txn_type = "pay".into();
    inner_pay.txn.sender = creator;
    inner_pay.txn.receiver = receiver;
    inner_pay.txn.amount = 100_000;
    inner_pay.txn.fee = 1_000;

    let inner_bytes = rmp_serde::to_vec_named(&inner_pay).unwrap();
    let inner_val: rmpv::Value = rmpv::decode::read_value(&mut &inner_bytes[..]).unwrap();

    // App call with inner txn in eval_delta.
    let mut call = SignedTransaction::default();
    call.txn.txn_type = "appl".into();
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

// ---------------------------------------------------------------------------
// 14. Keyreg in block — integration
// ---------------------------------------------------------------------------

fn keyreg_online_txn(sender: Address, fee: u64) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "keyreg".into();
    stx.txn.sender = sender;
    stx.txn.fee = fee;
    stx.txn.vote_pk = Some([0xAA; 32]);
    stx.txn.selection_pk = Some([0xBB; 32]);
    stx.txn.state_proof_pk = Some([0xCC; 64]);
    // vote_first <= round+1 and vote_last > round to pass keyreg coherency checks.
    stx.txn.vote_first = 1;
    stx.txn.vote_last = 300;
    stx.txn.vote_key_dilution = 10;
    stx
}

#[test]
fn test_keyreg_in_block() {
    let sender = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(&[(sender, 10_000_000), (fee_sink, 0)], fee_sink);

    let stx = keyreg_online_txn(sender, 1_000);
    let block = minimal_block(fee_sink, 1, vec![stx]);
    apply_block(&mut state, &block).unwrap();

    let acct = state.get_account(&sender).unwrap();
    assert_eq!(acct.status, AccountStatus::Online);
    assert_eq!(acct.vote_id, Some([0xAA; 32]));
    assert_eq!(acct.selection_id, Some([0xBB; 32]));
    assert_eq!(acct.state_proof_id, Some([0xCC; 64]));
    assert_eq!(acct.vote_first_valid, 1);
    assert_eq!(acct.vote_last_valid, 300);
    assert_eq!(acct.vote_key_dilution, 10);
    assert_eq!(acct.micro_algos, 9_999_000);
    assert_eq!(state.current_round, Round(1));
}

// ---------------------------------------------------------------------------
// 15. Lease across blocks — duplicate rejected
// ---------------------------------------------------------------------------

#[test]
fn test_lease_across_blocks() {
    let sender = Address([1u8; 32]);
    let receiver = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(sender, 10_000_000), (receiver, 100_000), (fee_sink, 0)],
        fee_sink,
    );

    let lease_val: [u8; 32] = [0xDD; 32];

    // Block 1 at round 1: txn with lease, last_valid = round + 5 = 6.
    let mut stx1 = pay_txn(sender, receiver, 1_000, 1_000);
    stx1.txn.lease = lease_val;
    stx1.txn.last_valid = Round(6);
    let block1 = minimal_block(fee_sink, 1, vec![stx1]);
    apply_block(&mut state, &block1).unwrap();

    // Block 2 at round 2: same sender, same lease — should be rejected.
    let mut stx2 = pay_txn(sender, receiver, 1_000, 1_000);
    stx2.txn.lease = lease_val;
    stx2.txn.last_valid = Round(7);
    let block2 = minimal_block(fee_sink, 2, vec![stx2]);
    let result = apply_block(&mut state, &block2);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("duplicate lease"),
        "expected duplicate lease error, got: {}",
        err_msg,
    );
}

// ---------------------------------------------------------------------------
// 16. Lease expired — second txn succeeds
// ---------------------------------------------------------------------------

#[test]
fn test_lease_expired_across_blocks() {
    let sender = Address([1u8; 32]);
    let receiver = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(sender, 10_000_000), (receiver, 100_000), (fee_sink, 0)],
        fee_sink,
    );

    let lease_val: [u8; 32] = [0xEE; 32];

    // Block 1 at round 1: txn with lease, last_valid = 1 (expires at round 1).
    let mut stx1 = pay_txn(sender, receiver, 1_000, 1_000);
    stx1.txn.lease = lease_val;
    stx1.txn.last_valid = Round(1);
    let block1 = minimal_block(fee_sink, 1, vec![stx1]);
    apply_block(&mut state, &block1).unwrap();

    // Advance through rounds 2-4 with empty blocks to let the lease expire.
    // purge_expired is called at end of apply_block with current_round.
    // The lease has last_valid=1, so it's purged when current_round > 1.
    for r in 2..=4 {
        let empty_block = minimal_block(fee_sink, r, vec![]);
        apply_block(&mut state, &empty_block).unwrap();
    }

    // Block 5 at round 5: same sender, same lease — should succeed (lease expired).
    let mut stx2 = pay_txn(sender, receiver, 1_000, 1_000);
    stx2.txn.lease = lease_val;
    stx2.txn.last_valid = Round(10);
    let block5 = minimal_block(fee_sink, 5, vec![stx2]);
    apply_block(&mut state, &block5).unwrap();

    // Both txns succeeded: 2 * (1_000 + 1_000) = 4_000 deducted total.
    assert_eq!(
        state.get_account(&sender).unwrap().micro_algos,
        10_000_000 - 4_000
    );
    assert_eq!(
        state.get_account(&receiver).unwrap().micro_algos,
        100_000 + 2_000
    );
}

// ---------------------------------------------------------------------------
// 17. Different senders, same lease — both succeed
// ---------------------------------------------------------------------------

#[test]
fn test_lease_different_senders_ok() {
    let sender_a = Address([1u8; 32]);
    let sender_b = Address([2u8; 32]);
    let receiver = Address([5u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[
            (sender_a, 10_000_000),
            (sender_b, 10_000_000),
            (receiver, 100_000),
            (fee_sink, 0),
        ],
        fee_sink,
    );

    let lease_val: [u8; 32] = [0xFF; 32];

    // Block 1: sender_a uses the lease.
    let mut stx1 = pay_txn(sender_a, receiver, 1_000, 1_000);
    stx1.txn.lease = lease_val;
    stx1.txn.last_valid = Round(10);
    let block1 = minimal_block(fee_sink, 1, vec![stx1]);
    apply_block(&mut state, &block1).unwrap();

    // Block 2: sender_b uses the same lease value — should succeed (different sender).
    let mut stx2 = pay_txn(sender_b, receiver, 2_000, 1_000);
    stx2.txn.lease = lease_val;
    stx2.txn.last_valid = Round(10);
    let block2 = minimal_block(fee_sink, 2, vec![stx2]);
    apply_block(&mut state, &block2).unwrap();

    // Both succeeded.
    assert_eq!(
        state.get_account(&sender_a).unwrap().micro_algos,
        10_000_000 - 2_000
    );
    assert_eq!(
        state.get_account(&sender_b).unwrap().micro_algos,
        10_000_000 - 3_000
    );
    assert_eq!(
        state.get_account(&receiver).unwrap().micro_algos,
        100_000 + 3_000
    );
}

// ---------------------------------------------------------------------------
// 18. Rewards recalculation round — rate drops to 0
// ---------------------------------------------------------------------------

#[test]
fn test_rewards_recalculation_rate_drops_to_zero() {
    let sender = Address([1u8; 32]);
    let receiver = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let rewards_pool = Address([4u8; 32]);

    let mut state = make_state(
        &[
            (sender, 10_000_000),
            (receiver, 5_000_000),
            (fee_sink, 0),
            (rewards_pool, 100_000_000),
        ],
        fee_sink,
    );
    state.rewards_pool = rewards_pool;

    // Set initial rewards state: rate=100, level=10, base=10 for both accounts.
    state.rewards_level = 10;
    state.rewards_rate = 100;
    state.get_or_default_account(&sender).rewards_base = 10;
    state.get_or_default_account(&receiver).rewards_base = 10;

    // Block 1: rewards_level rises to 20 (rate still 100).
    let mut block1 = minimal_block(fee_sink, 1, vec![]);
    block1.rewards_level = 20;
    block1.rewards_rate = 100;
    block1.rewards_pool = rewards_pool;
    apply_block(&mut state, &block1).unwrap();

    // Block 2: recalculation round reached, rate drops to 0, level stays 20.
    let stx = pay_txn(sender, receiver, 1_000, 1_000);
    let mut block2 = minimal_block(fee_sink, 2, vec![stx]);
    block2.rewards_level = 20;
    block2.rewards_rate = 0;
    block2.rewards_recalculation_round = Round(2);
    block2.rewards_pool = rewards_pool;
    apply_block(&mut state, &block2).unwrap();

    // Sender pending rewards: (20 - 10) * (10_000_000 / 1_000_000) = 100
    // Sender after rewards: 10_000_100, then -1_000 (amount) -1_000 (fee) = 9_998_100
    assert_eq!(state.get_account(&sender).unwrap().micro_algos, 9_998_100);
    // Receiver pending rewards: (20 - 10) * (5_000_000 / 1_000_000) = 50
    // Receiver after rewards: 5_000_050, then +1_000 = 5_001_050
    assert_eq!(state.get_account(&receiver).unwrap().micro_algos, 5_001_050,);
    // Both accounts' rewards_base updated to 20.
    assert_eq!(state.get_account(&sender).unwrap().rewards_base, 20);
    assert_eq!(state.get_account(&receiver).unwrap().rewards_base, 20);

    // Now rate is 0, so block 3 with level still 20: no new rewards.
    let stx2 = pay_txn(sender, receiver, 500, 1_000);
    let mut block3 = minimal_block(fee_sink, 3, vec![stx2]);
    block3.rewards_level = 20;
    block3.rewards_rate = 0;
    block3.rewards_pool = rewards_pool;
    apply_block(&mut state, &block3).unwrap();

    // No new rewards: (20 - 20) * ... = 0
    // Sender: 9_998_100 - 500 - 1_000 = 9_996_600
    assert_eq!(state.get_account(&sender).unwrap().micro_algos, 9_996_600);
    // Receiver: 5_001_050 + 500 = 5_001_550
    assert_eq!(state.get_account(&receiver).unwrap().micro_algos, 5_001_550,);
    assert_eq!(state.rewards_rate, 0);
}

// ---------------------------------------------------------------------------
// 19. Zero-balance / min-balance enforcement with opted-in assets
// ---------------------------------------------------------------------------

#[test]
fn test_min_balance_enforcement_with_assets() {
    let sender = Address([1u8; 32]);
    let creator = Address([5u8; 32]);
    let receiver = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    // Sender starts with 300_000 — just enough for base min (100k) + 1 asset opt-in (100k).
    let mut state = make_state(
        &[
            (sender, 300_000),
            (creator, 50_000_000),
            (receiver, 100_000),
            (fee_sink, 0),
        ],
        fee_sink,
    );
    let ctx = ApplyContext::new_replay(0, fee_sink, 1);

    // Create asset from creator.
    // Set txn_counter so txn_counter + 1 == 42.
    ctx.txn_counter.set(41);
    let params = AssetParams {
        total: 1_000,
        manager: Some(creator),
        ..Default::default()
    };
    let create = acfg_create_txn(creator, 1_000, params);
    apply_transaction(&mut state, &create, &ctx, 0).unwrap();

    // Sender opts in to asset.
    let optin = axfer_optin_txn(sender, 1_000, 42);
    apply_transaction(&mut state, &optin, &ctx, 0).unwrap();

    // Sender balance: 300_000 - 1_000 (fee) = 299_000
    // Min balance: 100_000 (base) + 100_000 (1 asset opt-in) = 200_000
    assert_eq!(state.get_account(&sender).unwrap().micro_algos, 299_000);
    assert_eq!(
        algo_ledger::min_balance(state.get_account(&sender).unwrap()),
        200_000
    );

    // Try to pay 100_000 which would leave sender at 299_000 - 100_000 - 1_000 = 198_000 < 200_000.
    let stx = pay_txn(sender, receiver, 100_000, 1_000);
    let result = apply_transaction(&mut state, &stx, &ctx, 0);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("below minimum balance"),
        "expected min-balance error, got: {}",
        err_msg,
    );

    // A smaller payment that keeps sender above min balance should succeed.
    let stx2 = pay_txn(sender, receiver, 97_000, 1_000);
    apply_transaction(&mut state, &stx2, &ctx, 0).unwrap();
    // 299_000 - 97_000 - 1_000 = 201_000 >= 200_000
    assert_eq!(state.get_account(&sender).unwrap().micro_algos, 201_000);
}

// ---------------------------------------------------------------------------
// 20. Account close + re-create in the same block
// ---------------------------------------------------------------------------

#[test]
fn test_close_and_recreate_same_block() {
    let addr = Address([1u8; 32]);
    let receiver = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(addr, 1_000_000), (receiver, 500_000), (fee_sink, 0)],
        fee_sink,
    );

    // Txn 1: Close addr, sending remainder to receiver.
    let mut close_txn = pay_txn(addr, receiver, 0, 1_000);
    close_txn.txn.close_remainder_to = receiver;

    // Txn 2: Send 200_000 from receiver back to addr (re-creating the account).
    let fund_txn = pay_txn(receiver, addr, 200_000, 1_000);

    let block = minimal_block(fee_sink, 1, vec![close_txn, fund_txn]);
    apply_block(&mut state, &block).unwrap();

    // addr was closed (remainder = 1_000_000 - 1_000 = 999_000 to receiver),
    // then re-created with 200_000.
    assert_eq!(state.get_account(&addr).unwrap().micro_algos, 200_000);
    // receiver: 500_000 + 999_000 - 200_000 - 1_000 = 1_298_000
    assert_eq!(state.get_account(&receiver).unwrap().micro_algos, 1_298_000,);
    // fee_sink: 1_000 + 1_000 = 2_000
    assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 2_000);
}

// ---------------------------------------------------------------------------
// 21. Fee pooling + stateful (fee=0 txn applied via apply_block)
// ---------------------------------------------------------------------------

#[test]
fn test_fee_pooling_stateful_apply_block() {
    let a = Address([1u8; 32]);
    let b = Address([2u8; 32]);
    let receiver = Address([5u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(a, 5_000_000), (b, 5_000_000), (receiver, 0), (fee_sink, 0)],
        fee_sink,
    );

    // Txn from A: fee=0, amount=100_000
    let mut txn_a = pay_txn(a, receiver, 100_000, 0);
    // Give them the same group ID to represent an atomic group.
    txn_a.txn.group = [0xAA; 32];

    // Txn from B: fee=2000, amount=50_000
    let mut txn_b = pay_txn(b, receiver, 50_000, 2_000);
    txn_b.txn.group = [0xAA; 32];

    let block = minimal_block(fee_sink, 1, vec![txn_a, txn_b]);
    apply_block(&mut state, &block).unwrap();

    // A: 5_000_000 - 100_000 - 0 (fee) = 4_900_000
    assert_eq!(state.get_account(&a).unwrap().micro_algos, 4_900_000);
    // B: 5_000_000 - 50_000 - 2_000 = 4_948_000
    assert_eq!(state.get_account(&b).unwrap().micro_algos, 4_948_000);
    // receiver: 100_000 + 50_000 = 150_000
    assert_eq!(state.get_account(&receiver).unwrap().micro_algos, 150_000,);
    // fee_sink: 0 + 2_000 = 2_000
    assert_eq!(state.get_account(&fee_sink).unwrap().micro_algos, 2_000);
}

// ---------------------------------------------------------------------------
// 22. Rekey chain: A→B then A→C
// ---------------------------------------------------------------------------

#[test]
fn test_rekey_chain() {
    let a = Address([1u8; 32]);
    let b = Address([2u8; 32]);
    let c = Address([4u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(&[(a, 5_000_000), (b, 0), (c, 0), (fee_sink, 0)], fee_sink);
    let ctx = ApplyContext::new_replay(0, fee_sink, 1);

    // Step 1: A rekeys to B.
    let mut stx1 = pay_txn(a, a, 0, 1_000);
    stx1.txn.rekey_to = Some(b);
    apply_transaction(&mut state, &stx1, &ctx, 0).unwrap();

    assert_eq!(state.get_account(&a).unwrap().auth_addr, Some(b));

    // Step 2: A rekeys to C (overwriting B).
    let mut stx2 = pay_txn(a, a, 0, 1_000);
    stx2.txn.rekey_to = Some(c);
    apply_transaction(&mut state, &stx2, &ctx, 0).unwrap();

    assert_eq!(state.get_account(&a).unwrap().auth_addr, Some(c));

    // Step 3: A rekeys back to self (clearing auth_addr).
    let mut stx3 = pay_txn(a, a, 0, 1_000);
    stx3.txn.rekey_to = Some(a);
    apply_transaction(&mut state, &stx3, &ctx, 0).unwrap();

    assert_eq!(state.get_account(&a).unwrap().auth_addr, None);

    // Total fees: 3 * 1_000 = 3_000
    assert_eq!(state.get_account(&a).unwrap().micro_algos, 4_997_000);
}

// ---------------------------------------------------------------------------
// 23. Asset close-out with pending rewards
// ---------------------------------------------------------------------------

#[test]
fn test_asset_close_out_with_rewards() {
    let holder = Address([1u8; 32]);
    let creator = Address([5u8; 32]);
    let close_to = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let rewards_pool = Address([4u8; 32]);

    let mut state = make_state(
        &[
            (holder, 10_000_000),
            (creator, 50_000_000),
            (close_to, 50_000_000),
            (fee_sink, 0),
            (rewards_pool, 100_000_000),
        ],
        fee_sink,
    );
    state.rewards_pool = rewards_pool;

    // Set up holder with pending rewards: base=0, current level will be 10.
    state.get_or_default_account(&holder).rewards_base = 0;
    state.get_or_default_account(&holder).status = AccountStatus::Online;

    let ctx_no_rewards = ApplyContext::new_replay(0, fee_sink, 1);

    // Create asset from creator.
    // Set txn_counter so txn_counter + 1 == 42.
    ctx_no_rewards.txn_counter.set(41);
    let params = AssetParams {
        total: 1_000,
        manager: Some(creator),
        ..Default::default()
    };
    let create = acfg_create_txn(creator, 1_000, params);
    apply_transaction(&mut state, &create, &ctx_no_rewards, 0).unwrap();

    // Holder opts in (no rewards context yet).
    let optin = axfer_optin_txn(holder, 1_000, 42);
    apply_transaction(&mut state, &optin, &ctx_no_rewards, 0).unwrap();
    // holder: 10_000_000 - 1_000 = 9_999_000

    // Transfer 500 units to holder.
    let xfer = axfer_transfer_txn(creator, holder, 500, 1_000, 42);
    apply_transaction(&mut state, &xfer, &ctx_no_rewards, 0).unwrap();

    assert_eq!(state.get_asset_holding(&holder, 42).unwrap().amount, 500,);

    // Reset holder rewards_base to 0 so there are pending rewards at level 10.
    state.get_or_default_account(&holder).rewards_base = 0;
    let holder_balance_before = state.get_account(&holder).unwrap().micro_algos;
    // holder_balance_before = 9_999_000

    // Close-to also opts in to the asset so they can receive the close-out.
    let optin2 = axfer_optin_txn(close_to, 1_000, 42);
    apply_transaction(&mut state, &optin2, &ctx_no_rewards, 0).unwrap();

    // Now close out holder's asset holding with rewards_level=10.
    let ctx_rewards = ApplyContext::new_replay(10, fee_sink, 2);

    let close = axfer_close_txn(holder, close_to, close_to, 0, 1_000, 42);
    apply_transaction(&mut state, &close, &ctx_rewards, 0).unwrap();

    // Pending rewards: (10 - 0) * (9_999_000 / 1_000_000) = 10 * 9 = 90
    // Holder Algo balance: 9_999_000 + 90 (rewards) - 1_000 (fee) = 9_998_090
    let holder_acct = state.get_account(&holder).unwrap();
    assert_eq!(holder_acct.micro_algos, holder_balance_before + 90 - 1_000);
    assert_eq!(holder_acct.rewards_base, 10);

    // Asset holding should be removed from holder.
    assert!(state.get_asset_holding(&holder, 42).is_none());

    // close_to should have received the 500 asset units.
    assert_eq!(state.get_asset_holding(&close_to, 42).unwrap().amount, 500,);
}
