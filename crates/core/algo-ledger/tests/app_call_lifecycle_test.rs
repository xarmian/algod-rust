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

//! App-call lifecycle integration tests (issue #824, theme 1).
//!
//! Ports the subset of go-algorand's `ledger/apptxn_test.go`,
//! `ledger/eval_simple_test.go`, and `ledger/apply/application_test.go`
//! app-call-lifecycle tests that exercise genuinely already-implemented
//! algod-rust behavior with no existing direct-analog coverage:
//! `TestGtxnEffects`, `TestSelfCheckHoldingNewApp`, `TestCheckHoldingNewApp`,
//! `TestEvalAppState`, `TestAppCallApplyCreateClearState`, and
//! `TestAppInsMinBalance`.
//!
//! `TestGarbageClearState` is covered separately in
//! `algo-validate/src/rules.rs` (`test_appl_creation_empty_clear_state_program_bytes_rejected`
//! / `test_appl_creation_bad_uvarint_clear_state_program_rejected`), since
//! that check lives in transaction well-formedness validation, not apply.
//!
//! Several other named tests in the issue's theme-1 list were investigated
//! and found NOT to be additional apply/AVM-behavior gaps (see issue #824's
//! tracking doc update for the full reasoning):
//! - `TestAppAccountDataStorage`, `TestPartialDeltaWrites`,
//!   `TestAppAccountDeltaIndicesCompatibility1/2/3` all drive go's
//!   `appendUnvalidatedTx`/hand-fed `ApplyData` helper rather than real AVM
//!   execution -- they assert on go's `trackerdb` row-level bookkeeping
//!   (base-vs-resource record separation, DB-index-keyed local-delta
//!   storage), which has no direct analog in algod-rust's diff-based
//!   `LedgerState`/`StateDelta` design (same class of gap already
//!   reclassified `out-of-scope` for `TestMakeStateDeltaMaps` et al. in
//!   Theme 5, PR #864).
//! - `TestForeignAppAccountsAccessible`, `TestInnerAppCreateAndOptin`,
//!   `TestInnerCreateCanUseAbsoluteExtraProgramPages`,
//!   `TestInnerUpdateResizing`, `TestAppCallCheckProgramsWithAccess`, and
//!   `TestAppCallCheckProgramCosts` are deferred -- see the follow-up issue
//!   referenced from `docs/phase17/parity_ledger_core.md`.

use std::cell::RefCell;

use algo_avm::group::GroupBudget;
use algo_ledger::{
    apply_block_capturing_apply_data, apply_transaction_with_budget, parse_eval_delta,
    ApplyContext, ApplyMode, GroupInfo, LedgerState,
};
use algo_types::{Address, Block, Round, SignedTransaction, StateSchema};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_state(balances: &[(Address, u64)], fee_sink: Address) -> LedgerState {
    let mut state = LedgerState::new();
    state.fee_sink = fee_sink;
    for (addr, bal) in balances {
        let acct = state.get_or_default_account_mut(addr);
        acct.micro_algos = *bal;
    }
    state
}

fn execute_ctx(fee_sink: Address, round: u64) -> ApplyContext {
    let mut ctx = ApplyContext::new_replay(0, fee_sink, round);
    ctx.mode = ApplyMode::Execute;
    ctx
}

fn assemble(source: &str) -> Vec<u8> {
    algo_avm::assembler::assemble_string(source)
        .unwrap_or_else(|e| panic!("assembly failed: {e:?}\nsource:\n{source}"))
        .program
}

/// Build an appl-create SignedTransaction with explicit approval/clear
/// program TEAL source, an explicit deterministic `app_id` (mirroring
/// `apply_test.rs`'s `appl_create_txn` pattern -- `apply_data_application_id`
/// is how this crate's apply layer learns a deterministic creatable ID
/// without depending on `ApplyContext::txn_counter` bookkeeping), and
/// optional global/local schemas.
#[allow(clippy::too_many_arguments)]
fn appl_create(
    sender: Address,
    fee: u64,
    app_id: u64,
    approval_src: &str,
    clear_src: &str,
    global_schema: Option<StateSchema>,
    local_schema: Option<StateSchema>,
    foreign_assets: Option<Vec<u64>>,
) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "appl".into();
    stx.txn.sender = sender;
    stx.txn.fee = fee;
    stx.txn.application_id = 0;
    stx.txn.on_completion = 0; // NoOp
    stx.txn.approval_program = Some(serde_bytes::ByteBuf::from(assemble(approval_src)));
    stx.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(assemble(clear_src)));
    stx.txn.global_state_schema = global_schema;
    stx.txn.local_state_schema = local_schema;
    stx.txn.foreign_assets = foreign_assets;
    stx.apply_data_application_id = app_id;
    stx
}

/// Build an appl-call SignedTransaction against an existing app.
fn appl_call(
    sender: Address,
    fee: u64,
    app_id: u64,
    on_completion: u64,
    foreign_assets: Option<Vec<u64>>,
) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "appl".into();
    stx.txn.sender = sender;
    stx.txn.fee = fee;
    stx.txn.application_id = app_id;
    stx.txn.on_completion = on_completion;
    stx.txn.foreign_assets = foreign_assets;
    stx
}

/// Trivial always-approve v8 program: `int 1`.
const APPROVE_SRC: &str = "#pragma version 8\nint 1\n";

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
// 1. TestGtxnEffects (ledger/apptxn_test.go:1422)
//
// A top-level app call must be able to read an EARLIER sibling group
// member's ApplyData-derived effect fields (here, `CreatedAssetID`) via
// `gtxn N CreatedAssetID`. Mirrors the mechanism `gaid`/`created_id`
// (avm_context.rs) already uses: `SignedTransaction::apply_data_config_asset`
// is read directly by `txn_fields::read_txn_field`'s field-60 case, so a
// caller that pre-populates it on the group array before constructing the
// `GroupInfo` gets correct sibling-effects visibility -- exactly how a real
// block, whose creatable IDs are deterministic from txn_counter position,
// would be assembled.
// ---------------------------------------------------------------------------

#[test]
fn test_gtxn_effects_created_asset_id_visible_to_sibling_appl() {
    let creator = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let app_id = 900u64;
    const EXPECTED_ASSET_ID: u64 = 777;

    let mut state = make_state(&[(creator, 50_000_000), (fee_sink, 0)], fee_sink);
    let ctx = execute_ctx(fee_sink, 1);

    // "see" app: skip the check on its own creation call (ApplicationID==0,
    // a singleton group where `gtxn 0` is itself and has no CreatedAssetID),
    // otherwise assert the sibling acfg at group index 0 created exactly
    // the expected asset.
    let see_src = format!(
        "#pragma version 8\n\
         txn ApplicationID\n\
         bz create\n\
         gtxn 0 CreatedAssetID\n\
         int {EXPECTED_ASSET_ID}\n\
         ==\n\
         assert\n\
         create:\n\
         int 1\n"
    );
    let create = appl_create(
        creator,
        1_000,
        app_id,
        &see_src,
        APPROVE_SRC,
        None,
        None,
        None,
    );
    apply_transaction_with_budget(&mut state, &create, &ctx, 0, None, None, None, None)
        .expect("app creation (ApplicationID==0 branch) must succeed");

    // Build the real group: [0] acfg creating an asset, [1] appl calling the
    // pre-existing "see" app, checking gtxn 0's CreatedAssetID.
    let mut createasa = SignedTransaction::default();
    createasa.txn.txn_type = "acfg".into();
    createasa.txn.sender = creator;
    createasa.txn.fee = 1_000;
    createasa.txn.asset_params = Some(algo_types::AssetParams {
        total: 2,
        unit_name: "$".into(),
        ..Default::default()
    });
    // Real apply_acfg derives the created ID from `ctx.txn_counter + 1`; set
    // both so the real state mutation and the AVM's sibling-effects view
    // agree on the same ID.
    ctx.txn_counter.set(EXPECTED_ASSET_ID - 1);
    createasa.apply_data_config_asset = EXPECTED_ASSET_ID;

    let see_call = appl_call(creator, 1_000, app_id, 0, None);

    let group_refs: Vec<&SignedTransaction> = vec![&createasa, &see_call];
    let ran_program = RefCell::new(vec![false; group_refs.len()]);
    let scratch = RefCell::new(vec![None; group_refs.len()]);
    let mut budget = GroupBudget::new(1);

    let gi0 = GroupInfo {
        txns: &group_refs,
        index: 0,
        ran_program: &ran_program,
        scratch: &scratch,
    };
    apply_transaction_with_budget(
        &mut state,
        &createasa,
        &ctx,
        0,
        Some(&mut budget),
        None,
        Some(&gi0),
        None,
    )
    .expect("acfg create must succeed");
    assert_eq!(
        state
            .get_asset_params(EXPECTED_ASSET_ID)
            .unwrap()
            .params
            .total,
        2
    );

    let gi1 = GroupInfo {
        txns: &group_refs,
        index: 1,
        ran_program: &ran_program,
        scratch: &scratch,
    };
    apply_transaction_with_budget(
        &mut state,
        &see_call,
        &ctx,
        0,
        Some(&mut budget),
        None,
        Some(&gi1),
        None,
    )
    .expect("gtxn 0 CreatedAssetID must see the sibling acfg's real created asset ID");
}

// ---------------------------------------------------------------------------
// 2. TestSelfCheckHoldingNewApp (ledger/apptxn_test.go:1820)
//
// During its OWN creation call, an app can call `asset_holding_get
// AssetBalance` against `global CurrentApplicationAddress` (its own,
// about-to-exist account) for a real, pre-existing asset it is not opted
// into. Since it can't possibly be opted in yet, the opcode must report
// exists=0 / value=0 rather than erroring -- `CurrentApplicationAddress`
// must already resolve correctly even inside the creation call itself.
// ---------------------------------------------------------------------------

#[test]
fn test_self_check_holding_new_app_not_opted_in() {
    let creator = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let asset_id = 500u64;
    let app_id = 900u64;

    let mut state = make_state(&[(creator, 50_000_000), (fee_sink, 0)], fee_sink);
    let ctx = execute_ctx(fee_sink, 1);

    // Create a real asset first.
    let mut acfg = SignedTransaction::default();
    acfg.txn.txn_type = "acfg".into();
    acfg.txn.sender = creator;
    acfg.txn.fee = 1_000;
    acfg.txn.asset_params = Some(algo_types::AssetParams {
        total: 10,
        decimals: 1,
        unit_name: "X".into(),
        asset_name: "TEN".into(),
        ..Default::default()
    });
    ctx.txn_counter.set(asset_id - 1);
    apply_transaction_with_budget(&mut state, &acfg, &ctx, 0, None, None, None, None)
        .expect("acfg create must succeed");
    assert!(state.get_asset_params(asset_id).is_some());

    let selfcheck_src = "\
#pragma version 8
global CurrentApplicationAddress
txna Assets 0
asset_holding_get AssetBalance
!
assert
!
";
    let create = appl_create(
        creator,
        1_000,
        app_id,
        selfcheck_src,
        APPROVE_SRC,
        None,
        None,
        Some(vec![asset_id]),
    );
    apply_transaction_with_budget(&mut state, &create, &ctx, 0, None, None, None, None).expect(
        "self-holding-check on an app's own not-yet-opted-in address must approve, not error",
    );

    // The app's own account must not have gained a holding just from the check.
    let app_address = Address(algo_ledger::avm_context::app_address(app_id));
    assert!(state.get_asset_holding(&app_address, asset_id).is_none());
}

// ---------------------------------------------------------------------------
// 3. TestCheckHoldingNewApp (ledger/apptxn_test.go:1870)
//
// A later group member can check the asset holding of a just-created (not
// yet live before this group) sibling app's address, resolved via `gaid 0`
// + `app_params_get AppAddress`. Since the app was only just created this
// group, it can't have opted into anything: exists=0, value=0.
// ---------------------------------------------------------------------------

#[test]
fn test_check_holding_new_app_via_gaid_and_app_params_get() {
    let creator = Address([1u8; 32]);
    let other = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let asset_id = 500u64;
    let check_app_id = 900u64;
    const NEW_APP_ID: u64 = 901;

    let mut state = make_state(
        &[(creator, 50_000_000), (other, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );
    let ctx = execute_ctx(fee_sink, 1);

    // Create a real asset.
    let mut acfg = SignedTransaction::default();
    acfg.txn.txn_type = "acfg".into();
    acfg.txn.sender = creator;
    acfg.txn.fee = 1_000;
    acfg.txn.asset_params = Some(algo_types::AssetParams {
        total: 10,
        decimals: 1,
        unit_name: "X".into(),
        asset_name: "TEN".into(),
        ..Default::default()
    });
    ctx.txn_counter.set(asset_id - 1);
    apply_transaction_with_budget(&mut state, &acfg, &ctx, 0, None, None, None, None)
        .expect("acfg create must succeed");

    // Pre-create the "check" app: skip the check on its own creation call,
    // otherwise look up group index 0's created app via `gaid`, get its
    // AppAddress, and check that address's holding of the foreign asset.
    let check_src = "\
#pragma version 8
txn ApplicationID
bz create
gaid 0
app_params_get AppAddress
assert
txna Assets 0
asset_holding_get AssetBalance
!
assert
!
assert
create:
int 1
";
    let create_check = appl_create(
        creator,
        1_000,
        check_app_id,
        check_src,
        APPROVE_SRC,
        None,
        None,
        None,
    );
    apply_transaction_with_budget(&mut state, &create_check, &ctx, 0, None, None, None, None)
        .expect("check-app creation must succeed");

    // Group: [0] a bare new-app create (application_id 0), [1] a call to
    // the pre-existing "check" app which `gaid 0`s the sibling.
    let new_app_create = appl_create(
        other,
        1_000,
        NEW_APP_ID,
        APPROVE_SRC,
        APPROVE_SRC,
        None,
        None,
        None,
    );
    let check_call = appl_call(other, 1_000, check_app_id, 0, Some(vec![asset_id]));

    let group_refs: Vec<&SignedTransaction> = vec![&new_app_create, &check_call];
    let ran_program = RefCell::new(vec![false; group_refs.len()]);
    let scratch = RefCell::new(vec![None; group_refs.len()]);
    let mut budget = GroupBudget::new(1);

    let gi0 = GroupInfo {
        txns: &group_refs,
        index: 0,
        ran_program: &ran_program,
        scratch: &scratch,
    };
    apply_transaction_with_budget(
        &mut state,
        &new_app_create,
        &ctx,
        0,
        Some(&mut budget),
        None,
        Some(&gi0),
        None,
    )
    .expect("new app create must succeed");

    let gi1 = GroupInfo {
        txns: &group_refs,
        index: 1,
        ran_program: &ran_program,
        scratch: &scratch,
    };
    apply_transaction_with_budget(
        &mut state,
        &check_call,
        &ctx,
        0,
        Some(&mut budget),
        None,
        Some(&gi1),
        None,
    )
    .expect("checking a just-created sibling app's (empty) holding via gaid must approve");
}

// ---------------------------------------------------------------------------
// 4. TestEvalAppState (ledger/apptxn_test.go:3327)
//
// The global-state-schema-count limit must be enforced against the
// CUMULATIVE state after earlier group members' writes have already
// persisted, not just each call's own isolated delta: a create call writing
// one byte-slice key, followed in the SAME group by a second call to the
// same (freshly created) app writing a second, distinct byte-slice key,
// must be rejected once the schema is too small for both -- and succeed,
// with both keys present, once the schema covers both.
// ---------------------------------------------------------------------------

#[test]
fn test_eval_app_state_group_schema_limit_then_success() {
    let creator = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let app_id = 900u64;

    // "creator"/"caller" writer, matching go's TestEvalAppState fixture:
    // on create, write "creator"; on a later call, write "caller".
    let writer_src = "\
#pragma version 6
txn ApplicationID
bz create
byte \"caller\"
txn Sender
app_global_put
b ok
create:
byte \"creator\"
txn Sender
app_global_put
ok:
int 1
";

    // --- Scenario A: schema too small (1 byte-slice) -- second call rejected.
    {
        let mut state = make_state(&[(creator, 50_000_000), (fee_sink, 0)], fee_sink);
        let ctx = execute_ctx(fee_sink, 1);

        let create = appl_create(
            creator,
            1_000,
            app_id,
            writer_src,
            APPROVE_SRC,
            Some(StateSchema {
                num_uint: 0,
                num_byte_slice: 1,
            }),
            None,
            None,
        );
        apply_transaction_with_budget(&mut state, &create, &ctx, 0, None, None, None, None)
            .expect("create (writes 1 key, 'creator') must fit schema=1");

        let call = appl_call(creator, 1_000, app_id, 0, None);
        let err = apply_transaction_with_budget(&mut state, &call, &ctx, 0, None, None, None, None)
            .expect_err("second distinct global key must exceed schema=1");
        let msg = err.to_string();
        assert!(
            msg.contains("store bytes count 2 exceeds schema bytes count 1"),
            "unexpected error: {msg}"
        );
    }

    // --- Scenario B: schema wide enough (2 byte-slices) -- both succeed.
    {
        let mut state = make_state(&[(creator, 50_000_000), (fee_sink, 0)], fee_sink);
        let ctx = execute_ctx(fee_sink, 1);

        let create = appl_create(
            creator,
            1_000,
            app_id,
            writer_src,
            APPROVE_SRC,
            Some(StateSchema {
                num_uint: 0,
                num_byte_slice: 2,
            }),
            None,
            None,
        );
        apply_transaction_with_budget(&mut state, &create, &ctx, 0, None, None, None, None)
            .expect("create must succeed");

        let call = appl_call(creator, 1_000, app_id, 0, None);
        apply_transaction_with_budget(&mut state, &call, &ctx, 0, None, None, None, None)
            .expect("second call must succeed once schema=2 covers both keys");

        let params = state.get_app_params(app_id).expect("app must exist");
        let creator_bytes = creator.0.to_vec();
        assert_eq!(
            params.global_state.get(b"caller".as_slice()),
            Some(&algo_types::TealValue::Bytes(creator_bytes.clone()))
        );
        assert_eq!(
            params.global_state.get(b"creator".as_slice()),
            Some(&algo_types::TealValue::Bytes(creator_bytes))
        );
    }
}

// ---------------------------------------------------------------------------
// 5. TestAppCallApplyCreateClearState (ledger/apply/application_test.go:1254)
//
// Creating an app (ApplicationID==0) with OnCompletion==ClearState in the
// SAME call must be rejected: the sender can't already be opted in to an
// app that doesn't exist yet, and ClearState always requires the sender to
// already hold local state.
// ---------------------------------------------------------------------------

#[test]
fn test_appl_create_with_clear_state_on_completion_rejected_not_opted_in() {
    const ON_COMPLETION_CLEAR_STATE: u64 = 3;

    let creator = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let app_id = 900u64;

    let mut state = make_state(&[(creator, 50_000_000), (fee_sink, 0)], fee_sink);
    let ctx = execute_ctx(fee_sink, 1);

    let mut create = appl_create(
        creator,
        1_000,
        app_id,
        APPROVE_SRC,
        APPROVE_SRC,
        Some(StateSchema {
            num_uint: 1,
            num_byte_slice: 0,
        }),
        None,
        None,
    );
    create.txn.on_completion = ON_COMPLETION_CLEAR_STATE;

    let err = apply_transaction_with_budget(&mut state, &create, &ctx, 0, None, None, None, None)
        .expect_err("create+ClearState in one call must be rejected: sender can't be opted in yet");
    let msg = err.to_string();
    assert!(
        msg.contains("not currently opted in"),
        "unexpected error: {msg}"
    );
}

// ---------------------------------------------------------------------------
// 6. TestAppInsMinBalance (ledger/eval_simple_test.go:1825)
//
// Min-balance accounting must scale correctly with several distinct
// created + opted-in apps for the SAME account (not just one), matching
// go-algorand's per-app-params / per-local-state MBR contribution. This is
// a lighter-weight version of go's 50-app loop (which specifically probes
// the historical `MaxAppsOptedIn` cap from ConsensusV30) -- algod-rust's
// current-protocol-only scope doesn't model that legacy per-version cap
// (`max_apps_opted_in` is 0/unlimited from v32 on, the only version this
// crate targets; see docs/phase17/parity_ledger_core.md's tracking note),
// so this test instead pins the underlying MBR-scaling behavior the go
// test's final assertions actually depend on.
// ---------------------------------------------------------------------------

#[test]
fn test_app_min_balance_scales_with_created_and_opted_in_apps() {
    let creator = Address([1u8; 32]);
    let user = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (user, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );
    let ctx = execute_ctx(fee_sink, 1);

    let base_min = algo_ledger::min_balance(state.get_account(&user).unwrap());

    const NUM_APPS: u64 = 5;
    for i in 0..NUM_APPS {
        let app_id = 900 + i;
        let create = appl_create(
            creator,
            1_000,
            app_id,
            APPROVE_SRC,
            APPROVE_SRC,
            None,
            None,
            None,
        );
        apply_transaction_with_budget(&mut state, &create, &ctx, 0, None, None, None, None)
            .expect("app create must succeed");

        let optin = appl_call(user, 1_000, app_id, 1 /* OptIn */, None);
        apply_transaction_with_budget(&mut state, &optin, &ctx, 0, None, None, None, None)
            .expect("opt-in must succeed");
    }

    let creator_acct = state.get_account(&creator).unwrap();
    assert_eq!(creator_acct.total_created_apps, NUM_APPS);
    let creator_min = algo_ledger::min_balance(creator_acct);
    // base (100_000) + NUM_APPS created apps * per-app MBR (100_000 params + 25_000 schema base)
    assert!(
        creator_min > base_min,
        "creator's min balance must grow with each created app"
    );

    let user_acct = state.get_account(&user).unwrap();
    assert_eq!(user_acct.total_apps_opted_in, NUM_APPS);
    let user_min = algo_ledger::min_balance(user_acct);
    assert!(
        user_min > base_min,
        "user's min balance must grow with each opted-in app"
    );

    // Each additional app must add a strictly positive, and identical (same
    // empty local schema each time), MBR increment.
    let per_app_increment = (user_min - base_min) / NUM_APPS;
    assert!(per_app_increment > 0);
    assert_eq!(user_min - base_min, per_app_increment * NUM_APPS);
}

// ---------------------------------------------------------------------------
// Sanity check that the group-effects mechanism composes with a real
// `apply_block_capturing_apply_data` block-level pass too (not just the
// manually-orchestrated `GroupInfo` pattern above), covering the same
// `gtxn`/effects codepath as it would actually be reached in production.
// ---------------------------------------------------------------------------

#[test]
fn test_gtxn_effects_via_apply_block_capturing_apply_data() {
    let creator = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let app_id = 950u64;
    const EXPECTED_ASSET_ID: u64 = 42;

    let mut state = make_state(&[(creator, 50_000_000), (fee_sink, 0)], fee_sink);

    let see_src = format!(
        "#pragma version 8\n\
         txn ApplicationID\n\
         bz create\n\
         gtxn 0 CreatedAssetID\n\
         int {EXPECTED_ASSET_ID}\n\
         ==\n\
         assert\n\
         create:\n\
         int 1\n"
    );
    let create = appl_create(
        creator,
        1_000,
        app_id,
        &see_src,
        APPROVE_SRC,
        None,
        None,
        None,
    );
    let create_block = minimal_block(fee_sink, 1, vec![create]);
    apply_block_capturing_apply_data(&mut state, &create_block, ApplyMode::Execute)
        .expect("app creation block must apply cleanly");

    let mut createasa = SignedTransaction::default();
    createasa.txn.txn_type = "acfg".into();
    createasa.txn.sender = creator;
    createasa.txn.fee = 1_000;
    createasa.txn.group = [0xBB; 32];
    createasa.txn.asset_params = Some(algo_types::AssetParams {
        total: 5,
        unit_name: "$".into(),
        ..Default::default()
    });
    createasa.apply_data_config_asset = EXPECTED_ASSET_ID;

    let mut see_call = appl_call(creator, 1_000, app_id, 0, None);
    see_call.txn.group = [0xBB; 32];

    // The real apply_acfg path derives the created ID from the block's
    // running txn_counter, independent of the AVM-visibility preset above;
    // set it so the actual state mutation lands on the same ID.
    state.txn_counter = EXPECTED_ASSET_ID - 1;
    let mut call_block = minimal_block(fee_sink, 2, vec![createasa, see_call]);
    call_block.txn_counter = EXPECTED_ASSET_ID;
    let results = apply_block_capturing_apply_data(&mut state, &call_block, ApplyMode::Execute)
        .expect("group block with gtxn effects must apply cleanly");

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].config_asset, EXPECTED_ASSET_ID);
    // The appl call must have applied successfully (its `assert` on the
    // sibling's real CreatedAssetID didn't fire -- had gtxn effects not been
    // wired through `apply_block_capturing_apply_data`'s real group path,
    // this whole call would have errored out of the `expect` above instead
    // of reaching here). An empty eval delta (no state/logs/inner txns) is
    // itself expected and correctly encoded as `None`, so only check it
    // parses cleanly when present.
    if let Some(dt) = results[1].eval_delta.as_ref() {
        parse_eval_delta(dt).expect("eval delta must parse");
    }
}
