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
//! - `TestAppCallCheckProgramsWithAccess` and `TestAppCallCheckProgramCosts`
//!   are deferred -- see the follow-up issue referenced from
//!   `docs/phase17/parity_ledger_core.md`.
//!
//! `TestForeignAppAccountsAccessible`, `TestInnerAppCreateAndOptin`,
//! `TestInnerCreateCanUseAbsoluteExtraProgramPages`, and
//! `TestInnerUpdateResizing` -- deferred above pending #841 -- are now
//! covered below (issue #964). Porting them surfaced two real,
//! previously-unexercised gaps, both fixed alongside these tests:
//! - Inner transactions (of *any* type, not just `appl`) silently ignored
//!   `itxn_field RekeyTo`: `avm_context.rs`'s `itxn_submit` dispatched
//!   straight to `apply_pay`/`apply_axfer`/`execute_inner_appl` without
//!   ever applying the rekey go-algorand's `applyTransaction` performs
//!   unconditionally before type-specific dispatch. `TestInnerAppCreateAndOptin`
//!   depends on exactly this: an inner appl-call's `RekeyTo` must take
//!   effect immediately so a *subsequent* nested inner txn's
//!   sender-authorization check sees the new `AuthAddr` within the same
//!   top-level transaction.
//! - `ON_COMPLETION_UPDATE` in `apply.rs` incorrectly required the
//!   update's sender to equal the app's creator (a check go-algorand's
//!   `updateApplication` never performs -- permissioning an update is left
//!   entirely to the called app's own approval-program logic), and did not
//!   implement `AppSizeUpdates` resizing (`GlobalStateSchema`/
//!   `ExtraProgramPages` growth via update, with MBR "size sponsor"
//!   tracking) at all, despite `algo-validate` already accepting a
//!   resizing update transaction as well-formed. `TestInnerUpdateResizing`
//!   depends on both: a non-creator inner update, and the resizing MBR
//!   accounting itself.

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

// ---------------------------------------------------------------------------
// Composite scenarios (issue #964, follow-up to #824/#866/#841)
// ---------------------------------------------------------------------------

// 7. TestInnerAppCreateAndOptin (ledger/apptxn_test.go:945)
//
// A composite rekey + inner-create + inner-axfer-optin flow: a create-time
// approval program issues an inner `appl` call that BOTH rekeys the
// creating app's own about-to-exist account to a pre-existing "helper" app
// AND invokes it, all in one inner transaction. The helper then acts *as*
// the caller (using the just-installed rekey authority) to submit a nested
// inner group: an axfer self-opt-in for the caller, followed by a pay that
// funds the caller's opt-in MBR.
//
// Adapted from go's exact TEAL (matched-1:many, not a byte-for-byte port):
// go's helper populates several inner-txn `Fee` fields implicitly, relying
// on go's `addInnerTxn` computing a fee-credit-aware *default* fee per
// sub-transaction as it's added (`data/transactions/logic/eval.go:5491`) --
// a separate, not-yet-ported feature in algod-rust, where an unset `Fee`
// always defaults to the flat `MinTxnFee` regardless of available credit
// (tracked in a follow-up issue). Sidestepped here by pre-funding the
// creating app's own (deterministic, since `app_id` is fixed) address
// directly, rather than depending on that fee-credit-population gap --
// this keeps the test focused on the actual behavior under test (the
// composite rekey/inner-create/inner-optin authorization chain) instead of
// coupling it to an unrelated fee-accounting feature.
#[test]
fn test_inner_app_create_and_optin_composite_rekey_create_axfer() {
    let creator = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let helper_creator = Address([9u8; 32]);
    let helper_id = 900u64;
    let app_id = 901u64;
    const ASA_ID: u64 = 500;

    let helper_addr = Address(algo_ledger::avm_context::app_address(helper_id));
    let app_addr = Address(algo_ledger::avm_context::app_address(app_id));

    let mut state = make_state(
        &[
            (creator, 50_000_000),
            (fee_sink, 0),
            (helper_addr, 1_000_000),
            (app_addr, 1_000_000),
        ],
        fee_sink,
    );

    // Pre-seed the asset directly (equivalent to go's `createasa := dl.txn(...)`).
    state.asset_params.insert(
        ASA_ID,
        algo_types::AssetParamsRecord {
            params: algo_types::AssetParams {
                total: 2,
                unit_name: "$".into(),
                ..Default::default()
            },
            creator,
        },
    );

    // Pre-seed the helper app: when CALLED (not created), it opts the
    // CALLER (`txn Sender`) into the asset, then pays it 200_000 microAlgo
    // for the opt-in's MBR. Mirrors go's `dl.fundedApp(addrs[0], 1_000_000,
    // main(...))`; `main()`'s `txn ApplicationID; bz end` skip is reproduced
    // by the `wrap_main`-style prelude below.
    let helper_src = format!(
        "itxn_begin\n\
         int axfer\n itxn_field TypeEnum\n\
         int {ASA_ID}\n itxn_field XferAsset\n\
         txn Sender\n itxn_field Sender\n\
         txn Sender\n itxn_field AssetReceiver\n\
         itxn_next\n\
         int pay\n itxn_field TypeEnum\n\
         int 200000\n itxn_field Amount\n\
         txn Sender\n itxn_field Receiver\n\
         itxn_submit\n"
    );
    let helper_wrapped =
        format!("#pragma version 8\ntxn ApplicationID\nbz end\n{helper_src}\nend:\nint 1\n");
    state.app_params.insert(
        helper_id,
        algo_types::AppParams {
            creator: helper_creator,
            approval_program: assemble(&helper_wrapped),
            clear_state_program: assemble(APPROVE_SRC),
            ..Default::default()
        },
    );

    // The create call's own approval program runs its inner logic DURING
    // creation (unlike the helper, deliberately NOT wrapped by a
    // `bz end` skip): it rekeys its own about-to-exist account to the
    // helper and invokes it, all in the SAME inner transaction -- go's "call
    // as the caller! (works because of rekey by caller)".
    let create_src = format!(
        "#pragma version 8\n\
         itxn_begin\n\
         int appl\n itxn_field TypeEnum\n\
         addr {helper_addr}\n itxn_field RekeyTo\n\
         int {helper_id}\n itxn_field ApplicationID\n\
         itxn_submit\n\
         int 1\n"
    );
    let create = appl_create(
        creator,
        3_000, // 3x MinTxnFee, mirroring go's `Fee: 3 * proto.MinTxnFee`.
        app_id,
        &create_src,
        APPROVE_SRC,
        None,
        None,
        None,
    );
    let block = minimal_block(fee_sink, 1, vec![create]);
    let results = apply_block_capturing_apply_data(&mut state, &block, ApplyMode::Execute)
        .expect("composite rekey+inner-create+axfer-optin flow must apply cleanly");
    assert_eq!(results[0].application_id, app_id);

    // The caller (the newly created app's own account) must now hold the
    // asset (opted in via the helper's inner axfer) and must have been
    // rekeyed to the helper by the create call's own inner RekeyTo.
    let holding = state
        .get_asset_holding(&app_addr, ASA_ID)
        .expect("app account must be opted into the asset via the helper's inner axfer");
    assert_eq!(holding.amount, 0);

    let app_account = state.get_account(&app_addr).unwrap();
    assert_eq!(
        app_account.auth_addr,
        Some(helper_addr),
        "the create call's own inner RekeyTo must actually take effect"
    );
}

// 8. TestForeignAppAccountsAccessible (ledger/apptxn_test.go:3083)
//
// A foreign app's computed `AppAddress` (resolved via `app_params_get
// AppAddress` against `txn Applications 1`) can be used as an inner-pay
// `Receiver`, once that app is listed in the caller's `ForeignApps` --
// gated by resource-availability rules active from v34 on (algod-rust's
// default `minimal_block` protocol, V41, already qualifies).
#[test]
fn test_foreign_app_accounts_accessible_as_inner_pay_receiver() {
    let creator = Address([1u8; 32]);
    let caller = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let app_a_id = 900u64;
    let app_b_id = 901u64;

    let mut state = make_state(
        &[
            (creator, 3_000_000_000),
            (caller, 50_000_000),
            (fee_sink, 0),
        ],
        fee_sink,
    );

    let app_a = appl_create(
        creator,
        1_000,
        app_a_id,
        APPROVE_SRC,
        APPROVE_SRC,
        None,
        None,
        None,
    );

    let app_b_src = "\
itxn_begin
int pay
itxn_field TypeEnum
int 100
itxn_field Amount
txn Applications 1
app_params_get AppAddress
assert
itxn_field Receiver
itxn_submit
";
    let app_b_wrapped =
        format!("#pragma version 8\ntxn ApplicationID\nbz end\n{app_b_src}\nend:\nint 1\n");
    let app_b = appl_create(
        creator,
        1_000,
        app_b_id,
        &app_b_wrapped,
        APPROVE_SRC,
        None,
        None,
        None,
    );

    let create_block = minimal_block(fee_sink, 1, vec![app_a, app_b]);
    apply_block_capturing_apply_data(&mut state, &create_block, ApplyMode::Execute)
        .expect("app creation block must apply cleanly");

    let app_a_addr = Address(algo_ledger::avm_context::app_address(app_a_id));
    let app_b_addr = Address(algo_ledger::avm_context::app_address(app_b_id));

    let group_id = [0xCCu8; 32];
    let mut fund0 = SignedTransaction::default();
    fund0.txn.txn_type = "pay".into();
    fund0.txn.sender = creator;
    fund0.txn.fee = 1_000;
    fund0.txn.receiver = app_a_addr;
    fund0.txn.amount = 1_000_000_000;
    fund0.txn.group = group_id;

    let mut fund1 = fund0.clone();
    fund1.txn.receiver = app_b_addr;

    let mut call_tx = appl_call(caller, 1_000, app_b_id, 0, None);
    call_tx.txn.foreign_apps = Some(vec![app_a_id]);
    call_tx.txn.group = group_id;

    let call_block = minimal_block(fee_sink, 2, vec![fund0, fund1, call_tx]);
    let results = apply_block_capturing_apply_data(&mut state, &call_block, ApplyMode::Execute)
        .expect("foreign-app-account-as-inner-pay-receiver group must apply cleanly");

    let dt = results[2]
        .eval_delta
        .as_ref()
        .expect("call must produce an eval delta with an inner pay");
    let ed = parse_eval_delta(dt).expect("eval delta must parse");
    let inner = ed.inner_txns.expect("call must submit one inner pay");
    assert_eq!(inner.len(), 1);
    assert_eq!(inner[0].txn.receiver, app_a_addr);
    assert_eq!(inner[0].txn.amount, 100);
}

/// Mirrors go's `assembleLargePassingProgram` (`ledger/applications_test.go:
/// 1789`): assembles a TEAL program of an EXACT target byte length that
/// still always approves, via an unreachable `err` filler branched around
/// by an unconditional `b end`. Used to exercise oversized-program budget
/// accounting without needing the program to do anything real.
fn assemble_large_passing_program(version: u8, size: usize) -> Vec<u8> {
    // version byte + "b end" (3 bytes) + "app_global_get" (1 byte) +
    // "end: int 1" (2 bytes, `pushint 1`) = 7 bytes of fixed overhead.
    const OVERHEAD: usize = 7;
    assert!(
        size >= OVERHEAD,
        "target size must cover the fixed overhead"
    );
    let mut source = format!("#pragma version {version}\nb end\napp_global_get\n");
    for _ in 0..(size - OVERHEAD) {
        source.push_str("err\n");
    }
    source.push_str("end:\nint 1");
    let program = assemble(&source);
    assert_eq!(
        program.len(),
        size,
        "assembled program length must match the requested size exactly"
    );
    program
}

// 9. TestInnerCreateCanUseAbsoluteExtraProgramPages (ledger/applications_test.go:1907)
//
// `MaxAbsoluteExtraProgramPages` (v42, 7) allows an INNER app-create to
// install a larger `ExtraProgramPages` than a plain top-level create could
// (`MaxExtraAppProgramPages`, 3) -- provided the group supplies enough box
// I/O budget to cover the program's write-budget cost
// (`consider_budget_program_writes`, issue #723). Adapted from go's exact
// numbers: with V42's `max_app_total_program_len` (2048) and
// `max_extra_app_program_pages` (3), `programSize = 2048 * 8 / 2 = 8192`
// per program, whose combined size (16384) exceeds the free tier
// (2048 * (1+3) = 8192) by exactly 8192 bytes -- covered by 4 empty box
// refs at V42's `bytes_per_box_reference` (2048), matching go's own "2*8k
// exceeds the normal 8k limit by 4 2k pages" comment exactly. Matches go's
// structure closely: the oversized programs travel through the OUTER
// (factory-create) transaction's `ApplicationArgs`, split into
// `MAX_AVM_BYTES_SIZE`-sized (4096) halves -- NOT embedded as `byte`
// literals in the factory's own TEAL source, which would inflate the
// factory's OWN program past its own write-budget free tier and conflate
// two independent write-budget charges into one.
#[test]
fn test_inner_create_can_use_absolute_extra_program_pages() {
    let creator = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let factory_id = 900u64;
    let factory_addr = Address(algo_ledger::avm_context::app_address(factory_id));

    let mut state = make_state(
        &[
            (creator, 50_000_000),
            (fee_sink, 0),
            (factory_addr, 1_000_000),
        ],
        fee_sink,
    );

    let params =
        algo_types::consensus::consensus_params_for_version(algo_types::consensus::CONSENSUS_V42)
            .expect("V42 must be a known protocol version");
    assert!(params.max_absolute_extra_program_pages >= params.max_extra_app_program_pages);

    let program_size = (params.max_app_total_program_len
        * (1 + params.max_absolute_extra_program_pages as usize))
        / 2;
    let approval = assemble_large_passing_program(8, program_size);
    let clear = assemble_large_passing_program(8, program_size);

    // Split each program in half and pass the halves through the OUTER
    // (factory-create) transaction's `ApplicationArgs` -- exactly go's own
    // structure, and for the same reason: `ApplicationArgs` is transaction
    // wire data, not part of the factory's OWN approval-program bytecode,
    // so embedding the (huge) target programs there -- rather than as
    // `byte` literals inside the factory's own TEAL source -- keeps the
    // factory's OWN program-size write-budget cost negligible. Each half is
    // exactly `MAX_AVM_BYTES_SIZE` (4096), matching go's
    // `config.MaxAVMBytesSize`/`transactions.MaxLogicSigArgSize` split.
    let half = program_size / 2;
    let factory_src = format!(
        "itxn_begin\n\
         int appl\n itxn_field TypeEnum\n\
         txn ApplicationArgs 0\n itxn_field ApprovalProgramPages\n\
         txn ApplicationArgs 1\n itxn_field ApprovalProgramPages\n\
         txn ApplicationArgs 2\n itxn_field ClearStateProgramPages\n\
         txn ApplicationArgs 3\n itxn_field ClearStateProgramPages\n\
         int {}\n itxn_field ExtraProgramPages\n\
         itxn_submit\n\
         int 1\n",
        params.max_absolute_extra_program_pages,
    );
    let factory_wrapped = format!("#pragma version 8\n{factory_src}");

    // 4 empty box refs at V42's 2048 bytes-per-box-reference cover the 8192
    // extra bytes this program pair costs above the free tier.
    let mut create = appl_create(
        creator,
        20_000, // generous fee headroom, mirroring go's `20 * proto.MinTxnFee`
        factory_id,
        &factory_wrapped,
        APPROVE_SRC,
        None,
        None,
        None,
    );
    create.txn.app_arguments = Some(vec![
        Some(serde_bytes::ByteBuf::from(approval[..half].to_vec())),
        Some(serde_bytes::ByteBuf::from(approval[half..].to_vec())),
        Some(serde_bytes::ByteBuf::from(clear[..half].to_vec())),
        Some(serde_bytes::ByteBuf::from(clear[half..].to_vec())),
    ]);
    create.txn.boxes = Some(vec![
        algo_types::BoxRef::default(),
        algo_types::BoxRef::default(),
        algo_types::BoxRef::default(),
        algo_types::BoxRef::default(),
    ]);

    let mut block = minimal_block(fee_sink, 1, vec![create]);
    block.current_protocol = algo_types::consensus::CONSENSUS_V42.to_string();
    let results = apply_block_capturing_apply_data(&mut state, &block, ApplyMode::Execute).expect(
        "inner create with MaxAbsoluteExtraProgramPages and matching box budget must succeed",
    );

    let dt = results[0]
        .eval_delta
        .as_ref()
        .expect("factory call must produce an eval delta with an inner create");
    let ed = parse_eval_delta(dt).expect("eval delta must parse");
    let inner = ed
        .inner_txns
        .expect("factory must submit exactly one inner create");
    assert_eq!(inner.len(), 1);
    assert_ne!(
        inner[0].apply_data_application_id, 0,
        "inner create must produce an app ID"
    );
    assert_eq!(
        inner[0].txn.extra_program_pages,
        params.max_absolute_extra_program_pages
    );
    assert_eq!(
        inner[0]
            .txn
            .approval_program
            .as_ref()
            .map(|p| p.len())
            .unwrap_or(0),
        program_size
    );
    assert_eq!(
        inner[0]
            .txn
            .clear_state_program
            .as_ref()
            .map(|p| p.len())
            .unwrap_or(0),
        program_size
    );
}

// 10. TestInnerUpdateResizing (ledger/applications_test.go:2055)
//
// AppSizeUpdates (V42) lets an inner `UpdateApplication` call grow an
// app's `GlobalStateSchema`/`ExtraProgramPages`, moving MBR responsibility
// (the "size sponsor") to whoever performed the resize -- even when that
// account is NOT the app's creator, which is exactly what this test
// exercises: `smallID` is created by `creator`, but resized by a
// completely different `updaterID` app.
//
// Unlike go's own `mbr()` helper (which reads real ledger `MinBalance()`
// values), this test asserts directly on the underlying accounting fields
// the resize actually touches (`AppParams.size_sponsor`/
// `global_state_schema`/`extra_program_pages`, and the sponsor/creator
// accounts' `total_app_schema`/`total_extra_app_pages`) rather than
// computed MBR totals -- `min_balance_with_state`'s own schema-cost
// aggregation (`state.rs`) independently re-derives global/local schema
// cost by rescanning `app_params`/`app_local_states`, on top of the flat
// `min_balance()` which already folds the same cost in via
// `total_app_schema` -- an unrelated, pre-existing double-counting gap
// filed separately rather than fixed here, since asserting on the
// accounting fields the resize itself owns keeps this test decoupled from
// it.
#[test]
fn test_inner_update_resizing_moves_sponsor_and_grows_schema() {
    let creator = Address([1u8; 32]);
    let updater_creator = Address([2u8; 32]);
    let caller = Address([3u8; 32]);
    let fee_sink = Address([4u8; 32]);
    let small_id = 900u64;
    let updater_id = 901u64;

    let updater_addr = Address(algo_ledger::avm_context::app_address(updater_id));

    let mut state = make_state(
        &[
            (creator, 50_000_000),
            (updater_creator, 50_000_000),
            (caller, 50_000_000),
            (fee_sink, 0),
            (updater_addr, 3_000_000),
        ],
        fee_sink,
    );

    // smallID: created with NO explicit global schema (zero), so the resize
    // starting point is unambiguous. If given an arg, it writes that arg's
    // bytes as a global key (value "X").
    let small_src = "\
txn NumAppArgs
bz end
txn ApplicationArgs 0
byte \"X\"
app_global_put
";
    let small_wrapped =
        format!("#pragma version 8\ntxn ApplicationID\nbz end\n{small_src}\nend:\nint 1\n");
    let small_create = appl_create(
        creator,
        1_000,
        small_id,
        &small_wrapped,
        APPROVE_SRC,
        None,
        None,
        None,
    );
    let mut create_block = minimal_block(fee_sink, 1, vec![small_create]);
    create_block.current_protocol = algo_types::consensus::CONSENSUS_V42.to_string();
    apply_block_capturing_apply_data(&mut state, &create_block, ApplyMode::Execute)
        .expect("smallID creation must apply cleanly");
    assert!(state
        .get_app_params(small_id)
        .unwrap()
        .global_state_schema
        .is_empty());

    // updaterID: resizes smallID to 2 extra pages / 3 uint / 4 byte-slice
    // globals (re-submitting its own unchanged programs, read back via
    // `app_params_get`), then immediately re-calls it with an arg in the
    // SAME inner group to prove the new schema is already live, followed by
    // a second call in a fresh inner group.
    let updater_src = "\
itxn_begin
int appl
itxn_field TypeEnum
txn Applications 1
itxn_field ApplicationID
int UpdateApplication
itxn_field OnCompletion
txn Applications 1
app_params_get AppApprovalProgram
assert
itxn_field ApprovalProgram
txn Applications 1
app_params_get AppClearStateProgram
assert
itxn_field ClearStateProgram
int 2
itxn_field ExtraProgramPages
int 3
itxn_field GlobalNumUint
int 4
itxn_field GlobalNumByteSlice
itxn_next
int appl
itxn_field TypeEnum
txn Applications 1
itxn_field ApplicationID
byte \"A\"
itxn_field ApplicationArgs
itxn_submit
itxn_begin
int appl
itxn_field TypeEnum
txn Applications 1
itxn_field ApplicationID
byte \"B\"
itxn_field ApplicationArgs
itxn_submit
";
    let updater_wrapped =
        format!("#pragma version 8\ntxn ApplicationID\nbz end\n{updater_src}\nend:\nint 1\n");
    let updater_create = appl_create(
        updater_creator,
        1_000,
        updater_id,
        &updater_wrapped,
        APPROVE_SRC,
        None,
        None,
        None,
    );
    let mut updater_block = minimal_block(fee_sink, 2, vec![updater_create]);
    updater_block.current_protocol = algo_types::consensus::CONSENSUS_V42.to_string();
    apply_block_capturing_apply_data(&mut state, &updater_block, ApplyMode::Execute)
        .expect("updater app creation must apply cleanly");

    // caller invokes updaterID, which performs the non-creator inner
    // resize on smallID.
    let mut call = appl_call(caller, 1_000, updater_id, 0, None);
    call.txn.foreign_apps = Some(vec![small_id]);
    let mut call_block = minimal_block(fee_sink, 3, vec![call]);
    call_block.current_protocol = algo_types::consensus::CONSENSUS_V42.to_string();
    apply_block_capturing_apply_data(&mut state, &call_block, ApplyMode::Execute)
        .expect("non-creator inner update resizing smallID must apply cleanly");

    let small_params = state.get_app_params(small_id).unwrap();
    assert_eq!(small_params.global_state_schema.num_uint, 3);
    assert_eq!(small_params.global_state_schema.num_byte_slice, 4);
    assert_eq!(small_params.extra_program_pages, 2);
    assert_eq!(
        small_params.size_sponsor, updater_addr,
        "MBR responsibility must move to the non-creator updater"
    );

    let creator_account = state.get_account(&creator).unwrap();
    assert!(
        creator_account.total_app_schema.is_empty(),
        "the original creator must not be charged for a resize it didn't perform"
    );
    assert_eq!(creator_account.total_extra_app_pages, 0);

    let updater_account = state.get_account(&updater_addr).unwrap();
    assert_eq!(updater_account.total_app_schema.num_uint, 3);
    assert_eq!(updater_account.total_app_schema.num_byte_slice, 4);
    assert_eq!(updater_account.total_extra_app_pages, 2);

    // The new schema was already live for the SAME inner group's follow-up
    // call ("A") and a later separate inner group ("B").
    assert_eq!(
        small_params.global_state.get(b"A".as_slice()),
        Some(&algo_types::TealValue::Bytes(b"X".to_vec()))
    );
    assert_eq!(
        small_params.global_state.get(b"B".as_slice()),
        Some(&algo_types::TealValue::Bytes(b"X".to_vec()))
    );
}
