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

//! Account/asset/app-index "offending foreign reference" edge cases (issue
//! #950, theme 1).
//!
//! Ports go-algorand's `test/e2e-go/features/transactions/accountv2_test.go`
//! `accountInformationCheckWithOffendingFields`-driven tests:
//! `TestAccountInformationWithBadAssetIdx`,
//! `TestAccountInformationWithMissingAssetIdx`,
//! `TestAccountInformationWithBadAppIdx`,
//! `TestAccountInformationWithMissingApp`, and
//! `TestAccountInformationWithMissingAddress`.
//!
//! Despite the "AccountInformation" name, none of these exercise the
//! `/v2/accounts/{address}` REST lookup endpoint at all -- they build an
//! app opt-in call transaction whose `ForeignAssets`/`ForeignApps`/
//! `Accounts` array carries one extra entry that does not resolve to any
//! real asset/app/account, then assert the call still succeeds as long as
//! the AVM program never actually touches that unresolved slot. This
//! mirrors go-algorand's `checkAppCallForOptionalUses`-style resolution:
//! `ForeignAssets`/`ForeignApps`/`Accounts` merely make an ID *available*
//! for `Assets`/`Apps`/`Accounts` referencing opcodes to resolve against;
//! an unused slot -- even one pointing at an asset/app ID or address that
//! was never created -- is never itself validated for existence.
//!
//! `algo-validate::rules` only enforces the *array-length* limits on these
//! fields (`test_appl_max_app_txn_foreign_apps_exceeded_rejected` /
//! `..._foreign_assets_exceeded_rejected`); it never checks that individual
//! entries resolve to something real, so the apply layer is the right place
//! to pin this "harmless when unused" behavior end-to-end.

use algo_ledger::{apply_transaction_with_budget, ApplyContext, ApplyMode, LedgerState};
use algo_types::{Address, SignedTransaction};

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

/// Trivial always-approve v8 program: `int 1`. The app never touches any
/// of its `Accounts`/`Assets`/`Apps` array slots, so an unresolvable extra
/// entry in `ForeignAssets`/`ForeignApps`/`Accounts` must be harmless.
const APPROVE_SRC: &str = "#pragma version 8\nint 1\n";

const ON_COMPLETION_OPT_IN: u64 = 1;

/// Build an appl-create SignedTransaction with an explicit deterministic
/// `app_id` (mirrors `app_call_lifecycle_test.rs`'s `appl_create`).
fn appl_create(sender: Address, fee: u64, app_id: u64) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "appl".into();
    stx.txn.sender = sender;
    stx.txn.fee = fee;
    stx.txn.application_id = 0;
    stx.txn.on_completion = 0; // NoOp
    stx.txn.approval_program = Some(serde_bytes::ByteBuf::from(assemble(APPROVE_SRC)));
    stx.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(assemble(APPROVE_SRC)));
    stx.apply_data_application_id = app_id;
    stx
}

/// Build an appl opt-in call against an existing app, with the given
/// offending `ForeignAssets`/`ForeignApps`/`Accounts` fields attached.
fn appl_opt_in(
    sender: Address,
    fee: u64,
    app_id: u64,
    foreign_assets: Option<Vec<u64>>,
    foreign_apps: Option<Vec<u64>>,
    accounts: Option<Vec<Address>>,
) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "appl".into();
    stx.txn.sender = sender;
    stx.txn.fee = fee;
    stx.txn.application_id = app_id;
    stx.txn.on_completion = ON_COMPLETION_OPT_IN;
    stx.txn.foreign_assets = foreign_assets;
    stx.txn.foreign_apps = foreign_apps;
    stx.txn.accounts = accounts;
    stx
}

/// Shared setup: fund a creator and a caller, create a trivial always-pass
/// app owned by the creator. Returns `(state, ctx, caller, app_id)`.
fn setup(app_id: u64) -> (LedgerState, ApplyContext, Address, Address) {
    let creator = Address([1u8; 32]);
    let caller = Address([2u8; 32]);
    let fee_sink = Address([3u8; 32]);

    let mut state = make_state(
        &[(creator, 50_000_000), (caller, 50_000_000), (fee_sink, 0)],
        fee_sink,
    );
    let ctx = execute_ctx(fee_sink, 1);

    let create = appl_create(creator, 1_000, app_id);
    apply_transaction_with_budget(&mut state, &create, &ctx, 0, None, None, None, None)
        .expect("app creation must succeed");

    (state, ctx, caller, creator)
}

// ---------------------------------------------------------------------------
// 1. TestAccountInformationWithBadAssetIdx
//    (accountv2_test.go:342) -- a foreign-asset entry far larger than any
//    real asset ID that could ever be allocated must not block the call.
// ---------------------------------------------------------------------------

#[test]
fn test_account_information_with_bad_asset_idx() {
    let app_id = 900u64;
    let (mut state, ctx, caller, _creator) = setup(app_id);

    let opt_in = appl_opt_in(
        caller,
        1_000,
        app_id,
        Some(vec![12_181_853_637_140_359_511u64]),
        None,
        None,
    );
    apply_transaction_with_budget(&mut state, &opt_in, &ctx, 0, None, None, None, None)
        .expect("opt-in with an unresolvable, oversized ForeignAssets entry must still succeed");

    assert!(state.get_app_local_state(&caller, app_id).is_some());
}

// ---------------------------------------------------------------------------
// 2. TestAccountInformationWithMissingAssetIdx (accountv2_test.go:351) -- a
//    plausible-looking but never-created asset ID must not block the call.
// ---------------------------------------------------------------------------

#[test]
fn test_account_information_with_missing_asset_idx() {
    let app_id = 901u64;
    let (mut state, ctx, caller, _creator) = setup(app_id);

    let opt_in = appl_opt_in(caller, 1_000, app_id, Some(vec![121_818u64]), None, None);
    apply_transaction_with_budget(&mut state, &opt_in, &ctx, 0, None, None, None, None)
        .expect("opt-in with a nonexistent ForeignAssets entry must still succeed");

    assert!(state.get_app_local_state(&caller, app_id).is_some());
}

// ---------------------------------------------------------------------------
// 3. TestAccountInformationWithBadAppIdx (accountv2_test.go:359)
// ---------------------------------------------------------------------------

#[test]
fn test_account_information_with_bad_app_idx() {
    let app_id = 902u64;
    let (mut state, ctx, caller, _creator) = setup(app_id);

    let opt_in = appl_opt_in(
        caller,
        1_000,
        app_id,
        None,
        Some(vec![12_181_853_637_140_359_511u64]),
        None,
    );
    apply_transaction_with_budget(&mut state, &opt_in, &ctx, 0, None, None, None, None)
        .expect("opt-in with an unresolvable, oversized ForeignApps entry must still succeed");

    assert!(state.get_app_local_state(&caller, app_id).is_some());
}

// ---------------------------------------------------------------------------
// 4. TestAccountInformationWithMissingApp (accountv2_test.go:367)
// ---------------------------------------------------------------------------

#[test]
fn test_account_information_with_missing_app() {
    let app_id = 903u64;
    let (mut state, ctx, caller, _creator) = setup(app_id);

    let opt_in = appl_opt_in(caller, 1_000, app_id, None, Some(vec![121_818u64]), None);
    apply_transaction_with_budget(&mut state, &opt_in, &ctx, 0, None, None, None, None)
        .expect("opt-in with a nonexistent ForeignApps entry must still succeed");

    assert!(state.get_app_local_state(&caller, app_id).is_some());
}

// ---------------------------------------------------------------------------
// 5. TestAccountInformationWithMissingAddress (accountv2_test.go:375) -- a
//    random, never-funded address in `Accounts` must not block the call.
// ---------------------------------------------------------------------------

#[test]
fn test_account_information_with_missing_address() {
    let app_id = 904u64;
    let (mut state, ctx, caller, _creator) = setup(app_id);

    let rand_addr = Address([0xABu8; 32]);
    let opt_in = appl_opt_in(caller, 1_000, app_id, None, None, Some(vec![rand_addr]));
    apply_transaction_with_budget(&mut state, &opt_in, &ctx, 0, None, None, None, None)
        .expect("opt-in with a never-funded Accounts entry must still succeed");

    assert!(state.get_app_local_state(&caller, app_id).is_some());
}
