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

//! Differential test of [`OverlayStore`] against [`SqliteLedger`] (issue
//! #1780).
//!
//! `OverlayStore` (issue #1776) is a second `LedgerStore` implementation
//! (copy-on-write over the committed ledger, journal-based rollback) that the
//! pool and the proposer run the unmodified apply code on. This test drives
//! random sequences of valid and invalid groups (payments with closes, asset
//! create / opt-in / transfer / close, app create / call / delete with boxes
//! and inner transactions) through
//!
//! * `evaluate_group` on a [`PendingOverlay`] (group at a time, failed groups
//!   rolled back by the overlay journal), and
//! * the same apply code directly on a plain [`SqliteLedger`] that never
//!   needs a rollback: for every group the reference ledger is rebuilt from
//!   the genesis setup plus the groups the overlay accepted so far, so a
//!   rejected group simply is not replayed,
//!
//! and asserts identical accept/reject verdicts, identical per-transaction
//! `ApplyData`, identical transaction counter, and identical final
//! account / resource / box state.

use std::collections::BTreeSet;

use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;

use algo_types::{
    AccountData, Address, AssetParams, Block, BoxRef, Round, SignedTransaction, Transaction,
    CONSENSUS_V41,
};

use crate::apply::{apply_block_impl_probe, ApplyData, ApplyMode, ExecProbe, ProbeRequest};
use crate::pending_overlay::{OverlayStore, PendingOverlay};
use crate::proposal_eval::evaluate_group;
use crate::sqlite::SqliteLedger;
use crate::store_trait::LedgerStore;

const ACTORS: u8 = 5;
const MAX_ID: u64 = 80;

fn addr(b: u8) -> Address {
    Address([b; 32])
}

fn app_addr(id: u64) -> Address {
    Address(crate::avm_context::app_address(id))
}

fn setup() -> SqliteLedger {
    let mut l = SqliteLedger::open_in_memory().unwrap();
    l.set_fee_sink(addr(0xF1));
    l.set_rewards_pool(addr(0xF2));
    // Issue #2116: the block-start withdrawal needs a pool at MinBalance.
    crate::apply::pool_fixtures::fund_test_rewards_pool(&mut l);
    l.set_protocol(CONSENSUS_V41.to_string());
    l.set_account(
        &addr(0xF1),
        AccountData {
            micro_algos: 10_000_000,
            ..Default::default()
        },
    );
    for i in 1..=ACTORS {
        l.set_account(
            &addr(i),
            AccountData {
                micro_algos: 20_000_000,
                ..Default::default()
            },
        );
    }
    l
}

fn template(l: &SqliteLedger) -> Block {
    Block {
        round: Round(l.current_round().0 + 1),
        current_protocol: CONSENSUS_V41.to_string(),
        fee_sink: addr(0xF1),
        rewards_pool: addr(0xF2),
        // V41 requires a genesis hash; the payset's stripped transactions
        // take this one back, so the proposal check's `Alive` (issue #2127)
        // passes for them.
        genesis_hash: [0x6E; 32],
        ..Block::default()
    }
}

/// Apply `group` straight on `l` (no overlay), the way `evaluate_group` does
/// through the overlay. On error the ledger may be partially modified: the
/// caller discards it.
fn apply_direct(
    l: &mut SqliteLedger,
    group: &[SignedTransaction],
) -> Result<(Vec<ApplyData>, u64), algo_error::AlgoError> {
    let mut block = template(l);
    block.payset = group.to_vec();
    let mut ad = Vec::new();
    let mut probe = ExecProbe {
        request: ProbeRequest {
            skip_epilogue: true,
            generate: true,
            ..ProbeRequest::default()
        },
        ..ExecProbe::default()
    };
    apply_block_impl_probe(
        l,
        &block,
        ApplyMode::Execute,
        false,
        None,
        None,
        Some(&mut ad),
        None,
        true,
        Some(&mut probe),
    )?;
    l.set_txn_counter(probe.out.final_txn_counter);
    Ok((ad, probe.out.final_txn_counter))
}

fn approval_program() -> Vec<u8> {
    algo_avm::assembler::assemble_string(
        "#pragma version 8
txn ApplicationID
bz approve
txn OnCompletion
int DeleteApplication
==
bnz approve
txna ApplicationArgs 0
byte \"box\"
==
bz not_box
byte \"k1\"
byte \"hello\"
box_put
b approve
not_box:
txna ApplicationArgs 0
byte \"pay\"
==
bz not_pay
itxn_begin
int pay
itxn_field TypeEnum
txn Sender
itxn_field Receiver
int 1000
itxn_field Amount
itxn_submit
b approve
not_pay:
txna ApplicationArgs 0
byte \"bdel\"
==
bz fail
byte \"k1\"
box_del
pop
b approve
fail:
int 0
return
approve:
int 1
return
",
    )
    .expect("approval assembles")
    .program
}

fn clear_program() -> Vec<u8> {
    algo_avm::assembler::assemble_string("#pragma version 8\nint 1\nreturn\n")
        .expect("clear assembles")
        .program
}

fn base_txn(sender: Address, ty: &str) -> Transaction {
    Transaction {
        txn_type: ty.into(),
        sender,
        fee: 1_000,
        first_valid: Round(1),
        last_valid: Round(1000),
        ..Default::default()
    }
}

/// Generator state: the ids the accepted groups have created so far.
#[derive(Default)]
struct Known {
    assets: Vec<u64>,
    apps: Vec<u64>,
}

fn pick_actor(rng: &mut ChaCha8Rng) -> Address {
    addr(rng.random_range(1..=ACTORS))
}

fn pick_id(rng: &mut ChaCha8Rng, ids: &[u64]) -> u64 {
    // Mostly known ids, sometimes a bogus one (a rejection path).
    if ids.is_empty() || rng.random_range(0..8) == 0 {
        rng.random_range(1..MAX_ID)
    } else {
        ids[rng.random_range(0..ids.len())]
    }
}

fn random_txn(rng: &mut ChaCha8Rng, known: &Known) -> Transaction {
    let sender = pick_actor(rng);
    match rng.random_range(0..11) {
        0 | 1 => {
            let mut t = base_txn(sender, "pay");
            t.receiver = if rng.random_range(0..4) == 0 {
                // A brand new account: the minimum-balance path.
                addr(100 + rng.random_range(0..4))
            } else {
                pick_actor(rng)
            };
            t.amount = match rng.random_range(0..4) {
                0 => 0,
                1 => 50_000, // below min balance for a new account
                2 => rng.random_range(1..5_000_000),
                _ => 1_000_000_000, // overspend
            };
            if rng.random_range(0..6) == 0 {
                t.close_remainder_to = pick_actor(rng);
            }
            t
        }
        2 => {
            let mut t = base_txn(sender, "acfg");
            t.asset_params = Some(AssetParams {
                total: rng.random_range(1..1_000_000),
                decimals: rng.random_range(0..4),
                default_frozen: rng.random_range(0..5) == 0,
                manager: Some(sender),
                clawback: Some(sender),
                ..Default::default()
            });
            t
        }
        3 | 4 => {
            // Opt in (self transfer of 0) or transfer.
            let mut t = base_txn(sender, "axfer");
            t.xaid = pick_id(rng, &known.assets);
            let to = if rng.random_range(0..2) == 0 {
                sender
            } else {
                pick_actor(rng)
            };
            t.asset_receiver = Some(to);
            t.asset_amount = if to == sender {
                0
            } else {
                rng.random_range(0..2_000)
            };
            t
        }
        5 => {
            // Close the holding out to another actor.
            let mut t = base_txn(sender, "axfer");
            t.xaid = pick_id(rng, &known.assets);
            t.asset_receiver = Some(pick_actor(rng));
            t.asset_close_to = Some(pick_actor(rng));
            t
        }
        6 => {
            let mut t = base_txn(sender, "appl");
            t.approval_program = Some(serde_bytes::ByteBuf::from(approval_program()));
            t.clear_state_program = Some(serde_bytes::ByteBuf::from(clear_program()));
            t
        }
        7..=9 => {
            let app = pick_id(rng, &known.apps);
            let mut t = base_txn(sender, "appl");
            t.application_id = app;
            let arg: &[u8] = match rng.random_range(0..4) {
                0 => b"box",
                1 => b"pay",
                2 => b"bdel",
                _ => b"nope",
            };
            t.app_arguments = Some(vec![Some(serde_bytes::ByteBuf::from(arg.to_vec()))]);
            t.boxes = Some(vec![BoxRef {
                index: 0,
                name: Some(serde_bytes::ByteBuf::from(b"k1".to_vec())),
            }]);
            if rng.random_range(0..3) == 0 {
                t.fee = 3_000; // cover inner fees by pooling
            }
            t
        }
        _ => {
            let mut t = base_txn(sender, "appl");
            t.application_id = pick_id(rng, &known.apps);
            t.on_completion = 5; // DeleteApplication
            t
        }
    }
}

fn random_group(rng: &mut ChaCha8Rng, known: &Known) -> Vec<SignedTransaction> {
    // Funding the app accounts keeps box / inner-pay calls from always
    // failing on minimum balance.
    let mut txns: Vec<Transaction> = Vec::new();
    if !known.apps.is_empty() && rng.random_range(0..3) == 0 {
        let mut t = base_txn(pick_actor(rng), "pay");
        t.receiver = app_addr(known.apps[rng.random_range(0..known.apps.len())]);
        t.amount = rng.random_range(100_000..1_000_000);
        txns.push(t);
    }
    let extra = match rng.random_range(0..4) {
        0 => 3,
        1 | 2 => 2,
        _ => 1,
    };
    for _ in 0..extra {
        txns.push(random_txn(rng, known));
    }
    if txns.len() > 1 {
        let gid = algo_codec::compute_group_id(&txns);
        for t in &mut txns {
            t.group = gid.0;
        }
    }
    txns.into_iter()
        .map(|txn| SignedTransaction {
            txn,
            ..Default::default()
        })
        .collect()
}

/// A canonical dump of everything observable through `LedgerStore` for the
/// accounts and ids the test can touch.
fn dump<S: LedgerStore>(s: &S) -> Vec<String> {
    let mut accounts: BTreeSet<Address> = BTreeSet::new();
    for i in 1..=ACTORS {
        accounts.insert(addr(i));
    }
    for i in 0..4 {
        accounts.insert(addr(100 + i));
    }
    accounts.insert(addr(0xF1));
    accounts.insert(addr(0xF2));
    for id in 1..=MAX_ID {
        accounts.insert(app_addr(id));
        if let Some(r) = s.get_asset_params(id) {
            accounts.insert(r.creator);
        }
        if let Some(p) = s.get_app_params(id) {
            accounts.insert(p.creator);
        }
    }
    let mut out = Vec::new();
    for a in &accounts {
        out.push(format!("acct {:?} = {:?}", a.0[0], s.get_account(a)));
        out.push(format!("hold {:?} = {:?}", a.0[0], {
            let mut v = s.asset_holdings_for_addr(a);
            v.sort_by_key(|(id, _)| *id);
            v
        }));
        out.push(format!("local {:?} = {:?}", a.0[0], {
            let mut v = s.app_local_states_for_addr(a);
            v.sort_by_key(|(id, _)| *id);
            v
        }));
        out.push(format!("cassets {:?} = {:?}", a.0[0], {
            let mut v = s.created_assets_for_addr(a);
            v.sort_by_key(|(id, _)| *id);
            v
        }));
        out.push(format!("capps {:?} = {:?}", a.0[0], {
            let mut v = s.created_apps_for_addr(a);
            v.sort_by_key(|(id, _)| *id);
            v
        }));
    }
    for id in 1..=MAX_ID {
        out.push(format!("asset {id} = {:?}", s.get_asset_params(id)));
        out.push(format!("app {id} = {:?}", s.get_app_params(id)));
        let mut keys = s.box_keys_for_app(id);
        keys.sort();
        let boxes: Vec<_> = keys.iter().map(|k| (k.clone(), s.get_box(id, k))).collect();
        out.push(format!("boxes {id} = {boxes:?}"));
    }
    out.push(format!("txn_counter = {}", s.txn_counter()));
    out
}

fn first_diff(a: &[String], b: &[String]) -> String {
    for (x, y) in a.iter().zip(b) {
        if x != y {
            return format!("overlay: {x}\nreference: {y}");
        }
    }
    format!("length differs: {} vs {}", a.len(), b.len())
}

fn run_sequence(seed: u64, groups: usize) -> (usize, usize, usize, usize, usize) {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let base = setup();
    let t = template(&base);
    let mut overlay = PendingOverlay::new(&base);
    let mut accepted: Vec<Vec<SignedTransaction>> = Vec::new();
    let mut known = Known::default();
    let (mut n_ok, mut n_rej, mut n_boxes) = (0, 0, 0);

    for step in 0..groups {
        let group = random_group(&mut rng, &known);

        // Reference: genesis setup + every accepted group, then this one.
        let mut reference = setup();
        for g in &accepted {
            apply_direct(&mut reference, g).expect("accepted group replays on the reference");
        }
        let direct = apply_direct(&mut reference, &group);

        let via_overlay = evaluate_group(&base, &mut overlay, &t, &group);

        match (via_overlay, direct) {
            (Ok(ov), Ok((ad, counter))) => {
                n_ok += 1;
                assert_eq!(
                    ov.apply_data, ad,
                    "seed {seed} step {step}: ApplyData differs for {group:?}"
                );
                assert_eq!(ov.final_txn_counter, counter, "seed {seed} step {step}");
                for d in &ad {
                    if d.config_asset != 0 {
                        known.assets.push(d.config_asset);
                    }
                    if d.application_id != 0 {
                        known.apps.push(d.application_id);
                    }
                }
                accepted.push(group);
            }
            (Err(_), Err(_)) => n_rej += 1,
            (Ok(_), Err(e)) => {
                panic!(
                    "seed {seed} step {step}: overlay accepted, direct rejected ({e}): {group:?}"
                )
            }
            (Err(e), Ok(_)) => {
                panic!(
                    "seed {seed} step {step}: overlay rejected ({e:?}), direct accepted: {group:?}"
                )
            }
        }

        // Final-state identity after every group (a rejected group must have
        // been rolled back completely).
        let mut replay = setup();
        for g in &accepted {
            apply_direct(&mut replay, g).expect("replay");
        }
        let store = OverlayStore::new(&base, &mut overlay);
        n_boxes += (1..=MAX_ID)
            .filter(|id| !store.box_keys_for_app(*id).is_empty())
            .count();
        let (a, b) = (dump(&store), dump(&replay));
        assert!(
            a == b,
            "seed {seed} step {step}: state differs\n{}",
            first_diff(&a, &b)
        );
    }
    (
        n_ok,
        n_rej,
        known.assets.len() + known.apps.len(),
        known.apps.len(),
        n_boxes,
    )
}

#[test]
fn overlay_matches_sqlite_ledger_on_random_group_sequences() {
    let (mut ok, mut rej, mut created, mut apps, mut boxes) = (0, 0, 0, 0, 0);
    for seed in 0..12u64 {
        let (o, r, c, a, b) = run_sequence(seed, 25);
        ok += o;
        rej += r;
        created += c;
        apps += a;
        boxes += b;
    }
    assert!(created > apps, "no asset was ever created");
    assert!(apps > 0, "no app was ever created");
    assert!(boxes > 0, "no box was ever written");
    // The generator must exercise both verdicts, or the comparison is vacuous.
    assert!(ok >= 40, "too few accepted groups: {ok}");
    assert!(rej >= 40, "too few rejected groups: {rej}");
}

// ---- issue #1781: the whole-payset evaluation on a per-read-locked overlay ----

/// [`setup`] plus an online account with an expired voting key (actor 3) and a
/// second, untouched one (0x40), so the expired / absent lists are not empty.
fn setup_with_online() -> SqliteLedger {
    let mut l = setup();
    for a in [addr(3), addr(0x40)] {
        let mut acct = l.get_account(&a).unwrap_or(AccountData {
            micro_algos: 20_000_000,
            ..Default::default()
        });
        acct.status = algo_types::AccountStatus::Online;
        acct.vote_id = Some([7u8; 32]);
        acct.vote_last_valid = 0;
        l.set_account(&a, acct);
    }
    l
}

/// Run `payset` through the legacy locked scratch apply and through the
/// overlay evaluation over a `LockedBase`, and require identical results.
fn assert_payset_passes_agree(seed: u64, payset: Vec<SignedTransaction>) -> bool {
    use crate::apply::{knock_offline_lists_from_modified, ListsRequest};
    use crate::locked_base::LockedBase;
    use crate::proposal_eval::evaluate_payset;
    use crate::shadow_execute::scratch_execute_payset;

    let own = std::sync::Arc::new(std::collections::HashSet::new());
    let request = || {
        Some(ListsRequest {
            own_addresses: own.clone(),
        })
    };

    let mut reference = setup_with_online();
    let mut block = template(&reference);
    block.payset = payset;
    let old = scratch_execute_payset(&mut reference, &block, request());

    let shared = std::sync::Mutex::new(setup_with_online());
    let base = LockedBase::new(&shared, Round(0));
    let new = evaluate_payset(&base, &block, request());
    assert!(!base.is_stale(), "seed {seed}: nothing advanced the ledger");
    assert!(
        base.stats().acquisitions > 0,
        "seed {seed}: reads went through the mutex"
    );

    match (old, new) {
        (Ok(o), Ok(n)) => {
            assert_eq!(o.apply_data, n.apply_data, "seed {seed}: ApplyData");
            assert_eq!(
                o.final_txn_counter, n.final_txn_counter,
                "seed {seed}: txn counter"
            );
            assert_eq!(
                o.final_state_proof_next, n.final_state_proof_next,
                "seed {seed}: state proof next round"
            );
            assert_eq!(
                o.final_fee_sink_available, n.final_fee_sink_available,
                "seed {seed}: fee sink available"
            );
            // The lists computed from each pass's modified accounts agree.
            let consensus =
                algo_types::consensus::consensus_params_for_version(CONSENSUS_V41).unwrap();
            let committed = setup_with_online();
            let lists = |m: Option<crate::apply::KnockOfflineModified>| {
                knock_offline_lists_from_modified(
                    &committed,
                    block.round.0,
                    &consensus,
                    &own,
                    &m.expect("modified accounts captured"),
                )
            };
            // The legacy pass reports a superset (every write since the last
            // commit); every account the overlay pass reports must agree with it.
            let (om, nm) = (
                o.knock_offline_modified.clone().unwrap(),
                n.knock_offline_modified.clone().unwrap(),
            );
            for (a, v) in &nm.accounts {
                assert_eq!(om.accounts.get(a), Some(v), "seed {seed}: modified {a:?}");
            }
            let (ol, nl) = (
                lists(o.knock_offline_modified),
                lists(n.knock_offline_modified),
            );
            assert_eq!(ol, nl, "seed {seed}: expired / absent lists");
            !nl.expired.is_empty()
        }
        (Err(o), Err(n)) => {
            use crate::shadow_execute::ScratchFailure as F;
            match (o, n) {
                (F::Txn { index: i, .. }, F::Txn { index: j, .. }) => {
                    assert_eq!(i, j, "seed {seed}: failing transaction");
                    false
                }
                (o, n) => panic!("seed {seed}: failure kinds differ: {o:?} vs {n:?}"),
            }
        }
        (o, n) => panic!("seed {seed}: verdicts differ: legacy {o:?} vs overlay {n:?}"),
    }
}

#[test]
fn overlay_payset_pass_matches_the_locked_scratch_apply() {
    let (mut checked, mut total, mut listed) = (0usize, 0usize, false);
    for seed in 0..24u64 {
        let mut rng = ChaCha8Rng::seed_from_u64(1_000 + seed);
        let base = setup_with_online();
        let t = template(&base);
        let mut overlay = PendingOverlay::new(&base);
        let mut known = Known::default();
        let mut payset: Vec<SignedTransaction> = Vec::new();
        for _ in 0..45 {
            let group = random_group(&mut rng, &known);
            if let Ok(ev) = evaluate_group(&base, &mut overlay, &t, &group) {
                for d in &ev.apply_data {
                    if d.config_asset != 0 {
                        known.assets.push(d.config_asset);
                    }
                    if d.application_id != 0 {
                        known.apps.push(d.application_id);
                    }
                }
                payset.extend(group);
            }
        }
        // Every few seeds a group the evaluator never admitted is smuggled
        // in: both passes must blame the same transaction.
        if seed % 4 == 3 {
            let mut bad = base_txn(addr(1), "pay");
            bad.receiver = addr(2);
            bad.amount = 1_000_000_000_000;
            payset.push(SignedTransaction {
                txn: bad,
                ..Default::default()
            });
        }
        total += payset.len();
        checked += 1;
        listed |= assert_payset_passes_agree(seed, payset);
    }
    assert_eq!(checked, 24);
    assert!(listed, "no seed produced an expired-account list");
    assert!(
        total > 300,
        "the generator produced too few transactions: {total}"
    );
}

/// Issue #1895: `evaluate_proposal_check` (overlay over a `LockedBase`, no
/// mutex held across the evaluation) returns exactly the verdict of the
/// locked `scratch_proposal_check` over random paysets with valid, wrong
/// and missing payout / fee / proposer header fields.
#[test]
fn overlay_payout_validation_matches_the_locked_scratch_validation() {
    use crate::locked_base::LockedBase;
    use crate::proposal_eval::evaluate_proposal_check;
    use crate::shadow_execute::{scratch_proposal_check, ProposalCheck};

    let (mut valid, mut violation, mut other, mut compared) = (0usize, 0usize, 0usize, 0usize);
    for seed in 0..24u64 {
        let mut rng = ChaCha8Rng::seed_from_u64(7_000 + seed);
        let base = setup_with_online();
        let t = template(&base);
        let mut overlay = PendingOverlay::new(&base);
        let mut known = Known::default();
        let mut payset: Vec<SignedTransaction> = Vec::new();
        for _ in 0..30 {
            let group = random_group(&mut rng, &known);
            if let Ok(ev) = evaluate_group(&base, &mut overlay, &t, &group) {
                for d in &ev.apply_data {
                    if d.config_asset != 0 {
                        known.assets.push(d.config_asset);
                    }
                    if d.application_id != 0 {
                        known.apps.push(d.application_id);
                    }
                }
                payset.extend(group);
            }
        }
        if seed % 6 == 5 {
            // A payset transaction no Execute pass can apply: no verdict.
            let mut bad = base_txn(addr(1), "pay");
            bad.receiver = addr(2);
            bad.amount = 1_000_000_000_000;
            payset.push(SignedTransaction {
                txn: bad,
                ..Default::default()
            });
        }
        let true_fees = crate::block_header::payset_fees_collected(&payset, &addr(0xF1));
        for variant in 0..8u64 {
            let mut block = template(&base);
            block.payset = payset.clone();
            block.fees_collected = match variant % 4 {
                3 => true_fees + 1,
                _ => true_fees,
            };
            block.proposer = match variant % 5 {
                0 => addr(3),
                1 => Address::ZERO,
                2 => addr(0x77),
                _ => addr(0x40),
            };
            block.proposer_payout = match variant {
                0 | 1 => 0,
                2 => 1,
                3 => 1_000,
                4 => 10_000_000,
                5 => u64::MAX,
                _ => rng.random_range(0..2_000_000u64),
            };
            let mut reference = setup_with_online();
            let locked = scratch_proposal_check(&mut reference, &block);

            let shared = std::sync::Mutex::new(setup_with_online());
            let lbase = LockedBase::new(&shared, Round(0));
            let overlay_check = evaluate_proposal_check(&lbase, &block);
            assert!(!lbase.is_stale());
            assert_eq!(
                locked, overlay_check,
                "seed {seed} variant {variant}: verdicts differ"
            );
            compared += 1;
            match locked {
                ProposalCheck::Valid => valid += 1,
                ProposalCheck::Violation { .. } => violation += 1,
                ProposalCheck::NoVerdict { .. } => other += 1,
            }
        }
    }
    assert!(compared > 150);
    assert!(valid > 0, "no valid verdict exercised");
    assert!(violation > 0, "no violation exercised");
    assert!(other > 0, "no no-verdict exercised");
}

/// Issue #1895: a commit landing in the middle of the overlay payout
/// validation yields a transient no-verdict (never a verdict computed across
/// two states), the same classification the locked path gives a busy or
/// advanced ledger.
#[test]
fn overlay_payout_validation_is_a_transient_no_verdict_when_the_ledger_advances() {
    use crate::locked_base::LockedBase;
    use crate::proposal_eval::evaluate_proposal_check;
    use crate::shadow_execute::ProposalCheck;
    use std::sync::{Arc, Mutex};

    let shared = Arc::new(Mutex::new(setup_with_online()));
    let mut block = template(&shared.lock().unwrap());
    block.proposer = addr(3);
    block.payset = (0..50u64)
        .map(|i| {
            let mut p = base_txn(addr(1), "pay");
            p.receiver = addr(2);
            p.amount = 100_000 + i;
            p.note = serde_bytes::ByteBuf::from(i.to_be_bytes().to_vec());
            SignedTransaction {
                txn: p,
                ..Default::default()
            }
        })
        .collect();
    block.fees_collected = crate::block_header::payset_fees_collected(&block.payset, &addr(0xF1));
    let lbase = LockedBase::new(&shared, Round(0));
    let m = shared.clone();
    lbase.before_acquisition(10, move || {
        m.lock().unwrap().set_current_round(Round(1));
    });
    match evaluate_proposal_check(&lbase, &block) {
        ProposalCheck::NoVerdict { transient, .. } => assert!(transient),
        other => panic!("expected a transient no-verdict, got {other:?}"),
    }
    assert!(lbase.is_stale());
    // And a base already at another round is the same transient no-verdict.
    let ahead = Mutex::new(setup_with_online());
    ahead.lock().unwrap().set_current_round(Round(5));
    let stale = LockedBase::new(&ahead, Round(0));
    assert!(matches!(
        evaluate_proposal_check(&stale, &block),
        ProposalCheck::NoVerdict {
            transient: true,
            ..
        }
    ));
}
