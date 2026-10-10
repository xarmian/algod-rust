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

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use algo_types::{
    AccountData, Address, AssetParams, Block, BoxRef, Round, SignedTransaction, Transaction,
    CONSENSUS_V41,
};

use crate::apply::{apply_block_impl_probe, ApplyData, ApplyMode, ExecProbe};
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
    let mut l = SqliteLedger::open_in_memory().expect("ledger");
    l.set_fee_sink(addr(0xF1));
    l.set_rewards_pool(addr(0xF2));
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
        skip_epilogue: true,
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
    l.set_txn_counter(probe.final_txn_counter);
    Ok((ad, probe.final_txn_counter))
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
    addr(rng.gen_range(1..=ACTORS))
}

fn pick_id(rng: &mut ChaCha8Rng, ids: &[u64]) -> u64 {
    // Mostly known ids, sometimes a bogus one (a rejection path).
    if ids.is_empty() || rng.gen_range(0..8) == 0 {
        rng.gen_range(1..MAX_ID)
    } else {
        ids[rng.gen_range(0..ids.len())]
    }
}

fn random_txn(rng: &mut ChaCha8Rng, known: &Known) -> Transaction {
    let sender = pick_actor(rng);
    match rng.gen_range(0..11) {
        0 | 1 => {
            let mut t = base_txn(sender, "pay");
            t.receiver = if rng.gen_range(0..4) == 0 {
                // A brand new account: the minimum-balance path.
                addr(100 + rng.gen_range(0..4))
            } else {
                pick_actor(rng)
            };
            t.amount = match rng.gen_range(0..4) {
                0 => 0,
                1 => 50_000, // below min balance for a new account
                2 => rng.gen_range(1..5_000_000),
                _ => 1_000_000_000, // overspend
            };
            if rng.gen_range(0..6) == 0 {
                t.close_remainder_to = pick_actor(rng);
            }
            t
        }
        2 => {
            let mut t = base_txn(sender, "acfg");
            t.asset_params = Some(AssetParams {
                total: rng.gen_range(1..1_000_000),
                decimals: rng.gen_range(0..4),
                default_frozen: rng.gen_range(0..5) == 0,
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
            let to = if rng.gen_range(0..2) == 0 {
                sender
            } else {
                pick_actor(rng)
            };
            t.asset_receiver = Some(to);
            t.asset_amount = if to == sender {
                0
            } else {
                rng.gen_range(0..2_000)
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
            let arg: &[u8] = match rng.gen_range(0..4) {
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
            if rng.gen_range(0..3) == 0 {
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
    if !known.apps.is_empty() && rng.gen_range(0..3) == 0 {
        let mut t = base_txn(pick_actor(rng), "pay");
        t.receiver = app_addr(known.apps[rng.gen_range(0..known.apps.len())]);
        t.amount = rng.gen_range(100_000..1_000_000);
        txns.push(t);
    }
    let extra = match rng.gen_range(0..4) {
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
