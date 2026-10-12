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

//! Differential test of the block-scoped `SqliteLedger` read memo (issue
//! #1757): two ledgers, one with the memo and one without, receive the same
//! random sequence of writes, snapshots, snapshot restores, block commits and
//! block rollbacks. After every operation every key of a small universe must
//! read identically from both, and after every commit the account totals and
//! the Merkle trie root must be identical.

use std::collections::BTreeMap;

use algo_ledger::{LedgerStore, SqliteLedger};
use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParams, AssetParamsRecord,
    StateSchema, TealValue,
};

const ADDRS: u8 = 6;
const ASSETS: u64 = 4;
const APPS: u64 = 4;
const APP0: u64 = 50;
const BOXES: u8 = 4;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn addr(i: u8) -> Address {
    Address([i + 1; 32])
}

fn box_key(i: u8) -> Vec<u8> {
    if i == 0 {
        Vec::new() // the empty key
    } else {
        vec![b'k', i]
    }
}

fn teal(rng: &mut Rng) -> BTreeMap<Vec<u8>, TealValue> {
    let mut m = BTreeMap::new();
    for k in 0..rng.below(3) {
        m.insert(vec![b'g', k as u8], TealValue::Uint(rng.below(1000)));
    }
    m
}

#[derive(Clone, Debug)]
enum Op {
    SetAccount(u8, u64),
    RemoveAccount(u8),
    SetHolding(u8, u64, u64),
    RemoveHolding(u8, u64),
    SetAssetParams(u64, u8, u64),
    RemoveAssetParams(u64),
    SetAppParams(u64, u8, u64),
    RemoveAppParams(u64),
    SetLocal(u8, u64, u64),
    RemoveLocal(u8, u64),
    RemoveAllHoldings(u64),
    RemoveAllLocals(u64),
    SetBox(u64, u8, u64),
    DeleteBox(u64, u8),
    Snapshot,
    Restore,
    Commit,
    Rollback,
    Begin,
}

fn random_op(rng: &mut Rng) -> Op {
    let a = rng.below(ADDRS as u64) as u8;
    let asset = 1 + rng.below(ASSETS);
    let app = APP0 + rng.below(APPS);
    let v = rng.below(5000);
    let b = rng.below(BOXES as u64) as u8;
    match rng.below(100) {
        0..=13 => Op::SetAccount(a, v),
        14..=15 => Op::RemoveAccount(a),
        16..=23 => Op::SetHolding(a, asset, v),
        24..=26 => Op::RemoveHolding(a, asset),
        27..=30 => Op::SetAssetParams(asset, a, v),
        31..=32 => Op::RemoveAssetParams(asset),
        33..=38 => Op::SetAppParams(app, a, v),
        39..=40 => Op::RemoveAppParams(app),
        41..=47 => Op::SetLocal(a, app, v),
        48..=50 => Op::RemoveLocal(a, app),
        51 => Op::RemoveAllHoldings(asset),
        52 => Op::RemoveAllLocals(app),
        53..=64 => Op::SetBox(app, b, v),
        65..=70 => Op::DeleteBox(app, b),
        71..=77 => Op::Snapshot,
        78..=84 => Op::Restore,
        85..=91 => Op::Commit,
        92..=94 => Op::Rollback,
        _ => Op::Begin,
    }
}

fn account(v: u64) -> AccountData {
    AccountData {
        micro_algos: v,
        update_round: v % 7,
        ..Default::default()
    }
}

fn app_params(creator: Address, v: u64) -> AppParams {
    let mut rng = Rng(v | 1);
    AppParams {
        creator,
        approval_program: vec![v as u8; (v % 5) as usize],
        clear_state_program: vec![2],
        global_state: teal(&mut rng),
        ..Default::default()
    }
}

fn local_state(v: u64) -> AppLocalState {
    let mut rng = Rng(v | 1);
    AppLocalState {
        schema: StateSchema::default(),
        key_value: teal(&mut rng),
    }
}

/// Everything readable through the memoised getters.
fn dump(l: &SqliteLedger) -> String {
    let mut out = String::new();
    for a in 0..ADDRS {
        out += &format!("acct {a}: {:?}\n", l.get_account(&addr(a)));
        for asset in 1..=ASSETS {
            out += &format!(
                "hold {a}/{asset}: {:?}\n",
                l.get_asset_holding(&addr(a), asset)
            );
        }
        for i in 0..APPS {
            out += &format!(
                "local {a}/{}: {:?}\n",
                APP0 + i,
                l.get_app_local_state(&addr(a), APP0 + i)
            );
        }
    }
    for asset in 1..=ASSETS {
        out += &format!("aparams {asset}: {:?}\n", l.get_asset_params(asset));
    }
    for i in 0..APPS {
        out += &format!("appparams {}: {:?}\n", APP0 + i, l.get_app_params(APP0 + i));
        for b in 0..BOXES {
            out += &format!(
                "box {}/{b}: {:?}\n",
                APP0 + i,
                l.get_box(APP0 + i, &box_key(b))
            );
        }
    }
    out
}

struct Side {
    l: SqliteLedger,
    snaps: Vec<<SqliteLedger as LedgerStore>::Snapshot>,
    in_block: bool,
}

impl Side {
    fn new(memo: bool) -> Self {
        let mut l = SqliteLedger::open_in_memory().unwrap();
        l.set_read_cache_enabled(memo);
        l.enable_trie();
        Self {
            l,
            snaps: Vec::new(),
            in_block: false,
        }
    }

    fn apply(&mut self, op: &Op) {
        let l = &mut self.l;
        match op {
            Op::SetAccount(a, v) => l.set_account(&addr(*a), account(*v)),
            Op::RemoveAccount(a) => l.remove_account(&addr(*a)),
            Op::SetHolding(a, id, v) => l.set_asset_holding(
                &addr(*a),
                *id,
                AssetHolding {
                    amount: *v,
                    frozen: v % 2 == 0,
                },
            ),
            Op::RemoveHolding(a, id) => l.remove_asset_holding(&addr(*a), *id),
            Op::SetAssetParams(id, creator, v) => l.set_asset_params(
                *id,
                AssetParamsRecord {
                    params: AssetParams {
                        total: *v,
                        ..Default::default()
                    },
                    creator: addr(*creator),
                },
            ),
            Op::RemoveAssetParams(id) => l.remove_asset_params(*id),
            Op::SetAppParams(id, creator, v) => {
                l.set_app_params(*id, app_params(addr(*creator), *v))
            }
            Op::RemoveAppParams(id) => l.remove_app_params(*id),
            Op::SetLocal(a, id, v) => l.set_app_local_state(&addr(*a), *id, local_state(*v)),
            Op::RemoveLocal(a, id) => l.remove_app_local_state(&addr(*a), *id),
            Op::RemoveAllHoldings(id) => l.remove_all_asset_holdings_for_asset(*id),
            Op::RemoveAllLocals(id) => l.remove_all_app_local_states_for_app(*id),
            Op::SetBox(app, b, v) => {
                // Includes empty values.
                let value = vec![*b; (*v % 4) as usize];
                l.set_box(*app, &box_key(*b), value)
            }
            Op::DeleteBox(app, b) => {
                l.delete_box(*app, &box_key(*b));
            }
            Op::Snapshot => {
                if self.in_block {
                    self.snaps.push(l.snapshot(&[]));
                }
            }
            Op::Restore => {
                if let Some(s) = self.snaps.pop() {
                    l.restore_snapshot(s);
                }
            }
            Op::Begin => {
                if !self.in_block {
                    l.begin_block().unwrap();
                    self.in_block = true;
                }
            }
            Op::Commit => {
                if self.in_block {
                    // Unrestored snapshots die with the block.
                    self.snaps.clear();
                    let _ = l.finalize_trie_updates();
                    l.commit_block().unwrap();
                    self.in_block = false;
                }
            }
            Op::Rollback => {
                if self.in_block {
                    self.snaps.clear();
                    l.rollback_block().unwrap();
                    self.in_block = false;
                }
            }
        }
    }
}

fn run(seed: u64, steps: usize) -> (u64, u64) {
    let mut rng = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1);
    let mut memo = Side::new(true);
    let mut plain = Side::new(false);
    let mut log: Vec<Op> = Vec::new();
    for step in 0..steps {
        let op = random_op(&mut rng);
        log.push(op.clone());
        // Writes mostly happen inside a block (the memo is only active there),
        // with some outside to cover the bypass.
        if !memo.in_block && rng.below(10) < 8 && !matches!(op, Op::Begin) {
            memo.apply(&Op::Begin);
            plain.apply(&Op::Begin);
        }
        memo.apply(&op);
        plain.apply(&op);
        let (dm, dp) = (dump(&memo.l), dump(&plain.l));
        assert_eq!(
            dm,
            dp,
            "seed {seed} step {step} after {op:?}: memoised reads diverge\nlast ops: {:?}",
            &log[log.len().saturating_sub(12)..]
        );
        if matches!(op, Op::Commit | Op::Rollback) {
            assert_eq!(
                memo.l.account_totals(),
                plain.l.account_totals(),
                "seed {seed} step {step}: account totals"
            );
            assert_eq!(
                memo.l.trie_root(),
                plain.l.trie_root(),
                "seed {seed} step {step}: trie root"
            );
        }
    }
    // Close any open block and compare the final committed state.
    for s in [&mut memo, &mut plain] {
        s.apply(&Op::Commit);
    }
    assert_eq!(dump(&memo.l), dump(&plain.l), "seed {seed}: final state");
    assert_eq!(
        memo.l.trie_root(),
        plain.l.trie_root(),
        "seed {seed}: final trie root"
    );
    assert_eq!(memo.l.account_totals(), plain.l.account_totals());
    assert_eq!(plain.l.read_cache_stats().0, 0, "disabled memo never hits");
    memo.l.read_cache_stats()
}

#[test]
fn memoised_reads_match_uncached_over_random_sequences() {
    let mut hits = 0;
    for seed in 1..=40u64 {
        hits += run(seed, 250).0;
    }
    assert!(
        hits > 1_000,
        "the memo must actually be exercised: {hits} hits"
    );
}
