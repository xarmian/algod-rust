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

//! go-algorand oracle parity for simulate's duplicate checks (issue #2125).
//!
//! go's simulate evaluates with `Validate: true`, so `BlockEvaluator.transaction`
//! runs `cow.checkDup` between `BlockHeader.Alive` and the authorizer check:
//! a transaction already in the ledger (or earlier in the same group) fails
//! with `transaction already in ledger: <txid>`, and a (sender, lease) pair
//! still leased fails with `transaction <txid> using an overlapping lease
//! (sender, lease):(<sender>, <lease>)`.
//!
//! `tests/fixtures/simulate_checkdup/oracle.json` is the real go output
//! (`tools/simulate-rewards-oracle`, `checkdup.go`): a genesis, the three
//! blocks go generated, and the simulate result of every scenario. Stage A
//! runs at latest = 3, some scenarios at the past round 1. Stage B appends
//! empty blocks until the simulated round is `2 + MaxTxnLife`, so block 2
//! sits on the `round - MaxTxnLife` boundary. This test applies the same
//! blocks to a Rust ledger and asserts the same failure message and
//! `failed_at` for each scenario, and that simulate leaves accounts, the
//! lease table and the txtail exactly as they were.

use std::path::PathBuf;

use algo_ledger::simulation::{SimulationRequest, Simulator};
use algo_ledger::sqlite::SqliteLedger;
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::{AccountData, AccountStatus, Address, Block, Round};
use base64::Engine as _;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct OracleAccount {
    addr: String,
    status: String,
    micro_algos: u64,
}

#[derive(Debug, Deserialize)]
struct OracleScenario {
    name: String,
    stage: String,
    round: u64,
    group_msgpack: String,
    failure_message: String,
    failed_at: Vec<usize>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    protocol: String,
    genesis_id: String,
    genesis_hash: String,
    fee_sink: String,
    rewards_pool: String,
    max_txn_life: u64,
    genesis_accounts: Vec<OracleAccount>,
    blocks: Vec<String>,
    stage_b_latest: u64,
    scenarios: Vec<OracleScenario>,
}

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("fixture base64")
}

fn addr(s: &str) -> Address {
    Address(b64(s).try_into().expect("32-byte address"))
}

fn load_oracle() -> Oracle {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/simulate_checkdup/oracle.json");
    let raw = std::fs::read_to_string(&path).expect("read oracle fixture");
    serde_json::from_str(&raw).expect("parse oracle fixture")
}

/// The go genesis, then go's blocks applied through the real apply path
/// (which records each block's txtail row and leases). Returns the last
/// block.
fn seed_go_blocks<L: LedgerStore>(store: &mut L, o: &Oracle) -> Block {
    store.set_protocol(o.protocol.clone());
    store.set_genesis_id(o.genesis_id.clone());
    store.set_genesis_hash(b64(&o.genesis_hash).try_into().expect("genesis hash"));
    store.set_fee_sink(addr(&o.fee_sink));
    store.set_rewards_pool(addr(&o.rewards_pool));
    for a in &o.genesis_accounts {
        let status = match a.status.as_str() {
            "Offline" => AccountStatus::Offline,
            "Not Participating" => AccountStatus::NotParticipating,
            other => panic!("unknown status {other}"),
        };
        store.set_account(
            &addr(&a.addr),
            AccountData {
                status,
                micro_algos: a.micro_algos,
                ..Default::default()
            },
        );
    }
    let mut last = None;
    for (i, b) in o.blocks.iter().enumerate() {
        let block = algo_codec::decode_block(&b64(b)).expect("decode go block");
        assert_eq!(block.round.0, i as u64 + 1);
        algo_ledger::apply::apply_block(store, &block).expect("apply go block");
        last = Some(block);
    }
    assert_eq!(store.current_round().0, o.blocks.len() as u64);
    last.expect("the fixture has blocks")
}

/// Empty blocks up to the round go reached for stage B, so the simulated
/// round is 2 + MaxTxnLife.
fn extend_to_stage_b<L: LedgerStore>(store: &mut L, o: &Oracle, last: &Block) {
    assert_eq!(o.stage_b_latest, 1 + o.max_txn_life);
    for round in o.blocks.len() as u64 + 1..=o.stage_b_latest {
        let block = Block {
            round: Round(round),
            timestamp: 1_700_000_000 + round as i64 * 5,
            payset: Vec::new(),
            ..last.clone()
        };
        algo_ledger::apply::apply_block(store, &block).expect("apply empty block");
    }
    assert_eq!(store.current_round().0, o.stage_b_latest);
}

/// Everything simulate must leave untouched: the accounts, the lease table
/// (`lease_fp`) and every txtail row.
type Fingerprint = (Vec<Option<AccountData>>, u64, Vec<Option<Vec<u8>>>);

fn ledger_fingerprint<L: LedgerStore>(
    store: &L,
    o: &Oracle,
    lease_fp: fn(&L) -> u64,
) -> Fingerprint {
    let accounts = o
        .genesis_accounts
        .iter()
        .map(|a| store.get_account(&addr(&a.addr)))
        .collect();
    let txtail = (0..=store.current_round().0)
        .map(|r| store.get_txtail(r).expect("get_txtail"))
        .collect();
    (accounts, lease_fp(store), txtail)
}

fn run_stage<L: LedgerStore>(store: &mut L, o: &Oracle, stage: &str, lease_fp: fn(&L) -> u64) {
    let scenarios: Vec<_> = o.scenarios.iter().filter(|s| s.stage == stage).collect();
    assert!(!scenarios.is_empty(), "stage {stage} has scenarios");
    for sc in scenarios {
        let group = algo_codec::decode_signed_txn_stream(&b64(&sc.group_msgpack))
            .unwrap_or_else(|e| panic!("{}: decode group: {e}", sc.name));
        let before = ledger_fingerprint(store, o, lease_fp);
        let result = Simulator::new(&mut *store)
            .simulate(SimulationRequest {
                round: (sc.round != 0).then_some(Round(sc.round)),
                txn_groups: vec![group],
                allow_empty_signatures: true,
                ..Default::default()
            })
            .unwrap_or_else(|e| panic!("{}: simulate: {e}", sc.name));
        assert!(
            ledger_fingerprint(store, o, lease_fp) == before,
            "{}: simulate must restore accounts, leases and txtail",
            sc.name
        );
        let g = &result.txn_groups[0];
        assert_eq!(
            g.failure_message.clone().unwrap_or_default(),
            sc.failure_message,
            "{}: failure message",
            sc.name
        );
        assert_eq!(
            g.failed_at.clone().unwrap_or_default(),
            sc.failed_at,
            "{}: failed_at",
            sc.name
        );
    }
}

fn run_oracle<L: LedgerStore>(store: &mut L, lease_fp: fn(&L) -> u64) {
    let o = load_oracle();
    let last = seed_go_blocks(store, &o);
    run_stage(store, &o, "A", lease_fp);
    extend_to_stage_b(store, &o, &last);
    run_stage(store, &o, "B", lease_fp);
}

/// Every scenario matches go-algorand's simulate: the duplicate-txid and
/// lease checks, their order (the lease before the txid, both before the
/// authorizer), the within-group cases, a past `round`, and the
/// `round - MaxTxnLife` edge of the scan window.
#[test]
fn simulate_checkdup_matches_go() {
    run_oracle(&mut LedgerState::new(), |s| s.lease_table.fingerprint());
}

/// The same oracle on `SqliteLedger`, whose txid lookup goes through its
/// incremental txtail cache rather than the trait's per-call rebuild.
#[test]
fn simulate_checkdup_matches_go_on_sqlite() {
    let mut ledger = SqliteLedger::open_in_memory().expect("in-memory ledger");
    run_oracle(&mut ledger, |l| {
        l.scratch_invariant_fingerprint()
            .expect("SqliteLedger fingerprints its lease table")
    });
}
