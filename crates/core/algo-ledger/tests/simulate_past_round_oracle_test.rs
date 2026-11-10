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

//! `simulate` at a past `Request.Round` against go-algorand (issue #2148).
//!
//! `tools/simulate-rewards-oracle/pastround.go` builds a go ledger on a
//! rewards-accruing chain (a large pool: the level advances every block), applies
//! three blocks (the third spends 800 of the sender's 1000 Algo) and simulates the
//! same payment at rounds 1, 2 and 3 through go's `Simulator`. The ledger here
//! applies the same blocks with the undo journal on and must answer every request
//! as go does: the failure text, and the rewards credited to the sender and the
//! receiver, which depend on the account state AND the rewards level of that
//! round.

use std::path::PathBuf;

use algo_ledger::simulation::{SimulationRequest, Simulator};
use algo_ledger::sqlite::SqliteLedger;
use algo_ledger::LedgerStore;
use algo_types::{AccountData, AccountStatus, Address, Round};
use base64::Engine as _;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct OracleAccount {
    addr: String,
    status: String,
    micro_algos: u64,
}

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    round: u64,
    group_msgpack: String,
    last_round: u64,
    failure_message: String,
    sender_rewards: u64,
    receiver_rewards: u64,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    protocol: String,
    genesis_id: String,
    genesis_hash: String,
    fee_sink: String,
    rewards_pool: String,
    genesis_accounts: Vec<OracleAccount>,
    blocks: Vec<String>,
    scenarios: Vec<Scenario>,
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
        .join("tests/fixtures/simulate_past_round/oracle.json");
    let raw = std::fs::read_to_string(&path).expect("read oracle fixture");
    serde_json::from_str(&raw).expect("parse oracle fixture")
}

/// go's genesis and its blocks, each applied in its own commit span with the
/// undo journal on.
fn seeded_ledger(o: &Oracle, window: u64) -> SqliteLedger {
    let mut l = SqliteLedger::open_in_memory().expect("in-memory ledger");
    l.set_protocol(o.protocol.clone());
    l.set_genesis_id(o.genesis_id.clone());
    l.set_genesis_hash(b64(&o.genesis_hash).try_into().expect("genesis hash"));
    l.set_fee_sink(addr(&o.fee_sink));
    l.set_rewards_pool(addr(&o.rewards_pool));
    let (mut offline_money, mut offline_units, mut notpart_money, mut notpart_units) =
        (0u64, 0u64, 0u64, 0u64);
    for a in &o.genesis_accounts {
        let status = match a.status.as_str() {
            "Offline" => AccountStatus::Offline,
            "Not Participating" => AccountStatus::NotParticipating,
            other => panic!("unknown status {other}"),
        };
        match status {
            AccountStatus::NotParticipating => {
                notpart_money += a.micro_algos;
                notpart_units += a.micro_algos / 1_000_000;
            }
            _ => {
                offline_money += a.micro_algos;
                offline_units += a.micro_algos / 1_000_000;
            }
        }
        l.set_account(
            &addr(&a.addr),
            AccountData {
                status,
                micro_algos: a.micro_algos,
                ..Default::default()
            },
        );
    }
    l.put_account_totals_seed(
        0,
        0,
        offline_money,
        offline_units,
        notpart_money,
        notpart_units,
    )
    .expect("seed totals");
    l.set_undo_window(window);
    for (i, b) in o.blocks.iter().enumerate() {
        let block = algo_codec::decode_block(&b64(b)).expect("decode go block");
        assert_eq!(block.round.0, i as u64 + 1);
        l.begin_block().expect("begin_block");
        algo_ledger::apply::apply_block(&mut l, &block).expect("apply go block");
        l.commit_block().expect("commit_block");
    }
    l
}

fn run(l: &mut SqliteLedger, sc: &Scenario) -> (String, u64, u64, u64) {
    let group = algo_codec::decode_signed_txn_stream(&b64(&sc.group_msgpack)).expect("group");
    let result = Simulator::new(l)
        .simulate(SimulationRequest {
            txn_groups: vec![group],
            allow_empty_signatures: true,
            round: Some(Round(sc.round)),
            ..Default::default()
        })
        .unwrap_or_else(|e| panic!("{}: simulate: {e}", sc.name));
    let g = &result.txn_groups[0];
    let ad = g.txn_results[0].apply_data.clone().unwrap_or_default();
    (
        g.failure_message.clone().unwrap_or_default(),
        ad.sender_rewards,
        ad.receiver_rewards,
        result.last_round.0,
    )
}

#[test]
fn simulate_at_a_past_round_matches_go() {
    let o = load_oracle();
    let mut l = seeded_ledger(&o, 100);
    assert_eq!(l.current_round(), Round(o.blocks.len() as u64));
    let before = (
        l.get_account(&addr(&o.fee_sink)),
        l.rewards_level(),
        l.txn_counter(),
        l.account_totals(),
    );
    let mut bad = Vec::new();
    for sc in &o.scenarios {
        let got = run(&mut l, sc);
        let want = (
            sc.failure_message.clone(),
            sc.sender_rewards,
            sc.receiver_rewards,
            sc.last_round,
        );
        if got != want {
            bad.push(format!(
                "{} (round {}): rust {:?} vs go {:?}",
                sc.name, sc.round, got, want
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "{} of {} past-round scenarios differ from go:\n{}",
        bad.len(),
        o.scenarios.len(),
        bad.join("\n")
    );
    // The scenarios are not all alike: the past rounds credit different
    // rewards than the latest one.
    let sender: std::collections::BTreeSet<u64> =
        o.scenarios.iter().map(|s| s.sender_rewards).collect();
    assert!(sender.len() >= 3, "the rounds must be distinguishable");
    assert_eq!(
        before,
        (
            l.get_account(&addr(&o.fee_sink)),
            l.rewards_level(),
            l.txn_counter(),
            l.account_totals(),
        ),
        "the ledger is restored after the rewound simulations"
    );
}

/// Without the undo journal only the latest round is served, with go's text.
#[test]
fn without_undo_data_only_the_latest_round_is_served() {
    let o = load_oracle();
    let mut l = seeded_ledger(&o, 0);
    for sc in &o.scenarios {
        if sc.round == o.blocks.len() as u64 {
            continue;
        }
        let group = algo_codec::decode_signed_txn_stream(&b64(&sc.group_msgpack)).expect("group");
        let err = Simulator::new(&mut l)
            .simulate(SimulationRequest {
                txn_groups: vec![group],
                allow_empty_signatures: true,
                round: Some(Round(sc.round)),
                ..Default::default()
            })
            .expect_err("a past round needs undo data");
        assert!(
            err.to_string().ends_with(&format!(
                "round {} before dbRound {}",
                sc.round,
                o.blocks.len()
            )),
            "{}: {err}",
            sc.name
        );
    }
}
