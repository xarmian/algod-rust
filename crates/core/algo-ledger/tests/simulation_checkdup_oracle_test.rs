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
//! (`tools/simulate-rewards-oracle`, `checkdup.go`): a genesis, one block
//! go generated with two payments from A (one leased), and the simulate
//! result of every scenario against that ledger. This test applies the same
//! block to a Rust ledger and asserts the same failure message and
//! `failed_at` for each scenario.

use std::path::PathBuf;

use algo_ledger::simulation::{SimulationRequest, Simulator};
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::{AccountData, AccountStatus, Address};
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
    genesis_accounts: Vec<OracleAccount>,
    block: String,
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

/// The go genesis, then go's block 1 applied through the real apply path
/// (which records the block's txtail row and leases).
fn ledger_after_block_1(o: &Oracle) -> LedgerState {
    let mut state = LedgerState::new();
    state.protocol = o.protocol.clone();
    state.genesis_id = o.genesis_id.clone();
    state.genesis_hash = b64(&o.genesis_hash).try_into().expect("genesis hash");
    state.fee_sink = addr(&o.fee_sink);
    state.rewards_pool = addr(&o.rewards_pool);
    for a in &o.genesis_accounts {
        let status = match a.status.as_str() {
            "Offline" => AccountStatus::Offline,
            "Not Participating" => AccountStatus::NotParticipating,
            other => panic!("unknown status {other}"),
        };
        state.set_account(
            &addr(&a.addr),
            AccountData {
                status,
                micro_algos: a.micro_algos,
                ..Default::default()
            },
        );
    }
    let block = algo_codec::decode_block(&b64(&o.block)).expect("decode go block 1");
    assert_eq!(block.round.0, 1);
    assert_eq!(block.payset.len(), 2, "go block 1 has both payments");
    algo_ledger::apply::apply_block(&mut state, &block).expect("apply go block 1");
    assert_eq!(state.current_round().0, 1);
    state
}

/// Every scenario matches go-algorand's simulate: the duplicate-txid and
/// lease checks, their order (the lease before the txid, both before the
/// authorizer), and the within-group cases.
#[test]
fn simulate_checkdup_matches_go() {
    let o = load_oracle();
    let mut state = ledger_after_block_1(&o);
    assert!(
        o.scenarios.iter().any(|s| s.failure_message.is_empty()),
        "the fixture has a control scenario that succeeds"
    );
    for sc in &o.scenarios {
        let group = algo_codec::decode_signed_txn_stream(&b64(&sc.group_msgpack))
            .unwrap_or_else(|e| panic!("{}: decode group: {e}", sc.name));
        let before = state.accounts.clone();
        let result = Simulator::new(&mut state)
            .simulate(SimulationRequest {
                txn_groups: vec![group],
                allow_empty_signatures: true,
                ..Default::default()
            })
            .unwrap_or_else(|e| panic!("{}: simulate: {e}", sc.name));
        assert_eq!(
            state.accounts, before,
            "{}: simulate must not change the ledger",
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
