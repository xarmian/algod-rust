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

//! go-algorand oracle parity for the application-mode AVM error texts
//! (issue #2225).
//!
//! The execution errors of the application-only opcodes (`app_*`, `asset_*`,
//! `acct_params_get`, `box_*`, `itxn*`, `gitxn*`, `gload*`, `gaid*`, `log`,
//! `block`, ...) cannot be reached from a LogicSig, where they only hit the
//! mode gate (pinned by the `avm-opcode-capture` vectors).
//! `tests/fixtures/simulate_app_errors/oracle.json` is the real go output of
//! `tools/simulate-rewards-oracle` (`apperr.go`): a genesis, one empty block
//! and, per scenario, an application creation call whose approval program
//! provokes one error, simulated through go's unmodified `Simulator`. This
//! test simulates the same transaction on a Rust ledger seeded the same way
//! and compares the failure message (go's `EvalError` text with its
//! `Details: app=..., pc=..., opcodes=...` context and the txid) and
//! `failed_at` in full.

use std::path::PathBuf;

use algo_ledger::simulation::{SimulationRequest, Simulator};
use algo_ledger::sqlite::SqliteLedger;
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
    source: String,
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
    blocks: Vec<String>,
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
        .join("tests/fixtures/simulate_app_errors/oracle.json");
    let raw = std::fs::read_to_string(&path).expect("read oracle fixture");
    serde_json::from_str(&raw).expect("parse oracle fixture")
}

/// The go genesis, then go's block applied through the real apply path.
fn seed<L: LedgerStore>(store: &mut L, o: &Oracle) {
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
    for (i, b) in o.blocks.iter().enumerate() {
        let block = algo_codec::decode_block(&b64(b)).expect("decode go block");
        assert_eq!(block.round.0, i as u64 + 1);
        algo_ledger::apply::apply_block(store, &block).expect("apply go block");
    }
}

/// Runs every scenario; returns the mismatches (go text beside ours).
fn mismatches<L: LedgerStore>(store: &mut L, o: &Oracle) -> Vec<String> {
    let mut out = Vec::new();
    for sc in &o.scenarios {
        let group = algo_codec::decode_signed_txn_stream(&b64(&sc.group_msgpack))
            .unwrap_or_else(|e| panic!("{}: decode group: {e}", sc.name));
        let result = Simulator::new(&mut *store)
            .simulate(SimulationRequest {
                txn_groups: vec![group],
                allow_empty_signatures: true,
                ..Default::default()
            })
            .unwrap_or_else(|e| panic!("{}: simulate: {e}", sc.name));
        let g = &result.txn_groups[0];
        let message = g.failure_message.clone().unwrap_or_default();
        let failed_at = g.failed_at.clone().unwrap_or_default();
        if message != sc.failure_message || failed_at != sc.failed_at {
            out.push(format!(
                "{}: {}\n    go:   {:?} failed_at={:?}\n    rust: {:?} failed_at={:?}",
                sc.name, sc.source, sc.failure_message, sc.failed_at, message, failed_at
            ));
        }
    }
    out
}

fn check<L: LedgerStore>(store: &mut L) {
    let o = load_oracle();
    assert!(o.scenarios.len() >= 40, "the fixture has its scenarios");
    seed(store, &o);
    let bad = mismatches(store, &o);
    assert!(
        bad.is_empty(),
        "{} of {} app-mode error scenarios differ from go-algorand:\n{}",
        bad.len(),
        o.scenarios.len(),
        bad.join("\n")
    );
}

#[test]
fn simulate_app_errors_match_go() {
    check(&mut LedgerState::new());
}

#[test]
fn simulate_app_errors_match_go_on_sqlite() {
    check(&mut SqliteLedger::open_in_memory().expect("in-memory ledger"));
}
