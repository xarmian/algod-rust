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

//! go-algorand oracle parity for a top-level ClearState program's use of the
//! group's pooled opcode budget (issue #2499).
//!
//! `tests/fixtures/simulate_clearstate_pool/oracle.json` is the real go
//! output of `tools/simulate-rewards-oracle` (`clearstatepool.go`): for the
//! current protocol and for v30, a genesis and a block that creates the apps
//! and opts the sender in, then one simulated group per scenario. go's
//! `data/transactions/logic/eval.go` rules it pins:
//!
//! - `step()` charges a ClearState program's opcodes to the shared
//!   `PooledApplicationBudget` even under `IsolateClearState`, where
//!   `remainingBudget()` caps the program at `MaxAppProgramCost - cx.cost`
//!   (`csp_small_then_logger`: the logger sees 1400 - 306 - 1);
//! - under `IsolateClearState`, `EvalContract` refuses to start it while the
//!   pool is below `MaxAppProgramCost`, failing the transaction
//!   (`burner_then_csp_small`);
//! - at v30 (no `IsolateClearState`) it runs on the pool with no gate and may
//!   issue inner transactions (`csp_big_then_call`, `csp_inner_pay`).
//!
//! This test seeds a Rust ledger the same way, simulates each group and
//! compares the failure message, failed-at, the group and per-transaction
//! budget figures, the logs and the inner transaction count.

use std::path::PathBuf;

use algo_ledger::eval_delta::parse_eval_delta;
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

#[derive(Debug, Deserialize, PartialEq)]
struct OracleTxn {
    app_budget_consumed: u64,
    logs: Vec<String>,
    inner_txns: usize,
}

#[derive(Debug, Deserialize)]
struct OracleScenario {
    name: String,
    group_msgpack: String,
    failure_message: String,
    failed_at: Vec<usize>,
    app_budget_added: u64,
    app_budget_consumed: u64,
    txns: Vec<OracleTxn>,
}

#[derive(Debug, Deserialize)]
struct OracleLedger {
    protocol: String,
    genesis_id: String,
    genesis_hash: String,
    fee_sink: String,
    rewards_pool: String,
    genesis_accounts: Vec<OracleAccount>,
    blocks: Vec<String>,
    scenarios: Vec<OracleScenario>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    ledgers: Vec<OracleLedger>,
}

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("fixture base64")
}

fn b64_encode(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn addr(s: &str) -> Address {
    Address(b64(s).try_into().expect("32-byte address"))
}

fn load_oracle() -> Oracle {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/simulate_clearstate_pool/oracle.json");
    let raw = std::fs::read_to_string(&path).expect("read oracle fixture");
    serde_json::from_str(&raw).expect("parse oracle fixture")
}

/// The go genesis, then go's blocks applied through the real apply path.
fn seed<L: LedgerStore>(store: &mut L, o: &OracleLedger) {
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

/// Runs every scenario of one ledger; returns the mismatches.
fn mismatches<L: LedgerStore>(store: &mut L, o: &OracleLedger) -> Vec<String> {
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
        let txns: Vec<OracleTxn> = g
            .txn_results
            .iter()
            .map(|t| {
                let delta = t
                    .apply_data
                    .as_ref()
                    .and_then(|ad| ad.eval_delta.as_ref())
                    .map(|dt| parse_eval_delta(dt).expect("eval delta"));
                OracleTxn {
                    app_budget_consumed: t.app_budget_consumed,
                    logs: delta
                        .as_ref()
                        .and_then(|d| d.logs.as_ref())
                        .map(|ls| ls.iter().map(|l| b64_encode(l)).collect())
                        .unwrap_or_default(),
                    inner_txns: delta
                        .as_ref()
                        .and_then(|d| d.inner_txns.as_ref())
                        .map_or(0, Vec::len),
                }
            })
            .collect();
        let got = (
            g.failure_message.clone().unwrap_or_default(),
            g.failed_at.clone().unwrap_or_default(),
            g.app_budget_added,
            g.app_budget_consumed,
        );
        let want = (
            sc.failure_message.clone(),
            sc.failed_at.clone(),
            sc.app_budget_added,
            sc.app_budget_consumed,
        );
        if got != want || txns != sc.txns {
            out.push(format!(
                "{} / {}:\n    go:   {:?} {:?}\n    rust: {:?} {:?}",
                o.protocol, sc.name, want, sc.txns, got, txns
            ));
        }
    }
    out
}

fn check<L: LedgerStore>(mut new_store: impl FnMut() -> L) {
    let o = load_oracle();
    assert_eq!(o.ledgers.len(), 2, "current protocol and v30");
    let mut bad = Vec::new();
    let mut total = 0;
    for l in &o.ledgers {
        let mut store = new_store();
        seed(&mut store, l);
        total += l.scenarios.len();
        bad.extend(mismatches(&mut store, l));
    }
    assert!(
        bad.is_empty(),
        "{} of {} ClearState pool scenarios differ from go-algorand:\n{}",
        bad.len(),
        total,
        bad.join("\n")
    );
}

#[test]
fn simulate_clearstate_pool_matches_go() {
    check(LedgerState::new);
}

#[test]
fn simulate_clearstate_pool_matches_go_on_sqlite() {
    check(|| SqliteLedger::open_in_memory().expect("in-memory ledger"));
}
