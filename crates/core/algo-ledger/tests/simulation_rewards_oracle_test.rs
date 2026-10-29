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

//! go-algorand oracle parity for simulate on a rewards-accruing chain
//! (issue #2118).
//!
//! go's `Simulator.Simulate` evaluates the group in `MakeBlock(prevHdr)` with
//! `Generate: true`, so `eval.StartEvaluator` gives the simulated block
//! `prevHdr.NextRewardsState(..)` and withdraws its rewards from the pool
//! before the group runs. `tests/fixtures/simulate_rewards/oracle.json` is
//! the real go simulate output (`tools/simulate-rewards-oracle`), together
//! with the ledger state it ran against; this test seeds that state and
//! asserts the same ApplyData rewards (`rs`/`rr`/`rc`), closing amount and
//! AVM-visible balances (`balance`, `min_balance`, `acct_params_get`,
//! including the rewards pool after the block-start withdrawal). The last
//! transaction is valid only from the simulated block's round (`start + 1`)
//! and logs `global Round` and `acct_params_get`'s `exists` flag for the
//! account the group just closed.

use std::path::PathBuf;

use algo_ledger::eval_delta::parse_eval_delta;
use algo_ledger::rewards::{next_rewards_state, RewardsState};
use algo_ledger::simulation::{SimulationRequest, Simulator};
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::{AccountData, AccountStatus, Address};
use base64::Engine as _;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct OracleRewardsState {
    rewards_level: u64,
    rewards_rate: u64,
    rewards_residue: u64,
    rewards_recalculation_round: u64,
}

impl From<&OracleRewardsState> for RewardsState {
    fn from(s: &OracleRewardsState) -> Self {
        RewardsState {
            rewards_level: s.rewards_level,
            rewards_rate: s.rewards_rate,
            rewards_residue: s.rewards_residue,
            rewards_recalculation_round: s.rewards_recalculation_round,
        }
    }
}

#[derive(Debug, Deserialize)]
struct OracleAccount {
    addr: String,
    status: String,
    micro_algos: u64,
    rewards_base: u64,
    rewarded_micro_algos: u64,
}

#[derive(Debug, Deserialize)]
struct OracleTxn {
    sender_rewards: u64,
    receiver_rewards: u64,
    close_rewards: u64,
    closing_amount: u64,
    application_id: u64,
    logs: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    protocol: String,
    genesis_id: String,
    genesis_hash: String,
    round: u64,
    txn_counter: u64,
    fee_sink: String,
    rewards_pool: String,
    rewards_state: OracleRewardsState,
    next_rewards_state: OracleRewardsState,
    reward_units: u64,
    accounts: Vec<OracleAccount>,
    prev_header: String,
    group_msgpack: String,
    last_round: u64,
    failure_message: String,
    txns: Vec<OracleTxn>,
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
        .join("tests/fixtures/simulate_rewards/oracle.json");
    let raw = std::fs::read_to_string(&path).expect("read oracle fixture");
    serde_json::from_str(&raw).expect("parse oracle fixture")
}

/// The go ledger at the fixture's round: its header rewards state and every
/// account exactly as `LookupWithoutRewards` returned it.
fn seed_state(o: &Oracle) -> LedgerState {
    let mut state = LedgerState::new();
    state.protocol = o.protocol.clone();
    state.genesis_id = o.genesis_id.clone();
    state.genesis_hash = b64(&o.genesis_hash).try_into().expect("genesis hash");
    state.current_round = o.round.into();
    state.txn_counter = o.txn_counter;
    state.fee_sink = addr(&o.fee_sink);
    state.rewards_pool = addr(&o.rewards_pool);
    state.rewards_level = o.rewards_state.rewards_level;
    state.rewards_rate = o.rewards_state.rewards_rate;
    state.rewards_residue = o.rewards_state.rewards_residue;
    state.rewards_recalculation_round = o.rewards_state.rewards_recalculation_round;
    // go's header for the latest round: `Simulate` builds the simulated
    // block from it (`MakeBlock(prevBlockHdr)`).
    state
        .put_block(o.round, &o.protocol, &b64(&o.prev_header), &[])
        .expect("store the latest header");
    for a in &o.accounts {
        let status = match a.status.as_str() {
            "Online" => AccountStatus::Online,
            "Offline" => AccountStatus::Offline,
            "Not Participating" => AccountStatus::NotParticipating,
            other => panic!("unknown status {other}"),
        };
        state.set_account(
            &addr(&a.addr),
            AccountData {
                status,
                micro_algos: a.micro_algos,
                rewards_base: a.rewards_base,
                rewarded_micro_algos: a.rewarded_micro_algos,
                ..Default::default()
            },
        );
    }
    state
}

/// The fixture's inputs reproduce go's `NextRewardsState` through the Rust
/// port, so the seeded ledger is the one go simulated against.
#[test]
fn oracle_inputs_match_rust_next_rewards_state() {
    let o = load_oracle();
    let state = seed_state(&o);
    let totals = state.account_totals();
    assert_eq!(
        totals.online.reward_units + totals.offline.reward_units,
        o.reward_units
    );
    let params = algo_types::consensus::consensus_params_for_version(&o.protocol)
        .expect("fixture protocol is known");
    let pool = state.get_account(&addr(&o.rewards_pool)).expect("pool");
    let next = next_rewards_state(
        (&o.rewards_state).into(),
        o.round + 1,
        &params,
        pool.micro_algos,
        o.reward_units,
    );
    assert_eq!(next, RewardsState::from(&o.next_rewards_state));
    assert!(
        next.rewards_level > o.rewards_state.rewards_level,
        "the scenario must accrue rewards in the simulated round"
    );
}

/// Simulate on a rewards-accruing chain matches go-algorand's simulate:
/// claims at the next round's rewards level, and the pool already debited
/// by the block-start withdrawal.
#[test]
fn simulate_uses_next_rewards_state_like_go() {
    let o = load_oracle();
    let mut state = seed_state(&o);
    let group = algo_codec::decode_signed_txn_stream(&b64(&o.group_msgpack)).expect("group");
    assert_eq!(group.len(), o.txns.len());

    let before = state.accounts.clone();
    let result = Simulator::new(&mut state)
        .simulate(SimulationRequest {
            txn_groups: vec![group],
            allow_empty_signatures: true,
            ..Default::default()
        })
        .expect("simulate");
    assert_eq!(
        state.accounts, before,
        "simulate must not change the ledger"
    );

    assert_eq!(result.last_round.0, o.last_round);
    let g = &result.txn_groups[0];
    assert_eq!(
        g.failure_message.clone().unwrap_or_default(),
        o.failure_message
    );
    for (i, (got, want)) in g.txn_results.iter().zip(&o.txns).enumerate() {
        let ad = got.apply_data.as_ref().expect("apply data");
        assert_eq!(ad.sender_rewards, want.sender_rewards, "txn {i} rs");
        assert_eq!(ad.receiver_rewards, want.receiver_rewards, "txn {i} rr");
        assert_eq!(ad.close_rewards, want.close_rewards, "txn {i} rc");
        assert_eq!(ad.closing_amount, want.closing_amount, "txn {i} ca");
        assert_eq!(ad.application_id, want.application_id, "txn {i} apid");
        let logs: Vec<u64> = ad
            .eval_delta
            .as_ref()
            .map(|dt| parse_eval_delta(dt).expect("eval delta"))
            .and_then(|dt| dt.logs)
            .unwrap_or_default()
            .iter()
            .map(|l| u64::from_be_bytes(l.as_slice().try_into().expect("8-byte log")))
            .collect();
        assert_eq!(
            logs, want.logs,
            "txn {i} logs (each program is in tools/simulate-rewards-oracle)"
        );
    }
}
