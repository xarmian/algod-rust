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
//! Issue #2178: the app-call transaction the `rest` bench tier's second
//! simulate request (`simulate_app`, `scripts/bench/rest_lib.py`) sends to both
//! nodes. It creates an application and opts the sender in, and the approval
//! program logs, writes a global and a local key and issues an inner payment,
//! so the response carries `logs`, `global-state-delta`, `local-state-delta`
//! and `inner-txns` in the `txn-result`. The programs live in
//! `scripts/bench/data/` (TEAL and assembled hex, the single copy the Python
//! tier reads); this test fails unless the assembler turns each TEAL into its
//! hex, and proves the request is a successful simulation with those pieces.

use algo_ledger::apply::pool_fixtures::{funded_simulation_state, TEST_GENESIS_HASH};
use algo_ledger::eval_delta::parse_eval_delta;
use algo_ledger::simulation::{SimulationRequest, Simulator};
use algo_ledger::LedgerStore;
use algo_types::{AccountData, Address, SignedTransaction, StateSchema, Transaction};
use serde_bytes::ByteBuf;

const FEE_SINK: Address = Address([0xFE; 32]);

const APPROVAL_TEAL: &str =
    include_str!("../../../../scripts/bench/data/simulate_app.approval.teal");
const APPROVAL_HEX: &str = include_str!("../../../../scripts/bench/data/simulate_app.approval.hex");
const CLEAR_TEAL: &str = include_str!("../../../../scripts/bench/data/simulate_app.clear.teal");
const CLEAR_HEX: &str = include_str!("../../../../scripts/bench/data/simulate_app.clear.hex");

fn hex_of(teal: &str) -> String {
    let p = algo_avm::assembler::assemble_string(teal).expect("assemble");
    p.program.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn bench_program_bytes_match_the_teal() {
    assert_eq!(hex_of(APPROVAL_TEAL), APPROVAL_HEX.trim());
    assert_eq!(hex_of(CLEAR_TEAL), CLEAR_HEX.trim());
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[test]
fn bench_app_create_simulates_with_logs_deltas_and_inner_txn() {
    let sender = Address([0xAA; 32]);
    let mut state = funded_simulation_state();
    state.fee_sink = FEE_SINK;
    state.protocol = algo_types::consensus::CONSENSUS_V41.to_string();
    state.set_account(
        &sender,
        AccountData {
            micro_algos: 10_000_000,
            ..Default::default()
        },
    );
    state.set_account(&FEE_SINK, AccountData::default());

    let stx = SignedTransaction {
        txn: Transaction {
            txn_type: "appl".into(),
            sender,
            // The inner payment pays no fee of its own: the outer covers both.
            fee: 2000,
            first_valid: 0.into(),
            last_valid: 1000.into(),
            on_completion: 1, // OptIn
            approval_program: Some(ByteBuf::from(unhex(APPROVAL_HEX.trim()))),
            clear_state_program: Some(ByteBuf::from(unhex(CLEAR_HEX.trim()))),
            global_state_schema: Some(StateSchema {
                num_uint: 1,
                num_byte_slice: 0,
            }),
            local_state_schema: Some(StateSchema {
                num_uint: 0,
                num_byte_slice: 1,
            }),
            genesis_hash: TEST_GENESIS_HASH,
            ..Default::default()
        },
        ..Default::default()
    };
    let result = Simulator::new(&mut state)
        .simulate(SimulationRequest {
            txn_groups: vec![vec![stx]],
            allow_empty_signatures: true,
            ..Default::default()
        })
        .expect("simulate");
    let group = &result.txn_groups[0];
    assert_eq!(group.failure_message, None, "{:?}", group.failure_message);
    let ad = group.txn_results[0]
        .apply_data
        .as_ref()
        .expect("apply data");
    assert_ne!(
        ad.application_id, 0,
        "the create reports its application id"
    );
    let dt = parse_eval_delta(ad.eval_delta.as_ref().expect("eval delta")).expect("parse");
    assert_eq!(dt.logs, Some(vec![b"hello".to_vec()]));
    assert_eq!(dt.global_delta.expect("gd").len(), 1);
    assert_eq!(dt.local_deltas.expect("ld").len(), 1);
    assert_eq!(dt.inner_txns.expect("itx").len(), 1);
}
