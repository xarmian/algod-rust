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

//! Simulate's verdict on every group go's `verify.TxnGroup` rejects, pinned
//! to go-algorand v5.0.5-stable's `Simulator.Simulate` (issue #2451).
//!
//! `fixtures/block_checkdup/oracle.json` (`tools/simulate-rewards-oracle`)
//! runs each `wellformed` row (one per `WellFormed` rule, the group-ID errors
//! and every signature class: no signature, two kinds, ed25519, multisig,
//! delegated LogicSig by key and by multisig, a LogicSig program that
//! rejects, errors or is malformed, a rekeyed authorizer) through go's
//! simulate with no request override. Simulate's `check` runs the same
//! `verify.TxnGroup`, so where it rejects, go answers before any evaluation:
//!
//! - a member's `TxGroupError` (`GroupIndex >= 0`) is the group's
//!   `FailureMessage` at `FailedAt [i]`: the bare reason for a not-well-formed
//!   member (go's frame wraps the `TxGroupError` from outside), the
//!   `transaction <%+v> invalid : <reason>` frame for a signature-stage one;
//! - anything else (the batch verifier's failure, a group-wide error) is the
//!   request error, its bare text.
//!
//! No text carries algod-rust's `validation error: ` prefix. A heartbeat's
//! pointer address is masked on both sides, nothing else.

use algo_ledger::apply::pool_fixtures::funded_simulation_state;
use algo_ledger::simulation::{SimulationRequest, Simulator, SimulatorError};
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::{AccountData, Address};

const FIXTURE: &str = include_str!("fixtures/block_checkdup/oracle.json");

fn b64(s: &str) -> Vec<u8> {
    data_encoding::BASE64
        .decode(s.as_bytes())
        .expect("base64 field")
}

fn address(s: &str) -> Address {
    Address(b64(s).try_into().expect("32-byte address"))
}

fn state(o: &serde_json::Value) -> LedgerState {
    let mut state = funded_simulation_state();
    state.protocol = o["protocol"].as_str().unwrap().to_string();
    state.fee_sink = address(o["fee_sink"].as_str().unwrap());
    state.rewards_pool = address(o["rewards_pool"].as_str().unwrap());
    for a in [state.fee_sink, state.rewards_pool] {
        state.set_account(
            &a,
            AccountData {
                micro_algos: 1_000_000,
                ..Default::default()
            },
        );
    }
    state
}

/// The first differing byte of two (multi-kilobyte) texts, with context.
fn first_difference(go: &str, rust: &str) -> String {
    let at = go
        .bytes()
        .zip(rust.bytes())
        .position(|(a, b)| a != b)
        .unwrap_or(go.len().min(rust.len()));
    let cut = |s: &str| {
        let lo = (0..=at.saturating_sub(60).min(s.len()))
            .rev()
            .find(|&i| s.is_char_boundary(i))
            .unwrap_or(0);
        let hi = ((at + 120).min(s.len())..=s.len())
            .find(|&i| s.is_char_boundary(i))
            .unwrap_or(s.len());
        format!("{:?}", &s[lo..hi])
    };
    format!(
        "byte {at}\n    go:   ...{}\n    rust: ...{}",
        cut(go),
        cut(rust)
    )
}

#[test]
fn simulate_reports_every_verify_failure_like_go() {
    let o: serde_json::Value = serde_json::from_str(FIXTURE).expect("oracle JSON");
    let mut compared = 0;
    let mut mismatches = Vec::new();
    for row in o["wellformed"].as_array().expect("wellformed rows") {
        let name = row["name"].as_str().unwrap();
        let verify_error = row["verify_error"].as_str().unwrap();
        // Only the groups go's `verify.TxnGroup` rejects end in `check`; the
        // others go on to evaluation, which this test is not about.
        if verify_error.is_empty() {
            continue;
        }
        let mut group = Vec::new();
        let mut decodes = true;
        for m in row["group"].as_array().unwrap() {
            match algo_codec::decode_signed_txn_stream(&b64(m.as_str().unwrap())) {
                Ok(mut one) => group.append(&mut one),
                Err(_) => decodes = false,
            }
        }
        // A zero sender cannot cross the wire in go either (issue #2197).
        if !decodes {
            continue;
        }
        compared += 1;

        let want = match row["simulate_error"].as_str().unwrap() {
            "" => {
                let failure = if row["simulate_failure_is_verify_error"]
                    .as_bool()
                    .unwrap_or(false)
                {
                    verify_error
                } else {
                    row["simulate_failure"].as_str().unwrap()
                };
                let at: Vec<u64> = row["simulate_failed_at"]
                    .as_array()
                    .map(|a| a.iter().map(|v| v.as_u64().unwrap()).collect())
                    .unwrap_or_default();
                format!("failure at {at:?}: {failure}")
            }
            request => format!("request error: {request}"),
        };

        let mut state = state(&o);
        let got = match Simulator::new(&mut state).simulate(SimulationRequest {
            txn_groups: vec![group],
            ..Default::default()
        }) {
            Err(SimulatorError::InvalidRequest(e)) => format!("request error: {}", e.message),
            Err(e) => format!("other error: {e}"),
            Ok(result) => {
                let g = &result.txn_groups[0];
                let at: Vec<u64> = g
                    .failed_at
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|i| i as u64)
                    .collect();
                format!(
                    "failure at {at:?}: {}",
                    algo_validate::mask_heartbeat_pointer(
                        g.failure_message.as_deref().unwrap_or_default()
                    )
                )
            }
        };
        if got != want {
            mismatches.push(format!("{name}: {}", first_difference(&want, &got)));
        }
    }
    assert!(
        compared > 150,
        "the oracle has the rejected rows ({compared})"
    );
    assert!(
        mismatches.is_empty(),
        "{} simulate verdict(s) differ from go v5.0.5:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
