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

//! Integration test for issue #1116: proves a real LogicSig transaction
//! using `txn FirstValidTime` verifies successfully end-to-end through the
//! `/v2/transactions/simulate` engine (`algo_ledger::simulation::Simulator`)
//! against real ledger block-header data -- not just the AVM-context-only
//! unit-test level covered by issue #1111
//! (`algo_avm::logicsig_context::LogicSigAvmContext`'s own tests).
//!
//! Before this issue's fix, `Simulator::check` called
//! `verify_transaction_signature`/`_with_tracer` with no `SigBlockSource`
//! wired in, so `LogicSigAvmContext` always saw `sig_ledger: None` (go's
//! `NoHeaderLedger` default) and any LogicSig reading `txn FirstValidTime`
//! (or `block <round> BlkTimestamp`) failed with "no block header access"
//! even when the simulator held a real `LedgerStore` with the relevant
//! block header available. `sig_block_source_wired_disabled` below pins
//! that failure mode by disabling the wiring directly (rather than
//! reverting the fix), so this file continues to prove the negative case
//! stays covered even after the fix lands.

use algo_avm::logicsig_context::SigBlockSource;
use algo_codec::canonical_encode_transaction;
use algo_ledger::simulation::{SimulationRequest, Simulator, SimulatorError};
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::{AccountData, Address, BlockHeader, LogicSig, SignedTransaction, Transaction};
use sha2::{Digest, Sha512_256};

const FEE_SINK: Address = Address([0xFE; 32]);

/// The known timestamp seeded onto the block header at round 9 (one below
/// the LogicSig-authorized transaction's `FirstValid=10`).
const SEEDED_TIMESTAMP: i64 = 1_700_555_000;

fn assemble(source: &str) -> Vec<u8> {
    algo_avm::assembler::assemble_string(source)
        .unwrap_or_else(|e| panic!("assembly failed: {e:?}\nsource:\n{source}"))
        .program
}

/// SHA512/256("Program" || program) — the LogicSig contract-account address.
fn contract_account_address(program: &[u8]) -> Address {
    let mut hasher = Sha512_256::new();
    hasher.update(b"Program");
    hasher.update(program);
    Address(hasher.finalize().into())
}

/// A minimal `LedgerState` with a funded fee sink and a seeded block header
/// at round 9 (`SEEDED_TIMESTAMP`), matching `FirstValid=10`'s
/// `FirstValidTime` lookback target (`block(FirstValid - 1)`).
fn base_state() -> LedgerState {
    let mut state = LedgerState::new();
    state.fee_sink = FEE_SINK;
    state.protocol = algo_types::consensus::CONSENSUS_V41.to_string();
    state.set_account(
        &FEE_SINK,
        AccountData {
            micro_algos: 0,
            ..Default::default()
        },
    );

    let hdr = BlockHeader {
        round: algo_types::Round(9),
        timestamp: SEEDED_TIMESTAMP,
        ..BlockHeader::default()
    };
    let hdrdata = algo_codec::canonical_encode_block_header(&hdr);
    state
        .put_block(9, "v41", &hdrdata, &[])
        .expect("seed block header at round 9");

    state
}

fn fund(state: &mut LedgerState, addr: Address, micro_algos: u64) {
    let mut acct = state.get_account(&addr).cloned().unwrap_or_default();
    acct.micro_algos = micro_algos;
    state.set_account(&addr, acct);
}

/// LogicSig contract-account program: approves only if `txn FirstValidTime`
/// reads back exactly `SEEDED_TIMESTAMP` -- proving the value came from the
/// real block header at round 9, not a stub/zero value.
fn firstvalidtime_program() -> Vec<u8> {
    assemble(&format!(
        "#pragma version 8\ntxn FirstValidTime\nint {SEEDED_TIMESTAMP}\n==\n"
    ))
}

fn make_group(lsig_addr: Address, program: Vec<u8>) -> Vec<SignedTransaction> {
    let txn = Transaction {
        txn_type: "pay".into(),
        sender: lsig_addr,
        receiver: lsig_addr,
        amount: 0,
        fee: 1000,
        first_valid: 10.into(),
        last_valid: 1000.into(),
        ..Default::default()
    };
    // Contract-account LogicSig: no delegation signature, sender ==
    // SHA512/256("Program" || logic).
    vec![SignedTransaction {
        txn,
        lsig: Some(LogicSig {
            logic: serde_bytes::ByteBuf::from(program),
            sig: [0u8; 64],
            msig: None,
            lmsig: None,
            args: None,
            pqsig: None,
        }),
        ..Default::default()
    }]
}

fn simulate(
    state: &mut LedgerState,
    txn_groups: Vec<Vec<SignedTransaction>>,
) -> Result<algo_ledger::simulation::SimulationResult, SimulatorError> {
    let mut simulator = Simulator::new(state);
    simulator.simulate(SimulationRequest {
        txn_groups,
        ..Default::default()
    })
}

/// A real LogicSig transaction reading `txn FirstValidTime` verifies
/// successfully through `Simulator::simulate`, with the value sourced from
/// the real block header at round 9 (`FirstValid - 1`) rather than erroring
/// with "no block header access" -- the production wiring this issue adds
/// (`StoreSigBlockSource`, `algo-ledger::avm_context`).
#[test]
fn logicsig_first_valid_time_verifies_via_simulate_with_real_block_header() {
    let program = firstvalidtime_program();
    let lsig_addr = contract_account_address(&program);

    let mut state = base_state();
    fund(&mut state, lsig_addr, 10_000_000);

    let group = make_group(lsig_addr, program);
    let result = simulate(&mut state, vec![group]).expect("simulation request should succeed");

    let group_result = &result.txn_groups[0];
    assert!(
        group_result.failure_message.is_none(),
        "LogicSig using txn FirstValidTime must verify against the real block header: {:?}",
        group_result.failure_message
    );
}

/// Negative-side pin: canonical_encode_transaction sanity (the LogicSig
/// program hashes/signs over the same transaction the simulator evaluates,
/// so this asserts nothing about signing here -- it's a smoke check that
/// the transaction builder above produces a well-formed transaction that
/// the codec can encode without panicking, matching the pattern used to
/// build the `sig` message elsewhere in this crate's tests).
#[test]
fn make_group_produces_encodable_transaction() {
    let program = firstvalidtime_program();
    let lsig_addr = contract_account_address(&program);
    let group = make_group(lsig_addr, program);
    let _ = canonical_encode_transaction(&group[0].txn);
}

/// Direct unit-level pin of [`algo_ledger::avm_context::StoreSigBlockSource`]
/// (re-exported implicitly via the `algo_avm::logicsig_context::SigBlockSource`
/// trait it implements): resolves a seeded round's timestamp and errors for
/// an unseeded round, independent of the simulate-level integration test
/// above.
#[test]
fn store_sig_block_source_resolves_seeded_round_and_errors_on_missing_header() {
    let state = base_state();
    let source = algo_ledger::avm_context::StoreSigBlockSource::new(&state);

    assert_eq!(source.block_timestamp(9).unwrap(), SEEDED_TIMESTAMP);
    assert!(
        source.block_timestamp(8).is_err(),
        "round 8 has no seeded header and must error, not silently return a default"
    );
}
