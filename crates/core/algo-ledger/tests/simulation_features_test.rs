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

//! Integration tests for simulation request features (issue #216):
//!
//! - `extra_opcode_budget` validation against `MAX_EXTRA_OPCODE_BUDGET`
//! - `fix_signers` rekey correction and `fixed_signer` reporting
//! - `allow_more_logging` AVM log-limit overrides
//! - `allow_unnamed_resources` unnamed-resource tracking

use std::collections::BTreeMap;

use algo_ledger::simulation::{
    SimulationRequest, Simulator, SimulatorError, LOG_BYTES_LIMIT, MAX_EXTRA_OPCODE_BUDGET,
    SIMULATION_MAX_LOG_CALLS,
};
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::{
    AccountData, Address, AppParams, AssetParams, AssetParamsRecord, SignedTransaction,
    StateSchema, Transaction,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FEE_SINK: Address = Address([0xFE; 32]);

/// Build a minimal `LedgerState` with a funded sender and fee sink.
fn setup_state(sender: Address) -> LedgerState {
    let mut state = LedgerState::new();
    state.fee_sink = FEE_SINK;
    state.protocol = algo_types::consensus::CONSENSUS_V41.to_string();

    state.set_account(
        &sender,
        AccountData {
            micro_algos: 10_000_000,
            ..Default::default()
        },
    );
    state.set_account(
        &FEE_SINK,
        AccountData {
            micro_algos: 0,
            ..Default::default()
        },
    );
    state
}

/// Register an app with the given approval program.
fn register_app(state: &mut LedgerState, creator: Address, app_id: u64, approval: Vec<u8>) {
    let app_params = AppParams {
        creator,
        approval_program: approval,
        clear_state_program: vec![0x06, 0x81, 0x01, 0x43], // v6: pushint 1; return
        global_state: BTreeMap::new(),
        local_state_schema: StateSchema::default(),
        global_state_schema: StateSchema::default(),
        extra_program_pages: 0,
        ..Default::default()
    };
    state.set_app_params(app_id, app_params);
    // Mark the creator as having created an app.
    let mut acct = state.get_account(&creator).cloned().unwrap_or_default();
    acct.total_created_apps += 1;
    state.set_account(&creator, acct);
}

/// Create an unsigned app-call transaction.
fn make_appl_txn(sender: Address, app_id: u64) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: "appl".into(),
            sender,
            fee: 1000,
            first_valid: 0.into(),
            last_valid: 1000.into(),
            application_id: app_id,
            on_completion: 0, // NoOp
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Create an unsigned zero-amount self-payment.
fn make_pay_txn(sender: Address) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: "pay".into(),
            sender,
            receiver: sender,
            amount: 0,
            fee: 1000,
            first_valid: 0.into(),
            last_valid: 1000.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// v6 program that logs `count` empty byte strings then approves.
fn logging_program(count: usize) -> Vec<u8> {
    let mut p = vec![0x06]; // version 6
    for _ in 0..count {
        p.extend_from_slice(&[0x80, 0x00]); // pushbytes ""
        p.push(0xb0); // log
    }
    p.extend_from_slice(&[0x81, 0x01, 0x43]); // pushint 1; return
    p
}

/// v6 program that logs `count` byte strings of `size` bytes each, then
/// approves.
fn logging_program_sized(count: usize, size: usize) -> Vec<u8> {
    let mut p = vec![0x06];
    for _ in 0..count {
        p.push(0x80); // pushbytes
                      // varint length
        let mut n = size;
        loop {
            let mut b = (n & 0x7f) as u8;
            n >>= 7;
            if n != 0 {
                b |= 0x80;
            }
            p.push(b);
            if n == 0 {
                break;
            }
        }
        p.extend(std::iter::repeat(0xAB).take(size));
        p.push(0xb0); // log
    }
    p.extend_from_slice(&[0x81, 0x01, 0x43]);
    p
}

fn simulate(
    state: &mut LedgerState,
    request: SimulationRequest,
) -> Result<algo_ledger::simulation::SimulationResult, SimulatorError> {
    let mut simulator = Simulator::new(state);
    simulator.simulate(request)
}

// ---------------------------------------------------------------------------
// extra_opcode_budget
// ---------------------------------------------------------------------------

#[test]
fn extra_opcode_budget_over_limit_rejected() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, vec![0x06, 0x81, 0x01, 0x43]);

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        extra_opcode_budget: MAX_EXTRA_OPCODE_BUDGET + 1,
        ..Default::default()
    };

    let err = simulate(&mut state, request).expect_err("over-limit budget must be rejected");
    match err {
        SimulatorError::InvalidRequest(e) => {
            assert_eq!(
                e.message,
                format!(
                    "extra budget {} > simulation extra budget limit {}",
                    MAX_EXTRA_OPCODE_BUDGET + 1,
                    MAX_EXTRA_OPCODE_BUDGET
                )
            );
        }
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

#[test]
fn extra_opcode_budget_at_limit_accepted() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, vec![0x06, 0x81, 0x01, 0x43]);

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        extra_opcode_budget: MAX_EXTRA_OPCODE_BUDGET,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("at-limit budget must be accepted");
    let group = &result.txn_groups[0];
    assert!(group.failure_message.is_none());
    assert_eq!(group.app_budget_added, 700 + MAX_EXTRA_OPCODE_BUDGET as u64);
    assert_eq!(
        result.eval_overrides.extra_opcode_budget,
        MAX_EXTRA_OPCODE_BUDGET
    );
}

/// v6 program that runs `reps` iterations of `int 1; pop` (cost 2 each),
/// then `int 1` to approve (cost 1) -- an unconditionally expensive
/// approval program with a precisely-controllable total opcode cost of
/// `2 * reps + 1`.
fn expensive_program(reps: usize) -> Vec<u8> {
    let mut source = String::from("#pragma version 6\n");
    for _ in 0..reps {
        source.push_str("int 1\npop\n");
    }
    source.push_str("int 1\n");
    algo_avm::assembler::assemble_string(&source)
        .expect("expensive_program must assemble")
        .program
}

/// go: `TestAppCallWithExtraBudgetReturningPC`
/// (`ledger/simulation/simulation_eval_test.go`) runs a two-app-call group
/// with `ExtraOpcodeBudget` and PC-trace both enabled, and checks that each
/// transaction's own opcode PC trace is reported correctly even though the
/// group's opcode budget is shared/pooled across transactions. algod-rust's
/// extra-budget accounting (`extra_opcode_budget_at_limit_accepted`) and its
/// PC tracing (`simulation_trace_test.rs`) are each tested individually but
/// not together on a multi-transaction group -- this closes that gap (phase17
/// `parity_ledger_sim.md`, `TestAppCallWithExtraBudgetReturningPC`).
#[test]
fn extra_opcode_budget_with_trace_reports_per_txn_pc_trace() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);

    // Cheap app: costs 1 opcode ("int 1").
    register_app(&mut state, sender, 100, expensive_program(0));
    // Expensive app: 700 reps of `int 1; pop` + a final `int 1` = cost 1402.
    // Alone this exceeds the default per-app-call budget of 700, so it can
    // only succeed by drawing on the group's pooled/extra budget.
    register_app(&mut state, sender, 200, expensive_program(700));

    let extra_opcode_budget = 100;
    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100), make_appl_txn(sender, 200)]],
        allow_empty_signatures: true,
        extra_opcode_budget,
        trace_config: algo_ledger::simulation::ExecTraceConfig {
            enable: true,
            stack: false,
            scratch: false,
            state: false,
        },
        ..Default::default()
    };

    let mut simulator = Simulator::new_with_developer_api(&mut state);
    let result = simulator
        .simulate(request)
        .expect("group must succeed with the pooled + extra budget");

    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group should succeed: {:?}",
        group.failure_message
    );
    assert_eq!(group.txn_results.len(), 2);
    assert_eq!(
        result.eval_overrides.extra_opcode_budget,
        extra_opcode_budget
    );
    // Total budget made available to the group: 700 per app call + extra.
    assert_eq!(group.app_budget_added, 700 * 2 + extra_opcode_budget as u64);
    assert_eq!(group.txn_results[0].app_budget_consumed, 1);
    // 700 reps of `int 1; pop` + a final `int 1`: the assembler hoists the
    // repeated `1` literal into an `intcblock` (cost 1) once it's reused
    // this many times, so the total is `2*700 + 2` = 1402, not the naive
    // `2*700 + 1`.
    assert_eq!(group.txn_results[1].app_budget_consumed, 1402);
    assert_eq!(
        group.app_budget_consumed,
        group.txn_results[0].app_budget_consumed + group.txn_results[1].app_budget_consumed
    );

    // Each transaction's own PC trace should be independently present and
    // correctly sized, regardless of the other transaction's budget draw.
    let cheap_trace = group.txn_results[0]
        .trace
        .as_ref()
        .expect("cheap txn should have a trace")
        .approval_program_trace
        .as_ref()
        .expect("cheap txn should have an approval program trace");
    assert_eq!(cheap_trace.opcodes.len(), 1, "one `int 1` opcode");
    assert_eq!(cheap_trace.opcodes[0].pc, 0);

    let expensive_trace = group.txn_results[1]
        .trace
        .as_ref()
        .expect("expensive txn should have a trace")
        .approval_program_trace
        .as_ref()
        .expect("expensive txn should have an approval program trace");
    assert_eq!(expensive_trace.opcodes.len(), 1402);
    // PCs are monotonically increasing byte offsets into the program.
    assert_eq!(expensive_trace.opcodes[0].pc, 0);
    assert!(
        expensive_trace
            .opcodes
            .windows(2)
            .all(|w| w[1].pc > w[0].pc),
        "PC trace must be strictly increasing for a branch-free program"
    );
}

/// go: `TestAppCallWithExtraBudgetOverBudget`
/// (`ledger/simulation/simulation_eval_test.go`) adds a small amount of
/// `ExtraOpcodeBudget` to a two-app-call group -- enough to matter, but not
/// enough to cover the group's total opcode cost -- and checks the group
/// still fails with go's "dynamic cost budget exceeded" message while the
/// per-transaction partial `AppBudgetConsumed`/`AppBudgetAdded` accounting
/// for the txn that ran out is still reported. algod-rust's AVM reports the
/// same condition with its own wording ("cost budget exceeded: budget is
/// {budget} after charging {cost}", `algo-avm/src/machine.rs`) rather than
/// go's exact string, so this asserts on the shared substring instead of a
/// byte-identical message (phase17 `parity_ledger_sim.md`,
/// `TestAppCallWithExtraBudgetOverBudget`).
#[test]
fn extra_opcode_budget_insufficient_still_fails_with_partial_accounting() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);

    // Cheap app: costs 1 opcode ("int 1").
    register_app(&mut state, sender, 100, expensive_program(0));
    // Expensive app: 703 reps of `int 1; pop` + a final `int 1`, well beyond
    // what the default pooled budget (1400) plus a small extra of 5 (1405)
    // can cover.
    register_app(&mut state, sender, 200, expensive_program(703));

    let extra_opcode_budget = 5;
    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100), make_appl_txn(sender, 200)]],
        allow_empty_signatures: true,
        extra_opcode_budget,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("request itself is well-formed");
    let group = &result.txn_groups[0];

    let failure_message = group
        .failure_message
        .as_deref()
        .expect("group must fail: insufficient extra budget");
    assert!(
        failure_message.contains("cost budget exceeded"),
        "expected a cost-budget-exceeded failure, got: {failure_message}"
    );
    assert_eq!(
        group.failed_at,
        Some(vec![1]),
        "the expensive (second) txn is the one that runs out of budget"
    );
    assert_eq!(
        result.eval_overrides.extra_opcode_budget,
        extra_opcode_budget
    );
    assert_eq!(group.app_budget_added, 700 * 2 + extra_opcode_budget as u64);
    // The cheap txn fully completes (cost 1); the expensive txn's reported
    // consumption is whatever it executed before running out, and together
    // they must self-consistently sum to the group total, without exceeding
    // what was made available.
    assert_eq!(group.txn_results[0].app_budget_consumed, 1);
    assert!(group.txn_results[1].app_budget_consumed > 0);
    assert_eq!(
        group.app_budget_consumed,
        group.txn_results[0].app_budget_consumed + group.txn_results[1].app_budget_consumed
    );
    // The group failed precisely because it ran the budget out, so the
    // reported consumption reaches (or, having charged the one opcode that
    // pushed it negative, slightly exceeds) what was made available.
    assert!(
        group.app_budget_consumed >= group.app_budget_added,
        "consumed ({}) should reach the available budget ({}) when the group fails on budget",
        group.app_budget_consumed,
        group.app_budget_added
    );
}

// ---------------------------------------------------------------------------
// allow_more_logging
// ---------------------------------------------------------------------------

#[test]
fn log_calls_over_default_limit_fail_without_allow_more_logging() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, logging_program(33));

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation returns a result");
    let group = &result.txn_groups[0];
    let msg = group
        .failure_message
        .as_ref()
        .expect("33 log calls must exceed the default 32-call limit");
    assert!(
        msg.contains("too many log calls in program. up to 32 is allowed"),
        "unexpected failure message: {msg}"
    );
}

#[test]
fn log_calls_at_default_limit_succeed() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, logging_program(32));

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    assert!(result.txn_groups[0].failure_message.is_none());
    // Without the flag, no log-limit overrides are reported.
    assert_eq!(result.eval_overrides.max_log_calls, None);
    assert_eq!(result.eval_overrides.max_log_size, None);
}

#[test]
fn allow_more_logging_raises_log_call_limit() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, logging_program(33));

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        allow_more_logging: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "33 log calls must succeed with allow_more_logging: {:?}",
        group.failure_message
    );
    assert_eq!(
        result.eval_overrides.max_log_calls,
        Some(SIMULATION_MAX_LOG_CALLS)
    );
    assert_eq!(result.eval_overrides.max_log_size, Some(LOG_BYTES_LIMIT));
}

#[test]
fn log_size_over_default_limit_fails_without_allow_more_logging() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);
    // 2 logs of 600 bytes each = 1200 bytes > 1024-byte default limit.
    register_app(&mut state, sender, 100, logging_program_sized(2, 600));

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation returns a result");
    let msg = result.txn_groups[0]
        .failure_message
        .as_ref()
        .expect("1200 logged bytes must exceed the 1024-byte default limit");
    assert!(
        msg.contains("program logs too large. 1200 bytes >  1024 bytes limit"),
        "unexpected failure message: {msg}"
    );
}

#[test]
fn allow_more_logging_raises_log_size_limit() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, logging_program_sized(2, 600));

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        allow_more_logging: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    assert!(
        result.txn_groups[0].failure_message.is_none(),
        "1200 logged bytes must succeed with allow_more_logging: {:?}",
        result.txn_groups[0].failure_message
    );
}

// ---------------------------------------------------------------------------
// fix_signers
// ---------------------------------------------------------------------------

#[test]
fn fix_signers_reports_ledger_auth_addr_for_unsigned_txn() {
    let sender = Address([0xAA; 32]);
    let auth = Address([0xBB; 32]);
    let mut state = setup_state(sender);

    // The sender is rekeyed to `auth` in the ledger.
    let mut acct = state.get_account(&sender).cloned().unwrap();
    acct.auth_addr = Some(auth);
    state.set_account(&sender, acct);

    let request = SimulationRequest {
        txn_groups: vec![vec![make_pay_txn(sender)]],
        allow_empty_signatures: true,
        fix_signers: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(group.failure_message.is_none());
    assert_eq!(
        group.txn_results[0].fixed_signer,
        Some(auth),
        "unsigned txn from a rekeyed sender must report the ledger auth addr"
    );
    assert!(result.eval_overrides.fix_signers);
}

#[test]
fn fix_signers_none_when_sender_not_rekeyed() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);

    let request = SimulationRequest {
        txn_groups: vec![vec![make_pay_txn(sender)]],
        allow_empty_signatures: true,
        fix_signers: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    assert_eq!(
        result.txn_groups[0].txn_results[0].fixed_signer, None,
        "a non-rekeyed sender needs no signer fix"
    );
}

#[test]
fn fix_signers_uses_static_rekey_from_earlier_txn() {
    let sender = Address([0xAA; 32]);
    let rekey_target = Address([0xCC; 32]);
    let mut state = setup_state(sender);

    // txn0 rekeys the sender to `rekey_target`; txn1 is a later unsigned
    // payment from the same sender, so its signer must be fixed to the
    // static-rekey target.
    let mut txn0 = make_pay_txn(sender);
    txn0.txn.rekey_to = Some(rekey_target);
    let txn1 = make_pay_txn(sender);

    let request = SimulationRequest {
        txn_groups: vec![vec![txn0, txn1]],
        allow_empty_signatures: true,
        fix_signers: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );
    assert_eq!(
        group.txn_results[0].fixed_signer, None,
        "txn0 is signed by the (not yet rekeyed) sender"
    );
    assert_eq!(
        group.txn_results[1].fixed_signer,
        Some(rekey_target),
        "txn1 follows the static rekey from txn0"
    );
}

#[test]
fn fix_signers_fixes_txns_after_app_call() {
    let sender = Address([0xAA; 32]);
    let other = Address([0xDD; 32]);
    let auth = Address([0xEE; 32]);
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, vec![0x06, 0x81, 0x01, 0x43]);

    // `other` is rekeyed to `auth` in the ledger.
    state.set_account(
        &other,
        AccountData {
            micro_algos: 10_000_000,
            auth_addr: Some(auth),
            ..Default::default()
        },
    );

    // txn0 is an app call — the pre-evaluation fix pass stops there, so txn1
    // must be fixed by the post-app-call pass.
    let txns = vec![make_appl_txn(sender, 100), make_pay_txn(other)];

    let request = SimulationRequest {
        txn_groups: vec![txns],
        allow_empty_signatures: true,
        fix_signers: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );
    assert_eq!(group.txn_results[0].fixed_signer, None);
    assert_eq!(
        group.txn_results[1].fixed_signer,
        Some(auth),
        "txn after the app call must be fixed from the ledger auth addr"
    );
}

#[test]
fn fix_signers_requires_allow_empty_signatures() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);

    let request = SimulationRequest {
        txn_groups: vec![vec![make_pay_txn(sender)]],
        allow_empty_signatures: false,
        fix_signers: true,
        ..Default::default()
    };

    let err = simulate(&mut state, request).expect_err("must be rejected");
    match err {
        SimulatorError::InvalidRequest(e) => {
            assert_eq!(
                e.message,
                "FixSigners requires AllowEmptySignatures to be enabled"
            );
        }
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// allow_unnamed_resources
// ---------------------------------------------------------------------------

/// Program at the given AVM `version`: pushint asset_id; asset_params_get
/// AssetTotal; pop; pop; pushint 1; return.
///
/// The version matters for unnamed-resource reporting: group-level sharing
/// of unnamed accesses only kicks in at `SHARED_RESOURCES_VERSION` (9, see
/// `avm_context::LedgerAvmContext::global_sharing`'s doc comment) -- below
/// that, an access is recorded purely into the accessing top-level
/// transaction's own local pool, which this engine's only exposed
/// `unnamed_resources_accessed` field (group-level) never surfaces, exactly
/// like go-algorand's `groupResourceTracker.addAsset` never touches
/// `globalResources.Assets` pre-v9 (`ledger/simulation/resources.go`).
fn asset_params_program_v(asset_id: u64, version: u8) -> Vec<u8> {
    let mut p = vec![version, 0x81];
    // varint asset_id
    let mut n = asset_id;
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        p.push(b);
        if n == 0 {
            break;
        }
    }
    p.extend_from_slice(&[0x71, 0x00]); // asset_params_get AssetTotal
    p.extend_from_slice(&[0x48, 0x48]); // pop; pop
    p.extend_from_slice(&[0x81, 0x01, 0x43]); // pushint 1; return
    p
}

/// v9 program (at `SHARED_RESOURCES_VERSION`, so a genuinely unnamed access
/// is promoted to the group-level report -- see [`asset_params_program_v`]'s
/// doc comment): pushint asset_id; asset_params_get AssetTotal; pop; pop;
/// pushint 1; return.
fn asset_params_program(asset_id: u64) -> Vec<u8> {
    asset_params_program_v(asset_id, 9)
}

/// Program at the given AVM `version`: pushbytes <32-byte addr>; balance;
/// pop; pushint 1; return. See [`asset_params_program_v`]'s doc comment for
/// why the version matters to unnamed-resource reporting.
fn balance_program_v(addr: &Address, version: u8) -> Vec<u8> {
    let mut p = vec![version, 0x80, 32];
    p.extend_from_slice(&addr.0);
    p.push(0x60); // balance
    p.push(0x48); // pop
    p.extend_from_slice(&[0x81, 0x01, 0x43]);
    p
}

/// v9 program (at `SHARED_RESOURCES_VERSION`): pushbytes <32-byte addr>;
/// balance; pop; pushint 1; return.
fn balance_program(addr: &Address) -> Vec<u8> {
    balance_program_v(addr, 9)
}

/// v9 program: pushbytes <32-byte addr>; acct_params_get AcctAuthAddr; pop;
/// pop; pushint 1; return. Used to prove an unnamed account is tracked
/// correctly even when accessed only via `acct_params_get` (go's
/// `TestUnnamedResources` rekey scenario checks exactly this field), not
/// just `balance`.
fn acct_auth_addr_program(addr: &Address) -> Vec<u8> {
    let mut p = vec![0x09, 0x80, 32]; // version 9; pushbytes <addr>
    p.extend_from_slice(&addr.0);
    p.extend_from_slice(&[0x73, 0x02]); // acct_params_get AcctAuthAddr
    p.extend_from_slice(&[0x48, 0x48]); // pop; pop (value, exists)
    p.extend_from_slice(&[0x81, 0x01, 0x43]); // pushint 1; return
    p
}

/// v8 program: pushbytes "bk"; box_get; pop; pop; pushint 1; return.
fn box_get_program() -> Vec<u8> {
    let mut p = vec![0x08]; // version 8 (boxes need v8)
    p.extend_from_slice(&[0x80, 0x02, b'b', b'k']); // pushbytes "bk"
    p.push(0xbe); // box_get
    p.extend_from_slice(&[0x48, 0x48]); // pop; pop
    p.extend_from_slice(&[0x81, 0x01, 0x43]);
    p
}

#[test]
fn unnamed_asset_access_tracked_when_allowed() {
    let sender = Address([0xAA; 32]);
    let asset_id = 555;
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, asset_params_program(asset_id));
    state.set_asset_params(
        asset_id,
        AssetParamsRecord {
            params: AssetParams {
                total: 1000,
                ..Default::default()
            },
            creator: sender,
        },
    );

    // The asset is NOT in the txn's foreign-assets array.
    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        allow_unnamed_resources: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );
    let unnamed = group
        .unnamed_resources_accessed
        .as_ref()
        .expect("unnamed resources must be reported");
    assert!(
        unnamed.assets.contains(&asset_id),
        "asset {asset_id} accessed outside foreign arrays must be tracked: {unnamed:?}"
    );
    assert!(result.eval_overrides.allow_unnamed_resources);
}

#[test]
fn named_asset_access_not_tracked() {
    let sender = Address([0xAA; 32]);
    let asset_id = 555;
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, asset_params_program(asset_id));
    state.set_asset_params(
        asset_id,
        AssetParamsRecord {
            params: AssetParams {
                total: 1000,
                ..Default::default()
            },
            creator: sender,
        },
    );

    let mut txn = make_appl_txn(sender, 100);
    txn.txn.foreign_assets = Some(vec![asset_id]);

    let request = SimulationRequest {
        txn_groups: vec![vec![txn]],
        allow_empty_signatures: true,
        allow_unnamed_resources: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(group.failure_message.is_none());
    assert!(
        group.unnamed_resources_accessed.is_none(),
        "a named asset must not appear in unnamed resources: {:?}",
        group.unnamed_resources_accessed
    );
}

#[test]
fn unnamed_account_access_tracked_when_allowed() {
    let sender = Address([0xAA; 32]);
    let stranger = Address([0x77; 32]);
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, balance_program(&stranger));
    state.set_account(
        &stranger,
        AccountData {
            micro_algos: 424_242,
            ..Default::default()
        },
    );

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        allow_unnamed_resources: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );
    let unnamed = group
        .unnamed_resources_accessed
        .as_ref()
        .expect("unnamed resources must be reported");
    assert!(
        unnamed.accounts.contains(&stranger),
        "account accessed outside the accounts array must be tracked: {unnamed:?}"
    );
}

#[test]
fn sender_account_access_not_tracked() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, balance_program(&sender));

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        allow_unnamed_resources: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(group.failure_message.is_none());
    assert!(
        group.unnamed_resources_accessed.is_none(),
        "the sender is always named: {:?}",
        group.unnamed_resources_accessed
    );
}

#[test]
fn unnamed_box_access_fails_without_flag_and_tracked_with_flag() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, box_get_program());
    state.set_box(100, b"bk", b"boxval".to_vec());

    // Without the flag: box access without a box ref must fail.
    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        ..Default::default()
    };
    let result = simulate(&mut state, request).expect("simulation returns a result");
    assert!(
        result.txn_groups[0].failure_message.is_some(),
        "box access without a box ref must fail when unnamed resources are not allowed"
    );

    // With the flag: access succeeds and the box is tracked.
    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        allow_unnamed_resources: true,
        ..Default::default()
    };
    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "box access must succeed with allow_unnamed_resources: {:?}",
        group.failure_message
    );
    let unnamed = group
        .unnamed_resources_accessed
        .as_ref()
        .expect("unnamed resources must be reported");
    assert!(
        unnamed.boxes.contains(&(100, b"bk".to_vec())),
        "unnamed box must be tracked: {unnamed:?}"
    );
}

// ---------------------------------------------------------------------------
// Rekeyed-account access + pre-v9/v9+ version sweep (issue #1240)
//
// Ports the two remaining uncovered facets of go-algorand's
// `TestUnnamedResources` (`ledger/simulation/simulation_eval_test.go`,
// commit `1088a2aad`, `v3.18.0-stable`): a rekeyed account accessed via
// `acct_params_get AcctAuthAddr`, and the `ResourceTracker` shape
// transition at `SHARED_RESOURCES_VERSION` (9) -- below that version an
// unnamed access is recorded only into the accessing top-level
// transaction's own local pool (never surfaced by this engine's group-level
// `unnamed_resources_accessed`, per go's `groupResourceTracker.addAccount`
// never touching `globalResources.Accounts` pre-v9); at/above it, the
// access is shared group-wide and does appear in the group-level report.
// ---------------------------------------------------------------------------

#[test]
fn unnamed_rekeyed_account_access_tracked_when_allowed() {
    let sender = Address([0xAA; 32]);
    let stranger = Address([0x77; 32]);
    let auth = Address([0x55; 32]);
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, acct_auth_addr_program(&stranger));
    // The unnamed account is rekeyed to `auth` -- mirrors go's
    // `env.Rekey(otherAccount.Addr, otherAccountAuthAddr)`.
    state.set_account(
        &stranger,
        AccountData {
            micro_algos: 424_242,
            auth_addr: Some(auth),
            ..Default::default()
        },
    );

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        allow_unnamed_resources: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "acct_params_get AcctAuthAddr on a rekeyed, wholly unnamed account must succeed: {:?}",
        group.failure_message
    );
    let unnamed = group
        .unnamed_resources_accessed
        .as_ref()
        .expect("unnamed resources must be reported");
    assert!(
        unnamed.accounts.contains(&stranger),
        "a rekeyed account accessed only via acct_params_get must still be tracked as unnamed: {unnamed:?}"
    );
}

#[test]
fn unnamed_account_access_below_shared_resources_version_not_promoted_to_group_level() {
    let sender = Address([0xAA; 32]);
    let stranger = Address([0x77; 32]);
    let mut state = setup_state(sender);
    // v8: below SHARED_RESOURCES_VERSION (9).
    register_app(&mut state, sender, 100, balance_program_v(&stranger, 8));
    state.set_account(
        &stranger,
        AccountData {
            micro_algos: 424_242,
            ..Default::default()
        },
    );

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        allow_unnamed_resources: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );
    assert!(
        group.unnamed_resources_accessed.is_none(),
        "a below-SHARED_RESOURCES_VERSION unnamed access is local to its own \
         transaction and must not be promoted to the group-level report \
         (mirrors go's groupResourceTracker.addAccount never touching \
         globalResources.Accounts pre-v9): {:?}",
        group.unnamed_resources_accessed
    );
}

#[test]
fn unnamed_account_access_at_shared_resources_version_promoted_to_group_level() {
    let sender = Address([0xAA; 32]);
    let stranger = Address([0x77; 32]);
    let mut state = setup_state(sender);
    // v9: at SHARED_RESOURCES_VERSION.
    register_app(&mut state, sender, 100, balance_program_v(&stranger, 9));
    state.set_account(
        &stranger,
        AccountData {
            micro_algos: 424_242,
            ..Default::default()
        },
    );

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        allow_unnamed_resources: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );
    let unnamed = group
        .unnamed_resources_accessed
        .as_ref()
        .expect("unnamed resources must be reported at SHARED_RESOURCES_VERSION");
    assert!(
        unnamed.accounts.contains(&stranger),
        "an at-SHARED_RESOURCES_VERSION unnamed access is group-shared and \
         must appear in the group-level report: {unnamed:?}"
    );
}

#[test]
fn no_unnamed_resources_reported_when_flag_off() {
    let sender = Address([0xAA; 32]);
    let asset_id = 555;
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, asset_params_program(asset_id));
    state.set_asset_params(
        asset_id,
        AssetParamsRecord {
            params: AssetParams {
                total: 1000,
                ..Default::default()
            },
            creator: sender,
        },
    );

    let request = SimulationRequest {
        txn_groups: vec![vec![make_appl_txn(sender, 100)]],
        allow_empty_signatures: true,
        allow_unnamed_resources: false,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    assert!(result.txn_groups[0].unnamed_resources_accessed.is_none());
    assert!(!result.eval_overrides.allow_unnamed_resources);
}

// ---------------------------------------------------------------------------
// CheckTxnGroup screen (issue #628)
//
// go-algorand's `Simulator.check()` (ledger/simulation/simulator.go:179)
// always calls `verify.TxnGroupWithTracer`, which always runs
// `transactions.CheckTxnGroup` — independent of `AllowEmptySignatures`, which
// only relaxes signature verification, not this structural screen. A
// malformed group (unknown txn type, box index exceeding foreign apps, etc.)
// must be rejected during simulate's check phase exactly like real block
// validation, not silently accepted or left to fail later during AVM eval.
// ---------------------------------------------------------------------------

#[test]
fn simulate_rejects_unknown_txn_type() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);

    let mut bogus = make_pay_txn(sender);
    bogus.txn.txn_type = "bogus".into();

    let request = SimulationRequest {
        txn_groups: vec![vec![bogus]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let err = simulate(&mut state, request).expect_err("unknown txn type must be rejected");
    match err {
        SimulatorError::InvalidRequest(e) => {
            assert!(
                e.message.contains("unknown"),
                "expected an unknown-type rejection, got: {}",
                e.message
            );
        }
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

#[test]
fn simulate_rejects_box_index_exceeding_foreign_apps() {
    let sender = Address([0xAA; 32]);
    let mut state = setup_state(sender);
    register_app(&mut state, sender, 100, vec![0x06, 0x81, 0x01, 0x43]);

    let mut appl = make_appl_txn(sender, 100);
    appl.txn.boxes = Some(vec![algo_types::BoxRef {
        index: 1, // no foreign_apps present, so index 1 is out of range
        name: None,
    }]);

    let request = SimulationRequest {
        txn_groups: vec![vec![appl]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    // Caught by `wellFormed`'s own box-index/ForeignApps bound (issue #701),
    // which mirrors upstream's exact message capitalization ("tx.Boxes[i]
    // .Index ... Exceeds len(tx.ForeignApps)"). This is a `WellFormed`
    // failure attributable to a single transaction (go-algorand's
    // `txnBatchPrep` wraps it with a known `GroupIndex`), so -- like
    // TestInvalidTxGroup's incentive-pool-sender case (issue #974) -- it
    // surfaces as the group's `FailureMessage`/`FailedAt` on an otherwise
    // successful `Result`, not a hard request error.
    let result = simulate(&mut state, request).expect("simulation returns a result");
    let group = &result.txn_groups[0];
    let msg = group
        .failure_message
        .as_ref()
        .expect("out-of-range box index must fail the group");
    assert!(
        msg.to_lowercase().contains("box"),
        "expected a box-index rejection, got: {msg}"
    );
    assert_eq!(group.failed_at, Some(vec![0]));
}
