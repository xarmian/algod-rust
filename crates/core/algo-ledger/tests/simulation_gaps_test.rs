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

//! Ledger-simulation missing-test-gap closures (issue #974).
//!
//! Ports the go-algorand `ledger/simulation` scenarios identified by
//! `docs/phase17/parity_ledger_sim.md` as implemented-but-untested through
//! the simulate endpoint itself: PC/stack-trace combinations, uneven
//! initial-states coverage (local/box vs. global), signature-mode edge
//! cases, and several miscellaneous single-scenario gaps.
//!
//! Grouped by the issue's four themes; each test's doc comment names the
//! go-algorand test it ports (`ledger/simulation/simulation_eval_test.go`
//! unless noted) and explains any deliberate simplification versus the
//! upstream fixture.

use std::collections::BTreeMap;

use algo_codec::canonical_encode_transaction;
use algo_ledger::simulation::{
    ExecTraceConfig, SimulationRequest, SimulationResult, Simulator, SimulatorError,
};
use algo_ledger::{apply_transaction, ApplyContext, ApplyMode, LedgerState, LedgerStore};
use algo_types::{
    AccountData, Address, AppParams, BoxRef, LogicSig, Round, SignedTransaction, StateSchema,
    Transaction,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha512_256};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FEE_SINK: Address = Address([0xFE; 32]);

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

/// SHA512/256(program) — the program hash reported in exec traces.
fn program_hash(program: &[u8]) -> [u8; 32] {
    Sha512_256::digest(program).into()
}

/// Domain-separation prefix for the top-level transaction signing message.
const TX_PREFIX: &[u8] = b"TX";

fn tx_sign_message(txn: &Transaction) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(TX_PREFIX);
    msg.extend_from_slice(&canonical_encode_transaction(txn));
    msg
}

fn sign(txn: Transaction, key: &SigningKey) -> SignedTransaction {
    let sig = key.sign(&tx_sign_message(&txn));
    SignedTransaction {
        txn,
        sig: sig.to_bytes(),
        ..Default::default()
    }
}

/// A minimal `LedgerState` with a funded fee sink and no other accounts.
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
    state
}

fn fund(state: &mut LedgerState, addr: Address, micro_algos: u64) {
    let mut acct = state.get_account(&addr).cloned().unwrap_or_default();
    acct.micro_algos = micro_algos;
    state.set_account(&addr, acct);
}

#[allow(clippy::too_many_arguments)]
fn register_app(
    state: &mut LedgerState,
    creator: Address,
    app_id: u64,
    approval: Vec<u8>,
    clear: Vec<u8>,
    global_schema: StateSchema,
    local_schema: StateSchema,
) {
    let app_params = AppParams {
        creator,
        approval_program: approval,
        clear_state_program: clear,
        global_state: BTreeMap::new(),
        local_state_schema: local_schema,
        global_state_schema: global_schema,
        extra_program_pages: 0,
        ..Default::default()
    };
    state.set_app_params(app_id, app_params);
    let mut acct = state.get_account(&creator).cloned().unwrap_or_default();
    acct.total_created_apps += 1;
    state.set_account(&creator, acct);
}

/// Build an unsigned app-call transaction.
fn appl_txn(sender: Address, app_id: u64, on_completion: u64) -> Transaction {
    Transaction {
        txn_type: "appl".into(),
        sender,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        application_id: app_id,
        on_completion,
        ..Default::default()
    }
}

fn app_args(txn: &mut Transaction, args: &[&[u8]]) {
    txn.app_arguments = Some(
        args.iter()
            .map(|a| Some(serde_bytes::ByteBuf::from(a.to_vec())))
            .collect(),
    );
}

fn simulate(
    state: &mut LedgerState,
    request: SimulationRequest,
) -> Result<SimulationResult, SimulatorError> {
    let mut simulator = Simulator::new_with_developer_api(state);
    simulator.simulate(request)
}

/// Apply a transaction for real (not simulated) — used to build up
/// pre-simulation ledger state exactly like go's `env.Txn`/`env.CreateApp`
/// helpers, so "prepare" steps persist and only the transactions under test
/// go through `Simulator::simulate`.
fn apply_real(state: &mut LedgerState, stx: &SignedTransaction) {
    let ctx = {
        let mut c = ApplyContext::new_replay(0, FEE_SINK, 0);
        c.mode = ApplyMode::Execute;
        c
    };
    apply_transaction(state, stx, &ctx, 0).unwrap_or_else(|e| panic!("prepare txn failed: {e}"));
}

// ---------------------------------------------------------------------------
// Theme 1: PC/stack-trace combination gaps
// ---------------------------------------------------------------------------

/// Port of `TestMaxDepthAppWithPCTrace`: a multi-level recursive app-call
/// chain combined with PC-trace capture. Simplified from go's byte-for-byte
/// PC-array fixture (which pins an elaborate, hand-crafted
/// `maxDepthTealApproval` program that recreates a fresh app instance at
/// each recursion level, since go-algorand -- like this engine -- forbids a
/// literal app self-call) to a chain of three distinct, pre-existing apps
/// (100 -> 200 -> 300) that still exercises the same previously-uncovered
/// combination: PC-trace entries populated at every level of a multi-hop
/// inner-call chain, including inside nested `InnerTraces`, not just the
/// single level of inner call already covered by
/// `simulation_trace_inner_txn_spawned_inners`.
#[test]
fn max_depth_app_with_pc_trace() {
    let sender = Address([0xAA; 32]);
    let (app_a, app_b, app_c) = (100u64, 200u64, 300u64);
    let mut state = base_state();
    fund(&mut state, sender, 20_000_000);

    // v8 program: on create (ApplicationID==0), just approve. Otherwise call
    // `next_app` (an inner appl call carrying no args), then approve.
    let hop = |next_app: u64| {
        format!(
            "#pragma version 8
txn ApplicationID
bz end
itxn_begin
int appl
itxn_field TypeEnum
int {next_app}
itxn_field ApplicationID
itxn_submit
end:
int 1
"
        )
    };
    let leaf = "#pragma version 8\nint 1\n";
    let clear = assemble("#pragma version 8\nint 1\n");

    let approval_a = assemble(&hop(app_b));
    let approval_b = assemble(&hop(app_c));
    let approval_c = assemble(leaf);

    for (id, approval, next) in [
        (app_a, approval_a.clone(), Some(app_b)),
        (app_b, approval_b.clone(), Some(app_c)),
        (app_c, approval_c.clone(), None),
    ] {
        register_app(
            &mut state,
            sender,
            id,
            approval,
            clear.clone(),
            StateSchema::default(),
            StateSchema::default(),
        );
        fund(
            &mut state,
            Address(algo_ledger::avm_context::app_address(id)),
            2_000_000,
        );
        let _ = next;
    }

    let mut txn = appl_txn(sender, app_a, 0);
    txn.foreign_apps = Some(vec![app_b, app_c]);
    txn.fee = 5000; // covers the chained inner-txn fees

    let request = SimulationRequest {
        txn_groups: vec![vec![SignedTransaction {
            txn,
            ..Default::default()
        }]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "chained inner-call must succeed: {:?}",
        group.failure_message
    );

    let trace = group.txn_results[0].trace.as_ref().expect("trace present");
    let outer_approval = trace
        .approval_program_trace
        .as_ref()
        .expect("outer approval trace present");
    assert!(
        !outer_approval.opcodes.is_empty(),
        "outer call must have a nonempty PC trace"
    );
    assert_eq!(trace.approval_program_hash, Some(program_hash(&approval_a)));

    // app_a calls app_b — exactly one nested inner trace at the top level.
    assert_eq!(trace.inner_traces.len(), 1, "app_a spawns one inner call");
    let inner_b = &trace.inner_traces[0];
    let inner_b_approval = inner_b
        .approval_program_trace
        .as_ref()
        .expect("app_b's inner call must carry an approval PC trace");
    assert!(!inner_b_approval.opcodes.is_empty());
    assert_eq!(
        inner_b.approval_program_hash,
        Some(program_hash(&approval_b))
    );

    // app_b calls app_c.
    assert_eq!(
        inner_b.inner_traces.len(),
        1,
        "app_b spawns one further inner call"
    );
    let inner_c = &inner_b.inner_traces[0];
    let inner_c_approval = inner_c
        .approval_program_trace
        .as_ref()
        .expect("app_c's inner call must still carry an approval PC trace");
    assert!(!inner_c_approval.opcodes.is_empty());
    // app_c is a leaf: no further recursion.
    assert!(inner_c.inner_traces.is_empty());
}

/// Port of `TestLogicSigPCandStackExposure`: a LogicSig-authorized payment
/// funds the LogicSig's contract account, which then issues an app call
/// authorized by that same LogicSig, with PC+stack tracing enabled. Proves
/// the exec trace captures both the `LogicSigTrace` (from signature
/// verification) and the app call's `ApprovalProgramTrace` in the same
/// simulated group, with correct program hashes -- the exact LogicSig +
/// approval multi-segment combination `simulation_trace_with_stack` (a
/// single-segment case) doesn't cover.
#[test]
fn logicsig_pc_and_stack_exposure() {
    let logicsig_program = assemble("#pragma version 8\nbyte \"a\"\nkeccak256\npop\nint 1\n");
    let lsig_addr = contract_account_address(&logicsig_program);
    let sender = Address([0xAA; 32]);
    let app_id = 1002u64;

    let mut state = base_state();
    fund(&mut state, sender, 20_000_000);

    let approval_src = "#pragma version 8\nbyte \"hello\"\nlog\nint 1\n";
    let approval = assemble(approval_src);
    let clear = assemble("#pragma version 8\nint 1\n");
    register_app(
        &mut state,
        sender,
        app_id,
        approval.clone(),
        clear,
        StateSchema::default(),
        StateSchema::default(),
    );

    let pay = Transaction {
        txn_type: "pay".into(),
        sender,
        receiver: lsig_addr,
        amount: 1_000_000,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        ..Default::default()
    };
    let mut appl = appl_txn(lsig_addr, app_id, 0);
    appl.fee = 1000;
    let appl_stx = SignedTransaction {
        txn: appl,
        lsig: Some(LogicSig {
            logic: serde_bytes::ByteBuf::from(logicsig_program.clone()),
            sig: [0u8; 64],
            msig: None,
            lmsig: None,
            args: None,
            pqsig: None,
        }),
        ..Default::default()
    };

    let request = SimulationRequest {
        txn_groups: vec![vec![
            SignedTransaction {
                txn: pay,
                ..Default::default()
            },
            appl_stx,
        ]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            stack: true,
            state: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );

    let trace = group.txn_results[1]
        .trace
        .as_ref()
        .expect("trace present on the app-call txn");

    let approval_trace = trace
        .approval_program_trace
        .as_ref()
        .expect("approval trace present");
    assert!(!approval_trace.opcodes.is_empty());
    assert_eq!(trace.approval_program_hash, Some(program_hash(&approval)));

    let lsig_trace = trace
        .logicsig_trace
        .as_ref()
        .expect("logicsig trace present");
    assert!(!lsig_trace.opcodes.is_empty());
    // The keccak256 opcode pops one value and pushes one 32-byte digest.
    let keccak_unit = lsig_trace
        .opcodes
        .iter()
        .find(|u| u.stack_pop_count == 1 && !u.stack_additions.is_empty())
        .expect("keccak256 opcode traced with a stack pop+push");
    assert_eq!(keccak_unit.stack_additions.len(), 1);
    assert_eq!(trace.logicsig_hash, Some(program_hash(&logicsig_program)));
    assert!(
        group.txn_results[1].logicsig_budget_consumed > 0,
        "logicsig budget consumed must be recorded"
    );
}

/// Port of `TestInvalidLogicSigPCandStack`: a LogicSig that legitimately
/// executes (accumulating a stack trace) but ultimately rejects the
/// transaction (top-of-stack zero after an underflowing subtraction). Its
/// `LogicSigTrace` must still be captured up to the rejection point, and the
/// group must report a recoverable `FailureMessage`/`FailedAt` rather than a
/// hard simulate error -- go-algorand attributes a rejecting LogicSig to its
/// transaction's `GroupIndex` (`TxGroupErrorReasonLogicSigFailed`), unlike a
/// genuine cryptographic signature failure.
#[test]
fn invalid_logicsig_pc_and_stack() {
    // `byte "a"; keccak256; pop; int 0; int 1; -` underflows (0 - 1 on a
    // uint64 stack), which the AVM treats as a program error, not merely a
    // reject -- still surfaced as a recoverable, per-transaction LogicSig
    // failure.
    let logicsig_program =
        assemble("#pragma version 8\nbyte \"a\"\nkeccak256\npop\nint 0\nint 1\n-\n");
    let lsig_addr = contract_account_address(&logicsig_program);
    let sender = Address([0xAA; 32]);
    let app_id = 1002u64;

    let mut state = base_state();
    fund(&mut state, sender, 20_000_000);

    let approval = assemble("#pragma version 8\nbyte \"hello\"\nlog\nint 1\n");
    let clear = assemble("#pragma version 8\nint 1\n");
    register_app(
        &mut state,
        sender,
        app_id,
        approval,
        clear,
        StateSchema::default(),
        StateSchema::default(),
    );

    let pay = Transaction {
        txn_type: "pay".into(),
        sender,
        receiver: lsig_addr,
        amount: 1_000_000,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        ..Default::default()
    };
    let mut appl = appl_txn(lsig_addr, app_id, 0);
    appl.fee = 1000;
    let appl_stx = SignedTransaction {
        txn: appl,
        lsig: Some(LogicSig {
            logic: serde_bytes::ByteBuf::from(logicsig_program.clone()),
            sig: [0u8; 64],
            msig: None,
            lmsig: None,
            args: None,
            pqsig: None,
        }),
        ..Default::default()
    };

    let request = SimulationRequest {
        txn_groups: vec![vec![
            SignedTransaction {
                txn: pay,
                ..Default::default()
            },
            appl_stx,
        ]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            stack: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let result =
        simulate(&mut state, request).expect("simulate must return a result, not a hard error");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_some(),
        "the rejecting LogicSig must fail the group"
    );
    assert_eq!(group.failed_at, Some(vec![1]));

    let trace = group.txn_results[1]
        .trace
        .as_ref()
        .expect("a partial trace must still be captured for the rejecting txn");
    let lsig_trace = trace
        .logicsig_trace
        .as_ref()
        .expect("logicsig trace present up to the point of rejection");
    assert!(!lsig_trace.opcodes.is_empty());
    assert_eq!(trace.logicsig_hash, Some(program_hash(&logicsig_program)));
    // The app call itself never ran.
    assert!(trace.approval_program_trace.is_none());
}

/// Port of `TestInvalidApp`: a LogicSig authorizes the sender successfully
/// (its own trace is captured), but the subsequent app call's approval
/// program rejects (`int 0`). Proves the combination of a *passing*
/// LogicSig trace alongside a *failing* approval-program trace in the same
/// simulated transaction, with PC+stack tracing enabled -- distinct from
/// `invalid_logicsig_pc_and_stack` above, where the LogicSig itself is what
/// fails.
#[test]
fn invalid_app_with_passing_logicsig_and_trace() {
    let logicsig_program = assemble("#pragma version 8\nbyte \"a\"\nkeccak256\npop\nint 1\n");
    let lsig_addr = contract_account_address(&logicsig_program);
    let sender = Address([0xAA; 32]);
    let app_id = 1002u64;

    let mut state = base_state();
    fund(&mut state, sender, 20_000_000);

    // Rejects unconditionally (`int 0`).
    let approval = assemble("#pragma version 8\nbyte \"hello\"\nlog\nint 0\n");
    let clear = assemble("#pragma version 8\nint 1\n");
    register_app(
        &mut state,
        sender,
        app_id,
        approval.clone(),
        clear,
        StateSchema::default(),
        StateSchema::default(),
    );

    let pay = Transaction {
        txn_type: "pay".into(),
        sender,
        receiver: lsig_addr,
        amount: 1_000_000,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        ..Default::default()
    };
    let mut appl = appl_txn(lsig_addr, app_id, 0);
    appl.fee = 1000;
    let appl_stx = SignedTransaction {
        txn: appl,
        lsig: Some(LogicSig {
            logic: serde_bytes::ByteBuf::from(logicsig_program.clone()),
            sig: [0u8; 64],
            msig: None,
            lmsig: None,
            args: None,
            pqsig: None,
        }),
        ..Default::default()
    };

    let request = SimulationRequest {
        txn_groups: vec![vec![
            SignedTransaction {
                txn: pay,
                ..Default::default()
            },
            appl_stx,
        ]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            stack: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulate must return a result");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_some(),
        "the rejecting app call must fail the group"
    );
    assert_eq!(group.failed_at, Some(vec![1]));

    let trace = group.txn_results[1].trace.as_ref().expect("trace present");

    // The LogicSig passed -- its trace is fully captured.
    let lsig_trace = trace
        .logicsig_trace
        .as_ref()
        .expect("logicsig trace present (it passed verification)");
    assert!(!lsig_trace.opcodes.is_empty());
    assert_eq!(trace.logicsig_hash, Some(program_hash(&logicsig_program)));

    // The approval program ran (and rejected) -- its trace up to the
    // rejecting opcode is still captured.
    let approval_trace = trace
        .approval_program_trace
        .as_ref()
        .expect("approval trace present up to rejection");
    assert!(!approval_trace.opcodes.is_empty());
    assert_eq!(trace.approval_program_hash, Some(program_hash(&approval)));
}

/// Port of `TestFrameBuryDigStackTrace`: a subroutine using `proto`,
/// `frame_dig`/`frame_bury`, `dig`/`cover`/`uncover`, `dupn`/`popn`/`bury`,
/// `pushbytess`/`pushints`, and `store`/`load`/`stores` (all fp-version/v8
/// stack-manipulation opcodes) computes `arg * 3`, with stack+scratch
/// tracing enabled. No existing test exercises a stack trace over this
/// opcode family.
#[test]
fn frame_bury_dig_stack_trace() {
    let sender = Address([0xAA; 32]);
    let app_id = 1001u64;
    let mut state = base_state();
    fund(&mut state, sender, 20_000_000);

    let src = "#pragma version 8
txn ApplicationID
bz end

txn NumAppArgs
int 1
==
assert

txn ApplicationArgs 0
btoi
callsub subroutine_manipulating_stack
itob
log
b end

subroutine_manipulating_stack:
  proto 1 1
  int 0
  dup
  dupn 4
  frame_dig -1
  frame_bury 0
  dig 5
  cover 5
  frame_dig 0
  frame_dig 1
  +
  bury 7
  popn 5
  uncover 1
  swap
  +
  pushbytess \"1!\" \"5!\"
  pushints 0 2 1 1 5 18446744073709551615
  store 1
  load 1
  stores
  load 1
  store 1
  retsub

end:
  int 1
";
    let approval = assemble(src);
    let clear = assemble("#pragma version 8\nint 1\n");
    register_app(
        &mut state,
        sender,
        app_id,
        approval.clone(),
        clear,
        StateSchema::default(),
        StateSchema::default(),
    );

    let mut txn = appl_txn(sender, app_id, 0);
    app_args(&mut txn, &[&[10u8]]);

    let request = SimulationRequest {
        txn_groups: vec![vec![SignedTransaction {
            txn,
            ..Default::default()
        }]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            stack: true,
            scratch: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );

    // arg (10) * 3 = 30, logged as an 8-byte big-endian integer.
    let apply_data = group.txn_results[0]
        .apply_data
        .as_ref()
        .expect("apply data present");
    let eval_delta_val = apply_data.eval_delta.as_ref().expect("eval delta present");
    let eval_delta = algo_ledger::parse_eval_delta(eval_delta_val).expect("eval delta parses");
    let logs = eval_delta.logs.expect("logs present");
    assert_eq!(logs.len(), 1);
    assert_eq!(
        u64::from_be_bytes(logs[0].as_slice().try_into().unwrap()),
        30
    );

    let trace = group.txn_results[0]
        .trace
        .as_ref()
        .expect("trace present")
        .approval_program_trace
        .as_ref()
        .expect("approval trace present");
    assert!(
        trace.opcodes.len() > 10,
        "the frame_dig/frame_bury/dupn/popn subroutine should trace many opcodes: {}",
        trace.opcodes.len()
    );
    // Scratch-slot 1 is written twice (`store 1` ... `stores` ... `store 1`);
    // scratch tracing must capture at least one of those writes.
    assert!(
        trace
            .opcodes
            .iter()
            .any(|u| u.scratch_changes.iter().any(|(slot, _)| *slot == 1)),
        "scratch slot 1 must be captured by scratch tracing"
    );
    // `dupn 4` pushes four copies of the top of stack without popping.
    assert!(
        trace
            .opcodes
            .iter()
            .any(|u| u.stack_pop_count == 0 && u.stack_additions.len() == 4),
        "dupn 4 should push exactly four stack values with no pops"
    );
}

// ---------------------------------------------------------------------------
// Theme 2: initial-states coverage (local/box vs. global)
// ---------------------------------------------------------------------------

/// A put/get/del local-state app, matching go's `testLocalInitialStatesHelper`
/// program.
const LOCAL_STATE_APP_SRC: &str = "#pragma version 8
txn ApplicationID
bz end

txn OnCompletion
int OptIn
==
bnz end

byte \"put\"
byte \"get\"
byte \"del\"

txn ApplicationArgs 0
match put get del
err

put:
  int 0
  txn ApplicationArgs 1
  txn ApplicationArgs 2
  app_local_put
  b end

get:
  int 0
  txn ApplicationArgs 1
  app_local_get
  pop
  b end

del:
  int 0
  txn ApplicationArgs 1
  app_local_del
  b end

end:
  int 1
";

/// Port of `TestLocalInitialStates`: local-state capture only had unit-level
/// coverage at the `InitialStatesAccumulator` level
/// (`accumulator_captures_local_and_box_state`); this drives the same
/// mechanism end-to-end through a real AVM-executed `app_local_put`/
/// `app_local_get`/`app_local_del` program, matching go's two cases: no
/// initial state (nothing written before simulation) and an initial value
/// captured once, on first touch, across `put`+`get`+`del` in a single
/// simulated group.
#[test]
fn local_initial_states() {
    let creator = Address([0xAA; 32]);
    let user = Address([0xBB; 32]);
    let app_id = 1001u64;
    let mut state = base_state();
    fund(&mut state, creator, 20_000_000);
    fund(&mut state, user, 20_000_000);

    let approval = assemble(LOCAL_STATE_APP_SRC);
    let clear = assemble("#pragma version 8\nint 1\n");
    register_app(
        &mut state,
        creator,
        app_id,
        approval,
        clear,
        StateSchema::default(),
        StateSchema {
            num_uint: 0,
            num_byte_slice: 8,
        },
    );

    // `user` opts in for real.
    apply_real(
        &mut state,
        &SignedTransaction {
            txn: appl_txn(user, app_id, 1 /* OptIn */),
            ..Default::default()
        },
    );

    // "Prepare": for real, put key="key" => "value".
    let mut prepare = appl_txn(user, app_id, 0);
    app_args(&mut prepare, &[b"put", b"key", b"value"]);
    apply_real(
        &mut state,
        &SignedTransaction {
            txn: prepare,
            ..Default::default()
        },
    );

    // Simulate: put a new value, get it, then delete it -- all in one group.
    let mut put_new = appl_txn(user, app_id, 0);
    app_args(&mut put_new, &[b"put", b"key", b"new-value"]);
    let mut get = appl_txn(user, app_id, 0);
    app_args(&mut get, &[b"get", b"key"]);
    let mut del = appl_txn(user, app_id, 0);
    app_args(&mut del, &[b"del", b"key"]);

    let request = SimulationRequest {
        txn_groups: vec![vec![
            SignedTransaction {
                txn: put_new,
                ..Default::default()
            },
            SignedTransaction {
                txn: get,
                ..Default::default()
            },
            SignedTransaction {
                txn: del,
                ..Default::default()
            },
        ]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            state: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );

    let initial = result
        .initial_states
        .as_ref()
        .expect("initial_states present");
    let app_entry = initial
        .app_initial_states
        .iter()
        .find(|(id, _)| *id == app_id)
        .expect("app appears in initial states");
    assert_eq!(app_entry.1.local_states.len(), 1);
    let (addr, kvs) = &app_entry.1.local_states[0];
    assert_eq!(*addr, user);
    assert_eq!(kvs.len(), 1);
    assert_eq!(kvs[0].0, b"key");
    let value_bytes = match &kvs[0].1 {
        algo_ledger::simulation::AvmValueTrace::Bytes(b) => b.clone(),
        other => panic!("expected bytes, got {other:?}"),
    };
    assert_eq!(
        value_bytes, b"value",
        "the FIRST-touched (pre-simulation) value must be captured, not the \
         put-new-value overwrite"
    );
}

/// Port of `TestLocalInitialStates`'s no-prior-write case: simulating a
/// `local_put` on a key never written before must report an empty
/// initial-states set for that app (no local key existed to capture).
#[test]
fn local_initial_states_empty_when_nothing_prewritten() {
    let creator = Address([0xAA; 32]);
    let user = Address([0xBB; 32]);
    let app_id = 1001u64;
    let mut state = base_state();
    fund(&mut state, creator, 20_000_000);
    fund(&mut state, user, 20_000_000);

    let approval = assemble(LOCAL_STATE_APP_SRC);
    let clear = assemble("#pragma version 8\nint 1\n");
    register_app(
        &mut state,
        creator,
        app_id,
        approval,
        clear,
        StateSchema::default(),
        StateSchema {
            num_uint: 0,
            num_byte_slice: 8,
        },
    );
    apply_real(
        &mut state,
        &SignedTransaction {
            txn: appl_txn(user, app_id, 1 /* OptIn */),
            ..Default::default()
        },
    );

    let mut put = appl_txn(user, app_id, 0);
    app_args(&mut put, &[b"put", b"key", b"value"]);

    let request = SimulationRequest {
        txn_groups: vec![vec![SignedTransaction {
            txn: put,
            ..Default::default()
        }]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            state: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    assert!(
        result.txn_groups[0].failure_message.is_none(),
        "group must succeed: {:?}",
        result.txn_groups[0].failure_message
    );
    let initial = result
        .initial_states
        .as_ref()
        .expect("initial_states present");
    // The app is touched (so it appears, matching go's `AllAppsInitialStates`
    // map, which gets an entry on any access), but writing a brand-new key
    // is a *creation*, not an initial value to diff against -- its
    // `local_states` must stay empty.
    let app_entry = initial
        .app_initial_states
        .iter()
        .find(|(id, _)| *id == app_id)
        .expect("app appears in initial states (it was touched)");
    assert!(
        app_entry.1.local_states.is_empty(),
        "a newly-created key must not report an initial value: {app_entry:?}"
    );
}

/// A create/read/write/delete box-manipulation app, matching go's
/// `boxTestProgram`'s command dispatch shape (simplified to the four box
/// opcodes this issue's scenarios need).
const BOX_STATE_APP_SRC: &str = "#pragma version 8
txn ApplicationID
bz end

byte \"create\"
byte \"read\"
byte \"write\"
byte \"delete\"
txn ApplicationArgs 0
match do_create do_read do_write do_delete
err

do_create:
  txn ApplicationArgs 1
  txn ApplicationArgs 2
  btoi
  box_create
  pop
  b end

do_read:
  txn ApplicationArgs 1
  box_get
  pop
  pop
  b end

do_write:
  txn ApplicationArgs 1
  txn ApplicationArgs 2
  box_put
  b end

do_delete:
  txn ApplicationArgs 1
  box_del
  pop
  b end

end:
  int 1
";

fn box_app_call(
    sender: Address,
    app_id: u64,
    args: &[&[u8]],
    box_name: &[u8],
) -> SignedTransaction {
    let mut txn = appl_txn(sender, app_id, 0);
    app_args(&mut txn, args);
    txn.boxes = Some(vec![BoxRef {
        index: 0,
        name: Some(box_name.to_vec().into()),
    }]);
    SignedTransaction {
        txn,
        ..Default::default()
    }
}

/// Port of `TestAppInitialBoxStates`: box-state initial-value capture only
/// had unit-level coverage (`accumulator_captures_local_and_box_state`);
/// this drives it end-to-end through real `box_create`/`box_get`/
/// `box_put`/`box_del` opcodes across two scenarios -- (1) a box read then
/// overwritten in the same simulated group must capture its pre-simulation
/// content, and (2) among three pre-existing boxes, only the ones actually
/// touched during simulation (one deleted, one read) appear in
/// `initial_states`; the untouched third box does not.
#[test]
fn app_initial_box_states() {
    let creator = Address([0xAA; 32]);
    let app_id = 1001u64;
    let mut state = base_state();
    fund(&mut state, creator, 20_000_000);

    let approval = assemble(BOX_STATE_APP_SRC);
    let clear = assemble("#pragma version 8\nint 1\n");
    register_app(
        &mut state,
        creator,
        app_id,
        approval,
        clear,
        StateSchema::default(),
        StateSchema::default(),
    );
    fund(
        &mut state,
        Address(algo_ledger::avm_context::app_address(app_id)),
        2_000_000,
    );

    // Prepare (for real): create + write box "A" = "initial box A content".
    apply_real(
        &mut state,
        &box_app_call(
            creator,
            app_id,
            &[b"create", b"A", &21u64.to_be_bytes()],
            b"A",
        ),
    );
    apply_real(
        &mut state,
        &box_app_call(
            creator,
            app_id,
            &[b"write", b"A", b"initial box A content"],
            b"A",
        ),
    );

    // Simulate: read A, then overwrite it.
    let request = SimulationRequest {
        txn_groups: vec![vec![
            box_app_call(creator, app_id, &[b"read", b"A"], b"A"),
            box_app_call(
                creator,
                app_id,
                &[b"write", b"A", b"box A get overwritten"],
                b"A",
            ),
        ]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            state: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let result = simulate(&mut state, request).expect("simulation should succeed");
    assert!(
        result.txn_groups[0].failure_message.is_none(),
        "group must succeed: {:?}",
        result.txn_groups[0].failure_message
    );
    let initial = result
        .initial_states
        .as_ref()
        .expect("initial_states present");
    let app_entry = initial
        .app_initial_states
        .iter()
        .find(|(id, _)| *id == app_id)
        .expect("app appears in initial states");
    assert_eq!(app_entry.1.boxes.len(), 1);
    assert_eq!(app_entry.1.boxes[0].0, b"A");
    assert_eq!(app_entry.1.boxes[0].1, b"initial box A content");

    // ---- Second scenario: three boxes, only two touched. ----
    let mut state2 = base_state();
    fund(&mut state2, creator, 20_000_000);
    let approval2 = assemble(BOX_STATE_APP_SRC);
    let clear2 = assemble("#pragma version 8\nint 1\n");
    register_app(
        &mut state2,
        creator,
        app_id,
        approval2,
        clear2,
        StateSchema::default(),
        StateSchema::default(),
    );
    fund(
        &mut state2,
        Address(algo_ledger::avm_context::app_address(app_id)),
        3_000_000,
    );
    for name in [b"A", b"B", b"C"] {
        apply_real(
            &mut state2,
            &box_app_call(
                creator,
                app_id,
                &[b"create", name, &21u64.to_be_bytes()],
                name,
            ),
        );
        let content: &[u8] = match name {
            b"A" => b"initial box A content",
            b"B" => b"initial box B content",
            _ => b"initial box C content",
        };
        apply_real(
            &mut state2,
            &box_app_call(creator, app_id, &[b"write", name, content], name),
        );
    }

    let request2 = SimulationRequest {
        txn_groups: vec![vec![
            box_app_call(creator, app_id, &[b"delete", b"C"], b"C"),
            box_app_call(creator, app_id, &[b"read", b"A"], b"A"),
        ]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            state: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let result2 = simulate(&mut state2, request2).expect("simulation should succeed");
    assert!(
        result2.txn_groups[0].failure_message.is_none(),
        "group must succeed: {:?}",
        result2.txn_groups[0].failure_message
    );
    let initial2 = result2
        .initial_states
        .as_ref()
        .expect("initial_states present");
    let app_entry2 = initial2
        .app_initial_states
        .iter()
        .find(|(id, _)| *id == app_id)
        .expect("app appears in initial states");
    let mut boxes: Vec<(Vec<u8>, Vec<u8>)> = app_entry2.1.boxes.clone();
    boxes.sort();
    assert_eq!(
        boxes,
        vec![
            (b"A".to_vec(), b"initial box A content".to_vec()),
            (b"C".to_vec(), b"initial box C content".to_vec()),
        ],
        "only the touched boxes (A read, C deleted) must be captured -- not the untouched B"
    );
}

/// Port of `TestAppInitialBoxStatesAboutBoxPut`: `box_put` on an
/// *existing* box must capture the pre-write content as its initial state
/// (`accumulator_write_to_missing_key_is_creation_not_recorded` only covers
/// the missing-key half at the unit level); `box_put` creating a brand-new
/// box must NOT report an initial value for it.
#[test]
fn app_initial_box_states_about_box_put() {
    let creator = Address([0xAA; 32]);
    let app_id = 1001u64;

    // Case 1: box "A" already exists; box_put overwrites it -- the old
    // content must be captured.
    let mut state = base_state();
    fund(&mut state, creator, 20_000_000);
    let approval = assemble(BOX_STATE_APP_SRC);
    let clear = assemble("#pragma version 8\nint 1\n");
    register_app(
        &mut state,
        creator,
        app_id,
        approval,
        clear,
        StateSchema::default(),
        StateSchema::default(),
    );
    fund(
        &mut state,
        Address(algo_ledger::avm_context::app_address(app_id)),
        2_000_000,
    );
    apply_real(
        &mut state,
        &box_app_call(
            creator,
            app_id,
            &[b"write", b"A", b"initial box A content"],
            b"A",
        ),
    );

    let request = SimulationRequest {
        txn_groups: vec![vec![box_app_call(
            creator,
            app_id,
            &[b"write", b"A", b"box A get overwritten"],
            b"A",
        )]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            state: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let result = simulate(&mut state, request).expect("simulation should succeed");
    assert!(result.txn_groups[0].failure_message.is_none());
    let initial = result
        .initial_states
        .as_ref()
        .expect("initial_states present");
    let app_entry = initial
        .app_initial_states
        .iter()
        .find(|(id, _)| *id == app_id)
        .expect("app appears in initial states");
    assert_eq!(app_entry.1.boxes.len(), 1);
    assert_eq!(app_entry.1.boxes[0].0, b"A");
    assert_eq!(app_entry.1.boxes[0].1, b"initial box A content");

    // Case 2: no prior box "A" -- box_put creates it fresh, so no initial
    // value is reported.
    let mut state2 = base_state();
    fund(&mut state2, creator, 20_000_000);
    let approval2 = assemble(BOX_STATE_APP_SRC);
    let clear2 = assemble("#pragma version 8\nint 1\n");
    register_app(
        &mut state2,
        creator,
        app_id,
        approval2,
        clear2,
        StateSchema::default(),
        StateSchema::default(),
    );
    fund(
        &mut state2,
        Address(algo_ledger::avm_context::app_address(app_id)),
        2_000_000,
    );

    let request2 = SimulationRequest {
        txn_groups: vec![vec![box_app_call(
            creator,
            app_id,
            &[b"write", b"A", b"box A get overwritten"],
            b"A",
        )]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            state: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let result2 = simulate(&mut state2, request2).expect("simulation should succeed");
    assert!(result2.txn_groups[0].failure_message.is_none());
    let initial2 = result2
        .initial_states
        .as_ref()
        .expect("initial_states present");
    let app_entry2 = initial2
        .app_initial_states
        .iter()
        .find(|(id, _)| *id == app_id)
        .expect("app appears in initial states (it was touched)");
    assert!(
        app_entry2.1.boxes.is_empty(),
        "a freshly-created box must not report an initial value: {app_entry2:?}"
    );
}

/// Port of `TestInitialStatesGetEx`: a *foreign* app reads another app's
/// global and local state cross-app (`app_global_get_ex`/
/// `app_local_get_ex`), and the pre-simulation values must be attributed to
/// the *target* app (`app_id_with_states`), not the reading app --
/// `accumulator_foreign_app_read_recorded_under_target_app` only proves this
/// at the unit level for a global read; this drives both the global and
/// local `_get_ex` halves through a real two-app AVM call.
#[test]
fn initial_states_get_ex() {
    let creator = Address([0xAA; 32]);
    let app_with_states = 1001u64;
    let app_reading = 1002u64;
    let mut state = base_state();
    fund(&mut state, creator, 20_000_000);

    let states_src = "#pragma version 8
txn ApplicationID
bz end

txn OnCompletion
int OptIn
==
bnz end

byte \"put\"
byte \"local_put\"
txn ApplicationArgs 0
match put local_put
err

put:
  txn ApplicationArgs 1
  txn ApplicationArgs 2
  app_global_put
  b end

local_put:
  int 0
  txn ApplicationArgs 1
  txn ApplicationArgs 2
  app_local_put
  b end

end:
  int 1
";
    let states_approval = assemble(states_src);
    let clear = assemble("#pragma version 8\nint 1\n");
    register_app(
        &mut state,
        creator,
        app_with_states,
        states_approval,
        clear.clone(),
        StateSchema {
            num_uint: 0,
            num_byte_slice: 8,
        },
        StateSchema {
            num_uint: 0,
            num_byte_slice: 8,
        },
    );

    let reading_src = "#pragma version 8
txn ApplicationID
bz end

byte \"read_global\"
byte \"read_local\"
txn ApplicationArgs 0
match read_global read_local
err

read_global:
  txn ApplicationArgs 1
  btoi
  txn ApplicationArgs 2
  app_global_get_ex
  assert
  pop
  b end

read_local:
  int 0
  txn ApplicationArgs 1
  btoi
  txn ApplicationArgs 2
  app_local_get_ex
  assert
  pop
  b end

end:
  int 1
";
    let reading_approval = assemble(reading_src);
    register_app(
        &mut state,
        creator,
        app_reading,
        reading_approval,
        clear,
        StateSchema::default(),
        StateSchema::default(),
    );

    // Prepare (for real): opt in, then put global "A" and local "B".
    apply_real(
        &mut state,
        &SignedTransaction {
            txn: appl_txn(creator, app_with_states, 1 /* OptIn */),
            ..Default::default()
        },
    );
    let mut put_global = appl_txn(creator, app_with_states, 0);
    app_args(&mut put_global, &[b"put", b"A", b"initial content A"]);
    apply_real(
        &mut state,
        &SignedTransaction {
            txn: put_global,
            ..Default::default()
        },
    );
    let mut put_local = appl_txn(creator, app_with_states, 0);
    app_args(&mut put_local, &[b"local_put", b"B", b"initial content B"]);
    apply_real(
        &mut state,
        &SignedTransaction {
            txn: put_local,
            ..Default::default()
        },
    );

    // Simulate: app_reading cross-reads global "A", then local "B".
    let mut read_global = appl_txn(creator, app_reading, 0);
    app_args(
        &mut read_global,
        &[b"read_global", &app_with_states.to_be_bytes(), b"A"],
    );
    read_global.foreign_apps = Some(vec![app_with_states]);
    let mut read_local = appl_txn(creator, app_reading, 0);
    app_args(
        &mut read_local,
        &[b"read_local", &app_with_states.to_be_bytes(), b"B"],
    );
    read_local.foreign_apps = Some(vec![app_with_states]);

    let request = SimulationRequest {
        txn_groups: vec![vec![
            SignedTransaction {
                txn: read_global,
                ..Default::default()
            },
            SignedTransaction {
                txn: read_local,
                ..Default::default()
            },
        ]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            state: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let result = simulate(&mut state, request).expect("simulation should succeed");
    assert!(
        result.txn_groups[0].failure_message.is_none(),
        "group must succeed: {:?}",
        result.txn_groups[0].failure_message
    );

    let initial = result
        .initial_states
        .as_ref()
        .expect("initial_states present");
    // Attributed to app_with_states, NOT app_reading.
    assert!(
        initial
            .app_initial_states
            .iter()
            .all(|(id, _)| *id != app_reading),
        "the reading app must not itself appear in initial states"
    );
    let app_entry = initial
        .app_initial_states
        .iter()
        .find(|(id, _)| *id == app_with_states)
        .expect("app_with_states appears in initial states");
    assert_eq!(app_entry.1.global_state.len(), 1);
    assert_eq!(app_entry.1.global_state[0].0, b"A");
    let global_value = match &app_entry.1.global_state[0].1 {
        algo_ledger::simulation::AvmValueTrace::Bytes(b) => b.clone(),
        other => panic!("expected bytes, got {other:?}"),
    };
    assert_eq!(global_value, b"initial content A");

    assert_eq!(app_entry.1.local_states.len(), 1);
    assert_eq!(app_entry.1.local_states[0].0, creator);
    assert_eq!(app_entry.1.local_states[0].1.len(), 1);
    assert_eq!(app_entry.1.local_states[0].1[0].0, b"B");
    let local_value = match &app_entry.1.local_states[0].1[0].1 {
        algo_ledger::simulation::AvmValueTrace::Bytes(b) => b.clone(),
        other => panic!("expected bytes, got {other:?}"),
    };
    assert_eq!(local_value, b"initial content B");
}

/// Port of `TestForeignAppBoxStateChangeTrace`: exercises the *foreign* box
/// opcode (`app_box_put`), which manipulates a box belonging to an app other
/// than the one executing. Confirms both the exec-trace `StateChanges` and
/// the reported `InitialStates` are attributed to the foreign box *owner*
/// (via `AppFamilyBoxAccess`), not the writer -- the distinguishing
/// behavior of the foreign-box path (which reads the target app off the
/// stack instead of using the executing app's own ID), previously only
/// unit-tested for the read side
/// (`accumulator_foreign_app_read_recorded_under_target_app`).
#[test]
fn foreign_app_box_state_change_trace() {
    let creator = Address([0xAA; 32]);
    let owner_id = 1001u64;
    let writer_id = 1002u64;
    let mut state = base_state();
    // `AppFamilyBoxAccess` and program version 13 need a newer consensus
    // version than the default V41 used elsewhere in this file.
    state.protocol = algo_types::consensus::CONSENSUS_V42.to_string();
    fund(&mut state, creator, 20_000_000);

    // owner: on creation, do nothing; on any real call, create box "b" =
    // "IIII" and opt into AppFamilyBoxAccess so a same-creator family member
    // may write its boxes.
    let owner_src = "#pragma version 13
txn ApplicationID
bz end
byte \"b\"
byte \"IIII\"
box_put
int 1
app_params_set AppFamilyBoxAccess
end:
int 1
";
    // writer: replaces the whole contents of box "b" owned by
    // Applications 1 (the owner) with "WWWW".
    let writer_src = "#pragma version 13
txn ApplicationID
bz end
txn Applications 1
byte \"b\"
byte \"WWWW\"
app_box_put
end:
int 1
";
    let owner_approval = assemble(owner_src);
    let writer_approval = assemble(writer_src);
    let clear = assemble("#pragma version 13\nint 1\n");

    register_app(
        &mut state,
        creator,
        owner_id,
        owner_approval,
        clear.clone(),
        StateSchema::default(),
        StateSchema::default(),
    );
    register_app(
        &mut state,
        creator,
        writer_id,
        writer_approval,
        clear,
        StateSchema::default(),
        StateSchema::default(),
    );
    // Fund the owner so it can carry box "b"'s minimum balance.
    fund(
        &mut state,
        Address(algo_ledger::avm_context::app_address(owner_id)),
        1_000_000,
    );

    // Run the owner once (for real) to create the box and opt into family
    // box access.
    let mut owner_call = appl_txn(creator, owner_id, 0);
    owner_call.boxes = Some(vec![BoxRef {
        index: 0,
        name: Some(b"b".to_vec().into()),
    }]);
    apply_real(
        &mut state,
        &SignedTransaction {
            txn: owner_call,
            ..Default::default()
        },
    );

    // Simulate a top-level call to the writer that touches the owner's box.
    let mut call = appl_txn(creator, writer_id, 0);
    call.foreign_apps = Some(vec![owner_id]);
    call.boxes = Some(vec![BoxRef {
        index: 1, // Applications[1] = foreign_apps[0] = owner
        name: Some(b"b".to_vec().into()),
    }]);

    let request = SimulationRequest {
        txn_groups: vec![vec![SignedTransaction {
            txn: call,
            ..Default::default()
        }]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            state: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );

    // The write's state change must be attributed to the foreign owner (not
    // the writer), keyed by "b", with the post-write value.
    let trace = group.txn_results[0]
        .trace
        .as_ref()
        .expect("trace present")
        .approval_program_trace
        .as_ref()
        .expect("approval trace present");
    let changes: Vec<_> = trace
        .opcodes
        .iter()
        .flat_map(|u| u.state_changes.iter())
        .collect();
    assert_eq!(changes.len(), 1, "exactly one box write");
    assert_eq!(
        changes[0].app_id, owner_id,
        "attributed to the owner, not the writer"
    );
    assert_eq!(changes[0].key, b"b");
    let new_value = match &changes[0].new_value {
        Some(algo_ledger::simulation::AvmValueTrace::Bytes(b)) => b.clone(),
        other => panic!("expected bytes, got {other:?}"),
    };
    assert_eq!(new_value, b"WWWW");

    // The pre-simulation box value is recorded under the owner; the writer
    // contributes no box initial state of its own.
    let initial = result
        .initial_states
        .as_ref()
        .expect("initial_states present");
    assert!(
        initial
            .app_initial_states
            .iter()
            .all(|(id, _)| *id != writer_id),
        "the writer must not itself appear in initial states"
    );
    let owner_entry = initial
        .app_initial_states
        .iter()
        .find(|(id, _)| *id == owner_id)
        .expect("owner appears in initial states");
    assert_eq!(owner_entry.1.boxes.len(), 1);
    assert_eq!(owner_entry.1.boxes[0].0, b"b");
    assert_eq!(owner_entry.1.boxes[0].1, b"IIII");
}

// ---------------------------------------------------------------------------
// Theme 3: signature-mode edge cases untested at the simulation level
// ---------------------------------------------------------------------------

/// Port of `TestWrongAuthorizerTxn` (both `optionalSigs` sub-cases): a
/// self-payment declares `auth_addr` = a real key that never rekeyed the
/// sender account. Whether the transaction is genuinely signed by that key
/// (`allow_empty_signatures: false`) or unsigned-but-`AllowEmptySignatures`
/// (which only relaxes *signature verification*, not the apply-time
/// authorizer check against the *declared* `auth_addr`), the group must
/// fail with the mismatched-authorizer message, attributed to txn index 0.
#[test]
fn wrong_authorizer_txn_both_signed_and_optional() {
    for optional_sigs in [false, true] {
        let sender_key = SigningKey::from_bytes(&[0x11; 32]);
        let sender_addr = Address(sender_key.verifying_key().to_bytes());
        let authority_key = SigningKey::from_bytes(&[0x22; 32]);
        let authority_addr = Address(authority_key.verifying_key().to_bytes());

        let mut state = base_state();
        fund(&mut state, sender_addr, 20_000_000);

        let txn = Transaction {
            txn_type: "pay".into(),
            sender: sender_addr,
            receiver: sender_addr,
            amount: 0,
            fee: 1000,
            first_valid: 0.into(),
            last_valid: 1000.into(),
            ..Default::default()
        };

        let stx = if optional_sigs {
            SignedTransaction {
                txn,
                sig: [0u8; 64],
                auth_addr: Some(authority_addr),
                ..Default::default()
            }
        } else {
            let mut signed = sign(txn, &authority_key);
            signed.auth_addr = Some(authority_addr);
            signed
        };

        let request = SimulationRequest {
            txn_groups: vec![vec![stx]],
            allow_empty_signatures: optional_sigs,
            ..Default::default()
        };

        let result = simulate(&mut state, request).unwrap_or_else(|e| {
            panic!("optional_sigs={optional_sigs}: simulate must return a result, not {e}")
        });
        let group = &result.txn_groups[0];
        let msg = group.failure_message.as_ref().unwrap_or_else(|| {
            panic!("optional_sigs={optional_sigs}: group must fail on the wrong authorizer")
        });
        assert!(
            msg.contains("should have been authorized by")
                && msg.contains("actually authorized by"),
            "optional_sigs={optional_sigs}: unexpected message: {msg}"
        );
        assert_eq!(group.failed_at, Some(vec![0]));
        assert_eq!(result.eval_overrides.allow_empty_signatures, optional_sigs);
    }
}

/// Port of `TestDefaultSignatureCheck`: signature checking when
/// `allow_empty_signatures` is NOT enabled. A missing signature must fail
/// the group (recoverable, `FailedAt: [0]`) rather than return a hard
/// simulate error; adding a valid signature must succeed; corrupting that
/// signature's bytes must then return a hard `InvalidRequest` error (a
/// genuine cryptographic verification failure has no attributable
/// transaction index, unlike a merely-missing signature).
#[test]
fn default_signature_check() {
    let sender_key = SigningKey::from_bytes(&[0x33; 32]);
    let sender_addr = Address(sender_key.verifying_key().to_bytes());
    let mut state = base_state();
    fund(&mut state, sender_addr, 20_000_000);

    let txn = Transaction {
        txn_type: "pay".into(),
        sender: sender_addr,
        receiver: sender_addr,
        amount: 0,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        ..Default::default()
    };

    // No signature at all.
    let unsigned = SignedTransaction {
        txn: txn.clone(),
        ..Default::default()
    };
    let result = simulate(
        &mut state,
        SimulationRequest {
            txn_groups: vec![vec![unsigned]],
            ..Default::default()
        },
    )
    .expect("missing signature must be a recoverable failure, not a hard error");
    let group = &result.txn_groups[0];
    let msg = group
        .failure_message
        .as_ref()
        .expect("missing signature must fail the group");
    assert!(msg.contains("no signature"), "unexpected message: {msg}");
    assert_eq!(group.failed_at, Some(vec![0]));

    // A real signature must succeed.
    let signed = sign(txn, &sender_key);
    let result = simulate(
        &mut state,
        SimulationRequest {
            txn_groups: vec![vec![signed.clone()]],
            ..Default::default()
        },
    )
    .expect("simulation should succeed");
    assert!(result.txn_groups[0].failure_message.is_none());

    // A corrupted signature is a hard error (no attributable index).
    let mut corrupted = signed;
    corrupted.sig[0] = corrupted.sig[0].wrapping_add(1);
    let err = simulate(
        &mut state,
        SimulationRequest {
            txn_groups: vec![vec![corrupted]],
            ..Default::default()
        },
    )
    .expect_err("a corrupted signature must be a hard request error");
    match err {
        SimulatorError::InvalidRequest(_) => {}
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

/// Port of `TestInvalidTxGroup`: a transaction from the incentive-pool
/// address is a `WellFormed` rejection, attributable to its own index --
/// like `TestDefaultSignatureCheck`'s missing-signature case, this must be
/// a recoverable group failure, not a hard `InvalidRequest`/`EvalFailure`
/// error (the go-algorand test's whole point: this class of error must be
/// classified as an invalid-*group* condition rather than a plain
/// evaluation failure, yet still surfaced through `Result`, not `error`).
#[test]
fn invalid_tx_group_incentive_pool_sender() {
    let mut state = base_state();
    let receiver = Address([0xBB; 32]);

    // Fund the (well-known) rewards-pool address as the sender, matching
    // go's `ledgertesting.PoolAddr()` -- an inherently invalid sender for
    // any ordinary transaction.
    let pool_addr = Address([0xCC; 32]);
    state.rewards_pool = pool_addr;
    fund(&mut state, pool_addr, 20_000_000);

    let txn = Transaction {
        txn_type: "pay".into(),
        sender: pool_addr,
        receiver,
        amount: 0,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        ..Default::default()
    };

    let result = simulate(
        &mut state,
        SimulationRequest {
            txn_groups: vec![vec![SignedTransaction {
                txn,
                ..Default::default()
            }]],
            allow_empty_signatures: true,
            ..Default::default()
        },
    )
    .expect("an incentive-pool sender must be a recoverable failure, not a hard error");
    let group = &result.txn_groups[0];
    let msg = group
        .failure_message
        .as_ref()
        .expect("incentive-pool-sender group must fail");
    assert!(msg.contains("incentive pool"), "unexpected message: {msg}");
    assert_eq!(group.failed_at, Some(vec![0]));
}

/// Port of `TestOptionalSignatures`: with `allow_empty_signatures` enabled,
/// both a genuinely-signed transaction and a completely unsigned one must
/// simulate successfully (the proxy-signing path for the unsigned case).
#[test]
fn optional_signatures_both_signed_and_unsigned() {
    for signed in [true, false] {
        let sender_key = SigningKey::from_bytes(&[0x44; 32]);
        let sender_addr = Address(sender_key.verifying_key().to_bytes());
        let mut state = base_state();
        fund(&mut state, sender_addr, 20_000_000);

        let txn = Transaction {
            txn_type: "pay".into(),
            sender: sender_addr,
            receiver: sender_addr,
            amount: 1,
            fee: 1000,
            first_valid: 0.into(),
            last_valid: 1000.into(),
            ..Default::default()
        };
        let stx = if signed {
            sign(txn, &sender_key)
        } else {
            SignedTransaction {
                txn,
                ..Default::default()
            }
        };

        let result = simulate(
            &mut state,
            SimulationRequest {
                txn_groups: vec![vec![stx]],
                allow_empty_signatures: true,
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| panic!("signed={signed}: simulation should succeed, got {e}"));
        assert!(
            result.txn_groups[0].failure_message.is_none(),
            "signed={signed}: group must succeed: {:?}",
            result.txn_groups[0].failure_message
        );
        assert!(result.eval_overrides.allow_empty_signatures);
    }
}

/// Port of `TestOptionalSignaturesIncorrect`: even with
/// `allow_empty_signatures` enabled, a transaction carrying an actually
/// *incorrect* signature (not merely a missing one) must still fail as a
/// hard `InvalidRequest` -- `AllowEmptySignatures` relaxes only the
/// no-signature case, not real-but-wrong-signature verification.
#[test]
fn optional_signatures_incorrect_is_hard_error() {
    let sender_key = SigningKey::from_bytes(&[0x55; 32]);
    let sender_addr = Address(sender_key.verifying_key().to_bytes());
    let mut state = base_state();
    fund(&mut state, sender_addr, 20_000_000);

    let txn = Transaction {
        txn_type: "pay".into(),
        sender: sender_addr,
        receiver: sender_addr,
        amount: 0,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        ..Default::default()
    };
    let mut stx = sign(txn, &sender_key);
    stx.sig[0] = stx.sig[0].wrapping_add(1);

    let err = simulate(
        &mut state,
        SimulationRequest {
            txn_groups: vec![vec![stx]],
            allow_empty_signatures: true,
            ..Default::default()
        },
    )
    .expect_err(
        "an incorrect signature must be a hard request error even under AllowEmptySignatures",
    );
    match err {
        SimulatorError::InvalidRequest(_) => {}
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

/// Port of `TestOptionalSignaturesProgramlessLogicSigContent`: an
/// unsigned transaction whose `LogicSig` carries `Args` but no program is
/// an "orphan" LogicSig -- go-algorand's `logicSigGroupSizeCheck` rejects
/// it once size pricing is enabled, attributed to the transaction's index
/// (a recoverable failure, not a hard error), previously entirely
/// unvalidated by `Simulator::check` (issue #974 -- the check existed in
/// `algo_validate::logic_sig_group_size_check` for real block validation
/// but was never wired into simulation's `check()`).
#[test]
fn optional_signatures_programless_logicsig_content() {
    let sender_key = SigningKey::from_bytes(&[0x66; 32]);
    let sender_addr = Address(sender_key.verifying_key().to_bytes());
    let mut state = base_state();
    // Size-pricing (which gates the orphan-LogicSig rejection) is a V42+
    // consensus feature.
    state.protocol = algo_types::consensus::CONSENSUS_V42.to_string();
    fund(&mut state, sender_addr, 20_000_000);

    let txn = Transaction {
        txn_type: "pay".into(),
        sender: sender_addr,
        receiver: sender_addr,
        amount: 0,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        ..Default::default()
    };
    let stx = SignedTransaction {
        txn,
        lsig: Some(LogicSig {
            logic: serde_bytes::ByteBuf::new(),
            sig: [0u8; 64],
            msig: None,
            lmsig: None,
            args: Some(vec![serde_bytes::ByteBuf::from(vec![1u8])]),
            pqsig: None,
        }),
        ..Default::default()
    };

    let result = simulate(
        &mut state,
        SimulationRequest {
            txn_groups: vec![vec![stx]],
            allow_empty_signatures: true,
            ..Default::default()
        },
    )
    .expect("an orphan LogicSig must be a recoverable failure, not a hard error");
    let group = &result.txn_groups[0];
    let msg = group
        .failure_message
        .as_ref()
        .expect("orphan LogicSig content must fail the group");
    assert!(
        msg.contains("LogicSig fields without LogicSig program"),
        "unexpected message: {msg}"
    );
    assert_eq!(group.failed_at, Some(vec![0]));
}

/// Port of `TestPartialMissingSignatures`: a group where only *some*
/// transactions carry a signature must still simulate successfully under
/// `allow_empty_signatures` -- the unsigned member is proxy-signed, the
/// signed member is verified for real, and the group applies both
/// transactions.
#[test]
fn partial_missing_signatures() {
    let sender_key = SigningKey::from_bytes(&[0x77; 32]);
    let sender_addr = Address(sender_key.verifying_key().to_bytes());
    let mut state = base_state();
    fund(&mut state, sender_addr, 20_000_000);

    let txn0 = Transaction {
        txn_type: "pay".into(),
        sender: sender_addr,
        receiver: sender_addr,
        amount: 0,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        ..Default::default()
    };
    let txn1 = Transaction {
        txn_type: "pay".into(),
        sender: sender_addr,
        receiver: sender_addr,
        amount: 1,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        ..Default::default()
    };

    // txn0 unsigned, txn1 genuinely signed.
    let stx0 = SignedTransaction {
        txn: txn0,
        ..Default::default()
    };
    let stx1 = sign(txn1, &sender_key);

    let result = simulate(
        &mut state,
        SimulationRequest {
            txn_groups: vec![vec![stx0, stx1]],
            allow_empty_signatures: true,
            ..Default::default()
        },
    )
    .expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );
    assert_eq!(group.txn_results.len(), 2);
    assert!(group.txn_results[0].apply_data.is_some());
    assert!(group.txn_results[1].apply_data.is_some());
}

// ---------------------------------------------------------------------------
// Theme 4: miscellaneous single-scenario gaps
// ---------------------------------------------------------------------------

/// Port of `TestStateProofTxn`: a `stpf`-typed transaction must be rejected
/// with a fixed message, regardless of its (unpopulated) StateProof fields
/// -- this is caught before signature verification even runs.
#[test]
fn state_proof_txn_rejected() {
    let mut state = base_state();
    let txn = Transaction {
        txn_type: "stpf".into(),
        first_valid: 0.into(),
        last_valid: 1000.into(),
        ..Default::default()
    };

    let err = simulate(
        &mut state,
        SimulationRequest {
            txn_groups: vec![vec![SignedTransaction {
                txn,
                ..Default::default()
            }]],
            ..Default::default()
        },
    )
    .expect_err("a StateProof transaction must be rejected");
    match err {
        SimulatorError::InvalidRequest(e) => {
            assert!(
                e.message
                    .contains("cannot simulate StateProof transactions"),
                "unexpected message: {}",
                e.message
            );
        }
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

/// Port of `TestSimpleGroupTxn`: two accounts sending money to each other
/// in a single group -- a group-membership sanity check with no other
/// existing simulate-specific coverage.
#[test]
fn simple_group_txn() {
    let sender1_key = SigningKey::from_bytes(&[0x81; 32]);
    let sender1 = Address(sender1_key.verifying_key().to_bytes());
    let sender2_key = SigningKey::from_bytes(&[0x82; 32]);
    let sender2 = Address(sender2_key.verifying_key().to_bytes());

    let mut state = base_state();
    fund(&mut state, sender1, 20_000_000);
    fund(&mut state, sender2, 20_000_000);

    let txn1 = Transaction {
        txn_type: "pay".into(),
        sender: sender1,
        receiver: sender2,
        amount: 1_000_000,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        ..Default::default()
    };
    let txn2 = Transaction {
        txn_type: "pay".into(),
        sender: sender2,
        receiver: sender1,
        amount: 10,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        ..Default::default()
    };

    let request = SimulationRequest {
        txn_groups: vec![vec![sign(txn1, &sender1_key), sign(txn2, &sender2_key)]],
        ..Default::default()
    };
    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );
    assert_eq!(group.txn_results.len(), 2);
    // Simulation never commits -- the real ledger balances must be
    // untouched.
    assert_eq!(state.get_account(&sender1).unwrap().micro_algos, 20_000_000);
    assert_eq!(state.get_account(&sender2).unwrap().micro_algos, 20_000_000);
}

/// Port of `TestStartRound`: `request.round` selects which historical round
/// an app call's `global Round` opcode observes; the default (no round
/// given) uses the current round; a round past the ledger's tip is
/// rejected.
#[test]
fn start_round_selection() {
    let sender = Address([0xAA; 32]);
    let app_id = 1001u64;
    let mut state = base_state();
    fund(&mut state, sender, 20_000_000);

    let src = "#pragma version 8
global Round
itob
log
int 1
";
    let approval = assemble(src);
    let clear = assemble("#pragma version 8\nint 1\n");
    register_app(
        &mut state,
        sender,
        app_id,
        approval,
        clear,
        StateSchema::default(),
        StateSchema::default(),
    );

    // Populate a few historical block headers so `request.round` has
    // something to select among.
    for r in 1..=3u64 {
        let hdr = algo_types::BlockHeader {
            round: Round(r),
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            ..Default::default()
        };
        let hdr_bytes = algo_codec::canonical_encode_block_header(&hdr);
        state
            .put_block(r, &hdr.current_protocol, &hdr_bytes, &[])
            .expect("put_block succeeds");
    }
    state.set_current_round(Round(3));

    let read_round = |state: &mut LedgerState, round: Option<Round>| -> u64 {
        let request = SimulationRequest {
            txn_groups: vec![vec![SignedTransaction {
                txn: appl_txn(sender, app_id, 0),
                ..Default::default()
            }]],
            allow_empty_signatures: true,
            round,
            ..Default::default()
        };
        let result = simulate(state, request).expect("simulation should succeed");
        let group = &result.txn_groups[0];
        assert!(
            group.failure_message.is_none(),
            "{:?}",
            group.failure_message
        );
        let apply_data = group.txn_results[0].apply_data.as_ref().unwrap();
        let eval_delta = algo_ledger::parse_eval_delta(apply_data.eval_delta.as_ref().unwrap())
            .expect("eval delta parses");
        let logs = eval_delta.logs.expect("logs present");
        u64::from_be_bytes(logs[0].as_slice().try_into().unwrap())
    };

    // Default: uses the current (latest) round.
    assert_eq!(read_round(&mut state, None), 3);
    // Explicit historical rounds.
    assert_eq!(read_round(&mut state, Some(Round(2))), 2);
    assert_eq!(read_round(&mut state, Some(Round(1))), 1);

    // A round past the ledger's tip must be rejected.
    let request = SimulationRequest {
        txn_groups: vec![vec![SignedTransaction {
            txn: appl_txn(sender, app_id, 0),
            ..Default::default()
        }]],
        allow_empty_signatures: true,
        round: Some(Round(4)),
        ..Default::default()
    };
    let err = simulate(&mut state, request).expect_err("a future round must be rejected");
    match err {
        SimulatorError::Internal(_) | SimulatorError::InvalidRequest(_) => {}
        other => panic!("expected an error rejecting the future round, got {other:?}"),
    }
}

/// Port of `TestGlobalStateTypeChangeErr`: an app declares a global schema
/// of one uint and zero byte-slices; writing a *bytes* value violates that
/// schema during a later call (the create call itself only reserves the
/// slot). No existing simulate-specific test exercises this global-state
/// type-mismatch trace/failure combination.
#[test]
fn global_state_type_change_err() {
    let sender = Address([0xAA; 32]);
    let app_id = 1001u64;
    let mut state = base_state();
    fund(&mut state, sender, 20_000_000);

    let src = "#pragma version 8
txn ApplicationID
bz end

byte \"global-key\"
byte \"I pretend myself as an uint\"
app_global_put

end:
  int 1
";
    let approval = assemble(src);
    let clear = assemble("#pragma version 8\nint 1\n");
    register_app(
        &mut state,
        sender,
        app_id,
        approval.clone(),
        clear,
        StateSchema {
            num_uint: 1,
            num_byte_slice: 0,
        },
        StateSchema::default(),
    );

    let request = SimulationRequest {
        txn_groups: vec![vec![SignedTransaction {
            txn: appl_txn(sender, app_id, 0),
            ..Default::default()
        }]],
        allow_empty_signatures: true,
        trace_config: ExecTraceConfig {
            enable: true,
            state: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let result = simulate(&mut state, request).expect("simulate must return a result");
    let group = &result.txn_groups[0];
    let msg = group
        .failure_message
        .as_ref()
        .expect("the global-state type change must fail the group");
    assert!(
        msg.contains("store bytes count 1 exceeds schema bytes count 0"),
        "unexpected message: {msg}"
    );
    assert_eq!(group.failed_at, Some(vec![0]));

    // A partial trace up to the rejecting opcode is still captured.
    let txn_trace = group.txn_results[0].trace.as_ref().expect("trace present");
    let approval_trace = txn_trace
        .approval_program_trace
        .as_ref()
        .expect("approval trace present");
    assert!(!approval_trace.opcodes.is_empty());
    assert_eq!(
        txn_trace.approval_program_hash,
        Some(program_hash(&approval))
    );
}

/// Port of `TestBalanceChangesWithApp`: a payment mid-group changes the
/// receiver's balance, and a later app call in the *same* group observes
/// the updated balance via the `balance` opcode -- proving simulate
/// evaluates the group sequentially with real intermediate state changes
/// visible, not a batch of independent dry-runs.
#[test]
fn balance_changes_with_app() {
    let sender = Address([0xAA; 32]);
    let receiver = Address([0xBB; 32]);
    let app_id = 1001u64;
    let mut state = base_state();
    fund(&mut state, sender, 20_000_000);
    fund(&mut state, receiver, 5_000_000);

    // v6: on create, approve. Otherwise assert `balance(Accounts[1]) ==
    // itob(ApplicationArgs[0])`.
    let src = "#pragma version 6
txn ApplicationID
bz end
int 1
balance
itob
txn ApplicationArgs 0
==
assert
end:
int 1
";
    let approval = assemble(src);
    let clear = assemble("#pragma version 6\nint 1\n");
    register_app(
        &mut state,
        sender,
        app_id,
        approval,
        clear,
        StateSchema::default(),
        StateSchema::default(),
    );

    let send_amount = 2_000_000u64;

    let mut check_start = appl_txn(sender, app_id, 0);
    check_start.accounts = Some(vec![receiver]);
    app_args(&mut check_start, &[&5_000_000u64.to_be_bytes()]);

    let payment = Transaction {
        txn_type: "pay".into(),
        sender,
        receiver,
        amount: send_amount,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        ..Default::default()
    };

    let mut check_end = appl_txn(sender, app_id, 0);
    check_end.accounts = Some(vec![receiver]);
    app_args(
        &mut check_end,
        &[&(5_000_000u64 + send_amount).to_be_bytes()],
    );

    let request = SimulationRequest {
        txn_groups: vec![vec![
            SignedTransaction {
                txn: check_start,
                ..Default::default()
            },
            SignedTransaction {
                txn: payment,
                ..Default::default()
            },
            SignedTransaction {
                txn: check_end,
                ..Default::default()
            },
        ]],
        allow_empty_signatures: true,
        ..Default::default()
    };
    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );
    assert_eq!(group.txn_results.len(), 3);
}

/// Port of `TestRekey`: a self-payment in the group rekeys the sender to a
/// second key; a later transaction from the same sender, signed by the NEW
/// key, must apply successfully -- proving simulate's per-transaction eval
/// loop threads real rekey side effects to later group members (matching
/// `apply_group_transactions`'s real-block behavior).
#[test]
fn rekey_within_group() {
    let sender_key = SigningKey::from_bytes(&[0x91; 32]);
    let sender_addr = Address(sender_key.verifying_key().to_bytes());
    let authority_key = SigningKey::from_bytes(&[0x92; 32]);
    let authority_addr = Address(authority_key.verifying_key().to_bytes());

    let mut state = base_state();
    fund(&mut state, sender_addr, 20_000_000);

    let mut txn1 = Transaction {
        txn_type: "pay".into(),
        sender: sender_addr,
        receiver: sender_addr,
        amount: 1,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        rekey_to: Some(authority_addr),
        ..Default::default()
    };
    let txn2 = Transaction {
        txn_type: "pay".into(),
        sender: sender_addr,
        receiver: sender_addr,
        amount: 2,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        ..Default::default()
    };
    txn1.group = [0u8; 32]; // no real group id needed; simulate doesn't verify it

    let stx1 = sign(txn1, &sender_key);
    let mut stx2 = sign(txn2, &authority_key);
    stx2.auth_addr = Some(authority_addr);

    let result = simulate(
        &mut state,
        SimulationRequest {
            txn_groups: vec![vec![stx1, stx2]],
            ..Default::default()
        },
    )
    .expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );
    assert_eq!(group.txn_results.len(), 2);
    assert!(group.txn_results[0].apply_data.is_some());
    assert!(group.txn_results[1].apply_data.is_some());
}

/// Port of `TestUnnamedResourcesAccountLocalWrite` (the `sharedResourcesVersion`
/// (v9+) branch): an app writes local state to an account outside its
/// `Accounts` array. Under `allow_unnamed_resources`, this must succeed and
/// the `(account, app)` pair must appear in `unnamed_resources_accessed`'s
/// `app_locals` set -- the field exists
/// (`UnnamedResourcesAccessed::app_locals`) but no test exercises the
/// local-write scenario (only reads are covered by the other
/// `unnamed_*_tracked_when_allowed` tests in `simulation_features_test.rs`).
#[test]
fn unnamed_resources_account_local_write() {
    let sender = Address([0xAA; 32]);
    let other = Address([0xCC; 32]);
    let app_id = 1001u64;
    let mut state = base_state();
    fund(&mut state, sender, 20_000_000);
    fund(&mut state, other, 20_000_000);

    // v9: on create/opt-in, do nothing; otherwise write to `other`'s local
    // state directly by raw address (outside the Accounts array).
    let src = format!(
        "#pragma version 9
txn ApplicationID
!
txn OnCompletion
int OptIn
==
||
bnz end

addr {other}
byte \"key\"
byte \"value\"
app_local_put

end:
int 1
"
    );
    let approval = assemble(&src);
    let clear = assemble("#pragma version 9\nint 1\n");
    register_app(
        &mut state,
        sender,
        app_id,
        approval,
        clear,
        StateSchema::default(),
        StateSchema {
            num_uint: 0,
            num_byte_slice: 1,
        },
    );
    apply_real(
        &mut state,
        &SignedTransaction {
            txn: appl_txn(other, app_id, 1 /* OptIn */),
            ..Default::default()
        },
    );

    let request = SimulationRequest {
        txn_groups: vec![vec![SignedTransaction {
            txn: appl_txn(sender, app_id, 0),
            ..Default::default()
        }]],
        allow_empty_signatures: true,
        allow_unnamed_resources: true,
        ..Default::default()
    };
    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "unnamed local write must succeed under v9+ with allow_unnamed_resources: {:?}",
        group.failure_message
    );
    let unnamed = group
        .unnamed_resources_accessed
        .as_ref()
        .expect("unnamed resources must be reported");
    assert!(
        unnamed.app_locals.contains(&(other, app_id)),
        "the (account, app) pair must be tracked: {unnamed:?}"
    );

    // Without the flag, the same write must fail.
    let mut state2 = base_state();
    fund(&mut state2, sender, 20_000_000);
    fund(&mut state2, other, 20_000_000);
    let src2 = format!(
        "#pragma version 9
txn ApplicationID
!
txn OnCompletion
int OptIn
==
||
bnz end

addr {other}
byte \"key\"
byte \"value\"
app_local_put

end:
int 1
"
    );
    let approval2 = assemble(&src2);
    let clear2 = assemble("#pragma version 9\nint 1\n");
    register_app(
        &mut state2,
        sender,
        app_id,
        approval2,
        clear2,
        StateSchema::default(),
        StateSchema {
            num_uint: 0,
            num_byte_slice: 1,
        },
    );
    apply_real(
        &mut state2,
        &SignedTransaction {
            txn: appl_txn(other, app_id, 1 /* OptIn */),
            ..Default::default()
        },
    );
    let result2 = simulate(
        &mut state2,
        SimulationRequest {
            txn_groups: vec![vec![SignedTransaction {
                txn: appl_txn(sender, app_id, 0),
                ..Default::default()
            }]],
            allow_empty_signatures: true,
            allow_unnamed_resources: false,
            ..Default::default()
        },
    )
    .expect("simulate must return a result");
    assert!(
        result2.txn_groups[0].failure_message.is_some(),
        "without allow_unnamed_resources, an unnamed local write must fail"
    );
}
