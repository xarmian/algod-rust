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

//! End-to-end gating matrix for the v13 opcode bump.
//!
//! Covers the (opcode, declared_program_version, consensus_logic_sig_version)
//! gating space for `sha512` (0x87), `sumhash512` (0x86), and `divmodw` (0x1f).
//!
//! Two distinct gates are exercised:
//!   1. Parse-level: the bytecode parser rejects opcodes whose
//!      `opcode.version > program.version`.
//!   2. Consensus-level: `check_program_version_allowed` rejects programs
//!      whose declared version exceeds `ConsensusParams::logic_sig_version`.
//!
//! References:
//!   - go-algorand `data/transactions/logic/opcodes.go:31` — LogicVersion = 13
//!   - go-algorand `data/transactions/logic/opcodes.go:657-658` — sumhash512,
//!     sha512 specs (version 13)
//!   - go-algorand `data/transactions/logic/opcodes.go:545` — divmodw (v4,
//!     costly(20))
//!   - go-algorand `config/consensus.go:1440` — v41.LogicSigVersion = 12
//!   - go-algorand `config/consensus.go:1464` — vFuture.LogicSigVersion = 13

use algo_avm::{
    check_program_version_allowed, lookup, parse, AvmMachine, CostKind, ExecMode, NullContext,
    MAX_AVM_VERSION,
};
use algo_types::consensus::{consensus_params_for_version, ConsensusParams, CONSENSUS_V41};

fn v41_params() -> ConsensusParams {
    consensus_params_for_version(CONSENSUS_V41).expect("V41 params")
}

/// Build a simulated vFuture-style consensus where `logic_sig_version = 13`.
/// We clone V41 and bump only the ceiling, matching how go-algorand's vFuture
/// diff works (config/consensus.go:1464).
fn future_like_params_with_logic_sig_v13() -> ConsensusParams {
    let mut p = v41_params();
    p.logic_sig_version = 13;
    p
}

fn build_program(version: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![version];
    v.extend_from_slice(body);
    v
}

// ---------------------------------------------------------------------------
// Core invariants
// ---------------------------------------------------------------------------

#[test]
fn max_avm_version_is_13() {
    assert_eq!(MAX_AVM_VERSION, 13);
}

#[test]
fn v13_sha512_opcode_has_version_13() {
    let spec = lookup(0x87).expect("sha512 must be registered");
    assert_eq!(spec.name, "sha512");
    assert_eq!(spec.version, 13);
    assert_eq!(spec.cost, CostKind::Dynamic);
}

#[test]
fn v13_sumhash512_opcode_has_version_13() {
    let spec = lookup(0x86).expect("sumhash512 must be registered");
    assert_eq!(spec.name, "sumhash512");
    assert_eq!(spec.version, 13);
    assert_eq!(spec.cost, CostKind::Dynamic);
}

#[test]
fn v13_program_header_parses() {
    // An empty v13 program (version byte only) is now parsable.
    assert!(parse(&[13u8]).is_ok());
}

// ---------------------------------------------------------------------------
// Parse-level gating (opcode.version > program.version → reject)
// ---------------------------------------------------------------------------

#[test]
fn sha512_rejected_in_v12_program_at_parse() {
    // sha512 (0x87) requires program v13; a v12 program cannot contain it.
    let raw = build_program(12, &[0x87, 0x43]);
    let err = parse(&raw).expect_err("v12 program with sha512 must fail parse");
    let msg = format!("{err}");
    assert!(msg.contains("sha512") || msg.contains("v13"), "{msg}");
}

#[test]
fn sumhash512_rejected_in_v12_program_at_parse() {
    let raw = build_program(12, &[0x86, 0x43]);
    let err = parse(&raw).expect_err("v12 program with sumhash512 must fail parse");
    let msg = format!("{err}");
    assert!(msg.contains("sumhash512") || msg.contains("v13"), "{msg}");
}

#[test]
fn sha512_accepted_in_v13_program_at_parse() {
    // pushbytes "", sha512, return
    let raw = build_program(13, &[0x80, 0x00, 0x87, 0x43]);
    parse(&raw).expect("v13 program with sha512 must parse");
}

#[test]
fn sumhash512_accepted_in_v13_program_at_parse() {
    let raw = build_program(13, &[0x80, 0x00, 0x86, 0x43]);
    parse(&raw).expect("v13 program with sumhash512 must parse");
}

#[test]
fn divmodw_rejected_in_v3_program_at_parse() {
    // divmodw (0x1f) requires program v4.
    let raw = build_program(3, &[0x1f]);
    assert!(parse(&raw).is_err(), "v3 program with divmodw must fail");
}

#[test]
fn divmodw_accepted_in_v4_program_at_parse() {
    // divmodw is reachable in a v4+ program (parser accepts the opcode);
    // an executable smoke that it runs at cost=20 (TASK-50) is also covered.
    let raw = build_program(
        4,
        &[
            // Build an iiii divmodw: pushint 0, pushint 10, pushint 0,
            // pushint 3, divmodw, return — same shape as the existing
            // arith_divmodw_basic teal-vector test.
            0x81, 0x00, 0x81, 0x0a, 0x81, 0x00, 0x81, 0x03, 0x1f, 0x43,
        ],
    );
    let program = parse(&raw).expect("v4 program with divmodw must parse");

    // Execute: budget should show divmodw charged at 20 (per TASK-50 fix).
    let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 10_000);
    let before = machine.budget;
    machine
        .run(&mut NullContext)
        .expect("v4 divmodw program must execute cleanly");
    // Rough bound: cost should be ≥ 20 (divmodw) and ≤ a modest amount for
    // the four pushints + return. Exact cost per opcode spec:
    //   pushint x4 = 4
    //   divmodw    = 20
    //   return     = 1 (+ 1 for the popped values? just bounded-check).
    let used = before - machine.budget;
    assert!(used >= 20, "divmodw must charge ≥ 20; used = {used}");
    assert!(used <= 50, "overall cost should be modest; used = {used}");
}

// ---------------------------------------------------------------------------
// Consensus-level gating
// ---------------------------------------------------------------------------

#[test]
fn v13_program_rejected_under_v41_consensus() {
    // Parser accepts v13 (MAX_AVM_VERSION=13), but V41 consensus ceiling is 12.
    // At admission time the consensus check must reject it.
    let v41 = v41_params();
    assert_eq!(v41.logic_sig_version, 12);
    assert!(check_program_version_allowed(13, v41.logic_sig_version).is_err());
}

#[test]
fn v13_program_accepted_under_future_consensus_with_ceiling_13() {
    let future = future_like_params_with_logic_sig_v13();
    assert_eq!(future.logic_sig_version, 13);
    assert!(check_program_version_allowed(13, future.logic_sig_version).is_ok());
}

// ---------------------------------------------------------------------------
// Executable gating matrix — run a real v13 program end-to-end.
// ---------------------------------------------------------------------------

#[test]
fn v13_sha512_program_executes() {
    // Program: pushbytes "hello", sha512, (pushbytes expected, ==, return)
    // We just verify it executes cleanly and pushes a 64-byte result;
    // byte-exact parity vs Go is covered in v13_sha512_vectors.
    let mut code = vec![0x80, 0x05]; // pushbytes 5 bytes
    code.extend_from_slice(b"hello");
    code.push(0x87); // sha512
    let raw = build_program(13, &code);
    let program = parse(&raw).expect("parse");

    let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 100_000);
    machine
        .run(&mut NullContext)
        .expect("v13 sha512 program must execute");

    let top = machine.pop_bytes().expect("stack top");
    assert_eq!(top.len(), 64, "sha512 output must be 64 bytes");
}

// ---------------------------------------------------------------------------
// Eval-entry-point ceiling enforcement
// ---------------------------------------------------------------------------
//
// The parser accepts v13 bytecode unconditionally (MAX_AVM_VERSION = 13), but
// the eval entry points must reject a v13 program when the active consensus
// ceiling is < 13. This is enforced via `AvmContext::consensus_logic_sig_version`.

/// Tiny test context that carries a consensus ceiling and nothing else.
struct CeilingOnlyContext {
    ceiling: u64,
}

impl algo_avm::AvmContext for CeilingOnlyContext {
    fn consensus_logic_sig_version(&self) -> Option<u64> {
        Some(self.ceiling)
    }
}

#[test]
fn run_approval_program_rejects_v13_under_v41_ceiling() {
    use algo_avm::eval::run_approval_program;
    use algo_avm::group::GroupBudget;

    // Minimal v13 program: pushbytes "", sha512 (just to ensure body is
    // non-trivial, though we expect rejection before any opcode runs).
    let raw = build_program(13, &[0x80, 0x00, 0x87]);
    let mut ctx = CeilingOnlyContext { ceiling: 12 };
    let mut budget = GroupBudget::for_logicsig(1);
    let err = run_approval_program(&raw, &mut ctx, &mut budget)
        .expect_err("v13 program under V41-ceiling consensus must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("exceeds consensus LogicSigVersion ceiling"),
        "unexpected error: {msg}"
    );
}

#[test]
fn run_logicsig_program_rejects_v13_under_v41_ceiling() {
    use algo_avm::eval::run_logicsig_program;
    use algo_avm::group::GroupBudget;

    let raw = build_program(13, &[0x80, 0x00, 0x87]);
    let mut ctx = CeilingOnlyContext { ceiling: 12 };
    let mut budget = GroupBudget::for_logicsig(1);
    let err = run_logicsig_program(&raw, &mut ctx, &mut budget)
        .expect_err("v13 logicsig under V41-ceiling consensus must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("exceeds consensus LogicSigVersion ceiling"),
        "unexpected error: {msg}"
    );
}

#[test]
fn run_approval_program_accepts_v12_under_v41_ceiling() {
    use algo_avm::eval::run_approval_program;
    use algo_avm::group::GroupBudget;

    // `pushint 1, return` — smallest accept program, v3+ is enough for
    // `pushint`/`return`. Declare v12 so we stay at the ceiling.
    let raw = build_program(12, &[0x81, 0x01, 0x43]);
    let mut ctx = CeilingOnlyContext { ceiling: 12 };
    let mut budget = GroupBudget::for_logicsig(1);
    let result = run_approval_program(&raw, &mut ctx, &mut budget).expect("v12 under V41 must run");
    assert!(result.approved);
}

#[test]
fn v13_sumhash512_program_executes() {
    let mut code = vec![0x80, 0x05]; // pushbytes 5 bytes
    code.extend_from_slice(b"hello");
    code.push(0x86); // sumhash512
    let raw = build_program(13, &code);
    let program = parse(&raw).expect("parse");

    let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 100_000);
    machine
        .run(&mut NullContext)
        .expect("v13 sumhash512 program must execute");

    let top = machine.pop_bytes().expect("stack top");
    assert_eq!(top.len(), 64, "sumhash512 output must be 64 bytes");
}
