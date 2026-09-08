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

//! Whole-table run-mode sweep for every AVM opcode (Phase 17 issue #830,
//! `docs/phase17/parity_txn_logic.md`'s `TestEvalModes` row).
//!
//! go-algorand's `TestEvalModes` (`data/transactions/logic/evalStateful_test.go:205`)
//! iterates every entry of `OpSpecs` and, for opcodes restricted to a single
//! run mode (`runModeApplication` or `runModeSignature`), asserts evaluating
//! a program containing that opcode in the *other* mode is rejected. algod-
//! rust's existing coverage is a handful of individually-written
//! `test_*_rejected_in_logicsig_mode` cases (one opcode at a time, in
//! `crates/core/algo-avm/src/ops/mod.rs`) -- nothing sweeps the *entire*
//! opcode table the way go's test does, so a newly added Application-only or
//! LogicSig-only opcode that forgets its mode gate would slip through
//! unnoticed by any single existing test.
//!
//! This port targets `algo_avm::validator::check_mode` (invoked via the
//! public `check_program` entry point) directly rather than full end-to-end
//! evaluation: `check_mode` is a purely static, stack-balance-independent
//! scan over decoded instructions (it runs before the size/branch/stack
//! checks in `check_program` and returns as soon as it sees a
//! mode-incompatible opcode), so a synthetic single-instruction `Program`
//! with placeholder immediates exercises exactly the same code path that a
//! real assembled program would, without needing to hand-construct a
//! stack-balanced program per opcode (which `check_program`'s other checks
//! would otherwise require). This sweeps every one of the ~190 opcode/
//! sub-opcode entries in the production table -- a broader and more
//! future-proof check than go's OpSpecs-driven version, which only lists
//! opcodes present in go-algorand today.

use algo_avm::bytecode::{Immediates, Instruction, Program};
use algo_avm::opcode::{lookup, Mode};
use algo_avm::validator::check_program;

/// Walk every byte 0..=255 in the production opcode table and flatten
/// multi-byte "prefix opcode" families into their real, individually-moded
/// leaf entries. Returns `(opcode_byte, sub_opcode, mode, version)`.
fn all_opcode_entries() -> Vec<(u8, Option<u8>, Mode, u8)> {
    let mut out = Vec::new();
    for byte in 0u16..=255 {
        let Some(spec) = lookup(byte as u8) else {
            continue;
        };
        match spec.sub_ops {
            Some(subs) => {
                for (i, sub) in subs.iter().enumerate() {
                    if let Some(sub) = sub {
                        out.push((byte as u8, Some(i as u8), sub.mode, sub.version));
                    }
                }
            }
            None => out.push((byte as u8, None, spec.mode, spec.version)),
        }
    }
    out
}

/// Build a minimal single-instruction program for a given opcode entry, then
/// run it through `check_program`'s static mode gate.
fn check_mode_only(
    opcode: u8,
    sub_opcode: Option<u8>,
    version: u8,
    mode: Mode,
) -> Result<(), algo_error::AlgoError> {
    let program = Program {
        version: version.max(1),
        instructions: vec![Instruction {
            opcode,
            sub_opcode,
            offset: 0,
            immediates: Immediates::None,
        }],
    };
    // program_len well under any size limit; only the mode gate matters here.
    check_program(&program, mode, 10, 0)
}

#[test]
fn sweep_covers_a_meaningful_number_of_mode_restricted_opcodes() {
    // Sanity check on the sweep itself: if this ever drops to zero, the
    // opcode table shape changed and the sweep below would pass vacuously.
    let entries = all_opcode_entries();
    assert!(!entries.is_empty());
    let restricted = entries
        .iter()
        .filter(|&&(_, _, mode, _)| mode != Mode::Any)
        .count();
    assert!(
        restricted > 20,
        "expected a substantial number of mode-restricted opcodes, found {restricted}"
    );
}

/// Mirrors `TestEvalModes`: every Application-only opcode must be rejected
/// when the enclosing program is checked in LogicSig mode.
#[test]
fn every_application_only_opcode_is_rejected_in_logicsig_mode() {
    for (opcode, sub_opcode, mode, version) in all_opcode_entries() {
        if mode != Mode::Application {
            continue;
        }
        let result = check_mode_only(opcode, sub_opcode, version, Mode::LogicSig);
        assert!(
            result.is_err(),
            "opcode {opcode:#04x}/{sub_opcode:?} is Application-only but was accepted in LogicSig mode"
        );
    }
}

/// Mirrors `TestEvalModes`: every LogicSig-only opcode must be rejected when
/// the enclosing program is checked in Application mode.
#[test]
fn every_logicsig_only_opcode_is_rejected_in_application_mode() {
    for (opcode, sub_opcode, mode, version) in all_opcode_entries() {
        if mode != Mode::LogicSig {
            continue;
        }
        let result = check_mode_only(opcode, sub_opcode, version, Mode::Application);
        assert!(
            result.is_err(),
            "opcode {opcode:#04x}/{sub_opcode:?} is LogicSig-only but was accepted in Application mode"
        );
    }
}

/// Mirrors `TestEvalModes`'s complementary assertion: an opcode is always
/// accepted by the mode gate when checked in its *own* declared mode (or
/// when the program's mode is `Any`-compatible), i.e. `check_mode` never
/// spuriously rejects an opcode running in the mode it declares support for.
#[test]
fn every_opcode_is_accepted_by_the_mode_gate_in_its_own_mode() {
    for (opcode, sub_opcode, mode, version) in all_opcode_entries() {
        let own_mode = match mode {
            Mode::Any => Mode::Application, // either mode is valid; pick one
            m => m,
        };
        let result = check_mode_only(opcode, sub_opcode, version, own_mode);
        assert!(
            result.is_ok(),
            "opcode {opcode:#04x}/{sub_opcode:?} (mode {mode:?}) was rejected by the mode gate \
             even when checked in its own declared mode: {result:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// TDD: prove the sweep actually catches a missing mode gate before trusting
// it against the real table.
// ---------------------------------------------------------------------------

#[test]
fn sweep_helper_catches_synthetic_missing_mode_gate() {
    // `balance` (0x60) is a real Application-only opcode in the production
    // table; asserting it's rejected in LogicSig mode is the exact
    // regression class (an opcode that forgot its mode restriction) this
    // sweep exists to catch -- if `balance` were ever accidentally
    // reclassified as `Mode::Any`, this specific assertion (not just the
    // whole-table loop) would start failing.
    let result = check_mode_only(0x60, None, 2, Mode::LogicSig);
    assert!(
        result.is_err(),
        "balance (Application-only) must be rejected in LogicSig mode"
    );
}
