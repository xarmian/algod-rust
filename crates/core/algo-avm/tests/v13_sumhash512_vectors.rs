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

//! Byte-exact parity tests for the `sumhash512` opcode (0x86, TEAL v13).
//!
//! Consumes vectors captured from go-algorand's upstream
//! `github.com/algorand/go-sumhash` package (the same one
//! `data/transactions/logic/crypto.go:120` calls via `sumhash.New512(nil)`)
//! and drives them through the Rust AVM opcode handler directly.
//!
//! The opcode is dispatched from the bytecode when running a v13 program;
//! until TASK-49 bumps `MAX_AVM_VERSION` to 13, these tests exercise the
//! handler directly with a pre-pushed stack.

use algo_avm::bytecode::{Immediates, Instruction};
use algo_avm::machine::ExecMode;
use algo_avm::ops::crypto::op_sumhash512;
use algo_avm::{parse, AvmMachine, AvmValue, Program};

fn empty_program() -> Program {
    parse(&[0x01]).expect("v1 empty program must parse")
}

fn new_machine(budget: i64) -> AvmMachine {
    AvmMachine::new(empty_program(), ExecMode::LogicSig, budget)
}

fn fake_instr() -> Instruction {
    Instruction {
        opcode: 0x86,
        sub_opcode: None,
        offset: 0,
        immediates: Immediates::None,
    }
}

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    input_hex: String,
    output_hex: String,
}

fn load_vectors() -> Vec<Vector> {
    let data = include_str!("fixtures/v13/sumhash512/vectors.json");
    serde_json::from_str(data).expect("vectors.json must deserialize")
}

#[test]
fn sumhash512_parity_all_fixture_vectors() {
    let vectors = load_vectors();
    assert!(
        vectors.len() >= 20,
        "expected >= 20 fixture vectors, got {}",
        vectors.len()
    );

    for v in &vectors {
        let input = hex::decode(&v.input_hex).expect("input_hex decodes");
        let expected = hex::decode(&v.output_hex).expect("output_hex decodes");
        assert_eq!(expected.len(), 64, "sumhash-512 output must be 64 bytes");

        // Budget large enough for the largest vector
        // (~1MB → 150 + 4 * ceil(1048576/7) = ~600K).
        let mut machine = new_machine(4_000_000);
        machine.push(AvmValue::Bytes(input)).expect("push input");

        op_sumhash512(&mut machine, &fake_instr())
            .unwrap_or_else(|e| panic!("op_sumhash512 failed on vector {}: {e}", v.name));

        let top = machine.pop_bytes().expect("pop result");
        assert_eq!(
            top, expected,
            "sumhash512 output mismatch on vector {}",
            v.name
        );
    }
}

#[test]
fn sumhash512_costs_150_plus_4_per_7_byte_chunk() {
    // cost = baseCost + chunkCost * DivCeil(len, chunkSize)
    //      = 150 + 4 * DivCeil(len, 7)
    //
    // Matches go-algorand opcodes.go:704 `costByLength(150, 4, 7, 0)` (the
    // corrected, non-reversed argument order fixed by go-algorand PR #6695
    // "AVM: Fix reversed costs arguments" / commit e4b8e0eac, first released
    // in v5.0.0-beta but applying unconditionally to every LogicSigVersion
    // that carries sumhash512). Values below are pinned exactly to
    // go-algorand's `TestHashCosts` (data/transactions/logic/crypto_test.go).
    let starting_budget = 10_000i64;

    // size 0 -> 150
    let mut machine = new_machine(starting_budget);
    machine.push(AvmValue::Bytes(vec![])).unwrap();
    op_sumhash512(&mut machine, &fake_instr()).unwrap();
    assert_eq!(
        starting_budget - machine.budget,
        150,
        "size-0 cost must be 150"
    );

    // size 1 -> 154
    let mut machine = new_machine(starting_budget);
    machine.push(AvmValue::Bytes(vec![0xaa])).unwrap();
    op_sumhash512(&mut machine, &fake_instr()).unwrap();
    assert_eq!(
        starting_budget - machine.budget,
        154,
        "size-1 cost must be 154"
    );

    // size 64 -> 190
    let mut machine = new_machine(starting_budget);
    machine.push(AvmValue::Bytes(vec![0xaa; 64])).unwrap();
    op_sumhash512(&mut machine, &fake_instr()).unwrap();
    assert_eq!(
        starting_budget - machine.budget,
        190,
        "size-64 cost must be 190"
    );

    // size 1000 -> 722
    let mut machine = new_machine(starting_budget);
    machine.push(AvmValue::Bytes(vec![0xaa; 1000])).unwrap();
    op_sumhash512(&mut machine, &fake_instr()).unwrap();
    assert_eq!(
        starting_budget - machine.budget,
        722,
        "size-1000 cost must be 722"
    );
}

#[test]
fn sumhash512_budget_exhaustion_is_an_error() {
    // Budget less than the base cost of 150: must error.
    let mut machine = new_machine(10);
    machine.push(AvmValue::Bytes(vec![])).unwrap();
    assert!(op_sumhash512(&mut machine, &fake_instr()).is_err());
}
