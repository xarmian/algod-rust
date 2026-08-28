//! Byte-exact parity tests for the `sha512` opcode (0x87, TEAL v13).
//!
//! Consumes vectors captured from go-algorand's underlying `crypto/sha512`
//! primitive (the same one `data/transactions/logic/crypto.go:128` calls into)
//! and drives them through the Rust AVM opcode handler directly.
//!
//! The opcode is dispatched from the bytecode when running a v13 program;
//! until TASK-49 bumps `MAX_AVM_VERSION` to 13, these tests exercise the
//! handler directly with a pre-pushed stack.

use algo_avm::bytecode::{Immediates, Instruction};
use algo_avm::machine::ExecMode;
use algo_avm::ops::crypto::op_sha512;
use algo_avm::{parse, AvmMachine, AvmValue, Program};

fn empty_program() -> Program {
    parse(&[0x01]).expect("v1 empty program must parse")
}

fn new_machine(budget: i64) -> AvmMachine {
    AvmMachine::new(empty_program(), ExecMode::LogicSig, budget)
}

fn fake_instr() -> Instruction {
    Instruction {
        opcode: 0x87,
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
    let data = include_str!("fixtures/v13/sha512/vectors.json");
    serde_json::from_str(data).expect("vectors.json must deserialize")
}

#[test]
fn sha512_parity_all_fixture_vectors() {
    let vectors = load_vectors();
    assert!(
        vectors.len() >= 20,
        "expected >= 20 fixture vectors, got {}",
        vectors.len()
    );

    for v in &vectors {
        let input = hex::decode(&v.input_hex).expect("input_hex decodes");
        let expected = hex::decode(&v.output_hex).expect("output_hex decodes");
        assert_eq!(expected.len(), 64, "SHA-512 output must be 64 bytes");

        // Budget large enough for the largest vector (~1MB → ~16.8M cost).
        let mut machine = new_machine(32_000_000);
        machine.push(AvmValue::Bytes(input)).expect("push input");

        op_sha512(&mut machine, &fake_instr())
            .unwrap_or_else(|e| panic!("op_sha512 failed on vector {}: {e}", v.name));

        let top = machine.pop_bytes().expect("pop result");
        assert_eq!(top, expected, "sha512 output mismatch on vector {}", v.name);
    }
}

#[test]
fn sha512_costs_15_plus_2_per_32_byte_chunk() {
    // cost = baseCost + chunkCost * DivCeil(len, chunkSize)
    //      = 15 + 2 * DivCeil(len, 32)
    //
    // Matches go-algorand opcodes.go:705 `costByLength(15, 2, 32, 0)` (the
    // corrected, non-reversed argument order fixed by go-algorand PR #6695
    // "AVM: Fix reversed costs arguments" / commit e4b8e0eac, first released
    // in v5.0.0-beta but applying unconditionally to every LogicSigVersion
    // that carries sha512). Values below are pinned exactly to
    // go-algorand's `TestHashCosts` (data/transactions/logic/crypto_test.go).
    let starting_budget = 10_000i64;

    // size 0 -> 15
    let mut machine = new_machine(starting_budget);
    machine.push(AvmValue::Bytes(vec![])).unwrap();
    op_sha512(&mut machine, &fake_instr()).unwrap();
    assert_eq!(
        starting_budget - machine.budget,
        15,
        "size-0 cost must be 15"
    );

    // size 1 -> 17
    let mut machine = new_machine(starting_budget);
    machine.push(AvmValue::Bytes(vec![0xaa])).unwrap();
    op_sha512(&mut machine, &fake_instr()).unwrap();
    assert_eq!(
        starting_budget - machine.budget,
        17,
        "size-1 cost must be 17"
    );

    // size 64 -> 19
    let mut machine = new_machine(starting_budget);
    machine.push(AvmValue::Bytes(vec![0xaa; 64])).unwrap();
    op_sha512(&mut machine, &fake_instr()).unwrap();
    assert_eq!(
        starting_budget - machine.budget,
        19,
        "size-64 cost must be 19"
    );

    // size 1000 -> 79
    let mut machine = new_machine(starting_budget);
    machine.push(AvmValue::Bytes(vec![0xaa; 1000])).unwrap();
    op_sha512(&mut machine, &fake_instr()).unwrap();
    assert_eq!(
        starting_budget - machine.budget,
        79,
        "size-1000 cost must be 79"
    );
}

#[test]
fn sha512_budget_exhaustion_is_an_error() {
    // Budget less than the base cost of 15: must error.
    let mut machine = new_machine(10);
    machine.push(AvmValue::Bytes(vec![])).unwrap();
    assert!(op_sha512(&mut machine, &fake_instr()).is_err());
}
