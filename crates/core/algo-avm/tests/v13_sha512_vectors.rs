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
fn sha512_costs_15_plus_32_per_2_byte_chunk() {
    // cost = baseCost + chunkCost * DivCeil(len, chunkSize)
    //      = 15 + 32 * DivCeil(len, 2)
    //
    // Matches go-algorand opcodes.go:658 `costByLength(15, 32, 2, 0)`.
    // For empty input: 15 + 32 * ceil(0/2) = 15 + 0 = 15.
    let starting_budget = 10_000i64;

    let mut machine = new_machine(starting_budget);
    machine.push(AvmValue::Bytes(vec![])).unwrap();
    op_sha512(&mut machine, &fake_instr()).unwrap();
    assert_eq!(
        starting_budget - machine.budget,
        15,
        "empty-input cost must be 15"
    );

    // For 1 byte: 15 + 32 * ceil(1/2) = 15 + 32 * 1 = 47.
    let mut machine = new_machine(starting_budget);
    machine.push(AvmValue::Bytes(vec![0xaa])).unwrap();
    op_sha512(&mut machine, &fake_instr()).unwrap();
    assert_eq!(
        starting_budget - machine.budget,
        47,
        "1-byte cost must be 47"
    );

    // For 2 bytes: 15 + 32 * ceil(2/2) = 15 + 32 = 47.
    let mut machine = new_machine(starting_budget);
    machine.push(AvmValue::Bytes(vec![0xaa, 0xbb])).unwrap();
    op_sha512(&mut machine, &fake_instr()).unwrap();
    assert_eq!(
        starting_budget - machine.budget,
        47,
        "2-byte cost must be 47"
    );

    // For 3 bytes: 15 + 32 * ceil(3/2) = 15 + 64 = 79.
    let mut machine = new_machine(starting_budget);
    machine
        .push(AvmValue::Bytes(vec![0xaa, 0xbb, 0xcc]))
        .unwrap();
    op_sha512(&mut machine, &fake_instr()).unwrap();
    assert_eq!(
        starting_budget - machine.budget,
        79,
        "3-byte cost must be 79"
    );
}

#[test]
fn sha512_budget_exhaustion_is_an_error() {
    // Budget less than the base cost of 15: must error.
    let mut machine = new_machine(10);
    machine.push(AvmValue::Bytes(vec![])).unwrap();
    assert!(op_sha512(&mut machine, &fake_instr()).is_err());
}
