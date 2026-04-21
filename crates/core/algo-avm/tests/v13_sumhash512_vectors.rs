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
        // (~1MB → 150 + 7 * ceil(1048576/4) = ~1.8M).
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
fn sumhash512_costs_150_plus_7_per_4_byte_chunk() {
    // cost = baseCost + chunkCost * DivCeil(len, chunkSize)
    //      = 150 + 7 * DivCeil(len, 4)
    //
    // Matches go-algorand opcodes.go:657 `costByLength(150, 7, 4, 0)`.
    let starting_budget = 10_000i64;

    // Empty: 150 + 7 * ceil(0/4) = 150.
    let mut machine = new_machine(starting_budget);
    machine.push(AvmValue::Bytes(vec![])).unwrap();
    op_sumhash512(&mut machine, &fake_instr()).unwrap();
    assert_eq!(
        starting_budget - machine.budget,
        150,
        "empty-input cost must be 150"
    );

    // 1 byte: 150 + 7 * ceil(1/4) = 150 + 7 = 157.
    let mut machine = new_machine(starting_budget);
    machine.push(AvmValue::Bytes(vec![0xaa])).unwrap();
    op_sumhash512(&mut machine, &fake_instr()).unwrap();
    assert_eq!(
        starting_budget - machine.budget,
        157,
        "1-byte cost must be 157"
    );

    // 4 bytes: 150 + 7 * ceil(4/4) = 157.
    let mut machine = new_machine(starting_budget);
    machine
        .push(AvmValue::Bytes(vec![0xaa, 0xbb, 0xcc, 0xdd]))
        .unwrap();
    op_sumhash512(&mut machine, &fake_instr()).unwrap();
    assert_eq!(
        starting_budget - machine.budget,
        157,
        "4-byte cost must be 157"
    );

    // 5 bytes: 150 + 7 * ceil(5/4) = 150 + 14 = 164.
    let mut machine = new_machine(starting_budget);
    machine
        .push(AvmValue::Bytes(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee]))
        .unwrap();
    op_sumhash512(&mut machine, &fake_instr()).unwrap();
    assert_eq!(
        starting_budget - machine.budget,
        164,
        "5-byte cost must be 164"
    );
}

#[test]
fn sumhash512_budget_exhaustion_is_an_error() {
    // Budget less than the base cost of 150: must error.
    let mut machine = new_machine(10);
    machine.push(AvmValue::Bytes(vec![])).unwrap();
    assert!(op_sumhash512(&mut machine, &fake_instr()).is_err());
}
