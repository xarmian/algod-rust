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

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use algo_avm::bytecode::parse;
use algo_avm::machine::{AvmMachine, ExecMode};
use algo_avm::NullContext;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a raw AVM program: version byte followed by opcode bytes.
fn prog(version: u8, code: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(1 + code.len());
    p.push(version);
    p.extend_from_slice(code);
    p
}

/// Encode a u64 as a varuint (unsigned LEB128) suitable for pushint immediates.
fn varuint(mut v: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if v == 0 {
            break;
        }
    }
    buf
}

/// Build a program that pushes two ints, adds them, pops the result, repeated
/// `n` times, then pushes 1 and returns (so the program approves).
///
/// Layout per iteration: pushint A, pushint B, +, pop
/// Final: pushint 1, return
fn arithmetic_program(n: usize) -> Vec<u8> {
    let mut code = Vec::new();
    for i in 0..n {
        // pushint <i>
        code.push(0x81);
        code.extend_from_slice(&varuint(i as u64));
        // pushint 1
        code.push(0x81);
        code.push(0x01);
        // + (0x08)
        code.push(0x08);
        // pop (0x48)
        code.push(0x48);
    }
    // pushint 1 (for approval)
    code.push(0x81);
    code.push(0x01);
    // return
    code.push(0x43);
    prog(3, &code)
}

/// Build a program that repeatedly concatenates byte strings.
///
/// Pushes a short byte string, then `n` times: pushes another short string and
/// concatenates. Finally pops the result, pushes 1, and returns.
fn concat_program(n: usize) -> Vec<u8> {
    // pushbytes "ab" (2 bytes)
    let mut code = vec![0x80, 0x02, b'a', b'b'];

    for _ in 0..n {
        // pushbytes "cd"
        code.push(0x80);
        code.push(0x02);
        code.push(b'c');
        code.push(b'd');
        // concat (0x50)
        code.push(0x50);
    }

    // pop the accumulated bytes
    code.push(0x48);
    // pushint 1
    code.push(0x81);
    code.push(0x01);
    // return
    code.push(0x43);
    prog(3, &code)
}

/// Build a program that hashes a byte string with sha256 `n` times
/// (each time feeding the previous hash output back in), then pops the
/// result, pushes 1, and returns.
fn sha256_program(n: usize) -> Vec<u8> {
    let mut code = Vec::new();
    // pushbytes with 32 bytes of data (simulating a hash-sized input)
    code.push(0x80);
    code.push(0x20); // length = 32
    code.extend_from_slice(&[0xABu8; 32]);

    // sha256 (0x01) repeated n times
    code.resize(code.len() + n, 0x01);

    // pop result
    code.push(0x48);
    // pushint 1
    code.push(0x81);
    code.push(0x01);
    // return
    code.push(0x43);
    prog(3, &code)
}

/// Build a program that hashes a byte string with keccak256 `n` times,
/// then pops the result, pushes 1, and returns.
fn keccak256_program(n: usize) -> Vec<u8> {
    let mut code = Vec::new();
    // pushbytes with 32 bytes of data
    code.push(0x80);
    code.push(0x20); // length = 32
    code.extend_from_slice(&[0xCDu8; 32]);

    // keccak256 (0x02) repeated n times
    code.resize(code.len() + n, 0x02);

    // pop result
    code.push(0x48);
    // pushint 1
    code.push(0x81);
    code.push(0x01);
    // return
    code.push(0x43);
    prog(3, &code)
}

/// Build a program with many diverse instructions for a larger parse benchmark.
///
/// Includes intcblock, bytecblock, arithmetic, branching, byte ops.
fn large_parse_program() -> Vec<u8> {
    let mut code = Vec::new();

    // intcblock with 4 values
    code.push(0x20); // intcblock
    code.push(0x04); // count = 4
    code.extend_from_slice(&varuint(0));
    code.extend_from_slice(&varuint(1));
    code.extend_from_slice(&varuint(42));
    code.extend_from_slice(&varuint(1_000_000));

    // bytecblock with 2 entries
    code.push(0x26); // bytecblock
    code.push(0x02); // count = 2
    code.push(0x03); // len = 3
    code.extend_from_slice(b"foo");
    code.push(0x04); // len = 4
    code.extend_from_slice(b"bar!");

    // 50 rounds of: intc_0, intc_1 (pushes 0 and 1), +, pop
    for _ in 0..50 {
        code.push(0x22); // intc_0
        code.push(0x23); // intc_1
        code.push(0x08); // +
        code.push(0x48); // pop
    }

    // 20 rounds of: bytec_0, bytec_1, concat, pop
    for _ in 0..20 {
        code.push(0x28); // bytec_0
        code.push(0x29); // bytec_1
        code.push(0x50); // concat
        code.push(0x48); // pop
    }

    // pushint 1, return
    code.push(0x81);
    code.push(0x01);
    code.push(0x43);

    prog(3, &code)
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_parse_simple(c: &mut Criterion) {
    // A small program: pushint 1, pushint 2, +, pushint 1, return
    let raw = prog(3, &[0x81, 0x01, 0x81, 0x02, 0x08, 0x81, 0x01, 0x43]);

    c.bench_function("parse: simple (4 instructions)", |b| {
        b.iter(|| {
            let _ = parse(black_box(&raw)).unwrap();
        });
    });
}

fn bench_parse_large(c: &mut Criterion) {
    let raw = large_parse_program();
    let instr_count = parse(&raw).unwrap().instructions.len();

    c.bench_function(&format!("parse: large ({instr_count} instructions)"), |b| {
        b.iter(|| {
            let _ = parse(black_box(&raw)).unwrap();
        });
    });
}

fn bench_arithmetic_execution(c: &mut Criterion) {
    // 100 iterations of pushint/pushint/add/pop
    let raw = arithmetic_program(100);
    let budget = 20_000;

    c.bench_function("exec: arithmetic 100 add+pop cycles", |b| {
        b.iter(|| {
            let program = parse(black_box(&raw)).unwrap();
            let mut machine = AvmMachine::new(program, ExecMode::LogicSig, budget);
            machine.run(&mut NullContext).unwrap();
        });
    });

    // Also bench a smaller iteration for comparison
    let raw_10 = arithmetic_program(10);
    c.bench_function("exec: arithmetic 10 add+pop cycles", |b| {
        b.iter(|| {
            let program = parse(black_box(&raw_10)).unwrap();
            let mut machine = AvmMachine::new(program, ExecMode::LogicSig, budget);
            machine.run(&mut NullContext).unwrap();
        });
    });
}

fn bench_concat_execution(c: &mut Criterion) {
    let raw = concat_program(50);
    let budget = 20_000;

    c.bench_function("exec: concat 50 iterations (2-byte strings)", |b| {
        b.iter(|| {
            let program = parse(black_box(&raw)).unwrap();
            let mut machine = AvmMachine::new(program, ExecMode::LogicSig, budget);
            machine.run(&mut NullContext).unwrap();
        });
    });
}

fn bench_sha256_execution(c: &mut Criterion) {
    // 10 chained sha256 hashes (each costs 35 budget)
    let raw = sha256_program(10);
    let budget = 20_000;

    c.bench_function("exec: sha256 x10 (chained, 32-byte input)", |b| {
        b.iter(|| {
            let program = parse(black_box(&raw)).unwrap();
            let mut machine = AvmMachine::new(program, ExecMode::LogicSig, budget);
            machine.run(&mut NullContext).unwrap();
        });
    });

    // Single sha256
    let raw_1 = sha256_program(1);
    c.bench_function("exec: sha256 x1 (32-byte input)", |b| {
        b.iter(|| {
            let program = parse(black_box(&raw_1)).unwrap();
            let mut machine = AvmMachine::new(program, ExecMode::LogicSig, budget);
            machine.run(&mut NullContext).unwrap();
        });
    });
}

fn bench_keccak256_execution(c: &mut Criterion) {
    // 10 chained keccak256 hashes (each costs 130 budget)
    let raw = keccak256_program(10);
    let budget = 20_000;

    c.bench_function("exec: keccak256 x10 (chained, 32-byte input)", |b| {
        b.iter(|| {
            let program = parse(black_box(&raw)).unwrap();
            let mut machine = AvmMachine::new(program, ExecMode::LogicSig, budget);
            machine.run(&mut NullContext).unwrap();
        });
    });

    // Single keccak256
    let raw_1 = keccak256_program(1);
    c.bench_function("exec: keccak256 x1 (32-byte input)", |b| {
        b.iter(|| {
            let program = parse(black_box(&raw_1)).unwrap();
            let mut machine = AvmMachine::new(program, ExecMode::LogicSig, budget);
            machine.run(&mut NullContext).unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_parse_simple,
    bench_parse_large,
    bench_arithmetic_execution,
    bench_concat_execution,
    bench_sha256_execution,
    bench_keccak256_execution,
);
criterion_main!(benches);
