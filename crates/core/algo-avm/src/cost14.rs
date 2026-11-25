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

//! The length-dependent opcode costs of AVM v14 (go-algorand v5.1,
//! `data/transactions/logic/opcodes.go` `costDescriptor`, `eval.go`
//! `bdivCost`/`bmulCost`/`bsqrtCost`/`bmodexpCost`; issue #2573).
//!
//! From `fullByteMathVersion` (14) the byte-math opcodes accept operands of
//! any length and charge for them; from `lengthCostVersion` (14) the opcodes
//! that copy a whole byte-array to change part of it (`setbyte`, `setbit`,
//! `replace2`, `replace3`) and `match` do too. Go computes the cost from the
//! stack as it stands before the opcode runs (`deets.Cost(program, pc,
//! stack)`); [`dynamic_cost`] is that computation, called by the machine
//! when it charges an instruction.

use crate::bytecode::{Immediates, Instruction};
use crate::machine::AvmValue;

/// go's `fullByteMathVersion`: byte math is unconstrained by `maxByteMathSize`,
/// has length-dependent costs, and `bmodexp` exists.
pub const FULL_BYTE_MATH_VERSION: u8 = 14;
/// go's `lengthCostVersion`: `setbyte`, `setbit`, `replace2`, `replace3` charge
/// for the array's length and `match` for each of its cases.
pub const LENGTH_COST_VERSION: u8 = 14;

/// The opcodes whose cost [`dynamic_cost`] computes at `version`.
pub fn has_dynamic_cost(opcode: u8, version: u8) -> bool {
    match opcode {
        // setbit, setbyte, replace2, replace3, match
        0x54 | 0x56 | 0x5c | 0x5d | 0x8e => version >= LENGTH_COST_VERSION,
        // bitlen, bsqrt, bmodexp, b+ .. b~
        0x93 | 0x96 | 0x99 | 0xa0..=0xae => version >= FULL_BYTE_MATH_VERSION,
        _ => false,
    }
}

/// Number of bytes of a stack value as go's `len(stackValue.Bytes)` sees it: a
/// uint64 has none.
fn blen(v: &AvmValue) -> usize {
    match v {
        AvmValue::Bytes(b) => b.len(),
        AvmValue::Uint64(_) => 0,
    }
}

fn bytes_of(v: &AvmValue) -> &[u8] {
    match v {
        AvmValue::Bytes(b) => b,
        AvmValue::Uint64(_) => &[],
    }
}

fn div_ceil(a: usize, b: usize) -> usize {
    a.div_ceil(b)
}

/// go's `costByLength(initial, perChunk, chunkSize, depth)`: the length of the
/// argument `depth` below the top.
fn by_length(stack: &[AvmValue], initial: usize, per: usize, chunk: usize, depth: usize) -> usize {
    let Some(top) = stack.len().checked_sub(1 + depth) else {
        return initial;
    };
    initial + per * div_ceil(blen(&stack[top]), chunk)
}

/// go's `costByLongest(initial, perChunk, chunkSize, args)`: the longest of the
/// top `args` arguments.
fn by_longest(stack: &[AvmValue], initial: usize, per: usize, chunk: usize, args: usize) -> usize {
    let count = stack
        .iter()
        .rev()
        .take(args)
        .map(blen)
        .max()
        .unwrap_or_default();
    initial + per * div_ceil(count, chunk)
}

/// go's `nonzero`: `b` without its leading zero bytes (empty if all zero).
fn nonzero(b: &[u8]) -> &[u8] {
    let skip = b.iter().take_while(|x| **x == 0).count();
    &b[skip..]
}

/// go's `bitlen`.
fn bitlen(b: &[u8]) -> usize {
    let nz = nonzero(b);
    match nz.first() {
        None => 0,
        Some(first) => (8 - first.leading_zeros() as usize) + 8 * (nz.len() - 1),
    }
}

fn ones_count(b: &[u8]) -> usize {
    b.iter().map(|x| x.count_ones() as usize).sum()
}

/// go's `divComplexity`.
pub(crate) fn div_complexity(la: usize, lb: usize, parsed: usize) -> usize {
    let quotient = la.saturating_sub(lb);
    let divisor = la.min(lb);
    10 + (1 + quotient / 16) * (8 + divisor / 16) / 2 + div_ceil(parsed, 32)
}

/// go's `divCost`.
fn div_cost(a: &[u8], b: &[u8]) -> usize {
    div_complexity(nonzero(a).len(), nonzero(b).len(), a.len().max(b.len()))
}

/// go's `mulComplexity`.
pub(crate) fn mul_complexity(la: usize, lb: usize) -> usize {
    const CHUNK: usize = 16;
    let (mut linear, mut factor) = (0, 6);
    if la.min(lb) >= 512 {
        factor = 12;
        linear = 4 * la.max(lb) / CHUNK;
    }
    linear + (8 + la / CHUNK) * (8 + lb / CHUNK) / factor
}

/// go's `modMulComplexity`.
pub(crate) fn mod_mul_complexity(lm: usize) -> usize {
    let w = div_ceil(lm, 8);
    2 + 2 * w + w * w / 10
}

/// go's `bsqrtCost`.
fn bsqrt_cost(a: &[u8]) -> usize {
    let l = a.len();
    let chunks = l / 96;
    // bits.Len(uint(l))
    let len_bits = (usize::BITS - l.leading_zeros()) as usize;
    5 + chunks * chunks * len_bits + l
}

/// go's `bmodexpCost`.
fn bmodexp_cost(base: &[u8], exp: &[u8], modulus: &[u8]) -> usize {
    let (lb, le, lm) = (base.len(), exp.len(), modulus.len());
    let exp_bits = bitlen(exp);
    let mut cost = 10 + div_ceil(lb + le + lm, 32);
    match exp_bits {
        0 => cost,
        1 => cost + div_cost(base, modulus),
        2..=64 => {
            let ones = ones_count(exp);
            cost += (exp_bits + ones) * (2 + mod_mul_complexity(lm));
            if lb > lm {
                let (sig_base, sig_mod) = (nonzero(base).len(), nonzero(modulus).len());
                cost += 3 * mul_complexity(lb, lb) + div_complexity(2 * sig_base, sig_mod, 2 * lb);
                cost += ones * (1 + (lb - lm) / 8) * (1 + lm / 8) / 2;
            }
            cost
        }
        _ => {
            let steps = 64 * div_ceil(exp_bits, 64) + 16;
            cost + div_cost(base, modulus) + steps * mod_mul_complexity(lm)
        }
    }
}

/// The v14 cost of `instr` given the stack before it runs, or `None` when the
/// opcode's cost is not a function of the stack computed here. Callers check
/// [`has_dynamic_cost`] first.
pub fn dynamic_cost(instr: &Instruction, stack: &[AvmValue]) -> Option<u64> {
    let n = stack.len();
    let top = |i: usize| n.checked_sub(1 + i).map(|k| &stack[k]);
    let cost = match instr.opcode {
        0x54 => by_length(stack, 1, 1, 32, 2), // setbit
        0x56 => by_length(stack, 1, 1, 32, 2), // setbyte
        0x5c => by_length(stack, 1, 1, 32, 1), // replace2
        0x5d => by_length(stack, 1, 1, 32, 2), // replace3
        0x8e => {
            // match: costByCount(1, 2): 1 + 2 per label; the count is the byte
            // after the opcode (missing, so free, if the program ends early).
            let labels = match instr.immediates {
                Immediates::Labels(ref l) => l.len(),
                _ => 0,
            };
            1 + 2 * labels
        }
        0x93 => by_length(stack, 1, 1, 32, 0), // bitlen
        0x96 => bsqrt_cost(bytes_of(top(0)?)), // bsqrt
        0x99 => bmodexp_cost(bytes_of(top(2)?), bytes_of(top(1)?), bytes_of(top(0)?)),
        0xa0 | 0xa1 => by_longest(stack, 2, 1, 32, 2), // b+, b-
        0xa2 | 0xaa => div_cost(bytes_of(top(1)?), bytes_of(top(0)?)), // b/, b%
        0xa3 => mul_complexity(blen(top(0)?), blen(top(1)?)), // b*
        0xa4..=0xa9 | 0xab..=0xad => by_longest(stack, 1, 1, 32, 2), // b< .. b!=, b| b& b^
        0xae => by_length(stack, 1, 1, 32, 0),         // b~
        _ => return None,
    };
    Some(cost as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    // go's `TestMulComplexity` (`eval_test.go`).
    #[test]
    fn mul_complexity_matches_go() {
        assert_eq!(mul_complexity(0, 0), 10);
        assert_eq!(mul_complexity(6, 7), 10);
        assert_eq!(mul_complexity(16, 7), 12);
        assert_eq!(mul_complexity(16, 16), 13);
        assert_eq!(mul_complexity(32, 16), 15);
        assert_eq!(mul_complexity(128, 128), 42);
        // continuity near the changeover at 512
        assert_eq!(mul_complexity(511, 511), 253);
        assert_eq!(mul_complexity(512, 512), 261);
        assert_eq!(mul_complexity(513, 513), 261);
        assert_eq!(mul_complexity(513, 511), 260);
        for la in 0..4096 {
            let (below, above) = (mul_complexity(la, 511), mul_complexity(la, 512));
            assert!(above >= below, "{la}");
            assert!(2 * (1 + la / 25) >= above - below, "{la}");
        }
        for la in (0..4096).step_by(7) {
            for lb in (0..4096).step_by(11) {
                assert_eq!(mul_complexity(la, lb), mul_complexity(lb, la));
            }
        }
    }

    fn bytes(n: usize) -> AvmValue {
        AvmValue::Bytes(vec![0xff; n])
    }

    // go's `TestCostByLongest`: `costDescriptor{2, 3 per 8 bytes, longestOf: 3}`
    // is not a table entry here; b+ is `2 + 1 per 32 bytes of the longer`.
    #[test]
    fn by_longest_charges_for_the_longer_operand() {
        // "1 + 1 per 32 bytes of 100 = 1 + 4"
        assert_eq!(by_longest(&[bytes(1), bytes(100)], 1, 1, 32, 2), 5);
        assert_eq!(by_longest(&[bytes(100), bytes(1)], 1, 1, 32, 2), 5);
        // "2 + 1 per 32 bytes of 100 = 2 + 4"
        assert_eq!(by_longest(&[bytes(100), bytes(1)], 2, 1, 32, 2), 6);
        // three arguments: 2 + 3 per 8 bytes of the longest of A, B and C
        let three = [bytes(9), bytes(1), AvmValue::Uint64(0)];
        assert_eq!(by_longest(&three, 2, 3, 8, 3), 2 + 3 * 2);
    }

    // The hand-computed bmodexp costs of go's `TestBytesModExp`: each is the
    // cost of the bmodexp instruction alone.
    #[test]
    fn bmodexp_cost_matches_go_s_hand_computed_regimes() {
        let c = |b: &[u8], e: &[u8], m: &[u8]| bmodexp_cost(b, e, m);
        // 5^0 mod 3: bitlen(B) is 0, so nothing beyond 10 + 1
        assert_eq!(c(&[5], &[0], &[3]), 11);
        // 5^1 mod 3: 10 + 1 + (10 + (1+0)*(8+0)/2 + 1)
        assert_eq!(c(&[5], &[1], &[3]), 26);
        // 2^11 mod 13: bitlen 4, popcount 3: 10 + 1 + (4+3)*(2+4)
        assert_eq!(c(&[2], &[0x0b], &[0x0d]), 53);
        // 258^3 mod 7: A longer than C
        assert_eq!(c(&[1, 2], &[3], &[7]), 81);
        // 2^(2^64) mod 13: two exponent words
        assert_eq!(c(&[2], &[1, 0, 0, 0, 0, 0, 0, 0, 0], &[0x0d]), 602);
        // (2^512-1)^1 mod (2^256-1), the modulus padded to 64 bytes
        let mut m = vec![0u8; 32];
        m.extend(vec![0xff; 32]);
        assert_eq!(c(&[0xff; 64], &[1], &m), 42);
        // 0^5 mod 7 and 7^0 mod 5 and x^0 mod 1
        assert_eq!(c(&[0], &[5], &[7]), 41);
        assert_eq!(c(&[7], &[0], &[5]), 11);
        assert_eq!(c(&[0x54, 0xb7], &[0], &[1]), 11);
    }

    /// Total cost of `source` assembled at `version` (LogicSig mode, no ledger).
    fn program_cost(source: &str, version: u8) -> u64 {
        use crate::machine::{AvmMachine, ExecMode};
        let src = format!(
            "#pragma version {version}
{source}"
        );
        let program = crate::assembler::assemble_string(&src)
            .expect("assembles")
            .program;
        let parsed = crate::bytecode::parse(&program).expect("parses");
        // this assembler lays an `intcblock` (cost 1) into any program that
        // pushes the constant 0; go's `pushint` programs have none: not counted
        let intcblocks = parsed
            .instructions
            .iter()
            .filter(|i| i.opcode == 0x20)
            .count() as u64;
        let mut m = AvmMachine::new(parsed, ExecMode::LogicSig, 1_000_000);
        m.run(&mut crate::context::NullContext).expect("runs");
        m.cost - intcblocks
    }

    // go's `TestCostByLongest` programs: 6 cost-1 opcodes besides the one tested.
    #[test]
    fn byte_math_programs_cost_what_go_charges_from_v14() {
        for op in ["b|", "b&", "b^"] {
            // 1 + 1 per 32 bytes of 100 = 1 + 4
            let a = format!(
                "pushbytes 0x01
pushint 100
bzero
{op}
len
pushint 100
=="
            );
            let b = format!(
                "pushint 100
bzero
pushbytes 0x01
{op}
len
pushint 100
=="
            );
            assert_eq!(program_cost(&a, 14), 6 + 5, "{op}");
            assert_eq!(program_cost(&b, 14), 6 + 5, "{op}");
            // before v14 these were a flat 6
            assert_eq!(
                program_cost(
                    &format!(
                        "pushbytes 0x01
pushbytes 0x02
{op}
len
pushint 1
=="
                    ),
                    13
                ),
                5 + 6,
                "{op} v13"
            );
        }
        // 2 + 1 per 32 bytes of 100 = 2 + 4
        assert_eq!(
            program_cost(
                "pushbytes 0x01
pushint 100
bzero
b+
len
pushint 1
==",
                14
            ),
            6 + 6
        );
        assert_eq!(
            program_cost(
                "pushint 100
bzero
pushbytes 0x01
b+
len
pushint 1
==",
                14
            ),
            6 + 6
        );
        assert_eq!(
            program_cost(
                "pushbytes 0x01
pushint 100
bzero
b-
len
pushint 1
==",
                14
            ),
            6 + 6
        );
    }

    // go's `modexpCost` hand-computed cases of `TestBytesModExp`: 4 pushbytes
    // and `==`/`pushbytes` are 5 cost-1 opcodes besides bmodexp.
    #[test]
    fn bmodexp_programs_cost_what_go_charges() {
        let p = |b: &str, e: &str, m: &str, r: &str| {
            program_cost(
                &format!(
                    "pushbytes {b}
pushbytes {e}
pushbytes {m}
bmodexp
pushbytes {r}
=="
                ),
                14,
            )
        };
        assert_eq!(p("0x05", "0x00", "0x03", "0x01"), 5 + 11);
        assert_eq!(p("0x05", "0x01", "0x03", "0x02"), 5 + 26);
        assert_eq!(p("0x02", "0x0b", "0x0d", "0x07"), 5 + 53);
        assert_eq!(p("0x0102", "0x03", "0x07", "0x06"), 5 + 81);
        assert_eq!(p("0x02", "0x010000000000000000", "0x0d", "0x03"), 5 + 602);
    }

    #[test]
    fn divmodw_expw_get_cheaper_and_match_charges_per_case_from_v14() {
        let divmodw = "pushint 1
pushint 0
pushint 0
pushint 3
divmodw
pop
pop
pop
pop
pushint 1";
        // 4 pushint + 4 pop + pushint = 9 cost-1 opcodes
        assert_eq!(program_cost(divmodw, 13), 9 + 20);
        assert_eq!(program_cost(divmodw, 14), 9 + 2);
        let expw = "pushint 2
pushint 3
expw
pop
pop
pushint 1";
        assert_eq!(program_cost(expw, 13), 5 + 10);
        assert_eq!(program_cost(expw, 14), 5 + 1);
        // match: costByCount(1, 2): 1 + 2 per label
        let m = "pushint 1
pushint 1
pushint 2
match a b
a:
b:
pushint 1";
        assert_eq!(program_cost(m, 13), 5);
        assert_eq!(program_cost(m, 14), 4 + 1 + 2 * 2);
    }

    /// Run `source` assembled at `version`; whether the program approved.
    fn accepts(source: &str, version: u8) -> bool {
        use crate::machine::{AvmMachine, ExecMode};
        let src = format!(
            "#pragma version {version}
{source}"
        );
        let program = crate::assembler::assemble_string(&src)
            .expect("assembles")
            .program;
        let parsed = crate::bytecode::parse(&program).expect("parses");
        let mut m = AvmMachine::new(parsed, ExecMode::LogicSig, 1_000_000);
        m.run(&mut crate::context::NullContext).expect("runs")
    }

    // go's `TestBytesZeroShared`, program part: go's bzero results share one
    // array, which must never be written. Values are owned here, so this is
    // the observable half: every op that modifies a bzero result leaves
    // the right bytes behind (and a second bzero is still all zeros).
    #[test]
    fn bzero_results_survive_every_modifying_op() {
        let program = "
int 0; bzero; byte 0x; ==; assert
int 8; bzero; int 0; int 1; setbyte; byte 0x0100000000000000; ==; assert
int 8; bzero; int 63; int 1; setbit; byte 0x0000000000000001; ==; assert
int 8; bzero; byte 0x01; replace2 1; byte 0x0001000000000000; ==; assert
int 8; bzero; int 2; byte 0x01; replace3; byte 0x0000010000000000; ==; assert
int 8; bzero; b~; byte 0xffffffffffffffff; ==; assert
int 8; bzero; byte 0x01; b|; byte 0x0000000000000001; ==; assert
int 8; bzero; byte 0x01; b^; byte 0x0000000000000001; ==; assert
int 8; bzero; byte 0x01; b&; byte 0x0000000000000000; ==; assert
int 8; bzero; byte 0x01; b+; byte 0x01; ==; assert
int 4; bzero; byte 0x01; concat; byte 0x0000000001; ==; assert
byte 0x01; int 4; bzero; concat; byte 0x0100000000; ==; assert
int 8; bzero; dup; int 0; int 1; setbyte; pop; byte 0x0000000000000000; ==
";
        for v in [7, 13, 14] {
            assert!(accepts(program, v), "v{v}");
        }
    }

    // v14 length costs of the copying opcodes (`lengthCostVersion`): 1 + 1 per
    // 32 bytes of the array, and `bitlen` likewise ("or 1 if A is a uint64").
    #[test]
    fn copying_opcodes_charge_for_the_array_length_from_v14() {
        // setbyte on 100 bytes: pushint 100, bzero, pushint 0, pushint 1, setbyte, len
        let setbyte = "pushint 100
bzero
pushint 7
pushint 1
setbyte
len
pushint 100
==";
        // 8 opcodes: 7 cost-1 besides setbyte, which costs 1 before v14 and 1 + 1 per
        // 32 bytes of 100 (= 5) from it
        assert_eq!(program_cost(setbyte, 13), 8);
        assert_eq!(program_cost(setbyte, 14), 8 + 4);
        let bitlen_uint = "pushint 5
bitlen
pushint 3
==";
        assert_eq!(program_cost(bitlen_uint, 14), program_cost(bitlen_uint, 13));
        let bitlen_bytes = "pushint 100
bzero
bitlen
pushint 0
==";
        assert_eq!(
            program_cost(bitlen_bytes, 14),
            program_cost(bitlen_bytes, 13) + 4
        );
    }

    // go's `TestBytesModExp`: its 24 vectors (`tests/fixtures/go_bmodexp_vectors.jsonl`,
    // extracted verbatim from go's test), each accepted / rejected / failing
    // with go's text, and costing exactly what go charges.
    #[test]
    fn bmodexp_matches_every_go_vector() {
        use crate::machine::{AvmMachine, ExecMode};
        let fixture = include_str!("../tests/fixtures/go_bmodexp_vectors.jsonl");
        let mut n = 0;
        for line in fixture.lines().filter(|l| !l.trim().is_empty()) {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let s = |k: &str| v[k].as_str().unwrap().to_string();
            let src = format!(
                "#pragma version 14
pushbytes {}
pushbytes {}
pushbytes {}
bmodexp
pushbytes {}
==",
                s("base"),
                s("exp"),
                s("modulus"),
                s("result")
            );
            let program = crate::assembler::assemble_string(&src)
                .expect("assembles")
                .program;
            let parsed = crate::bytecode::parse(&program).expect("parses");
            // (this assembler lays an `intcblock` into some programs; go has none)
            let intcblocks = parsed
                .instructions
                .iter()
                .filter(|i| i.opcode == 0x20)
                .count() as u64;
            let mut m = AvmMachine::new(parsed, ExecMode::LogicSig, 16 * 20_000);
            let run = m.run(&mut crate::context::NullContext);
            match s("outcome").as_str() {
                "accept" => {
                    assert!(run.unwrap(), "{line}");
                    assert_eq!(
                        m.cost - intcblocks,
                        v["cost"].as_u64().unwrap() + 5,
                        "{line}"
                    );
                }
                "reject" => {
                    assert!(!run.unwrap(), "{line}");
                    assert_eq!(v["cost"].as_u64().unwrap(), 0);
                }
                _ => {
                    let e = run.expect_err(line).to_string();
                    assert!(e.contains(&s("error")), "{line}: {e}");
                }
            }
            n += 1;
        }
        assert_eq!(n, 24);
    }

    // go's `TestRapidNonzero` (seeded): `nonzero` and `bitlen` against references.
    #[test]
    fn nonzero_and_bitlen_match_references() {
        use num_bigint::BigUint;
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        for i in 0..2000usize {
            let zeros = if i < 140 { i } else { (next() % 4097) as usize };
            let tail: Vec<u8> = (0..next() % 131).map(|_| next() as u8).collect();
            let mut input = vec![0u8; zeros];
            input.extend_from_slice(&tail);
            let want: &[u8] = match input.iter().position(|b| *b != 0) {
                Some(p) => &input[p..],
                None => &[],
            };
            assert_eq!(nonzero(&input), want);
            assert_eq!(bitlen(&input) as u64, BigUint::from_bytes_be(&input).bits());
        }
    }

    #[test]
    fn only_the_listed_opcodes_are_dynamic_and_only_from_v14() {
        for op in [
            0x54u8, 0x56, 0x5c, 0x5d, 0x8e, 0x93, 0x96, 0x99, 0xa0, 0xa9, 0xae,
        ] {
            assert!(!has_dynamic_cost(op, 13), "{op:#x}");
            assert!(has_dynamic_cost(op, 14), "{op:#x}");
        }
        for op in [0x01u8, 0x1f, 0x95, 0xaf, 0x85] {
            assert!(!has_dynamic_cost(op, 14), "{op:#x}");
        }
    }
}
