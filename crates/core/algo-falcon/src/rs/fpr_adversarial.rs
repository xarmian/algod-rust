// Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand), and derives from the Falcon
// reference implementation (Falcon Project, MIT).
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

//! Adversarial differential hunt (issue #2016): the Rust `fpr` layer uses native
//! `f64`, the vendored C is built with `FALCON_FPEMU=1` (Pornin's integer
//! emulation). Random operands almost never reach the places where the two can
//! legitimately differ, so this module feeds both the operand classes that do:
//! exact round-to-nearest-even ties, subnormal and underflowing results,
//! signed zeros, huge exponent gaps (sticky bits), perfect squares and exact
//! quotients, i64 boundaries and exponent extremes. Every mismatch is sorted
//! into a class so that "bit-identical on everything Falcon can reach" and
//! "different only outside Falcon's domain" can be told apart.

use std::collections::BTreeMap;

use super::fpr::*;
use crate::c_internals as cint;

/// xorshift64* -- deterministic, so a failure reproduces from the printed case.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

const MANT_BITS: u32 = 52;

/// Divergent operand tuples kept per (operation, class) for the committed fixture.
const RECORDS_PER_CLASS: u64 = 6;

/// Mantissas that stress rounding: empty, tiny, half, all ones, alternating,
/// and the patterns around the round/sticky bits of a 53-bit result.
fn mantissas() -> Vec<u64> {
    let full = (1u64 << MANT_BITS) - 1;
    vec![
        0,
        1,
        2,
        3,
        1 << 25,
        1 << 26,
        (1 << 26) - 1,
        (1 << 51) - 1,
        1 << 51,
        (1 << 51) + 1,
        full - 1,
        full,
        0x5_5555_5555_5555 & full,
        0xA_AAAA_AAAA_AAAA & full,
        0x0_0000_FFFF_FFFF,
        0x8_0000_0000_0001 & full,
    ]
}

/// Biased exponents, from the subnormal edge to the infinity/NaN encoding.
fn exponents() -> Vec<u64> {
    let mut e: Vec<u64> = vec![
        0, // zero / subnormal
        1, 2, 3, 52, 53, 54, // near the smallest normals and the 2^-1022+52 mark
        300, 511, 512, 700,
    ];
    e.extend(990..=1060); // |x| in [2^-33, 2^37]: where Falcon lives
    e.extend([1400, 1534, 1535, 1536, 1600, 2040, 2045, 2046, 2047]);
    e
}

fn operands() -> Vec<f64> {
    let mut v = Vec::new();
    for &e in &exponents() {
        for &m in &mantissas() {
            for s in [0u64, 1] {
                v.push(f64::from_bits((s << 63) | (e << MANT_BITS) | m));
            }
        }
    }
    v
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Class {
    /// both zero, differing only in the sign of zero
    ZeroSign,
    /// an operand is a subnormal
    SubnormalOperand,
    /// an operand is infinity or NaN (FPEMU has no such values)
    NonFiniteOperand,
    /// the result underflows (native subnormal, or flushed to zero)
    Underflow,
    /// the result overflows to infinity
    Overflow,
    /// every operand and result is a normal finite number or zero: a real bug
    InDomain,
}

fn is_subnormal(x: f64) -> bool {
    x.is_subnormal()
}
fn is_nonfinite(x: f64) -> bool {
    !x.is_finite()
}

/// Whether the *exact* (infinitely precise) result of `op` on `ops` is below
/// the smallest normal number, i.e. where the C emulation flushes to zero.
/// Looking at the rounded result is not enough: a product just under
/// `f64::MIN_POSITIVE` rounds *up to* it in native arithmetic, so the exact
/// residual (a fused multiply-add is exact here) decides on which side of the
/// boundary the true result lies.
fn exact_result_underflows(op: &str, ops: &[f64], native: f64) -> bool {
    const MIN: f64 = f64::MIN_POSITIVE;
    // The residual of a product/quotient that is within an ulp of 2^-1022 is
    // itself ~2^-1076, i.e. below the smallest subnormal and lost. Scaling one
    // operand by 2^100 (exact: operands here are normal) moves the whole
    // computation far from the boundary, where the residual is representable.
    let scale = f64::from_bits((1023 + 100) << 52);
    let threshold = MIN * scale;
    match op {
        "mul" | "sqr" => {
            let (x, y) = if op == "mul" { (ops[0], ops[1]) } else { (ops[0], ops[0]) };
            let xs = x * scale;
            let p = xs * y;
            if p.abs() < threshold {
                return true;
            }
            if p.abs() == threshold {
                let e = xs.mul_add(y, -p); // exact: xs*y - p
                return e != 0.0 && e.is_sign_negative() != p.is_sign_negative();
            }
            false
        }
        "div" | "inv" => {
            let (x, y) = if op == "div" { (ops[0], ops[1]) } else { (1.0, ops[0]) };
            let xs = x * scale;
            let q = xs / y;
            if q.abs() < threshold {
                return true;
            }
            if q.abs() == threshold {
                let r = (-q).mul_add(y, xs); // exact: xs - q*y, so xs/y = q + r/y
                if r == 0.0 {
                    return false;
                }
                let delta_negative = r.is_sign_negative() != y.is_sign_negative();
                return delta_negative != q.is_sign_negative();
            }
            false
        }
        // x * 0.5 is exact except in the subnormal range, where it can round
        // up to the smallest normal
        "half" => ops[0].abs() < 2.0 * MIN,
        // sums/differences/doubling/negation/sqrt never round across the boundary
        _ => native.abs() < MIN,
    }
}

/// Classifies one mismatch. Each out-of-domain class has a *positive* test, so
/// a real bug (normal operands, a result that should be a normal number, yet
/// the two implementations disagree) can only end up as `InDomain`:
///
/// * `Overflow`: the true result exceeds the largest double (Rust gives
///   infinity); the emulation has no infinity and produces wrapped garbage;
/// * `ZeroSign`: both results are zero;
/// * `Underflow`: the exact result is below the smallest normal number and the
///   C flushed it (to zero, or to a stray subnormal).
///
/// `float_result` is false for operations returning an integer or a boolean
/// (`lt`, `rint`, `floor`, `trunc`, `of`): their result is not a double, so
/// only the operands can place them out of domain.
fn classify(op: &str, ops: &[f64], native: u64, emulated: u64, float_result: bool) -> Class {
    if ops.iter().any(|&o| is_nonfinite(o)) {
        return Class::NonFiniteOperand;
    }
    if ops.iter().any(|&o| is_subnormal(o)) {
        return Class::SubnormalOperand;
    }
    if !float_result {
        return Class::InDomain;
    }
    let (n, c) = (f64::from_bits(native), f64::from_bits(emulated));
    if n.is_infinite() {
        return Class::Overflow;
    }
    if n == 0.0 && c == 0.0 {
        return Class::ZeroSign;
    }
    // (the C normally flushes to exactly zero; for `half` just above the smallest
    // normal it leaves a stray subnormal -- still "below the normal range")
    if (c == 0.0 || c.is_subnormal()) && exact_result_underflows(op, ops, n) {
        return Class::Underflow;
    }
    Class::InDomain
}

/// One operation evaluated by the Rust `fpr` layer and by the emulated C
/// (`a` and `b` are the raw IEEE-754 bit patterns; unary operations ignore
/// `b`; comparisons and conversions return their integer result). Returns
/// `(rust, c)`.
pub(super) fn both(op: &str, a: u64, b: u64) -> (u64, u64) {
    let (x, y) = (f64::from_bits(a), f64::from_bits(b));
    // SAFETY: the C functions are pure arithmetic on their arguments.
    unsafe {
        match op {
            "add" => (fpr_add(x, y).to_bits(), cint::falcon_inner_fpr_add(a, b)),
            "sub" => (fpr_sub(x, y).to_bits(), cint::shim::falcon_shim_x_fpr_sub(a, b)),
            "mul" => (fpr_mul(x, y).to_bits(), cint::falcon_inner_fpr_mul(a, b)),
            "div" => (fpr_div(x, y).to_bits(), cint::falcon_inner_fpr_div(a, b)),
            "lt" => (u64::from(fpr_lt(x, y)), cint::shim::falcon_shim_x_fpr_lt(a, b) as u64),
            "inv" => (fpr_inv(x).to_bits(), cint::shim::falcon_shim_x_fpr_inv(a)),
            "sqr" => (fpr_sqr(x).to_bits(), cint::shim::falcon_shim_x_fpr_sqr(a)),
            "half" => (fpr_half(x).to_bits(), cint::shim::falcon_shim_x_fpr_half(a)),
            "double" => (fpr_double(x).to_bits(), cint::shim::falcon_shim_x_fpr_double(a)),
            "neg" => (fpr_neg(x).to_bits(), cint::shim::falcon_shim_x_fpr_neg(a)),
            "sqrt" => (fpr_sqrt(x).to_bits(), cint::falcon_inner_fpr_sqrt(a)),
            "rint" => (fpr_rint(x) as u64, cint::shim::falcon_shim_x_fpr_rint(a) as u64),
            "floor" => (fpr_floor(x) as u64, cint::shim::falcon_shim_x_fpr_floor(a) as u64),
            "trunc" => (fpr_trunc(x) as u64, cint::shim::falcon_shim_x_fpr_trunc(a) as u64),
            "of" => (fpr_of(a as i64).to_bits(), cint::shim::falcon_shim_x_fpr_of(a as i64)),
            _ => panic!("unknown operation {op}"),
        }
    }
}

/// Whether `op` returns a double (as opposed to a boolean or an integer).
fn float_result(op: &str) -> bool {
    !matches!(op, "lt" | "rint" | "floor" | "trunc" | "of")
}

const BINARY: [&str; 5] = ["add", "sub", "mul", "div", "lt"];
const UNARY: [&str; 10] = ["inv", "sqr", "half", "double", "neg", "sqrt", "rint", "floor", "trunc", "of"];

/// A recorded divergence: the operands and what each implementation returns.
#[derive(Clone, Debug)]
struct Record {
    op: &'static str,
    class: Class,
    a: u64,
    b: u64,
    rust: u64,
    c: u64,
}

#[derive(Default)]
struct Report {
    records: Vec<Record>,
    /// (op, class) -> (count, first examples)
    found: BTreeMap<(&'static str, Class), (u64, Vec<String>)>,
    compared: BTreeMap<&'static str, u64>,
}

impl Report {
    fn compare(&mut self, op: &'static str, ops: &[f64], native: u64, emulated: u64) {
        *self.compared.entry(op).or_default() += 1;
        if native == emulated {
            return;
        }
        let class = classify(op, ops, native, emulated, float_result(op));
        let entry = self.found.entry((op, class)).or_default();
        entry.0 += 1;
        if entry.0 <= RECORDS_PER_CLASS {
            self.records.push(Record {
                op,
                class,
                a: ops.first().map_or(0, |o| o.to_bits()),
                b: ops.get(1).map_or(0, |o| o.to_bits()),
                rust: native,
                c: emulated,
            });
        }
        if entry.1.len() < 3 {
            let operands: Vec<String> = ops.iter().map(|o| format!("{:#018x}", o.to_bits())).collect();
            entry.1.push(format!(
                "{op}({}) rust={native:#018x} c={emulated:#018x}",
                operands.join(", ")
            ));
        }
    }

    fn count(&self, class: Class) -> u64 {
        self.found.iter().filter(|((_, c), _)| *c == class).map(|(_, (n, _))| *n).sum()
    }

    fn print(&self) {
        println!("== fpr adversarial differential: operations compared");
        for (op, n) in &self.compared {
            println!("   {op:6} {n}");
        }
        if self.found.is_empty() {
            println!("== no mismatches");
        }
        for ((op, class), (n, examples)) in &self.found {
            println!("== MISMATCH {op} [{class:?}]: {n}");
            for e in examples {
                println!("     {e}");
            }
        }
    }
}

/// Operand pairs that are exact ties for add/mul/div, built by construction
/// rather than hoped for.
fn tie_pairs(rng: &mut Rng, n: usize) -> Vec<(f64, f64)> {
    let mut out = Vec::new();
    for _ in 0..n {
        let e = 1000 + rng.next() % 50;
        let m = rng.next() & ((1 << MANT_BITS) - 1);
        let x = f64::from_bits((e << MANT_BITS) | m);
        // y = ±2^(exp(x) - 53 + j): the half-ulp region of x
        let j = (rng.next() % 7) as i64 - 3;
        let ye = (e as i64 - 53 + j).clamp(1, 2046) as u64;
        let y = f64::from_bits(((rng.next() & 1) << 63) | (ye << MANT_BITS));
        out.push((x, y));
        // products of two 27-bit integers: 54-bit exact products (half-ulp ties)
        let a = (rng.next() % (1 << 27)) | (1 << 26);
        let b = (rng.next() % (1 << 27)) | (1 << 26);
        out.push((a as f64, b as f64));
        // exact and near-exact quotients
        let d = (rng.next() % (1 << 26)) + 1;
        let q = rng.next() % (1 << 26);
        out.push(((d * q) as f64, d as f64));
        out.push(((d * q + 1) as f64, d as f64));
    }
    out
}

fn run() -> Report {
    let mut r = Report::default();
    let ops = operands();
    let mut rng = Rng(0xA5A5_1234_DEAD_BEEF);

    let mut pairs: Vec<(f64, f64)> = Vec::new();
    for &x in &ops {
        // every operand against a rotating subset of the others keeps this
        // O(n * k) rather than O(n^2) while still crossing every class
        for _ in 0..40 {
            let y = ops[(rng.next() as usize) % ops.len()];
            pairs.push((x, y));
        }
    }
    pairs.extend(tie_pairs(&mut rng, 20_000));
    // the corners, all against all
    for &x in ops.iter().step_by(37) {
        for &y in ops.iter().step_by(41) {
            pairs.push((x, y));
        }
    }

    for &(x, y) in &pairs {
        let (xb, yb) = (x.to_bits(), y.to_bits());
        for op in BINARY {
            // C's fpr_div is undefined for a zero divisor
            if op == "div" && y == 0.0 {
                continue;
            }
            let (rs, c) = both(op, xb, yb);
            r.compare(op, &[x, y], rs, c);
        }
        for op in UNARY {
            let x = match op {
                "inv" if x == 0.0 => continue,
                // sqrt of a negative number is out of the algorithm's domain
                "sqrt" => x.abs(),
                // integer conversions only make sense for finite values
                "rint" | "floor" | "trunc" if !x.is_finite() => continue,
                "of" => continue,
                _ => x,
            };
            let (rs, c) = both(op, x.to_bits(), 0);
            r.compare(op, &[x], rs, c);
        }
    }
    {
        // perfect squares and their neighbours
        for _ in 0..50_000 {
            let k = rng.next() % (1 << 26) + 1;
            for v in [k * k, k * k + 1, k * k - 1] {
                let x = v as f64;
                let (rs, c) = both("sqrt", x.to_bits(), 0);
                r.compare("sqrt", &[x], rs, c);
            }
        }
        // i64 boundaries through fpr_of
        let mut ints: Vec<i64> = vec![0, 1, -1, i64::MAX, i64::MIN, i64::MAX - 1, i64::MIN + 1];
        for s in 50..63 {
            for d in [-2i64, -1, 0, 1, 2] {
                ints.push((1i64 << s).wrapping_add(d));
                ints.push((-(1i64 << s)).wrapping_add(d));
            }
        }
        for _ in 0..50_000 {
            ints.push((rng.next() as i64) >> (rng.next() % 64));
        }
        for i in ints {
            let (rs, c) = both("of", i as u64, 0);
            r.compare("of", &[], rs, c);
        }
    }
    r
}

#[test]
fn adversarial_operands_report() {
    let r = run();
    r.print();
    let in_domain = r.count(Class::InDomain);
    assert_eq!(in_domain, 0, "in-domain mismatches between the Rust fpr layer and the emulated C: see report above");
}

/// Keygen and signing never leave the domain in which the Rust and the
/// emulated C agree bit for bit: normal finite numbers (no subnormals, no
/// infinities/NaNs), exponents hundreds of binades away from both limits, and
/// none of the two operations that treat `-0` differently ever see it.
#[test]
fn falcon_keygen_and_signing_stay_inside_the_bit_identical_domain() {
    use super::fpr::domain;

    // 10 keys x 6 messages in CI; scale up by hand for a heavier measurement
    let env = |name: &str, default: u32| {
        std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
    };
    let (seeds, messages) = (env("FALCON_DOMAIN_SEEDS", 10), env("FALCON_DOMAIN_MESSAGES", 6));
    domain::reset();
    for seed in 0u32..seeds {
        let seed_bytes = [seed as u8, (seed >> 8) as u8, 7, 7, 7, 7, 7, 7];
        let (pubkey, privkey) = crate::backend::rust::keygen(&seed_bytes).expect("keygen");
        assert_eq!(pubkey.len(), crate::FALCON_DET1024_PUBKEY_SIZE);
        for m in 0u32..messages {
            let mut msg = vec![0u8; (m as usize) * 37 % 400];
            for (i, b) in msg.iter_mut().enumerate() {
                *b = (i as u32).wrapping_mul(31).wrapping_add(m + seed) as u8;
            }
            crate::backend::rust::sign(&privkey, &msg).expect("sign");
        }
    }
    let st = domain::take();
    println!("== falcon domain over keygen + signing: {st:?}");
    // (keygen alone is ~10^7 operations per key: this proves the layer is exercised)
    assert!(st.ops > 10_000_000 * u64::from(seeds), "the run must exercise the fpr layer: {st:?}");
    assert_eq!(st.subnormal, 0, "{st:?}");
    assert_eq!(st.nonfinite, 0, "{st:?}");
    assert_eq!(st.div_zero_over_negative, 0, "fpr_div(0, negative) differs in the sign of zero: {st:?}");
    assert_eq!(st.half_negative_zero, 0, "fpr_half(-0) differs in the sign of zero: {st:?}");
    // The smallest normal is 2^-1022 and the largest 2^1023. Keygen's big-integer
    // to floating-point conversions reach about 2^+-572 (observed), i.e. ~450
    // binades short of either limit, so neither underflow (where FPEMU flushes
    // to zero) nor overflow (where FPEMU has no infinity) is reachable.
    assert!(st.min_exp > -800, "{st:?}");
    assert!(st.max_exp < 800, "{st:?}");
}

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/falcon/fpr_divergences.jsonl");

fn class_name(c: Class) -> &'static str {
    match c {
        Class::ZeroSign => "zero-sign",
        Class::SubnormalOperand => "subnormal-operand",
        Class::NonFiniteOperand => "non-finite-operand",
        Class::Underflow => "underflow",
        Class::Overflow => "overflow",
        Class::InDomain => "in-domain",
    }
}

/// Regenerates `tests/fixtures/falcon/fpr_divergences.jsonl` (run by hand:
/// `FALCON_WRITE_FPR_DIVERGENCES=1 cargo test -p algo-falcon --features
/// c-internals-test --lib write_divergence_fixture`).
#[test]
fn write_divergence_fixture() {
    if std::env::var_os("FALCON_WRITE_FPR_DIVERGENCES").is_none() {
        return;
    }
    let r = run();
    let mut lines = Vec::new();
    for rec in &r.records {
        lines.push(format!(
            "{{\"op\":\"{}\",\"class\":\"{}\",\"a\":\"{:#018x}\",\"b\":\"{:#018x}\",\"rust\":\"{:#018x}\",\"c\":\"{:#018x}\"}}",
            rec.op,
            class_name(rec.class),
            rec.a,
            rec.b,
            rec.rust,
            rec.c
        ));
    }
    lines.sort();
    std::fs::write(FIXTURE, lines.join("\n") + "\n").unwrap();
    println!("wrote {} records to {FIXTURE}", lines.len());
}

fn hex_field(line: &str, key: &str) -> u64 {
    let pat = format!("\"{key}\":\"");
    let start = line.find(&pat).unwrap_or_else(|| panic!("no {key} in {line}")) + pat.len();
    let end = start + line[start..].find('"').unwrap();
    u64::from_str_radix(line[start..end].trim_start_matches("0x"), 16).unwrap()
}

fn str_field<'a>(line: &'a str, key: &str) -> &'a str {
    let pat = format!("\"{key}\":\"");
    let start = line.find(&pat).unwrap_or_else(|| panic!("no {key} in {line}")) + pat.len();
    let end = start + line[start..].find('"').unwrap();
    &line[start..end]
}

/// The committed fixture is the test data asked for in issue #2016: operand
/// tuples on which the Rust `fpr` layer and the emulated C are NOT
/// bit-identical. Replaying it pins both sides of every divergence (a change
/// to either implementation shows up here) and proves each one lies outside
/// the domain Falcon reaches (see the domain test above).
#[test]
fn committed_divergences_are_still_divergent_and_out_of_domain() {
    let text = std::fs::read_to_string(FIXTURE).expect("fpr_divergences.jsonl");
    let mut classes: std::collections::BTreeSet<String> = Default::default();
    let mut n = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let op = str_field(line, "op");
        let (a, b) = (hex_field(line, "a"), hex_field(line, "b"));
        let (rust, c) = both(op, a, b);
        assert_eq!(rust, hex_field(line, "rust"), "Rust result changed: {line}");
        assert_eq!(c, hex_field(line, "c"), "C result changed: {line}");
        assert_ne!(rust, c, "no longer a divergence: {line}");
        let class = str_field(line, "class");
        assert_ne!(class, "in-domain", "an in-domain divergence must be fixed, not recorded: {line}");
        classes.insert(class.to_string());
        n += 1;
    }
    assert!(n >= 50, "fixture unexpectedly small: {n}");
    for want in ["zero-sign", "subnormal-operand", "non-finite-operand", "underflow", "overflow"] {
        assert!(classes.contains(want), "fixture lacks the {want} class");
    }
}
