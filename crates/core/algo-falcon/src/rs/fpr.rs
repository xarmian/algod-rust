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

//! Floating-point layer (`fpr.h` / `fpr.c`): the `fpr` type and the small
//! set of operations the FFT, the sampler and key generation use.
//!
//! Ported from the Falcon reference implementation, `falcon-c/fpr.h` and
//! `falcon-c/fpr.c` (Copyright (c) 2017-2019 Falcon Project, MIT License,
//! author Thomas Pornin), vendored verbatim under
//! `crates/core/algo-falcon/falcon-c/` as part of github.com/algorand/falcon
//! v0.1.0; the MIT notice is preserved in `falcon-c/LICENSE`.
//!
//! # Why this is bit-identical to the C build
//!
//! The vendored C is compiled with `FALCON_FPEMU=1`: every `fpr` operation
//! is an integer emulation of IEEE-754 binary64 with round-to-nearest-even,
//! written so that a strict native `double` build (`FALCON_FPNATIVE`, no
//! FMA contraction, no extended precision) produces the same bits. Rust's
//! `f64` is exactly that: `+ - * /` and `sqrt` are correctly rounded on
//! every target, Rust never contracts into FMA, and x86-64 uses SSE2 rather
//! than x87. Falcon never reaches subnormals, infinities or NaNs. So this
//! module is the `FALCON_FPNATIVE` branch of `fpr.h`, with three deliberate
//! exceptions, all proven by the differential tests against the emulated C:
//!
//! 1. **`expm_p63` is the emulated, 64-bit fixed-point version** from
//!    `fpr.c`, not the native branch's double Horner evaluation: the two are
//!    *not* bit-identical in their low bits, and this value feeds the
//!    Gaussian sampler, i.e. the signature. The one floating-point step it
//!    needs (`trunc(x * 2^63)`) is identical in both builds.
//! 2. Every constant is taken from the `FALCON_FPEMU` section as a bit
//!    pattern (`f64::from_bits`), never from a decimal literal.
//! 3. `rint`, `floor` and `trunc` are the emulated branch's bit-level
//!    algorithms (not `f64::round`, which rounds half away from zero, and
//!    not `as i64`, which saturates where the C wraps or zeroes), so they
//!    agree with the C build on every input, not just the in-range ones.

use super::fpr_tables::{GM_TAB_BITS, P2_TAB_BITS};

/// The Falcon floating-point type: an IEEE-754 binary64.
pub(crate) type Fpr = f64;

const fn c(bits: u64) -> Fpr {
    f64::from_bits(bits)
}

const fn table<const N: usize>(bits: [u64; N]) -> [Fpr; N] {
    let mut out = [0.0f64; N];
    let mut i = 0;
    while i < N {
        out[i] = f64::from_bits(bits[i]);
        i += 1;
    }
    out
}

// Constants, as the `FALCON_FPEMU` bit patterns in `fpr.h`.
pub(crate) const FPR_Q: Fpr = c(4667981563525332992);
pub(crate) const FPR_INVERSE_OF_Q: Fpr = c(4545632735260551042);
pub(crate) const FPR_INV_2SQRSIGMA0: Fpr = c(4594603506513722306);
pub(crate) const FPR_INV_SIGMA: [Fpr; 11] = table([
    0,
    4574611497772390042,
    4574501679055810265,
    4574396282908341804,
    4574245855758572086,
    4574103865040221165,
    4573969550563515544,
    4573842244705920822,
    4573721358406441454,
    4573606369665796042,
    4573496814039276259,
]);
pub(crate) const FPR_SIGMA_MIN: [Fpr; 11] = table([
    0,
    4607707126469777035,
    4607777455861499430,
    4607846828256951418,
    4607949175006100261,
    4608049571757433526,
    4608148125896792003,
    4608244935301382692,
    4608340089478362016,
    4608433670533905013,
    4608525754002622308,
]);
pub(crate) const FPR_LOG2: Fpr = c(4604418534313441775);
pub(crate) const FPR_INV_LOG2: Fpr = c(4609176140021203710);
pub(crate) const FPR_BNORM_MAX: Fpr = c(4670353323383631276);
pub(crate) const FPR_ZERO: Fpr = c(0);
pub(crate) const FPR_ONE: Fpr = c(4607182418800017408);
pub(crate) const FPR_TWO: Fpr = c(4611686018427387904);
pub(crate) const FPR_ONEHALF: Fpr = c(4602678819172646912);
pub(crate) const FPR_INVSQRT2: Fpr = c(4604544271217802189);
pub(crate) const FPR_INVSQRT8: Fpr = c(4600040671590431693);
pub(crate) const FPR_PTWO31: Fpr = c(4746794007248502784);
pub(crate) const FPR_PTWO31M1: Fpr = c(4746794007244308480);
pub(crate) const FPR_MTWO31M1: Fpr = c(13970166044099084288);
pub(crate) const FPR_PTWO63M1: Fpr = c(4890909195324358656);
pub(crate) const FPR_MTWO63M1: Fpr = c(14114281232179134464);
pub(crate) const FPR_PTWO63: Fpr = c(4890909195324358656);

/// `fpr_gm_tab`: FFT roots of unity as `[re, im]` pairs.
pub(crate) const FPR_GM_TAB: [Fpr; 2048] = table(GM_TAB_BITS);
/// `fpr_p2_tab`: `2^(1-k)` for `k` in `0..=10` (`2.0, 1.0, 0.5, ...`).
pub(crate) const FPR_P2_TAB: [Fpr; 11] = table(P2_TAB_BITS);

/// `fpr_of`: exact conversion of a small integer.
#[inline(always)]
pub(crate) fn fpr_of(i: i64) -> Fpr {
    let r = i as f64;
    #[cfg(all(test, feature = "c-internals-test"))]
    domain::note(r);
    r
}

/// `fpr_ursh`: `x >> n` for `n` in `0..=63`, written as the C does (two
/// steps) so that no shift count ever reaches the operand width.
#[inline(always)]
fn fpr_ursh(mut x: u64, n: u32) -> u64 {
    x ^= (x ^ (x >> 32)) & (u64::from(n >> 5)).wrapping_neg();
    x >> (n & 31)
}

/// `fpr_irsh`: arithmetic `x >> n` for `n` in `0..=63`.
#[inline(always)]
fn fpr_irsh(mut x: i64, n: u32) -> i64 {
    x ^= (x ^ (x >> 32)) & (i64::from(n >> 5)).wrapping_neg();
    x >> (n & 31)
}

/// `fpr_ulsh`: `x << n` for `n` in `0..=63`.
#[inline(always)]
fn fpr_ulsh(mut x: u64, n: u32) -> u64 {
    x ^= (x ^ (x << 32)) & (u64::from(n >> 5)).wrapping_neg();
    x << (n & 31)
}

/// `fpr_rint`: round to nearest, ties to even, as an `i64`.
///
/// This is the `FALCON_FPEMU` algorithm (pure bit manipulation of the
/// binary64 encoding), ported verbatim so that every input — including the
/// out-of-`i64`-range values where a native `(int64_t)` cast is
/// implementation-defined — gives the C build's result.
#[inline]
pub(crate) fn fpr_rint(x: Fpr) -> i64 {
    #[cfg(all(test, feature = "c-internals-test"))]
    domain::note(x);
    let x = x.to_bits();
    let mut m: u64 = ((x << 10) | (1u64 << 62)) & ((1u64 << 63) - 1);
    let mut e: i32 = 1085 - ((x >> 52) as i32 & 0x7FF);
    m &= (u64::from(((e - 64) as u32) >> 31)).wrapping_neg();
    e &= 63;
    let d: u64 = fpr_ulsh(m, (63 - e) as u32);
    let dd: u32 = (d as u32) | ((d >> 32) as u32 & 0x1FFF_FFFF);
    let f: u32 = ((d >> 61) as u32) | ((dd | dd.wrapping_neg()) >> 31);
    m = fpr_ursh(m, e as u32).wrapping_add(u64::from((0xC8u32 >> f) & 1));
    let s: u32 = (x >> 63) as u32;
    ((m as i64) ^ (i64::from(s)).wrapping_neg()).wrapping_add(i64::from(s))
}

/// `fpr_floor`: largest integer `<= x` (emulated algorithm, see
/// [`fpr_rint`]).
#[inline]
pub(crate) fn fpr_floor(x: Fpr) -> i64 {
    #[cfg(all(test, feature = "c-internals-test"))]
    domain::note(x);
    let x = x.to_bits();
    let e: i32 = (x >> 52) as i32 & 0x7FF;
    let t: u64 = x >> 63;
    let mut xi: i64 = (((x << 10) | (1u64 << 62)) & ((1u64 << 63) - 1)) as i64;
    xi = (xi ^ (t as i64).wrapping_neg()).wrapping_add(t as i64);
    let cc: i32 = 1085 - e;
    xi = fpr_irsh(xi, (cc & 63) as u32);
    xi ^= (xi ^ (t as i64).wrapping_neg()) & (i64::from(((63 - cc) as u32) >> 31)).wrapping_neg();
    xi
}

/// `fpr_trunc`: round toward zero (emulated algorithm, see [`fpr_rint`]);
/// yields 0 for |x| >= 2^63, which `expm_p63` relies on when `ccs == 1`.
#[inline]
pub(crate) fn fpr_trunc(x: Fpr) -> i64 {
    #[cfg(all(test, feature = "c-internals-test"))]
    domain::note(x);
    let x = x.to_bits();
    let e: i32 = (x >> 52) as i32 & 0x7FF;
    let mut xu: u64 = ((x << 10) | (1u64 << 62)) & ((1u64 << 63) - 1);
    let cc: i32 = 1085 - e;
    xu = fpr_ursh(xu, (cc & 63) as u32);
    xu &= (u64::from(((cc - 64) as u32) >> 31)).wrapping_neg();
    let t: u64 = x >> 63;
    xu = (xu ^ t.wrapping_neg()).wrapping_add(t);
    xu as i64
}

/// Test-only record of the operand/result domain the Falcon algorithms
/// actually reach (issue #2016): the Rust port computes with native `f64`
/// while the C emulation (`FALCON_FPEMU`) differs from it only outside
/// "normal finite numbers, exponent far from the limits, no `-0` in the two
/// operations that treat it differently"; this proves, empirically, that
/// keygen and signing stay inside that domain. Thread-local so that the
/// adversarial differential test, which deliberately leaves the domain,
/// cannot pollute another test's measurement.
#[cfg(all(test, feature = "c-internals-test"))]
pub(crate) mod domain {
    use std::cell::Cell;

    #[derive(Clone, Copy, Debug)]
    pub(crate) struct Stats {
        pub ops: u64,
        pub min_exp: i32,
        pub max_exp: i32,
        pub subnormal: u64,
        pub nonfinite: u64,
        /// `fpr_div` with a zero numerator and a negative divisor (Rust: -0, C: +0)
        pub div_zero_over_negative: u64,
        /// `fpr_half(-0)` (Rust: -0, C: +0)
        pub half_negative_zero: u64,
    }

    impl Stats {
        const fn new() -> Self {
            Self {
                ops: 0,
                min_exp: i32::MAX,
                max_exp: i32::MIN,
                subnormal: 0,
                nonfinite: 0,
                div_zero_over_negative: 0,
                half_negative_zero: 0,
            }
        }
    }

    thread_local! {
        static STATS: Cell<Stats> = const { Cell::new(Stats::new()) };
    }

    pub(crate) fn reset() {
        STATS.with(|s| s.set(Stats::new()));
    }

    pub(crate) fn take() -> Stats {
        STATS.with(|s| s.get())
    }

    pub(crate) fn note(v: f64) {
        STATS.with(|s| {
            let mut st = s.get();
            st.ops += 1;
            if v == 0.0 {
                // zero is in the domain
            } else if !v.is_finite() {
                st.nonfinite += 1;
            } else if v.is_subnormal() {
                st.subnormal += 1;
            } else {
                let e = ((v.to_bits() >> 52) & 0x7ff) as i32 - 1023;
                st.min_exp = st.min_exp.min(e);
                st.max_exp = st.max_exp.max(e);
            }
            s.set(st);
        });
    }

    pub(crate) fn note_div(x: f64, y: f64) {
        if x == 0.0 && y.is_sign_negative() {
            STATS.with(|s| {
                let mut st = s.get();
                st.div_zero_over_negative += 1;
                s.set(st);
            });
        }
    }

    pub(crate) fn note_half(x: f64) {
        if x == 0.0 && x.is_sign_negative() {
            STATS.with(|s| {
                let mut st = s.get();
                st.half_negative_zero += 1;
                s.set(st);
            });
        }
    }
}

#[inline(always)]
pub(crate) fn fpr_add(x: Fpr, y: Fpr) -> Fpr {
    let r = x + y;
    #[cfg(all(test, feature = "c-internals-test"))]
    {
        domain::note(x);
        domain::note(y);
        domain::note(r);
    }
    r
}

#[inline(always)]
pub(crate) fn fpr_sub(x: Fpr, y: Fpr) -> Fpr {
    let r = x - y;
    #[cfg(all(test, feature = "c-internals-test"))]
    {
        domain::note(x);
        domain::note(y);
        domain::note(r);
    }
    r
}

#[inline(always)]
pub(crate) fn fpr_neg(x: Fpr) -> Fpr {
    let r = -x;
    #[cfg(all(test, feature = "c-internals-test"))]
    {
        domain::note(x);
        domain::note(r);
    }
    r
}

#[inline(always)]
pub(crate) fn fpr_half(x: Fpr) -> Fpr {
    let r = x * 0.5;
    #[cfg(all(test, feature = "c-internals-test"))]
    {
        domain::note_half(x);
        domain::note(x);
        domain::note(r);
    }
    r
}

#[inline(always)]
pub(crate) fn fpr_double(x: Fpr) -> Fpr {
    let r = x + x;
    #[cfg(all(test, feature = "c-internals-test"))]
    {
        domain::note(x);
        domain::note(r);
    }
    r
}

#[inline(always)]
pub(crate) fn fpr_mul(x: Fpr, y: Fpr) -> Fpr {
    let r = x * y;
    #[cfg(all(test, feature = "c-internals-test"))]
    {
        domain::note(x);
        domain::note(y);
        domain::note(r);
    }
    r
}

#[inline(always)]
pub(crate) fn fpr_sqr(x: Fpr) -> Fpr {
    let r = x * x;
    #[cfg(all(test, feature = "c-internals-test"))]
    {
        domain::note(x);
        domain::note(r);
    }
    r
}

#[inline(always)]
pub(crate) fn fpr_inv(x: Fpr) -> Fpr {
    let r = 1.0 / x;
    #[cfg(all(test, feature = "c-internals-test"))]
    {
        domain::note(x);
        domain::note(r);
    }
    r
}

#[inline(always)]
pub(crate) fn fpr_div(x: Fpr, y: Fpr) -> Fpr {
    let r = x / y;
    #[cfg(all(test, feature = "c-internals-test"))]
    {
        domain::note_div(x, y);
        domain::note(x);
        domain::note(y);
        domain::note(r);
    }
    r
}

/// `fpr_sqrt`: correctly rounded square root (`sqrtsd` on x86-64, `fsqrt`
/// on AArch64, soft-float otherwise — all correctly rounded).
#[inline(always)]
pub(crate) fn fpr_sqrt(x: Fpr) -> Fpr {
    let r = x.sqrt();
    #[cfg(all(test, feature = "c-internals-test"))]
    {
        domain::note(x);
        domain::note(r);
    }
    r
}

#[inline(always)]
pub(crate) fn fpr_lt(x: Fpr, y: Fpr) -> bool {
    #[cfg(all(test, feature = "c-internals-test"))]
    {
        domain::note(x);
        domain::note(y);
    }
    x < y
}

/// `fpr_expm_p63`: `2^63 * ccs * exp(-x)` as a fixed-point integer, for
/// `0 <= x < ln 2` and `0 < ccs <= 1`. This is the **emulated** (`fpr.c`)
/// algorithm: the FACCT polynomial evaluated in 64-bit fixed point. The
/// native-double Horner form in `fpr.h` is not bit-identical and must not
/// be used (it would change signatures).
pub(crate) fn fpr_expm_p63(x: Fpr, ccs: Fpr) -> u64 {
    // Coefficients scaled by 2^63 and converted to integers (`C[]` in fpr.c).
    const C: [u64; 13] = [
        0x00000004741183A3,
        0x00000036548CFC06,
        0x0000024FDCBF140A,
        0x0000171D939DE045,
        0x0000D00CF58F6F84,
        0x000680681CF796E3,
        0x002D82D8305B0FEA,
        0x011111110E066FD0,
        0x0555555555070F00,
        0x155555555581FF00,
        0x400000000002B400,
        0x7FFFFFFFFFFF4800,
        0x8000000000000000,
    ];
    // High 64 bits of the 128-bit product; the C computes exactly this with
    // four 32x32 partial products.
    #[inline(always)]
    fn mulhi(z: u64, y: u64) -> u64 {
        ((u128::from(z) * u128::from(y)) >> 64) as u64
    }
    let mut y: u64 = C[0];
    let z: u64 = (fpr_trunc(fpr_mul(x, FPR_PTWO63)) as u64) << 1;
    for &cu in &C[1..] {
        y = cu.wrapping_sub(mulhi(z, y));
    }
    // Apply the scaling factor, converted to the same fixed-point format.
    let z: u64 = (fpr_trunc(fpr_mul(ccs, FPR_PTWO63)) as u64) << 1;
    mulhi(z, y)
}

#[cfg(test)]
// The decimal literals below are the `FALCON_FPNATIVE` constants exactly as
// `fpr.h` spells them; comparing the bit-pattern constants against them is
// the point of the test.
#[allow(clippy::excessive_precision, clippy::approx_constant)]
mod tests {
    use super::*;

    #[test]
    fn constants_decode_to_the_expected_values() {
        assert_eq!(FPR_Q, 12289.0);
        assert_eq!(FPR_INVERSE_OF_Q, 1.0 / 12289.0);
        assert_eq!(FPR_ZERO, 0.0);
        assert_eq!(FPR_ONE, 1.0);
        assert_eq!(FPR_TWO, 2.0);
        assert_eq!(FPR_ONEHALF, 0.5);
        assert_eq!(FPR_PTWO31, 2147483648.0);
        assert_eq!(FPR_PTWO31M1, 2147483647.0);
        assert_eq!(FPR_MTWO31M1, -2147483647.0);
        assert_eq!(FPR_PTWO63, 9223372036854775808.0);
        assert_eq!(FPR_LOG2, 0.69314718055994530941723212146);
        assert_eq!(FPR_INV_LOG2, 1.4426950408889634073599246810);
        assert_eq!(FPR_INVSQRT2, 0.707106781186547524400844362105);
        assert_eq!(FPR_INVSQRT8, 0.353553390593273762200422181052);
        assert_eq!(FPR_BNORM_MAX, 16822.4121);
        assert_eq!(FPR_INV_2SQRSIGMA0, 0.150865048875372721532312163019);
        assert_eq!(FPR_INV_SIGMA[10], 0.0059386453095331159950250124336477482);
        assert_eq!(FPR_SIGMA_MIN[10], 1.2982803343442918539708792538826807);
        assert_eq!(FPR_P2_TAB[0], 2.0);
        assert_eq!(FPR_P2_TAB[1], 1.0);
        assert_eq!(FPR_P2_TAB[10], 1.0 / 512.0);
        // gm_tab = [0, 0, -0.0, 1.0, invsqrt2, invsqrt2, -invsqrt2, invsqrt2, ...]
        assert_eq!(FPR_GM_TAB[2].to_bits(), (-0.0f64).to_bits());
        assert_eq!(FPR_GM_TAB[3], 1.0);
        assert_eq!(FPR_GM_TAB[4], FPR_INVSQRT2);
        assert_eq!(FPR_GM_TAB[5], FPR_INVSQRT2);
        assert_eq!(FPR_GM_TAB[6], -FPR_INVSQRT2);
    }

    #[test]
    fn rint_rounds_half_to_even_and_handles_large_values() {
        for (x, want) in [
            (0.0, 0),
            (0.5, 0),
            (1.5, 2),
            (2.5, 2),
            (-0.5, 0),
            (-1.5, -2),
            (-2.5, -2),
            (3.4999, 3),
            (3.5001, 4),
            (-3.4999, -3),
            (1e15 + 0.5, 1_000_000_000_000_000),
            (4503599627370497.0, 4503599627370497),
            (-4503599627370497.0, -4503599627370497),
            (1e18, 1_000_000_000_000_000_000),
            (-1e18, -1_000_000_000_000_000_000),
        ] {
            assert_eq!(fpr_rint(x), want, "rint({x})");
            assert_eq!(fpr_rint(x), x.round_ties_even() as i64, "rint({x}) vs std");
            assert_eq!(fpr_floor(x), x.floor() as i64, "floor({x}) vs std");
            assert_eq!(fpr_trunc(x), x.trunc() as i64, "trunc({x}) vs std");
        }
    }

    #[test]
    fn floor_and_trunc() {
        assert_eq!(fpr_floor(2.7), 2);
        assert_eq!(fpr_floor(-2.7), -3);
        assert_eq!(fpr_floor(-3.0), -3);
        assert_eq!(fpr_trunc(2.7), 2);
        assert_eq!(fpr_trunc(-2.7), -2);
        // Emulated semantics beyond the i64 range: 2^63 truncates to 0.
        assert_eq!(fpr_trunc(FPR_PTWO63), 0);
    }

    #[test]
    fn expm_p63_tracks_exp() {
        // 2^63 * ccs * exp(-x) for a few points, within 2^-50 relative.
        // (ccs = 1.0 exactly is the C's quirk: trunc(2^63) = 0 so the result
        // is 0; the sampler always passes ccs < 1.)
        for x in [0.0f64, 0.1, 0.25, 0.5, 0.69] {
            let got = fpr_expm_p63(x, 0.75) as f64 / 9223372036854775808.0;
            let want = 0.75 * (-x).exp();
            assert!((got - want).abs() < 1e-14, "x={x}: {got} vs {want}");
        }
        assert_eq!(fpr_expm_p63(0.3, 1.0), 0);
        // ccs = 0.5 scales exp(0) = 1 to 2^62.
        assert_eq!(fpr_expm_p63(0.0, 0.5), 1u64 << 62);
    }
}

/// Differential tests against the vendored C's emulated FP
/// (`falcon_inner_fpr_*`, exported from `fpr.c`).
#[cfg(all(test, feature = "c-backend"))]
mod c_diff {
    use super::*;
    use crate::c_internals as cint;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        /// A random finite normal double with exponent in `[lo, hi]`.
        fn fpr(&mut self, lo: i32, hi: i32) -> f64 {
            let e = (lo + (self.next() % ((hi - lo + 1) as u64)) as i32 + 1023) as u64;
            let m = self.next() & ((1u64 << 52) - 1);
            let s = self.next() & 1;
            f64::from_bits((s << 63) | (e << 52) | m)
        }
        /// A random "Falcon-shaped" value: small integers, scaled integers
        /// and values across the exponent range the signer/keygen sees.
        fn falcon_value(&mut self) -> f64 {
            match self.next() % 4 {
                0 => (self.next() as i64 >> (self.next() % 52)) as f64,
                1 => self.fpr(-60, 60),
                2 => self.fpr(-4, 20),
                _ => self.fpr(-1, 1),
            }
        }
    }

    #[test]
    fn tables_and_constants_match_c() {
        unsafe {
            for (i, (rs, c)) in FPR_GM_TAB
                .iter()
                .zip(cint::falcon_inner_fpr_gm_tab.iter())
                .enumerate()
            {
                assert_eq!(rs.to_bits(), *c, "gm_tab[{i}]");
            }
            for (i, (rs, c)) in FPR_P2_TAB
                .iter()
                .zip(cint::falcon_inner_fpr_p2_tab.iter())
                .enumerate()
            {
                assert_eq!(rs.to_bits(), *c, "p2_tab[{i}]");
            }
        }
    }

    #[test]
    fn arithmetic_matches_emulated_c_bit_for_bit() {
        let mut rng = Rng(0x5EED_CAFE_F00D_0001);
        let mut checked = 0u64;
        for _ in 0..200_000 {
            let x = rng.falcon_value();
            let y = rng.falcon_value();
            let (xb, yb) = (x.to_bits(), y.to_bits());
            unsafe {
                assert_eq!(
                    fpr_add(x, y).to_bits(),
                    cint::falcon_inner_fpr_add(xb, yb),
                    "add {x} {y}"
                );
                assert_eq!(
                    fpr_mul(x, y).to_bits(),
                    cint::falcon_inner_fpr_mul(xb, yb),
                    "mul {x} {y}"
                );
                if y != 0.0 {
                    assert_eq!(
                        fpr_div(x, y).to_bits(),
                        cint::falcon_inner_fpr_div(xb, yb),
                        "div {x} {y}"
                    );
                }
                if x >= 0.0 {
                    assert_eq!(
                        fpr_sqrt(x).to_bits(),
                        cint::falcon_inner_fpr_sqrt(xb),
                        "sqrt {x}"
                    );
                }
            }
            checked += 1;
        }
        assert_eq!(checked, 200_000);
    }

    #[test]
    fn expm_p63_matches_emulated_c_bit_for_bit() {
        let mut rng = Rng(0xE4B0_0000_0000_0001);
        for i in 0..100_000 {
            // x in [0, ln 2), ccs in (0, 1].
            let x = (rng.next() as f64 / u64::MAX as f64) * std::f64::consts::LN_2;
            let ccs = 1.0 - (rng.next() as f64 / u64::MAX as f64) * 0.999;
            let (x, ccs) = if i == 0 { (0.0, 1.0) } else { (x, ccs) };
            let want = unsafe { cint::falcon_inner_fpr_expm_p63(x.to_bits(), ccs.to_bits()) };
            assert_eq!(fpr_expm_p63(x, ccs), want, "expm_p63({x}, {ccs})");
        }
    }

    /// `fpr_rint/floor/trunc/lt/of/neg/half/double/sub/sqr/inv` are
    /// `static inline` in `fpr.h`; the shim TU re-exports them.
    #[cfg(feature = "c-internals-test")]
    #[test]
    fn inline_helpers_match_emulated_c_bit_for_bit() {
        use cint::shim as sh;
        let mut rng = Rng(0x1234_0000_ABCD_0002);
        for _ in 0..200_000 {
            let x = rng.falcon_value();
            let y = rng.falcon_value();
            let (xb, yb) = (x.to_bits(), y.to_bits());
            unsafe {
                assert_eq!(fpr_rint(x), sh::falcon_shim_x_fpr_rint(xb), "rint {x}");
                assert_eq!(fpr_floor(x), sh::falcon_shim_x_fpr_floor(xb), "floor {x}");
                assert_eq!(fpr_trunc(x), sh::falcon_shim_x_fpr_trunc(xb), "trunc {x}");
                assert_eq!(
                    i32::from(fpr_lt(x, y)),
                    sh::falcon_shim_x_fpr_lt(xb, yb),
                    "lt {x} {y}"
                );
                assert_eq!(
                    fpr_neg(x).to_bits(),
                    sh::falcon_shim_x_fpr_neg(xb),
                    "neg {x}"
                );
                assert_eq!(
                    fpr_half(x).to_bits(),
                    sh::falcon_shim_x_fpr_half(xb),
                    "half {x}"
                );
                assert_eq!(
                    fpr_double(x).to_bits(),
                    sh::falcon_shim_x_fpr_double(xb),
                    "double {x}"
                );
                assert_eq!(
                    fpr_sub(x, y).to_bits(),
                    sh::falcon_shim_x_fpr_sub(xb, yb),
                    "sub {x} {y}"
                );
                assert_eq!(
                    fpr_sqr(x).to_bits(),
                    sh::falcon_shim_x_fpr_sqr(xb),
                    "sqr {x}"
                );
                if x != 0.0 {
                    assert_eq!(
                        fpr_inv(x).to_bits(),
                        sh::falcon_shim_x_fpr_inv(xb),
                        "inv {x}"
                    );
                }
                let i = rng.next() as i64 >> (rng.next() % 64);
                assert_eq!(fpr_of(i).to_bits(), sh::falcon_shim_x_fpr_of(i), "of {i}");
            }
        }
        // Exact ties and the 2^52 boundary, where rint's two code paths meet.
        for x in [
            0.5,
            1.5,
            2.5,
            -0.5,
            -1.5,
            -2.5,
            4503599627370495.5,
            4503599627370496.0,
            4503599627370497.0,
            -4503599627370497.0,
            1e18,
            -1e18,
        ] {
            unsafe {
                assert_eq!(
                    fpr_rint(x),
                    sh::falcon_shim_x_fpr_rint(x.to_bits()),
                    "rint {x}"
                );
                assert_eq!(
                    fpr_floor(x),
                    sh::falcon_shim_x_fpr_floor(x.to_bits()),
                    "floor {x}"
                );
            }
        }
    }
}
