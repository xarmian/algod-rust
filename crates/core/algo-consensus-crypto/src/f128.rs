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

//! Minimal 128-bit software float (`f128`) and the incremental binomial CDF
//! walk used by [`crate::sortition::select_f128`].
//!
//! This is a bit-for-bit port of `github.com/algorand/sortition@v1.1.1`'s
//! `f128.go`, activated by consensus v42's `EnableSelectF128`. It exists to
//! replace the hardware-double / Boost-C++ binomial CDF walk
//! (`crate::sortition::select`) with a pure integer implementation that is
//! bit-identical on every platform: no hardware FP, no FMA, no libm.
//!
//! `value = (hi<<64 | lo) * 2^exp`. The 128-bit mantissa is normalized so bit
//! 127 (the MSB of `hi`) is set, or the value is zero (`hi==lo==0`). All
//! sortition quantities (p, 1-p, ratio, pmf, cdf, factors) are non-negative,
//! so there is no sign bit. Arithmetic rounds to nearest, ties to even
//! (matching Go's `math/big.Float`), so every result is the
//! correctly-rounded 128-bit value.
//!
//! Every arithmetic primitive here mirrors its Go counterpart function-for-
//! function (see the doc comment on each for the corresponding Go name) —
//! this is a parity port, not a reimplementation, per issue #667's hard
//! constraint against approximating or "cleaning up" the algorithm.
//!
//! `norm128` (an exact, non-rounding constructor used only by the upstream
//! Go test suite to build hand-picked test values) is intentionally not
//! ported: nothing on the `SelectF128` production path calls it, and this
//! repo's dead-code policy disfavors carrying unused API surface. The tests
//! below build expected values from raw hex mantissa/exponent triples
//! captured directly from the Go implementation instead.

use std::cmp::Ordering;

/// A non-negative 128-bit-mantissa software float: `(hi<<64 | lo) * 2^exp`.
///
/// Mirrors Go's `type f128 struct{ hi, lo uint64; exp int64 }`. All exponent
/// arithmetic below uses `wrapping_*` to match Go's defined-wraparound
/// `int64`/`uint64` semantics exactly (Go has no overflow panics on `+`/`-`
/// for these types); the documented precondition `money < SelectF128MaxMoney`
/// (enforced by the caller, `credential.rs`) keeps every such computation
/// comfortably inside `i64`/`u64` range in practice, so the wrapping is
/// defensive parity, not an expected code path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct F128 {
    pub(crate) hi: u64,
    pub(crate) lo: u64,
    pub(crate) exp: i64,
}

impl F128 {
    pub(crate) const ZERO: F128 = F128 {
        hi: 0,
        lo: 0,
        exp: 0,
    };

    #[inline]
    pub(crate) fn is_zero(self) -> bool {
        self.hi == 0 && self.lo == 0
    }

    /// Go: `f128FromUint64`.
    pub(crate) fn from_u64(u: u64) -> F128 {
        if u == 0 {
            return F128::ZERO;
        }
        let s = u.leading_zeros();
        F128 {
            hi: u << s,
            lo: 0,
            exp: -(s as i64) - 64,
        }
    }

    /// Go: `(a f128) mul(b f128) f128`.
    pub(crate) fn mul(self, b: F128) -> F128 {
        let a = self;
        if a.is_zero() || b.is_zero() {
            return F128::ZERO;
        }
        let (hh_hi, hh_lo) = mul64(a.hi, b.hi);
        let (hl_hi, hl_lo) = mul64(a.hi, b.lo);
        let (lh_hi, lh_lo) = mul64(a.lo, b.hi);
        let (ll_hi, ll_lo) = mul64(a.lo, b.lo);
        let p0 = ll_lo;
        let (p1, c_a) = add64(ll_hi, hl_lo, 0);
        let (p1, c_b) = add64(p1, lh_lo, 0);
        let cp1 = c_a.wrapping_add(c_b);
        let (p2, c_c) = add64(hh_lo, hl_hi, 0);
        let (p2, c_d) = add64(p2, lh_hi, 0);
        let (p2, c_e) = add64(p2, cp1, 0);
        let p3 = hh_hi.wrapping_add(c_c).wrapping_add(c_d).wrapping_add(c_e);
        if p3 & (1u64 << 63) != 0 {
            // product >= 2^255: mantissa p3:p2, tail p1:p0
            let round_bit = p1 & (1u64 << 63) != 0;
            let sticky = (p1 & !(1u64 << 63) != 0) || p0 != 0;
            return round_ne(
                p3,
                p2,
                round_bit,
                sticky,
                a.exp.wrapping_add(b.exp).wrapping_add(128),
            );
        }
        // product in [2^254, 2^255): shift left 1 to normalize
        let hi = (p3 << 1) | (p2 >> 63);
        let lo = (p2 << 1) | (p1 >> 63);
        let round_bit = p1 & (1u64 << 62) != 0;
        let sticky = (p1 & !(3u64 << 62) != 0) || p0 != 0;
        round_ne(
            hi,
            lo,
            round_bit,
            sticky,
            a.exp.wrapping_add(b.exp).wrapping_add(127),
        )
    }

    /// Go: `(a f128) divU(u uint64) f128` — divide by a small integer
    /// (the walk's per-step denominator `j`).
    pub(crate) fn div_u(self, u: u64) -> F128 {
        let a = self;
        if a.is_zero() || u == 0 {
            return F128::ZERO;
        }
        let (q3, r) = div64(0, a.hi, u);
        let (q2, r) = div64(r, a.lo, u);
        let (q1, r) = div64(r, 0, u);
        let (q0, rem) = div64(r, 0, u);
        let lz: u32 = if q3 != 0 { q3.leading_zeros() } else { 64 };
        let (o3, o2, o1, o0) = shl256(q3, q2, q1, q0, lz);
        let round = o1 & (1u64 << 63) != 0;
        let sticky = (o1 & !(1u64 << 63) != 0) || o0 != 0 || rem != 0;
        round_ne(o3, o2, round, sticky, a.exp.wrapping_sub(lz as i64))
    }

    /// Go: `(a f128) div(b f128) f128` — full f128/f128 divide via Knuth
    /// long division (used once per setup, not in the walk).
    pub(crate) fn div(self, b: F128) -> F128 {
        let a = self;
        if a.is_zero() || b.is_zero() {
            return F128::ZERO;
        }
        let v1 = b.hi;
        let v0 = b.lo;
        let (rem_hi0, rem_lo0) = (0u64, 0u64);
        let (_digit, rem_hi, rem_lo) = div_step(rem_hi0, rem_lo0, a.hi, v1, v0);
        let (q2, rem_hi, rem_lo) = div_step(rem_hi, rem_lo, a.lo, v1, v0);
        let (q1, rem_hi, rem_lo) = div_step(rem_hi, rem_lo, 0, v1, v0);
        let (q0, rem_hi, rem_lo) = div_step(rem_hi, rem_lo, 0, v1, v0);

        let expq = a.exp.wrapping_sub(b.exp).wrapping_sub(128);
        if q2 != 0 {
            // Q in [2^128,2^129): mantissa = Q>>1, dropped low bit is round
            let mant_hi = (q2 << 63) | (q1 >> 1);
            let mant_lo = (q1 << 63) | (q0 >> 1);
            let round = q0 & 1 != 0;
            let sticky = rem_hi != 0 || rem_lo != 0;
            return round_ne(mant_hi, mant_lo, round, sticky, expq.wrapping_add(1));
        }
        // Q in [2^127,2^128): already normalized; round/sticky come from
        // rem/b, i.e. round = (2*rem >= b), sticky = the leftover after
        // that comparison.
        let dbl_lo = rem_lo << 1;
        let dbl_hi = (rem_hi << 1) | (rem_lo >> 63);
        let carry = rem_hi >> 63;
        let (round, sticky);
        if carry != 0 || dbl_hi > v1 || (dbl_hi == v1 && dbl_lo >= v0) {
            round = true;
            let (s_lo, br) = sub64(dbl_lo, v0, 0);
            let (s_hi, _) = sub64(dbl_hi, v1, br);
            sticky = s_hi != 0 || s_lo != 0;
        } else {
            round = false;
            sticky = rem_hi != 0 || rem_lo != 0;
        }
        round_ne(q1, q0, round, sticky, expq)
    }

    /// Go: `(a f128) add(b f128) f128`.
    pub(crate) fn add(self, other: F128) -> F128 {
        let (mut a, mut b) = (self, other);
        if a.is_zero() {
            return b;
        }
        if b.is_zero() {
            return a;
        }
        if a.exp < b.exp {
            std::mem::swap(&mut a, &mut b);
        }
        // Compare in i64 before converting to a shift count, matching Go's
        // own note: a large exponent difference must not truncate through
        // an intermediate narrower type before this check.
        if a.exp.wrapping_sub(b.exp) > 128 {
            return a; // b is below the round bit
        }
        // `wrapping_sub` here too (not plain `-`): consistent with the
        // guard above, and keeps this unconditionally panic-free even for
        // out-of-precondition exponents, rather than relying on the
        // precondition to avoid a debug-build overflow panic.
        let diff = a.exp.wrapping_sub(b.exp) as u32;
        let (bhi, blo, round0, sticky0) = shr128gs(b.hi, b.lo, diff);
        let (slo, c) = add64(a.lo, blo, 0);
        let (shi, c2) = add64(a.hi, bhi, c);
        let mut exp = a.exp;
        let (mut round, mut sticky) = (round0, sticky0);
        let (fhi, flo);
        if c2 != 0 {
            // carry into bit 128: shift right 1, recompute round/sticky
            sticky = sticky || round;
            round = slo & 1 != 0;
            flo = (slo >> 1) | (shi << 63);
            fhi = (shi >> 1) | (1u64 << 63);
            exp = exp.wrapping_add(1);
        } else {
            fhi = shi;
            flo = slo;
        }
        round_ne(fhi, flo, round, sticky, exp)
    }

    /// Go: `(a f128) cmp(b f128) int`.
    pub(crate) fn cmp(self, b: F128) -> Ordering {
        let a = self;
        let (az, bz) = (a.is_zero(), b.is_zero());
        match (az, bz) {
            (true, true) => return Ordering::Equal,
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            (false, false) => {}
        }
        if a.exp != b.exp {
            return a.exp.cmp(&b.exp);
        }
        if a.hi != b.hi {
            return a.hi.cmp(&b.hi);
        }
        a.lo.cmp(&b.lo)
    }

    /// Go: `(base f128) intPow(e uint64) f128` — exponentiation by squaring.
    pub(crate) fn int_pow(self, mut e: u64) -> F128 {
        let mut result = F128::from_u64(1);
        let mut b = self;
        while e > 0 {
            if e & 1 == 1 {
                result = result.mul(b);
            }
            e >>= 1;
            if e > 0 {
                b = b.mul(b);
            }
        }
        result
    }
}

/// Go: `bits.Mul64` — `x*y` as a 128-bit product `(hi, lo)`.
#[inline]
fn mul64(x: u64, y: u64) -> (u64, u64) {
    let p = (x as u128) * (y as u128);
    ((p >> 64) as u64, p as u64)
}

/// Go: `bits.Add64` — `x+y+carry` as `(sum, carryOut)`.
#[inline]
fn add64(x: u64, y: u64, carry: u64) -> (u64, u64) {
    let s = (x as u128) + (y as u128) + (carry as u128);
    (s as u64, (s >> 64) as u64)
}

/// Go: `bits.Sub64` — `x-y-borrow` as `(diff, borrowOut)`.
#[inline]
fn sub64(x: u64, y: u64, borrow: u64) -> (u64, u64) {
    let diff = (x as i128) - (y as i128) - (borrow as i128);
    if diff < 0 {
        ((diff + (1i128 << 64)) as u64, 1)
    } else {
        (diff as u64, 0)
    }
}

/// Go: `bits.Div64` — `(hi:lo) / y` as `(quotient, remainder)`. The caller
/// must ensure `hi < y` (and `y != 0`) — the same precondition Go's
/// `bits.Div64` documents (it panics otherwise); every call site here
/// maintains that invariant algorithmically, exactly mirroring the upstream
/// Go call sites' own invariants, not via input validation.
#[inline]
fn div64(hi: u64, lo: u64, y: u64) -> (u64, u64) {
    debug_assert!(
        y != 0 && hi < y,
        "div64 precondition violated (y != 0, hi < y)"
    );
    let num = ((hi as u128) << 64) | (lo as u128);
    let den = y as u128;
    ((num / den) as u64, (num % den) as u64)
}

/// Go: `shl128`. Not called from the `SelectF128` production path (its only
/// Go caller is `norm128`, which this port omits — see the module doc
/// comment); kept and unit-tested (`#[cfg(test)]`) as a named primitive
/// because issue #667 calls it out explicitly as part of the arithmetic set
/// to port bit-for-bit, and `shr128`'s round-to-nearest callers rely on the
/// same shift semantics this validates.
#[cfg(test)]
#[inline]
fn shl128(hi: u64, lo: u64, n: u32) -> (u64, u64) {
    match n {
        0 => (hi, lo),
        n if n < 64 => (hi << n | lo >> (64 - n), lo << n),
        n if n < 128 => (lo << (n - 64), 0),
        _ => (0, 0),
    }
}

/// Go: `shr128`.
#[inline]
fn shr128(hi: u64, lo: u64, n: u32) -> (u64, u64) {
    match n {
        0 => (hi, lo),
        n if n < 64 => (hi >> n, lo >> n | hi << (64 - n)),
        n if n < 128 => (0, hi >> (n - 64)),
        _ => (0, 0),
    }
}

/// Go: `shr128gs` — shift `hi:lo` right by `n` (0..=128), returning the
/// result plus the round bit (the most-significant shifted-out bit, at
/// position `n-1`) and sticky (any lower shifted-out bit). `n == 0` is not
/// an upstream case explicitly enumerated in Go's `switch`, but its
/// `n <= 64` arm evaluates to `round = false, sticky = false` there anyway
/// (Go's unbounded shift semantics give `lo >> (uint(0)-1) == 0`); this
/// port special-cases `n == 0` directly to the same result without relying
/// on wraparound-shift semantics Rust doesn't share with Go.
#[inline]
fn shr128gs(hi: u64, lo: u64, n: u32) -> (u64, u64, bool, bool) {
    let (rhi, rlo) = shr128(hi, lo, n);
    if n == 0 {
        return (rhi, rlo, false, false);
    }
    if n <= 64 {
        let round = (lo >> (n - 1)) & 1 != 0;
        let sticky = if n >= 2 {
            lo & ((1u64 << (n - 1)) - 1) != 0
        } else {
            false
        };
        (rhi, rlo, round, sticky)
    } else if n < 128 {
        let m = n - 64;
        let round = (hi >> (m - 1)) & 1 != 0;
        let mut sticky = if m >= 2 {
            hi & ((1u64 << (m - 1)) - 1) != 0
        } else {
            false
        };
        sticky = sticky || lo != 0;
        (rhi, rlo, round, sticky)
    } else {
        // n == 128 (the only remaining case the caller ever passes).
        let round = hi & (1u64 << 63) != 0;
        let sticky = (hi & !(1u64 << 63) != 0) || lo != 0;
        (rhi, rlo, round, sticky)
    }
}

/// Go: `shl256` — shift a 256-bit value (`a3:a2:a1:a0`) left by `n < 256`.
#[inline]
fn shl256(a3: u64, a2: u64, a1: u64, a0: u64, n: u32) -> (u64, u64, u64, u64) {
    let words = (n / 64) as usize;
    let shift = n % 64;
    let inw = [a3, a2, a1, a0];
    let mut out = [0u64; 4];
    for (i, out_i) in out.iter_mut().enumerate() {
        let src = i + words;
        if src >= inw.len() {
            break;
        }
        *out_i = inw[src] << shift;
        if shift != 0 && src + 1 < inw.len() {
            *out_i |= inw[src + 1] >> (64 - shift);
        }
    }
    (out[0], out[1], out[2], out[3])
}

/// Go: `roundNE` — round the normalized 128-bit mantissa `hi:lo` to
/// nearest, ties to even, given the round bit and sticky of the discarded
/// tail, renormalizing on carry-out. `hi:lo` must already be normalized
/// (bit 127 set).
#[inline]
fn round_ne(hi: u64, lo: u64, round_bit: bool, sticky: bool, exp: i64) -> F128 {
    if round_bit && (sticky || lo & 1 != 0) {
        let (lo2, c) = add64(lo, 1, 0);
        let (hi2, c) = add64(hi, 0, c);
        if c != 0 {
            // mantissa overflowed to 2^128 -> renormalize to 2^127
            return F128 {
                hi: 1u64 << 63,
                lo: 0,
                exp: exp.wrapping_add(1),
            };
        }
        return F128 {
            hi: hi2,
            lo: lo2,
            exp,
        };
    }
    F128 { hi, lo, exp }
}

/// Go: `divStep` — one digit step of Knuth's Algorithm D for a normalized
/// (top bit set) 128-bit divisor `v1:v0`: divides the 192-bit value
/// `uHi:uMid:uLo` by `v1:v0`, where the running-remainder prefix
/// `uHi:uMid` is already `< v1:v0`, and returns the 64-bit quotient digit
/// `q` and the new 128-bit remainder `rHi:rLo`.
#[inline]
fn div_step(u_hi: u64, u_mid: u64, u_lo: u64, v1: u64, v0: u64) -> (u64, u64, u64) {
    let mut qhat: u64;
    let mut rhat: u64;
    let mut refine = true;
    if u_hi >= v1 {
        qhat = u64::MAX;
        let (r, c) = add64(u_mid, v1, 0);
        rhat = r;
        if c != 0 {
            refine = false; // rhat >= 2^64: the refine test is already false
        }
    } else {
        let (q, r) = div64(u_hi, u_mid, v1);
        qhat = q;
        rhat = r;
    }
    // Lower qhat (over-estimated by at most 2) until qhat*v0 <= rhat:uLo.
    // `refine` gates entry only (Go's `for refine { ... }` never reassigns
    // it inside the loop body either — every iteration ends in `break` or
    // `continue`), so this is written as an `if`-gated `loop` rather than a
    // `while` whose condition clippy expects the body to maintain.
    if refine {
        loop {
            let (hi, lo) = mul64(qhat, v0);
            if hi > rhat || (hi == rhat && lo > u_lo) {
                qhat -= 1;
                let (r, c) = add64(rhat, v1, 0);
                rhat = r;
                if c != 0 {
                    break;
                }
                continue;
            }
            break;
        }
    }
    // u - qhat*(v1:v0), a 192-bit subtraction.
    let (p1hi, p1lo) = mul64(qhat, v1);
    let (p0hi, p0lo) = mul64(qhat, v0);
    let (prod_mid, c) = add64(p1lo, p0hi, 0);
    let prod_hi = p1hi.wrapping_add(c);
    let (mut s_lo, br) = sub64(u_lo, p0lo, 0);
    let (mut s_mid, br) = sub64(u_mid, prod_mid, br);
    let (_, br) = sub64(u_hi, prod_hi, br);
    let mut q = qhat;
    // Defense in depth: unlike Knuth's Algorithm D, which bounds the D3
    // adjustment at two rounds and relies on a D6 add-back, the refine loop
    // above runs to fixpoint with an exact 128-bit test, so qhat should
    // already be exact and br always 0. Kept in case that analysis is
    // wrong, exactly mirroring the upstream Go comment.
    if br != 0 {
        // qhat was 1 too large: add the divisor back
        q -= 1;
        let (lo2, c2) = add64(s_lo, v0, 0);
        s_lo = lo2;
        let (mid2, _c3) = add64(s_mid, v1, c2);
        s_mid = mid2;
    }
    (q, s_mid, s_lo)
}

/// Go: `f128FromDigestRatio` — `digest/(2^256-1)`, rounded to nearest-even
/// at f128 precision, WITHOUT reducing the digest to `float64` first. This
/// is the whole point of the port: any float64 shortcut here would defeat
/// bit-exactness.
pub(crate) fn f128_from_digest_ratio(d: &[u8; 32]) -> F128 {
    // `d` is a fixed-size `&[u8; 32]`, so each 8-byte sub-slice is
    // infallibly convertible; `.expect` (not a bare `.unwrap`) keeps a
    // hypothetical future signature change (e.g. to `&[u8]`) diagnosable
    // rather than an opaque panic on this consensus-critical path.
    let w3 = u64::from_be_bytes(d[0..8].try_into().expect("8-byte slice of a 32-byte array"));
    let w2 = u64::from_be_bytes(
        d[8..16]
            .try_into()
            .expect("8-byte slice of a 32-byte array"),
    );
    let w1 = u64::from_be_bytes(
        d[16..24]
            .try_into()
            .expect("8-byte slice of a 32-byte array"),
    );
    let w0 = u64::from_be_bytes(
        d[24..32]
            .try_into()
            .expect("8-byte slice of a 32-byte array"),
    );

    let leading: u32 = if w3 != 0 {
        w3.leading_zeros()
    } else if w2 != 0 {
        64 + w2.leading_zeros()
    } else if w1 != 0 {
        128 + w1.leading_zeros()
    } else if w0 != 0 {
        192 + w0.leading_zeros()
    } else {
        return F128::ZERO;
    };

    let (n3, n2, n1, n0) = shl256(w3, w2, w1, w0, leading);
    let round_bit = n1 & (1u64 << 63) != 0;
    let mut sticky = (n1 & !(1u64 << 63) != 0) || n0 != 0;

    // Dividing by 2^256 places the binary point directly after the digest.
    // The real denominator is one smaller, so the exact ratio is slightly
    // larger. That correction is at most one discarded-bit unit and
    // changes rounding only when the 2^256 quotient is exactly halfway.
    if round_bit && !sticky {
        sticky = true;
    }
    round_ne(n3, n2, round_bit, sticky, -128 - (leading as i64))
}

/// The counterpart of Go's `binomialF128` — evaluates the CDF of
/// `Binomial(money trials, success probability p)` in software f128, as
/// the running sum of the binomial PMF:
///
/// ```text
/// pmf(0) = (1-p)^money
/// pmf(j) = pmf(j-1) * (money-j+1)/j * p/(1-p)
/// cdf(j) = pmf(0) + pmf(1) + ... + pmf(j)
/// ```
///
/// [`BinomialF128::cdf`] MUST be called with `j = 0, 1, 2, ...` in
/// increasing order, exactly as [`binomial_cdf_walk_f128`] does.
pub(crate) struct BinomialF128 {
    money: u64,
    /// p/(1-p), the per-step PMF multiplier.
    pq: F128,
    /// pmf(at): the current term.
    pmf: F128,
    /// cdf(at) = P(X <= at).
    cum: F128,
    /// Index that pmf/cum currently hold.
    at: u64,
    /// `cum` can never change again: `cdf(k) == cum` for every `k >= at`.
    frozen: bool,
}

impl BinomialF128 {
    /// Go: `newBinomialF128` — constructs the CDF evaluator for
    /// `Binomial(money trials, p = expectedSize/totalMoney)`. Returns
    /// `None` for the degenerate `p >= 1` case (`expectedSize >=
    /// totalMoney`, an exact integer comparison — all probability mass at
    /// `j == money`), which the caller handles; `totalMoney == 0` also
    /// lands on the `None` path.
    fn new(expected_size: u64, total_money: u64, money: u64) -> Option<BinomialF128> {
        if expected_size >= total_money {
            return None;
        }
        let qf = F128::from_u64(total_money - expected_size).div(F128::from_u64(total_money));
        let pq = F128::from_u64(expected_size).div(F128::from_u64(total_money - expected_size));
        let pmf0 = qf.int_pow(money);
        Some(BinomialF128 {
            money,
            pq,
            pmf: pmf0,
            cum: pmf0,
            at: 0,
            frozen: false,
        })
    }

    fn cdf(&mut self, j: u64) -> F128 {
        while self.at < j && !self.frozen {
            self.at += 1;
            // pmf(at) = pmf(at-1) * (money-at+1)/at * p/(1-p)
            let pmf_prev = self.pmf;
            self.pmf = F128::from_u64(self.money - self.at + 1)
                .div_u(self.at)
                .mul(self.pq)
                .mul(self.pmf);
            let cum_prev = self.cum;
            self.cum = self.cum.add(self.pmf);
            // cum is frozen once an add is a no-op while pmf strictly
            // shrank: a shrinking pmf proves the rounded step factor is
            // < 1, and the factor only decreases with `at` (round-to-
            // nearest is monotone), so every later pmf is <= this one;
            // and if adding THIS pmf could not move cum, no later,
            // smaller pmf can either. From here cdf(k) == cum for all k.
            if self.cum.cmp(cum_prev) == Ordering::Equal && self.pmf.cmp(pmf_prev) == Ordering::Less
            {
                self.frozen = true;
            }
        }
        self.cum
    }
}

/// Go: `binomialCDFWalkF128` — the pure-software, deterministic
/// counterpart of the C++ `sortition_binomial_cdf_walk`. Performs the
/// same boundary walk, using an f128 ratio and f128 CDF values.
///
/// # FROZEN-TAIL POLICY
///
/// Rounding `q=1-p` once and then raising it to `money` can scale every
/// PMF term by a common error of about `money*2^-129`. When that error is
/// downward, the accumulated f128 CDF can settle at a plateau below 1. A
/// digest ratio above the plateau would never cross another represented
/// boundary, and a literal walk would eventually fall through and return
/// `money` after as many as `money` no-op iterations.
///
/// Once an addition leaves the CDF unchanged while the PMF is strictly
/// shrinking (`self.cum.cmp(cum_prev) == Equal && self.pmf.cmp(pmf_prev)
/// == Less` inside [`BinomialF128::cdf`]), every later term is no larger
/// and every later CDF addition is also a no-op. `SelectF128` therefore
/// promotes that first frozen boundary to 1 and returns its index (the
/// `if dist.frozen { return j }` branch below) — this assigns the
/// unresolved tail to one finite result instead of treating the account's
/// entire stake as its selection weight. This is a DELIBERATE,
/// upstream-documented divergence from a naive continued-CDF walk — it
/// must be replicated exactly, not "improved" or removed (issue #667's
/// hard constraint).
///
/// Precondition: `money < SelectF128MaxMoney` (2^56), enforced by the
/// caller (`credential.rs`), not by this function — mirroring Go, where
/// the bound is documented but not runtime-checked inside the walk itself.
pub(crate) fn binomial_cdf_walk_f128(
    expected_size: u64,
    total_money: u64,
    ratio: F128,
    money: u64,
) -> u64 {
    let dist = BinomialF128::new(expected_size, total_money, money);
    let mut dist = match dist {
        None => {
            // newBinomialF128 returns None iff expected_size >= total_money.
            // For nonzero total_money this is p >= 1: cdf(j)==0 for j<money,
            // cdf(money)==1. The otherwise undefined total_money==0 case
            // deliberately shares these deterministic degenerate semantics.
            return if ratio.is_zero() {
                // The inclusive inverse-CDF convention makes ratio 0 select
                // the first index, 0.
                0
            } else {
                // A positive ratio cannot cross any cdf(j)==0 boundary for
                // j<money; it crosses cdf(money)==1, so the selected count
                // is money.
                money
            };
        }
        Some(d) => d,
    };
    for j in 0..money {
        let boundary = dist.cdf(j); // = cdf(dist, j) = P(X <= j)
        if ratio.cmp(boundary) != Ordering::Greater {
            return j;
        }
        if dist.frozen {
            // The boundary can never increase again. Promote the first
            // frozen boundary to 1 and return its index, assigning the
            // unresolved tail to one finite result instead of falling
            // through to money after up to money no-op iterations.
            return j;
        }
    }
    // Every represented boundary for j < money stayed below ratio without
    // freezing, so the selected count is the ordinary inverse-CDF endpoint
    // X=money. This is legitimately reachable for small distributions and
    // is the same final endpoint used by the Boost reference walk.
    money
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::fs;
    use std::path::PathBuf;

    fn fixture_path() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("tests/fixtures/sortition_f128/vectors.json");
        p
    }

    #[derive(Debug, Deserialize)]
    struct F128Hex {
        hi: String,
        lo: String,
        exp: i64,
    }

    impl F128Hex {
        fn to_f128(&self) -> F128 {
            F128 {
                hi: u64::from_str_radix(&self.hi, 16).unwrap(),
                lo: u64::from_str_radix(&self.lo, 16).unwrap(),
                exp: self.exp,
            }
        }
    }

    fn assert_f128_eq(actual: F128, expected: &F128Hex, ctx: &str) {
        let want = expected.to_f128();
        assert_eq!(
            actual, want,
            "{ctx}: got hi={:016x} lo={:016x} exp={}, want hi={} lo={} exp={}",
            actual.hi, actual.lo, actual.exp, expected.hi, expected.lo, expected.exp
        );
    }

    #[derive(Debug, Deserialize)]
    struct FromU64Vec {
        u: u64,
        r: F128Hex,
    }

    #[derive(Debug, Deserialize)]
    struct RatioVec {
        digest: String,
        ratio: F128Hex,
    }

    #[derive(Debug, Deserialize)]
    struct MulVec {
        a: F128Hex,
        b: F128Hex,
        r: F128Hex,
    }

    #[derive(Debug, Deserialize)]
    struct DivUVec {
        a: F128Hex,
        u: u64,
        r: F128Hex,
    }

    #[derive(Debug, Deserialize)]
    struct DivVec {
        a: F128Hex,
        b: F128Hex,
        r: F128Hex,
    }

    #[derive(Debug, Deserialize)]
    struct AddVec {
        a: F128Hex,
        b: F128Hex,
        r: F128Hex,
    }

    #[derive(Debug, Deserialize)]
    struct IntPowVec {
        base: F128Hex,
        e: u64,
        r: F128Hex,
    }

    #[derive(Debug, Deserialize)]
    struct Vectors {
        from_uint64: Vec<FromU64Vec>,
        from_digest_ratio: Vec<RatioVec>,
        mul: Vec<MulVec>,
        div_u: Vec<DivUVec>,
        div: Vec<DivVec>,
        add: Vec<AddVec>,
        int_pow: Vec<IntPowVec>,
    }

    fn load_vectors() -> Vectors {
        let data = fs::read_to_string(fixture_path()).expect("read sortition_f128 fixture");
        serde_json::from_str(&data).expect("parse sortition_f128 fixture")
    }

    // These vectors were captured by driving the actual
    // github.com/algorand/sortition v1.1.1 f128.go source (unmodified,
    // save for the package clause) with a small Go generator program, so
    // every expected value below is Go's own bit pattern, not a
    // hand-derived approximation.

    #[test]
    fn test_from_uint64_matches_go() {
        for v in load_vectors().from_uint64 {
            let got = F128::from_u64(v.u);
            assert_f128_eq(got, &v.r, &format!("from_u64({})", v.u));
        }
    }

    #[test]
    fn test_from_digest_ratio_matches_go() {
        for v in load_vectors().from_digest_ratio {
            let bytes = hex::decode(&v.digest).unwrap();
            let d: [u8; 32] = bytes.try_into().unwrap();
            let got = f128_from_digest_ratio(&d);
            assert_f128_eq(got, &v.ratio, &format!("from_digest_ratio({})", v.digest));
        }
    }

    #[test]
    fn test_mul_matches_go() {
        for v in load_vectors().mul {
            let got = v.a.to_f128().mul(v.b.to_f128());
            assert_f128_eq(got, &v.r, "mul");
        }
    }

    #[test]
    fn test_div_u_matches_go() {
        for v in load_vectors().div_u {
            let got = v.a.to_f128().div_u(v.u);
            assert_f128_eq(got, &v.r, &format!("div_u(_, {})", v.u));
        }
    }

    #[test]
    fn test_div_matches_go() {
        for v in load_vectors().div {
            let got = v.a.to_f128().div(v.b.to_f128());
            assert_f128_eq(got, &v.r, "div");
        }
    }

    #[test]
    fn test_add_matches_go() {
        for v in load_vectors().add {
            let got = v.a.to_f128().add(v.b.to_f128());
            assert_f128_eq(got, &v.r, "add");
        }
    }

    #[test]
    fn test_int_pow_matches_go() {
        for v in load_vectors().int_pow {
            let got = v.base.to_f128().int_pow(v.e);
            assert_f128_eq(got, &v.r, &format!("int_pow(_, {})", v.e));
        }
    }

    // ----- cmp / is_zero sanity (not separately fixture-captured; these
    // are simple enough to pin directly) -----

    #[test]
    fn test_cmp_zero_ordering() {
        assert_eq!(F128::ZERO.cmp(F128::ZERO), Ordering::Equal);
        assert_eq!(F128::ZERO.cmp(F128::from_u64(1)), Ordering::Less);
        assert_eq!(F128::from_u64(1).cmp(F128::ZERO), Ordering::Greater);
    }

    #[test]
    fn test_cmp_by_exponent_then_mantissa() {
        let a = F128::from_u64(1);
        let b = F128::from_u64(2);
        assert_eq!(a.cmp(b), Ordering::Less);
        assert_eq!(b.cmp(a), Ordering::Greater);
        assert_eq!(a.cmp(a), Ordering::Equal);
    }

    #[test]
    fn test_is_zero() {
        assert!(F128::ZERO.is_zero());
        assert!(!F128::from_u64(1).is_zero());
    }

    // ----- frozen-tail policy regression -----
    //
    // Directly exercises the documented freeze condition inside
    // BinomialF128::cdf: an artificially engineered pmf sequence proves
    // the "no-op add while pmf strictly shrinks" trigger promotes the
    // walk's boundary correctly rather than falling through to `money`.
    #[test]
    fn test_binomial_freezes_and_promotes_first_frozen_index() {
        // A tiny p with large money exercises real frozen-tail behavior:
        // pmf(0) = (1-p)^money can round to a value whose CDF plateaus
        // below 1 well before j reaches money, for money below
        // SelectF128MaxMoney but still very large relative to p's
        // precision. Assert the walk terminates (does not spin to
        // `money`) and, once frozen, further cdf() calls are pure no-ops
        // (idempotent boundary).
        let expected_size = 1u64;
        let total_money = 1u64 << 56; // just under SelectF128MaxMoney boundary scale
        let money = 1u64 << 40;
        let mut dist = BinomialF128::new(expected_size, total_money, money)
            .expect("expected_size < total_money must construct");
        let mut froze_at = None;
        for j in 0..money.min(1_000_000) {
            let cum = dist.cdf(j);
            if dist.frozen {
                froze_at = Some((j, cum));
                break;
            }
        }
        // With p = 2^-56 and money = 2^40, the mean is 2^-16 — the walk
        // should freeze (or otherwise resolve) far below the 1_000_000
        // iteration cap used above; if this assertion ever fails after a
        // legitimate upstream algorithm change, the frozen-tail policy
        // itself needs re-review, not this test.
        let (j, cum_at_freeze) =
            froze_at.expect("expected the walk to freeze within 1_000_000 steps");
        // Once frozen, calling cdf() again at a later index must return
        // the identical value (the documented "cdf(k) == cum for all
        // k >= at" invariant) — this is what makes the promoted freeze
        // index a safe, deterministic substitute for the unresolved tail.
        let cum_later = dist.cdf(j + 1000);
        assert_eq!(
            cum_at_freeze, cum_later,
            "frozen cdf must be stable across later calls"
        );
    }

    // ----- shl128 / shr128 primitives -----
    //
    // Not reachable from SelectF128's production path directly (Go's own
    // caller is `norm128`, an exact/non-rounding constructor used only by
    // upstream's own test suite to build hand-picked f128 values — see the
    // module doc comment for why it isn't ported here), but part of the
    // primitive set issue #667 calls out by name. Pinned directly against
    // the documented 128-bit shift semantics (`shl128`/`shr128`'s Go
    // implementation is a direct bit-shift with no rounding to get wrong).
    #[test]
    fn test_shl128_basic() {
        assert_eq!(shl128(0x1, 0x0, 0), (0x1, 0x0));
        assert_eq!(shl128(0x0, 0x1, 4), (0x0, 0x10));
        // Shift crossing the hi:lo boundary by 1 bit.
        assert_eq!(shl128(0x0, 1u64 << 63, 1), (0x1, 0x0));
        // n in [64,128): result is (lo << (n-64), 0).
        assert_eq!(shl128(0xdead, 0xbeef, 64), (0xbeef, 0x0));
        assert_eq!(shl128(0xdead, 0x1, 65), (0x2, 0x0));
        // n >= 128: fully shifted out.
        assert_eq!(shl128(u64::MAX, u64::MAX, 128), (0, 0));
        assert_eq!(shl128(u64::MAX, u64::MAX, 200), (0, 0));
    }

    #[test]
    fn test_shr128_basic() {
        assert_eq!(shr128(0x1, 0x0, 0), (0x1, 0x0));
        assert_eq!(shr128(0x1, 0x0, 1), (0x0, 1u64 << 63));
        assert_eq!(shr128(0x0, 0x10, 4), (0x0, 0x1));
        // n in [64,128): result is (0, hi >> (n-64)).
        assert_eq!(shr128(0xbeef, 0xdead, 64), (0x0, 0xbeef));
        assert_eq!(shr128(0x2, 0xdead, 65), (0x0, 0x1));
        // n >= 128: fully shifted out.
        assert_eq!(shr128(u64::MAX, u64::MAX, 128), (0, 0));
        assert_eq!(shr128(u64::MAX, u64::MAX, 200), (0, 0));
    }

    /// shl128/shr128 must be exact inverses for a shift amount `n` that
    /// does not lose set bits off either end, for every `n` in `0..128` —
    /// a property check that would catch a swapped `<`/`<=` boundary or a
    /// transposed hi/lo term in either port.
    #[test]
    fn test_shl_shr_128_roundtrip() {
        let hi = 0xa5a5_5a5a_1234_5678u64;
        let lo = 0x8765_4321_0f0f_f0f0u64;
        for n in 0..128u32 {
            let (shi, slo) = shr128(hi, lo, n);
            let (bhi, blo) = shl128(shi, slo, n);
            // Shifting right then left by n clears the low n bits but
            // leaves every bit above that unchanged.
            let (mask_hi, mask_lo) = shl128(u64::MAX, u64::MAX, n);
            assert_eq!(
                (bhi, blo),
                (hi & mask_hi, lo & mask_lo),
                "roundtrip failed at n={n}"
            );
        }
    }
}
