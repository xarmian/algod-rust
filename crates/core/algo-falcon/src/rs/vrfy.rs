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

//! Arithmetic modulo q = 12289, the NTT, and the integer parts of
//! verification and key completion (`vrfy.c`).
//!
//! Ported from the Falcon reference implementation, `falcon-c/vrfy.c`
//! (Copyright (c) 2017-2019 Falcon Project, MIT License, author Thomas
//! Pornin), vendored verbatim under `crates/core/algo-falcon/falcon-c/` as
//! part of github.com/algorand/falcon v0.1.0; the MIT notice is preserved in
//! `falcon-c/LICENSE`.
//!
//! All values are kept in `[0, q)` in `u32` arithmetic with the C's
//! branch-free reductions (`d += q & -(d >> 31)`), written with `wrapping_*`
//! where the C relies on unsigned wraparound. Where the C takes a `tmp`
//! scratch pointer, the Rust allocates the scratch itself.

use super::common::is_short;
use super::ntt_tables::{GMB, IGMB};

pub(crate) const Q: u32 = 12289;
/// `-1/q mod 2^16`.
const Q0I: u32 = 12287;
/// `2^16 mod q`.
const R: u32 = 4091;
/// `2^32 mod q`.
const R2: u32 = 10952;

/// `mq_conv_small`: a small signed integer to `[0, q)`.
#[inline(always)]
pub(crate) fn mq_conv_small(x: i32) -> u32 {
    let mut y = x as u32;
    y = y.wrapping_add(Q & (y >> 31).wrapping_neg());
    y
}

/// `mq_add`: `x + y mod q` for `x, y` in `[0, q)`.
#[inline(always)]
pub(crate) fn mq_add(x: u32, y: u32) -> u32 {
    let mut d = x.wrapping_add(y).wrapping_sub(Q);
    d = d.wrapping_add(Q & (d >> 31).wrapping_neg());
    d
}

/// `mq_sub`: `x - y mod q`.
#[inline(always)]
pub(crate) fn mq_sub(x: u32, y: u32) -> u32 {
    let mut d = x.wrapping_sub(y);
    d = d.wrapping_add(Q & (d >> 31).wrapping_neg());
    d
}

/// `mq_rshift1`: `x / 2 mod q`.
#[inline(always)]
fn mq_rshift1(mut x: u32) -> u32 {
    x = x.wrapping_add(Q & (x & 1).wrapping_neg());
    x >> 1
}

/// `mq_montymul`: `x * y / R mod q` (Montgomery multiplication, R = 2^16).
#[inline(always)]
pub(crate) fn mq_montymul(x: u32, y: u32) -> u32 {
    let mut z = x.wrapping_mul(y);
    let w = (z.wrapping_mul(Q0I) & 0xFFFF).wrapping_mul(Q);
    z = z.wrapping_add(w) >> 16;
    z = z.wrapping_sub(Q);
    z = z.wrapping_add(Q & (z >> 31).wrapping_neg());
    z
}

#[inline(always)]
fn mq_montysqr(x: u32) -> u32 {
    mq_montymul(x, x)
}

/// `mq_div_12289`: `x / y mod q` via `y^(q-2)` with a fixed addition chain.
pub(crate) fn mq_div_12289(x: u32, y: u32) -> u32 {
    let y0 = mq_montymul(y, R2);
    let y1 = mq_montysqr(y0);
    let y2 = mq_montymul(y1, y0);
    let y3 = mq_montymul(y2, y1);
    let y4 = mq_montysqr(y3);
    let y5 = mq_montysqr(y4);
    let y6 = mq_montysqr(y5);
    let y7 = mq_montysqr(y6);
    let y8 = mq_montysqr(y7);
    let y9 = mq_montymul(y8, y2);
    let y10 = mq_montymul(y9, y8);
    let y11 = mq_montysqr(y10);
    let y12 = mq_montysqr(y11);
    let y13 = mq_montymul(y12, y9);
    let y14 = mq_montysqr(y13);
    let y15 = mq_montysqr(y14);
    let y16 = mq_montymul(y15, y10);
    let y17 = mq_montysqr(y16);
    let y18 = mq_montymul(y17, y0);
    mq_montymul(y18, x)
}

/// `mq_NTT`: in-place NTT of `a[0..2^logn]` (bit-reversed output order).
pub(crate) fn mq_ntt(a: &mut [u16], logn: u32) {
    let n = 1usize << logn;
    let mut t = n;
    let mut m = 1usize;
    while m < n {
        let ht = t >> 1;
        let mut j1 = 0usize;
        for i in 0..m {
            let s = u32::from(GMB[m + i]);
            let j2 = j1 + ht;
            for j in j1..j2 {
                let u = u32::from(a[j]);
                let v = mq_montymul(u32::from(a[j + ht]), s);
                a[j] = mq_add(u, v) as u16;
                a[j + ht] = mq_sub(u, v) as u16;
            }
            j1 += t;
        }
        t = ht;
        m <<= 1;
    }
}

/// `mq_iNTT`: inverse of [`mq_ntt`].
pub(crate) fn mq_intt(a: &mut [u16], logn: u32) {
    let n = 1usize << logn;
    let mut t = 1usize;
    let mut m = n;
    while m > 1 {
        let hm = m >> 1;
        let dt = t << 1;
        let mut j1 = 0usize;
        for i in 0..hm {
            let j2 = j1 + t;
            let s = u32::from(IGMB[hm + i]);
            for j in j1..j2 {
                let u = u32::from(a[j]);
                let v = u32::from(a[j + t]);
                a[j] = mq_add(u, v) as u16;
                let w = mq_sub(u, v);
                a[j + t] = mq_montymul(w, s) as u16;
            }
            j1 += dt;
        }
        t = dt;
        m = hm;
    }
    let mut ni = R;
    let mut m = n;
    while m > 1 {
        ni = mq_rshift1(ni);
        m >>= 1;
    }
    for v in a[..n].iter_mut() {
        *v = mq_montymul(u32::from(*v), ni) as u16;
    }
}

/// `mq_poly_tomonty`: convert to Montgomery representation.
pub(crate) fn mq_poly_tomonty(f: &mut [u16], logn: u32) {
    let n = 1usize << logn;
    for v in f[..n].iter_mut() {
        *v = mq_montymul(u32::from(*v), R2) as u16;
    }
}

/// `mq_poly_montymul_ntt`: `f *= g` pointwise, `g` in Montgomery form.
pub(crate) fn mq_poly_montymul_ntt(f: &mut [u16], g: &[u16], logn: u32) {
    let n = 1usize << logn;
    for (x, y) in f[..n].iter_mut().zip(&g[..n]) {
        *x = mq_montymul(u32::from(*x), u32::from(*y)) as u16;
    }
}

/// `mq_poly_sub`: `f -= g` pointwise.
pub(crate) fn mq_poly_sub(f: &mut [u16], g: &[u16], logn: u32) {
    let n = 1usize << logn;
    for (x, y) in f[..n].iter_mut().zip(&g[..n]) {
        *x = mq_sub(u32::from(*x), u32::from(*y)) as u16;
    }
}

/// `to_ntt_monty`: NTT then Montgomery form (how the public key is
/// prepared for verification).
pub(crate) fn to_ntt_monty(h: &mut [u16], logn: u32) {
    mq_ntt(h, logn);
    mq_poly_tomonty(h, logn);
}

/// `verify_raw`: given the hashed message `c0`, the signature `s2` and the
/// public key `h` (already `to_ntt_monty`), compute `s1 = c0 - s2*h` and
/// check that `(s1, s2)` is short.
pub(crate) fn verify_raw(c0: &[u16], s2: &[i16], h: &[u16], logn: u32) -> bool {
    let n = 1usize << logn;
    let mut tt = vec![0u16; n];
    for u in 0..n {
        let mut w = s2[u] as i32 as u32;
        w = w.wrapping_add(Q & (w >> 31).wrapping_neg());
        tt[u] = w as u16;
    }
    mq_ntt(&mut tt, logn);
    mq_poly_montymul_ntt(&mut tt, h, logn);
    mq_intt(&mut tt, logn);
    mq_poly_sub(&mut tt, c0, logn);
    let mut s1 = vec![0i16; n];
    for u in 0..n {
        let mut w = tt[u] as i32;
        w -= (Q & ((Q >> 1).wrapping_sub(w as u32) >> 31).wrapping_neg()) as i32;
        s1[u] = w as i16;
    }
    is_short(&s1, s2, logn)
}

/// `compute_public`: `h = g/f mod q` (not in NTT form). Returns `false` if
/// `f` is not invertible mod q.
pub(crate) fn compute_public(h: &mut [u16], f: &[i8], g: &[i8], logn: u32) -> bool {
    let n = 1usize << logn;
    let mut tt = vec![0u16; n];
    for u in 0..n {
        tt[u] = mq_conv_small(i32::from(f[u])) as u16;
        h[u] = mq_conv_small(i32::from(g[u])) as u16;
    }
    mq_ntt(h, logn);
    mq_ntt(&mut tt, logn);
    for u in 0..n {
        if tt[u] == 0 {
            return false;
        }
        h[u] = mq_div_12289(u32::from(h[u]), u32::from(tt[u])) as u16;
    }
    mq_intt(h, logn);
    true
}

/// `complete_private`: recompute `G = (1 + g*F) / f mod q` from `f, g, F`;
/// returns `false` if `f` is not invertible or `G` has a coefficient
/// outside `[-127, 127]`.
pub(crate) fn complete_private(
    big_g: &mut [i8],
    f: &[i8],
    g: &[i8],
    big_f: &[i8],
    logn: u32,
) -> bool {
    let n = 1usize << logn;
    let mut t1 = vec![0u16; n];
    let mut t2 = vec![0u16; n];
    for u in 0..n {
        t1[u] = mq_conv_small(i32::from(g[u])) as u16;
        t2[u] = mq_conv_small(i32::from(big_f[u])) as u16;
    }
    mq_ntt(&mut t1, logn);
    mq_ntt(&mut t2, logn);
    mq_poly_tomonty(&mut t1, logn);
    mq_poly_montymul_ntt(&mut t1, &t2, logn);
    for u in 0..n {
        t2[u] = mq_conv_small(i32::from(f[u])) as u16;
    }
    mq_ntt(&mut t2, logn);
    for u in 0..n {
        if t2[u] == 0 {
            return false;
        }
        t1[u] = mq_div_12289(u32::from(t1[u]), u32::from(t2[u])) as u16;
    }
    mq_intt(&mut t1, logn);
    for u in 0..n {
        let mut w = u32::from(t1[u]);
        w = w.wrapping_sub(Q & !(w.wrapping_sub(Q >> 1) >> 31).wrapping_neg());
        let gi = w as i32;
        if !(-127..=127).contains(&gi) {
            return false;
        }
        big_g[u] = gi as i8;
    }
    true
}

/// `is_invertible`: whether `s2` is invertible mod q (no zero NTT
/// coefficient).
pub(crate) fn is_invertible(s2: &[i16], logn: u32) -> bool {
    let n = 1usize << logn;
    let mut tt = vec![0u16; n];
    for u in 0..n {
        let mut w = s2[u] as i32 as u32;
        w = w.wrapping_add(Q & (w >> 31).wrapping_neg());
        tt[u] = w as u16;
    }
    mq_ntt(&mut tt, logn);
    let mut r: u32 = 0;
    for &t in &tt[..n] {
        r |= u32::from(t).wrapping_sub(1);
    }
    (1u32.wrapping_sub(r >> 31)) != 0
}

/// `verify_recover`: recover the public key `h = (c0 - s1) / s2 mod q` and
/// check that `(s1, s2)` is short and `s2` invertible.
pub(crate) fn verify_recover(h: &mut [u16], c0: &[u16], s1: &[i16], s2: &[i16], logn: u32) -> bool {
    let n = 1usize << logn;
    let mut tt = vec![0u16; n];
    for u in 0..n {
        let mut w = s2[u] as i32 as u32;
        w = w.wrapping_add(Q & (w >> 31).wrapping_neg());
        tt[u] = w as u16;
        let mut w = s1[u] as i32 as u32;
        w = w.wrapping_add(Q & (w >> 31).wrapping_neg());
        w = mq_sub(u32::from(c0[u]), w);
        h[u] = w as u16;
    }
    mq_ntt(&mut tt, logn);
    mq_ntt(h, logn);
    let mut r: u32 = 0;
    for u in 0..n {
        r |= u32::from(tt[u]).wrapping_sub(1);
        h[u] = mq_div_12289(u32::from(h[u]), u32::from(tt[u])) as u16;
    }
    mq_intt(h, logn);
    r = !r & (u32::from(is_short(s1, s2, logn))).wrapping_neg();
    (r >> 31) != 0
}

/// `count_nttzero`: number of zero coefficients of `sig` in NTT form.
pub(crate) fn count_nttzero(sig: &[i16], logn: u32) -> u32 {
    let n = 1usize << logn;
    let mut s2 = vec![0u16; n];
    for u in 0..n {
        let mut w = sig[u] as i32 as u32;
        w = w.wrapping_add(Q & (w >> 31).wrapping_neg());
        s2[u] = w as u16;
    }
    mq_ntt(&mut s2, logn);
    let mut r: u32 = 0;
    for &v in &s2[..n] {
        let w = u32::from(v).wrapping_sub(1);
        r = r.wrapping_add(w >> 31);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn montgomery_and_division_are_consistent() {
        // montymul(x, R2) = x*R mod q; montymul(xR, 1) = x.
        for x in [0u32, 1, 2, 12288, 4091, 7777] {
            let xr = mq_montymul(x, R2);
            assert_eq!(mq_montymul(xr, 1), x);
            for y in [1u32, 3, 12288, 5555] {
                let d = mq_div_12289(x, y);
                // d * y == x mod q
                assert_eq!((d * y) % Q, x % Q, "x={x} y={y}");
            }
        }
        assert_eq!(mq_add(12288, 1), 0);
        assert_eq!(mq_sub(0, 1), 12288);
        assert_eq!(mq_conv_small(-1), 12288);
        assert_eq!(mq_conv_small(5), 5);
    }

    #[test]
    fn intt_inverts_ntt() {
        for logn in 1..=10u32 {
            let n = 1usize << logn;
            let a: Vec<u16> = (0..n).map(|i| ((i * 7919 + 13) % 12289) as u16).collect();
            let mut b = a.clone();
            mq_ntt(&mut b, logn);
            mq_intt(&mut b, logn);
            assert_eq!(a, b, "logn={logn}");
        }
    }

    #[test]
    fn compute_public_then_complete_private_round_trip() {
        // Tiny f, g with f invertible: h = g/f; check h*f == g.
        let logn = 3u32;
        let n = 8usize;
        let f: Vec<i8> = vec![3, -1, 2, 0, 1, -2, 1, 1];
        let g: Vec<i8> = vec![1, 2, -1, 0, 0, 3, -2, 1];
        let mut h = vec![0u16; n];
        assert!(compute_public(&mut h, &f, &g, logn));
        // h*f in NTT domain == g
        let mut hf = h.clone();
        let mut ff: Vec<u16> = f
            .iter()
            .map(|&v| mq_conv_small(i32::from(v)) as u16)
            .collect();
        mq_ntt(&mut hf, logn);
        mq_ntt(&mut ff, logn);
        mq_poly_tomonty(&mut ff, logn);
        mq_poly_montymul_ntt(&mut hf, &ff, logn);
        mq_intt(&mut hf, logn);
        let gg: Vec<u16> = g
            .iter()
            .map(|&v| mq_conv_small(i32::from(v)) as u16)
            .collect();
        assert_eq!(hf, gg);
    }
}

/// Differential tests against the vendored C (`falcon_inner_*` in vrfy.c).
#[cfg(all(test, feature = "c-backend"))]
mod c_diff {
    use super::*;
    use crate::c_internals as c;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn u16s(&mut self, n: usize) -> Vec<u16> {
            (0..n).map(|_| (self.next() % 12289) as u16).collect()
        }
        fn i16s(&mut self, n: usize, spread: i32) -> Vec<i16> {
            (0..n)
                .map(|_| ((self.next() % (2 * spread as u64 + 1)) as i32 - spread) as i16)
                .collect()
        }
        fn i8s(&mut self, n: usize, spread: i32) -> Vec<i8> {
            (0..n)
                .map(|_| ((self.next() % (2 * spread as u64 + 1)) as i32 - spread) as i8)
                .collect()
        }
    }

    #[test]
    fn ntt_family_matches_c() {
        let mut rng = Rng(0x7177_0000_0000_0003);
        for case in 0..200 {
            let logn = 1 + (case % 10) as u32;
            let n = 1usize << logn;
            let a = rng.u16s(n);
            let b = rng.u16s(n);
            let (mut x, mut y) = (a.clone(), a.clone());
            mq_ntt(&mut x, logn);
            unsafe { c::falcon_inner_mq_NTT(y.as_mut_ptr(), logn) };
            assert_eq!(x, y, "case {case}: mq_NTT");
            mq_poly_montymul_ntt(&mut x, &b, logn);
            unsafe { c::falcon_inner_mq_poly_montymul_ntt(y.as_mut_ptr(), b.as_ptr(), logn) };
            assert_eq!(x, y, "case {case}: mq_poly_montymul_ntt");
            mq_intt(&mut x, logn);
            unsafe { c::falcon_inner_mq_iNTT(y.as_mut_ptr(), logn) };
            assert_eq!(x, y, "case {case}: mq_iNTT");
            mq_poly_sub(&mut x, &b, logn);
            unsafe { c::falcon_inner_mq_poly_sub(y.as_mut_ptr(), b.as_ptr(), logn) };
            assert_eq!(x, y, "case {case}: mq_poly_sub");
            let (mut x, mut y) = (a.clone(), a.clone());
            to_ntt_monty(&mut x, logn);
            unsafe { c::falcon_inner_to_ntt_monty(y.as_mut_ptr(), logn) };
            assert_eq!(x, y, "case {case}: to_ntt_monty");
            for _ in 0..50 {
                let p = (rng.next() % 12289) as u32;
                let q = (rng.next() % 12289) as u32;
                assert_eq!(mq_sub(p, q), unsafe { c::falcon_inner_mq_sub(p, q) });
            }
        }
    }

    #[test]
    fn verify_raw_and_count_nttzero_match_c() {
        let mut rng = Rng(0x7EF1_0000_0000_0004);
        for case in 0..300 {
            let logn = 1 + (case % 10) as u32;
            let n = 1usize << logn;
            let c0 = rng.u16s(n);
            // Mostly short vectors (so both outcomes occur), sometimes wide.
            let spread = if case % 4 == 0 { 2047 } else { 40 };
            let s2 = rng.i16s(n, spread);
            let mut h = rng.u16s(n);
            to_ntt_monty(&mut h, logn);
            let rs = verify_raw(&c0, &s2, &h, logn);
            let mut tmp = vec![0u8; 2 * n + 8];
            let cc = unsafe {
                c::falcon_inner_verify_raw(
                    c0.as_ptr(),
                    s2.as_ptr(),
                    h.as_ptr(),
                    logn,
                    tmp.as_mut_ptr(),
                )
            };
            assert_eq!(i32::from(rs), cc, "case {case}: verify_raw");
            let rs = count_nttzero(&s2, logn);
            let cc = unsafe { c::falcon_inner_count_nttzero(s2.as_ptr(), logn, tmp.as_mut_ptr()) };
            assert_eq!(rs as i32, cc, "case {case}: count_nttzero");
            let rs = is_invertible(&s2, logn);
            let cc = unsafe { c::falcon_inner_is_invertible(s2.as_ptr(), logn, tmp.as_mut_ptr()) };
            assert_eq!(i32::from(rs), cc, "case {case}: is_invertible");
            let s1 = rng.i16s(n, spread);
            let mut hx = vec![0u16; n];
            let mut hy = vec![0u16; n];
            let rs = verify_recover(&mut hx, &c0, &s1, &s2, logn);
            let cc = unsafe {
                c::falcon_inner_verify_recover(
                    hy.as_mut_ptr(),
                    c0.as_ptr(),
                    s1.as_ptr(),
                    s2.as_ptr(),
                    logn,
                    tmp.as_mut_ptr(),
                )
            };
            assert_eq!(
                (i32::from(rs), &hx),
                (cc, &hy),
                "case {case}: verify_recover"
            );
        }
    }

    #[test]
    fn compute_public_and_complete_private_match_c() {
        let mut rng = Rng(0xC0B1_0000_0000_0005);
        for case in 0..300 {
            let logn = 1 + (case % 10) as u32;
            let n = 1usize << logn;
            let spread = if case % 5 == 0 { 127 } else { 6 };
            let f = rng.i8s(n, spread);
            let g = rng.i8s(n, spread);
            let big_f = rng.i8s(n, spread);
            let mut hx = vec![0u16; n];
            let mut hy = vec![0u16; n];
            let mut tmp = vec![0u8; 4 * n + 8];
            let rs = compute_public(&mut hx, &f, &g, logn);
            let cc = unsafe {
                c::falcon_inner_compute_public(
                    hy.as_mut_ptr(),
                    f.as_ptr(),
                    g.as_ptr(),
                    logn,
                    tmp.as_mut_ptr(),
                )
            };
            assert_eq!(i32::from(rs), cc, "case {case}: compute_public result");
            if rs {
                assert_eq!(hx, hy, "case {case}: compute_public h");
            }
            let mut gx = vec![0i8; n];
            let mut gy = vec![0i8; n];
            let rs = complete_private(&mut gx, &f, &g, &big_f, logn);
            let cc = unsafe {
                c::falcon_inner_complete_private(
                    gy.as_mut_ptr(),
                    f.as_ptr(),
                    g.as_ptr(),
                    big_f.as_ptr(),
                    logn,
                    tmp.as_mut_ptr(),
                )
            };
            assert_eq!(i32::from(rs), cc, "case {case}: complete_private result");
            if rs {
                assert_eq!(gx, gy, "case {case}: complete_private G");
            }
        }
    }
}
