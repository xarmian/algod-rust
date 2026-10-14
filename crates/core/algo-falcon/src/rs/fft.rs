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

//! FFT over the ring R[X]/(X^n+1) and polynomial operations in FFT
//! representation (`fft.c`).
//!
//! Ported from the Falcon reference implementation, `falcon-c/fft.c`
//! (Copyright (c) 2017-2019 Falcon Project, MIT License, author Thomas
//! Pornin), vendored verbatim under `crates/core/algo-falcon/falcon-c/` as
//! part of github.com/algorand/falcon v0.1.0; the MIT notice is preserved in
//! `falcon-c/LICENSE`.
//!
//! Representation: a polynomial of degree `< n` in FFT form is stored as
//! `n` values, the real parts of its `n/2` complex evaluations in `f[0..n/2]`
//! and the imaginary parts in `f[n/2..n]`. The order of every floating-point
//! operation follows the C's `FPC_*` macros exactly, because a different
//! association would round differently; the AVX2 branches of the C are not
//! compiled in the vendored build and are not ported.

use super::fpr::*;

#[inline(always)]
fn fpc_add(a_re: Fpr, a_im: Fpr, b_re: Fpr, b_im: Fpr) -> (Fpr, Fpr) {
    (fpr_add(a_re, b_re), fpr_add(a_im, b_im))
}

#[inline(always)]
fn fpc_sub(a_re: Fpr, a_im: Fpr, b_re: Fpr, b_im: Fpr) -> (Fpr, Fpr) {
    (fpr_sub(a_re, b_re), fpr_sub(a_im, b_im))
}

#[inline(always)]
fn fpc_mul(a_re: Fpr, a_im: Fpr, b_re: Fpr, b_im: Fpr) -> (Fpr, Fpr) {
    (
        fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im)),
        fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re)),
    )
}

#[inline(always)]
fn fpc_div(a_re: Fpr, a_im: Fpr, b_re: Fpr, b_im: Fpr) -> (Fpr, Fpr) {
    let mut m = fpr_add(fpr_sqr(b_re), fpr_sqr(b_im));
    m = fpr_inv(m);
    let b_re = fpr_mul(b_re, m);
    let b_im = fpr_mul(fpr_neg(b_im), m);
    (
        fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im)),
        fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re)),
    )
}

/// `FFT`: in-place forward transform of `f[0..2^logn]`.
pub(crate) fn fft(f: &mut [Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut t = hn;
    let mut m = 2usize;
    for _u in 1..logn {
        let ht = t >> 1;
        let hm = m >> 1;
        let mut j1 = 0usize;
        for i1 in 0..hm {
            let j2 = j1 + ht;
            let s_re = FPR_GM_TAB[(m + i1) << 1];
            let s_im = FPR_GM_TAB[((m + i1) << 1) + 1];
            for j in j1..j2 {
                let x_re = f[j];
                let x_im = f[j + hn];
                let y_re = f[j + ht];
                let y_im = f[j + ht + hn];
                let (y_re, y_im) = fpc_mul(y_re, y_im, s_re, s_im);
                let (a, b) = fpc_add(x_re, x_im, y_re, y_im);
                f[j] = a;
                f[j + hn] = b;
                let (a, b) = fpc_sub(x_re, x_im, y_re, y_im);
                f[j + ht] = a;
                f[j + ht + hn] = b;
            }
            j1 += t;
        }
        t = ht;
        m <<= 1;
    }
}

/// `iFFT`: in-place inverse transform of `f[0..2^logn]`.
pub(crate) fn ifft(f: &mut [Fpr], logn: u32) {
    let n = 1usize << logn;
    let mut t = 1usize;
    let mut m = n;
    let hn = n >> 1;
    let mut u = logn;
    while u > 1 {
        let hm = m >> 1;
        let dt = t << 1;
        let mut i1 = 0usize;
        let mut j1 = 0usize;
        while j1 < hn {
            let j2 = j1 + t;
            let s_re = FPR_GM_TAB[(hm + i1) << 1];
            let s_im = fpr_neg(FPR_GM_TAB[((hm + i1) << 1) + 1]);
            for j in j1..j2 {
                let x_re = f[j];
                let x_im = f[j + hn];
                let y_re = f[j + t];
                let y_im = f[j + t + hn];
                let (a, b) = fpc_add(x_re, x_im, y_re, y_im);
                f[j] = a;
                f[j + hn] = b;
                let (x_re, x_im) = fpc_sub(x_re, x_im, y_re, y_im);
                let (a, b) = fpc_mul(x_re, x_im, s_re, s_im);
                f[j + t] = a;
                f[j + t + hn] = b;
            }
            i1 += 1;
            j1 += dt;
        }
        t = dt;
        m = hm;
        u -= 1;
    }
    if logn > 0 {
        let ni = FPR_P2_TAB[logn as usize];
        for v in f[..n].iter_mut() {
            *v = fpr_mul(*v, ni);
        }
    }
}

/// `poly_add`: `a += b` (both in FFT or both in normal representation).
pub(crate) fn poly_add(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    for (x, y) in a[..n].iter_mut().zip(&b[..n]) {
        *x = fpr_add(*x, *y);
    }
}

/// `poly_sub`: `a -= b`.
pub(crate) fn poly_sub(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    for (x, y) in a[..n].iter_mut().zip(&b[..n]) {
        *x = fpr_sub(*x, *y);
    }
}

/// `poly_neg`: `a = -a`.
pub(crate) fn poly_neg(a: &mut [Fpr], logn: u32) {
    let n = 1usize << logn;
    for x in a[..n].iter_mut() {
        *x = fpr_neg(*x);
    }
}

/// `poly_adj_fft`: Hermitian adjoint in FFT representation (negate the
/// imaginary parts).
pub(crate) fn poly_adj_fft(a: &mut [Fpr], logn: u32) {
    let n = 1usize << logn;
    for x in a[(n >> 1)..n].iter_mut() {
        *x = fpr_neg(*x);
    }
}

/// `poly_mul_fft`: `a *= b` in FFT representation.
pub(crate) fn poly_mul_fft(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let (re, im) = fpc_mul(a[u], a[u + hn], b[u], b[u + hn]);
        a[u] = re;
        a[u + hn] = im;
    }
}

/// `poly_muladj_fft`: `a *= adj(b)` in FFT representation.
pub(crate) fn poly_muladj_fft(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let (re, im) = fpc_mul(a[u], a[u + hn], b[u], fpr_neg(b[u + hn]));
        a[u] = re;
        a[u + hn] = im;
    }
}

/// `poly_mulselfadj_fft`: `a *= adj(a)` (result is real).
pub(crate) fn poly_mulselfadj_fft(a: &mut [Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let a_re = a[u];
        let a_im = a[u + hn];
        a[u] = fpr_add(fpr_sqr(a_re), fpr_sqr(a_im));
        a[u + hn] = FPR_ZERO;
    }
}

/// `poly_mulconst`: `a *= x` for a real constant `x`.
pub(crate) fn poly_mulconst(a: &mut [Fpr], x: Fpr, logn: u32) {
    let n = 1usize << logn;
    for v in a[..n].iter_mut() {
        *v = fpr_mul(*v, x);
    }
}

/// `poly_div_fft`: `a /= b` in FFT representation.
pub(crate) fn poly_div_fft(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let (re, im) = fpc_div(a[u], a[u + hn], b[u], b[u + hn]);
        a[u] = re;
        a[u + hn] = im;
    }
}

/// `poly_invnorm2_fft`: `d = 1 / (a*adj(a) + b*adj(b))` (real, half-size).
pub(crate) fn poly_invnorm2_fft(d: &mut [Fpr], a: &[Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let a_re = a[u];
        let a_im = a[u + hn];
        let b_re = b[u];
        let b_im = b[u + hn];
        d[u] = fpr_inv(fpr_add(
            fpr_add(fpr_sqr(a_re), fpr_sqr(a_im)),
            fpr_add(fpr_sqr(b_re), fpr_sqr(b_im)),
        ));
    }
}

/// `poly_add_muladj_fft`: `d = F*adj(f) + G*adj(g)`.
pub(crate) fn poly_add_muladj_fft(
    d: &mut [Fpr],
    big_f: &[Fpr],
    big_g: &[Fpr],
    f: &[Fpr],
    g: &[Fpr],
    logn: u32,
) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let (a_re, a_im) = fpc_mul(big_f[u], big_f[u + hn], f[u], fpr_neg(f[u + hn]));
        let (b_re, b_im) = fpc_mul(big_g[u], big_g[u + hn], g[u], fpr_neg(g[u + hn]));
        d[u] = fpr_add(a_re, b_re);
        d[u + hn] = fpr_add(a_im, b_im);
    }
}

/// `poly_mul_autoadj_fft`: `a *= b` where `b` is real (auto-adjoint,
/// half-size).
pub(crate) fn poly_mul_autoadj_fft(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for u in 0..hn {
        a[u] = fpr_mul(a[u], b[u]);
        a[u + hn] = fpr_mul(a[u + hn], b[u]);
    }
}

/// `poly_div_autoadj_fft`: `a /= b` where `b` is real (half-size).
pub(crate) fn poly_div_autoadj_fft(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let ib = fpr_inv(b[u]);
        a[u] = fpr_mul(a[u], ib);
        a[u + hn] = fpr_mul(a[u + hn], ib);
    }
}

/// `poly_LDL_fft`: LDL decomposition of the Gram matrix `[g00 g01; adj(g01)
/// g11]`, in place: `g01` receives `l10`, `g11` receives `d11`.
pub(crate) fn poly_ldl_fft(g00: &[Fpr], g01: &mut [Fpr], g11: &mut [Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let g00_re = g00[u];
        let g00_im = g00[u + hn];
        let g01_re = g01[u];
        let g01_im = g01[u + hn];
        let g11_re = g11[u];
        let g11_im = g11[u + hn];
        let (mu_re, mu_im) = fpc_div(g01_re, g01_im, g00_re, g00_im);
        let (g01_re, g01_im) = fpc_mul(mu_re, mu_im, g01_re, fpr_neg(g01_im));
        let (a, b) = fpc_sub(g11_re, g11_im, g01_re, g01_im);
        g11[u] = a;
        g11[u + hn] = b;
        g01[u] = mu_re;
        g01[u + hn] = fpr_neg(mu_im);
    }
}

/// `poly_LDLmv_fft`: as [`poly_ldl_fft`] but writing `d11` and `l10` to
/// separate outputs.
pub(crate) fn poly_ldlmv_fft(
    d11: &mut [Fpr],
    l10: &mut [Fpr],
    g00: &[Fpr],
    g01: &[Fpr],
    g11: &[Fpr],
    logn: u32,
) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let g00_re = g00[u];
        let g00_im = g00[u + hn];
        let g01_re = g01[u];
        let g01_im = g01[u + hn];
        let g11_re = g11[u];
        let g11_im = g11[u + hn];
        let (mu_re, mu_im) = fpc_div(g01_re, g01_im, g00_re, g00_im);
        let (g01_re, g01_im) = fpc_mul(mu_re, mu_im, g01_re, fpr_neg(g01_im));
        let (a, b) = fpc_sub(g11_re, g11_im, g01_re, g01_im);
        d11[u] = a;
        d11[u + hn] = b;
        l10[u] = mu_re;
        l10[u + hn] = fpr_neg(mu_im);
    }
}

/// `poly_split_fft`: split `f` (degree `2^logn`, FFT form) into its even and
/// odd halves `f0`, `f1` (degree `2^(logn-1)`, FFT form).
pub(crate) fn poly_split_fft(f0: &mut [Fpr], f1: &mut [Fpr], f: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let qn = hn >> 1;
    f0[0] = f[0];
    f1[0] = f[hn];
    for u in 0..qn {
        let a_re = f[u << 1];
        let a_im = f[(u << 1) + hn];
        let b_re = f[(u << 1) + 1];
        let b_im = f[(u << 1) + 1 + hn];
        let (t_re, t_im) = fpc_add(a_re, a_im, b_re, b_im);
        f0[u] = fpr_half(t_re);
        f0[u + qn] = fpr_half(t_im);
        let (t_re, t_im) = fpc_sub(a_re, a_im, b_re, b_im);
        let (t_re, t_im) = fpc_mul(
            t_re,
            t_im,
            FPR_GM_TAB[(u + hn) << 1],
            fpr_neg(FPR_GM_TAB[((u + hn) << 1) + 1]),
        );
        f1[u] = fpr_half(t_re);
        f1[u + qn] = fpr_half(t_im);
    }
}

/// `poly_merge_fft`: inverse of [`poly_split_fft`].
pub(crate) fn poly_merge_fft(f: &mut [Fpr], f0: &[Fpr], f1: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let qn = hn >> 1;
    f[0] = f0[0];
    f[hn] = f1[0];
    for u in 0..qn {
        let a_re = f0[u];
        let a_im = f0[u + qn];
        let (b_re, b_im) = fpc_mul(
            f1[u],
            f1[u + qn],
            FPR_GM_TAB[(u + hn) << 1],
            FPR_GM_TAB[((u + hn) << 1) + 1],
        );
        let (t_re, t_im) = fpc_add(a_re, a_im, b_re, b_im);
        f[u << 1] = t_re;
        f[(u << 1) + hn] = t_im;
        let (t_re, t_im) = fpc_sub(a_re, a_im, b_re, b_im);
        f[(u << 1) + 1] = t_re;
        f[(u << 1) + 1 + hn] = t_im;
    }
}

#[cfg(test)]
#[allow(clippy::needless_range_loop)]
mod tests {
    use super::*;

    fn poly(n: usize, seed: u64) -> Vec<Fpr> {
        let mut s = seed;
        (0..n)
            .map(|_| {
                s ^= s >> 12;
                s ^= s << 25;
                s ^= s >> 27;
                ((s.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 40) as i64 - (1 << 23)) as f64 / 64.0
            })
            .collect()
    }

    #[test]
    fn ifft_inverts_fft_to_within_rounding() {
        for logn in 1..=10u32 {
            let n = 1usize << logn;
            let a = poly(n, 7 + logn as u64);
            let mut b = a.clone();
            fft(&mut b, logn);
            ifft(&mut b, logn);
            for (x, y) in a.iter().zip(&b) {
                assert!((x - y).abs() < 1e-7, "logn={logn}: {x} vs {y}");
            }
        }
    }

    #[test]
    fn fft_multiplication_matches_schoolbook_mod_xn_plus_1() {
        let logn = 4u32;
        let n = 1usize << logn;
        let a = poly(n, 1);
        let b = poly(n, 2);
        // schoolbook a*b mod X^n+1
        let mut want = vec![0.0f64; n];
        for i in 0..n {
            for j in 0..n {
                let k = i + j;
                if k < n {
                    want[k] += a[i] * b[j];
                } else {
                    want[k - n] -= a[i] * b[j];
                }
            }
        }
        let mut fa = a.clone();
        let mut fb = b.clone();
        fft(&mut fa, logn);
        fft(&mut fb, logn);
        poly_mul_fft(&mut fa, &fb, logn);
        ifft(&mut fa, logn);
        for (x, y) in want.iter().zip(&fa) {
            assert!((x - y).abs() < 1e-6 * x.abs().max(1.0), "{x} vs {y}");
        }
    }

    #[test]
    fn split_then_merge_is_identity() {
        for logn in 2..=10u32 {
            let n = 1usize << logn;
            let mut f = poly(n, 99 + logn as u64);
            fft(&mut f, logn);
            let mut f0 = vec![0.0; n / 2];
            let mut f1 = vec![0.0; n / 2];
            poly_split_fft(&mut f0, &mut f1, &f, logn);
            let mut g = vec![0.0; n];
            poly_merge_fft(&mut g, &f0, &f1, logn);
            for (x, y) in f.iter().zip(&g) {
                assert!(
                    (x - y).abs() < 1e-9 * x.abs().max(1.0),
                    "logn={logn}: {x} vs {y}"
                );
            }
        }
    }
}

/// Differential tests against the vendored C (`falcon_inner_FFT` etc.). The
/// comparison is bit-exact: same inputs, identical output bits.
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
        /// Values shaped like Falcon's: small-ish integers over 64, or a
        /// wider dynamic range.
        fn poly(&mut self, n: usize, wide: bool) -> Vec<Fpr> {
            (0..n)
                .map(|_| {
                    let v = ((self.next() >> 40) as i64 - (1 << 23)) as f64 / 64.0;
                    if wide {
                        let e = (self.next() % 40) as i32 - 20;
                        v * 2f64.powi(e)
                    } else {
                        v
                    }
                })
                .collect()
        }
        /// Strictly positive real half-size polynomial (for autoadj divisors).
        fn positive(&mut self, hn: usize) -> Vec<Fpr> {
            (0..hn).map(|_| 1.0 + (self.next() >> 44) as f64).collect()
        }
    }

    fn bits(v: &[Fpr]) -> Vec<u64> {
        v.iter().map(|x| x.to_bits()).collect()
    }

    #[test]
    fn fft_and_ifft_match_c() {
        let mut rng = Rng(0xF47_0000_0000_0001);
        for case in 0..200 {
            let logn = 1 + (case % 10) as u32;
            let n = 1usize << logn;
            let a = rng.poly(n, case % 2 == 1);
            let mut rs = a.clone();
            let mut cc = a.clone();
            fft(&mut rs, logn);
            unsafe { c::falcon_inner_FFT(cc.as_mut_ptr() as *mut u64, logn) };
            assert_eq!(bits(&rs), bits(&cc), "case {case}: FFT logn={logn}");
            ifft(&mut rs, logn);
            unsafe { c::falcon_inner_iFFT(cc.as_mut_ptr() as *mut u64, logn) };
            assert_eq!(bits(&rs), bits(&cc), "case {case}: iFFT logn={logn}");
        }
    }

    #[test]
    fn poly_ops_match_c() {
        let mut rng = Rng(0x9017_0000_0000_0002);
        for case in 0..150 {
            let logn = 1 + (case % 10) as u32;
            let n = 1usize << logn;
            let hn = n >> 1;
            let wide = case % 3 == 0;
            let a0 = rng.poly(n, wide);
            let b0 = rng.poly(n, wide);
            let k = rng.poly(1, wide)[0];
            macro_rules! unary {
                ($rs:ident, $c:ident $(, $extra:expr)*) => {{
                    let mut x = a0.clone();
                    let mut y = a0.clone();
                    $rs(&mut x $(, $extra)*, logn);
                    unsafe { c::$c(y.as_mut_ptr() as *mut u64 $(, $extra)*, logn) };
                    assert_eq!(bits(&x), bits(&y), "case {case}: {} logn={logn}", stringify!($rs));
                }};
            }
            macro_rules! binary {
                ($rs:ident, $c:ident, $b:expr) => {{
                    let mut x = a0.clone();
                    let mut y = a0.clone();
                    let bb: &[Fpr] = $b;
                    $rs(&mut x, bb, logn);
                    unsafe { c::$c(y.as_mut_ptr() as *mut u64, bb.as_ptr() as *const u64, logn) };
                    assert_eq!(
                        bits(&x),
                        bits(&y),
                        "case {case}: {} logn={logn}",
                        stringify!($rs)
                    );
                }};
            }
            unary!(poly_neg, falcon_inner_poly_neg);
            unary!(poly_adj_fft, falcon_inner_poly_adj_fft);
            unary!(poly_mulselfadj_fft, falcon_inner_poly_mulselfadj_fft);
            binary!(poly_add, falcon_inner_poly_add, &b0);
            binary!(poly_sub, falcon_inner_poly_sub, &b0);
            binary!(poly_mul_fft, falcon_inner_poly_mul_fft, &b0);
            binary!(poly_muladj_fft, falcon_inner_poly_muladj_fft, &b0);
            binary!(poly_div_fft, falcon_inner_poly_div_fft, &b0);
            {
                let mut x = a0.clone();
                let mut y = a0.clone();
                poly_mulconst(&mut x, k, logn);
                unsafe {
                    c::falcon_inner_poly_mulconst(y.as_mut_ptr() as *mut u64, k.to_bits(), logn)
                };
                assert_eq!(bits(&x), bits(&y), "case {case}: poly_mulconst");
            }
            let pos = rng.positive(hn);
            binary!(
                poly_mul_autoadj_fft,
                falcon_inner_poly_mul_autoadj_fft,
                &pos
            );
            binary!(
                poly_div_autoadj_fft,
                falcon_inner_poly_div_autoadj_fft,
                &pos
            );
            {
                let mut dx = vec![0.0; hn];
                let mut dy = vec![0.0; hn];
                poly_invnorm2_fft(&mut dx, &a0, &b0, logn);
                unsafe {
                    c::falcon_inner_poly_invnorm2_fft(
                        dy.as_mut_ptr() as *mut u64,
                        a0.as_ptr() as *const u64,
                        b0.as_ptr() as *const u64,
                        logn,
                    )
                };
                assert_eq!(bits(&dx), bits(&dy), "case {case}: poly_invnorm2_fft");
            }
            {
                let c0 = rng.poly(n, wide);
                let d0 = rng.poly(n, wide);
                let mut dx = vec![0.0; n];
                let mut dy = vec![0.0; n];
                poly_add_muladj_fft(&mut dx, &a0, &b0, &c0, &d0, logn);
                unsafe {
                    c::falcon_inner_poly_add_muladj_fft(
                        dy.as_mut_ptr() as *mut u64,
                        a0.as_ptr() as *const u64,
                        b0.as_ptr() as *const u64,
                        c0.as_ptr() as *const u64,
                        d0.as_ptr() as *const u64,
                        logn,
                    )
                };
                assert_eq!(bits(&dx), bits(&dy), "case {case}: poly_add_muladj_fft");
            }
            {
                // Gram-like inputs: g00 positive real, g11 anything.
                let g00: Vec<Fpr> = rng
                    .positive(hn)
                    .into_iter()
                    .chain(std::iter::repeat_n(0.0, hn))
                    .collect();
                let mut g01x = a0.clone();
                let mut g11x = b0.clone();
                let mut g01y = a0.clone();
                let mut g11y = b0.clone();
                poly_ldl_fft(&g00, &mut g01x, &mut g11x, logn);
                unsafe {
                    c::falcon_inner_poly_LDL_fft(
                        g00.as_ptr() as *const u64,
                        g01y.as_mut_ptr() as *mut u64,
                        g11y.as_mut_ptr() as *mut u64,
                        logn,
                    )
                };
                assert_eq!(
                    (bits(&g01x), bits(&g11x)),
                    (bits(&g01y), bits(&g11y)),
                    "case {case}: poly_LDL_fft"
                );
                let mut d11x = vec![0.0; n];
                let mut l10x = vec![0.0; n];
                let mut d11y = vec![0.0; n];
                let mut l10y = vec![0.0; n];
                poly_ldlmv_fft(&mut d11x, &mut l10x, &g00, &a0, &b0, logn);
                unsafe {
                    c::falcon_inner_poly_LDLmv_fft(
                        d11y.as_mut_ptr() as *mut u64,
                        l10y.as_mut_ptr() as *mut u64,
                        g00.as_ptr() as *const u64,
                        a0.as_ptr() as *const u64,
                        b0.as_ptr() as *const u64,
                        logn,
                    )
                };
                assert_eq!(
                    (bits(&d11x), bits(&l10x)),
                    (bits(&d11y), bits(&l10y)),
                    "case {case}: poly_LDLmv_fft"
                );
            }
            if logn >= 2 {
                let mut f0x = vec![0.0; hn];
                let mut f1x = vec![0.0; hn];
                let mut f0y = vec![0.0; hn];
                let mut f1y = vec![0.0; hn];
                poly_split_fft(&mut f0x, &mut f1x, &a0, logn);
                unsafe {
                    c::falcon_inner_poly_split_fft(
                        f0y.as_mut_ptr() as *mut u64,
                        f1y.as_mut_ptr() as *mut u64,
                        a0.as_ptr() as *const u64,
                        logn,
                    )
                };
                assert_eq!(
                    (bits(&f0x), bits(&f1x)),
                    (bits(&f0y), bits(&f1y)),
                    "case {case}: poly_split_fft"
                );
                let mut mx = vec![0.0; n];
                let mut my = vec![0.0; n];
                poly_merge_fft(&mut mx, &f0x, &f1x, logn);
                unsafe {
                    c::falcon_inner_poly_merge_fft(
                        my.as_mut_ptr() as *mut u64,
                        f0x.as_ptr() as *const u64,
                        f1x.as_ptr() as *const u64,
                        logn,
                    )
                };
                assert_eq!(bits(&mx), bits(&my), "case {case}: poly_merge_fft");
            }
        }
    }
}
