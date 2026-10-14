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

//! Key generation (`keygen.c`): Gaussian sampling of `f`, `g`, and the NTRU
//! equation solver (`fG - gF = q`) over big integers in RNS/CRT
//! representation with floating-point Babai reduction.
//!
//! Ported from the Falcon reference implementation, `falcon-c/keygen.c`
//! (Copyright (c) 2017-2019 Falcon Project, MIT License, author Thomas
//! Pornin), vendored verbatim under `crates/core/algo-falcon/falcon-c/` as
//! part of github.com/algorand/falcon v0.1.0; the MIT notice is preserved in
//! `falcon-c/LICENSE`.
//!
//! # Port structure
//!
//! The C threads one `uint32_t` scratch arena through every function and
//! carves regions out of it with pointer arithmetic, including `memmove`s
//! of regions over each other and floating-point regions reinterpreted on
//! top of dead integer regions. This port keeps **the same arena and the
//! same offsets for every integer region** (`t: &mut [u32]` plus `usize`
//! offsets in place of pointers), so the big-integer data flow — including
//! every in-place move — is the C's. Only the floating-point vectors
//! (`rt1..rt6`) and the integer vector `k` get their own allocations: the C
//! never reads those regions back through a different type, so the results
//! are identical and the Rust stays free of type punning. Big integers are
//! little-endian arrays of 31-bit limbs (bit 31 clear) as in the C.
//!
//! `FALCON_KG_CHACHA20` is **not** enabled in the vendored build (the
//! `#define` in `config.h` sits inside a comment), so `f` and `g` are sampled
//! straight from the SHAKE256 context, 8 little-endian bytes per draw
//! (`get_rng_u64`); this port does the same. go-algorand inherits this from
//! the same C.

// Index loops are kept in the C's shape on purpose: every `u` below indexes
// several arrays and arena regions at once, exactly as the C does, which is
// what makes the port reviewable side by side with keygen.c.
#![allow(clippy::needless_range_loop)]

use super::fft::*;
use super::fpr::*;
use super::keygen_tables::{SmallPrime, PRIMES, REV10};
use super::shake256::Shake256;
use super::vrfy::compute_public;

#[inline(always)]
fn mkn(logn: u32) -> usize {
    1usize << logn
}

// ---------------------------------------------------------------------------
// Arithmetic modulo a 31-bit prime p (Montgomery form with R = 2^31)
// ---------------------------------------------------------------------------

/// `modp_set`: a signed value to `[0, p)`.
#[inline(always)]
fn modp_set(x: i32, p: u32) -> u32 {
    let mut w = x as u32;
    w = w.wrapping_add(p & (w >> 31).wrapping_neg());
    w
}

/// `modp_norm`: `[0, p)` back to a signed value in `[-(p-1)/2, (p-1)/2]`.
#[inline(always)]
fn modp_norm(x: u32, p: u32) -> i32 {
    x.wrapping_sub(p & ((x.wrapping_sub((p.wrapping_add(1)) >> 1)) >> 31).wrapping_sub(1)) as i32
}

/// `modp_ninv31`: `-1/p mod 2^31`.
fn modp_ninv31(p: u32) -> u32 {
    let mut y: u32 = 2u32.wrapping_sub(p);
    y = y.wrapping_mul(2u32.wrapping_sub(p.wrapping_mul(y)));
    y = y.wrapping_mul(2u32.wrapping_sub(p.wrapping_mul(y)));
    y = y.wrapping_mul(2u32.wrapping_sub(p.wrapping_mul(y)));
    y = y.wrapping_mul(2u32.wrapping_sub(p.wrapping_mul(y)));
    0x7FFF_FFFF & y.wrapping_neg()
}

/// `modp_R`: `2^31 mod p`.
#[inline(always)]
fn modp_r(p: u32) -> u32 {
    (1u32 << 31).wrapping_sub(p)
}

#[inline(always)]
fn modp_add(a: u32, b: u32, p: u32) -> u32 {
    let mut d = a.wrapping_add(b).wrapping_sub(p);
    d = d.wrapping_add(p & (d >> 31).wrapping_neg());
    d
}

#[inline(always)]
fn modp_sub(a: u32, b: u32, p: u32) -> u32 {
    let mut d = a.wrapping_sub(b);
    d = d.wrapping_add(p & (d >> 31).wrapping_neg());
    d
}

/// `modp_montymul`: `a*b/R mod p`.
#[inline(always)]
fn modp_montymul(a: u32, b: u32, p: u32, p0i: u32) -> u32 {
    let z: u64 = u64::from(a) * u64::from(b);
    let w: u64 = (z.wrapping_mul(u64::from(p0i)) & 0x7FFF_FFFF) * u64::from(p);
    let mut d: u32 = ((z.wrapping_add(w)) >> 31) as u32;
    d = d.wrapping_sub(p);
    d = d.wrapping_add(p & (d >> 31).wrapping_neg());
    d
}

/// `modp_R2`: `2^62 mod p`.
fn modp_r2(p: u32, p0i: u32) -> u32 {
    let mut z = modp_r(p);
    z = modp_add(z, z, p);
    z = modp_montymul(z, z, p, p0i);
    z = modp_montymul(z, z, p, p0i);
    z = modp_montymul(z, z, p, p0i);
    z = modp_montymul(z, z, p, p0i);
    z = modp_montymul(z, z, p, p0i);
    z = (z.wrapping_add(p & (z & 1).wrapping_neg())) >> 1;
    z
}

/// `modp_Rx`: `2^(31*x) mod p`.
fn modp_rx(x: u32, p: u32, p0i: u32, r2: u32) -> u32 {
    let x = x.wrapping_sub(1);
    let mut r = r2;
    let mut z = modp_r(p);
    let mut i = 0u32;
    while (1u32 << i) <= x {
        if (x & (1u32 << i)) != 0 {
            z = modp_montymul(z, r, p, p0i);
        }
        r = modp_montymul(r, r, p, p0i);
        i += 1;
    }
    z
}

/// `modp_div`: `a/b mod p` (`b` in Montgomery form, result plain).
fn modp_div(a: u32, b: u32, p: u32, p0i: u32, r: u32) -> u32 {
    let e = p.wrapping_sub(2);
    let mut z = r;
    let mut i: i32 = 30;
    while i >= 0 {
        z = modp_montymul(z, z, p, p0i);
        let z2 = modp_montymul(z, b, p, p0i);
        z ^= (z ^ z2) & ((e >> i) & 1).wrapping_neg();
        i -= 1;
    }
    z = modp_montymul(z, 1, p, p0i);
    modp_montymul(a, z, p, p0i)
}

/// `modp_mkgm2`: NTT twiddle tables `gm`/`igm` (both in the arena `t`) for
/// degree `2^logn`, from the 2048-th root of unity `g`.
fn modp_mkgm2(t: &mut [u32], gm: usize, igm: usize, logn: u32, g: u32, p: u32, p0i: u32) {
    let n = mkn(logn);
    let r2 = modp_r2(p, p0i);
    let mut g = modp_montymul(g, r2, p, p0i);
    for _ in logn..10 {
        g = modp_montymul(g, g, p, p0i);
    }
    let ig = modp_div(r2, g, p, p0i, modp_r(p));
    let k = 10 - logn;
    let mut x1 = modp_r(p);
    let mut x2 = modp_r(p);
    for u in 0..n {
        let v = usize::from(REV10[u << k]);
        t[gm + v] = x1;
        t[igm + v] = x2;
        x1 = modp_montymul(x1, g, p, p0i);
        x2 = modp_montymul(x2, ig, p, p0i);
    }
}

/// `modp_NTT2_ext`: NTT of the strided polynomial at `a` (arena offset),
/// twiddles at `gm` (arena offset).
fn modp_ntt2_ext(t: &mut [u32], a: usize, stride: usize, gm: usize, logn: u32, p: u32, p0i: u32) {
    if logn == 0 {
        return;
    }
    let n = mkn(logn);
    let mut tt = n;
    let mut m = 1usize;
    while m < n {
        let ht = tt >> 1;
        let mut v1 = 0usize;
        for u in 0..m {
            let s = t[gm + m + u];
            let mut r1 = a + v1 * stride;
            let mut r2 = r1 + ht * stride;
            for _ in 0..ht {
                let x = t[r1];
                let y = modp_montymul(t[r2], s, p, p0i);
                t[r1] = modp_add(x, y, p);
                t[r2] = modp_sub(x, y, p);
                r1 += stride;
                r2 += stride;
            }
            v1 += tt;
        }
        tt = ht;
        m <<= 1;
    }
}

/// `modp_iNTT2_ext`.
fn modp_intt2_ext(t: &mut [u32], a: usize, stride: usize, igm: usize, logn: u32, p: u32, p0i: u32) {
    if logn == 0 {
        return;
    }
    let n = mkn(logn);
    let mut tt = 1usize;
    let mut m = n;
    while m > 1 {
        let hm = m >> 1;
        let dt = tt << 1;
        let mut v1 = 0usize;
        for u in 0..hm {
            let s = t[igm + hm + u];
            let mut r1 = a + v1 * stride;
            let mut r2 = r1 + tt * stride;
            for _ in 0..tt {
                let x = t[r1];
                let y = t[r2];
                t[r1] = modp_add(x, y, p);
                t[r2] = modp_montymul(modp_sub(x, y, p), s, p, p0i);
                r1 += stride;
                r2 += stride;
            }
            v1 += dt;
        }
        tt = dt;
        m = hm;
    }
    let ni = 1u32 << (31 - logn);
    let mut r = a;
    for _ in 0..n {
        t[r] = modp_montymul(t[r], ni, p, p0i);
        r += stride;
    }
}

#[inline(always)]
fn modp_ntt2(t: &mut [u32], a: usize, gm: usize, logn: u32, p: u32, p0i: u32) {
    modp_ntt2_ext(t, a, 1, gm, logn, p, p0i)
}

#[inline(always)]
fn modp_intt2(t: &mut [u32], a: usize, igm: usize, logn: u32, p: u32, p0i: u32) {
    modp_intt2_ext(t, a, 1, igm, logn, p, p0i)
}

/// `modp_poly_rec_res`: `f(x) * f(-x)` as a half-degree polynomial, in NTT
/// representation.
fn modp_poly_rec_res(t: &mut [u32], f: usize, logn: u32, p: u32, p0i: u32, r2: u32) {
    let hn = 1usize << (logn - 1);
    for u in 0..hn {
        let w0 = t[f + (u << 1)];
        let w1 = t[f + (u << 1) + 1];
        t[f + u] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
    }
}

// ---------------------------------------------------------------------------
// Big integers (31-bit limbs) in the arena
// ---------------------------------------------------------------------------

/// `zint_sub`: `a -= b` if `ctl == 1`; returns the borrow.
fn zint_sub(t: &mut [u32], a: usize, b: usize, len: usize, ctl: u32) -> u32 {
    let mut cc: u32 = 0;
    let m = ctl.wrapping_neg();
    for u in 0..len {
        let mut aw = t[a + u];
        let w = aw.wrapping_sub(t[b + u]).wrapping_sub(cc);
        cc = w >> 31;
        aw ^= ((w & 0x7FFF_FFFF) ^ aw) & m;
        t[a + u] = aw;
    }
    cc
}

/// `zint_mul_small`: `m *= x`; returns the carry limb.
fn zint_mul_small(t: &mut [u32], m: usize, mlen: usize, x: u32) -> u32 {
    let mut cc: u32 = 0;
    for u in 0..mlen {
        let z: u64 = u64::from(t[m + u]) * u64::from(x) + u64::from(cc);
        t[m + u] = (z as u32) & 0x7FFF_FFFF;
        cc = (z >> 31) as u32;
    }
    cc
}

/// `zint_mod_small_unsigned`: `d mod p` for an unsigned big integer.
fn zint_mod_small_unsigned(t: &[u32], d: usize, dlen: usize, p: u32, p0i: u32, r2: u32) -> u32 {
    let mut x: u32 = 0;
    let mut u = dlen;
    while u > 0 {
        u -= 1;
        x = modp_montymul(x, r2, p, p0i);
        let mut w = t[d + u].wrapping_sub(p);
        w = w.wrapping_add(p & (w >> 31).wrapping_neg());
        x = modp_add(x, w, p);
    }
    x
}

/// `zint_mod_small_signed`: `d mod p` for a two's-complement big integer.
fn zint_mod_small_signed(
    t: &[u32],
    d: usize,
    dlen: usize,
    p: u32,
    p0i: u32,
    r2: u32,
    rx: u32,
) -> u32 {
    if dlen == 0 {
        return 0;
    }
    let mut z = zint_mod_small_unsigned(t, d, dlen, p, p0i, r2);
    z = modp_sub(z, rx & (t[d + dlen - 1] >> 30).wrapping_neg(), p);
    z
}

/// `zint_add_mul_small`: `x += s * y` (`x` has `len + 1` limbs).
fn zint_add_mul_small(t: &mut [u32], x: usize, y: usize, len: usize, s: u32) {
    let mut cc: u32 = 0;
    for u in 0..len {
        let xw = t[x + u];
        let yw = t[y + u];
        let z: u64 = u64::from(yw) * u64::from(s) + u64::from(xw) + u64::from(cc);
        t[x + u] = (z as u32) & 0x7FFF_FFFF;
        cc = (z >> 31) as u32;
    }
    t[x + len] = cc;
}

/// `zint_norm_zero`: normalize `x` (mod `p`, both `len` limbs) into
/// `[-p/2, p/2]`.
fn zint_norm_zero(t: &mut [u32], x: usize, p: usize, len: usize) {
    let mut r: u32 = 0;
    let mut bb: u32 = 0;
    let mut u = len;
    while u > 0 {
        u -= 1;
        let wx = t[x + u];
        let wp = (t[p + u] >> 1) | (bb << 30);
        bb = t[p + u] & 1;
        let mut cc = wp.wrapping_sub(wx);
        cc = (cc.wrapping_neg() >> 31) | (cc >> 31).wrapping_neg();
        r |= cc & ((r & 1).wrapping_sub(1));
    }
    zint_sub(t, x, p, len, r >> 31);
}

/// `zint_rebuild_CRT`: rebuild `num` big integers (each `xlen` limbs, stride
/// `xstride`, at arena offset `xx`) from their residues modulo the first
/// `xlen` primes; `tmp` (arena offset, `xlen` limbs) receives the product of
/// the primes.
#[allow(clippy::too_many_arguments)]
fn zint_rebuild_crt(
    t: &mut [u32],
    xx: usize,
    xlen: usize,
    xstride: usize,
    num: usize,
    primes: &[SmallPrime],
    normalize_signed: bool,
    tmp: usize,
) {
    t[tmp] = primes[0].p;
    for u in 1..xlen {
        let p = primes[u].p;
        let s = primes[u].s;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let mut x = xx;
        for _ in 0..num {
            let xp = t[x + u];
            let xq = zint_mod_small_unsigned(t, x, u, p, p0i, r2);
            let xr = modp_montymul(s, modp_sub(xp, xq, p), p, p0i);
            zint_add_mul_small(t, x, tmp, u, xr);
            x += xstride;
        }
        t[tmp + u] = zint_mul_small(t, tmp, u, p);
    }
    if normalize_signed {
        let mut x = xx;
        for _ in 0..num {
            zint_norm_zero(t, x, tmp, xlen);
            x += xstride;
        }
    }
}

/// `zint_negate`: `a = -a` if `ctl == 1`.
fn zint_negate(t: &mut [u32], a: usize, len: usize, ctl: u32) {
    let mut cc = ctl;
    let m = ctl.wrapping_neg() >> 1;
    for u in 0..len {
        let mut aw = t[a + u];
        aw = (aw ^ m).wrapping_add(cc);
        t[a + u] = aw & 0x7FFF_FFFF;
        cc = aw >> 31;
    }
}

/// `zint_co_reduce`: `(a, b) <- ((xa*a + xb*b) / 2^31, (ya*a + yb*b) / 2^31)`
/// with sign fix-up; returns the negation flags.
#[allow(clippy::too_many_arguments)]
fn zint_co_reduce(
    t: &mut [u32],
    a: usize,
    b: usize,
    len: usize,
    xa: i64,
    xb: i64,
    ya: i64,
    yb: i64,
) -> u32 {
    let mut cca: i64 = 0;
    let mut ccb: i64 = 0;
    for u in 0..len {
        let wa = u64::from(t[a + u]);
        let wb = u64::from(t[b + u]);
        let za: u64 = wa
            .wrapping_mul(xa as u64)
            .wrapping_add(wb.wrapping_mul(xb as u64))
            .wrapping_add(cca as u64);
        let zb: u64 = wa
            .wrapping_mul(ya as u64)
            .wrapping_add(wb.wrapping_mul(yb as u64))
            .wrapping_add(ccb as u64);
        if u > 0 {
            t[a + u - 1] = (za as u32) & 0x7FFF_FFFF;
            t[b + u - 1] = (zb as u32) & 0x7FFF_FFFF;
        }
        cca = (za as i64) >> 31;
        ccb = (zb as i64) >> 31;
    }
    t[a + len - 1] = cca as u32;
    t[b + len - 1] = ccb as u32;
    let nega = ((cca as u64) >> 63) as u32;
    let negb = ((ccb as u64) >> 63) as u32;
    zint_negate(t, a, len, nega);
    zint_negate(t, b, len, negb);
    nega | (negb << 1)
}

/// `zint_finish_mod`: finish a modular reduction of `a` modulo `m`.
fn zint_finish_mod(t: &mut [u32], a: usize, len: usize, m: usize, neg: u32) {
    let mut cc: u32 = 0;
    for u in 0..len {
        cc = (t[a + u].wrapping_sub(t[m + u]).wrapping_sub(cc)) >> 31;
    }
    let xm = neg.wrapping_neg() >> 1;
    let ym = (neg | (1u32.wrapping_sub(cc))).wrapping_neg();
    cc = neg;
    for u in 0..len {
        let mut aw = t[a + u];
        let mw = (t[m + u] ^ xm) & ym;
        aw = aw.wrapping_sub(mw).wrapping_sub(cc);
        t[a + u] = aw & 0x7FFF_FFFF;
        cc = aw >> 31;
    }
}

/// `zint_co_reduce_mod`: as [`zint_co_reduce`] but modulo `m`.
#[allow(clippy::too_many_arguments)]
fn zint_co_reduce_mod(
    t: &mut [u32],
    a: usize,
    b: usize,
    m: usize,
    len: usize,
    m0i: u32,
    xa: i64,
    xb: i64,
    ya: i64,
    yb: i64,
) {
    let mut cca: i64 = 0;
    let mut ccb: i64 = 0;
    let fa: u32 = (t[a]
        .wrapping_mul(xa as u32)
        .wrapping_add(t[b].wrapping_mul(xb as u32)))
    .wrapping_mul(m0i)
        & 0x7FFF_FFFF;
    let fb: u32 = (t[a]
        .wrapping_mul(ya as u32)
        .wrapping_add(t[b].wrapping_mul(yb as u32)))
    .wrapping_mul(m0i)
        & 0x7FFF_FFFF;
    for u in 0..len {
        let wa = u64::from(t[a + u]);
        let wb = u64::from(t[b + u]);
        let mw = u64::from(t[m + u]);
        let za: u64 = wa
            .wrapping_mul(xa as u64)
            .wrapping_add(wb.wrapping_mul(xb as u64))
            .wrapping_add(mw.wrapping_mul(u64::from(fa)))
            .wrapping_add(cca as u64);
        let zb: u64 = wa
            .wrapping_mul(ya as u64)
            .wrapping_add(wb.wrapping_mul(yb as u64))
            .wrapping_add(mw.wrapping_mul(u64::from(fb)))
            .wrapping_add(ccb as u64);
        if u > 0 {
            t[a + u - 1] = (za as u32) & 0x7FFF_FFFF;
            t[b + u - 1] = (zb as u32) & 0x7FFF_FFFF;
        }
        cca = (za as i64) >> 31;
        ccb = (zb as i64) >> 31;
    }
    t[a + len - 1] = cca as u32;
    t[b + len - 1] = ccb as u32;
    zint_finish_mod(t, a, len, m, ((cca as u64) >> 63) as u32);
    zint_finish_mod(t, b, len, m, ((ccb as u64) >> 63) as u32);
}

/// `zint_bezout`: constant-time binary extended GCD. On success (`x` and
/// `y` coprime, both odd) `u*x - v*y = 1` with `u < y`, `v < x`. `tmp`
/// needs `4*len` limbs.
fn zint_bezout(
    t: &mut [u32],
    u: usize,
    v: usize,
    x: usize,
    y: usize,
    len: usize,
    tmp: usize,
) -> bool {
    if len == 0 {
        return false;
    }
    let u0 = u;
    let v0 = v;
    let u1 = tmp;
    let v1 = u1 + len;
    let a = v1 + len;
    let b = a + len;
    let x0i = modp_ninv31(t[x]);
    let y0i = modp_ninv31(t[y]);
    t.copy_within(x..x + len, a);
    t.copy_within(y..y + len, b);
    t[u0] = 1;
    for i in 1..len {
        t[u0 + i] = 0;
    }
    for i in 0..len {
        t[v0 + i] = 0;
    }
    t.copy_within(y..y + len, u1);
    t.copy_within(x..x + len, v1);
    t[v1] = t[v1].wrapping_sub(1);
    let mut num: u32 = 62 * (len as u32) + 30;
    while num >= 30 {
        let mut c0: u32 = u32::MAX;
        let mut c1: u32 = u32::MAX;
        let mut a0: u32 = 0;
        let mut a1: u32 = 0;
        let mut b0: u32 = 0;
        let mut b1: u32 = 0;
        let mut j = len;
        while j > 0 {
            j -= 1;
            let aw = t[a + j];
            let bw = t[b + j];
            a0 ^= (a0 ^ aw) & c0;
            a1 ^= (a1 ^ aw) & c1;
            b0 ^= (b0 ^ bw) & c0;
            b1 ^= (b1 ^ bw) & c1;
            c1 = c0;
            c0 &= (((aw | bw).wrapping_add(0x7FFF_FFFF)) >> 31).wrapping_sub(1);
        }
        a1 |= a0 & c1;
        a0 &= !c1;
        b1 |= b0 & c1;
        b0 &= !c1;
        let mut a_hi: u64 = (u64::from(a0) << 31) + u64::from(a1);
        let mut b_hi: u64 = (u64::from(b0) << 31) + u64::from(b1);
        let mut a_lo: u32 = t[a];
        let mut b_lo: u32 = t[b];
        let mut pa: i64 = 1;
        let mut pb: i64 = 0;
        let mut qa: i64 = 0;
        let mut qb: i64 = 1;
        for i in 0..31 {
            let rz: u64 = b_hi.wrapping_sub(a_hi);
            let rt: u32 = ((rz ^ ((a_hi ^ b_hi) & (a_hi ^ rz))) >> 63) as u32;
            let oa: u32 = (a_lo >> i) & 1;
            let ob: u32 = (b_lo >> i) & 1;
            let cab: u32 = oa & ob & rt;
            let cba: u32 = oa & ob & !rt;
            let ca: u32 = cab | (oa ^ 1);
            a_lo = a_lo.wrapping_sub(b_lo & cab.wrapping_neg());
            a_hi = a_hi.wrapping_sub(b_hi & (u64::from(cab)).wrapping_neg());
            pa = pa.wrapping_sub(qa & (i64::from(cab)).wrapping_neg());
            pb = pb.wrapping_sub(qb & (i64::from(cab)).wrapping_neg());
            b_lo = b_lo.wrapping_sub(a_lo & cba.wrapping_neg());
            b_hi = b_hi.wrapping_sub(a_hi & (u64::from(cba)).wrapping_neg());
            qa = qa.wrapping_sub(pa & (i64::from(cba)).wrapping_neg());
            qb = qb.wrapping_sub(pb & (i64::from(cba)).wrapping_neg());
            a_lo = a_lo.wrapping_add(a_lo & ca.wrapping_sub(1));
            pa = pa.wrapping_add(pa & (i64::from(ca)).wrapping_sub(1));
            pb = pb.wrapping_add(pb & (i64::from(ca)).wrapping_sub(1));
            a_hi ^= (a_hi ^ (a_hi >> 1)) & (u64::from(ca)).wrapping_neg();
            b_lo = b_lo.wrapping_add(b_lo & ca.wrapping_neg());
            qa = qa.wrapping_add(qa & (i64::from(ca)).wrapping_neg());
            qb = qb.wrapping_add(qb & (i64::from(ca)).wrapping_neg());
            b_hi ^= (b_hi ^ (b_hi >> 1)) & (u64::from(ca)).wrapping_sub(1);
        }
        let r = zint_co_reduce(t, a, b, len, pa, pb, qa, qb);
        pa = pa.wrapping_sub((pa.wrapping_add(pa)) & (i64::from(r & 1)).wrapping_neg());
        pb = pb.wrapping_sub((pb.wrapping_add(pb)) & (i64::from(r & 1)).wrapping_neg());
        qa = qa.wrapping_sub((qa.wrapping_add(qa)) & (i64::from(r >> 1)).wrapping_neg());
        qb = qb.wrapping_sub((qb.wrapping_add(qb)) & (i64::from(r >> 1)).wrapping_neg());
        zint_co_reduce_mod(t, u0, u1, y, len, y0i, pa, pb, qa, qb);
        zint_co_reduce_mod(t, v0, v1, x, len, x0i, pa, pb, qa, qb);
        num -= 30;
    }
    let mut rc: u32 = t[a] ^ 1;
    for j in 1..len {
        rc |= t[a + j];
    }
    ((1u32.wrapping_sub((rc | rc.wrapping_neg()) >> 31)) & t[x] & t[y]) != 0
}

/// `zint_add_scaled_mul_small`: `x += k * y * 2^(31*sch + scl)`.
#[allow(clippy::too_many_arguments)]
fn zint_add_scaled_mul_small(
    t: &mut [u32],
    x: usize,
    xlen: usize,
    y: usize,
    ylen: usize,
    k: i32,
    sch: u32,
    scl: u32,
) {
    if ylen == 0 {
        return;
    }
    let ysign: u32 = (t[y + ylen - 1] >> 30).wrapping_neg() >> 1;
    let mut tw: u32 = 0;
    let mut cc: i32 = 0;
    for u in (sch as usize)..xlen {
        let v = u - sch as usize;
        let wy = if v < ylen { t[y + v] } else { ysign };
        let wys = ((wy << scl) & 0x7FFF_FFFF) | tw;
        tw = wy >> (31 - scl);
        let z: u64 = ((i64::from(wys))
            .wrapping_mul(i64::from(k))
            .wrapping_add(i64::from(t[x + u]))
            .wrapping_add(i64::from(cc))) as u64;
        t[x + u] = (z as u32) & 0x7FFF_FFFF;
        let ccu = (z >> 31) as u32;
        cc = ccu as i32;
    }
}

/// `zint_sub_scaled`: `x -= y * 2^(31*sch + scl)`.
fn zint_sub_scaled(
    t: &mut [u32],
    x: usize,
    xlen: usize,
    y: usize,
    ylen: usize,
    sch: u32,
    scl: u32,
) {
    if ylen == 0 {
        return;
    }
    let ysign: u32 = (t[y + ylen - 1] >> 30).wrapping_neg() >> 1;
    let mut tw: u32 = 0;
    let mut cc: u32 = 0;
    for u in (sch as usize)..xlen {
        let v = u - sch as usize;
        let wy = if v < ylen { t[y + v] } else { ysign };
        let wys = ((wy << scl) & 0x7FFF_FFFF) | tw;
        tw = wy >> (31 - scl);
        let w = t[x + u].wrapping_sub(wys).wrapping_sub(cc);
        t[x + u] = w & 0x7FFF_FFFF;
        cc = w >> 31;
    }
}

/// `zint_one_to_plain`: a one-limb two's-complement value to `i32`.
#[inline(always)]
fn zint_one_to_plain(t: &[u32], x: usize) -> i32 {
    let mut w = t[x];
    w |= (w & 0x4000_0000) << 1;
    w as i32
}

// ---------------------------------------------------------------------------
// Polynomials with big-integer / floating-point / small coefficients
// ---------------------------------------------------------------------------

/// `poly_big_to_fp`: convert a big-integer polynomial (`flen` limbs, stride
/// `fstride`) to floating point.
fn poly_big_to_fp(d: &mut [Fpr], t: &[u32], f: usize, flen: usize, fstride: usize, logn: u32) {
    let n = mkn(logn);
    if flen == 0 {
        for x in d[..n].iter_mut() {
            *x = FPR_ZERO;
        }
        return;
    }
    let mut fo = f;
    for du in d[..n].iter_mut() {
        let neg: u32 = (t[fo + flen - 1] >> 30).wrapping_neg();
        let xm: u32 = neg >> 1;
        let mut cc: u32 = neg & 1;
        let mut x = FPR_ZERO;
        let mut fsc = FPR_ONE;
        for v in 0..flen {
            let mut w = (t[fo + v] ^ xm).wrapping_add(cc);
            cc = w >> 31;
            w &= 0x7FFF_FFFF;
            w = w.wrapping_sub((w << 1) & neg);
            x = fpr_add(x, fpr_mul(fpr_of(i64::from(w as i32)), fsc));
            fsc = fpr_mul(fsc, FPR_PTWO31);
        }
        *du = x;
        fo += fstride;
    }
}

/// `poly_big_to_small`: one-limb big integers to `i8`, rejecting values
/// outside `[-lim, lim]`.
fn poly_big_to_small(d: &mut [i8], t: &[u32], s: usize, lim: i32, logn: u32) -> bool {
    let n = mkn(logn);
    for u in 0..n {
        let z = zint_one_to_plain(t, s + u);
        if z < -lim || z > lim {
            return false;
        }
        d[u] = z as i8;
    }
    true
}

/// `poly_sub_scaled`: `F -= k * f * 2^(31*sch + scl)` (schoolbook, modulo
/// `X^n + 1`).
#[allow(clippy::too_many_arguments)]
fn poly_sub_scaled(
    t: &mut [u32],
    big_f: usize,
    flen_big: usize,
    fstride_big: usize,
    f: usize,
    flen: usize,
    fstride: usize,
    k: &[i32],
    sch: u32,
    scl: u32,
    logn: u32,
) {
    let n = mkn(logn);
    for u in 0..n {
        let mut kf: i32 = k[u].wrapping_neg();
        let mut x = big_f + u * fstride_big;
        let mut y = f;
        for v in 0..n {
            zint_add_scaled_mul_small(t, x, flen_big, y, flen, kf, sch, scl);
            if u + v == n - 1 {
                x = big_f;
                kf = kf.wrapping_neg();
            } else {
                x += fstride_big;
            }
            y += fstride;
        }
    }
}

/// `poly_sub_scaled_ntt`: as [`poly_sub_scaled`] but with the product
/// computed by NTT modulo `flen + 1` primes. `tmp` (arena offset) needs
/// `2n + n*(flen+1) + n` limbs.
#[allow(clippy::too_many_arguments)]
fn poly_sub_scaled_ntt(
    t: &mut [u32],
    big_f: usize,
    flen_big: usize,
    fstride_big: usize,
    f: usize,
    flen: usize,
    fstride: usize,
    k: &[i32],
    sch: u32,
    scl: u32,
    logn: u32,
    tmp: usize,
) {
    let n = mkn(logn);
    let tlen = flen + 1;
    let gm = tmp;
    let igm = gm + mkn(logn);
    let fk = igm + mkn(logn);
    let t1 = fk + n * tlen;
    for u in 0..tlen {
        let p = PRIMES[u].p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(flen as u32, p, p0i, r2);
        modp_mkgm2(t, gm, igm, logn, PRIMES[u].g, p, p0i);
        for v in 0..n {
            t[t1 + v] = modp_set(k[v], p);
        }
        modp_ntt2(t, t1, gm, logn, p, p0i);
        let mut y = f;
        let mut x = fk + u;
        for _ in 0..n {
            t[x] = zint_mod_small_signed(t, y, flen, p, p0i, r2, rx);
            y += fstride;
            x += tlen;
        }
        modp_ntt2_ext(t, fk + u, tlen, gm, logn, p, p0i);
        let mut x = fk + u;
        for v in 0..n {
            t[x] = modp_montymul(modp_montymul(t[t1 + v], t[x], p, p0i), r2, p, p0i);
            x += tlen;
        }
        modp_intt2_ext(t, fk + u, tlen, igm, logn, p, p0i);
    }
    zint_rebuild_crt(t, fk, tlen, tlen, n, &PRIMES, true, t1);
    let mut x = big_f;
    let mut y = fk;
    for _ in 0..n {
        zint_sub_scaled(t, x, flen_big, y, tlen, sch, scl);
        x += fstride_big;
        y += tlen;
    }
}

/// `gauss_1024_12289`: cumulative distribution for the f/g coefficients.
const GAUSS_1024_12289: [u64; 27] = [
    1283868770400643928,
    6416574995475331444,
    4078260278032692663,
    2353523259288686585,
    1227179971273316331,
    575931623374121527,
    242543240509105209,
    91437049221049666,
    30799446349977173,
    9255276791179340,
    2478152334826140,
    590642893610164,
    125206034929641,
    23590435911403,
    3948334035941,
    586753615614,
    77391054539,
    9056793210,
    940121950,
    86539696,
    7062824,
    510971,
    32764,
    1862,
    94,
    4,
    0,
];

/// `get_rng_u64`: 8 bytes from the SHAKE256 context, little-endian.
#[inline]
fn get_rng_u64(rng: &mut Shake256) -> u64 {
    let mut b = [0u8; 8];
    rng.extract(&mut b);
    u64::from_le_bytes(b)
}

/// `mkgauss`: one Gaussian sample (sum of `2^(10-logn)` base samples).
pub(crate) fn mkgauss(rng: &mut Shake256, logn: u32) -> i32 {
    let g = 1u32 << (10 - logn);
    let mut val: i32 = 0;
    for _ in 0..g {
        let mut r = get_rng_u64(rng);
        let neg: u32 = (r >> 63) as u32;
        r &= !(1u64 << 63);
        let mut f: u32 = ((r.wrapping_sub(GAUSS_1024_12289[0])) >> 63) as u32;
        let mut v: u32 = 0;
        r = get_rng_u64(rng);
        r &= !(1u64 << 63);
        for (k, &gk) in GAUSS_1024_12289.iter().enumerate().skip(1) {
            let tt: u32 = (((r.wrapping_sub(gk)) >> 63) as u32) ^ 1;
            v |= (k as u32) & (tt & (f ^ 1)).wrapping_neg();
            f |= tt;
        }
        v = (v ^ neg.wrapping_neg()).wrapping_add(neg);
        val = val.wrapping_add(v as i32);
    }
    val
}

const MAX_BL_SMALL: [usize; 11] = [1, 1, 2, 2, 4, 7, 14, 27, 53, 106, 209];
const MAX_BL_LARGE: [usize; 10] = [2, 2, 5, 7, 12, 21, 40, 78, 157, 308];
/// `BITLENGTH[depth] = (avg, std)`.
const BITLENGTH: [(i32, i32); 11] = [
    (4, 0),
    (11, 1),
    (24, 1),
    (50, 1),
    (102, 1),
    (202, 2),
    (401, 4),
    (794, 5),
    (1577, 8),
    (3138, 13),
    (6308, 25),
];
const DEPTH_INT_FG: u32 = 4;

/// `poly_small_sqnorm`: squared norm of a small polynomial, saturating.
pub(crate) fn poly_small_sqnorm(f: &[i8], logn: u32) -> u32 {
    let n = mkn(logn);
    let mut s: u32 = 0;
    let mut ng: u32 = 0;
    for &v in &f[..n] {
        let z = i32::from(v);
        s = s.wrapping_add((z * z) as u32);
        ng |= s;
    }
    s | (ng >> 31).wrapping_neg()
}

/// `poly_small_to_fp`.
fn poly_small_to_fp(x: &mut [Fpr], f: &[i8], logn: u32) {
    let n = mkn(logn);
    for (xu, &fu) in x[..n].iter_mut().zip(&f[..n]) {
        *xu = fpr_of(i64::from(fu));
    }
}

/// `make_fg_step`: one level of the field norm computation on
/// `(f, g)` stored at arena offset `data`.
fn make_fg_step(t: &mut [u32], data: usize, logn: u32, depth: u32, in_ntt: bool, out_ntt: bool) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let slen = MAX_BL_SMALL[depth as usize];
    let tlen = MAX_BL_SMALL[depth as usize + 1];
    let fd = data;
    let gd = fd + hn * tlen;
    let fs = gd + hn * tlen;
    let gs = fs + n * slen;
    let gm = gs + n * slen;
    let igm = gm + n;
    let t1 = igm + n;
    t.copy_within(data..data + 2 * n * slen, fs);
    for u in 0..slen {
        let p = PRIMES[u].p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        modp_mkgm2(t, gm, igm, logn, PRIMES[u].g, p, p0i);
        let mut x = fs + u;
        for v in 0..n {
            t[t1 + v] = t[x];
            x += slen;
        }
        if !in_ntt {
            modp_ntt2(t, t1, gm, logn, p, p0i);
        }
        let mut x = fd + u;
        for v in 0..hn {
            let w0 = t[t1 + (v << 1)];
            let w1 = t[t1 + (v << 1) + 1];
            t[x] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
            x += tlen;
        }
        if in_ntt {
            modp_intt2_ext(t, fs + u, slen, igm, logn, p, p0i);
        }
        let mut x = gs + u;
        for v in 0..n {
            t[t1 + v] = t[x];
            x += slen;
        }
        if !in_ntt {
            modp_ntt2(t, t1, gm, logn, p, p0i);
        }
        let mut x = gd + u;
        for v in 0..hn {
            let w0 = t[t1 + (v << 1)];
            let w1 = t[t1 + (v << 1) + 1];
            t[x] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
            x += tlen;
        }
        if in_ntt {
            modp_intt2_ext(t, gs + u, slen, igm, logn, p, p0i);
        }
        if !out_ntt {
            modp_intt2_ext(t, fd + u, tlen, igm, logn - 1, p, p0i);
            modp_intt2_ext(t, gd + u, tlen, igm, logn - 1, p, p0i);
        }
    }
    zint_rebuild_crt(t, fs, slen, slen, n, &PRIMES, true, gm);
    zint_rebuild_crt(t, gs, slen, slen, n, &PRIMES, true, gm);
    for u in slen..tlen {
        let p = PRIMES[u].p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(slen as u32, p, p0i, r2);
        modp_mkgm2(t, gm, igm, logn, PRIMES[u].g, p, p0i);
        let mut x = fs;
        for v in 0..n {
            t[t1 + v] = zint_mod_small_signed(t, x, slen, p, p0i, r2, rx);
            x += slen;
        }
        modp_ntt2(t, t1, gm, logn, p, p0i);
        let mut x = fd + u;
        for v in 0..hn {
            let w0 = t[t1 + (v << 1)];
            let w1 = t[t1 + (v << 1) + 1];
            t[x] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
            x += tlen;
        }
        let mut x = gs;
        for v in 0..n {
            t[t1 + v] = zint_mod_small_signed(t, x, slen, p, p0i, r2, rx);
            x += slen;
        }
        modp_ntt2(t, t1, gm, logn, p, p0i);
        let mut x = gd + u;
        for v in 0..hn {
            let w0 = t[t1 + (v << 1)];
            let w1 = t[t1 + (v << 1) + 1];
            t[x] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
            x += tlen;
        }
        if !out_ntt {
            modp_intt2_ext(t, fd + u, tlen, igm, logn - 1, p, p0i);
            modp_intt2_ext(t, gd + u, tlen, igm, logn - 1, p, p0i);
        }
    }
}

/// `make_fg`: compute the field norms of `f`, `g` down to `depth`, at
/// arena offset `data`.
fn make_fg(t: &mut [u32], data: usize, f: &[i8], g: &[i8], logn: u32, depth: u32, out_ntt: bool) {
    let n = mkn(logn);
    let ft = data;
    let gt = ft + n;
    let p0 = PRIMES[0].p;
    for u in 0..n {
        t[ft + u] = modp_set(i32::from(f[u]), p0);
        t[gt + u] = modp_set(i32::from(g[u]), p0);
    }
    if depth == 0 && out_ntt {
        let p = PRIMES[0].p;
        let p0i = modp_ninv31(p);
        let gm = gt + n;
        let igm = gm + mkn(logn);
        modp_mkgm2(t, gm, igm, logn, PRIMES[0].g, p, p0i);
        modp_ntt2(t, ft, gm, logn, p, p0i);
        modp_ntt2(t, gt, gm, logn, p, p0i);
        return;
    }
    for d in 0..depth {
        make_fg_step(t, data, logn - d, d, d != 0, (d + 1) < depth || out_ntt);
    }
}

/// `solve_NTRU_deepest`: solve at depth `logn_top` (degree 1), leaving
/// `(F, G)` as `len`-limb big integers at the arena start.
pub(crate) fn solve_ntru_deepest(t: &mut [u32], logn_top: u32, f: &[i8], g: &[i8]) -> bool {
    let len = MAX_BL_SMALL[logn_top as usize];
    let fp_ = 0usize;
    let gp_ = fp_ + len;
    let fp = gp_ + len;
    let gp = fp + len;
    let t1 = gp + len;
    make_fg(t, fp, f, g, logn_top, logn_top, false);
    zint_rebuild_crt(t, fp, len, len, 2, &PRIMES, false, t1);
    if !zint_bezout(t, gp_, fp_, fp, gp, len, t1) {
        return false;
    }
    let q: u32 = 12289;
    if zint_mul_small(t, fp_, len, q) != 0 || zint_mul_small(t, gp_, len, q) != 0 {
        return false;
    }
    true
}

/// `solve_NTRU_intermediate`: lift the solution from depth `depth + 1` to
/// `depth` with Babai reduction.
pub(crate) fn solve_ntru_intermediate(
    t: &mut [u32],
    logn_top: u32,
    f: &[i8],
    g: &[i8],
    depth: u32,
) -> bool {
    let logn = logn_top - depth;
    let n = 1usize << logn;
    let hn = n >> 1;
    let slen = MAX_BL_SMALL[depth as usize];
    let dlen = MAX_BL_SMALL[depth as usize + 1];
    let llen = MAX_BL_LARGE[depth as usize];

    // The (F, G) from the deeper level are at the start; put (f, g) at
    // this level right after them.
    let fd = 0usize;
    let gd = fd + dlen * hn;
    let ft = gd + dlen * hn;
    make_fg(t, ft, f, g, logn_top, depth, true);

    // Move (f, g) after the space for the new (F, G), then (Fd, Gd) after.
    let big_ft = 0usize;
    let big_gt = big_ft + n * llen;
    let t1 = big_gt + n * llen;
    t.copy_within(ft..ft + 2 * n * slen, t1);
    let ft = t1;
    let gt = ft + slen * n;
    let t1 = gt + slen * n;
    t.copy_within(fd..fd + 2 * hn * dlen, t1);
    let fd = t1;
    let gd = fd + hn * dlen;

    // Residues of (Fd, Gd) modulo the first llen primes, into (Ft, Gt).
    for u in 0..llen {
        let p = PRIMES[u].p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(dlen as u32, p, p0i, r2);
        let (mut xs, mut ys, mut xd, mut yd) = (fd, gd, big_ft + u, big_gt + u);
        for _ in 0..hn {
            t[xd] = zint_mod_small_signed(t, xs, dlen, p, p0i, r2, rx);
            t[yd] = zint_mod_small_signed(t, ys, dlen, p, p0i, r2, rx);
            xs += dlen;
            ys += dlen;
            xd += llen;
            yd += llen;
        }
    }

    // Compute F = Fd * g', G = Gd * f' modulo each prime (NTT domain).
    for u in 0..llen {
        let p = PRIMES[u].p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        if u == slen {
            zint_rebuild_crt(t, ft, slen, slen, n, &PRIMES, true, t1);
            zint_rebuild_crt(t, gt, slen, slen, n, &PRIMES, true, t1);
        }
        let gm = t1;
        let igm = gm + n;
        let fx = igm + n;
        let gx = fx + n;
        modp_mkgm2(t, gm, igm, logn, PRIMES[u].g, p, p0i);
        if u < slen {
            let (mut x, mut y) = (ft + u, gt + u);
            for v in 0..n {
                t[fx + v] = t[x];
                t[gx + v] = t[y];
                x += slen;
                y += slen;
            }
            modp_intt2_ext(t, ft + u, slen, igm, logn, p, p0i);
            modp_intt2_ext(t, gt + u, slen, igm, logn, p, p0i);
        } else {
            let rx = modp_rx(slen as u32, p, p0i, r2);
            let (mut x, mut y) = (ft, gt);
            for v in 0..n {
                t[fx + v] = zint_mod_small_signed(t, x, slen, p, p0i, r2, rx);
                t[gx + v] = zint_mod_small_signed(t, y, slen, p, p0i, r2, rx);
                x += slen;
                y += slen;
            }
            modp_ntt2(t, fx, gm, logn, p, p0i);
            modp_ntt2(t, gx, gm, logn, p, p0i);
        }
        let fp = gx + n;
        let gp = fp + hn;
        let (mut x, mut y) = (big_ft + u, big_gt + u);
        for v in 0..hn {
            t[fp + v] = t[x];
            t[gp + v] = t[y];
            x += llen;
            y += llen;
        }
        modp_ntt2(t, fp, gm, logn - 1, p, p0i);
        modp_ntt2(t, gp, gm, logn - 1, p, p0i);
        let (mut x, mut y) = (big_ft + u, big_gt + u);
        for v in 0..hn {
            let fta = t[fx + (v << 1)];
            let ftb = t[fx + (v << 1) + 1];
            let gta = t[gx + (v << 1)];
            let gtb = t[gx + (v << 1) + 1];
            let mfp = modp_montymul(t[fp + v], r2, p, p0i);
            let mgp = modp_montymul(t[gp + v], r2, p, p0i);
            t[x] = modp_montymul(gtb, mfp, p, p0i);
            t[x + llen] = modp_montymul(gta, mfp, p, p0i);
            t[y] = modp_montymul(ftb, mgp, p, p0i);
            t[y + llen] = modp_montymul(fta, mgp, p, p0i);
            x += llen << 1;
            y += llen << 1;
        }
        modp_intt2_ext(t, big_ft + u, llen, igm, logn, p, p0i);
        modp_intt2_ext(t, big_gt + u, llen, igm, logn, p, p0i);
    }

    // Rebuild F and G from their residues (signed).
    zint_rebuild_crt(t, big_ft, llen, llen, n, &PRIMES, true, t1);
    zint_rebuild_crt(t, big_gt, llen, llen, n, &PRIMES, true, t1);

    // Babai reduction with floating-point approximations.
    let mut rt3 = vec![FPR_ZERO; n];
    let mut rt4 = vec![FPR_ZERO; n];
    let mut rt5 = vec![FPR_ZERO; hn];
    let mut rt1 = vec![FPR_ZERO; n];
    let mut rt2 = vec![FPR_ZERO; n];
    let mut k = vec![0i32; n];
    // The C's scratch for poly_sub_scaled_ntt starts after `k` which sits
    // after the fpr buffers; with those held separately, `t1` is free.
    let scratch = t1;

    let mut rlen = if slen > 10 { 10 } else { slen };
    poly_big_to_fp(&mut rt3, t, ft + slen - rlen, rlen, slen, logn);
    poly_big_to_fp(&mut rt4, t, gt + slen - rlen, rlen, slen, logn);
    let scale_fg: i32 = 31 * (slen - rlen) as i32;
    let minbl_fg: i32 = BITLENGTH[depth as usize].0 - 6 * BITLENGTH[depth as usize].1;
    let maxbl_fg: i32 = BITLENGTH[depth as usize].0 + 6 * BITLENGTH[depth as usize].1;
    fft(&mut rt3, logn);
    fft(&mut rt4, logn);
    poly_invnorm2_fft(&mut rt5, &rt3, &rt4, logn);
    poly_adj_fft(&mut rt3, logn);
    poly_adj_fft(&mut rt4, logn);

    let mut fglen = llen;
    let mut maxbl_big_fg: i32 = 31 * llen as i32;
    let mut scale_k: i32 = maxbl_big_fg - minbl_fg;
    loop {
        rlen = if fglen > 10 { 10 } else { fglen };
        let scale_big_fg: i32 = 31 * (fglen - rlen) as i32;
        poly_big_to_fp(&mut rt1, t, big_ft + fglen - rlen, rlen, llen, logn);
        poly_big_to_fp(&mut rt2, t, big_gt + fglen - rlen, rlen, llen, logn);
        fft(&mut rt1, logn);
        fft(&mut rt2, logn);
        poly_mul_fft(&mut rt1, &rt3, logn);
        poly_mul_fft(&mut rt2, &rt4, logn);
        poly_add(&mut rt2, &rt1, logn);
        poly_mul_autoadj_fft(&mut rt2, &rt5, logn);
        ifft(&mut rt2, logn);

        // Multiply by 2^dc with a square-and-multiply on 2 or 1/2.
        let mut dc: i32 = scale_k - scale_big_fg + scale_fg;
        let mut pt;
        if dc < 0 {
            dc = -dc;
            pt = FPR_TWO;
        } else {
            pt = FPR_ONEHALF;
        }
        let mut pdc = FPR_ONE;
        while dc != 0 {
            if (dc & 1) != 0 {
                pdc = fpr_mul(pdc, pt);
            }
            dc >>= 1;
            pt = fpr_sqr(pt);
        }
        for u in 0..n {
            let xv = fpr_mul(rt2[u], pdc);
            if !fpr_lt(FPR_MTWO31M1, xv) || !fpr_lt(xv, FPR_PTWO31M1) {
                return false;
            }
            k[u] = fpr_rint(xv) as i32;
        }

        let sch: u32 = (scale_k / 31) as u32;
        let scl: u32 = (scale_k % 31) as u32;
        if depth <= DEPTH_INT_FG {
            poly_sub_scaled_ntt(
                t, big_ft, fglen, llen, ft, slen, slen, &k, sch, scl, logn, scratch,
            );
            poly_sub_scaled_ntt(
                t, big_gt, fglen, llen, gt, slen, slen, &k, sch, scl, logn, scratch,
            );
        } else {
            poly_sub_scaled(t, big_ft, fglen, llen, ft, slen, slen, &k, sch, scl, logn);
            poly_sub_scaled(t, big_gt, fglen, llen, gt, slen, slen, &k, sch, scl, logn);
        }

        let new_maxbl_big_fg: i32 = scale_k + maxbl_fg + 10;
        if new_maxbl_big_fg < maxbl_big_fg {
            maxbl_big_fg = new_maxbl_big_fg;
            if (fglen as i32) * 31 >= maxbl_big_fg + 31 {
                fglen -= 1;
            }
        }
        if scale_k <= 0 {
            break;
        }
        scale_k -= 25;
        if scale_k < 0 {
            scale_k = 0;
        }
    }

    // Sign-extend (F, G) to slen limbs if they were shortened.
    if fglen < slen {
        let (mut xf, mut xg) = (big_ft, big_gt);
        for _ in 0..n {
            let sw = (t[xf + fglen - 1] >> 30).wrapping_neg() >> 1;
            for v in fglen..slen {
                t[xf + v] = sw;
            }
            let sw = (t[xg + fglen - 1] >> 30).wrapping_neg() >> 1;
            for v in fglen..slen {
                t[xg + v] = sw;
            }
            xf += llen;
            xg += llen;
        }
    }

    // Compact (F, G) to slen limbs each at the start of the arena.
    let (mut x, mut y) = (0usize, 0usize);
    for _ in 0..(n << 1) {
        t.copy_within(y..y + slen, x);
        x += slen;
        y += llen;
    }
    true
}

/// `solve_NTRU_binary_depth1`: the depth-1 step, specialised (all
/// residues fit in the first few primes, Babai in one round).
pub(crate) fn solve_ntru_binary_depth1(t: &mut [u32], logn_top: u32, f: &[i8], g: &[i8]) -> bool {
    let depth = 1u32;
    let n_top = 1usize << logn_top;
    let logn = logn_top - depth;
    let n = 1usize << logn;
    let hn = n >> 1;
    let slen = MAX_BL_SMALL[depth as usize];
    let dlen = MAX_BL_SMALL[depth as usize + 1];
    let llen = MAX_BL_LARGE[depth as usize];

    let fd = 0usize;
    let gd = fd + dlen * hn;
    let big_ft = gd + dlen * hn;
    let big_gt = big_ft + llen * n;

    for u in 0..llen {
        let p = PRIMES[u].p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(dlen as u32, p, p0i, r2);
        let (mut xs, mut ys, mut xd, mut yd) = (fd, gd, big_ft + u, big_gt + u);
        for _ in 0..hn {
            t[xd] = zint_mod_small_signed(t, xs, dlen, p, p0i, r2, rx);
            t[yd] = zint_mod_small_signed(t, ys, dlen, p, p0i, r2, rx);
            xs += dlen;
            ys += dlen;
            xd += llen;
            yd += llen;
        }
    }

    t.copy_within(big_ft..big_ft + llen * n, 0);
    let big_ft = 0usize;
    t.copy_within(big_gt..big_gt + llen * n, big_ft + llen * n);
    let big_gt = big_ft + llen * n;
    let ft = big_gt + llen * n;
    let gt = ft + slen * n;
    let t1 = gt + slen * n;

    for u in 0..llen {
        let p = PRIMES[u].p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let gm = t1;
        let mut igm = gm + n_top;
        let mut fx = igm + n;
        let mut gx = fx + n_top;
        modp_mkgm2(t, gm, igm, logn_top, PRIMES[u].g, p, p0i);
        for v in 0..n_top {
            t[fx + v] = modp_set(i32::from(f[v]), p);
            t[gx + v] = modp_set(i32::from(g[v]), p);
        }
        modp_ntt2(t, fx, gm, logn_top, p, p0i);
        modp_ntt2(t, gx, gm, logn_top, p, p0i);
        let mut e = logn_top;
        while e > logn {
            modp_poly_rec_res(t, fx, e, p, p0i, r2);
            modp_poly_rec_res(t, gx, e, p, p0i, r2);
            e -= 1;
        }
        // depth > 0: compact the tables.
        t.copy_within(igm..igm + n, gm + n);
        igm = gm + n;
        t.copy_within(fx..fx + n, igm + n);
        fx = igm + n;
        t.copy_within(gx..gx + n, fx + n);
        gx = fx + n;

        let fp = gx + n;
        let gp = fp + hn;
        let (mut x, mut y) = (big_ft + u, big_gt + u);
        for v in 0..hn {
            t[fp + v] = t[x];
            t[gp + v] = t[y];
            x += llen;
            y += llen;
        }
        modp_ntt2(t, fp, gm, logn - 1, p, p0i);
        modp_ntt2(t, gp, gm, logn - 1, p, p0i);
        let (mut x, mut y) = (big_ft + u, big_gt + u);
        for v in 0..hn {
            let fta = t[fx + (v << 1)];
            let ftb = t[fx + (v << 1) + 1];
            let gta = t[gx + (v << 1)];
            let gtb = t[gx + (v << 1) + 1];
            let mfp = modp_montymul(t[fp + v], r2, p, p0i);
            let mgp = modp_montymul(t[gp + v], r2, p, p0i);
            t[x] = modp_montymul(gtb, mfp, p, p0i);
            t[x + llen] = modp_montymul(gta, mfp, p, p0i);
            t[y] = modp_montymul(ftb, mgp, p, p0i);
            t[y + llen] = modp_montymul(fta, mgp, p, p0i);
            x += llen << 1;
            y += llen << 1;
        }
        modp_intt2_ext(t, big_ft + u, llen, igm, logn, p, p0i);
        modp_intt2_ext(t, big_gt + u, llen, igm, logn, p, p0i);
        if u < slen {
            modp_intt2(t, fx, igm, logn, p, p0i);
            modp_intt2(t, gx, igm, logn, p, p0i);
            let (mut x, mut y) = (ft + u, gt + u);
            for v in 0..n {
                t[x] = t[fx + v];
                t[y] = t[gx + v];
                x += slen;
                y += slen;
            }
        }
    }

    zint_rebuild_crt(t, big_ft, llen, llen, n << 1, &PRIMES, true, t1);
    zint_rebuild_crt(t, ft, slen, slen, n << 1, &PRIMES, true, t1);

    // Floating-point reduction.
    let mut rt1 = vec![FPR_ZERO; n];
    let mut rt2 = vec![FPR_ZERO; n];
    poly_big_to_fp(&mut rt1, t, big_ft, llen, llen, logn);
    poly_big_to_fp(&mut rt2, t, big_gt, llen, llen, logn);
    t.copy_within(ft..ft + 2 * slen * n, 0);
    let ft = 0usize;
    let gt = ft + slen * n;
    let mut rt3 = vec![FPR_ZERO; n];
    let mut rt4 = vec![FPR_ZERO; n];
    poly_big_to_fp(&mut rt3, t, ft, slen, slen, logn);
    poly_big_to_fp(&mut rt4, t, gt, slen, slen, logn);
    fft(&mut rt1, logn);
    fft(&mut rt2, logn);
    fft(&mut rt3, logn);
    fft(&mut rt4, logn);
    let mut rt5 = vec![FPR_ZERO; n];
    let mut rt6 = vec![FPR_ZERO; hn];
    poly_add_muladj_fft(&mut rt5, &rt1, &rt2, &rt3, &rt4, logn);
    poly_invnorm2_fft(&mut rt6, &rt3, &rt4, logn);
    poly_mul_autoadj_fft(&mut rt5, &rt6, logn);
    ifft(&mut rt5, logn);
    for u in 0..n {
        let z = rt5[u];
        if !fpr_lt(z, FPR_PTWO63M1) || !fpr_lt(FPR_MTWO63M1, z) {
            return false;
        }
        rt5[u] = fpr_of(fpr_rint(z));
    }
    fft(&mut rt5, logn);
    poly_mul_fft(&mut rt3, &rt5, logn);
    poly_mul_fft(&mut rt4, &rt5, logn);
    poly_sub(&mut rt1, &rt3, logn);
    poly_sub(&mut rt2, &rt4, logn);
    ifft(&mut rt1, logn);
    ifft(&mut rt2, logn);

    // (F, G) as one-limb values at the arena start.
    let big_ft = 0usize;
    let big_gt = big_ft + n;
    for u in 0..n {
        t[big_ft + u] = fpr_rint(rt1[u]) as u32;
        t[big_gt + u] = fpr_rint(rt2[u]) as u32;
    }
    true
}

/// `solve_NTRU_binary_depth0`: the final (depth 0) step, modulo one prime.
pub(crate) fn solve_ntru_binary_depth0(t: &mut [u32], logn: u32, f: &[i8], g: &[i8]) -> bool {
    let n = 1usize << logn;
    let hn = n >> 1;
    let p = PRIMES[0].p;
    let p0i = modp_ninv31(p);
    let r2 = modp_r2(p, p0i);

    let fp = 0usize;
    let gp = fp + hn;
    let ft = gp + hn;
    let gt = ft + n;
    let gm = gt + n;
    let igm = gm + n;
    modp_mkgm2(t, gm, igm, logn, PRIMES[0].g, p, p0i);
    for u in 0..hn {
        t[fp + u] = modp_set(zint_one_to_plain(t, fp + u), p);
        t[gp + u] = modp_set(zint_one_to_plain(t, gp + u), p);
    }
    modp_ntt2(t, fp, gm, logn - 1, p, p0i);
    modp_ntt2(t, gp, gm, logn - 1, p, p0i);
    for u in 0..n {
        t[ft + u] = modp_set(i32::from(f[u]), p);
        t[gt + u] = modp_set(i32::from(g[u]), p);
    }
    modp_ntt2(t, ft, gm, logn, p, p0i);
    modp_ntt2(t, gt, gm, logn, p, p0i);
    let mut u = 0usize;
    while u < n {
        let fta = t[ft + u];
        let ftb = t[ft + u + 1];
        let gta = t[gt + u];
        let gtb = t[gt + u + 1];
        let mfp = modp_montymul(t[fp + (u >> 1)], r2, p, p0i);
        let mgp = modp_montymul(t[gp + (u >> 1)], r2, p, p0i);
        t[ft + u] = modp_montymul(gtb, mfp, p, p0i);
        t[ft + u + 1] = modp_montymul(gta, mfp, p, p0i);
        t[gt + u] = modp_montymul(ftb, mgp, p, p0i);
        t[gt + u + 1] = modp_montymul(fta, mgp, p, p0i);
        u += 2;
    }
    modp_intt2(t, ft, igm, logn, p, p0i);
    modp_intt2(t, gt, igm, logn, p, p0i);

    // (F, G) now in ft/gt; move them to the start and set up scratch.
    let gp = fp + n;
    let t1 = gp + n;
    t.copy_within(ft..ft + 2 * n, fp);
    let t2 = t1 + n;
    let t3 = t2 + n;
    let t4 = t3 + n;
    let t5 = t4 + n;

    // t2 = f*adj(F) + g*adj(G), t3 = f*adj(f) + g*adj(g) (mod p, NTT domain).
    modp_mkgm2(t, t1, t2, logn, PRIMES[0].g, p, p0i);
    modp_ntt2(t, fp, t1, logn, p, p0i);
    modp_ntt2(t, gp, t1, logn, p, p0i);
    t[t4] = modp_set(i32::from(f[0]), p);
    t[t5] = t[t4];
    for u in 1..n {
        t[t4 + u] = modp_set(i32::from(f[u]), p);
        t[t5 + n - u] = modp_set(-i32::from(f[u]), p);
    }
    modp_ntt2(t, t4, t1, logn, p, p0i);
    modp_ntt2(t, t5, t1, logn, p, p0i);
    for u in 0..n {
        let w = modp_montymul(t[t5 + u], r2, p, p0i);
        t[t2 + u] = modp_montymul(w, t[fp + u], p, p0i);
        t[t3 + u] = modp_montymul(w, t[t4 + u], p, p0i);
    }
    t[t4] = modp_set(i32::from(g[0]), p);
    t[t5] = t[t4];
    for u in 1..n {
        t[t4 + u] = modp_set(i32::from(g[u]), p);
        t[t5 + n - u] = modp_set(-i32::from(g[u]), p);
    }
    modp_ntt2(t, t4, t1, logn, p, p0i);
    modp_ntt2(t, t5, t1, logn, p, p0i);
    for u in 0..n {
        let w = modp_montymul(t[t5 + u], r2, p, p0i);
        t[t2 + u] = modp_add(t[t2 + u], modp_montymul(w, t[gp + u], p, p0i), p);
        t[t3 + u] = modp_add(t[t3 + u], modp_montymul(w, t[t4 + u], p, p0i), p);
    }

    // Convert back, normalize to signed, and compute k = round(t2 / t3) in FP.
    modp_mkgm2(t, t1, t4, logn, PRIMES[0].g, p, p0i);
    modp_intt2(t, t2, t4, logn, p, p0i);
    modp_intt2(t, t3, t4, logn, p, p0i);
    for u in 0..n {
        t[t1 + u] = modp_norm(t[t2 + u], p) as u32;
        t[t2 + u] = modp_norm(t[t3 + u], p) as u32;
    }
    let mut rt3 = vec![FPR_ZERO; n];
    for u in 0..n {
        rt3[u] = fpr_of(i64::from(t[t2 + u] as i32));
    }
    fft(&mut rt3, logn);
    // The C keeps only the first hn entries (rt3 is auto-adjoint); rt2 = rt3[..hn].
    let rt2: Vec<Fpr> = rt3[..hn].to_vec();
    let mut rt3 = vec![FPR_ZERO; n];
    for u in 0..n {
        rt3[u] = fpr_of(i64::from(t[t1 + u] as i32));
    }
    fft(&mut rt3, logn);
    poly_div_autoadj_fft(&mut rt3, &rt2, logn);
    ifft(&mut rt3, logn);
    for u in 0..n {
        t[t1 + u] = modp_set(fpr_rint(rt3[u]) as i32, p);
    }

    // (F, G) -= k * (f, g) mod p, then normalize.
    let t2 = t1 + n;
    let t3 = t2 + n;
    let t4 = t3 + n;
    let t5 = t4 + n;
    modp_mkgm2(t, t2, t3, logn, PRIMES[0].g, p, p0i);
    for u in 0..n {
        t[t4 + u] = modp_set(i32::from(f[u]), p);
        t[t5 + u] = modp_set(i32::from(g[u]), p);
    }
    modp_ntt2(t, t1, t2, logn, p, p0i);
    modp_ntt2(t, t4, t2, logn, p, p0i);
    modp_ntt2(t, t5, t2, logn, p, p0i);
    for u in 0..n {
        let kw = modp_montymul(t[t1 + u], r2, p, p0i);
        t[fp + u] = modp_sub(t[fp + u], modp_montymul(kw, t[t4 + u], p, p0i), p);
        t[gp + u] = modp_sub(t[gp + u], modp_montymul(kw, t[t5 + u], p, p0i), p);
    }
    modp_intt2(t, fp, t3, logn, p, p0i);
    modp_intt2(t, gp, t3, logn, p, p0i);
    for u in 0..n {
        t[fp + u] = modp_norm(t[fp + u], p) as u32;
        t[gp + u] = modp_norm(t[gp + u], p) as u32;
    }
    true
}

/// `solve_NTRU`: find `(F, G)` with `fG - gF = q`, coefficients within
/// `[-lim, lim]`.
pub(crate) fn solve_ntru(
    t: &mut [u32],
    logn: u32,
    big_f: &mut [i8],
    big_g: &mut [i8],
    f: &[i8],
    g: &[i8],
    lim: i32,
) -> bool {
    let n = mkn(logn);
    if !solve_ntru_deepest(t, logn, f, g) {
        return false;
    }
    if logn <= 2 {
        let mut depth = logn;
        while depth > 0 {
            depth -= 1;
            if !solve_ntru_intermediate(t, logn, f, g, depth) {
                return false;
            }
        }
    } else {
        let mut depth = logn;
        while depth > 2 {
            depth -= 1;
            if !solve_ntru_intermediate(t, logn, f, g, depth) {
                return false;
            }
        }
        if !solve_ntru_binary_depth1(t, logn, f, g) {
            return false;
        }
        if !solve_ntru_binary_depth0(t, logn, f, g) {
            return false;
        }
    }
    if !poly_big_to_small(big_f, t, 0, lim, logn) || !poly_big_to_small(big_g, t, n, lim, logn) {
        return false;
    }

    // Verify fG - gF = q modulo the first prime.
    let gt_big = 0usize;
    let ft = gt_big + n;
    let gt = ft + n;
    let ft_big = gt + n;
    let gm = ft_big + n;
    let p = PRIMES[0].p;
    let p0i = modp_ninv31(p);
    modp_mkgm2(t, gm, 0, logn, PRIMES[0].g, p, p0i);
    for u in 0..n {
        t[gt_big + u] = modp_set(i32::from(big_g[u]), p);
    }
    for u in 0..n {
        t[ft + u] = modp_set(i32::from(f[u]), p);
        t[gt + u] = modp_set(i32::from(g[u]), p);
        t[ft_big + u] = modp_set(i32::from(big_f[u]), p);
    }
    modp_ntt2(t, ft, gm, logn, p, p0i);
    modp_ntt2(t, gt, gm, logn, p, p0i);
    modp_ntt2(t, ft_big, gm, logn, p, p0i);
    modp_ntt2(t, gt_big, gm, logn, p, p0i);
    let r = modp_montymul(12289, 1, p, p0i);
    for u in 0..n {
        let z = modp_sub(
            modp_montymul(t[ft + u], t[gt_big + u], p, p0i),
            modp_montymul(t[gt + u], t[ft_big + u], p, p0i),
            p,
        );
        if z != r {
            return false;
        }
    }
    true
}

/// `poly_small_mkgauss`: sample `f` with odd parity, every coefficient in
/// `[-127, 127]`.
pub(crate) fn poly_small_mkgauss(rng: &mut Shake256, f: &mut [i8], logn: u32) {
    let n = mkn(logn);
    let mut mod2: u32 = 0;
    for u in 0..n {
        loop {
            let s = mkgauss(rng, logn);
            if !(-127..=127).contains(&s) {
                continue;
            }
            if u == n - 1 {
                if (mod2 ^ ((s & 1) as u32)) == 0 {
                    continue;
                }
            } else {
                mod2 ^= (s & 1) as u32;
            }
            f[u] = s as i8;
            break;
        }
    }
}

/// `keygen`: generate a private key `(f, g, F, G)` and, optionally, the
/// public key `h`, drawing randomness directly from the SHAKE256 context
/// `rng`. `big_g` and `h` are optional like the C's `NULL` arguments.
pub(crate) fn keygen(
    rng: &mut Shake256,
    f: &mut [i8],
    g: &mut [i8],
    big_f: &mut [i8],
    big_g: Option<&mut [i8]>,
    h: Option<&mut [u16]>,
    logn: u32,
) {
    let n = mkn(logn);
    // Generous arena: the C needs 28*n bytes = 7*n limbs for everything
    // including the floating-point buffers this port keeps separately.
    let mut t = vec![0u32; 8 * n + 1024];
    let mut g_local = vec![0i8; n];
    let mut h_local = vec![0u16; n];
    let big_g: &mut [i8] = match big_g {
        Some(x) => x,
        None => &mut g_local,
    };
    let h: &mut [u16] = match h {
        Some(x) => x,
        None => &mut h_local,
    };
    loop {
        poly_small_mkgauss(rng, f, logn);
        poly_small_mkgauss(rng, g, logn);
        let mut lim: i32 = 1 << (super::codec::MAX_FG_BITS[logn as usize] - 1);
        for u in 0..n {
            let fu = i32::from(f[u]);
            let gu = i32::from(g[u]);
            if fu >= lim || fu <= -lim || gu >= lim || gu <= -lim {
                lim = -1;
                break;
            }
        }
        if lim < 0 {
            continue;
        }
        let normf = poly_small_sqnorm(f, logn);
        let normg = poly_small_sqnorm(g, logn);
        let norm = (normf.wrapping_add(normg)) | ((normf | normg) >> 31).wrapping_neg();
        if norm >= 16823 {
            continue;
        }
        // Orthogonalized vector norm check.
        let mut rt1 = vec![FPR_ZERO; n];
        let mut rt2 = vec![FPR_ZERO; n];
        let mut rt3 = vec![FPR_ZERO; n >> 1];
        poly_small_to_fp(&mut rt1, f, logn);
        poly_small_to_fp(&mut rt2, g, logn);
        fft(&mut rt1, logn);
        fft(&mut rt2, logn);
        poly_invnorm2_fft(&mut rt3, &rt1, &rt2, logn);
        poly_adj_fft(&mut rt1, logn);
        poly_adj_fft(&mut rt2, logn);
        poly_mulconst(&mut rt1, FPR_Q, logn);
        poly_mulconst(&mut rt2, FPR_Q, logn);
        poly_mul_autoadj_fft(&mut rt1, &rt3, logn);
        poly_mul_autoadj_fft(&mut rt2, &rt3, logn);
        ifft(&mut rt1, logn);
        ifft(&mut rt2, logn);
        let mut bnorm = FPR_ZERO;
        for u in 0..n {
            bnorm = fpr_add(bnorm, fpr_sqr(rt1[u]));
            bnorm = fpr_add(bnorm, fpr_sqr(rt2[u]));
        }
        if !fpr_lt(bnorm, FPR_BNORM_MAX) {
            continue;
        }
        if !compute_public(h, f, g, logn) {
            continue;
        }
        let lim: i32 = (1 << (super::codec::MAX_FG_BITS_BIG[logn as usize] - 1)) - 1;
        if !solve_ntru(&mut t, logn, big_f, big_g, f, g, lim) {
            continue;
        }
        break;
    }
}

/// Differential tests against the vendored C (`falcon_inner_keygen`).
#[cfg(all(test, feature = "c-backend"))]
mod c_diff {
    use super::*;
    use crate::c_internals::{self as c, CInnerShake256};

    /// (f, g, F, G, h, 16 bytes of remaining SHAKE stream).
    type KeygenOut = (Vec<i8>, Vec<i8>, Vec<i8>, Vec<i8>, Vec<u16>, Vec<u8>);

    fn run_c(seed: &[u8], logn: u32) -> KeygenOut {
        let n = 1usize << logn;
        let mut src = CInnerShake256::new();
        src.inject(seed);
        src.flip();
        let mut f = vec![0i8; n];
        let mut g = vec![0i8; n];
        let mut big_f = vec![0i8; n];
        let mut big_g = vec![0i8; n];
        let mut h = vec![0u16; n];
        let mut tmp = vec![0u8; 28 * 1024 + 7 + 64];
        unsafe {
            c::falcon_inner_keygen(
                &mut src,
                f.as_mut_ptr(),
                g.as_mut_ptr(),
                big_f.as_mut_ptr(),
                big_g.as_mut_ptr(),
                h.as_mut_ptr(),
                logn,
                tmp.as_mut_ptr(),
            )
        };
        (f, g, big_f, big_g, h, src.extract_vec(16))
    }

    fn run_rs(seed: &[u8], logn: u32) -> KeygenOut {
        let n = 1usize << logn;
        let mut src = Shake256::prng_from_seed(seed);
        let mut f = vec![0i8; n];
        let mut g = vec![0i8; n];
        let mut big_f = vec![0i8; n];
        let mut big_g = vec![0i8; n];
        let mut h = vec![0u16; n];
        keygen(
            &mut src,
            &mut f,
            &mut g,
            &mut big_f,
            Some(&mut big_g),
            Some(&mut h),
            logn,
        );
        (f, g, big_f, big_g, h, src.extract_vec(16))
    }

    #[cfg(feature = "c-internals-test")]
    #[test]
    fn keygen_steps_match_c() {
        use crate::c_internals::shim as sh;
        let seed = [0x33u8; 32];
        // 1. mkgauss / poly_small_mkgauss streams, straight from SHAKE256.
        let mut rp = Shake256::prng_from_seed(&seed);
        let mut cp = CInnerShake256::new();
        cp.inject(&seed);
        cp.flip();
        for logn in [10u32, 9, 5, 1] {
            for i in 0..300 {
                assert_eq!(
                    mkgauss(&mut rp, logn),
                    unsafe { sh::falcon_shim_x_mkgauss(&mut cp, logn) },
                    "mkgauss logn={logn} #{i}"
                );
            }
        }
        for logn in 1..=10u32 {
            let n = 1usize << logn;
            let mut fr = vec![0i8; n];
            let mut fc = vec![0i8; n];
            poly_small_mkgauss(&mut rp, &mut fr, logn);
            unsafe { sh::falcon_shim_x_poly_small_mkgauss(&mut cp, fc.as_mut_ptr(), logn) };
            assert_eq!(fr, fc, "poly_small_mkgauss logn={logn}");
            assert_eq!(poly_small_sqnorm(&fr, logn), unsafe {
                sh::falcon_shim_x_poly_small_sqnorm(fr.as_ptr(), logn)
            });
        }
        // 2. The NTRU solver, step by step, on the C's own (valid) f, g.
        for logn in [1u32, 2, 3, 4, 6, 10] {
            let n = 1usize << logn;
            let (f, g, _, _, _, _) = run_c(&[0x44u8; 32], logn);
            let mut tr = vec![0u32; 8 * 1024 + 1024];
            let mut tc = vec![0u32; 8 * 1024 + 1024];
            let rr = solve_ntru_deepest(&mut tr, logn, &f, &g);
            let rc = unsafe {
                sh::falcon_shim_x_solve_NTRU_deepest(logn, f.as_ptr(), g.as_ptr(), tc.as_mut_ptr())
            };
            assert_eq!(rr, rc != 0, "deepest result logn={logn}");
            let len = MAX_BL_SMALL[logn as usize];
            assert_eq!(&tr[..2 * len], &tc[..2 * len], "deepest (F, G) logn={logn}");
            if logn <= 2 {
                let mut depth = logn;
                while depth > 0 {
                    depth -= 1;
                    let rr = solve_ntru_intermediate(&mut tr, logn, &f, &g, depth);
                    let rc = unsafe {
                        sh::falcon_shim_x_solve_NTRU_intermediate(
                            logn,
                            f.as_ptr(),
                            g.as_ptr(),
                            depth,
                            tc.as_mut_ptr(),
                        )
                    };
                    assert_eq!(rr, rc != 0, "intermediate result logn={logn} depth={depth}");
                    let slen = MAX_BL_SMALL[depth as usize];
                    let hn2 = 2 * (1usize << (logn - depth));
                    assert_eq!(
                        &tr[..hn2 * slen],
                        &tc[..hn2 * slen],
                        "intermediate (F, G) logn={logn} depth={depth}"
                    );
                }
            } else {
                let mut depth = logn;
                while depth > 2 {
                    depth -= 1;
                    let rr = solve_ntru_intermediate(&mut tr, logn, &f, &g, depth);
                    let rc = unsafe {
                        sh::falcon_shim_x_solve_NTRU_intermediate(
                            logn,
                            f.as_ptr(),
                            g.as_ptr(),
                            depth,
                            tc.as_mut_ptr(),
                        )
                    };
                    assert_eq!(rr, rc != 0, "intermediate result logn={logn} depth={depth}");
                    let slen = MAX_BL_SMALL[depth as usize];
                    let cnt = 2 * (1usize << (logn - depth));
                    assert_eq!(
                        &tr[..cnt * slen],
                        &tc[..cnt * slen],
                        "intermediate (F, G) logn={logn} depth={depth}"
                    );
                }
                let rr = solve_ntru_binary_depth1(&mut tr, logn, &f, &g);
                let rc = unsafe {
                    sh::falcon_shim_x_solve_NTRU_binary_depth1(
                        logn,
                        f.as_ptr(),
                        g.as_ptr(),
                        tc.as_mut_ptr(),
                    )
                };
                assert_eq!(rr, rc != 0, "depth1 result logn={logn}");
                assert_eq!(&tr[..n], &tc[..n], "depth1 (F, G) logn={logn}");
                let rr = solve_ntru_binary_depth0(&mut tr, logn, &f, &g);
                let rc = unsafe {
                    sh::falcon_shim_x_solve_NTRU_binary_depth0(
                        logn,
                        f.as_ptr(),
                        g.as_ptr(),
                        tc.as_mut_ptr(),
                    )
                };
                assert_eq!(rr, rc != 0, "depth0 result logn={logn}");
                assert_eq!(&tr[..2 * n], &tc[..2 * n], "depth0 (F, G) logn={logn}");
            }
            let lim: i32 = (1 << (super::super::codec::MAX_FG_BITS_BIG[logn as usize] - 1)) - 1;
            let mut big_fr = vec![0i8; n];
            let mut big_gr = vec![0i8; n];
            let mut big_fc = vec![0i8; n];
            let mut big_gc = vec![0i8; n];
            let rr = solve_ntru(&mut tr, logn, &mut big_fr, &mut big_gr, &f, &g, lim);
            let rc = unsafe {
                sh::falcon_shim_x_solve_NTRU(
                    logn,
                    big_fc.as_mut_ptr(),
                    big_gc.as_mut_ptr(),
                    f.as_ptr(),
                    g.as_ptr(),
                    lim,
                    tc.as_mut_ptr(),
                )
            };
            assert_eq!(rr, rc != 0, "solve_NTRU result logn={logn}");
            assert_eq!(
                (big_fr, big_gr),
                (big_fc, big_gc),
                "solve_NTRU (F, G) logn={logn}"
            );
        }
    }

    #[test]
    fn keygen_matches_c_for_small_degrees() {
        // Every logn from 1 to 9: exercises deepest/intermediate at all
        // depths plus the two binary levels, cheaply.
        for logn in 1..=9u32 {
            for seed_byte in [0u8, 7, 0xa5] {
                let seed = [seed_byte; 32];
                assert_eq!(
                    run_rs(&seed, logn),
                    run_c(&seed, logn),
                    "logn={logn} seed={seed_byte:#x}"
                );
            }
        }
    }

    #[test]
    fn keygen_matches_c_for_falcon_1024() {
        for seed_byte in [0u8, 1, 0x5a, 0xff] {
            let seed = [seed_byte; 32];
            assert_eq!(run_rs(&seed, 10), run_c(&seed, 10), "seed={seed_byte:#x}");
        }
    }
}
