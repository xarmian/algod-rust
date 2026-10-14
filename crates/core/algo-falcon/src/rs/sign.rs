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

//! Signature generation (`sign.c`): the fast-Fourier lattice sampler over
//! a dynamically built LDL tree, the discrete Gaussian samplers, and
//! `sign_dyn`.
//!
//! Ported from the Falcon reference implementation, `falcon-c/sign.c`
//! (Copyright (c) 2017-2019 Falcon Project, MIT License, author Thomas
//! Pornin), vendored verbatim under `crates/core/algo-falcon/falcon-c/` as
//! part of github.com/algorand/falcon v0.1.0; the MIT notice is preserved in
//! `falcon-c/LICENSE`.
//!
//! Only the dynamic-tree path (`sign_dyn`, what `falcon_sign_dyn_finish`
//! and therefore `det1024` use) is ported. The expanded-key path
//! (`expand_privkey`, `ffSampling_fft`, `sign_tree`) is not reachable from
//! the deterministic API and is left out.
//!
//! The C threads one `fpr` scratch arena through `do_sign_dyn` and the
//! recursive sampler with pointer arithmetic; this port gives each named
//! buffer its own allocation and replicates the C's copies (`memcpy` /
//! `memmove`) as `clone_from_slice`, so every value read is the value the C
//! reads. The floating-point operation order is the C's, which is what
//! makes the sampled vectors — and so the signature bytes — identical.

use super::common::is_short_half;
use super::fft::*;
use super::fpr::*;
use super::rng::Prng;
use super::shake256::Shake256;

/// `sampler_context`: the PRNG plus `sigma_min[logn]`.
pub(crate) struct SamplerContext {
    pub(crate) p: Prng,
    pub(crate) sigma_min: Fpr,
}

/// `gaussian0_sampler`: sample from the half-Gaussian with sigma_0 = 1.8205,
/// by comparing 72 random bits against the cumulative table, in constant
/// time.
pub(crate) fn gaussian0_sampler(p: &mut Prng) -> i32 {
    const DIST: [u32; 54] = [
        10745844, 3068844, 3741698, 5559083, 1580863, 8248194, 2260429, 13669192, 2736639, 708981,
        4421575, 10046180, 169348, 7122675, 4136815, 30538, 13063405, 7650655, 4132, 14505003,
        7826148, 417, 16768101, 11363290, 31, 8444042, 8086568, 1, 12844466, 265321, 0, 1232676,
        13644283, 0, 38047, 9111839, 0, 870, 6138264, 0, 14, 12545723, 0, 0, 3104126, 0, 0, 28824,
        0, 0, 198, 0, 0, 1,
    ];
    let lo = p.get_u64();
    let hi = p.get_u8();
    let v0 = (lo as u32) & 0xFF_FFFF;
    let v1 = ((lo >> 24) as u32) & 0xFF_FFFF;
    let v2 = ((lo >> 48) as u32) | (hi << 16);
    let mut z: i32 = 0;
    for w in DIST.as_chunks::<3>().0 {
        let w0 = w[2];
        let w1 = w[1];
        let w2 = w[0];
        let mut cc = v0.wrapping_sub(w0) >> 31;
        cc = v1.wrapping_sub(w1).wrapping_sub(cc) >> 31;
        cc = v2.wrapping_sub(w2).wrapping_sub(cc) >> 31;
        z += cc as i32;
    }
    z
}

/// `BerExp`: return 1 with probability `ccs * exp(-x)`.
fn ber_exp(p: &mut Prng, x: Fpr, ccs: Fpr) -> i32 {
    let mut s: i32 = fpr_trunc(fpr_mul(x, FPR_INV_LOG2)) as i32;
    let r = fpr_sub(x, fpr_mul(fpr_of(i64::from(s)), FPR_LOG2));
    let mut sw = s as u32;
    sw ^= (sw ^ 63) & (63u32.wrapping_sub(sw) >> 31).wrapping_neg();
    s = sw as i32;
    let z: u64 = ((fpr_expm_p63(r, ccs) << 1).wrapping_sub(1)) >> s;
    let mut i: i32 = 64;
    let mut w: u32;
    loop {
        i -= 8;
        w = p.get_u8().wrapping_sub(((z >> i) as u32) & 0xFF);
        if w != 0 || i <= 0 {
            break;
        }
    }
    (w >> 31) as i32
}

/// `sampler`: sample an integer from the discrete Gaussian of centre `mu`
/// and inverse standard deviation `isigma`.
pub(crate) fn sampler(spc: &mut SamplerContext, mu: Fpr, isigma: Fpr) -> i32 {
    let s: i32 = fpr_floor(mu) as i32;
    let r = fpr_sub(mu, fpr_of(i64::from(s)));
    let dss = fpr_half(fpr_sqr(isigma));
    let ccs = fpr_mul(isigma, spc.sigma_min);
    loop {
        let z0 = gaussian0_sampler(&mut spc.p);
        let b = (spc.p.get_u8() & 1) as i32;
        let z = b + ((b << 1) - 1) * z0;
        let mut x = fpr_mul(fpr_sqr(fpr_sub(fpr_of(i64::from(z)), r)), dss);
        x = fpr_sub(x, fpr_mul(fpr_of(i64::from(z0 * z0)), FPR_INV_2SQRSIGMA0));
        if ber_exp(&mut spc.p, x, ccs) != 0 {
            return s + z;
        }
    }
}

/// `smallints_to_fpr`.
fn smallints_to_fpr(r: &mut [Fpr], t: &[i8], logn: u32) {
    let n = 1usize << logn;
    for (x, &v) in r[..n].iter_mut().zip(&t[..n]) {
        *x = fpr_of(i64::from(v));
    }
}

/// `ffSampling_fft_dyntree`: sample `(t0, t1)` in place, building the LDL
/// tree on the fly from the Gram matrix `(g00, g01, g11)` (all FFT form,
/// consumed/destroyed). `tmp` needs at least `5 * 2^logn` entries.
#[allow(clippy::too_many_arguments)]
fn ff_sampling_fft_dyntree(
    spc: &mut SamplerContext,
    t0: &mut [Fpr],
    t1: &mut [Fpr],
    g00: &mut [Fpr],
    g01: &mut [Fpr],
    g11: &mut [Fpr],
    orig_logn: u32,
    logn: u32,
    tmp: &mut [Fpr],
) {
    if logn == 0 {
        let mut leaf = g00[0];
        leaf = fpr_mul(fpr_sqrt(leaf), FPR_INV_SIGMA[orig_logn as usize]);
        t0[0] = fpr_of(i64::from(sampler(spc, t0[0], leaf)));
        t1[0] = fpr_of(i64::from(sampler(spc, t1[0], leaf)));
        return;
    }
    let n = 1usize << logn;
    let hn = n >> 1;

    // Decompose G into LDL; the decomposed matrix replaces G.
    poly_ldl_fft(g00, g01, g11, logn);

    // Split d00 and d11 (both auto-adjoint) and the result overwrites the
    // original values.
    {
        let (tmp_a, tmp_b) = tmp.split_at_mut(hn);
        poly_split_fft(tmp_a, &mut tmp_b[..hn], g00, logn);
    }
    g00[..n].copy_from_slice(&tmp[..n]);
    {
        let (tmp_a, tmp_b) = tmp.split_at_mut(hn);
        poly_split_fft(tmp_a, &mut tmp_b[..hn], g11, logn);
    }
    g11[..n].copy_from_slice(&tmp[..n]);

    // Keep l10 in tmp[0..n]; g01 becomes [d00 first half, d11 first half].
    tmp[..n].copy_from_slice(&g01[..n]);
    g01[..hn].copy_from_slice(&g00[..hn]);
    g01[hn..n].copy_from_slice(&g11[..hn]);

    let (l10, rest) = tmp.split_at_mut(n);
    let (z1, rest2) = rest.split_at_mut(n);

    // Split t1 and use the sub-tree on (g11, g01+hn) for it.
    {
        let (z1a, z1b) = z1.split_at_mut(hn);
        poly_split_fft(z1a, z1b, t1, logn);
        let (g11a, g11b) = g11.split_at_mut(hn);
        let (_g01a, g01b) = g01.split_at_mut(hn);
        ff_sampling_fft_dyntree(spc, z1a, z1b, g11a, g11b, g01b, orig_logn, logn - 1, rest2);
    }
    {
        let (z1a, z1b) = z1.split_at_mut(hn);
        poly_merge_fft(&mut rest2[..n], z1a, z1b, logn);
    }

    // Compute tb0 = t0 + (t1 - z1) * l10, in z1 (freed), then in t0.
    z1[..n].copy_from_slice(&t1[..n]);
    poly_sub(z1, &rest2[..n], logn);
    t1[..n].copy_from_slice(&rest2[..n]);
    poly_mul_fft(l10, z1, logn);
    poly_add(t0, l10, logn);

    // Second recursive invocation on (g00, g01[..hn]), using l10's slot as z0.
    let z0 = l10;
    {
        let (z0a, z0b) = z0.split_at_mut(hn);
        poly_split_fft(z0a, z0b, t0, logn);
        let (g00a, g00b) = g00.split_at_mut(hn);
        let (g01a, _g01b) = g01.split_at_mut(hn);
        ff_sampling_fft_dyntree(spc, z0a, z0b, g00a, g00b, g01a, orig_logn, logn - 1, rest);
    }
    let (z0a, z0b) = z0.split_at_mut(hn);
    poly_merge_fft(t0, z0a, z0b, logn);
}

/// `do_sign_dyn`: one signing attempt. Returns `true` and fills `s2` when
/// the sampled vector is short enough.
#[allow(clippy::too_many_arguments)]
fn do_sign_dyn(
    spc: &mut SamplerContext,
    s2: &mut [i16],
    f: &[i8],
    g: &[i8],
    big_f: &[i8],
    big_g: &[i8],
    hm: &[u16],
    logn: u32,
) -> bool {
    let n = 1usize << logn;
    let mut b00 = vec![FPR_ZERO; n];
    let mut b01 = vec![FPR_ZERO; n];
    let mut b10 = vec![FPR_ZERO; n];
    let mut b11 = vec![FPR_ZERO; n];

    // Lattice basis B = [[g, -f], [G, -F]], in FFT form.
    smallints_to_fpr(&mut b01, f, logn);
    smallints_to_fpr(&mut b00, g, logn);
    smallints_to_fpr(&mut b11, big_f, logn);
    smallints_to_fpr(&mut b10, big_g, logn);
    fft(&mut b01, logn);
    fft(&mut b00, logn);
    fft(&mut b11, logn);
    fft(&mut b10, logn);
    poly_neg(&mut b01, logn);
    poly_neg(&mut b11, logn);

    // Gram matrix G = B*adj(B): g00 in b00, g01 in b01, g11 in b10; the
    // original b01 (= -f in FFT) is kept in t0 for the target computation.
    let mut t0 = b01.clone();
    poly_mulselfadj_fft(&mut t0, logn); // t0 <- b01*adj(b01)
    let mut t1 = b00.clone();
    poly_muladj_fft(&mut t1, &b10, logn); // t1 <- b00*adj(b10)
    poly_mulselfadj_fft(&mut b00, logn); // b00 <- b00*adj(b00)
    poly_add(&mut b00, &t0, logn); // b00 <- g00
    t0.copy_from_slice(&b01);
    poly_muladj_fft(&mut b01, &b11, logn); // b01 <- b01*adj(b11)
    poly_add(&mut b01, &t1, logn); // b01 <- g01
    poly_mulselfadj_fft(&mut b10, logn); // b10 <- b10*adj(b10)
    t1.copy_from_slice(&b11);
    poly_mulselfadj_fft(&mut t1, logn); // t1 <- b11*adj(b11)
    poly_add(&mut b10, &t1, logn); // b10 <- g11

    let mut g00 = b00;
    let mut g01 = b01;
    let mut g11 = b10;
    let b01_neg_f = t0; // -f in FFT form

    // Target vector: (hm*F/q, -hm*f/q) i.e. t0 = hm*b11*ni, t1 = hm*(-b01)*ni.
    let mut t0 = vec![FPR_ZERO; n];
    let mut t1 = vec![FPR_ZERO; n];
    for u in 0..n {
        t0[u] = fpr_of(i64::from(hm[u]));
        t1[u] = FPR_ZERO;
    }
    fft(&mut t0, logn);
    let ni = FPR_INVERSE_OF_Q;
    t1.copy_from_slice(&t0);
    poly_mul_fft(&mut t1, &b01_neg_f, logn);
    poly_mulconst(&mut t1, fpr_neg(ni), logn);
    poly_mul_fft(&mut t0, &b11, logn);
    poly_mulconst(&mut t0, ni, logn);

    // Apply the sampling.
    let mut scratch = vec![FPR_ZERO; 5 * n + 8];
    ff_sampling_fft_dyntree(
        spc,
        &mut t0,
        &mut t1,
        &mut g00,
        &mut g01,
        &mut g11,
        logn,
        logn,
        &mut scratch,
    );

    // Rebuild the basis (the C recomputes it over the Gram matrix's storage).
    let mut b00 = vec![FPR_ZERO; n];
    let mut b01 = vec![FPR_ZERO; n];
    let mut b10 = vec![FPR_ZERO; n];
    let mut b11 = vec![FPR_ZERO; n];
    smallints_to_fpr(&mut b01, f, logn);
    smallints_to_fpr(&mut b00, g, logn);
    smallints_to_fpr(&mut b11, big_f, logn);
    smallints_to_fpr(&mut b10, big_g, logn);
    fft(&mut b01, logn);
    fft(&mut b00, logn);
    fft(&mut b11, logn);
    fft(&mut b10, logn);
    poly_neg(&mut b01, logn);
    poly_neg(&mut b11, logn);

    // (t0, t1) * B: tx = t0*b00 + t1*b10, ty = t0*b01 + t1*b11.
    let mut tx = t0.clone();
    let mut ty = t1.clone();
    poly_mul_fft(&mut tx, &b00, logn);
    poly_mul_fft(&mut ty, &b10, logn);
    poly_add(&mut tx, &ty, logn);
    ty.copy_from_slice(&t0);
    poly_mul_fft(&mut ty, &b01, logn);
    t0.copy_from_slice(&tx);
    poly_mul_fft(&mut t1, &b11, logn);
    poly_add(&mut t1, &ty, logn);
    ifft(&mut t0, logn);
    ifft(&mut t1, logn);

    // s1 = hm - round(t0), s2 = -round(t1); accept if (s1, s2) is short.
    let mut sqn: u32 = 0;
    let mut ng: u32 = 0;
    let mut s1tmp = vec![0i16; n];
    for u in 0..n {
        let z: i32 = i32::from(hm[u]) - (fpr_rint(t0[u]) as i32);
        sqn = sqn.wrapping_add((z * z) as u32);
        ng |= sqn;
        s1tmp[u] = z as i16;
    }
    sqn |= (ng >> 31).wrapping_neg();
    let mut s2tmp = vec![0i16; n];
    for u in 0..n {
        s2tmp[u] = (-fpr_rint(t1[u])) as i16;
    }
    if is_short_half(sqn, &s2tmp, logn) {
        s2[..n].copy_from_slice(&s2tmp);
        return true;
    }
    false
}

/// `sign_dyn`: sign the hashed message `hm` with the private key
/// `(f, g, F, G)`, drawing sampler randomness from `rng` (a flipped
/// SHAKE256 context). Retries until a short enough signature is found,
/// re-seeding the ChaCha20 PRNG from `rng` on each attempt, exactly as the
/// C.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_dyn(
    sig: &mut [i16],
    rng: &mut Shake256,
    f: &[i8],
    g: &[i8],
    big_f: &[i8],
    big_g: &[i8],
    hm: &[u16],
    logn: u32,
) {
    loop {
        let mut spc = SamplerContext {
            p: Prng::init(rng),
            sigma_min: FPR_SIGMA_MIN[logn as usize],
        };
        if do_sign_dyn(&mut spc, sig, f, g, big_f, big_g, hm, logn) {
            break;
        }
    }
}

/// Differential tests against the vendored C (`falcon_inner_sampler`,
/// `falcon_inner_gaussian0_sampler`, `falcon_inner_sign_dyn`). Real keys
/// come from the C backend's keygen, decoded with the codec port.
#[cfg(all(test, feature = "c-backend"))]
mod c_diff {
    use super::*;
    use crate::c_internals::{self as c, CInnerShake256, CPrng, CSamplerContext};
    use crate::rs::codec::{trim_i8_decode, MAX_FG_BITS, MAX_FG_BITS_BIG};
    use crate::rs::common::hash_to_point_ct;
    use crate::rs::vrfy::complete_private;
    use crate::{falcon_keygen_with, FalconBackend, FALCON_DET1024_PRIVKEY_SIZE};

    /// Decode a det1024 private key into (f, g, F, G).
    fn decode_privkey(sk: &[u8]) -> (Vec<i8>, Vec<i8>, Vec<i8>, Vec<i8>) {
        assert_eq!(sk.len(), FALCON_DET1024_PRIVKEY_SIZE);
        assert_eq!(sk[0], 0x50 + 10);
        let logn = 10u32;
        let n = 1usize << logn;
        let mut f = vec![0i8; n];
        let mut g = vec![0i8; n];
        let mut big_f = vec![0i8; n];
        let mut big_g = vec![0i8; n];
        let mut u = 1usize;
        let v = trim_i8_decode(&mut f, logn, u32::from(MAX_FG_BITS[10]), &sk[u..]);
        assert!(v > 0);
        u += v;
        let v = trim_i8_decode(&mut g, logn, u32::from(MAX_FG_BITS[10]), &sk[u..]);
        assert!(v > 0);
        u += v;
        let v = trim_i8_decode(&mut big_f, logn, u32::from(MAX_FG_BITS_BIG[10]), &sk[u..]);
        assert!(v > 0);
        u += v;
        assert_eq!(u, sk.len());
        assert!(complete_private(&mut big_g, &f, &g, &big_f, logn));
        (f, g, big_f, big_g)
    }

    #[test]
    fn gaussian0_and_sampler_match_c() {
        let seed = [0x11u8; 32];
        let mut rs_src = Shake256::prng_from_seed(&seed);
        let mut c_src = CInnerShake256::new();
        c_src.inject(&seed);
        c_src.flip();
        let mut rs_p = Prng::init(&mut rs_src);
        let mut c_p = CPrng::init(&mut c_src);
        for i in 0..5000 {
            assert_eq!(
                gaussian0_sampler(&mut rs_p),
                unsafe { c::falcon_inner_gaussian0_sampler(&mut c_p) },
                "gaussian0 #{i}"
            );
        }
        let mut spc = SamplerContext {
            p: rs_p,
            sigma_min: FPR_SIGMA_MIN[10],
        };
        let mut cspc = CSamplerContext {
            p: c_p,
            sigma_min: FPR_SIGMA_MIN[10].to_bits(),
        };
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        for i in 0..5000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            // Realistic inputs: centres of a few hundred, and 1/sigma for
            // sigma in roughly [1.1, 1.9] (what the leaf normalisation
            // produces). Outside that range x can go negative and the C's
            // shift becomes undefined, so neither side is meaningful.
            let mu = ((x >> 32) as f64 / 4294967296.0 - 0.5) * 400.0;
            let isigma = 0.53 + (x & 0xFF) as f64 / 700.0;
            let rs = sampler(&mut spc, mu, isigma);
            let cc = unsafe {
                c::falcon_inner_sampler(
                    &mut cspc as *mut _ as *mut core::ffi::c_void,
                    mu.to_bits(),
                    isigma.to_bits(),
                )
            };
            assert_eq!(rs, cc, "sampler #{i} mu={mu} isigma={isigma}");
        }
    }

    #[test]
    fn sign_dyn_matches_c_on_real_keys() {
        let logn = 10u32;
        let n = 1usize << logn;
        for seed_byte in [0u8, 1, 0x5a, 0xff] {
            let seed = [seed_byte; 32];
            let (_pk, sk) = falcon_keygen_with(FalconBackend::C, &seed).unwrap();
            let (f, g, big_f, big_g) = decode_privkey(&sk);
            for msg_len in [0usize, 1, 32, 1000] {
                let msg: Vec<u8> = (0..msg_len)
                    .map(|i| (i * 7 + usize::from(seed_byte)) as u8)
                    .collect();
                // hm = hash_to_point_ct(SHAKE256(salt || msg)) with the det1024 salt.
                let mut salt = [0u8; 40];
                salt[1] = 10;
                salt[2..12].copy_from_slice(b"FALCON_DET");
                let mut hsc = Shake256::new();
                hsc.inject(&salt);
                hsc.inject(&msg);
                hsc.flip();
                let mut hm = vec![0u16; n];
                hash_to_point_ct(&mut hsc, &mut hm, logn);
                // Sampler RNG = SHAKE256(logn || privkey || msg).
                let mut rs_rng = Shake256::new();
                rs_rng.inject(&[10u8]);
                rs_rng.inject(&sk);
                rs_rng.inject(&msg);
                rs_rng.flip();
                let mut c_rng = CInnerShake256::new();
                c_rng.inject(&[10u8]);
                c_rng.inject(&sk);
                c_rng.inject(&msg);
                c_rng.flip();
                let mut sig_rs = vec![0i16; n];
                let mut sig_c = vec![0i16; n];
                sign_dyn(&mut sig_rs, &mut rs_rng, &f, &g, &big_f, &big_g, &hm, logn);
                let mut tmp = vec![0u8; 78 * n + 7 + 64];
                unsafe {
                    c::falcon_inner_sign_dyn(
                        sig_c.as_mut_ptr(),
                        &mut c_rng,
                        f.as_ptr(),
                        g.as_ptr(),
                        big_f.as_ptr(),
                        big_g.as_ptr(),
                        hm.as_ptr(),
                        logn,
                        tmp.as_mut_ptr(),
                    )
                };
                assert_eq!(
                    sig_rs, sig_c,
                    "seed {seed_byte:#x} msg_len {msg_len}: s2 differs"
                );
                assert_eq!(
                    rs_rng.extract_vec(16),
                    c_rng.extract_vec(16),
                    "RNG consumption differs"
                );
            }
        }
    }
}
