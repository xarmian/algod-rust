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

//! Test-only bindings to the vendored C library's *internal* symbols
//! (`falcon_inner_*`, the `Zf()` prefix in `inner.h`), used by the
//! per-module differential tests in `rs/` to prove each ported module
//! byte-identical to the C it replaces (DIV-001). Compiled only for tests
//! with the `c-backend` feature.

use std::os::raw::c_void;

use crate::backend::c::{shake256_init_prng_from_seed, Shake256Context};

/// `inner_shake256_context` (`inner.h`): 25 lanes + the byte pointer.
#[repr(C)]
pub(crate) struct CInnerShake256 {
    a: [u64; 25],
    dptr: u64,
}

extern "C" {
    fn falcon_inner_i_shake256_init(sc: *mut CInnerShake256);
    fn falcon_inner_i_shake256_inject(sc: *mut CInnerShake256, input: *const u8, len: usize);
    fn falcon_inner_i_shake256_flip(sc: *mut CInnerShake256);
    fn falcon_inner_i_shake256_extract(sc: *mut CInnerShake256, out: *mut u8, len: usize);

    // Public API (falcon.h); `shake256_init_prng_from_seed` is declared in
    // `backend::c` and shared from there.
    fn shake256_extract(sc: *mut Shake256Context, out: *mut c_void, len: usize);

    // codec.c
    pub(crate) fn falcon_inner_modq_encode(
        out: *mut u8,
        max_out_len: usize,
        x: *const u16,
        logn: u32,
    ) -> usize;
    pub(crate) fn falcon_inner_modq_decode(
        x: *mut u16,
        logn: u32,
        input: *const u8,
        max_in_len: usize,
    ) -> usize;
    pub(crate) fn falcon_inner_trim_i16_encode(
        out: *mut u8,
        max_out_len: usize,
        x: *const i16,
        logn: u32,
        bits: u32,
    ) -> usize;
    pub(crate) fn falcon_inner_trim_i16_decode(
        x: *mut i16,
        logn: u32,
        bits: u32,
        input: *const u8,
        max_in_len: usize,
    ) -> usize;
    pub(crate) fn falcon_inner_trim_i8_encode(
        out: *mut u8,
        max_out_len: usize,
        x: *const i8,
        logn: u32,
        bits: u32,
    ) -> usize;
    pub(crate) fn falcon_inner_trim_i8_decode(
        x: *mut i8,
        logn: u32,
        bits: u32,
        input: *const u8,
        max_in_len: usize,
    ) -> usize;
    pub(crate) fn falcon_inner_comp_encode(
        out: *mut u8,
        max_out_len: usize,
        x: *const i16,
        logn: u32,
    ) -> usize;
    pub(crate) fn falcon_inner_comp_decode(
        x: *mut i16,
        logn: u32,
        input: *const u8,
        max_in_len: usize,
    ) -> usize;
    pub(crate) static falcon_inner_max_fg_bits: [u8; 11];
    pub(crate) static falcon_inner_max_FG_bits: [u8; 11];
    pub(crate) static falcon_inner_max_sig_bits: [u8; 11];

    // fpr.c (FALCON_FPEMU: `fpr` is a u64 bit pattern)
    pub(crate) fn falcon_inner_fpr_add(x: u64, y: u64) -> u64;
    pub(crate) fn falcon_inner_fpr_mul(x: u64, y: u64) -> u64;
    pub(crate) fn falcon_inner_fpr_div(x: u64, y: u64) -> u64;
    pub(crate) fn falcon_inner_fpr_sqrt(x: u64) -> u64;
    pub(crate) fn falcon_inner_fpr_expm_p63(x: u64, ccs: u64) -> u64;
    pub(crate) static falcon_inner_fpr_gm_tab: [u64; 2048];
    pub(crate) static falcon_inner_fpr_p2_tab: [u64; 11];
}

/// `static inline` helpers re-exported by `falcon-c-test/shim_*.c`.
#[cfg(feature = "c-internals-test")]
pub(crate) mod shim {
    extern "C" {
        pub(crate) fn falcon_shim_x_fpr_rint(x: u64) -> i64;
        pub(crate) fn falcon_shim_x_fpr_floor(x: u64) -> i64;
        pub(crate) fn falcon_shim_x_fpr_trunc(x: u64) -> i64;
        pub(crate) fn falcon_shim_x_fpr_lt(x: u64, y: u64) -> i32;
        pub(crate) fn falcon_shim_x_fpr_of(i: i64) -> u64;
        pub(crate) fn falcon_shim_x_fpr_neg(x: u64) -> u64;
        pub(crate) fn falcon_shim_x_fpr_half(x: u64) -> u64;
        pub(crate) fn falcon_shim_x_fpr_double(x: u64) -> u64;
        pub(crate) fn falcon_shim_x_fpr_sub(x: u64, y: u64) -> u64;
        pub(crate) fn falcon_shim_x_fpr_sqr(x: u64) -> u64;
        pub(crate) fn falcon_shim_x_fpr_inv(x: u64) -> u64;
    }
}

impl CInnerShake256 {
    pub(crate) fn new() -> Self {
        let mut sc = CInnerShake256 {
            a: [0; 25],
            dptr: 0,
        };
        unsafe { falcon_inner_i_shake256_init(&mut sc) };
        sc
    }

    pub(crate) fn inject(&mut self, data: &[u8]) {
        unsafe { falcon_inner_i_shake256_inject(self, data.as_ptr(), data.len()) };
    }

    pub(crate) fn flip(&mut self) {
        unsafe { falcon_inner_i_shake256_flip(self) };
    }

    pub(crate) fn extract_vec(&mut self, n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        unsafe { falcon_inner_i_shake256_extract(self, out.as_mut_ptr(), n) };
        out
    }
}

/// `shake256_init_prng_from_seed` followed by one `shake256_extract` of `n`
/// bytes, through the public C API.
pub(crate) fn shake256_prng_from_seed_extract(seed: &[u8], n: usize) -> Vec<u8> {
    let mut sc = Shake256Context::zeroed();
    let seed_ptr = if seed.is_empty() {
        std::ptr::null()
    } else {
        seed.as_ptr() as *const c_void
    };
    let mut out = vec![0u8; n];
    unsafe {
        shake256_init_prng_from_seed(&mut sc, seed_ptr, seed.len());
        shake256_extract(&mut sc, out.as_mut_ptr() as *mut c_void, n);
    }
    out
}
