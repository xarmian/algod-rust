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

//! The vendored-C backend: FFI bindings to the `falcon-c/` library
//! (github.com/algorand/falcon v0.1.0, MIT), compiled by `build.rs` when the
//! `c-backend` cargo feature is on. This is the implementation go-algorand
//! itself links through cgo (`crypto/falconWrapper.go`), so it is also the
//! local reference the pure-Rust backend is diffed against.
//!
//! Every function here assumes the caller (the dispatchers in `lib.rs`) has
//! already validated buffer sizes; the C library trusts its inputs.

use std::os::raw::{c_int, c_void};

use crate::{
    FalconError, FALCON_DET1024_PRIVKEY_SIZE, FALCON_DET1024_PUBKEY_SIZE,
    FALCON_DET1024_SIG_COMPRESSED_MAXSIZE, FALCON_DET1024_SIG_CT_SIZE,
};

/// Size of the SHAKE256 context structure (26 * u64 = 208 bytes).
const SHAKE256_CONTEXT_SIZE: usize = 26;

/// Opaque SHAKE256 context (matches the C `shake256_context` struct).
///
/// The `[u64; 26]` layout comes from `falcon.h` line 402:
/// `uint64_t opaque_contents[26]` (208 bytes total).
#[repr(C)]
struct Shake256Context {
    opaque_contents: [u64; SHAKE256_CONTEXT_SIZE],
}

extern "C" {
    fn shake256_init_prng_from_seed(sc: *mut Shake256Context, seed: *const c_void, seed_len: usize);

    fn falcon_det1024_keygen(
        rng: *mut Shake256Context,
        privkey: *mut c_void,
        pubkey: *mut c_void,
    ) -> c_int;

    fn falcon_det1024_sign_compressed(
        sig: *mut c_void,
        sig_len: *mut usize,
        privkey: *const c_void,
        data: *const c_void,
        data_len: usize,
    ) -> c_int;

    fn falcon_det1024_verify_compressed(
        sig: *const c_void,
        sig_len: usize,
        pubkey: *const c_void,
        data: *const c_void,
        data_len: usize,
    ) -> c_int;

    fn falcon_det1024_convert_compressed_to_ct(
        sig_ct: *mut c_void,
        sig_compressed: *const c_void,
        sig_compressed_len: usize,
    ) -> c_int;

    fn falcon_det1024_get_salt_version(sig: *const c_void) -> c_int;
}

fn ptr_or_null(data: &[u8]) -> *const c_void {
    if data.is_empty() {
        std::ptr::null()
    } else {
        data.as_ptr() as *const c_void
    }
}

/// `falcon_det1024_verify_compressed`. Sizes are pre-validated by the caller.
pub(crate) fn verify(pubkey: &[u8], sig: &[u8], data: &[u8]) -> Result<bool, FalconError> {
    debug_assert_eq!(pubkey.len(), FALCON_DET1024_PUBKEY_SIZE);
    debug_assert!(sig.len() >= 2 && sig.len() <= FALCON_DET1024_SIG_COMPRESSED_MAXSIZE);
    let rc = unsafe {
        falcon_det1024_verify_compressed(
            sig.as_ptr() as *const c_void,
            sig.len(),
            pubkey.as_ptr() as *const c_void,
            ptr_or_null(data),
            data.len(),
        )
    };
    Ok(rc == 0)
}

/// `shake256_init_prng_from_seed` + `falcon_det1024_keygen`.
pub(crate) fn keygen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), FalconError> {
    let mut rng = Shake256Context {
        opaque_contents: [0u64; SHAKE256_CONTEXT_SIZE],
    };
    unsafe {
        shake256_init_prng_from_seed(&mut rng, ptr_or_null(seed), seed.len());
    }

    let mut pubkey = vec![0u8; FALCON_DET1024_PUBKEY_SIZE];
    let mut privkey = vec![0u8; FALCON_DET1024_PRIVKEY_SIZE];
    let rc = unsafe {
        falcon_det1024_keygen(
            &mut rng,
            privkey.as_mut_ptr() as *mut c_void,
            pubkey.as_mut_ptr() as *mut c_void,
        )
    };
    if rc != 0 {
        return Err(FalconError::KeygenFailed(rc));
    }
    Ok((pubkey, privkey))
}

/// `falcon_det1024_sign_compressed`. The private key size is pre-validated.
pub(crate) fn sign(privkey: &[u8], data: &[u8]) -> Result<Vec<u8>, FalconError> {
    debug_assert_eq!(privkey.len(), FALCON_DET1024_PRIVKEY_SIZE);
    let mut sig = vec![0u8; FALCON_DET1024_SIG_COMPRESSED_MAXSIZE];
    let mut sig_len: usize = FALCON_DET1024_SIG_COMPRESSED_MAXSIZE;
    let rc = unsafe {
        falcon_det1024_sign_compressed(
            sig.as_mut_ptr() as *mut c_void,
            &mut sig_len,
            privkey.as_ptr() as *const c_void,
            ptr_or_null(data),
            data.len(),
        )
    };
    if rc != 0 {
        return Err(FalconError::SignFailed(rc));
    }
    sig.truncate(sig_len);
    Ok(sig)
}

/// `falcon_det1024_convert_compressed_to_ct`. The signature size is
/// pre-validated.
pub(crate) fn convert_compressed_to_ct(
    sig_compressed: &[u8],
) -> Result<[u8; FALCON_DET1024_SIG_CT_SIZE], FalconError> {
    debug_assert!(
        sig_compressed.len() >= 2 && sig_compressed.len() <= FALCON_DET1024_SIG_COMPRESSED_MAXSIZE
    );
    let mut sig_ct = [0u8; FALCON_DET1024_SIG_CT_SIZE];
    let rc = unsafe {
        falcon_det1024_convert_compressed_to_ct(
            sig_ct.as_mut_ptr() as *mut c_void,
            sig_compressed.as_ptr() as *const c_void,
            sig_compressed.len(),
        )
    };
    if rc != 0 {
        return Err(FalconError::ConvertToCtFailed(rc));
    }
    Ok(sig_ct)
}

/// `falcon_det1024_get_salt_version`. The C function
/// (`falcon-c/deterministic.c:167`) unconditionally reads `sig[1]` with no
/// length check of its own, so the caller's `sig.len() >= 2` validation is
/// what makes this call sound on attacker-controlled input.
pub(crate) fn salt_version(sig: &[u8]) -> Result<u8, FalconError> {
    debug_assert!(sig.len() >= 2);
    let rc = unsafe { falcon_det1024_get_salt_version(sig.as_ptr() as *const c_void) };
    if rc < 0 {
        return Err(FalconError::SaltVersionFailed(rc));
    }
    Ok(rc as u8)
}
