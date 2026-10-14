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

//! Algorand's deterministic Falcon-1024 layer (`deterministic.c` /
//! `deterministic.h`): seed-derived keys, deterministic signing with a
//! fixed versioned salt, the unsalted wire format (header `0xBA`, one salt
//! version byte) and the compressed → CT conversion.
//!
//! Ported from `falcon-c/deterministic.c` (Copyright (c) Algorand, Inc.,
//! MIT License, part of github.com/algorand/falcon v0.1.0), vendored
//! verbatim under `crates/core/algo-falcon/falcon-c/`; the MIT notice is
//! preserved in `falcon-c/LICENSE`.
//!
//! This is the layer go-algorand's `crypto/falconWrapper.go` calls through
//! cgo; see `docs/DIVERGENCES.md` `DIV-001`.

use super::codec::{comp_decode, trim_i16_encode, MAX_SIG_BITS};
use super::falcon::{
    get_logn, keygen_make, sig_compressed_maxsize, sign_dyn_finish_compressed, verify_compressed,
    FALCON_ERR_BADSIG, FALCON_ERR_FORMAT, FALCON_ERR_SIZE,
};
use super::shake256::Shake256;

pub(crate) const LOGN: u32 = 10;
pub(crate) const PUBKEY_SIZE: usize = 1793;
pub(crate) const PRIVKEY_SIZE: usize = 2305;
/// Salted compressed maximum (`FALCON_SIG_COMPRESSED_MAXSIZE(10)`).
const SALTED_SIG_COMPRESSED_MAXSIZE: usize = sig_compressed_maxsize(LOGN);
/// Unsalted det1024 compressed maximum: salt (40) replaced by version (1).
pub(crate) const SIG_COMPRESSED_MAXSIZE: usize = SALTED_SIG_COMPRESSED_MAXSIZE - 40 + 1;
/// `FALCON_DET1024_SIG_CT_SIZE`.
pub(crate) const SIG_CT_SIZE: usize = 1538;
pub(crate) const CURRENT_SALT_VERSION: u8 = 0;
/// `FALCON_DET1024_SIG_COMPRESSED_HEADER` (`0x3A | 0x80`).
pub(crate) const SIG_COMPRESSED_HEADER: u8 = 0xBA;
/// `FALCON_DET1024_SIG_CT_HEADER` (`0x5A | 0x80`).
pub(crate) const SIG_CT_HEADER: u8 = 0xDA;

/// `falcon_det1024_keygen`.
pub(crate) fn keygen(rng: &mut Shake256, privkey: &mut [u8], pubkey: &mut [u8]) -> i32 {
    keygen_make(rng, LOGN, privkey, Some(pubkey))
}

/// `falcon_det1024_write_salt`: `[salt_version, logn, "FALCON_DET" + zeros]`.
pub(crate) fn write_salt(dst: &mut [u8; 40], salt_version: u8) {
    dst.fill(0);
    dst[0] = salt_version;
    dst[1] = LOGN as u8;
    dst[2..12].copy_from_slice(b"FALCON_DET");
}

/// `falcon_det1024_sign_compressed`: deterministic signature over `data`.
/// `sig` must hold `SIG_COMPRESSED_MAXSIZE` bytes; the used length is
/// returned in `sig_len`.
pub(crate) fn sign_compressed(
    sig: &mut [u8],
    sig_len: &mut usize,
    privkey: &[u8],
    data: &[u8],
) -> i32 {
    if get_logn(privkey) != LOGN as i32 {
        return FALCON_ERR_FORMAT;
    }
    // SHAKE(logn || privkey || data), set to output mode: the sampler RNG.
    let mut detrng = Shake256::new();
    detrng.inject(&[LOGN as u8]);
    detrng.inject(&privkey[..PRIVKEY_SIZE]);
    detrng.inject(data);
    detrng.flip();

    let mut salt = [0u8; 40];
    write_salt(&mut salt, CURRENT_SALT_VERSION);

    // SHAKE(salt || data), still in input mode.
    let mut hd = Shake256::new();
    hd.inject(&salt);
    hd.inject(data);

    let mut saltedsig = vec![0u8; SALTED_SIG_COMPRESSED_MAXSIZE];
    let mut saltedsig_len = SALTED_SIG_COMPRESSED_MAXSIZE;
    let r = sign_dyn_finish_compressed(
        &mut detrng,
        &mut saltedsig,
        &mut saltedsig_len,
        &privkey[..PRIVKEY_SIZE],
        &mut hd,
        &salt,
    );
    if r != 0 {
        return r;
    }

    // Transform the salted signature to the unsalted format.
    sig[0] = saltedsig[0] | 0x80;
    sig[1] = CURRENT_SALT_VERSION;
    sig[2..2 + saltedsig_len - 41].copy_from_slice(&saltedsig[41..saltedsig_len]);
    *sig_len = saltedsig_len - 40 + 1;
    0
}

/// `falcon_det1024_convert_compressed_to_ct`.
pub(crate) fn convert_compressed_to_ct(sig_ct: &mut [u8], sig_compressed: &[u8]) -> i32 {
    if sig_compressed[0] != SIG_COMPRESSED_HEADER {
        return FALCON_ERR_BADSIG;
    }
    let mut coeffs = vec![0i16; 1 << LOGN];
    let v = comp_decode(&mut coeffs, LOGN, &sig_compressed[2..]);
    if v == 0 {
        return FALCON_ERR_SIZE;
    }
    sig_ct[0] = SIG_CT_HEADER;
    sig_ct[1] = sig_compressed[1];
    let v = trim_i16_encode(
        Some(&mut sig_ct[2..SIG_CT_SIZE]),
        &coeffs,
        LOGN,
        u32::from(MAX_SIG_BITS[LOGN as usize]),
    );
    if v == 0 {
        return FALCON_ERR_SIZE;
    }
    0
}

/// `falcon_det1024_resalt`: rebuild the salted signature from an unsalted one.
fn resalt(salted_sig: &mut [u8], unsalted_sig: &[u8]) {
    salted_sig[0] = unsalted_sig[0] & !0x80;
    let mut salt = [0u8; 40];
    write_salt(&mut salt, unsalted_sig[1]);
    salted_sig[1..41].copy_from_slice(&salt);
    salted_sig[41..41 + unsalted_sig.len() - 2].copy_from_slice(&unsalted_sig[2..]);
}

/// `falcon_det1024_verify_compressed`.
pub(crate) fn verify_compressed_det(sig: &[u8], pubkey: &[u8], data: &[u8]) -> i32 {
    if sig.len() < 2 {
        return FALCON_ERR_BADSIG;
    }
    if sig[0] != SIG_COMPRESSED_HEADER {
        return FALCON_ERR_BADSIG;
    }
    // Add back the salt; drop the version byte.
    let salted_sig_len = sig.len() + 40 - 1;
    if salted_sig_len > SALTED_SIG_COMPRESSED_MAXSIZE {
        return FALCON_ERR_BADSIG;
    }
    let mut salted_sig = vec![0u8; salted_sig_len];
    resalt(&mut salted_sig, sig);
    verify_compressed(&salted_sig, &pubkey[..PUBKEY_SIZE], data)
}

/// `falcon_det1024_get_salt_version`.
pub(crate) fn get_salt_version(sig: &[u8]) -> i32 {
    i32::from(sig[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_the_c_header() {
        assert_eq!(SIG_COMPRESSED_MAXSIZE, 1423);
        assert_eq!(SALTED_SIG_COMPRESSED_MAXSIZE, 1462);
        let mut s = [0xffu8; 40];
        write_salt(&mut s, 3);
        assert_eq!(
            &s[..12],
            &[3, 10, b'F', b'A', b'L', b'C', b'O', b'N', b'_', b'D', b'E', b'T']
        );
        assert!(s[12..].iter().all(|&b| b == 0));
    }

    /// Pure-Rust end to end: keygen from a seed, sign, verify, CT convert,
    /// salt version; and the documented rejections.
    #[test]
    fn keygen_sign_verify_round_trip_pure_rust() {
        let mut rng = Shake256::prng_from_seed(&[9u8; 32]);
        let mut sk = [0u8; PRIVKEY_SIZE];
        let mut pk = [0u8; PUBKEY_SIZE];
        assert_eq!(keygen(&mut rng, &mut sk, &mut pk), 0);
        let msg = b"deterministic falcon";
        let mut sig = [0u8; SIG_COMPRESSED_MAXSIZE];
        let mut len = 0usize;
        assert_eq!(sign_compressed(&mut sig, &mut len, &sk, msg), 0);
        assert!((2..=SIG_COMPRESSED_MAXSIZE).contains(&len));
        assert_eq!(sig[0], SIG_COMPRESSED_HEADER);
        assert_eq!(get_salt_version(&sig), 0);
        assert_eq!(verify_compressed_det(&sig[..len], &pk, msg), 0);
        assert_eq!(
            verify_compressed_det(&sig[..len], &pk, b"other"),
            FALCON_ERR_BADSIG
        );
        let mut bad = sig;
        bad[0] = 0x3A;
        assert_eq!(
            verify_compressed_det(&bad[..len], &pk, msg),
            FALCON_ERR_BADSIG
        );
        assert_eq!(
            verify_compressed_det(&sig[..len - 1], &pk, msg),
            FALCON_ERR_FORMAT
        );
        let mut ct = [0u8; SIG_CT_SIZE];
        assert_eq!(convert_compressed_to_ct(&mut ct, &sig[..len]), 0);
        assert_eq!(ct[0], SIG_CT_HEADER);
        assert_eq!(ct[1], 0);
        // Signing is deterministic.
        let mut sig2 = [0u8; SIG_COMPRESSED_MAXSIZE];
        let mut len2 = 0usize;
        assert_eq!(sign_compressed(&mut sig2, &mut len2, &sk, msg), 0);
        assert_eq!((&sig[..len], len), (&sig2[..len2], len2));
    }
}
